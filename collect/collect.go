package collect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// maxPlanBytes bounds the plan JSON we are willing to decode. Terraform plans for
// very large states are big but not unbounded, and this keeps a malformed or
// hostile input from exhausting the runner.
const maxPlanBytes = 256 << 20

// indexSuffix matches a count or for_each subscript anywhere in an address, and
// trailingIndex matches only the one belonging to the resource itself.
var (
	indexSuffix   = regexp.MustCompile(`\[[^\]]*\]`)
	trailingIndex = regexp.MustCompile(`\[([^\]]*)\]$`)
)

var deniedKey = regexp.MustCompile(`(?i)(^|_)(password|passwd|secret|token|api_?key|private_?key|access_?key|client_?secret|authorization|cookie|user_?data|connection_?string|certificate_?body|secret_?string)($|_)`)

type rawPlan struct {
	FormatVersion    string `json:"format_version"`
	TerraformVersion string `json:"terraform_version"`
	ResourceChanges  []struct {
		Address      string `json:"address"`
		Module       string `json:"module_address"`
		Mode         string `json:"mode"`
		Type         string `json:"type"`
		Name         string `json:"name"`
		ProviderName string `json:"provider_name"`
		Change       struct {
			Actions        []string `json:"actions"`
			After          any      `json:"after"`
			AfterSensitive any      `json:"after_sensitive"`
		} `json:"change"`
	} `json:"resource_changes"`
	Configuration *config `json:"configuration"`
}

type config struct {
	RootModule *configModule `json:"root_module"`
}

type configModule struct {
	Resources   []configResource            `json:"resources"`
	ModuleCalls map[string]configModuleCall `json:"module_calls"`
}

type configModuleCall struct {
	Module *configModule `json:"module"`
	// Source locates a module whose directory the manifest does not record,
	// which is the case for a local path module.
	Source string `json:"source"`
}

type configResource struct {
	Address     string         `json:"address"`
	Expressions map[string]any `json:"expressions"`
}

// FromPlanJSON decodes `terraform show -json` output and returns the sanitized
// bundle built from it.
//
// No configuration directory, so no locals: every reference that goes through
// one stays unresolved. FromPlanJSONWithSource is what a runner should call.
func FromPlanJSON(input io.Reader) (*Bundle, error) {
	return FromPlanJSONWithSource(input, "")
}

// FromPlanJSONWithSource additionally reads the configuration's locals from the
// .tf files under sourceDir, which the plan JSON does not carry.
//
// Only `locals` blocks are read, and only the names and references inside them.
// An unreadable or absent directory is not an error: it yields a bundle with no
// symbols, which is exactly what version 2 produced.
func FromPlanJSONWithSource(input io.Reader, sourceDir string) (*Bundle, error) {
	decoder := json.NewDecoder(io.LimitReader(input, maxPlanBytes))
	// Numbers are kept as their original literals. Round-tripping them through
	// float64 would rewrite ports and CIDR-adjacent values that the renderer reads
	// back as text.
	decoder.UseNumber()

	var plan rawPlan
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("decode Terraform plan JSON: %w", err)
	}
	if plan.FormatVersion == "" {
		return nil, errors.New("input is not Terraform plan JSON: format_version missing")
	}

	result := collect(plan, sourceDir)
	return &result, nil
}

func collect(plan rawPlan, sourceDir string) Bundle {
	result := Bundle{
		SchemaVersion:    SchemaVersion,
		TerraformVersion: plan.TerraformVersion,
		FormatVersion:    plan.FormatVersion,
		Resources:        make([]Resource, 0, len(plan.ResourceChanges)),
		Stats:            Stats{Profile: "standard"},
	}

	for _, change := range plan.ResourceChanges {
		values, keep := sanitize(change.Change.After, change.Change.AfterSensitive, &result.Stats)
		valueMap, _ := values.(map[string]any)
		if !keep {
			valueMap = nil
		}
		result.Resources = append(result.Resources, Resource{
			Address: change.Address, Module: change.Module, Mode: change.Mode,
			Type: change.Type, Name: change.Name, ProviderName: change.ProviderName,
			Actions: change.Change.Actions, Values: valueMap,
		})
	}
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].Address < result.Resources[j].Address })
	result.References = collectReferences(plan.Configuration)

	if sourceDir != "" && len(result.References) > 0 {
		scanner := newSymbolScanner(sourceDir)
		scanner.scan(plan.Configuration.RootModule, scanner.rootPath, "")
		if len(scanner.symbols) > 0 {
			for _, refs := range scanner.symbols {
				sort.Strings(refs)
			}
			result.Symbols = scanner.symbols
		}
	}
	return result
}

// sanitize walks a planned value alongside Terraform's own sensitivity mask and
// returns the value with everything redactable removed. The bool reports whether
// the value survived at all.
func sanitize(value, sensitive any, report *Stats) (any, bool) {
	if markedSensitive(sensitive) {
		report.SensitivePathsRemoved++
		return nil, false
	}

	switch current := value.(type) {
	case map[string]any:
		mask, _ := sensitive.(map[string]any)
		clean := make(map[string]any, len(current))
		for key, child := range current {
			if deniedKey.MatchString(normalizeKey(key)) {
				report.DeniedKeysRemoved++
				continue
			}
			cleaned, keep := sanitize(child, mask[key], report)
			if keep {
				clean[key] = cleaned
			}
		}
		return clean, true
	case []any:
		mask, _ := sensitive.([]any)
		clean := make([]any, 0, len(current))
		for index, child := range current {
			var childMask any
			if index < len(mask) {
				childMask = mask[index]
			}
			cleaned, keep := sanitize(child, childMask, report)
			switch {
			case keep:
				clean = append(clean, cleaned)
			case isObject(child):
				// A redacted object becomes an empty object rather than null.
				// Consumers index nested blocks positionally and skip non-object
				// elements, so a null here would silently shift every later block
				// down by one and make `route[1]` read as `route[0]`.
				clean = append(clean, map[string]any{})
			default:
				clean = append(clean, nil)
			}
		}
		return clean, true
	default:
		return value, true
	}
}

func isObject(value any) bool {
	_, ok := value.(map[string]any)
	return ok
}

func markedSensitive(value any) bool {
	marked, ok := value.(bool)
	return ok && marked
}

// normalizeKey folds camelCase, kebab-case and dotted keys into snake_case so a
// single denied-key pattern catches every spelling of the same attribute.
func normalizeKey(value string) string {
	var result strings.Builder
	for index, r := range value {
		if index > 0 && r >= 'A' && r <= 'Z' {
			previous := value[index-1]
			// Preserve boundaries after punctuation and non-ASCII characters too,
			// but do not split acronym runs or duplicate normalized separators.
			if previous != '_' && previous != '-' && previous != '.' &&
				(previous < 'A' || previous > 'Z' ||
					index+1 < len(value) && value[index+1] >= 'a' && value[index+1] <= 'z') {
				result.WriteByte('_')
			}
		}
		if r == '-' || r == '.' {
			result.WriteByte('_')
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// collectReferences reports every reference each configured resource makes,
// exactly as written and without resolving any of it.
//
// Resolution used to happen here: a reference was matched against the plan's
// resources, paired to the right instance of a counted resource, deduplicated,
// and anything left over was discarded. All of that moved to the renderer.
//
// The division is between extracting and interpreting. What a configuration
// says is a fact about the customer's repository and belongs in the open, where
// it can be audited. What a reference *means* for a diagram — which instance it
// pairs with, whether it implies containment — is a product decision, and
// keeping it here meant every new diagramming rule needed a new release of this
// action in every customer's workflow.
//
// Sources are the addresses the configuration uses, without count subscripts.
// The renderer expands them against the resources the bundle carries.
func collectReferences(configuration *config) []Reference {
	if configuration == nil || configuration.RootModule == nil {
		return nil
	}
	seen := make(map[Reference]bool)
	collectModuleReferences(configuration.RootModule, "", seen)

	result := make([]Reference, 0, len(seen))
	for item := range seen {
		result = append(result, item)
	}
	// Materializing from a map leaves the order undefined, and the emitted
	// bundle must be byte-identical for identical input.
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		switch {
		case left.Source != right.Source:
			return left.Source < right.Source
		case left.Ref != right.Ref:
			return left.Ref < right.Ref
		case left.Via != right.Via:
			return left.Via < right.Via
		case left.BlockType != right.BlockType:
			return left.BlockType < right.BlockType
		default:
			return left.BlockIndex < right.BlockIndex
		}
	})
	return result
}

// collectModuleReferences walks one configuration module. prefix is the module
// path this body sits under ("" at the root, "module.network" one level down).
//
// Threading the prefix is what makes cross-module references usable: inside a
// module body Terraform writes addresses relative to that module
// ("aws_vpc.main"), while the plan addresses them absolutely
// ("module.network.aws_vpc.main"). An unprefixed reference names something else
// entirely, or nothing.
func collectModuleReferences(module *configModule, prefix string, seen map[Reference]bool) {
	for _, current := range module.Resources {
		source := qualifyRef(prefix, strings.Split(current.Address, "."))
		if source == "" {
			continue
		}
		walkExpressions(current.Expressions, func(via, blockType string, blockIndex int, rawRef string) {
			// qualifyRef drops what can never name a resource — a variable, a
			// count index — so those never reach the bundle.
			target := qualifyRef(prefix, strings.Split(rawRef, "."))
			if target == "" || target == source {
				return
			}
			seen[Reference{
				Source: source, Via: via, BlockType: blockType,
				BlockIndex: blockIndex, Ref: target,
			}] = true
		})
	}
	for name, call := range module.ModuleCalls {
		if call.Module != nil {
			collectModuleReferences(call.Module, prefix+"module."+name+".", seen)
		}
	}
}

// bareAddress strips count and for_each subscripts, giving the form the
// configuration writes an address in.
func bareAddress(address string) string {
	return indexSuffix.ReplaceAllString(address, "")
}

// walkExpressions reports every reference in a resource's expressions, tagged with
// the nested block it came from.
//
// Terraform encodes a leaf expression as an object carrying "references" or
// "constant_value", and a nested block as an object (or array of objects) whose
// keys are themselves attribute names. That distinction is the only thing
// separating `route = [...]` the block list from a tuple-valued attribute.
func walkExpressions(expressions map[string]any, emit func(via, blockType string, blockIndex int, rawRef string)) {
	for attribute, value := range expressions {
		switch node := value.(type) {
		case map[string]any:
			if isExpressionNode(node) {
				emitRefs(node, attribute, "", -1, emit)
				continue
			}
			// A single nested block: its attributes are the interesting names.
			emitBlock(node, attribute, 0, emit)
		case []any:
			for index, element := range node {
				block, ok := element.(map[string]any)
				if !ok {
					continue
				}
				if isExpressionNode(block) {
					emitRefs(block, attribute, "", -1, emit)
					continue
				}
				emitBlock(block, attribute, index, emit)
			}
		}
	}
}

func emitBlock(block map[string]any, blockType string, blockIndex int, emit func(via, blockType string, blockIndex int, rawRef string)) {
	for inner, value := range block {
		emitRefs(value, inner, blockType, blockIndex, emit)
	}
}

func emitRefs(value any, via, blockType string, blockIndex int, emit func(via, blockType string, blockIndex int, rawRef string)) {
	for _, reference := range expressionReferences(value) {
		emit(via, blockType, blockIndex, reference)
	}
}

func isExpressionNode(node map[string]any) bool {
	if _, ok := node["references"]; ok {
		return true
	}
	_, ok := node["constant_value"]
	return ok
}

func expressionReferences(value any) []string {
	var references []string
	var walk func(any)
	walk = func(current any) {
		switch node := current.(type) {
		case map[string]any:
			for key, child := range node {
				if key == "references" {
					if values, ok := child.([]any); ok {
						for _, value := range values {
							if reference, ok := value.(string); ok {
								references = append(references, reference)
							}
						}
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(value)
	return references
}

// resourceAddress truncates a reference such as "aws_subnet.public.id" to the
// address of the resource it names.
func resourceAddress(reference string) string {
	parts := strings.Split(reference, ".")

	// Consume any number of leading module.<name> pairs.
	start := 0
	for start+1 < len(parts) && parts[start] == "module" {
		start += 2
	}

	// A data source needs three segments ("data.aws_ami.recent") where a managed
	// resource needs two. Without this a reference to a data source truncates to
	// "data.aws_ami", which names nothing and is discarded for the wrong reason.
	length := 2
	if start < len(parts) && parts[start] == "data" {
		length = 3
	}

	end := start + length
	if end > len(parts) {
		return ""
	}
	return strings.Join(parts[:end], ".")
}

// ContainsDeniedKey reports whether any key anywhere in the value matches the
// redaction pattern.
//
// Exported so a consumer can re-check a bundle it received without carrying its
// own copy of the pattern. Two copies would drift, and the copy that drifts is
// the one that stops catching things.
func ContainsDeniedKey(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if deniedKey.MatchString(normalizeKey(key)) || ContainsDeniedKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if ContainsDeniedKey(child) {
				return true
			}
		}
	}
	return false
}
