package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
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
}

type configResource struct {
	Address     string         `json:"address"`
	Expressions map[string]any `json:"expressions"`
}

// FromPlanJSON decodes `terraform show -json` output and returns the sanitized
// bundle built from it.
func FromPlanJSON(input io.Reader) (*Bundle, error) {
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

	result := collect(plan)
	return &result, nil
}

func collect(plan rawPlan) Bundle {
	result := Bundle{
		SchemaVersion:    SchemaVersion,
		TerraformVersion: plan.TerraformVersion,
		FormatVersion:    plan.FormatVersion,
		Resources:        make([]Resource, 0, len(plan.ResourceChanges)),
		Stats:            Stats{Profile: "standard"},
	}

	// Configuration addresses a resource once ("aws_subnet.this") while the plan
	// addresses every instance count produced ("module.vpc.aws_subnet.this[0]").
	// Index the instances by their subscript-free form so a reference written
	// against the configuration can find the concrete resources it names.
	instances := make(map[string][]string, len(plan.ResourceChanges))
	for _, change := range plan.ResourceChanges {
		bare := bareAddress(change.Address)
		instances[bare] = append(instances[bare], change.Address)
	}
	for _, list := range instances {
		sort.Strings(list)
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
	result.Relationships = collectRelationships(plan.Configuration, instances)
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
			result.WriteByte('_')
		}
		if r == '-' || r == '.' {
			result.WriteByte('_')
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func collectRelationships(configuration *config, instances map[string][]string) []Relation {
	if configuration == nil || configuration.RootModule == nil {
		return nil
	}
	relations := make(map[string]Relation)
	collectModuleRelationships(configuration.RootModule, "", instances, relations)

	result := make([]Relation, 0, len(relations))
	for _, item := range relations {
		result = append(result, item)
	}
	// Materializing from a map leaves the order undefined, and the receiver's
	// output must be byte-identical for identical input, so sort on every field
	// that distinguishes two relations.
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		switch {
		case left.Source != right.Source:
			return left.Source < right.Source
		case left.Target != right.Target:
			return left.Target < right.Target
		case left.Via != right.Via:
			return left.Via < right.Via
		case left.BlockType != right.BlockType:
			return left.BlockType < right.BlockType
		case left.BlockIndex != right.BlockIndex:
			return left.BlockIndex < right.BlockIndex
		default:
			return left.RawRef < right.RawRef
		}
	})
	return result
}

// collectModuleRelationships walks one configuration module. prefix is the module
// path this body sits under ("" at the root, "module.network" one level down).
//
// Threading the prefix is what makes cross-module edges survive: inside a module
// body Terraform writes addresses relative to that module ("aws_vpc.main"), while
// resource_changes addresses them absolutely ("module.network.aws_vpc.main"). An
// unprefixed walk produces targets that match nothing and are silently discarded.
func collectModuleRelationships(module *configModule, prefix string, instances map[string][]string, relations map[string]Relation) {
	for _, current := range module.Resources {
		sources := instances[bareAddress(qualify(prefix, current.Address))]
		if len(sources) == 0 {
			continue
		}
		walkExpressions(current.Expressions, func(via, blockType string, blockIndex int, rawRef string) {
			targets := resolveTargets(prefix, rawRef, instances)
			if len(targets) == 0 {
				return
			}
			for _, source := range sources {
				for _, target := range matchInstances(source, targets) {
					if target == source {
						continue
					}
					item := Relation{
						Source: source, Target: target, Via: via,
						BlockType: blockType, BlockIndex: blockIndex, RawRef: rawRef,
					}
					key := relationKey(item)
					if existing, seen := relations[key]; seen && !preferRef(item.RawRef, existing.RawRef) {
						continue
					}
					relations[key] = item
				}
			}
		})
	}
	for name, call := range module.ModuleCalls {
		if call.Module != nil {
			collectModuleRelationships(call.Module, qualify(prefix, "module."+name), instances, relations)
		}
	}
}

// matchInstances decides which instances of a target a given source instance
// actually refers to.
//
// Counted resources are usually declared in parallel — subnet[i] belongs to route
// table[i] — so an index that exists on both sides pairs them one to one. Where no
// such pairing exists the reference really is one-to-many, as in an autoscaling
// group naming every private subnet, and every instance is reported.
func matchInstances(source string, targets []string) []string {
	if len(targets) == 1 {
		return targets
	}
	if index := trailingIndex.FindStringSubmatch(source); index != nil {
		for _, target := range targets {
			if match := trailingIndex.FindStringSubmatch(target); match != nil && match[1] == index[1] {
				return []string{target}
			}
		}
	}
	return targets
}

// bareAddress strips every count or for_each subscript, giving the address as the
// configuration spells it.
func bareAddress(address string) string {
	return indexSuffix.ReplaceAllString(address, "")
}

// relationKey deliberately excludes RawRef. Terraform reports a single reference
// twice, once as "aws_vpc.main" and once as "aws_vpc.main.id", and keying on the
// raw text would emit both as separate edges.
func relationKey(item Relation) string {
	hash := sha256.Sum256([]byte(strings.Join([]string{
		item.Source, item.Target, item.Via, item.BlockType,
		strconv.Itoa(item.BlockIndex),
	}, "\x00")))
	return hex.EncodeToString(hash[:])
}

// preferRef picks between two spellings of the same reference. The longer one
// carries the attribute that was actually read ("aws_vpc.main.id" over
// "aws_vpc.main"), which is strictly more information for a consumer trying to
// resolve an indirect reference. Length ties break lexicographically so that the
// choice does not depend on map iteration order.
func preferRef(candidate, existing string) bool {
	if len(candidate) != len(existing) {
		return len(candidate) > len(existing)
	}
	return candidate < existing
}

func qualify(prefix, address string) string {
	if prefix == "" {
		return address
	}
	return prefix + "." + address
}

// resolveTargets turns a raw reference into the plan resources it names. A
// reference inside a module body is usually module-relative, but may already be
// absolute, so try the qualified form first and fall back to the bare one.
func resolveTargets(prefix, rawRef string, instances map[string][]string) []string {
	address := resourceAddress(rawRef)
	if address == "" {
		return nil
	}
	if prefix != "" {
		if found := instances[bareAddress(qualify(prefix, address))]; len(found) > 0 {
			return found
		}
	}
	return instances[bareAddress(address)]
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
