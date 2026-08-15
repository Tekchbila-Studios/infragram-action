package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

const schemaVersion = 1

var deniedKey = regexp.MustCompile(`(?i)(^|_)(password|passwd|secret|token|api_?key|private_?key|access_?key|client_?secret|authorization|cookie|user_?data|connection_?string|certificate_?body|secret_?string)($|_)`)

type bundle struct {
	SchemaVersion    int        `json:"schema_version"`
	TerraformVersion string     `json:"terraform_version,omitempty"`
	FormatVersion    string     `json:"terraform_format_version,omitempty"`
	Resources        []resource `json:"resources"`
	Relationships    []relation `json:"relationships,omitempty"`
	Stats            stats      `json:"sanitization"`
}

type resource struct {
	Address      string         `json:"address"`
	Module       string         `json:"module_address,omitempty"`
	Mode         string         `json:"mode,omitempty"`
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	ProviderName string         `json:"provider_name,omitempty"`
	Actions      []string       `json:"actions,omitempty"`
	Values       map[string]any `json:"values,omitempty"`
}

type relation struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Via    string `json:"via,omitempty"`
}

type stats struct {
	Profile               string `json:"profile"`
	SensitivePathsRemoved int    `json:"sensitive_paths_removed"`
	DeniedKeysRemoved     int    `json:"denied_keys_removed"`
}

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

func main() {
	input := flag.String("input", "-", "Terraform plan JSON file, or - for stdin")
	output := flag.String("output", "-", "sanitized bundle file, or - for stdout")
	flag.Parse()

	if err := run(*input, *output); err != nil {
		fmt.Fprintf(os.Stderr, "infragram-collect: %v\n", err)
		os.Exit(1)
	}
}

func run(inputPath, outputPath string) error {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeInput()

	decoder := json.NewDecoder(io.LimitReader(input, 256<<20))
	decoder.UseNumber()
	var plan rawPlan
	if err := decoder.Decode(&plan); err != nil {
		return fmt.Errorf("decode Terraform plan JSON: %w", err)
	}
	if plan.FormatVersion == "" {
		return errors.New("input is not Terraform plan JSON: format_version missing")
	}

	result := collect(plan)
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode sanitized bundle: %w", err)
	}
	encoded = append(encoded, '\n')

	if outputPath == "-" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	return os.WriteFile(outputPath, encoded, 0o600)
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}

func collect(plan rawPlan) bundle {
	result := bundle{
		SchemaVersion:    schemaVersion,
		TerraformVersion: plan.TerraformVersion,
		FormatVersion:    plan.FormatVersion,
		Resources:        make([]resource, 0, len(plan.ResourceChanges)),
		Stats:            stats{Profile: "standard"},
	}

	knownResources := make(map[string]bool, len(plan.ResourceChanges))
	for _, change := range plan.ResourceChanges {
		knownResources[change.Address] = true
		values, keep := sanitize(change.Change.After, change.Change.AfterSensitive, &result.Stats)
		valueMap, _ := values.(map[string]any)
		if !keep {
			valueMap = nil
		}
		result.Resources = append(result.Resources, resource{
			Address: change.Address, Module: change.Module, Mode: change.Mode,
			Type: change.Type, Name: change.Name, ProviderName: change.ProviderName,
			Actions: change.Change.Actions, Values: valueMap,
		})
	}
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].Address < result.Resources[j].Address })
	result.Relationships = collectRelationships(plan.Configuration, knownResources)
	return result
}

func sanitize(value, sensitive any, report *stats) (any, bool) {
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
			if keep {
				clean = append(clean, cleaned)
			} else {
				clean = append(clean, nil)
			}
		}
		return clean, true
	default:
		return value, true
	}
}

func markedSensitive(value any) bool {
	marked, ok := value.(bool)
	return ok && marked
}

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

func collectRelationships(configuration *config, knownResources map[string]bool) []relation {
	if configuration == nil || configuration.RootModule == nil {
		return nil
	}
	relations := make(map[string]relation)
	collectModuleRelationships(configuration.RootModule, knownResources, relations)
	result := make([]relation, 0, len(relations))
	for _, item := range relations {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		if result[i].Target != result[j].Target {
			return result[i].Target < result[j].Target
		}
		return result[i].Via < result[j].Via
	})
	return result
}

func collectModuleRelationships(module *configModule, knownResources map[string]bool, relations map[string]relation) {
	for _, current := range module.Resources {
		for attribute, expression := range current.Expressions {
			for _, reference := range expressionReferences(expression) {
				target := resourceAddress(reference)
				if target == "" || target == current.Address || !knownResources[target] {
					continue
				}
				item := relation{Source: current.Address, Target: target, Via: attribute}
				hash := sha256.Sum256([]byte(item.Source + "\x00" + item.Target + "\x00" + item.Via))
				relations[hex.EncodeToString(hash[:])] = item
			}
		}
	}
	for _, call := range module.ModuleCalls {
		if call.Module != nil {
			collectModuleRelationships(call.Module, knownResources, relations)
		}
	}
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

func resourceAddress(reference string) string {
	parts := strings.Split(reference, ".")
	if len(parts) < 2 {
		return ""
	}
	end := 2
	for end+1 < len(parts) && parts[end-2] == "module" {
		end += 2
	}
	if end > len(parts) {
		return ""
	}
	return strings.Join(parts[:end], ".")
}
