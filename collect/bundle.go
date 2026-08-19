// Package collect turns Terraform plan JSON into the sanitized bundle that is the
// only artifact Infragr.am ever receives.
//
// It lives in this repository, and not in the renderer, because the redaction it
// performs is the product's security boundary: it runs inside the customer's own
// runner, and this repository is the auditable record of what leaves it. The
// renderer imports this package so that it renders from genuinely sanitized input
// rather than from a copy of the sanitizer that can drift.
package collect

// SchemaVersion is the bundle schema this package emits.
//
// Version 2 exists because a flat {source, target, via} relationship is not enough
// to reconstruct a diagram. Terraform expresses a route table's routes as repeated
// nested blocks, and the destination CIDR of a route lives in one block while the
// gateway it points at lives in the same block's sibling attribute. Without the
// enclosing block name and its ordinal, the two cannot be paired again downstream,
// and a public subnet becomes indistinguishable from a private one.
const SchemaVersion = 2

// Bundle is the sanitized payload uploaded to Infragr.am.
type Bundle struct {
	SchemaVersion    int        `json:"schema_version"`
	TerraformVersion string     `json:"terraform_version,omitempty"`
	FormatVersion    string     `json:"terraform_format_version,omitempty"`
	Resources        []Resource `json:"resources"`
	Relationships    []Relation `json:"relationships,omitempty"`
	Stats            Stats      `json:"sanitization"`
}

// Resource is one planned Terraform resource, with its attributes sanitized.
type Resource struct {
	Address      string         `json:"address"`
	Module       string         `json:"module_address,omitempty"`
	Mode         string         `json:"mode,omitempty"`
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	ProviderName string         `json:"provider_name,omitempty"`
	Actions      []string       `json:"actions,omitempty"`
	Values       map[string]any `json:"values,omitempty"`
}

// Relation is one reference from one resource to another.
//
// Via is the attribute that carries the reference. When the reference sits inside a
// nested block, Via is the attribute *within* that block and BlockType names the
// block, so `route { gateway_id = ... }` yields Via "gateway_id" and BlockType
// "route" rather than collapsing to Via "route".
type Relation struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Via    string `json:"via,omitempty"`
	// BlockType is the enclosing nested block, empty for a top-level attribute.
	BlockType string `json:"block_type,omitempty"`
	// BlockIndex is the ordinal of the enclosing block instance, and -1 for a
	// top-level attribute. It is always encoded: 0 is a meaningful value, so it
	// must not be elided as an empty one.
	BlockIndex int `json:"block_index"`
	// RawRef is the reference exactly as Terraform wrote it, before it was
	// truncated to a resource address.
	RawRef string `json:"raw_ref,omitempty"`
}

// Stats reports what redaction removed, so the receiver can tell an empty
// attribute set apart from a heavily redacted one.
type Stats struct {
	Profile               string `json:"profile"`
	SensitivePathsRemoved int    `json:"sensitive_paths_removed"`
	DeniedKeysRemoved     int    `json:"denied_keys_removed"`
}
