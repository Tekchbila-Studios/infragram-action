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
//
// Version 3 stops interpreting. Earlier versions resolved each reference here —
// matching it to a plan resource, pairing it to the right instance of a counted
// resource, and discarding whatever was left over. Two things were wrong with
// that. Terraform's plan JSON contains no locals, so a reference written
// `vpc_id = local.vpc_id` — which is how the registry's modules are built —
// named something the plan never defined and was silently dropped, costing
// those modules every link between their resources. And resolution is a product
// decision, so keeping it here meant every change to it needed a new release of
// this action in every customer's workflow.
//
// A version 3 bundle carries what the configuration says and nothing more:
// References is every reference as written, and Symbols is what the locals name.
// Whoever renders it decides what that means.
const SchemaVersion = 3

// Bundle is the sanitized payload uploaded to Infragr.am.
type Bundle struct {
	SchemaVersion    int        `json:"schema_version"`
	TerraformVersion string     `json:"terraform_version,omitempty"`
	FormatVersion    string     `json:"terraform_format_version,omitempty"`
	Resources        []Resource `json:"resources"`
	// References is every reference each configured resource makes, unresolved.
	References []Reference `json:"references,omitempty"`
	// Symbols maps a module-qualified local to what it references. Values never
	// appear: a local holding a literal has no references and is omitted.
	Symbols map[string][]string `json:"symbols,omitempty"`
	Stats   Stats               `json:"sanitization"`
}

// Reference is one reference from a configured resource, exactly as written.
//
// Source and RawRef are addresses as the configuration spells them, qualified by
// their module and without count subscripts — the configuration declares
// `aws_subnet.public` once however many instances the plan produces. Expanding
// them against the resources in the bundle, and deciding which instance pairs
// with which, is the renderer's job.
type Reference struct {
	Source string `json:"source"`
	// Via is the attribute carrying the reference. When it sits inside a nested
	// block, Via is the attribute *within* that block and BlockType names the
	// block, so `route { gateway_id = ... }` yields Via "gateway_id" and
	// BlockType "route" rather than collapsing to Via "route".
	Via string `json:"via,omitempty"`
	// BlockType is the enclosing nested block, empty for a top-level attribute.
	BlockType string `json:"block_type,omitempty"`
	// BlockIndex is the ordinal of the enclosing block instance, and -1 for a
	// top-level attribute. It is always encoded: 0 is a meaningful value, so it
	// must not be elided as an empty one.
	BlockIndex int `json:"block_index"`
	// Ref is what the reference names, normalized to an address: a resource, or
	// a local that leads to one through Symbols. It is deliberately not the
	// traversal as written — `aws_vpc.main.id` is reported as `aws_vpc.main` —
	// because the attribute selected off a resource says nothing about the edge,
	// and because Symbols is keyed by this same normalized form.
	Ref string `json:"ref"`
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

// Stats reports what redaction removed, so the receiver can tell an empty
// attribute set apart from a heavily redacted one.
type Stats struct {
	Profile               string `json:"profile"`
	SensitivePathsRemoved int    `json:"sensitive_paths_removed"`
	DeniedKeysRemoved     int    `json:"denied_keys_removed"`
}
