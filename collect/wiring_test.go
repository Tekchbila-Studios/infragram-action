package collect

import (
	"reflect"
	"testing"
)

// modulePlan is the shape that costs a module-wired resource its links: the
// VPC lives in one module, the endpoint in another, and the only thing joining
// them is `vpc_id = var.vpc_id` on one side and `vpc_id = module.vpc.vpc_id` on
// the other. Neither half names a resource by itself.
const modulePlan = `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"module.vpc.aws_vpc.this[0]","module_address":"module.vpc","type":"aws_vpc","name":"this","change":{"actions":["create"],"after":{}}},
    {"address":"module.endpoints.aws_vpc_endpoint.this[\"s3\"]","module_address":"module.endpoints","type":"aws_vpc_endpoint","name":"this","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{
    "resources":[],
    "module_calls":{
      "vpc":{"module":{
        "resources":[{"address":"aws_vpc.this","expressions":{"cidr_block":{"constant_value":"10.0.0.0/16"}}}],
        "outputs":{"vpc_id":{"expression":{"references":["aws_vpc.this[0].id","aws_vpc.this"]}}}
      }},
      "endpoints":{
        "expressions":{"vpc_id":{"references":["module.vpc.vpc_id","module.vpc"]}},
        "module":{
          "resources":[{"address":"aws_vpc_endpoint.this","expressions":{"vpc_id":{"references":["var.vpc_id"]}}}]
        }
      }
    }
  }}
}`

// TestVariableReferenceSurvives: the reference a module-wired resource makes is
// to a variable, and dropping it at collection left the resource with no link
// to anything at all.
func TestVariableReferenceSurvives(t *testing.T) {
	bundle := bundleFrom(t, modulePlan)
	findReference(t, bundle, "module.endpoints.aws_vpc_endpoint.this", "module.endpoints.var.vpc_id", "vpc_id")
}

// TestModuleWiringSymbolsJoinBothHalves: the two hops that carry a reference
// across a module boundary, in the spellings qualifyRef produces.
func TestModuleWiringSymbolsJoinBothHalves(t *testing.T) {
	bundle := bundleFrom(t, modulePlan)
	for name, want := range map[string][]string{
		"module.vpc.vpc_id":           {"module.vpc.aws_vpc.this"},
		"module.endpoints.var.vpc_id": {"module.vpc.vpc_id"},
	} {
		if got := bundle.Symbols[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("symbols[%q] = %v, want %v", name, got, want)
		}
	}
}

// TestModuleWiringNeedsNoSourceDirectory: module wiring is in the plan, unlike
// locals, so it survives a bundle collected without the .tf files.
func TestModuleWiringNeedsNoSourceDirectory(t *testing.T) {
	bundle := bundleFrom(t, modulePlan)
	if len(bundle.Symbols) == 0 {
		t.Fatal("no symbols collected without a source directory")
	}
}

// TestWiringNeverEmitsValues: an argument or output holding a literal has no
// references, so nothing about it reaches the bundle — the rule the locals
// scanner follows, applied to the other two places a value can sit.
func TestWiringNeverEmitsValues(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[],
  "configuration":{"root_module":{"resources":[],"module_calls":{
    "db":{
      "expressions":{"password":{"constant_value":"hunter2"}},
      "module":{"resources":[],"outputs":{"endpoint":{"expression":{"constant_value":"db.example.com"}}}}
    }
  }}}
}`)
	for name, refs := range bundle.Symbols {
		t.Errorf("literal produced a symbol: %q -> %v", name, refs)
	}
}

// TestWiringIsDeterministic: symbol targets are sorted and deduplicated, since
// the bundle must be byte-identical for identical input and the walk iterates
// maps.
func TestWiringIsDeterministic(t *testing.T) {
	first := bundleFrom(t, modulePlan)
	for i := 0; i < 20; i++ {
		next := bundleFrom(t, modulePlan)
		if !reflect.DeepEqual(first.Symbols, next.Symbols) {
			t.Fatalf("symbols differ between runs:\n%v\n%v", first.Symbols, next.Symbols)
		}
	}
}

// TestPruneKeepsUninstantiatedResourceReferences is the guard on how far the
// prune may go. A registry module declares a resource for every optional
// feature and instantiates a few; the rest have no entry in the plan. Whether
// one of those may still appear in a diagram is the renderer's call, so the
// reference stays — dropping it here is the version 2 mistake.
func TestPruneKeepsUninstantiatedResourceReferences(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"module.vpc.aws_network_acl_rule.public","module_address":"module.vpc","type":"aws_network_acl_rule","name":"public","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[],"module_calls":{"vpc":{"module":{"resources":[
    {"address":"aws_network_acl_rule.public","expressions":{"network_acl_id":{"references":["aws_network_acl.public"]}}}
  ]}}}}}
}`)
	findReference(t, bundle, "module.vpc.aws_network_acl_rule.public", "module.vpc.aws_network_acl.public", "network_acl_id")
}

// TestPruneDropsDanglingSymbols: a variable handed a literal, and a local
// holding a constant, name nothing the symbol table can reach. They cannot
// become an edge under any interpretation, so they do not travel.
func TestPruneDropsDanglingSymbols(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"module.net.aws_subnet.this","module_address":"module.net","type":"aws_subnet","name":"this","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[],"module_calls":{"net":{
    "expressions":{"cidr":{"constant_value":"10.0.0.0/16"}},
    "module":{"resources":[{"address":"aws_subnet.this","expressions":{"cidr_block":{"references":["var.cidr"]}}}]}
  }}}}}
}`)
	for _, reference := range bundle.References {
		if reference.Ref == "module.net.var.cidr" {
			t.Errorf("dangling variable reference survived: %+v", reference)
		}
	}
	if _, ok := bundle.Symbols["module.net.var.cidr"]; ok {
		t.Errorf("dangling variable symbol survived: %v", bundle.Symbols)
	}
}

// TestPruneKeepsTheChainItNeeds: every hop of a surviving reference stays, or
// the renderer walks into a hole halfway across a module boundary.
func TestPruneKeepsTheChainItNeeds(t *testing.T) {
	bundle := bundleFrom(t, modulePlan)
	for _, name := range []string{"module.endpoints.var.vpc_id", "module.vpc.vpc_id"} {
		if len(bundle.Symbols[name]) == 0 {
			t.Errorf("symbol %q was pruned out of a live chain: %v", name, bundle.Symbols)
		}
	}
}
