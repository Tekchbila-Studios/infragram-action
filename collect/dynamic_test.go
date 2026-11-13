package collect

import (
	"strings"
	"testing"
)

const dynamicSource = `
variable "ingress_rules" {}
variable "routes" {}

resource "aws_security_group" "this" {
  name = "db-password-is-hunter2"

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port       = ingress.value.port
      security_groups = [aws_security_group.bastion.id]
      description     = "a literal"
    }
  }
}

resource "aws_route_table" "this" {
  for_each = aws_subnet.private

  dynamic "route" {
    for_each = var.routes
    iterator = entry
    content {
      nat_gateway_id = entry.value.nat_gateway_id
      cidr_block     = each.value.cidr_block
    }
  }
}

resource "aws_launch_template" "this" {
  dynamic "block_device_mappings" {
    for_each = local.volumes
    content {
      dynamic "ebs" {
        for_each = [block_device_mappings.value.ebs]
        content {
          kms_key_id = ebs.value.kms_key_id
        }
      }
    }
  }

  network_interfaces {
    dynamic "ipv6_addresses" {
      for_each = aws_subnet.private
      content {
        ipv6_address = ipv6_addresses.value.ipv6_cidr_block
      }
    }
  }
}

locals {
  volumes = [aws_kms_key.disk.arn]
}
`

func scanDynamic(t *testing.T, prefix string) map[Reference]bool {
	t.Helper()
	dir := writeModule(t, t.TempDir(), "root", dynamicSource)
	scanner := newSymbolScanner(dir)
	scanner.scanDynamicBlocks(dir, prefix)
	return scanner.references
}

func wantReference(t *testing.T, got map[Reference]bool, want Reference) {
	t.Helper()
	if !got[want] {
		t.Errorf("missing %+v\n  have %v", want, got)
	}
}

// TestDynamicBlockReportsWhatItsContentReads: an attribute that reads the
// iterator links to what the for_each references, and one that names a resource
// links to it directly, both in the shape the plan uses for a written block.
func TestDynamicBlockReportsWhatItsContentReads(t *testing.T) {
	got := scanDynamic(t, "")
	wantReference(t, got, Reference{Source: "aws_security_group.this", Via: "from_port", BlockType: "ingress", Ref: "var.ingress_rules"})
	wantReference(t, got, Reference{Source: "aws_security_group.this", Via: "security_groups", BlockType: "ingress", Ref: "aws_security_group.bastion"})
}

// TestDynamicBlockHonoursIteratorAndEach: a renamed iterator resolves to its
// own collection, and `each` to the resource's.
func TestDynamicBlockHonoursIteratorAndEach(t *testing.T) {
	got := scanDynamic(t, "")
	wantReference(t, got, Reference{Source: "aws_route_table.this", Via: "nat_gateway_id", BlockType: "route", Ref: "var.routes"})
	wantReference(t, got, Reference{Source: "aws_route_table.this", Via: "cidr_block", BlockType: "route", Ref: "aws_subnet.private"})
}

// TestNestedDynamicBlocksKeepTheOutermostBlock: an inner iterator resolves
// through the outer one, and the reference is filed under the outermost block
// with the nested block as its via, as the plan does for written blocks.
func TestNestedDynamicBlocksKeepTheOutermostBlock(t *testing.T) {
	got := scanDynamic(t, "module.eks.")
	wantReference(t, got, Reference{Source: "module.eks.aws_launch_template.this", Via: "ebs", BlockType: "block_device_mappings", Ref: "module.eks.local.volumes"})
	wantReference(t, got, Reference{Source: "module.eks.aws_launch_template.this", Via: "ipv6_addresses", BlockType: "network_interfaces", Ref: "module.eks.aws_subnet.private"})
}

// TestDynamicBlocksNeverEmitValues: only names leave the source. A literal in
// a dynamic block's content, or anywhere else in the resource, has no path
// into a reference.
func TestDynamicBlocksNeverEmitValues(t *testing.T) {
	for reference := range scanDynamic(t, "") {
		for _, field := range []string{reference.Source, reference.Via, reference.BlockType, reference.Ref} {
			if strings.Contains(field, "hunter2") || strings.Contains(field, "literal") {
				t.Errorf("a value reached the bundle: %+v", reference)
			}
		}
	}
}

// TestDynamicReferencesReachTheBundle: the scan's references are merged with
// the plan's, and one that names a resource the plan carries survives pruning.
func TestDynamicReferencesReachTheBundle(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "root", dynamicSource)
	bundle, err := FromPlanJSONWithSource(strings.NewReader(`{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"aws_security_group.this","type":"aws_security_group","name":"this","change":{"actions":["create"],"after":{}}},
    {"address":"aws_security_group.bastion","type":"aws_security_group","name":"bastion","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[
    {"address":"aws_security_group.this","expressions":{"name":{"constant_value":"x"}}}
  ]}}
}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	reference := findReference(t, bundle, "aws_security_group.this", "aws_security_group.bastion", "security_groups")
	if reference.BlockType != "ingress" || reference.BlockIndex != 0 {
		t.Errorf("block = %q[%d], want ingress[0]", reference.BlockType, reference.BlockIndex)
	}
	for _, kept := range bundle.References {
		if kept.Ref == "var.ingress_rules" {
			t.Errorf("a root variable names nothing and should be pruned: %+v", kept)
		}
	}
}
