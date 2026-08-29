package collect

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeModule(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "main.tf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A local holding a literal must contribute nothing at all.
//
// This is the property that makes reading the customer's configuration
// acceptable: the scanner reads only traversals, so a value has no path into the
// bundle even when it sits in the same expression as a reference. `mixed` below
// wraps a secret around a real resource reference, and only the reference
// survives.
func TestScanLocalsNeverEmitsValues(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, ".", `
locals {
  db_password = "hunter2-SUPERSECRET"
  api_key     = "sk-live-DEADBEEF"
  vpc_id      = aws_vpc.main.id
  mixed       = "prefix-${aws_vpc.main.cidr_block}-SECRETSUFFIX"
}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
`)

	scanner := newSymbolScanner(dir)
	scanner.scanLocals(dir, "")

	if _, present := scanner.symbols["local.db_password"]; present {
		t.Error("a literal-only local was published")
	}
	if _, present := scanner.symbols["local.api_key"]; present {
		t.Error("a literal-only local was published")
	}
	if got := scanner.symbols["local.vpc_id"]; !reflect.DeepEqual(got, []string{"aws_vpc.main"}) {
		t.Errorf("local.vpc_id = %v, want [aws_vpc.main]", got)
	}
	if got := scanner.symbols["local.mixed"]; !reflect.DeepEqual(got, []string{"aws_vpc.main"}) {
		t.Errorf("local.mixed = %v, want only the reference", got)
	}

	for symbol, refs := range scanner.symbols {
		for _, ref := range refs {
			for _, secret := range []string{"hunter2", "DEADBEEF", "SECRETSUFFIX", "10.0.0.0"} {
				if contains(ref, secret) {
					t.Errorf("%s carried a literal: %q", symbol, ref)
				}
			}
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// A local declared inside a module is published under that module's prefix, so
// two modules declaring the same local name stay distinct.
func TestScanQualifiesLocalsByModule(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, ".", `locals { vpc_id = aws_vpc.root.id }`)
	writeModule(t, root, "child", `locals { vpc_id = aws_vpc.child.id }`)

	scanner := newSymbolScanner(root)
	scanner.scan(&configModule{
		ModuleCalls: map[string]configModuleCall{
			"network": {Module: &configModule{}, Source: "./child"},
		},
	}, root, "")

	if got := scanner.symbols["local.vpc_id"]; !reflect.DeepEqual(got, []string{"aws_vpc.root"}) {
		t.Errorf("root local.vpc_id = %v, want [aws_vpc.root]", got)
	}
	want := []string{"module.network.aws_vpc.child"}
	if got := scanner.symbols["module.network.local.vpc_id"]; !reflect.DeepEqual(got, want) {
		t.Errorf("module local.vpc_id = %v, want %v", got, want)
	}
}

// The two walks spell the module prefix differently — the scanner with a
// trailing dot, the relationship walk without — and a symbol emitted by one has
// to be findable by the other. They disagreed once, producing a table keyed
// "module.vpc.local.vpc_id" against references reading "module.vpclocal.vpc_id",
// and every edge silently failed to resolve.
func TestQualifyRefNormalisesModulePrefix(t *testing.T) {
	withDot := qualifyRef("module.vpc.", []string{"local", "vpc_id"})
	withoutDot := qualifyRef("module.vpc", []string{"local", "vpc_id"})
	if withDot != withoutDot {
		t.Errorf("prefix spelling changed the symbol: %q vs %q", withDot, withoutDot)
	}
	if withDot != "module.vpc.local.vpc_id" {
		t.Errorf("qualifyRef = %q, want module.vpc.local.vpc_id", withDot)
	}
}

// Names that can never become an edge are dropped at the source rather than
// travelling to be dropped at the far end.
func TestQualifyRefDropsNonResourceScopes(t *testing.T) {
	for _, segments := range [][]string{
		{"var", "cidr"},
		{"count", "index"},
		{"each", "value"},
		{"path", "module"},
		{"terraform", "workspace"},
		{"self", "id"},
		{"local"},
	} {
		if got := qualifyRef("module.vpc.", segments); got != "" {
			t.Errorf("qualifyRef(%v) = %q, want empty", segments, got)
		}
	}
}

// An absent or unreadable configuration directory is not an error: it yields a
// bundle with no symbols, which is what version 2 always produced.
func TestScanToleratesMissingSource(t *testing.T) {
	scanner := newSymbolScanner(filepath.Join(t.TempDir(), "does-not-exist"))
	scanner.scan(&configModule{}, scanner.rootPath, "")
	if len(scanner.symbols) != 0 {
		t.Errorf("symbols = %v, want none", scanner.symbols)
	}
}
