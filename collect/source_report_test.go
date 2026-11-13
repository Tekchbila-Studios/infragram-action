package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const reportPlan = `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"aws_vpc.main","type":"aws_vpc","name":"main","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{
    "resources":[{"address":"aws_vpc.main","expressions":{}}],
    "module_calls":{"remote":{"source":"terraform-aws-modules/vpc/aws","module":{}}}
  }}
}`

// TestSourceReportNamesWhatCouldNotBeRead: a module with no source directory
// and a file that will not parse are both reported, and a file that parses is
// not.
func TestSourceReportNamesWhatCouldNotBeRead(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "root", `locals { vpc = aws_vpc.main.id }`)
	if err := os.WriteFile(filepath.Join(dir, "broken.tf"), []byte(`resource "x" {`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, err := FromPlanJSONWithSource(strings.NewReader(reportPlan), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := SourceReport{
		ModulesUnread: []string{"module.remote"},
		FilesUnparsed: []string{"root module: broken.tf"},
	}
	if !reflect.DeepEqual(bundle.Source, want) {
		t.Errorf("report = %+v, want %+v", bundle.Source, want)
	}
}

// TestSourceReportIsEmptyWithoutASourceDirectory: nobody asked for the source
// to be read, so there is nothing to warn about.
func TestSourceReportIsEmptyWithoutASourceDirectory(t *testing.T) {
	bundle, err := FromPlanJSON(strings.NewReader(reportPlan))
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Source.Empty() {
		t.Errorf("report = %+v, want empty", bundle.Source)
	}
}

// TestSourceReportNeverReachesTheBundle: the report is for the run's own log.
// Module and file names in it must not be uploaded.
func TestSourceReportNeverReachesTheBundle(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "root", `locals { vpc = aws_vpc.main.id }`)
	if err := os.WriteFile(filepath.Join(dir, "broken.tf"), []byte(`resource "x" {`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, err := FromPlanJSONWithSource(strings.NewReader(reportPlan), dir)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Source.Empty() {
		t.Fatal("test needs a non-empty report")
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"broken.tf", "module.remote", "ModulesUnread", "FilesUnparsed", "Source"} {
		if strings.Contains(string(encoded), leaked) {
			t.Errorf("%q reached the encoded bundle: %s", leaked, encoded)
		}
	}
}
