package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Tekchbila-Studios/infragram-action/collect"
)

// TestWarnSaysNothingWhenEverythingWasRead: a clean scan prints nothing.
func TestWarnSaysNothingWhenEverythingWasRead(t *testing.T) {
	var out bytes.Buffer
	warn(&out, collect.SourceReport{}, true)
	if out.Len() != 0 {
		t.Errorf("printed %q for an empty report", out.String())
	}
}

// TestWarnNamesWhatWasNotRead: each kind of gap gets one line, as a workflow
// annotation inside GitHub Actions and as plain text elsewhere.
func TestWarnNamesWhatWasNotRead(t *testing.T) {
	report := collect.SourceReport{
		ModulesUnread: []string{"module.vpc"},
		FilesUnparsed: []string{"root module: broken.tf"},
	}
	var annotated, plain bytes.Buffer
	warn(&annotated, report, true)
	warn(&plain, report, false)

	lines := strings.Split(strings.TrimSpace(annotated.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "::warning::") || !strings.HasPrefix(lines[1], "::warning::") {
		t.Fatalf("want two annotations, got %q", annotated.String())
	}
	if !strings.Contains(lines[0], "module.vpc") || !strings.Contains(lines[1], "broken.tf") {
		t.Errorf("names missing from %q", annotated.String())
	}
	if strings.Contains(plain.String(), "::warning::") || !strings.Contains(plain.String(), "infragram-collect: warning: ") {
		t.Errorf("plain output = %q", plain.String())
	}
}

// TestWarnCutsALongListShort: an uninitialised root can miss every module.
func TestWarnCutsALongListShort(t *testing.T) {
	var report collect.SourceReport
	for i := 0; i < maxListed+5; i++ {
		report.ModulesUnread = append(report.ModulesUnread, "module.m")
	}
	var out bytes.Buffer
	warn(&out, report, false)
	if !strings.Contains(out.String(), "and 5 more") {
		t.Errorf("list not cut short: %q", out.String())
	}
}

// TestWarnCannotStartAWorkflowCommand: a file name carrying a line break must
// not put a second command on its own line in the step's log.
func TestWarnCannotStartAWorkflowCommand(t *testing.T) {
	var out bytes.Buffer
	warn(&out, collect.SourceReport{FilesUnparsed: []string{"root module: a\n::add-mask::x.tf"}}, true)
	if strings.Count(out.String(), "\n") != 1 {
		t.Errorf("a line break survived: %q", out.String())
	}
}
