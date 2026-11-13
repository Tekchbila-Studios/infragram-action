// Command infragram-collect reads Terraform plan JSON and writes the sanitized
// bundle that is the only artifact leaving the runner.
//
// All of the redaction lives in the collect package so that the renderer can
// import it and exercise the same code, rather than reimplementing it.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Tekchbila-Studios/infragram-action/collect"

	"encoding/json"
)

func main() {
	input := flag.String("input", "-", "Terraform plan JSON file, or - for stdin")
	output := flag.String("output", "-", "sanitized bundle file, or - for stdout")
	// The plan JSON carries no locals, so a reference through one names
	// something the plan never defines. Pointing at the configuration lets the
	// bundle carry what those names refer to; without it they are simply lost.
	source := flag.String("source", "", "Terraform configuration directory, for reading locals")
	flag.Parse()

	if err := run(*input, *output, *source); err != nil {
		fmt.Fprintf(os.Stderr, "infragram-collect: %v\n", err)
		os.Exit(1)
	}
}

func run(inputPath, outputPath, sourceDir string) error {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeInput()

	bundle, err := collect.FromPlanJSONWithSource(input, sourceDir)
	if err != nil {
		return err
	}

	warn(os.Stderr, bundle.Source, os.Getenv("GITHUB_ACTIONS") == "true")

	encoded, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("encode sanitized bundle: %w", err)
	}
	encoded = append(encoded, '\n')

	if outputPath == "-" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	// The bundle is scanned before upload and deleted afterwards, but it exists on
	// the runner's disk in between, so keep it readable only by its owner.
	return os.WriteFile(outputPath, encoded, 0o600)
}

// maxListed bounds how many names one warning spells out. A root that was never
// initialised can miss every module it calls.
const maxListed = 10

// warn tells whoever ran the collector what source it could not read. The
// bundle is still written: the diagram is drawn from the plan, and is only
// missing the links that pass through the unread locals and dynamic blocks.
//
// This goes to the run's own log and nowhere else. Nothing here is uploaded.
func warn(out io.Writer, report collect.SourceReport, annotate bool) {
	prefix, names := "infragram-collect: warning: ", listed
	if annotate {
		prefix, names = "::warning::", func(list []string) string { return escapeCommand(listed(list)) }
	}
	if len(report.ModulesUnread) > 0 {
		fmt.Fprintf(out, "%sNo Terraform source could be read for: %s. Links that pass through locals and dynamic blocks there will be missing from the diagram. Check that this step points at the configuration directory and that terraform init has run in it, so module source is present.\n",
			prefix, names(report.ModulesUnread))
	}
	if len(report.FilesUnparsed) > 0 {
		fmt.Fprintf(out, "%sCould not parse: %s. Links that pass through locals and dynamic blocks in those files will be missing from the diagram.\n",
			prefix, names(report.FilesUnparsed))
	}
}

// listed joins names for a sentence, cutting a long list short.
func listed(names []string) string {
	if len(names) <= maxListed {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:maxListed], ", "), len(names)-maxListed)
}

// escapeCommand makes text safe as the message of a GitHub workflow command. A
// file name is whatever a pull request's author chose, and a line break in one
// would otherwise start a command of their own in this step's log.
func escapeCommand(text string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(text)
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
