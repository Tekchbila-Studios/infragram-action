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

	"github.com/Tekchbila-Studios/infragram-action/collect"

	"encoding/json"
)

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

	bundle, err := collect.FromPlanJSON(input)
	if err != nil {
		return err
	}

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
