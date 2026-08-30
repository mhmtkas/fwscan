// Package cli wires the cobra command tree and owns the process exit code.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes, per docs/output-spec.md section 5.
const (
	ExitOK    = 0 // scan completed, nothing at or above --fail-on
	ExitFound = 1 // scan completed, findings at or above --fail-on
	ExitError = 2 // scan could not complete
)

// ThresholdError reports that the scan itself succeeded but findings met the
// --fail-on threshold. It is distinguished from a real failure so that the
// caller can map it to exit 1 rather than exit 2, and so that nothing is
// printed for it — the report has already said everything the user needs.
type ThresholdError struct{ Count int }

func (e *ThresholdError) Error() string {
	return fmt.Sprintf("%d findings at or above the --fail-on threshold", e.Count)
}

// NewRootCmd builds the command tree. Version is injected rather than read from
// a package variable so tests can construct a tree without touching globals.
func NewRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "fwscan",
		Short: "Firmware SBOM & CVE scanner",
		Long: "fwscan scans a Linux-based firmware rootfs, emits a CycloneDX SBOM,\n" +
			"and reports known vulnerabilities via OSV.dev.",
		Version:       version,
		SilenceUsage:  true, // usage on a runtime failure is noise, not help
		SilenceErrors: true, // main prints errors itself, in the agreed format
	}
	root.AddCommand(newVersionCmd(version))
	return root
}

// Execute runs the command tree and returns the process exit code. User-facing
// errors are lowercase one-liners on stderr; a Go stack trace never reaches the
// user (CLAUDE.md conventions).
func Execute(version string) int {
	err := NewRootCmd(version).Execute()
	if err == nil {
		return ExitOK
	}
	var threshold *ThresholdError
	if errors.As(err, &threshold) {
		return ExitFound
	}
	fmt.Fprintf(os.Stderr, "fwscan: %v\n", err)
	return ExitError
}
