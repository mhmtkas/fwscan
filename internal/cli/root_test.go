package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/match"
	"github.com/mhmtkas/fwscan/internal/model"
)

func TestVersionCmd(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCmd("1.2.3")
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	// Rendered the same way as the report header: a version number gets its
	// "v", and a source-build stamp such as "dev" is left alone.
	if got := out.String(); !strings.HasPrefix(got, "fwscan v1.2.3 (") {
		t.Errorf("version output = %q, want it to start with the injected version", got)
	}
	out.Reset()
	root = NewRootCmd("dev")
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := out.String(); !strings.HasPrefix(got, "fwscan dev (") {
		t.Errorf("version output = %q, want a source build to stay undressed", got)
	}
}

func TestThresholdErrorMessage(t *testing.T) {
	var threshold error = &ThresholdError{Count: 3}
	if !errors.As(threshold, new(*ThresholdError)) {
		t.Fatal("ThresholdError does not match itself via errors.As")
	}
	if got, want := threshold.Error(), "3 findings at or above the --fail-on threshold"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// Exit 1 is the contract every CI pipeline using this tool depends on: a scan
// that completed and found something is not a scan that failed. It was checked
// only by an integration test behind a build tag, so the default test run never
// exercised it -- and the test named for it built a ThresholdError by hand and
// asserted errors.As matched, which passes with the branch in Execute deleted.
//
// This runs Execute itself, with the matcher replaced rather than the network
// reached, so all three codes are covered where they are actually decided.
func TestExecuteReturnsTheDocumentedExitCodes(t *testing.T) {
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")

	previous := newMatcher
	t.Cleanup(func() { newMatcher = previous })

	tests := []struct {
		name     string
		findings []model.Finding
		args     []string
		want     int
	}{
		{
			name: "a clean scan",
			args: []string{"scan", "--fail-on", "critical", image},
			want: ExitOK,
		},
		{
			name:     "findings below the threshold",
			findings: []model.Finding{{Severity: model.SeverityLow, ID: "CVE-2020-0001"}},
			args:     []string{"scan", "--fail-on", "critical", image},
			want:     ExitOK,
		},
		{
			name:     "findings at the threshold",
			findings: []model.Finding{{Severity: model.SeverityCritical, ID: "CVE-2020-0002"}},
			args:     []string{"scan", "--fail-on", "critical", image},
			want:     ExitFound,
		},
		{
			name: "a scan that could not run",
			args: []string{"scan", filepath.Join(t.TempDir(), "not-here")},
			want: ExitError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := tt.findings
			newMatcher = func() match.Matcher {
				return matcherFunc(func(context.Context, []model.Component) ([]model.Finding, error) {
					return findings, nil
				})
			}

			// Execute reads os.Args, and writes the failure line to os.Stderr.
			args, stderr := os.Args, os.Stderr
			devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("open %s: %v", os.DevNull, err)
			}
			os.Args = append([]string{"fwscan"}, tt.args...)
			os.Stderr = devNull
			t.Cleanup(func() {
				os.Args, os.Stderr = args, stderr
				_ = devNull.Close()
			})

			if got := Execute("v0.1.0"); got != tt.want {
				t.Errorf("Execute() = %d, want %d", got, tt.want)
			}
		})
	}
}
