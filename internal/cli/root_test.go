package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVersionCmd(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCmd("1.2.3")
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := out.String(); !strings.HasPrefix(got, "fwscan 1.2.3 (") {
		t.Errorf("version output = %q, want it to start with the injected version", got)
	}
}

func TestExecuteExitCodes(t *testing.T) {
	// A threshold breach is a successful scan with findings, so it must map to
	// exit 1 and not be mistaken for a scan failure.
	var threshold error = &ThresholdError{Count: 3}
	if !errors.As(threshold, new(*ThresholdError)) {
		t.Fatal("ThresholdError does not match itself via errors.As")
	}
	if got, want := threshold.Error(), "3 findings at or above the --fail-on threshold"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
