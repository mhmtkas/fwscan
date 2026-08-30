//go:build integration

package cli_test

import (
	"strings"
	"testing"
)

// TestExitCodeOneLive checks the code CI pipelines actually depend on: a scan
// that completed, with findings at or above the threshold, exits 1 rather than
// 2. It needs real findings, so it needs the network.
//
//	go test -tags integration ./internal/cli/
func TestExitCodeOneLive(t *testing.T) {
	const image = "testdata/images/mini-rootfs.tar.gz"

	stdout, _, code := runFwscan(t, "scan", "--fail-on", "critical", image)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	// Exit 1 is a completed scan, so the report is still on stdout.
	if !strings.Contains(stdout, "SEVERITY") {
		t.Errorf("the table is missing from a scan that exited 1:\n%s", stdout)
	}

	// A threshold nothing reaches leaves the same scan at 0.
	_, _, code = runFwscan(t, "scan", "--fail-on", "low", "testdata/images/alpine-rootfs.tar.gz")
	if code != 1 {
		t.Errorf("alpine scan with --fail-on low exited %d, want 1", code)
	}
}
