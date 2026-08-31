//go:build apkoracle || cvss4oracle

// Shared by the oracle tests, which check this package's ports against the
// upstream implementations they came from. Both need a container to run the
// original in.

package match

import (
	"os/exec"
	"testing"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available; skipping the oracle")
	}
}
