package cli_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The exit code is a contract with CI pipelines, so it is checked by running
// the real binary and reading the real status, not by inspecting a returned
// error.

var (
	buildOnce  sync.Once
	binaryPath string
	buildErr   error
)

func fwscanBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fwscan-e2e-")
		if err != nil {
			buildErr = err
			return
		}
		binaryPath = filepath.Join(dir, "fwscan")
		cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/fwscan")
		cmd.Dir = filepath.Join("..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = err
			t.Logf("build output: %s", out)
		}
	})
	if buildErr != nil {
		t.Fatalf("building fwscan: %v", buildErr)
	}
	return binaryPath
}

func runFwscan(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runFwscanWithPath(t, "", args...)
}

// runFwscanWithPath runs the binary with PATH replaced, so a test can hide an
// external tool without touching the machine's own environment.
func runFwscanWithPath(t *testing.T, path string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(fwscanBinary(t), args...)
	cmd.Dir = filepath.Join("..", "..")
	if path != "" {
		cmd.Env = append(os.Environ(), "PATH="+path)
	}
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running fwscan: %v", err)
	}
	return out.String(), errBuf.String(), code
}

func TestExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}

	const image = "testdata/images/mini-rootfs.tar.gz"

	t.Run("0 when no threshold is set", func(t *testing.T) {
		stdout, _, code := runFwscan(t, "scan", "--no-network", image)
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		if !strings.Contains(stdout, "Cataloged") {
			t.Errorf("report missing from stdout:\n%s", stdout)
		}
	})

	t.Run("0 when nothing meets the threshold", func(t *testing.T) {
		// --no-network produces no findings at all, so no threshold can be met.
		_, _, code := runFwscan(t, "scan", "--no-network", "--fail-on", "low", image)
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})

	t.Run("2 on an unreadable target", func(t *testing.T) {
		stdout, stderr, code := runFwscan(t, "scan", "/nonexistent/path")
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
		if stdout != "" {
			t.Errorf("stdout must stay empty on failure, got:\n%s", stdout)
		}
		if !strings.Contains(stderr, "no such path") {
			t.Errorf("stderr = %q", stderr)
		}
	})

	t.Run("2 on an invalid --fail-on", func(t *testing.T) {
		_, stderr, code := runFwscan(t, "scan", "--no-network", "--fail-on", "spicy", image)
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
		if !strings.Contains(stderr, "invalid --fail-on") {
			t.Errorf("stderr = %q", stderr)
		}
	})

	t.Run("2 on an unknown flag", func(t *testing.T) {
		// Cobra's own usage error path, which output-spec section 5 also puts
		// at exit 2.
		_, _, code := runFwscan(t, "scan", "--nonsense", image)
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})

	t.Run("2 when the target is missing entirely", func(t *testing.T) {
		_, _, code := runFwscan(t, "scan")
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})

	t.Run("0 for version", func(t *testing.T) {
		stdout, _, code := runFwscan(t, "version")
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		if !strings.HasPrefix(stdout, "fwscan ") {
			t.Errorf("stdout = %q", stdout)
		}
	})
}
