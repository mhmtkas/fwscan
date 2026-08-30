package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every user-facing failure has to be a single lowercase line on stderr with
// something the reader can act on, and exit 2. A Go stack trace or a wrapped
// error repeating itself is a bug in its own right.
func TestErrorMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}

	tests := []struct {
		name     string
		args     func(t *testing.T) []string
		contains []string
		absent   []string
	}{
		{
			name: "unreadable input",
			args: func(t *testing.T) []string {
				return []string{"scan", filepath.Join(t.TempDir(), "not-here")}
			},
			contains: []string{"no such path", "not-here"},
		},
		{
			name: "unsupported format",
			args: func(t *testing.T) []string {
				path := filepath.Join(t.TempDir(), "firmware.bin")
				if err := os.WriteFile(path, bytes.Repeat([]byte{0x41}, 4096), 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
				return []string{"scan", path}
			},
			contains: []string{
				"unsupported format",
				"is not a rootfs directory, a tar archive, or a squashfs image",
				"binwalk",
			},
			// The sentinel's own text must not be printed twice.
			absent: []string{"unsupported format: unsupported format"},
		},
		{
			name: "extraction failure",
			args: func(t *testing.T) []string {
				// A real tarball cut short: detection still recognises it, and
				// extraction then runs off the end. Cutting less than this can
				// leave a complete tar behind a truncated gzip stream, which
				// legitimately scans fine.
				whole, err := os.ReadFile(filepath.Join("..", "..",
					"testdata", "images", "mini-rootfs.tar.gz"))
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				path := filepath.Join(t.TempDir(), "rootfs.tar.gz")
				if err := os.WriteFile(path, whole[:3000], 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
				return []string{"scan", path}
			},
			contains: []string{"archive is truncated"},
		},
		{
			name: "invalid threshold",
			args: func(_ *testing.T) []string {
				return []string{"scan", "--no-network", "--fail-on", "catastrophic",
					"testdata/images/mini-rootfs.tar.gz"}
			},
			contains: []string{"invalid --fail-on", "critical, high, medium or low"},
		},
		{
			name: "unwritable output",
			args: func(t *testing.T) []string {
				return []string{"scan", "--no-network", "--output",
					filepath.Join(t.TempDir(), "missing-dir", "report.json"),
					"testdata/images/mini-rootfs.tar.gz"}
			},
			contains: []string{"write report"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runFwscan(t, tt.args(t)...)

			if code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout must stay empty on failure, got:\n%s", stdout)
			}

			assertUserFacingMessage(t, stderr)
			for _, want := range tt.contains {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr does not mention %q:\n%s", want, stderr)
				}
			}
			for _, unwanted := range tt.absent {
				if strings.Contains(stderr, unwanted) {
					t.Errorf("stderr repeats itself (%q):\n%s", unwanted, stderr)
				}
			}
		})
	}
}

// assertUserFacingMessage enforces the shape every error shares.
func assertUserFacingMessage(t *testing.T, stderr string) {
	t.Helper()

	trimmed := strings.TrimRight(stderr, "\n")
	if trimmed == "" {
		t.Fatal("nothing on stderr")
	}
	if strings.Contains(trimmed, "\n") {
		t.Errorf("message spans several lines:\n%s", stderr)
	}
	if !strings.HasPrefix(trimmed, "fwscan: ") {
		t.Errorf("message is not prefixed with the tool name: %q", trimmed)
	}

	body := strings.TrimPrefix(trimmed, "fwscan: ")
	if body == "" {
		t.Fatal("message has no body")
	}
	if first := body[:1]; first != strings.ToLower(first) {
		t.Errorf("message does not start lowercase: %q", body)
	}
	// A stack trace or a panic is never a user-facing message.
	for _, forbidden := range []string{"goroutine ", "panic:", ".go:", "0x"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("message leaks internals (%q): %q", forbidden, body)
		}
	}
}

// The missing-unsquashfs message is the one failure a user is most likely to
// hit on a fresh machine, so it is checked end to end with the tool hidden.
func TestMissingUnsquashfsMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	stdout, stderr, code := runFwscanWithPath(t, "/nonexistent-bin",
		"scan", "testdata/images/mini-rootfs.squashfs")

	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("stdout not empty:\n%s", stdout)
	}
	assertUserFacingMessage(t, stderr)
	for _, want := range []string{"squashfs-tools", "apt install squashfs-tools", "brew install squashfs"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not mention %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "executable file not found") {
		t.Errorf("the raw exec error leaked:\n%s", stderr)
	}
}
