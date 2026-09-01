package report

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := WriteFileAtomic(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "first\n")
		return err
	}); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	assertContents(t, path, "first\n")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// CreateTemp makes files 0600; a report is meant to be readable.
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("permissions = %o, want 644", perm)
	}

	// A failure must leave the previous file untouched and drop the temp file.
	sentinel := errors.New("boom")
	err = WriteFileAtomic(path, func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want the writer's own error", err)
	}
	assertContents(t, path, "first\n")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the report", names)
	}
}

func TestWriteFileAtomicUnwritableDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "report.json")
	if err := WriteFileAtomic(path, func(io.Writer) error { return nil }); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

func assertContents(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(body) != want {
		t.Errorf("contents = %q, want %q", body, want)
	}
}

// A mistyped --output that lands on a directory has to say so. The rename would
// otherwise fail with "file exists", naming a temp file the user never chose.
func TestWriteFileAtomicRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	err := WriteFileAtomic(dir, func(w io.Writer) error {
		_, writeErr := io.WriteString(w, "never written")
		return writeErr
	})
	if err == nil {
		t.Fatal("writing over a directory succeeded")
	}
	if !strings.Contains(err.Error(), "it is a directory") {
		t.Errorf("error = %v, want it to name the mistake", err)
	}
}
