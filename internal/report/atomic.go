package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes through a temp file in the destination's own directory
// and renames it into place, so a reader never sees a half-written report and a
// failure part-way through leaves any previous file intact.
//
// The temp file is created alongside the destination rather than in the system
// temp directory, because rename is only atomic within a filesystem.
func WriteFileAtomic(path string, write func(io.Writer) error) (err error) {
	// Checked up front, because the failure otherwise surfaces from the rename
	// as "rename <dir>/.tmp123 <dir>: file exists", which names the temp file
	// and blames the wrong thing. The destination being a directory is the
	// mistake, and saying so is the difference between a fixable message and a
	// puzzling one.
	if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
		return fmt.Errorf("cannot write %s: it is a directory", path)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("create temp file next to %s: %w", path, err)
	}
	tmpName := tmp.Name()

	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = write(tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("flush %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	// CreateTemp makes the file 0600. A scan report is meant to be read by
	// colleagues and CI, not guarded, so it gets ordinary file permissions.
	if err = os.Chmod(tmpName, 0o644); err != nil { //nolint:gosec // a report is not a secret
		return fmt.Errorf("set permissions on %s: %w", path, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
