// Package input turns a path — an extracted rootfs directory, a tarball, or a
// filesystem image — into an fs.FS that catalogers can read.
//
// fs.FS is the seam between input and catalog: every handler only has to
// produce one, and every cataloger only has to read one. That is what lets
// catalogers be tested against fstest.MapFS with no fixture files at all.
package input

import (
	"fmt"
	"io/fs"
)

// CleanupFunc releases whatever Open allocated — usually a temp directory.
// It is always non-nil, so callers can defer it unconditionally, and it is safe
// to call more than once.
type CleanupFunc func()

// Source opens one kind of input.
type Source interface {
	// Name identifies the source in error messages, e.g. "directory".
	Name() string
	// Open exposes the rootfs at path as an fs.FS.
	Open(path string) (fs.FS, CleanupFunc, error)
}

// noopCleanup is the cleanup for sources that allocate nothing.
func noopCleanup() {}

// Open detects the format at path and opens it.
//
// The returned cleanup is never nil, including on the error path, so
// `defer cleanup()` immediately after the call is always correct.
func Open(path string) (fs.FS, CleanupFunc, error) {
	format, _, err := Detect(path)
	if err != nil {
		return nil, noopCleanup, err
	}
	src, err := sourceFor(format)
	if err != nil {
		return nil, noopCleanup, err
	}
	rootfs, cleanup, err := src.Open(path)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, noopCleanup, fmt.Errorf("%s: %w", src.Name(), err)
	}
	if cleanup == nil {
		cleanup = noopCleanup
	}
	return rootfs, cleanup, nil
}

// sourceFor maps a detected format to its handler. Formats that are recognised
// but not yet implemented get a clear message rather than a confusing one; the
// remaining handlers arrive in T5 and T11.
func sourceFor(format Format) (Source, error) {
	switch format {
	case FormatDirectory:
		return NewDir(), nil
	case FormatUnknown:
		return nil, fmt.Errorf("unsupported format: %w", ErrUnsupportedFormat)
	default:
		return nil, fmt.Errorf("%s images are not supported yet: %w", format, ErrUnsupportedFormat)
	}
}
