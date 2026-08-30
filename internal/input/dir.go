package input

import (
	"fmt"
	"io/fs"
	"os"
)

// Dir opens an already-extracted rootfs directory. This is the simplest input
// and the one every other handler reduces to: tarballs and images are extracted
// to a temp directory and then read exactly like this.
type Dir struct{}

// NewDir returns the directory source.
func NewDir() *Dir { return &Dir{} }

// Name implements Source.
func (Dir) Name() string { return "directory" }

// Open implements Source. Nothing is allocated, so cleanup is a no-op.
//
// os.DirFS confines reads to the directory: the returned fs.FS rejects absolute
// paths and any path escaping the root, so a cataloger cannot be tricked into
// reading outside the image by a crafted path.
func (Dir) Open(path string) (fs.FS, CleanupFunc, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return nil, noopCleanup, fmt.Errorf("%s is not a directory", path)
	}
	return os.DirFS(path), noopCleanup, nil
}
