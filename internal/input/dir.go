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

// Open implements Source. Nothing is extracted, so cleanup only releases the
// handle the root holds open.
//
// Reads go through os.Root rather than os.DirFS. os.DirFS rejects a path that
// spells its way out -- "../etc/passwd" -- but it hands what survives to the
// operating system, which follows symlinks wherever they point: a rootfs
// containing "var/lib/dpkg/status -> /etc/shadow" would have the host's file
// read and reported as the image's. This is the input README recommends most,
// since binwalk -e produces a directory, so it is the one most likely to be
// pointed at a tree the user did not build themselves. os.Root resolves every
// component within the directory and refuses one that leaves it.
func (Dir) Open(path string) (fs.FS, CleanupFunc, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return nil, noopCleanup, fmt.Errorf("%s is not a directory", path)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("open %s: %w", path, err)
	}
	return root.FS(), func() { _ = root.Close() }, nil
}
