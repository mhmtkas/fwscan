package input

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrUnsquashfsMissing reports that the external tool is not installed. The
// spike settled on Plan A — shell out to unsquashfs — after confirming it
// handles all four compressions (spike/NOTES.md T0.4). It is the only external
// command fwscan ever runs (CLAUDE.md rule 8).
var ErrUnsquashfsMissing = errors.New("unsquashfs not found")

// unsquashfsBinary is the tool fwscan shells out to.
const unsquashfsBinary = "unsquashfs"

// lookPath is a variable so a test can simulate the tool being absent without
// touching the real PATH.
var lookPath = exec.LookPath

// SquashFS extracts a squashfs image by running unsquashfs.
type SquashFS struct{}

// NewSquashFS returns the squashfs source.
func NewSquashFS() *SquashFS { return &SquashFS{} }

// Name implements Source.
func (SquashFS) Name() string { return "squashfs" }

// Open implements Source. The image is extracted into a temp directory the
// returned cleanup removes.
func (SquashFS) Open(path string) (fs.FS, CleanupFunc, error) {
	binary, err := lookPath(unsquashfsBinary)
	if err != nil {
		// The message has to tell the user what to do. "exec: unsquashfs:
		// executable file not found in $PATH" does not.
		return nil, noopCleanup, fmt.Errorf(
			"%w: scanning squashfs images needs squashfs-tools 4.4 or newer. "+
				"install it with your package manager, for example "+
				"'apt install squashfs-tools' or 'brew install squashfs'",
			ErrUnsquashfsMissing)
	}

	dest, err := os.MkdirTemp(tempRoot, tempDirNamespace)
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dest) }

	// unsquashfs refuses to write into an existing non-empty directory, and
	// -d must therefore name a path it creates itself.
	target := filepath.Join(dest, "rootfs")

	// #nosec G204 -- binary comes from LookPath and the only variable argument
	// is the user's own scan target. This is the one sanctioned shell-out.
	cmd := exec.Command(binary, "-no-progress", "-quiet", "-d", target, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return nil, noopCleanup, fmt.Errorf("unsquashfs failed: %w: %s",
			err, firstLine(string(out)))
	}

	root, err := openExtracted(target)
	if err != nil {
		cleanup()
		return nil, noopCleanup, err
	}
	return root.FS(), func() {
		_ = root.Close()
		cleanup()
	}, nil
}

// openExtracted opens what unsquashfs produced and confines every later read to
// it.
//
// This used to walk the extracted tree, resolve every symlink, and abort the
// scan if one pointed outside. That check was wrong in both directions.
//
// It aborted on ordinary images. A rootfs is full of absolute symlinks --
// bin/sh pointing at /bin/busybox, and everything update-alternatives creates
// -- and when the machine running the scan happened to have that path too,
// which on Linux it usually does, the link resolved outside the temp directory
// and the scan died accusing the user's own image of being hostile. The first
// real OpenWrt or Yocto image anyone scanned hit it.
//
// And it never checked what it claimed to. unsquashfs does the writing here, so
// the promise at stake is that nothing lands outside the temp directory -- and
// walking the inside of that directory cannot discover what was written beyond
// it. The check read as a guarantee while providing none.
//
// What can be guaranteed is what fwscan itself reads. os.Root refuses to
// resolve a path out of the extracted tree, so a link aimed at the host is not
// readable, which is the same guarantee the tar and directory inputs give.
func openExtracted(target string) (*os.Root, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("unsquashfs produced no output: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("unsquashfs produced %s, which is not a directory", target)
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return nil, fmt.Errorf("open the extracted rootfs: %w", err)
	}
	return root, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "no output"
	}
	return s
}

// squashfsCompressionIDs maps the superblock's compression field to a name.
// The values are fixed by the squashfs on-disk format.
var squashfsCompressionIDs = map[uint16]Compression{
	1: CompressionGzip,
	4: CompressionXz,
	5: CompressionLZ4,
	6: CompressionZstd,
}

// squashfsCompressionOffset is where the 16-bit compression id sits in the
// superblock: after magic, inodes, mkfs_time, block_size and fragments, each
// four bytes.
const squashfsCompressionOffset = 20

// squashfsCompression reads the compression the image was built with, so the
// report header can say "rootfs.squashfs (squashfs, zstd)". Compressions
// fwscan has no name for — lzma and lzo — report as none rather than a guess;
// unsquashfs still handles them if it was built with support.
func squashfsCompression(header []byte) Compression {
	if len(header) < squashfsCompressionOffset+2 {
		return CompressionNone
	}
	id := binary.LittleEndian.Uint16(header[squashfsCompressionOffset:])
	if c, ok := squashfsCompressionIDs[id]; ok {
		return c
	}
	return CompressionNone
}
