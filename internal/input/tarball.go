package input

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnsafePath reports an archive entry that would write outside the
// extraction directory. It is its own error so tests and the CLI can recognise
// a hostile archive rather than pattern-matching a message.
var ErrUnsafePath = errors.New("archive entry escapes the extraction directory")

// Extraction bounds. A firmware rootfs is large but not unbounded, and this
// code is handed untrusted images (CLAUDE.md rule 9).
const (
	maxEntries       = 1 << 20  // one million files
	maxTotalBytes    = 16 << 30 // 16 GiB written in total
	maxSingleFile    = 8 << 30  // 8 GiB for any one file
	extractDirPerm   = 0o755
	extractFilePerm  = 0o644
	tempDirNamespace = "fwscan-extract-"
)

// tempRoot is where extraction directories are created. Empty means the
// system temp directory, which is what every real run uses. Tests point it at
// their own directory so that counting what an extraction left behind cannot
// be confused by another package's test binary running at the same time --
// `go test ./...` runs packages in parallel and they share os.TempDir().
var tempRoot string

// Tarball opens a tar archive, transparently decompressing it first.
type Tarball struct {
	compression Compression
}

// NewTarball returns a tar source for an archive with the given outer
// compression. CompressionNone means a plain .tar.
func NewTarball(c Compression) *Tarball { return &Tarball{compression: c} }

// Name implements Source.
func (t Tarball) Name() string {
	if t.compression == CompressionNone {
		return "tar"
	}
	return "tar+" + string(t.compression)
}

// Open implements Source. The archive is extracted into a temp directory that
// the returned cleanup removes; nothing is ever written outside it.
func (t Tarball) Open(path string) (fs.FS, CleanupFunc, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the user's scan target
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dest, err := os.MkdirTemp(tempRoot, tempDirNamespace)
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("create temp dir: %w", err)
	}

	// Everything from here on -- every write during extraction and every read
	// a cataloger makes afterwards -- goes through this root. os.Root resolves
	// each path component itself and refuses one that leaves the directory, so
	// confinement holds where the kernel walks the path rather than where this
	// code inspects a string.
	root, err := os.OpenRoot(dest)
	if err != nil {
		_ = os.RemoveAll(dest)
		return nil, noopCleanup, fmt.Errorf("open temp dir: %w", err)
	}
	cleanup := func() {
		_ = root.Close()
		_ = os.RemoveAll(dest)
	}

	stream, closer, err := decompress(f, t.compression)
	if err != nil {
		cleanup()
		return nil, noopCleanup, err
	}
	defer func() { _ = closer.Close() }()

	if err := extractTar(tar.NewReader(stream), root); err != nil {
		cleanup()
		return nil, noopCleanup, err
	}
	return root.FS(), cleanup, nil
}

// extractTar writes the archive into root, refusing anything that would land
// outside it.
func extractTar(tr *tar.Reader, root *os.Root) error {
	var entries int
	var written int64
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("archive is truncated")
			}
			return fmt.Errorf("reading archive: %w", err)
		}

		entries++
		if entries > maxEntries {
			return fmt.Errorf("archive has more than %d entries", maxEntries)
		}

		name, err := safeName(header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, extractDirPerm); err != nil {
				return fmt.Errorf("create %s: %w", header.Name, err)
			}
		case tar.TypeReg:
			n, err := writeFile(tr, root, name, header.Size)
			if err != nil {
				return err
			}
			written += n
			if written > maxTotalBytes {
				return fmt.Errorf("archive expands beyond %d bytes", int64(maxTotalBytes))
			}
		case tar.TypeSymlink:
			if err := writeSymlink(root, name, header.Linkname); err != nil {
				return err
			}
		case tar.TypeLink:
			// A hard link's target must itself be inside the archive.
			source, err := safeName(header.Linkname)
			if err != nil {
				return err
			}
			if _, err := root.Lstat(source); err != nil {
				// The source is missing, usually because it was an absolute
				// symlink this extractor deliberately dropped. Real rootfs
				// images contain exactly that -- bin/sh pointing at
				// /bin/busybox, with another name hard-linked to it -- so
				// skipping the link is right and failing the scan is not.
				continue
			}
			if err := mkdirParent(root, name); err != nil {
				return fmt.Errorf("create parent of %s: %w", header.Name, err)
			}
			if err := root.Link(source, name); err != nil && !errors.Is(err, os.ErrExist) {
				// The path in the OS error is inside a temp directory the user
				// never named, so only the archive's own name is reported.
				return fmt.Errorf("cannot create the hard link %s", header.Name)
			}
		default:
			// Character devices, block devices, FIFOs and sockets are not
			// needed to catalog a rootfs and creating them may need privileges.
			continue
		}
	}
}

// safeName turns an entry name into a path relative to the extraction root,
// refusing anything that escapes it. This is the zip-slip check: an entry named
// "../../etc/cron.d/backdoor" must never be written.
//
// It is a lexical check, and lexical checks cannot see symlinks -- that is what
// os.Root is for. Its job is to give a hostile *name* an error that says so,
// naming the entry, instead of a kernel error naming a temp path the user never
// chose.
func safeName(name string) (string, error) {
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, name)
	}
	// Windows-style absolute paths and drive letters would also escape.
	if filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, name)
	}
	// An archive written from a directory names its own root "./", so "." is
	// the archive root rather than an escape.
	clean := filepath.Clean(filepath.FromSlash(name))
	if escapesLexically(clean) {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, name)
	}
	return clean, nil
}

// escapesLexically reports whether a cleaned relative path starts by going up.
func escapesLexically(path string) bool {
	return path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator))
}

// mkdirParent creates the directories an entry needs, if it needs any.
func mkdirParent(root *os.Root, name string) error {
	dir := filepath.Dir(name)
	if dir == "." {
		return nil
	}
	return root.MkdirAll(dir, extractDirPerm)
}

// isInside reports whether path is root itself or lives beneath it.
func isInside(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// writeFile creates one regular file, bounded so a single entry cannot fill the
// disk however large the archive claims it is.
func writeFile(r io.Reader, root *os.Root, name string, size int64) (int64, error) {
	target := filepath.Base(name)
	if size > maxSingleFile {
		return 0, fmt.Errorf("entry %s declares %d bytes, over the limit", target, size)
	}
	if err := mkdirParent(root, name); err != nil {
		return 0, fmt.Errorf("create parent of %s: %w", target, err)
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, extractFilePerm)
	if errors.Is(err, os.ErrExist) {
		// A duplicate entry overwrites rather than failing the whole scan.
		f, err = root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, extractFilePerm)
	}
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", target, err)
	}
	defer func() { _ = f.Close() }()

	// LimitReader rather than trusting header.Size: a lying header must not be
	// able to make this write more than it declared.
	n, err := io.Copy(f, io.LimitReader(r, maxSingleFile))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			// The destination is a fresh temp file, so a short read is the
			// archive running out, not a disk problem. Say which.
			return n, fmt.Errorf("archive is truncated, it ends part-way through %s", target)
		}
		return n, fmt.Errorf("extracting %s: %w", target, err)
	}
	return n, nil
}

// writeSymlink creates a symlink, skipping the ones that point out of the
// extraction root.
//
// The test below is lexical and so it is a tidy-up, not the guarantee. A chain
// of relative links can climb out one step at a time while every step still
// reads as inside -- l0 -> "..", then l1 -> "l0/..", and each link resolves
// through the one before it. What stops that is os.Root: it re-resolves every
// component at the point the kernel does, so a path that only becomes an escape
// once the links are followed is refused there, both for writes during
// extraction and for reads afterwards. This function drops the links a real
// rootfs carries -- absolute ones into paths that exist only on the device --
// so the extracted tree is not littered with entries nothing can open.
func writeSymlink(root *os.Root, name, linkname string) error {
	resolved := linkname
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(name), filepath.FromSlash(linkname))
	}
	if filepath.IsAbs(linkname) || escapesLexically(resolved) {
		// Skipped, not fatal: rootfs images legitimately contain absolute
		// symlinks into paths that only exist on the running device. Dropping
		// the link loses nothing a cataloger needs.
		return nil
	}
	if err := mkdirParent(root, name); err != nil {
		return fmt.Errorf("create parent of %s: %w", filepath.Base(name), err)
	}
	if err := root.Symlink(linkname, name); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("symlink %s: %w", filepath.Base(name), err)
	}
	return nil
}
