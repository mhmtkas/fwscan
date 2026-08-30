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

	dest, err := os.MkdirTemp("", tempDirNamespace)
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dest) }

	stream, closer, err := decompress(f, t.compression)
	if err != nil {
		cleanup()
		return nil, noopCleanup, err
	}
	defer func() { _ = closer.Close() }()

	if err := extractTar(tar.NewReader(stream), dest); err != nil {
		cleanup()
		return nil, noopCleanup, err
	}
	return os.DirFS(dest), cleanup, nil
}

// extractTar writes the archive into dest, refusing anything that would land
// outside it.
func extractTar(tr *tar.Reader, dest string) error {
	root, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return fmt.Errorf("resolve temp dir: %w", err)
	}

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

		target, err := safeJoin(root, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, extractDirPerm); err != nil {
				return fmt.Errorf("create %s: %w", header.Name, err)
			}
		case tar.TypeReg:
			n, err := writeFile(tr, target, header.Size)
			if err != nil {
				return err
			}
			written += n
			if written > maxTotalBytes {
				return fmt.Errorf("archive expands beyond %d bytes", int64(maxTotalBytes))
			}
		case tar.TypeSymlink:
			if err := writeSymlink(root, target, header.Linkname); err != nil {
				return err
			}
		case tar.TypeLink:
			// A hard link's target must itself be inside the archive.
			source, err := safeJoin(root, header.Linkname)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), extractDirPerm); err != nil {
				return fmt.Errorf("create parent of %s: %w", header.Name, err)
			}
			if err := os.Link(source, target); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("link %s: %w", header.Name, err)
			}
		default:
			// Character devices, block devices, FIFOs and sockets are not
			// needed to catalog a rootfs and creating them may need privileges.
			continue
		}
	}
}

// safeJoin resolves name against root and refuses anything that escapes it.
// This is the zip-slip check: an entry named "../../etc/cron.d/backdoor" must
// never be written.
func safeJoin(root, name string) (string, error) {
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, name)
	}
	// Windows-style absolute paths and drive letters would also escape.
	if filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, name)
	}
	target := filepath.Join(root, filepath.FromSlash(name))
	if !isInside(root, target) {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, name)
	}
	return target, nil
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
func writeFile(r io.Reader, target string, size int64) (int64, error) {
	if size > maxSingleFile {
		return 0, fmt.Errorf("entry %s declares %d bytes, over the limit", filepath.Base(target), size)
	}
	if err := os.MkdirAll(filepath.Dir(target), extractDirPerm); err != nil {
		return 0, fmt.Errorf("create parent of %s: %w", filepath.Base(target), err)
	}
	// gosec flags the variable path; safeJoin is the mitigation and every
	// caller passes a target that has already been through it.
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, extractFilePerm) //nolint:gosec // path validated by safeJoin
	if errors.Is(err, os.ErrExist) {
		// A duplicate entry overwrites rather than failing the whole scan.
		f, err = os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, extractFilePerm) //nolint:gosec // path validated by safeJoin
	}
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", filepath.Base(target), err)
	}
	defer func() { _ = f.Close() }()

	// LimitReader rather than trusting header.Size: a lying header must not be
	// able to make this write more than it declared.
	n, err := io.Copy(f, io.LimitReader(r, maxSingleFile))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			// The destination is a fresh temp file, so a short read is the
			// archive running out, not a disk problem. Say which.
			return n, fmt.Errorf("archive is truncated, it ends part-way through %s",
				filepath.Base(target))
		}
		return n, fmt.Errorf("extracting %s: %w", filepath.Base(target), err)
	}
	return n, nil
}

// writeSymlink creates a symlink only when its target stays inside the
// extraction root. os.DirFS follows symlinks through the operating system, so
// an unchecked link to /etc/shadow would let a cataloger read the host.
func writeSymlink(root, target, linkname string) error {
	resolved := linkname
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(target), filepath.FromSlash(linkname))
	}
	if filepath.IsAbs(linkname) || !isInside(root, resolved) {
		// Skipped, not fatal: rootfs images legitimately contain absolute
		// symlinks into paths that only exist on the running device. Dropping
		// the link loses nothing a cataloger needs.
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), extractDirPerm); err != nil {
		return fmt.Errorf("create parent of %s: %w", filepath.Base(target), err)
	}
	if err := os.Symlink(linkname, target); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("symlink %s: %w", filepath.Base(target), err)
	}
	return nil
}
