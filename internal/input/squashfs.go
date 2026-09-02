package input

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrUnsquashfsMissing reports that the external tool is not installed. The
// spike settled on Plan A — shell out to unsquashfs — after confirming it
// handles all four compressions (spike/NOTES.md T0.4). It is the only external
// command fwscan ever runs (CLAUDE.md rule 8).
var ErrUnsquashfsMissing = errors.New("unsquashfs not found")

// unsquashfsBinary is the tool fwscan shells out to.
const unsquashfsBinary = "unsquashfs"

// unsquashfsTimeout bounds the shell-out. Extracting a real rootfs takes
// seconds; ten minutes is far past any of them and well short of a CI job's
// patience.
const unsquashfsTimeout = 10 * time.Minute

// maxToolOutput bounds what is kept of the tool's own output. Only the first
// line is ever shown, and the rest comes from the image.
const maxToolOutput = 64 << 10

// boundedBuffer collects at most maxToolOutput bytes and silently drops the
// rest.
type boundedBuffer struct{ buf bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := maxToolOutput - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(room, len(p))])
	}
	// The writer reports everything consumed: a full buffer is not the tool's
	// problem, and an error here would show as a broken pipe rather than as
	// whatever went wrong with the image.
	return len(p), nil
}

func (b *boundedBuffer) String() string { return b.buf.String() }

// lookPath is a variable so a test can simulate the tool being absent without
// touching the real PATH.
var lookPath = exec.LookPath

// SquashFS extracts a squashfs image by running unsquashfs.
type SquashFS struct {
	compression Compression
}

// NewSquashFS returns a squashfs source for an image with the given outer
// compression. CompressionNone means the image is not wrapped.
func NewSquashFS(c Compression) *SquashFS { return &SquashFS{compression: c} }

// Name implements Source.
func (s SquashFS) Name() string {
	if s.compression == CompressionNone {
		return "squashfs"
	}
	return "squashfs+" + string(s.compression)
}

// Open implements Source. The image is extracted into a temp directory the
// returned cleanup removes.
func (s SquashFS) Open(ctx context.Context, path string) (fs.FS, CleanupFunc, error) {
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

	// A wrapped image -- rootfs.squashfs.gz and the rest of the shapes Yocto
	// and OpenWrt emit -- has to be unwrapped first: unsquashfs seeks around
	// its input, so it needs a file rather than a stream. Detection already
	// looked through the wrapper to find the squashfs inside; without this the
	// image reached unsquashfs still compressed and the user got the tool's own
	// complaint about a missing superblock.
	image := path
	if s.compression != CompressionNone {
		var err error
		image, err = decompressToFile(ctx, path, s.compression, filepath.Join(dest, "image.squashfs"))
		if err != nil {
			cleanup()
			return nil, noopCleanup, err
		}
	}

	// unsquashfs refuses to write into an existing non-empty directory, and
	// -d must therefore name a path it creates itself.
	target := filepath.Join(dest, "rootfs")

	// The tool is given a deadline of its own as well as the caller's context.
	// unsquashfs is handed an untrusted image and has been known to sit on a
	// malformed one; without a bound, a scan in CI hangs rather than fails, and
	// a hang is the failure nobody gets an error message for.
	ctx, cancel := context.WithTimeout(ctx, unsquashfsTimeout)
	defer cancel()

	// #nosec G204 -- binary comes from LookPath and the only variable argument
	// is the user's own scan target. This is the one sanctioned shell-out.
	cmd := exec.CommandContext(ctx, binary, "-no-progress", "-quiet", "-d", target, image)
	// Bounded rather than CombinedOutput: the output belongs to the image too,
	// and only the first line of it is ever shown.
	var out boundedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out

	if err := cmd.Run(); err != nil {
		cleanup()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, noopCleanup, fmt.Errorf(
				"unsquashfs did not finish within %s; the image may be malformed", unsquashfsTimeout)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, noopCleanup, fmt.Errorf("extraction stopped: %w", ctxErr)
		}
		return nil, noopCleanup, fmt.Errorf("unsquashfs could not read the image: %s",
			toolMessage(out.String(), image, path))
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

// decompressToFile unwraps a compressed image into dest and returns its path.
// The same bound applies as to an archive: an image is untrusted input, and
// unwrapping it is exactly the step a decompression bomb is aimed at.
func decompressToFile(ctx context.Context, path string, c Compression, dest string) (string, error) {
	in, err := os.Open(path) //nolint:gosec // the path is the user's scan target
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = in.Close() }()

	info, err := in.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}

	stream, closer, err := decompress(in, c)
	if err != nil {
		return "", err
	}
	defer func() { _ = closer.Close() }()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, extractFilePerm) //nolint:gosec // dest is this package's own temp directory
	if err != nil {
		return "", fmt.Errorf("create the unwrapped image: %w", err)
	}
	defer func() { _ = out.Close() }()

	budget := &extractBudget{source: info.Size()}
	if _, err := io.Copy(budget.writer(out), &cancellableReader{ctx: ctx, reader: stream}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("extraction stopped: %w", ctxErr)
		}
		return "", fmt.Errorf("unwrapping the %s image: %w", c, err)
	}
	return dest, nil
}

// cancellableReader stops a copy when its context ends. An image can be
// gigabytes and io.Copy would otherwise run to the end of it after the scan
// was told to stop.
type cancellableReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *cancellableReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// toolMessage turns unsquashfs's output into one line fit for a user, with the
// temp path it was handed replaced by the path the user actually named. The
// tool's own wording is kept: it is the most specific thing available about
// what is wrong with the image, and paraphrasing it would lose that.
func toolMessage(out, image, path string) string {
	line := firstLine(out)
	if image != path {
		line = strings.ReplaceAll(line, image, path)
	}
	return strings.TrimPrefix(line, "FATAL ERROR: ")
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
