package input

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"

	"github.com/mhmtkas/fwscan/internal/catalog"
)

// requireSquashfsTools skips when the host has no squashfs-tools. CI installs
// them, so the matrix below really does run there.
func requireSquashfsTools(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("unsquashfs"); err != nil {
		t.Skip("unsquashfs not installed; see the development section of CONTRIBUTING.md")
	}
}

// requireMksquashfs skips when the image builder is missing. It comes from the
// same squashfs-tools package as unsquashfs, so CI has both.
func requireMksquashfs(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("mksquashfs"); err != nil {
		t.Skip("mksquashfs not installed; see the development section of CONTRIBUTING.md")
	}
}

// buildSquashFS packs a directory into an image and returns its path.
func buildSquashFS(t *testing.T, src string) string {
	t.Helper()
	image := filepath.Join(t.TempDir(), "built.squashfs")
	cmd := exec.Command("mksquashfs", src, image,
		"-noappend", "-all-root", "-no-xattrs", "-quiet", "-no-progress")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mksquashfs: %v: %s", err, out)
	}
	return image
}

// Every real rootfs image carries absolute symlinks: bin/sh pointing at
// /bin/busybox, and everything update-alternatives creates. Scanning one has to
// work -- and the links must not become a way to read the host.
//
// This is the case that used to abort the scan. The extractor resolved every
// symlink after extraction and refused the image if one landed outside the temp
// directory, which an absolute link does whenever its target exists on the
// machine running the scan.
func TestSquashFSWithAbsoluteSymlinks(t *testing.T) {
	requireSquashfsTools(t)
	requireMksquashfs(t)

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("HOST-FILE-LEAKED\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := t.TempDir()
	for name, body := range map[string]string{
		"var/lib/dpkg/status": testStatus,
		"usr/lib/os-release":  testOSRelease,
		"bin/busybox":         "BusyBox\n",
	} {
		full := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The shape every image has, and the same shape aimed at a file that really
	// exists outside the image -- which is what made the old check fire.
	if err := os.Symlink("/bin/busybox", filepath.Join(src, "bin", "sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(src, "etc-leak")); err != nil {
		t.Fatal(err)
	}

	rootfs, cleanup, err := Open(context.Background(), buildSquashFS(t, src))
	if err != nil {
		t.Fatalf("Open() error = %v; a rootfs with absolute symlinks is an ordinary image, not a hostile one", err)
	}
	defer cleanup()

	comps, err := catalog.NewDpkg().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(comps) == 0 {
		t.Error("no packages cataloged from an image that has a dpkg database")
	}

	// The links are present but lead nowhere reachable: reads stay inside.
	for _, name := range []string{"etc-leak", "bin/sh"} {
		f, err := rootfs.Open(name)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(f)
		_ = f.Close()
		t.Errorf("%s is readable and yields %q; an absolute link must not resolve on the host", name, body)
	}
}

// Every compression must scan to the same components. The gzip image is
// committed; make fixtures builds the rest, so the variants are skipped rather
// than failed when they have not been built.
func TestSquashFSCompressionMatrix(t *testing.T) {
	requireSquashfsTools(t)

	tests := []struct {
		name            string
		file            string
		wantCompression Compression
		committed       bool
	}{
		{"gzip", "mini-rootfs.squashfs", CompressionGzip, true},
		{"lz4", "mini-rootfs.lz4.squashfs", CompressionLZ4, false},
		{"zstd", "mini-rootfs.zstd.squashfs", CompressionZstd, false},
		{"xz", "mini-rootfs.xz.squashfs", CompressionXz, false},
	}

	var reference []string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "testdata", "images", tt.file)
			if _, err := os.Stat(path); err != nil {
				if tt.committed {
					t.Fatalf("committed fixture missing: %v", err)
				}
				t.Skipf("%s not built; run make fixtures", tt.file)
			}

			format, compression, err := Detect(path)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if format != FormatSquashFS {
				t.Errorf("format = %s, want squashfs", format)
			}
			if compression != tt.wantCompression {
				t.Errorf("compression = %s, want %s", compression, tt.wantCompression)
			}

			rootfs, cleanup, err := Open(context.Background(), path)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer cleanup()

			comps, err := catalog.NewDpkg().Catalog(context.Background(), rootfs)
			if err != nil {
				t.Fatalf("Catalog() error = %v", err)
			}
			if len(comps) == 0 {
				t.Fatal("no components found")
			}

			var got []string
			for _, c := range comps {
				got = append(got, c.Name+"@"+c.Version+" "+c.PURL)
			}
			if reference == nil {
				reference = got
				return
			}
			if len(got) != len(reference) {
				t.Fatalf("got %d components, the gzip image gave %d", len(got), len(reference))
			}
			for i := range got {
				if got[i] != reference[i] {
					t.Errorf("component %d differs from the gzip image:\n got  %s\n want %s", i, got[i], reference[i])
				}
			}
		})
	}
}

func TestSquashFSCleanupRemovesTempDir(t *testing.T) {
	requireSquashfsTools(t)

	path := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.squashfs")
	rootfs, cleanup, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := rootfs.Open(catalog.DpkgStatusPath); err != nil {
		t.Fatalf("status not readable before cleanup: %v", err)
	}
	cleanup()
	if _, err := rootfs.Open(catalog.DpkgStatusPath); err == nil {
		t.Error("still readable after cleanup; the temp dir was not removed")
	}
}

// The message a user sees when the tool is missing has to say what to install.
func TestSquashFSMissingUnsquashfs(t *testing.T) {
	original := lookPath
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	t.Cleanup(func() { lookPath = original })

	path := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.squashfs")
	_, cleanup, err := Open(context.Background(), path)
	cleanup()

	if err == nil {
		t.Fatal("Open() returned no error with unsquashfs missing")
	}
	if !errors.Is(err, ErrUnsquashfsMissing) {
		t.Errorf("error %v does not wrap ErrUnsquashfsMissing", err)
	}
	message := err.Error()
	for _, want := range []string{"squashfs-tools", "apt install squashfs-tools", "brew install squashfs"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q does not mention %q", message, want)
		}
	}
	if message != strings.ToLower(message[:1])+message[1:] {
		t.Errorf("message %q does not start lowercase", message)
	}
	// A raw exec error is not an actionable message.
	if strings.Contains(message, "executable file not found") {
		t.Errorf("the raw exec error leaked to the user: %q", message)
	}
}

func TestSquashFSCorruptImage(t *testing.T) {
	requireSquashfsTools(t)

	// Valid magic, rubbish behind it.
	path := filepath.Join(t.TempDir(), "broken.squashfs")
	body := make([]byte, 1024)
	copy(body, []byte("hsqs"))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, cleanup, err := Open(context.Background(), path)
	cleanup()
	if err == nil {
		t.Fatal("Open() on a corrupt image returned no error")
	}
	if strings.Count(err.Error(), "\n") > 0 {
		t.Errorf("error spans multiple lines: %q", err)
	}
}

func TestSquashFSName(t *testing.T) {
	if got := NewSquashFS(CompressionNone).Name(); got != "squashfs" {
		t.Errorf("Name() = %q, want squashfs", got)
	}
}

func TestSquashfsCompressionFromSuperblock(t *testing.T) {
	header := func(id byte) []byte {
		b := make([]byte, 64)
		copy(b, []byte("hsqs"))
		b[squashfsCompressionOffset] = id
		return b
	}
	tests := []struct {
		name string
		id   byte
		want Compression
	}{
		{"gzip", 1, CompressionGzip},
		{"xz", 4, CompressionXz},
		{"lz4", 5, CompressionLZ4},
		{"zstd", 6, CompressionZstd},
		// lzma and lzo have no name in fwscan's vocabulary; unsquashfs still
		// handles them, so they report as none rather than as a wrong guess.
		{"lzma reports none", 2, CompressionNone},
		{"lzo reports none", 3, CompressionNone},
		{"unknown id reports none", 99, CompressionNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := squashfsCompression(header(tt.id)); got != tt.want {
				t.Errorf("squashfsCompression() = %s, want %s", got, tt.want)
			}
		})
	}
	if got := squashfsCompression([]byte("hsqs")); got != CompressionNone {
		t.Errorf("truncated header = %s, want none", got)
	}
}

// A standalone-compressed image -- rootfs.squashfs.gz and the rest of the
// shapes Yocto and OpenWrt emit -- is listed as supported in docs/scope.md, and
// detection handled it: it looks through the wrapper and reports the squashfs
// inside. Dispatch did not, and handed the still-compressed file to unsquashfs,
// which answered with its own complaint about a missing superblock.
func TestSquashFSWrappedInAnOuterCompression(t *testing.T) {
	requireSquashfsTools(t)

	image, err := os.ReadFile(filepath.Join("..", "..", "testdata", "images", "mini-rootfs.squashfs"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	bare, cleanup, err := Open(context.Background(), filepath.Join("..", "..", "testdata", "images", "mini-rootfs.squashfs"))
	if err != nil {
		t.Fatalf("Open() on the bare image error = %v", err)
	}
	reference, err := catalog.NewDpkg().Catalog(context.Background(), bare)
	cleanup()
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}

	for _, tt := range []struct {
		name string
		wrap func(io.Writer) (io.WriteCloser, error)
	}{
		{"gzip", func(w io.Writer) (io.WriteCloser, error) { return gzip.NewWriter(w), nil }},
		{"zstd", func(w io.Writer) (io.WriteCloser, error) { return zstd.NewWriter(w) }},
		{"lz4", func(w io.Writer) (io.WriteCloser, error) { return lz4.NewWriter(w), nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			zw, err := tt.wrap(&buf)
			if err != nil {
				t.Fatalf("writer: %v", err)
			}
			if _, err := zw.Write(image); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := zw.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			path := filepath.Join(t.TempDir(), "rootfs.squashfs."+tt.name)
			if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}

			format, _, err := Detect(path)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if format != FormatSquashFS {
				t.Fatalf("format = %s, want squashfs", format)
			}

			rootfs, cleanup, err := Open(context.Background(), path)
			if err != nil {
				t.Fatalf("Open() error = %v; a wrapped image is supported input", err)
			}
			defer cleanup()

			comps, err := catalog.NewDpkg().Catalog(context.Background(), rootfs)
			if err != nil {
				t.Fatalf("Catalog() error = %v", err)
			}
			// The wrapper must not change what is inside it.
			if len(comps) != len(reference) {
				t.Fatalf("got %d components, the bare image gave %d", len(comps), len(reference))
			}
		})
	}
}

// Unwrapping is a step that can fail on its own, before unsquashfs is reached,
// and its failures are as user-facing as any other.
func TestSquashFSWrapperFailures(t *testing.T) {
	requireSquashfsTools(t)

	image, err := os.ReadFile(filepath.Join("..", "..", "testdata", "images", "mini-rootfs.squashfs"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var whole bytes.Buffer
	zw := gzip.NewWriter(&whole)
	if _, err := zw.Write(image); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	t.Run("truncated wrapper", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rootfs.squashfs.gz")
		// Enough to detect as a wrapped squashfs, not enough to unwrap.
		if err := os.WriteFile(path, whole.Bytes()[:len(whole.Bytes())/2], 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, cleanup, err := Open(context.Background(), path)
		cleanup()
		if err == nil {
			t.Fatal("a truncated image opened without complaint")
		}
		assertNoStackTrace(t, err)
	})

	t.Run("the unwrapped image is bounded", func(t *testing.T) {
		restore := func(ratio, floor int64) func() {
			return func() { maxExpansionRatio, minExpansionBytes = ratio, floor }
		}(maxExpansionRatio, minExpansionBytes)
		t.Cleanup(restore)
		// The fixture is 4 KiB and gzips to about 3 KiB, so the bound has to be
		// set below "any expansion at all" for this small an image to cross it.
		maxExpansionRatio, minExpansionBytes = 0, 1<<10

		path := filepath.Join(t.TempDir(), "rootfs.squashfs.gz")
		if err := os.WriteFile(path, whole.Bytes(), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, cleanup, err := Open(context.Background(), path)
		cleanup()
		if err == nil {
			t.Fatal("unwrapping ignored the expansion bound")
		}
		if !errors.Is(err, ErrDecompressionBomb) {
			t.Errorf("error %v does not wrap ErrDecompressionBomb", err)
		}
	})
}

// assertNoStackTrace guards the CLI convention: a user-facing failure is a
// message, never a dump.
func assertNoStackTrace(t *testing.T, err error) {
	t.Helper()
	if strings.Contains(err.Error(), "goroutine ") || strings.Contains(err.Error(), ".go:") {
		t.Errorf("error looks like a stack trace: %v", err)
	}
}

// Unwrapping a compressed image is a copy that can run for gigabytes, and a
// scan told to stop must not finish it first.
func TestUnwrappingStopsWhenTheContextIsCancelled(t *testing.T) {
	requireSquashfsTools(t)

	image, err := os.ReadFile(filepath.Join("..", "..", "testdata", "images", "mini-rootfs.squashfs"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var wrapped bytes.Buffer
	zw := gzip.NewWriter(&wrapped)
	if _, err := zw.Write(image); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rootfs.squashfs.gz")
	if err := os.WriteFile(path, wrapped.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, cleanup, err := Open(ctx, path)
	cleanup()
	if err == nil {
		t.Fatal("a cancelled context unwrapped and extracted the image")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not wrap context.Canceled", err)
	}
}
