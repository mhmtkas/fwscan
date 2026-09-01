package input

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"

	"github.com/mhmtkas/fwscan/internal/catalog"
	"github.com/mhmtkas/fwscan/internal/model"
)

const testStatus = "Package: openssl\n" +
	"Status: install ok installed\n" +
	"Architecture: amd64\n" +
	"Version: 1.1.1k-1+deb11u2\n" +
	"Description: toolkit\n" +
	" continuation\n" +
	"\n" +
	"Package: zlib1g\n" +
	"Status: install ok installed\n" +
	"Architecture: amd64\n" +
	"Source: zlib\n" +
	"Version: 1:1.2.11.dfsg-2\n"

const testOSRelease = "ID=debian\nVERSION_CODENAME=bullseye\n"

// buildTar returns a tar archive of a minimal rootfs, including a directory
// entry, a symlink and an unsupported entry type, so extraction is exercised
// beyond plain files.
func buildTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeDir(t, tw, "var/lib/dpkg")
	writeReg(t, tw, "var/lib/dpkg/status", testStatus)
	writeReg(t, tw, "usr/lib/os-release", testOSRelease)
	writeReg(t, tw, "bin/busybox", "BusyBox v1.30.1\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "bin/sh", Typeflag: tar.TypeSymlink, Linkname: "busybox", Mode: 0o777,
	}); err != nil {
		t.Fatalf("symlink header: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: "dev/null", Typeflag: tar.TypeChar, Mode: 0o666,
	}); err != nil {
		t.Fatalf("char device header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func writeDir(t *testing.T, tw *tar.Writer, name string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("dir header %s: %v", name, err)
	}
}

func writeReg(t *testing.T, tw *tar.Writer, name, body string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
	}); err != nil {
		t.Fatalf("header %s: %v", name, err)
	}
	if _, err := io.WriteString(tw, body); err != nil {
		t.Fatalf("body %s: %v", name, err)
	}
}

// compressTo wraps raw in the named compression.
func compressTo(t *testing.T, raw []byte, c Compression) []byte {
	t.Helper()
	var out bytes.Buffer
	var w io.WriteCloser
	switch c {
	case CompressionNone:
		return raw
	case CompressionGzip:
		w = gzip.NewWriter(&out)
	case CompressionXz:
		xw, err := xz.NewWriter(&out)
		if err != nil {
			t.Fatalf("xz writer: %v", err)
		}
		w = xw
	case CompressionZstd:
		zw, err := zstd.NewWriter(&out)
		if err != nil {
			t.Fatalf("zstd writer: %v", err)
		}
		w = zw
	case CompressionLZ4:
		w = lz4.NewWriter(&out)
	default:
		t.Fatalf("unhandled compression %s", c)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("compress: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close compressor: %v", err)
	}
	return out.Bytes()
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

var wantComponents = []model.Component{
	{
		Name: "openssl", Version: "1.1.1k-1+deb11u2", Arch: "amd64",
		Source: "openssl", SourceVersion: "1.1.1k-1+deb11u2", Distro: "bullseye",
		PURL:       "pkg:deb/debian/openssl@1.1.1k-1%2Bdeb11u2?arch=amd64&distro=bullseye",
		Confidence: model.ConfidenceHigh, Evidence: catalog.DpkgStatusPath,
	},
	{
		Name: "zlib1g", Version: "1:1.2.11.dfsg-2", Arch: "amd64",
		Source: "zlib", SourceVersion: "1:1.2.11.dfsg-2", Distro: "bullseye",
		PURL:       "pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2?arch=amd64&distro=bullseye",
		Confidence: model.ConfidenceHigh, Evidence: catalog.DpkgStatusPath,
	},
}

// Every packaging of the same rootfs must catalog identically.
func TestTarballAllCompressions(t *testing.T) {
	raw := buildTar(t)

	tests := []struct {
		name            string
		filename        string
		compression     Compression
		wantCompression Compression
	}{
		{"plain tar", "rootfs.tar", CompressionNone, CompressionNone},
		{"gzip", "rootfs.tar.gz", CompressionGzip, CompressionGzip},
		{"xz", "rootfs.tar.xz", CompressionXz, CompressionXz},
		{"zstd", "rootfs.tar.zst", CompressionZstd, CompressionZstd},
		{"lz4", "rootfs.tar.lz4", CompressionLZ4, CompressionLZ4},

		// Detection must ignore the extension entirely.
		{"lz4 misnamed as gz", "rootfs.tar.gz", CompressionLZ4, CompressionLZ4},
		{"zstd misnamed as tar", "rootfs.tar", CompressionZstd, CompressionZstd},
		{"gzip with no extension at all", "rootfs", CompressionGzip, CompressionGzip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemp(t, tt.filename, compressTo(t, raw, tt.compression))

			format, compression, err := Detect(path)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if format != FormatTar {
				t.Errorf("Detect() format = %s, want tar", format)
			}
			if compression != tt.wantCompression {
				t.Errorf("Detect() compression = %s, want %s", compression, tt.wantCompression)
			}

			rootfs, cleanup, err := Open(context.Background(), path)
			if err != nil {
				t.Fatalf("Open(context.Background(), ) error = %v", err)
			}
			defer cleanup()

			comps, err := catalog.NewDpkg().Catalog(rootfs)
			if err != nil {
				t.Fatalf("Catalog() error = %v", err)
			}
			if len(comps) != len(wantComponents) {
				t.Fatalf("got %d components, want %d: %+v", len(comps), len(wantComponents), comps)
			}
			for i := range comps {
				if comps[i] != wantComponents[i] {
					t.Errorf("component %d:\n got  %+v\n want %+v", i, comps[i], wantComponents[i])
				}
			}
		})
	}
}

func TestTarballCleanupRemovesTempDir(t *testing.T) {
	path := writeTemp(t, "rootfs.tar", buildTar(t))
	rootfs, cleanup, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open(context.Background(), ) error = %v", err)
	}
	if _, err := rootfs.Open(catalog.DpkgStatusPath); err != nil {
		t.Fatalf("status not readable before cleanup: %v", err)
	}
	cleanup()
	if _, err := rootfs.Open(catalog.DpkgStatusPath); err == nil {
		t.Error("status still readable after cleanup; the temp dir was not removed")
	}
	cleanup() // must be safe twice
}

// Zip-slip and friends: an entry that would write outside the extraction
// directory must be refused, not silently skipped.
func TestTarballRejectsEscapingEntries(t *testing.T) {
	tests := []struct {
		name  string
		entry tar.Header
	}{
		{"parent traversal", tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}},
		{"deep traversal", tar.Header{Name: "var/../../escape", Typeflag: tar.TypeReg, Mode: 0o644}},
		{"absolute path", tar.Header{Name: "/etc/cron.d/backdoor", Typeflag: tar.TypeReg, Mode: 0o644}},
		{"traversing directory", tar.Header{Name: "../outside/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{"hard link out", tar.Header{Name: "inside", Typeflag: tar.TypeLink, Linkname: "../../etc/passwd"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			if err := tw.WriteHeader(&tt.entry); err != nil {
				t.Fatalf("header: %v", err)
			}
			if err := tw.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			path := writeTemp(t, "hostile.tar", buf.Bytes())

			_, cleanup, err := Open(context.Background(), path)
			cleanup()
			if err == nil {
				t.Fatal("Open(context.Background(), ) error = nil, want the entry rejected")
			}
			if !errors.Is(err, ErrUnsafePath) {
				t.Errorf("error %v does not wrap ErrUnsafePath", err)
			}
		})
	}
}

// An absolute symlink is normal in a rootfs and must not fail the scan, but it
// must not be created either — os.DirFS would follow it out to the host.
func TestTarballDropsEscapingSymlinks(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeReg(t, tw, "var/lib/dpkg/status", testStatus)
	writeReg(t, tw, "usr/lib/os-release", testOSRelease)
	for _, link := range []struct{ name, target string }{
		{"etc/shadow", "/etc/shadow"},
		{"etc/escape", "../../../../etc/passwd"},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: link.name, Typeflag: tar.TypeSymlink, Linkname: link.target, Mode: 0o777,
		}); err != nil {
			t.Fatalf("symlink header: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	path := writeTemp(t, "links.tar", buf.Bytes())
	rootfs, cleanup, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open(context.Background(), ) error = %v, want escaping symlinks to be dropped rather than fatal", err)
	}
	defer cleanup()

	for _, name := range []string{"etc/shadow", "etc/escape"} {
		if _, err := rootfs.Open(name); err == nil {
			t.Errorf("%s exists; an escaping symlink must not be created", name)
		}
	}
	// The scan still works.
	comps, err := catalog.NewDpkg().Catalog(rootfs)
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(comps) != 2 {
		t.Errorf("got %d components, want 2", len(comps))
	}
}

// A symlink that stays inside the image is preserved, because rootfs layouts
// depend on them — /etc/os-release is one.
func TestTarballKeepsInternalSymlinks(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeReg(t, tw, "var/lib/dpkg/status", testStatus)
	writeReg(t, tw, "usr/lib/os-release", testOSRelease)
	writeReg(t, tw, "bin/busybox", "BusyBox\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "bin/sh", Typeflag: tar.TypeSymlink, Linkname: "busybox", Mode: 0o777,
	}); err != nil {
		t.Fatalf("symlink header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rootfs, cleanup, err := Open(context.Background(), writeTemp(t, "links.tar", buf.Bytes()))
	if err != nil {
		t.Fatalf("Open(context.Background(), ) error = %v", err)
	}
	defer cleanup()

	body, err := fs.ReadFile(rootfs, "bin/sh")
	if err != nil {
		t.Fatalf("internal symlink not usable: %v", err)
	}
	if string(body) != "BusyBox\n" {
		t.Errorf("bin/sh resolved to %q", body)
	}
}

func TestTarballName(t *testing.T) {
	if got := NewTarball(CompressionNone).Name(); got != "tar" {
		t.Errorf("Name() = %q, want tar", got)
	}
	if got := NewTarball(CompressionZstd).Name(); got != "tar+zstd" {
		t.Errorf("Name() = %q, want tar+zstd", got)
	}
}

func TestTarballCorruptArchive(t *testing.T) {
	// gzip magic with rubbish behind it: the decompressor must fail cleanly.
	path := writeTemp(t, "broken.gz", append([]byte{0x1F, 0x8B}, bytes.Repeat([]byte{0x00}, 64)...))
	if _, _, err := Detect(path); err == nil {
		t.Error("Detect() on a corrupt gzip returned no error")
	}
}

func TestSafeName(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		want    string
		wantErr bool
	}{
		{"plain", "var/lib/dpkg/status", "var/lib/dpkg/status", false},
		{"dot segments that stay inside", "var/./lib/../lib/dpkg", "var/lib/dpkg", false},
		// An archive written from a directory names its own root; that is not
		// an escape, and refusing it would refuse most real tarballs.
		{"the archive root", "./", ".", false},
		{"parent escape", "../etc/passwd", "", true},
		{"absolute", "/etc/passwd", "", true},
		{"deep escape", "a/b/../../../etc", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := safeName(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Fatalf("safeName(%q) error = %v, wantErr %v", tt.entry, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("safeName(%q) = %q, want %q", tt.entry, got, tt.want)
			}
		})
	}
}

// extractInto runs extractTar against a directory, the way Tarball.Open does.
func extractInto(t *testing.T, dir string, archive []byte) error {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%s): %v", dir, err)
	}
	defer func() { _ = root.Close() }()
	budget := &extractBudget{source: int64(len(archive))}
	return extractTar(context.Background(), tar.NewReader(budget.reader(bytes.NewReader(archive))), root, budget)
}

// Extraction bounds. A crafted archive must not be able to fill the disk or
// exhaust inodes (CLAUDE.md rule 9).
func TestExtractBounds(t *testing.T) {
	t.Run("oversized declared entry is refused", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		// A header that lies about a colossal size. Nothing is actually
		// written, so the test stays fast.
		if err := tw.WriteHeader(&tar.Header{
			Name: "huge", Typeflag: tar.TypeReg, Mode: 0o644, Size: maxSingleFile + 1,
		}); err != nil {
			t.Fatalf("header: %v", err)
		}
		// Deliberately not writing the declared body; the size check fires
		// before any read.
		raw := buf.Bytes()

		dir := t.TempDir()
		err := extractInto(t, dir, raw)
		if err == nil {
			t.Fatal("extractTar() error = nil, want the oversized entry refused")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("over the limit")) {
			t.Errorf("error = %v, want it to mention the limit", err)
		}
	})

	t.Run("unsupported entry types are skipped, not fatal", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, typ := range []byte{tar.TypeChar, tar.TypeBlock, tar.TypeFifo} {
			if err := tw.WriteHeader(&tar.Header{
				Name: "dev/x" + string(rune('a'+typ)), Typeflag: typ, Mode: 0o666,
			}); err != nil {
				t.Fatalf("header: %v", err)
			}
		}
		writeReg(t, tw, "var/lib/dpkg/status", testStatus)
		if err := tw.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		dir := t.TempDir()
		if err := extractInto(t, dir, buf.Bytes()); err != nil {
			t.Fatalf("extractTar() error = %v, want device nodes skipped", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "var", "lib", "dpkg", "status")); err != nil {
			t.Errorf("regular file after skipped entries: %v", err)
		}
	})

	t.Run("truncated archive fails cleanly", func(t *testing.T) {
		raw := buildTar(t)
		path := writeTemp(t, "truncated.tar", raw[:len(raw)/2])
		_, cleanup, err := Open(context.Background(), path)
		cleanup()
		if err == nil {
			t.Error("Open(context.Background(), ) on a truncated archive returned no error")
		}
	})
}
