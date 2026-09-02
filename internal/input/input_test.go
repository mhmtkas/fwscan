package input

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/catalog"
	"github.com/mhmtkas/fwscan/internal/model"
)

// writeRootfs lays out a minimal Debian rootfs on disk and returns its path.
func writeRootfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"var/lib/dpkg/status": "Package: openssl\n" +
			"Status: install ok installed\n" +
			"Architecture: amd64\n" +
			"Version: 1.1.1k-1+deb11u2\n" +
			"Source: openssl\n" +
			"Description: toolkit\n" +
			" continuation line\n" +
			"\n" +
			"Package: removed\n" +
			"Status: deinstall ok config-files\n" +
			"Architecture: amd64\n" +
			"Version: 9.9-1\n",
		"usr/lib/os-release": "ID=debian\nVERSION_CODENAME=bullseye\n",
	}
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

// The point of the fs.FS seam: a directory on disk must catalog to exactly what
// an in-memory filesystem with the same content catalogs to.
func TestDirectoryCatalogsLikeMapFS(t *testing.T) {
	root := writeRootfs(t)

	rootfs, cleanup, err := Open(context.Background(), root)
	if err != nil {
		t.Fatalf("Open(context.Background(), ) error = %v", err)
	}
	defer cleanup()

	comps, err := catalog.NewDpkg().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}

	want := []model.Component{{
		Name: "openssl", Version: "1.1.1k-1+deb11u2", Arch: "amd64",
		Source: "openssl", SourceVersion: "1.1.1k-1+deb11u2", Distro: "bullseye",
		PURL:       "pkg:deb/debian/openssl@1.1.1k-1%2Bdeb11u2?arch=amd64&distro=bullseye",
		Confidence: model.ConfidenceHigh, Evidence: catalog.DpkgStatusPath,
	}}
	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	if comps[0] != want[0] {
		t.Errorf("component:\n got  %+v\n want %+v", comps[0], want[0])
	}
}

func TestOpenCleanupIsNoopForDirectories(t *testing.T) {
	root := writeRootfs(t)
	_, cleanup, err := Open(context.Background(), root)
	if err != nil {
		t.Fatalf("Open(context.Background(), ) error = %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup is nil; callers defer it unconditionally")
	}
	// A no-op cleanup must leave the user's own directory alone, and must be
	// safe to call more than once.
	cleanup()
	cleanup()
	if _, err := os.Stat(filepath.Join(root, "var", "lib", "dpkg", "status")); err != nil {
		t.Errorf("cleanup removed something from the source directory: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "image.bin")
	if err := os.WriteFile(regular, []byte("not a rootfs"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		wantErrIs  error
		wantSubstr string
	}{
		{"missing path", filepath.Join(t.TempDir(), "nope"), nil, "no such path"},
		{"unrecognised file", regular, ErrUnsupportedFormat, "unsupported format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup, err := Open(context.Background(), tt.path)
			if cleanup == nil {
				t.Fatal("cleanup is nil on the error path")
			}
			cleanup()
			if err == nil {
				t.Fatal("Open(context.Background(), ) error = nil, want an error")
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("error %v does not wrap %v", err, tt.wantErrIs)
			}
			if got := err.Error(); tt.wantSubstr != "" && !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("error = %q, want it to mention %q", got, tt.wantSubstr)
			}
			if got := err.Error(); got != "" && got[0] >= 'A' && got[0] <= 'Z' {
				t.Errorf("error %q starts uppercase; user-facing errors are lowercase", got)
			}
		})
	}
}

func TestDirOpenRejectsNonDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := NewDir().Open(context.Background(), file); err == nil {
		t.Error("Dir.Open() on a regular file returned no error")
	}
	if _, _, err := NewDir().Open(context.Background(), filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("Dir.Open() on a missing path returned no error")
	}
	if got := NewDir().Name(); got != "directory" {
		t.Errorf("Name() = %q, want directory", got)
	}
}

// os.DirFS confines reads to the root, so a cataloger cannot be walked out of
// the image by a crafted path.
func TestDirFSConfinesReads(t *testing.T) {
	root := writeRootfs(t)
	rootfs, cleanup, err := Open(context.Background(), root)
	if err != nil {
		t.Fatalf("Open(context.Background(), ) error = %v", err)
	}
	defer cleanup()

	for _, escape := range []string{"../etc/passwd", "/etc/passwd", "var/../../etc/passwd"} {
		if _, err := rootfs.Open(escape); err == nil {
			t.Errorf("opening %q succeeded; reads must be confined to the image", escape)
		}
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "image.bin")
	if err := os.WriteFile(file, []byte("xxxx"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := []struct {
		name            string
		path            string
		wantFormat      Format
		wantCompression Compression
		wantErr         bool
	}{
		{"directory", dir, FormatDirectory, CompressionNone, false},
		{"regular file is not yet recognised", file, FormatUnknown, CompressionNone, false},
		{"missing", filepath.Join(dir, "absent"), FormatUnknown, CompressionNone, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, compression, err := Detect(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Detect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if format != tt.wantFormat || compression != tt.wantCompression {
				t.Errorf("Detect() = (%s, %s), want (%s, %s)", format, compression, tt.wantFormat, tt.wantCompression)
			}
		})
	}
}

func TestFormatAndCompressionStrings(t *testing.T) {
	// These strings reach the user in the terminal header, so they are part of
	// the output format rather than internal names.
	if got := FormatSquashFS.String(); got != "squashfs" {
		t.Errorf("FormatSquashFS = %q", got)
	}
	if got := CompressionZstd.String(); got != "zstd" {
		t.Errorf("CompressionZstd = %q", got)
	}
	if got := CompressionNone.String(); got != "none" {
		t.Errorf("CompressionNone = %q", got)
	}
}
