package input

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/catalog"
)

// requireSquashfsTools skips when the host has no squashfs-tools. CI installs
// them, so the matrix below really does run there.
func requireSquashfsTools(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("unsquashfs"); err != nil {
		t.Skip("unsquashfs not installed; run make fixtures notes in CONTRIBUTING.md")
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

			rootfs, cleanup, err := Open(path)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer cleanup()

			comps, err := catalog.NewDpkg().Catalog(rootfs)
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
	rootfs, cleanup, err := Open(path)
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
	_, cleanup, err := Open(path)
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

	_, cleanup, err := Open(path)
	cleanup()
	if err == nil {
		t.Fatal("Open() on a corrupt image returned no error")
	}
	if strings.Count(err.Error(), "\n") > 0 {
		t.Errorf("error spans multiple lines: %q", err)
	}
}

func TestSquashFSName(t *testing.T) {
	if got := NewSquashFS().Name(); got != "squashfs" {
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
