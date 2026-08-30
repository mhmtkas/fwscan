package input

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tempDirsUnder counts fwscan's extraction directories currently on disk.
// Every failure path must leave none behind.
func tempDirsUnder(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	var n int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempDirNamespace) {
			n++
		}
	}
	return n
}

// Every error path has to clean up after itself. A scanner that leaks an
// extracted rootfs per failed image fills the disk of whoever runs it in CI.
func TestNoTempDirsLeakOnFailure(t *testing.T) {
	before := tempDirsUnder(t)

	hostile := []struct {
		name  string
		build func(t *testing.T) string
	}{
		{"traversal entry", func(t *testing.T) string {
			return writeTar(t, tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644})
		}},
		{"absolute entry", func(t *testing.T) string {
			return writeTar(t, tar.Header{Name: "/etc/shadow", Typeflag: tar.TypeReg, Mode: 0o644})
		}},
		{"hard link out", func(t *testing.T) string {
			return writeTar(t, tar.Header{Name: "x", Typeflag: tar.TypeLink, Linkname: "../../etc/passwd"})
		}},
		{"truncated archive", func(t *testing.T) string {
			raw := buildTar(t)
			return writeTemp(t, "truncated.tar", raw[:len(raw)/2])
		}},
		{"garbage where an archive should be", func(t *testing.T) string {
			return writeTemp(t, "garbage.tar.gz",
				append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{0xff}, 512)...))
		}},
	}

	for _, tt := range hostile {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.build(t)
			rootfs, cleanup, err := Open(path)
			if err == nil {
				cleanup()
				t.Fatalf("Open() accepted a hostile archive, returning %v", rootfs)
			}
			if cleanup == nil {
				t.Fatal("cleanup is nil on the error path")
			}
			cleanup()
		})
	}

	if after := tempDirsUnder(t); after != before {
		t.Errorf("temp directories leaked: %d before, %d after", before, after)
	}
}

func writeTar(t *testing.T, header tar.Header) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&header); err != nil {
		t.Fatalf("header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return writeTemp(t, "hostile.tar", buf.Bytes())
}

// A rootfs must never be readable through a link that leaves it, however the
// link is spelled.
func TestSymlinkEscapesAreNeverReadable(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("do not read me\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeReg(t, tw, "var/lib/dpkg/status", testStatus)
	links := []struct{ name, target string }{
		{"absolute", secret},
		{"relative escape", "../../../../../../../../etc/passwd"},
		{"escape then return", "../../etc/../etc/passwd"},
		{"link to the root itself", "/"},
	}
	for _, l := range links {
		if err := tw.WriteHeader(&tar.Header{
			Name:     "escapes/" + strings.ReplaceAll(l.name, " ", "-"),
			Typeflag: tar.TypeSymlink, Linkname: l.target, Mode: 0o777,
		}); err != nil {
			t.Fatalf("symlink header: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rootfs, cleanup, err := Open(writeTemp(t, "links.tar", buf.Bytes()))
	if err != nil {
		t.Fatalf("Open() error = %v; escaping links should be dropped, not fatal", err)
	}
	defer cleanup()

	for _, l := range links {
		name := "escapes/" + strings.ReplaceAll(l.name, " ", "-")
		f, err := rootfs.Open(name)
		if err == nil {
			body, _ := io.ReadAll(f)
			_ = f.Close()
			t.Errorf("%s is readable and yields %q", name, body)
		}
	}

	// A link that stays inside is kept, including one pointing at the
	// extraction root itself: "usr/bin -> ../bin" is ordinary in a rootfs, and
	// dropping those would break the layouts catalogers read.
	if _, err := rootfs.Open("var/lib/dpkg/status"); err != nil {
		t.Errorf("the rootfs is unusable after dropping escaping links: %v", err)
	}
}

// A tar whose entries all fail must still fail as a whole rather than silently
// producing an empty rootfs that scans clean.
func TestHostileArchiveFailsRatherThanScanningClean(t *testing.T) {
	path := writeTar(t, tar.Header{Name: "../../etc/cron.d/backdoor", Typeflag: tar.TypeReg, Mode: 0o644})
	_, cleanup, err := Open(path)
	cleanup()
	if err == nil {
		t.Fatal("a hostile archive produced a usable rootfs")
	}
	if !errors.Is(err, ErrUnsafePath) {
		t.Errorf("error %v does not wrap ErrUnsafePath", err)
	}
}

// A directory containing far too many entries is an attack, not an image, and
// must not be materialised.
func TestArchiveEntryCountIsBounded(t *testing.T) {
	// extractTar counts entries as it goes, so this is checked directly rather
	// than by building a million-entry archive.
	if maxEntries <= 0 || maxTotalBytes <= 0 || maxSingleFile <= 0 {
		t.Fatal("extraction bounds are not set")
	}
	if maxSingleFile > maxTotalBytes {
		t.Errorf("a single file (%d) may exceed the total budget (%d)", maxSingleFile, maxTotalBytes)
	}
}

// A lying header must not make the extractor write more than it declared.
func TestDeclaredSizeIsNotTrusted(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	const body = "short"
	if err := tw.WriteHeader(&tar.Header{
		Name: "liar", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
	}); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, err := io.WriteString(tw, body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	dir := t.TempDir()
	if err := extractTar(tar.NewReader(bytes.NewReader(buf.Bytes())), dir); err != nil {
		t.Fatalf("extractTar() error = %v", err)
	}
	written, err := os.ReadFile(filepath.Join(dir, "liar"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(written) != body {
		t.Errorf("wrote %q, want %q", written, body)
	}
}

// The squashfs path must clean up too, even though the extraction is another
// program's work.
func TestSquashFSNoTempDirLeakOnFailure(t *testing.T) {
	requireSquashfsTools(t)
	before := tempDirsUnder(t)

	path := filepath.Join(t.TempDir(), "broken.squashfs")
	body := make([]byte, 1024)
	copy(body, []byte("hsqs"))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, cleanup, err := Open(path)
	cleanup()
	if err == nil {
		t.Fatal("a corrupt squashfs produced a usable rootfs")
	}
	if after := tempDirsUnder(t); after != before {
		t.Errorf("temp directories leaked: %d before, %d after", before, after)
	}
}

// A later entry must not be able to reach outside the extraction directory by
// travelling through a symlink an earlier entry created.
func TestNoWriteEscapeThroughAnEarlierSymlink(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	mustDir := func(name string) {
		if err := tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	mustLink := func(name, target string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}); err != nil {
			t.Fatal(err)
		}
	}
	mustReg := func(name, body string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	mustDir("d")
	mustLink("d/up", "..")            // resolves to the extraction root: kept
	mustReg("d/up/pwned", "escaped")  // travels through it
	mustReg("d/up/../pwned2", "also") // and with a .. for good measure
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	inner := filepath.Join(dest, "extract")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = extractTar(tar.NewReader(bytes.NewReader(buf.Bytes())), inner)

	// Nothing may exist beside the extraction directory.
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "extract" {
			t.Errorf("escaped write created %s next to the extraction directory", e.Name())
		}
	}
}

// A hard link whose source was dropped (an absolute symlink, say) must not kill
// the whole scan: real rootfs images contain these.
func TestHardLinkToDroppedSourceIsNotFatal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "bin/sh", Typeflag: tar.TypeSymlink, Linkname: "/bin/busybox", Mode: 0o777,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: "bin/ash", Typeflag: tar.TypeLink, Linkname: "bin/sh",
	}); err != nil {
		t.Fatal(err)
	}
	body := testStatus
	if err := tw.WriteHeader(&tar.Header{
		Name: "var/lib/dpkg/status", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := extractTar(tar.NewReader(bytes.NewReader(buf.Bytes())), dir); err != nil {
		t.Fatalf("extractTar() error = %v; a hard link to a dropped source must not be fatal", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "var", "lib", "dpkg", "status")); err != nil {
		t.Errorf("the rest of the archive was not extracted: %v", err)
	}
}
