package input

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// isolateTempRoot points extraction at a directory only this test uses, and
// returns a function counting the extraction directories inside it.
//
// Counting os.TempDir() directly does not work: `go test ./...` runs package
// binaries in parallel, and internal/cli's end-to-end tests run the real fwscan
// binary, which creates and removes extraction directories in the same place.
// The count then reflects another package's timing rather than this test's
// behaviour.
func isolateTempRoot(t *testing.T) func() int {
	t.Helper()
	dir := t.TempDir()
	previous := tempRoot
	tempRoot = dir
	t.Cleanup(func() { tempRoot = previous })

	return func() int {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read temp root: %v", err)
		}
		var n int
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), tempDirNamespace) {
				n++
			}
		}
		return n
	}
}

// Every error path has to clean up after itself. A scanner that leaks an
// extracted rootfs per failed image fills the disk of whoever runs it in CI.
func TestNoTempDirsLeakOnFailure(t *testing.T) {
	count := isolateTempRoot(t)
	before := count()

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
			rootfs, cleanup, err := Open(context.Background(), path)
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

	if after := count(); after != before {
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

	rootfs, cleanup, err := Open(context.Background(), writeTemp(t, "links.tar", buf.Bytes()))
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
	_, cleanup, err := Open(context.Background(), path)
	cleanup()
	if err == nil {
		t.Fatal("a hostile archive produced a usable rootfs")
	}
	if !errors.Is(err, ErrUnsafePath) {
		t.Errorf("error %v does not wrap ErrUnsafePath", err)
	}
}

// A decompression bomb is a few hundred bytes that unpack to gigabytes. The
// absolute cap does not stop one on its own -- the cost is entirely on the
// defender, and the extraction directory is a tmpfs on most systems, so the
// bytes land in memory.
func TestDecompressionBombIsRefused(t *testing.T) {
	// Lowered so the test can build a bomb in memory rather than on the disk
	// it is protecting. The shape is what matters, not the scale.
	restore := func(ratio, floor int64) func() {
		return func() { maxExpansionRatio, minExpansionBytes = ratio, floor }
	}(maxExpansionRatio, minExpansionBytes)
	t.Cleanup(restore)
	maxExpansionRatio, minExpansionBytes = 20, 4<<10

	var tarred bytes.Buffer
	tw := tar.NewWriter(&tarred)
	const body = 1 << 20 // a megabyte of zeros, which gzip reduces to almost nothing
	if err := tw.WriteHeader(&tar.Header{
		Name: "payload", Typeflag: tar.TypeReg, Mode: 0o644, Size: body,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(tw, io.LimitReader(zeroReader{}, body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var bomb bytes.Buffer
	zw := gzip.NewWriter(&bomb)
	if _, err := zw.Write(tarred.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	ratio := int64(tarred.Len()) / int64(bomb.Len())
	if ratio <= maxExpansionRatio {
		t.Fatalf("the fixture only expands %dx, which is inside the limit; it does not test the guard", ratio)
	}

	_, cleanup, err := Open(context.Background(), writeTemp(t, "bomb.tar.gz", bomb.Bytes()))
	cleanup()
	if err == nil {
		t.Fatal("a decompression bomb unpacked without complaint")
	}
	if !errors.Is(err, ErrDecompressionBomb) {
		t.Errorf("error %v does not wrap ErrDecompressionBomb", err)
	}
}

// An archive does not have to compress at all to amplify. The tar reader
// expands a GNU sparse entry to its declared length, so the bytes never travel
// through the stream and a guard that watches only the stream never sees them.
func TestSparseEntryExpansionIsBounded(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar not installed; needed to build a sparse archive")
	}

	dir := t.TempDir()
	sparse := filepath.Join(dir, "big")
	// truncate makes a file that is all holes: 200 MiB of nothing.
	if err := os.Truncate(mustCreate(t, sparse), 200<<20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	// posix format on purpose. GNU's own sparse format arrives with typeflag
	// 'S', which this extractor skips like any other entry type it has no use
	// for; the posix encoding arrives as an ordinary regular file whose holes
	// the reader fills in, so it is the shape that can actually amplify.
	archive := filepath.Join(dir, "sparse.tar")
	cmd := exec.Command("tar", "--sparse", "--format=posix", "-cf", archive, "-C", dir, "big")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("tar --sparse unavailable here: %v: %s", err, out)
	}

	info, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 1<<20 {
		t.Skipf("tar did not store the file sparsely (archive is %d bytes)", info.Size())
	}

	restore := func(ratio, floor int64) func() {
		return func() { maxExpansionRatio, minExpansionBytes = ratio, floor }
	}(maxExpansionRatio, minExpansionBytes)
	t.Cleanup(restore)
	maxExpansionRatio, minExpansionBytes = 20, 4<<10

	_, cleanup, err := Open(context.Background(), archive)
	cleanup()
	if err == nil {
		t.Fatalf("a %d byte archive expanded to 200 MiB without complaint", info.Size())
	}
	if !errors.Is(err, ErrDecompressionBomb) {
		t.Errorf("error %v does not wrap ErrDecompressionBomb", err)
	}
}

func mustCreate(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// The ratio is a bound on hostile input, not on real images: firmware that
// carries a zero-filled partition compresses enormously and honestly.
func TestOrdinaryImagesDoNotTripTheExpansionGuard(t *testing.T) {
	for _, name := range []string{"mini-rootfs.tar.gz", "alpine-rootfs.tar.gz"} {
		t.Run(name, func(t *testing.T) {
			_, cleanup, err := Open(context.Background(), filepath.Join("..", "..", "testdata", "images", name))
			defer cleanup()
			if err != nil {
				t.Errorf("Open() error = %v; a committed fixture must not trip the expansion guard", err)
			}
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// An archive holding far too many entries is an attack on the filesystem's
// inodes rather than an image, and must not be materialised.
//
// This used to assert that three constants were positive and that one was
// smaller than another, which passes with the counter deleted from extractTar
// altogether. The bound is lowered instead so the archive that crosses it is
// small enough for a test to build.
func TestArchiveEntryCountIsBounded(t *testing.T) {
	restore := maxEntries
	t.Cleanup(func() { maxEntries = restore })
	maxEntries = 16

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range maxEntries + 4 {
		if err := tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("f%03d", i), Typeflag: tar.TypeReg, Mode: 0o644,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	err := extractInto(t, dir, buf.Bytes())
	if err == nil {
		t.Fatal("an archive past the entry limit extracted without complaint")
	}
	if !strings.Contains(err.Error(), "files and directories") {
		t.Errorf("error = %v, want it to name the object limit", err)
	}

	// The extraction stops where the bound is, rather than after finishing.
	written, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) > maxEntries {
		t.Errorf("%d files were written past a limit of %d", len(written), maxEntries)
	}

	// And an archive inside the limit is untouched by it.
	if err := extractInto(t, t.TempDir(), buf.Bytes()[:0]); err != nil {
		t.Errorf("an empty archive was refused: %v", err)
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
	if err := extractInto(t, dir, buf.Bytes()); err != nil {
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
	count := isolateTempRoot(t)
	before := count()

	path := filepath.Join(t.TempDir(), "broken.squashfs")
	body := make([]byte, 1024)
	copy(body, []byte("hsqs"))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, cleanup, err := Open(context.Background(), path)
	cleanup()
	if err == nil {
		t.Fatal("a corrupt squashfs produced a usable rootfs")
	}
	if after := count(); after != before {
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

	// One hop is what a lexical check can see. Two hops is what it cannot: each
	// link resolves through the one before it, so the chain climbs a directory
	// per step while every step still reads as inside. "chain/b" resolves to
	// "chain/a/.." -> the extraction root's parent.
	mustDir("chain")
	mustLink("chain/a", "..")
	mustLink("chain/b", "a/..")
	mustReg("chain/b/pwned3", "two hops")
	mustReg("chain/b/etc/pwned4", "two hops and a directory")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	inner := filepath.Join(dest, "extract")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = extractInto(t, inner, buf.Bytes())

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

// The input README recommends most is a directory, because binwalk -e produces
// one, so it is the input most likely to be a tree the user did not build. A
// symlink in it must not read the host: os.DirFS only rejects a path that spells
// its way out, and hands what survives to the operating system, which follows
// the link wherever it points.
func TestDirectoryInputCannotReadThroughASymlink(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("HOST-FILE-LEAKED\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The absolute link a crafted image would carry, aimed at a real host file.
	if err := os.Symlink(secret, filepath.Join(root, "var", "lib", "dpkg", "status")); err != nil {
		t.Fatal(err)
	}
	// And the chain that no lexical check can see, aimed at the same file.
	if err := os.MkdirAll(filepath.Join(root, "chain"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(root, "chain", "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a/..", filepath.Join(root, "chain", "b")); err != nil {
		t.Fatal(err)
	}

	rootfs, cleanup, err := Open(context.Background(), root)
	if err != nil {
		t.Fatalf("Open() error = %v; a directory holding an escaping link is still scannable", err)
	}
	defer cleanup()

	for _, name := range []string{"var/lib/dpkg/status", "chain/b", "chain/b/secret"} {
		f, err := rootfs.Open(name)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(f)
		_ = f.Close()
		t.Errorf("%s is readable and yields %q; reads must not leave the image", name, body)
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
	if err := extractInto(t, dir, buf.Bytes()); err != nil {
		t.Fatalf("extractTar() error = %v; a hard link to a dropped source must not be fatal", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "var", "lib", "dpkg", "status")); err != nil {
		t.Errorf("the rest of the archive was not extracted: %v", err)
	}
}

// An interrupted scan must stop, and must not leave an extracted rootfs behind.
// Extraction is the only part of fwscan that writes gigabytes, so it is the one
// place where not honouring a cancellation is expensive.
func TestExtractionStopsWhenTheContextIsCancelled(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range 64 {
		body := strings.Repeat("x", 1024)
		if err := tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("f%03d", i), Typeflag: tar.TypeReg,
			Mode: 0o644, Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	budget := &extractBudget{source: int64(buf.Len())}
	err = extractTar(ctx, tar.NewReader(budget.reader(bytes.NewReader(buf.Bytes()))), root, budget)
	if err == nil {
		t.Fatal("extraction ran to completion under a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not wrap context.Canceled", err)
	}

	written, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 0 {
		t.Errorf("%d files were written after cancellation", len(written))
	}
}

// The cleanup a caller is handed has to be safe on both paths, because a
// cancelled scan runs it from the cancellation and again on the way out.
func TestCleanupIsSafeToCallTwice(t *testing.T) {
	count := isolateTempRoot(t)
	before := count()

	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	_, cleanup, err := Open(context.Background(), image)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	cleanup()
	cleanup()
	if after := count(); after != before {
		t.Errorf("%d extraction directories left behind", after-before)
	}
}

// An xz stream declares its own dictionary size and the decoder allocates all
// of it before producing a byte, so a 180-byte file could cost 1.5 GiB of
// memory -- during detection, before any budget existed to notice.
func TestXZDictionaryIsBounded(t *testing.T) {
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz not installed; needed to build a stream declaring a large dictionary")
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "small.tar")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeReg(t, tw, "var/lib/dpkg/status", testStatus)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	// Well past the cap, and still a file of a few hundred bytes.
	cmd := exec.Command("xz", "-k", "-f", "--lzma2=dict=512MiB", plain)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("xz could not build the stream: %v: %s", err, out)
	}
	bomb := plain + ".xz"

	// Detection alone must not pay for the dictionary.
	if _, _, err := Detect(bomb); err == nil {
		t.Error("Detect() accepted a stream declaring a 512 MiB dictionary")
	}
	_, cleanup, err := Open(context.Background(), bomb)
	cleanup()
	if err == nil {
		t.Fatal("a stream declaring a 512 MiB dictionary was decompressed")
	}

	// The dictionary is declared per block, and a file may hold several
	// streams back to back, so a declaration in the last block of the last
	// stream must be found too.
	cmd = exec.Command("xz", "-k", "-f", "-9", plain)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("xz: %v: %s", err, out)
	}
	good, err := os.ReadFile(bomb)
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("xz", "-k", "-f", "--lzma2=dict=512MiB", plain)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("xz: %v: %s", err, out)
	}
	bad, err := os.ReadFile(bomb)
	if err != nil {
		t.Fatal(err)
	}
	concatenated := filepath.Join(dir, "two.tar.xz")
	if err := os.WriteFile(concatenated, append(append([]byte{}, good...), bad...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, cleanup, err := Open(context.Background(), concatenated); err == nil {
		cleanup()
		t.Error("a large dictionary in the second of two streams was not found")
	} else {
		cleanup()
		if !errors.Is(err, ErrXZDictionary) {
			t.Errorf("error %v does not wrap ErrXZDictionary", err)
		}
	}

	// And an ordinary xz archive still works, including a multi-block one.
	if err := os.WriteFile(bomb, good, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, cleanup, err := Open(context.Background(), bomb); err != nil {
		cleanup()
		t.Fatalf("an xz -9 archive was refused: %v", err)
	} else {
		cleanup()
	}
	cmd = exec.Command("xz", "-k", "-f", "-T2", "--block-size=512", plain)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("xz: %v: %s", err, out)
	}
	if _, cleanup, err := Open(context.Background(), bomb); err != nil {
		cleanup()
		t.Fatalf("a multi-block xz archive was refused: %v", err)
	} else {
		cleanup()
	}
}

// One entry with a very deep name creates a directory per level, and every
// entry beneath a deep prefix makes the kernel re-resolve all of it: a 10 KB
// archive made 200,000 directories and took half a minute doing so.
func TestPathDepthIsBounded(t *testing.T) {
	deep := strings.Repeat("d/", maxPathDepth+1) + "f"
	if _, err := safeName(deep); err == nil {
		t.Errorf("a %d-level path was accepted", maxPathDepth+1)
	}
	if _, err := safeName(strings.Repeat("d/", maxPathDepth-1) + "f"); err != nil {
		t.Errorf("a %d-level path was refused: %v", maxPathDepth, err)
	}

	// Path components count against the object budget, since each is a
	// directory to create.
	restore := maxEntries
	t.Cleanup(func() { maxEntries = restore })
	maxEntries = 64

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range 4 {
		if err := tw.WriteHeader(&tar.Header{
			Name: strings.Repeat("d/", 20) + fmt.Sprintf("f%d", i), Typeflag: tar.TypeReg, Mode: 0o644,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractInto(t, t.TempDir(), buf.Bytes()); err == nil {
		t.Error("four entries implying 84 objects extracted under a budget of 64")
	}
}
