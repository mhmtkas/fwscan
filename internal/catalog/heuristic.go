package catalog

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"

	"github.com/mhmtkas/fwscan/internal/model"
)

// Heuristic finds software that no package database accounts for: a kernel, a
// statically linked busybox, a bare shared library. Firmware is full of it.
//
// Everything this cataloger returns is Confidence: low and carries Evidence
// (CLAUDE.md conventions). A filename is a hint, not a fact — libssl.so.3 says
// the ABI is 3, not which 3.x is installed — and the report separates the two
// so a reader can triage rather than guess.
//
// Low-confidence components deliberately carry no purl, so the matcher does not
// query them. Asking OSV about a version that was inferred from a filename,
// without knowing which distribution it belongs to, reintroduces exactly the
// cross-release false positives the release qualifier exists to prevent
// (spike/NOTES.md T0.3). See open question 5 there.
type Heuristic struct{}

// NewHeuristic returns the heuristic cataloger.
func NewHeuristic() *Heuristic { return &Heuristic{} }

// Name implements Cataloger.
func (Heuristic) Name() string { return "heuristic" }

// Catalog implements Cataloger. Detectors are independent: one finding nothing
// does not stop the others, and a rootfs where none match is not an error.
func (Heuristic) Catalog(ctx context.Context, root fs.FS) ([]model.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var comps []model.Component
	for _, detect := range []func(fs.FS) []model.Component{detectKernel, detectBusybox, detectSharedLibraries} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		comps = append(comps, detect(root)...)
	}

	slices.SortFunc(comps, model.CompareComponents)
	return comps, nil
}

func lowConfidence(name, version, evidence string) model.Component {
	return model.Component{
		Name:       name,
		Version:    version,
		Confidence: model.ConfidenceLow,
		Evidence:   evidence,
	}
}

// kernelModulesDir is where kernel modules live, one directory per version.
const kernelModulesDir = "lib/modules"

// kernelVersion matches a release string like "5.10.0-11-arm64" or "6.1.0-rpi7".
// It must start with a digit; a directory named "extra" is not a kernel.
var kernelVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?[A-Za-z0-9.\-_+]*$`)

// detectKernel reads kernel versions from lib/modules/<version>/ names. This is
// the most reliable heuristic in the set: the directory name is the kernel's
// own release string, put there by the build.
func detectKernel(root fs.FS) []model.Component {
	entries, ok := readDirBounded(root, kernelModulesDir)
	if !ok {
		return nil
	}
	var comps []model.Component
	for _, entry := range entries {
		if !entry.IsDir() || !kernelVersion.MatchString(entry.Name()) {
			continue
		}
		comps = append(comps, lowConfidence(
			"linux-kernel", entry.Name(), path.Join(kernelModulesDir, entry.Name())))
	}
	return comps
}

// busyboxPaths are where a busybox binary is usually found.
var busyboxPaths = []string{
	"bin/busybox",
	"usr/bin/busybox",
	"sbin/busybox",
	"usr/sbin/busybox",
}

// busyboxBanner matches the version string busybox embeds in its own binary.
var busyboxBanner = regexp.MustCompile(`BusyBox v([0-9]+\.[0-9]+\.[0-9]+)`)

// Bounds on what a hostile image can make the detectors do (CLAUDE.md rule 9).
const (
	// maxBinaryScan bounds how much of a binary is searched. The banner sits in
	// the first data pages in practice.
	maxBinaryScan = 8 << 20
	// maxDirEntries bounds a single directory listing. A rootfs with a million
	// files in lib/ is not a rootfs, and fs.ReadDir materialises the whole
	// listing before returning it.
	maxDirEntries = 100_000
)

// readDirBounded lists a directory, refusing one large enough to be an attack
// rather than an image.
func readDirBounded(root fs.FS, dir string) ([]fs.DirEntry, bool) {
	entries, err := fs.ReadDir(root, dir)
	if err != nil || len(entries) > maxDirEntries {
		return nil, false
	}
	return entries, true
}

// detectBusybox reads the version out of the busybox binary's own banner. In
// embedded images busybox is frequently the entire userland and frequently
// unmanaged by any package database, which is why it earns a detector of its
// own.
func detectBusybox(root fs.FS) []model.Component {
	for _, p := range busyboxPaths {
		f, err := root.Open(p)
		if err != nil {
			continue
		}
		version := scanForBanner(f, busyboxBanner)
		_ = f.Close()
		if version != "" {
			return []model.Component{lowConfidence("busybox", version, p)}
		}
	}
	return nil
}

// scanForBanner searches a binary for the first match of re, reading in bounded
// chunks and overlapping them so a match spanning a boundary is not missed.
func scanForBanner(r io.Reader, re *regexp.Regexp) string {
	const chunk = 64 << 10
	overlap := 64

	reader := bufio.NewReaderSize(io.LimitReader(r, maxBinaryScan), chunk)
	var carry []byte
	buf := make([]byte, chunk)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			window := append(carry, buf[:n]...) //nolint:gocritic // carry is intentionally rebuilt
			if m := re.FindSubmatch(window); m != nil {
				return string(m[1])
			}
			if len(window) > overlap {
				carry = slices.Clone(window[len(window)-overlap:])
			} else {
				carry = slices.Clone(window)
			}
		}
		if err != nil {
			return ""
		}
	}
}

// libraryDirs are searched for bare shared libraries.
var libraryDirs = []string{
	"lib",
	"lib64",
	"usr/lib",
	"usr/lib64",
	"lib/x86_64-linux-gnu",
	"lib/aarch64-linux-gnu",
	"lib/arm-linux-gnueabihf",
	"usr/lib/x86_64-linux-gnu",
	"usr/lib/aarch64-linux-gnu",
	"usr/lib/arm-linux-gnueabihf",
}

// libraryPatterns maps a filename shape to the component it implies.
//
// The glibc pattern yields a real version: libc-2.31.so names 2.31 exactly. The
// OpenSSL one does not — libssl.so.3 names the ABI, and every 3.x shares it —
// so what is recorded is the soname, and the low confidence is doing real work.
var libraryPatterns = []struct {
	name    string
	re      *regexp.Regexp
	comment string
}{
	{name: "glibc", re: regexp.MustCompile(`^libc-([0-9]+\.[0-9]+(\.[0-9]+)?)\.so$`)},
	{name: "openssl", re: regexp.MustCompile(`^libssl\.so\.([0-9]+(\.[0-9]+)*)$`)},
	{name: "openssl", re: regexp.MustCompile(`^libcrypto\.so\.([0-9]+(\.[0-9]+)*)$`)},
	{name: "musl", re: regexp.MustCompile(`^libc\.musl-[a-z0-9_]+\.so\.([0-9]+)$`)},
}

// detectSharedLibraries reports libraries whose filenames carry a version.
func detectSharedLibraries(root fs.FS) []model.Component {
	seen := map[string]bool{}
	var comps []model.Component

	for _, dir := range libraryDirs {
		entries, ok := readDirBounded(root, dir)
		if !ok {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			for _, pattern := range libraryPatterns {
				m := pattern.re.FindStringSubmatch(entry.Name())
				if m == nil {
					continue
				}
				key := pattern.name + "@" + m[1]
				if seen[key] {
					break
				}
				seen[key] = true
				comps = append(comps, lowConfidence(pattern.name, m[1], path.Join(dir, entry.Name())))
				break
			}
		}
	}
	return comps
}
