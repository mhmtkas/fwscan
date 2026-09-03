package catalog

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

// statusFS builds a rootfs containing just a dpkg database, plus an os-release
// naming the given codename when one is supplied.
func statusFS(status, codename string) fstest.MapFS {
	m := fstest.MapFS{DpkgStatusPath: &fstest.MapFile{Data: []byte(status)}}
	if codename != "" {
		m["usr/lib/os-release"] = &fstest.MapFile{
			Data: []byte("PRETTY_NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_CODENAME=" + codename + "\n"),
		}
	}
	return m
}

func TestDpkgCatalog(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		codename string
		want     []model.Component
	}{
		{
			name:     "normal stanza",
			codename: "bookworm",
			status: "Package: openssl\n" +
				"Status: install ok installed\n" +
				"Architecture: amd64\n" +
				"Version: 3.0.11-1~deb12u2\n" +
				"Description: Secure Sockets Layer toolkit\n",
			want: []model.Component{{
				Name: "openssl", Version: "3.0.11-1~deb12u2", Arch: "amd64",
				Source: "openssl", SourceVersion: "3.0.11-1~deb12u2", DistroID: "debian", DistroBase: "debian", Distro: "bookworm",
				PURL:       "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=bookworm",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name:     "multi-line Description cannot smuggle a package",
			codename: "bookworm",
			status: "Package: real-pkg\n" +
				"Status: install ok installed\n" +
				"Architecture: amd64\n" +
				"Version: 1.0-1\n" +
				"Description: first line\n" +
				" Package: decoy\n" +
				" Status: install ok installed\n" +
				" .\n" +
				" still the description\n",
			want: []model.Component{{
				Name: "real-pkg", Version: "1.0-1", Arch: "amd64",
				Source: "real-pkg", SourceVersion: "1.0-1", DistroID: "debian", DistroBase: "debian", Distro: "bookworm",
				PURL:       "pkg:deb/debian/real-pkg@1.0-1?arch=amd64&distro=bookworm",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name:     "not-installed packages are excluded",
			codename: "bullseye",
			status: "Package: gone\n" +
				"Status: deinstall ok config-files\n" +
				"Architecture: amd64\n" +
				"Version: 9.9-1\n" +
				"\n" +
				"Package: broken\n" +
				"Status: install ok half-installed\n" +
				"Architecture: amd64\n" +
				"Version: 8.8-1\n" +
				"\n" +
				"Package: present\n" +
				"Status: install ok installed\n" +
				"Architecture: amd64\n" +
				"Version: 1.0-1\n",
			want: []model.Component{{
				Name: "present", Version: "1.0-1", Arch: "amd64",
				Source: "present", SourceVersion: "1.0-1", DistroID: "debian", DistroBase: "debian", Distro: "bullseye",
				PURL:       "pkg:deb/debian/present@1.0-1?arch=amd64&distro=bullseye",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name:     "epoch version is preserved and percent-encoded in the purl",
			codename: "bullseye",
			status: "Package: zlib1g\n" +
				"Status: install ok installed\n" +
				"Architecture: amd64\n" +
				"Source: zlib\n" +
				"Version: 1:1.2.11.dfsg-2\n",
			want: []model.Component{{
				Name: "zlib1g", Version: "1:1.2.11.dfsg-2", Arch: "amd64",
				Source: "zlib", SourceVersion: "1:1.2.11.dfsg-2", DistroID: "debian", DistroBase: "debian", Distro: "bullseye",
				PURL:       "pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2?arch=amd64&distro=bullseye",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name:     "Source with a version overrides the binary version",
			codename: "bullseye",
			status: "Package: bsdutils\n" +
				"Status: install ok installed\n" +
				"Architecture: amd64\n" +
				"Source: util-linux (2.36.1-8+deb11u1)\n" +
				"Version: 1:2.36.1-8+deb11u1\n",
			want: []model.Component{{
				Name: "bsdutils", Version: "1:2.36.1-8+deb11u1", Arch: "amd64",
				Source: "util-linux", SourceVersion: "2.36.1-8+deb11u1", DistroID: "debian", DistroBase: "debian", Distro: "bullseye",
				PURL:       "pkg:deb/debian/bsdutils@1:2.36.1-8%2Bdeb11u1?arch=amd64&distro=bullseye",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name:     "arch all is carried through as a qualifier",
			codename: "bookworm",
			status: "Package: tzdata\n" +
				"Status: install ok installed\n" +
				"Architecture: all\n" +
				"Version: 2026b-0+deb12u1\n",
			want: []model.Component{{
				Name: "tzdata", Version: "2026b-0+deb12u1", Arch: "all",
				Source: "tzdata", SourceVersion: "2026b-0+deb12u1", DistroID: "debian", DistroBase: "debian", Distro: "bookworm",
				PURL:       "pkg:deb/debian/tzdata@2026b-0%2Bdeb12u1?arch=all&distro=bookworm",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name: "no os-release means no distro qualifier",
			status: "Package: busybox\n" +
				"Status: install ok installed\n" +
				"Architecture: arm64\n" +
				"Version: 1.30.1-6\n",
			want: []model.Component{{
				Name: "busybox", Version: "1.30.1-6", Arch: "arm64",
				Source: "busybox", SourceVersion: "1.30.1-6",
				PURL:       "pkg:deb/debian/busybox@1.30.1-6?arch=arm64",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name:     "malformed lines are skipped, not fatal",
			codename: "bookworm",
			status: "this line has no colon\n" +
				"Package: survivor\n" +
				"Status: install ok installed\n" +
				"Architecture: amd64\n" +
				"Version: 1.0\n",
			want: []model.Component{{
				Name: "survivor", Version: "1.0", Arch: "amd64",
				Source: "survivor", SourceVersion: "1.0", DistroID: "debian", DistroBase: "debian", Distro: "bookworm",
				PURL:       "pkg:deb/debian/survivor@1.0?arch=amd64&distro=bookworm",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
		{
			name:     "stanza without a trailing blank line is still flushed",
			codename: "bookworm",
			status:   "Package: last\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.0",
			want: []model.Component{{
				Name: "last", Version: "2.0", Arch: "amd64",
				Source: "last", SourceVersion: "2.0", DistroID: "debian", DistroBase: "debian", Distro: "bookworm",
				PURL:       "pkg:deb/debian/last@2.0?arch=amd64&distro=bookworm",
				Confidence: model.ConfidenceHigh, Evidence: DpkgStatusPath,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDpkg().Catalog(context.Background(), statusFS(tt.status, tt.codename))
			if err != nil {
				t.Fatalf("Catalog() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d components, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("component %d:\n got  %+v\n want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDpkgCatalogNoDatabase(t *testing.T) {
	// An image without dpkg is not an error; it is an image without dpkg.
	got, err := NewDpkg().Catalog(context.Background(), fstest.MapFS{"etc/hostname": &fstest.MapFile{Data: []byte("box\n")}})
	if err != nil {
		t.Fatalf("Catalog() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d components, want 0", len(got))
	}
}

func TestDpkgName(t *testing.T) {
	if got := NewDpkg().Name(); got != "dpkg" {
		t.Errorf("Name() = %q, want %q", got, "dpkg")
	}
}

// TestDpkgRealFixture parses the committed bookworm database. The expected
// count is the one dpkg-query itself produced in spike/NOTES.md T0.2.
func TestDpkgRealFixture(t *testing.T) {
	const wantPackages = 88

	status, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dpkg-status", "bookworm-slim-status"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	osRelease, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dpkg-status", "bookworm-slim-os-release"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	root := fstest.MapFS{
		DpkgStatusPath:       &fstest.MapFile{Data: status},
		"usr/lib/os-release": &fstest.MapFile{Data: osRelease},
	}
	comps, err := NewDpkg().Catalog(context.Background(), root)
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(comps) != wantPackages {
		t.Fatalf("got %d packages, want %d", len(comps), wantPackages)
	}

	for _, c := range comps {
		if c.Confidence != model.ConfidenceHigh {
			t.Errorf("%s: confidence = %q, want high", c.Name, c.Confidence)
		}
		if c.Evidence != DpkgStatusPath {
			t.Errorf("%s: evidence = %q, want %q", c.Name, c.Evidence, DpkgStatusPath)
		}
		if c.Distro != "bookworm" {
			t.Errorf("%s: distro = %q, want bookworm", c.Name, c.Distro)
		}
		if c.Name == "" || c.Version == "" || c.PURL == "" {
			t.Errorf("incomplete component: %+v", c)
		}
		if strings.Contains(c.PURL, "+") {
			t.Errorf("%s: purl has a literal '+', want it percent-encoded: %s", c.Name, c.PURL)
		}
	}

	// bsdutils is the epoch-vs-source case the spike surfaced.
	var bsdutils *model.Component
	for i := range comps {
		if comps[i].Name == "bsdutils" {
			bsdutils = &comps[i]
		}
	}
	if bsdutils == nil {
		t.Fatal("bsdutils not found in the fixture")
	}
	if bsdutils.Source != "util-linux" {
		t.Errorf("bsdutils source = %q, want util-linux", bsdutils.Source)
	}
	if strings.HasPrefix(bsdutils.SourceVersion, "1:") {
		t.Errorf("bsdutils source version %q kept the binary's epoch", bsdutils.SourceVersion)
	}
}

func TestAllCatalogers(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() returned no catalogers")
	}
	var names []string
	for _, c := range all {
		names = append(names, c.Name())
	}
	if !slicesContains(names, "dpkg") {
		t.Errorf("All() = %v, want it to include dpkg", names)
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

var _ fs.FS = fstest.MapFS{}

// The continuation-line accumulator has to be linear.
//
// It used to append to the map entry directly, which copies the whole field on
// every line. Measured on the machine this was written on: 100k continuation
// lines took 4.3s, 200k took 15.3s and 400k took 56.5s -- the shape of a
// quadratic, and the field limit permits about 1.4M such lines, so a status
// file of a few megabytes was several minutes of CPU with no timeout anywhere
// above it. A builder makes the same input parse in about 30ms.
//
// The budget is two orders of magnitude above what the linear version needs and
// an order of magnitude below what the quadratic one took, so it fails on a
// regression without flaking on a slow machine.
func TestContinuationLinesParseInLinearTime(t *testing.T) {
	const lines = 400_000
	const budget = 5 * time.Second

	var b strings.Builder
	b.WriteString("Package: openssl\nStatus: install ok installed\n")
	b.WriteString("Architecture: amd64\nVersion: 1.1.1k-1\nDescription: toolkit\n")
	for i := 0; i < lines; i++ {
		b.WriteString(" a\n")
	}

	start := time.Now()
	comps, err := parseStatus(strings.NewReader(b.String()), OSRelease{ID: "debian", Codename: "bullseye"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("parseStatus() error = %v", err)
	}
	if elapsed > budget {
		t.Errorf("%d continuation lines took %s, over the %s budget: the accumulator is quadratic again",
			lines, elapsed.Round(time.Millisecond), budget)
	}

	// Linear and correct are separate claims.
	if len(comps) != 1 {
		t.Fatalf("got %d components, want 1", len(comps))
	}
	if comps[0].Name != "openssl" || comps[0].Version != "1.1.1k-1" {
		t.Errorf("got %s %s, want openssl 1.1.1k-1", comps[0].Name, comps[0].Version)
	}
}

// Every per-part limit can be satisfied by a file that is still arbitrarily
// long, so the file itself is bounded too.
func TestStatusFileSizeIsBounded(t *testing.T) {
	restore := maxStatusBytes
	t.Cleanup(func() { maxStatusBytes = restore })
	maxStatusBytes = 4 << 10

	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("Package: p\nStatus: install ok installed\nVersion: 1\n\n")
	}

	if _, err := parseStatus(strings.NewReader(b.String()), OSRelease{ID: "debian", Codename: "bullseye"}); err == nil {
		t.Error("a status file past the size limit parsed without complaint")
	}

	// The apk database is bounded the same way.
	var a strings.Builder
	for i := 0; i < 1000; i++ {
		a.WriteString("P:p\nV:1\n\n")
	}
	if _, err := parseApkInstalled(strings.NewReader(a.String()), "v3.16"); err == nil {
		t.Error("an apk database past the size limit parsed without complaint")
	}
}

// The distribution an image says it is decides which body of OSV data its
// packages are queried against, so it has to survive cataloging.
func TestDpkgCarriesTheDistribution(t *testing.T) {
	status := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.2-0ubuntu1.10\n"
	root := fstest.MapFS{
		"var/lib/dpkg/status": &fstest.MapFile{Data: []byte(status)},
		"usr/lib/os-release": &fstest.MapFile{Data: []byte(
			"ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n")},
	}
	comps, err := NewDpkg().Catalog(context.Background(), root)
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components, want 1", len(comps))
	}
	got := comps[0]
	if got.DistroID != "ubuntu" || got.Distro != "jammy" || got.DistroVersion != "22.04" {
		t.Errorf("distro = %q/%q/%q, want ubuntu/jammy/22.04", got.DistroID, got.Distro, got.DistroVersion)
	}
	// The component's own purl says Ubuntu too, which is what the SBOM carries.
	if !strings.Contains(got.PURL, "pkg:deb/ubuntu/openssl") {
		t.Errorf("purl = %q, want the ubuntu namespace", got.PURL)
	}
}
