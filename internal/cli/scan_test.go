package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/mhmtkas/fwscan/internal/match"
	"github.com/mhmtkas/fwscan/internal/model"
)

// End to end through the cobra command, with the network skipped so the result
// is deterministic. This is the "fwscan scan testdata/images/..." path.
func TestScanEndToEndNoNetwork(t *testing.T) {
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	if _, err := os.Stat(image); err != nil {
		t.Fatalf("fixture image missing: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", image})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v (stderr: %s)", err, stderr.String())
	}

	got := stdout.String()
	for _, want := range []string{
		"fwscan v0.1.0",
		"(tar, gzip)",
		"Packages    7 (6 high confidence, 1 low)",
		"Cataloged 7 packages. CVE lookup skipped (--no-network).",
		"1 low-confidence component was identified by filename heuristics",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// No lookup happened, so there must be no Findings line and no table.
	for _, unwanted := range []string{"Findings", "SEVERITY"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("output contains %q in --no-network mode:\n%s", unwanted, got)
		}
	}
	// The fixture is a bullseye rootfs, and bullseye left free security support
	// on 2026-08-31, so a scan of it warns. That warning is the point of the
	// support table and belongs on stderr; what matters here is that it is the
	// only thing there and that it stayed out of the report.
	if got := stderr.String(); !strings.Contains(got, "left free security support") {
		t.Errorf("stderr does not carry the support warning: %q", got)
	} else if strings.Count(strings.TrimSpace(got), "\n") != 0 {
		t.Errorf("unexpected extra stderr: %s", got)
	}
}

// stdout must carry only the report, so piping it stays safe.
func TestScanDiagnosticsGoToStderr(t *testing.T) {
	empty := t.TempDir() // a directory with no package database

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", empty})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(stderr.String(), "no package database found") {
		t.Errorf("warning not on stderr: %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "no package database found") {
		t.Errorf("warning leaked into stdout:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Packages    0") {
		t.Errorf("report missing from stdout:\n%s", stdout.String())
	}
}

func TestScanErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing path", []string{"scan", filepath.Join(t.TempDir(), "absent")}, "no such path"},
		{"unsupported file", []string{"scan", writeJunk(t)}, "unsupported format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			root := NewRootCmd("v0.1.0")
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs(tt.args)

			err := root.Execute()
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout must stay empty on failure, got:\n%s", stdout.String())
			}
		})
	}
}

func writeJunk(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "junk.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x41}, 1024), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestScanWritesSBOM(t *testing.T) {
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	out := filepath.Join(t.TempDir(), "bom.cdx.json")

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", "--sbom", out, image})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v (stderr: %s)", err, stderr.String())
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("sbom not written: %v", err)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name       string `json:"name"`
			PackageURL string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
		Vulnerabilities any `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Errorf("format = %s %s, want CycloneDX 1.6", doc.BOMFormat, doc.SpecVersion)
	}
	if len(doc.Components) != 7 {
		t.Errorf("got %d components, want 7", len(doc.Components))
	}
	if doc.Vulnerabilities != nil {
		t.Error("the SBOM carries vulnerabilities")
	}
	for _, c := range doc.Components {
		var hasConfidence, hasEvidence bool
		for _, p := range c.Properties {
			switch p.Name {
			case "fwscan:confidence":
				hasConfidence = true
			case "fwscan:evidence":
				hasEvidence = true
			}
		}
		if !hasConfidence || !hasEvidence {
			t.Errorf("%s: missing confidence or evidence property", c.Name)
		}
	}
}

// A failure part-way through must not leave a truncated file behind, and must
// not destroy a file that was already there.
func TestScanSBOMPathUnwritable(t *testing.T) {
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	unwritable := filepath.Join(t.TempDir(), "no-such-dir", "bom.json")

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", "--sbom", unwritable, image})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error writing to a missing directory")
	}
	if !strings.Contains(err.Error(), "sbom") {
		t.Errorf("error = %q, want it to name the sbom", err)
	}
}

func TestScanWritesJSONReport(t *testing.T) {
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	out := filepath.Join(t.TempDir(), "report.json")

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", "--output", out, image})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v (stderr: %s)", err, stderr.String())
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	if !bytes.HasSuffix(body, []byte("}\n")) {
		t.Error("report does not end with a trailing newline")
	}

	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Tool          struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		Scan struct {
			Target      string `json:"target"`
			Format      string `json:"format"`
			Compression string `json:"compression"`
		} `json:"scan"`
		Summary struct {
			Packages struct {
				Total int `json:"total"`
			} `json:"packages"`
		} `json:"summary"`
		Components []map[string]any `json:"components"`
		Findings   []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != "1" || doc.Tool.Name != "fwscan" || doc.Tool.Version != "0.1.0" {
		t.Errorf("header = %+v %+v", doc.SchemaVersion, doc.Tool)
	}
	if doc.Scan.Format != "tar" || doc.Scan.Compression != "gzip" {
		t.Errorf("scan block = %+v", doc.Scan)
	}
	if doc.Summary.Packages.Total != 7 || len(doc.Components) != 7 {
		t.Errorf("packages = %d, components = %d, want 7 and 7", doc.Summary.Packages.Total, len(doc.Components))
	}
	// --no-network still produces the array, empty.
	if doc.Findings == nil {
		t.Error("findings is null, want an empty array")
	}
	if len(doc.Findings) != 0 {
		t.Errorf("got %d findings in --no-network mode", len(doc.Findings))
	}
}

// exploding is a matcher that fails the test if anything asks it to look
// something up. --no-network must never construct a request, let alone send one.
type exploding struct{ t *testing.T }

func (e exploding) Match(context.Context, []model.Component) ([]model.Finding, error) {
	e.t.Error("the matcher was invoked in --no-network mode")
	return nil, errors.New("matcher must not be called")
}

func TestNoNetworkNeverCallsTheMatcher(t *testing.T) {
	original := newMatcher
	newMatcher = func() match.Matcher { return exploding{t: t} }
	t.Cleanup(func() { newMatcher = original })

	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	out := filepath.Join(t.TempDir(), "report.json")

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", "--output", out, image})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
}

// Without --no-network the matcher is called, which keeps the test above
// honest: it would otherwise pass even if the flag did nothing.
func TestNetworkModeCallsTheMatcher(t *testing.T) {
	var called bool
	original := newMatcher
	newMatcher = func() match.Matcher {
		return matcherFunc(func(context.Context, []model.Component) ([]model.Finding, error) {
			called = true
			return nil, nil
		})
	}
	t.Cleanup(func() { newMatcher = original })

	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", image})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !called {
		t.Error("the matcher was not called without --no-network")
	}
	if !strings.Contains(stdout.String(), "Findings") {
		t.Error("the Findings line is missing when the lookup did run")
	}
}

type matcherFunc func(context.Context, []model.Component) ([]model.Finding, error)

func (f matcherFunc) Match(ctx context.Context, comps []model.Component) ([]model.Finding, error) {
	return f(ctx, comps)
}

// The failure a mistyped --output produces has to name the mistake. Writing
// through a temp file means the rename is what fails, and its message names the
// temp file and says "file exists", which is both wrong and unfixable.
func TestOutputPathThatIsADirectory(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")

	cmd := NewRootCmd("v0.1.0")
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"scan", "--no-network", "--output", dir, image})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("writing a report over a directory succeeded")
	}
	if !strings.Contains(err.Error(), "it is a directory") {
		t.Errorf("error = %v, want it to say the destination is a directory", err)
	}
	if strings.Contains(err.Error(), ".tmp") {
		t.Errorf("error = %v, names the temp file rather than the destination", err)
	}
}

// A Debian lookup that cannot be scoped to a release still runs, and says so.
// Without the release OSV answers across every Debian release and names another
// release's fix as the one to install; silently unscoped is the worse outcome.
func TestReleaseWarnings(t *testing.T) {
	status := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.1.1n-0+deb11u5\n"
	deb := model.Component{Name: "openssl", Version: "1.1.1n-0+deb11u5", PURL: "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u5?arch=amd64"}

	tests := []struct {
		name  string
		files map[string]string
		comps []model.Component
		want  []string
	}{
		{
			name:  "a bullseye image warns about nothing",
			files: map[string]string{"var/lib/dpkg/status": status, "usr/lib/os-release": "ID=debian\nVERSION_ID=\"11\"\nVERSION_CODENAME=bullseye\n"},
			comps: []model.Component{func() model.Component { c := deb; c.Distro, c.DistroVersion = "bullseye", "11"; return c }()},
		},
		{
			name:  "no os-release at all",
			files: map[string]string{"var/lib/dpkg/status": status},
			comps: []model.Component{deb},
			want:  []string{"no release found"},
		},
		{
			// Ubuntu has its own OSV data and fwscan queries it, so there is
			// nothing to warn about.
			name:  "an ubuntu image",
			files: map[string]string{"var/lib/dpkg/status": status, "usr/lib/os-release": "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n"},
			comps: []model.Component{func() model.Component {
				c := deb
				c.DistroID, c.Distro, c.DistroVersion = "ubuntu", "jammy", "22.04"
				c.PURL = "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=jammy"
				return c
			}()},
		},
		{
			// A derivative fwscan has no data for is queried as Debian, which
			// returns nothing rather than an error, so it says so.
			name:  "a derivative with no data of its own",
			files: map[string]string{"var/lib/dpkg/status": status, "usr/lib/os-release": "ID=linuxmint\nVERSION_ID=\"21\"\nVERSION_CODENAME=vanessa\n"},
			comps: []model.Component{func() model.Component {
				c := deb
				c.DistroID, c.Distro, c.DistroVersion = "linuxmint", "vanessa", "21"
				return c
			}()},
			want: []string{"this is linuxmint"},
		},
		{
			name:  "an alpine image is not a debian lookup",
			files: map[string]string{"lib/apk/db/installed": "P:openssl\nV:1.1.1o-r0\n\n"},
			comps: []model.Component{{Name: "openssl", Version: "1.1.1o-r0", PURL: "pkg:apk/alpine/openssl@1.1.1o-r0"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fstest.MapFS{}
			for name, body := range tt.files {
				root[name] = &fstest.MapFile{Data: []byte(body)}
			}
			got := releaseWarnings(root, tt.comps)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d warnings %q, want %d", len(got), got, len(tt.want))
			}
			for i, want := range tt.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("warning %d = %q, want it to mention %q", i, got[i], want)
				}
			}
		})
	}
}

// A diagnostic can quote the image -- an os-release ID is as attacker-controlled
// as a package name -- and the report has been sanitised since it was written.
// The warnings went to stderr around that, raw.
func TestDiagnosticsAreSanitised(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "lib", "dpkg", "status"),
		[]byte("Package: x\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"),
		[]byte("ID=\"\x1b[2Jpwned\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd("v0.1.0")
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--no-network", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(stderr.String(), "pwned") {
		t.Fatalf("the os-release warning did not fire: %q", stderr.String())
	}
	if strings.ContainsRune(stderr.String(), 0x1b) {
		t.Errorf("stderr carries a raw escape: %q", stderr.String())
	}
}

// An image can carry a package database fwscan does not read -- opkg and rpm
// are documented non-goals. A real OpenWrt image has 150 opkg packages; fwscan
// reports the two its filename heuristics recognise, and reporting two where
// there are a hundred and fifty without saying so is an answer that gets acted
// on and should not be.
func TestUnreadDatabaseWarnings(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{
			name:  "an openwrt image",
			files: []string{"usr/lib/opkg/status"},
			want:  []string{"an opkg database at usr/lib/opkg/status"},
		},
		{
			name:  "opkg at the other path it uses",
			files: []string{"var/lib/opkg/status"},
			want:  []string{"an opkg database at var/lib/opkg/status"},
		},
		{
			name:  "an rpm image",
			files: []string{"var/lib/rpm/rpmdb.sqlite"},
			want:  []string{"an rpm database"},
		},
		{
			// Both rpm paths present is still one warning: the reader needs to
			// know the manager is unread, not how many files it keeps.
			name:  "one warning per manager",
			files: []string{"var/lib/rpm/Packages", "var/lib/rpm/rpmdb.sqlite"},
			want:  []string{"an rpm database"},
		},
		{
			name:  "a debian image warns about nothing",
			files: []string{"var/lib/dpkg/status"},
		},
		{
			name:  "an alpine image warns about nothing",
			files: []string{"lib/apk/db/installed"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fstest.MapFS{}
			for _, f := range tt.files {
				root[f] = &fstest.MapFile{Data: []byte("Package: x\n")}
			}
			got := unreadDatabaseWarnings(root)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d warnings %q, want %d", len(got), got, len(tt.want))
			}
			for i, want := range tt.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("warning %d = %q, want it to mention %q", i, got[i], want)
				}
			}
		})
	}
}

// "No known vulnerabilities found." is the wrong thing to leave a reader with
// when the data could not have said otherwise. OSV's Debian export carries a
// record per CVE for a supported release and only DSA/DLA advisories for an
// oldstable one -- and an advisory exists exactly when a fix shipped, so a
// patched oldstable image answers zero while its unfixed CVEs are simply absent
// from the data. Measured on a real Debian 11 rootfs: fwscan 0, a scanner
// reading the Debian Security Tracker 211, all of them unfixed.
func TestEmptyResultWarnings(t *testing.T) {
	deb := model.Component{Name: "libc6", Version: "2.31-13+deb11u14", PURL: "pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=bullseye"}
	apk := model.Component{Name: "musl", Version: "1.2.4-r2", PURL: "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64"}
	finding := model.Finding{Component: deb, ID: "CVE-2024-0001", Severity: model.SeverityHigh}

	tests := []struct {
		name     string
		comps    []model.Component
		findings []model.Finding
		want     bool
	}{
		{"a debian image with nothing found", []model.Component{deb}, nil, true},
		{"a debian image with findings", []model.Component{deb}, []model.Finding{finding}, false},
		{"an alpine image with nothing found", []model.Component{apk}, nil, false},
		{"no components at all", nil, nil, false},
		{"a mixed image with nothing found", []model.Component{apk, deb}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := emptyResultWarnings(tt.comps, tt.findings)
			if (len(got) > 0) != tt.want {
				t.Fatalf("got %q, want a warning: %v", got, tt.want)
			}
			// The reason zero can be wrong now comes from supportWarnings,
			// which names the release and the date its support ended rather
			// than gesturing at "oldstable". This warning's job is only to say
			// that a Debian image with no findings is worth a second look.
			if tt.want && !strings.Contains(got[0], "no findings for a Debian image") {
				t.Errorf("warning = %q, want it to flag the empty result", got[0])
			}
		})
	}
}

func TestScanWritesCRAReport(t *testing.T) {
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	dir := t.TempDir()
	bom := filepath.Join(dir, "bom.cdx.json")
	evidence := filepath.Join(dir, "evidence.md")

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", "--sbom", bom, "--cra", evidence, image})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v (stderr: %s)", err, stderr.String())
	}

	body, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatalf("cra report not written: %v", err)
	}
	got := string(body)
	for _, want := range []string{
		"# Vulnerability handling evidence",
		"Regulation (EU) 2024/2847",
		// The document names the SBOM the same run produced, so the two are
		// filed together rather than as two unrelated files.
		bom,
		// --no-network was given, and the document has to say the lookup did
		// not happen rather than present an empty section as a clean result.
		"no vulnerability lookup was performed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the evidence report does not contain %q", want)
		}
	}
}

// The stderr warnings are the limitations section. A scan that warned and a
// document that does not carry the warning would be a document that overstates
// what was checked.
func TestCRAReportCarriesTheScanWarnings(t *testing.T) {
	// A directory with no package database at all: the scan warns, and the
	// warning is the only thing that explains an empty inventory.
	image := t.TempDir()
	evidence := filepath.Join(t.TempDir(), "evidence.md")

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", "--cra", evidence, image})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan failed: %v (stderr: %s)", err, stderr.String())
	}

	body, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatalf("cra report not written: %v", err)
	}
	if !strings.Contains(string(body), "no package database found") {
		t.Errorf("the warning on stderr is not in the report:\n%s", body)
	}
	if !strings.Contains(string(body), "No SBOM was written by this run") {
		t.Errorf("the report does not say the inventory is missing:\n%s", body)
	}
}

func TestScanCRAPathUnwritable(t *testing.T) {
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")
	unwritable := filepath.Join(t.TempDir(), "no-such-dir", "evidence.md")

	var stdout, stderr bytes.Buffer
	root := NewRootCmd("v0.1.0")
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--no-network", "--cra", unwritable, image})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error writing to a missing directory")
	}
	if !strings.Contains(err.Error(), "cra") {
		t.Errorf("error = %q, want it to name the cra report", err)
	}
}

// The support warning is the explanation behind fwscan's worst result: a
// bullseye image reports nothing, and the reason is a date rather than the
// image. Before this the scan could only say it had found nothing.
func TestSupportWarnings(t *testing.T) {
	deb := func(id, series, version string) model.Component {
		return model.Component{
			Name: "openssl", Version: "1.1.1n", PURL: "pkg:deb/" + id + "/openssl@1.1.1n",
			Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
			DistroID: id, Distro: series, DistroVersion: version,
		}
	}
	at := func(s string) time.Time {
		d, err := time.Parse(time.DateOnly, s)
		if err != nil {
			t.Fatalf("bad date: %v", err)
		}
		return d
	}

	tests := []struct {
		name    string
		comps   []model.Component
		now     string
		want    string
		wantNot bool
	}{
		{
			name:  "a release past free support says when and what covers it now",
			comps: []model.Component{deb("debian", "bullseye", "11")},
			now:   "2026-09-03",
			want:  "left free security support on 2026-08-31",
		},
		{
			// The same image, three days earlier, is a different answer. The
			// warning is about a date, so it has to be computed from one.
			name:    "the same release before that date is not warned about",
			comps:   []model.Component{deb("debian", "bullseye", "11")},
			now:     "2026-08-30",
			wantNot: true,
		},
		{
			name:    "a freely supported release is silent",
			comps:   []model.Component{deb("debian", "bookworm", "12")},
			now:     "2026-09-03",
			wantNot: true,
		},
		{
			name:    "an ubuntu release in free support is silent",
			comps:   []model.Component{deb("ubuntu", "jammy", "22.04")},
			now:     "2026-09-03",
			wantNot: true,
		},
		{
			name:  "an ubuntu release on ESM names the subscription",
			comps: []model.Component{deb("ubuntu", "bionic", "18.04")},
			now:   "2026-09-03",
			want:  "ESM (Ubuntu Pro)",
		},
		{
			name:  "a release past every tier says nobody publishes updates",
			comps: []model.Component{deb("debian", "jessie", "8")},
			now:   "2026-09-03",
			want:  "nobody publishes security updates for it",
		},
		{
			// releaseWarnings already says a derivative is queried as Debian;
			// inventing a support date for one would be worse than silence.
			name:    "a derivative is not given a support date",
			comps:   []model.Component{deb("linuxmint", "vanessa", "21")},
			now:     "2026-09-03",
			wantNot: true,
		},
		{
			// A heuristic component carries no distribution it can vouch for.
			name: "a low-confidence component is not read for a release",
			comps: []model.Component{{
				Name: "busybox", Version: "1.30.1", Confidence: model.ConfidenceLow,
				Evidence: "bin/busybox", DistroID: "debian", Distro: "bullseye",
			}},
			now:     "2026-09-03",
			wantNot: true,
		},
		{
			name:    "an image with no packages at all",
			comps:   nil,
			now:     "2026-09-03",
			wantNot: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := supportWarnings(tt.comps, at(tt.now))
			if tt.wantNot {
				if len(got) != 0 {
					t.Errorf("got warnings %q, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d warnings, want 1: %q", len(got), got)
			}
			if !strings.Contains(got[0], tt.want) {
				t.Errorf("warning = %q, want it to contain %q", got[0], tt.want)
			}
		})
	}
}
