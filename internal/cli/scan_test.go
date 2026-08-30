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
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr: %s", stderr.String())
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
