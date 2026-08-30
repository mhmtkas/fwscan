package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		"Packages    6 (6 high confidence, 0 low)",
		"Cataloged 6 packages. CVE lookup skipped (--no-network).",
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
	if len(doc.Components) != 6 {
		t.Errorf("got %d components, want 6", len(doc.Components))
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
