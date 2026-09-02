package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/model"
)

func TestJSONGolden(t *testing.T) {
	tests := []struct {
		name   string
		golden string
		build  func() ([]model.Component, []model.Finding)
	}{
		{
			name:   "findings",
			golden: "report-findings.json",
			build:  sampleFindings,
		},
		{
			name:   "no findings",
			golden: "report-clean.json",
			build: func() ([]model.Component, []model.Finding) {
				return []model.Component{highComponent("openssl", "3.0.11-1~deb12u2")}, nil
			},
		},
		{
			name:   "no components at all",
			golden: "report-empty.json",
			build:  func() ([]model.Component, []model.Finding) { return nil, nil },
		},
		{
			// --no-network: the same document, findings empty and the summary
			// zeroed, so one parser handles both modes.
			name:   "no-network mode",
			golden: "report-no-network.json",
			build: func() ([]model.Component, []model.Finding) {
				comps, _ := sampleFindings()
				return comps, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps, findings := tt.build()
			var buf bytes.Buffer
			if err := JSON(&buf, "v0.1.0", fixedInfo(), comps, findings); err != nil {
				t.Fatalf("JSON() error = %v", err)
			}
			assertGolden(t, tt.golden, buf.Bytes())
		})
	}
}

func TestJSONShape(t *testing.T) {
	comps, findings := sampleFindings()
	var buf bytes.Buffer
	if err := JSON(&buf, "v0.1.0", fixedInfo(), comps, findings); err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	raw := buf.String()

	if !strings.HasSuffix(raw, "}\n") {
		t.Error("output does not end with a trailing newline")
	}
	if strings.Contains(raw, `\u0026`) {
		t.Error("purl qualifiers are HTML-escaped")
	}

	var doc JSONReport
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if doc.SchemaVersion != "1" {
		t.Errorf("schema_version = %q, want \"1\"", doc.SchemaVersion)
	}
	// output-spec renders the version with a leading v in the terminal and
	// without one here, from the same injected value.
	if doc.Tool.Version != "0.1.0" {
		t.Errorf("tool.version = %q, want 0.1.0", doc.Tool.Version)
	}
	if doc.Scan.StartedAt != "2026-08-30T14:05:11Z" {
		t.Errorf("started_at = %q, want RFC 3339 UTC", doc.Scan.StartedAt)
	}
	if doc.Scan.DurationMS != 8421 {
		t.Errorf("duration_ms = %d, want 8421", doc.Scan.DurationMS)
	}

	// Components sorted by name.
	var names []string
	for _, c := range doc.Components {
		names = append(names, c.Name)
	}
	want := []string{"busybox", "linux-kernel", "openssh", "openssl", "zlib1g"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("components sorted %v, want %v", names, want)
		}
	}

	// Findings in the severity order from section 1.
	var ids []string
	for _, f := range doc.Findings {
		ids = append(ids, f.ID)
	}
	wantIDs := []string{"CVE-2022-3602", "CVE-2022-48174", "CVE-2023-38408", "CVE-2010-4756"}
	for i := range wantIDs {
		if ids[i] != wantIDs[i] {
			t.Fatalf("findings sorted %v, want %v", ids, wantIDs)
		}
	}

	for _, f := range doc.Findings {
		if f.Source != "osv.dev" {
			t.Errorf("%s: source = %q", f.ID, f.Source)
		}
		if f.Aliases == nil {
			t.Errorf("%s: aliases is null, want an empty array", f.ID)
		}
		// A non-CVSS severity must carry no vector.
		if f.Severity == string(model.SeverityUnknown) && f.CVSSVector != "" {
			t.Errorf("%s: unknown severity carries a vector %q", f.ID, f.CVSSVector)
		}
	}
}

// In --no-network mode the document keeps its shape: the findings array is
// present and empty, and the summary is zeroed, so one parser handles both.
func TestJSONNoNetworkShape(t *testing.T) {
	comps, _ := sampleFindings()
	var buf bytes.Buffer
	if err := JSON(&buf, "v0.1.0", fixedInfo(), comps, nil); err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Error("findings is not an empty array")
	}

	var doc JSONReport
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Summary.Findings != (jsonFindingSummary{}) {
		t.Errorf("findings summary = %+v, want all zeros", doc.Summary.Findings)
	}
	if len(doc.Components) != 5 {
		t.Errorf("got %d components, want 5", len(doc.Components))
	}
}

func TestVersionRendering(t *testing.T) {
	tests := []struct {
		in, plain, display string
	}{
		{"v0.1.0", "0.1.0", "v0.1.0"},
		{"0.1.0", "0.1.0", "v0.1.0"},
		{"", "", ""},
		// Not version numbers, so they do not get dressed as one. "dev" is
		// main.go's default and what `go install` leaves in place; the other two
		// are what `git describe` produces from a source build.
		{"dev", "dev", "dev"},
		{"abc1234", "abc1234", "abc1234"},
		{"abc1234-dirty", "abc1234-dirty", "abc1234-dirty"},
		// A hash that happens to start with a digit is still a hash.
		{"1a2b3c4", "1a2b3c4", "1a2b3c4"},
		{"933c3e6-dirty", "933c3e6-dirty", "933c3e6-dirty"},
		// Pre-release and build metadata keep the version shape.
		{"0.2.0-rc.1", "0.2.0-rc.1", "v0.2.0-rc.1"},
		{"0.0.0-20260902045748-c3043c9f8192", "0.0.0-20260902045748-c3043c9f8192", "v0.0.0-20260902045748-c3043c9f8192"},
	}
	for _, tt := range tests {
		if got := PlainVersion(tt.in); got != tt.plain {
			t.Errorf("PlainVersion(%q) = %q, want %q", tt.in, got, tt.plain)
		}
		if got := DisplayVersion(tt.in); got != tt.display {
			t.Errorf("DisplayVersion(%q) = %q, want %q", tt.in, got, tt.display)
		}
	}
}
