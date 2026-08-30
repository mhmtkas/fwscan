package model

import (
	"slices"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  Severity
		known bool
	}{
		{"critical", "critical", SeverityCritical, true},
		{"uppercase", "HIGH", SeverityHigh, true},
		{"padded", "  medium  ", SeverityMedium, true},
		{"moderate is medium", "Moderate", SeverityMedium, true},
		{"low", "low", SeverityLow, true},
		{"explicit unknown", "unknown", SeverityUnknown, true},
		{"empty is unrecognised", "", SeverityUnknown, false},
		{"gibberish is unrecognised", "spicy", SeverityUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := ParseSeverity(tt.in)
			if got != tt.want || known != tt.known {
				t.Errorf("ParseSeverity(%q) = (%q, %v), want (%q, %v)", tt.in, got, known, tt.want, tt.known)
			}
		})
	}
}

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		name      string
		severity  Severity
		threshold Severity
		want      bool
	}{
		{"critical meets high", SeverityCritical, SeverityHigh, true},
		{"high meets high", SeverityHigh, SeverityHigh, true},
		{"medium does not meet high", SeverityMedium, SeverityHigh, false},
		{"low meets low", SeverityLow, SeverityLow, true},
		{"critical meets low", SeverityCritical, SeverityLow, true},

		// output-spec section 5: unknown never triggers exit 1, whatever the
		// threshold is — including a threshold of unknown itself.
		{"unknown never meets low", SeverityUnknown, SeverityLow, false},
		{"unknown never meets unknown", SeverityUnknown, SeverityUnknown, false},
		{"unknown never meets critical", SeverityUnknown, SeverityCritical, false},
		{"garbage never meets low", Severity("nonsense"), SeverityLow, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.AtLeast(tt.threshold); got != tt.want {
				t.Errorf("%q.AtLeast(%q) = %v, want %v", tt.severity, tt.threshold, got, tt.want)
			}
		})
	}
}

func comp(name string) Component { return Component{Name: name} }

func TestCompareFindings(t *testing.T) {
	tests := []struct {
		name string
		a, b Finding
		want int // -1 a first, 1 b first, 0 equal
	}{
		{
			"severity bucket beats score",
			Finding{Severity: SeverityCritical, CVSS: 9.0},
			Finding{Severity: SeverityHigh, CVSS: 8.9},
			-1,
		},
		{
			"lower bucket sorts later even with a higher score",
			Finding{Severity: SeverityLow, CVSS: 3.9},
			Finding{Severity: SeverityMedium, CVSS: 4.0},
			1,
		},
		{
			"unknown sorts last",
			Finding{Severity: SeverityUnknown, CVSS: 0},
			Finding{Severity: SeverityLow, CVSS: 0.1},
			1,
		},
		{
			"score descending within a bucket",
			Finding{Severity: SeverityHigh, CVSS: 8.8},
			Finding{Severity: SeverityHigh, CVSS: 7.1},
			-1,
		},
		{
			"name ascending when score ties",
			Finding{Severity: SeverityHigh, CVSS: 7.5, Component: comp("apache2")},
			Finding{Severity: SeverityHigh, CVSS: 7.5, Component: comp("zlib")},
			-1,
		},
		{
			"id ascending when name ties",
			Finding{Severity: SeverityHigh, CVSS: 7.5, Component: comp("openssl"), ID: "CVE-2022-0778"},
			Finding{Severity: SeverityHigh, CVSS: 7.5, Component: comp("openssl"), ID: "CVE-2022-3602"},
			-1,
		},
		{
			"fully equal",
			Finding{Severity: SeverityHigh, CVSS: 7.5, Component: comp("openssl"), ID: "CVE-1"},
			Finding{Severity: SeverityHigh, CVSS: 7.5, Component: comp("openssl"), ID: "CVE-1"},
			0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareFindings(tt.a, tt.b)
			if sign(got) != tt.want {
				t.Errorf("CompareFindings() sign = %d, want %d (raw %d)", sign(got), tt.want, got)
			}
			// A comparator that is not antisymmetric produces an unstable sort,
			// which would make golden files flap.
			if back := CompareFindings(tt.b, tt.a); sign(back) != -tt.want {
				t.Errorf("not antisymmetric: reverse sign = %d, want %d", sign(back), -tt.want)
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestCompareFindingsSortsWholeSlice(t *testing.T) {
	in := []Finding{
		{ID: "CVE-5", Severity: SeverityUnknown, Component: comp("busybox")},
		{ID: "CVE-3", Severity: SeverityHigh, CVSS: 7.5, Component: comp("zlib")},
		{ID: "CVE-1", Severity: SeverityCritical, CVSS: 9.8, Component: comp("openssl")},
		{ID: "CVE-2", Severity: SeverityHigh, CVSS: 8.1, Component: comp("openssh")},
		{ID: "CVE-4", Severity: SeverityHigh, CVSS: 7.5, Component: comp("apt")},
		{ID: "CVE-0", Severity: SeverityLow, CVSS: 2.0, Component: comp("tar")},
	}
	slices.SortFunc(in, CompareFindings)

	want := []string{"CVE-1", "CVE-2", "CVE-4", "CVE-3", "CVE-0", "CVE-5"}
	for i, id := range want {
		if in[i].ID != id {
			t.Fatalf("position %d = %s, want %s (full order %v)", i, in[i].ID, id, ids(in))
		}
	}
}

func TestCompareComponents(t *testing.T) {
	in := []Component{
		{Name: "zlib1g", Version: "1:1.2.11"},
		{Name: "openssl", Version: "3.0.2"},
		{Name: "openssl", Version: "1.1.1n"},
		{Name: "apt", Version: "2.2.4"},
	}
	slices.SortFunc(in, CompareComponents)
	want := []string{"apt", "openssl", "openssl", "zlib1g"}
	for i, name := range want {
		if in[i].Name != name {
			t.Fatalf("position %d = %s, want %s", i, in[i].Name, name)
		}
	}
	if in[1].Version != "1.1.1n" {
		t.Errorf("equal names not tie-broken by version: got %q first", in[1].Version)
	}
}

func TestConfidenceValues(t *testing.T) {
	// These strings appear verbatim in the JSON report and in SBOM properties,
	// so a rename is a format change, not a refactor.
	if ConfidenceHigh != "high" || ConfidenceLow != "low" {
		t.Errorf("confidence constants changed: %q, %q", ConfidenceHigh, ConfidenceLow)
	}
}

func ids(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}
