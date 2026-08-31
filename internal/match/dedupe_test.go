package match

import (
	"context"
	"testing"

	"github.com/mhmtkas/fwscan/internal/model"
)

// The whole path, against the recorded responses. zlib's query returns both
// DEBIAN-CVE-2022-37434 and DSA-5218-1, the advisory that shipped the fix; the
// two describe one issue and must reach the report as one row.
func TestOSVMatchCollapsesAnAdvisoryOntoItsCVE(t *testing.T) {
	osv := newFakeOSV(t)

	findings, err := osv.Match(context.Background(),
		[]model.Component{debComponent("zlib1g", "1:1.2.11.dfsg-2", "zlib", "1:1.2.11.dfsg-2")})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}

	var matching []model.Finding
	for _, f := range findings {
		if f.ID == "CVE-2022-37434" {
			matching = append(matching, f)
		}
	}
	if len(matching) != 1 {
		t.Fatalf("CVE-2022-37434 appears %d times, want once", len(matching))
	}

	f := matching[0]
	// The advisory carries no severity and, because its affected purl has no
	// distro qualifier, no fixed version either. The scored record must win.
	if f.Severity != model.SeverityCritical || f.FixedVersion != "1:1.2.11.dfsg-2+deb11u2" {
		t.Errorf("kept the advisory's empty assessment: severity %q, fixed %q",
			f.Severity, f.FixedVersion)
	}
	if !containsString(f.Aliases, "DSA-5218-1") {
		t.Errorf("aliases = %v, want the merged record's id to survive", f.Aliases)
	}
	if !containsString(f.Aliases, "DEBIAN-CVE-2022-37434") {
		t.Errorf("aliases = %v, want the scored record's id kept too", f.Aliases)
	}
}

func TestDedupeFindings(t *testing.T) {
	zlib := debComponent("zlib1g", "1:1.2.11.dfsg-2", "zlib", "1:1.2.11.dfsg-2")
	other := debComponent("libc6", "2.31-13", "glibc", "2.31-13")

	scored := model.Finding{
		Component: zlib, ID: "CVE-1", Aliases: []string{"DEBIAN-CVE-1"},
		Severity: model.SeverityHigh, CVSS: 7.5,
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		FixedVersion: "1.0",
	}
	advisory := model.Finding{
		Component: zlib, ID: "CVE-1", Aliases: []string{"DSA-1", "DEBIAN-CVE-1"},
		Severity: model.SeverityUnknown,
	}

	tests := []struct {
		name  string
		input []model.Finding
		want  func(*testing.T, []model.Finding)
	}{
		{
			name:  "an unscored duplicate never displaces a scored one",
			input: []model.Finding{scored, advisory},
			want: func(t *testing.T, got []model.Finding) {
				mustBeOne(t, got, model.SeverityHigh, 7.5, "1.0")
				if !containsString(got[0].Aliases, "DSA-1") {
					t.Errorf("aliases = %v, want DSA-1 merged in", got[0].Aliases)
				}
			},
		},
		{
			name: "order does not decide the outcome",
			// The advisory arrives first here. OSV's response order is not
			// something the report may depend on.
			input: []model.Finding{advisory, scored},
			want: func(t *testing.T, got []model.Finding) {
				mustBeOne(t, got, model.SeverityHigh, 7.5, "1.0")
			},
		},
		{
			name: "a fix is taken from whichever record knows one",
			input: []model.Finding{
				{Component: zlib, ID: "CVE-1", Severity: model.SeverityHigh, CVSS: 7.5},
				{Component: zlib, ID: "CVE-1", Severity: model.SeverityUnknown, FixedVersion: "1.0"},
			},
			want: func(t *testing.T, got []model.Finding) {
				mustBeOne(t, got, model.SeverityHigh, 7.5, "1.0")
			},
		},
		{
			name: "the more severe assessment wins",
			input: []model.Finding{
				{Component: zlib, ID: "CVE-1", Severity: model.SeverityMedium, CVSS: 5.0, CVSSVector: "v3"},
				{Component: zlib, ID: "CVE-1", Severity: model.SeverityCritical, CVSS: 9.8, CVSSVector: "v4"},
			},
			want: func(t *testing.T, got []model.Finding) {
				mustBeOne(t, got, model.SeverityCritical, 9.8, "")
				if got[0].CVSSVector != "v4" {
					t.Errorf("vector = %q, want the one the winning score came from", got[0].CVSSVector)
				}
			},
		},
		{
			name:  "the same CVE in two components stays two findings",
			input: []model.Finding{scored, {Component: other, ID: "CVE-1"}},
			want: func(t *testing.T, got []model.Finding) {
				if len(got) != 2 {
					t.Fatalf("got %d findings, want 2", len(got))
				}
			},
		},
		{
			name:  "different CVEs in one component stay separate",
			input: []model.Finding{scored, {Component: zlib, ID: "CVE-2"}},
			want: func(t *testing.T, got []model.Finding) {
				if len(got) != 2 {
					t.Fatalf("got %d findings, want 2", len(got))
				}
			},
		},
		{
			name:  "nothing to do",
			input: nil,
			want: func(t *testing.T, got []model.Finding) {
				if len(got) != 0 {
					t.Fatalf("got %d findings, want 0", len(got))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, dedupeFindings(tt.input))
		})
	}
}

func mustBeOne(t *testing.T, got []model.Finding, severity model.Severity, score float64, fixed string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Severity != severity || got[0].CVSS != score || got[0].FixedVersion != fixed {
		t.Errorf("finding = (%q, %v, %q), want (%q, %v, %q)",
			got[0].Severity, got[0].CVSS, got[0].FixedVersion, severity, score, fixed)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
