package report

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

func renderCRA(t *testing.T, comps []model.Component, findings []model.Finding, opts CRAOptions) string {
	t.Helper()
	var buf bytes.Buffer
	if err := CRA(&buf, "0.1.0", fixedInfo(), comps, findings, opts); err != nil {
		t.Fatalf("CRA: %v", err)
	}
	return buf.String()
}

// The whole document, against a golden, so any change to a sentence in it is a
// change somebody has to look at. The wording is not decoration: output-spec
// section 5 fixes what this file has to say about its own limits, and a
// paragraph quietly dropped from it is the defect this catches.
func TestCRAGolden(t *testing.T) {
	comps, findings := sampleFindings()
	got := renderCRA(t, comps, findings, CRAOptions{
		SBOMPath: "bom.cdx.json",
		Warnings: []string{"an opkg database was found at usr/lib/opkg/status and not read"},
	})
	assertGolden(t, "cra-findings.md", []byte(got))
}

// The three sections whose text changes with the shape of the scan, each
// checked for the claim it has to make rather than for its exact wording.
func TestCRASectionsFollowTheScan(t *testing.T) {
	comps, findings := sampleFindings()

	tests := []struct {
		name     string
		comps    []model.Component
		findings []model.Finding
		opts     CRAOptions
		want     []string
		notWant  []string
	}{
		{
			name:     "a scan that found vulnerabilities splits them by fix availability",
			comps:    comps,
			findings: findings,
			opts:     CRAOptions{SBOMPath: "bom.cdx.json"},
			// Two of the four sample findings carry a fixed version.
			want: []string{
				"4 findings. 2 have a fix published for the installed release; 2 do not.",
				"| CVE-2022-3602 | openssl | 1.1.1n-0+deb11u3 | critical | fix available: 1.1.1n-0+deb11u5 |  |",
				"| CVE-2022-48174 | busybox | 1.30.1-6 | critical | no fix published |  |",
				"    bom.cdx.json",
				"debian bullseye",
			},
		},
		{
			name:     "a clean scan says what the absence of findings means",
			comps:    comps,
			findings: nil,
			opts:     CRAOptions{SBOMPath: "bom.cdx.json"},
			want:     []string{"No known vulnerabilities were reported"},
			// The wrong reading of an empty section is that the image is
			// sound, and the document has to close that off itself.
			notWant: []string{"| Vulnerability | Component |"},
		},
		{
			name:     "a --no-network scan says nothing was checked",
			comps:    comps,
			findings: nil,
			opts:     CRAOptions{NoNetwork: true, SBOMPath: "bom.cdx.json"},
			want: []string{
				"no vulnerability lookup was performed",
				"because nothing was checked, not because nothing was\nfound",
			},
			notWant: []string{"No known vulnerabilities were reported"},
		},
		{
			name:     "a run without --sbom names the flag that would produce the inventory",
			comps:    comps,
			findings: findings,
			opts:     CRAOptions{},
			want:     []string{"No SBOM was written by this run", "`--sbom <file>`"},
		},
		{
			name:     "an image with no heuristic components has no section for them",
			comps:    []model.Component{highComponent("openssl", "1.1.1n-0+deb11u3")},
			findings: nil,
			opts:     CRAOptions{SBOMPath: "bom.cdx.json"},
			notWant:  []string{"Components identified without a package database"},
		},
		{
			name:     "scan warnings become part of the record",
			comps:    comps,
			findings: findings,
			opts: CRAOptions{Warnings: []string{
				"an opkg database was found at usr/lib/opkg/status and not read",
			}},
			want: []string{"- an opkg database was found at usr/lib/opkg/status and not read"},
		},
		{
			name:     "findings with no severity are counted in the limitations",
			comps:    comps,
			findings: findings,
			opts:     CRAOptions{},
			want:     []string{"1 finding carries no severity score"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderCRA(t, tt.comps, tt.findings, tt.opts)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("document does not contain %q\n--- got ---\n%s", want, got)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("document contains %q and should not\n--- got ---\n%s", notWant, got)
				}
			}
		})
	}
}

// The five obligations no scanner can speak to are named in the document
// itself. This is the difference between an evidence file and a file somebody
// mistakes for a compliance certificate, so it is asserted rather than left to
// the golden alone.
func TestCRANamesWhatItDoesNotEvidence(t *testing.T) {
	comps, findings := sampleFindings()
	got := renderCRA(t, comps, findings, CRAOptions{})

	if !strings.Contains(got, "It is not a\ncompliance statement") {
		t.Error("the document does not disclaim being a compliance statement")
	}
	for _, obligation := range obligationsNotEvidenced {
		if !strings.Contains(got, obligation) {
			t.Errorf("the document does not name the obligation %q", obligation)
		}
	}
}

// A package name comes out of a hostile image and lands in a Markdown table. A
// pipe in one would end the cell early and shift every column after it, which
// turns a crafted package name into a forged row in a compliance document.
func TestCRACellsCannotBreakTheTable(t *testing.T) {
	hostile := model.Component{
		Name:       "evil | injected",
		Version:    "1.0\n| CVE-0000-0000 | forged | 1.0 | low | fix available: 1.0 |",
		Arch:       "arm64",
		PURL:       "pkg:deb/debian/evil@1.0",
		Confidence: model.ConfidenceHigh,
		Evidence:   "var/lib/dpkg/status",
		DistroID:   "debian",
		DistroBase: "debian",
		Distro:     "bullseye",
	}
	findings := []model.Finding{{
		Component: hostile, ID: "CVE-2022-3602\n| also | forged |",
		Severity: model.SeverityHigh, CVSS: 8.1,
		CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}}

	got := renderCRA(t, []model.Component{hostile}, findings, CRAOptions{})

	// One header row, one separator, one finding. Nothing the image supplied
	// may add a fourth.
	var rows int
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "| CVE") || strings.HasPrefix(line, "| Vulnerability |") {
			rows++
		}
	}
	if rows != 2 {
		t.Errorf("findings table has %d rows from a payload that supplied newlines, want 2\n%s", rows, got)
	}
	if strings.Contains(got, "| forged |") {
		t.Errorf("a forged row survived into the document:\n%s", got)
	}
	if !strings.Contains(got, `evil \| injected`) {
		t.Errorf("the pipe in a package name was not escaped:\n%s", got)
	}
}

func TestMdCell(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"ordinary text is unchanged", "openssl 1.1.1n", "openssl 1.1.1n"},
		{"a pipe is escaped", "a|b", `a\|b`},
		{"a backslash is escaped first", `a\b`, `a\\b`},
		{"an escaped pipe cannot be unescaped by the payload", `a\|b`, `a\\\|b`},
		// Sanitize replaces control characters with U+FFFD, so a newline
		// cannot end a table row before mdCell ever sees it.
		{"a newline is replaced, not carried", "a\nb", "a\uFFFDb"},
		{"a carriage return is replaced", "a\rb", "a\uFFFDb"},
		{"an escape sequence is replaced", "a\x1b[31mb", "a\uFFFD[31mb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mdCell(tt.in); got != tt.want {
				t.Errorf("mdCell(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDistributions(t *testing.T) {
	tests := []struct {
		name  string
		comps []model.Component
		want  []string
	}{
		{
			name:  "no distribution at all",
			comps: []model.Component{lowComponent("busybox", "1.30.1", "bin/busybox")},
			want:  nil,
		},
		{
			name: "one distribution is not repeated per package",
			comps: []model.Component{
				highComponent("openssl", "1.1.1n"),
				highComponent("zlib1g", "1.2.11"),
			},
			want: []string{"debian bullseye"},
		},
		{
			name: "an id with no release still names itself",
			comps: []model.Component{{
				Name: "openssl", DistroID: "alpine", DistroBase: "alpine", Confidence: model.ConfidenceHigh,
			}},
			want: []string{"alpine"},
		},
		{
			name: "two distributions are both named, in order",
			comps: []model.Component{
				{Name: "b", DistroID: "ubuntu", DistroBase: "ubuntu", Distro: "jammy"},
				{Name: "a", DistroID: "debian", DistroBase: "debian", Distro: "bullseye"},
			},
			want: []string{"debian bullseye", "ubuntu jammy"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := distributions(tt.comps)
			if len(got) != len(tt.want) {
				t.Fatalf("distributions() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("distributions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// Given the same scan the bytes have to be identical, or the file cannot be
// diffed between builds, which is most of what makes it useful as evidence.
func TestCRAIsDeterministic(t *testing.T) {
	comps, findings := sampleFindings()
	opts := CRAOptions{SBOMPath: "bom.cdx.json", Warnings: []string{"a warning"}}
	first := renderCRA(t, comps, findings, opts)
	second := renderCRA(t, comps, findings, opts)
	if first != second {
		t.Error("two renderings of the same scan differ")
	}
}

// A release out of free support puts the reader in one of two situations, and
// the document has to say which. Either the vulnerabilities below were
// recovered from the vendor's own records, or there was nothing to recover them
// from and the list is short because the data is gone. Telling somebody to
// distrust a report that is complete is its own kind of wrong, and it is the
// wording this project would most deserve to be criticised for getting lazy
// about.
func TestCRASaysWhereRecoveredFindingsCameFrom(t *testing.T) {
	comps, findings := sampleFindings()

	// After bullseye left free support on 2026-08-31.
	info := fixedInfo()
	info.StartedAt = time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)

	render := func(t *testing.T, findings []model.Finding) string {
		t.Helper()
		var buf bytes.Buffer
		if err := CRA(&buf, "0.1.0", info, comps, findings, CRAOptions{}); err != nil {
			t.Fatalf("CRA: %v", err)
		}
		return buf.String()
	}

	t.Run("recovered from a fallback source", func(t *testing.T) {
		recovered := slices.Clone(findings)
		for i := range recovered {
			recovered[i].Source = "security-tracker.debian.org"
		}
		got := render(t, recovered)
		if !strings.Contains(got, "read from security-tracker.debian.org") {
			t.Errorf("the document does not name the source it fell back to:\n%s", got)
		}
		if strings.Contains(got, "the section below is incomplete") {
			t.Errorf("the document calls a recovered section incomplete:\n%s", got)
		}
	})

	t.Run("nothing recovered it", func(t *testing.T) {
		got := render(t, findings)
		if !strings.Contains(got, "the section below is incomplete") {
			t.Errorf("the document does not warn that the data is gone:\n%s", got)
		}
	})

	t.Run("the support status itself is stated either way", func(t *testing.T) {
		for _, f := range [][]model.Finding{findings, nil} {
			if got := render(t, f); !strings.Contains(got, "Support status: paid tier only") {
				t.Errorf("the support status is missing:\n%s", got)
			}
		}
	})
}
