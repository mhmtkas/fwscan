package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// goldenPath keeps every golden in one place so output-spec changes are easy to
// review as a diff.
func goldenPath(name string) string {
	return filepath.Join("..", "..", "testdata", "golden", name)
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := goldenPath(name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run: go test ./internal/report/ -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output does not match %s\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// fixedInfo has a frozen timestamp and duration so the goldens do not change
// from one run to the next.
func fixedInfo() ScanInfo {
	return ScanInfo{
		Target:      "rootfs.squashfs",
		Format:      "squashfs",
		Compression: "zstd",
		StartedAt:   time.Date(2026, 8, 30, 14, 5, 11, 0, time.UTC),
		Duration:    8421 * time.Millisecond,
	}
}

func highComponent(name, version string) model.Component {
	return model.Component{
		Name: name, Version: version, Arch: "arm64",
		// Percent-encoded exactly as output-spec section 3 requires: "+"
		// becomes %2B.
		PURL:       "pkg:deb/debian/" + name + "@" + strings.ReplaceAll(version, "+", "%2B") + "?arch=arm64&distro=bullseye",
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
	}
}

func lowComponent(name, version, evidence string) model.Component {
	return model.Component{
		Name: name, Version: version,
		Confidence: model.ConfidenceLow, Evidence: evidence,
	}
}

// sampleFindings mirrors the example in output-spec section 2, including a
// finding with no known fix and a low-confidence one.
func sampleFindings() ([]model.Component, []model.Finding) {
	openssl := highComponent("openssl", "1.1.1n-0+deb11u3")
	openssh := highComponent("openssh", "8.4p1-5+deb11u1")
	busybox := lowComponent("busybox", "1.30.1-6", "bin/busybox")
	zlib := highComponent("zlib1g", "1:1.2.11.dfsg-2")

	comps := []model.Component{busybox, openssh, openssl, zlib}
	findings := []model.Finding{
		{
			Component: openssl, ID: "CVE-2022-3602", Severity: model.SeverityCritical,
			CVSS: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			FixedVersion: "1.1.1n-0+deb11u5",
		},
		{
			Component: busybox, ID: "CVE-2022-48174", Severity: model.SeverityCritical,
			CVSS: 9.1, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
		},
		{
			Component: openssh, ID: "CVE-2023-38408", Severity: model.SeverityHigh,
			CVSS: 8.1, FixedVersion: "8.4p1-5+deb11u3",
		},
		{
			Component: zlib, ID: "CVE-2010-4756", Severity: model.SeverityUnknown,
		},
	}
	return comps, findings
}

func TestTerminalGolden(t *testing.T) {
	tests := []struct {
		name      string
		golden    string
		build     func() ([]model.Component, []model.Finding)
		noNetwork bool
	}{
		{
			name:   "findings with a low-confidence component",
			golden: "terminal-findings.txt",
			build:  sampleFindings,
		},
		{
			name:   "no findings",
			golden: "terminal-clean.txt",
			build: func() ([]model.Component, []model.Finding) {
				return []model.Component{
					highComponent("openssl", "3.0.11-1~deb12u2"),
					highComponent("zlib1g", "1:1.2.13.dfsg-1"),
				}, nil
			},
		},
		{
			name:      "no-network mode",
			golden:    "terminal-no-network.txt",
			noNetwork: true,
			build: func() ([]model.Component, []model.Finding) {
				comps, _ := sampleFindings()
				return comps, nil
			},
		},
		{
			name:   "no low-confidence components means no footnote",
			golden: "terminal-no-footnote.txt",
			build: func() ([]model.Component, []model.Finding) {
				openssl := highComponent("openssl", "1.1.1k-1+deb11u1")
				return []model.Component{openssl}, []model.Finding{{
					Component: openssl, ID: "CVE-2022-0778", Severity: model.SeverityHigh,
					CVSS: 7.5, FixedVersion: "1.1.1k-1+deb11u2",
				}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps, findings := tt.build()
			var buf bytes.Buffer
			if err := Terminal(&buf, "v0.1.0", fixedInfo(), comps, findings, tt.noNetwork); err != nil {
				t.Fatalf("Terminal() error = %v", err)
			}
			assertGolden(t, tt.golden, buf.Bytes())
		})
	}
}

func TestTargetLine(t *testing.T) {
	tests := []struct {
		name string
		info ScanInfo
		want string
	}{
		{"format and compression", ScanInfo{Target: "a.tar.gz", Format: "tar", Compression: "gzip"}, "a.tar.gz (tar, gzip)"},
		{"compression omitted when none", ScanInfo{Target: "rootfs", Format: "directory", Compression: "none"}, "rootfs (directory)"},
		{"compression omitted when empty", ScanInfo{Target: "rootfs", Format: "directory"}, "rootfs (directory)"},
		{"no format at all", ScanInfo{Target: "rootfs"}, "rootfs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := targetLine(tt.info); got != tt.want {
				t.Errorf("targetLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCounts(t *testing.T) {
	comps := []model.Component{
		highComponent("a", "1"), highComponent("b", "1"),
		lowComponent("c", "1", "bin/c"),
	}
	got := CountPackages(comps)
	if got != (PackageCounts{Total: 3, HighConfidence: 2, LowConfidence: 1}) {
		t.Errorf("CountPackages() = %+v", got)
	}

	findings := []model.Finding{
		{Severity: model.SeverityCritical}, {Severity: model.SeverityHigh},
		{Severity: model.SeverityMedium}, {Severity: model.SeverityLow},
		{Severity: model.SeverityUnknown}, {Severity: model.Severity("nonsense")},
	}
	wantCounts := FindingCounts{Total: 6, Critical: 1, High: 1, Medium: 1, Low: 1, Unknown: 2}
	if got := CountFindings(findings); got != wantCounts {
		t.Errorf("CountFindings() = %+v, want %+v", got, wantCounts)
	}
}

func TestFormatScore(t *testing.T) {
	// A zero score means unrated, not harmless, so it must not print as 0.0.
	if got := formatScore(0); got != noFixedVersion {
		t.Errorf("formatScore(0) = %q, want %q", got, noFixedVersion)
	}
	if got := formatScore(9.8); got != "9.8" {
		t.Errorf("formatScore(9.8) = %q", got)
	}
	if got := formatScore(10); got != "10.0" {
		t.Errorf("formatScore(10) = %q", got)
	}
}
