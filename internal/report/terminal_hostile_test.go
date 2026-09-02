package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/model"
)

// A package name or version carrying a tab would break the tabwriter's column
// alignment, and both come from an untrusted image.
func TestTabInFieldDoesNotBreakTheTable(t *testing.T) {
	comp := model.Component{
		Name: "evil\tname", Version: "1.0\t-1",
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
	}
	var buf bytes.Buffer
	err := Terminal(&buf, "v0.1.0", fixedInfo(), []model.Component{comp},
		[]model.Finding{{Component: comp, ID: "CVE-1", Severity: model.SeverityHigh, CVSS: 7.5}}, false)
	if err != nil {
		t.Fatalf("Terminal() error = %v", err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "\t") {
			t.Errorf("a tab from the image reached the output: %q", line)
		}
	}
}

// Control characters and ANSI escapes from an image must not reach a terminal.
func TestControlCharactersAreNotEmitted(t *testing.T) {
	comp := model.Component{
		Name: "pkg\x1b[31m", Version: "1.0\x07",
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
	}
	var buf bytes.Buffer
	if err := Terminal(&buf, "v0.1.0", fixedInfo(), []model.Component{comp},
		[]model.Finding{{Component: comp, ID: "CVE-1", Severity: model.SeverityHigh, CVSS: 7.5}}, false); err != nil {
		t.Fatalf("Terminal() error = %v", err)
	}
	if strings.ContainsAny(buf.String(), "\x1b\x07") {
		t.Errorf("an escape sequence from the image reached stdout: %q", buf.String())
	}
}
