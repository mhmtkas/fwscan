package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/model"
)

func TestSanitize(t *testing.T) {
	const repl = "�"

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ordinary text is untouched", "libssl1.1", "libssl1.1"},
		{"a version is untouched", "1:1.2.11.dfsg-2+deb11u2", "1:1.2.11.dfsg-2+deb11u2"},
		{"the em dash survives", "—", "—"},
		{"non-ascii names survive", "paketé", "paketé"},

		{"escape is replaced", "pkg\x1b[31m", "pkg" + repl + "[31m"},
		{"bell is replaced", "pkg\a", "pkg" + repl},
		{"carriage return is replaced", "a\rb", "a" + repl + "b"},
		{"newline is replaced", "a\nb", "a" + repl + "b"},
		{"tab is replaced", "a\tb", "a" + repl + "b"},
		{"NUL is replaced", "a\x00b", "a" + repl + "b"},
		{"DEL is replaced", "a\x7fb", "a" + repl + "b"},
		{"C1 control is replaced", "a\u0085b", "a" + repl + "b"},
		{"line separator is replaced", "a\u2028b", "a" + repl + "b"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sanitize(tt.in); got != tt.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// A crafted image must not be able to write escape sequences to the reader's
// terminal through the report.
func TestTerminalNeverEmitsControlCharacters(t *testing.T) {
	hostile := model.Component{
		// A colour code, a title-setting OSC sequence, a carriage return to
		// overwrite the line, and a tab to shift the columns.
		Name:       "openssl\x1b[31m\x1b]0;pwned\a",
		Version:    "1.0\r\thidden",
		Confidence: model.ConfidenceHigh,
		Evidence:   "var/lib/dpkg/status",
	}
	info := fixedInfo()
	info.Target = "rootfs\x1b[2Jcleared.squashfs"

	var buf bytes.Buffer
	err := Terminal(&buf, "v0.1.0", info, []model.Component{hostile}, []model.Finding{{
		Component: hostile, ID: "CVE-1\x1b[0m", Severity: model.SeverityCritical,
		CVSS: 9.8, FixedVersion: "2.0\x1b[1m",
	}}, false)
	if err != nil {
		t.Fatalf("Terminal() error = %v", err)
	}

	out := buf.String()
	for _, r := range out {
		if r == '\n' {
			continue // the report's own line breaks
		}
		if unsafeForTerminal(r) {
			t.Fatalf("control character %q reached stdout in:\n%q", r, out)
		}
	}
	// The package is still reported, just defanged.
	if !strings.Contains(out, "openssl") {
		t.Errorf("the package name was lost entirely:\n%s", out)
	}
}

// The trick these two ranges enable is not garbling the terminal but making a
// name read as a different name, which for a tool whose whole output is names
// the reader is asked to trust is the more damaging one.
func TestSanitizeRemovesInvisibleReorderingCharacters(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		// Written as escapes on purpose: pasted verbatim they are invisible in
		// the source too, which is the whole point of them.
		{"right-to-left override", "libssl\u202egnp.so"},
		{"left-to-right override", "libssl\u202dx"},
		{"first strong isolate", "libssl\u2066x\u2069"},
		{"zero width space", "open\u200bssl"},
		{"zero width joiner", "open\u200dssl"},
		{"byte order mark", "\ufeffopenssl"},
		{"word joiner", "open\u2060ssl"},
		{"soft hyphen", "open\u00adssl"},
		{"left-to-right mark", "open\u200essl"},
		{"tag character", "openssl\U000E0041"},
		{"variation selector", "openssl\ufe0f"},
		{"hangul filler", "open\u3164ssl"},
		{"combining grapheme joiner", "open\u034fssl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.input)
			if got == tt.input {
				t.Errorf("Sanitize(%q) left it unchanged", tt.input)
			}
			if !strings.ContainsRune(got, replacementRune) {
				t.Errorf("Sanitize(%q) = %q, want the character replaced visibly", tt.input, got)
			}
		})
	}
}
