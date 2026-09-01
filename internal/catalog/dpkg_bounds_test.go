package catalog

import (
	"strings"
	"testing"
)

// The parser is handed untrusted firmware, so a crafted status file must be
// rejected rather than allowed to exhaust memory (CLAUDE.md rule 9).
func TestParseStatusBounds(t *testing.T) {
	t.Run("too many stanzas", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < maxStanzas+2; i++ {
			b.WriteString("Package: p\nStatus: install ok installed\nVersion: 1\n\n")
		}
		if _, err := parseStatus(strings.NewReader(b.String()), "", ""); err == nil {
			t.Fatal("parseStatus() error = nil, want a stanza-count error")
		} else if !strings.Contains(err.Error(), "stanzas") {
			t.Errorf("error = %v, want it to mention stanzas", err)
		}
	})

	t.Run("unbounded continuation field", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("Package: p\nStatus: install ok installed\nVersion: 1\nDescription: start\n")
		line := " " + strings.Repeat("x", 4096) + "\n"
		for written := 0; written <= maxFieldBytes; written += len(line) {
			b.WriteString(line)
		}
		if _, err := parseStatus(strings.NewReader(b.String()), "", ""); err == nil {
			t.Fatal("parseStatus() error = nil, want a field-size error")
		} else if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("error = %v, want it to mention the size limit", err)
		}
	})

	t.Run("single line longer than the scanner buffer", func(t *testing.T) {
		status := "Package: p\nStatus: install ok installed\nVersion: " +
			strings.Repeat("9", maxLineBytes+1) + "\n"
		if _, err := parseStatus(strings.NewReader(status), "", ""); err == nil {
			t.Fatal("parseStatus() error = nil, want a token-too-long error")
		}
	})

	t.Run("continuation before any field is ignored", func(t *testing.T) {
		status := " orphaned continuation\nPackage: p\nStatus: install ok installed\nVersion: 1\n"
		got, err := parseStatus(strings.NewReader(status), "", "")
		if err != nil {
			t.Fatalf("parseStatus() error = %v", err)
		}
		if len(got) != 1 || got[0].Name != "p" {
			t.Errorf("got %+v, want the single package p", got)
		}
	})

	t.Run("stanza with no Package field is skipped", func(t *testing.T) {
		status := "Status: install ok installed\nVersion: 1\n\nPackage: real\nStatus: install ok installed\nVersion: 2\n"
		got, err := parseStatus(strings.NewReader(status), "", "")
		if err != nil {
			t.Fatalf("parseStatus() error = %v", err)
		}
		if len(got) != 1 || got[0].Name != "real" {
			t.Errorf("got %+v, want only the named package", got)
		}
	})
}
