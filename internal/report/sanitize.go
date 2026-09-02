package report

import (
	"strings"
	"unicode"
)

// Sanitize makes a string from an untrusted image safe to write to a terminal.
//
// Package names, versions and paths are attacker-controlled: they come out of a
// firmware image fwscan makes no assumptions about. An escape sequence in one of
// them reaches the reader's terminal verbatim, where it can recolour,
// reposition or hide output. A report that can be made to lie about itself is
// worse than no report.
//
// It is exported because the report is not the only thing an image's own words
// reach the terminal through. An error message names the archive entry that
// caused it, and an entry name is as attacker-controlled as a package name, so
// the CLI applies this to everything it prints on the error path.
//
// Characters are replaced rather than dropped, so a field that contained
// something still shows that it did.
//
// The JSON report and the SBOM need no equivalent: JSON encoding escapes
// control characters on its own.
func Sanitize(s string) string {
	if !strings.ContainsFunc(s, unsafeForTerminal) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unsafeForTerminal(r) {
			b.WriteRune(replacementRune)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// replacementRune stands in for anything unprintable. U+FFFD is the
// conventional choice and renders visibly in every terminal font.
const replacementRune = '�'

func unsafeForTerminal(r rune) bool {
	switch {
	case r == '\t':
		// tabwriter reads a tab as a column separator, so one inside a package
		// name would shift the whole row.
		return true
	case r < 0x20 || r == 0x7F:
		// C0 controls and DEL. This is the one that matters: ESC lives here.
		return true
	case r >= 0x80 && r <= 0x9F:
		// C1 controls, which some terminals still honour as escapes.
		return true
	case r == '\u2028' || r == '\u2029':
		// Line and paragraph separators.
		return true
	case r >= '\u202A' && r <= '\u202E', r >= '\u2066' && r <= '\u2069':
		// Bidirectional overrides and isolates. These reorder the characters
		// around them without being visible themselves, so a package name can
		// be made to read as a different one -- the Trojan Source trick. A
		// scanner's whole output is names the reader is asked to trust.
		return true
	case unicode.Is(unicode.Cf, r):
		// Every format character: the zero-width space, joiner and
		// non-joiner, the word joiner, the soft hyphen, the byte order mark,
		// the directional marks, the tag block. None of them is visible, and
		// two names that render identically must not be able to hide that
		// they differ. The category is used rather than a list, because a
		// list is only ever as complete as the last attack someone thought of.
		return true
	case r >= '\uFE00' && r <= '\uFE0F', r >= 0xE0100 && r <= 0xE01EF:
		// Variation selectors: marks that change how the previous character
		// is drawn, or not at all.
		return true
	case r == '\u034F', r == '\u115F', r == '\u1160', r == '\u3164', r == '\uFFA0':
		// The combining grapheme joiner and the Hangul fillers, which are
		// letters by category and blank on screen.
		return true
	default:
		return false
	}
}
