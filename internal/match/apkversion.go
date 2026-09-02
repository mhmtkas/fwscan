package match

import "strings"

// apk version parsing and comparison.
//
// This is written from the format documented in apk-package(5), section
// "PACKAGE NAMES AND VERSIONS", and pinned to apk's own answers by an oracle
// test. It is deliberately not derived from apk-tools' implementation, which is
// GPL-2.0-only where this project is Apache-2.0.
//
// The documented format is
//
//	number{.number}...{letter}{_suffix{number}}...{-r#}
//
// and the documented suffix ordering is
//
//	alpha, beta, pre, rc, <no suffix>, cvs, svn, git, hg, p
//
// where "<no suffix>" is a position in the middle of the list rather than the
// absence of one. That single detail is most of the algorithm: it is why a
// pre-release sorts below the plain version and a patch release above it.
//
// It matters because go-deb-version, which handles the Debian side, does not
// reject an apk version -- it silently answers by Debian's rules. It orders
// 1.0_alpha1 above 1.0, where apk orders it below. OSV decides on the server
// which versions a record affects, so a wrong local ordering cannot suppress a
// finding; what it corrupts is the choice of fixed version, which picks the fix
// window containing the installed version and, under the wrong rules, names a
// later release's fix than the one that applies (spike/NOTES.md T0.5, question
// 4).
//
// Three rules the manual page does not state are taken from apk's observed
// behaviour, and apkversion_oracle_test.go holds them against apk itself:
//
//   - A component written with leading zeros is a fraction rather than an
//     integer, so 1.00 sorts below 1.0 and 1.000 below 1.00, while 1.01 sorts
//     below 1.1 the way .01 sorts below .1. Only components introduced by a dot
//     read this way; a leading zero on the first component is just a digit.
//   - Letters and numbers may alternate, so 1.0a1a is a version -- but a letter
//     must follow a number, so 1.0aa is not.
//   - A trailing separator ends the version instead of invalidating it: 1.0-r
//     means 1.0-r0, 1.0. carries one more component than 1.0, and 1.0_ carries
//     an unwritten suffix.

// apkMaxDigits bounds a single run of digits. Eighteen digits is more than any
// real version carries and the last width that cannot overflow int64, so a
// longer run is refused rather than silently wrapped.
const apkMaxDigits = 18

// An apk version compares as a sequence of parts, and the first pair that
// differs decides. The class of a part therefore matters as much as its value,
// and the classes are ordered by how late they may appear in the format:
// continuing with a further number makes a version newer than continuing with a
// letter, which is newer than continuing with a suffix, and so on down to
// having nothing left to say.
type apkPartClass int

const (
	apkNumber apkPartClass = iota
	apkLetter
	apkSuffix
	apkSuffixNumber
	apkRevision
	// apkAbsent is never produced by the parser. It is what the shorter of two
	// versions compares as once it has run out of parts.
	apkAbsent
)

type apkPart struct {
	class apkPartClass
	value int64
}

// apkSuffixRanks scores the documented suffix ordering, with the pre-release
// suffixes below zero and the post-release ones from zero up. Where "<no
// suffix>" falls is not expressed here but in compareAPKPart, because absence
// is not a suffix with a score: it sorts above a pre-release suffix and below
// every other one. Longer names are listed before their own prefixes so that
// "pre" is not read as "p".
var apkSuffixRanks = []struct {
	name string
	rank int64
}{
	{"alpha", -4},
	{"beta", -3},
	{"pre", -2},
	{"rc", -1},
	{"cvs", 0},
	{"svn", 1},
	{"git", 2},
	{"hg", 3},
	{"p", 4},
}

// apkSuffixRank scores the suffix at the head of s and reports how many bytes
// it spans, or 0 when s does not start with a suffix apk knows.
func apkSuffixRank(s string) (rank int64, n int) {
	for _, suffix := range apkSuffixRanks {
		if strings.HasPrefix(s, suffix.name) {
			return suffix.rank, len(suffix.name)
		}
	}
	return 0, 0
}

type apkParser struct {
	in    string
	i     int
	parts []apkPart
}

// parseAPKVersion splits a version into its comparable parts, or reports that
// the string is not an apk version. The empty string is rejected, where apk
// accepts it: an empty version reaching the matcher means a cataloger produced
// nothing useful, and concluding an ordering from it would be worse than
// declining to.
func parseAPKVersion(s string) ([]apkPart, bool) {
	if s == "" {
		return nil, false
	}
	p := apkParser{in: s}
	if !p.core() || !p.suffixes() || !p.revisions() || p.i != len(p.in) {
		return nil, false
	}
	return p.parts, true
}

// core reads the numeric components together with any letters interleaved
// among them. A letter may only follow a number and a bare number may only
// follow a letter, which is what makes 1.0a1a a version and 1.0aa not one.
func (p *apkParser) core() bool {
	// The first component is a plain integer -- a leading zero on it is just a
	// digit -- and it may be empty, which is how a version may open with a
	// letter.
	v, ok := p.digits()
	if !ok {
		return false
	}
	p.emit(apkNumber, v)

	afterNumber := true
	for p.i < len(p.in) {
		c := p.in[p.i]
		switch {
		case c == '.' && afterNumber:
			p.i++
			if !p.dottedComponent() {
				return false
			}
		case isASCIILower(c) && afterNumber:
			p.emit(apkLetter, int64(c))
			p.i++
			afterNumber = false
		case isASCIIDigit(c) && !afterNumber:
			v, ok := p.digits()
			if !ok {
				return false
			}
			p.emit(apkNumber, v)
			afterNumber = true
		default:
			// Not part of the core; hand the rest to suffixes and revisions.
			return true
		}
	}
	return true
}

// dottedComponent reads one component after a dot, where leading zeros mean a
// fraction. The redundant zeros are absorbed into a depth marker that sinks the
// component below any written without them, one step per zero; the last zero
// stays with the digits so that .01 still carries the value 1.
func (p *apkParser) dottedComponent() bool {
	zeros := 0
	for p.i+zeros < len(p.in) && p.in[p.i+zeros] == '0' {
		zeros++
	}
	if zeros > 0 {
		p.emit(apkNumber, int64(1-zeros))
		p.i += zeros - 1
	}
	v, ok := p.digits()
	if !ok {
		return false
	}
	p.emit(apkNumber, v)
	return true
}

// suffixes reads the _suffix{number} components. A lone trailing underscore is
// accepted and stands at the "<no suffix>" position of the documented ordering.
func (p *apkParser) suffixes() bool {
	for p.i < len(p.in) && p.in[p.i] == '_' {
		p.i++
		if p.i == len(p.in) {
			// An underscore with nothing after it is a suffix nobody wrote.
			// apk scores it as the first post-release suffix, which makes
			// 1.0_ and 1.0_cvs the same version.
			p.emit(apkSuffix, 0)
			return true
		}
		rank, n := apkSuffixRank(p.in[p.i:])
		if n == 0 {
			return false
		}
		p.i += n
		p.emit(apkSuffix, rank)

		if p.i < len(p.in) && isASCIIDigit(p.in[p.i]) {
			v, ok := p.digits()
			if !ok {
				return false
			}
			p.emit(apkSuffixNumber, v)
		}
	}
	return true
}

// revisions reads the -r{number} build components. apk accepts more than one,
// and a trailing -r with no digits reads as -r0.
func (p *apkParser) revisions() bool {
	for p.i+1 < len(p.in) && p.in[p.i] == '-' && p.in[p.i+1] == 'r' {
		p.i += 2
		v, ok := p.digits()
		if !ok {
			return false
		}
		p.emit(apkRevision, v)
	}
	return true
}

// digits reads the run of digits at the cursor, which may be empty. It reports
// false for a run long enough to overflow, rather than returning a wrapped
// value that would compare wrongly without saying so.
func (p *apkParser) digits() (int64, bool) {
	start := p.i
	var v int64
	for p.i < len(p.in) && isASCIIDigit(p.in[p.i]) {
		v = v*10 + int64(p.in[p.i]-'0')
		p.i++
	}
	return v, p.i-start < apkMaxDigits
}

func (p *apkParser) emit(class apkPartClass, value int64) {
	p.parts = append(p.parts, apkPart{class: class, value: value})
}

// apkVersionValid reports whether a string parses as an apk version.
func apkVersionValid(s string) bool {
	_, ok := parseAPKVersion(s)
	return ok
}

// apkVersionCompare returns -1, 0 or 1 for a sorting before, equal to, or
// after b. Both versions must already have passed apkVersionValid; an
// unparseable one compares as if it had no parts at all.
func apkVersionCompare(a, b string) int {
	pa, _ := parseAPKVersion(a)
	pb, _ := parseAPKVersion(b)
	return compareAPKParts(pa, pb)
}

func compareAPKParts(a, b []apkPart) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareAPKPart(a[i], b[i]); c != 0 {
			return c
		}
	}
	// Everything in common is equal, so whichever version still has something
	// to say decides -- in which direction is compareAPKPart's business.
	switch {
	case len(a) > len(b):
		return compareAPKPart(a[len(b)], apkPart{class: apkAbsent})
	case len(b) > len(a):
		return -compareAPKPart(b[len(a)], apkPart{class: apkAbsent})
	}
	return 0
}

// compareAPKPart orders one pair of parts. Parts of the same class compare by
// value. Across classes, a pre-release suffix is the only part that can make
// the longer version the older one, so it loses to whatever it is against;
// failing that, the part belonging to the earlier position in the format wins,
// which leaves having run out as the oldest thing a version can do.
func compareAPKPart(a, b apkPart) int {
	if a.class == b.class {
		switch {
		case a.value < b.value:
			return -1
		case a.value > b.value:
			return 1
		default:
			return 0
		}
	}
	switch {
	case a.class == apkSuffix && a.value < 0:
		return -1
	case b.class == apkSuffix && b.value < 0:
		return 1
	case a.class < b.class:
		return 1
	default:
		return -1
	}
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func isASCIILower(c byte) bool { return c >= 'a' && c <= 'z' }
