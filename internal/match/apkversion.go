package match

import "strings"

// apk version comparison, ported from apk-tools 2.14.4 `src/version.c` (the
// version Alpine 3.19 ships). The algorithm is Gentoo's, not Debian's:
//
//	{digit}{.digit}...{letter}{_suffix{#}}...{-r#}
//
// It matters because `go-deb-version`, which handles the Debian side, does not
// error on an apk version — it silently produces the wrong answer. It orders
// 1.0_alpha1 above 1.0, where apk orders it below, and that is the direction
// that hides a vulnerability: an installed pre-release sorts above the fixed
// version, so the "installed is older than the fix" test fails and the finding
// is dropped (spike/NOTES.md T0.5, question 4).
//
// The port is deliberately literal — same token ladder, same sentinel values,
// same order of tests — so that a future reader can diff it against upstream.
// spike/apkvercmp/ checks it against `apk version -t` as the oracle.

// apkToken is version.c's `enum PARTS`. The numeric order is load-bearing: the
// final comparison, when everything up to that point is equal, decides on which
// token type the two versions diverged at.
type apkToken int

const (
	apkTokenInvalid     apkToken = -1
	apkTokenDigitOrZero apkToken = 0
	apkTokenDigit       apkToken = 1
	apkTokenLetter      apkToken = 2
	apkTokenSuffix      apkToken = 3
	apkTokenSuffixNo    apkToken = 4
	apkTokenRevisionNo  apkToken = 5
	apkTokenEnd         apkToken = 6
)

// Suffix ordering. A pre-suffix scores below zero so it sorts under a version
// with no suffix at all; a post-suffix scores at or above zero so it sorts over
// one. Order within each list is the ordering itself.
var (
	apkPreSuffixes  = []string{"alpha", "beta", "pre", "rc"}
	apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}
)

// apkScanner walks a version string one token at a time, carrying the type of
// the token it is about to read. It is version.c's (blob, type) pair.
type apkScanner struct {
	s   string
	tok apkToken
}

// next decides the type of the token that follows, consuming the separator that
// announced it. It is version.c's next_token().
func (sc *apkScanner) next() {
	n := apkTokenInvalid

	switch {
	case sc.s == "" || sc.s[0] == 0:
		n = apkTokenEnd
	case (sc.tok == apkTokenDigit || sc.tok == apkTokenDigitOrZero) && isASCIILower(sc.s[0]):
		n = apkTokenLetter
	case sc.tok == apkTokenLetter && isASCIIDigit(sc.s[0]):
		n = apkTokenDigit
	case sc.tok == apkTokenSuffix && isASCIIDigit(sc.s[0]):
		n = apkTokenSuffixNo
	default:
		switch sc.s[0] {
		case '.':
			n = apkTokenDigitOrZero
		case '_':
			n = apkTokenSuffix
		case '-':
			// Only "-r" starts a revision. A bare "-" is not valid apk.
			if len(sc.s) > 1 && sc.s[1] == 'r' {
				n = apkTokenRevisionNo
				sc.s = sc.s[1:]
			}
		}
		sc.s = sc.s[1:]
	}

	// Tokens may only move forward along the ladder, with three exceptions:
	// another dotted component, another suffix, and a digit run after a letter.
	switch {
	case n >= sc.tok:
	case n == apkTokenDigitOrZero && sc.tok == apkTokenDigit,
		n == apkTokenSuffix && sc.tok == apkTokenSuffixNo,
		n == apkTokenDigit && sc.tok == apkTokenLetter:
	default:
		n = apkTokenInvalid
	}
	sc.tok = n
}

// get consumes the next token and returns its comparable value. It is
// version.c's get_token(). A return of -1 with the scanner left on
// apkTokenInvalid is the error signal, and the caller must check the token
// rather than the value: -1 is also a legitimate value for a "rc" suffix.
func (sc *apkScanner) get() int64 {
	if sc.s == "" {
		sc.tok = apkTokenEnd
		return 0
	}

	i := 0
	next := apkTokenInvalid
	var v int64

	switch sc.tok {
	case apkTokenDigitOrZero, apkTokenDigit, apkTokenSuffixNo, apkTokenRevisionNo:
		// A dotted component written with leading zeros is a fraction, not an
		// integer: 1.00 sorts below 1.0, and each extra zero pushes it lower.
		if sc.tok == apkTokenDigitOrZero && sc.s[0] == '0' {
			for i+1 < len(sc.s) && sc.s[i+1] == '0' {
				i++
			}
			next = apkTokenDigit
			v = int64(-i)
			break
		}
		for i < len(sc.s) && isASCIIDigit(sc.s[i]) {
			v = v*10 + int64(sc.s[i]-'0')
			i++
		}
		// Upstream's overflow guard: 18 digits is more than any real version
		// and more than int64 can be trusted to hold through the multiply.
		if i >= 18 {
			sc.tok = apkTokenInvalid
			return -1
		}
	case apkTokenLetter:
		v = int64(sc.s[i])
		i++
	case apkTokenSuffix:
		value, n := apkSuffixValue(sc.s)
		if n == 0 {
			sc.tok = apkTokenInvalid
			return -1
		}
		v, i = value, n
	default:
		sc.tok = apkTokenInvalid
		return -1
	}

	sc.s = sc.s[i:]
	switch {
	case sc.s == "":
		sc.tok = apkTokenEnd
	case next != apkTokenInvalid:
		sc.tok = next
	default:
		sc.next()
	}
	return v
}

// apkSuffixValue scores a suffix and reports how many bytes it spans, or 0 when
// the text is not a suffix apk knows. Pre-suffixes are tried first, so "_pre1"
// is "pre" and not the post-suffix "p" followed by junk.
func apkSuffixValue(s string) (value int64, n int) {
	for i, suffix := range apkPreSuffixes {
		if strings.HasPrefix(s, suffix) {
			return int64(i - len(apkPreSuffixes)), len(suffix)
		}
	}
	for i, suffix := range apkPostSuffixes {
		if strings.HasPrefix(s, suffix) {
			return int64(i), len(suffix)
		}
	}
	return 0, 0
}

// apkVersionValid reports whether a string parses cleanly all the way to the
// end. It is version.c's apk_version_validate(), except that the empty string
// is rejected: upstream accepts it, but an empty version reaching the matcher
// means a cataloger produced nothing useful, and concluding an ordering from it
// would be worse than declining to.
func apkVersionValid(s string) bool {
	if s == "" {
		return false
	}
	sc := apkScanner{s: s, tok: apkTokenDigit}
	for sc.tok != apkTokenEnd && sc.tok != apkTokenInvalid {
		sc.get()
	}
	return sc.tok == apkTokenEnd
}

// apkVersionCompare returns -1, 0 or 1 for a before, equal to, or after b. It
// is version.c's apk_version_compare_blob_fuzzy() with fuzzy off, and assumes
// both inputs already passed apkVersionValid.
func apkVersionCompare(a, b string) int {
	sa := apkScanner{s: a, tok: apkTokenDigit}
	sb := apkScanner{s: b, tok: apkTokenDigit}

	var av, bv int64
	for sa.tok == sb.tok && sa.tok != apkTokenEnd && sa.tok != apkTokenInvalid && av == bv {
		av = sa.get()
		bv = sb.get()
	}

	switch {
	case av < bv:
		return -1
	case av > bv:
		return 1
	}
	if sa.tok == sb.tok {
		return 0
	}

	// Everything read so far is equal and one string still has tokens left.
	// The longer one is the newer one -- unless what it continues with is a
	// pre-release suffix, which makes it older: 1.0_alpha1 < 1.0 < 1.0_p1.
	if sa.tok == apkTokenSuffix {
		peek := sa
		if peek.get() < 0 {
			return -1
		}
	}
	if sb.tok == apkTokenSuffix {
		peek := sb
		if peek.get() < 0 {
			return 1
		}
	}
	switch {
	case sa.tok > sb.tok:
		return -1
	case sb.tok > sa.tok:
		return 1
	}
	return 0
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func isASCIILower(c byte) bool { return c >= 'a' && c <= 'z' }
