package match

import (
	debversion "github.com/knqyf263/go-deb-version"
)

// Version comparison, dispatched per ecosystem.
//
// Debian and Alpine do not share an ordering, and neither library rejects the
// other's input -- go-deb-version parses an apk version happily and returns the
// wrong answer (spike/NOTES.md T0.5, question 4). So the comparison is keyed on
// the same packageKind that decided the query shape: whatever chose how to ask
// OSV also chooses how to read the answer.
//
// go-deb-version implements dpkg's algorithm; the spike cross-checked it
// against `dpkg --compare-versions` on 18 cases, including the two that matter
// here: +debXuN suffixes compare numerically, so u7 sorts below u10, and an
// epoch sorts above a version without one (spike/NOTES.md T0.5). apk's
// algorithm lives in apkversion.go.

// compareVersions reports whether a is less than, equal to, or greater than b,
// returning -1, 0 or 1. The bool is false when either version is unparseable
// for the given ecosystem, or when the ecosystem is not one with a known
// ordering; callers must not draw a conclusion from the ordering in that case.
func compareVersions(kind packageKind, a, b string) (int, bool) {
	switch kind {
	case kindDeb:
		va, err := debversion.NewVersion(a)
		if err != nil {
			return 0, false
		}
		vb, err := debversion.NewVersion(b)
		if err != nil {
			return 0, false
		}
		return va.Compare(vb), true
	case kindApk:
		if !apkVersionValid(a) || !apkVersionValid(b) {
			return 0, false
		}
		return apkVersionCompare(a, b), true
	default:
		return 0, false
	}
}

// versionLess reports whether a sorts before b. Unparseable input yields false,
// which keeps the caller conservative: an unknown ordering never satisfies a
// "before the fix" test.
func versionLess(kind packageKind, a, b string) bool {
	c, ok := compareVersions(kind, a, b)
	return ok && c < 0
}
