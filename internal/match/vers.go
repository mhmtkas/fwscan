package match

import (
	debversion "github.com/knqyf263/go-deb-version"
)

// Debian version comparison. go-deb-version implements dpkg's algorithm; the
// spike cross-checked it against `dpkg --compare-versions` on 18 cases,
// including the two that matter here: +debXuN suffixes compare numerically, so
// u7 sorts below u10, and an epoch sorts above a version without one
// (spike/NOTES.md T0.5).

// compareVersions reports whether a is less than, equal to, or greater than b,
// returning -1, 0 or 1. The bool is false when either version is unparseable,
// in which case callers must not draw a conclusion from the ordering.
func compareVersions(a, b string) (int, bool) {
	va, err := debversion.NewVersion(a)
	if err != nil {
		return 0, false
	}
	vb, err := debversion.NewVersion(b)
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

// versionLess reports whether a sorts before b. Unparseable input yields false,
// which keeps the caller conservative: an unknown ordering never satisfies a
// "before the fix" test.
func versionLess(a, b string) bool {
	c, ok := compareVersions(a, b)
	return ok && c < 0
}
