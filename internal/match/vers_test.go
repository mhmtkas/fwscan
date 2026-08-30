package match

import "testing"

// The table the spike cross-checked against `dpkg --compare-versions`, carried
// into the code as a real test (spike/NOTES.md T0.5). dpkg is the oracle; if
// go-deb-version ever drifts from it, this catches it.
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"backport revisions", "1.1.1k-1+deb11u1", "1.1.1k-1+deb11u2", -1},
		{"backport vs later upstream", "1.1.1k-1+deb11u2", "1.1.1n-0+deb11u1", -1},
		{"openssh backport", "8.4p1-5+deb11u1", "8.4p1-5+deb11u3", -1},
		{"suffix compares numerically, not lexically", "3.7.9-2+deb12u7", "3.7.9-2+deb12u10", -1},
		{"epoch beats no epoch", "1:1.2.11.dfsg-2", "1.2.11.dfsg-2", 1},
		{"epoch ordering", "1:1.2.11.dfsg-2", "2:1.0-1", -1},
		{"tilde sorts before the release", "1.0~rc1", "1.0", -1},
		{"tilde ordering", "1.0~rc1", "1.0~rc2", -1},
		{"native before revisioned", "1.0", "1.0-1", -1},
		{"binNMU is newer", "5.1-2", "5.1-2+b3", -1},
		{"binary epoch outranks the source version", "1:2.36.1-8+deb11u1", "2.36.1-8+deb11u1", 1},
		{"security revisions", "2.36.1-8+deb11u1", "2.36.1-8+deb11u2", -1},
		{"upstream bump", "1.2.13.dfsg-1", "1.2.11.dfsg-2+deb11u2", 1},
		{"equal", "1.0", "1.0", 0},
		{"digits", "0", "1", -1},
		{"+really", "1.0+really1.3.1-1", "1.0-1", 1},
		{"binNMU vs plain", "2.38.1-5+deb12u3+b1", "2.38.1-5+deb12u3", 1},
		{"deb suffix added", "1.30.1-6", "1.30.1-6+deb11u1", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := compareVersions(tt.a, tt.b)
			if !ok {
				t.Fatalf("compareVersions(%q, %q) could not parse", tt.a, tt.b)
			}
			if sign(got) != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, sign(got), tt.want)
			}
			// The reverse comparison must agree, or ordering is not a total order.
			back, _ := compareVersions(tt.b, tt.a)
			if sign(back) != -tt.want {
				t.Errorf("reverse compareVersions(%q, %q) = %d, want %d", tt.b, tt.a, sign(back), -tt.want)
			}
		})
	}
}

func TestCompareVersionsUnparseable(t *testing.T) {
	for _, pair := range [][2]string{
		{"not a version!", "1.0"},
		{"1.0", "also bad!"},
		{"", "1.0"},
	} {
		if _, ok := compareVersions(pair[0], pair[1]); ok {
			t.Errorf("compareVersions(%q, %q) claimed to parse", pair[0], pair[1])
		}
		// An unknown ordering must never look like "before the fix".
		if versionLess(pair[0], pair[1]) {
			t.Errorf("versionLess(%q, %q) = true on unparseable input", pair[0], pair[1])
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
