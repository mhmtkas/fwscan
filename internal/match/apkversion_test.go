package match

import (
	"encoding/json"
	"testing"
)

// Every pair below was checked against `apk version -t` from apk-tools 2.14.4;
// apkversion_oracle_test.go runs the full corpus (3844 pairs) against it. apk is
// the oracle. If this table and apk ever disagree, apk is right.
func TestAPKVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"pre-release sorts below the release", "1.0_alpha1", "1.0", -1},
		{"post-release sorts above the release", "1.0_p1", "1.0", 1},
		{"pre-suffix ordering", "1.0_alpha1", "1.0_beta1", -1},
		{"pre before rc", "1.0_pre1", "1.0_rc1", -1},
		{"post-suffix ordering", "1.0_cvs", "1.0_git", -1},
		{"suffix number", "1.0_alpha1", "1.0_alpha2", -1},
		{"bare suffix below a numbered one", "1.0_alpha", "1.0_alpha1", -1},
		{"pre-suffix below a post-suffix", "1.0_alpha1-r1", "1.0_p1-r0", -1},
		{"revision compares numerically", "1.0-r2", "1.0-r10", -1},
		{"a revision outranks none", "1.0", "1.0-r0", -1},
		{"dotted components are numbers", "1.9", "1.10", -1},
		{"leading zeros sort below", "1.00", "1.0", -1},
		{"more leading zeros sort lower", "1.000", "1.00", -1},
		{"letter component", "1.0a", "1.0b", -1},
		{"a letter outranks none", "1.0", "1.0a", -1},
		{"openssl release ordering", "1.1.1o-r0", "1.1.1q-r0", -1},
		{"openssh patch suffix", "9.3_p1-r0", "9.3_p2-r0", -1},
		{"openssh across releases", "9.3_p2-r0", "9.6_p1-r0", -1},
		{"equal", "1.36.1-r5", "1.36.1-r5", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apkVersionCompare(tt.a, tt.b); got != tt.want {
				t.Errorf("apkVersionCompare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			// The reverse must agree, or the ordering is not a total order.
			if back := apkVersionCompare(tt.b, tt.a); back != -tt.want {
				t.Errorf("apkVersionCompare(%q, %q) = %d, want %d", tt.b, tt.a, back, -tt.want)
			}
		})
	}
}

func TestAPKVersionValid(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"1.0", true},
		{"1.0-r0", true},
		{"1.0_alpha1-r2", true},
		{"1.2.3a_rc1-r4", true},
		{"01", true},
		// A trailing separator ends the version rather than invalidating it.
		{"1.0.", true},
		{"1.0-r", true},
		{"1.0_foo", false},
		{"1.0-x", false},
		{"1.0__1", false},
		{"notaversion", false},
		{"1.0+1", false},
		// Debian shapes: an epoch, a tilde and a plain revision are all invalid
		// apk, which is the point of comparing per ecosystem.
		{"1:1.0", false},
		{"1.0~rc1", false},
		{"1.0-1", false},
		// apk itself accepts the empty string; the matcher does not, because an
		// empty version means a cataloger produced nothing to compare.
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := apkVersionValid(tt.version); got != tt.want {
				t.Errorf("apkVersionValid(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// The regression this comparator exists for: go-deb-version does not reject an
// apk version, it silently orders it by Debian's rules. The two disagree on
// exactly the pre-release suffixes, and nothing but the ecosystem tells them
// apart (spike/NOTES.md T0.5, question 4).
func TestVersionComparisonIsEcosystemSpecific(t *testing.T) {
	const installed, fix = "1.0_alpha1", "1.0"

	if !versionLess(kindApk, installed, fix) {
		t.Errorf("apk: %q must sort below %q", installed, fix)
	}
	if versionLess(kindDeb, installed, fix) {
		t.Errorf("deb: %q sorting below %q would mean the two rule sets agree, "+
			"and this test no longer proves anything", installed, fix)
	}

	// An ecosystem with no ordering must decline rather than guess.
	if _, ok := compareVersions(kindUnknown, "1.0", "2.0"); ok {
		t.Error("compareVersions claimed an ordering for an unknown ecosystem")
	}
	if versionLess(kindUnknown, "1.0", "2.0") {
		t.Error("versionLess claimed an ordering for an unknown ecosystem")
	}
}

// A record with more than one fix window for the same release is where the
// wrong ordering becomes a wrong answer: output-spec section 1 asks for the
// window containing the installed version, and picking by Debian's rules skips
// past it and names a later release than the one that fixes the issue.
func TestFixedVersionPicksTheWindowContainingAPreRelease(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "ALPINE-CVE-2024-0001",
	  "affected": [{
	    "package": {"ecosystem": "Alpine:v3.16", "name": "demo", "purl": "pkg:apk/alpine/demo?arch=source"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [
	      {"introduced": "0"}, {"fixed": "1.0"},
	      {"introduced": "1.5"}, {"fixed": "2.0"}
	    ]}]
	  }]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	key := queryKey{source: "demo", version: "1.0_alpha1", distro: "v3.16", kind: kindApk}
	if got := fixedVersion(record, key); got != "1.0" {
		t.Errorf("fixedVersion = %q, want 1.0: 1.0_alpha1 is inside the first window", got)
	}

	// Self-guard: this case only covers the regression while the two rule sets
	// still disagree on it. Under Debian's rules 1.0_alpha1 is not below 1.0,
	// so the search falls through the first window and answers 2.0 instead.
	if versionLess(kindDeb, key.version, "1.0") {
		t.Error("Debian rules now agree with apk here; pick a case where they differ")
	}
}
