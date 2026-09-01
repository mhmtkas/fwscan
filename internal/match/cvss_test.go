package match

import "testing"

// Vectors and their published base scores, taken from FIRST's CVSS v3.1
// examples and from the CVE records the spike touched. Any drift in the
// formula shows up here immediately.
func TestCVSS3BaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
		ok     bool
	}{
		{"CVE-2022-0778, network DoS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, true},
		{"CVE-2022-37434, full compromise", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"scope changed raises the score", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, true},
		{"CVE-2014-0160 Heartbleed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, true},
		{"CVE-2009-0658 local, user interaction", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, true},
		{"CVE-2012-1516 scope changed, low privileges", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, true},
		{"adjacent network", "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.0, true},
		{"no impact scores zero", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, true},
		{"scope changed with low impacts", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, true},
		{"v3.0 is accepted too", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"temporal metrics are ignored", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C", 7.5, true},

		{"v2 vector is rejected", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 0, false},
		{"v4 vector is rejected", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L", 0, false},
		{"empty is rejected", "", 0, false},
		{"missing a required metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", 0, false},
		{"unknown metric value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0, false},
		{"garbage after the prefix", "CVSS:3.1/nonsense", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cvss3BaseScore(tt.vector)
			if ok != tt.ok {
				t.Fatalf("cvss3BaseScore(%q) ok = %v, want %v", tt.vector, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("cvss3BaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

func TestRoundUp(t *testing.T) {
	// The specification's Roundup, which is not the same as rounding half up:
	// anything above a tenth goes to the next tenth.
	tests := []struct{ in, want float64 }{
		{4.0, 4.0},
		{4.02, 4.1},
		{4.00, 4.0},
		{6.999999, 7.0},
		{0.0, 0.0},
		{9.95, 10.0},
	}
	for _, tt := range tests {
		if got := roundUp(tt.in); got != tt.want {
			t.Errorf("roundUp(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// CVSS v2 is output-spec section 1's third step and the fallback the spec makes
// mandatory, and it was sixty-five lines of hand-written arithmetic with no test
// at all. v3 and v4 each have both a table and an oracle; v2 had neither, so
// nothing but luck stood between the formula and a transposed constant.
//
// Every expected score below is the published base score for the CVE named
// beside it, taken from the vector in its own NVD record.
func TestCVSS2BaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{"CVE-2014-0160 heartbleed", "AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0},
		{"CVE-2014-6271 shellshock", "AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0},
		{"CVE-2011-3389 beast", "AV:N/AC:M/Au:N/C:P/I:N/A:N", 4.3},
		{"CVE-2016-5195 dirty cow", "AV:L/AC:L/Au:N/C:C/I:C/A:C", 7.2},
		{"CVE-2010-4756", "AV:N/AC:M/Au:S/C:N/I:N/A:P", 3.5},
		{"complete availability only", "AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8},
		{"no impact at all scores zero", "AV:N/AC:L/Au:N/C:N/I:N/A:N", 0.0},
		// Not a published CVE: the corners of the metric space the ones above
		// do not reach. Worked through the v2.0 formula by hand -- impact
		// 10.41 * (1 - (1 - 0.275)^3) = 6.443, exploitability
		// 20 * 0.395 * 0.35 * 0.45 = 1.244, and
		// (0.6 * 6.443 + 0.4 * 1.244 - 1.5) * 1.176 = 3.37.
		{"local, hard, multiple auth", "AV:L/AC:H/Au:M/C:P/I:P/A:P", 3.4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cvss2BaseScore(tt.vector)
			if !ok {
				t.Fatalf("cvss2BaseScore(%q) refused a valid vector", tt.vector)
			}
			if got != tt.want {
				t.Errorf("cvss2BaseScore(%q) = %.1f, want %.1f", tt.vector, got, tt.want)
			}
		})
	}
}

// A vector this cannot score must be refused rather than scored as something
// else: output-spec section 1 falls through to the next step when a vector does
// not parse, and a silently wrong number would stop that happening.
func TestCVSS2RejectsWhatItCannotScore(t *testing.T) {
	for _, vector := range []string{
		"AV:X/AC:L/Au:N/C:P/I:N/A:N",                   // no such access vector
		"AV:N/AC:L/Au:N/C:P/I:N/A:Z",                   // no such impact
		"AV:N/AC:L/Au:N/C:P/I:N",                       // a metric missing
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // a v3 vector
		"",
	} {
		t.Run(vector, func(t *testing.T) {
			if score, ok := cvss2BaseScore(vector); ok {
				t.Errorf("cvss2BaseScore(%q) = %.1f, want it refused", vector, score)
			}
		})
	}
}
