package match

import "testing"

// Every score below came from FIRST's reference calculator.
// cvss4_oracle_test.go runs the whole base metric space -- 104,976 vectors --
// against it; this table is the readable subset, one case per behaviour the
// implementation has to get right.
func TestCVSS4BaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{
			"the most severe vector there is",
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
			10.0,
		},
		{
			"total impact on the vulnerable system alone",
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			9.3,
		},
		{
			"attack complexity pulls it down",
			"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
			9.1,
		},
		{
			"local rather than network",
			"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			8.6,
		},
		{
			"privileges required, confidentiality only",
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
			7.1,
		},
		{
			"low impact across the board",
			"CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:H/SI:N/SA:N",
			4.1,
		},
		{
			"partial impact behind a user click",
			"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L",
			2.3,
		},
		{
			"physical access and every barrier raised",
			"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
			1.0,
		},
		{
			// The shortcut in the specification: no impact anywhere is zero
			// without consulting the tables.
			"no impact on anything",
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
			0.0,
		},
		{
			// Debian's OSV records write out every metric, defined or not. The
			// threat and environmental ones must not change the base score.
			"trailing not-defined metrics are ignored",
			"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
			4.8,
		},
		{
			"the same vector without them scores the same",
			"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
			4.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cvss4BaseScore(tt.vector)
			if !ok {
				t.Fatalf("cvss4BaseScore(%q) rejected the vector", tt.vector)
			}
			if got != tt.want {
				t.Errorf("cvss4BaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

// A vector that is not understood must produce no score at all. Guessing at a
// malformed vector would put a number in the SCORE column that nothing backs.
func TestCVSS4BaseScoreRejects(t *testing.T) {
	tests := []struct {
		name   string
		vector string
	}{
		{"empty", ""},
		{"a v3 vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"no version prefix", "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"a missing base metric", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"},
		{"an unknown metric", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:H"},
		{"an unknown value", "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"a base metric taking X", "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"metrics out of order", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"a repeated metric", "CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"a metric with no value", "CVSS:4.0/AV/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if score, ok := cvss4BaseScore(tt.vector); ok {
				t.Errorf("cvss4BaseScore(%q) = %v, want no score", tt.vector, score)
			}
		})
	}
}

// The lookup table is transcribed data, so its shape is worth asserting: a
// dropped line would otherwise only show up as one wrong score somewhere.
func TestCVSS4LookupTableIsComplete(t *testing.T) {
	if len(cvss4MacroVectorScores) != 270 {
		t.Errorf("lookup table has %d entries, want 270", len(cvss4MacroVectorScores))
	}
	for macroVector, score := range cvss4MacroVectorScores {
		if len(macroVector) != 6 {
			t.Errorf("key %q is not six digits", macroVector)
		}
		if score < 0 || score > 10 {
			t.Errorf("%s scores %v, outside 0..10", macroVector, score)
		}
	}
}
