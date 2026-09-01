package match

import (
	"math"
	"strings"
)

// CVSS v3.x base-score computation, per the specification's formula. There is
// no permitted dependency that does this (CLAUDE.md rule 7), and output-spec
// section 1 asks for it to be implemented with a table-driven test against
// published vectors rather than approximated.
//
// Only base metrics are read. Temporal and environmental metrics may be present
// in a vector and are ignored, which is correct: the base score is what the
// severity buckets are defined against.

// baseMetrics holds the eight base metrics a v3 vector must carry.
type baseMetrics struct {
	attackVector, attackComplexity           float64
	privilegesRequired, userInteraction      float64
	confidentiality, integrity, availability float64
	scopeChanged                             bool
}

// cvss3BaseScore computes the base score for a CVSS v3.0 or v3.1 vector.
// The bool reports whether the vector was understood; an unparseable or
// incomplete vector yields no score rather than a wrong one.
func cvss3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, false
	}

	var (
		m         baseMetrics
		seen      = map[string]bool{}
		privToken string
	)
	for _, part := range strings.Split(vector, "/")[1:] {
		key, value, found := strings.Cut(part, ":")
		if !found {
			continue
		}
		switch key {
		case "AV":
			m.attackVector, found = lookup(value, map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
		case "AC":
			m.attackComplexity, found = lookup(value, map[string]float64{"L": 0.77, "H": 0.44})
		case "PR":
			// PR depends on Scope, which may appear later in the vector, so the
			// token is stored and resolved after the whole vector is read.
			privToken, found = value, value == "N" || value == "L" || value == "H"
		case "UI":
			m.userInteraction, found = lookup(value, map[string]float64{"N": 0.85, "R": 0.62})
		case "S":
			m.scopeChanged, found = value == "C", value == "C" || value == "U"
		case "C":
			m.confidentiality, found = lookup(value, map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
		case "I":
			m.integrity, found = lookup(value, map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
		case "A":
			m.availability, found = lookup(value, map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
		default:
			continue // temporal and environmental metrics
		}
		if !found {
			return 0, false
		}
		seen[key] = true
	}

	for _, required := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if !seen[required] {
			return 0, false
		}
	}

	// Privileges Required is scored differently when Scope is Changed.
	if m.scopeChanged {
		m.privilegesRequired, _ = lookup(privToken, map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50})
	} else {
		m.privilegesRequired, _ = lookup(privToken, map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27})
	}

	return m.score(), true
}

func lookup(key string, table map[string]float64) (float64, bool) {
	v, ok := table[key]
	return v, ok
}

func (m baseMetrics) score() float64 {
	iss := 1 - (1-m.confidentiality)*(1-m.integrity)*(1-m.availability)

	var impact float64
	if m.scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * m.attackVector * m.attackComplexity * m.privilegesRequired * m.userInteraction

	total := impact + exploitability
	if m.scopeChanged {
		total *= 1.08
	}
	return roundUp(math.Min(total, 10))
}

// roundUp implements the specification's Roundup: round up to one decimal
// place, computed on integers so that values already at a tenth are not nudged
// upward by floating-point noise.
func roundUp(f float64) float64 {
	i := int64(math.Round(f * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}

// CVSS v2 base-score computation. output-spec section 1 keeps v2 as a fallback
// when a record has no v3 vector. Debian's OSV data carried none across the 292
// records the spike examined, so this path is unlikely to fire for Debian
// images — but the spec asks for it and other ecosystems still publish v2.
func cvss2BaseScore(vector string) (float64, bool) {
	access := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}
	complexity := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
	authentication := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
	impact := map[string]float64{"N": 0.0, "P": 0.275, "C": 0.660}

	var av, ac, au, c, i, a float64
	seen := map[string]bool{}
	for _, part := range strings.Split(strings.TrimPrefix(vector, "AV:"), "/") {
		key, value, found := strings.Cut(part, ":")
		if !found {
			// The first segment loses its key to the TrimPrefix above.
			key, value = "AV", part
		}
		var table map[string]float64
		switch key {
		case "AV":
			table = access
		case "AC":
			table = complexity
		case "Au":
			table = authentication
		case "C", "I", "A":
			table = impact
		default:
			continue
		}
		v, ok := table[value]
		if !ok {
			return 0, false
		}
		switch key {
		case "AV":
			av = v
		case "AC":
			ac = v
		case "Au":
			au = v
		case "C":
			c = v
		case "I":
			i = v
		case "A":
			a = v
		}
		seen[key] = true
	}
	for _, required := range []string{"AV", "AC", "Au", "C", "I", "A"} {
		if !seen[required] {
			return 0, false
		}
	}

	impactScore := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	exploitability := 20 * av * ac * au
	fImpact := 1.176
	if impactScore == 0 {
		fImpact = 0
	}
	score := ((0.6 * impactScore) + (0.4 * exploitability) - 1.5) * fImpact
	// Not "< 0": the arithmetic can produce a negative zero, which is
	// equal to zero and encodes in JSON as -0. A report should not carry a
	// score nobody can explain.
	if score <= 0 {
		score = 0
	}
	// v2 rounds to one decimal place, ordinary rounding rather than v3's Roundup.
	return math.Round(score*10) / 10, true
}
