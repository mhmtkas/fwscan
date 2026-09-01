package match

import (
	"math"
	"slices"
	"strings"
)

// CVSS v4.0 base-score computation.
//
// v4 abandoned v3's closed-form formula. A vector is first reduced to a
// six-digit MacroVector, one digit per equivalence class (EQ1..EQ6); that
// MacroVector has a hand-assigned score in cvss4_lookup.go; and the vector's
// own score is that number minus an interpolated distance, measured by how far
// the vector sits from the most severe vector its MacroVector can contain. None
// of it can be derived, so the tables below are transcribed from FIRST's
// reference calculator (github.com/FIRSTdotorg/cvss-v4-calculator at commit
// c5b0d409ae9f57c44264c6ce5f27d89298e1d32a) and checked against it by the
// oracle test in cvss4_oracle_test.go.
//
// That calculator is Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and
// contributors, and is licensed BSD-2-Clause, which requires its copyright
// notice, conditions and disclaimer to travel with any copy. They are in
// THIRD_PARTY_LICENSES.txt at the root of this repository, which also ships in
// every release archive.
//
// Only the base score is computed. Threat and environmental metrics are
// validated when a vector carries them but do not contribute, exactly as the v3
// path ignores temporal and environmental metrics: output-spec section 1's
// buckets are defined against the base score.

// cvss4MetricValues is the full metric set with the values each accepts, in the
// specification's order. Parsing enforces both, because a vector that carries a
// metric the specification does not define is not a vector this can score.
var cvss4MetricValues = []struct {
	key    string
	values []string
}{
	// Base.
	{"AV", []string{"N", "A", "L", "P"}},
	{"AC", []string{"L", "H"}},
	{"AT", []string{"N", "P"}},
	{"PR", []string{"N", "L", "H"}},
	{"UI", []string{"N", "P", "A"}},
	{"VC", []string{"H", "L", "N"}},
	{"VI", []string{"H", "L", "N"}},
	{"VA", []string{"H", "L", "N"}},
	{"SC", []string{"H", "L", "N"}},
	{"SI", []string{"H", "L", "N"}},
	{"SA", []string{"H", "L", "N"}},
	// Threat.
	{"E", []string{"X", "A", "P", "U"}},
	// Environmental.
	{"CR", []string{"X", "H", "M", "L"}},
	{"IR", []string{"X", "H", "M", "L"}},
	{"AR", []string{"X", "H", "M", "L"}},
	{"MAV", []string{"X", "N", "A", "L", "P"}},
	{"MAC", []string{"X", "L", "H"}},
	{"MAT", []string{"X", "N", "P"}},
	{"MPR", []string{"X", "N", "L", "H"}},
	{"MUI", []string{"X", "N", "P", "A"}},
	{"MVC", []string{"X", "H", "L", "N"}},
	{"MVI", []string{"X", "H", "L", "N"}},
	{"MVA", []string{"X", "H", "L", "N"}},
	{"MSC", []string{"X", "H", "L", "N"}},
	{"MSI", []string{"X", "S", "H", "L", "N"}},
	{"MSA", []string{"X", "S", "H", "L", "N"}},
	// Supplemental.
	{"S", []string{"X", "N", "P"}},
	{"AU", []string{"X", "N", "Y"}},
	{"R", []string{"X", "A", "U", "I"}},
	{"V", []string{"X", "D", "C"}},
	{"RE", []string{"X", "L", "M", "H"}},
	{"U", []string{"X", "Clear", "Green", "Amber", "Red"}},
}

// cvss4BaseKeys are the eleven metrics every vector must carry.
var cvss4BaseKeys = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

// cvss4Levels ranks each metric value by severity, least severe last. The
// numbers are positions on a scale, not weights: only differences between two
// values of the same metric are ever used.
var cvss4Levels = map[string]map[string]float64{
	"AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	"PR": {"N": 0.0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0.0, "P": 0.1, "A": 0.2},
	"AC": {"L": 0.0, "H": 0.1},
	"AT": {"N": 0.0, "P": 0.1},
	"VC": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0.0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"CR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"IR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

// cvss4DistanceKeys are the metrics a severity distance is measured over, in
// the order the reference implementation sums them. Order is load-bearing only
// in that floating-point addition is not associative; keeping it identical
// keeps the score identical.
var cvss4DistanceKeys = []string{
	"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR",
}

// cvss4MaxComposed holds, per equivalence class and level, the most severe
// vectors that level can contain. EQ3 is indexed by EQ6 as well, because the
// two are not independent.
var (
	cvss4MaxEQ1 = map[int][]string{
		0: {"AV:N/PR:N/UI:N/"},
		1: {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
		2: {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"},
	}
	cvss4MaxEQ2 = map[int][]string{
		0: {"AC:L/AT:N/"},
		1: {"AC:H/AT:N/", "AC:L/AT:P/"},
	}
	cvss4MaxEQ3EQ6 = map[int]map[int][]string{
		0: {
			0: {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"},
			1: {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"},
		},
		1: {
			0: {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"},
			1: {
				"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
				"VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
				"VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
			},
		},
		2: {
			1: {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"},
		},
	}
	cvss4MaxEQ4 = map[int][]string{
		0: {"SC:H/SI:S/SA:S/"},
		1: {"SC:H/SI:H/SA:H/"},
		2: {"SC:L/SI:L/SA:L/"},
	}
	cvss4MaxEQ5 = map[int][]string{
		0: {"E:A/"},
		1: {"E:P/"},
		2: {"E:U/"},
	}
)

// cvss4MaxSeverity is the depth of each equivalence class: how many severity
// steps separate its most and least severe members, plus one.
var (
	cvss4MaxSeverityEQ1    = map[int]float64{0: 1, 1: 4, 2: 5}
	cvss4MaxSeverityEQ2    = map[int]float64{0: 1, 1: 2}
	cvss4MaxSeverityEQ3EQ6 = map[int]map[int]float64{
		0: {0: 7, 1: 6},
		1: {0: 8, 1: 8},
		2: {1: 10},
	}
	cvss4MaxSeverityEQ4 = map[int]float64{0: 6, 1: 5, 2: 4}
)

// cvss4Step is the distance one severity level spans.
const cvss4Step = 0.1

// cvss4BaseScore computes the base score for a CVSS v4.0 vector. The bool
// reports whether the vector was understood; an unparseable or incomplete
// vector yields no score rather than a wrong one.
func cvss4BaseScore(vector string) (float64, bool) {
	metrics, ok := parseCVSS4Vector(vector)
	if !ok {
		return 0, false
	}

	// A vector with no impact anywhere scores zero, without consulting the
	// tables at all.
	noImpact := true
	for _, key := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if cvss4Metric(metrics, key) != "N" {
			noImpact = false
			break
		}
	}
	if noImpact {
		return 0, true
	}

	eq1, eq2, eq3, eq4, eq5, eq6 := cvss4EquivalenceClasses(metrics)
	value, ok := cvss4MacroVectorScores[cvss4MacroVector(eq1, eq2, eq3, eq4, eq5, eq6)]
	if !ok {
		// Every reachable combination is in the table, so this cannot happen
		// for a vector that parsed. Refusing beats inventing a score.
		return 0, false
	}

	// Each equivalence class contributes the score it would lose by dropping
	// one level, scaled by how far into its own level this vector already sits.
	distances := cvss4SeverityDistances(metrics, eq1, eq2, eq3, eq4, eq5, eq6)

	lower := []cvss4Lower{
		lowerFor(cvss4MacroVector(eq1+1, eq2, eq3, eq4, eq5, eq6), distances.eq1, cvss4MaxSeverityEQ1[eq1]),
		lowerFor(cvss4MacroVector(eq1, eq2+1, eq3, eq4, eq5, eq6), distances.eq2, cvss4MaxSeverityEQ2[eq2]),
		cvss4LowerEQ3EQ6(eq1, eq2, eq3, eq4, eq5, eq6, distances.eq3eq6),
		lowerFor(cvss4MacroVector(eq1, eq2, eq3, eq4+1, eq5, eq6), distances.eq4, cvss4MaxSeverityEQ4[eq4]),
		// EQ5 has no severity distance of its own: every member of a level is
		// equally severe, so it can only ever contribute zero.
		lowerFor(cvss4MacroVector(eq1, eq2, eq3, eq4, eq5+1, eq6), 0, 1),
	}

	var sum float64
	existing := 0
	for _, l := range lower {
		if !l.exists {
			continue
		}
		existing++
		sum += (value - l.score) * (l.current / (l.depth * cvss4Step))
	}

	mean := 0.0
	if existing > 0 {
		mean = sum / float64(existing)
	}

	score := value - mean
	if score < 0 {
		score = 0
	}
	if score > 10 {
		score = 10
	}
	return math.Round(score*10) / 10, true
}

// cvss4Lower is one equivalence class's contribution: the score of the
// MacroVector one level down, how far the vector already sits into its own
// level, and how deep that level is.
type cvss4Lower struct {
	score   float64
	exists  bool
	current float64
	depth   float64
}

// lowerFor looks up a next-lower MacroVector. A key that is not in the table
// means there is no lower level, which the mean then leaves out.
func lowerFor(macroVector string, current, depth float64) cvss4Lower {
	score, exists := cvss4MacroVectorScores[macroVector]
	return cvss4Lower{score: score, exists: exists, current: current, depth: depth}
}

// cvss4LowerEQ3EQ6 finds the next lower MacroVector for the EQ3/EQ6 pair, which
// move together. From 00 there are two ways down and the better-scoring one
// wins; every other level has exactly one.
func cvss4LowerEQ3EQ6(eq1, eq2, eq3, eq4, eq5, eq6 int, current float64) cvss4Lower {
	depth := cvss4MaxSeverityEQ3EQ6[eq3][eq6]

	if eq3 == 0 && eq6 == 0 {
		left, leftOK := cvss4MacroVectorScores[cvss4MacroVector(eq1, eq2, eq3, eq4, eq5, eq6+1)]
		right, rightOK := cvss4MacroVectorScores[cvss4MacroVector(eq1, eq2, eq3+1, eq4, eq5, eq6)]
		// The reference implementation compares the two with JavaScript's
		// rules, where any comparison against a missing entry is false and the
		// right-hand path is taken. Reproduced rather than corrected: this is
		// the scoring anyone else will have computed.
		if leftOK && rightOK && left > right {
			return lowerFor(cvss4MacroVector(eq1, eq2, eq3, eq4, eq5, eq6+1), current, depth)
		}
		return lowerFor(cvss4MacroVector(eq1, eq2, eq3+1, eq4, eq5, eq6), current, depth)
	}

	// 01 and 11 step EQ3; 10 steps EQ6; anything else steps both and lands
	// outside the table, which is the intended "no lower MacroVector".
	switch {
	case eq6 == 1 && (eq3 == 0 || eq3 == 1):
		return lowerFor(cvss4MacroVector(eq1, eq2, eq3+1, eq4, eq5, eq6), current, depth)
	case eq3 == 1 && eq6 == 0:
		return lowerFor(cvss4MacroVector(eq1, eq2, eq3, eq4, eq5, eq6+1), current, depth)
	default:
		return lowerFor(cvss4MacroVector(eq1, eq2, eq3+1, eq4, eq5, eq6+1), current, depth)
	}
}

// cvss4Distances is how far the vector sits from the most severe vector its
// MacroVector can hold, split by equivalence class.
type cvss4Distances struct {
	eq1, eq2, eq3eq6, eq4 float64
}

// cvss4SeverityDistances composes every candidate "most severe" vector for this
// MacroVector and measures against the first one the scored vector does not
// exceed on any metric.
func cvss4SeverityDistances(metrics map[string]string, eq1, eq2, eq3, eq4, eq5, eq6 int) cvss4Distances {
	var distance map[string]float64

	for _, one := range cvss4MaxEQ1[eq1] {
		for _, two := range cvss4MaxEQ2[eq2] {
			for _, three := range cvss4MaxEQ3EQ6[eq3][eq6] {
				for _, four := range cvss4MaxEQ4[eq4] {
					for _, five := range cvss4MaxEQ5[eq5] {
						maxVector := parseCVSS4MaxVector(one + two + three + four + five)
						distance = map[string]float64{}
						exceeds := false
						for _, key := range cvss4DistanceKeys {
							d := cvss4Levels[key][cvss4Metric(metrics, key)] - cvss4Levels[key][maxVector[key]]
							distance[key] = d
							if d < 0 {
								exceeds = true
							}
						}
						if !exceeds {
							return cvss4Sum(distance)
						}
					}
				}
			}
		}
	}

	// No candidate dominates the vector on every metric. The reference
	// implementation falls out of its loop still holding the last candidate's
	// distances and uses them, so this does too.
	return cvss4Sum(distance)
}

func cvss4Sum(distance map[string]float64) cvss4Distances {
	return cvss4Distances{
		eq1:    distance["AV"] + distance["PR"] + distance["UI"],
		eq2:    distance["AC"] + distance["AT"],
		eq3eq6: distance["VC"] + distance["VI"] + distance["VA"] + distance["CR"] + distance["IR"] + distance["AR"],
		eq4:    distance["SC"] + distance["SI"] + distance["SA"],
	}
}

// cvss4EquivalenceClasses reduces a vector to its six levels.
func cvss4EquivalenceClasses(m map[string]string) (eq1, eq2, eq3, eq4, eq5, eq6 int) {
	av, pr, ui := cvss4Metric(m, "AV"), cvss4Metric(m, "PR"), cvss4Metric(m, "UI")
	ac, at := cvss4Metric(m, "AC"), cvss4Metric(m, "AT")
	vc, vi, va := cvss4Metric(m, "VC"), cvss4Metric(m, "VI"), cvss4Metric(m, "VA")
	sc, si, sa := cvss4Metric(m, "SC"), cvss4Metric(m, "SI"), cvss4Metric(m, "SA")

	// EQ1: how little the attacker needs before they can start.
	switch {
	case av == "N" && pr == "N" && ui == "N":
		eq1 = 0
	case av != "P" && (av == "N" || pr == "N" || ui == "N"):
		eq1 = 1
	default:
		eq1 = 2
	}

	// EQ2: whether the attack is reliable.
	if ac == "L" && at == "N" {
		eq2 = 0
	} else {
		eq2 = 1
	}

	// EQ3: impact on the vulnerable system.
	switch {
	case vc == "H" && vi == "H":
		eq3 = 0
	case vc == "H" || vi == "H" || va == "H":
		eq3 = 1
	default:
		eq3 = 2
	}

	// EQ4: impact on subsequent systems. Level 0 is the Safety case, which only
	// an environmental MSI:S or MSA:S can reach, so a base score never does.
	switch {
	case cvss4Metric(m, "MSI") == "S" || cvss4Metric(m, "MSA") == "S":
		eq4 = 0
	case sc == "H" || si == "H" || sa == "H":
		eq4 = 1
	default:
		eq4 = 2
	}

	// EQ5: exploit maturity, which a base score always takes at its worst case.
	switch cvss4Metric(m, "E") {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	default:
		eq5 = 2
	}

	// EQ6: whether the impact lands where the requirement is highest.
	cr, ir, ar := cvss4Metric(m, "CR"), cvss4Metric(m, "IR"), cvss4Metric(m, "AR")
	if (cr == "H" && vc == "H") || (ir == "H" && vi == "H") || (ar == "H" && va == "H") {
		eq6 = 0
	} else {
		eq6 = 1
	}
	return eq1, eq2, eq3, eq4, eq5, eq6
}

func cvss4MacroVector(eq1, eq2, eq3, eq4, eq5, eq6 int) string {
	digits := [6]int{eq1, eq2, eq3, eq4, eq5, eq6}
	var b strings.Builder
	for _, d := range digits {
		if d < 0 || d > 9 {
			// Stepping past the end of an equivalence class produces a
			// MacroVector that is not in the table, which is the signal that
			// there is no lower one. A two-digit level would corrupt the key
			// rather than miss it.
			return ""
		}
		b.WriteByte(byte('0' + d))
	}
	return b.String()
}

// cvss4Metric resolves one metric for a base score. Threat and environmental
// metrics take the values the specification assigns when they are not defined:
// E:X scores as E:A, and CR:X, IR:X and AR:X score as H. The reference
// implementation additionally lets an M-prefixed metric override its base
// counterpart, which produces an environmental score rather than a base one and
// is deliberately not implemented here -- the same reason the v3 path ignores
// temporal and environmental metrics.
func cvss4Metric(metrics map[string]string, key string) string {
	switch key {
	case "E":
		return "A"
	case "CR", "IR", "AR":
		return "H"
	case "MSI", "MSA":
		return "X"
	}
	return metrics[key]
}

// parseCVSS4Vector reads a vector into its metrics, enforcing the prefix, the
// specification's metric order, the permitted values, and the presence of all
// eleven base metrics.
func parseCVSS4Vector(vector string) (map[string]string, bool) {
	rest, found := strings.CutPrefix(vector, "CVSS:4.0/")
	if !found {
		return nil, false
	}

	metrics := make(map[string]string, len(cvss4MetricValues))
	next := 0
	for _, part := range strings.Split(rest, "/") {
		key, value, found := strings.Cut(part, ":")
		if !found {
			return nil, false
		}
		// Scanning forward from the last metric accepted enforces the order and
		// rejects a repeat in the same pass.
		i := next
		for i < len(cvss4MetricValues) && cvss4MetricValues[i].key != key {
			i++
		}
		if i == len(cvss4MetricValues) || !slices.Contains(cvss4MetricValues[i].values, value) {
			return nil, false
		}
		metrics[key] = value
		next = i + 1
	}

	for _, key := range cvss4BaseKeys {
		if _, ok := metrics[key]; !ok {
			return nil, false
		}
	}
	return metrics, true
}

// parseCVSS4MaxVector reads one of the composed "most severe" vectors, which
// are plain slash-separated pairs with a trailing slash.
func parseCVSS4MaxVector(vector string) map[string]string {
	metrics := make(map[string]string, 15)
	for _, part := range strings.Split(strings.TrimSuffix(vector, "/"), "/") {
		if key, value, found := strings.Cut(part, ":"); found {
			metrics[key] = value
		}
	}
	return metrics
}
