package model

import "strings"

// Severity is the bucket a finding falls into. The five values are closed: the
// output spec defines them and nothing may invent a sixth.
type Severity string

// The five buckets, most severe first. These strings are user-visible in both
// the terminal table and the JSON report, so renaming one is a format change.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// rank orders severities for sorting and for --fail-on threshold comparisons.
// Higher is more severe. Unknown deliberately sits at the bottom rather than
// being absent, so that it sorts last instead of unpredictably.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityUnknown:
		return 0
	default:
		// An unrecognised value is treated as unknown rather than panicking;
		// a malformed severity must never take the scan down.
		return 0
	}
}

// AtLeast reports whether s meets or exceeds threshold. Unknown never meets any
// threshold, including SeverityUnknown itself — output-spec section 5 states
// that unknown-severity findings never trigger exit 1.
func (s Severity) AtLeast(threshold Severity) bool {
	if s == SeverityUnknown || s.rank() == 0 {
		return false
	}
	return s.rank() >= threshold.rank()
}

// ParseSeverity maps a textual level to a bucket, case-insensitively. The bool
// reports whether the input was recognised; unrecognised input yields
// SeverityUnknown so callers can use the value directly either way.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical, true
	case "high":
		return SeverityHigh, true
	case "medium", "moderate":
		return SeverityMedium, true
	case "low":
		return SeverityLow, true
	case "unknown", "":
		return SeverityUnknown, s == "unknown"
	default:
		return SeverityUnknown, false
	}
}

// CompareFindings orders two findings per output-spec section 1: severity
// bucket descending, then CVSS score descending, then component name ascending,
// then vulnerability id ascending. It returns a negative number, zero, or a
// positive number, matching the slices.SortFunc convention.
func CompareFindings(a, b Finding) int {
	if d := b.Severity.rank() - a.Severity.rank(); d != 0 {
		return d
	}
	switch {
	case a.CVSS > b.CVSS:
		return -1
	case a.CVSS < b.CVSS:
		return 1
	}
	if d := strings.Compare(a.Component.Name, b.Component.Name); d != 0 {
		return d
	}
	return strings.Compare(a.ID, b.ID)
}

// CompareComponents orders components by name ascending, as output-spec
// section 3 requires for the JSON report. The spec names no tie-break, and an
// unstable one would make the report and the goldens flap between runs, so the
// remaining fields settle it: version, then architecture, which is what
// separates the same package built for two of them in one image, then the purl,
// which separates anything the first three do not.
func CompareComponents(a, b Component) int {
	if d := strings.Compare(a.Name, b.Name); d != 0 {
		return d
	}
	if d := strings.Compare(a.Version, b.Version); d != 0 {
		return d
	}
	if d := strings.Compare(a.Arch, b.Arch); d != 0 {
		return d
	}
	return strings.Compare(a.PURL, b.PURL)
}
