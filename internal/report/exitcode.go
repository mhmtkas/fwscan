package report

import (
	"fmt"

	"github.com/mhmtkas/fwscan/internal/model"
)

// ThresholdFindings counts the findings that meet or exceed threshold.
//
// Unknown-severity findings never count, whatever the threshold, because
// output-spec section 5 states they never trigger exit 1. That is the right
// call: an unrated finding is not evidence of severity, and a fifth of Debian's
// OSV records carry no severity at all (spike/NOTES.md T0.3). Failing a build on
// them would make --fail-on unusable.
func ThresholdFindings(findings []model.Finding, threshold model.Severity) int {
	if threshold == "" {
		return 0
	}
	var n int
	for _, f := range findings {
		if f.Severity.AtLeast(threshold) {
			n++
		}
	}
	return n
}

// ParseFailOn validates a --fail-on value.
//
// "unknown" is rejected rather than accepted-and-ignored: a user who typed it
// wants the build to fail on unrated findings, and silently never failing would
// be worse than saying it is not a valid threshold.
func ParseFailOn(value string) (model.Severity, error) {
	if value == "" {
		return "", nil
	}
	severity, known := model.ParseSeverity(value)
	if !known || severity == model.SeverityUnknown {
		return "", fmt.Errorf("invalid --fail-on %q: use critical, high, medium or low", value)
	}
	return severity, nil
}
