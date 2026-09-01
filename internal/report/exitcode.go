package report

import (
	"fmt"
	"strings"

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
	// The flag's vocabulary is output-spec section 5's four words, and only
	// those. model.ParseSeverity is deliberately more forgiving because it
	// reads OSV's own wording, where "moderate" is a real level -- but a
	// threshold nobody documented, silently accepted, is a flag whose meaning
	// depends on which parser it happened to reach.
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return model.SeverityCritical, nil
	case "high":
		return model.SeverityHigh, nil
	case "medium":
		return model.SeverityMedium, nil
	case "low":
		return model.SeverityLow, nil
	default:
		return "", fmt.Errorf("invalid --fail-on %q: use critical, high, medium or low", value)
	}
}
