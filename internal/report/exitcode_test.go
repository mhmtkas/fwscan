package report

import (
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/model"
)

func finding(severity model.Severity) model.Finding {
	return model.Finding{Severity: severity, Component: model.Component{Name: "pkg"}}
}

// The full threshold-by-severity matrix from output-spec section 5.
func TestThresholdFindings(t *testing.T) {
	all := []model.Finding{
		finding(model.SeverityCritical),
		finding(model.SeverityHigh),
		finding(model.SeverityMedium),
		finding(model.SeverityLow),
		finding(model.SeverityUnknown),
	}

	tests := []struct {
		name      string
		findings  []model.Finding
		threshold model.Severity
		want      int
	}{
		{"no threshold means never fail", all, "", 0},
		{"critical", all, model.SeverityCritical, 1},
		{"high catches critical too", all, model.SeverityHigh, 2},
		{"medium", all, model.SeverityMedium, 3},
		{"low catches everything rated", all, model.SeverityLow, 4},

		// The rule that matters: unknown never counts, at any threshold.
		{"unknown alone never trips low", []model.Finding{finding(model.SeverityUnknown)}, model.SeverityLow, 0},
		{"unknown alone never trips critical", []model.Finding{finding(model.SeverityUnknown)}, model.SeverityCritical, 0},
		{"a pile of unknowns still never trips", []model.Finding{
			finding(model.SeverityUnknown), finding(model.SeverityUnknown), finding(model.SeverityUnknown),
		}, model.SeverityLow, 0},

		{"no findings", nil, model.SeverityLow, 0},
		{"only lower severities", []model.Finding{finding(model.SeverityLow)}, model.SeverityHigh, 0},
		{"exact match counts", []model.Finding{finding(model.SeverityMedium)}, model.SeverityMedium, 1},
		{"several at the same level", []model.Finding{
			finding(model.SeverityHigh), finding(model.SeverityHigh), finding(model.SeverityCritical),
		}, model.SeverityHigh, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ThresholdFindings(tt.findings, tt.threshold); got != tt.want {
				t.Errorf("ThresholdFindings(%q) = %d, want %d", tt.threshold, got, tt.want)
			}
		})
	}
}

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    model.Severity
		wantErr bool
	}{
		{"empty means unset", "", "", false},
		{"critical", "critical", model.SeverityCritical, false},
		{"high", "high", model.SeverityHigh, false},
		{"medium", "medium", model.SeverityMedium, false},
		{"low", "low", model.SeverityLow, false},
		{"case insensitive", "HIGH", model.SeverityHigh, false},
		{"padded", "  medium ", model.SeverityMedium, false},

		// Accepting "unknown" would mean accepting a threshold that can never
		// be met, which is worse than rejecting it.
		{"unknown is rejected", "unknown", "", true},
		{"gibberish is rejected", "spicy", "", true},
		{"a number is rejected", "9", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFailOn(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseFailOn(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err != nil {
				message := err.Error()
				if message != strings.ToLower(message[:1])+message[1:] {
					t.Errorf("error %q does not start lowercase", message)
				}
				if !strings.Contains(message, "critical, high, medium or low") {
					t.Errorf("error %q does not list the valid values", message)
				}
				return
			}
			if got != tt.want {
				t.Errorf("ParseFailOn(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
