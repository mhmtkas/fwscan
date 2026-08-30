// Package report renders scan results. Everything it emits is fixed by
// docs/output-spec.md; nothing here is a formatting preference.
package report

import (
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

// ScanInfo describes the scan itself, for the report header and the JSON
// report's scan block.
type ScanInfo struct {
	// Target is the path as the user gave it, not a resolved absolute path:
	// the report should read back like the command they typed.
	Target      string
	Format      string
	Compression string
	StartedAt   time.Time
	Duration    time.Duration
}

// PackageCounts summarises components by confidence.
type PackageCounts struct {
	Total          int
	HighConfidence int
	LowConfidence  int
}

// CountPackages tallies components by confidence.
func CountPackages(comps []model.Component) PackageCounts {
	counts := PackageCounts{Total: len(comps)}
	for _, c := range comps {
		if c.Confidence == model.ConfidenceHigh {
			counts.HighConfidence++
		} else {
			counts.LowConfidence++
		}
	}
	return counts
}

// FindingCounts summarises findings by severity. All five buckets are always
// present, because output-spec section 2 requires the header to list them all
// even when they are zero.
type FindingCounts struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// CountFindings tallies findings by severity bucket.
func CountFindings(findings []model.Finding) FindingCounts {
	counts := FindingCounts{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			counts.Critical++
		case model.SeverityHigh:
			counts.High++
		case model.SeverityMedium:
			counts.Medium++
		case model.SeverityLow:
			counts.Low++
		default:
			counts.Unknown++
		}
	}
	return counts
}
