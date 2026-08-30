package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

// SchemaVersion identifies the JSON report format. It is a string, per
// output-spec section 3, and is bumped only by a deliberate format change.
const SchemaVersion = "1"

// findingSource names where a finding came from. Only OSV exists in v1; the
// field is present so a second source can be added without a schema break.
const findingSource = "osv.dev"

// JSONReport is the top-level document. Field names are final (output-spec
// section 3) and every one of them is snake_case.
type JSONReport struct {
	SchemaVersion string          `json:"schema_version"`
	Tool          jsonTool        `json:"tool"`
	Scan          jsonScan        `json:"scan"`
	Summary       jsonSummary     `json:"summary"`
	Components    []jsonComponent `json:"components"`
	Findings      []jsonFinding   `json:"findings"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonScan struct {
	Target      string `json:"target"`
	Format      string `json:"format"`
	Compression string `json:"compression"`
	StartedAt   string `json:"started_at"`
	DurationMS  int64  `json:"duration_ms"`
}

type jsonSummary struct {
	Packages jsonPackageSummary `json:"packages"`
	Findings jsonFindingSummary `json:"findings"`
}

type jsonPackageSummary struct {
	Total          int `json:"total"`
	HighConfidence int `json:"high_confidence"`
	LowConfidence  int `json:"low_confidence"`
}

type jsonFindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type jsonComponent struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Arch       string `json:"arch"`
	PURL       string `json:"purl"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type jsonFinding struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
	Severity         string   `json:"severity"`
	CVSSScore        float64  `json:"cvss_score"`
	CVSSVector       string   `json:"cvss_vector"`
	Confidence       string   `json:"confidence"`
	Source           string   `json:"source"`
}

// JSON writes the machine-readable report to w.
//
// findings being nil rather than empty is meaningful: in --no-network mode
// nothing was looked up, and the summary is zeroed while the array is empty.
// The document is otherwise identical, so a CI pipeline can parse one shape.
func JSON(w io.Writer, version string, info ScanInfo, comps []model.Component, findings []model.Finding) error {
	report := BuildJSON(version, info, comps, findings)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	// Purls carry "&" between qualifiers; escaping it is valid JSON but makes
	// the report unreadable and awkward to grep.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("report: encode json: %w", err)
	}
	// json.Encoder already ends with a newline, which is the trailing newline
	// at EOF output-spec section 3 asks for.
	return nil
}

// BuildJSON assembles the document. Separate from JSON so tests can assert on
// the structure rather than on formatting.
func BuildJSON(version string, info ScanInfo, comps []model.Component, findings []model.Finding) JSONReport {
	packages := CountPackages(comps)
	counts := CountFindings(findings)

	sortedComps := slices.Clone(comps)
	slices.SortFunc(sortedComps, model.CompareComponents)

	sortedFindings := slices.Clone(findings)
	slices.SortFunc(sortedFindings, model.CompareFindings)

	report := JSONReport{
		SchemaVersion: SchemaVersion,
		Tool:          jsonTool{Name: "fwscan", Version: PlainVersion(version)},
		Scan: jsonScan{
			Target:      info.Target,
			Format:      info.Format,
			Compression: info.Compression,
			StartedAt:   info.StartedAt.UTC().Format(time.RFC3339),
			DurationMS:  info.Duration.Milliseconds(),
		},
		Summary: jsonSummary{
			Packages: jsonPackageSummary{
				Total:          packages.Total,
				HighConfidence: packages.HighConfidence,
				LowConfidence:  packages.LowConfidence,
			},
			Findings: jsonFindingSummary{
				Critical: counts.Critical,
				High:     counts.High,
				Medium:   counts.Medium,
				Low:      counts.Low,
				Unknown:  counts.Unknown,
			},
		},
		// Both arrays are always present, never null: a consumer should be able
		// to range over them without a nil check.
		Components: make([]jsonComponent, 0, len(sortedComps)),
		Findings:   make([]jsonFinding, 0, len(sortedFindings)),
	}

	for _, c := range sortedComps {
		report.Components = append(report.Components, jsonComponent{
			Name:       c.Name,
			Version:    c.Version,
			Arch:       c.Arch,
			PURL:       c.PURL,
			Confidence: string(c.Confidence),
			Evidence:   c.Evidence,
		})
	}
	for _, f := range sortedFindings {
		aliases := f.Aliases
		if aliases == nil {
			aliases = []string{}
		}
		report.Findings = append(report.Findings, jsonFinding{
			ID:               f.ID,
			Aliases:          aliases,
			Package:          f.Component.Name,
			InstalledVersion: f.Component.Version,
			FixedVersion:     f.FixedVersion,
			Severity:         string(f.Severity),
			CVSSScore:        f.CVSS,
			CVSSVector:       f.CVSSVector,
			Confidence:       string(f.Component.Confidence),
			Source:           findingSource,
		})
	}
	return report
}

// PlainVersion strips a leading "v". output-spec renders the version with a "v"
// in the terminal header and without one in the JSON tool block, so one
// injected value has to serve both.
func PlainVersion(version string) string {
	return strings.TrimPrefix(version, "v")
}

// DisplayVersion is the terminal form, carrying the leading "v".
func DisplayVersion(version string) string {
	if version == "" {
		return version
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}
