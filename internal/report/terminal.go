package report

import (
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"

	"github.com/mhmtkas/fwscan/internal/model"
)

// noFixedVersion is what the FIXED column shows when no fix is known.
// output-spec section 2 specifies this glyph literally, which is why it is the
// one non-ASCII character in the output.
const noFixedVersion = "—"

// Terminal writes the human-readable report to w, which is stdout. Diagnostics
// never come here: stdout carries only the report so it stays pipe-safe.
//
// Passing findings as nil is not the same as passing an empty slice.
// noNetwork distinguishes "we looked and found nothing" from "we did not look".
func Terminal(w io.Writer, version string, info ScanInfo, comps []model.Component, findings []model.Finding, noNetwork bool) error {
	packages := CountPackages(comps)

	if err := writeHeader(w, version, info, packages, findings, noNetwork); err != nil {
		return err
	}

	if noNetwork {
		if _, err := fmt.Fprintf(w, "\nCataloged %d packages. CVE lookup skipped (--no-network).\n", packages.Total); err != nil {
			return err
		}
		return writeFootnote(w, packages)
	}

	if len(findings) == 0 {
		if _, err := fmt.Fprint(w, "\nNo known vulnerabilities found.\n"); err != nil {
			return err
		}
		return writeFootnote(w, packages)
	}

	if err := writeTable(w, findings); err != nil {
		return err
	}
	return writeFootnote(w, packages)
}

func writeHeader(w io.Writer, version string, info ScanInfo, packages PackageCounts, findings []model.Finding, noNetwork bool) error {
	if _, err := fmt.Fprintf(w, "fwscan %s\n\n", DisplayVersion(version)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Target      %s\n", targetLine(info)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Packages    %d (%d high confidence, %d low)\n",
		packages.Total, packages.HighConfidence, packages.LowConfidence); err != nil {
		return err
	}
	if noNetwork {
		// The Findings line is skipped entirely rather than shown as zero:
		// nothing was looked up, so reporting zero findings would be a lie.
		return nil
	}
	c := CountFindings(findings)
	_, err := fmt.Fprintf(w, "  Findings    %d   critical: %d  high: %d  medium: %d  low: %d  unknown: %d\n",
		c.Total, c.Critical, c.High, c.Medium, c.Low, c.Unknown)
	return err
}

// targetLine renders "path (format, compression)", dropping the compression
// when there is none.
func targetLine(info ScanInfo) string {
	switch {
	case info.Format == "":
		return info.Target
	case info.Compression == "" || info.Compression == "none":
		return fmt.Sprintf("%s (%s)", info.Target, info.Format)
	default:
		return fmt.Sprintf("%s (%s, %s)", info.Target, info.Format, info.Compression)
	}
}

// writeTable renders the seven columns output-spec section 2 fixes, in order.
// tabwriter sizes them to the run's content; no external table library.
func writeTable(w io.Writer, findings []model.Finding) error {
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tSCORE\tPACKAGE\tINSTALLED\tFIXED\tVULN ID\tCONF"); err != nil {
		return err
	}
	for _, f := range findings {
		fixed := f.FixedVersion
		if fixed == "" {
			fixed = noFixedVersion
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, formatScore(f.CVSS), f.Component.Name, f.Component.Version,
			fixed, f.ID, f.Component.Confidence); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// formatScore renders a CVSS score. A score of zero means none was derived, and
// printing "0.0" would read as "harmless" rather than "unrated".
func formatScore(score float64) string {
	if score == 0 {
		return noFixedVersion
	}
	return strconv.FormatFloat(score, 'f', 1, 64)
}

// writeFootnote explains low-confidence components. It appears only when there
// is at least one, per output-spec section 2.
func writeFootnote(w io.Writer, packages PackageCounts) error {
	if packages.LowConfidence == 0 {
		return nil
	}
	// output-spec section 2 writes this sentence for a plural count. The
	// singular form is the same sentence made grammatical, not a new format.
	noun, verb := "components", "were"
	if packages.LowConfidence == 1 {
		noun, verb = "component", "was"
	}
	_, err := fmt.Fprintf(w,
		"\n%d low-confidence %s %s identified by filename heuristics and may be false positives.\n"+
			"Run with --output report.json for full details including aliases and evidence paths.\n",
		packages.LowConfidence, noun, verb)
	return err
}
