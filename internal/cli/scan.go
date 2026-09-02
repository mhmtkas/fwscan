package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mhmtkas/fwscan/internal/catalog"
	"github.com/mhmtkas/fwscan/internal/input"
	"github.com/mhmtkas/fwscan/internal/match"
	"github.com/mhmtkas/fwscan/internal/model"
	"github.com/mhmtkas/fwscan/internal/report"
	"github.com/mhmtkas/fwscan/internal/sbom"
)

// newMatcher builds the vulnerability matcher. It is a variable so a test can
// substitute one that fails loudly if it is ever called, which is how
// --no-network is proven to make no network calls at all.
var newMatcher = func() match.Matcher { return match.NewOSV() }

type scanOptions struct {
	noNetwork  bool
	sbomPath   string
	outputPath string
	failOn     string
}

func newScanCmd(version string) *cobra.Command {
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a firmware rootfs for packages and known vulnerabilities",
		Long: "Scan an extracted rootfs directory, a rootfs tarball, or a squashfs image.\n" +
			"The format is detected from the file's contents, not its name, so an lz4\n" +
			"image called .gz is read correctly.\n\n" +
			"Packages come from the dpkg and apk databases in the image. Anything found\n" +
			"by filename or version-string heuristics instead is reported at low\n" +
			"confidence and is not looked up.\n\n" +
			"Exit codes: 0 clean, 1 findings at or above --fail-on, 2 the scan could\n" +
			"not complete.",
		Example: "  # print a report\n" +
			"  fwscan scan rootfs.squashfs\n\n" +
			"  # produce both artifacts and fail the build on anything high or worse\n" +
			"  fwscan scan --sbom bom.cdx.json --output report.json --fail-on high rootfs.tar.gz\n\n" +
			"  # SBOM only, no network\n" +
			"  fwscan scan --no-network --sbom bom.cdx.json ./extracted-rootfs",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args[0], version, opts)
		},
	}
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false,
		"catalog packages only; skip the CVE lookup")
	cmd.Flags().StringVar(&opts.sbomPath, "sbom", "",
		"write a CycloneDX 1.6 SBOM to this file")
	cmd.Flags().StringVar(&opts.outputPath, "output", "",
		"write the full machine-readable report to this file")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "",
		"exit 1 when a finding is at or above this severity (critical|high|medium|low)")
	return cmd
}

func runScan(cmd *cobra.Command, target, version string, opts scanOptions) error {
	started := time.Now()

	// Validated before any work, so a typo fails immediately rather than after
	// a long scan.
	threshold, err := report.ParseFailOn(opts.failOn)
	if err != nil {
		return err
	}

	rootfs, detected, cleanup, err := input.Open(cmd.Context(), target)
	if err != nil {
		return err
	}
	// Cleanup runs on the way out, and every stage below returns promptly on
	// a cancelled context, so a scan interrupted at the keyboard unwinds to
	// here rather than being killed with the extracted rootfs still on disk.
	// Running cleanup from the cancellation itself, in parallel with a stage
	// still reading the rootfs, would race that stage into a misleading
	// failure -- or into an empty result and exit 0.
	defer cleanup()

	comps, err := catalogAll(cmd.Context(), rootfs)
	if err != nil {
		return err
	}
	// Diagnostics go to stderr so stdout stays a clean report, and through
	// Sanitize because a warning can quote the image -- an os-release ID is as
	// attacker-controlled as a package name, and an escape sequence in one
	// reaches the terminal exactly as it would in the report. A failed write
	// is not worth failing the scan over.
	diagnostic := func(message string) {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "fwscan: "+report.Sanitize(message))
	}
	if len(comps) == 0 {
		// A rootfs with no package database is a legitimate result, but silence
		// would look like a bug.
		diagnostic("no package database found; is this a Linux rootfs?")
	}
	for _, warning := range unreadDatabaseWarnings(rootfs) {
		diagnostic(warning)
	}
	for _, warning := range releaseWarnings(rootfs, comps) {
		diagnostic(warning)
	}

	// The SBOM is written before the CVE lookup, so a network failure still
	// leaves the user with the artifact that does not depend on the network.
	if opts.sbomPath != "" {
		if err := writeSBOM(opts.sbomPath, comps, version, started); err != nil {
			return err
		}
	}

	var findings []model.Finding
	if !opts.noNetwork {
		findings, err = newMatcher().Match(cmd.Context(), comps)
		if err != nil {
			return err
		}
		for _, warning := range emptyResultWarnings(comps, findings) {
			diagnostic(warning)
		}
	}

	info := report.ScanInfo{
		Target:      target,
		Format:      detected.Format.String(),
		Compression: detected.Compression.String(),
		StartedAt:   started.UTC(),
		Duration:    time.Since(started),
	}
	if opts.outputPath != "" {
		if err := writeJSONReport(opts.outputPath, version, info, comps, findings); err != nil {
			return err
		}
	}

	if err := report.Terminal(cmd.OutOrStdout(), version, info, comps, findings, opts.noNetwork); err != nil {
		return err
	}

	// The report has already told the user everything; the threshold breach
	// only changes the exit code, and ThresholdError prints nothing.
	if n := report.ThresholdFindings(findings, threshold); n > 0 {
		return &ThresholdError{Count: n}
	}
	return nil
}

func writeJSONReport(path, version string, info report.ScanInfo, comps []model.Component, findings []model.Finding) error {
	err := report.WriteFileAtomic(path, func(w io.Writer) error {
		return report.JSON(w, version, info, comps, findings)
	})
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func writeSBOM(path string, comps []model.Component, version string, started time.Time) error {
	opts := sbom.Options{ToolVersion: version, Timestamp: started}
	err := report.WriteFileAtomic(path, func(w io.Writer) error {
		return sbom.Write(w, comps, opts)
	})
	if err != nil {
		return fmt.Errorf("write sbom: %w", err)
	}
	return nil
}

// catalogAll runs every cataloger over the rootfs and returns the union,
// sorted by name so the output is stable run to run.
// unsupportedDatabases are the package databases fwscan can find but not read.
// Each is a documented non-goal (docs/scope.md); the point of naming them is
// that an image carrying one is not an image with nothing in it.
var unsupportedDatabases = []struct {
	path    string
	manager string
}{
	{"usr/lib/opkg/status", "an opkg"},
	{"var/lib/opkg/status", "an opkg"},
	{"var/lib/rpm/Packages", "an rpm"},
	{"var/lib/rpm/rpmdb.sqlite", "an rpm"},
	{"usr/lib/sysimage/rpm/rpmdb.sqlite", "an rpm"},
}

// unreadDatabaseWarnings names a package database the image has and fwscan does
// not read.
//
// A real OpenWrt image carries 150 opkg packages; fwscan reads none of them and
// reports the two components its filename heuristics recognise. Reporting two
// where there are a hundred and fifty, without saying so, is the shape of an
// answer that gets acted on and should not be.
func unreadDatabaseWarnings(rootfs fs.FS) []string {
	seen := map[string]bool{}
	var warnings []string
	for _, db := range unsupportedDatabases {
		if seen[db.manager] {
			continue
		}
		if _, err := fs.Stat(rootfs, db.path); err != nil {
			continue
		}
		seen[db.manager] = true
		warnings = append(warnings, fmt.Sprintf(
			"this image has %s database at %s, which fwscan does not read; "+
				"only components identified another way are reported",
			db.manager, db.path))
	}
	return warnings
}

// emptyResultWarnings explains a Debian lookup that found nothing.
//
// OSV's Debian export is not the same shape for every release. For a supported
// one it carries a DEBIAN-CVE-… record per CVE, including the many a release
// never fixes; for an oldstable one those records drop the release and only the
// DSA and DLA advisories remain -- and an advisory exists exactly when a fix
// shipped. So on a fully patched oldstable image every advisory is satisfied and
// the answer is zero, while the CVEs the release chose not to fix are simply
// not in the data. Measured on a Debian 11 rootfs: OSV had nothing, and a
// scanner reading the Debian Security Tracker reported 211 findings, every one
// of them unfixed.
//
// "No known vulnerabilities found." is the wrong thing to leave a reader with
// there, so it does not stand alone.
func emptyResultWarnings(comps []model.Component, findings []model.Finding) []string {
	if len(findings) > 0 {
		return nil
	}
	debian := false
	for _, c := range comps {
		if strings.HasPrefix(c.PURL, "pkg:deb/debian/") {
			debian = true
			break
		}
	}
	if !debian {
		return nil
	}
	return []string{"no findings for a Debian image with " + strconv.Itoa(len(comps)) +
		" packages. On an oldstable release OSV carries only the CVEs that received a DSA or DLA, " +
		"so one this tool reports as clean may still carry CVEs the release has chosen not to fix"}
}

// releaseWarnings says what a Debian lookup could not be scoped to. Every
// Debian query carries the image's release, because without it OSV answers
// across every release at once and reports another release's fix as the one to
// install (spike/NOTES.md T0.3). An image that does not say its release, or
// says one OSV's Debian data does not cover, gets a report anyway -- silently
// unscoped is worse than loudly unscoped.
func releaseWarnings(rootfs fs.FS, comps []model.Component) []string {
	var dpkg *model.Component
	for i := range comps {
		if strings.HasPrefix(comps[i].PURL, "pkg:deb/") {
			dpkg = &comps[i]
			break
		}
	}
	if dpkg == nil {
		return nil
	}

	var warnings []string
	if dpkg.Distro == "" {
		warnings = append(warnings, "no release found in os-release; the vulnerability lookup is not "+
			"scoped to a Debian release and may name fixes from other releases")
	}
	if id := catalog.ReadOSRelease(rootfs).ID; id != "" && id != "debian" {
		warnings = append(warnings, fmt.Sprintf("os-release says this is %s; the vulnerability lookup "+
			"uses OSV's Debian data only and may find nothing for it", id))
	}
	return warnings
}

func catalogAll(ctx context.Context, rootfs fs.FS) ([]model.Component, error) {
	var comps []model.Component
	for _, c := range catalog.All() {
		found, err := c.Catalog(ctx, rootfs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name(), err)
		}
		comps = append(comps, found...)
	}
	slices.SortFunc(comps, model.CompareComponents)
	return comps, nil
}
