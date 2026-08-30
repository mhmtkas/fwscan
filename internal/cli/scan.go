package cli

import (
	"fmt"
	"io"
	"io/fs"
	"slices"
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
}

func newScanCmd(version string) *cobra.Command {
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a firmware rootfs for packages and known vulnerabilities",
		Long: "Scan an extracted rootfs directory, a rootfs tarball, or a filesystem\n" +
			"image. The format is detected from the file's contents, not its name.",
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
	return cmd
}

func runScan(cmd *cobra.Command, target, version string, opts scanOptions) error {
	started := time.Now()

	format, compression, err := input.Detect(target)
	if err != nil {
		return err
	}

	rootfs, cleanup, err := input.Open(target)
	if err != nil {
		return err
	}
	defer cleanup()

	comps, err := catalogAll(rootfs)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		// A rootfs with no package database is a legitimate result, but silence
		// would look like a bug. The warning goes to stderr so stdout stays a
		// clean report.
		// A failed warning write is not worth failing the scan over.
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
			"fwscan: no package database found; is this a Linux rootfs?")
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
	}

	info := report.ScanInfo{
		Target:      target,
		Format:      format.String(),
		Compression: compression.String(),
		StartedAt:   started.UTC(),
		Duration:    time.Since(started),
	}
	if opts.outputPath != "" {
		if err := writeJSONReport(opts.outputPath, version, info, comps, findings); err != nil {
			return err
		}
	}

	return report.Terminal(cmd.OutOrStdout(), version, info, comps, findings, opts.noNetwork)
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
func catalogAll(rootfs fs.FS) ([]model.Component, error) {
	var comps []model.Component
	for _, c := range catalog.All() {
		found, err := c.Catalog(rootfs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name(), err)
		}
		comps = append(comps, found...)
	}
	slices.SortFunc(comps, model.CompareComponents)
	return comps, nil
}
