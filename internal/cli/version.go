package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/mhmtkas/fwscan/internal/report"
)

func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the fwscan version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The same rendering as the report header, so the two never
			// disagree about what version this is.
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "fwscan %s (%s/%s, %s)\n",
				report.DisplayVersion(version), runtime.GOOS, runtime.GOARCH, runtime.Version())
			return err
		},
	}
}
