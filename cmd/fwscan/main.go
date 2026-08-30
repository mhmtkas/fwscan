// Command fwscan scans a Linux firmware rootfs for installed packages, emits a
// CycloneDX SBOM, and reports known vulnerabilities from OSV.dev.
package main

import (
	"os"

	"github.com/mhmtkas/fwscan/internal/cli"
)

// version is overwritten at release time via -ldflags. Keep the default
// recognisable so a locally built binary never claims to be a release.
var version = "dev"

func main() {
	os.Exit(cli.Execute(version))
}
