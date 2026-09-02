// Command fwscan scans a Linux firmware rootfs for installed packages, emits a
// CycloneDX SBOM, and reports known vulnerabilities from OSV.dev.
package main

import (
	"os"
	"runtime/debug"
	"strings"

	"github.com/mhmtkas/fwscan/internal/cli"
)

// version is overwritten at release time via -ldflags. Keep the default
// recognisable so a locally built binary never claims to be a release.
var version = "dev"

func main() {
	os.Exit(cli.Execute(resolvedVersion()))
}

// resolvedVersion prefers the stamped version and falls back to what the Go
// toolchain recorded. `go install github.com/mhmtkas/fwscan/cmd/fwscan@v0.1.0`
// runs no ldflags, but it does embed the module version in the binary, and a
// user who installed a release that way should not be told they are running
// "dev".
func resolvedVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return version
	}
	return strings.TrimPrefix(info.Main.Version, "v")
}
