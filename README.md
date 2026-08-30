# fwscan

[![ci](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml/badge.svg)](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mhmtkas/fwscan.svg)](https://pkg.go.dev/github.com/mhmtkas/fwscan)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Point it at a firmware image, get a CycloneDX SBOM and a prioritized CVE report.**

fwscan scans Linux-based firmware rootfs images, identifies installed packages
from package-manager databases, emits a CycloneDX 1.6 SBOM, and reports known
vulnerabilities via [OSV.dev](https://osv.dev).

> **Status: pre-release, under active development.** The command surface below is
> the v0.1.0 target, not a description of what is finished today. Follow
> [`TASKS.md`](TASKS.md) for what has actually landed.

## Why

Existing options are fragmented (binwalk for extraction, syft/grype for
containers — neither firmware-native end to end) or expensive enterprise
platforms. The EU Cyber Resilience Act makes SBOM generation and vulnerability
handling a legal obligation for products sold in the EU from 2027, and firmware
teams need a simple answer in minutes.

fwscan is **backport-aware**: a Debian package patched via a security backport is
reported as clean, because the query carries the release codename. That single
detail is the difference between a usable report and the classic scanner false
positive — "OpenSSH 8.4 is vulnerable!" when Debian fixed it in
`8.4p1-5+deb11u3`. See [`spike/NOTES.md`](spike/NOTES.md) for the evidence.

## Planned command surface (v0.1.0)

```
fwscan scan <path-to-rootfs|tarball|squashfs>
    --output <file.json>      # machine-readable report
    --sbom <file.cdx.json>    # write CycloneDX SBOM
    --fail-on <low|medium|high|critical>
    --no-network              # SBOM only, skip CVE lookup
fwscan version
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` scan error.

## Building from source

Requires Go (see `go.mod` for the version) and, for squashfs images,
`squashfs-tools` 4.4 or newer.

```sh
git clone https://github.com/mhmtkas/fwscan
cd fwscan
make build      # -> bin/fwscan
make test
make lint
```

Release binaries and `go install` instructions land at v0.1.0.

## Limitations

Deliberately out of scope for v1: binary fingerprinting of unmanaged binaries,
encrypted or obfuscated firmware, SPDX output, opkg/rpm catalogers, kernel
config and kernel CVE applicability analysis, VEX, and offline operation. For
multi-partition flash dumps, UBI, JFFS2 and cramfs, extract with binwalk first
and point fwscan at the resulting rootfs. The full list lives in
[`docs/mvp-scope.md`](docs/mvp-scope.md).

Name note: an unrelated, low-activity `fwscan` package exists on PyPI. This
project is a Go tool distributed through GitHub releases and is not connected to
it.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a vulnerability *in fwscan
itself*, see [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
