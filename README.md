# fwscan

[![ci](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml/badge.svg)](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mhmtkas/fwscan.svg)](https://pkg.go.dev/github.com/mhmtkas/fwscan)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Point it at a firmware image, get a CycloneDX SBOM and a prioritized CVE report.**

fwscan scans Linux-based firmware rootfs images, identifies installed packages
from the package databases inside them, emits a CycloneDX 1.6 SBOM, and reports
known vulnerabilities from [OSV.dev](https://osv.dev). One static binary, no
configuration, no API key.

```console
$ fwscan scan rootfs.tar.gz

fwscan v0.1.0

  Target      rootfs.tar.gz (tar, gzip)
  Packages    7 (6 high confidence, 1 low)
  Findings    97   critical: 9  high: 44  medium: 36  low: 1  unknown: 7

SEVERITY  SCORE  PACKAGE      INSTALLED         FIXED                    VULN ID           CONF
critical  9.8    zlib1g       1:1.2.11.dfsg-2   1:1.2.11.dfsg-2+deb11u2  CVE-2022-37434    high
critical  9.1    libssl1.1    1.1.1k-1+deb11u1  1.1.1w-0+deb11u2         CVE-2024-5535     high
high      8.1    libc6        2.31-13+deb11u2   2.31-13+deb11u10         CVE-2024-33599    high
high      7.8    bash         5.1-2+b3          —                        CVE-2022-3715     high
...

1 low-confidence component was identified by filename heuristics and may be a false positive.
Run with --output report.json for full details including aliases and evidence paths.
```

## Why another scanner

Firmware teams are being asked for SBOMs. The EU Cyber Resilience Act makes SBOM
generation and vulnerability handling a legal obligation for products sold in the
EU from 2027. The existing options are fragmented — binwalk extracts, syft and
grype understand containers, none of them is firmware-native end to end — or they
are enterprise platforms with a sales call attached.

**fwscan is backport-aware, and that is the point.** Debian and Alpine patch
security bugs without moving the upstream version. OpenSSL 1.1.1k looks
vulnerable to CVE-2022-0778 and is not, if the installed package is
`1.1.1k-1+deb11u2` — the fix was backported into the Debian revision. A scanner
that compares upstream versions reports that as a critical finding. fwscan
carries the release into every query, so it reports it as fixed.

That single detail is the difference between a report someone acts on and a
report someone learns to ignore. The evidence behind it, including what happens
without the release qualifier, is in [`spike/NOTES.md`](spike/NOTES.md).

## Install

Download a binary from the [releases page](https://github.com/mhmtkas/fwscan/releases)
— linux/amd64, linux/arm64, darwin/arm64:

```sh
curl -sSfL -o fwscan.tar.gz \
  https://github.com/mhmtkas/fwscan/releases/latest/download/fwscan_0.1.0_linux_amd64.tar.gz
tar -xzf fwscan.tar.gz fwscan
sudo install fwscan /usr/local/bin/
fwscan version
```

Or with Go:

```sh
go install github.com/mhmtkas/fwscan/cmd/fwscan@latest
```

Scanning **squashfs** images additionally needs `squashfs-tools` 4.4 or newer
(`apt install squashfs-tools`, `brew install squashfs`). Nothing else is needed
for directories or tarballs.

## Quickstart

```sh
# an extracted rootfs directory
fwscan scan ./rootfs

# a tarball, any compression — detected by content, not by file extension
fwscan scan firmware-rootfs.tar.zst

# a squashfs image
fwscan scan rootfs.squashfs

# both artifacts, and fail a build on anything high or worse
fwscan scan --sbom bom.cdx.json --output report.json --fail-on high rootfs.squashfs

# SBOM only, no network
fwscan scan --no-network --sbom bom.cdx.json ./rootfs
```

### The whole command surface

```
fwscan scan <path-to-rootfs|tarball|squashfs>
    --output <file.json>      # machine-readable report
    --sbom <file.cdx.json>    # CycloneDX 1.6 SBOM
    --fail-on <low|medium|high|critical>
    --no-network              # SBOM only, skip the CVE lookup
fwscan version
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` the scan could
not complete. Diagnostics go to stderr and the report to stdout, so piping is
safe.

## What it reads

| Input | Notes |
|---|---|
| Extracted rootfs directory | The simplest path |
| Tarball: `.tar`, `.tar.gz`, `.tar.xz`, `.tar.zst`, `.tar.lz4` | Compression detected by magic bytes; an lz4 archive named `.gz` still works |
| SquashFS with gzip, xz, lz4 or zstd | Extracted with `unsquashfs` |

Packages come from **dpkg** (`var/lib/dpkg/status`) and **apk**
(`lib/apk/db/installed`). Everything from a package database is reported at
`high` confidence.

The kernel version, the busybox version and versioned shared libraries are
detected by filename or version string and reported at `low` confidence with the
path they came from. They are **not** looked up: a version inferred from a
filename has no release to scope it to, and querying it would manufacture
findings rather than find them. `libssl.so.3` names an ABI, not a release.

## Output

- **Terminal** — severity-sorted table, by default.
- **`--output report.json`** — the full result: every component with its purl,
  confidence and evidence path, and every finding with its aliases, CVSS vector
  and fixed version.
- **`--sbom bom.cdx.json`** — CycloneDX 1.6, validated against the official
  schema in CI. Components only: an SBOM that changes every time a CVE is
  published cannot be shared or diffed, so vulnerabilities stay in the report.

## Limitations

Deliberately out of scope for v1:

| Not supported | Why |
|---|---|
| Binary fingerprinting of unmanaged binaries | A large accuracy problem; v2 |
| Encrypted or obfuscated firmware | Per-vendor work |
| SPDX output | CycloneDX covers the CRA; SPDX behind a flag later |
| opkg and rpm databases | Debian and Alpine first |
| Kernel config and kernel CVE applicability | Genuinely hard, config-dependent |
| VEX exploitability statements | Needs a stable core first |
| Offline operation | The lookup needs OSV.dev; `--no-network` gives the SBOM only |
| False-positive suppression config | Waiting for real users to report real false positives |

Multi-partition flash dumps, UBI, JFFS2 and cramfs are not read directly:
extract with binwalk first and point fwscan at the resulting rootfs. It does not
try to compete with binwalk on extraction.

Two honest caveats. Roughly a fifth of Debian's OSV records carry no severity at
all — 57 of the 292 the spike measured — and land in the `unknown` bucket, which
`--fail-on` never triggers on. They are mostly old issues Debian itself marked
minor, but they are visible in the report and invisible to the exit code, so
read the output as well as the status.

Second: components identified by filename heuristics rather than by a package
database are listed in the report and the SBOM, but are never looked up. A
version guessed from a filename carries no release to scope the query to, and an
unscoped query invents vulnerabilities rather than finding them. They are
counted separately on the `Packages` line so the difference is visible.

Severity comes from the record's CVSS vector, v3.1 or v4.0, scored locally: v4
base scores match FIRST's reference calculator across the whole base metric
space.

## Name

An unrelated, low-activity `fwscan` package exists on PyPI. This is a Go tool
distributed through GitHub releases and is not connected to it.

## Development

```sh
make build            # -> bin/fwscan
make test             # go test ./... -race -cover
make lint             # golangci-lint run
make fixtures         # rebuild the squashfs test images
make validate-sbom    # generate an SBOM and check it against the CycloneDX schema
make test-integration # the tests that hit the real OSV API
make test-apk-oracle  # check the apk version comparator against apk itself
make test-cvss4-oracle # check CVSS v4 scores against FIRST's calculator
make snapshot         # build release artifacts locally
make demo             # scan the fixture, for an asciinema recording
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md), and
[`docs/mvp-scope.md`](docs/mvp-scope.md) before proposing a feature — the
non-goals above are deliberate.

## Security

To report a vulnerability *in fwscan itself*, see [`SECURITY.md`](SECURITY.md).
fwscan parses untrusted firmware, so extraction is bounded and confined to a temp
directory it removes afterwards.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
