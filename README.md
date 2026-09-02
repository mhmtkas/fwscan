# fwscan

[![ci](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml/badge.svg)](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Point it at a rootfs — a directory, a tarball, or a squashfs image — and get a
CycloneDX SBOM and a CVE report.**

fwscan reads the dpkg or apk database inside a Linux root filesystem, emits a
CycloneDX 1.6 SBOM, and queries [OSV.dev](https://osv.dev) for known
vulnerabilities. One static binary, no configuration, no API key, no database to
provision.

It reads **Debian, Ubuntu and Alpine** packages. It does not read opkg, rpm,
buildroot or Yocto manifests, so it will not tell you much about an OpenWrt or a
Yocto image beyond a kernel version and a busybox. That boundary is deliberate
and [documented](docs/scope.md); read it before adopting this.

```console
$ fwscan scan rootfs.tar.gz

fwscan v0.1.0

  Target      rootfs.tar.gz (tar, gzip)
  Packages    7 (6 high confidence, 1 low)
  Findings    9   critical: 2  high: 2  medium: 5  low: 0  unknown: 0

SEVERITY  SCORE  PACKAGE    INSTALLED         FIXED                    VULN ID         CONF
critical  9.8    zlib1g     1:1.2.11.dfsg-2   1:1.2.11.dfsg-2+deb11u2  CVE-2022-37434  high
critical  9.1    libssl1.1  1.1.1k-1+deb11u1  1.1.1n-0+deb11u6         CVE-2024-5535   high
high      7.5    libssl1.1  1.1.1k-1+deb11u1  1.1.1k-1+deb11u2         CVE-2022-0778   high
high      7.5    libssl1.1  1.1.1k-1+deb11u1  1.1.1n-0+deb11u6         CVE-2024-4741   high
medium    5.9    libssl1.1  1.1.1k-1+deb11u1  1.1.1n-0+deb11u6         CVE-2024-2511   high
...

1 low-confidence component was identified by filename heuristics and may be a false positive.
Run with --output report.json for full details including aliases and evidence paths.
```

That is the fixture image in `testdata/images/` against the OSV responses
recorded in `testdata/osv/`, byte for byte what the end-to-end test compares
against. A live scan of the same image finds more, because OSV has more; the
shape is the same.

## Why this exists, and when not to use it

Firmware teams are being asked for SBOMs. The EU Cyber Resilience Act makes SBOM
generation and vulnerability handling a legal obligation for products sold in
the EU from 2027, and the reporting obligations start earlier. The tools that
answer that today mostly assume a container: they take an image reference, pull
from a registry, and want a vulnerability database staged first.

fwscan takes a path. A directory, a tarball in any of five compressions, or a
squashfs image — the shapes an appliance rootfs actually arrives in — and one
command produces both artifacts. There is no database to provision and nothing
to keep fresh, because the CVE data is fetched at scan time. That is the whole
of the difference in workflow, and for a CI job that has to produce an SBOM per
build it is a real one.

**It is backport-aware**, which any usable Debian or Alpine scanner has to be.
OpenSSL 1.1.1k looks vulnerable to CVE-2022-0778 and is not, if the installed
package is `1.1.1k-1+deb11u2` — the fix was backported into the Debian revision.
fwscan carries the release into every query, so it reports that as fixed. The
evidence, including what happens without the release qualifier, is in
[`spike/NOTES.md`](spike/NOTES.md).

**grype is backport-aware too, and it is a good tool.** On current releases the
two are level or fwscan is ahead; on a release past its support window fwscan is
far behind, for a reason that is about the data source rather than the matching.
[`docs/comparison.md`](docs/comparison.md) has the numbers and the commands to
re-derive them. Read it before choosing this over grype.

**Use something else if** your image is OpenWrt, Yocto or rpm-based; if you need
to scan a running host or a registry image; if you need offline operation or a
policy engine or VEX. fwscan does one thing.

## Install

Download a binary from the [releases page](https://github.com/mhmtkas/fwscan/releases)
— linux/amd64, linux/arm64, darwin/arm64:

```sh
VERSION=0.1.0   # the release you want; see the releases page
curl -sSfL -o fwscan.tar.gz \
  "https://github.com/mhmtkas/fwscan/releases/download/v${VERSION}/fwscan_${VERSION}_linux_amd64.tar.gz"
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
| Binary fingerprinting of unmanaged binaries | An accuracy problem with no bottom; not planned |
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

Input is bounded because it is untrusted. An archive or image whose declared
contents are out of proportion to its size — more than 4 GiB in total, or over
5000× the file it came from past 64 MiB — is refused rather than extracted, as
is an xz stream declaring a dictionary over 128 MiB (`xz -9` uses 64 MiB) and a
path more than 256 levels deep. No real firmware image is near any of these.

**fwscan reports the CVEs a distribution has issued a fix for. It does not
report the ones a distribution has chosen not to fix**, because OSV's data for
those thins out as a release ages, and disappears once it leaves support.

On supported releases this costs little and fwscan is level with grype or ahead
of it: 182 findings to 179 on a Debian bookworm rootfs, 148 to 144 on trixie,
140 to 101 on Ubuntu 22.04, 56 to 58 on Alpine 3.21. On a release past its
support window it costs a great deal — on a fully patched Debian 11 rootfs
fwscan reports **nothing** where grype reports 211, every one of them a CVE
Debian has not fixed. A scan of a Debian image that finds nothing says so on
stderr rather than leaving you with "No known vulnerabilities found".

Where both tools report a finding they agree on Alpine. On Debian they often
differ on severity, because fwscan scores the CVSS vector and grype reports
Debian's own rating, which is `negligible` for a great many CVEs.
Debian and Ubuntu are queried against their own OSV data, and an Ubuntu image
is never told about a fix that only an Ubuntu Pro subscription ships.
[`docs/comparison.md`](docs/comparison.md) has the full table — seven real
images — and the commands to re-derive it. A second data source, which is what
would close the gap, is on the roadmap and is not in v0.1.0.

**Some findings carry no severity**, land in the `unknown` bucket, and so never
trigger `--fail-on` — roughly a fifth of Debian's OSV records, 57 of the 292 the
spike measured, mostly old issues Debian itself marked minor. They are visible in
the report and invisible to the exit code, so read the output as well as the
status.

**Components identified by filename heuristics are never looked up.** They are
listed in the report and the SBOM, but a version guessed from a filename carries
no release to scope a query to, and an unscoped query invents vulnerabilities
rather than finding them. They are counted separately on the `Packages` line so
the difference is visible.

Severity is scored locally from the record's CVSS vector — v3.1, v4.0 or v2, in
that order of preference. The v4 scorer matches FIRST's reference calculator
across the whole base metric space.

## Roadmap

The first thing after v0.1.0 is a CRA compliance report (`--report cra`), then
VEX output, then offline vulnerability data for air-gapped builds. An opkg
cataloger, SPDX, NVD as a second source and the rest follow.
[`docs/roadmap.md`](docs/roadmap.md) has the order and the reasoning;
[`docs/scope.md`](docs/scope.md) has what is excluded and why.

## Name

An unrelated, low-activity `fwscan` package exists on PyPI. This is a Go tool
distributed through GitHub releases and is not connected to it.

## Development

```sh
make build            # -> bin/fwscan
make test             # go test ./... -cover, with -race where the kernel supports it
make lint             # golangci-lint run
make fixtures         # rebuild the squashfs test images
make validate-sbom    # generate an SBOM and check it against the CycloneDX schema
make test-integration # the tests that hit the real OSV API
make test-apk-oracle  # check the apk version comparator against apk itself (needs Docker)
make test-cvss4-oracle # check CVSS v4 scores against FIRST's calculator (needs Docker)
make snapshot         # build release artifacts locally
make demo             # scan the fixture, for an asciinema recording
make third-party-licenses # regenerate THIRD_PARTY_LICENSES.txt after a dependency change
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md), and
[`docs/scope.md`](docs/scope.md) before proposing a feature — the
non-goals above are deliberate, and [`docs/roadmap.md`](docs/roadmap.md) says
which of them are expected later.

## Security

To report a vulnerability *in fwscan itself*, see [`SECURITY.md`](SECURITY.md).
fwscan parses untrusted firmware, so extraction is bounded and confined to a temp
directory it removes afterwards.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

The release binaries bundle their Go dependencies, and the CVSS v4 scoring
tables are transcribed from FIRST's reference calculator. Those components'
licences and notices are in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt), which ships in every
release archive.
