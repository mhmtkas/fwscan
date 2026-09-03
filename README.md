# fwscan

[![ci](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml/badge.svg)](https://github.com/mhmtkas/fwscan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Point it at a rootfs — a directory, a tarball, or a squashfs image — and get a
CycloneDX SBOM and a CVE report.**

fwscan reads the dpkg or apk database inside a Linux root filesystem, emits a
CycloneDX 1.6 SBOM, and queries [OSV.dev](https://osv.dev) for known
vulnerabilities — falling back to the distribution's own records for a release
OSV has stopped carrying. One static binary, no configuration, no API key,
nothing to install or keep fresh on disk.

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

The fixture is a Debian 11 rootfs, so a live scan of it also prints this on
stderr, which is the second half of the answer:

```
fwscan: debian 11 (bullseye) left free security support on 2026-08-31 and is now
covered only by Extended LTS (Freexian, commercial), until 2031-06-30. OSV drops a
release when free support ends, so the vulnerabilities below were read from Debian's
own security tracker instead; nothing there carries a fix, because none is
published for this release
```

## Why this exists, and when not to use it

Firmware teams are being asked for SBOMs. The EU Cyber Resilience Act makes SBOM
generation and vulnerability handling a legal obligation for products sold in
the EU from 2027, and the reporting obligations start earlier. The tools that
answer that today mostly assume a container: they take an image reference, pull
from a registry, and want a vulnerability database staged first.

fwscan takes a path. A directory, a tarball in any of five compressions, or a
squashfs image — the shapes an appliance rootfs actually arrives in — and one
command produces both artifacts. trivy will not read a tarball or a squashfs
image at all; grype reads the tarball and returns nothing for the squashfs.

It also keeps no state on disk: the vulnerability data is fetched per scan, so
there is no database to stage and nothing to keep fresh. Be clear about the size
of that. On a warm cache trivy scans the same rootfs in 0.35 seconds against
fwscan's 2.8, and pays for it with 1.3 GB of local cache (grype's is 2.0 GB).
The trade is disk and setup against speed and offline capability, and which side
you want depends on whether your CI runners are ephemeral.

**It is backport-aware**, which any usable Debian or Alpine scanner has to be.
OpenSSL 1.1.1k looks vulnerable to CVE-2022-0778 and is not, if the installed
package is `1.1.1k-1+deb11u2` — the fix was backported into the Debian revision.
fwscan carries the release into every query, so it reports that as fixed. The
evidence, including what happens without the release qualifier, is in
[`spike/NOTES.md`](spike/NOTES.md).

**grype and trivy are backport-aware too, and both are good tools.** On every
Debian and Ubuntu image measured, the three are level or fwscan is ahead. The
matching is a commodity and this README does not pretend otherwise;
[`docs/comparison.md`](docs/comparison.md) has the numbers, three tools across
seven real images, and the commands to re-derive them. Read it before choosing
this over either.

**Two things here have no equivalent in either.** `--cra` writes the scan up as
evidence toward the Cyber Resilience Act's vulnerability-handling obligations,
naming the ones it cannot speak to rather than letting a reader assume they are
covered. And every scan says whether the release in the image still receives
security updates and whether those updates are free — which, for a product being
placed on the market, is a more important sentence than any row in the table.
Both are below.

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

# the SBOM plus a CRA evidence report that references it
fwscan scan --sbom bom.cdx.json --cra evidence.md rootfs.squashfs
```

### The whole command surface

```
fwscan scan <path-to-rootfs|tarball|squashfs>
    --output <file.json>      # machine-readable report
    --sbom <file.cdx.json>    # CycloneDX 1.6 SBOM
    --cra <file.md>           # Cyber Resilience Act evidence report
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
- **`--cra evidence.md`** — the scan written up as evidence toward the Cyber
  Resilience Act's vulnerability-handling obligations. See below.

## Is this release still supported

Every scan says whether the release in the image still receives security
updates, and whether those updates are free — on stderr, and in the evidence
report above the vulnerability table. Debian's LTS is volunteer work published
to everyone; its Extended LTS is Freexian's to sell, and every Ubuntu tier past
the first needs an Ubuntu Pro subscription. A reader told only "still supported"
about a Debian 11 image would draw the opposite of the right conclusion.

The dates are `distro-info-data`, the table Debian and Ubuntu maintain for this
question, embedded in the binary rather than fetched, so an offline run still
knows. A distribution the table does not carry is reported as unknown rather
than guessed at.

That answer also decides where the vulnerability data comes from. **A Debian
release past free support is read from Debian's own security tracker.** OSV's
Debian data is built from an export that carries a release only while it is
freely supported, so Debian 11 left it on 2026-08-31 and a scan of a bullseye
image went from a full report to an empty one — not because the image had been
fixed but because the data had gone. For that case, and only that case, fwscan
reads the export's input instead. A supported release fetches none of it.

## How it compares

Measured on 3 September 2026, with grype 0.118.0 and trivy 0.74.0, both
databases rebuilt that day. fwscan fetches its data per scan and the others
ship a database, so all three counts move; re-derive them rather than quote
them.

| Image | fwscan | grype | trivy |
|---|---|---|---|
| Debian 11 bullseye | 208 | 211 | 222 |
| Debian 12 bookworm | 182 | 179 | 188 |
| Debian 13 trixie | 184 | 144 | — |
| Ubuntu 22.04 | 140 | 101 | 67 |
| Ubuntu 24.04 | 120 | 101 | 74 |
| Ubuntu 26.04 | 151 | 153 | 117 |
| Alpine 3.21.7 | 0 | 3, of which 0 from Alpine's data | — |
| Alpine 3.16.9 (end of life) | 4 | 67, of which 4 from Alpine's data | — |
| squashfs image | reads it | 0 artifacts | not scanned |
| tarball | reads it | reads it | not scanned |

On Debian 11, against trivy with a database built the same day: 111 CVEs in
both, none that fwscan reports and trivy does not. Four hours later the same
image gave fwscan 232 findings rather than 208, all from upstream publishing
rather than any change here — which is what the caveat above is about.

On Alpine the two agree **exactly** on Alpine's own data: 4 to 4, 10 to 10 and 0
to 0 across three releases. grype's larger totals come from matching package
names against NVD's CPE strings, a technique
[`docs/scope.md`](docs/scope.md) excludes by name, and the Alpine column above
says which half is which. Those rows are the latest point release of each tag —
3.16.9, 3.19.9, 3.21.7, fully patched; an earlier pass using the `.0` images
reported 27, 42 and 56 from the same tool.

On Debian the two often differ on severity, because fwscan scores the CVSS
vector and grype reports Debian's own rating, which is `negligible` for a great
many CVEs. Debian and Ubuntu are queried against their own data, and an Ubuntu
image is never told about a fix that only an Ubuntu Pro subscription ships.

Severity is scored locally from the record's CVSS vector — v3.1, v4.0 or v2, in
that order of preference. The v4 scorer matches FIRST's reference calculator
across the whole base metric space.

[`docs/comparison.md`](docs/comparison.md) has the full table — seven real
images, three tools — and every command needed to re-derive it.

## Cyber Resilience Act evidence

Annex I, Part II of Regulation (EU) 2024/2847 lists eight vulnerability-handling
obligations. Three of them are things a scan can produce evidence for:
identifying and documenting the components a product contains, establishing
which carry known vulnerabilities, and recording whether a fix exists. The other
five are about testing, disclosure and update distribution, and no tool can
observe them from a filesystem.

`--cra evidence.md` writes a Markdown document covering the three and naming the
five it does not cover, in its own body, every time. It has the scan's
provenance — target, tool version, data source, timestamp — a reference to the
SBOM rather than a second copy of the inventory, one row per finding split by
whether a fix exists for the installed release, and a `Justification` column
left deliberately empty, because the reason an unresolved finding is acceptable
belongs to whoever ships the product.

It is not a compliance statement and says so at the top. A generated file that
let a reader assume the other five obligations were covered would be worse than
no file at all.

```sh
fwscan scan --sbom bom.cdx.json --cra evidence.md rootfs.squashfs
```

The exact structure is fixed by
[`docs/output-spec.md`](docs/output-spec.md) section 5, and
[`testdata/golden/cra-findings.md`](testdata/golden/cra-findings.md) is a
complete example.

## Limitations

Deliberately out of scope for v1:

| Not supported | Why |
|---|---|
| Yocto, Buildroot and other custom builds | No package database fwscan reads, or one with no distribution release behind it; the kernel and busybox are found by heuristics and nothing is looked up |
| Binary fingerprinting of unmanaged binaries | An accuracy problem with no bottom; not planned |
| Encrypted or obfuscated firmware | Per-vendor work |
| SPDX output | CycloneDX covers the CRA; SPDX behind a flag later |
| opkg and rpm databases | Debian, Ubuntu and Alpine first |
| Kernel config and kernel CVE applicability | Genuinely hard, config-dependent |
| VEX exploitability statements | Needs a stable core first |
| Offline operation | The lookup needs the network; `--no-network` gives the SBOM only |
| False-positive suppression config | Waiting for real users to report real false positives |

Multi-partition flash dumps, UBI, JFFS2 and cramfs are not read directly:
extract with binwalk first and point fwscan at the resulting rootfs. It does not
try to compete with binwalk on extraction.

Input is bounded because it is untrusted. An archive or image whose declared
contents are out of proportion to its size — more than 4 GiB in total, or over
5000× the file it came from past 64 MiB — is refused rather than extracted, as
is an xz stream declaring a dictionary over 128 MiB (`xz -9` uses 64 MiB) and a
path more than 256 levels deep. No real firmware image is near any of these.

**Some findings carry no severity**, land in the `unknown` bucket, and so never
trigger `--fail-on`: the record they came from published no CVSS vector. That is
30 of 182 findings on a bookworm image and 71 of 208 on a bullseye one, mostly
old issues the distribution itself marked minor. They are visible in the report
and invisible to the exit code, so read the output as well as the status.

**Components identified by filename heuristics are never looked up.** They are
listed in the report and the SBOM, but a version guessed from a filename carries
no release to scope a query to, and an unscoped query invents vulnerabilities
rather than finding them. They are counted separately on the `Packages` line so
the difference is visible.

### Vendor packages in a vendor image

`var/lib/dpkg/status` records what is installed. It does not record where a
package came from, so fwscan cannot tell a package from the distribution's
archive apart from one a vendor built and installed themselves. Three
consequences, all measured on synthetic images:

**A vendor version of a distribution package is handled correctly.** dpkg's
version ordering understands a vendor suffix, so `libssl1.1
1.1.1k-1+deb11u1acme1` gets the same findings as the stock version, and
`zlib1g 1:1.2.11.dfsg-2+deb11u2acme1` — a vendor rebuild on top of the fixed
version — is correctly not reported for the CVEs that fix closed. This is the
common case and it works.

**A vendor package the distribution has never shipped produces no findings**,
which is right, but it is still described in the SBOM as
`pkg:deb/debian/your-package@1.0.0`. That purl asserts a Debian archive package
and is wrong. Treat the purls of your own packages as names rather than as
identifiers a downstream tool can resolve.

**A vendor package that shares a name with a distribution source package
inherits its vulnerabilities.** A package called `curl` at version `0.1-acme1`
sorts below every fix Debian ever published for curl and is reported against all
of them — 163 findings for one package, in a test image. A vendor package whose
`Source:` field names a distribution package does the same. If your build
installs packages under names the distribution also uses, expect false positives
there and check that section of the report by hand.

There is no reliable automatic fix for the last two: the information needed to
tell the cases apart is not in the file being read. Naming the failure is the
honest option, and a version-plausibility guess would be a worse one.

### Images with no distribution release

An image whose os-release carries no `VERSION_CODENAME` — a Yocto build, a
hand-assembled rootfs — has its dpkg packages **cataloged but not looked up**,
and the scan says so.

That is not caution. Without a release the query carries no distro qualifier and
matches the source package in every Debian release at once. A Yocto image built
with `package_deb`, six packages, produced 182 findings that way, with fixed
versions from Debian 6, 8, 9, 10, 11, 12, 13 and unstable — including a Debian 8
busybox offered as the fix for a busybox thirteen minor versions newer. None of
them installable on that image. The measurement is in
[`spike/NOTES.md`](spike/NOTES.md) under T66.

The SBOM is unaffected and complete: it does not depend on a release. If your
build can put a `VERSION_CODENAME` in os-release that names the distribution
release your packages actually came from, the lookup works normally.

### Derivative distributions

A derivative that declares its base in os-release's `ID_LIKE` — Raspberry Pi OS,
Armbian, Linux Mint — is looked up in that base's data, under the release its
`VERSION_CODENAME` names, and the scan says so. That is where its packages came
from, so it is the right answer: a Raspberry Pi OS bullseye image gets the same
45 findings for `libssl1.1` that Debian bullseye does, rather than the 28 it
would get without.

A dpkg-based image that names no base fwscan recognises is queried as Debian
anyway, because that is what one is most likely built from — and the scan says
that too, because if the derivative renumbered its packages the query returns
nothing rather than an error.

## Roadmap

Next is VEX output, then offline vulnerability data for air-gapped builds. An
opkg cataloger, SPDX, NVD as a second source and the rest follow.
[`docs/roadmap.md`](docs/roadmap.md) has the order and the reasoning;
[`docs/scope.md`](docs/scope.md) has what is excluded and why.

## Name

`fw` is short for firmware, which is the audience rather than the capability:
this reads dpkg and apk, so a Debian, Ubuntu or Alpine rootfs, and the first
screen above says so. It does not extract or fingerprint binaries the way
binwalk does.

An abandoned `fwscan` package exists on PyPI at 0.0.5, and a handful of
unrelated GitHub repositories share the name. None is connected to this. This
one is a Go tool distributed through GitHub releases.

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
