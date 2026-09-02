# fwscan — scope

What fwscan is for, who it is for, and what it deliberately does not do. When
this document and an implementation disagree, this document is what the
implementation was built to satisfy; when it and `docs/output-spec.md` disagree
about a format, the output spec wins.

## The problem

Embedded device manufacturers need to know what software ships inside their
firmware and which known vulnerabilities affect it. The EU Cyber Resilience Act,
fully applicable in 2027, makes SBOM generation and vulnerability handling a
legal obligation for products sold in the EU.

The existing options sit at two extremes. Open source pieces exist but must be
assembled — binwalk for extraction, syft and grype for containers, neither
firmware-native end to end — and enterprise platforms are priced for enterprise
procurement. fwscan is the middle: point it at a firmware image, get a CycloneDX
SBOM and a severity-sorted CVE report.

## Who it is for

A firmware or embedded Linux engineer at a small or mid-size device
manufacturer, who builds Debian, Yocto or OpenWrt based Linux firmware, has been
asked for an SBOM by compliance or by a customer, and wants a working answer
from a command line rather than a sales call.

Not the target, and this shapes the non-goals below: security researchers doing
deep binary analysis, and RTOS, bare-metal, Windows or VxWorks images.

## Goals

1. Scan a Linux firmware rootfs and identify installed packages with versions.
2. Emit a valid CycloneDX 1.6 JSON SBOM.
3. Match components against known vulnerabilities via OSV.dev.
4. Produce a human-readable, severity-sorted terminal report.
5. Run as a single installable binary, with no configuration for the ordinary
   case.

## Non-goals

These are deliberate exclusions, not gaps waiting to be filled. The failure mode
for a tool in this space is scope creep into "binwalk plus Ghidra plus
everything", and each row below is a place that creep would start.

| Excluded | Why |
|---|---|
| Binary fingerprinting of unmanaged binaries | An accuracy problem with no bottom; fwscan reports what a package database states and labels anything else as low confidence |
| Encrypted or obfuscated firmware | Per-vendor work with no general solution |
| SPDX output | CycloneDX covers the CRA obligation; a second format is a maintenance cost without a second use |
| opkg and rpm package databases | Start narrow: dpkg and apk cover the images this was built for |
| Kernel configuration and kernel CVE applicability | Genuinely hard, and config-dependent in ways a scanner cannot see |
| Web dashboard, continuous monitoring, hosted service | A different product |
| VEX exploitability statements | Valuable for the CRA, but needs a stable core underneath it |
| False-positive suppression configuration | Worth adding when real users report false positives, not before |
| Offline operation | Vulnerability data comes from OSV.dev at scan time; `--no-network` skips the lookup rather than substituting a local database |

`docs/roadmap.md` lists which of these are expected to arrive later, and in what
order.

## What it reads and what it produces

| Input | Supported |
|---|---|
| An extracted rootfs directory | Yes |
| A rootfs tarball, plain or compressed with gzip, xz, zstd or lz4 | Yes — compression is detected by content, not by file name |
| A SquashFS image, with gzip, xz, lz4 or zstd internal compression | Yes, via `unsquashfs` |
| A full flash dump | No — extract the rootfs with binwalk first |

| Identification | Confidence |
|---|---|
| dpkg status database, Debian or Ubuntu | High |
| apk installed database | High |
| Filename heuristics for unmanaged components such as BusyBox and the kernel | Low, always with the evidence path, and never queried against OSV |

Outputs are a terminal report, a JSON report, and a CycloneDX 1.6 SBOM. Their
exact shapes — field names, severity mapping, sort order, exit codes — are
specified in `docs/output-spec.md`, which is the authority on all three.

## Architecture

Input handlers produce an `fs.FS`; catalogers read one and produce components;
the matcher consumes components and produces findings; reporters render them.
Each stage is an interface, so a new cataloger or a second vulnerability source
is an addition rather than a refactor. `docs/architecture.md` describes the
pipeline in full, including how to add a cataloger.

## Dependencies

The dependency list is closed by design, and adding to it is a decision rather
than a convenience: `cyclonedx-go` for SBOM serialisation, `packageurl-go` for
purl construction, `go-deb-version` for Debian version comparison, `cobra` for
the command line, and `pierrec/lz4`, `klauspost/compress` and `ulikunitz/xz` for
decompression. apk version comparison and CVSS scoring are implemented in this
repository rather than taken from a dependency; the reasons are recorded where
they are implemented.

`unsquashfs` is the only external program fwscan ever runs.
