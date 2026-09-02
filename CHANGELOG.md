# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-02

First release. Scans a Linux firmware rootfs, emits a CycloneDX SBOM, and
reports known vulnerabilities from OSV.dev.

### Added

**Scanning**

- `fwscan scan` reading extracted rootfs directories, tar archives with gzip, xz,
  zstd or lz4 compression, and squashfs images. The format is detected from the
  file's contents, never from its name.
- dpkg cataloger (`var/lib/dpkg/status`) and apk cataloger
  (`lib/apk/db/installed`), both resolving the source package the vulnerability
  data is keyed on.
- Heuristic detectors for the kernel version, the busybox version and versioned
  shared libraries, reported at low confidence with the path they came from.
- Standalone-compressed images: `rootfs.squashfs.gz` and the other shapes Yocto
  and OpenWrt emit are unwrapped before extraction.
- Severity from CVSS v3.1, v4.0 or v2 vectors, scored locally. The v4 path
  matches FIRST's reference calculator across the whole base metric space; where
  a record carries no vector of its own but names the CVEs it fixed, each
  finding takes the vector of its own CVE's record, which is what makes
  `--fail-on` usable on an oldstable Debian image. An advisory that fixed
  several CVEs in one upload is reported as one finding per CVE, not one per
  advisory.

**Vulnerability matching**

- OSV.dev matcher, release-aware for both Debian and Alpine, so a package
  patched by a security backport is reported as fixed rather than vulnerable.
- Lookups batched and deduplicated by source package; vulnerability details
  fetched through a bounded worker pool.
- CVSS v3 and v2 base scores computed from their vectors, mapped to the severity
  buckets in `docs/output-spec.md`.
- Fixed versions selected per release, so a bookworm fix is never reported to a
  bullseye image.

**Output**

- Severity-sorted terminal report.
- `--output` for the full JSON report, written atomically.
- `--sbom` for a CycloneDX 1.6 document, validated against the official schema in
  CI, carrying components only.
- `--fail-on` and the exit codes from `docs/output-spec.md` section 5: 0 clean,
  1 findings at or above the threshold, 2 the scan could not complete.
- `--no-network` to produce the SBOM without any vulnerability lookup.

**Project**

- Release binaries for linux/amd64, linux/arm64 and darwin/arm64, with
  checksums.
- CI running lint, race tests, the squashfs compression matrix and CycloneDX
  schema validation.
- `spike/NOTES.md`, the evidence behind the query formats and the squashfs
  strategy, including the checks that failed before they passed.
- `THIRD_PARTY_LICENSES.txt` in every release archive, carrying the licences and
  notices of the dependencies the binaries link and of the CVSS v4 reference
  calculator this project transcribes. `make third-party-licenses` regenerates
  it from the module cache and CI fails if the committed copy has drifted.
- `docs/scope.md`, `docs/roadmap.md`, `docs/architecture.md`,
  `docs/output-spec.md` and `docs/comparison.md` — what fwscan is for, what is
  coming, how it is built, exactly what it emits, and how it measures against
  syft and grype.

### Known limitations

- fwscan finds less than grype does on the same image, and the gap is the data
  source rather than the matching: OSV's export for an oldstable Debian release
  lists the CVEs that received an advisory, while the Debian Security Tracker
  carries every CVE's per-release status. `docs/comparison.md` measures it — 113
  findings to 38 on the fixture image, with every fwscan finding also one of
  grype's and the two agreeing on what they share. A second data source is on
  the roadmap.
- Roughly a fifth of Debian's OSV records carry no severity and land in the
  `unknown` bucket, which `--fail-on` never triggers on.
- Heuristic components are reported but not looked up: a version read off a
  filename carries no release to scope a query to.
- No offline mode, no SPDX output, no opkg or rpm support, no VEX. See the
  limitations table in the README.

### Note on this changelog

This is the first release, so there is nothing to compare it against. The
defects fixed during the pre-publication review never reached a user and are
not changelog entries; they are in the commit history, each with the
measurement that found it.

[0.1.0]: https://github.com/mhmtkas/fwscan/releases/tag/v0.1.0
