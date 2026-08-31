# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The rule for a finding's `id` and `aliases` now lives in `docs/output-spec.md`
  section 3 rather than only in a code comment: the plain CVE from OSV's
  `upstream` field is the identifier, and the `DEBIAN-CVE-…`/`ALPINE-CVE-…`
  record id is kept as an alias. No behaviour change — the matcher already did
  this.
- `docs/output-spec.md` section 2 no longer shows a finding against a
  low-confidence component, and states instead that components identified by
  filename heuristics are cataloged and reported but never queried against OSV.
  The example implied a lookup the scanner deliberately does not perform.
- The README's limitations section gives the combined share of findings that
  `--fail-on` cannot see — severity-less records and CVSS v4-only records
  together — instead of describing the two separately, and now also says that
  heuristically identified components are never looked up.
- `make test` now probes for race-detector support and runs without it on
  kernels that cannot provide it, instead of failing outright. CI uses the new
  `make test-race`, which still requires it.

### Fixed

- An Alpine package whose version carries a pre-release suffix — `_alpha`,
  `_beta`, `_pre` or `_rc` — is now ordered by apk's rules rather than Debian's.
  The two disagree on exactly those suffixes, and the Debian library does not
  reject an apk version, it answers wrongly. Where an advisory records more than
  one fix window for a release, that named a later release's fix than the one
  that actually resolves the issue. Version comparison is now chosen by the same
  ecosystem that chooses the query shape.
- A vulnerability unfixed in the scanned release no longer reports another
  release's fixed version, which pointed at a package that does not exist for
  that image.
- Control characters from a package name or version are replaced before
  reaching the terminal, so a crafted image cannot write escape sequences to
  the reader's screen.
- A paginated OSV result is reported as an error rather than silently
  truncating the findings.
- A hard link whose source was a dropped absolute symlink no longer aborts the
  whole scan.
- A CVSS vector scoring exactly zero no longer produces an `unknown` severity
  that still carries a vector.

## [0.1.0] — 2026-08-30

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

### Known limitations

- Roughly a fifth of Debian's OSV records carry no severity and land in the
  `unknown` bucket, which `--fail-on` never triggers on.
- Records carrying only a CVSS v4 vector also report as `unknown`.
- Heuristic components are reported but not looked up.
- No offline mode, no SPDX output, no opkg or rpm support, no VEX. See the
  limitations table in the README.

[Unreleased]: https://github.com/mhmtkas/fwscan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mhmtkas/fwscan/releases/tag/v0.1.0
