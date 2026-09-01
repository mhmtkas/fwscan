# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `THIRD_PARTY_LICENSES.txt`, carrying the licences and notices of the Go
  dependencies linked into the release binaries and of FIRST's CVSS v4
  reference calculator, whose MacroVector table this project transcribes. Those
  licences require the notices to travel with any copy; the release archives now
  include the file, `make third-party-licenses` regenerates it from the module
  cache, and CI fails if the committed copy has drifted.
- CVSS v4.0 base scoring. A record carrying only a v4 vector used to report as
  `unknown`, which meant it could never trigger `--fail-on`; every such record
  in the data the spike measured was a 2025 or 2026 CVE, so the blind spot was
  growing with each release. v4 scores now map to the same severity bands as
  v3, and `docs/output-spec.md` section 1 carries the rule.

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
- The apk version comparator is now written from the format documented in
  `apk-package(5)` rather than ported from apk-tools' implementation, which is
  GPL-2.0-only and could not be distributed under this project's Apache-2.0
  licence. Behaviour is unchanged and still checked against `apk version -t`
  itself, over a corpus grown from 3844 to 8464 ordered pairs.

### Fixed

- The fixed version reported for a finding is no longer sometimes a version
  older than the one installed, which read as an instruction to downgrade. It is
  only reported when it is genuinely newer, or when the two cannot be ordered at
  all — an ecosystem with no version comparison of its own, where declining to
  answer would lose the column entirely.
- A finding's fixed version is no longer taken from a neighbouring release.
  Release matching searched the affected package's purl for `distro=<release>`,
  and a substring search reads `distro=bullseye` out of `distro=bullseye-backports`;
  the qualifier is now parsed and compared. Backports is a different release with
  a different fixed version, which is the confusion the qualifier exists to
  prevent.
- A cancelled scan now fails instead of quietly reporting fewer vulnerabilities
  than it found. When the context was cancelled while vulnerability records were
  being fetched, the loop handing out work skipped the record it was holding and
  moved to the next one, so every remaining record was dropped; no worker had
  failed, so no error was raised either, and the report came back short with
  nothing saying so. The fetch now stops on cancellation and reports it, refuses
  to return fewer records than it was asked for, and the matcher treats a
  missing record as an error rather than a finding to skip.
- Error messages are sanitised before reaching the terminal. A message names
  the archive entry that caused it, and an entry name comes from the image, so
  escape sequences in one reached the terminal verbatim — enough to clear the
  screen and scroll a fabricated result into view. The report has been sanitised
  since it was written; the error path had not been. Sanitising also now covers
  bidirectional overrides and zero-width characters, which do not garble a
  terminal but do make one name read as another.
- Parsing a dpkg status file is now linear in its size. Continuation lines were
  appended to the field directly, which copies the whole field each time, and
  the field limit permits enough of them for a status file of a few megabytes to
  cost minutes of CPU with no timeout above it. Measured before and after:
  400,000 continuation lines took 56.5 seconds, and now take about 30
  milliseconds. The file as a whole is also bounded at 256 MiB, which the
  per-line, per-field and per-stanza limits did not imply.
- Extraction is now bounded against the size of the archive it came from, not
  only by an absolute cap. The absolute caps were a formality rather than a
  bound — 16 GiB total and 8 GiB per file, when the extraction directory is a
  tmpfs on most systems — and are now 4 GiB and 2 GiB. Alongside them, an
  archive that has produced more than 64 MiB at over 5000 times its own size on
  disk is refused. That covers the amplification a lexical size check cannot
  see: a PAX sparse entry is expanded to its declared length by the reader, so a
  10 KiB uncompressed tar could produce 200 MiB without a single one of those
  bytes passing through the decompressor.
- Scanning a squashfs image no longer fails on an ordinary absolute symlink.
  A rootfs is full of them — `bin/sh` pointing at `/bin/busybox`, and everything
  `update-alternatives` creates — and the extractor resolved every link after
  extraction and refused the image if one landed outside its temp directory,
  which an absolute link does whenever the scanning machine has that path too.
  The first real OpenWrt or Yocto image would have hit it. Reads are confined by
  `os.Root` instead, so such a link is simply not readable.
- Extraction and reads are now confined by `os.Root` instead of by inspecting
  path strings. A tar archive could write outside its extraction directory
  through a chain of relative symlinks — `a -> ..` then `b -> a/..`, where every
  step still reads as inside but each one climbs a directory — and a scanned
  directory could have a symlink read the host's files and report their contents
  as the image's. `os.Root` re-resolves every path component where the kernel
  does, so neither escape survives it. The lexical checks remain, to name the
  offending archive entry in the error instead of a temp path the user never
  chose.
- A vulnerability is no longer reported twice for the same component. OSV
  returns the DSA or DLA advisory alongside the `DEBIAN-CVE-…` record for one
  issue, and both resolve to the same CVE; the advisory carries no severity and
  no release-scoped fix, so the second row was the emptier one. On the fixture
  image this was 17 of 114 findings, and it inflated the `unknown` bucket from 7
  to 24.
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
