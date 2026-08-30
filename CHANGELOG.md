# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 0 spike: public Debian rootfs fixtures, a dpkg status parsing proof of
  concept validated against `dpkg-query`, OSV backport-awareness validation, the
  squashfs compression matrix, and the consolidated decision log in
  `spike/NOTES.md`.
- Repository scaffolding: Go module, package layout, `Makefile`, `golangci-lint`
  configuration, CI workflow, and the `fwscan version` command.
- Domain model: `Component`, `Finding`, `Confidence` and `Severity`, with the
  finding and component sort orders from output-spec section 1.
- dpkg cataloger reading `var/lib/dpkg/status`, resolving source package name
  and version, detecting the release codename from `os-release`, and building
  purls with the release qualifier the spike proved necessary.
- Input layer: `Source` interface, content-based format detection, and the
  extracted-rootfs-directory handler.
- Tarball input with transparent gzip, xz, zstd and lz4 decompression,
  extraction to a temp directory, and path-traversal protection.
- OSV matcher: batched `querybatch` queries, concurrent detail fetches, CVSS
  v3 and v2 base-score computation, severity mapping and per-release fixed
  version selection.
- Terminal report and the `fwscan scan` command, wiring input, cataloging and
  matching into a working end-to-end scan.
- CycloneDX 1.6 SBOM output behind `--sbom`, validated against the official
  schema by `make validate-sbom` in CI.
- JSON report behind `--output`, written atomically, with the schema and sort
  orders from output-spec section 3.
- `--no-network` mode, proven by test to make no vulnerability lookup at all.
- SquashFS input via `unsquashfs`, with the internal compression read from the
  superblock and an actionable error when the tool is missing.
- apk cataloger for Alpine images, and matcher support for the ecosystem query
  shape Alpine requires.
- Heuristic detectors for the kernel, busybox and versioned shared libraries,
  all reported at low confidence with evidence.
- `--fail-on` and the exit codes from output-spec section 5.
- Hostile-input hardening: fuzz targets for the dpkg and apk parsers, bounded
  directory listings, and tests asserting no temp directory survives a failure.
- Error message pass: every user-facing failure is a single lowercase
  actionable line on stderr, with help text carrying examples and exit codes.

[Unreleased]: https://github.com/mhmtkas/fwscan/commits/main
