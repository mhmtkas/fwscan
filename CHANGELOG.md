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

[Unreleased]: https://github.com/mhmtkas/fwscan/commits/main
