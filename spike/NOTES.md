# fwscan — Spike Notes (Phase 0)

**Go module path: `github.com/mhmtkas/fwscan`** — fixed by the T0.0 initial
commit; all Go code uses this path.

This file is the binding decision log for Phase 0. Later tasks are gated on the
conclusions recorded here (T3 and T6 on the purl format from T0.3, T11 on the
squashfs plan from T0.4). Every conclusion must be backed by recorded
request/response evidence, never by assumption. Sections stay marked UNRESOLVED
until their task lands.

## T0.0 — Repo provisioning — DONE

- Repo: `mhmtkas/fwscan`, private, default branch `main`.
- Topics: `sbom`, `firmware`, `security`, `cyclonedx`, `embedded-linux`,
  `vulnerability-scanning`.
- Initial commit: `CLAUDE.md`, `TASKS.md`, `docs/output-spec.md`,
  `docs/mvp-scope.md`, `docs/phase0-spike-and-repo-skeleton.md`, `LICENSE`
  (Apache-2.0), plus a `.gitignore` holding only `.DS_Store`.
- Toolchain on the dev machine: Go 1.27.0 (darwin/arm64), gh 2.98.0.
- Repo goes public only at T19, with explicit maintainer approval. Until then
  the whole history is treated as future-public: CLAUDE.md rule 10
  (no employer-derived data) applies from this first commit onward.

## T0.1 — Public fixture acquisition — DONE

Two rootfs samples, both from the official `library/debian` images on Docker Hub.
Full provenance — tags, manifest and layer digests, package counts, `status`
checksums — is in `spike/fixtures/PROVENANCE.md`.

- `spike/fixtures/debian-bookworm-slim/` — Debian 12.15, 88 packages. Supplies the
  T0.3 **backport true-negative** case; 33 of its packages carry a `+deb12uN`
  security-update suffix.
- `spike/fixtures/debian-bullseye-20220125-slim/` — Debian 11.2, 96 packages. Supplies
  the T0.3 **true-positive** case; oldest dated `bullseye-*-slim` tag still published,
  so the set of subsequently-fixed CVEs is as large as possible.

Each fixture keeps only `var/lib/dpkg/status`, `usr/lib/os-release` and
`etc/debian_version`, laid out at their real rootfs-relative paths so a cataloger
can be pointed straight at the directory. 176 KB total.

Fetched by `spike/fetch-rootfs.sh`, which reads the layer blob from the registry
API without a Docker daemon and refuses the blob unless its SHA-256 matches the
digest the registry advertised. Docker Desktop is not running on this machine and
is not needed.

**Finding that constrains T0.2 and T3:** every stanza in both files is
`Status: install ok installed`. Real fixtures therefore cannot exercise the
not-installed filter, and the test for that path must use a synthetic stanza.
Covered by real data instead: multi-line `Description`, epoch versions
(`zlib1g 1:1.2.11.dfsg-2`), binNMU suffixes (`bash 5.1-2+b3`), and
`Architecture: all` mixed with `amd64`.

**Deviation from the task text, for the record:** the task offered
`debootstrap --variant=minbase` as an alternative source. The registry route was
used instead because it pins provenance by digest and needs no privileged local
tooling; `debootstrap` is not installed and would not run natively on macOS.

## T0.2 — dpkg status parsing PoC — UNRESOLVED

Parsed counts vs the `dpkg-query --admindir` oracle go here.

## T0.3 — OSV backport-awareness validation — UNRESOLVED

**Gates T3 and T6.** Final purl construction rule (including whether a
`distro`/release qualifier is required), with request/response evidence for the
backport true-negative and the true-positive check, plus batch latency and
rate-limit observations.

## T0.4 — SquashFS compression matrix — UNRESOLVED

**Gates T11.** Extraction matrix for gzip/xz/lz4/zstd, tool versions, magic-byte
table, and the final Plan A (shell out to `unsquashfs`) vs Plan B (pure Go)
decision.

## T0.5 — Decision log — UNRESOLVED

Consolidated conclusions and anything that contradicts the MVP scope and so
needs maintainer review.
