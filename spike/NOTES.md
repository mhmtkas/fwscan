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

## T0.1 — Public fixture acquisition — UNRESOLVED

Sources and provenance for both Debian rootfs samples go here.

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
