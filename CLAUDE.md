# CLAUDE.md — fwscan agent instructions

fwscan is an open source Go CLI that scans Linux-based firmware rootfs images, emits a CycloneDX 1.6 SBOM, and reports known vulnerabilities via OSV.dev.

Authoritative documents, in order of precedence:
1. `docs/output-spec.md` — exact output formats, severity mapping, exit codes
2. `docs/scope.md` — functional scope, goals and non-goals
3. `docs/architecture.md` — the pipeline, the interfaces between its stages, and how to add a cataloger
4. `.private/TASKS.md` — the work queue

The last one is not in the repository. It and `.private/phase0-spike-and-repo-skeleton.md` are working documents addressed to whoever is building this rather than to whoever is reading it, so `.private/` is ignored by git and the two copies do not travel between machines on their own.

If these documents conflict with your own judgment about what would be "better", the documents win. Propose changes as a note in the PR description; do not implement them unilaterally.

## Hard rules

1. **Non-goals are binding.** The scope document's non-goals table (binary fingerprinting, SPDX, opkg/rpm, kernel CVE analysis, dashboards, VEX, offline mode, FP suppression config) is a hard boundary. Do not add any of these, even partially, even behind a flag.
2. **One task per branch/PR.** Work on exactly one `.private/TASKS.md` task at a time. Branch name `task/T<nn>-short-slug`. Do not batch tasks.
3. **Spike-gated decisions are frozen until unfrozen.** The OSV purl format (including any `distro`/release qualifier) and the squashfs strategy (shell-out vs pure Go) are decided by `spike/NOTES.md`, which **you produce yourself** by completing tasks T0.1–T0.5 in `.private/TASKS.md` before starting any gated task. NOTES.md conclusions must be backed by recorded request/response evidence — never by assumption. If a T0 check fails or contradicts the scope, write up the finding and stop for maintainer review; do not guess and continue.
4. **Never invent output formats.** Terminal layout, JSON schema, SBOM fields, severity mapping, and exit codes come only from `docs/output-spec.md`. If the spec is silent on something, ask; do not improvise.
5. **Definition of done** for every task: acceptance criteria in `.private/TASKS.md` met, `make lint` and `make test` green locally, new code covered by tests (table-driven where applicable), no decrease in overall coverage, CHANGELOG.md updated under `[Unreleased]`. Do not report a task as complete without having actually run the commands.
6. **Test against fixtures, not the network.** Unit tests must not call OSV.dev; use recorded responses in `testdata/osv/`. Only the explicitly marked integration test (build tag `integration`) may hit the real API.
7. **Dependencies:** cyclonedx-go, packageurl-go, go-deb-version, cobra, pierrec/lz4, klauspost/compress, ulikunitz/xz, plus stdlib. The list is closed; adding to it requires asking first.
8. **External tools:** the only permitted runtime shell-out is `unsquashfs` (if spike selected Plan A). Detect its absence and fail with a clear, actionable error message. Nothing else gets exec'd.
9. **Security posture:** this tool parses untrusted firmware images. Treat all parsed input as hostile — bound allocations, guard against path traversal on extraction (zip-slip equivalents for tar/squashfs), never write outside the designated temp dir, always clean up temp dirs via the returned cleanup func.
10. **No employer-derived data.** Test fixtures and examples must come from public images (official Debian/Raspberry Pi OS/OpenWrt releases) or synthetically built rootfs dirs. Never embed data from private/work systems.

## Conventions

- Go: latest stable in `go.mod`; `gofmt` + `golangci-lint` clean; wrap errors with `%w` and context (`fmt.Errorf("dpkg: parse %s: %w", path, err)`); accept `context.Context` on anything that does I/O.
- Interfaces at package boundaries: input produces `fs.FS`; catalogers consume `fs.FS`; matchers consume `[]model.Component`. `docs/architecture.md` describes them.
- Confidence levels: `high` only for package-manager DB results; every heuristic result is `low` and must carry `Evidence`.
- Commits: Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). Reference the task ID in the body.
- Errors to users (CLI) are lowercase, actionable, and never show a raw Go stack trace.
- Comments explain *why*, not *what*. No commented-out code in main.

## When to stop and ask

- `spike/NOTES.md` missing or ambiguous on purl format / squashfs plan
- Output spec silent on a formatting or schema question
- A task's acceptance criteria seem to require violating a non-goal
- A new dependency seems necessary
- OSV responses in practice don't match the recorded fixtures' shape
