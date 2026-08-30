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

## T0.2 — dpkg status parsing PoC — DONE

PoC: `spike/dpkgpoc/main.go` (stdlib only, `go run` without a module). Parses
RFC-822 stanzas, keeps `Status: install ok installed` only, extracts
Package/Version/Architecture. Throwaway — T3 reimplements it; what carries
forward is the evidence below and the parsing rules it validates.

### Oracle comparison — both fixtures match byte-for-byte

Oracle exactly as T0.2 specifies:
`dpkg-query --admindir=<fixture>/var/lib/dpkg -W -f='${Package} ${Version}\n'`,
both sides `LC_ALL=C sort`ed. dpkg-query 1.23.7 (darwin-arm64).

| Fixture | Oracle lines | PoC lines | diff | SHA-256 of the agreed output |
|---|---|---|---|---|
| `debian-bookworm-slim` | 88 | 88 | identical | `92bc3e2ef67fc47b2be0323a97f87cdfaa9ccd6d87deb918d37578f86b64bf59` |
| `debian-bullseye-20220125-slim` | 96 | 96 | identical | `f9a6b61e647d03bb6fdb5523a316e1354e413b298f7535baaaaf606886f2df62` |

### Finding: the specified oracle does not test the status filter

`dpkg-query -W` lists **every** stanza in the database regardless of `Status`. It
agreed with the PoC on both fixtures only because those fixtures are 100%
`install ok installed` (the T0.1 finding). Taken alone, that comparison would
pass even for a parser with no status filter at all.

The filter is therefore validated separately, against a synthetic database at
`spike/fixtures/synthetic/status-edge-cases` and a status-aware oracle
(`-f='${db:Status-Abbrev} ...'`, keeping `ii`):

| Stanza | `Status` | Oracle | PoC | Agree |
|---|---|---|---|---|
| `installed-pkg` | `install ok installed` | kept | kept | yes |
| `removed-pkg` | `deinstall ok config-files` | dropped | dropped | yes |
| `halfinstalled-pkg` | `install ok half-installed` | dropped | dropped | yes |
| `epoch-pkg` | `install ok installed` | kept | kept | yes |

**Carry into T3:** assert on a synthetic not-installed stanza, and use the
status-aware oracle form if a fixture is ever regenerated. The plain
`-W -f='${Package} ${Version}'` oracle is necessary but not sufficient.

### Parsing rules the evidence establishes

- **Continuation lines** (leading space or tab) belong to the previous field. The
  synthetic `Description` embeds `Package:` and `Status:` decoy lines indented by
  one space; the PoC emitted 0 decoy packages, so continuations neither open a
  field nor break the stanza.
- **Stanza boundary** is a blank line, and the last stanza need not be followed by
  one — flush on EOF.
- **Epoch versions** pass through verbatim (`1:1.2.11.dfsg-2`); no normalisation.
- **`Architecture: all`** appears alongside `amd64` and needs no special case at
  parse time. Whether `all` belongs in the purl `?arch=` qualifier is a T0.3
  question, not a parsing one.
- **Malformed lines** (no colon) are skipped rather than treated as fatal — a
  hostile image must not be able to abort the scan.

## T0.3 — OSV backport-awareness validation — DONE — **BINDING ON T3 AND T6**

Kill-risk #1 is retired: OSV is backport-aware for Debian **only if the query
carries the release codename**. Getting that qualifier right is, as the plan
predicted, the single most important finding of the spike.

Evidence: `spike/osv-evidence/` (recorded requests and responses).
Scripts: `purls.py` (purl derivation), `backport-test.py`, `batch.py`.

### The purl rule — final

```
pkg:deb/debian/<SOURCE-package>@<SOURCE-version>?arch=source&distro=<codename>
```

Four independent things have to be right, and each was wrong in an obvious first
attempt:

1. **Source package name, not binary name.** OSV's Debian data is keyed on source
   packages. `pkg:deb/debian/libssl1.1@1.1.1k-1+deb11u1` returns **0** vulns;
   `pkg:deb/debian/openssl@...` returns 111. Querying binary names silently
   reports every package as clean — the worst possible failure mode.
2. **`distro=<codename>`, and the codename only.** `distro=bullseye` works.
   `distro=debian-11` and `distro=debian-11.2` both return **0**. Take the value
   from `VERSION_CODENAME` in the rootfs's `usr/lib/os-release` (both fixtures
   carry it; `/etc/os-release` is a symlink to it and may not survive extraction).
3. **Source version, not binary version.** They differ for binNMUs
   (`bash` binary `5.1-2+b3`, source `5.1-2`) and, more dangerously, when a binary
   carries an epoch its source does not: querying `util-linux` as
   `1:2.36.1-8+deb11u1` returns 7 vulns, the correct `2.36.1-8+deb11u1` returns 9.
   The epoch form silently loses two findings.
4. **Percent-encode the version.** `+` → `%2B` and `:` → `%3A`, per the purl spec
   and output-spec §3.

`arch=source` mirrors the purl OSV itself publishes in its records. It is not
required for matching (`arch=amd64`, `arch=all` and no arch all return the same
111), but it states the truth about what is being queried and costs nothing.

Deriving source name and version from a dpkg stanza:

| `Source:` field | Source name | Source version |
|---|---|---|
| absent | the `Package` value | the `Version` value |
| `util-linux` | `util-linux` | the `Version` value |
| `util-linux (2.36.1-8+deb11u1)` | `util-linux` | `2.36.1-8+deb11u1` |

The parenthesised form appears exactly when the two versions diverge, so honouring
it resolves both the binNMU and the epoch cases automatically.

### Backport true-negative — PASS

Ground truth from the Debian Security Tracker page for CVE-2022-0778: source
`openssl`, release `bullseye`, fixed at **`1.1.1k-1+deb11u2`** (DSA-5103-1). Note
the upstream version does not change — only the Debian revision — which is
precisely the case that makes naive scanners cry wolf.

| Installed version | Expected | `?distro=bullseye` | bare purl |
|---|---|---|---|
| `1.1.1k-1+deb11u1` (one revision before the fix) | flagged | flagged — PASS | flagged — PASS |
| `1.1.1k-1+deb11u2` (**the backported fix**) | clean | clean — PASS | **flagged — FALSE POSITIVE** |
| `1.1.1n-0+deb11u1` (later upstream) | clean | clean — PASS | **flagged — FALSE POSITIVE** |

Without the qualifier OSV matches across every Debian release at once, so a
version that is fixed in bullseye still falls inside some other release's
vulnerable range. Two false positives out of three. **The `distro` qualifier is
not optional; it is the feature.**

### True-positive — PASS

Ground truth from the tracker for CVE-2022-37434: source `zlib`, bullseye, fixed
at `1:1.2.11.dfsg-2+deb11u2`.

- `zlib@1:1.2.11.dfsg-2` (the version in the bullseye fixture) → flagged. Correct.
- `zlib@1:1.2.11.dfsg-2+deb11u1` → still flagged. Correct: the fix is `u2`.
- OSV's `affected[]` entry for `Debian:11` carries `fixed: 1:1.2.11.dfsg-2+deb11u2`,
  matching the tracker exactly.

Here the epoch is genuine — `zlib`'s source version really does start `1:` — which
is why the rule is "use the source version as recorded", not "strip epochs".

### Batch behaviour

`POST /v1/querybatch`, one call, no pagination observed at any size tried.

| Batch | Request body | Latency | Results | With vulns | Total vulns | `next_page_token` |
|---|---|---|---|---|---|---|
| 131 purls (both fixtures) | 11.4 KB | 0.81 s | 131 | 59 | 380 | none |
| 393 purls | 33.4 KB | 1.28 s | 393 | 181 | 1384 | none |

393-purl call repeated 5 times back to back: 1.14–1.35 s, median 1.31 s. No
rate-limit response, no `Retry-After`, no rate-limit headers returned at all.
Seven batch calls plus ~600 detail fetches in a few minutes drew no throttling.
No API key is needed.

The 393-purl batch was built by querying the two fixtures' source/version pairs
against additional Debian releases, since the fixtures alone yield 131 unique
purls. That is honest load for a scale measurement, not an accuracy measurement.

**Deduplication matters:** 88 and 96 binary packages collapse to 63 and 68 unique
source purls — about 28% fewer queries. The matcher should dedupe on
(source name, source version) and fan the results back out to every binary
package that shares a source.

### `querybatch` returns identifiers only — cost of details

`querybatch` gives `{id, modified}` per hit. Severity, `affected[].ranges` and the
fixed version all require `GET /v1/vulns/{id}`.

Both fixtures together: 131 purls → **292 unique vulnerability ids**.

| Strategy | Wall clock |
|---|---|
| serial detail fetch | 271 ms each → 79 s |
| 10 concurrent workers | **8.1 s** |

**Carry into T6:** batch the queries, dedupe the ids, then fetch details with a
bounded worker pool (10 is comfortable and drew no throttling). Serial fetching
makes a trivial scan take over a minute and must not ship.

### Three findings that conflict with `docs/output-spec.md` — MAINTAINER REVIEW NEEDED

Measured across all 292 records. Recorded here rather than resolved unilaterally;
T0.5 carries them forward, and T6 must not be written against the spec as it
currently stands without a decision.

**1. Vulnerability ids are `DEBIAN-CVE-…`, and `aliases` is always empty.**
Output-spec §3 shows `"id": "CVE-2022-3602"` with `"aliases": ["DSA-5343-1"]`.
Reality: the record id is `DEBIAN-CVE-2022-3602`, `aliases` is empty on
**0/292** records — every single one — and the plain CVE id lives in a field the
spec never mentions, `upstream: ["CVE-2022-37434"]` (present on 288/292).
*Proposed rule:* report `id` = the CVE from `upstream[]` when there is one, else
the OSV id; report `aliases` = the OSV id plus any remaining `upstream` entries.
That yields the id shape the spec's example shows and keeps the OSV id traceable.

**2. CVSS v4 has no rule, and v2 never occurs.** Severity types across 292 records:

| Type | Records |
|---|---|
| CVSS_V3 only | 224 |
| **CVSS_V4 only** | **11** |
| both V3 and V4 | 0 |
| no severity at all | 57 |
| CVSS_V2 anywhere | **0** |

The 11 v4-only records carry a `CVSS:4.0/...` vector and **no v3 fallback**, so
under output-spec §1 as written they fall through to `unknown`. They are all
2025–2026 CVEs, so the share grows over time, not shrinks. Meanwhile §1's step 2
(CVSS v2) is unreachable for Debian data, and step 3 (ecosystem severity) is too:
none of the 57 severity-less records carry a `database_specific.severity`, at
record level or affected level — the only `database_specific` key present is
`source`. Effectively only steps 1 and 4 of the four-step mapping ever fire.
*Proposed rule:* add CVSS v4 base-score computation between steps 1 and 2, mapped
to the same four buckets. *Alternative, if that is too much for v1:* treat v4 as
`unknown` and say so in the README.

**3. 57 of 292 findings (19.5%) will be `unknown`.** They are mostly old,
Debian-marked-minor issues (CVE-2005-2541, CVE-2007-5686, CVE-2010-4756,
CVE-2011-3389). Per output-spec §5, `unknown` never triggers exit 1, so a fifth
of the output is advisory noise that `--fail-on` ignores. Worth a line in the
README's limitations section; no code change proposed.

## T0.4 — SquashFS compression matrix — UNRESOLVED

**Gates T11.** Extraction matrix for gzip/xz/lz4/zstd, tool versions, magic-byte
table, and the final Plan A (shell out to `unsquashfs`) vs Plan B (pure Go)
decision.

## T0.5 — Decision log — UNRESOLVED

Consolidated conclusions and anything that contradicts the MVP scope and so
needs maintainer review.
