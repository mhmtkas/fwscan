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

### Three findings that conflict with `docs/output-spec.md` — ALL THREE DECIDED

Measured across all 292 records. Recorded here rather than resolved
unilaterally. All three were decided by the maintainer on 31 Aug 2026 and the
spec now carries the rules.

**1. Vulnerability ids are `DEBIAN-CVE-…`, and `aliases` is always empty.**
Output-spec §3 shows `"id": "CVE-2022-3602"` with `"aliases": ["DSA-5343-1"]`.
Reality: the record id is `DEBIAN-CVE-2022-3602`, `aliases` is empty on
**0/292** records — every single one — and the plain CVE id lives in a field the
spec never mentions, `upstream: ["CVE-2022-37434"]` (present on 288/292).
*Decided 31 Aug 2026, now normative in output-spec §3:* report `id` = the CVE
from `upstream[]` when there is one, else the OSV id; report `aliases` = the OSV
id plus any remaining `upstream` entries. That yields the id shape the spec's
example shows and keeps the OSV id traceable. The matcher already did this; the
decision moves the rule out of a code comment and into the spec.

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
*Decided 31 Aug 2026, now normative in output-spec §1 as step 2:* compute the
v4 base score and map it to the same four bands as v3. The alternative on the
table — leave v4 as `unknown` and document it — was rejected: the affected CVEs
are all recent, so the gap grows with every release, and an advisory that never
reaches `--fail-on` is a gate that quietly stops working. Implemented in T21.

**3. 57 of 292 findings (19.5%) will be `unknown`.** They are mostly old,
Debian-marked-minor issues (CVE-2005-2541, CVE-2007-5686, CVE-2010-4756,
CVE-2011-3389). Per output-spec §5, `unknown` never triggers exit 1, so a fifth
of the output is advisory noise that `--fail-on` ignores.
*Decided 31 Aug 2026:* documented in the README's limitations section, no code
change. The share was briefly stated as 68 of 292 (23.3%), pooling these with
finding 2's v4-only records; once T21 made those scoreable it went back to the
57 records that genuinely carry no severity at all, 19.5%.

## T0.3a — Alpine query format — addendum, recorded during T12

The original spike covered Debian only. T12 added an apk cataloger, and Alpine
turned out **not** to follow the Debian rule, so it was validated the same way
rather than assumed.

### Purl queries do not work for Alpine at all

| Query | Vulns |
|---|---|
| `pkg:apk/alpine/openssl@1.1.1n-r0` | 0 |
| `…?arch=x86_64` | 0 |
| `…?distro=alpine-3.16` | 0 |
| `…?distro=v3.16` | 0 |
| `…?distro=3.16` | 0 |
| `pkg:apk/openssl@1.1.1n-r0?distro=v3.16` | 0 |
| **ecosystem `Alpine:v3.16`, name `openssl`, version `1.1.1o-r0`** | **10** |

The reason is visible in OSV's own records. An Alpine advisory's affected
entries carry `purl: pkg:apk/alpine/openssl?arch=source` — **no distro
qualifier at all** — and the release lives only in the `ecosystem` field
(`Alpine:v3.13`, `Alpine:v3.14`, `Alpine:v3.16`, …). A purl cannot express which
release it means, so a purl query cannot be release-scoped, and OSV returns
nothing rather than guessing.

**Consequence for the matcher:** Debian is queried by purl, Alpine by
`{package: {name, ecosystem}, version}`. Two query shapes, one matcher.

### The ecosystem string is exact

| Ecosystem | Vulns |
|---|---|
| `Alpine:v3.16` | 10 |
| `Alpine:v3.16.0` | 0 |
| `Alpine:3.16` | 0 |
| `Alpine` | 0 |

So: `Alpine:v` + major.minor, truncated from `VERSION_ID` (`3.16.0` → `v3.16`).
The patch component must be dropped and the `v` is mandatory. Both failure modes
are silent, exactly like the Debian ones.

### Source package names again

`libssl1.1` at `1.1.1o-r0` returns 0; its origin `openssl` returns 10. The apk
database records the origin in the `o:` field, which is the direct analogue of
dpkg's `Source:`.

### Backport true-negative holds

`openssl` on `Alpine:v3.16`: `1.1.1o-r0` returns 10 vulnerabilities including
ALPINE-CVE-2022-2097, and `1.1.1q-r0` — the version that fixes it — returns 9,
with that CVE gone. Release-scoped matching works for Alpine too, through the
ecosystem field rather than a qualifier.

### Record shape

Identical to Debian's: ids are `ALPINE-CVE-2022-2097`, `aliases` is empty, and
the plain CVE is in `upstream`. The identifier reconciliation written for Debian
applies unchanged.

**Question 4, decided 31 Aug 2026 — see T20 below.** apk versions are not
Debian versions. `1.1.1o-r0` and `1.0_alpha1` follow apk's own ordering rules,
which `go-deb-version` does not implement. It happens to order the common
`x.y.z-rN` shape correctly, and that is what the fixed-version selection relied
on, but a version carrying a pre-release suffix was compared wrongly. Resolved
by porting apk's own algorithm rather than by taking a dependency.

## T0.4 — SquashFS compression matrix — DONE — **BINDING ON T4, T5 AND T11**

Kill-risk #2 is retired. **Plan A: shell out to `unsquashfs`.** All four
compressors build and extract cleanly, so no pure-Go squashfs reader is needed
and Plan B is not exercised.

### Extraction matrix

Host: macOS 15 (darwin/arm64), squashfs-tools **4.7.5 (2026/03/01)** from
Homebrew — the same binary provides `mksquashfs` and `unsquashfs`. Source
tree: the bullseye fixture plus a fake `bin/busybox`, a `bin/sh` symlink and an
empty `lib/modules/5.10.0-11-arm64/` directory, 16 entries, 96 KB.

| `-comp` | Build | Image size | Extract | Content vs source | `unsquashfs -s` reports |
|---|---|---|---|---|---|
| `gzip` | OK | 24576 B | OK | identical | `Compression gzip` |
| `xz` | OK | 24576 B | OK | identical | `Compression xz` |
| `lz4` | OK | 40960 B | OK | identical | `Compression lz4` |
| `zstd` | OK | 24576 B | OK | identical | `Compression zstd` |

"Identical" means the SHA-256 over the sorted per-file SHA-256 list matched the
source tree exactly (`f8eef1c87021f0bb387bf9c5ce475b3e1a2c17214956d87f6175946c82bd6e71`)
for all four. Symlinks and the empty directory survived the round trip.

lz4 is 67% larger than the others at this size, as expected — it trades ratio for
decompression speed, which is exactly why embedded vendors pick it.

### Version requirement

lz4 and zstd support both landed in squashfs-tools **4.4**; 4.7.5 was used here
and Debian bookworm ships 4.5.x. T11's CI step must install `squashfs-tools` and
should assert the version is ≥ 4.4, because a too-old `unsquashfs` fails only at
extraction time, on the compressor the user happens to have, with a message
fwscan does not control.

### Magic bytes — observed, not quoted

Every value below was read off a file produced during this task, not copied from
documentation. These feed `input/detect.go` (T4) and `input/decompress.go` (T5).

| Format | Offset | Bytes | ASCII |
|---|---|---|---|
| SquashFS, little endian | 0 | `68 73 71 73` | `hsqs` |
| gzip | 0 | `1F 8B` | |
| xz | 0 | `FD 37 7A 58 5A 00` | |
| zstd | 0 | `28 B5 2F FD` | |
| lz4 frame | 0 | `04 22 4D 18` | |
| tar (POSIX/ustar) | **257** | `75 73 74 61 72` | `ustar` |

Two traps worth stating plainly:

- **tar has no magic at offset 0.** The `ustar` string sits at offset 257, inside
  the first header block. A detector that only ever looks at offset 0 will
  classify an uncompressed tarball as unknown. The observed first bytes of the
  test tar were `2e 5f 72 6f 6f 74` — just the first filename.
- **Big-endian squashfs is `sqsh`, not `hsqs`.** Only the little-endian form was
  produced here. Big-endian images are effectively extinct on the targets fwscan
  cares about; if one ever appears, `unsquashfs` handles it and fwscan's detector
  simply would not recognise it. Not treated as v1 scope.

### Plan A consequences carried into T11 and T15

- `unsquashfs` is the only permitted runtime shell-out (CLAUDE.md rule 8). Its
  absence must be detected up front and reported with an install hint, never as a
  raw `exec: "unsquashfs": executable file not found in $PATH`.
- Extraction goes to the caller-owned temp dir and the returned cleanup function
  removes it, on every error path.
- `unsquashfs` is being handed a hostile image. Path traversal inside the archive
  is its problem, not one fwscan can fix from outside, but fwscan must still
  verify after extraction that nothing landed outside the temp dir — the same
  check T5 applies to tar. T15 re-verifies this.

## T0.5 — Decision log — DONE — Phase 0 closed

### Verdict: continue. Both kill-risks retired, no change to the MVP scope.

| Spike exit criterion | Result |
|---|---|
| dpkg parser matches ground truth | PASS — byte-for-byte on both fixtures (T0.2) |
| OSV backport true-negative **and** true-positive | PASS — with the release qualifier (T0.3) |
| All four squashfs compressions extract | PASS — Plan A, no pure-Go reader needed (T0.4) |
| Version comparison matches `dpkg --compare-versions` | PASS — 18/18 (below) |
| NOTES.md written | this file |

### Frozen decisions the gated tasks read

**Purl construction (gates T3, T6)**

```
pkg:deb/debian/<SOURCE-name>@<percent-encoded SOURCE-version>?arch=source&distro=<codename>
```

Source name and version come from the `Source:` field, falling back to
`Package`/`Version`; codename comes from `VERSION_CODENAME` in
`usr/lib/os-release`. Full derivation table and the evidence for each of the four
constraints are in T0.3. The `distro` qualifier is mandatory: without it two of
three backport cases are false positives.

**SquashFS (gates T11)** — Plan A, shell out to `unsquashfs`, require ≥ 4.4.

**Matcher shape (feeds T6)** — dedupe on (source name, source version) before
querying, roughly 28% fewer queries; one `querybatch` call handles 393 purls in
1.3 s with no pagination; fetch vulnerability details with a bounded pool of ten
workers, never serially.

### Version comparison — `go-deb-version` vs `dpkg --compare-versions`

Harness in `spike/vercmp/`. dpkg 1.23.7 as oracle,
`knqyf263/go-deb-version v0.0.0-20241115132648-6f4aee6ccd23`. **18/18 agree**,
covering every case the plan asked for plus the ones the earlier tasks turned up:

| Case | Pair | Both say |
|---|---|---|
| backport revisions | `1.1.1k-1+deb11u1` vs `…u2` | lt |
| backport vs later upstream | `1.1.1k-1+deb11u2` vs `1.1.1n-0+deb11u1` | lt |
| **numeric, not lexical, suffix** | `3.7.9-2+deb12u7` vs `…u10` | lt |
| epoch beats no epoch | `1:1.2.11.dfsg-2` vs `1.2.11.dfsg-2` | gt |
| epoch ordering | `1:1.2.11.dfsg-2` vs `2:1.0-1` | lt |
| tilde sorts before release | `1.0~rc1` vs `1.0` | lt |
| native vs revisioned | `1.0` vs `1.0-1` | lt |
| binNMU | `5.1-2` vs `5.1-2+b3` | lt |
| `+really` | `1.0+really1.3.1-1` vs `1.0-1` | gt |

Two of these matter beyond box-ticking. `+deb12u7 < +deb12u10` proves the suffix
is compared numerically — a string compare would call u7 the newer one and
suppress a real finding. And `1:X > X` is the mechanism behind the T0.3 epoch
trap: sending a binary version that carries an epoch its source lacks sorts the
query above every fixed-version range, silently hiding vulnerabilities.

`dpkg --compare-versions` is the oracle, not the library. This table is carried
into T6 as a table-driven unit test.

### Maintainer decisions — all five resolved 31 Aug 2026

Five questions, all conflicts between measured OSV behaviour and
`docs/output-spec.md`. All five were decided on 31 Aug 2026; the spec, the
README, the code and this file agree, and none of them is waiting on anyone.

1. **Ids arrive as `DEBIAN-CVE-…` and `aliases` is empty on 0/292 records.** The
   plain CVE sits in `upstream[]`, a field the spec never mentioned.
   *Decided:* `id` = the CVE from `upstream[]`, `aliases` = the OSV id plus the
   rest. Ratifies what the matcher already did, and output-spec §3 now carries
   the rule under "Identifier derivation" so it is no longer only a code comment.
   Four of the 292 records have no `upstream` CVE and keep their OSV id —
   deterministic, and the alias list stays traceable either way.
2. **CVSS v4 had no rule.** 11 of 292 records were v4-only with no v3 fallback
   and fell through to `unknown`; all are 2025–2026 CVEs, so the share grows
   rather than shrinks. Meanwhile spec §1's v2 step and ecosystem-severity step
   are both unreachable for Debian data — 0 records carry v2, 0 carry
   `database_specific.severity`. *Decided:* implement v4 scoring in full rather
   than document the gap. A gate that silently stops covering new advisories is
   worse than one that is loud about what it cannot see.

   Resolved by T21. v4 has no formula: a vector reduces to a six-digit
   MacroVector, whose score is hand-assigned in a 270-entry table, and the
   vector's own score is that number minus an interpolated distance from the
   most severe vector its MacroVector can hold. The table is data and cannot be
   derived, so it is transcribed from FIRST's reference calculator
   (github.com/FIRSTdotorg/cvss-v4-calculator at commit
   c5b0d409ae9f57c44264c6ce5f27d89298e1d32a, BSD-2-Clause) and the algorithm
   ported from the same commit. No dependency, so CLAUDE.md rule 7 is untouched.

   That reference implementation is the oracle, run as JavaScript under Node.
   Verification is exhaustive rather than sampled — all 104,976 base vectors
   (4·2·2·3·3·3·3·3·3·3·3), 0 mismatches — because a transcription slip would
   sit in exactly one of 270 cells and a sample would probably walk past it.
   `make test-cvss4-oracle` reruns it.

   Only base metrics are scored. A Debian record writes out every metric,
   defined or not (`…/E:X/CR:X/…/U:X`); those are validated but scored at their
   not-defined defaults, exactly as the v3 path ignores temporal and
   environmental metrics.
3. **19.5% of findings will be `unknown`** and therefore invisible to
   `--fail-on`. Mostly old Debian-marked-minor issues. *Decided:* no code change,
   the README states the share. It briefly stated a pooled 23.3%, counting
   question 2's v4-only records alongside these; T21 made those scoreable, so
   the number is back to the 57 records that carry no severity at all, 19.5%.
   A `--fail-on unknown` level was considered and rejected — the bucket is
   mostly issues Debian itself marked minor, so the gate would fire on
   everything and get switched off.
4. **apk versions are not Debian versions** — see T0.3a above. *Decided:*
   port apk's own comparison. Measured first: `go-deb-version` does not reject
   an apk version, it silently orders it by Debian's rules, and the two disagree
   on exactly the four pre-release suffixes — it reports `1.0_alpha1`,
   `1.0_pre1` and `1.0_rc1` as *greater* than `1.0`, where apk orders all three
   below it. (`1.0_p1` and `1.0_git20230101` it happens to get right.)

   The consequence is narrower than it first looks, and worth stating precisely:
   OSV decides on the server which versions an advisory affects, so a wrong
   local ordering cannot suppress a finding. What it corrupts is
   `fixedVersion()`, which uses the ordering to pick the fix window containing
   the installed version (output-spec §1). A record carrying more than one
   window for a release then answers with a later release's fix than the one
   that actually fixes the issue. An earlier draft of this file claimed the
   finding was suppressed outright; that was wrong.

   Resolved by T20: `internal/match/apkversion.go` is a literal port of
   apk-tools 2.14.4 `src/version.c`, so no new dependency and CLAUDE.md rule 7
   is untouched. `apk version -t` is the oracle, run against a 62-string corpus
   — 3844 ordered pairs plus a validity pass — with 0 mismatches;
   `make test-apk-oracle` reruns it, and the curated subset is a unit test.
   Comparison is now dispatched on the same `packageKind` that chose the query
   shape, so the ecosystem decides both how to ask OSV and how to read the
   answer.
5. **Heuristic components are not matched.** T13's detectors carry no purl, so
   the matcher skips them and they appear in the report and the SBOM but never
   produce a finding. output-spec section 2's example table used to show a
   low-confidence finding (`busybox … CVE-2022-48174 … low`), which read as the
   spec expecting them to be matched. *Decided:* the behaviour is right and the
   example was wrong. A version inferred from a filename, with no release to
   scope it to, is exactly the input that made the bare purl produce two false
   positives out of three in T0.3; `libssl.so.3` names an ABI, not a release,
   and querying "openssl 3" against every distribution at once manufactures
   findings rather than finding them. The example row is gone and §2 now states
   the rule. The reporter still renders a low-confidence finding correctly and
   `testdata/golden/terminal-findings.txt` still covers that rendering, so
   enabling the lookup later stays a matcher change and not a format change.

   Revisit in v1.x along one line only: a real upstream version scraped from an
   embedded banner (`BusyBox v1.30.1`) could be queried against an upstream
   ecosystem with no distro scope, whereas a bare soname carries no version and
   must never be queried. That distinction did not exist when the detectors were
   written and would have to be added to them first.

### Surprises worth remembering

- Querying **binary** package names returns zero vulnerabilities rather than an
  error. A scanner built on that mistake reports every image as clean and looks
  like it is working.
- `distro=debian-11` also returns zero. Both failure modes are silent; only
  ground truth catches them, which is the entire justification for this spike.
- The fixtures are 100% `install ok installed`, so the status filter needs
  synthetic coverage (T0.1, T0.2).
- tar has no magic number at offset 0 (T0.4).
