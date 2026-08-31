# Recorded OSV responses

Unit tests must not touch the network (CLAUDE.md rule 6). These files are real
responses from `api.osv.dev`, recorded 2026-08-30, replayed by an
`httptest.Server` in `internal/match`.

- **`querybatch-by-purl.json`** — the `vulns` array `POST /v1/querybatch`
  returned for each query, keyed by the purl for Debian and by
  `ecosystem|name|version` for Alpine. Two keying schemes because OSV needs two
  query shapes: Alpine cannot be queried by purl at all (`spike/NOTES.md`,
  T0.3a).
- **`vulns.json`** — full `GET /v1/vulns/{id}` documents, keyed by id.

## What was trimmed, and why

The real `querybatch` answers are large: `openssl@1.1.1k-1+deb11u1` alone comes
back with 55 vulnerabilities. Each result was cut down to the ids whose full
record is also committed here, so the fixture stays small and every id the
matcher follows resolves. Nothing about the response *shape* was altered.

The records kept were chosen to cover every branch of the severity mapping in
output-spec section 1, plus the duplicate-collapsing rule:

| Record | Covers |
|---|---|
| `DEBIAN-CVE-2022-0778` | CVSS v3, and the backport true-negative — present at `1.1.1k-1+deb11u1`, absent at `+deb11u2` |
| `DEBIAN-CVE-2022-37434` | CVSS v3 plus per-release fixed versions across eight affected entries |
| `DEBIAN-CVE-2010-4756` | no severity at all, so the `unknown` bucket |
| `DEBIAN-CVE-2025-6141` | CVSS v4 only, with no v3 to fall back to |
| `ALPINE-CVE-2022-37434` | fourteen affected releases whose purls are all identical, so only the ecosystem field distinguishes them |
| `ALPINE-CVE-2022-2097` | Alpine backport true-negative — present at `1.1.1o-r0`, absent at `1.1.1q-r0` |
| `DSA-5218-1` | the same issue as `DEBIAN-CVE-2022-37434`, arriving as a second record |

`DSA-5218-1` is why zlib's query returns three ids. OSV returns the advisory
alongside the CVE record: it lists `CVE-2022-37434` in `upstream`, so the
identifier rule resolves both to the same id, but it carries no severity and its
affected purl is `pkg:deb/debian/zlib?arch=source` with no `distro` qualifier,
so no release matches and it yields no fixed version either. Reported as it
arrives, that is a second, emptier row for a CVE already in the table.

`ALPINE-CVE-2022-37434` earns its place. Every one of its affected entries
carries the same purl, `pkg:apk/alpine/zlib?arch=source`, and they differ only
in `ecosystem`. Matching them by purl picks v3.11's fix, `1.2.11-r4`, which is
*older* than the installed `1.2.12-r1` — a fix that reads as a downgrade. That
regression is what the Alpine test guards.

## The one synthetic record

`SYNTHETIC-ECOSYSTEM-SEVERITY` is **not** a recorded response. Step 3 of the
severity mapping reads a textual level from `database_specific.severity`, and
Debian's OSV data carries that field on none of the 292 records the spike
examined (`spike/NOTES.md`, T0.3). Constructing one is the only way to cover
that branch. It is clearly named so it can never be mistaken for real data.
