# Recorded OSV responses

Unit tests must not touch the network (CLAUDE.md rule 6). These files are real
responses from `api.osv.dev`, recorded 2026-08-30, replayed by an
`httptest.Server` in `internal/match`.

- **`querybatch-by-purl.json`** — the `vulns` array `POST /v1/querybatch`
  returned for each query purl, keyed by that purl.
- **`vulns.json`** — full `GET /v1/vulns/{id}` documents, keyed by id.

## What was trimmed, and why

The real `querybatch` answers are large: `openssl@1.1.1k-1+deb11u1` alone comes
back with 55 vulnerabilities. Each result was cut down to the ids whose full
record is also committed here, so the fixture stays small and every id the
matcher follows resolves. Nothing about the response *shape* was altered.

The four records kept were chosen to cover every branch of the severity mapping
in output-spec section 1:

| Record | Covers |
|---|---|
| `DEBIAN-CVE-2022-0778` | CVSS v3, and the backport true-negative — present at `1.1.1k-1+deb11u1`, absent at `+deb11u2` |
| `DEBIAN-CVE-2022-37434` | CVSS v3 plus per-release fixed versions across eight affected entries |
| `DEBIAN-CVE-2010-4756` | no severity at all, so the `unknown` bucket |
| `DEBIAN-CVE-2025-6141` | CVSS v4 only, with no v3 to fall back to |

## The one synthetic record

`SYNTHETIC-ECOSYSTEM-SEVERITY` is **not** a recorded response. Step 3 of the
severity mapping reads a textual level from `database_specific.severity`, and
Debian's OSV data carries that field on none of the 292 records the spike
examined (`spike/NOTES.md`, T0.3). Constructing one is the only way to cover
that branch. It is clearly named so it can never be mistaken for real data.
