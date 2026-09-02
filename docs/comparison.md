# fwscan next to syft and grype

Measured, not asserted. Everything below was run on 2 September 2026 against the
two images committed in `testdata/images/`, with syft 1.51.1, grype 0.118.0 and
the fwscan tree released as v0.1.0. The commands are given so the numbers can
be re-derived rather than trusted; fwscan queries OSV live, so its counts move as
OSV's data moves.

The short version: **grype reports three times as many findings as fwscan on
the Debian 11 image, and on the findings they share the two agree.** The gap
has one cause, set out below, and it is not fwscan's to close.

## Cataloging

```sh
syft scan testdata/images/mini-rootfs.squashfs -o json
fwscan scan --no-network testdata/images/mini-rootfs.squashfs
```

| Image | syft | fwscan |
|---|---|---|
| `mini-rootfs.squashfs` | 6 packages | 7 (6 from dpkg, 1 from a filename heuristic) |
| `mini-rootfs.tar.gz` | 7 packages | 7 (6 from dpkg, 1 from a filename heuristic) |

syft reads both, including the squashfs image. Note the plain path: a
`syft scan file:…` invocation forces the wrong source type and returns nothing,
which is easy to mistake for a limitation.

The one package fwscan adds is BusyBox, identified from its filename and
reported at low confidence with the path as evidence. It is never queried
against OSV (`docs/output-spec.md` section 2), so it is a difference in the
inventory, not in the findings.

## Findings

```sh
grype testdata/images/mini-rootfs.tar.gz -o json
fwscan scan testdata/images/mini-rootfs.tar.gz --output report.json
```

| | grype | fwscan |
|---|---|---|
| Findings (one per package and CVE) | 113 | 38 |
| Carrying a severity | 108 of 113 | 38 of 38 |
| Carrying a fixed version | 63 of 113 | 38 of 38 |
| Findings the other does not have | 75 | 0 |

Both tools count one finding per package and CVE, so the rows are comparable.
Every one of fwscan's 38 is also one of grype's 113, so fwscan reports nothing
grype misses. On the 38 they share, the two agree on both the severity and the
fixed version in 32 cases; the other six differ only on the fixed version, for
one reason set out below, and agree on the severity.

## Why

The fixture is Debian 11, and for Debian 11 the OSV export contains **only DSA
and DLA advisory records**. Checked directly:

```sh
curl -X POST https://api.osv.dev/v1/query \
  -d '{"package":{"purl":"pkg:deb/debian/openssl?arch=source&distro=bullseye"},
       "version":"1.1.1k-1+deb11u1"}'
```

returns ten records, all `DSA-…` or `DLA-…`, and none with a `severity` array.
The per-CVE `DEBIAN-CVE-…` records that carry CVSS vectors exist — but list only
Debian 12, 13 and 14. `DEBIAN-CVE-2023-0286` is one of many: it has a vector, and
no Debian 11 entry at all.

Three things follow from that shape. fwscan reads all three correctly, and the
measurement above is what it reports once it does:

1. **The severity is one hop away.** An advisory names the CVEs it fixed in
   `upstream`, and each of their `DEBIAN-CVE-…` records has the vector. fwscan
   follows that hop, so every finding on this image is ranked.

2. **The fixed version is in the advisory itself.** `DSA-5514-1`'s affected
   entry for glibc carries `ecosystem: "Debian:11"` and
   `fixed: 2.31-13+deb11u7`. An advisory's purl has no `distro` qualifier, since
   one advisory covers several releases, so the release is matched on the
   ecosystem field against the image's own `VERSION_ID`.

3. **An advisory is several findings.** `DLA-3942-1` names six CVEs. Each is a
   vulnerability of its own, with its own assessment — `CVE-2024-5535` is a 9.1
   critical and `CVE-2024-9143` a 4.3 medium — and fwscan reports each one,
   with the advisory as an alias of every one of them.

What remains — 75 findings grype has and fwscan does not — is a property of the
data source. OSV's Debian export for an oldstable release lists the CVEs that
received an advisory; grype's database is the Debian Security Tracker, which
carries every CVE's per-release status. No change to fwscan closes that gap: it
needs a second source, which the roadmap carries and v0.1.0 does not.

### The six findings the two describe differently

All six are the CVEs of `DLA-3942-1` on `libssl1.1`. fwscan reports their fix
at `1.1.1n-0+deb11u6`, grype at `1.1.1w-0+deb11u2`. Both are real: Debian
shipped `DLA-3942-1` at the first and `DLA-3942-2` at the second, and both
advisories cover the same six CVEs. fwscan reports the lowest version that
resolves a finding, on the grounds that the column answers what version stops
being affected; grype reports the latest advisory. Neither is wrong, and
`docs/output-spec.md` section 1 states which one this tool means.

## Backport awareness

`docs/scope.md` and the README rest on Debian and Alpine patching security bugs
without moving the upstream version. That remains true and remains the reason
the release qualifier is carried into every query (`spike/NOTES.md` T0.3).

It is not, however, a difference from grype. Asked about the same image, grype
reports `CVE-2022-0778` against `libssl1.1 1.1.1k-1+deb11u1` with the fix at
`1.1.1k-1+deb11u2` — the Debian revision, correctly, not the upstream version.
Any claim that other scanners get backports wrong would be false, and this
document exists partly to keep that claim out of the README.

## What fwscan does that these do not

Stated narrowly, because the numbers above do not support a broad claim:

- One command from a firmware image to both an SBOM and a report, with no
  database to provision first.
- Confidence and evidence on every component, so a filename guess is visibly a
  filename guess rather than an inventory entry like any other.
- A CRA-oriented compliance report, which is the first roadmap item and the
  reason this tool exists separately at all.

## Reproducing

syft and grype were downloaded from their GitHub releases; grype builds its
database on first run. fwscan queries OSV live, so the counts move as OSV's data
moves — the point of the comparison is the shape of the difference and the
reasons for it, not the exact figures.
