# fwscan next to syft and grype

Measured, not asserted. Everything below was run on 2 September 2026 against the
two images committed in `testdata/images/`, with syft 1.51.1, grype 0.118.0 and
fwscan at commit `a8eb612`. The commands are given so the numbers can be
re-derived rather than trusted.

The short version: **on the images tested today, grype reports considerably more
than fwscan does, and ranks what it reports.** The reasons are specific and are
set out below, because two of them are fwscan's to fix and one is not.

## Cataloging

```sh
syft scan testdata/images/mini-rootfs.squashfs -o json
fwscan scan --no-network testdata/images/mini-rootfs.squashfs
```

| Image | syft | fwscan |
|---|---|---|
| `mini-rootfs.squashfs` | 6 packages | 7 (6 from dpkg, 1 from a filename heuristic) |
| `mini-rootfs.tar.gz` | 7 packages | 7 (6 from dpkg, 1 from a filename heuristic) |

syft reads both, including the squashfs image. An earlier draft of this document
claimed otherwise, on the strength of a `syft scan file:…` invocation that forces
the wrong source type and returns nothing; with a plain path it reads the image.

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
| Findings | 113 | 16 |
| Carrying a severity | 108 of 113 | 0 of 16 |
| Carrying a fixed version | 63 of 113 | 0 of 16 |
| Findings the other does not have | 97 | 0 |

Every one of fwscan's 16 findings is also one of grype's 113. fwscan reports no
finding grype misses, ranks none of them, and names a fix for none of them —
which means `--fail-on` cannot fire on this image at all.

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

Three consequences, of different kinds:

1. **Severity is missing but recoverable.** Each advisory names its CVE in
   `upstream`, and that `DEBIAN-CVE-…` record has the vector. fwscan already
   reads `upstream` to choose the identifier; it does not follow it for the
   assessment. This is fwscan's to fix.

2. **The fixed version is missing but recoverable.** `DSA-5514-1`'s affected
   entry for glibc carries `ecosystem: "Debian:11"` and `fixed: 2.31-13+deb11u7`
   — the same version grype reports. fwscan cannot see it because it matches the
   release on the purl's `distro` qualifier, and an advisory's purl carries none.
   Also fwscan's to fix.

3. **The count is a property of the data source.** OSV's Debian export for an
   oldstable release lists what received an advisory; grype's database is the
   Debian Security Tracker, which carries every CVE's per-release status. No
   change to fwscan closes that gap — it needs a second source, which is a
   roadmap item and not a v0.1.0 one.

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
