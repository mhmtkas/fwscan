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
| Carrying a severity | 108 of 113 | 16 of 16 |
| Carrying a fixed version | 63 of 113 | 16 of 16 |
| Findings the other does not have | 97 | 0 |

Every one of fwscan's 16 findings is also one of grype's 113, so fwscan reports
nothing grype misses. On the 16 they share, the two agree on both the severity
and the fixed version in 15 cases; the sixteenth is a definitional difference set
out below, not an error.

The first measurement of this table read `0 of 16` in both middle rows — every
finding unranked and unfixed. That was the state this document was written to
record, and it is what prompted the two changes described under **Why**.

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

Three consequences, of different kinds. Two were fwscan's to fix and have been:

1. **Severity was missing but recoverable — fixed.** Each advisory names its CVE
   in `upstream`, and that `DEBIAN-CVE-…` record has the vector. fwscan already
   read `upstream` to choose the identifier and now follows it for the
   assessment too. All sixteen findings are ranked where none were, so
   `--fail-on` works on this image.

2. **The fixed version was missing but recoverable — fixed.** `DSA-5514-1`'s
   affected entry for glibc carries `ecosystem: "Debian:11"` and
   `fixed: 2.31-13+deb11u7`. fwscan matched releases only on the purl's `distro`
   qualifier, which an advisory does not carry; it now falls back to the
   ecosystem, compared against the image's own `VERSION_ID`. All sixteen
   findings name a fix where none did, and fifteen match grype exactly.

3. **The count is a property of the data source, and stands.** OSV's Debian
   export for an oldstable release lists what received an advisory; grype's
   database is the Debian Security Tracker, which carries every CVE's
   per-release status. No change to fwscan closes that gap — it needs a second
   source, which the roadmap carries and v0.1.0 does not.

### The one finding the two describe differently

`CVE-2023-5678` on `libssl1.1`: fwscan reports the fix at `1.1.1n-0+deb11u6`,
grype at `1.1.1w-0+deb11u2`. Both are real. Debian shipped `DLA-3942-1` at the
first and `DLA-3942-2` at the second, and both advisories cover the CVE. fwscan
reports the lowest version that resolves the finding, on the grounds that the
column answers what version stops being affected; grype reports the latest
advisory. Neither is wrong, and `docs/output-spec.md` section 1 states which one
this tool means.

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
