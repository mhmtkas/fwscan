# Fixture provenance

Both fixtures come from the **official `library/debian` images on Docker Hub** —
public, redistributable, and reproducible by digest. No private, work-derived, or
otherwise non-public data is present here (CLAUDE.md rule 10).

Fetched 2026-08-30 with `spike/fetch-rootfs.sh <tag> <outdir>`, which pulls the
layer blob straight from the registry API (no Docker daemon) and aborts unless
the blob's SHA-256 matches the digest the registry advertised. Both images are
single-layer, so the layer below *is* the whole rootfs.

Only three files per image are kept: the dpkg database plus two distro-identity
files. Everything else was discarded to keep the repository small.

## debian-bookworm-slim

Role: **backport true-negative** source for T0.3 — a current point release whose
packages carry `+deb12uN` security-update suffixes.

| | |
|---|---|
| Image | `debian:bookworm-slim` |
| Platform | `linux/amd64` |
| Manifest digest | `sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867` |
| Layer digest | `sha256:a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71` |
| Distro | Debian GNU/Linux 12 (bookworm), `debian_version` 12.15 |
| Packages | 88, all `Status: install ok installed` |
| `status` SHA-256 | `f837965a67204a8e632f02d3de84aea3155fcd2cfa6d75627e7aa039ad8b222c` |

33 packages carry a `+deb12uN` suffix, so there is no shortage of backport
candidates for the T0.3 true-negative check — for example `libgnutls30
3.7.9-2+deb12u7`, `libc6 2.36-9+deb12u14`, `perl-base 5.36.0-7+deb12u3`.

Note the tag is mutable: `bookworm-slim` will point at a newer build over time.
The manifest digest above pins exactly what was fetched, and the `status`
checksum detects any drift in the committed copy.

## debian-bullseye-20220125-slim

Role: **true-positive** source for T0.3 — a deliberately old, known-vulnerable
package set.

| | |
|---|---|
| Image | `debian:bullseye-20220125-slim` |
| Platform | `linux/amd64` |
| Manifest digest | `sha256:125f346eac7055d8e1de1b036b1bd39781be5bad3d36417c109729d71af0cd73` |
| Layer digest | `sha256:5eb5b503b37671af16371272f9c5313a3e82f1d0756e14506704489ad9900803` |
| Distro | Debian GNU/Linux 11 (bullseye), `debian_version` 11.2 |
| Packages | 96, all `Status: install ok installed` |
| `status` SHA-256 | `f68b23965b5f0069466c440a1d451ab70fd7776711549337211755c2fc4ffbd9` |

Chosen as the oldest dated `bullseye-*-slim` tag Docker Hub still publishes, which
maximises the number of subsequently-fixed CVEs. This tag is immutable.

Candidate true-positives (ground truth to be confirmed against the Debian
Security Tracker in T0.3, not assumed here):

| Package | Version | Why interesting |
|---|---|---|
| `libssl1.1` | `1.1.1k-1+deb11u1` | predates the 1.1.1n security update |
| `zlib1g` | `1:1.2.11.dfsg-2` | predates the `+deb11u1` fix; also the epoch case |
| `libgcrypt20` | `1.8.7-6` | native-looking version, no security suffix |
| `libc6` | `2.31-13+deb11u2` | several later `+deb11uN` updates exist |

## Parsing edge cases these fixtures do and do not cover

Covered by real data: multi-line `Description` fields; epoch versions
(`zlib1g 1:1.2.11.dfsg-2`, `bsdutils 1:2.38.1-5+deb12u3`); binNMU suffixes
(`bash 5.1-2+b3`, `libcap2 1:2.66-4+deb12u3+b1`); `Architecture: all` alongside
`amd64`.

**Not covered:** every stanza in both files is `Status: install ok installed`, so
neither fixture exercises the not-installed filter. T0.2 and T3 must cover that
path with a synthetic stanza (`fstest.MapFS`), not with these files.
