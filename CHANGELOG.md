# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-03

First release. Reads the dpkg or apk database in a Linux root filesystem, emits
a CycloneDX SBOM, and reports known vulnerabilities from OSV.dev.

### Added

**Scanning**

- Debian, Ubuntu and Alpine packages, each queried against its own OSV dataset.
  Debian and Ubuntu are keyed separately and a query under the wrong one returns
  nothing rather than an error, so the distribution travels from os-release into
  every purl. Entries for the Ubuntu Pro and FIPS tiers, which share a release
  number with the main archive and sometimes carry no fix at all, are not
  reported: a fix only a subscriber can install is not an answer.

- `fwscan scan` reading extracted rootfs directories, tar archives with gzip, xz,
  zstd or lz4 compression, and squashfs images. The format is detected from the
  file's contents, never from its name.
- dpkg cataloger (`var/lib/dpkg/status`) and apk cataloger
  (`lib/apk/db/installed`), both resolving the source package the vulnerability
  data is keyed on.
- Heuristic detectors for the kernel version, the busybox version and versioned
  shared libraries, reported at low confidence with the path they came from.
- Standalone-compressed images: `rootfs.squashfs.gz` and the other shapes Yocto
  and OpenWrt emit are unwrapped before extraction.
- Severity from CVSS v3.1, v4.0 or v2 vectors, scored locally. The v4 path
  matches FIRST's reference calculator across the whole base metric space; where
  a record carries no vector of its own but names the CVEs it fixed, each
  finding takes the vector of its own CVE's record, which is what makes
  `--fail-on` usable on an oldstable Debian image. An advisory that fixed
  several CVEs in one upload is reported as one finding per CVE, not one per
  advisory.

**Vulnerability matching**

- OSV.dev matcher, release-aware for Debian, Ubuntu and Alpine, so a package
  patched by a security backport is reported as fixed rather than vulnerable.
- Debian's own security tracker as a fallback for a release past free support.
  OSV's Debian data is built from an export that carries a release for exactly
  as long as it is freely supported, so Debian 11 left it on 2026-08-31 and a
  scan of a bullseye image reported nothing at all. fwscan now reads the
  export's input instead — the CVE list plus the DSA and DLA advisories, which
  are not optional: a CVE closed by an advisory carries no per-release line, and
  without them every such CVE is a false positive. On a real Debian 11 rootfs
  that is 0 findings against 208. Checked against trivy on the same image with a
  database built the same day: 111 CVEs in both, none fwscan reports and trivy
  does not. It runs only for a release OSV has dropped; a supported release is
  answered by OSV alone and fetches none of it. Where it runs, the scan and the
  evidence report name it as the source rather than warning that the results are
  incomplete: they are not, and telling a reader to distrust a complete report
  is its own kind of wrong. Where no fallback covers the release — an Ubuntu
  release on ESM, say — the warning stands.
- Lookups batched and deduplicated by source package; vulnerability details
  fetched through a bounded worker pool.
- CVSS v3 and v2 base scores computed from their vectors, mapped to the severity
  buckets in `docs/output-spec.md`.
- Fixed versions selected per release, so a bookworm fix is never reported to a
  bullseye image.

**Output**

- Severity-sorted terminal report.
- `--output` for the full JSON report, written atomically.
- `--sbom` for a CycloneDX 1.6 document, validated against the official schema in
  CI, carrying components only.
- `--fail-on` and the exit codes from `docs/output-spec.md` section 5: 0 clean,
  1 findings at or above the threshold, 2 the scan could not complete.
- `--no-network` to produce the SBOM without any vulnerability lookup.
- A dpkg image with no release in os-release is cataloged but not looked up.
  Without a release the query carries no distro qualifier and matches the source
  package in every Debian release at once: a Yocto image built with
  `package_deb`, six packages, produced 182 findings with fixed versions from
  eight different Debian releases, none installable there. The SBOM is
  unaffected, and the scan says which packages were skipped and why. This
  matches what the apk path already did.
- Derivative distributions are looked up in the data of the base they declare in
  os-release's `ID_LIKE`, under the release their `VERSION_CODENAME` names, and
  the scan says which base it used. Raspberry Pi OS, Armbian and Linux Mint all
  declare one, and between them they are most of the Debian-derived device
  images there are. A Raspberry Pi OS bullseye image gets the 45 findings Debian
  bullseye gets for `libssl1.1`, not the 28 an unrecognised distribution gets.
  An image that names no base fwscan knows is still queried as Debian, and still
  says so.
- Every scan reports whether the release in the image still receives security
  updates, and whether those updates are free. This is the explanation behind
  the tool's worst result: a Debian 11 image scanned after 2026-08-31 yields no
  findings at all, because that is the day Debian 11 left free support, the
  security tracker's export stopped carrying it, and OSV's Debian data is built
  from that export. The scan now names the release, the day, and the tier that
  covers it — Freexian's commercial Extended LTS, in that case — instead of
  reporting a clean image. The dates are `distro-info-data`, the table Debian
  and Ubuntu maintain for the question, embedded rather than fetched so an
  offline run still knows.
- `--cra <file>` writes the scan as a Markdown evidence report for Annex I,
  Part II of Regulation (EU) 2024/2847, the Cyber Resilience Act: scan
  provenance, a reference to the SBOM rather than a second copy of the
  inventory, one row per finding split by whether a fix exists for the
  installed release, an empty `Justification` column for the manufacturer to
  fill, and the scan's own stderr warnings filed as limitations. It names the
  five obligations it cannot evidence, in its own body, every time it is
  generated, and says at the top that it is not a compliance statement. A
  generated file that let a reader assume otherwise would be worse than no
  file.


**Project**

- Release binaries for linux/amd64, linux/arm64 and darwin/arm64, with
  checksums.
- CI running lint, race tests, the squashfs compression matrix and CycloneDX
  schema validation.
- `spike/NOTES.md`, the evidence behind the query formats and the squashfs
  strategy, including the checks that failed before they passed.
- `THIRD_PARTY_LICENSES.txt` in every release archive, carrying the licences and
  notices of the dependencies the binaries link and of the CVSS v4 reference
  calculator this project transcribes. `make third-party-licenses` regenerates
  it from the module cache and CI fails if the committed copy has drifted.
- `docs/scope.md`, `docs/roadmap.md`, `docs/architecture.md`,
  `docs/output-spec.md` and `docs/comparison.md` — what fwscan is for, what is
  coming, how it is built, exactly what it emits, and how it measures against
  syft and grype.

### Found by testing on real firmware before release

- A squashfs image containing device nodes — which every real rootfs does, `/dev/console`
  at the least — was refused. `unsquashfs` cannot create them without root, says
  so, exits 2 and extracts everything else; fwscan treated any non-zero status as
  failure. The first real OpenWrt image tried against it produced 1069 files
  including the package database and was rejected anyway. Exit 2 is read as what
  it means and exit 1 still is not.
- An image carrying a package database fwscan does not read — opkg, rpm — now
  says so. A real OpenWrt image lists 150 opkg packages; fwscan reports the two
  its filename heuristics recognise, and reporting two of a hundred and fifty
  without a word is an answer that gets acted on and should not be.

### Known limitations

- fwscan reports the CVEs a distribution has issued a fix for, not the ones it
  has chosen not to fix. OSV's data for the latter thins as a release ages and
  is gone once it leaves support, so on a supported release fwscan is level with
  grype — 182 findings to 179 on a Debian bookworm rootfs — and on a fully
  patched Debian 11 rootfs it reports nothing where grype reports 211, all of
  them unfixed. A scan of a Debian image that finds nothing says so rather than
  reporting a clean result. `docs/comparison.md` measures seven real images. A
  second data source is on the roadmap.
- A dpkg-based distribution that is neither Debian nor Ubuntu is queried against
  Debian's data, which may have nothing for it. The scan says so on stderr.
- Roughly a fifth of Debian's OSV records carry no severity and land in the
  `unknown` bucket, which `--fail-on` never triggers on.
- Heuristic components are reported but not looked up: a version read off a
  filename carries no release to scope a query to.
- No offline mode, no SPDX output, no opkg or rpm support, no VEX. See the
  limitations table in the README.

### Note on this changelog

This is the first release, so there is nothing to compare it against. The
defects fixed during the pre-publication review never reached a user and are
not changelog entries; they are in the commit history, each with the
measurement that found it.

[0.1.0]: https://github.com/mhmtkas/fwscan/releases/tag/v0.1.0
