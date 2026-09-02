# Roadmap

What is expected next, in the order it is expected. This is a statement of
direction rather than a commitment to dates. Everything here is currently a
non-goal; `docs/scope.md` explains why each one is excluded today.

The first item on this list, a CRA evidence report, shipped in v0.2.0 as
`--cra`. It is written up in `docs/output-spec.md` section 5 rather than here.

## v1.x

1. **VEX output.** The natural companion to the evidence report, and the format
   the same audience will be asked for next. It is also what fills the
   `Justification` column that report leaves empty: a reason recorded against an
   unresolved finding is a VEX statement in everything but format.

2. **Offline vulnerability data.** For air-gapped build environments, where the
   scan cannot reach OSV.dev at all.

## Later

An opkg cataloger for OpenWrt; colour output; SPDX as a second SBOM format; NVD
as a secondary vulnerability source; a false-positive suppression file; ext4
image input; an rpm cataloger.

## Not planned

Binary fingerprinting of unmanaged binaries, encrypted or obfuscated firmware,
kernel configuration analysis, and anything hosted. `docs/scope.md` gives the
reasoning for each.
