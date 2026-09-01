# Roadmap

What is expected after v0.1.0, in the order it is expected. This is a statement
of direction rather than a commitment to dates. Everything here is currently a
non-goal; `docs/scope.md` explains why each one is excluded today.

## v1.x

1. **CRA compliance report (`--report cra`).** A reporter that renders scan
   results as a compliance-oriented document mapped to the EU Cyber Resilience
   Act's vulnerability-handling obligations: the component inventory by
   reference to the SBOM, known-vulnerability status with severity and fix
   availability, placeholders for justifying unresolved findings, and scan
   provenance — tool version, date, data source. This is the item that moves
   fwscan from a scanner to a compliance tool, and it needs no changes to the
   core: it is a new reporter over the results that already exist.

2. **VEX output.** The natural companion to the CRA report, and the format the
   same audience will be asked for next.

3. **Offline vulnerability data.** For air-gapped build environments, where the
   scan cannot reach OSV.dev at all.

## Later

An opkg cataloger for OpenWrt; colour output; SPDX as a second SBOM format; NVD
as a secondary vulnerability source; a false-positive suppression file; ext4
image input; an rpm cataloger.

## Not planned

Binary fingerprinting of unmanaged binaries, encrypted or obfuscated firmware,
kernel configuration analysis, and anything hosted. `docs/scope.md` gives the
reasoning for each.
