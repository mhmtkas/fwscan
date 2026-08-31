# fwscan — Output Specification (v1)

Normative spec for everything fwscan prints or writes. The agent implements exactly this; changes go through the maintainer.

## 1. Severity mapping (applies everywhere)

Severity is derived per finding from the OSV record, in this priority order:

1. **CVSS v3.x vector** — if the OSV `severity` array contains an entry with `type: "CVSS_V3"`, compute the base score from the vector and map:
   - 9.0–10.0 → `critical`
   - 7.0–8.9 → `high`
   - 4.0–6.9 → `medium`
   - 0.1–3.9 → `low`
2. **CVSS v4.0 vector** (`type: "CVSS_V4"`) — only if no v3: compute the base score and map it to the same bands as step 1. v4 has no closed-form formula: reduce the vector to its six-digit MacroVector, take that MacroVector's score from the specification's lookup table, and subtract the interpolated severity distance, exactly as FIRST's reference calculator does. Only the base metrics contribute; threat, environmental and supplemental metrics are validated when present but scored at their not-defined defaults, the same way step 1 ignores v3's temporal and environmental metrics.
3. **CVSS v2** (`type: "CVSS_V2"`) — only if neither v3 nor v4: 7.0+ → `high`, 4.0–6.9 → `medium`, else `low` (v2 has no critical band).
4. **Ecosystem severity** — if no CVSS at all but `database_specific.severity` (or affected-level equivalent) provides a textual level, lowercase it and map to the same four buckets where the wording matches; anything unmappable → `unknown`.
5. Otherwise → `unknown`.

Store both the bucket and the numeric score (score `0` + bucket `unknown` when absent). Sorting order everywhere: `critical > high > medium > low > unknown`; ties broken by CVSS score descending, then component name ascending, then vuln ID ascending. Use an existing CVSS parsing library only if already permitted by CLAUDE.md's dependency rule; otherwise implement the base-score computation with a full table-driven test against published example vectors. For v4 the MacroVector lookup table is data that cannot be derived: transcribe it from the reference implementation, record which commit it came from, and check the result against that implementation rather than against hand-computed values.

`FixedVersion`: from the OSV `affected[].ranges[].events` for the matching Debian/Alpine range, take the `fixed` event if present; empty string otherwise. If multiple ranges match, prefer the one whose `introduced`–`fixed` window contains the installed version.

## 2. Terminal report (default output, stdout)

Plain ASCII; no color in v1 (color is a v1.x nicety — do not implement now). Fixed structure:

```
fwscan v0.1.0

  Target      rootfs.squashfs (squashfs, zstd)
  Packages    412 (409 high confidence, 3 low)
  Findings    17   critical: 2  high: 6  medium: 8  low: 1  unknown: 0

SEVERITY  SCORE  PACKAGE     INSTALLED           FIXED               VULN ID           CONF
critical  9.8    openssl     1.1.1n-0+deb11u3    1.1.1n-0+deb11u5    CVE-2022-3602     high
high      8.1    openssh     8.4p1-5+deb11u1     8.4p1-5+deb11u3     CVE-2023-38408    high
...

3 low-confidence components were identified by filename heuristics and may be false positives.
Run with --output report.json for full details including aliases and evidence paths.
```

Rules:
- Header block: tool name + version; `Target` shows path + detected format + detected compression (omit compression when none); `Packages` counts by confidence; `Findings` line always lists all five buckets even when 0.
- Table: exactly these 7 columns in this order. `FIXED` shows `—` when no fixed version is known. Column widths sized to content per run (simple padding; no external table library beyond stdlib `text/tabwriter`).
- When there are zero findings: print header block, then `No known vulnerabilities found.` — no empty table.
- The low-confidence footnote appears only when ≥1 low-confidence component exists.
- Low-confidence components are cataloged, counted in `Packages` and written to the SBOM and the JSON `components` array, but are **not** queried against OSV in v1, so no finding carries `low` in the `CONF` column. A version inferred from a filename has no release to scope the query to, and an unscoped query manufactures findings instead of finding them (`spike/NOTES.md` T0.3). The column still accepts `high|low` so that enabling the lookup later is a matcher change, not a format change.
- With `--no-network`: skip the `Findings` line and table entirely; after the header print `Cataloged 412 packages. CVE lookup skipped (--no-network).`
- All diagnostics/progress/warnings go to **stderr**; stdout carries only the report, so it stays pipe-safe.

## 3. JSON report (`--output <file>`)

Top-level schema (field names are final):

```json
{
  "schema_version": "1",
  "tool": { "name": "fwscan", "version": "0.1.0" },
  "scan": {
    "target": "rootfs.squashfs",
    "format": "squashfs",
    "compression": "zstd",
    "started_at": "2026-08-30T14:05:11Z",
    "duration_ms": 8421
  },
  "summary": {
    "packages": { "total": 412, "high_confidence": 409, "low_confidence": 3 },
    "findings": { "critical": 2, "high": 6, "medium": 8, "low": 1, "unknown": 0 }
  },
  "components": [
    {
      "name": "openssl",
      "version": "1.1.1n-0+deb11u3",
      "arch": "arm64",
      "purl": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u3?arch=arm64",
      "confidence": "high",
      "evidence": "var/lib/dpkg/status"
    }
  ],
  "findings": [
    {
      "id": "CVE-2022-3602",
      "aliases": ["DSA-5343-1"],
      "package": "openssl",
      "installed_version": "1.1.1n-0+deb11u3",
      "fixed_version": "1.1.1n-0+deb11u5",
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "confidence": "high",
      "source": "osv.dev"
    }
  ]
}
```

Rules: keys snake_case; timestamps RFC 3339 UTC; purl percent-encoding per the purl spec (note `+` → `%2B`); `components` sorted by name; `findings` sorted by the severity ordering from §1; `cvss_vector` empty string when severity came from a non-CVSS path; file written atomically (temp + rename); trailing newline at EOF. The exact purl string construction (including any `distro` qualifier) follows `spike/NOTES.md`, but the encoding and JSON placement follow this spec.

**Identifier derivation.** OSV names its Debian and Alpine records `DEBIAN-CVE-…` and `ALPINE-CVE-…`, leaves `aliases` empty, and puts the plain CVE in an `upstream` array. So `id` is the first `CVE-…` entry in `upstream[]` when there is one and the OSV record id otherwise; `aliases` is the OSV record id, then the remaining `upstream` entries, then whatever the record's own `aliases` holds, de-duplicated and in that order. This keeps the id ecosystem-neutral, as the example above shows, without losing the record id the finding came from.

## 4. SBOM (`--sbom <file>`)

CycloneDX 1.6 JSON via `cyclonedx-go`. Per component: `type: "library"` (`"operating-system"` for the detected distro pseudo-component if one is emitted — optional, not required in v1), `name`, `version`, `purl`, and two custom properties: `fwscan:confidence`, `fwscan:evidence`. Metadata: tool name/version + timestamp. Output must validate against the official CycloneDX 1.6 schema; `make validate-sbom` enforces this in CI. The SBOM contains **components only** — never findings (vulnerability data belongs to the report, keeping the SBOM stable and shareable).

## 5. Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; no findings at or above `--fail-on` threshold (or `--fail-on` unset) |
| 1 | Scan completed; ≥1 finding at or above the `--fail-on` severity |
| 2 | Scan error (unreadable input, unsupported format, extraction failure, OSV unreachable without `--no-network`) |

`--fail-on` accepts `critical|high|medium|low`. `unknown`-severity findings never trigger exit 1. Usage errors (bad flags) follow cobra's default behavior and also exit 2.

## 6. Golden files

`testdata/golden/` holds one golden terminal output and one golden JSON report generated from the committed fixture image with a recorded OSV response set. Report tests compare against these byte-for-byte (with the timestamp/duration fields normalized). Any intentional format change must update goldens in the same PR and call it out in the PR description.
