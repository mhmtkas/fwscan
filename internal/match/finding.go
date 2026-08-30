package match

import (
	"strings"

	"github.com/mhmtkas/fwscan/internal/model"
)

// buildFinding turns one OSV record plus the component it hit into a Finding.
func buildFinding(record vulnRecord, comp model.Component, key queryKey) model.Finding {
	severity, score, vector := severityOf(record)
	id, aliases := identify(record)

	return model.Finding{
		Component:    comp,
		ID:           id,
		Aliases:      aliases,
		Severity:     severity,
		CVSS:         score,
		CVSSVector:   vector,
		FixedVersion: fixedVersion(record, key),
	}
}

// identify chooses the identifier shown to the user.
//
// OSV's Debian records are named DEBIAN-CVE-2022-0778 and carry the plain CVE
// in an "upstream" field; their "aliases" field was empty on all 292 records
// the spike examined. output-spec section 3's example shows a plain CVE id, so
// the upstream CVE is preferred and the OSV id is kept as an alias, which keeps
// the record traceable. This reconciliation is flagged in spike/NOTES.md for
// maintainer review.
func identify(record vulnRecord) (id string, aliases []string) {
	id = record.ID
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && s != id && !seen[s] {
			seen[s] = true
			aliases = append(aliases, s)
		}
	}

	for _, up := range record.Upstream {
		if strings.HasPrefix(up, "CVE-") {
			id = up
			break
		}
	}
	if id != record.ID {
		add(record.ID)
	}
	for _, up := range record.Upstream {
		add(up)
	}
	for _, a := range record.Aliases {
		add(a)
	}
	return id, aliases
}

// severityOf maps a record to a bucket, a score and the vector it came from,
// following output-spec section 1's priority order exactly.
//
// The spike measured what Debian data actually contains: 224 of 292 records
// carried a v3 vector, 11 carried v4 only, 57 carried nothing, and none carried
// v2 or a database_specific severity. Steps 2 and 3 below are therefore
// unreachable for Debian in practice, and v4-only records fall through to
// unknown because the spec defines no rule for them. Both facts are recorded in
// spike/NOTES.md as open questions rather than decided here.
func severityOf(record vulnRecord) (model.Severity, float64, string) {
	// 1. CVSS v3.x.
	if vector, ok := vectorOfType(record, "CVSS_V3"); ok {
		if score, ok := cvss3BaseScore(vector); ok {
			return bucketFromV3Score(score), score, vector
		}
	}

	// 2. CVSS v2, only when there is no v3.
	if vector, ok := vectorOfType(record, "CVSS_V2"); ok {
		if score, ok := cvss2BaseScore(vector); ok {
			return bucketFromV2Score(score), score, vector
		}
	}

	// 3. A textual level from the database's own metadata.
	if level, ok := ecosystemSeverity(record); ok {
		if bucket, known := model.ParseSeverity(level); known {
			return bucket, 0, ""
		}
	}

	// 4. Nothing usable.
	return model.SeverityUnknown, 0, ""
}

func vectorOfType(record vulnRecord, want string) (string, bool) {
	for _, s := range record.Severity {
		if s.Type == want && s.Score != "" {
			return s.Score, true
		}
	}
	return "", false
}

// ecosystemSeverity looks for a textual level, at record level first and then
// on the affected entries, which is where some ecosystems put it.
func ecosystemSeverity(record vulnRecord) (string, bool) {
	if level, ok := stringField(record.DatabaseSpecific, "severity"); ok {
		return level, true
	}
	for _, a := range record.Affected {
		if level, ok := stringField(a.DatabaseSpecific, "severity"); ok {
			return level, true
		}
	}
	return "", false
}

func stringField(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// bucketFromV3Score maps a v3 base score per output-spec section 1.
func bucketFromV3Score(score float64) model.Severity {
	switch {
	case score >= 9.0:
		return model.SeverityCritical
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

// bucketFromV2Score maps a v2 base score. v2 has no critical band, so 7.0 and
// above is high (output-spec section 1, step 2).
func bucketFromV2Score(score float64) model.Severity {
	switch {
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

// fixedVersion picks the fix for the release the component actually came from.
//
// An OSV record lists one affected entry per Debian release, each with its own
// fixed version — zlib's CVE-2022-37434 is fixed at 1:1.2.11.dfsg-2+deb11u2 in
// bullseye but 1:1.2.11.dfsg-4.1 in bookworm. Reporting the wrong release's fix
// would send someone chasing a version that does not exist for them.
//
// Where several ranges match, output-spec section 1 asks for the one whose
// introduced-to-fixed window contains the installed version.
func fixedVersion(record vulnRecord, key queryKey) string {
	var fallback string
	for _, a := range record.Affected {
		if a.Package.Name != key.source {
			continue
		}
		matchesRelease := key.distro == "" || strings.Contains(a.Package.PURL, "distro="+key.distro)

		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				if !matchesRelease {
					if fallback == "" {
						fallback = e.Fixed
					}
					continue
				}
				// Prefer a window that actually contains the installed version.
				if versionLess(key.version, e.Fixed) {
					return e.Fixed
				}
				if fallback == "" {
					fallback = e.Fixed
				}
			}
		}
	}
	return fallback
}
