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
// the record traceable. output-spec section 3 carries this rule under
// "Identifier derivation"; spike/NOTES.md records the evidence behind it.
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

// dedupeFindings collapses findings that name the same vulnerability in the
// same component.
//
// OSV answers a single package query with several records describing one issue:
// a DEBIAN-CVE-… record with the CVSS vector and the release's fixed version,
// and the DSA or DLA advisory that shipped the fix, which carries neither and
// whose affected purl has no distro qualifier to match a release against. Both
// resolve to the same CVE through the identifier rule in output-spec section 3,
// so without this the report shows a CVE twice -- once scored and once as
// unknown -- and inflates both the finding count and the unknown bucket. A DSA
// covering four CVEs collapses onto the first of them, which made the second
// row not even a copy of the first.
func dedupeFindings(findings []model.Finding) []model.Finding {
	type identity struct {
		component model.Component
		id        string
	}

	at := make(map[identity]int, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		key := identity{component: f.Component, id: f.ID}
		i, seen := at[key]
		if !seen {
			at[key] = len(out)
			out = append(out, f)
			continue
		}
		out[i] = mergeFindings(out[i], f)
	}
	return out
}

// mergeFindings folds one duplicate into another.
//
// Severity, score and vector move together or not at all: they are one record's
// assessment, and pairing a score with a vector that does not produce it would
// report a number nothing backs. The fixed version is taken from whichever
// record knows one, because a fix already survived the release check in
// fixedVersion() and an advisory that names no release cannot contradict it.
// Aliases are the union, so the record ids of everything merged away stay
// visible in the JSON report.
func mergeFindings(kept, other model.Finding) model.Finding {
	// CompareFindings ranks by severity then score, and the two agree on
	// component and id here, so it reduces to "is the other assessment
	// better". Only a strictly better one displaces what is already there.
	if model.CompareFindings(other, kept) < 0 {
		kept.Severity, kept.CVSS, kept.CVSSVector = other.Severity, other.CVSS, other.CVSSVector
	}
	if kept.FixedVersion == "" {
		kept.FixedVersion = other.FixedVersion
	}

	seen := make(map[string]bool, len(kept.Aliases)+len(other.Aliases))
	seen[kept.ID] = true
	for _, a := range kept.Aliases {
		seen[a] = true
	}
	for _, a := range other.Aliases {
		if !seen[a] {
			seen[a] = true
			kept.Aliases = append(kept.Aliases, a)
		}
	}
	return kept
}

// severityOf maps a record to a bucket, a score and the vector it came from,
// following output-spec section 1's priority order exactly.
//
// The spike measured what Debian data actually contains: 224 of 292 records
// carried a v3 vector, 11 carried v4 only, 57 carried nothing, and none carried
// v2 or a database_specific severity. Steps 3 and 4 below are therefore
// unreachable for Debian in practice. The 57 severity-less records were
// reviewed and deliberately left as unknown, which the README's limitations
// section states.
func severityOf(record vulnRecord) (model.Severity, float64, string) {
	// 1. CVSS v3.x. output-spec section 1's bands start at 0.1, so a vector
	// scoring exactly 0 -- no impact on anything -- maps to no bucket. It falls
	// through rather than being reported as an unknown severity that
	// nonetheless carries a vector, which would contradict section 3.
	if vector, ok := vectorOfType(record, "CVSS_V3"); ok {
		if score, ok := cvss3BaseScore(vector); ok {
			if bucket := bucketFromCVSSScore(score); bucket != model.SeverityUnknown {
				return bucket, score, vector
			}
		}
	}

	// 2. CVSS v4, which shares v3's bands. A v4 vector may carry threat and
	// environmental metrics; only the base metrics are scored, as for v3.
	if vector, ok := vectorOfType(record, "CVSS_V4"); ok {
		if score, ok := cvss4BaseScore(vector); ok {
			if bucket := bucketFromCVSSScore(score); bucket != model.SeverityUnknown {
				return bucket, score, vector
			}
		}
	}

	// 3. CVSS v2, only when there is neither v3 nor v4.
	if vector, ok := vectorOfType(record, "CVSS_V2"); ok {
		if score, ok := cvss2BaseScore(vector); ok {
			return bucketFromV2Score(score), score, vector
		}
	}

	// 4. A textual level from the database's own metadata.
	if level, ok := ecosystemSeverity(record); ok {
		if bucket, known := model.ParseSeverity(level); known {
			return bucket, 0, ""
		}
	}

	// 5. Nothing usable.
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

// bucketFromCVSSScore maps a v3 or v4 base score per output-spec section 1.
// The two share one set of bands.
func bucketFromCVSSScore(score float64) model.Severity {
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

// affectedMatchesRelease reports whether an affected entry describes the same
// release the component came from.
//
// The two ecosystems say it in different places. Debian's affected purls carry
// a distro qualifier; Alpine's carry none at all and put the release in the
// ecosystem field instead (spike/NOTES.md T0.3a). Matching only on the purl
// would silently pick another release's fix — which reads as a fixed version
// older than the one installed.
func affectedMatchesRelease(a affected, key queryKey) bool {
	if eco := key.ecosystem(); eco != "" {
		return a.Package.Ecosystem == eco
	}
	if key.distro == "" {
		return true
	}
	return strings.Contains(a.Package.PURL, "distro="+key.distro)
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
		// Entries for other releases are skipped outright rather than kept as a
		// fallback. A release with no fix of its own is still unfixed, and
		// borrowing another release's version tells the reader to install
		// something that does not exist for them -- which is worse than saying
		// no fix is known.
		if !affectedMatchesRelease(a, key) {
			continue
		}

		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				// Prefer a window that actually contains the installed version.
				if versionLess(key.kind, key.version, e.Fixed) {
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
