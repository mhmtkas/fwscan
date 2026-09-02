package match

import (
	"slices"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/mhmtkas/fwscan/internal/model"
)

// buildFinding turns one OSV record, read under one of its identities, plus
// the component it hit into a Finding.
func buildFinding(record vulnRecord, ident recordIdentity, comp model.Component, key queryKey) model.Finding {
	severity, score, vector := severityOf(record)

	return model.Finding{
		Component:    comp,
		ID:           ident.id,
		Aliases:      ident.aliases,
		Severity:     severity,
		CVSS:         score,
		CVSSVector:   vector,
		FixedVersion: fixedVersion(record, key),
	}
}

// recordIdentity is one vulnerability a record describes: the identifier shown
// to the user, the other names it goes by, and the record to borrow an
// assessment from when this one has none.
type recordIdentity struct {
	id      string
	aliases []string
	// borrowFrom is the database's own record for this CVE -- DEBIAN-CVE-… or
	// ALPINE-CVE-… -- named in upstream, or empty when there is none.
	borrowFrom string
}

// identities lists the vulnerabilities a record describes.
//
// OSV's Debian and Alpine records are named DEBIAN-CVE-2022-0778 and carry the
// plain CVE in an "upstream" field; their "aliases" field was empty on all 292
// records the spike examined. output-spec section 3 shows a plain CVE id, so
// the upstream CVE is the identifier and the record id is kept as an alias,
// which keeps the record traceable.
//
// A DSA or DLA advisory names every CVE the upload fixed, and one upload
// routinely fixes several -- DLA-3942-1 names six. That is six vulnerabilities,
// each with an assessment of its own, and output-spec section 1 asks for one
// finding per vulnerability: reporting the advisory as one finding under the
// first CVE's name hid the rest inside `aliases`, where a 9.1 critical could sit
// under a 5.3 medium and never reach --fail-on. So an advisory yields one
// identity per CVE it names. Its own id is an alias of each; the sibling CVEs
// are not aliases of one another, because they are not the same vulnerability.
func identities(record vulnRecord) []recordIdentity {
	var cves []string
	seen := map[string]bool{}
	for _, up := range record.Upstream {
		if strings.HasPrefix(up, "CVE-") && !seen[up] {
			seen[up] = true
			cves = append(cves, up)
		}
	}

	if len(cves) == 0 {
		// Not a record that names a CVE. It is its own identity, and every
		// other name it carries is an alias.
		ident := recordIdentity{id: record.ID}
		for _, name := range append(append([]string{}, record.Upstream...), record.Aliases...) {
			ident.addAlias(name)
			if ident.borrowFrom == "" && name != record.ID && strings.Contains(name, "-CVE-") {
				ident.borrowFrom = name
			}
		}
		return []recordIdentity{ident}
	}

	out := make([]recordIdentity, 0, len(cves))
	for _, cve := range cves {
		ident := recordIdentity{id: cve}
		ident.addAlias(record.ID)
		// The database's own record for this CVE is named DEBIAN-CVE-… or
		// ALPINE-CVE-…: the CVE with a prefix. It is the alias that belongs
		// to this identity, and the record to borrow an assessment from.
		for _, up := range record.Upstream {
			if up != record.ID && strings.HasSuffix(up, "-"+cve) {
				ident.addAlias(up)
				if ident.borrowFrom == "" {
					ident.borrowFrom = up
				}
			}
		}
		for _, alias := range record.Aliases {
			ident.addAlias(alias)
		}
		out = append(out, ident)
	}
	return out
}

func (r *recordIdentity) addAlias(name string) {
	if name == "" || name == r.id || slices.Contains(r.aliases, name) {
		return
	}
	r.aliases = append(r.aliases, name)
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
	// Two records can name different fixes for the same issue in the same
	// release, and which of them arrived first is not a reason to prefer it.
	if other.FixedVersion != "" {
		kept.FixedVersion = preferFix(kindOf(kept.Component), kept.FixedVersion, other.FixedVersion)
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

	// 3. CVSS v2, only when there is neither v3 nor v4. A vector scoring 0 is
	// no assessment on this path either, for the same reason as above: v2's
	// bands start at 0.1, and "low, score 0, vector present" is a row that
	// contradicts itself.
	if vector, ok := vectorOfType(record, "CVSS_V2"); ok {
		if score, ok := cvss2BaseScore(vector); ok && score > 0 {
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
	// The qualifier is compared, not searched for. A substring search reads
	// "distro=bullseye" out of "distro=bullseye-backports", and backports is a
	// different release with a different fixed version -- the exact confusion
	// the release qualifier exists to prevent, arriving as a plausible-looking
	// wrong version in the FIXED column.
	if qualifier := purlDistro(a.Package.PURL); qualifier != "" {
		return qualifier == key.distro
	}
	// No qualifier at all. That is what a DSA or DLA advisory looks like: one
	// purl for every release it covers, with the release named in the ecosystem
	// field instead. Matching on that is how the fixed version an advisory
	// carries becomes reachable -- and on an oldstable image, advisories are
	// the only records OSV has.
	if want := key.advisoryEcosystem(); want != "" {
		return a.Package.Ecosystem == want
	}
	return false
}

// purlDistro reads the distro qualifier of a purl, or "" if it carries none or
// does not parse. A purl this cannot read is not one to draw a release from.
func purlDistro(purl string) string {
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		return ""
	}
	return parsed.Qualifiers.Map()["distro"]
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
	// Second and third choices, in that order. "newer" is a fix that is above
	// the installed version but whose window does not contain it -- the right
	// answer for a record with a single window, and the best available for one
	// whose windows do not fit. "unordered" is for versions that cannot be
	// compared at all: an ecosystem with no comparison, or a version neither
	// side parses. A fix *known* to be older than what is installed is neither;
	// it is a wrong answer that tells the reader to downgrade.
	var contained, newer, unordered string
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
			// A GIT range's events are commit hashes rather than versions, so
			// its "fixed" is forty characters of hex. Printing that in the
			// FIXED column tells the reader to install a commit.
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}

			// Events arrive in order and describe a sequence of windows: an
			// introduced opens one, the fixed that follows closes it.
			var introduced string
			for _, e := range r.Events {
				if e.Introduced != "" {
					introduced = e.Introduced
					continue
				}
				if e.Fixed == "" {
					continue
				}
				// output-spec section 1: where several ranges match, the one
				// whose window contains the installed version wins. Only the
				// upper bound used to be tested, so a record carrying a window
				// the installed version sits *below* answered with that
				// window's fix rather than with the one it belongs to.
				if windowContains(key.kind, key.version, introduced, e.Fixed) {
					contained = preferFix(key.kind, contained, e.Fixed)
					continue
				}
				if versionLess(key.kind, key.version, e.Fixed) {
					newer = preferFix(key.kind, newer, e.Fixed)
				}
				if _, ordered := compareVersions(key.kind, key.version, e.Fixed); !ordered && unordered == "" {
					unordered = e.Fixed
				}
			}
		}
	}
	if contained != "" {
		return contained
	}
	// A fix that is merely newer is second best: it is the right answer for a
	// record with one window, and the only answer available for one whose
	// windows do not fit.
	if newer != "" {
		return newer
	}
	return unordered
}

// preferFix chooses between two versions that both fix the same issue, keeping
// the lower one.
//
// A release can carry more than one advisory for a CVE -- Debian's DLA-3942-1
// fixed one in openssl at 1.1.1n-0+deb11u6 and DLA-3942-2 shipped again at
// 1.1.1w-0+deb11u2 -- and both are true. The lower is the answer to the question
// the column asks, which is what version stops being affected, not what version
// is newest. Without a rule the answer would depend on the order OSV happened to
// return the records in, which is worse than either choice.
func preferFix(kind packageKind, current, candidate string) string {
	if current == "" {
		return candidate
	}
	if versionLess(kind, candidate, current) {
		return candidate
	}
	return current
}

// windowContains reports whether the installed version falls inside an
// introduced-to-fixed window, which is half-open: the version that fixes the
// issue is not itself affected by it.
//
// An ordering that cannot be established is not containment. Declining here
// costs a preference, not the answer: the caller still has the fixed version as
// a candidate.
func windowContains(kind packageKind, installed, introduced, fixed string) bool {
	if introduced != "" {
		c, ordered := compareVersions(kind, installed, introduced)
		if !ordered || c < 0 {
			return false
		}
	}
	return versionLess(kind, installed, fixed)
}
