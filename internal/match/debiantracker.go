package match

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

// This file reads the Debian security tracker's own lists: the source OSV's
// Debian data is built from, and the only place a release past free support is
// still recorded.
//
// OSV is preferred everywhere it has an answer, because it is keyed, versioned
// and small. It stops carrying a Debian release the day that release leaves
// free support -- Debian 11 on 2026-08-31 -- because the tracker's JSON export
// does, and the export is what OSV's importer reads. The lists below are the
// export's input rather than its output, and they keep every release, including
// the ones only Freexian still patches.
//
// Measured 2026-09-03 on a bullseye rootfs: 0 findings through OSV, 111 CVEs
// through these lists, and every CVE trivy reported bar its own TEMP- ids.

// SourceDebianTracker names this source in the JSON report, so a reader can
// tell which findings came from a database OSV does not carry.
const SourceDebianTracker = "security-tracker.debian.org"

// DefaultTrackerBase is where the Debian security tracker's lists live.
const DefaultTrackerBase = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/"

const (
	// The advisory lists, together about 2 MB, and not optional. A CVE fixed by
	// a DSA or a DLA carries no per-release line in CVE/list at all: the fixed
	// version lives in the advisory instead. Without these, zlib in bullseye at
	// 1:1.2.11.dfsg-2+deb11u2 is compared against unstable's 1:1.2.11.dfsg-4,
	// found to be behind it, and reported as vulnerable to CVE-2018-25032 --
	// which DSA-5111-1 fixed for that release at 1:1.2.11.dfsg-2+deb11u1. Every
	// CVE ever closed by an advisory would be a false positive.
	debianCVEPath = "CVE/list"
	debianDSAPath = "DSA/list"
	debianDLAPath = "DLA/list"
)

// Bounds on a source fwscan does not control (CLAUDE.md rule 9). The file was
// 60 MB on 2026-09-03 and grows by roughly a megabyte a month; the cap is an
// order of magnitude above that, and it is enforced while streaming so a
// response that never ends is cut off rather than accumulated.
const (
	maxTrackerBytes   = 512 << 20
	maxTrackerLine    = 1 << 20
	trackerTimeout    = 5 * time.Minute
	maxTrackerEntries = 200_000
)

// trackerStatus is what Debian has decided about a vulnerability in a release.
// The distinction is the useful part of this source: "no fix exists yet" and
// "we have decided not to fix this" are different facts about a product, and
// the second is the one a compliance reader has to write a justification for.
type trackerStatus string

const (
	// trackerOpen is affected with no decision recorded: a fix may still come.
	trackerOpen trackerStatus = "affected"
	// trackerDeferred is <no-dsa> and <postponed>: affected, and Debian has
	// said it will not issue a security update on its own schedule.
	trackerDeferred trackerStatus = "fix deferred"
	// trackerWontFix is <ignored>: affected, and Debian has closed it.
	trackerWontFix trackerStatus = "will not fix"
)

// trackerEntry is one CVE's verdict for one source package in one release.
type trackerEntry struct {
	id     string
	source string
	// fixedVersion is set only when the release itself has a fix. A version on
	// the unstable line is not one: it names a package that release cannot
	// install, and reporting it would send a reader to an upgrade that does not
	// exist for them.
	fixedVersion string
	// unstableFix is the version unstable was fixed at, used to decide whether
	// a release that has no line of its own is affected at all.
	unstableFix string
	status      trackerStatus
	// note is the parenthesised reason Debian recorded, e.g. "Minor issue".
	note string
	// scopedSeen records that a line for the release itself has been read, so
	// a later unstable line cannot overwrite it.
	scopedSeen bool
	// unaffected records an explicit "not affected" verdict, which has to
	// survive as a decision rather than as an absence.
	unaffected bool
}

// markers are the states a package line can carry instead of a version.
var markers = map[string]struct {
	affected bool
	status   trackerStatus
	// scopedClears marks a state that means "affected" on the unstable line and
	// "not affected" on a release's own line.
	scopedClears bool
}{
	"<unfixed>":   {affected: true, status: trackerOpen},
	"<no-dsa>":    {affected: true, status: trackerDeferred},
	"<postponed>": {affected: true, status: trackerDeferred},
	"<ignored>":   {affected: true, status: trackerWontFix},
	// <removed> means the source package is gone, and what that implies depends
	// on which line it is on. On the unstable line it means gone from unstable,
	// which says nothing about a stable release that still ships it -- and the
	// image in front of us has it installed, so it does. That is affected with
	// no fix coming. On a release's own line it means gone from that release,
	// which is a statement about the release and is taken as written.
	"<removed>":      {affected: true, status: trackerOpen, scopedClears: true},
	"<not-affected>": {affected: false},
	"<itp>":          {affected: false},
	"<undetermined>": {affected: false},
	// The release stopped tracking this package before the CVE was filed.
	// Reporting it would claim knowledge nobody has.
	"<end-of-life>": {affected: false},
}

// fetchDebianTracker streams the tracker's CVE list and returns the entries for
// the given source packages in the given release.
//
// The file is large and almost entirely irrelevant to any one image -- most of
// it is NOT-FOR-US lines about software Debian does not ship -- so it is parsed
// as it arrives and only the named packages are kept. Nothing is buffered.
func fetchDebianTracker(ctx context.Context, client *http.Client, base, release string, sources map[string]bool) ([]trackerEntry, error) {
	if base == "" || release == "" || len(sources) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, trackerTimeout)
	defer cancel()

	fixes := advisoryFixes{}
	for _, u := range []string{base + debianDSAPath, base + debianDLAPath} {
		if err := get(ctx, client, u, func(r io.Reader) error {
			return parseDebianAdvisories(r, release, sources, fixes)
		}); err != nil {
			return nil, err
		}
	}

	var entries []trackerEntry
	err := get(ctx, client, base+debianCVEPath, func(r io.Reader) error {
		var perr error
		entries, perr = parseDebianTracker(r, release, sources, fixes)
		return perr
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// get streams one of the tracker's files through parse. The body is never
// buffered: the CVE list is tens of megabytes and almost all of it names
// software Debian does not ship.
func get(ctx context.Context, client *http.Client, url string, parse func(io.Reader) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("debian tracker: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("debian tracker: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("debian tracker: %s: %s", url, resp.Status)
	}
	return parse(io.LimitReader(resp.Body, maxTrackerBytes))
}

// advisoryFixes maps a CVE to the version each source package was fixed at in
// one release, as recorded by the DSA and DLA advisories.
type advisoryFixes map[string]map[string]string

func (a advisoryFixes) add(cve, source, version string) {
	if a[cve] == nil {
		a[cve] = map[string]string{}
	}
	// The lowest fix wins, matching how the OSV path picks between windows: it
	// is the earliest version that carries the patch, and telling somebody to
	// install more than they need to is its own kind of wrong.
	if have, ok := a[cve][source]; ok {
		if cmp, ok := compareVersions(kindDeb, version, have); !ok || cmp >= 0 {
			return
		}
	}
	a[cve][source] = version
}

// parseDebianAdvisories reads DSA/list or DLA/list, which share a format:
//
//	[01 Apr 2022] DSA-5111-1 zlib - security update
//		{CVE-2018-25032}
//		[bullseye] - zlib 1:1.2.11.dfsg-2+deb11u1
//
// Only the release asked about is kept, and only for packages in the image.
func parseDebianAdvisories(r io.Reader, release string, sources map[string]bool, into advisoryFixes) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), maxTrackerLine)

	bracket := "[" + release + "]"
	var cves []string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			cves = nil
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "{") {
			cves = cves[:0]
			for _, f := range strings.Fields(strings.Trim(trimmed, "{}")) {
				if id := strings.Trim(f, "{}"); isCVEID(id) {
					cves = append(cves, id)
				}
			}
			continue
		}
		if len(cves) == 0 {
			continue
		}
		source, state, _, scoped, ok := parsePackageLine(line, bracket)
		if !ok || !scoped || !sources[source] {
			continue
		}
		// An advisory line can carry a marker rather than a version --
		// <not-affected> for a release the upload did not need. Only a real
		// version is a fix.
		if _, isMarker := markers[state]; isMarker || state == "" {
			continue
		}
		for _, cve := range cves {
			into.add(cve, source, state)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("debian tracker: %w", err)
	}
	return nil
}

// parseDebianTracker reads the list's line format.
//
// A record is a CVE line at column zero followed by indented lines. Only the
// package lines matter:
//
//   - glibc 2.37-10                          the state in unstable
//     [bullseye] - glibc <ignored> (Minor issue)   an override for one release
//
// A release with no line of its own follows unstable, which is why both are
// kept: the unstable version is what decides whether a release that never got
// its own entry is behind.
func parseDebianTracker(r io.Reader, release string, sources map[string]bool, fixes advisoryFixes) ([]trackerEntry, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), maxTrackerLine)

	bracket := "[" + release + "]"

	var (
		out     []trackerEntry
		id      string
		current map[string]*trackerEntry
	)
	flush := func() {
		for _, e := range current {
			if e.status == "" {
				continue
			}
			// An advisory fixed this for the release, at a version the release
			// can install. That outranks unstable's version, which it cannot.
			if e.fixedVersion == "" {
				if v, ok := fixes[e.id][e.source]; ok {
					e.fixedVersion, e.unstableFix = v, ""
				}
			}
			out = append(out, *e)
		}
		current = nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			if len(out) >= maxTrackerEntries {
				break
			}
			id = recordID(line)
			continue
		}
		if id == "" {
			continue
		}
		source, state, note, scoped, ok := parsePackageLine(line, bracket)
		if !ok || !sources[source] {
			continue
		}
		if current == nil {
			current = map[string]*trackerEntry{}
		}
		e := current[source]
		if e == nil {
			e = &trackerEntry{id: id, source: source}
			current[source] = e
		}
		applyState(e, state, note, scoped)
	}
	flush()

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("debian tracker: %w", err)
	}
	return out, nil
}

// recordID reads the CVE name off a record's first line, which is the name
// followed by a parenthesised description.
//
// The shape is checked rather than the prefix. Debian files placeholders as
// CVE-YYYY-XXXX while an identifier is being assigned, and there are hundreds
// of them; taking those at face value reports one vulnerability many times
// under a name that identifies nothing.
func recordID(line string) string {
	name := line
	if i := strings.IndexAny(name, " \t"); i >= 0 {
		name = name[:i]
	}
	if !isCVEID(name) {
		return ""
	}
	return name
}

// isCVEID reports whether s is CVE-<digits>-<digits>.
func isCVEID(s string) bool {
	rest, ok := strings.CutPrefix(s, "CVE-")
	if !ok {
		return false
	}
	year, id, ok := strings.Cut(rest, "-")
	return ok && allDigits(year) && allDigits(id)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parsePackageLine reads one indented line. It reports the source package, the
// version or marker recorded for it, the parenthesised note, and whether the
// line was scoped to the release asked about rather than to unstable.
//
// Lines for other releases are rejected here rather than filtered later, so an
// entry can never take a verdict meant for bookworm and apply it to bullseye.
func parsePackageLine(line, bracket string) (source, state, note string, scoped, ok bool) {
	s := strings.TrimLeft(line, " \t")
	switch {
	case strings.HasPrefix(s, "- "):
		s = s[2:]
	case strings.HasPrefix(s, bracket+" - "):
		s = s[len(bracket)+3:]
		scoped = true
	default:
		// A NOTE, a {DSA-…} reference, or a line for another release.
		return "", "", "", false, false
	}

	if i := strings.Index(s, " ("); i >= 0 {
		note = strings.TrimSuffix(strings.TrimSpace(s[i+2:]), ")")
		s = s[:i]
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", "", "", false, false
	}
	source = fields[0]
	if len(fields) > 1 {
		state = fields[1]
	}
	return source, state, note, scoped, true
}

// applyState folds one line into the entry being built. A line scoped to the
// release always wins, whichever order the two arrive in.
func applyState(e *trackerEntry, state, note string, scoped bool) {
	if !scoped {
		// A verdict for the release itself always wins, whichever order the
		// two lines arrive in. The file writes unstable first, but nothing in
		// the format promises it, and "not affected in bullseye" recorded as an
		// absence rather than a status would otherwise be silently overwritten
		// by unstable's "unfixed" and reported as a vulnerability.
		if e.scopedSeen {
			return
		}
		e.unstableFix = ""
		if m, isMarker := markers[state]; isMarker {
			if !m.affected {
				e.status = ""
				e.markUnaffected()
				return
			}
			e.status, e.note, e.fixedVersion = m.status, note, ""
			return
		}
		// A version on the unstable line is not a fix this release can install,
		// so it is recorded as the comparison point and not as a fixed version.
		e.unstableFix, e.status, e.note, e.fixedVersion = state, trackerOpen, note, ""
		return
	}

	e.scopedSeen = true
	if m, isMarker := markers[state]; isMarker {
		if !m.affected || m.scopedClears {
			e.status = ""
			e.markUnaffected()
			return
		}
		e.status, e.note, e.fixedVersion, e.unstableFix = m.status, note, "", ""
		return
	}
	// The release has its own fix, at a version it can actually install.
	e.status, e.note, e.fixedVersion, e.unstableFix = trackerOpen, note, state, ""
}

func (e *trackerEntry) markUnaffected() {
	e.fixedVersion, e.unstableFix, e.note = "", "", ""
	e.unaffected = true
}

// trackerFindings turns entries into findings for the components they name.
//
// The version comparison is the whole of the accuracy here. An entry with a
// fixed version for the release is a finding only while the installed version
// is behind it. An entry that carries only unstable's fix is a finding only
// while the installed version is behind that -- which is how a CVE fixed before
// the release was cut is correctly not reported -- and it carries no fixed
// version of its own, because the version that fixed unstable is not one this
// release can install.
func trackerFindings(entries []trackerEntry, bySource map[string][]model.Component) []model.Finding {
	var out []model.Finding
	for _, e := range entries {
		if e.unaffected || e.status == "" {
			continue
		}
		for _, comp := range bySource[e.source] {
			installed := comp.Version
			switch {
			case e.fixedVersion != "":
				if cmp, ok := compareVersions(kindDeb, installed, e.fixedVersion); !ok || cmp >= 0 {
					continue
				}
			case e.unstableFix != "":
				if cmp, ok := compareVersions(kindDeb, installed, e.unstableFix); !ok || cmp >= 0 {
					continue
				}
			}
			out = append(out, model.Finding{
				Component:    comp,
				ID:           e.id,
				Severity:     model.SeverityUnknown,
				FixedVersion: e.fixedVersion,
				Source:       SourceDebianTracker,
			})
		}
	}
	return out
}
