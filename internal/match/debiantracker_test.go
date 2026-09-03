package match

import (
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

func trackerFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "tracker", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(body)
}

// trackerSources are the packages the fixture image is treated as having. The
// parser must ignore every record about anything else, which is almost the
// whole of the real file.
func trackerSources() map[string]bool {
	return map[string]bool{
		"zlib": true, "openssl": true, "tar": true,
		"diffutils": true, "pcre3": true, "coreutils": true,
	}
}

func parseFixture(t *testing.T, release string) []trackerEntry {
	t.Helper()
	sources := trackerSources()
	fixes := advisoryFixes{}
	for _, name := range []string{"DSA-list", "DLA-list"} {
		if err := parseDebianAdvisories(strings.NewReader(trackerFixture(t, name)), release, sources, fixes); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
	}
	entries, err := parseDebianTracker(strings.NewReader(trackerFixture(t, "CVE-list")), release, sources, fixes)
	if err != nil {
		t.Fatalf("parse CVE-list: %v", err)
	}
	return entries
}

func entryFor(entries []trackerEntry, id string) (trackerEntry, bool) {
	for _, e := range entries {
		if e.id == id {
			return e, true
		}
	}
	return trackerEntry{}, false
}

// Each case is a shape the real file uses, and each one changes what a reader
// is told about a product they ship.
func TestParseDebianTracker(t *testing.T) {
	entries := parseFixture(t, "bullseye")

	tests := []struct {
		name        string
		id          string
		present     bool
		status      trackerStatus
		fixed       string
		unstableFix string
		note        string
	}{
		{
			name: "an unfixed package is affected with no fix",
			id:   "CVE-2026-90001", present: true, status: trackerOpen, note: "bug #900001",
		},
		{
			// Debian has closed this. It is the row a compliance reader has to
			// write a justification against, so the decision has to survive.
			name: "a release-scoped ignore is will-not-fix",
			id:   "CVE-2026-90002", present: true, status: trackerWontFix, note: "Minor issue",
		},
		{
			name: "a release-scoped no-dsa is deferred",
			id:   "CVE-2026-90003", present: true, status: trackerDeferred, note: "Minor issue",
		},
		{
			// The unstable line says unfixed and the release line overrides it.
			// Taking the unstable verdict here would invent a vulnerability.
			name: "a release-scoped not-affected wins over the unstable line",
			id:   "CVE-2026-90004", present: false,
		},
		{
			// Unstable's version is not a fix this release can install, so it
			// is kept only as the comparison point.
			name: "a version on the unstable line is not a fix for the release",
			id:   "CVE-2026-90005", present: true, status: trackerOpen, unstableFix: "1.35-1",
		},
		{
			// An advisory fixed this in the release, at a version the release
			// can install. That is a real fixed version.
			name: "an advisory supplies the release's fixed version",
			id:   "CVE-2026-90007", present: true, status: trackerOpen, fixed: "1:1.2.11.dfsg-2+deb11u1",
		},
		{
			name: "a DLA supplies one too",
			id:   "CVE-2026-90008", present: true, status: trackerOpen, fixed: "1:3.7-5+deb11u1",
		},
		{
			// Removed from unstable says nothing about a release still
			// shipping the package, and the image in front of us has it.
			name: "removed on the unstable line is still affected",
			id:   "CVE-2026-90009", present: true, status: trackerOpen,
		},
		{
			name: "removed on the release's own line is not",
			id:   "CVE-2026-90010", present: false,
		},
		{
			// The only scoped line names bookworm, so bullseye follows
			// unstable, which says unfixed.
			name: "a line for another release does not apply",
			id:   "CVE-2026-90011", present: true, status: trackerOpen,
		},
		{
			name: "end of life for the package in this release is not reported",
			id:   "CVE-2026-90012", present: false,
		},
		{
			name: "a record about software Debian does not ship",
			id:   "CVE-2026-90013", present: false,
		},
		{
			name: "a record about a package the image does not have",
			id:   "CVE-2026-90014", present: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := entryFor(entries, tt.id)
			if ok != tt.present {
				t.Fatalf("%s present = %v, want %v", tt.id, ok, tt.present)
			}
			if !ok {
				return
			}
			if got.status != tt.status {
				t.Errorf("status = %q, want %q", got.status, tt.status)
			}
			if got.fixedVersion != tt.fixed {
				t.Errorf("fixedVersion = %q, want %q", got.fixedVersion, tt.fixed)
			}
			if got.unstableFix != tt.unstableFix {
				t.Errorf("unstableFix = %q, want %q", got.unstableFix, tt.unstableFix)
			}
			if tt.note != "" && got.note != tt.note {
				t.Errorf("note = %q, want %q", got.note, tt.note)
			}
		})
	}
}

// Debian files placeholders while an identifier is assigned, and its own
// TEMP- identifiers for issues that have no CVE. Neither names a vulnerability
// anybody can look up, and CVE-YYYY-XXXX is not even unique: taking it at face
// value reports many different issues under one name.
func TestPlaceholderIdentifiersAreRejected(t *testing.T) {
	for _, e := range parseFixture(t, "bullseye") {
		if !isCVEID(e.id) {
			t.Errorf("entry has a placeholder identifier: %q", e.id)
		}
	}
}

func TestIsCVEID(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"CVE-2026-90001", true},
		{"CVE-1999-0001", true},
		{"CVE-2026-1234567890", true},
		{"CVE-2026-XXXX", false},
		{"TEMP-0000000-ABCDEF", false},
		{"CVE-2026", false},
		{"CVE-2026-", false},
		{"CVE--1", false},
		{"CVE-", false},
		{"", false},
		{"DSA-9001-1", false},
		{"cve-2026-90001", false},
	}
	for _, tt := range tests {
		if got := isCVEID(tt.in); got != tt.want {
			t.Errorf("isCVEID(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// Asking about one release must never return another's verdict.
func TestParseIsScopedToOneRelease(t *testing.T) {
	entries := parseFixture(t, "bookworm")

	// bookworm's own line says not-affected where bullseye follows unstable.
	if _, ok := entryFor(entries, "CVE-2026-90011"); ok {
		t.Error("a bookworm scan took bullseye's verdict for CVE-2026-90011")
	}
	// The advisory fixed bullseye and buster, never bookworm, so no fixed
	// version may leak across.
	if e, ok := entryFor(entries, "CVE-2026-90007"); ok && e.fixedVersion != "" {
		t.Errorf("a bookworm scan took bullseye's fixed version: %q", e.fixedVersion)
	}
	// bullseye's ignore must not silence bookworm, which is still unfixed.
	if e, ok := entryFor(entries, "CVE-2026-90002"); !ok || e.status != trackerOpen {
		t.Errorf("CVE-2026-90002 for bookworm = %v (present %v), want affected", e.status, ok)
	}
}

// The version comparison is what keeps this from reporting everything Debian
// has ever recorded against a package.
func TestTrackerFindings(t *testing.T) {
	comp := func(name, version, source string) model.Component {
		return model.Component{
			Name: name, Version: version, Source: source, SourceVersion: version,
			Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
			DistroID: "debian", Distro: "bullseye", DistroVersion: "11",
		}
	}
	bySource := map[string][]model.Component{
		// Two binaries from one source, which is the ordinary case and the
		// reason a finding count is larger than a CVE count.
		"zlib":      {comp("zlib1g", "1:1.2.11.dfsg-2+deb11u1", "zlib"), comp("zlib1g-dev", "1:1.2.11.dfsg-2+deb11u1", "zlib")},
		"tar":       {comp("tar", "1.34-1", "tar")},
		"diffutils": {comp("diffutils", "1:3.7-5", "diffutils")},
		"pcre3":     {comp("libpcre3", "2:8.39-13", "pcre3")},
		"openssl":   {comp("libssl1.1", "1.1.1n-0+deb11u1", "openssl")},
		"coreutils": {comp("coreutils", "8.32-4", "coreutils")},
	}

	findings := trackerFindings(parseFixture(t, "bullseye"), bySource)
	byID := map[string][]model.Finding{}
	for _, f := range findings {
		byID[f.ID] = append(byID[f.ID], f)
	}

	t.Run("one finding per binary package", func(t *testing.T) {
		if n := len(byID["CVE-2026-90001"]); n != 2 {
			t.Errorf("got %d findings for a source with two binaries, want 2", n)
		}
	})

	t.Run("a release behind unstable's fix is affected", func(t *testing.T) {
		// tar 1.34-1 installed, unstable fixed at 1.35-1.
		if len(byID["CVE-2026-90005"]) != 1 {
			t.Error("a package behind unstable's fix was not reported")
		}
		if f := byID["CVE-2026-90005"]; len(f) == 1 && f[0].FixedVersion != "" {
			t.Errorf("fixed version = %q, want empty: unstable's version is not installable here", f[0].FixedVersion)
		}
	})

	t.Run("a release already past unstable's fix is not", func(t *testing.T) {
		// tar 1.34-1 installed, unstable fixed at 1.30-1: the fix predates the
		// release, which is why most of the file is not a finding.
		if n := len(byID["CVE-2026-90006"]); n != 0 {
			t.Errorf("got %d findings for a CVE fixed before the release, want 0", n)
		}
	})

	t.Run("an advisory's fix silences a package that has it", func(t *testing.T) {
		// zlib1g is at 1:1.2.11.dfsg-2+deb11u1, exactly the DSA's version.
		// Without the advisory lists this compares against unstable's
		// 1:1.2.13-1 instead and reports a vulnerability that was fixed.
		if n := len(byID["CVE-2026-90007"]); n != 0 {
			t.Errorf("got %d findings for a CVE the installed version already fixes, want 0", n)
		}
	})

	t.Run("an advisory's fix is reported for a package behind it", func(t *testing.T) {
		// diffutils is at 1:3.7-5 and the DLA fixed 1:3.7-5+deb11u1.
		f := byID["CVE-2026-90008"]
		if len(f) != 1 {
			t.Fatalf("got %d findings, want 1", len(f))
		}
		if f[0].FixedVersion != "1:3.7-5+deb11u1" {
			t.Errorf("fixed version = %q, want the advisory's", f[0].FixedVersion)
		}
	})

	t.Run("every finding names the tracker as its source", func(t *testing.T) {
		for _, f := range findings {
			if f.Source != SourceDebianTracker {
				t.Errorf("%s: source = %q, want %q", f.ID, f.Source, SourceDebianTracker)
			}
		}
	})

	t.Run("severity is left unknown for the caller to fill", func(t *testing.T) {
		for _, f := range findings {
			if f.Severity != model.SeverityUnknown {
				t.Errorf("%s: severity = %q, want unknown", f.ID, f.Severity)
			}
		}
	})
}

// The fallback exists for one situation and must not fire outside it. A scan
// that reached for tens of megabytes on every supported Debian image would be a
// regression in the common case to fix the rare one.
func TestDebianFallbackTargets(t *testing.T) {
	comp := func(id, series, version string) model.Component {
		return model.Component{
			Name: "libssl1.1", Version: "1.1.1n", Source: "openssl",
			Confidence: model.ConfidenceHigh,
			DistroID:   id, Distro: series, DistroVersion: version,
		}
	}
	tests := []struct {
		name  string
		comps []model.Component
		want  string
	}{
		{
			name:  "a debian release past free support",
			comps: []model.Component{comp("debian", "bullseye", "11")},
			want:  "bullseye",
		},
		{
			name:  "a freely supported debian release is answered by OSV",
			comps: []model.Component{comp("debian", "bookworm", "12")},
			want:  "",
		},
		{
			// Ubuntu's extended tiers are in OSV under the Pro ecosystems, so
			// the answer for an Ubuntu image out of support is a different one.
			name:  "ubuntu is not this fallback's business",
			comps: []model.Component{comp("ubuntu", "bionic", "18.04")},
			want:  "",
		},
		{
			name:  "a derivative whose release is unknown",
			comps: []model.Component{comp("linuxmint", "vanessa", "21")},
			want:  "",
		},
		{
			name:  "an image with no release recorded",
			comps: []model.Component{comp("debian", "", "")},
			want:  "",
		},
		{
			name: "a heuristic component is not read for a release",
			comps: []model.Component{{
				Name: "busybox", Version: "1.30.1", Confidence: model.ConfidenceLow,
				DistroID: "debian", Distro: "bullseye",
			}},
			want: "",
		},
		{name: "no components at all", comps: nil, want: ""},
	}

	at := mustDay(t, "2026-09-03")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, sources, bySource := debianFallbackTargets(tt.comps, at)
			if got != tt.want {
				t.Fatalf("release = %q, want %q", got, tt.want)
			}
			if tt.want == "" {
				if len(sources) != 0 || len(bySource) != 0 {
					t.Error("no release to ask about, but packages were collected")
				}
				return
			}
			if !sources["openssl"] {
				t.Errorf("sources = %v, want the source package", slices.Sorted(maps.Keys(sources)))
			}
		})
	}
}

// The same image on either side of a date is a different answer, so the date is
// the thing being tested.
func TestFallbackTurnsOnWhenFreeSupportEnds(t *testing.T) {
	comps := []model.Component{{
		Name: "libssl1.1", Version: "1.1.1n", Source: "openssl",
		Confidence: model.ConfidenceHigh,
		DistroID:   "debian", Distro: "bullseye", DistroVersion: "11",
	}}
	if got, _, _ := debianFallbackTargets(comps, mustDay(t, "2026-08-31")); got != "" {
		t.Errorf("the fallback fired while bullseye was still freely supported: %q", got)
	}
	if got, _, _ := debianFallbackTargets(comps, mustDay(t, "2026-09-01")); got != "bullseye" {
		t.Errorf("the fallback did not fire the day after free support ended: %q", got)
	}
}

func mustDay(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		t.Fatalf("bad date %q: %v", s, err)
	}
	return d.UTC()
}

// The fallback end to end: a Debian release past free support, the tracker's
// three lists, and OSV consulted only for the severity of each CVE it names.
func TestMatchFallsBackToTheDebianTracker(t *testing.T) {
	var trackerHits, vulnHits int32

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		// OSV no longer carries this release, so it answers with nothing. That
		// is the situation, not a failure.
		_, _ = io.WriteString(w, `{"results":[{}]}`)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&vulnHits, 1)
		id := r.PathValue("id")
		if id != "CVE-2026-90001" {
			// Most CVEs the tracker names are not in OSV at all. A 404 here is
			// an ordinary answer and must not fail the scan.
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"id":"CVE-2026-90001","severity":[
			{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
	})
	for path, name := range map[string]string{
		"/tracker/CVE/list": "CVE-list",
		"/tracker/DSA/list": "DSA-list",
		"/tracker/DLA/list": "DLA-list",
	} {
		body := trackerFixture(t, name)
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&trackerHits, 1)
			_, _ = io.WriteString(w, body)
		})
	}

	server := httptest.NewServer(mux)
	defer server.Close()

	newMatcher := func(now string) *OSV {
		osv := NewOSV()
		osv.BaseURL = server.URL
		osv.HTTPClient = server.Client()
		osv.TrackerBase = server.URL + "/tracker/"
		osv.Now = func() time.Time { return mustDay(t, now) }
		return osv
	}

	comps := []model.Component{{
		Name: "zlib1g", Version: "1:1.2.11.dfsg-2", Arch: "arm64",
		Source: "zlib", SourceVersion: "1:1.2.11.dfsg-2",
		PURL:       "pkg:deb/debian/zlib@1:1.2.11.dfsg-2?arch=source&distro=bullseye",
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
		DistroID: "debian", Distro: "bullseye", DistroVersion: "11",
	}}

	t.Run("past free support the tracker answers", func(t *testing.T) {
		atomic.StoreInt32(&trackerHits, 0)
		findings, err := newMatcher("2026-09-03").Match(context.Background(), comps)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		if atomic.LoadInt32(&trackerHits) != 3 {
			t.Errorf("fetched %d tracker lists, want 3", trackerHits)
		}
		if len(findings) == 0 {
			t.Fatal("no findings from the tracker")
		}
		for _, f := range findings {
			if f.Source != SourceDebianTracker {
				t.Errorf("%s came from %q, want the tracker", f.ID, f.Source)
			}
		}
		// The one CVE the fake OSV scores, scored; the rest, which it answers
		// 404 for, left unknown rather than failing the scan.
		var scored, unknown int
		for _, f := range findings {
			if f.ID == "CVE-2026-90001" {
				scored++
				if f.Severity != model.SeverityCritical || f.CVSS != 9.8 {
					t.Errorf("severity = %s/%v, want critical/9.8", f.Severity, f.CVSS)
				}
			} else if f.Severity == model.SeverityUnknown {
				unknown++
			}
		}
		if scored == 0 {
			t.Error("the CVE OSV does score was not scored")
		}
		if unknown == 0 {
			t.Error("a CVE OSV has never heard of should be reported at unknown severity")
		}
	})

	t.Run("while freely supported the tracker is never fetched", func(t *testing.T) {
		atomic.StoreInt32(&trackerHits, 0)
		if _, err := newMatcher("2026-08-31").Match(context.Background(), comps); err != nil {
			t.Fatalf("Match: %v", err)
		}
		if got := atomic.LoadInt32(&trackerHits); got != 0 {
			t.Errorf("fetched the tracker %d times for a supported release, want 0", got)
		}
	})
}

// An unreachable tracker must fail the scan rather than pass silently: the
// whole point of the fallback is that OSV returned nothing, so a quiet failure
// here is an empty report that looks like a clean one.
func TestTrackerFailureIsNotSilent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{}]}`)
	})
	mux.HandleFunc("GET /tracker/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()
	osv.TrackerBase = server.URL + "/tracker/"
	osv.Now = func() time.Time { return mustDay(t, "2026-09-03") }

	_, err := osv.Match(context.Background(), []model.Component{{
		Name: "zlib1g", Version: "1:1.2.11.dfsg-2", Source: "zlib", SourceVersion: "1:1.2.11.dfsg-2",
		PURL:       "pkg:deb/debian/zlib@1:1.2.11.dfsg-2?arch=source&distro=bullseye",
		Confidence: model.ConfidenceHigh,
		DistroID:   "debian", Distro: "bullseye", DistroVersion: "11",
	}})
	if err == nil {
		t.Fatal("an unreachable tracker produced no error")
	}
	if !strings.Contains(err.Error(), "debian tracker") {
		t.Errorf("error = %q, want it to name the source", err)
	}
}

// The edges of the parser: input it should refuse, and input it should survive.
func TestParseDebianTrackerEdges(t *testing.T) {
	sources := map[string]bool{"zlib": true}

	t.Run("a line that is not a package line", func(t *testing.T) {
		entries, err := parseDebianTracker(strings.NewReader(
			"CVE-2026-90001 (desc)\n\tNOTE: https://example.invalid\n\t{DSA-1-1}\n\tRESERVED\n"),
			"bullseye", sources, advisoryFixes{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("got %d entries from a record with no package line", len(entries))
		}
	})

	t.Run("an indented line before any record", func(t *testing.T) {
		entries, err := parseDebianTracker(strings.NewReader(
			"\t- zlib <unfixed>\nCVE-2026-90001 (desc)\n\t- zlib <unfixed>\n"),
			"bullseye", sources, advisoryFixes{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(entries) != 1 {
			t.Errorf("got %d entries, want the one that follows a record header", len(entries))
		}
	})

	t.Run("a package line with no state at all", func(t *testing.T) {
		entries, err := parseDebianTracker(strings.NewReader(
			"CVE-2026-90001 (desc)\n\t- zlib\n"), "bullseye", sources, advisoryFixes{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		// A bare package name is not a version and not a marker; it is treated
		// as a version, which no installed package can be behind.
		if len(entries) == 1 && entries[0].fixedVersion != "" {
			t.Errorf("a bare package name became a fixed version: %q", entries[0].fixedVersion)
		}
	})

	t.Run("a line longer than the scanner will take", func(t *testing.T) {
		long := "CVE-2026-90001 (" + strings.Repeat("x", maxTrackerLine+1) + ")\n"
		_, err := parseDebianTracker(strings.NewReader(long), "bullseye", sources, advisoryFixes{})
		if err == nil {
			t.Error("an oversized line was accepted")
		}
	})

	t.Run("the unstable line cannot undo a release verdict that came first", func(t *testing.T) {
		// The file writes unstable first, but nothing in the format promises
		// it, and reversing the two must not change the answer.
		entries, err := parseDebianTracker(strings.NewReader(
			"CVE-2026-90001 (desc)\n\t[bullseye] - zlib <not-affected>\n\t- zlib <unfixed>\n"),
			"bullseye", sources, advisoryFixes{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("got %d entries; the release said not affected", len(entries))
		}
	})
}

func TestAdvisoryFixesKeepTheLowestVersion(t *testing.T) {
	fixes := advisoryFixes{}
	fixes.add("CVE-2026-90001", "zlib", "1:1.2.11.dfsg-2+deb11u3")
	fixes.add("CVE-2026-90001", "zlib", "1:1.2.11.dfsg-2+deb11u1")
	fixes.add("CVE-2026-90001", "zlib", "1:1.2.11.dfsg-2+deb11u2")
	// Two advisories can both carry a fix for one CVE. The earliest version
	// that has the patch is the one to name: sending somebody to a later
	// upload than they need is its own kind of wrong.
	if got := fixes["CVE-2026-90001"]["zlib"]; got != "1:1.2.11.dfsg-2+deb11u1" {
		t.Errorf("kept %q, want the lowest fix", got)
	}
	// A version neither parser can compare must not silently displace a good
	// one.
	fixes.add("CVE-2026-90001", "zlib", "not a version")
	if got := fixes["CVE-2026-90001"]["zlib"]; got != "1:1.2.11.dfsg-2+deb11u1" {
		t.Errorf("an unparseable version displaced the fix: %q", got)
	}
}

func TestFetchDebianTrackerRefusesNothingToDo(t *testing.T) {
	tests := []struct {
		name, base, release string
		sources             map[string]bool
	}{
		{name: "no base", base: "", release: "bullseye", sources: map[string]bool{"zlib": true}},
		{name: "no release", base: "http://127.0.0.1:0/", release: "", sources: map[string]bool{"zlib": true}},
		{name: "no packages", base: "http://127.0.0.1:0/", release: "bullseye", sources: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// None of these may make a request; the address would refuse one.
			entries, err := fetchDebianTracker(context.Background(), http.DefaultClient, tt.base, tt.release, tt.sources)
			if err != nil || entries != nil {
				t.Errorf("got %v, %v; want nothing attempted", entries, err)
			}
		})
	}
}
