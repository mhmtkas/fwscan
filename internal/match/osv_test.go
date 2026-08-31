package match

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/catalog"
	"github.com/mhmtkas/fwscan/internal/model"
)

// newFakeOSV serves the recorded responses in testdata/osv. No test in this
// package reaches the network (CLAUDE.md rule 6).
func newFakeOSV(t *testing.T) *OSV {
	t.Helper()

	byPURL := map[string]struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}{}
	readFixture(t, "querybatch-by-purl.json", &byPURL)

	var vulns map[string]json.RawMessage
	readFixture(t, "vulns.json", &vulns)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var resp batchResponse
		resp.Results = make([]batchResult, len(req.Queries))
		for i, q := range req.Queries {
			resp.Results[i].Vulns = byPURL[fixtureKey(q)].Vulns
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := vulns[r.PathValue("id")]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()
	return osv
}

// fixtureKey mirrors how the recorded responses are keyed: by purl for the
// ecosystems OSV matches that way, and by ecosystem|name|version for the ones
// it does not.
func fixtureKey(q query) string {
	if q.Package.PURL != "" {
		return q.Package.PURL
	}
	return q.Package.Ecosystem + "|" + q.Package.Name + "|" + q.Version
}

func readFixture(t *testing.T, name string, into any) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "osv", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func debComponent(name, version, source, sourceVersion string) model.Component {
	return model.Component{
		Name: name, Version: version, Arch: "amd64",
		Source: source, SourceVersion: sourceVersion, Distro: "bullseye",
		// The purl is what tells the matcher which query shape to use, so a
		// component without one is never looked up.
		PURL:       catalog.BinaryPURL(name, version, "amd64", "bullseye"),
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
	}
}

func apkComponent(name, version, origin string) model.Component {
	return model.Component{
		Name: name, Version: version, Arch: "x86_64",
		Source: origin, SourceVersion: version, Distro: "v3.16",
		PURL:       catalog.ApkPURL(name, version, "x86_64", "v3.16"),
		Confidence: model.ConfidenceHigh, Evidence: catalog.ApkInstalledPath,
	}
}

func TestOSVMatch(t *testing.T) {
	osv := newFakeOSV(t)

	tests := []struct {
		name  string
		comps []model.Component
		check func(t *testing.T, findings []model.Finding)
	}{
		{
			name:  "true positive carries the release's fixed version",
			comps: []model.Component{debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1")},
			check: func(t *testing.T, findings []model.Finding) {
				f := findOne(t, findings, "CVE-2022-0778")
				if f.Severity != model.SeverityHigh {
					t.Errorf("severity = %q, want high", f.Severity)
				}
				if f.CVSS != 7.5 {
					t.Errorf("cvss = %v, want 7.5", f.CVSS)
				}
				if !strings.HasPrefix(f.CVSSVector, "CVSS:3.1/") {
					t.Errorf("vector = %q, want a v3.1 vector", f.CVSSVector)
				}
				// The DEBIAN- id stays reachable even though the CVE is shown.
				if !contains(f.Aliases, "DEBIAN-CVE-2022-0778") {
					t.Errorf("aliases = %v, want the OSV id kept", f.Aliases)
				}
				if f.Component.Name != "libssl1.1" {
					t.Errorf("finding attached to %q, want the binary package", f.Component.Name)
				}
			},
		},
		{
			name: "backported fix is not reported",
			// The upstream version is unchanged; only the Debian revision moved.
			// This is the false positive the whole design exists to avoid.
			comps: []model.Component{debComponent("libssl1.1", "1.1.1k-1+deb11u2", "openssl", "1.1.1k-1+deb11u2")},
			check: func(t *testing.T, findings []model.Finding) {
				if len(findings) != 0 {
					t.Errorf("got %d findings, want none: %+v", len(findings), findings)
				}
			},
		},
		{
			name:  "unknown package yields nothing",
			comps: []model.Component{debComponent("ghost", "1.0-1", "definitely-not-a-real-package", "1.0-1")},
			check: func(t *testing.T, findings []model.Finding) {
				if len(findings) != 0 {
					t.Errorf("got %d findings, want none", len(findings))
				}
			},
		},
		{
			name:  "per-release fixed version is selected",
			comps: []model.Component{debComponent("zlib1g", "1:1.2.11.dfsg-2", "zlib", "1:1.2.11.dfsg-2")},
			check: func(t *testing.T, findings []model.Finding) {
				f := findOne(t, findings, "CVE-2022-37434")
				// bullseye's fix, not bookworm's 1:1.2.11.dfsg-4.1.
				if f.FixedVersion != "1:1.2.11.dfsg-2+deb11u2" {
					t.Errorf("fixed version = %q, want bullseye's", f.FixedVersion)
				}
				if f.Severity != model.SeverityCritical || f.CVSS != 9.8 {
					t.Errorf("severity = %q score = %v, want critical 9.8", f.Severity, f.CVSS)
				}
			},
		},
		{
			name:  "textual ecosystem severity is honoured when there is no CVSS",
			comps: []model.Component{debComponent("zlib1g", "1:1.2.11.dfsg-2", "zlib", "1:1.2.11.dfsg-2")},
			check: func(t *testing.T, findings []model.Finding) {
				f := findOne(t, findings, "CVE-2099-0001")
				if f.Severity != model.SeverityMedium {
					t.Errorf("severity = %q, want medium from the textual level", f.Severity)
				}
				if f.CVSS != 0 || f.CVSSVector != "" {
					t.Errorf("score = %v vector = %q, want both empty on a non-CVSS path", f.CVSS, f.CVSSVector)
				}
			},
		},
		{
			name: "one lookup serves every binary sharing a source",
			comps: []model.Component{
				debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
				debComponent("openssl", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
			},
			check: func(t *testing.T, findings []model.Finding) {
				var names []string
				for _, f := range findings {
					if f.ID == "CVE-2022-0778" {
						names = append(names, f.Component.Name)
					}
				}
				if len(names) != 2 {
					t.Errorf("got the finding on %v, want it on both binaries", names)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := osv.Match(context.Background(), tt.comps)
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			tt.check(t, findings)
		})
	}
}

// A CVSS v4-only record has no v3 to fall back to, and output-spec section 1
// defines no v4 rule, so it lands on unknown. Recorded here so that a later
// decision to support v4 shows up as a deliberate change to this expectation
// rather than a silent one (spike/NOTES.md T0.3, open question 2).
func TestCVSSv4OnlyFallsThroughToUnknown(t *testing.T) {
	var vulns map[string]vulnRecord
	readFixture(t, "vulns.json", &vulns)

	record, ok := vulns["DEBIAN-CVE-2025-6141"]
	if !ok {
		t.Fatal("the v4-only fixture is missing")
	}
	if _, ok := vectorOfType(record, "CVSS_V4"); !ok {
		t.Fatal("fixture no longer carries a v4 vector")
	}
	severity, score, vector := severityOf(record)
	if severity != model.SeverityUnknown || score != 0 || vector != "" {
		t.Errorf("severityOf() = (%q, %v, %q), want unknown with no score", severity, score, vector)
	}
}

func TestNoSeverityIsUnknown(t *testing.T) {
	var vulns map[string]vulnRecord
	readFixture(t, "vulns.json", &vulns)

	severity, score, _ := severityOf(vulns["DEBIAN-CVE-2010-4756"])
	if severity != model.SeverityUnknown || score != 0 {
		t.Errorf("severityOf() = (%q, %v), want unknown with no score", severity, score)
	}
}

func TestMatchEmptyInput(t *testing.T) {
	osv := newFakeOSV(t)
	findings, err := osv.Match(context.Background(), nil)
	if err != nil || findings != nil {
		t.Errorf("Match(nil) = (%v, %v), want (nil, nil)", findings, err)
	}
	// Components with nothing to query are skipped rather than sent.
	findings, err = osv.Match(context.Background(), []model.Component{{Name: "", Version: ""}})
	if err != nil || len(findings) != 0 {
		t.Errorf("Match(empty component) = (%v, %v), want no findings", findings, err)
	}
}

func TestMatchContextCancellation(t *testing.T) {
	osv := newFakeOSV(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := osv.Match(ctx, []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
	})
	if err == nil {
		t.Fatal("Match() with a cancelled context returned no error")
	}
}

func TestMatchServerErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()

	_, err := osv.Match(context.Background(), []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
	})
	if err == nil {
		t.Fatal("Match() against a failing server returned no error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v, want it to mention the status", err)
	}
}

func TestMatchBatching(t *testing.T) {
	osv := newFakeOSV(t)
	osv.BatchSize = 1 // force several round trips

	comps := []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
		debComponent("zlib1g", "1:1.2.11.dfsg-2", "zlib", "1:1.2.11.dfsg-2"),
		debComponent("ghost", "1.0-1", "definitely-not-a-real-package", "1.0-1"),
	}
	findings, err := osv.Match(context.Background(), comps)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if len(findings) < 3 {
		t.Errorf("got %d findings across batches, want at least 3", len(findings))
	}
	// Findings arrive already sorted by the output spec's order.
	for i := 1; i < len(findings); i++ {
		if model.CompareFindings(findings[i-1], findings[i]) > 0 {
			t.Errorf("findings not sorted at index %d: %+v then %+v", i, findings[i-1], findings[i])
		}
	}
}

// A component with no Source falls back to its own name and version.
func TestKeyForFallsBackToBinary(t *testing.T) {
	key := keyFor(model.Component{Name: "busybox", Version: "1.30.1-6", Distro: "bullseye"})
	if key.source != "busybox" || key.version != "1.30.1-6" {
		t.Errorf("keyFor() = %+v, want the binary name and version", key)
	}
}

func findOne(t *testing.T, findings []model.Finding, id string) model.Finding {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s not present in %+v", id, findings)
	return model.Finding{}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// Debian and Alpine need different query shapes. Getting this wrong is silent:
// a purl query for Alpine returns nothing rather than an error, so an Alpine
// image would scan perfectly clean (spike/NOTES.md T0.3a).
func TestQueryShapePerEcosystem(t *testing.T) {
	tests := []struct {
		name          string
		component     model.Component
		wantOK        bool
		wantPURL      string
		wantName      string
		wantEcosystem string
		wantVersion   string
	}{
		{
			name:      "debian is queried by purl",
			component: debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
			wantOK:    true,
			wantPURL:  "pkg:deb/debian/openssl@1.1.1k-1%2Bdeb11u1?arch=source&distro=bullseye",
		},
		{
			name:          "alpine is queried by ecosystem",
			component:     apkComponent("libssl1.1", "1.1.1o-r0", "openssl"),
			wantOK:        true,
			wantName:      "openssl",
			wantEcosystem: "Alpine:v3.16",
			wantVersion:   "1.1.1o-r0",
		},
		{
			name: "alpine without a release cannot be queried",
			component: model.Component{
				Name: "openssl", Version: "1.1.1o-r0", Source: "openssl", SourceVersion: "1.1.1o-r0",
				PURL: "pkg:apk/alpine/openssl@1.1.1o-r0",
			},
			wantOK: false,
		},
		{
			name: "a heuristic component has no purl and is not queried",
			component: model.Component{
				Name: "busybox", Version: "1.30.1", Source: "busybox", SourceVersion: "1.30.1",
				Confidence: model.ConfidenceLow, Evidence: "bin/busybox",
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := queryFor(keyFor(tt.component))
			if ok != tt.wantOK {
				t.Fatalf("queryFor() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.Package.PURL != tt.wantPURL {
				t.Errorf("purl = %q, want %q", got.Package.PURL, tt.wantPURL)
			}
			if got.Package.Name != tt.wantName {
				t.Errorf("name = %q, want %q", got.Package.Name, tt.wantName)
			}
			if got.Package.Ecosystem != tt.wantEcosystem {
				t.Errorf("ecosystem = %q, want %q", got.Package.Ecosystem, tt.wantEcosystem)
			}
			if got.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", got.Version, tt.wantVersion)
			}
		})
	}
}

// The request must carry exactly one shape: a purl query with an empty name and
// ecosystem, or an ecosystem query with no purl. Sending both would be
// ambiguous.
func TestQueryOmitsUnusedFields(t *testing.T) {
	deb, _ := queryFor(keyFor(debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1")))
	body, err := json.Marshal(deb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), `"ecosystem"`) || strings.Contains(string(body), `"name"`) {
		t.Errorf("debian query carries ecosystem fields: %s", body)
	}

	apk, _ := queryFor(keyFor(apkComponent("libssl1.1", "1.1.1o-r0", "openssl")))
	body, err = json.Marshal(apk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), `"purl"`) {
		t.Errorf("alpine query carries a purl: %s", body)
	}
	if !strings.Contains(string(body), `"version":"1.1.1o-r0"`) {
		t.Errorf("alpine query missing the version: %s", body)
	}
}

// Alpine, end to end through the recorded responses.
func TestOSVMatchAlpine(t *testing.T) {
	osv := newFakeOSV(t)

	t.Run("fixed version comes from the right release", func(t *testing.T) {
		findings, err := osv.Match(context.Background(),
			[]model.Component{apkComponent("zlib", "1.2.12-r1", "zlib")})
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
		f := findOne(t, findings, "CVE-2022-37434")

		// The record lists a fixed version for every Alpine release from 3.11
		// to 3.24, and every one of those entries carries the *same* purl,
		// pkg:apk/alpine/zlib?arch=source. Only the ecosystem field tells them
		// apart. Picking the wrong entry yields 1.2.11-r4, which is older than
		// the installed 1.2.12-r1 -- a fix that reads as a downgrade.
		if f.FixedVersion != "1.2.12-r2" {
			t.Errorf("fixed version = %q, want 1.2.12-r2 (v3.16's)", f.FixedVersion)
		}
		if f.FixedVersion == "1.2.11-r4" {
			t.Error("picked v3.11's fix; affected entries are being matched by purl")
		}
	})

	t.Run("backported fix is not reported", func(t *testing.T) {
		findings, err := osv.Match(context.Background(),
			[]model.Component{apkComponent("libssl1.1", "1.1.1q-r0", "openssl")})
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
		if _, ok := findByIDForTest(findings, "CVE-2022-2097"); ok {
			t.Error("reported against the version that fixes it")
		}
	})

	t.Run("vulnerable version is reported on every binary sharing the origin", func(t *testing.T) {
		findings, err := osv.Match(context.Background(), []model.Component{
			apkComponent("libssl1.1", "1.1.1o-r0", "openssl"),
			apkComponent("libcrypto1.1", "1.1.1o-r0", "openssl"),
		})
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
		var names []string
		for _, f := range findings {
			if f.ID == "CVE-2022-2097" {
				names = append(names, f.Component.Name)
			}
		}
		if len(names) != 2 {
			t.Errorf("finding landed on %v, want both binaries", names)
		}
	})
}

// A reported fix that is older than what is installed is always wrong, whatever
// produced it.
func TestFixedVersionIsNeverOlderThanInstalled(t *testing.T) {
	osv := newFakeOSV(t)

	comps := []model.Component{
		apkComponent("zlib", "1.2.12-r1", "zlib"),
		apkComponent("libssl1.1", "1.1.1o-r0", "openssl"),
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
		debComponent("zlib1g", "1:1.2.11.dfsg-2", "zlib", "1:1.2.11.dfsg-2"),
	}
	findings, err := osv.Match(context.Background(), comps)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings to check")
	}
	for _, f := range findings {
		if f.FixedVersion == "" {
			continue
		}
		if versionLess(kindOf(f.Component), f.FixedVersion, f.Component.Version) {
			t.Errorf("%s on %s: fixed %q is older than installed %q",
				f.ID, f.Component.Name, f.FixedVersion, f.Component.Version)
		}
	}
}

func findByIDForTest(findings []model.Finding, id string) (model.Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

// The message a user sees when OSV cannot be reached has to point at the way
// out, which is the flag that finishes the scan without it.
func TestUnreachableMessageIsActionable(t *testing.T) {
	// A server that is closed before use gives a real dial failure.
	server := httptest.NewServer(http.NewServeMux())
	url := server.URL
	server.Close()

	osv := NewOSV()
	osv.BaseURL = url

	_, err := osv.Match(context.Background(), []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
	})
	if err == nil {
		t.Fatal("Match() against a dead server returned no error")
	}
	message := err.Error()
	for _, want := range []string{"cannot reach", "--no-network"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q does not mention %q", message, want)
		}
	}
	if first := message[:1]; first != strings.ToLower(first) {
		t.Errorf("message %q does not start lowercase", message)
	}
	if strings.Contains(message, "\n") {
		t.Errorf("message spans several lines: %q", message)
	}
}

// A non-200 is a different problem from an unreachable host and says so.
func TestServiceErrorMessageIsActionable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer server.Close()

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()

	_, err := osv.Match(context.Background(), []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
	})
	if err == nil {
		t.Fatal("Match() against a rate-limiting server returned no error")
	}
	for _, want := range []string{"429", "rate limiting", "--no-network"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not mention %q", err, want)
		}
	}
}

// A release with no fix of its own is still unfixed. Borrowing another
// release's fixed version tells the reader to install something that does not
// exist for them, which is worse than reporting no known fix.
func TestFixedVersionDoesNotBorrowAnotherRelease(t *testing.T) {
	record := vulnRecord{ID: "TEST-1", Affected: []affected{
		affectedEntry("Debian:12", "openssl", "pkg:deb/debian/openssl?arch=source&distro=bookworm", "3.0.11-1~deb12u2"),
		// bullseye is listed as affected but carries no fixed event.
		affectedEntry("Debian:11", "openssl", "pkg:deb/debian/openssl?arch=source&distro=bullseye", ""),
	}}
	key := queryKey{source: "openssl", version: "1.1.1k-1+deb11u1", distro: "bullseye", kind: kindDeb}

	if got := fixedVersion(record, key); got != "" {
		t.Errorf("fixedVersion() = %q, want empty; bullseye has no fix of its own", got)
	}

	// The release that does have one still reports it.
	key.distro = "bookworm"
	key.version = "3.0.0-1"
	if got := fixedVersion(record, key); got != "3.0.11-1~deb12u2" {
		t.Errorf("fixedVersion() = %q, want bookworm's own fix", got)
	}
}

// affectedEntry builds an affected entry; fixed may be empty for a release that
// is affected but unfixed.
func affectedEntry(ecosystem, name, purl, fixed string) affected {
	var a affected
	a.Package.Ecosystem = ecosystem
	a.Package.Name = name
	a.Package.PURL = purl

	var r struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
		} `json:"events"`
	}
	r.Type = "ECOSYSTEM"
	r.Events = append(r.Events, struct {
		Introduced string `json:"introduced"`
		Fixed      string `json:"fixed"`
	}{Introduced: "0"})
	if fixed != "" {
		r.Events = append(r.Events, struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
		}{Fixed: fixed})
	}
	a.Ranges = append(a.Ranges, r)
	return a
}

// A paginated result means the answer is incomplete. Reporting it as if it were
// whole is the one outcome a vulnerability scanner must never produce.
func TestPaginatedResultIsRefused(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, batchResponse{Results: []batchResult{{
			Vulns: []struct {
				ID string `json:"id"`
			}{{ID: "DEBIAN-CVE-2022-0778"}},
			NextPageToken: "there-is-more",
		}}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()

	_, err := osv.Match(context.Background(), []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
	})
	if err == nil {
		t.Fatal("a paginated result was accepted as complete")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error = %v, want it to say the report would be incomplete", err)
	}
}

// output-spec section 3 requires cvss_vector to be empty whenever the severity
// did not come from CVSS. A vector that parses but scores exactly 0 falls
// outside every band in section 1, so it must not leave a vector behind.
func TestZeroScoringVectorLeavesNoVector(t *testing.T) {
	record := vulnRecord{Severity: []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}

	severity, score, vector := severityOf(record)
	if severity != model.SeverityUnknown {
		t.Errorf("severity = %q, want unknown", severity)
	}
	if score != 0 || vector != "" {
		t.Errorf("score = %v vector = %q, want both empty on a non-CVSS outcome", score, vector)
	}
}

// The bands in output-spec section 1, at their exact edges.
func TestSeverityBucketBoundaries(t *testing.T) {
	v3 := []struct {
		score float64
		want  model.Severity
	}{
		{10.0, model.SeverityCritical}, {9.0, model.SeverityCritical},
		{8.9, model.SeverityHigh}, {7.0, model.SeverityHigh},
		{6.9, model.SeverityMedium}, {4.0, model.SeverityMedium},
		{3.9, model.SeverityLow}, {0.1, model.SeverityLow},
		{0.0, model.SeverityUnknown},
	}
	for _, tt := range v3 {
		if got := bucketFromV3Score(tt.score); got != tt.want {
			t.Errorf("bucketFromV3Score(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}

	// v2 has no critical band.
	v2 := []struct {
		score float64
		want  model.Severity
	}{
		{10.0, model.SeverityHigh}, {7.0, model.SeverityHigh},
		{6.9, model.SeverityMedium}, {4.0, model.SeverityMedium},
		{3.9, model.SeverityLow}, {0.0, model.SeverityLow},
	}
	for _, tt := range v2 {
		if got := bucketFromV2Score(tt.score); got != tt.want {
			t.Errorf("bucketFromV2Score(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
