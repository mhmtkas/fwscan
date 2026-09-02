package match

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mhmtkas/fwscan/internal/catalog"
	"github.com/mhmtkas/fwscan/internal/model"
	"github.com/mhmtkas/fwscan/internal/purl"
)

// newFakeOSV serves the recorded responses in testdata/osv. No test in this
// package reaches the network (CLAUDE.md rule 6).
func newFakeOSV(t *testing.T) *OSV {
	t.Helper()
	batch, vuln := fakeOSVHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", batch)
	mux.HandleFunc("GET /v1/vulns/{id}", vuln)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()
	return osv
}

// fakeOSVHandlers serves the recorded responses. It is separate from
// newFakeOSV so a test can wrap either handler -- to count requests, or to
// interfere partway through -- without restating how the fixtures are keyed.
func fakeOSVHandlers(t *testing.T) (batch, vuln http.HandlerFunc) {
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

	return func(w http.ResponseWriter, r *http.Request) {
			mux.ServeHTTP(w, r)
		}, func(w http.ResponseWriter, r *http.Request) {
			mux.ServeHTTP(w, r)
		}
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
		PURL:       purl.Binary(name, version, "amd64", "bullseye"),
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
	}
}

func apkComponent(name, version, origin string) model.Component {
	return model.Component{
		Name: name, Version: version, Arch: "x86_64",
		Source: origin, SourceVersion: version, Distro: "v3.16",
		PURL:       purl.Apk(name, version, "x86_64", "v3.16"),
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

// A CVSS v4-only record is scored from its v4 vector. It used to fall through
// to unknown, which kept a growing share of recent CVEs out of --fail-on's
// reach; output-spec section 1 now carries a v4 rule (spike/NOTES.md T0.3,
// question 2). The vector is a real one from Debian's OSV data, trailing X
// metrics and all.
func TestCVSSv4OnlyIsScored(t *testing.T) {
	var vulns map[string]vulnRecord
	readFixture(t, "vulns.json", &vulns)

	record, ok := vulns["DEBIAN-CVE-2025-6141"]
	if !ok {
		t.Fatal("the v4-only fixture is missing")
	}
	if _, ok := vectorOfType(record, "CVSS_V4"); !ok {
		t.Fatal("fixture no longer carries a v4 vector")
	}
	if _, ok := vectorOfType(record, "CVSS_V3"); ok {
		t.Fatal("fixture gained a v3 vector, so it no longer tests the v4 path")
	}

	severity, score, vector := severityOf(record)
	if severity != model.SeverityMedium || score != 4.8 {
		t.Errorf("severityOf() = (%q, %v), want (medium, 4.8)", severity, score)
	}
	if !strings.HasPrefix(vector, "CVSS:4.0/") {
		t.Errorf("vector = %q, want the v4 vector it was scored from", vector)
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
	// The error says what happened. It used to be wrapped as a transport
	// failure, and told whoever pressed Ctrl-C to check their network.
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not wrap context.Canceled", err)
	}
	if strings.Contains(err.Error(), "check the network") {
		t.Errorf("a cancellation is reported as a network failure: %v", err)
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
	record := vulnRecord{Severity: []severityEntry{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
	}}

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
		if got := bucketFromCVSSScore(tt.score); got != tt.want {
			t.Errorf("bucketFromCVSSScore(%v) = %q, want %q", tt.score, got, tt.want)
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

// A cancellation arriving after the batch query has succeeded must not be able
// to produce a short report. The producer used to skip the id it was holding
// and try the next one, so a cancellation dropped every id that remained; with
// no worker having failed there was no error either, and the scan reported
// fewer vulnerabilities than it had found without a word about it.
//
// The cancellation is timed differently on each run so that more than one
// interleaving is covered: before any record is fetched, and between two of
// them.
func TestCancellationNeverProducesAShortReport(t *testing.T) {
	// zlib is the fixture entry OSV answers with several records, and the
	// Alpine packages add ids of their own: the more records a scan fetches,
	// the more a dropped id has to lose.
	components := []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
		debComponent("zlib1g", "1:1.2.11.dfsg-2", "zlib", "1:1.2.11.dfsg-2"),
		apkComponent("libssl1.1", "1.1.1n-r0", "openssl"),
		apkComponent("zlib", "1.2.12-r1", "zlib"),
	}

	whole, err := newFakeOSV(t).Match(context.Background(), components)
	if err != nil {
		t.Fatalf("baseline Match() error = %v", err)
	}
	if len(whole) < 2 {
		t.Fatalf("the fixture yields %d findings; the case needs several to have any to drop", len(whole))
	}

	for run := range 40 {
		t.Run(fmt.Sprintf("cancel-at-%d", run), func(t *testing.T) {
			batch, vuln := fakeOSVHandlers(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var fetched atomic.Int64
			mux := http.NewServeMux()
			mux.HandleFunc("POST /v1/querybatch", batch)
			mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
				if fetched.Add(1) == int64(run%6)+1 {
					cancel()
				}
				vuln(w, r)
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			osv := NewOSV()
			osv.BaseURL = server.URL
			osv.HTTPClient = server.Client()
			osv.Concurrency = 1

			findings, err := osv.Match(ctx, components)
			if err != nil {
				return // refusing to answer is the correct outcome
			}
			if len(findings) != len(whole) {
				t.Fatalf("Match() returned %d findings and no error, want %d: "+
					"a cancelled scan must fail rather than under-report",
					len(findings), len(whole))
			}
		})
	}
}

// The same invariant, asserted directly on the fetch rather than through a
// timing window: whatever a cancelled context does to the work loop, a short
// map must never come back paired with a nil error.
func TestFetchVulnsRefusesToReturnAShortMap(t *testing.T) {
	osv := newFakeOSV(t)
	osv.Concurrency = 1

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ids := []string{
		"DEBIAN-CVE-2022-0778", "DEBIAN-CVE-2022-37434", "DSA-5218-1",
		"ALPINE-CVE-2022-2097", "ALPINE-CVE-2022-37434",
	}
	records, err := osv.fetchVulns(ctx, ids)
	if err == nil && len(records) != len(ids) {
		t.Fatalf("fetchVulns returned %d of %d records and no error", len(records), len(ids))
	}
}

// A fix older than what is installed is never an answer. It reads as an
// instruction to downgrade, and the version it names is one the reader already
// passed.
//
// The existing property test asserts this over the committed fixture, which
// happens not to contain a record shaped this way; this one builds the shape.
func TestFixedVersionRefusesToNameAnOlderVersion(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "DEBIAN-CVE-2024-0002",
	  "affected": [{
	    "package": {"ecosystem": "Debian:11", "name": "demo",
	                "purl": "pkg:deb/debian/demo?arch=source&distro=bullseye"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.9"}]}]
	  }]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	key := queryKey{source: "demo", version: "1.0", distro: "bullseye", kind: kindDeb}
	if got := fixedVersion(record, key); got != "" {
		t.Errorf("fixedVersion = %q, want none: 0.9 is older than the installed 1.0", got)
	}
}

// The fallback exists for versions that cannot be ordered at all -- an
// ecosystem with no comparison of its own -- and that case must keep working,
// or the fix above would be a silent loss of the FIXED column everywhere the
// ordering is unknown.
func TestFixedVersionStillAnswersWhenOrderingIsUnknown(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "OSV-2024-0003",
	  "affected": [{
	    "package": {"ecosystem": "Whatever", "name": "demo"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2024-07-01"}]}]
	  }]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	key := queryKey{source: "demo", version: "2024-01-01", kind: kindUnknown}
	if got := fixedVersion(record, key); got != "2024-07-01" {
		t.Errorf("fixedVersion = %q, want 2024-07-01", got)
	}
}

// bullseye and bullseye-backports are different releases with different fixed
// versions. Searching the purl for "distro=bullseye" reads the first out of the
// second, and the result is a plausible-looking wrong version in the FIXED
// column -- the exact confusion the release qualifier exists to prevent.
func TestReleaseMatchingIsNotASubstringSearch(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "DEBIAN-CVE-2024-0004",
	  "affected": [{
	    "package": {"ecosystem": "Debian:11", "name": "demo",
	                "purl": "pkg:deb/debian/demo?arch=source&distro=bullseye-backports"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]
	  }]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	key := queryKey{source: "demo", version: "1.0", distro: "bullseye", kind: kindDeb}
	if got := fixedVersion(record, key); got != "" {
		t.Errorf("fixedVersion = %q, want none: 9.9 is the backports fix, not bullseye's", got)
	}

	// And the release it does name still matches.
	key.distro = "bullseye-backports"
	if got := fixedVersion(record, key); got != "9.9" {
		t.Errorf("fixedVersion = %q, want 9.9 for the release the entry actually names", got)
	}
}

// output-spec section 1 asks for the range whose introduced-to-fixed window
// contains the installed version. Only the upper bound used to be tested, so a
// record listing a window the installed version sits *below* answered with that
// window's fix instead of the one it belongs to.
func TestFixedVersionPrefersTheWindowThatContainsTheVersion(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "DEBIAN-CVE-2024-0005",
	  "affected": [{
	    "package": {"ecosystem": "Debian:11", "name": "demo",
	                "purl": "pkg:deb/debian/demo?arch=source&distro=bullseye"},
	    "ranges": [
	      {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.5"}]},
	      {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}
	    ]
	  }]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	// 1.0 is below the first window entirely; it belongs to the second.
	key := queryKey{source: "demo", version: "1.0", distro: "bullseye", kind: kindDeb}
	if got := fixedVersion(record, key); got != "9.9" {
		t.Errorf("fixedVersion = %q, want 9.9: 1.0 is not inside [2.0, 2.5)", got)
	}

	// And a version that is inside the first window still gets the first fix.
	key.version = "2.2"
	if got := fixedVersion(record, key); got != "2.5" {
		t.Errorf("fixedVersion = %q, want 2.5: 2.2 is inside [2.0, 2.5)", got)
	}
}

// A GIT range's events are commit hashes, not versions. Reporting one in the
// FIXED column tells the reader to install a commit.
func TestFixedVersionIgnoresGitRanges(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "DEBIAN-CVE-2024-0006",
	  "affected": [{
	    "package": {"ecosystem": "Debian:11", "name": "demo",
	                "purl": "pkg:deb/debian/demo?arch=source&distro=bullseye"},
	    "ranges": [
	      {"type": "GIT", "events": [{"introduced": "0"},
	        {"fixed": "9f8a3c2b1d0e4f5a6b7c8d9e0f1a2b3c4d5e6f70"}]}
	    ]
	  }]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	key := queryKey{source: "demo", version: "1.0", distro: "bullseye", kind: kindDeb}
	if got := fixedVersion(record, key); got != "" {
		t.Errorf("fixedVersion = %q, want none: that is a commit hash, not a version", got)
	}
}

// For an oldstable Debian release, OSV returns only DSA and DLA advisories: the
// per-CVE records that carry vectors and release-scoped fixes exist but list
// only newer releases (spike/NOTES.md T18a). An advisory names its release in
// the ecosystem field rather than in the purl, which carries no distro
// qualifier because one advisory covers several releases.
func TestAdvisoryFixIsMatchedByEcosystem(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "DSA-5514-1",
	  "upstream": ["CVE-2023-4911", "DEBIAN-CVE-2023-4911"],
	  "affected": [
	    {"package": {"ecosystem": "Debian:11", "name": "glibc",
	                 "purl": "pkg:deb/debian/glibc?arch=source"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31-13+deb11u7"}]}]},
	    {"package": {"ecosystem": "Debian:12", "name": "glibc",
	                 "purl": "pkg:deb/debian/glibc?arch=source"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.36-9+deb12u3"}]}]}
	  ]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	key := queryKey{
		source: "glibc", version: "2.31-13+deb11u2",
		distro: "bullseye", release: "11", kind: kindDeb,
	}
	if got := fixedVersion(record, key); got != "2.31-13+deb11u7" {
		t.Errorf("fixedVersion = %q, want 2.31-13+deb11u7", got)
	}

	// The neighbouring release's fix is not borrowed.
	key.release, key.distro = "12", "bookworm"
	if got := fixedVersion(record, key); got != "2.36-9+deb12u3" {
		t.Errorf("fixedVersion = %q, want the bookworm fix", got)
	}

	// An image that does not say which release it is gets no answer rather than
	// an arbitrary one.
	key.release = ""
	if got := fixedVersion(record, key); got != "" {
		t.Errorf("fixedVersion = %q, want none when the release is unknown", got)
	}
}

// A release can carry more than one advisory for the same issue: Debian's
// DLA-3942-1 fixed openssl at 1.1.1n-0+deb11u6 and DLA-3942-2 shipped again at
// 1.1.1w-0+deb11u2. Both are true, so which one is reported must not depend on
// the order OSV happened to return them in.
func TestTheLowestFixWins(t *testing.T) {
	const first, second = "1.1.1n-0+deb11u6", "1.1.1w-0+deb11u2"

	build := func(a, b string) vulnRecord {
		var record vulnRecord
		body := `{"id":"DLA-3942-1","affected":[
		  {"package":{"ecosystem":"Debian:11","name":"openssl","purl":"pkg:deb/debian/openssl?arch=source"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + a + `"}]}]},
		  {"package":{"ecosystem":"Debian:11","name":"openssl","purl":"pkg:deb/debian/openssl?arch=source"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + b + `"}]}]}
		]}`
		if err := json.Unmarshal([]byte(body), &record); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		return record
	}

	key := queryKey{
		source: "openssl", version: "1.1.1k-1+deb11u1",
		distro: "bullseye", release: "11", kind: kindDeb,
	}
	for _, order := range [][2]string{{first, second}, {second, first}} {
		if got := fixedVersion(build(order[0], order[1]), key); got != first {
			t.Errorf("fixedVersion with %v = %q, want the lower fix %q", order, got, first)
		}
	}
}

// An advisory carries no severity of its own, and on an oldstable image
// advisories are all there is -- so every finding reported as unknown, and
// --fail-on could not fire at all. The vector is one hop away, in the record the
// advisory names as upstream.
func TestSeverityIsBorrowedFromTheUpstreamRecord(t *testing.T) {
	const (
		advisory = "DSA-5514-1"
		upstream = "DEBIAN-CVE-2023-4911"
		vector   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
	)

	records := map[string]string{
		advisory: `{"id":"` + advisory + `","upstream":["CVE-2023-4911","` + upstream + `"],
		  "affected":[{"package":{"ecosystem":"Debian:11","name":"glibc","purl":"pkg:deb/debian/glibc?arch=source"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.31-13+deb11u7"}]}]}]}`,
		// The per-CVE record: it has the vector, and no Debian 11 entry at all,
		// which is exactly why the advisory is the only thing the query finds.
		upstream: `{"id":"` + upstream + `","upstream":["CVE-2023-4911"],
		  "severity":[{"type":"CVSS_V3","score":"` + vector + `"}],
		  "affected":[{"package":{"ecosystem":"Debian:12","name":"glibc","purl":"pkg:deb/debian/glibc?arch=source&distro=bookworm"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.36-9+deb12u3"}]}]}]}`,
	}

	var upstreamFetches atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, batchResponse{Results: []batchResult{{
			Vulns: []struct {
				ID string `json:"id"`
			}{{ID: advisory}},
		}}})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == upstream {
			upstreamFetches.Add(1)
		}
		body, ok := records[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()

	component := model.Component{
		Name: "libc6", Version: "2.31-13+deb11u2",
		Source: "glibc", SourceVersion: "2.31-13+deb11u2",
		Distro: "bullseye", DistroVersion: "11",
		PURL:       purl.Binary("libc6", "2.31-13+deb11u2", "arm64", "bullseye"),
		Confidence: model.ConfidenceHigh, Evidence: catalog.DpkgStatusPath,
	}

	findings, err := osv.Match(context.Background(), []model.Component{component})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	got := findings[0]
	if got.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high: the advisory's own record carries none", got.Severity)
	}
	if got.CVSS != 7.8 || got.CVSSVector != vector {
		t.Errorf("score/vector = %v/%q, want 7.8 and the borrowed vector", got.CVSS, got.CVSSVector)
	}
	if got.FixedVersion != "2.31-13+deb11u7" {
		t.Errorf("fixed_version = %q, want 2.31-13+deb11u7", got.FixedVersion)
	}
	if n := upstreamFetches.Load(); n != 1 {
		t.Errorf("the upstream record was fetched %d times, want once", n)
	}
}

// Borrowing is an improvement, not a requirement: a scan must not fail because
// the record an advisory names cannot be fetched.
func TestABrokenUpstreamFetchIsNotFatal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, batchResponse{Results: []batchResult{{
			Vulns: []struct {
				ID string `json:"id"`
			}{{ID: "DSA-1-1"}},
		}}})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "DSA-1-1" {
			http.Error(w, "gone", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"DSA-1-1","upstream":["DEBIAN-CVE-2023-4911"],
		  "affected":[{"package":{"ecosystem":"Debian:11","name":"glibc","purl":"pkg:deb/debian/glibc?arch=source"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.31-13+deb11u7"}]}]}]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()

	findings, err := osv.Match(context.Background(), []model.Component{{
		Name: "libc6", Version: "2.31-13+deb11u2",
		Source: "glibc", SourceVersion: "2.31-13+deb11u2",
		Distro: "bullseye", DistroVersion: "11",
		PURL:       purl.Binary("libc6", "2.31-13+deb11u2", "arm64", "bullseye"),
		Confidence: model.ConfidenceHigh, Evidence: catalog.DpkgStatusPath,
	}})
	if err != nil {
		t.Fatalf("Match() error = %v; a failed borrow must not fail the scan", err)
	}
	if len(findings) != 1 || findings[0].Severity != model.SeverityUnknown {
		t.Fatalf("got %+v, want one finding left at unknown", findings)
	}
	if findings[0].FixedVersion != "2.31-13+deb11u7" {
		t.Errorf("fixed_version = %q, want the advisory's own answer to survive", findings[0].FixedVersion)
	}
}

// A scanner reading an answer it will act on should not follow a redirect to
// somewhere else, and on a POST the body travels with it. The default policy
// would.
func TestRedirectsToAnotherHostAreRefused(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, batchResponse{Results: []batchResult{{}}})
	}))
	defer elsewhere.Close()

	var agents []string
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.Header.Get("User-Agent"))
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	osv := NewOSV()
	osv.BaseURL = redirector.URL
	// The client is the test's, but with no policy of its own, so the package
	// supplies one.
	osv.HTTPClient = redirector.Client()

	_, err := osv.Match(context.Background(), []model.Component{
		debComponent("libssl1.1", "1.1.1k-1+deb11u1", "openssl", "1.1.1k-1+deb11u1"),
	})
	if err == nil {
		t.Fatal("a redirect to another host was followed")
	}
	if !strings.Contains(err.Error(), "refusing a redirect") {
		t.Errorf("error = %v, want it to name the refused redirect", err)
	}

	// And the request said who it was.
	if len(agents) == 0 || !strings.HasPrefix(agents[0], "fwscan") {
		t.Errorf("user agent = %q, want fwscan to identify itself", agents)
	}
}

// A DSA or DLA advisory names every CVE the upload fixed, and one upload
// routinely fixes several. That is several vulnerabilities, each with an
// assessment of its own, and output-spec section 1 asks for one finding per
// vulnerability. Reported as one finding under the first CVE's name, the rest
// sat inside aliases -- where a 9.1 critical could hide under a 5.3 medium and
// never reach --fail-on.
func TestAnAdvisoryNamingSeveralCVEsIsSeveralFindings(t *testing.T) {
	var record vulnRecord
	if err := json.Unmarshal([]byte(`{
	  "id": "DLA-9999-1",
	  "upstream": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003",
	               "DEBIAN-CVE-2024-0001", "DEBIAN-CVE-2024-0002", "DEBIAN-CVE-2024-0003"],
	  "affected": [{"package": {"ecosystem": "Debian:11", "name": "demo",
	                            "purl": "pkg:deb/debian/demo?arch=source"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0-1"}]}]}]
	}`), &record); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	got := identities(record)
	if len(got) != 3 {
		t.Fatalf("got %d identities, want 3: %+v", len(got), got)
	}
	for i, want := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		ident := got[i]
		if ident.id != want {
			t.Errorf("identity %d = %q, want %q", i, ident.id, want)
		}
		// The advisory and the database's own record for this CVE are its
		// names. The sibling CVEs are not: they are other vulnerabilities.
		wantAliases := []string{"DLA-9999-1", "DEBIAN-" + want}
		if !slices.Equal(ident.aliases, wantAliases) {
			t.Errorf("aliases of %s = %v, want %v", want, ident.aliases, wantAliases)
		}
		if ident.borrowFrom != "DEBIAN-"+want {
			t.Errorf("%s borrows from %q, want its own record", want, ident.borrowFrom)
		}
	}

	// And a record that names one CVE is one identity, exactly as before.
	single := vulnRecord{ID: "DEBIAN-CVE-2022-0778", Upstream: []string{"CVE-2022-0778"}}
	got = identities(single)
	if len(got) != 1 || got[0].id != "CVE-2022-0778" ||
		!slices.Equal(got[0].aliases, []string{"DEBIAN-CVE-2022-0778"}) || got[0].borrowFrom != "" {
		t.Errorf("single-CVE identity = %+v", got)
	}

	// A record naming no CVE at all is its own identity.
	bare := vulnRecord{ID: "GHSA-xxxx", Aliases: []string{"OTHER-1"}}
	got = identities(bare)
	if len(got) != 1 || got[0].id != "GHSA-xxxx" || !slices.Equal(got[0].aliases, []string{"OTHER-1"}) {
		t.Errorf("bare identity = %+v", got)
	}
}

// Through Match: each expanded finding carries the vector of its own CVE, and
// where the database's own record for one of them also came back from the
// query, the two merge into one finding rather than two rows.
func TestExpandedFindingsCarryTheirOwnAssessments(t *testing.T) {
	records := map[string]string{
		"DLA-9999-1": `{"id":"DLA-9999-1",
		  "upstream":["CVE-2024-0001","CVE-2024-0002","DEBIAN-CVE-2024-0001","DEBIAN-CVE-2024-0002"],
		  "affected":[{"package":{"ecosystem":"Debian:11","name":"demo","purl":"pkg:deb/debian/demo?arch=source"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]}]}`,
		// Critical, and only reachable by borrowing.
		"DEBIAN-CVE-2024-0001": `{"id":"DEBIAN-CVE-2024-0001","upstream":["CVE-2024-0001"],
		  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
		  "affected":[{"package":{"ecosystem":"Debian:12","name":"demo","purl":"pkg:deb/debian/demo?arch=source&distro=bookworm"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0-1"}]}]}]}`,
		// Low, and also returned by the query in its own right, so it merges.
		"DEBIAN-CVE-2024-0002": `{"id":"DEBIAN-CVE-2024-0002","upstream":["CVE-2024-0002"],
		  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}],
		  "affected":[{"package":{"ecosystem":"Debian:11","name":"demo","purl":"pkg:deb/debian/demo?arch=source&distro=bullseye"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.5-1"}]}]}]}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, batchResponse{Results: []batchResult{{
			Vulns: []struct {
				ID string `json:"id"`
			}{{ID: "DLA-9999-1"}, {ID: "DEBIAN-CVE-2024-0002"}},
		}}})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := records[r.PathValue("id")]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	osv := NewOSV()
	osv.BaseURL = server.URL
	osv.HTTPClient = server.Client()

	findings, err := osv.Match(context.Background(), []model.Component{{
		Name: "demo", Version: "1.0-1", Source: "demo", SourceVersion: "1.0-1",
		Distro: "bullseye", DistroVersion: "11",
		PURL:       purl.Binary("demo", "1.0-1", "arm64", "bullseye"),
		Confidence: model.ConfidenceHigh, Evidence: catalog.DpkgStatusPath,
	}})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per CVE, the duplicate merged): %+v", len(findings), findings)
	}

	first := findings[0]
	if first.ID != "CVE-2024-0001" || first.Severity != model.SeverityCritical || first.CVSS != 9.8 {
		t.Errorf("first = %s %s %.1f, want CVE-2024-0001 critical 9.8 borrowed from its own record", first.ID, first.Severity, first.CVSS)
	}
	if first.FixedVersion != "2.0-1" {
		t.Errorf("first fixed = %q, want the advisory's 2.0-1 (the CVE record has no bullseye entry)", first.FixedVersion)
	}
	if slices.Contains(first.Aliases, "CVE-2024-0002") {
		t.Errorf("CVE-2024-0002 listed as an alias of CVE-2024-0001; they are different vulnerabilities")
	}

	second := findings[1]
	if second.ID != "CVE-2024-0002" || second.Severity != model.SeverityLow {
		t.Errorf("second = %s %s, want CVE-2024-0002 low", second.ID, second.Severity)
	}
	// Merged: the advisory's fix (2.0-1) and the record's own (1.5-1) -- the
	// lower wins -- and both record ids survive as aliases.
	if second.FixedVersion != "1.5-1" {
		t.Errorf("second fixed = %q, want 1.5-1", second.FixedVersion)
	}
	for _, want := range []string{"DLA-9999-1", "DEBIAN-CVE-2024-0002"} {
		if !slices.Contains(second.Aliases, want) {
			t.Errorf("aliases of CVE-2024-0002 = %v, missing %s", second.Aliases, want)
		}
	}
}

// A vector that scores 0.0 is no assessment on any path. v3 already fell
// through; v2 reported low with a score of 0 and the vector attached, which
// the terminal rendered as "low  —" and the JSON as a score nothing supports.
func TestZeroScoringV2VectorIsNoAssessment(t *testing.T) {
	record := vulnRecord{Severity: []severityEntry{
		{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:N/I:N/A:N"},
	}}
	severity, score, vector := severityOf(record)
	if severity != model.SeverityUnknown || score != 0 || vector != "" {
		t.Errorf("severityOf = %q, %v, %q; want unknown with nothing attached", severity, score, vector)
	}
}

// OSV is trusted, but a client that follows any number of ids into any number
// of detail fetches is one a compromised or impersonated service could point
// at a million requests. Both the per-package and per-scan counts are capped.
func TestHostileRecordCountsAreRefused(t *testing.T) {
	ids := make([]struct {
		ID string `json:"id"`
	}, maxVulnsPerPackage+1)
	for i := range ids {
		ids[i].ID = fmt.Sprintf("DEBIAN-CVE-2024-%06d", i)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, batchResponse{Results: []batchResult{{Vulns: ids}}})
	})
	var fetched atomic.Int64
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, _ *http.Request) {
		fetched.Add(1)
		http.Error(w, "should not be reached", http.StatusInternalServerError)
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
		t.Fatal("a response naming more records than the cap was followed")
	}
	if n := fetched.Load(); n != 0 {
		t.Errorf("%d detail fetches were made before the cap fired", n)
	}
}

// A record's upstream and alias lists are read once each, up to a bound. The
// largest real advisory names a few dozen CVEs; a hostile record can name a
// million, and matching every CVE against every name was quadratic.
func TestIdentitiesReadNamesOnceUpToTheBound(t *testing.T) {
	record := vulnRecord{ID: "DLA-1-1"}
	for i := range maxNamesPerRecord * 3 {
		record.Upstream = append(record.Upstream, fmt.Sprintf("CVE-2024-%06d", i))
	}
	got := identities(record)
	if len(got) != maxNamesPerRecord {
		t.Errorf("got %d identities, want the bound of %d", len(got), maxNamesPerRecord)
	}
	// Order is preserved, so the first names win rather than a random subset.
	if got[0].id != "CVE-2024-000000" || got[len(got)-1].id != fmt.Sprintf("CVE-2024-%06d", maxNamesPerRecord-1) {
		t.Errorf("first/last = %s/%s", got[0].id, got[len(got)-1].id)
	}
}
