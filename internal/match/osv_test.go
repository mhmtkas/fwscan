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
		resp.Results = make([]struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		}, len(req.Queries))
		for i, q := range req.Queries {
			resp.Results[i].Vulns = byPURL[q.Package.PURL].Vulns
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
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
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
