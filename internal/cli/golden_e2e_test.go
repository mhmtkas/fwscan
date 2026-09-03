package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/mhmtkas/fwscan/internal/match"
)

var updateGolden = flag.Bool("update-e2e", false, "rewrite the end-to-end golden files")

// The report goldens in internal/report are rendered from structs written by
// hand. They test the renderer, which is worth testing, but nothing between the
// image and the renderer: identifier derivation, the collapse rule, severity
// mapping and the choice of fixed version all sit outside a byte-for-byte
// comparison, and every one of them has had a defect that a golden would have
// shown.
//
// This runs the pipeline the user runs -- the committed fixture image through
// input, catalog, the real matcher against the recorded OSV responses, and out
// to both reports -- and compares the result byte for byte. Only the two fields
// that cannot repeat are normalised.
func TestEndToEndAgainstRecordedResponses(t *testing.T) {
	server := recordedOSV(t)

	previous := newMatcher
	newMatcher = func() match.Matcher {
		osv := match.NewOSV()
		osv.BaseURL = server.URL
		osv.HTTPClient = server.Client()
		// The fixture is a bullseye rootfs, and bullseye left free support on
		// 2026-08-31, after which the matcher falls back to the Debian security
		// tracker. Two things follow. The clock is frozen to the golden's own
		// scan date, so this file does not change its meaning on a date nobody
		// edited it; and the tracker is pointed at the same recorded server, so
		// no test can reach salsa.debian.org (CLAUDE.md rule 6).
		osv.Now = func() time.Time { return time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC) }
		osv.TrackerBase = server.URL + "/tracker/"
		return osv
	}
	t.Cleanup(func() { newMatcher = previous })

	reportPath := filepath.Join(t.TempDir(), "report.json")
	image := filepath.Join("..", "..", "testdata", "images", "mini-rootfs.tar.gz")

	var stdout bytes.Buffer
	cmd := NewRootCmd("v0.1.0")
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"scan", "--output", reportPath, image})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	assertE2EGolden(t, "e2e-terminal.txt", stdout.Bytes())

	produced, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	assertE2EGolden(t, "e2e-report.json", normaliseScanTimes(t, produced))
}

// normaliseScanTimes replaces the two fields that cannot repeat between runs.
// Everything else in the document is a claim about the image and must match
// exactly.
func normaliseScanTimes(t *testing.T, doc []byte) []byte {
	t.Helper()
	var check map[string]any
	if err := json.Unmarshal(doc, &check); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}
	doc = regexp.MustCompile(`"started_at": "[^"]*"`).
		ReplaceAll(doc, []byte(`"started_at": "2026-01-01T00:00:00Z"`))
	doc = regexp.MustCompile(`"duration_ms": \d+`).
		ReplaceAll(doc, []byte(`"duration_ms": 0`))
	return doc
}

func assertE2EGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run: go test ./internal/cli/ -update-e2e): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output does not match %s\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// recordedOSV serves the responses in testdata/osv/. A package the recording
// does not cover answers with no vulnerabilities, which is what OSV does for a
// package it has nothing on.
func recordedOSV(t *testing.T) *httptest.Server {
	t.Helper()

	var byPURL map[string]json.RawMessage
	readOSVFixture(t, "querybatch-by-purl.json", &byPURL)
	var vulns map[string]json.RawMessage
	readOSVFixture(t, "vulns.json", &vulns)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Queries []struct {
				Package struct {
					PURL      string `json:"purl"`
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		results := make([]json.RawMessage, len(request.Queries))
		for i, q := range request.Queries {
			key := q.Package.PURL
			if key == "" {
				key = q.Package.Ecosystem + "|" + q.Package.Name + "|" + q.Version
			}
			if recorded, ok := byPURL[key]; ok {
				results[i] = recorded
				continue
			}
			results[i] = json.RawMessage(`{"vulns":[]}`)
		}
		body, err := json.Marshal(map[string]any{"results": results})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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
	return server
}

func readOSVFixture(t *testing.T, name string, into any) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "osv", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
}
