//go:build integration

package match

import (
	"context"
	"testing"
	"time"

	"github.com/mhmtkas/fwscan/internal/model"
)

// TestOSVLiveBackportBehaviour is the only test allowed to reach the real API
// (CLAUDE.md rule 6). Run it with:
//
//	go test -tags integration ./internal/match/
//
// It re-checks, against production, the finding the whole matcher is built on:
// the release qualifier makes OSV backport-aware. Ground truth is the Debian
// Security Tracker, which records CVE-2022-0778 as fixed in bullseye at
// openssl 1.1.1k-1+deb11u2.
func TestOSVLiveBackportBehaviour(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	osv := NewOSV()

	vulnerable := model.Component{
		Name: "libssl1.1", Version: "1.1.1k-1+deb11u1", Arch: "amd64",
		Source: "openssl", SourceVersion: "1.1.1k-1+deb11u1", Distro: "bullseye",
		Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
	}
	fixed := vulnerable
	fixed.Version, fixed.SourceVersion = "1.1.1k-1+deb11u2", "1.1.1k-1+deb11u2"

	t.Run("true positive", func(t *testing.T) {
		findings, err := osv.Match(ctx, []model.Component{vulnerable})
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
		f, ok := findByID(findings, "CVE-2022-0778")
		if !ok {
			t.Fatalf("CVE-2022-0778 not reported for a version older than the fix")
		}
		if f.FixedVersion == "" {
			t.Error("no fixed version reported")
		}
		if f.Severity == model.SeverityUnknown {
			t.Error("severity is unknown; the record carries a CVSS v3 vector")
		}
	})

	t.Run("backport true negative", func(t *testing.T) {
		findings, err := osv.Match(ctx, []model.Component{fixed})
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
		if _, ok := findByID(findings, "CVE-2022-0778"); ok {
			t.Error("CVE-2022-0778 reported against the version that fixes it; " +
				"the distro qualifier is not reaching the query")
		}
	})
}

func findByID(findings []model.Finding, id string) (model.Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}
