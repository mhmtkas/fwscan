//go:build integration

package match

import (
	"context"
	"testing"
	"time"

	"github.com/mhmtkas/fwscan/internal/catalog"
	"github.com/mhmtkas/fwscan/internal/model"
	"github.com/mhmtkas/fwscan/internal/purl"
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

	debian := func(version string) model.Component {
		return model.Component{
			Name: "libssl1.1", Version: version, Arch: "amd64",
			Source: "openssl", SourceVersion: version, Distro: "bullseye",
			// The release number is how an advisory names bullseye, and for
			// an oldstable release advisories are all OSV returns; without it
			// the fixed version cannot be matched.
			DistroVersion: "11",
			// The purl is what selects the query shape, so a component without
			// one is never looked up.
			PURL:       purl.Binary(purl.NamespaceDebian, "libssl1.1", version, "amd64", "bullseye"),
			Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
		}
	}
	vulnerable := debian("1.1.1k-1+deb11u1")
	fixed := debian("1.1.1k-1+deb11u2")

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

	// Alpine goes through a different query shape entirely, so it needs its own
	// live check (spike/NOTES.md T0.3a).
	t.Run("alpine is queried by ecosystem", func(t *testing.T) {
		alpine := model.Component{
			Name: "zlib", Version: "1.2.12-r1", Arch: "x86_64",
			Source: "zlib", SourceVersion: "1.2.12-r1", Distro: "v3.16",
			PURL:       purl.Apk("zlib", "1.2.12-r1", "x86_64", "v3.16"),
			Confidence: model.ConfidenceHigh, Evidence: catalog.ApkInstalledPath,
		}
		findings, err := osv.Match(ctx, []model.Component{alpine})
		if err != nil {
			t.Fatalf("Match() error = %v", err)
		}
		f, ok := findByID(findings, "CVE-2022-37434")
		if !ok {
			t.Fatal("CVE-2022-37434 not reported; the ecosystem query is not reaching OSV")
		}
		if f.FixedVersion != "1.2.12-r2" {
			t.Errorf("fixed version = %q, want v3.16's 1.2.12-r2", f.FixedVersion)
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
