package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/mhmtkas/fwscan/internal/model"
)

func testComponents() []model.Component {
	return []model.Component{
		{
			Name: "zlib1g", Version: "1:1.2.11.dfsg-2", Arch: "amd64",
			Source: "zlib", SourceVersion: "1:1.2.11.dfsg-2", Distro: "bullseye",
			PURL:       "pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2?arch=amd64&distro=bullseye",
			Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
		},
		{
			Name: "openssl", Version: "1.1.1k-1+deb11u1", Arch: "amd64",
			Source: "openssl", SourceVersion: "1.1.1k-1+deb11u1", Distro: "bullseye",
			PURL:       "pkg:deb/debian/openssl@1.1.1k-1%2Bdeb11u1?arch=amd64&distro=bullseye",
			Confidence: model.ConfidenceHigh, Evidence: "var/lib/dpkg/status",
		},
		{
			Name: "busybox", Version: "1.30.1",
			Confidence: model.ConfidenceLow, Evidence: "bin/busybox",
		},
	}
}

func TestBuild(t *testing.T) {
	opts := Options{ToolVersion: "v0.1.0", Timestamp: time.Date(2026, 8, 30, 14, 5, 11, 0, time.UTC)}
	bom := Build(testComponents(), opts)

	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("spec version = %v, want 1.6", bom.SpecVersion)
	}
	if bom.Metadata == nil || bom.Metadata.Timestamp != "2026-08-30T14:05:11Z" {
		t.Errorf("metadata timestamp = %+v", bom.Metadata)
	}
	tools := bom.Metadata.Tools.Components
	if tools == nil || len(*tools) != 1 || (*tools)[0].Name != "fwscan" || (*tools)[0].Version != "v0.1.0" {
		t.Errorf("tool metadata = %+v", tools)
	}

	comps := *bom.Components
	if len(comps) != 3 {
		t.Fatalf("got %d components, want 3", len(comps))
	}
	// output-spec section 3 sorts components by name; the SBOM follows suit so
	// two scans of the same image diff cleanly.
	wantOrder := []string{"busybox", "openssl", "zlib1g"}
	for i, name := range wantOrder {
		if comps[i].Name != name {
			t.Errorf("component %d = %s, want %s", i, comps[i].Name, name)
		}
	}

	for _, c := range comps {
		if c.Type != cdx.ComponentTypeLibrary {
			t.Errorf("%s: type = %s, want library", c.Name, c.Type)
		}
		if c.BOMRef == "" {
			t.Errorf("%s: empty bom-ref", c.Name)
		}
		props := propertyMap(t, c)
		if _, ok := props[PropertyConfidence]; !ok {
			t.Errorf("%s: missing %s", c.Name, PropertyConfidence)
		}
		if _, ok := props[PropertyEvidence]; !ok {
			t.Errorf("%s: missing %s", c.Name, PropertyEvidence)
		}
	}

	// A heuristic component has no purl, so its bom-ref falls back to name@version.
	if comps[0].BOMRef != "busybox@1.30.1" {
		t.Errorf("fallback bom-ref = %q", comps[0].BOMRef)
	}
	if props := propertyMap(t, comps[0]); props[PropertyConfidence] != "low" {
		t.Errorf("busybox confidence = %q, want low", props[PropertyConfidence])
	}
}

func propertyMap(t *testing.T, c cdx.Component) map[string]string {
	t.Helper()
	out := map[string]string{}
	if c.Properties == nil {
		return out
	}
	for _, p := range *c.Properties {
		out[p.Name] = p.Value
	}
	return out
}

// output-spec section 4 is explicit: the SBOM carries components only. An SBOM
// that changes whenever a CVE is published cannot be shared or diffed.
func TestWriteContainsNoVulnerabilities(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, testComponents(), Options{ToolVersion: "v0.1.0"}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, present := doc["vulnerabilities"]; present {
		t.Error("the SBOM carries a vulnerabilities block")
	}
	for _, forbidden := range []string{"CVE-", "vulnerabilit", "DEBIAN-CVE"} {
		if strings.Contains(buf.String(), forbidden) {
			t.Errorf("the SBOM mentions %q", forbidden)
		}
	}
}

func TestWriteShape(t *testing.T) {
	var buf bytes.Buffer
	opts := Options{ToolVersion: "v0.1.0", Timestamp: time.Date(2026, 8, 30, 14, 5, 11, 0, time.UTC)}
	if err := Write(&buf, testComponents(), opts); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`"bomFormat": "CycloneDX"`,
		`"specVersion": "1.6"`,
		`"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json"`,
		`"fwscan:confidence"`,
		`"fwscan:evidence"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %s", want)
		}
	}

	// A purl qualifier separator must stay a literal "&". The escaped form is
	// valid JSON but makes every Debian purl unreadable and breaks naive string
	// matching downstream.
	if strings.Contains(out, `\u0026`) {
		t.Error("purl qualifiers are HTML-escaped")
	}
	if !strings.Contains(out, "?arch=amd64&distro=bullseye") {
		t.Error("purl qualifiers missing from the output")
	}
}

func TestWriteEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, nil, Options{ToolVersion: "v0.1.0"}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("empty SBOM is not valid JSON: %v", err)
	}
	// A timestamp is still stamped even with nothing to report.
	metadata, ok := doc["metadata"].(map[string]any)
	if !ok || metadata["timestamp"] == "" {
		t.Errorf("metadata missing from an empty SBOM: %+v", doc["metadata"])
	}
}
