// Package sbom serialises components as a CycloneDX 1.6 JSON document.
package sbom

import (
	"fmt"
	"io"
	"slices"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/mhmtkas/fwscan/internal/model"
)

// Property names for the two custom fields output-spec section 4 requires.
const (
	PropertyConfidence = "fwscan:confidence"
	PropertyEvidence   = "fwscan:evidence"
)

// Options carries what the document's metadata block needs.
type Options struct {
	ToolVersion string
	Timestamp   time.Time
}

// Write serialises comps as CycloneDX 1.6 JSON.
//
// The document holds components only. Vulnerabilities deliberately never appear
// here (output-spec section 4): an SBOM that changes every time a new CVE is
// published is not something anyone can share or diff, so findings stay in the
// report and the SBOM stays stable.
func Write(w io.Writer, comps []model.Component, opts Options) error {
	bom := Build(comps, opts)

	encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	// Without this, "&" inside a purl's qualifiers is written as \u0026. That
	// is valid JSON, but it makes every Debian purl unreadable and breaks naive
	// string matching in downstream tooling.
	encoder.SetEscapeHTML(false)
	if err := encoder.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return fmt.Errorf("sbom: encode: %w", err)
	}
	return nil
}

// Build assembles the BOM. It is separate from Write so tests can inspect the
// structure without going through JSON.
func Build(comps []model.Component, opts Options) *cdx.BOM {
	timestamp := opts.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.Metadata = &cdx.Metadata{
		Timestamp: timestamp.UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "fwscan",
				Version: opts.ToolVersion,
			}},
		},
	}

	sorted := slices.Clone(comps)
	slices.SortFunc(sorted, model.CompareComponents)

	refs := bomRefs(sorted)
	components := make([]cdx.Component, 0, len(sorted))
	for i, c := range sorted {
		components = append(components, componentOf(c, refs[i]))
	}
	bom.Components = &components
	return bom
}

func componentOf(c model.Component, ref string) cdx.Component {
	properties := []cdx.Property{
		{Name: PropertyConfidence, Value: string(c.Confidence)},
		{Name: PropertyEvidence, Value: c.Evidence},
	}
	return cdx.Component{
		BOMRef:     ref,
		Type:       cdx.ComponentTypeLibrary,
		Name:       c.Name,
		Version:    c.Version,
		PackageURL: c.PURL,
		Properties: &properties,
	}
}

// bomRefs assigns each component a reference that is unique within the
// document, which CycloneDX requires. The purl is the natural choice and the
// name@version pair is the fallback for a component that has no purl, which a
// filename heuristic produces -- but neither is guaranteed unique. Two
// components can share a purl when an image carries the same package for two
// architectures, and two heuristic results can share a name and version. A
// suffix is added only where a collision actually occurs, so the ordinary
// document is unchanged.
func bomRefs(comps []model.Component) []string {
	seen := make(map[string]int, len(comps))
	refs := make([]string, len(comps))
	for i, c := range comps {
		ref := bomRef(c)
		if n := seen[ref]; n > 0 {
			ref = fmt.Sprintf("%s#%d", ref, n+1)
		}
		seen[bomRef(c)]++
		refs[i] = ref
	}
	return refs
}

func bomRef(c model.Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	return c.Name + "@" + c.Version
}
