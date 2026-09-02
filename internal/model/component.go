// Package model holds the types that flow through the scan pipeline. Input
// handlers produce an fs.FS, catalogers turn that into Components, and matchers
// turn Components into Findings. Everything downstream — the terminal report,
// the JSON report and the SBOM — reads only these types.
package model

// Confidence records how a component was identified. It exists so that a report
// can separate what is known from what is guessed: a package-manager database
// says a package is installed, a filename only suggests it.
type Confidence string

const (
	// ConfidenceHigh is reserved for package-manager databases. Nothing else
	// may claim it (CLAUDE.md conventions).
	ConfidenceHigh Confidence = "high"
	// ConfidenceLow marks filename and version-string heuristics. Every
	// low-confidence component must carry Evidence.
	ConfidenceLow Confidence = "low"
)

// Component is one piece of software found in the image.
type Component struct {
	Name    string
	Version string
	Arch    string
	// Source and SourceVersion name the source package the binary was built
	// from. They are separate fields because OSV's Debian data is keyed on
	// source packages and the versions genuinely differ for binNMUs and for
	// binaries carrying an epoch their source does not (spike/NOTES.md T0.3).
	// They fall back to Name and Version when the database does not say.
	Source        string
	SourceVersion string
	// DistroVersion is the release number the image reports for itself, e.g.
	// "11" -- os-release's VERSION_ID. It is not part of any output; it exists
	// because OSV names a Debian release two ways. A per-CVE record identifies
	// it in the purl's distro qualifier, by codename; a DSA or DLA advisory
	// carries no qualifier at all and names the release in its ecosystem field,
	// as "Debian:11". Without this the advisories cannot be matched to a
	// release, and for an oldstable image advisories are all OSV returns
	// (spike/NOTES.md T18a).
	DistroVersion string

	// Distro is the release, under the name its ecosystem queries by: a Debian
	// codename such as "bookworm", or an Alpine release such as "v3.16". Empty
	// when the image did not identify itself, which costs the query its scope
	// -- without it OSV matches across every release at once and reports
	// backported fixes as vulnerable.
	Distro     string
	PURL       string
	Confidence Confidence
	// Evidence is the path inside the image the finding came from, e.g.
	// "var/lib/dpkg/status". Always relative, never host-absolute: it describes
	// the image, not wherever the image happened to be extracted.
	Evidence string
}

// Finding is one known vulnerability affecting one component.
type Finding struct {
	Component Component
	// ID is the identifier shown to the user. OSV's Debian records are named
	// DEBIAN-CVE-…; the plain CVE is preferred here when one is available.
	ID      string
	Aliases []string
	// Severity is the bucket derived per docs/output-spec.md section 1.
	Severity Severity
	// CVSS is the numeric base score, 0 when no score could be derived.
	CVSS float64
	// CVSSVector is the vector the score came from, empty when the severity was
	// not derived from CVSS. Required by output-spec section 3.
	CVSSVector string
	// FixedVersion is empty when no fix is known, which the terminal report
	// renders as an em dash.
	FixedVersion string
}
