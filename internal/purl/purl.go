// Package purl builds the package URLs fwscan emits and queries with.
//
// It sits below both catalog and match because both build purls and neither
// owns the format: a cataloger names the binary package it found, the matcher
// names the source package it asks OSV about, and the two must agree on
// encoding down to the percent-escaping of a version's "+".
package purl

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

// The purl namespaces of the dpkg-based distributions fwscan queries. OSV keys
// its Debian and Ubuntu data separately and under these names, so the namespace
// decides which body of data a query reaches.
const (
	NamespaceDebian = "debian"
	NamespaceUbuntu = "ubuntu"
)

// Namespace maps an os-release ID to the purl namespace to query under.
//
// Anything else falls back to Debian, which is what a derivative is most likely
// to be built from; the scan warns separately when it is scanning something it
// has no data for, since a wrong namespace returns zero results rather than an
// error.
func Namespace(osReleaseID string) string {
	if strings.EqualFold(osReleaseID, NamespaceUbuntu) {
		return NamespaceUbuntu
	}
	return NamespaceDebian
}

// Binary identifies an installed dpkg binary package, which is what the SBOM
// and the JSON report carry (output-spec section 3). The distro qualifier is
// included when known so the purl states which release the version belongs to;
// it is what makes a Debian or Ubuntu version string meaningful.
func Binary(namespace, name, version, arch, codename string) string {
	return deb(namespace, name, version, arch, codename)
}

// Source identifies the source package a query is about: source name, source
// version, arch=source. It is a different purl from Binary, and it is the one
// OSV is asked about (spike/NOTES.md T0.3).
func Source(namespace, name, version, codename string) string {
	return deb(namespace, name, version, "source", codename)
}

func deb(namespace, name, version, arch, codename string) string {
	if name == "" {
		return ""
	}
	if namespace == "" {
		namespace = NamespaceDebian
	}
	qualifiers := map[string]string{}
	if arch != "" {
		qualifiers["arch"] = arch
	}
	if codename != "" {
		qualifiers["distro"] = codename
	}
	// packageurl-go percent-encodes the version, so "+" becomes "%2B" as
	// output-spec section 3 requires.
	return packageurl.NewPackageURL(
		packageurl.TypeDebian, namespace, name, version,
		packageurl.QualifiersFromMap(qualifiers), "",
	).ToString()
}

// Apk identifies an installed apk package, for the SBOM and the JSON report.
//
// Note this purl is *not* what the matcher queries. OSV's own Alpine records
// carry no distro qualifier and keep the release in their ecosystem field, so
// Alpine has to be queried by ecosystem instead (spike/NOTES.md T0.3a). The
// qualifier here is for the reader's benefit: a bare apk version says nothing
// about which Alpine release it belongs to.
func Apk(name, version, arch, release string) string {
	if name == "" {
		return ""
	}
	qualifiers := map[string]string{}
	if arch != "" {
		qualifiers["arch"] = arch
	}
	if release != "" {
		qualifiers["distro"] = "alpine-" + strings.TrimPrefix(release, "v")
	}
	return packageurl.NewPackageURL(
		"apk", "alpine", name, version,
		packageurl.QualifiersFromMap(qualifiers), "",
	).ToString()
}
