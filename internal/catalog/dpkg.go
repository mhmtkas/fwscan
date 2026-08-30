package catalog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/mhmtkas/fwscan/internal/model"
)

// DpkgStatusPath is where dpkg records installed packages, relative to the
// rootfs. It is also the Evidence value every component from this cataloger
// carries.
const DpkgStatusPath = "var/lib/dpkg/status"

// installedStatus is the only Status value that means the package's files are
// on disk. Anything else — deinstall, config-files, half-installed — is a
// record of a package that is not there (spike/NOTES.md T0.2).
const installedStatus = "install ok installed"

// Bounds on a hostile status file. dpkg stanzas are small; these limits are
// generous by two orders of magnitude and still cap memory at a few hundred
// megabytes for the pathological case (CLAUDE.md rule 9).
const (
	maxLineBytes  = 1 << 20 // 1 MiB, vs a few hundred bytes in practice
	maxStanzas    = 500_000 // a full Debian archive is ~65k source packages
	maxFieldBytes = 4 << 20 // a Description that grows without bound
)

// sourceWithVersion matches the "name (version)" form of the Source field. The
// parenthesised version appears exactly when the source version differs from
// the binary version — binNMUs, and binaries carrying an epoch their source
// does not (spike/NOTES.md T0.3).
var sourceWithVersion = regexp.MustCompile(`^(\S+)\s*\((.+)\)\s*$`)

// Dpkg catalogs packages from a dpkg status database.
type Dpkg struct{}

// NewDpkg returns the dpkg cataloger.
func NewDpkg() *Dpkg { return &Dpkg{} }

// Name implements Cataloger.
func (Dpkg) Name() string { return "dpkg" }

// Catalog implements Cataloger. A rootfs with no dpkg database yields no
// components and no error.
func (d Dpkg) Catalog(root fs.FS) ([]model.Component, error) {
	f, err := root.Open(DpkgStatusPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the package database: %w", err)
	}
	defer func() { _ = f.Close() }()

	codename := detectCodename(root)

	comps, err := parseStatus(f, codename)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", DpkgStatusPath, err)
	}
	return comps, nil
}

// parseStatus reads RFC-822-style stanzas separated by blank lines.
func parseStatus(r io.Reader, codename string) ([]model.Component, error) {
	var (
		out      []model.Component
		fields   = map[string]string{}
		lastKey  string
		stanzas  int
		fieldLen int
	)

	flush := func() error {
		defer func() {
			fields = map[string]string{}
			lastKey, fieldLen = "", 0
		}()
		if len(fields) == 0 {
			return nil
		}
		stanzas++
		if stanzas > maxStanzas {
			return fmt.Errorf("status file has more than %d stanzas", maxStanzas)
		}
		if fields["Status"] != installedStatus || fields["Package"] == "" {
			return nil
		}
		out = append(out, componentFrom(fields, codename))
		return nil
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := flush(); err != nil {
				return nil, err
			}
		case line[0] == ' ' || line[0] == '\t':
			// A continuation line belongs to the previous field. Treating it as
			// a new field is the classic multi-line Description bug: a
			// Description can contain lines that look exactly like "Package:".
			if lastKey == "" {
				continue
			}
			fieldLen += len(line)
			if fieldLen > maxFieldBytes {
				return nil, fmt.Errorf("field %q exceeds %d bytes", lastKey, maxFieldBytes)
			}
			fields[lastKey] += "\n" + strings.TrimSpace(line)
		default:
			key, value, found := strings.Cut(line, ":")
			if !found {
				// A malformed line must not take the scan down; a hostile image
				// would otherwise be a denial of service on the whole tool.
				continue
			}
			lastKey = key
			fieldLen = len(line)
			fields[key] = strings.TrimSpace(value)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// The last stanza need not be followed by a blank line.
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// componentFrom builds a Component from one parsed stanza.
func componentFrom(fields map[string]string, codename string) model.Component {
	name := fields["Package"]
	version := fields["Version"]
	arch := fields["Architecture"]
	sourceName, sourceVersion := sourceOf(fields)

	return model.Component{
		Name:          name,
		Version:       version,
		Arch:          arch,
		Source:        sourceName,
		SourceVersion: sourceVersion,
		Distro:        codename,
		PURL:          BinaryPURL(name, version, arch, codename),
		Confidence:    model.ConfidenceHigh,
		Evidence:      DpkgStatusPath,
	}
}

// sourceOf resolves the source package name and version for a stanza:
//
//	Source: util-linux (2.36.1-8+deb11u1)  -> that name and that version
//	Source: util-linux                     -> that name, the binary Version
//	absent                                 -> the binary Package and Version
//
// Honouring the parenthesised form is what keeps binNMU and epoch cases correct.
// Querying OSV with a binary version carrying an epoch its source lacks sorts
// the query above every fixed-version range and silently loses findings
// (spike/NOTES.md T0.3).
func sourceOf(fields map[string]string) (name, version string) {
	name, version = fields["Package"], fields["Version"]
	src := strings.TrimSpace(fields["Source"])
	if src == "" {
		return name, version
	}
	if m := sourceWithVersion.FindStringSubmatch(src); m != nil {
		return m[1], m[2]
	}
	return src, version
}

// BinaryPURL builds the purl identifying an installed binary package, which is
// what the SBOM and the JSON report carry (output-spec section 3). The distro
// qualifier is included when known so the purl states which release the version
// belongs to; it is what makes a Debian version string meaningful.
//
// The OSV query purl is a different thing — source package, source version,
// arch=source — and is built by the matcher.
func BinaryPURL(name, version, arch, codename string) string {
	return debPURL(name, version, arch, codename)
}

// SourcePURL builds the purl used to query OSV, per spike/NOTES.md T0.3.
func SourcePURL(sourceName, sourceVersion, codename string) string {
	return debPURL(sourceName, sourceVersion, "source", codename)
}

func debPURL(name, version, arch, codename string) string {
	if name == "" {
		return ""
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
		packageurl.TypeDebian, "debian", name, version,
		packageurl.QualifiersFromMap(qualifiers), "",
	).ToString()
}
