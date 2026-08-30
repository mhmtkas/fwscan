package catalog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/mhmtkas/fwscan/internal/model"
)

// ApkInstalledPath is where apk records installed packages, relative to the
// rootfs.
const ApkInstalledPath = "lib/apk/db/installed"

// The apk database is RFC-822-ish but with single-letter field names.
const (
	apkFieldPackage = "P"
	apkFieldVersion = "V"
	apkFieldArch    = "A"
	apkFieldOrigin  = "o" // the source package, dpkg's Source: by another name
)

// Apk catalogs packages from an Alpine apk database.
type Apk struct{}

// NewApk returns the apk cataloger.
func NewApk() *Apk { return &Apk{} }

// Name implements Cataloger.
func (Apk) Name() string { return "apk" }

// Catalog implements Cataloger. A rootfs with no apk database yields no
// components and no error.
func (Apk) Catalog(root fs.FS) ([]model.Component, error) {
	f, err := root.Open(ApkInstalledPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("apk: open %s: %w", ApkInstalledPath, err)
	}
	defer func() { _ = f.Close() }()

	release := detectAlpineRelease(root)

	comps, err := parseApkInstalled(f, release)
	if err != nil {
		return nil, fmt.Errorf("apk: parse %s: %w", ApkInstalledPath, err)
	}
	return comps, nil
}

// parseApkInstalled reads stanzas separated by blank lines.
//
// Unlike dpkg there is no Status field: presence in this file is what
// "installed" means. There is also no continuation-line syntax, so a line
// without a colon is simply malformed.
func parseApkInstalled(r io.Reader, release string) ([]model.Component, error) {
	var (
		out     []model.Component
		fields  = map[string]string{}
		stanzas int
	)

	flush := func() error {
		defer func() { fields = map[string]string{} }()
		if fields[apkFieldPackage] == "" {
			return nil
		}
		stanzas++
		if stanzas > maxStanzas {
			return fmt.Errorf("database has more than %d entries", maxStanzas)
		}
		out = append(out, apkComponent(fields, release))
		return nil
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found || len(key) != 1 {
			// Every apk field name is a single character. Anything else is
			// malformed and skipped rather than fatal.
			continue
		}
		// A repeated field keeps the first value. F: and R: repeat per file and
		// are not read at all; the fields that matter appear once.
		if _, seen := fields[key]; !seen {
			fields[key] = strings.TrimSpace(value)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func apkComponent(fields map[string]string, release string) model.Component {
	name := fields[apkFieldPackage]
	version := fields[apkFieldVersion]
	arch := fields[apkFieldArch]

	source := fields[apkFieldOrigin]
	if source == "" {
		source = name
	}

	return model.Component{
		Name:    name,
		Version: version,
		Arch:    arch,
		Source:  source,
		// apk records no separate origin version: the origin is built at the
		// same version as its binaries.
		SourceVersion: version,
		Distro:        release,
		PURL:          ApkPURL(name, version, arch, release),
		Confidence:    model.ConfidenceHigh,
		Evidence:      ApkInstalledPath,
	}
}

// ApkPURL builds the purl identifying an installed apk package, for the SBOM
// and the JSON report.
//
// Note this purl is *not* what the matcher queries. OSV's own Alpine records
// carry no distro qualifier and keep the release in their ecosystem field, so
// Alpine has to be queried by ecosystem instead (spike/NOTES.md T0.3a). The
// qualifier here is for the reader's benefit: a bare apk version says nothing
// about which Alpine release it belongs to.
func ApkPURL(name, version, arch, release string) string {
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

// alpineReleasePaths is searched in order.
var alpineReleasePaths = []string{
	"etc/alpine-release",
	"usr/lib/os-release",
	"etc/os-release",
}

// detectAlpineRelease returns the OSV ecosystem suffix for the image, e.g.
// "v3.16".
//
// OSV's Alpine ecosystem is "Alpine:v<major>.<minor>" exactly: "Alpine:3.16"
// and "Alpine:v3.16.0" both return nothing, silently (spike/NOTES.md T0.3a).
// So the patch component is dropped and the "v" is mandatory.
func detectAlpineRelease(root fs.FS) string {
	for _, path := range alpineReleasePaths {
		f, err := root.Open(path)
		if err != nil {
			continue
		}
		var raw string
		if path == "etc/alpine-release" {
			raw = readFirstLine(f)
		} else {
			raw = parseOSReleaseField(f, "VERSION_ID")
		}
		_ = f.Close()
		if release := alpineEcosystemVersion(raw); release != "" {
			return release
		}
	}
	return ""
}

// alpineEcosystemVersion turns "3.16.0" into "v3.16".
func alpineEcosystemVersion(raw string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return ""
	}
	major, minor := parts[0], parts[1]
	if !allDigits(major) || !allDigits(minor) {
		return ""
	}
	return "v" + major + "." + minor
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func readFirstLine(r io.Reader) string {
	sc := bufio.NewScanner(io.LimitReader(r, maxOSReleaseSize))
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}
