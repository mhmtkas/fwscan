package catalog

import (
	"bufio"
	"bytes"
	"io"
	"io/fs"
	"strings"
)

// osReleasePaths is searched in order. usr/lib/os-release comes first because
// /etc/os-release is a symlink to it on Debian, and a symlink does not always
// survive extraction — the spike's Docker layers carried the usr/lib copy only.
var osReleasePaths = []string{
	"usr/lib/os-release",
	"etc/os-release",
}

// maxOSReleaseSize bounds the read. os-release is a handful of lines; anything
// larger is a hostile image, not a distro identity file.
const maxOSReleaseSize = 64 << 10

// OSRelease is what the image says about itself in os-release. Any field may
// be empty; an image without the file is unusual but not broken.
type OSRelease struct {
	// ID is the distribution, e.g. "debian" or "ubuntu".
	ID string
	// Codename is VERSION_CODENAME, e.g. "bookworm": the distro qualifier
	// OSV's per-CVE Debian records carry.
	Codename string
	// VersionID is VERSION_ID, e.g. "12": how OSV's advisories name the same
	// release, in their ecosystem field.
	VersionID string
	// IDLike is ID_LIKE, the distributions this one is derived from, closest
	// first. Raspberry Pi OS, Armbian and Linux Mint all name their base here,
	// and a derivative that does is a derivative fwscan can answer for: its
	// packages are the base's packages, under the base's release.
	IDLike []string
}

// Base is the distribution whose vulnerability data answers for this image: the
// ID when fwscan knows it, otherwise the closest entry in ID_LIKE that it
// knows, and empty when neither says anything it recognises.
//
// Everything downstream keys on this rather than on ID, so a Raspberry Pi OS
// image is queried as Debian, gets Debian's support dates, and reaches the
// Debian fallback -- and so that all three agree with each other.
func (o OSRelease) Base() string {
	if known(o.ID) {
		return strings.ToLower(o.ID)
	}
	for _, like := range o.IDLike {
		if known(like) {
			return strings.ToLower(like)
		}
	}
	return ""
}

// known reports whether fwscan has data keyed on this distribution.
func known(id string) bool {
	switch strings.ToLower(id) {
	case "debian", "ubuntu":
		return true
	}
	return false
}

// ReadOSRelease reports what the image says about itself. It is exported so
// the scan can warn about what it could not scope: a dpkg image with no
// release, or with a release OSV's Debian data does not cover.
func ReadOSRelease(root fs.FS) OSRelease {
	// The first file that names a release wins; a file that only names the
	// distribution is not enough to stop looking, because the release is what
	// every query needs. Its ID is kept in case no file names a release.
	var partial OSRelease
	for _, path := range osReleasePaths {
		f, err := root.Open(path)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(f, maxOSReleaseSize))
		_ = f.Close()
		if err != nil {
			continue
		}
		info := OSRelease{
			ID:        parseOSReleaseField(bytes.NewReader(body), "ID"),
			Codename:  parseCodename(bytes.NewReader(body)),
			VersionID: parseOSReleaseField(bytes.NewReader(body), "VERSION_ID"),
			IDLike:    parseIDLike(bytes.NewReader(body)),
		}
		if info.Codename != "" || info.VersionID != "" {
			if info.ID == "" {
				info.ID = partial.ID
			}
			if len(info.IDLike) == 0 {
				info.IDLike = partial.IDLike
			}
			return info
		}
		if partial.ID == "" {
			partial.ID = info.ID
		}
		if len(partial.IDLike) == 0 {
			partial.IDLike = info.IDLike
		}
	}
	return partial
}

// maxIDLike bounds how many bases an image may claim. The specification says a
// space-separated list ordered by closeness; a real one has one or two entries,
// and a hostile file is not going to be walked in full.
const maxIDLike = 8

// parseIDLike reads ID_LIKE, which os-release defines as a space-separated list
// ordered from closest to most distant.
func parseIDLike(r io.Reader) []string {
	fields := strings.Fields(parseOSReleaseField(r, "ID_LIKE"))
	if len(fields) > maxIDLike {
		fields = fields[:maxIDLike]
	}
	return fields
}

// parseCodename reads VERSION_CODENAME from os-release's shell-ish syntax.
func parseCodename(r io.Reader) string {
	value := parseOSReleaseField(r, "VERSION_CODENAME")
	// Debian codenames are single lowercase words; anything else is not one.
	if strings.ContainsAny(value, " \t/") {
		return ""
	}
	return value
}

// parseOSReleaseField reads one key from os-release's shell-ish syntax,
// tolerating quotes and ignoring everything else.
func parseOSReleaseField(r io.Reader, want string) string {
	sc := bufio.NewScanner(io.LimitReader(r, maxOSReleaseSize))
	for sc.Scan() {
		key, value, found := strings.Cut(sc.Text(), "=")
		if !found || strings.TrimSpace(key) != want {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return ""
}
