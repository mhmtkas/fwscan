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
		}
		if info.Codename != "" || info.VersionID != "" {
			if info.ID == "" {
				info.ID = partial.ID
			}
			return info
		}
		if partial.ID == "" {
			partial.ID = info.ID
		}
	}
	return partial
}

// detectRelease reads both names a release goes by.
//
// The codename -- "bookworm" -- is the distro qualifier every OSV query needs:
// without it OSV matches across all Debian releases at once and reports
// backported fixes as vulnerable (spike/NOTES.md T0.3). The version id -- "11"
// -- is how OSV's DSA and DLA advisories name the same release, in their
// ecosystem field, and for an oldstable image advisories are all OSV returns
// (spike/NOTES.md T18a).
//
// Either may be empty, and neither is a reason to fail: a rootfs with a dpkg
// database and no os-release is unusual but not broken. It costs the matching
// each empty one would have done, and nothing else.
func detectRelease(root fs.FS) (codename, version string) {
	info := ReadOSRelease(root)
	return info.Codename, info.VersionID
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
