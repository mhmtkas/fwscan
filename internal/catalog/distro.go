package catalog

import (
	"bufio"
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

// detectCodename returns the Debian release codename for the image, e.g.
// "bookworm". It is the distro qualifier every OSV query needs: without it OSV
// matches across all Debian releases at once and reports backported fixes as
// vulnerable (spike/NOTES.md T0.3).
//
// An empty string means the image did not say. Callers must treat that as "no
// distro qualifier", not as a reason to fail: a rootfs with a dpkg database but
// no os-release is unusual but not broken.
func detectCodename(root fs.FS) string {
	for _, path := range osReleasePaths {
		f, err := root.Open(path)
		if err != nil {
			continue
		}
		codename := parseCodename(f)
		_ = f.Close()
		if codename != "" {
			return codename
		}
	}
	return ""
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
