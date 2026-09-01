package catalog

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseCodename(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "VERSION_CODENAME=bookworm\n", "bookworm"},
		{"double quoted", "VERSION_CODENAME=\"bullseye\"\n", "bullseye"},
		{"single quoted", "VERSION_CODENAME='trixie'\n", "trixie"},
		{"padded", "  VERSION_CODENAME =  forky  \n", "forky"},
		{"among other keys", "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nX=y\n", "bookworm"},
		{"absent", "ID=debian\nVERSION_ID=\"12\"\n", ""},
		{"empty value", "VERSION_CODENAME=\n", ""},
		{"value with a space is not a codename", "VERSION_CODENAME=not a codename\n", ""},
		{"value with a slash is rejected", "VERSION_CODENAME=../../etc\n", ""},
		{"no equals sign", "VERSION_CODENAME bookworm\n", ""},
		{"empty file", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseCodename(strings.NewReader(tt.in)); got != tt.want {
				t.Errorf("parseCodename(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDetectReleasePathPreference(t *testing.T) {
	// On Debian /etc/os-release is a symlink into /usr/lib, and the symlink does
	// not always survive extraction. usr/lib must therefore be tried first, and
	// etc must still work when it is the only copy present.
	both := fstest.MapFS{
		"usr/lib/os-release": &fstest.MapFile{Data: []byte("VERSION_CODENAME=bookworm\n")},
		"etc/os-release":     &fstest.MapFile{Data: []byte("VERSION_CODENAME=stale\n")},
	}
	if got := mustCodename(both); got != "bookworm" {
		t.Errorf("with both present, got %q, want bookworm", got)
	}

	etcOnly := fstest.MapFS{"etc/os-release": &fstest.MapFile{Data: []byte("VERSION_CODENAME=bullseye\n")}}
	if got := mustCodename(etcOnly); got != "bullseye" {
		t.Errorf("with only etc present, got %q, want bullseye", got)
	}

	// A usr/lib copy that does not name a codename must fall through to etc
	// rather than stopping the search.
	unhelpfulUsrLib := fstest.MapFS{
		"usr/lib/os-release": &fstest.MapFile{Data: []byte("ID=debian\n")},
		"etc/os-release":     &fstest.MapFile{Data: []byte("VERSION_CODENAME=trixie\n")},
	}
	if got := mustCodename(unhelpfulUsrLib); got != "trixie" {
		t.Errorf("with an unhelpful usr/lib copy, got %q, want trixie", got)
	}

	if got := mustCodename(fstest.MapFS{}); got != "" {
		t.Errorf("with no os-release, got %q, want empty", got)
	}
}

// A release goes by two names in OSV's data, and both come from os-release: the
// codename is the distro qualifier a per-CVE record carries, and the version id
// is how an advisory names the same release in its ecosystem field
// (spike/NOTES.md T18a).
func TestDetectRelease(t *testing.T) {
	tests := []struct {
		name              string
		files             fstest.MapFS
		codename, version string
	}{
		{
			name: "both fields",
			files: fstest.MapFS{"usr/lib/os-release": &fstest.MapFile{Data: []byte(
				"PRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\nVERSION_ID=\"11\"\nVERSION_CODENAME=bullseye\nID=debian\n")}},
			codename: "bullseye", version: "11",
		},
		{
			// Debian unstable has a codename and no version id.
			name: "codename only",
			files: fstest.MapFS{"usr/lib/os-release": &fstest.MapFile{Data: []byte(
				"VERSION_CODENAME=sid\nID=debian\n")}},
			codename: "sid", version: "",
		},
		{
			name: "version only",
			files: fstest.MapFS{"etc/os-release": &fstest.MapFile{Data: []byte(
				"VERSION_ID=\"11\"\nID=debian\n")}},
			codename: "", version: "11",
		},
		{
			name:     "no os-release at all",
			files:    fstest.MapFS{},
			codename: "", version: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codename, version := detectRelease(tt.files)
			if codename != tt.codename || version != tt.version {
				t.Errorf("detectRelease() = %q, %q, want %q, %q",
					codename, version, tt.codename, tt.version)
			}
		})
	}
}

// mustCodename keeps the path-preference test reading about codenames, which is
// what it is about, rather than about the pair detectRelease returns.
func mustCodename(root fs.FS) string {
	codename, _ := detectRelease(root)
	return codename
}

// errorFS serves one path whose contents cannot be read. A rootfs is untrusted
// and its files can fail mid-read; identifying the release is a convenience and
// must not be the thing that takes a scan down.
type errorFS struct{ path string }

func (e errorFS) Open(name string) (fs.File, error) {
	if name != e.path {
		return nil, fs.ErrNotExist
	}
	return unreadableFile{}, nil
}

type unreadableFile struct{}

func (unreadableFile) Stat() (fs.FileInfo, error) { return nil, errUnreadable }
func (unreadableFile) Read([]byte) (int, error)   { return 0, errUnreadable }
func (unreadableFile) Close() error               { return nil }

var errUnreadable = errors.New("cannot read")

func TestDetectReleaseSurvivesAnUnreadableFile(t *testing.T) {
	codename, version := detectRelease(errorFS{path: "usr/lib/os-release"})
	if codename != "" || version != "" {
		t.Errorf("detectRelease() = %q, %q, want both empty", codename, version)
	}
}
