package catalog

import (
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

func TestDetectCodenamePathPreference(t *testing.T) {
	// On Debian /etc/os-release is a symlink into /usr/lib, and the symlink does
	// not always survive extraction. usr/lib must therefore be tried first, and
	// etc must still work when it is the only copy present.
	both := fstest.MapFS{
		"usr/lib/os-release": &fstest.MapFile{Data: []byte("VERSION_CODENAME=bookworm\n")},
		"etc/os-release":     &fstest.MapFile{Data: []byte("VERSION_CODENAME=stale\n")},
	}
	if got := detectCodename(both); got != "bookworm" {
		t.Errorf("with both present, got %q, want bookworm", got)
	}

	etcOnly := fstest.MapFS{"etc/os-release": &fstest.MapFile{Data: []byte("VERSION_CODENAME=bullseye\n")}}
	if got := detectCodename(etcOnly); got != "bullseye" {
		t.Errorf("with only etc present, got %q, want bullseye", got)
	}

	// A usr/lib copy that does not name a codename must fall through to etc
	// rather than stopping the search.
	unhelpfulUsrLib := fstest.MapFS{
		"usr/lib/os-release": &fstest.MapFile{Data: []byte("ID=debian\n")},
		"etc/os-release":     &fstest.MapFile{Data: []byte("VERSION_CODENAME=trixie\n")},
	}
	if got := detectCodename(unhelpfulUsrLib); got != "trixie" {
		t.Errorf("with an unhelpful usr/lib copy, got %q, want trixie", got)
	}

	if got := detectCodename(fstest.MapFS{}); got != "" {
		t.Errorf("with no os-release, got %q, want empty", got)
	}
}
