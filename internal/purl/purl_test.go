package purl

import "testing"

func TestSource(t *testing.T) {
	// The exact form spike/NOTES.md T0.3 proved backport-aware.
	got := Source("openssl", "1.1.1k-1+deb11u2", "bullseye")
	want := "pkg:deb/debian/openssl@1.1.1k-1%2Bdeb11u2?arch=source&distro=bullseye"
	if got != want {
		t.Errorf("Source() = %q, want %q", got, want)
	}
	if got := Source("", "1.0", "bullseye"); got != "" {
		t.Errorf("Source() with no name = %q, want empty", got)
	}
}

func TestBinary(t *testing.T) {
	// The "+" of a Debian revision must arrive percent-encoded, which
	// output-spec section 3 requires and downstream tooling relies on.
	want := "pkg:deb/debian/libssl1.1@1.1.1k-1%2Bdeb11u2?arch=amd64&distro=bullseye"
	if got := Binary("libssl1.1", "1.1.1k-1+deb11u2", "amd64", "bullseye"); got != want {
		t.Errorf("Binary() = %q, want %q", got, want)
	}
	if got := Binary("", "1.0", "amd64", "bullseye"); got != "" {
		t.Errorf("Binary() with no name = %q, want empty", got)
	}
	// A component from an image that did not identify its release still gets a
	// purl; it just cannot say which release the version belongs to.
	if got := Binary("bash", "5.1-2", "amd64", ""); got != "pkg:deb/debian/bash@5.1-2?arch=amd64" {
		t.Errorf("Binary() with no codename = %q", got)
	}
}

func TestApk(t *testing.T) {
	// The release loses its leading "v": OSV and the purl spec write Alpine
	// releases as "alpine-3.16".
	want := "pkg:apk/alpine/openssl@1.1.1o-r0?arch=x86_64&distro=alpine-3.16"
	if got := Apk("openssl", "1.1.1o-r0", "x86_64", "v3.16"); got != want {
		t.Errorf("Apk() = %q, want %q", got, want)
	}
	if got := Apk("", "1.0", "x86_64", "v3.16"); got != "" {
		t.Errorf("Apk() with no name = %q, want empty", got)
	}
}
