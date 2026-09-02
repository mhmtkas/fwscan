package catalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/mhmtkas/fwscan/internal/model"
)

func apkFS(installed, release string) fstest.MapFS {
	m := fstest.MapFS{ApkInstalledPath: &fstest.MapFile{Data: []byte(installed)}}
	if release != "" {
		m["etc/alpine-release"] = &fstest.MapFile{Data: []byte(release + "\n")}
	}
	return m
}

func TestApkCatalog(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		release   string
		want      []model.Component
	}{
		{
			name:    "normal entry",
			release: "3.16.0",
			installed: "C:Q1sboUEnyV+bt26L3Nbb/SQi1JAmE=\n" +
				"P:zlib\n" +
				"V:1.2.12-r1\n" +
				"A:x86_64\n" +
				"S:53346\n" +
				"T:A compression/decompression Library\n" +
				"o:zlib\n" +
				"D:so:libc.musl-x86_64.so.1\n",
			want: []model.Component{{
				Name: "zlib", Version: "1.2.12-r1", Arch: "x86_64",
				Source: "zlib", SourceVersion: "1.2.12-r1", Distro: "v3.16",
				PURL:       "pkg:apk/alpine/zlib@1.2.12-r1?arch=x86_64&distro=alpine-3.16",
				Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
			}},
		},
		{
			name:    "origin differs from the package name",
			release: "3.16.0",
			installed: "P:libssl1.1\n" +
				"V:1.1.1o-r0\n" +
				"A:x86_64\n" +
				"o:openssl\n",
			want: []model.Component{{
				Name: "libssl1.1", Version: "1.1.1o-r0", Arch: "x86_64",
				Source: "openssl", SourceVersion: "1.1.1o-r0", Distro: "v3.16",
				PURL:       "pkg:apk/alpine/libssl1.1@1.1.1o-r0?arch=x86_64&distro=alpine-3.16",
				Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
			}},
		},
		{
			name:    "missing origin falls back to the package name",
			release: "3.16.0",
			installed: "P:scanelf\n" +
				"V:1.3.4-r0\n" +
				"A:x86_64\n",
			want: []model.Component{{
				Name: "scanelf", Version: "1.3.4-r0", Arch: "x86_64",
				Source: "scanelf", SourceVersion: "1.3.4-r0", Distro: "v3.16",
				PURL:       "pkg:apk/alpine/scanelf@1.3.4-r0?arch=x86_64&distro=alpine-3.16",
				Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
			}},
		},
		{
			name:    "missing version still yields a component",
			release: "3.16.0",
			installed: "P:broken\n" +
				"A:x86_64\n" +
				"o:broken\n",
			want: []model.Component{{
				Name: "broken", Arch: "x86_64",
				Source: "broken", Distro: "v3.16",
				PURL:       "pkg:apk/alpine/broken?arch=x86_64&distro=alpine-3.16",
				Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
			}},
		},
		{
			name:    "several stanzas",
			release: "3.16.0",
			installed: "P:musl\nV:1.2.3-r0\nA:x86_64\no:musl\n" +
				"\n" +
				"P:busybox\nV:1.35.0-r13\nA:x86_64\no:busybox\n" +
				"\n" +
				"P:ssl_client\nV:1.35.0-r13\nA:x86_64\no:busybox\n",
			want: []model.Component{
				{
					Name: "musl", Version: "1.2.3-r0", Arch: "x86_64",
					Source: "musl", SourceVersion: "1.2.3-r0", Distro: "v3.16",
					PURL:       "pkg:apk/alpine/musl@1.2.3-r0?arch=x86_64&distro=alpine-3.16",
					Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
				},
				{
					Name: "busybox", Version: "1.35.0-r13", Arch: "x86_64",
					Source: "busybox", SourceVersion: "1.35.0-r13", Distro: "v3.16",
					PURL:       "pkg:apk/alpine/busybox@1.35.0-r13?arch=x86_64&distro=alpine-3.16",
					Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
				},
				{
					Name: "ssl_client", Version: "1.35.0-r13", Arch: "x86_64",
					Source: "busybox", SourceVersion: "1.35.0-r13", Distro: "v3.16",
					PURL:       "pkg:apk/alpine/ssl_client@1.35.0-r13?arch=x86_64&distro=alpine-3.16",
					Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
				},
			},
		},
		{
			name:    "no release means no distro qualifier",
			release: "",
			installed: "P:musl\n" +
				"V:1.2.3-r0\n" +
				"A:x86_64\n",
			want: []model.Component{{
				Name: "musl", Version: "1.2.3-r0", Arch: "x86_64",
				Source: "musl", SourceVersion: "1.2.3-r0",
				PURL:       "pkg:apk/alpine/musl@1.2.3-r0?arch=x86_64",
				Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
			}},
		},
		{
			name:    "malformed and repeated lines",
			release: "3.16.0",
			installed: "no colon here\n" +
				"LONGKEY:value\n" +
				"P:apk-tools\n" +
				"V:2.12.9-r3\n" +
				"A:x86_64\n" +
				"o:apk-tools\n" +
				"F:usr\n" +
				"R:bin\n" +
				"F:etc\n",
			want: []model.Component{{
				Name: "apk-tools", Version: "2.12.9-r3", Arch: "x86_64",
				Source: "apk-tools", SourceVersion: "2.12.9-r3", Distro: "v3.16",
				PURL:       "pkg:apk/alpine/apk-tools@2.12.9-r3?arch=x86_64&distro=alpine-3.16",
				Confidence: model.ConfidenceHigh, Evidence: ApkInstalledPath,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewApk().Catalog(context.Background(), apkFS(tt.installed, tt.release))
			if err != nil {
				t.Fatalf("Catalog() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d components, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("component %d:\n got  %+v\n want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestApkCatalogNoDatabase(t *testing.T) {
	got, err := NewApk().Catalog(context.Background(), fstest.MapFS{"etc/hostname": &fstest.MapFile{Data: []byte("box\n")}})
	if err != nil {
		t.Fatalf("Catalog() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d components, want 0", len(got))
	}
	if got := NewApk().Name(); got != "apk" {
		t.Errorf("Name() = %q, want apk", got)
	}
}

// OSV's Alpine ecosystem is "Alpine:v<major>.<minor>" exactly. Alpine:3.16 and
// Alpine:v3.16.0 both return nothing, silently (spike/NOTES.md T0.3a).
func TestAlpineEcosystemVersion(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"3.16.0", "v3.16"},
		{"3.16", "v3.16"},
		{"v3.16.0", "v3.16"},
		{"  3.19.1  ", "v3.19"},
		{"3.20.0_alpha20240329", "v3.20"},
		{"edge", ""},
		{"3", ""},
		{"", ""},
		{"x.y", ""},
	}
	for _, tt := range tests {
		if got := alpineEcosystemVersion(tt.in); got != tt.want {
			t.Errorf("alpineEcosystemVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDetectAlpineReleasePathPreference(t *testing.T) {
	// etc/alpine-release is the most direct source and wins.
	both := fstest.MapFS{
		"etc/alpine-release": &fstest.MapFile{Data: []byte("3.16.0\n")},
		"usr/lib/os-release": &fstest.MapFile{Data: []byte("VERSION_ID=3.99.0\n")},
	}
	if got := detectAlpineRelease(both); got != "v3.16" {
		t.Errorf("got %q, want v3.16", got)
	}

	osReleaseOnly := fstest.MapFS{
		"usr/lib/os-release": &fstest.MapFile{Data: []byte("ID=alpine\nVERSION_ID=3.19.1\n")},
	}
	if got := detectAlpineRelease(osReleaseOnly); got != "v3.19" {
		t.Errorf("got %q, want v3.19", got)
	}

	// An alpine-release that says "edge" carries no usable release, so the
	// search falls through rather than stopping.
	edge := fstest.MapFS{
		"etc/alpine-release": &fstest.MapFile{Data: []byte("edge\n")},
		"etc/os-release":     &fstest.MapFile{Data: []byte("VERSION_ID=3.18.4\n")},
	}
	if got := detectAlpineRelease(edge); got != "v3.18" {
		t.Errorf("got %q, want v3.18", got)
	}

	if got := detectAlpineRelease(fstest.MapFS{}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// TestApkRealFixture parses the committed Alpine database.
func TestApkRealFixture(t *testing.T) {
	const wantPackages = 14

	installed, err := os.ReadFile(filepath.Join("..", "..", "testdata", "apk-db", "alpine-3.16.0-installed"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	osRelease, err := os.ReadFile(filepath.Join("..", "..", "testdata", "apk-db", "alpine-3.16.0-os-release"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	root := fstest.MapFS{
		ApkInstalledPath:     &fstest.MapFile{Data: installed},
		"usr/lib/os-release": &fstest.MapFile{Data: osRelease},
	}
	comps, err := NewApk().Catalog(context.Background(), root)
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(comps) != wantPackages {
		t.Fatalf("got %d packages, want %d", len(comps), wantPackages)
	}

	byName := map[string]model.Component{}
	for _, c := range comps {
		if c.Confidence != model.ConfidenceHigh || c.Evidence != ApkInstalledPath {
			t.Errorf("%s: confidence %q evidence %q", c.Name, c.Confidence, c.Evidence)
		}
		if c.Distro != "v3.16" {
			t.Errorf("%s: distro = %q, want v3.16", c.Name, c.Distro)
		}
		byName[c.Name] = c
	}

	// Several binaries share one origin, which is what the matcher deduplicates.
	for name, wantOrigin := range map[string]string{
		"libssl1.1":    "openssl",
		"libcrypto1.1": "openssl",
		"ssl_client":   "busybox",
		"busybox":      "busybox",
	} {
		c, ok := byName[name]
		if !ok {
			t.Errorf("%s missing from the fixture", name)
			continue
		}
		if c.Source != wantOrigin {
			t.Errorf("%s: source = %q, want %q", name, c.Source, wantOrigin)
		}
	}
}
