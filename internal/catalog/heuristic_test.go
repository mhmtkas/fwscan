package catalog

import (
	"bytes"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mhmtkas/fwscan/internal/model"
)

func TestDetectKernel(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
		want []model.Component
	}{
		{
			name: "hit",
			fsys: fstest.MapFS{
				"lib/modules/5.10.0-11-arm64/modules.dep": &fstest.MapFile{},
			},
			want: []model.Component{
				lowConfidence("linux-kernel", "5.10.0-11-arm64", "lib/modules/5.10.0-11-arm64"),
			},
		},
		{
			name: "two kernels",
			fsys: fstest.MapFS{
				"lib/modules/5.10.0-11-arm64/modules.dep": &fstest.MapFile{},
				"lib/modules/6.1.0-rpi7-rpi-v8/kernel/x":  &fstest.MapFile{},
			},
			want: []model.Component{
				lowConfidence("linux-kernel", "5.10.0-11-arm64", "lib/modules/5.10.0-11-arm64"),
				lowConfidence("linux-kernel", "6.1.0-rpi7-rpi-v8", "lib/modules/6.1.0-rpi7-rpi-v8"),
			},
		},
		{
			name: "two-component version",
			fsys: fstest.MapFS{"lib/modules/6.1/modules.dep": &fstest.MapFile{}},
			want: []model.Component{lowConfidence("linux-kernel", "6.1", "lib/modules/6.1")},
		},
		{
			name: "miss: no modules directory",
			fsys: fstest.MapFS{"etc/hostname": &fstest.MapFile{Data: []byte("box\n")}},
		},
		{
			name: "malformed: a directory that is not a version",
			fsys: fstest.MapFS{
				"lib/modules/extra/x":       &fstest.MapFile{},
				"lib/modules/README":        &fstest.MapFile{},
				"lib/modules/..evil/x":      &fstest.MapFile{},
				"lib/modules/v5.10-notaver": &fstest.MapFile{},
			},
		},
		{
			name: "a file where a version directory is expected",
			fsys: fstest.MapFS{"lib/modules/5.10.0-11-arm64": &fstest.MapFile{Data: []byte("not a dir")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertComponents(t, detectKernel(tt.fsys), tt.want)
		})
	}
}

func TestDetectBusybox(t *testing.T) {
	// A real binary has the banner buried in a blob of other bytes.
	binary := func(banner string) []byte {
		var b bytes.Buffer
		b.Write(bytes.Repeat([]byte{0x7f, 'E', 'L', 'F', 0x00}, 200))
		b.WriteString(banner)
		b.Write(bytes.Repeat([]byte{0x00}, 500))
		return b.Bytes()
	}

	tests := []struct {
		name string
		fsys fstest.MapFS
		want []model.Component
	}{
		{
			name: "hit in bin",
			fsys: fstest.MapFS{"bin/busybox": &fstest.MapFile{
				Data: binary("BusyBox v1.30.1 (Debian 1:1.30.1-6) multi-call binary."),
			}},
			want: []model.Component{lowConfidence("busybox", "1.30.1", "bin/busybox")},
		},
		{
			name: "hit in usr/bin",
			fsys: fstest.MapFS{"usr/bin/busybox": &fstest.MapFile{
				Data: binary("BusyBox v1.35.0 () multi-call binary."),
			}},
			want: []model.Component{lowConfidence("busybox", "1.35.0", "usr/bin/busybox")},
		},
		{
			name: "miss: no busybox",
			fsys: fstest.MapFS{"bin/sh": &fstest.MapFile{Data: []byte("#!/bin/sh\n")}},
		},
		{
			name: "malformed: binary with no banner",
			fsys: fstest.MapFS{"bin/busybox": &fstest.MapFile{Data: binary("not busybox at all")}},
		},
		{
			name: "malformed: truncated banner",
			fsys: fstest.MapFS{"bin/busybox": &fstest.MapFile{Data: binary("BusyBox v1.30")}},
		},
		{
			name: "empty file",
			fsys: fstest.MapFS{"bin/busybox": &fstest.MapFile{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertComponents(t, detectBusybox(tt.fsys), tt.want)
		})
	}
}

// The banner must still be found when it straddles a read boundary.
func TestDetectBusyboxAcrossChunkBoundary(t *testing.T) {
	const banner = "BusyBox v1.36.1 (Alpine) multi-call binary."
	for _, offset := range []int{65536 - 10, 65536 - 1, 65536, 65536 + 5, 131072 - 20} {
		body := make([]byte, offset, offset+len(banner)+64)
		body = append(body, banner...)
		body = append(body, bytes.Repeat([]byte{0}, 64)...)

		got := detectBusybox(fstest.MapFS{"bin/busybox": &fstest.MapFile{Data: body}})
		if len(got) != 1 || got[0].Version != "1.36.1" {
			t.Errorf("banner at offset %d: got %+v", offset, got)
		}
	}
}

func TestDetectSharedLibraries(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
		want []model.Component
	}{
		{
			name: "glibc names a real version",
			fsys: fstest.MapFS{"lib/libc-2.31.so": &fstest.MapFile{}},
			want: []model.Component{lowConfidence("glibc", "2.31", "lib/libc-2.31.so")},
		},
		{
			name: "openssl soname only",
			fsys: fstest.MapFS{"usr/lib/libssl.so.3": &fstest.MapFile{}},
			want: []model.Component{lowConfidence("openssl", "3", "usr/lib/libssl.so.3")},
		},
		{
			name: "openssl 1.1 soname",
			fsys: fstest.MapFS{"lib/x86_64-linux-gnu/libssl.so.1.1": &fstest.MapFile{}},
			want: []model.Component{lowConfidence("openssl", "1.1", "lib/x86_64-linux-gnu/libssl.so.1.1")},
		},
		{
			name: "musl",
			fsys: fstest.MapFS{"lib/libc.musl-x86_64.so.1": &fstest.MapFile{}},
			want: []model.Component{lowConfidence("musl", "1", "lib/libc.musl-x86_64.so.1")},
		},
		{
			// Both name the same soname, so only one component is reported.
			// fs.ReadDir sorts, so libcrypto is the one seen first.
			name: "libssl and libcrypto at the same soname report once",
			fsys: fstest.MapFS{
				"usr/lib/libssl.so.3":    &fstest.MapFile{},
				"usr/lib/libcrypto.so.3": &fstest.MapFile{},
			},
			want: []model.Component{lowConfidence("openssl", "3", "usr/lib/libcrypto.so.3")},
		},
		{
			name: "miss: unversioned development symlink",
			fsys: fstest.MapFS{
				"usr/lib/libssl.so": &fstest.MapFile{},
				"usr/lib/libc.so":   &fstest.MapFile{},
			},
		},
		{
			name: "miss: nothing in a library directory",
			fsys: fstest.MapFS{"lib/firmware/blob.bin": &fstest.MapFile{}},
		},
		{
			name: "malformed: a directory named like a library",
			fsys: fstest.MapFS{"lib/libssl.so.3/placeholder": &fstest.MapFile{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertComponents(t, detectSharedLibraries(tt.fsys), tt.want)
		})
	}
}

// Everything the heuristic cataloger produces is low confidence, carries
// evidence, and carries no purl — which is what keeps it out of the matcher.
func TestHeuristicInvariants(t *testing.T) {
	fsys := fstest.MapFS{
		"lib/modules/5.10.0-11-arm64/modules.dep": &fstest.MapFile{},
		"bin/busybox":           &fstest.MapFile{Data: []byte("BusyBox v1.30.1 (Debian) multi-call binary.")},
		"lib/libc-2.31.so":      &fstest.MapFile{},
		"usr/lib/libssl.so.1.1": &fstest.MapFile{},
	}
	comps, err := NewHeuristic().Catalog(fsys)
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(comps) != 4 {
		t.Fatalf("got %d components, want 4: %+v", len(comps), comps)
	}
	for _, c := range comps {
		if c.Confidence != model.ConfidenceLow {
			t.Errorf("%s: confidence = %q, want low", c.Name, c.Confidence)
		}
		if c.Evidence == "" {
			t.Errorf("%s: no evidence recorded", c.Name)
		}
		if strings.HasPrefix(c.Evidence, "/") {
			t.Errorf("%s: evidence %q is absolute; it must describe the image", c.Name, c.Evidence)
		}
		if c.PURL != "" {
			t.Errorf("%s: has a purl %q; heuristics must not be queried", c.Name, c.PURL)
		}
	}
	// Sorted by name, like every other cataloger's output.
	for i := 1; i < len(comps); i++ {
		if model.CompareComponents(comps[i-1], comps[i]) > 0 {
			t.Errorf("not sorted at %d: %s then %s", i, comps[i-1].Name, comps[i].Name)
		}
	}
	if got := NewHeuristic().Name(); got != "heuristic" {
		t.Errorf("Name() = %q, want heuristic", got)
	}
}

func TestHeuristicEmptyRootfs(t *testing.T) {
	comps, err := NewHeuristic().Catalog(fstest.MapFS{})
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("got %d components from an empty rootfs", len(comps))
	}
}

func assertComponents(t *testing.T, got, want []model.Component) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d components, want %d:\n got  %+v\n want %+v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("component %d:\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
}
