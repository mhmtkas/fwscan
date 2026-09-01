package catalog

import (
	"strings"
	"testing"

	"github.com/mhmtkas/fwscan/internal/model"
)

// These parsers read untrusted firmware, so the property under test is not
// "produces the right answer" but "cannot be made to misbehave": no panic, no
// unbounded growth, and nothing claiming high confidence without a name.

func FuzzParseStatus(f *testing.F) {
	seeds := []string{
		"",
		"\n",
		"\n\n\n",
		"Package: openssl\nStatus: install ok installed\nVersion: 1.1.1k-1+deb11u1\nArchitecture: amd64\n",
		"Package: a\nStatus: deinstall ok config-files\nVersion: 1\n",
		// A Description that impersonates a stanza.
		"Package: a\nStatus: install ok installed\nVersion: 1\nDescription: x\n Package: b\n Status: install ok installed\n",
		// Source in both shapes.
		"Package: bsdutils\nStatus: install ok installed\nVersion: 1:2.36.1-8+deb11u1\nSource: util-linux (2.36.1-8+deb11u1)\n",
		"Package: libblkid1\nStatus: install ok installed\nVersion: 2.36.1-8\nSource: util-linux\n",
		// Structural noise.
		"no colon at all\n",
		":\n",
		"Package:\nStatus:\nVersion:\n",
		" leading continuation with no field\n",
		"Package: a\nStatus: install ok installed\nVersion: 1",
		"\x00\x01\x02binary garbage\n",
		"Package: \xff\xfe\nStatus: install ok installed\nVersion: \xff\n",
		strings.Repeat("Package: p\nStatus: install ok installed\nVersion: 1\n\n", 50),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		comps, err := parseStatus(strings.NewReader(data), "bookworm", "")
		if err != nil {
			return // a rejection is a valid outcome
		}
		for _, c := range comps {
			if c.Name == "" {
				t.Fatalf("component with no name: %+v", c)
			}
			if c.Confidence != model.ConfidenceHigh {
				t.Fatalf("dpkg component is not high confidence: %+v", c)
			}
			if c.Evidence != DpkgStatusPath {
				t.Fatalf("wrong evidence: %+v", c)
			}
			// The source always resolves to something, so a component is never
			// silently unqueryable.
			if c.Source == "" {
				t.Fatalf("component with no source: %+v", c)
			}
		}
	})
}

func FuzzParseApkInstalled(f *testing.F) {
	seeds := []string{
		"",
		"\n\n",
		"P:musl\nV:1.2.3-r0\nA:x86_64\no:musl\n",
		"P:libssl1.1\nV:1.1.1o-r0\nA:x86_64\no:openssl\n",
		"P:no-version\nA:x86_64\n",
		"P:\nV:\nA:\n",
		"C:Q1sboUEnyV+bt26L3Nbb/SQi1JAmE=\nP:a\nV:1\nA:x\nF:etc\nR:fstab\nZ:Q1x=\n",
		"LONGKEY:value\nP:a\nV:1\n",
		"no colon\n",
		"P:a\nV:1\n\nP:b\nV:2\n\nP:c\nV:3\n",
		"\x00\x01P:\xffa\nV:1\n",
		strings.Repeat("P:p\nV:1\nA:x\n\n", 50),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		comps, err := parseApkInstalled(strings.NewReader(data), "v3.16")
		if err != nil {
			return
		}
		for _, c := range comps {
			if c.Name == "" {
				t.Fatalf("component with no name: %+v", c)
			}
			if c.Confidence != model.ConfidenceHigh {
				t.Fatalf("apk component is not high confidence: %+v", c)
			}
			if c.Evidence != ApkInstalledPath {
				t.Fatalf("wrong evidence: %+v", c)
			}
			if c.Source == "" {
				t.Fatalf("component with no source: %+v", c)
			}
		}
	})
}
