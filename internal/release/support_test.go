package release

import (
	"testing"
	"time"
)

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

// The table is vendored data, so these cases are assertions about the real
// schedules Debian and Ubuntu publish. Each date below is the day the vendor's
// own CSV names, and a case is here because something in fwscan behaves
// differently on either side of it.
func TestLookup(t *testing.T) {
	tests := []struct {
		name            string
		id, series, ver string
		at              string
		found           bool
		wantVersion     string
		wantWindow      string
		wantFree        bool
		wantEOL         bool
		wantUnreleased  bool
	}{
		{
			// The case this package was written for. Debian 11 left free
			// support on 2026-08-31, which is the day OSV's Debian data stopped
			// carrying it, which is why a scan of a bullseye image reports
			// nothing.
			name: "debian 11 the day before free support ended",
			id:   "debian", series: "bullseye", ver: "11", at: "2026-08-31",
			found: true, wantVersion: "11", wantWindow: "LTS", wantFree: true,
		},
		{
			name: "debian 11 the day after",
			id:   "debian", series: "bullseye", ver: "11", at: "2026-09-01",
			found: true, wantWindow: "Extended LTS (Freexian, commercial)", wantFree: false,
		},
		{
			name: "debian 12 is in free LTS",
			id:   "debian", series: "bookworm", ver: "12", at: "2026-09-03",
			found: true, wantWindow: "LTS", wantFree: true,
		},
		{
			name: "debian 13 is in ordinary security support",
			id:   "debian", series: "trixie", ver: "13", at: "2026-09-03",
			found: true, wantWindow: "security support", wantFree: true,
		},
		{
			// Ubuntu's extended tiers need a subscription, so a release in one
			// is not "supported" in any sense that helps a reader.
			name: "ubuntu 18.04 is ESM only",
			id:   "ubuntu", series: "bionic", ver: "18.04", at: "2026-09-03",
			found: true, wantWindow: "ESM (Ubuntu Pro)", wantFree: false,
		},
		{
			name: "ubuntu 22.04 is freely supported",
			id:   "ubuntu", series: "jammy", ver: "22.04", at: "2026-09-03",
			found: true, wantVersion: "22.04 LTS", wantWindow: "security support", wantFree: true,
		},
		{
			// os-release reports "24.04"; distro-info-data writes "24.04 LTS".
			name: "an ubuntu release matches on its version when the codename is missing",
			id:   "ubuntu", series: "", ver: "24.04", at: "2026-09-03",
			found: true, wantVersion: "24.04 LTS", wantFree: true, wantWindow: "security support",
		},
		{
			// Every tier including Freexian's has run out.
			name: "debian 8 is past everything",
			id:   "debian", series: "jessie", ver: "8", at: "2026-09-03",
			found: true, wantEOL: true,
		},
		{
			name: "a derivative is not in the table",
			id:   "linuxmint", series: "vanessa", ver: "21", at: "2026-09-03",
			found: false,
		},
		{
			name: "a release nobody has heard of is not guessed at",
			id:   "debian", series: "notarelease", ver: "999", at: "2026-09-03",
			found: false,
		},
		{
			// A release with a row but no release date yet is in no window: it
			// cannot be running on anything.
			name: "an unreleased series is in no support window",
			id:   "debian", series: "duke", ver: "15", at: "2026-09-03",
			found: true, wantWindow: "", wantUnreleased: true,
		},
		{
			// forky has a row and a creation date but no release date. A
			// caller that treated "no window" as end of life dereferenced
			// Current and crashed on a real image, so the state is named.
			name: "a development branch is unreleased rather than dead",
			id:   "debian", series: "forky", ver: "14", at: "2026-09-03",
			found: true, wantWindow: "", wantUnreleased: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Lookup(tt.id, tt.series, tt.ver, day(tt.at))
			if ok != tt.found {
				t.Fatalf("Lookup(%q, %q, %q) found = %v, want %v", tt.id, tt.series, tt.ver, ok, tt.found)
			}
			if !ok {
				return
			}
			if tt.wantVersion != "" && got.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVersion)
			}
			window := ""
			if got.Current != nil {
				window = got.Current.Name
			}
			if window != tt.wantWindow {
				t.Errorf("current window = %q, want %q", window, tt.wantWindow)
			}
			if got.FreelySupported() != tt.wantFree {
				t.Errorf("FreelySupported() = %v, want %v", got.FreelySupported(), tt.wantFree)
			}
			if got.EndOfLife() != tt.wantEOL {
				t.Errorf("EndOfLife() = %v, want %v", got.EndOfLife(), tt.wantEOL)
			}
			if got.Unreleased() != tt.wantUnreleased {
				t.Errorf("Unreleased() = %v, want %v", got.Unreleased(), tt.wantUnreleased)
			}
			// The three states are exclusive, and a caller reaching past all
			// three finds a nil Current. That is what crashed.
			if got.Current == nil && !got.EndOfLife() && !got.Unreleased() {
				t.Error("no current window and neither end of life nor unreleased")
			}
		})
	}
}

// FreelySupported is what predicts whether OSV holds per-CVE records for a
// release: OSV's Debian data is built from the security tracker's JSON export,
// and that export carries a release for exactly as long as it is freely
// supported. Measured against the API on 2026-09-03: glibc under Debian:11
// returned five records, all DSA or DLA, and DEBIAN-CVE-2023-4806 listed
// Debian:12, 13 and 14 and not 11.
func TestFreeSupportPredictsOSVCoverage(t *testing.T) {
	at := day("2026-09-03")
	covered := map[string]bool{"bookworm": true, "trixie": true, "bullseye": false, "buster": false}
	for series, want := range covered {
		s, ok := Lookup("debian", series, "", at)
		if !ok {
			t.Fatalf("debian %s is not in the table", series)
		}
		if s.FreelySupported() != want {
			t.Errorf("debian %s: FreelySupported() = %v, want %v", series, s.FreelySupported(), want)
		}
	}
}

func TestLastFree(t *testing.T) {
	// The end of the last free tier, not of the last tier: Debian 11's Extended
	// LTS runs to 2031 and is Freexian's to sell.
	s, ok := Lookup("debian", "bullseye", "", day("2026-09-03"))
	if !ok {
		t.Fatal("bullseye is not in the table")
	}
	if got := s.LastFree(); !got.Equal(day("2026-08-31")) {
		t.Errorf("LastFree() = %s, want 2026-08-31", got.Format(time.DateOnly))
	}
}

// Windows have to be in order, or windowAt returns the wrong tier for a date
// two of them cover.
func TestWindowsAreOrdered(t *testing.T) {
	for _, table := range [][]Support{debianTable, ubuntuTable} {
		for _, r := range table {
			for i := 1; i < len(r.Windows); i++ {
				if r.Windows[i].Until.Before(r.Windows[i-1].Until) {
					t.Errorf("%s: window %q ends before %q",
						r.Series, r.Windows[i].Name, r.Windows[i-1].Name)
				}
			}
		}
	}
}

// The embedded files are the reason this package can answer offline. An empty
// table is the failure mode that would make every lookup silently report
// unknown, which reads exactly like a derivative and would hide the problem.
func TestTablesAreNotEmpty(t *testing.T) {
	if len(debianTable) < 10 {
		t.Errorf("the debian table has %d rows, which is too few to be the real file", len(debianTable))
	}
	if len(ubuntuTable) < 20 {
		t.Errorf("the ubuntu table has %d rows, which is too few to be the real file", len(ubuntuTable))
	}
	for _, r := range debianTable {
		if r.Series == "" {
			t.Error("a debian row has no series")
		}
	}
}

func TestUnknownDistributionIsNotGuessedAt(t *testing.T) {
	for _, id := range []string{"", "alpine", "openwrt", "raspbian", "DEBIAN\x00"} {
		if _, ok := Lookup(id, "bullseye", "11", day("2026-09-03")); ok {
			t.Errorf("Lookup(%q, ...) claimed to know the release", id)
		}
	}
	// The one spelling that must work is the one os-release uses, in whatever
	// case the image wrote it.
	if _, ok := Lookup("Debian", "bullseye", "11", day("2026-09-03")); !ok {
		t.Error(`Lookup("Debian", ...) did not match the table`)
	}
}
