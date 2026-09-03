// Package release answers how much longer a distribution release receives
// security updates, and whether those updates are free.
//
// It exists because a scan that reports nothing is ambiguous. A Debian 11
// image scanned after 2026-08-31 produces no findings at all, and the reason is
// not that the image is sound: it is that Debian 11 left free support that day,
// OSV's Debian data is built from the security tracker's export, and that
// export carries only releases still inside a free support window. Without this
// table fwscan can say "no findings" and cannot say why.
//
// The dates come from distro-info-data, the table Debian and Ubuntu maintain
// for exactly this question, vendored rather than fetched so a scan needs no
// second network call and an air-gapped run still knows. See debian.csv and
// ubuntu.csv, and THIRD_PARTY_LICENSES.txt for their terms.
package release

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"io"
	"strings"
	"time"
)

//go:embed debian.csv
var debianCSV []byte

//go:embed ubuntu.csv
var ubuntuCSV []byte

// Window is one support tier: how long it lasts and whether its updates can be
// installed without paying for them.
//
// The distinction is not a detail. Debian 11 is covered by Freexian's Extended
// LTS until 2031 and Ubuntu 18.04 by Ubuntu Pro until 2028, and in both cases a
// reader told only "still supported" would draw the wrong conclusion about an
// image they are shipping.
type Window struct {
	// Name is the tier as its vendor names it, for reporting.
	Name string
	// Until is the day the tier ends. Always set: a window with no end date is
	// not recorded as a window at all.
	Until time.Time
	// Free reports whether the updates in this tier are published to everyone.
	// Debian's LTS is; its Extended LTS and Ubuntu's ESM are not.
	Free bool
}

// Support describes one release.
type Support struct {
	// ID and Series are the os-release ID and VERSION_CODENAME the image
	// reported, echoed back so a caller can render them without keeping them.
	ID     string
	Series string
	// Version is the release number, e.g. "11" or "22.04 LTS".
	Version string
	// Released is the day the release shipped. Zero for one that has not.
	Released time.Time
	// Windows are the support tiers in order, earliest ending first.
	Windows []Window
	// Current is the window containing the date asked about, and is nil when
	// the release is past every tier or has not been released yet.
	Current *Window
}

// EndOfLife reports whether the release is past every support tier, free or
// paid. Nothing further will be published for it by anyone.
func (s Support) EndOfLife() bool {
	return s.Current == nil && !s.Released.IsZero()
}

// Unreleased reports whether the release has not shipped yet: a development
// branch such as Debian forky or sid.
//
// It is a third state, not a shade of the other two. Such a release is in no
// support window, so Current is nil and FreelySupported is false, which reads
// exactly like end of life -- and a caller that assumed those two cases were
// the only ones would dereference Current and crash. One did.
func (s Support) Unreleased() bool {
	return s.Current == nil && s.Released.IsZero()
}

// FreelySupported reports whether the release is in a tier whose updates are
// published to everyone. This is also what predicts OSV coverage for Debian:
// the security tracker's JSON export, which OSV's Debian data is built from,
// carries a release for exactly as long as it is freely supported.
func (s Support) FreelySupported() bool {
	return s.Current != nil && s.Current.Free
}

// LastFree is the day free support ended, or zero if it has not. Used to say
// when a release stopped receiving public security updates rather than only
// that it did.
func (s Support) LastFree() time.Time {
	var last time.Time
	for _, w := range s.Windows {
		if w.Free && w.Until.After(last) {
			last = w.Until
		}
	}
	return last
}

// Lookup finds the release the image reported, as of at.
//
// The series is matched first because it is unambiguous -- "bullseye" names one
// release forever -- and the version is the fallback for an image whose
// os-release carries no VERSION_CODENAME. Neither is trusted to be a release
// this table knows: a derivative reports its own name, and an unknown release
// is reported as unknown rather than guessed at.
func Lookup(id, series, version string, at time.Time) (Support, bool) {
	table, ok := tableFor(id)
	if !ok {
		return Support{}, false
	}
	for _, r := range table {
		if !matches(r, series, version) {
			continue
		}
		r.ID = id
		r.Current = windowAt(r, at)
		return r, true
	}
	return Support{}, false
}

func matches(r Support, series, version string) bool {
	if series != "" && strings.EqualFold(r.Series, series) {
		return true
	}
	// distro-info-data writes Ubuntu's long-term releases as "24.04 LTS" while
	// os-release reports "24.04", so the version is compared on its first
	// field rather than whole.
	return series == "" && version != "" && strings.EqualFold(versionNumber(r.Version), version)
}

func versionNumber(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// windowAt returns the tier covering at. Windows are ordered, so the first one
// that has not ended is the one in force; a release whose windows have all
// ended, or which has not been released, is in none.
func windowAt(r Support, at time.Time) *Window {
	if r.Released.IsZero() || at.Before(r.Released) {
		return nil
	}
	for i := range r.Windows {
		if !at.After(r.Windows[i].Until) {
			return &r.Windows[i]
		}
	}
	return nil
}

func tableFor(id string) ([]Support, bool) {
	switch strings.ToLower(id) {
	case "debian":
		return debianTable, true
	case "ubuntu":
		return ubuntuTable, true
	default:
		return nil, false
	}
}

var (
	debianTable = mustParse(debianCSV, debianWindows)
	ubuntuTable = mustParse(ubuntuCSV, ubuntuWindows)
)

// debianWindows names Debian's three tiers. LTS is done by a volunteer team and
// published to everyone; Extended LTS is Freexian's commercial offering and is
// not, which is why a bullseye image today is not "still supported" in any
// sense a reader would assume.
func debianWindows(f fields) []Window {
	return windows(f,
		window{column: "eol", name: "security support", free: true},
		window{column: "eol-lts", name: "LTS", free: true},
		window{column: "eol-elts", name: "Extended LTS (Freexian, commercial)", free: false},
	)
}

// ubuntuWindows names Ubuntu's. Everything past the first requires an Ubuntu
// Pro subscription, so a fix named in one of those tiers is not a fix most
// readers can install. eol-server is deliberately not a window: it applied to
// releases before 12.04 and duplicates eol for every release since.
func ubuntuWindows(f fields) []Window {
	return windows(f,
		window{column: "eol", name: "security support", free: true},
		window{column: "eol-esm", name: "ESM (Ubuntu Pro)", free: false},
		window{column: "eol-legacy", name: "Legacy add-on (Ubuntu Pro)", free: false},
	)
}

type window struct {
	column, name string
	free         bool
}

func windows(f fields, defs ...window) []Window {
	var out []Window
	for _, d := range defs {
		until, ok := f.date(d.column)
		if !ok {
			continue
		}
		// A tier that ends before one already recorded would put the list out
		// of order and make windowAt return the wrong one. distro-info-data
		// does not do this, and the parser does not assume it never will.
		if len(out) > 0 && until.Before(out[len(out)-1].Until) {
			continue
		}
		out = append(out, Window{Name: d.name, Until: until, Free: d.free})
	}
	return out
}

// fields is one CSV row addressed by column name. The two files do not share a
// header -- Debian has eol-lts and eol-elts where Ubuntu has eol-server,
// eol-esm and eol-legacy -- and rows are ragged, because a release that has not
// reached a tier yet simply stops early.
type fields struct {
	index map[string]int
	row   []string
}

func (f fields) get(column string) string {
	i, ok := f.index[column]
	if !ok || i >= len(f.row) {
		return ""
	}
	return strings.TrimSpace(f.row[i])
}

func (f fields) date(column string) (time.Time, bool) {
	v := f.get(column)
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.DateOnly, v)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// mustParse reads a vendored table. The files are embedded, so a parse failure
// is a build-time mistake in this repository rather than anything an image can
// cause; the result is an empty table and every lookup reporting unknown, which
// degrades to the behaviour fwscan had before this package existed.
func mustParse(data []byte, windowsFor func(fields) []Window) []Support {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		return nil
	}
	index := make(map[string]int, len(header))
	for i, name := range header {
		index[strings.TrimSpace(name)] = i
	}

	var out []Support
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		f := fields{index: index, row: row}
		series := f.get("series")
		if series == "" {
			continue
		}
		released, _ := f.date("release")
		out = append(out, Support{
			Series:   series,
			Version:  f.get("version"),
			Released: released,
			Windows:  windowsFor(f),
		})
	}
	return out
}
