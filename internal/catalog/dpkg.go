package catalog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"

	"github.com/mhmtkas/fwscan/internal/model"
	"github.com/mhmtkas/fwscan/internal/purl"
)

// DpkgStatusPath is where dpkg records installed packages, relative to the
// rootfs. It is also the Evidence value every component from this cataloger
// carries.
const DpkgStatusPath = "var/lib/dpkg/status"

// installedStatus is the only Status value that means the package's files are
// on disk. Anything else — deinstall, config-files, half-installed — is a
// record of a package that is not there (spike/NOTES.md T0.2).
const installedStatus = "install ok installed"

// Bounds on a hostile status file. dpkg stanzas are small; these limits are
// generous by two orders of magnitude and still cap memory at a few hundred
// megabytes for the pathological case (CLAUDE.md rule 9).
const (
	maxLineBytes  = 1 << 20 // 1 MiB, vs a few hundred bytes in practice
	maxStanzas    = 500_000 // a full Debian archive is ~65k source packages
	maxFieldBytes = 4 << 20 // a Description that grows without bound
)

// maxStatusBytes bounds the whole file, which the per-part limits above do not:
// each of them can be satisfied by a file that is still arbitrarily long. A
// real status file is a few megabytes. It is a variable so a test can lower it;
// nothing else assigns to it.
var maxStatusBytes int64 = 256 << 20

// sourceWithVersion matches the "name (version)" form of the Source field. The
// parenthesised version appears exactly when the source version differs from
// the binary version — binNMUs, and binaries carrying an epoch their source
// does not (spike/NOTES.md T0.3).
var sourceWithVersion = regexp.MustCompile(`^(\S+)\s*\((.+)\)\s*$`)

// Dpkg catalogs packages from a dpkg status database.
type Dpkg struct{}

// NewDpkg returns the dpkg cataloger.
func NewDpkg() *Dpkg { return &Dpkg{} }

// Name implements Cataloger.
func (Dpkg) Name() string { return "dpkg" }

// Catalog implements Cataloger. A rootfs with no dpkg database yields no
// components and no error.
func (d Dpkg) Catalog(ctx context.Context, root fs.FS) ([]model.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := root.Open(DpkgStatusPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the package database: %w", err)
	}
	defer func() { _ = f.Close() }()

	codename, release := detectRelease(root)

	comps, err := parseStatus(f, codename, release)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", DpkgStatusPath, err)
	}
	return comps, nil
}

// parseStatus reads RFC-822-style stanzas separated by blank lines.
func parseStatus(r io.Reader, codename, release string) ([]model.Component, error) {
	var (
		out    []model.Component
		fields = map[string]string{}
		// The field currently being read. Continuation lines are appended to a
		// builder rather than to the map entry: "s += line" copies the whole
		// field on every line, which is quadratic, and the limits here permit
		// enough continuation lines for that to cost an hour of CPU on a few
		// megabytes of input. A builder appends in amortised constant time.
		lastKey  string
		value    strings.Builder
		stanzas  int
		fieldLen int
		read     int64
	)

	// commit stores the field that has just ended, if there is one.
	commit := func() {
		if lastKey != "" {
			fields[lastKey] = value.String()
		}
		lastKey, fieldLen = "", 0
		value.Reset()
	}

	flush := func() error {
		commit()
		defer func() {
			fields = map[string]string{}
		}()
		if len(fields) == 0 {
			return nil
		}
		stanzas++
		if stanzas > maxStanzas {
			return fmt.Errorf("status file has more than %d stanzas", maxStanzas)
		}
		if fields["Status"] != installedStatus || fields["Package"] == "" {
			return nil
		}
		out = append(out, componentFrom(fields, codename, release))
		return nil
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := sc.Text()

		// A bound on the whole file, not only on its parts. Every individual
		// limit here can be satisfied by a file that is still arbitrarily long.
		read += int64(len(line)) + 1
		if read > maxStatusBytes {
			return nil, fmt.Errorf("package database is larger than %d bytes", maxStatusBytes)
		}

		switch {
		case line == "":
			if err := flush(); err != nil {
				return nil, err
			}
		case line[0] == ' ' || line[0] == '\t':
			// A continuation line belongs to the previous field. Treating it as
			// a new field is the classic multi-line Description bug: a
			// Description can contain lines that look exactly like "Package:".
			if lastKey == "" {
				continue
			}
			fieldLen += len(line)
			if fieldLen > maxFieldBytes {
				return nil, fmt.Errorf("field %q exceeds %d bytes", lastKey, maxFieldBytes)
			}
			value.WriteByte('\n')
			value.WriteString(strings.TrimSpace(line))
		default:
			key, rest, found := strings.Cut(line, ":")
			if !found {
				// A malformed line must not take the scan down; a hostile image
				// would otherwise be a denial of service on the whole tool.
				continue
			}
			commit()
			lastKey = key
			fieldLen = len(line)
			value.WriteString(strings.TrimSpace(rest))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// The last stanza need not be followed by a blank line.
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// componentFrom builds a Component from one parsed stanza.
func componentFrom(fields map[string]string, codename, release string) model.Component {
	name := fields["Package"]
	version := fields["Version"]
	arch := fields["Architecture"]
	sourceName, sourceVersion := sourceOf(fields)

	return model.Component{
		Name:          name,
		Version:       version,
		Arch:          arch,
		Source:        sourceName,
		SourceVersion: sourceVersion,
		Distro:        codename,
		DistroVersion: release,
		PURL:          purl.Binary(name, version, arch, codename),
		Confidence:    model.ConfidenceHigh,
		Evidence:      DpkgStatusPath,
	}
}

// sourceOf resolves the source package name and version for a stanza:
//
//	Source: util-linux (2.36.1-8+deb11u1)  -> that name and that version
//	Source: util-linux                     -> that name, the binary Version
//	absent                                 -> the binary Package and Version
//
// Honouring the parenthesised form is what keeps binNMU and epoch cases correct.
// Querying OSV with a binary version carrying an epoch its source lacks sorts
// the query above every fixed-version range and silently loses findings
// (spike/NOTES.md T0.3).
func sourceOf(fields map[string]string) (name, version string) {
	name, version = fields["Package"], fields["Version"]
	src := strings.TrimSpace(fields["Source"])
	if src == "" {
		return name, version
	}
	if m := sourceWithVersion.FindStringSubmatch(src); m != nil {
		return m[1], m[2]
	}
	return src, version
}
