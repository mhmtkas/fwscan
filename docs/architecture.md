# Architecture

fwscan is a four-stage pipeline. Each stage is an interface, so a new input
format, package database or vulnerability source is an addition rather than a
refactor.

```
  path                fs.FS              []Component          []Finding
    │                   │                     │                   │
    ▼                   ▼                     ▼                   ▼
┌─────────┐        ┌──────────┐         ┌──────────┐        ┌───────────┐
│  input  │───────▶│  catalog │────────▶│  match   │───────▶│  report   │
│         │        │          │         │          │        │           │
│ dir     │        │ dpkg     │         │ OSV      │        │ terminal  │
│ tar+    │        │ apk      │         │ querybatch│       │ json      │
│  gz/xz/ │        │ heuristic│         │ + details │       │ sbom      │
│  zst/lz4│        │          │         │           │       │ cra       │
│ squashfs│        │          │         │ debian    │       │ exit code │
│         │        │          │         │ tracker   │       │           │
└─────────┘        └──────────┘         └──────────┘        └───────────┘
     │                   │                    ▲                   ▲
     │                   └──── release ───────┴───────────────────┘
     │                        (support dates)
     └── cleanup() removes the temp dir
```

`internal/release` is not a stage. It is a table consulted by two of them, and
what it answers decides which data source a scan reaches at all.

## The seam that matters

`input` produces an `fs.FS`. That single decision is why the rest is simple:

- Every input handler only has to produce one. A directory is opened as an
  `os.Root` and served through `Root.FS`; a tarball and a squashfs image are
  extracted to a temp directory and then served the same way.
- Every cataloger only has to read one, which makes it testable against
  `fstest.MapFS` with no fixture files at all. Most of the cataloger tests are
  ten-line string literals.
- Reads are confined where the kernel resolves the path, not where a string is
  inspected. `os.Root` refuses any path component — including one reached
  through a symlink — that leaves the directory, so a crafted image cannot walk
  a cataloger onto the host. `os.DirFS` would not do: it rejects a path that
  spells its way out and follows a symlink wherever it points.

`input.Open` always returns a non-nil cleanup, including on its error paths, so
`defer cleanup()` immediately after the call is always correct.

## Stages

### `internal/input`

Detection is by content, never by file extension — firmware build systems name
things carelessly, and an lz4 image called `.gz` is common. Magic numbers were
read off real files during the spike rather than copied from documentation,
which is how the fact that tar has no magic at offset 0 (`ustar` sits at 257)
ended up recorded rather than discovered in production.

Extraction is hostile-input territory, and the guarantee is layered. Every
write goes through the same `os.Root` the reads will use, so a path that only
becomes an escape once symlinks are followed — `a -> ..` then `b -> a/..`, each
step reading as inside — is refused by the kernel-side resolution rather than by
a string check. `safeName` still runs first, so a hostile entry name produces an
error naming the entry instead of a temp path. Symlinks pointing out are dropped
rather than created; hard links must point inside. The entry count, total bytes
and single-file size are bounded, `io.Copy` is capped rather than trusting the
declared header size, and the whole extraction is bounded against the size of
the archive on disk — more than 64 MiB at over 5000× the source is refused,
which is what catches a PAX sparse entry that expands without a byte passing
through the decompressor. Extraction checks the context between entries, so an
interrupted scan stops and its cleanup runs.

`unsquashfs` writes outside `os.Root`, so it cannot be confined the same way; it
runs under a deadline and the caller's cancellation with bounded output, and
what fwscan then reads from its output directory is confined exactly as above.

### `internal/catalog`

```go
type Cataloger interface {
    Name() string
    Catalog(root fs.FS) ([]model.Component, error)
}
```

A cataloger that finds nothing returns an empty slice and a nil error. An image
without a dpkg database is not an error; it is an image without a dpkg database.
Errors are for a database that exists and cannot be read.

`Confidence: high` is reserved for package-manager databases. Everything else is
`low` and carries `Evidence` — the path inside the image it came from.

### `internal/match`

```go
type Matcher interface {
    Match(ctx context.Context, comps []model.Component) ([]model.Finding, error)
}
```

Six things here are not obvious, and all of them are spike conclusions
(`spike/NOTES.md`) rather than design preferences:

1. **OSV keys Debian data on source packages.** Querying `libssl1.1` returns
   zero vulnerabilities — not an error, zero. The `Source:` field resolves the
   name, and its parenthesised version wins over the binary `Version` when they
   differ.
2. **The release must reach the query, and how differs by ecosystem.** Debian
   goes as a purl with `?distro=bullseye`. Alpine cannot: OSV's Alpine records
   carry no distro qualifier and keep the release in their `ecosystem` field, so
   Alpine goes as `{name, ecosystem: "Alpine:v3.16"}` plus a version. Both
   failure modes are silent — the wrong shape returns zero results, and an image
   scans perfectly clean.
3. **`querybatch` returns identifiers only.** Severity and fixed versions need a
   second request each, which is why lookups are deduplicated by source package
   and details are fetched through a bounded worker pool.
4. **An advisory is several vulnerabilities.** For an oldstable Debian release
   OSV returns only DSA and DLA records, each naming every CVE its upload
   fixed, with no severity of its own and no `distro` qualifier on its purl. So
   a record becomes one finding per CVE, each taking its assessment from that
   CVE's own record and the release from the advisory's `ecosystem` field.
5. **A query that cannot carry a release is not made.** An unscoped Debian purl
   does not return nothing — it returns every release at once. A Yocto image
   with a dpkg database and no `VERSION_CODENAME` produced 182 findings for six
   packages, carrying fixed versions from eight Debian releases (T66). The apk
   path already refused for the same reason with the opposite symptom, and the
   deb path now does too.
6. **OSV stops carrying a Debian release the day it leaves free support**,
   because its importer reads the security tracker's JSON export and that export
   does. So the matcher has a second source for exactly that case: the tracker's
   own `CVE/list`, plus the `DSA/list` and `DLA/list` files that hold the
   per-release fixed versions a CVE closed by an advisory has nowhere else
   (T58). It runs only when `internal/release` says the release is out of free
   support, and a finding from it carries `source: security-tracker.debian.org`
   so a reader can tell the halves apart.

### `internal/release`

A vendored copy of `distro-info-data`, the table Debian and Ubuntu maintain of
when each release was made and when each support tier ends, embedded rather than
fetched so an offline run still knows.

It is consulted rather than chained, by `match` and by `report`, and it answers
one question with three consequences: which support window covers this release
today, and is that window free.

- `match` uses it to decide whether OSV can answer at all, which is what gates
  the Debian fallback above. Free support and OSV coverage are the same
  boundary, because they come from the same export.
- `report` uses it for the support paragraph the CRA document opens its
  vulnerability section with, where a release past free support is the finding
  rather than a footnote.
- Three states, and they are exhaustive: in a window, past every window, and not
  yet released. The third is not a shade of the second — a development branch
  has no release date, so it sits in no window while not being dead — and code
  that assumed two states dereferenced a nil window and crashed on a real forky
  rootfs (T67).

A distribution the table does not name is reported as unknown rather than
guessed at. `catalog` resolves a derivative to its base first, through
os-release's `ID_LIKE`, so Raspberry Pi OS is looked up as Debian.

### `internal/purl`

Both `catalog` and `match` build purls and neither owns the format: a cataloger
names the binary package it found, the matcher names the source package it asks
OSV about, and the two have to agree down to the percent-encoding of a version's
`+`. So the constructors sit in one package below both, and `catalog` depends on
nothing but `model` and it.

### `internal/report` and `internal/sbom`

Everything these emit is fixed by [`output-spec.md`](output-spec.md). Files are
written through a temp file and a rename, so a reader never sees a half-written
report and a failure leaves any previous one intact. The SBOM carries components
only, never findings.

Four renderers over one set of results: the terminal table, the JSON report, the
CycloneDX SBOM, and the CRA evidence document. The last needs nothing from the
pipeline that the others do not already have, which is why it could be added
without touching input, cataloging or matching — but it does read
`internal/release`, because what it has to say about a release out of support is
the part of it that matters.

Anything from the image reaches all four through `report.Sanitize`, and the
Markdown one escapes further: a pipe is a printable character that ends a table
cell, so a crafted package name could otherwise forge a row in a compliance
document.

## Adding a cataloger

Say you want opkg, the OpenWrt package manager. (It is on the roadmap and not
in this release — this is the walkthrough, not an invitation.)

**1. Write the parser.** New file in `internal/catalog`, one type with the two
interface methods:

```go
type Opkg struct{}

func NewOpkg() *Opkg     { return &Opkg{} }
func (Opkg) Name() string { return "opkg" }

func (Opkg) Catalog(root fs.FS) ([]model.Component, error) {
    f, err := root.Open("usr/lib/opkg/status")
    if err != nil {
        if errors.Is(err, fs.ErrNotExist) {
            return nil, nil // no opkg here, not a problem
        }
        return nil, fmt.Errorf("reading the package database: %w", err)
    }
    defer func() { _ = f.Close() }()
    // ...
}
```

**2. Bound your allocations.** The file is untrusted. Cap the line length, the
number of entries and any field that accumulates. `dpkg.go` has the pattern.

**3. Resolve the source package.** Whatever the format calls it, the matcher
needs the name OSV keys on, plus the release. Set `Source`, `SourceVersion` and
`Distro`, not just `Name` and `Version`.

**4. Prove the query shape before writing the matcher path.** Do not assume it
matches Debian's. Alpine did not, and finding out cost one probe and saved a
scanner that reported every Alpine image as clean. Record the evidence in
`spike/NOTES.md` the way T0.3 and T0.3a do.

**5. Register it** in `All()` in `cataloger.go`.

**6. Test against `fstest.MapFS`.** No fixture files needed:

```go
root := fstest.MapFS{
    "usr/lib/opkg/status": &fstest.MapFile{Data: []byte("Package: busybox\n...")},
}
comps, err := NewOpkg().Catalog(root)
```

Cover the normal entry, a not-installed entry, a version with whatever the
format's equivalent of an epoch is, and a malformed line. Add a fuzz target next
to the ones in `fuzz_test.go`.

**7. Add a real fixture** from a public image, with provenance recorded the way
`spike/fixtures/PROVENANCE.md` does it, and assert an exact package count
against the format's own tooling if there is any.

## Adding a matcher

Implement `Matcher`, put recorded responses in `testdata/osv/`, and keep the unit
tests off the network — only the `integration`-tagged tests may reach a real API.
`report` consumes `[]model.Finding` and does not care where they came from.
`sbom` does not see findings at all: it serialises `[]model.Component` and is
written before the matcher runs, so a network failure still leaves the artifact
that does not depend on the network.
