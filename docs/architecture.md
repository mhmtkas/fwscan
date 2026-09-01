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
│  gz/xz/ │        │ heuristic│         │ + details │       │ exit code │
│  zst/lz4│        │          │         │           │       │           │
│ squashfs│        │          │         │           │       │  sbom     │
└─────────┘        └──────────┘         └──────────┘        └───────────┘
     │                                                            ▲
     └── cleanup() removes the temp dir ─────────────────────────┘
```

## The seam that matters

`input` produces an `fs.FS`. That single decision is why the rest is simple:

- Every input handler only has to produce one. A directory is `os.DirFS`; a
  tarball and a squashfs image are extracted to a temp directory and then are
  also `os.DirFS`.
- Every cataloger only has to read one, which makes it testable against
  `fstest.MapFS` with no fixture files at all. Most of the cataloger tests are
  ten-line string literals.
- Reads are confined. `os.DirFS` rejects absolute paths and paths climbing out
  of the root, so a crafted image cannot walk a cataloger onto the host.

`input.Open` always returns a non-nil cleanup, including on its error paths, so
`defer cleanup()` immediately after the call is always correct.

## Stages

### `internal/input`

Detection is by content, never by file extension — firmware build systems name
things carelessly, and an lz4 image called `.gz` is common. Magic numbers were
read off real files during the spike rather than copied from documentation,
which is how the fact that tar has no magic at offset 0 (`ustar` sits at 257)
ended up recorded rather than discovered in production.

Extraction is hostile-input territory: entry paths go through `safeJoin`, which
refuses anything resolving outside the temp directory; symlinks pointing out are
dropped rather than created, because `os.DirFS` follows symlinks through the
operating system; entry count, total bytes and single-file size are all bounded;
and `io.Copy` is capped rather than trusting the declared header size.

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

Three things here are not obvious and are all spike conclusions
(`spike/NOTES.md`):

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

### `internal/report` and `internal/sbom`

Everything these emit is fixed by [`output-spec.md`](output-spec.md). Files are
written through a temp file and a rename, so a reader never sees a half-written
report and a failure leaves any previous one intact. The SBOM carries components
only, never findings.

## Adding a cataloger

Say you want opkg, the OpenWrt package manager. (It is a v1.1 non-goal today —
this is the walkthrough, not an invitation.)

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
