# Contributing to fwscan

Thanks for looking. fwscan is a narrow tool on purpose, so the most useful thing
you can do before writing code is check that the change fits the scope.

## Before you start

Read [`docs/scope.md`](docs/scope.md), particularly the non-goals table.
Binary fingerprinting, SPDX output, opkg/rpm catalogers, kernel CVE
applicability, VEX and offline mode are deliberately excluded from v1 — a pull
request adding one of them will be declined however good the code is.
[`docs/roadmap.md`](docs/roadmap.md) says which are expected later and in what
order; open an issue first and let's talk about where it belongs.

The output formats are fixed by [`docs/output-spec.md`](docs/output-spec.md).
Terminal layout, JSON schema, SBOM fields, severity mapping and exit codes come
from there, not from taste. Changing one is a spec change plus a golden-file
update in the same pull request, called out in the description.

## Development

```sh
make build    # -> bin/fwscan
make fixtures # build the squashfs images the tests need
make test     # go test ./... -cover, with -race where the kernel supports it
make lint     # golangci-lint run
make help     # everything else
```

Run `make fixtures` once in a fresh clone. Three of the four squashfs
decompressors are covered by images that are built rather than committed — an
image compresses to roughly its own size, so committing four near-copies of one
fixture is a poor trade — and without them `make test` passes with those three
tests skipped. CI builds them, so it is honest; a contributor who has not may
touch lz4, zstd or xz handling and see nothing.

The race detector needs a 48-bit virtual address space on arm64, and several
single-board kernels are built narrower — an Orange Pi 5 is 39-bit, a Raspberry
Pi 5 is 47. `make test` detects that and runs without it rather than dying with
`ThreadSanitizer: unsupported VMA range`. CI runs on amd64 and uses
`make test-race`, which insists on it.

You need Go (version in `go.mod`) and `golangci-lint` **version 2** —
`.golangci.yml` is a v2 configuration and v1 refuses it. `make lint` says so
rather than failing with a bare "no such file". Scanning squashfs images
needs `squashfs-tools` 4.4 or newer — earlier builds lack lz4 and zstd support.

## What a good pull request looks like

- **One change.** Unrelated fixes go in unrelated pull requests.
- **Tests.** Table-driven where the input space is a table. Catalogers are tested
  against `fstest.MapFS`, so a new one needs no fixture files.
- **No network in unit tests.** OSV responses live in `testdata/osv/` and the
  Debian security tracker's lists in `testdata/tracker/`, both as recorded or
  hand-built fixtures. Only the `integration` build tag may reach a real API.
  This is easy to break by accident: the matcher's defaults point at the real
  services, so a test that constructs one must clear `TrackerBase` or point it
  at a server of its own. One did not, and the end-to-end test quietly started
  fetching 60 MB from salsa.debian.org on every run.
- **`make lint test` green**, and coverage not going backwards.
- **`CHANGELOG.md` updated** under `[Unreleased]`.
- **Conventional Commits**: `feat:`, `fix:`, `test:`, `docs:`, `chore:`.

## Test fixtures

Fixtures must come from public images — official Debian, Raspberry Pi OS or
OpenWrt releases — or from synthetically built rootfs directories. Never commit
anything derived from a private or employer system, and record where a fixture
came from. `spike/fixtures/PROVENANCE.md` shows the expected level of detail.

Keep them small. A dpkg status file and a couple of identity files is usually
enough; whole rootfs images are not.

## Adding a cataloger

`internal/catalog` defines a one-method interface. A new cataloger reads from an
`fs.FS`, returns `[]model.Component`, sets `Confidence: high` only when the
evidence is a package-manager database, and always sets `Evidence` to the path
inside the image it read. Heuristics are `Confidence: low`, without exception.

## Security

Please do not open public issues for security problems in fwscan itself. See
[`SECURITY.md`](SECURITY.md).
