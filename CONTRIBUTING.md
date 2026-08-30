# Contributing to fwscan

Thanks for looking. fwscan is a narrow tool on purpose, so the most useful thing
you can do before writing code is check that the change fits the scope.

## Before you start

Read [`docs/mvp-scope.md`](docs/mvp-scope.md), particularly the non-goals table.
Binary fingerprinting, SPDX output, opkg/rpm catalogers, kernel CVE
applicability, VEX and offline mode are deliberately excluded from v1 — a pull
request adding one of them will be declined however good the code is. Open an
issue first and let's talk about the version it belongs in.

The output formats are fixed by [`docs/output-spec.md`](docs/output-spec.md).
Terminal layout, JSON schema, SBOM fields, severity mapping and exit codes come
from there, not from taste. Changing one is a spec change plus a golden-file
update in the same pull request, called out in the description.

## Development

```sh
make build   # -> bin/fwscan
make test    # go test ./... -race -cover
make lint    # golangci-lint run
make help    # everything else
```

You need Go (version in `go.mod`) and `golangci-lint`. Scanning squashfs images
needs `squashfs-tools` 4.4 or newer — earlier builds lack lz4 and zstd support.

## What a good pull request looks like

- **One change.** Unrelated fixes go in unrelated pull requests.
- **Tests.** Table-driven where the input space is a table. Catalogers are tested
  against `fstest.MapFS`, so a new one needs no fixture files.
- **No network in unit tests.** OSV responses live in `testdata/osv/` as recorded
  fixtures. Only the `integration` build tag may reach the real API.
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
