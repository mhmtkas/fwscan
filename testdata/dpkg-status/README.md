# dpkg status samples

`bookworm-slim-status` and `bookworm-slim-os-release` are the dpkg database and
distro identity file from the official `debian:bookworm-slim` image on Docker
Hub, Debian 12.15, 88 packages, all `install ok installed`.

Full provenance — image tag, manifest and layer digests, checksums — is in
[`spike/fixtures/PROVENANCE.md`](../../spike/fixtures/PROVENANCE.md). Both files
are public and redistributable.

The 88-package count is asserted byte-for-byte against `dpkg-query` in
`spike/NOTES.md` (T0.2), so the expected value in the tests is oracle-backed
rather than self-fulfilling.
