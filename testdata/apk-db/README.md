# apk database sample

`alpine-3.16.0-installed` and `alpine-3.16.0-os-release` come from the official
`alpine:3.16.0` image on Docker Hub, `linux/amd64`, 14 packages.

| | |
|---|---|
| Manifest digest | `sha256:4ff3ca91275773af45cb4b0834e12b7eb47d1c18f770a0b151381cd227f4c253` |
| Layer digest | `sha256:2408cc74d12b6cd092bb8b516ba7d5e290f485d3eb9672efc00f0583730179e8` |

Pulled through the registry API with the blob checksum verified against the
digest the registry advertised, the same way as the Debian fixtures. Public and
redistributable.

3.16.0 is deliberately an old release, so it carries known-vulnerable versions:
`libssl1.1`/`libcrypto1.1` at `1.1.1o-r0` (origin `openssl`, fixed at
`1.1.1q-r0`), `zlib 1.2.12-r1`, `busybox 1.35.0-r13`.

It also exercises the parsing cases that matter: several binaries share one
origin (`libssl1.1` and `libcrypto1.1` both come from `openssl`;
`busybox` and `ssl_client` both from `busybox`), which is what the
deduplicating matcher collapses.
