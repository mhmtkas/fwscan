# Security Policy

## Reporting a vulnerability in fwscan

Please report security issues **privately** through GitHub's
[private vulnerability reporting](https://github.com/mhmtkas/fwscan/security/advisories/new),
or by email to <mhmt.kas@gmail.com> with `fwscan` in the subject if you cannot
use GitHub. Do not open a public issue for a security problem.

Include what you have: affected version or commit, a description of the impact,
and the smallest input that reproduces it. If the trigger is an image, attach
the smallest crafted one that shows the behaviour rather than a real product
image — a hand-built `var/lib/dpkg/status` in a directory is usually enough.

Expect an acknowledgement within 7 days. This is a solo-maintained project, so
please allow reasonable time for a fix before public disclosure; 90 days is the
default assumption, shorter if the issue is being actively exploited.

## What is in scope

fwscan parses untrusted root filesystems and reads two network sources it does
not control, so anything either can make it do is in scope:

- memory, disk or CPU exhaustion driven by crafted input: unbounded
  allocation, an archive or image that expands out of proportion to its size,
  or a parser that slows super-linearly
- writing outside the designated temp directory during extraction, including
  path traversal and symlink escapes in tar or squashfs archives, or reading
  the host through a link inside an image
- terminal escape or invisible-character injection through anything fwscan
  prints, including its own diagnostics
- **content injection into the `--cra` evidence document**: it is Markdown
  that gets filed, and a package name or version is attacker-controlled, so a
  crafted image that can add, alter or hide a table row in it is a
  vulnerability even though no code runs
- command injection through any path handed to `unsquashfs`
- crashes or wrong behaviour that crafted image metadata can trigger — the
  dpkg or apk database, `os-release` (including `ID_LIKE`), `alpine-release`
- anything a hostile or compromised response from OSV.dev or from Debian's
  security tracker (`salsa.debian.org`) can make fwscan do beyond reporting
  wrong findings: unbounded reads, following a redirect off-host, writing
  anywhere. Wrong findings from a wrong upstream record are not a
  vulnerability in fwscan; a response that crashes it or exhausts the host
  is.

## What is not in scope

- Vulnerabilities in the packages fwscan *reports on* — those belong to their
  upstreams. fwscan reporting them is the tool working correctly.
- False positives or false negatives in CVE matching. Those are correctness bugs;
  please open a normal issue with the purl and the OSV record.
- Anything requiring the attacker to already control the machine running fwscan.

## Supported versions

Until v1.0.0, only the latest release receives fixes. A published tag is never
re-cut; a fix is a new release.
