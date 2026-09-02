# Security Policy

## Reporting a vulnerability in fwscan

Please report security issues **privately** through GitHub's
[private vulnerability reporting](https://github.com/mhmtkas/fwscan/security/advisories/new).
Do not open a public issue for a security problem.

Include what you have: affected version or commit, a description of the impact,
and the smallest input that reproduces it. If the trigger is a firmware image,
attach the smallest crafted image that shows the behaviour rather than a real
product image.

Expect an acknowledgement within 7 days. This is a solo-maintained project, so
please allow reasonable time for a fix before public disclosure; 90 days is the
default assumption, shorter if the issue is being actively exploited.

## What is in scope

fwscan parses untrusted firmware images, so anything an image can make it do is
in scope:

- memory, disk or CPU exhaustion driven by crafted input: unbounded
  allocation, an archive or image that expands out of proportion to its size,
  or a parser that slows super-linearly
- writing outside the designated temp directory during extraction, including
  path traversal and symlink escapes in tar or squashfs archives, or reading
  the host through a link inside an image
- terminal escape or invisible-character injection through anything fwscan
  prints, including its own diagnostics
- command injection through any path handed to `unsquashfs`
- crashes that a crafted package database can trigger

## What is not in scope

- Vulnerabilities in the packages fwscan *reports on* — those belong to their
  upstreams. fwscan reporting them is the tool working correctly.
- False positives or false negatives in CVE matching. Those are correctness bugs;
  please open a normal issue with the purl and the OSV record.
- Anything requiring the attacker to already control the machine running fwscan.

## Supported versions

Until v1.0.0, only the latest release receives fixes.
