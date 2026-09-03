#!/usr/bin/env bash
# Run fwscan over every class of image it claims to handle, and print what came
# back. This is the check that "ready to release" means something: unit tests
# cover the code, and this covers the claims.
#
# It is not run in CI. It fetches roughly 700 MB from Docker Hub and queries
# live vulnerability data, so its numbers move between runs by design -- read
# the exit codes, the warnings and the shape, not the counts.
#
# Every row below exists because a bug was found in it or because the code has a
# branch nobody had exercised on a real image:
#
#   debian 11    a release past free support, answered by the security tracker
#   debian 12/13 the ordinary case
#   debian 14    an unreleased branch, which is in no support window and is not
#                dead -- assuming those were the same crashed the scan (T67)
#   debian 8     past every tier, and old enough to have no VERSION_CODENAME
#   ubuntu       three releases, including the two current LTSes
#   alpine       three, one of them end of life
#   openwrt      squashfs input, and an opkg database that is not read
#   rocky/fedora an rpm database that is not read
#
# Usage: scripts/real-image-matrix.sh [workdir]
set -uo pipefail

cd "$(dirname "$0")/.."
WORK=${1:-${TMPDIR:-/tmp}/fwscan-matrix}
FWSCAN=${FWSCAN:-./bin/fwscan}
mkdir -p "$WORK/out"

[ -x "$FWSCAN" ] || { echo "no binary at $FWSCAN; run make build, or set FWSCAN"; exit 2; }

# fetch <repo> <tag> <name> -- one rootfs layer from the registry, once.
fetch() {
	local repo=$1 tag=$2 name=$3
	[ -f "$WORK/$name/layer.tar.gz" ] && return 0
	REPO_OVERRIDE="$repo" ./spike/fetch-rootfs.sh "$tag" "$WORK/$name" >/dev/null 2>&1 || true
	[ -f "$WORK/$name/layer.tar.gz" ]
}

printf '%-14s %-5s %-7s %-9s %s\n' IMAGE EXIT PKGS FINDINGS WARNINGS
printf '%.0s-' {1..78}; printf '\n'

run() {
	local name=$1 path=$2
	local out="$WORK/out/$name"
	"$FWSCAN" scan --sbom "$out.cdx.json" --output "$out.json" --cra "$out.md" \
		"$path" >"$out.txt" 2>"$out.err"
	local rc=$? pkgs findings warns
	pkgs=$(grep -oE 'Packages +[0-9]+' "$out.txt" | grep -oE '[0-9]+')
	findings=$(grep -oE 'Findings +[0-9]+' "$out.txt" | grep -oE '[0-9]+')
	warns=$(grep -c '^fwscan: ' "$out.err")
	printf '%-14s %-5s %-7s %-9s %s\n' "$name" "$rc" "${pkgs:-—}" "${findings:-—}" "$warns"
	# A warning nobody reads is not a warning, so print them.
	sed 's/^fwscan: /    · /' "$out.err"
}

# repo|tag|name -- the registry images. Debian is the default repo.
while IFS='|' read -r repo tag name; do
	[ -n "$name" ] || continue
	if fetch "$repo" "$tag" "$name"; then
		run "$name" "$WORK/$name/layer.tar.gz"
	else
		printf '%-14s %s\n' "$name" "(could not fetch)"
	fi
done <<'EOF'
library/debian|bullseye|debian-11
library/debian|bookworm|debian-12
library/debian|trixie|debian-13
library/debian|forky|debian-14
library/debian|jessie|debian-8
library/ubuntu|jammy|ubuntu-22.04
library/ubuntu|noble|ubuntu-24.04
library/ubuntu|resolute|ubuntu-26.04
library/alpine|3.16|alpine-3.16
library/alpine|3.19|alpine-3.19
library/alpine|3.21|alpine-3.21
library/rockylinux|9|rocky-9
library/fedora|42|fedora-42
EOF

# Exit codes, on an image known to have findings.
echo
echo "exit codes (ubuntu-24.04):"
for level in critical high medium low; do
	"$FWSCAN" scan --fail-on "$level" "$WORK/ubuntu-24.04/layer.tar.gz" >/dev/null 2>&1
	printf '    --fail-on %-9s exit %s   (want 1)\n' "$level" "$?"
done
"$FWSCAN" scan --fail-on critical "$WORK/fedora-42/layer.tar.gz" >/dev/null 2>&1
printf '    no findings          exit %s   (want 0)\n' "$?"
"$FWSCAN" scan --no-network --sbom "$WORK/out/nn.cdx.json" \
	"$WORK/ubuntu-24.04/layer.tar.gz" >/dev/null 2>&1
printf '    --no-network         exit %s   (want 0)\n' "$?"
"$FWSCAN" scan "$WORK/does-not-exist" >/dev/null 2>&1
printf '    unreadable input     exit %s   (want 2)\n' "$?"

cat <<'NOTE'

What to look for, in order of how much it matters:

  * Every exit is 0, except the --fail-on rows and the unreadable input.
  * Every image with no findings has a warning saying why. A zero with no
    warning is the failure mode this whole file exists to catch.
  * debian-11 findings carry source security-tracker.debian.org; every other
    row carries osv.dev. Check with:
        jq -r '[.findings[].source]|unique' <out>/debian-11.json
  * debian-14 finishes in seconds. If it takes half a minute it is fetching
    tracker lists it does not need (T69).
  * No Ubuntu fixed version mentions esm, fips or pro:
        jq -r '.findings[].fixed_version' <out>/ubuntu-*.json | grep -Ei 'esm|fips|pro'
NOTE
