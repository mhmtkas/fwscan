#!/bin/sh
# Regenerate THIRD_PARTY_LICENSES.txt, the licence terms fwscan is obliged to
# ship alongside its binaries and its source.
#
# Two sources feed it. The Go modules linked into the release binaries, whose
# LICENSE and NOTICE files are read from the module cache; and the components
# under licenses/, which are code or data transcribed into this repository
# rather than imported, and so have no module cache entry to read.
#
# The module set is the union over the platforms .goreleaser.yaml builds, so a
# dependency that links on only one of them is still covered. Output order is
# sorted, so regenerating an unchanged tree produces an unchanged file and CI
# can check that the committed copy is current.

set -eu

cd "$(dirname "$0")/.."

out=THIRD_PARTY_LICENSES.txt
module=$(go list -m)

# Components transcribed into this repository rather than imported, as
# "name|version|licence file|what was copied". FIRST's calculator is data -- the
# CVSS v4 MacroVector table cannot be derived, only copied -- and
# distro-info-data is the vendors' own table of release and end-of-support
# dates, embedded so a scan can answer offline. Neither is linked against, and
# both sets of terms travel with this repository regardless.
transcribed='github.com/FIRSTdotorg/cvss-v4-calculator|c5b0d409ae9f57c44264c6ce5f27d89298e1d32a|licenses/cvss-v4-calculator.txt|The CVSS v4 MacroVector table and scoring steps in internal/match/cvss4.go and internal/match/cvss4_lookup.go are transcribed from this project.
salsa.debian.org/debian/distro-info-data|2026-09-03|licenses/distro-info-data.txt|internal/release/debian.csv and internal/release/ubuntu.csv are copies of this project'"'"'s tables of release and end-of-support dates.'

rule() {
	printf '%s\n' '--------------------------------------------------------------------------------'
}

# first_of prints the first of the named files that exists in a directory.
first_of() {
	dir=$1
	shift
	for name in "$@"; do
		if [ -f "$dir/$name" ]; then
			printf '%s\n' "$dir/$name"
			return 0
		fi
	done
	return 1
}

linked_modules() {
	for platform in linux/amd64 linux/arm64 darwin/arm64; do
		GOOS=${platform%/*} GOARCH=${platform#*/} \
			go list -deps -f '{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' ./cmd/fwscan
	done | grep -v '^$' | grep -v "^$module|" | sort -u
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
	cat <<'HEADER'
Third-party licences
====================

fwscan is licensed under Apache-2.0; see LICENSE. Its release binaries also
contain the components listed below, and its source carries data transcribed
from the last one. Their licences require that these notices travel with any
copy, in source or in binary form, so this file ships in every release archive
as well as in the repository.

Regenerate with `make third-party-licenses` after changing a dependency.
HEADER

	linked_modules | while IFS='|' read -r path version dir; do
		licence=$(first_of "$dir" LICENSE LICENSE.txt LICENCE COPYING) || {
			echo "no licence file found for $path in $dir" >&2
			exit 1
		}
		printf '\n'
		rule
		printf '%s %s\n' "$path" "$version"
		rule
		printf '\n'
		cat "$licence"
		if notice=$(first_of "$dir" NOTICE NOTICE.txt); then
			printf '\nNOTICE:\n\n'
			cat "$notice"
		fi
	done

	printf '%s\n' "$transcribed" | while IFS='|' read -r name version licence note; do
		printf '\n'
		rule
		printf '%s %s\n' "$name" "$version"
		printf 'Not linked. %s\n' "$note" | fold -s -w 78
		rule
		printf '\n'
		cat "$licence"
	done
} >"$tmp"

mv "$tmp" "$out"
trap - EXIT
printf 'wrote %s\n' "$out"
