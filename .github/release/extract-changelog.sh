#!/usr/bin/env bash
#
# Usage: extract-changelog.sh "<component> <version>"
# Reads the exact plain or bracketed H2 section from CHANGELOG.md in the
# current directory. Bare version selectors support legacy bracketed headings.
# Exits nonzero when no nonempty matching section exists.

set -euo pipefail

version="${1:?usage: extract-changelog.sh <version>}"

changelog="CHANGELOG.md"
if [ ! -f "$changelog" ]; then
    echo "error: $changelog not found (run from repo root)" >&2
    exit 1
fi

# Match the whole selector, allowing a date suffix separated by whitespace.
# Component selectors never fall back to unrelated bare version headings.
anchor="## ${version}"
bracketed="## [${version}]"

body=$(awk -v anchor="$anchor" -v bracketed="$bracketed" '
    function matches(line, prefix, suffix) {
        if (index(line, prefix) != 1) return 0
        suffix = substr(line, length(prefix) + 1)
        return suffix == "" || suffix ~ /^[[:space:]]/
    }
    in_section && $0 ~ /^##([[:space:]]|$)/ { exit }
    matches($0, anchor) || matches($0, bracketed) { in_section = 1; next }
    in_section { print }
' "$changelog")

if [ -z "$body" ]; then
    echo "error: no section found for version ${version} in ${changelog}" >&2
    exit 1
fi

# Strip leading/trailing blank lines for cleanliness.
printf '%s\n' "$body" | awk '
    NF { first = first ? first : NR; last = NR; lines[NR] = $0 }
    !NF { lines[NR] = $0 }
    END {
        for (i = first; i <= last; i++) print lines[i]
    }
'
