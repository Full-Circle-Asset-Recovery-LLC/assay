#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 DESTINATION_DIRECTORY" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "assay-engine v0.5.15 baseline is available only for x86_64 Linux" >&2
  exit 1
fi
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
manifest="$script_dir/assay-engine-v0.5.15-linux-x86_64.json"
mapfile -t metadata < <(python3 - "$manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

values = (
    manifest["distribution"]["repository"],
    str(manifest["distribution"]["release_id"]),
    manifest["distribution"]["release_tag"],
    manifest["distribution"]["release_state"],
    str(manifest["distribution"]["prerelease"]).lower(),
    str(manifest["distribution"]["asset_id"]),
    manifest["artifact"]["asset_name"],
    manifest["artifact"]["elf_build_id_sha1"],
    manifest["artifact"]["sha256"],
    str(manifest["artifact"]["size_bytes"]),
    manifest["artifact"]["version_output"],
)
print("\n".join(values))
PY
)
if [[ ${#metadata[@]} -ne 11 ]]; then
  echo "baseline manifest did not yield the required metadata" >&2
  exit 1
fi

repository="${metadata[0]}"
release_id="${metadata[1]}"
release_tag="${metadata[2]}"
release_state="${metadata[3]}"
expected_prerelease="${metadata[4]}"
asset_id="${metadata[5]}"
asset_name="${metadata[6]}"
expected_build_id="${metadata[7]}"
expected_sha256="${metadata[8]}"
expected_size="${metadata[9]}"
expected_version="${metadata[10]}"

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
release_json="$scratch/release.json"
api="https://api.github.com/repos/$repository"
headers=(
  --header "X-GitHub-Api-Version: 2022-11-28"
)

curl --fail --silent --show-error --location \
  "${headers[@]}" \
  --header "Accept: application/vnd.github+json" \
  "$api/releases/$release_id" >"$release_json"

mapfile -t release < <(python3 - "$release_json" "$release_tag" "$asset_id" "$asset_name" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    release = json.load(handle)
if release.get("tag_name") != sys.argv[2]:
    raise SystemExit(f"release tag mismatch: expected {sys.argv[2]!r}, got {release.get('tag_name')!r}")
matches = [
    asset
    for asset in release.get("assets", [])
    if str(asset.get("id")) == sys.argv[3] and asset.get("name") == sys.argv[4]
]
if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one asset with id {sys.argv[3]} and name {sys.argv[4]!r}, found {len(matches)}"
    )
print(str(release.get("draft", False)).lower())
print(str(release.get("prerelease", False)).lower())
print(matches[0]["url"])
print(str(matches[0].get("size", "")))
print(str(matches[0].get("digest", "")))
PY
)
if [[ ${#release[@]} -ne 5 ]]; then
  echo "release metadata did not identify exactly one baseline asset" >&2
  exit 1
fi
if [[ "$release_state" != "published" || "${release[0]}" != "false" ]]; then
  echo "baseline release $release_tag does not match manifest state $release_state" >&2
  exit 1
fi
if [[ "$expected_prerelease" != "true" || "${release[1]}" != "$expected_prerelease" ]]; then
  echo "baseline release $release_tag is not the required prerelease" >&2
  exit 1
fi
if [[ "${release[3]}" != "$expected_size" ]]; then
  echo "GitHub asset size mismatch: expected $expected_size, got ${release[3]}" >&2
  exit 1
fi
if [[ "${release[4]}" != "sha256:$expected_sha256" ]]; then
  echo "GitHub asset digest mismatch: expected sha256:$expected_sha256, got ${release[4]}" >&2
  exit 1
fi

download="$scratch/$asset_name"
curl --fail --silent --show-error --location \
  "${headers[@]}" \
  --header "Accept: application/octet-stream" \
  "$api/releases/assets/$asset_id" >"$download"

actual_size="$(wc -c <"$download" | tr -d '[:space:]')"
actual_sha256="$(sha256sum "$download" | awk '{print $1}')"
actual_build_id="$(readelf -n "$download" | awk '/Build ID:/{print $3; exit}')"
if [[ "$actual_size" != "$expected_size" ]]; then
  echo "baseline size mismatch: expected $expected_size, got $actual_size" >&2
  exit 1
fi
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "baseline sha256 mismatch: expected $expected_sha256, got $actual_sha256" >&2
  exit 1
fi
if [[ "$actual_build_id" != "$expected_build_id" ]]; then
  echo "baseline ELF build ID mismatch: expected $expected_build_id, got $actual_build_id" >&2
  exit 1
fi

destination="$(mkdir -p "$1" && cd "$1" && pwd -P)"
chmod 0700 "$destination"
installed="$destination/assay-engine-v0.5.15"
install -m 0500 "$download" "$installed"
actual_version="$($installed --version)"
if [[ "$actual_version" != "$expected_version" ]]; then
  echo "baseline version mismatch: expected '$expected_version', got '$actual_version'" >&2
  exit 1
fi

printf '%s\n' "$installed"
