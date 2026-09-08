#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 DESTINATION_DIRECTORY" >&2
  exit 2
fi
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  manifest="$script_dir/assay-engine-v0.5.15-darwin-aarch64.json"
  metadata=()
  while IFS= read -r value; do
    metadata+=("$value")
  done < <(python3 - "$manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

values = (
    manifest["distribution"]["url"],
    manifest["artifact"]["asset_name"],
    manifest["artifact"]["sha256"],
    str(manifest["artifact"]["size_bytes"]),
    manifest["artifact"]["version_output"],
)
print("\n".join(values))
PY
  )
  if [[ ${#metadata[@]} -ne 5 ]]; then
    echo "Darwin baseline manifest did not yield the required metadata" >&2
    exit 1
  fi
  scratch="$(mktemp -d)"
  trap 'rm -rf -- "$scratch"' EXIT
  download="$scratch/${metadata[1]}"
  curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors --connect-timeout 15 --max-time 180 \
    "${metadata[0]}" >"$download"
  actual_size="$(wc -c <"$download" | tr -d '[:space:]')"
  actual_sha256="$(shasum -a 256 "$download" | awk '{print $1}')"
  if [[ "$actual_size" != "${metadata[3]}" ]]; then
    echo "baseline size mismatch: expected ${metadata[3]}, got $actual_size" >&2
    exit 1
  fi
  if [[ "$actual_sha256" != "${metadata[2]}" ]]; then
    echo "baseline sha256 mismatch: expected ${metadata[2]}, got $actual_sha256" >&2
    exit 1
  fi
  destination="$(mkdir -p "$1" && cd "$1" && pwd -P)"
  chmod 0700 "$destination"
  installed="$destination/assay-engine-v0.5.15"
  install -m 0500 "$download" "$installed"
  actual_version="$("$installed" --version)"
  if [[ "$actual_version" != "${metadata[4]}" ]]; then
    echo "baseline version mismatch: expected '${metadata[4]}', got '$actual_version'" >&2
    exit 1
  fi
  printf '%s\n' "$installed"
  exit 0
fi
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "assay-engine v0.5.15 baseline is available only for x86_64 Linux or arm64 Darwin" >&2
  exit 1
fi
manifest="$script_dir/assay-engine-v0.5.15-linux-x86_64.json"
mapfile -t metadata < <(python3 - "$manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

values = (
    manifest["distribution"]["repository"],
    manifest["distribution"]["commit"],
    manifest["distribution"]["path"],
    manifest["artifact"]["asset_name"],
    manifest["artifact"]["gzip_sha256"],
    str(manifest["artifact"]["gzip_size_bytes"]),
    manifest["artifact"]["elf_build_id_sha1"],
    manifest["artifact"]["sha256"],
    str(manifest["artifact"]["size_bytes"]),
    manifest["artifact"]["version_output"],
)
print("\n".join(values))
PY
)
if [[ ${#metadata[@]} -ne 10 ]]; then
  echo "baseline manifest did not yield the required metadata" >&2
  exit 1
fi

repository="${metadata[0]}"
fixture_commit="${metadata[1]}"
fixture_path="${metadata[2]}"
asset_name="${metadata[3]}"
expected_gzip_sha256="${metadata[4]}"
expected_gzip_size="${metadata[5]}"
expected_build_id="${metadata[6]}"
expected_sha256="${metadata[7]}"
expected_size="${metadata[8]}"
expected_version="${metadata[9]}"

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
archive="$scratch/$asset_name.gz"
curl --fail --silent --show-error --location \
  --retry 3 --retry-all-errors --connect-timeout 15 --max-time 180 \
  "https://raw.githubusercontent.com/$repository/$fixture_commit/$fixture_path" >"$archive"

actual_gzip_size="$(wc -c <"$archive" | tr -d '[:space:]')"
actual_gzip_sha256="$(sha256sum "$archive" | awk '{print $1}')"
if [[ "$actual_gzip_size" != "$expected_gzip_size" ]]; then
  echo "baseline archive size mismatch: expected $expected_gzip_size, got $actual_gzip_size" >&2
  exit 1
fi
if [[ "$actual_gzip_sha256" != "$expected_gzip_sha256" ]]; then
  echo "baseline archive sha256 mismatch: expected $expected_gzip_sha256, got $actual_gzip_sha256" >&2
  exit 1
fi

download="$scratch/$asset_name"
gzip --decompress --stdout "$archive" >"$download"

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
actual_version="$("$installed" --version)"
if [[ "$actual_version" != "$expected_version" ]]; then
  echo "baseline version mismatch: expected '$expected_version', got '$actual_version'" >&2
  exit 1
fi

printf '%s\n' "$installed"
