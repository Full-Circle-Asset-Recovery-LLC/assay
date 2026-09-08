#!/usr/bin/env python3
"""Install the release-attested native Darwin v0.5.15 test baseline."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def github_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "assay-baseline-installer",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def download(url: str, maximum_bytes: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "assay-baseline-installer",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(maximum_bytes + 1)
    if len(payload) > maximum_bytes:
        fail("baseline download exceeded its attested size")
    return payload


def main() -> None:
    if len(sys.argv) != 2:
        fail(f"usage: {sys.argv[0]} DESTINATION_DIRECTORY")
    if platform.system() != "Darwin" or platform.machine() not in {"arm64", "aarch64"}:
        fail("Darwin baseline requires an Apple Silicon macOS runner")

    script_dir = Path(__file__).resolve().parent
    manifest = json.loads(
        (script_dir / "assay-engine-v0.5.15-darwin-aarch64.json").read_text(
            encoding="utf-8"
        )
    )
    artifact = manifest["artifact"]
    source = manifest["source"]
    distribution = manifest["distribution"]
    if manifest.get("schema_version") != 1:
        fail("unsupported Darwin baseline manifest schema")
    if source["repository"] != distribution["repository"]:
        fail("baseline source and distribution repositories differ")
    repository = distribution["repository"]
    api = f"https://api.github.com/repos/{repository}"

    release = github_json(f"{api}/releases/{distribution['release_id']}")
    matching_assets = [
        item
        for item in release.get("assets", [])
        if item.get("id") == distribution["asset_id"]
        and item.get("name") == artifact["asset_name"]
    ]
    if len(matching_assets) != 1:
        fail("release did not contain exactly one attested Darwin baseline asset")
    asset = matching_assets[0]
    if (
        distribution["release_state"] != "published"
        or release.get("tag_name") != distribution["release_tag"]
        or bool(release.get("draft"))
        or bool(release.get("prerelease")) != distribution["prerelease"]
        or asset.get("size") != artifact["size_bytes"]
        or asset.get("digest") != f"sha256:{artifact['sha256']}"
    ):
        fail("Darwin baseline release metadata differs from its checked-in attestation")

    tag_ref = github_json(f"{api}/git/ref/tags/{distribution['release_tag']}")
    tag_object = tag_ref.get("object", {})
    if (
        tag_object.get("type") != "tag"
        or tag_object.get("sha") != distribution["tag_object_sha"]
    ):
        fail("Darwin baseline release tag object differs from its attestation")
    annotated_tag = github_json(f"{api}/git/tags/{distribution['tag_object_sha']}")
    tagged_source = annotated_tag.get("object", {})
    if (
        tagged_source.get("type") != "commit"
        or tagged_source.get("sha") != source["commit"]
    ):
        fail(
            "Darwin baseline release tag does not resolve to its attested source commit"
        )

    payload = download(asset["url"], artifact["size_bytes"])
    if len(payload) != artifact["size_bytes"]:
        fail("Darwin baseline byte length differs from its attestation")
    if hashlib.sha256(payload).hexdigest() != artifact["sha256"]:
        fail("Darwin baseline digest differs from its attestation")
    if len(payload) < 16:
        fail("Darwin baseline is too short to contain a Mach-O header")
    magic, cpu_type, _cpu_subtype, file_type = struct.unpack("<IIII", payload[:16])
    if magic != 0xFEEDFACF or cpu_type != 0x0100000C or file_type != 2:
        fail("Darwin baseline is not an arm64 Mach-O executable")

    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination, 0o700)
    installed = destination / "assay-engine-v0.5.15"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".assay-engine-", dir=destination
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, stat.S_IRUSR | stat.S_IXUSR)
        os.replace(temporary_name, installed)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass

    version = subprocess.run(
        [installed, "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if version != artifact["version_output"]:
        fail(
            f"Darwin baseline version mismatch: expected {artifact['version_output']!r}, got {version!r}"
        )
    print(installed)


if __name__ == "__main__":
    main()
