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
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "assay-baseline-installer",
    }
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        headers=headers,
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


def record(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"missing or malformed {description}")
    return value


def git_sha(value: Any, description: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        fail(f"missing or malformed {description}")
    return value


def tag_commit(api: str, tag_sha: str, name: str) -> tuple[dict[str, Any], str]:
    tag = record(github_json(f"{api}/git/tags/{tag_sha}"), "tag object")
    if tag.get("sha") != tag_sha or tag.get("tag") != name:
        fail("Darwin baseline tag object identity differs from its requested identity")
    target = record(tag.get("object"), "tag target")
    if target.get("type") != "commit":
        fail("Darwin baseline annotated tag must directly name a commit")
    return tag, git_sha(target.get("sha"), "tag commit SHA")


def commit_tree(api: str, commit_sha: str) -> str:
    commit = record(github_json(f"{api}/git/commits/{commit_sha}"), "commit object")
    if commit.get("sha") != commit_sha:
        fail("Darwin baseline commit identity differs from its requested identity")
    tree = record(commit.get("tree"), "commit tree")
    return git_sha(tree.get("sha"), "commit tree SHA")


def verification_status(tag: dict[str, Any]) -> dict[str, Any]:
    # Diagnostic only: these fields do not attest a build or establish continuity.
    verification = tag.get("verification")
    if not isinstance(verification, dict):
        return {"verified": None, "reason": None}
    verified, reason = verification.get("verified"), verification.get("reason")
    return {
        "verified": verified if isinstance(verified, bool) else None,
        "reason": reason[:128] if isinstance(reason, str) else None,
    }


def validate_provenance(
    api: str, source: dict[str, Any], distribution: dict[str, Any]
) -> dict[str, Any] | None:
    original_sha = git_sha(distribution["tag_object_sha"], "attested tag SHA")
    original_commit = git_sha(source["commit"], "attested commit SHA")
    name = distribution["release_tag"]
    original, target = tag_commit(api, original_sha, name)
    if target != original_commit:
        fail("Darwin baseline original tag does not name its attested source commit")
    original_tree = commit_tree(api, original_commit)

    current_ref = record(github_json(f"{api}/git/ref/tags/{name}"), "current tag ref")
    if current_ref.get("ref") != f"refs/tags/{name}":
        fail("Darwin baseline current tag ref name differs from its requested identity")
    current_object = record(current_ref.get("object"), "current tag ref object")
    if current_object.get("type") != "tag":
        fail("Darwin baseline current ref must name an annotated tag")
    current_sha = git_sha(current_object.get("sha"), "current tag SHA")
    current, current_commit = tag_commit(api, current_sha, name)
    if current_sha == original_sha and current_commit != original_commit:
        fail("Darwin baseline original tag identity returned inconsistent source commits")
    current_tree = commit_tree(api, current_commit)
    if current_tree != original_tree:
        fail("Darwin baseline current tag source tree differs from its attested source")
    if current_sha == original_sha:
        return None
    return {
        "event": "SAME_TREE_REF_DRIFT",
        "original_tag_object": original_sha,
        "original_commit": original_commit,
        "current_tag_object": current_sha,
        "current_commit": current_commit,
        "tree": original_tree,
        "original_verification": verification_status(original),
        "current_verification": verification_status(current),
    }


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

    release = record(github_json(f"{api}/releases/{distribution['release_id']}"), "release")
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(item, dict) for item in assets):
        fail("missing or malformed Darwin baseline release assets")
    matching_assets = [
        item
        for item in assets
        if item.get("id") == distribution["asset_id"]
        and item.get("name") == artifact["asset_name"]
    ]
    if len(matching_assets) != 1:
        fail("release did not contain exactly one attested Darwin baseline asset")
    asset = matching_assets[0]
    if (
        distribution["release_state"] != "published"
        or release.get("id") != distribution["release_id"]
        or release.get("tag_name") != distribution["release_tag"]
        or release.get("draft") is not False
        or release.get("prerelease") is not distribution["prerelease"]
        or asset.get("size") != artifact["size_bytes"]
        or asset.get("digest") != f"sha256:{artifact['sha256']}"
    ):
        fail("Darwin baseline release metadata differs from its checked-in attestation")

    ref_drift = validate_provenance(api, source, distribution)

    payload = download(asset["browser_download_url"], artifact["size_bytes"])
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
        version = subprocess.run(
            [temporary_name, "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if version != artifact["version_output"]:
            fail(
                f"Darwin baseline version mismatch: expected {artifact['version_output']!r}, got {version!r}"
            )
        os.replace(temporary_name, installed)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass

    if ref_drift is not None:
        print(json.dumps(ref_drift, sort_keys=True), file=sys.stderr)
    print(installed)


if __name__ == "__main__":
    main()
