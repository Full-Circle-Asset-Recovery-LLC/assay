"""Package a reviewed engine build with immutable source and ABI provenance."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def output(*args):
    return subprocess.check_output(args, text=True).strip()


source = os.environ["SOURCE_SHA"]
if not re.fullmatch(r"[0-9a-f]{40}", source) or output("git", "rev-parse", "HEAD") != source:
    raise SystemExit("source binding mismatch")
if output("git", "status", "--porcelain", "--untracked-files=no"):
    raise SystemExit("tracked source changed during build")
binary = Path("target/release/assay-engine")
version = output(str(binary), "--version")
if version != "assay-engine " + os.environ["EXPECTED_ENGINE_VERSION"]:
    raise SystemExit("engine version does not match the approved backport")
symbols = output("readelf", "--version-info", str(binary))
versions = {tuple(map(int, value.split("."))) for value in re.findall(r"GLIBC_([0-9.]+)", symbols)}
if not versions or max(versions) > (2, 35):
    raise SystemExit("engine exceeds consumer glibc 2.35 compatibility ceiling")
destination = Path("dist/engine-backport")
destination.mkdir(parents=True, exist_ok=False)
installed = destination / "assay-engine-linux-x86_64"
shutil.copyfile(binary, installed)
installed.chmod(0o500)
sha = hashlib.sha256(installed.read_bytes()).hexdigest()
manifest = {
    "source_sha": source,
    "source_repository": os.environ["SOURCE_REPOSITORY"],
    "workflow_run_id": os.environ["WORKFLOW_RUN_ID"],
    "workflow_run_attempt": os.environ["WORKFLOW_RUN_ATTEMPT"],
    "rustc": output("rustc", "--version"),
    "target": "x86_64-unknown-linux-gnu",
    "cargo_lock_sha256": hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest(),
    "binary_sha256": sha,
    "binary_version": version,
    "glibc_max_required": ".".join(map(str, max(versions))),
}
(destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
(destination / "checksums.txt").write_text(sha + "  " + installed.name + "\n")
print(json.dumps(manifest, indent=2))
