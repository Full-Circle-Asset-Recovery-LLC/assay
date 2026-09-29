# Releasing

Two independent tracks. The binary release and library releases share a repo but no longer share a
release cycle.

```text
   push to main                          workflows                          GitHub releases
══════════════════════           ══════════════════════           ═══════════════════════════════

crates/assay/Cargo.toml ──bump──►   release.yml             ──►   assay-lua-v<X.Y.Z>
                                    (assay binary)                 ├── assay-linux-x86_64
                                                                   ├── assay-darwin-aarch64
                                                                   └── lua-checksums.txt
                                                                              ▲
                                                                              │ GET binary
                                                                              │
libs/<name>/VERSION     ──bump──►   release-libs.yml        ──►   assay-lib-<name>-v<libver>
                                    (per-lib tarball)              ├── assay-lib-<name>-<libver>.tar.gz
                                                                   └── assay-lib-<name>-<libver>.tar.gz.sha256
                                                                              ▲
                                                                              │ GET per-lib URL
                                                                              │
                                                                   ┌──────────┴──────────┐
                                                                   │ assay install       │
                                                                   │   (client)          │
                                                                   └─────────────────────┘
```

## Releasing the binary

1. Bump `crates/assay/Cargo.toml` `version` (and `Cargo.lock` to match).
2. Add a `## assay-lua <X.Y.Z> — <date>` section to `CHANGELOG.md`.
3. Open a PR titled `release: assay-lua <X.Y.Z>`. Squash-merge.
4. `release.yml` fires on push to `main`, sees the new version, builds the Linux + macOS binaries,
   tags `assay-lua-v<X.Y.Z>`, creates the release.

The release-existence check is by tag — re-running the workflow on the same version is a no-op.

## Releasing a maintenance engine

Maintenance engine builds use the `maintenance/engine-0.5.15` branch and independent build
metadata. They do not publish the Lua binary or library crates.

1. Choose a new, unused `assay-engine` version such as `0.5.15+schedule.2`. Update its manifest,
   lockfile, changelog, workflow module notes, and the backport workflow's `EXPECTED_ENGINE_VERSION`.
2. Review the maintenance PR and wait for every check, including PostgreSQL 16 and 18. Merge
   only after those checks succeed.
3. Wait for the post-merge `Engine backport` workflow. Its package job produces
   `engine-backport-<merge-sha>` only after verification. Download the artifact from that exact run.
4. Check `manifest.json` against the merged source SHA, repository, workflow run and attempt,
   binary version, lockfile hash and glibc ceiling. Verify `checksums.txt` and the binary's version.
5. Create the new release tag at that merge SHA and upload `assay-engine-linux-x86_64`,
   `manifest.json`, and `checksums.txt` from the verified artifact. Never replace an existing
   version's assets or reuse a tag for different bytes.
6. Read back the release assets and checksums before a consumer updates its version/checksum
   pin. Keep the previous immutable release for rollback.

## Releasing a library

1. Bump `libs/<name>/VERSION`.
2. Add a `## <name> <X.Y.Z> — <date>` section to `CHANGELOG.md` (optional — the release notes fall
   back to a generated stub if missing).
3. Open a PR. Squash-merge.
4. `release-libs.yml` fires on push to `main` when any `libs/*/VERSION` changes, builds a flat
   tarball of `libs/<name>/` (excluding tests), tags `assay-lib-<name>-v<libver>`, creates the
   release.

Idempotent: already-released versions are skipped. Manual re-run via `workflow_dispatch` is safe.

## Consumer install

`assay install` reads a consumer's `Manifest.lua` and resolves each lib to its per-lib release URL
(default `…/releases/download/assay-lib-<name>-v<libver>/assay-lib-<name>-<libver>.tar.gz`),
downloads, verifies sha256, extracts into `<lib_dir>/<name>/`. See
[`docs/modules/install.md`](docs/modules/install.md) for the consumer side.

## Design notes

Architecture rationale and the install protocol live in
[`.claude/plans/21-libs-folder-and-install.md`](.claude/plans/21-libs-folder-and-install.md).
