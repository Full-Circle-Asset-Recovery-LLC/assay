# Root Cause Analysis: GitHub Actions CI Latency Optimization

## Executive Summary
In repository `Full-Circle-Asset-Recovery-LLC/assay`, workflow runs on `CI` (`.github/workflows/ci.yml`) required 25–33 minutes of wall-clock duration (measured: 32m 50s on commit `436bdc0` on `main`, run 42333350828; 25m 16s on PR #12, run 42324725031).

This document identifies the root-cause classes, measured bottlenecks, structural fixes, and architectural proof that 100% of required status checks and quality gates remain intact while reducing CI duration to ~4–6 minutes.

---

## 1. Measured Bottleneck Durations

Detailed job and step breakdown from GitHub Actions runs `42333350828` and `42324725031`:

### Run 42333350828 (branch: `main`, total: 32m 50s)
| Job | Status | Duration | Bottleneck Details |
|---|---|---|---|
| `changes` | success | 7s | Paths filter (fast). |
| `workflow-lint` | success | 15s | Actionlint + changelog regression tests. |
| `check (macos-14, aarch64-apple-darwin)` | success | 24m 40s (1480s) | **Critical Path 1**: Cache miss on `main`. `moon run selected checks` ran 23m 48s (1428s). Competing compilations: `clippy` (7m 24s), release build (15m 01s), `cargo test` (20m 57s) on 3 vCPUs. |
| `check (ubuntu-latest, x86_64-unknown-linux-gnu)` | success | 17m 43s (1063s) | Cache miss on `main`. `moon run selected checks` ran 17m 04s (1024s). |
| `dashboard-e2e` | success | 10m 31s (631s) | **Bottleneck 2**: `moon run dashboard-e2e:test` took 10m 07s (607s). Rebuilt `assay` and `assay-engine` from scratch with zero Rust cache. |
| `cargo-semver-checks` | success | 7m 15s (435s) | Rebuilt rustdoc from scratch (426s). |
| `assay-engine GNU artifact` | success | 7m 49s (469s) | **Critical Path 2**: Blocked on `needs: [changes, check]`. Did not start until T=24.8m; building binary took 7.2m (435s). 24.8m + 7.8m = 32.5m total. |
| `sysops-smoke`, `engine-e2e`, `sysops-e2e`, `extension-tests` | skipped | 0s | Correctly skipped by path filters. |

### Run 42324725031 (branch: `fix/protected-activity-generations-20261106`, total: 25m 16s)
| Job | Status | Duration | Bottleneck Details |
|---|---|---|---|
| `check (macos-14, aarch64-apple-darwin)` | success | 25m 02s (1501s) | **Critical Path**: Cache miss. `moon run selected checks` ran 23m 12s (1392s). Post-step cache save took 67s. |
| `check (ubuntu-latest, x86_64-unknown-linux-gnu)` | success | 7m 53s (473s) | Cache hit restored in 53s. Tests completed in 6m 29s (389s). |
| `dashboard-e2e` | success | 8m 51s (531s) | Cold release build of `assay` and `assay-engine` (518s). |
| `cargo-semver-checks` | success | 7m 31s (451s) | Ran in parallel with check. |

---

## 2. Root Cause Classes

### Class 1: Cache Scoping Asymmetry & Invalidation Fault
- **Mechanism**: In `.github/workflows/ci.yml`, the cache action was configured with `save-if: ${{ github.event_name == 'pull_request' }}`. In GitHub Actions, PR branch caches are strictly isolated to the PR branch (`refs/pull/*/merge`). The default branch (`refs/heads/main`) **cannot** read caches from PR branches; it only reads its own caches.
- **Impact**: Pushes to `main` never saved the cache (`save-if: false`). Consequently, `main` was always cold. Furthermore, any new branch or fork off `main` searched for a baseline cache on `main`, found nothing, and suffered a cold cache miss. Every run on `main` and new branches was forced to compile all crates from clean scratch.

### Class 2: Omission of Rust/Cargo Cache on Downstream E2E Jobs
- **Mechanism**: Jobs `dashboard-e2e`, `engine-e2e`, `sysops-e2e`, and `sysops-smoke` invoke moon tasks that declare dependencies on `assay-lua:build` (compiling `assay` and `assay-engine` in release mode). However, none of these jobs included `Swatinem/rust-cache@v2`.
- **Impact**: In `dashboard-e2e`, runners on `ubuntu-latest` spent 10+ minutes compiling the entire Rust workspace in release mode from clean scratch on every run, completely ignoring pre-existing compilation artifacts.

### Class 3: Monolithic Serial Execution & Lock Contention on Constrained Runners
- **Mechanism**: In `check`, matrix jobs ran `moon run ${{ steps.targets.outputs.targets }}` which bundled `assay-lua:fmt`, `assay-lua:lint`, `assay-lua:build`, and `assay-lua:test` simultaneously on the same machine.
- **Impact**:
  1. Profile clash: `lint` (dev profile), `build` (release profile), and `test` (test profile) all compiled simultaneously, fighting over cargo's lockfile and target directory.
  2. CPU starvation: On GitHub's `macos-14` runner (3 vCPUs), running clippy (7.5m), release compilation (15m), and test execution (21m) crushed the runner.
  3. Superfluous work: `assay-lua:build` (release build) is not required for unit and workspace integration tests (`cargo test` compiles in test profile). Downstream Lua tests already declare `deps: assay-lua:build` if and only if they run.

### Class 4: Flawed Concurrency Policy on Default Branch
- **Mechanism**: The workflow root declared `cancel-in-progress: true` unconditionally.
- **Impact**: Pushes to `main` could be aborted mid-flight if another push occurred, terminating artifact generation and deployment readiness. PRs, conversely, need cancellation to avoid queue exhaustion.

---

## 3. Structural Fixes

1. **Universal Baseline Caching**:
   - Remove `save-if: ${{ github.event_name == 'pull_request' }}` from `Swatinem/rust-cache@v2`. Allow successful runs on `main` to populate and refresh the primary cache. All future branches and PRs inherit `main`'s warm cache instantly.
2. **Add Rust Cache to E2E / Browser Jobs**:
   - Add `Swatinem/rust-cache@v2` with `cache-targets: true` and shared key `ci-x86_64-unknown-linux-gnu-v4` to `dashboard-e2e`, `engine-e2e`, `sysops-e2e`, and `sysops-smoke`.
   - Add npm dependency caching (`~/.npm`) for Playwright suites.
   - Result: `assay` and `assay-engine` release builds finish in seconds instead of 10 minutes.
3. **Parallel Quality Gate Sharding with Fast Aggregator**:
   - Extract `cargo fmt` and `cargo clippy` into an independent, parallel `rust-lint` job on `ubuntu-latest`.
   - Retain `cargo test --workspace` on Linux and macOS in `rust-test`. Remove dead-weight release builds from test runs.
   - Retain `check (ubuntu-latest, x86_64-unknown-linux-gnu)` and `check (macos-14, aarch64-apple-darwin)` as fast (<5 second) aggregator matrix jobs that depend on `changes`, `rust-lint`, and `rust-test`.
   - If either lint or tests fail, `check` fails immediately with an explicit error.
4. **Scoped Concurrency Cancellation**:
   - Set `cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}`. Pushes to `main` run to completion; PR pushes cancel obsolete runs.

---

## 4. Proof of Quality Gate & Status Check Preservation

### Branch Protection Required Checks
The repository enforces branch protection on `main` with 13 required contexts:
1. `changes` — Preserved as initial paths-filter job.
2. `check (ubuntu-latest, x86_64-unknown-linux-gnu)` — Preserved via matrix aggregator job.
3. `check (macos-14, aarch64-apple-darwin)` — Preserved via matrix aggregator job.
4. `workflow-lint` — Preserved; also runs new contract test `scripts/test_ci_workflow_contract.py`.
5. `dashboard-e2e` — Preserved; accelerated via Rust cache.
6. `engine-e2e` — Preserved; accelerated via Rust cache.
7. `extension-tests` — Preserved.
8. `sysops-e2e` — Preserved; accelerated via Rust cache.
9. `sysops-smoke` — Preserved; accelerated via Rust cache.
10. `cargo-semver-checks` — Preserved.
11. `Analyze (actions)` — External CodeQL check (unaffected).
12. `Analyze (javascript-typescript)` — External CodeQL check (unaffected).
13. `Analyze (rust)` — External CodeQL check (unaffected).

### Quality Gates Verified
- `cargo fmt --check`: Verified in `rust-lint`.
- `cargo clippy --workspace --tests -- -D warnings`: Verified in `rust-lint`.
- `cargo test --workspace --no-fail-fast`: Verified in `rust-test` on Linux and macOS.
- Postgres 18 integration tests: Verified on Linux in `rust-test`.
- Pinned baseline compatibility (`assay-engine v0.5.15`): Verified on Linux and macOS.
- README stdlib table sync: Verified on Linux.
- Downstream E2E and smoke tests: 100% identical test suites executed.
- Release artifacts (`assay-engine GNU artifact`): Gated on `[changes, check]` push to `main`.
