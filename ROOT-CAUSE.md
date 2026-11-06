# Protected activity claim generations

## Class

A delayed activity writer can mutate a different durable claim when reporting authority is optional
or reused across manual retry cycles. Due-time ordering alone also does not establish eligibility.

## Mechanism

The original revision ignored report fences and scheduled retry times. A newer merged revision
applies owner/attempt fences transactionally, but retains unfenced id-only writers and resets
`attempt` to one on manual retry. Its old owner/attempt tuple is therefore indistinguishable from a
new same-worker claim. Two real HTTP reproductions show both an unfenced delayed completion settling
another worker's attempt and an old exact fence completing a newly reopened same-worker claim,
including durable row and event readbacks. Existing backend/race/isolation suites pass despite these
cases.

## Structural fix

Add nullable durable `claim_generation`: NULL denotes unchanged legacy behavior, zero denotes
explicitly protected scheduling before its first claim, and each protected claim atomically
increments the value without overflow. Retry and manual reopen never reset it; `attempt`, retry
budget and backoff keep their legacy meanings. Protected reports require the generation, positive
attempt and nonblank exact owner under the existing transaction/parent cancellation locks. Every
legacy heartbeat, completion, settlement and retry writer rejects protected rows. Internal timeout
uses the captured generation; terminal reconciliation may repair only the captured terminal
generation. Scheduling the same workflow/sequence with a different protection mode is a conflict.
Both scheduling command builders carry the opt-in. A stronger health capability is published only by
backends implementing the complete contract.

Maintenance calls also bind the captured generation to the activity's authoritative parent row, and
raw retry validates the protection boundary before any no-op/invalid-transition early return. The
expanded boundary corpus reproduced both gaps on SQLite and PostgreSQL before these guards were
applied.

Threat model: delayed, duplicate, reordered and concurrent cooperative worker reports, multiple
workers/engine instances, manual reopen and cancellation races, malformed or incomplete fences,
mistaken maintenance parent bindings, and upgrading legacy databases. Authentication remains an
existing boundary; deliberate forgery of the exact current fence or privileged database modification
is outside this protocol's scope. Existing rows remain legacy. Production migration, binary
replacement and rollback are separate release transactions; an old binary must never operate a
database after protected claims are accepted.

## Proof

Preserved original-revision red evidence and the newer candidate's harmful before/after readbacks.
New protected-mode HTTP tests run against SQLite and PostgreSQL without weakening stale-response
conflict or no-write assertions. Test manual reopen separately from retry counters, raw legacy
writer rejection, timeout/reconcile/cancel interleavings, scheduling idempotency, capability gating,
overflow, persistence and old-schema upgrade. Existing legacy tests retain all expectations; only
exhaustive Rust literal initializers gain explicit None/default fields where the additive public
types require them. Run targeted suites, full workflow/engine tests, formatting and clippy before
source publication. No production migration or deployment is performed by this source lane.

## SQL edit containment

Class: a text replacement intended to add the activity column/value can also alter an unrelated
INSERT with the same placeholder count. Mechanism: replacing the thirteen-placeholder VALUES pattern
matched both activity creation and schedule creation; the latter still had thirteen columns and
bindings but fourteen placeholders. The unchanged schedule API tests reproduced HTTP 500 instead of
201 (and a dependent 404 instead of 200). Structural fix: restore the unrelated schedule SQL
verbatim, restrict activity edits to their function and named column projection, and verify the
complete SQL diff for matching changed columns, values and bindings. Proof: rerun the existing
schedule/API and full backend suites without editing their assertions. This is patch containment,
with no new runtime abstraction or behavior change outside protected activities.

## Hosted runner compatibility

### Class

Hosted runner selectors can resolve to an operating system unsupported by the pinned toolchain or to
a retired image, preventing required checks from reaching application tests.

### Mechanism

CI run `42313339806`, dashboard job `128219918113`, checked out
`301090e64a8071ef80adf38b95dbe454ca295530` on hosted image `ubuntu-26.04` version `20261101.186.1`.
The locked Playwright 1.59.1 installer rejected `ubuntu26.04-x64` on all three attempts. No
dashboard assertions or engine/worker fixtures ran. The workflow's hosted fallback was
`ubuntu-latest`; its SHA256 `33c174a11bb9095ae8583b8085f2ce5a38f5a14b756e7397557447b44b175d10` was
identical at source base `c43db57c10f1b8657eb42caf909df13c0d1401b2` and the checked-out head.
Browser lockfile, Moon task, test specification and installer were also unchanged by the source
repair. This is deterministic tooling/image incompatibility rather than a dashboard test defect or
transient download failure.

The same run's macOS job `128219918127` was cancelled before runner assignment: its runner name and
steps were empty, logs were unavailable, and the check annotation said
`The configuration 'macos-14-arm64-us-default' is not supported`. GitHub retired macOS 14 images on
November 2, 2026. The existing matrix and ARM64 target were unchanged by the source repair. Branch
protection explicitly requires `check (macos-14, aarch64-apple-darwin)`, so simply renaming the
matrix row would leave a required context unsatisfied.

### Structural fix

Pin only the dashboard job's hosted fallback to the explicitly supported `ubuntu-24.04` label.
Preserve its existing self-hosted condition, all browser/package versions, retry behavior, install
commands, test commands, artifact handling and required checks. The supported operating system must
be a deliberate toolchain input rather than following a moving `latest` alias. Keep `macos-14` only
as the legacy required-status identifier and self-hosted selector, while mapping its hosted fallback
to supported ARM64 `macos-15`. Preserve the existing `aarch64-apple-darwin` target, self-hosted
opt-in and all required status names; do not change branch protection. No protocol source or release
workflow changes are needed.

### Proof

The original failed job log and image metadata are retained outside the source tree. Playwright's
[exact v1.59.1 requirements](https://github.com/microsoft/playwright/blob/v1.59.1/docs/src/intro-js.md#system-requirements)
list Ubuntu 22.04 and 24.04; its
[tagged host-platform implementation](https://github.com/microsoft/playwright/blob/v1.59.1/packages/playwright-core/src/server/utils/hostPlatform.ts#L82-L84)
marks Ubuntu 24.04 supported and versions at or above 26 unsupported. GitHub's
[runner image inventory](https://github.com/actions/runner-images#available-images) provides the
`ubuntu-24.04` x64 and `macos-15` ARM64 labels. The provider's
[macOS 14 retirement notice](https://github.com/actions/runner-images/issues/13518) establishes that
the old image cannot be repaired by retrying. Validate that parsed YAML differs only in the two
hosted runner selections; evaluate maintainer/other-actor and macOS opt-in true/false/unset routing,
retaining Linux paths, required matrix identifiers, install/test steps and the ARM64 target. Require
fresh CI metadata to show actual macOS 15 ARM64 and Ubuntu 24.04 runners under the unchanged
required contexts. Local configuration validation is not application acceptance. A same-image blind
rerun cannot fix either incompatibility.
