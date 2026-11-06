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
