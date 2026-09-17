//! Session-default isolation must not weaken the cancellation fence.
#![cfg(all(feature = "backend-postgres", target_os = "linux"))]

mod common;
#[path = "common/pg_report_isolation_data.rs"]
mod pg_report_isolation_data;
#[path = "common/pg_report_isolation_fixture.rs"]
mod pg_report_isolation_fixture;
#[path = "common/pg_report_isolation_protocol.rs"]
mod pg_report_isolation_protocol;

use futures_util::FutureExt;
use pg_report_isolation_fixture::Fixture;
use std::panic::AssertUnwindSafe;

async fn isolation_contract(default: &'static str) {
    // Keep every partial resource outside the caught scenario future.
    let mut fixture = Fixture::new();
    let outcome = AssertUnwindSafe(pg_report_isolation_protocol::scenario(
        &mut fixture,
        default,
    ))
    .catch_unwind()
    .await;
    // Individual cleanup steps catch both panics and errors and have deadlines.
    // No semantic assertion (including the expected old-code RED) precedes this.
    let cleanup = match AssertUnwindSafe(fixture.cleanup()).catch_unwind().await {
        Ok(errors) => errors,
        Err(_) => {
            // Step-level guards normally catch cleanup panics. If orchestration
            // itself panics, retry remaining owned resources and still fail closed.
            let retry = AssertUnwindSafe(fixture.cleanup()).catch_unwind().await;
            match retry {
                Ok(mut errors) => {
                    errors.push("cleanup orchestration panicked".into());
                    errors
                }
                Err(_) => vec!["cleanup orchestration and retry both panicked".into()],
            }
        }
    };
    assert!(cleanup.is_empty(), "cleanup failed closed: {cleanup:#?}");
    match outcome {
        Ok(Ok(evidence)) => evidence.assert_contract(default),
        Ok(Err(error)) => panic!("isolation scenario failed after cleanup: {error:#}"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn read_committed_control_rejects_cancelled_heartbeat() {
    isolation_contract("read committed").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn repeatable_read_regression_rejects_cancelled_heartbeat() {
    isolation_contract("repeatable read").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn serializable_uses_the_same_strict_false_no_write_contract() {
    isolation_contract("serializable").await;
}
