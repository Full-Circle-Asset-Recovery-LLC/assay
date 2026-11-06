//! Eligibility is checked inside the atomic backend claim operation.
mod common;

use assay_workflow::types::WorkflowActivity;
use common::{Backend, make_workflow};
use rstest::rstest;

fn activity(workflow_id: &str, seq: i32, scheduled_at: f64) -> WorkflowActivity {
    WorkflowActivity {
        claim_generation: None,
        id: None,
        workflow_id: workflow_id.to_owned(),
        seq,
        name: "verify".to_owned(),
        task_queue: "claims".to_owned(),
        input: None,
        status: "PENDING".to_owned(),
        result: None,
        error: None,
        attempt: 1,
        max_attempts: 3,
        initial_interval_secs: 1.0,
        backoff_coefficient: 2.0,
        start_to_close_secs: 300.0,
        heartbeat_timeout_secs: None,
        claimed_by: None,
        scheduled_at,
        started_at: None,
        completed_at: None,
        last_heartbeat: None,
    }
}

#[rstest]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::pg(Backend::Postgres)
)]
#[cfg_attr(feature = "backend-sqlite", case::sqlite(Backend::Sqlite))]
#[tokio::test(flavor = "multi_thread")]
async fn future_rows_stay_pending_while_due_rows_are_claimed(#[case] backend: Backend) {
    let store = backend.setup().await.unwrap();
    store
        .create_workflow(&make_workflow("due-contract", "main", "claims"))
        .await
        .unwrap();
    let future = store
        .create_activity(&activity("due-contract", 1, f64::MAX))
        .await
        .unwrap();
    let first = store
        .create_activity(&activity("due-contract", 2, 0.0))
        .await
        .unwrap();
    let second = store
        .create_activity(&activity("due-contract", 3, 1.0))
        .await
        .unwrap();
    assert_eq!(
        store
            .claim_activity("claims", "worker-1")
            .await
            .unwrap()
            .unwrap()
            .id,
        Some(first)
    );
    assert_eq!(
        store
            .claim_activity("claims", "worker-2")
            .await
            .unwrap()
            .unwrap()
            .id,
        Some(second)
    );
    assert!(
        store
            .claim_activity("claims", "worker-3")
            .await
            .unwrap()
            .is_none(),
        "future row must remain ineligible"
    );
    let pending = store.get_activity(future).await.unwrap().unwrap();
    assert_eq!(pending.status, "PENDING");
    assert!(pending.claimed_by.is_none());
    assert!(pending.started_at.is_none());
    match &store {
        #[cfg(feature = "backend-postgres")]
        common::Harness::Postgres { store, .. } => {
            sqlx::query("UPDATE workflow.activities SET scheduled_at = 0 WHERE id = $1")
                .bind(future)
                .execute(store.pool())
                .await
                .unwrap();
        }
        #[cfg(feature = "backend-sqlite")]
        common::Harness::Sqlite { store, .. } => {
            sqlx::query("UPDATE workflow.activities SET scheduled_at = 0 WHERE id = ?")
                .bind(future)
                .execute(store.pool())
                .await
                .unwrap();
        }
    }
    assert_eq!(
        store
            .claim_activity("claims", "worker-3")
            .await
            .unwrap()
            .unwrap()
            .id,
        Some(future)
    );
}
