//! Additive migration leaves legacy rows unchanged and preserves protected generations.
mod common;
use assay_workflow::types::{ScheduleActivityOpts, WorkflowActivity};
use assay_workflow::{WorkflowCtx, WorkflowStore};
use common::{Backend, Harness, make_workflow};
use rstest::rstest;
use std::sync::Arc;

async fn set_generation(harness: &Harness, id: i64, generation: i64) {
    match harness {
        #[cfg(feature = "backend-postgres")]
        Harness::Postgres { store, .. } => {
            sqlx::query("UPDATE workflow.activities SET claim_generation = $1 WHERE id = $2")
                .bind(generation)
                .bind(id)
                .execute(store.pool())
                .await
                .unwrap();
        }
        #[cfg(feature = "backend-sqlite")]
        Harness::Sqlite { store, .. } => {
            sqlx::query("UPDATE workflow.activities SET claim_generation = ? WHERE id = ?")
                .bind(generation)
                .bind(id)
                .execute(store.pool())
                .await
                .unwrap();
        }
    }
}
async fn protected<S: WorkflowStore>(store: S) -> (WorkflowCtx<S>, i64) {
    assert!(store.supports_activity_claim_generation_fencing());
    let state = WorkflowCtx::start(Arc::new(store));
    state
        .start_workflow(
            "main",
            "ExampleWorkflow",
            "protected-migration",
            None,
            "protected-queue",
            None,
        )
        .await
        .unwrap();
    let row = state
        .schedule_activity(
            "protected-migration",
            1,
            "verify",
            None,
            "protected-queue",
            ScheduleActivityOpts {
                claim_generation_fencing: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(row.claim_generation, Some(0));
    (state, row.id.unwrap())
}
fn legacy() -> WorkflowActivity {
    WorkflowActivity {
        claim_generation: None,
        id: None,
        workflow_id: "legacy-migration".into(),
        seq: 1,
        name: "verify".into(),
        task_queue: "legacy-queue".into(),
        input: Some("{\"legacy\":true}".into()),
        status: "PENDING".into(),
        result: None,
        error: None,
        attempt: 1,
        max_attempts: 3,
        initial_interval_secs: 1.0,
        backoff_coefficient: 2.0,
        start_to_close_secs: 300.0,
        heartbeat_timeout_secs: None,
        claimed_by: None,
        scheduled_at: 1.0,
        started_at: None,
        completed_at: None,
        last_heartbeat: None,
    }
}

#[rstest]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::postgres(Backend::Postgres)
)]
#[cfg_attr(feature = "backend-sqlite", case::sqlite(Backend::Sqlite))]
#[tokio::test(flavor = "multi_thread")]
async fn old_schema_upgrade_retains_legacy_rows_and_reopened_claim_identity(
    #[case] backend: Backend,
) {
    let h = backend.setup().await.unwrap();
    h.create_workflow(&make_workflow("legacy-migration", "main", "legacy-queue"))
        .await
        .unwrap();
    let id = h.create_activity(&legacy()).await.unwrap();
    let expected = h.get_activity(id).await.unwrap().unwrap();
    match &h {
        #[cfg(feature = "backend-postgres")]
        Harness::Postgres { store, .. } => {
            sqlx::query("ALTER TABLE workflow.activities DROP COLUMN claim_generation")
                .execute(store.pool())
                .await
                .unwrap();
            let reopened = assay_workflow::PostgresStore::from_pool(store.pool().clone())
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(reopened.get_activity(id).await.unwrap()).unwrap(),
                serde_json::to_value(Some(&expected)).unwrap()
            );
            let (state, protected_id) = protected(reopened).await;
            let claimed = state
                .claim_activity("protected-queue", "worker-1")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(claimed.claim_generation, Some(1));
            drop(state);
            let reopened = assay_workflow::PostgresStore::from_pool(store.pool().clone())
                .await
                .unwrap();
            assert_eq!(
                reopened
                    .get_activity(protected_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .claim_generation,
                Some(1)
            );
            assert!(
                reopened
                    .heartbeat_activity(protected_id, None)
                    .await
                    .is_err()
            );
        }
        #[cfg(feature = "backend-sqlite")]
        Harness::Sqlite { store, .. } => {
            sqlx::query("ALTER TABLE workflow.activities DROP COLUMN claim_generation")
                .execute(store.pool())
                .await
                .unwrap();
            let reopened = assay_workflow::SqliteStore::from_attached_pool(store.pool().clone())
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(reopened.get_activity(id).await.unwrap()).unwrap(),
                serde_json::to_value(Some(&expected)).unwrap()
            );
            let (state, protected_id) = protected(reopened).await;
            let claimed = state
                .claim_activity("protected-queue", "worker-1")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(claimed.claim_generation, Some(1));
            drop(state);
            let reopened = assay_workflow::SqliteStore::from_attached_pool(store.pool().clone())
                .await
                .unwrap();
            assert_eq!(
                reopened
                    .get_activity(protected_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .claim_generation,
                Some(1)
            );
            assert!(
                reopened
                    .heartbeat_activity(protected_id, None)
                    .await
                    .is_err()
            );
        }
    }
}

#[rstest]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::postgres(Backend::Postgres)
)]
#[cfg_attr(feature = "backend-sqlite", case::sqlite(Backend::Sqlite))]
#[tokio::test(flavor = "multi_thread")]
async fn claim_generation_overflow_rejects_without_changing_the_pending_row(
    #[case] backend: Backend,
) {
    let h = backend.setup().await.unwrap();
    match &h {
        #[cfg(feature = "backend-postgres")]
        Harness::Postgres { store, .. } => {
            let (state, id) = protected(store.clone()).await;
            set_generation(&h, id, i64::MAX).await;
            let before = serde_json::to_value(h.get_activity(id).await.unwrap()).unwrap();
            assert!(
                state
                    .claim_activity("protected-queue", "worker-1")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                serde_json::to_value(h.get_activity(id).await.unwrap()).unwrap(),
                before
            );
        }
        #[cfg(feature = "backend-sqlite")]
        Harness::Sqlite { store, .. } => {
            let (state, id) = protected(store.clone()).await;
            set_generation(&h, id, i64::MAX).await;
            let before = serde_json::to_value(h.get_activity(id).await.unwrap()).unwrap();
            assert!(
                state
                    .claim_activity("protected-queue", "worker-1")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                serde_json::to_value(h.get_activity(id).await.unwrap()).unwrap(),
                before
            );
        }
    }
}
