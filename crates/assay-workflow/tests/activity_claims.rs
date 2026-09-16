//! Due-time claims and retry CAS regressions using the legacy store API.
mod common;

use assay_workflow::WorkflowStore;
use assay_workflow::types::*;
use common::{Backend, Harness, make_workflow};
use rstest::rstest;

const QUEUE: &str = "retry-fence-q";

async fn seed<S: WorkflowStore>(store: &S, due: f64) -> i64 {
    store
        .create_workflow(&make_workflow("wf-fence", "main", QUEUE))
        .await
        .unwrap();
    store
        .create_activity(&WorkflowActivity {
            id: None,
            workflow_id: "wf-fence".into(),
            seq: 1,
            name: "verify".into(),
            task_queue: QUEUE.into(),
            input: None,
            status: "PENDING".into(),
            result: None,
            error: None,
            attempt: 1,
            max_attempts: 3,
            initial_interval_secs: 60.0,
            backoff_coefficient: 1.0,
            start_to_close_secs: 300.0,
            heartbeat_timeout_secs: None,
            claimed_by: None,
            scheduled_at: due,
            started_at: None,
            completed_at: None,
            last_heartbeat: None,
        })
        .await
        .unwrap()
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

async fn due_time_contract<S: WorkflowStore>(store: &S) {
    seed(store, now() + 3600.0).await;
    assert!(
        store
            .claim_activity(QUEUE, "worker-1")
            .await
            .unwrap()
            .is_none(),
        "a future scheduled_at must not be claimable"
    );
}

async fn cancelled_parent_contract<S: WorkflowStore>(store: &S) {
    seed(store, 1.0).await;
    store
        .update_workflow_status("wf-fence", WorkflowStatus::Cancelled, None, None)
        .await
        .unwrap();
    assert!(
        store
            .claim_activity(QUEUE, "worker-1")
            .await
            .unwrap()
            .is_none(),
        "terminal workflows must not dispatch leftover pending activities"
    );
}

async fn duplicate_retry_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    let due = now() + 3600.0;
    store.requeue_activity_for_retry(id, 2, due).await.unwrap();
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(
        store.get_activity(id).await.unwrap().unwrap().scheduled_at,
        due,
        "a duplicate retry must not overwrite the pending retry deadline"
    );
    store.cancel_pending_activities("wf-fence").await.unwrap();
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(
        store.get_activity(id).await.unwrap().unwrap().status,
        "CANCELLED"
    );
}

async fn legacy_failed_retry_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    store
        .complete_activity(id, None, Some("failure"), true)
        .await
        .unwrap();
    store
        .update_workflow_status("wf-fence", WorkflowStatus::Waiting, None, None)
        .await
        .unwrap();
    let due = now() + 3600.0;
    store.requeue_activity_for_retry(id, 2, due).await.unwrap();
    let act = store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(act.status, "PENDING");
    assert_eq!(act.attempt, 2);
    assert_eq!(act.scheduled_at, due);
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(
        store.get_activity(id).await.unwrap().unwrap().scheduled_at,
        due
    );
    assert!(
        store
            .claim_activity(QUEUE, "worker-2")
            .await
            .unwrap()
            .is_none()
    );
}

async fn pending_cancellation_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .append_event(&WorkflowEvent {
            id: None,
            workflow_id: "wf-fence".into(),
            seq: 1,
            event_type: "WorkflowCancelRequested".into(),
            payload: None,
            timestamp: now(),
        })
        .await
        .unwrap();
    assert!(
        store
            .claim_activity(QUEUE, "worker-1")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.get_activity(id).await.unwrap().unwrap().status,
        "PENDING"
    );
}

macro_rules! backend_contract {
    ($name:ident, $contract:ident) => {
        #[rstest]
        #[cfg_attr(feature = "backend-sqlite", case::sqlite(Backend::Sqlite))]
        #[cfg_attr(
            all(feature = "backend-postgres", target_os = "linux"),
            case::postgres(Backend::Postgres)
        )]
        #[tokio::test]
        async fn $name(#[case] backend: Backend) {
            let harness = backend.setup().await.unwrap();
            match &harness {
                #[cfg(feature = "backend-sqlite")]
                Harness::Sqlite { store, .. } => $contract(store).await,
                #[cfg(feature = "backend-postgres")]
                Harness::Postgres { store, .. } => $contract(store).await,
            }
        }
    };
}

backend_contract!(claim_respects_due_time, due_time_contract);
backend_contract!(claim_rejects_cancelled_parent, cancelled_parent_contract);
backend_contract!(retry_compare_and_swap, duplicate_retry_contract);
backend_contract!(
    backend_legacy_failed_retry_keeps_cas,
    legacy_failed_retry_contract
);
backend_contract!(
    backend_pending_cancellation_blocks_claim,
    pending_cancellation_contract
);

async fn waiting_parent_claim_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .update_workflow_status("wf-fence", WorkflowStatus::Waiting, None, None)
        .await
        .unwrap();
    let claimed = store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.id, Some(id));
    assert_eq!(claimed.attempt, 1);
    assert!(store.supports_activity_due_time_claims());
}

async fn cancelled_parent_retry_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    store
        .update_workflow_status("wf-fence", WorkflowStatus::Cancelled, None, None)
        .await
        .unwrap();
    let before = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(
        serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
        before
    );
}

backend_contract!(waiting_parent_can_claim, waiting_parent_claim_contract);
backend_contract!(
    cancelled_parent_cannot_retry,
    cancelled_parent_retry_contract
);

#[cfg(all(feature = "backend-postgres", target_os = "linux"))]
async fn wait_for_blocked_query(pool: &sqlx::PgPool) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM pg_stat_activity
                WHERE datname = current_database() AND pid <> pg_backend_pid()
                  AND wait_event_type = 'Lock' AND query LIKE '%workflow.%'",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting.0 > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("legacy settlement must reach its blocked parent lock");
}

#[cfg(all(feature = "backend-postgres", target_os = "linux"))]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_legacy_settlement_locks_parent_before_activity() {
    use assay_workflow::PostgresStore;
    use std::sync::Arc;
    use std::time::Duration;

    let harness = Backend::Postgres.setup().await.unwrap();
    let Harness::Postgres { store, .. } = &harness else {
        unreachable!()
    };
    let store = Arc::new(
        PostgresStore::from_pool(store.pool().clone())
            .await
            .unwrap(),
    );
    let id = seed(&*store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    let mut blocker = store.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM workflow.workflows WHERE id = 'wf-fence' FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let legacy_store = Arc::clone(&store);
    let legacy = tokio::spawn(async move {
        legacy_store
            .settle_activity(&ActivitySettlement {
                activity_id: id,
                workflow_id: "wf-fence",
                result: Some("42"),
                error: None,
                failed: false,
                event_type: "ActivityCompleted",
                payload: &serde_json::json!({"activity_id": id, "result": 42}).to_string(),
                now: 120.0,
            })
            .await
    });
    wait_for_blocked_query(store.pool()).await;
    let mut probe = store.pool().begin().await.unwrap();
    let activity_lock =
        sqlx::query("SELECT id FROM workflow.activities WHERE id = $1 FOR UPDATE NOWAIT")
            .bind(id)
            .fetch_one(&mut *probe)
            .await;
    probe.rollback().await.unwrap();
    blocker.commit().await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), legacy)
        .await
        .expect("legacy settlement must finish after the parent unlocks")
        .unwrap()
        .unwrap();
    assert_eq!(outcome, SettleOutcome::Settled);
    assert!(
        activity_lock.is_ok(),
        "legacy settlement locked activity before parent: {activity_lock:?}"
    );
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 1);
    assert_eq!(
        store
            .get_activity(id)
            .await
            .unwrap()
            .unwrap()
            .result
            .as_deref(),
        Some("42")
    );
}
