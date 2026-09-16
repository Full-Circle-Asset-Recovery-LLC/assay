//! Due-time claims and retry compare-and-set through the existing store API.
#![cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
mod common;

use assay_workflow::WorkflowStore;
use assay_workflow::types::*;
use common::{Backend, Harness, make_event, make_workflow};
use rstest::rstest;

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

async fn seed<S: WorkflowStore>(
    store: &S,
    key: &str,
    due: f64,
    parent: &str,
    archived: bool,
    running: bool,
) -> i64 {
    let mut workflow = make_workflow(key, "main", key);
    workflow.status = parent.into();
    if archived {
        workflow.archived_at = Some(1.0);
    }
    store.create_workflow(&workflow).await.unwrap();
    store
        .create_activity(&WorkflowActivity {
            id: None,
            workflow_id: key.into(),
            seq: 1,
            name: "read_record".into(),
            task_queue: key.into(),
            input: None,
            status: if running { "RUNNING" } else { "PENDING" }.into(),
            result: None,
            error: None,
            attempt: 1,
            max_attempts: 3,
            initial_interval_secs: 60.0,
            backoff_coefficient: 1.0,
            start_to_close_secs: 300.0,
            heartbeat_timeout_secs: Some(30.0),
            claimed_by: running.then(|| "worker-1".into()),
            scheduled_at: due,
            started_at: running.then_some(1.0),
            completed_at: None,
            last_heartbeat: running.then_some(1.0),
        })
        .await
        .unwrap()
}

async fn snapshot<S: WorkflowStore>(store: &S, id: i64) -> serde_json::Value {
    serde_json::to_value(store.get_activity(id).await.unwrap().unwrap()).unwrap()
}

async fn future_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, "future", now() + 3600.0, "PENDING", false, false).await;
    let before = snapshot(store, id).await;
    assert!(
        store
            .claim_activity("future", "worker-1")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(snapshot(store, id).await, before);
    let id = seed(store, "retry", 1.0, "RUNNING", false, false).await;
    assert_eq!(
        store
            .claim_activity("retry", "worker-1")
            .await
            .unwrap()
            .unwrap()
            .id,
        Some(id)
    );
    let due = now() + 3600.0;
    store.requeue_activity_for_retry(id, 2, due).await.unwrap();
    let before = snapshot(store, id).await;
    assert_eq!(before["status"], "PENDING");
    assert_eq!(before["attempt"], 2);
    assert_eq!(before["scheduled_at"], due);
    for field in ["claimed_by", "started_at", "last_heartbeat", "error"] {
        assert!(before[field].is_null(), "{field}");
    }
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert!(
        store
            .claim_activity("retry", "worker-2")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        snapshot(store, id).await,
        before,
        "duplicate retry must not shorten its deadline"
    );
    assert_eq!(store.get_event_count("retry").await.unwrap(), 0);
}

async fn live_claim_contract<S: WorkflowStore>(store: &S) {
    for parent in ["PENDING", "RUNNING", "WAITING"] {
        let id = seed(store, parent, 1.0, parent, false, false).await;
        let (first, second) = tokio::join!(
            store.claim_activity(parent, "worker-1"),
            store.claim_activity(parent, "worker-2"),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(
            usize::from(first.is_some()) + usize::from(second.is_some()),
            1
        );
        let claimed = first.or(second).unwrap();
        assert_eq!(claimed.id, Some(id));
        assert_eq!(claimed.status, "RUNNING");
        assert_eq!(claimed.attempt, 1);
        assert!(claimed.started_at.unwrap() > 1.0);
        assert!(matches!(
            claimed.claimed_by.as_deref(),
            Some("worker-1" | "worker-2")
        ));
        assert!(
            store
                .claim_activity(parent, "worker-3")
                .await
                .unwrap()
                .is_none()
        );
    }
}

async fn inactive_parent_contract<S: WorkflowStore>(store: &S) {
    for (parent, archived) in [
        ("COMPLETED", false),
        ("FAILED", false),
        ("CANCELLED", false),
        ("TIMED_OUT", false),
        ("UNKNOWN", false),
        ("RUNNING", true),
    ] {
        for running in [false, true] {
            let key = format!("{parent}-{archived}-{running}");
            let id = seed(store, &key, 1.0, parent, archived, running).await;
            let before = snapshot(store, id).await;
            assert!(
                store
                    .claim_activity(&key, "worker-2")
                    .await
                    .unwrap()
                    .is_none()
            );
            store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
            assert_eq!(snapshot(store, id).await, before, "inactive parent: {key}");
            assert_eq!(store.get_event_count(&key).await.unwrap(), 0);
        }
    }
}

async fn cancellation_request_contract<S: WorkflowStore>(store: &S) {
    for running in [false, true] {
        let key = format!("cancel-{running}");
        let id = seed(store, &key, 1.0, "RUNNING", false, running).await;
        let mut event = make_event(&key, 1);
        event.event_type = "WorkflowCancelRequested".into();
        store.append_event(&event).await.unwrap();
        store.append_event(&make_event(&key, 2)).await.unwrap();
        let before = snapshot(store, id).await;
        assert!(
            store
                .claim_activity(&key, "worker-2")
                .await
                .unwrap()
                .is_none()
        );
        store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
        assert_eq!(snapshot(store, id).await, before);
        assert_eq!(store.get_event_count(&key).await.unwrap(), 2);
    }
}

async fn failed_retry_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, "failed-retry", 1.0, "WAITING", false, true).await;
    store
        .complete_activity(id, Some("legacy-result"), Some("failure"), true)
        .await
        .unwrap();
    let failed = store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(failed.status, "FAILED");
    let due = now() + 3600.0;
    store.requeue_activity_for_retry(id, 2, due).await.unwrap();
    let retried = store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(retried.status, "PENDING");
    assert_eq!(retried.attempt, 2);
    assert_eq!(retried.scheduled_at, due);
    assert_eq!(
        retried.result, failed.result,
        "retain existing retry field semantics"
    );
    assert_eq!(retried.completed_at, failed.completed_at);
    assert!(retried.error.is_none());
    let before = snapshot(store, id).await;
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(snapshot(store, id).await, before);
    assert!(
        store
            .claim_activity("failed-retry", "worker-2")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .cancel_pending_activities("failed-retry")
            .await
            .unwrap(),
        1
    );
    let cancelled = snapshot(store, id).await;
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(snapshot(store, id).await, cancelled);
}

async fn invalid_attempt_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, "invalid-attempt", 1.0, "RUNNING", false, true).await;
    let before = snapshot(store, id).await;
    for attempt in [i32::MIN, -1, 0, 1, 3, i32::MAX] {
        store
            .requeue_activity_for_retry(id, attempt, 1.0)
            .await
            .unwrap();
        assert_eq!(
            snapshot(store, id).await,
            before,
            "non-successor attempt {attempt}"
        );
    }
    store
        .requeue_activity_for_retry(i64::MAX, 2, 1.0)
        .await
        .unwrap();
    assert_eq!(snapshot(store, id).await, before);
}

async fn concurrent_retry_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, "retry-race", 1.0, "RUNNING", false, true).await;
    let first_due = now() + 3600.0;
    let second_due = first_due + 3600.0;
    let (first, second) = tokio::join!(
        store.requeue_activity_for_retry(id, 2, first_due),
        store.requeue_activity_for_retry(id, 2, second_due),
    );
    first.unwrap();
    second.unwrap();
    let row = store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(row.attempt, 2);
    assert_eq!(row.status, "PENDING");
    assert!(row.scheduled_at == first_due || row.scheduled_at == second_due);
    let before = snapshot(store, id).await;
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(snapshot(store, id).await, before);
    assert_eq!(store.get_event_count("retry-race").await.unwrap(), 0);
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
            // A configured but unavailable database is a failure, never a skip.
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

backend_contract!(future_claim_and_retry_deadline, future_contract);
backend_contract!(live_parent_claim_has_one_winner, live_claim_contract);
backend_contract!(
    inactive_parent_cannot_claim_or_retry,
    inactive_parent_contract
);
backend_contract!(
    cancel_request_blocks_claim_and_retry,
    cancellation_request_contract
);
backend_contract!(legacy_failed_retry_retains_cas, failed_retry_contract);
backend_contract!(
    non_successor_retry_leaves_row_unchanged,
    invalid_attempt_contract
);
backend_contract!(concurrent_retry_advances_once, concurrent_retry_contract);

#[cfg(all(feature = "backend-postgres", target_os = "linux"))]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_retry_locks_parent_before_activity() {
    use assay_workflow::PostgresStore;
    use std::sync::Arc;
    use std::time::Duration;
    let harness = Backend::Postgres.setup().await.unwrap();
    let store = match &harness {
        Harness::Postgres { store, .. } => store,
        #[cfg(feature = "backend-sqlite")]
        Harness::Sqlite { .. } => unreachable!(),
    };
    let store = Arc::new(
        PostgresStore::from_pool(store.pool().clone())
            .await
            .unwrap(),
    );
    let id = seed(&*store, "lock-order", 1.0, "RUNNING", false, true).await;
    let mut blocker = store.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM workflow.workflows WHERE id = 'lock-order' FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let retry_store = Arc::clone(&store);
    let retry =
        tokio::spawn(async move { retry_store.requeue_activity_for_retry(id, 2, 1.0).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()
                 AND pid <> pg_backend_pid() AND wait_event_type = 'Lock'
                 AND query LIKE '%workflow.workflows%'",
            )
            .fetch_one(store.pool())
            .await
            .unwrap();
            if waiting.0 > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retry must wait for its parent lock");
    let mut probe = store.pool().begin().await.unwrap();
    let activity_lock =
        sqlx::query("SELECT id FROM workflow.activities WHERE id = $1 FOR UPDATE NOWAIT")
            .bind(id)
            .fetch_one(&mut *probe)
            .await;
    probe.rollback().await.unwrap();
    blocker.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), retry)
        .await
        .expect("retry must finish after parent unlock")
        .unwrap()
        .unwrap();
    assert!(
        activity_lock.is_ok(),
        "retry locked activity before parent: {activity_lock:?}"
    );
    let row = store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(row.attempt, 2);
    assert_eq!(row.status, "PENDING");
}
