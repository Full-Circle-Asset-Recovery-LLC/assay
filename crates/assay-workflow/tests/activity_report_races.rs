//! Cross-backend report races and timeout recovery regressions.
mod common;

#[cfg(feature = "backend-sqlite")]
use assay_workflow::SqliteStore;
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

async fn simultaneous_reports_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    let fence = ActivityFence {
        expected_attempt: 1,
        claimed_by: Some("worker-1"),
    };
    let (first, second) = tokio::join!(
        store.report_activity(id, fence, ActivityReport::Fail { error: "retry" }, now()),
        store.report_activity(
            id,
            fence,
            ActivityReport::Complete { result: Some("42") },
            now()
        ),
    );
    assert_ne!(
        first.unwrap(),
        second.unwrap(),
        "exactly one competing report may apply"
    );
    let act = store.get_activity(id).await.unwrap().unwrap();
    assert!(matches!(act.status.as_str(), "PENDING" | "COMPLETED"));
    assert_eq!(
        store.get_event_count("wf-fence").await.unwrap(),
        i64::from(act.status == "COMPLETED")
    );
}

async fn waiting_workflow_contract<S: WorkflowStore>(store: &S) {
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
    // The owner is optional; attempt-only callers still receive atomic fencing.
    let fence = ActivityFence {
        expected_attempt: 1,
        claimed_by: None,
    };
    assert!(
        store
            .report_activity(
                id,
                fence,
                ActivityReport::Heartbeat { details: None },
                now()
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .report_activity(id, fence, ActivityReport::Fail { error: "retry" }, 1.0)
            .await
            .unwrap()
    );
    let later = store
        .claim_activity(QUEUE, "worker-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(later.attempt, 2);
    assert!(
        !store
            .report_activity(
                id,
                fence,
                ActivityReport::Complete {
                    result: Some("stale")
                },
                now()
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .report_activity(
                id,
                ActivityFence {
                    expected_attempt: 2,
                    claimed_by: Some("worker-2")
                },
                ActivityReport::Complete { result: Some("42") },
                now()
            )
            .await
            .unwrap()
    );
}

async fn cancellation_report_race_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    let fence = ActivityFence {
        expected_attempt: 1,
        claimed_by: Some("worker-1"),
    };
    let event = WorkflowEvent {
        id: None,
        workflow_id: "wf-fence".into(),
        seq: 1,
        event_type: "WorkflowCancelRequested".into(),
        payload: None,
        timestamp: now(),
    };
    let (report, cancel) = tokio::join!(
        store.report_activity(id, fence, ActivityReport::Fail { error: "retry" }, 1.0),
        store.append_event(&event),
    );
    let applied = report.unwrap();
    cancel.unwrap();
    let act = store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(act.attempt, if applied { 2 } else { 1 });
    assert!(
        store
            .claim_activity(QUEUE, "worker-2")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .report_activity(
                id,
                fence,
                ActivityReport::Complete {
                    result: Some("late")
                },
                now()
            )
            .await
            .unwrap()
    );
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 1);
}

macro_rules! backend_contract {
    ($name:ident, $contract:ident) => {
        #[rstest]
        #[cfg_attr(feature = "backend-sqlite", case::sqlite(Backend::Sqlite))]
        #[cfg_attr(feature = "backend-postgres", case::postgres(Backend::Postgres))]
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

backend_contract!(
    backend_competing_reports_have_one_winner,
    simultaneous_reports_contract
);
backend_contract!(backend_waiting_is_live, waiting_workflow_contract);
backend_contract!(
    backend_cancellation_serializes_with_retry,
    cancellation_report_race_contract
);

#[cfg(feature = "backend-sqlite")]
#[tokio::test]
async fn timeout_rechecks_heartbeat_and_does_not_fail_cancelled_workflow() {
    let store = SqliteStore::new("sqlite::memory:").await.unwrap();
    let id = seed(&store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    let tick = now();
    sqlx::query(
        "UPDATE workflow.activities SET heartbeat_timeout_secs = 10,
        started_at = ?, last_heartbeat = ?, max_attempts = 1 WHERE id = ?",
    )
    .bind(tick)
    .bind(tick - 20.0)
    .bind(id)
    .execute(store.pool())
    .await
    .unwrap();
    let captured = store.get_timed_out_activities(tick).await.unwrap();
    assert_eq!(captured.len(), 1);
    let fence = ActivityFence {
        expected_attempt: 1,
        claimed_by: Some("worker-1"),
    };
    assert!(
        store
            .report_activity(id, fence, ActivityReport::Heartbeat { details: None }, tick)
            .await
            .unwrap()
    );
    assert!(
        !store
            .report_activity(id, fence, ActivityReport::Timeout, tick)
            .await
            .unwrap()
    );
    store
        .update_workflow_status("wf-fence", WorkflowStatus::Cancelled, None, None)
        .await
        .unwrap();
    assert!(
        !store
            .report_activity(id, fence, ActivityReport::Timeout, tick + 1000.0)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .get_workflow("wf-fence")
            .await
            .unwrap()
            .unwrap()
            .status,
        "CANCELLED"
    );
    assert_eq!(
        store.get_activity(id).await.unwrap().unwrap().status,
        "RUNNING"
    );
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 0);
}

#[cfg(feature = "backend-postgres")]
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

#[cfg(feature = "backend-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_legacy_and_fenced_settlement_lock_parent_before_activity() {
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
    // Old activity-first settlement already owns this lock while waiting for
    // the parent, creating a cycle with a parent-first fenced report.
    let mut probe = store.pool().begin().await.unwrap();
    let activity_lock =
        sqlx::query("SELECT id FROM workflow.activities WHERE id = $1 FOR UPDATE NOWAIT")
            .bind(id)
            .fetch_one(&mut *probe)
            .await;
    probe.rollback().await.unwrap();
    let fenced_store = Arc::clone(&store);
    let fenced = tokio::spawn(async move {
        fenced_store
            .report_activity(
                id,
                ActivityFence {
                    expected_attempt: 1,
                    claimed_by: Some("worker-1"),
                },
                ActivityReport::Complete { result: Some("43") },
                121.0,
            )
            .await
    });
    blocker.commit().await.unwrap();
    let (legacy, fenced) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(legacy, fenced)
    })
    .await
    .expect("mixed settlement paths must not deadlock");
    legacy.unwrap().unwrap();
    fenced.unwrap().unwrap();
    assert!(
        activity_lock.is_ok(),
        "legacy settlement locked activity before parent: {activity_lock:?}"
    );
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 1);
    let result = store
        .get_activity(id)
        .await
        .unwrap()
        .unwrap()
        .result
        .unwrap();
    assert!(matches!(result.as_str(), "42" | "43"));
}
