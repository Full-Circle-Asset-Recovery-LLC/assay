//! Both native stores implement the additive report contract before HTTP exposure.
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
            heartbeat_timeout_secs: Some(10.0),
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

async fn fenced_reports_contract<S: WorkflowStore>(store: &S) {
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
    let stale = ActivityFence {
        expected_attempt: 2,
        ..fence
    };
    let reports = [
        ActivityReport::Heartbeat { details: None },
        ActivityReport::Fail { error: "retry" },
        ActivityReport::Complete { result: Some("42") },
    ];
    let before = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    for report in reports {
        assert!(
            !store
                .report_activity(id, stale, report, now())
                .await
                .unwrap()
        );
        assert!(
            !store
                .report_activity(
                    id,
                    ActivityFence {
                        claimed_by: Some("wrong"),
                        ..fence
                    },
                    report,
                    now()
                )
                .await
                .unwrap()
        );
        assert_eq!(
            serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
            before
        );
        assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 0);
    }
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
            .report_activity(id, fence, ActivityReport::Fail { error: "retry" }, now())
            .await
            .unwrap()
    );
    let pending = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    assert_eq!(pending["attempt"], 2);
    assert_eq!(pending["status"], "PENDING");
    for report in reports {
        assert!(
            !store
                .report_activity(id, fence, report, now())
                .await
                .unwrap()
        );
        assert_eq!(
            serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
            pending
        );
    }
    assert!(
        store
            .claim_activity(QUEUE, "worker-2")
            .await
            .unwrap()
            .is_none()
    );
}

async fn cancellation_request_contract<S: WorkflowStore>(store: &S) {
    let id = seed(store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
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
    let fence = ActivityFence {
        expected_attempt: 1,
        claimed_by: Some("worker-1"),
    };
    let before = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    for report in [
        ActivityReport::Heartbeat { details: None },
        ActivityReport::Fail { error: "retry" },
        ActivityReport::Complete { result: Some("42") },
        ActivityReport::Timeout,
    ] {
        assert!(
            !store
                .report_activity(id, fence, report, now() + 10000.0)
                .await
                .unwrap()
        );
        assert_eq!(
            serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
            before
        );
        assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 1);
    }
    store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
    assert_eq!(
        serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
        before
    );
    assert!(
        store
            .claim_activity(QUEUE, "worker-2")
            .await
            .unwrap()
            .is_none()
    );
}

async fn terminal_completion_contract<S: WorkflowStore>(store: &S) {
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
    assert!(
        store
            .report_activity(
                id,
                fence,
                ActivityReport::Complete { result: Some("42") },
                now()
            )
            .await
            .unwrap()
    );
    let before = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    assert_eq!(before["status"], "COMPLETED");
    assert_eq!(before["result"], "42");
    let events = store.list_events("wf-fence").await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "ActivityCompleted");
    // Drain dispatch to prove rejected duplicate completion does not re-arm it.
    store
        .claim_workflow_task(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    store
        .release_workflow_task("wf-fence", "worker-1")
        .await
        .unwrap();
    assert!(
        !store
            .report_activity(
                id,
                fence,
                ActivityReport::Complete { result: Some("43") },
                now()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
        before
    );
    assert!(
        store
            .claim_workflow_task(QUEUE, "worker-2")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 1);
}

async fn terminal_parent_reports_contract<S: WorkflowStore>(store: &S) {
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
    let before = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    for status in [
        WorkflowStatus::Completed,
        WorkflowStatus::Failed,
        WorkflowStatus::Cancelled,
        WorkflowStatus::TimedOut,
    ] {
        store
            .update_workflow_status("wf-fence", status, None, None)
            .await
            .unwrap();
        for report in [
            ActivityReport::Fail { error: "retry" },
            ActivityReport::Complete { result: Some("42") },
            ActivityReport::Heartbeat { details: None },
        ] {
            assert!(
                !store
                    .report_activity(id, fence, report, now())
                    .await
                    .unwrap()
            );
            assert_eq!(
                serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
                before
            );
        }
        store.requeue_activity_for_retry(id, 2, 1.0).await.unwrap();
        assert_eq!(
            serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
            before
        );
    }
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 0);
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

backend_contract!(backend_fenced_reports, fenced_reports_contract);
backend_contract!(
    backend_cancel_request_rejects_reports,
    cancellation_request_contract
);
backend_contract!(
    backend_terminal_completion_is_atomic,
    terminal_completion_contract
);
backend_contract!(
    backend_terminal_parents_reject_reports,
    terminal_parent_reports_contract
);

#[cfg(feature = "backend-sqlite")]
#[tokio::test]
async fn fenced_event_failure_rolls_back_every_write() {
    let store = SqliteStore::new("sqlite::memory:").await.unwrap();
    let id = seed(&store, 1.0).await;
    store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER workflow.block_report_events BEFORE INSERT ON events
        BEGIN SELECT RAISE(ABORT, 'injected report write failure'); END",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let before = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    let error = store
        .report_activity(
            id,
            ActivityFence {
                expected_attempt: 1,
                claimed_by: Some("worker-1"),
            },
            ActivityReport::Complete { result: Some("42") },
            now(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected report write failure"));
    assert_eq!(
        serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
        before
    );
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 0);
    assert!(
        store
            .claim_workflow_task(QUEUE, "worker-2")
            .await
            .unwrap()
            .is_none()
    );
}

async fn monotonic_heartbeat_contract<S: WorkflowStore>(store: &S) {
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
    let report = ActivityReport::Heartbeat { details: None };
    assert!(
        store
            .report_activity(id, fence, report, 110.0)
            .await
            .unwrap()
    );
    assert!(
        store
            .report_activity(id, fence, report, 100.0)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .get_activity(id)
            .await
            .unwrap()
            .unwrap()
            .last_heartbeat,
        Some(110.0)
    );
    assert!(
        store
            .get_timed_out_activities(112.0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !store
            .report_activity(id, fence, ActivityReport::Timeout, 112.0)
            .await
            .unwrap()
    );
    let current = store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(current.status, "RUNNING");
    assert_eq!(current.attempt, 1);
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 0);
}

backend_contract!(
    reordered_heartbeats_do_not_expire_a_live_attempt,
    monotonic_heartbeat_contract
);
