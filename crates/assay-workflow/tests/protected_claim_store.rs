//! Storage writers and engine maintenance obey the protected claim boundary.
mod common;
use assay_workflow::types::{
    ActivityFence, ActivityReport, ActivitySettlement, ScheduleActivityOpts, SettleOutcome,
};
use assay_workflow::{WorkflowCtx, WorkflowStore};
use common::{Backend, Harness};
use rstest::rstest;
use serde_json::{Value, json};
use std::sync::Arc;

struct Fixture<S: WorkflowStore> {
    store: Arc<S>,
    state: WorkflowCtx<S>,
    id: i64,
}
impl<S: WorkflowStore> Fixture<S> {
    async fn new(store: S, attempts: i32) -> Self {
        let store = Arc::new(store);
        let state = WorkflowCtx::start(store.clone());
        state
            .start_workflow(
                "main",
                "ExampleWorkflow",
                "protected-store",
                None,
                "claims",
                None,
            )
            .await
            .unwrap();
        let row = state
            .schedule_activity(
                "protected-store",
                1,
                "verify",
                None,
                "claims",
                ScheduleActivityOpts {
                    claim_generation_fencing: Some(true),
                    max_attempts: Some(attempts),
                    initial_interval_secs: Some(0.0),
                    heartbeat_timeout_secs: Some(10.0),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let id = row.id.unwrap();
        state
            .claim_activity("claims", "worker-1")
            .await
            .unwrap()
            .unwrap();
        Self { store, state, id }
    }
    async fn snapshot(&self) -> Value {
        json!({"activity":self.store.get_activity(self.id).await.unwrap(),"events":self.store.list_events("protected-store").await.unwrap(),"workflow":self.store.get_workflow("protected-store").await.unwrap()})
    }
}
fn fence(generation: i64, attempt: i32) -> ActivityFence<'static> {
    ActivityFence {
        expected_claim_generation: Some(generation),
        expected_attempt: attempt,
        claimed_by: Some("worker-1"),
    }
}
fn settlement(id: i64, generation: Option<i64>) -> ActivitySettlement<'static> {
    ActivitySettlement {
        expected_claim_generation: generation,
        activity_id: id,
        workflow_id: "protected-store",
        result: Some("null"),
        error: None,
        failed: false,
        event_type: "ActivityCompleted",
        payload: "{}",
        now: 1.0,
    }
}

async fn raw_writers<S: WorkflowStore>(store: S) {
    let f = Fixture::new(store, 3).await;
    let before = f.snapshot().await;
    assert!(f.store.heartbeat_activity(f.id, None).await.is_err());
    assert_eq!(f.snapshot().await, before);
    assert!(
        f.store
            .complete_activity(f.id, Some("null"), None, false)
            .await
            .is_err()
    );
    assert_eq!(f.snapshot().await, before);
    assert!(
        f.store
            .requeue_activity_for_retry(f.id, 2, 0.0)
            .await
            .is_err()
    );
    assert!(
        f.store
            .requeue_activity_for_retry(f.id, 1, 0.0)
            .await
            .is_err()
    );
    assert_eq!(f.snapshot().await, before);
    assert!(
        f.store
            .settle_activity(&settlement(f.id, None))
            .await
            .is_err()
    );
    assert!(
        f.store
            .settle_activity(&settlement(f.id, Some(1)))
            .await
            .is_err(),
        "repair cannot settle a running generation"
    );
    assert_eq!(f.snapshot().await, before);
    assert!(f.state.heartbeat_activity(f.id, None).await.is_err());
    assert!(f.state.fail_activity(f.id, "legacy retry").await.is_err());
    assert!(
        f.state
            .complete_activity(f.id, None, None, false)
            .await
            .is_err()
    );
    assert_eq!(f.snapshot().await, before);
    assert!(
        !f.store
            .report_activity(
                f.id,
                ActivityFence {
                    expected_claim_generation: None,
                    ..fence(1, 1)
                },
                ActivityReport::Complete { result: None },
                1.0
            )
            .await
            .unwrap()
    );
    assert!(
        !f.store
            .report_activity(
                f.id,
                ActivityFence {
                    claimed_by: None,
                    ..fence(1, 1)
                },
                ActivityReport::Complete { result: None },
                1.0
            )
            .await
            .unwrap()
    );
    assert_eq!(f.snapshot().await, before);
}

async fn retry_budget<S: WorkflowStore>(store: S) {
    let f = Fixture::new(store, 3).await;
    for attempt in 1..=3 {
        assert!(
            f.state
                .fail_activity_fenced(f.id, "retry", fence(i64::from(attempt), attempt))
                .await
                .unwrap()
        );
        if attempt < 3 {
            let row = f
                .state
                .claim_activity("claims", "worker-1")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.attempt, attempt + 1);
            assert_eq!(row.claim_generation, Some(i64::from(attempt) + 1));
        }
    }
    f.state
        .fail_workflow("protected-store", "activity failed")
        .await
        .unwrap();
    f.state
        .retry_failed_activity("protected-store", "operator", "dependency repaired")
        .await
        .unwrap();
    let reopened = f
        .state
        .claim_activity("claims", "worker-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            reopened.attempt,
            reopened.max_attempts,
            reopened.claim_generation
        ),
        (1, 3, Some(4))
    );
    assert_eq!(
        (reopened.initial_interval_secs, reopened.backoff_coefficient),
        (0.0, 2.0)
    );
    assert!(
        f.state
            .fail_activity_fenced(f.id, "fresh retry budget", fence(4, 1))
            .await
            .unwrap()
    );
    let row = f
        .state
        .claim_activity("claims", "worker-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((row.attempt, row.claim_generation), (2, Some(5)));
    let before = f.snapshot().await;
    assert!(
        !f.store
            .report_activity(f.id, fence(1, 1), ActivityReport::Timeout, f64::MAX)
            .await
            .unwrap()
    );
    assert_eq!(
        f.snapshot().await,
        before,
        "captured stale timeout cannot touch a new generation"
    );
}

async fn repair<S: WorkflowStore>(store: S) {
    let f = Fixture::new(store, 1).await;
    assert!(
        f.state
            .fail_activity_fenced(f.id, "retry", fence(1, 1))
            .await
            .unwrap()
    );
    f.state
        .fail_workflow("protected-store", "activity failed")
        .await
        .unwrap();
    f.state
        .retry_failed_activity("protected-store", "operator", "dependency repaired")
        .await
        .unwrap();
    f.state
        .claim_activity("claims", "worker-1")
        .await
        .unwrap()
        .unwrap();
    assert!(
        f.state
            .complete_activity_fenced(f.id, Some("{\"new\":true}"), fence(2, 1))
            .await
            .unwrap()
    );
    let before = f.snapshot().await;
    assert!(
        f.store
            .settle_activity(&settlement(f.id, Some(1)))
            .await
            .is_err()
    );
    assert!(
        f.store
            .settle_activity(&settlement(f.id, None))
            .await
            .is_err()
    );
    assert_eq!(
        f.snapshot().await,
        before,
        "stale terminal repair must write nothing"
    );
    assert_eq!(
        f.store
            .settle_activity(&settlement(f.id, Some(2)))
            .await
            .unwrap(),
        SettleOutcome::AlreadySettled
    );
    assert_eq!(
        f.snapshot().await,
        before,
        "current terminal repair preserves the stored result/event"
    );
    f.state
        .start_workflow(
            "main",
            "ExampleWorkflow",
            "other-workflow",
            None,
            "claims",
            None,
        )
        .await
        .unwrap();
    let mut wrong_parent = settlement(f.id, Some(2));
    wrong_parent.workflow_id = "other-workflow";
    assert!(
        f.store.settle_activity(&wrong_parent).await.is_err(),
        "repair must bind the generation to its actual parent"
    );
    assert_eq!(
        f.store.list_events("other-workflow").await.unwrap().len(),
        1
    );
    f.state
        .cancel_workflow("protected-store", Some("stop"))
        .await
        .unwrap();
    let cancelled = f.snapshot().await;
    assert!(
        f.store
            .settle_activity(&settlement(f.id, Some(2)))
            .await
            .is_err()
    );
    assert_eq!(f.snapshot().await, cancelled);
}

async fn cancellation<S: WorkflowStore>(store: S) {
    let f = Fixture::new(store, 3).await;
    f.state
        .cancel_workflow("protected-store", Some("stop"))
        .await
        .unwrap();
    let before = f.snapshot().await;
    for report in [
        ActivityReport::Heartbeat { details: None },
        ActivityReport::Complete { result: None },
        ActivityReport::Fail { error: "retry" },
        ActivityReport::Timeout,
    ] {
        assert!(
            !f.store
                .report_activity(f.id, fence(1, 1), report, f64::MAX)
                .await
                .unwrap()
        );
        assert_eq!(f.snapshot().await, before);
    }
}

#[derive(Clone, Copy)]
enum Contract {
    RawWriters,
    RetryBudget,
    Repair,
    Cancellation,
}
async fn run<S: WorkflowStore>(store: S, contract: Contract) {
    match contract {
        Contract::RawWriters => raw_writers(store).await,
        Contract::RetryBudget => retry_budget(store).await,
        Contract::Repair => repair(store).await,
        Contract::Cancellation => cancellation(store).await,
    }
}
#[rstest]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::pg_raw(Backend::Postgres, Contract::RawWriters)
)]
#[cfg_attr(
    feature = "backend-sqlite",
    case::sqlite_raw(Backend::Sqlite, Contract::RawWriters)
)]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::pg_retry(Backend::Postgres, Contract::RetryBudget)
)]
#[cfg_attr(
    feature = "backend-sqlite",
    case::sqlite_retry(Backend::Sqlite, Contract::RetryBudget)
)]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::pg_repair(Backend::Postgres, Contract::Repair)
)]
#[cfg_attr(
    feature = "backend-sqlite",
    case::sqlite_repair(Backend::Sqlite, Contract::Repair)
)]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::pg_cancel(Backend::Postgres, Contract::Cancellation)
)]
#[cfg_attr(
    feature = "backend-sqlite",
    case::sqlite_cancel(Backend::Sqlite, Contract::Cancellation)
)]
#[tokio::test(flavor = "multi_thread")]
async fn protected_storage_contract(#[case] backend: Backend, #[case] contract: Contract) {
    let harness = backend.setup().await.unwrap();
    match &harness {
        #[cfg(feature = "backend-postgres")]
        Harness::Postgres { store, .. } => run(store.clone(), contract).await,
        #[cfg(feature = "backend-sqlite")]
        Harness::Sqlite { store, .. } => run(store.clone(), contract).await,
    }
}
