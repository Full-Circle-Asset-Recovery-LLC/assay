//! HTTP reports must be bound to the current durable claim.
use std::sync::Arc;

use assay_workflow::types::ScheduleActivityOpts;
use assay_workflow::{SqliteStore, WorkflowCtx, WorkflowStore};
use rstest::rstest;
use serde_json::{Value, json};

struct Server {
    base: String,
    state: Arc<WorkflowCtx<SqliteStore>>,
    store: Arc<SqliteStore>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn new(max_attempts: i32) -> (Self, i64) {
        let store = Arc::new(SqliteStore::new("sqlite::memory:").await.unwrap());
        let state = Arc::new(WorkflowCtx::start(store.clone()));
        state
            .start_workflow(
                "main",
                "ExampleWorkflow",
                "claim-contract",
                None,
                "claims",
                None,
            )
            .await
            .unwrap();
        let activity = state
            .schedule_activity(
                "claim-contract",
                1,
                "verify",
                None,
                "claims",
                ScheduleActivityOpts {
                    claim_generation_fencing: Some(true),
                    max_attempts: Some(max_attempts),
                    initial_interval_secs: Some(3600.0),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let id = activity.id.unwrap();
        state
            .claim_activity("claims", "worker-1")
            .await
            .unwrap()
            .unwrap();
        let app = assay_workflow::api::router(state.clone(), |r| r);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            Self {
                base,
                state,
                store,
                task,
            },
            id,
        )
    }

    async fn report(&self, id: i64, action: &str, body: Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!(
                "{}/api/v1/engine/workflow/tasks/{id}/{action}",
                self.base
            ))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn snapshot(&self, id: i64) -> Value {
        json!({
            "activity": self.store.get_activity(id).await.unwrap(),
            "events": self.store.list_events("claim-contract").await.unwrap(),
            "workflow": self.store.get_workflow("claim-contract").await.unwrap(),
        })
    }
}

fn report_body(attempt: i32, owner: &str) -> Value {
    json!({"expected_claim_generation": attempt, "expected_attempt": attempt, "claimed_by": owner, "result": {"verified":true}, "error":"retry", "details":"working"})
}

#[rstest]
#[case("heartbeat", 1, "old-worker", "RUNNING", 3)]
#[case("heartbeat", 2, "worker-1", "RUNNING", 3)]
#[case("complete", 1, "old-worker", "RUNNING", 3)]
#[case("complete", 2, "worker-1", "RUNNING", 3)]
#[case("fail", 1, "old-worker", "RUNNING", 3)]
#[case("fail", 2, "worker-1", "RUNNING", 3)]
#[case("fail", 1, "old-worker", "RUNNING", 1)]
#[case("heartbeat", 1, "worker-1", "PENDING", 3)]
#[case("complete", 1, "worker-1", "PENDING", 3)]
#[case("fail", 1, "worker-1", "PENDING", 3)]
#[case("heartbeat", 1, "worker-1", "COMPLETED", 3)]
#[case("complete", 1, "worker-1", "COMPLETED", 3)]
#[case("fail", 1, "worker-1", "COMPLETED", 3)]
#[tokio::test]
async fn stale_reports_are_conflicts_without_side_effects(
    #[case] action: &str,
    #[case] attempt: i32,
    #[case] owner: &str,
    #[case] status: &str,
    #[case] max_attempts: i32,
) {
    let (server, id) = Server::new(max_attempts).await;
    if status == "PENDING" {
        sqlx::query(
            "UPDATE workflow.activities SET status = 'PENDING', claimed_by = NULL WHERE id = ?",
        )
        .bind(id)
        .execute(server.store.pool())
        .await
        .unwrap();
    } else if status == "COMPLETED" {
        assert_eq!(
            server
                .report(id, "complete", report_body(1, "worker-1"))
                .await
                .status(),
            200
        );
    }
    let before = server.snapshot(id).await;
    let response = server.report(id, action, report_body(attempt, owner)).await;
    assert_eq!(
        response.status(),
        409,
        "{action} must reject the stale claim"
    );
    assert_eq!(
        server.snapshot(id).await,
        before,
        "a rejected report must write nothing"
    );
}

#[rstest]
#[case("heartbeat")]
#[case("complete")]
#[case("fail")]
#[tokio::test]
async fn malformed_fences_never_fall_back_to_unfenced_reports(#[case] action: &str) {
    let (server, id) = Server::new(3).await;
    for fence in [
        json!({"expected_attempt":1}),
        json!({"claimed_by":"worker-1"}),
        json!({"expected_attempt":0,"claimed_by":"worker-1"}),
        json!({"expected_attempt":1,"claimed_by":" "}),
        json!({"expected_attempt":null,"claimed_by":null}),
    ] {
        let mut body =
            json!({"expected_claim_generation":1,"result":null,"error":"retry","details":null});
        body.as_object_mut()
            .unwrap()
            .extend(fence.as_object().unwrap().clone());
        let before = server.snapshot(id).await;
        let response = server.report(id, action, body).await;
        assert_eq!(response.status(), 400, "malformed fence must be rejected");
        assert_eq!(server.snapshot(id).await, before);
    }
}

#[tokio::test]
async fn retry_waits_until_due_and_old_attempt_cannot_report_after_reclaim() {
    let (server, id) = Server::new(3).await;
    assert_eq!(
        server
            .report(id, "heartbeat", report_body(1, "worker-1"))
            .await
            .status(),
        200
    );
    assert!(
        server
            .store
            .get_activity(id)
            .await
            .unwrap()
            .unwrap()
            .last_heartbeat
            .is_some()
    );
    assert_eq!(
        server
            .report(id, "fail", report_body(1, "worker-1"))
            .await
            .status(),
        200
    );
    let retry = server.store.get_activity(id).await.unwrap().unwrap();
    assert_eq!(
        (retry.status.as_str(), retry.attempt, retry.claimed_by),
        ("PENDING", 2, None)
    );
    assert!(
        server
            .state
            .claim_activity("claims", "worker-2")
            .await
            .unwrap()
            .is_none(),
        "future retries must not be claimable"
    );
    sqlx::query("UPDATE workflow.activities SET scheduled_at = 0 WHERE id = ?")
        .bind(id)
        .execute(server.store.pool())
        .await
        .unwrap();
    let claim = server
        .state
        .claim_activity("claims", "worker-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.attempt, 2);
    for action in ["heartbeat", "complete", "fail"] {
        let before = server.snapshot(id).await;
        assert_eq!(
            server
                .report(id, action, report_body(1, "worker-1"))
                .await
                .status(),
            409
        );
        assert_eq!(server.snapshot(id).await, before);
    }
    assert_eq!(
        server
            .report(id, "complete", report_body(2, "worker-2"))
            .await
            .status(),
        200
    );
    assert_eq!(
        server
            .report(id, "complete", report_body(2, "worker-2"))
            .await
            .status(),
        409
    );
    let events = server.store.list_events("claim-contract").await.unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.event_type == "ActivityCompleted")
            .count(),
        1
    );
}

#[tokio::test]
async fn concurrent_completion_accepts_one_exact_claim() {
    let (server, id) = Server::new(3).await;
    let reports = (0..8).map(|_| server.report(id, "complete", report_body(1, "worker-1")));
    let responses = futures_util::future::join_all(reports).await;
    assert_eq!(responses.iter().filter(|r| r.status() == 200).count(), 1);
    assert_eq!(responses.iter().filter(|r| r.status() == 409).count(), 7);
    assert_eq!(
        server
            .store
            .list_events("claim-contract")
            .await
            .unwrap()
            .iter()
            .filter(|e| e.event_type == "ActivityCompleted")
            .count(),
        1
    );
}

#[tokio::test]
async fn health_advertises_implemented_claim_capabilities() {
    let (server, _) = Server::new(3).await;
    let response = reqwest::get(format!("{}/api/v1/engine/workflow/health", server.base))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["capabilities"]["activity_attempt_fencing"], true);
    assert_eq!(body["capabilities"]["activity_due_time_claims"], true);
}

#[rstest]
#[case("heartbeat")]
#[case("complete")]
#[case("fail")]
#[tokio::test]
async fn claimed_activities_require_a_fence(#[case] action: &str) {
    let (server, id) = Server::new(3).await;
    let before = server.snapshot(id).await;
    let response = server
        .report(
            id,
            action,
            json!({"result":null,"error":"retry","details":null}),
        )
        .await;
    assert_eq!(
        response.status(),
        409,
        "unfenced report must not bypass the claim"
    );
    assert_eq!(server.snapshot(id).await, before);
}

#[tokio::test]
async fn manual_retry_never_reuses_a_previous_owner_attempt_pair() {
    let (server, id) = Server::new(1).await;
    assert_eq!(
        server
            .report(id, "fail", report_body(1, "worker-1"))
            .await
            .status(),
        200
    );
    server
        .state
        .fail_workflow("claim-contract", "activity failed")
        .await
        .unwrap();
    server
        .state
        .retry_failed_activity("claim-contract", "operator", "dependency repaired")
        .await
        .unwrap();
    let claim = server
        .state
        .claim_activity("claims", "worker-1")
        .await
        .unwrap()
        .unwrap();
    assert!(
        claim
            .claim_generation
            .is_some_and(|generation| generation > 1),
        "manual retry must not reuse a previous claim generation"
    );
    for action in ["heartbeat", "complete", "fail"] {
        let before = server.snapshot(id).await;
        assert_eq!(
            server
                .report(id, action, report_body(1, "worker-1"))
                .await
                .status(),
            409
        );
        assert_eq!(server.snapshot(id).await, before);
    }
}

#[tokio::test]
async fn delayed_unfenced_completion_cannot_settle_a_reclaimed_attempt() {
    let (server, id) = Server::new(3).await;
    assert_eq!(
        server
            .report(id, "fail", report_body(1, "worker-1"))
            .await
            .status(),
        200
    );
    // Inject a due timestamp without using the legacy retry transition.
    sqlx::query("UPDATE workflow.activities SET scheduled_at = 0 WHERE id = ?")
        .bind(id)
        .execute(server.store.pool())
        .await
        .unwrap();
    let reclaimed = server
        .state
        .claim_activity("claims", "worker-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (reclaimed.attempt, reclaimed.claimed_by.as_deref()),
        (2, Some("worker-2"))
    );
    let before = server.snapshot(id).await;
    let response = server
        .report(id, "complete", json!({"result":{"from":"old-worker"}}))
        .await;
    let after = server.snapshot(id).await;
    assert_eq!(
        response.status(),
        409,
        "delayed unfenced completion must not alter the current claim; before={before}; after={after}"
    );
    assert_eq!(after, before);
}

#[tokio::test]
async fn pre_reopen_exact_fence_cannot_complete_a_new_same_worker_claim() {
    let (server, id) = Server::new(1).await;
    assert_eq!(
        server
            .report(id, "fail", report_body(1, "worker-1"))
            .await
            .status(),
        200
    );
    server
        .state
        .fail_workflow("claim-contract", "activity failed")
        .await
        .unwrap();
    server
        .state
        .retry_failed_activity("claim-contract", "operator", "dependency repaired")
        .await
        .unwrap();
    let reclaimed = server
        .state
        .claim_activity("claims", "worker-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.claimed_by.as_deref(), Some("worker-1"));
    let before = server.snapshot(id).await;
    let response = server
        .report(id, "complete", report_body(1, "worker-1"))
        .await;
    let after = server.snapshot(id).await;
    assert_eq!(
        response.status(),
        409,
        "pre-reopen fence must reject the new claim; before={before}; after={after}"
    );
    assert_eq!(after, before);
}
