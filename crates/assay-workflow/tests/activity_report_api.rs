//! Opt-in HTTP report fencing and strict capability readback.
#![cfg(feature = "backend-sqlite")]

mod common;

use assay_workflow::types::*;
use assay_workflow::{SqliteStore, WorkflowCtx, WorkflowStore};
use common::make_workflow;
use std::sync::Arc;

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

async fn api_server() -> (String, Arc<SqliteStore>, tokio::task::JoinHandle<()>) {
    let store = Arc::new(SqliteStore::new("sqlite::memory:").await.unwrap());
    seed(&*store, 1.0).await;
    let state = Arc::new(WorkflowCtx::start(Arc::clone(&store)));
    let app = assay_workflow::api::router(state, |router| router);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/api/v1/engine/workflow",
        listener.local_addr().unwrap()
    );
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, store, handle)
}

#[tokio::test]
async fn reports_reject_stale_attempt_and_owner_without_side_effects() {
    let (url, store, server) = api_server().await;
    let task = store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    let id = task.id.unwrap();
    let client = reqwest::Client::new();
    let before = serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap();
    for endpoint in ["fail", "complete", "heartbeat"] {
        for (attempt, owner) in [(2, "worker-1"), (1, "other-worker")] {
            let response = client
                .post(format!("{url}/tasks/{id}/{endpoint}"))
                .json(
                    &serde_json::json!({"expected_attempt": attempt, "claimed_by": owner,
                    "error": "retry", "result": {"ok": true}, "details": "alive"}),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                409,
                "{endpoint} must reject stale ownership"
            );
            assert_eq!(
                serde_json::to_value(store.get_activity(id).await.unwrap()).unwrap(),
                before
            );
            assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 0);
        }
    }
    server.abort();
}

#[tokio::test]
async fn fenced_fail_waits_and_stale_reports_cannot_mutate_later_claim() {
    let (url, store, server) = api_server().await;
    let task = store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap();
    let id = task.id.unwrap();
    let client = reqwest::Client::new();
    let body =
        serde_json::json!({"expected_attempt": 1, "claimed_by": "worker-1", "error": "retry"});
    let response = client
        .post(format!("{url}/tasks/{id}/fail"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        store
            .claim_activity(QUEUE, "worker-2")
            .await
            .unwrap()
            .is_none()
    );
    let response = client
        .post(format!("{url}/tasks/{id}/fail"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
    sqlx::query("UPDATE workflow.activities SET scheduled_at = 1 WHERE id = ?")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    let later = store
        .claim_activity(QUEUE, "worker-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(later.attempt, 2);
    let before = serde_json::to_value(&later).unwrap();
    for endpoint in ["fail", "complete", "heartbeat"] {
        let response = client
            .post(format!("{url}/tasks/{id}/{endpoint}"))
            .json(
                &serde_json::json!({"expected_attempt": 1, "claimed_by": "worker-1",
                "error": "late", "result": "late", "details": "late"}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 409);
        assert_eq!(
            serde_json::to_value(store.get_activity(id).await.unwrap().unwrap()).unwrap(),
            before
        );
    }
    assert_eq!(store.get_event_count("wf-fence").await.unwrap(), 0);
    server.abort();
}

#[tokio::test]
async fn health_advertises_explicit_capabilities_and_invalid_fences_reject() {
    let (url, store, server) = api_server().await;
    let client = reqwest::Client::new();
    let response: serde_json::Value = client
        .get(format!("{url}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["capabilities"]["activity_attempt_fencing"], true);
    assert_eq!(response["capabilities"]["activity_due_time_claims"], true);
    let id = store
        .claim_activity(QUEUE, "worker-1")
        .await
        .unwrap()
        .unwrap()
        .id
        .unwrap();
    for body in [
        serde_json::json!({"claimed_by":"worker-1"}),
        serde_json::json!({"expected_attempt":0}),
    ] {
        assert_eq!(
            client
                .post(format!("{url}/tasks/{id}/complete"))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    server.abort();
}
