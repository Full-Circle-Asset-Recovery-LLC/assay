//! Protected claims use durable generations independently of retry counters.
mod common;

use assay_workflow::{WorkflowCtx, WorkflowStore};
use common::{Backend, Harness};
use rstest::rstest;
use serde_json::{Value, json};
use std::sync::Arc;

struct Server<S: WorkflowStore> {
    base: String,
    state: Arc<WorkflowCtx<S>>,
    task: tokio::task::JoinHandle<()>,
}
impl<S: WorkflowStore> Drop for Server<S> {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl<S: WorkflowStore> Server<S> {
    async fn new(store: S) -> Self {
        let state = Arc::new(WorkflowCtx::start(Arc::new(store)));
        state
            .start_workflow(
                "main",
                "ExampleWorkflow",
                "protected-contract",
                None,
                "claims",
                None,
            )
            .await
            .unwrap();
        let app = assay_workflow::api::router(state.clone(), |r| r);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, state, task }
    }
    async fn post(&self, path: &str, body: Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/api/v1/engine/workflow/{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn schedule(&self, max_attempts: i32) -> Value {
        let response = self
            .post(
                "workflows/protected-contract/activities",
                json!({
                    "name":"verify","seq":1,"task_queue":"claims","max_attempts":max_attempts,
                    "initial_interval_secs":0.0,"claim_generation_fencing":true
                }),
            )
            .await;
        assert_eq!(response.status(), 201);
        let row: Value = response.json().await.unwrap();
        assert_eq!(
            row["claim_generation"], 0,
            "protected scheduling must persist its opt-in"
        );
        row
    }
    async fn claim(&self, owner: &str) -> Value {
        let response = self
            .post("tasks/poll", json!({"queue":"claims","worker_id":owner}))
            .await;
        assert_eq!(response.status(), 200);
        response.json().await.unwrap()
    }
    async fn snapshot(&self, id: i64) -> Value {
        json!({"activity":self.state.get_activity(id).await.unwrap(),"events":self.state.get_events("protected-contract").await.unwrap()})
    }
    async fn report(&self, id: i64, action: &str, body: Value) -> reqwest::Response {
        self.post(&format!("tasks/{id}/{action}"), body).await
    }
}
fn fence(row: &Value) -> Value {
    json!({"expected_attempt":row["attempt"],"claimed_by":row["claimed_by"],
        "expected_claim_generation":row["claim_generation"],"result":{"verified":true},"error":"retry","details":"working"})
}

async fn contract<S: WorkflowStore>(store: S) {
    let server = Server::new(store).await;
    let row = server.schedule(1).await;
    let id = row["id"].as_i64().unwrap();
    let health: Value = reqwest::get(format!("{}/api/v1/engine/workflow/health", server.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        health["capabilities"]["activity_claim_generation_fencing"],
        true
    );
    let before = server.snapshot(id).await;
    let mismatch = server
        .post(
            "workflows/protected-contract/activities",
            json!({"name":"verify","seq":1,"task_queue":"claims"}),
        )
        .await;
    assert_eq!(
        mismatch.status(),
        409,
        "idempotent scheduling must not downgrade protected mode"
    );
    assert_eq!(server.snapshot(id).await, before);
    let first = server.claim("worker-1").await;
    assert_eq!(first["claim_generation"], 1);
    let old = fence(&first);
    for action in ["heartbeat", "complete", "fail"] {
        for body in [
            json!({"result":null,"error":"retry","details":null}),
            json!({"expected_attempt":1,"claimed_by":"worker-1","result":null,"error":"retry"}),
        ] {
            let before = server.snapshot(id).await;
            assert_eq!(server.report(id, action, body).await.status(), 409);
            assert_eq!(server.snapshot(id).await, before);
        }
    }
    assert_eq!(
        server.report(id, "heartbeat", old.clone()).await.status(),
        200
    );
    assert_eq!(server.report(id, "fail", old.clone()).await.status(), 200);
    server
        .state
        .fail_workflow("protected-contract", "activity failed")
        .await
        .unwrap();
    server
        .state
        .retry_failed_activity("protected-contract", "operator", "dependency repaired")
        .await
        .unwrap();
    let second = server.claim("worker-1").await;
    assert_eq!(
        second["attempt"], 1,
        "manual retry counter semantics stay unchanged"
    );
    assert_eq!(second["max_attempts"], 1);
    assert_eq!(
        second["claim_generation"], 2,
        "manual retry must not reuse a claim generation"
    );
    for action in ["heartbeat", "complete", "fail"] {
        let before = server.snapshot(id).await;
        let response = server.report(id, action, old.clone()).await;
        let after = server.snapshot(id).await;
        assert_eq!(
            response.status(),
            409,
            "old exact fence must not change the new same-worker claim; before={before}; after={after}"
        );
        assert_eq!(after, before);
    }
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
    let current = fence(&second);
    assert_eq!(
        server
            .report(id, "complete", current.clone())
            .await
            .status(),
        200
    );
    assert_eq!(server.report(id, "complete", current).await.status(), 409);
    server
        .state
        .claim_workflow_task("claims", "workflow-worker")
        .await
        .unwrap()
        .unwrap();
    let commands = server
        .post(
            "workflow-tasks/protected-contract/commands",
            json!({
                "worker_id": "workflow-worker",
                "commands": [{"type":"ScheduleActivity", "seq":2, "name":"verify",
                    "task_queue":"claims", "claim_generation_fencing":true}]
            }),
        )
        .await;
    assert_eq!(commands.status(), 200);
    let command_activity = server.claim("worker-2").await;
    assert_eq!(command_activity["seq"], 2);
    assert_eq!(
        command_activity["claim_generation"], 1,
        "workflow command must retain protected scheduling"
    );
}

#[rstest]
#[cfg_attr(
    all(feature = "backend-postgres", target_os = "linux"),
    case::postgres(Backend::Postgres)
)]
#[cfg_attr(feature = "backend-sqlite", case::sqlite(Backend::Sqlite))]
#[tokio::test(flavor = "multi_thread")]
async fn protected_generation_blocks_delayed_and_reopened_claim_writers(#[case] backend: Backend) {
    let harness = backend.setup().await.unwrap();
    match &harness {
        #[cfg(feature = "backend-postgres")]
        Harness::Postgres { store, .. } => contract(store.clone()).await,
        #[cfg(feature = "backend-sqlite")]
        Harness::Sqlite { store, .. } => contract(store.clone()).await,
    }
}
