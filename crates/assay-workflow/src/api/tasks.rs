use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::workflows::AppError;
use crate::ctx::WorkflowCtx;
use crate::store::WorkflowStore;
use crate::types::{ActivityFence, WorkflowWorker};

pub fn router<S: WorkflowStore + 'static>() -> Router<Arc<WorkflowCtx<S>>> {
    Router::new()
        .route("/workers/register", post(register_worker))
        .route("/workers/heartbeat", post(worker_heartbeat))
        .route("/tasks/poll", post(poll_task))
        .route("/tasks/{id}/complete", post(complete_task))
        .route("/tasks/{id}/fail", post(fail_task))
        .route("/tasks/{id}/heartbeat", post(heartbeat_task))
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterWorkerRequest {
    /// Namespace (default: "main")
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Human-readable worker identity (e.g. "pipeline-pod-1")
    pub identity: String,
    /// Task queue this worker listens on
    pub queue: String,
    /// Workflow types this worker can execute
    pub workflows: Option<Vec<String>>,
    /// Activity types this worker can execute
    pub activities: Option<Vec<String>>,
    #[serde(default = "default_concurrent")]
    pub max_concurrent_workflows: i32,
    #[serde(default = "default_concurrent")]
    pub max_concurrent_activities: i32,
}

fn default_namespace() -> String {
    "main".to_string()
}

fn default_concurrent() -> i32 {
    10
}

#[derive(Serialize, ToSchema)]
pub struct RegisterWorkerResponse {
    /// Server-assigned worker ID
    pub worker_id: String,
}

#[utoipa::path(
    post, path = "/api/v1/engine/workflow/workers/register",
    tag = "tasks",
    request_body = RegisterWorkerRequest,
    responses(
        (status = 200, description = "Worker registered", body = RegisterWorkerResponse),
    ),
)]
pub async fn register_worker<S: WorkflowStore>(
    State(state): State<Arc<WorkflowCtx<S>>>,
    Json(req): Json<RegisterWorkerRequest>,
) -> Result<Json<RegisterWorkerResponse>, AppError> {
    let now = timestamp_now();
    let worker_id = format!("w-{}", uuid_short());

    let worker = WorkflowWorker {
        id: worker_id.clone(),
        namespace: req.namespace,
        identity: req.identity,
        task_queue: req.queue,
        workflows: req.workflows.map(|v| serde_json::to_string(&v).unwrap()),
        activities: req.activities.map(|v| serde_json::to_string(&v).unwrap()),
        max_concurrent_workflows: req.max_concurrent_workflows,
        max_concurrent_activities: req.max_concurrent_activities,
        active_tasks: 0,
        last_heartbeat: now,
        registered_at: now,
    };

    state.register_worker(&worker).await?;
    Ok(Json(RegisterWorkerResponse { worker_id }))
}

#[derive(Deserialize, ToSchema)]
pub struct HeartbeatRequest {
    pub worker_id: String,
}

#[utoipa::path(
    post, path = "/api/v1/engine/workflow/workers/heartbeat",
    tag = "tasks",
    responses(
        (status = 200, description = "Heartbeat recorded"),
        (status = 404, description = "Registration is gone — register again"),
    ),
)]
pub async fn worker_heartbeat<S: WorkflowStore>(
    State(state): State<Arc<WorkflowCtx<S>>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    // A silent worker's registration is reaped after WORKER_TIMEOUT_SECS.
    // Answering 200 to a heartbeat for a row that no longer exists leaves
    // the worker heartbeating into the void until someone restarts it; 404
    // tells it to register again.
    if state.heartbeat_worker(&req.worker_id).await? {
        Ok(axum::http::StatusCode::OK)
    } else {
        Ok(axum::http::StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize, ToSchema)]
pub struct PollRequest {
    /// Task queue to poll from
    pub queue: String,
    /// Worker ID (from register response)
    pub worker_id: String,
}

#[utoipa::path(
    post, path = "/api/v1/engine/workflow/tasks/poll",
    tag = "tasks",
    request_body = PollRequest,
    responses(
        (status = 200, description = "Activity task (or null if none available)", body = WorkflowActivity),
    ),
)]
pub async fn poll_task<S: WorkflowStore>(
    State(state): State<Arc<WorkflowCtx<S>>>,
    Json(req): Json<PollRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let activity = state.claim_activity(&req.queue, &req.worker_id).await?;

    match activity {
        Some(act) => Ok(Json(serde_json::to_value(act)?)),
        None => Ok(Json(serde_json::json!({ "task": null }))),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CompleteTaskBody {
    /// Optional positive claim attempt. Opts into transactional ownership fencing.
    pub expected_attempt: Option<i32>,
    /// Optional claim owner; requires expected_attempt when supplied.
    pub claimed_by: Option<String>,
    /// JSON result from the completed activity
    pub result: Option<serde_json::Value>,
}

#[utoipa::path(
    post, path = "/api/v1/engine/workflow/tasks/{id}/complete",
    tag = "tasks",
    params(("id" = i64, Path, description = "Activity task ID")),
    request_body = CompleteTaskBody,
    responses((status = 200, description = "Task completed"), (status = 409, description = "Stale or cancelled claim"), (status = 400, description = "Invalid fence")),
)]
pub async fn complete_task<S: WorkflowStore>(
    State(state): State<Arc<WorkflowCtx<S>>>,
    Path(id): Path<i64>,
    Json(body): Json<CompleteTaskBody>,
) -> Result<axum::http::StatusCode, AppError> {
    let result = body.result.map(|v| v.to_string());
    if let Some(fence) = report_fence(body.expected_attempt, body.claimed_by.as_deref())? {
        return Ok(report_status(
            state
                .complete_activity_fenced(id, result.as_deref(), fence)
                .await?,
        ));
    }
    state
        .complete_activity(id, result.as_deref(), None, false)
        .await?;
    Ok(axum::http::StatusCode::OK)
}

#[derive(Deserialize, ToSchema)]
pub struct FailTaskBody {
    /// Optional positive claim attempt. Opts into transactional ownership fencing.
    pub expected_attempt: Option<i32>,
    /// Optional claim owner; requires expected_attempt when supplied.
    pub claimed_by: Option<String>,
    /// Error message describing why the task failed
    pub error: String,
}

#[utoipa::path(
    post, path = "/api/v1/engine/workflow/tasks/{id}/fail",
    tag = "tasks",
    params(("id" = i64, Path, description = "Activity task ID")),
    request_body = FailTaskBody,
    responses((status = 200, description = "Task marked as failed"), (status = 409, description = "Stale or cancelled claim"), (status = 400, description = "Invalid fence")),
)]
pub async fn fail_task<S: WorkflowStore>(
    State(state): State<Arc<WorkflowCtx<S>>>,
    Path(id): Path<i64>,
    Json(body): Json<FailTaskBody>,
) -> Result<axum::http::StatusCode, AppError> {
    // fail_activity honors the activity's retry policy: re-queues with
    // backoff while attempts remain, otherwise marks FAILED + appends
    // ActivityFailed event.
    if let Some(fence) = report_fence(body.expected_attempt, body.claimed_by.as_deref())? {
        return Ok(report_status(
            state.fail_activity_fenced(id, &body.error, fence).await?,
        ));
    }
    state.fail_activity(id, &body.error).await?;
    Ok(axum::http::StatusCode::OK)
}

#[derive(Deserialize, ToSchema)]
pub struct HeartbeatTaskBody {
    /// Optional positive claim attempt. Opts into transactional ownership fencing.
    pub expected_attempt: Option<i32>,
    /// Optional claim owner; requires expected_attempt when supplied.
    pub claimed_by: Option<String>,
    pub details: Option<String>,
}

#[utoipa::path(
    post, path = "/api/v1/engine/workflow/tasks/{id}/heartbeat",
    tag = "tasks",
    params(("id" = i64, Path, description = "Activity task ID")),
    request_body = HeartbeatTaskBody,
    responses((status = 200, description = "Heartbeat recorded"), (status = 409, description = "Stale or cancelled claim"), (status = 400, description = "Invalid fence")),
)]
pub async fn heartbeat_task<S: WorkflowStore>(
    State(state): State<Arc<WorkflowCtx<S>>>,
    Path(id): Path<i64>,
    Json(body): Json<HeartbeatTaskBody>,
) -> Result<axum::http::StatusCode, AppError> {
    if let Some(fence) = report_fence(body.expected_attempt, body.claimed_by.as_deref())? {
        return Ok(report_status(
            state
                .heartbeat_activity_fenced(id, body.details.as_deref(), fence)
                .await?,
        ));
    }
    state
        .heartbeat_activity(id, body.details.as_deref())
        .await?;
    Ok(axum::http::StatusCode::OK)
}

fn report_fence(
    expected_attempt: Option<i32>,
    claimed_by: Option<&str>,
) -> Result<Option<ActivityFence<'_>>, AppError> {
    match expected_attempt {
        Some(attempt) if attempt > 0 => Ok(Some(ActivityFence {
            expected_attempt: attempt,
            claimed_by,
        })),
        None if claimed_by.is_none() => Ok(None),
        _ => Err(AppError::bad_request(
            "expected_attempt must be positive and is required with claimed_by".into(),
        )),
    }
}

fn report_status(applied: bool) -> axum::http::StatusCode {
    if applied {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::CONFLICT
    }
}

fn timestamp_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn uuid_short() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    format!("{:016x}", h.finish())
}

use crate::types::WorkflowActivity;
