//! Compile-time compatibility for the legacy public task API, plus wire docs.

#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use std::future::Future;
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use std::sync::Arc;

use assay_workflow::api::openapi::ApiDoc;
use assay_workflow::api::tasks::{CompleteTaskBody, FailTaskBody, HeartbeatTaskBody};
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use assay_workflow::api::tasks::{complete_task, fail_task, heartbeat_task};
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use assay_workflow::api::workflows::AppError;
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use assay_workflow::{WorkflowCtx, WorkflowStore};
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use axum::Json;
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use axum::extract::{Path, State};
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
use axum::http::StatusCode;
use utoipa::OpenApi;

// This generic function is type-checked without constructing a database store.
// Its function-pointer coercions fix all three legacy argument types and outputs.
#[cfg(any(feature = "backend-sqlite", feature = "backend-postgres"))]
fn legacy_handler_signatures<S: WorkflowStore>() {
    type LegacyHandler<S, B, F> = fn(State<Arc<WorkflowCtx<S>>>, Path<i64>, Json<B>) -> F;

    fn accepts_legacy_handler<S, B, F>(handler: LegacyHandler<S, B, F>)
    where
        S: WorkflowStore,
        F: Future<Output = Result<StatusCode, AppError>>,
    {
        std::hint::black_box(handler);
    }

    accepts_legacy_handler::<S, CompleteTaskBody, _>(complete_task::<S>);
    accepts_legacy_handler::<S, FailTaskBody, _>(fail_task::<S>);
    accepts_legacy_handler::<S, HeartbeatTaskBody, _>(heartbeat_task::<S>);
}

#[test]
fn legacy_task_bodies_remain_exhaustively_constructible() {
    #[cfg(feature = "backend-sqlite")]
    legacy_handler_signatures::<assay_workflow::SqliteStore>();
    #[cfg(feature = "backend-postgres")]
    legacy_handler_signatures::<assay_workflow::PostgresStore>();
    let complete = CompleteTaskBody { result: None };
    let fail = FailTaskBody {
        error: "legacy failure".into(),
    };
    let heartbeat = HeartbeatTaskBody {
        details: Some("legacy details".into()),
    };
    assert!(complete.result.is_none());
    assert_eq!(fail.error, "legacy failure");
    assert_eq!(heartbeat.details.as_deref(), Some("legacy details"));
}

#[test]
fn report_wire_schemas_retain_optional_fence_fields() {
    let doc: serde_json::Value =
        serde_json::from_str(&ApiDoc::openapi().to_json().unwrap()).unwrap();
    for (action, schema_name) in [
        ("complete", "CompleteTaskReportBody"),
        ("fail", "FailTaskReportBody"),
        ("heartbeat", "HeartbeatTaskReportBody"),
    ] {
        let path = format!("/api/v1/engine/workflow/tasks/{{id}}/{action}");
        let schema = &doc["components"]["schemas"][schema_name];
        assert_eq!(
            doc["paths"][&path]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{schema_name}")
        );
        for field in ["expected_attempt", "claimed_by"] {
            assert!(schema["properties"].get(field).is_some());
            assert!(
                !schema["required"]
                    .as_array()
                    .is_some_and(|fields| fields.iter().any(|value| value.as_str() == Some(field)))
            );
        }
    }
}
