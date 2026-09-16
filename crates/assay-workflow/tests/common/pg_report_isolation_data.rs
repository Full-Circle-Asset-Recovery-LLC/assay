//! Raw snapshots include all persisted columns, not just public DTO fields.
#![cfg(all(feature = "backend-postgres", target_os = "linux"))]
use crate::common::{make_event, make_workflow};
use anyhow::{Result, ensure};
use assay_workflow::{PostgresStore, WorkflowStore, types::*};
use serde_json::Value;
use sqlx::PgPool;

pub const WORKFLOW: &str = "isolation-current";
pub const HISTORY: &str = "isolation-history";
pub const QUEUE: &str = "isolation-queue";
pub const OWNER: &str = "isolation-worker";
pub const HEARTBEAT: f64 = 9876543210.0;

#[derive(Debug, PartialEq)]
pub struct Snapshot {
    pub workflows: Value,
    pub activities: Value,
    pub events: Value,
    pub engine_history: Value,
    pub parent_tuple: Value,
}

pub async fn snapshot(pool: &PgPool) -> Result<Snapshot> {
    // One statement gives every relation the same READ COMMITTED snapshot.
    let raw: String = sqlx::query_scalar(
        "SELECT jsonb_build_object(
            'workflows', (SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY id), '[]'::jsonb)
                FROM workflow.workflows w),
            'activities', (SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY id), '[]'::jsonb)
                FROM workflow.activities a),
            'events', (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id), '[]'::jsonb)
                FROM workflow.events e),
            'engine_history', (SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY id), '[]'::jsonb)
                FROM engine.events h),
            'parent_tuple', (SELECT jsonb_build_object('xmin', xmin::text, 'ctid', ctid::text)
                FROM workflow.workflows WHERE id = $1)
        )::text",
    )
    .bind(WORKFLOW)
    .fetch_one(pool)
    .await?;
    let value: Value = serde_json::from_str(&raw)?;
    Ok(Snapshot {
        workflows: value["workflows"].clone(),
        activities: value["activities"].clone(),
        events: value["events"].clone(),
        engine_history: value["engine_history"].clone(),
        parent_tuple: value["parent_tuple"].clone(),
    })
}

pub async fn seed(store: &PostgresStore) -> Result<i64> {
    for id in [WORKFLOW, HISTORY] {
        let mut workflow = make_workflow(id, "main", QUEUE);
        workflow.status = if id == WORKFLOW {
            "RUNNING"
        } else {
            "COMPLETED"
        }
        .into();
        workflow.claimed_by = Some(OWNER.into());
        if id == HISTORY {
            workflow.result = Some("historical-result".into());
            workflow.completed_at = Some(120.0);
        }
        store.create_workflow(&workflow).await?;
        let mut event = make_event(id, 1);
        event.timestamp = 110.0;
        store.append_event(&event).await?;
    }
    let id = store
        .create_activity(&activity(WORKFLOW, "PENDING"))
        .await?;
    let historical_id = store
        .create_activity(&activity(HISTORY, "COMPLETED"))
        .await?;
    // create_activity deliberately omits owner/start/result fields. Use the
    // native claim path for the running attempt, not an unpersisted DTO owner.
    let claimed = store
        .claim_activity(QUEUE, OWNER)
        .await?
        .ok_or_else(|| anyhow::anyhow!("seed claim missing"))?;
    ensure!(claimed.id == Some(id), "wrong seed activity claimed");
    seed_history_activity(store.pool(), historical_id).await?;
    let mut historical_event = make_event(HISTORY, 2);
    historical_event.event_type = "WorkflowCompleted".into();
    historical_event.payload = Some(r#"{"result":"historical-result"}"#.into());
    historical_event.timestamp = 120.0;
    store.append_event(&historical_event).await?;
    sqlx::query(
        "UPDATE workflow.workflows SET needs_dispatch = TRUE,
        dispatch_claimed_by = $1, dispatch_last_heartbeat = 115.0 WHERE id = $2",
    )
    .bind(OWNER)
    .bind(WORKFLOW)
    .execute(store.pool())
    .await?;
    sqlx::query(
        "INSERT INTO engine.events (ts, namespace, subsystem, kind, payload)
        VALUES (120.0, 'main', 'workflow', 'WorkflowCompleted',
            '{\"workflow_id\":\"isolation-history\",\"result\":\"historical-result\"}'::jsonb)",
    )
    .execute(store.pool())
    .await?;
    let stored = store
        .get_activity(id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("seed missing"))?;
    ensure!(
        stored.status == "RUNNING"
            && stored.attempt == 2
            && stored.claimed_by.as_deref() == Some(OWNER),
        "invalid matching attempt seed"
    );
    Ok(id)
}

async fn seed_history_activity(pool: &PgPool, id: i64) -> Result<()> {
    let changed = sqlx::query(
        "UPDATE workflow.activities SET result = 'historical-result',
        claimed_by = $1, started_at = 110.0, completed_at = 120.0, last_heartbeat = 115.0
        WHERE id = $2 AND status = 'COMPLETED'",
    )
    .bind(OWNER)
    .bind(id)
    .execute(pool)
    .await?;
    ensure!(
        changed.rows_affected() == 1,
        "historical activity seed missing"
    );
    Ok(())
}

fn activity(workflow: &str, status: &str) -> WorkflowActivity {
    WorkflowActivity {
        id: None,
        workflow_id: workflow.into(),
        seq: 1,
        name: "isolation-heartbeat".into(),
        task_queue: QUEUE.into(),
        input: Some(r#"{"seed":true}"#.into()),
        status: status.into(),
        result: (status == "COMPLETED").then(|| "historical-result".into()),
        error: None,
        attempt: 2,
        max_attempts: 4,
        initial_interval_secs: 20.0,
        backoff_coefficient: 2.0,
        start_to_close_secs: 300.0,
        heartbeat_timeout_secs: Some(60.0),
        claimed_by: Some(OWNER.into()),
        scheduled_at: 100.0,
        started_at: Some(110.0),
        completed_at: (status == "COMPLETED").then_some(120.0),
        last_heartbeat: Some(115.0),
    }
}

pub fn cancellation() -> WorkflowEvent {
    let mut event = make_event(WORKFLOW, 2);
    event.event_type = "WorkflowCancelRequested".into();
    event.payload = Some(r#"{"reason":"isolation-cancel","requested_by":"test"}"#.into());
    event.timestamp = 125.5;
    event
}

pub fn assert_cancel_only(
    before: &Snapshot,
    committed: &Snapshot,
    id: i64,
    marker: &WorkflowEvent,
) {
    assert_eq!(
        before.workflows, committed.workflows,
        "cancel changed parent/dispatch/history"
    );
    assert_eq!(
        before.parent_tuple, committed.parent_tuple,
        "cancel rewrote parent tuple"
    );
    assert_eq!(
        before.activities, committed.activities,
        "cancel changed activities"
    );
    assert_eq!(
        before.engine_history, committed.engine_history,
        "cancel changed engine history"
    );
    let mut expected = before.events.as_array().expect("events array").clone();
    expected.push(serde_json::json!({
        "id": id, "workflow_id": marker.workflow_id, "seq": marker.seq,
        "event_type": marker.event_type, "payload": marker.payload,
        "timestamp": marker.timestamp, "activity_id": null,
    }));
    assert_eq!(
        Value::Array(expected),
        committed.events,
        "committed marker must match append_event id/payload/seq/timestamp exactly"
    );
}
