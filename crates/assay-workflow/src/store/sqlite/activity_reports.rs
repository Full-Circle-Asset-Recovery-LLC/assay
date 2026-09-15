//! Atomic attempt reports. Parent lock always precedes the activity lock.
use super::*;
use crate::store::activity_reports::{ReportWrite, plan_report};

impl SqliteStore {
    pub(super) async fn apply_activity_report(
        &self,
        id: i64,
        fence: ActivityFence<'_>,
        report: ActivityReport<'_>,
        now: f64,
    ) -> Result<bool> {
        if fence.expected_attempt <= 0 {
            return Ok(false);
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Lock even a cancelling parent first. The following statement gets
        // a fresh PostgreSQL snapshot after any cancellation writer commits.
        let parent: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM workflow.workflows WHERE id =
             (SELECT workflow_id FROM workflow.activities WHERE id = ?) ",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((workflow_id,)) = parent else {
            return Ok(false);
        };
        let live: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM workflow.workflows w WHERE id = ?
             AND status IN ('PENDING', 'RUNNING', 'WAITING') AND archived_at IS NULL
             AND NOT EXISTS (SELECT 1 FROM workflow.events e WHERE e.workflow_id = w.id
                 AND e.event_type = 'WorkflowCancelRequested')",
        )
        .bind(&workflow_id)
        .fetch_optional(&mut *tx)
        .await?;
        if live.is_none() {
            return Ok(false);
        }
        let current = sqlx::query_as::<_, SqliteActivityRow>(
            "SELECT id, workflow_id, seq, name, task_queue, input, status, result, error, attempt, max_attempts, initial_interval_secs, backoff_coefficient, start_to_close_secs, heartbeat_timeout_secs, claimed_by, scheduled_at, started_at, completed_at, last_heartbeat FROM workflow.activities WHERE id = ? "
        ).bind(id).fetch_optional(&mut *tx).await?;
        let Some(current) = current else {
            return Ok(false);
        };
        let act: WorkflowActivity = current.into();
        if act.status != "RUNNING"
            || act.attempt != fence.expected_attempt
            || fence
                .claimed_by
                .is_some_and(|owner| act.claimed_by.as_deref() != Some(owner))
        {
            return Ok(false);
        }
        let Some(write) = plan_report(&act, report, now) else {
            return Ok(false);
        };
        Self::write_activity_report(&mut tx, &act, write, now).await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn write_activity_report(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        act: &WorkflowActivity,
        write: ReportWrite<'_>,
        now: f64,
    ) -> Result<()> {
        match write {
            ReportWrite::Heartbeat => {
                sqlx::query("UPDATE workflow.activities SET last_heartbeat = CASE WHEN last_heartbeat IS NULL OR last_heartbeat < ? THEN ? ELSE last_heartbeat END WHERE id = ?")
                    .bind(now)
                    .bind(now)
                    .bind(act.id)
                    .execute(&mut **tx)
                    .await?;
            }
            ReportWrite::Retry {
                attempt,
                scheduled_at,
            } => {
                sqlx::query(
                    "UPDATE workflow.activities SET status = 'PENDING', attempt = ?,
                    scheduled_at = ?, claimed_by = NULL, started_at = NULL,
                    last_heartbeat = NULL, completed_at = NULL, error = NULL WHERE id = ?",
                )
                .bind(attempt)
                .bind(scheduled_at)
                .bind(act.id)
                .execute(&mut **tx)
                .await?;
            }
            ReportWrite::Settle {
                result,
                error,
                payload,
                failed,
                timeout,
            } => {
                sqlx::query(
                    "UPDATE workflow.activities SET status = ?, result = ?, error = ?,
                    completed_at = ? WHERE id = ?",
                )
                .bind(if failed { "FAILED" } else { "COMPLETED" })
                .bind(result)
                .bind(error)
                .bind(now)
                .bind(act.id)
                .execute(&mut **tx)
                .await?;
                Self::append_report_event(tx, act, &payload, failed, now).await?;
                if timeout {
                    sqlx::query(
                        "UPDATE workflow.workflows SET status = 'FAILED', error = ?,
                        updated_at = ?, completed_at = ?, needs_dispatch = 1 WHERE id = ?",
                    )
                    .bind(format!(
                        "Activity '{}' timed out after {} attempts",
                        act.name, act.max_attempts
                    ))
                    .bind(now)
                    .bind(now)
                    .bind(&act.workflow_id)
                    .execute(&mut **tx)
                    .await?;
                } else {
                    sqlx::query("UPDATE workflow.workflows SET needs_dispatch = 1 WHERE id = ?")
                        .bind(&act.workflow_id)
                        .execute(&mut **tx)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn append_report_event(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        act: &WorkflowActivity,
        payload: &str,
        failed: bool,
        now: f64,
    ) -> Result<()> {
        let seq: (i32,) = sqlx::query_as(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM workflow.events WHERE workflow_id = ?",
        )
        .bind(&act.workflow_id)
        .fetch_one(&mut **tx)
        .await?;
        sqlx::query(
            "INSERT INTO workflow.events
            (workflow_id, seq, event_type, payload, activity_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&act.workflow_id)
        .bind(seq.0)
        .bind(if failed {
            "ActivityFailed"
        } else {
            "ActivityCompleted"
        })
        .bind(payload)
        .bind(act.id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

impl SqliteStore {
    pub(super) async fn claim_due_activity(
        &self,
        task_queue: &str,
        worker_id: &str,
    ) -> Result<Option<WorkflowActivity>> {
        let now = timestamp_now();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let candidate: Option<(i64,)> = sqlx::query_as(
            "SELECT a.id FROM workflow.activities a JOIN workflow.workflows w ON w.id = a.workflow_id
             WHERE a.task_queue = ? AND a.status = 'PENDING' AND a.scheduled_at <= ?
               AND w.status IN ('PENDING', 'RUNNING', 'WAITING') AND w.archived_at IS NULL
               AND NOT EXISTS (SELECT 1 FROM workflow.events e WHERE e.workflow_id = w.id
                   AND e.event_type = 'WorkflowCancelRequested')
             ORDER BY a.scheduled_at ASC  LIMIT 1"
        ).bind(task_queue).bind(now).fetch_optional(&mut *tx).await?;
        let Some((id,)) = candidate else {
            return Ok(None);
        };
        // A fresh statement observes cancellation committed while acquiring locks.
        let row = sqlx::query_as::<_, SqliteActivityRow>(
            "UPDATE workflow.activities SET status = 'RUNNING', claimed_by = ?, started_at = ?
             WHERE id = ? AND status = 'PENDING' AND scheduled_at <= ?
               AND EXISTS (SELECT 1 FROM workflow.workflows w WHERE w.id = workflow.activities.workflow_id
                   AND w.status IN ('PENDING', 'RUNNING', 'WAITING') AND w.archived_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM workflow.events e WHERE e.workflow_id = w.id
                       AND e.event_type = 'WorkflowCancelRequested'))
             RETURNING id, workflow_id, seq, name, task_queue, input, status, result, error, attempt, max_attempts, initial_interval_secs, backoff_coefficient, start_to_close_secs, heartbeat_timeout_secs, claimed_by, scheduled_at, started_at, completed_at, last_heartbeat"
        ).bind(worker_id).bind(now).bind(id).bind(now).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(row.map(Into::into))
    }

    pub(super) async fn retry_activity_cas(
        &self,
        id: i64,
        next_attempt: i32,
        next_scheduled_at: f64,
    ) -> Result<()> {
        if next_attempt <= 1 {
            return Ok(());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "SELECT id FROM workflow.workflows WHERE id =
            (SELECT workflow_id FROM workflow.activities WHERE id = ?) ",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query("UPDATE workflow.activities
            SET status = 'PENDING', attempt = ?, scheduled_at = ?,
                claimed_by = NULL, started_at = NULL, last_heartbeat = NULL, error = NULL
            WHERE id = ? AND status IN ('RUNNING', 'FAILED') AND attempt = ?
              AND EXISTS (SELECT 1 FROM workflow.workflows w WHERE w.id = workflow.activities.workflow_id
                AND w.status IN ('PENDING', 'RUNNING', 'WAITING') AND w.archived_at IS NULL
                AND NOT EXISTS (SELECT 1 FROM workflow.events e WHERE e.workflow_id = w.id
                    AND e.event_type = 'WorkflowCancelRequested'))")
            .bind(next_attempt).bind(next_scheduled_at).bind(id).bind(next_attempt - 1)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
