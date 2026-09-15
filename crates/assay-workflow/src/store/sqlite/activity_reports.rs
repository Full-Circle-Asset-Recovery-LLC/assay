//! Due-time claims and legacy retry compare-and-swap.
use super::*;

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
