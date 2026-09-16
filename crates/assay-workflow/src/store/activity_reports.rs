//! Shared report planning; database implementations hold ownership locks first.
use crate::activities::{failed_event_payload, settled_event_payload};
use crate::types::{ActivityReport, WorkflowActivity};

pub(super) enum ReportWrite<'a> {
    Heartbeat,
    Retry {
        attempt: i32,
        scheduled_at: f64,
    },
    Settle {
        result: Option<&'a str>,
        error: Option<&'a str>,
        payload: String,
        failed: bool,
        timeout: bool,
    },
}

pub(super) fn plan_report<'a>(
    act: &WorkflowActivity,
    report: ActivityReport<'a>,
    now: f64,
) -> Option<ReportWrite<'a>> {
    let error = match report {
        ActivityReport::Heartbeat { .. } => return Some(ReportWrite::Heartbeat),
        ActivityReport::Complete { result } => {
            return Some(ReportWrite::Settle {
                result,
                error: None,
                failed: false,
                timeout: false,
                payload: settled_event_payload(act.id?, act.seq, &act.name, result, None)
                    .to_string(),
            });
        }
        ActivityReport::Fail { error } => error,
        ActivityReport::Timeout => {
            let heartbeat_expired = act.heartbeat_timeout_secs.is_some_and(|timeout| {
                act.last_heartbeat
                    .or(act.started_at)
                    .is_some_and(|last| now - last > timeout)
            });
            if !heartbeat_expired {
                return None;
            }
            "heartbeat timeout — max retries exhausted"
        }
    };
    if act.attempt < act.max_attempts {
        let interval = act.initial_interval_secs * act.backoff_coefficient.powi(act.attempt - 1);
        return Some(ReportWrite::Retry {
            attempt: act.attempt + 1,
            scheduled_at: now + interval,
        });
    }
    Some(ReportWrite::Settle {
        result: None,
        error: Some(error),
        failed: true,
        timeout: matches!(report, ActivityReport::Timeout),
        payload: failed_event_payload(act.id?, act.seq, &act.name, error, act.attempt).to_string(),
    })
}
