//! Two trigger barriers establish the race without sleeps or timing guesses.
#![cfg(all(feature = "backend-postgres", target_os = "linux"))]
use crate::pg_report_isolation_data::{self as data, Snapshot};
use crate::pg_report_isolation_fixture::{Fixture, bounded, finish_worker};
use anyhow::{Context, Result, ensure};
use assay_workflow::{PostgresStore, WorkflowStore, types::*};
use sqlx::{PgPool, Postgres, Transaction};

const GATE_NAMESPACE: i32 = 1819301;
const CANCEL_GATE: i32 = 1001;
const UPDATE_GATE: i32 = 1002;
const CANCEL_INSERT: &str = "INSERT INTO workflow.events (workflow_id, seq, event_type, payload, timestamp) VALUES ($1, $2, $3, $4, $5) RETURNING id";
const PARENT_SELECT: &str = "SELECT id FROM workflow.workflows WHERE id = (SELECT workflow_id FROM workflow.activities WHERE id = $1) FOR UPDATE";

#[derive(Debug, PartialEq)]
pub struct Session {
    pid: i32,
    started: String,
    database: String,
    default_isolation: String,
    current_isolation: String,
}

#[derive(Debug, PartialEq)]
struct Sessions {
    reporter: Session,
    canceller: Session,
    observer: Session,
    admin: Session,
}

pub struct Evidence {
    before: Snapshot,
    while_cancel_uncommitted: Snapshot,
    committed: Snapshot,
    after: Snapshot,
    cancel_id: i64,
    marker: WorkflowEvent,
    report: Result<bool>,
    sessions_before: Sessions,
    sessions_after: Sessions,
}

impl Evidence {
    pub fn assert_contract(self, default: &str) {
        assert_eq!(self.sessions_before.reporter.default_isolation, default);
        assert_eq!(self.sessions_before.reporter.current_isolation, default);
        for session in [
            &self.sessions_before.canceller,
            &self.sessions_before.observer,
            &self.sessions_before.admin,
        ] {
            assert_eq!(session.default_isolation, "read committed");
            assert_eq!(session.current_isolation, "read committed");
        }
        assert_eq!(
            self.sessions_before, self.sessions_after,
            "dedicated reporter/canceller/observer/admin identity/defaults changed"
        );
        assert_eq!(
            self.before, self.while_cancel_uncommitted,
            "blocked AFTER INSERT must not publish its uncommitted marker"
        );
        data::assert_cancel_only(&self.before, &self.committed, self.cancel_id, &self.marker);
        // All defaults use the identical strict contract, including SERIALIZABLE.
        assert!(
            matches!(&self.report, Ok(false)),
            "cancelled report must return Ok(false), not true or an error: {:?}",
            self.report
        );
        assert_eq!(
            self.committed, self.after,
            "report changed raw parent/dispatch/activity/event/engine history or parent xmin/ctid"
        );
    }
}

struct Prepared {
    observer: PgPool,
    reporter: PostgresStore,
    canceller: PostgresStore,
    activity: i64,
    sessions: Sessions,
}

pub async fn scenario(fixture: &mut Fixture, default: &str) -> Result<Evidence> {
    let prepared = prepare(fixture, default).await?;
    let gate_pid = hold_barriers(fixture).await?;
    let before = bounded("initial raw snapshot", data::snapshot(&prepared.observer)).await?;
    let marker = data::cancellation();
    start_workers(fixture, &prepared, gate_pid, &marker).await?;
    finish_race(fixture, prepared, before, marker).await
}

async fn prepare(fixture: &mut Fixture, default: &str) -> Result<Prepared> {
    fixture.setup().await?;
    let observer = fixture.observer()?.clone();
    let reporter_pool = fixture
        .reporter
        .as_ref()
        .context("reporter pool missing")?
        .clone();
    let canceller_pool = fixture
        .canceller
        .as_ref()
        .context("canceller pool missing")?
        .clone();
    let seed_store = bounded(
        "migrate observer",
        PostgresStore::from_pool(observer.clone()),
    )
    .await?;
    let reporter = bounded("migrate reporter", PostgresStore::from_pool(reporter_pool)).await?;
    let canceller = bounded(
        "migrate canceller",
        PostgresStore::from_pool(canceller_pool),
    )
    .await?;
    let activity = bounded("seed", data::seed(&seed_store)).await?;
    // Only this dedicated max-one reporter connection changes its default.
    set_default(reporter.pool(), default).await?;
    let sessions = read_sessions(fixture).await?;
    for session in [&sessions.canceller, &sessions.observer, &sessions.admin] {
        ensure!(
            session.default_isolation == "read committed"
                && session.current_isolation == "read committed",
            "fixture must use READ COMMITTED"
        );
    }
    ensure!(
        sessions.reporter.database == fixture.name
            && sessions.canceller.database == fixture.name
            && sessions.observer.database == fixture.name,
        "worker/observer database mismatch"
    );
    ensure!(
        sessions.reporter.pid != sessions.canceller.pid,
        "workers share a backend"
    );
    bounded("install barriers", install_barriers(&observer, activity)).await?;
    Ok(Prepared {
        observer,
        reporter,
        canceller,
        activity,
        sessions,
    })
}

async fn hold_barriers(fixture: &mut Fixture) -> Result<i32> {
    let pool = fixture
        .barriers
        .as_ref()
        .context("barrier pool missing")?
        .clone();
    fixture.cancel_gate = Some(bounded("begin cancel gate", pool.begin()).await?);
    let gate_pid = bounded(
        "lock cancel gate",
        lock_gate(
            fixture
                .cancel_gate
                .as_mut()
                .context("cancel gate missing")?,
            CANCEL_GATE,
        ),
    )
    .await?;
    fixture.update_gate = Some(bounded("begin update gate", pool.begin()).await?);
    bounded(
        "lock update gate",
        lock_gate(
            fixture
                .update_gate
                .as_mut()
                .context("update gate missing")?,
            UPDATE_GATE,
        ),
    )
    .await?;
    Ok(gate_pid)
}

async fn start_workers(
    fixture: &mut Fixture,
    prepared: &Prepared,
    gate_pid: i32,
    marker: &WorkflowEvent,
) -> Result<()> {
    let canceller = prepared.canceller.clone();
    let pending_marker = marker.clone();
    fixture.cancel_worker = Some(tokio::spawn(async move {
        canceller.append_event(&pending_marker).await
    }));
    bounded(
        "exact canceller AFTER INSERT wait",
        observe_wait(
            &prepared.observer,
            &prepared.sessions.canceller,
            gate_pid,
            CANCEL_INSERT,
            Some(CANCEL_GATE),
        ),
    )
    .await?;
    let reporter = prepared.reporter.clone();
    let activity = prepared.activity;
    fixture.report_worker = Some(tokio::spawn(async move {
        reporter
            .report_activity(
                activity,
                ActivityFence {
                    expected_attempt: 2,
                    claimed_by: Some(data::OWNER),
                },
                ActivityReport::Heartbeat {
                    details: Some("must-not-apply"),
                },
                data::HEARTBEAT,
            )
            .await
    }));
    bounded(
        "exact reporter parent lock wait",
        observe_wait(
            &prepared.observer,
            &prepared.sessions.reporter,
            prepared.sessions.canceller.pid,
            PARENT_SELECT,
            None,
        ),
    )
    .await?;
    Ok(())
}

async fn finish_race(
    fixture: &mut Fixture,
    prepared: Prepared,
    before: Snapshot,
    marker: WorkflowEvent,
) -> Result<Evidence> {
    let while_cancel_uncommitted = bounded(
        "uncommitted marker snapshot",
        data::snapshot(&prepared.observer),
    )
    .await?;
    let cancel_gate = fixture.cancel_gate.take().context("cancel gate missing")?;
    bounded("release cancellation only", cancel_gate.rollback()).await?;
    let cancel_id = finish_worker(&mut fixture.cancel_worker, "append_event commit").await??;
    // The update gate stays closed even on the old buggy implementation. The
    // committed-marker snapshot therefore cannot accidentally include its write.
    let committed = bounded(
        "committed marker snapshot",
        data::snapshot(&prepared.observer),
    )
    .await?;
    let update_gate = fixture.update_gate.take().context("update gate missing")?;
    bounded("release report update", update_gate.rollback()).await?;
    let report = finish_worker(&mut fixture.report_worker, "report_activity result").await?;
    let after = bounded("final raw snapshot", data::snapshot(&prepared.observer)).await?;
    let sessions_after = read_sessions(fixture).await?;
    Ok(Evidence {
        before,
        while_cancel_uncommitted,
        committed,
        after,
        cancel_id,
        marker,
        report,
        sessions_before: prepared.sessions,
        sessions_after,
    })
}

async fn read_sessions(fixture: &Fixture) -> Result<Sessions> {
    Ok(Sessions {
        reporter: bounded(
            "reporter identity",
            session(fixture.reporter.as_ref().context("reporter missing")?),
        )
        .await?,
        canceller: bounded(
            "canceller identity",
            session(fixture.canceller.as_ref().context("canceller missing")?),
        )
        .await?,
        observer: bounded("observer identity", session(fixture.observer()?)).await?,
        admin: bounded(
            "admin identity",
            session(fixture.admin.as_ref().context("admin missing")?),
        )
        .await?,
    })
}

async fn set_default(pool: &PgPool, default: &str) -> Result<()> {
    let sql = match default {
        "read committed" => "SET default_transaction_isolation = 'read committed'",
        "repeatable read" => "SET default_transaction_isolation = 'repeatable read'",
        "serializable" => "SET default_transaction_isolation = 'serializable'",
        _ => anyhow::bail!("unexpected isolation level"),
    };
    bounded(
        "set dedicated session default",
        sqlx::query(sql).execute(pool),
    )
    .await?;
    Ok(())
}

async fn session(pool: &PgPool) -> Result<Session> {
    let (pid, started, database, default_isolation, current_isolation): (i32, String, String, String, String) = sqlx::query_as(
        "SELECT pid, backend_start::text, datname,
            current_setting('default_transaction_isolation'), current_setting('transaction_isolation')
         FROM pg_stat_activity WHERE pid = pg_backend_pid()")
        .fetch_one(pool).await?;
    Ok(Session {
        pid,
        started,
        database,
        default_isolation,
        current_isolation,
    })
}

async fn lock_gate(tx: &mut Transaction<'static, Postgres>, key: i32) -> Result<i32> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(GATE_NAMESPACE)
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await?)
}

async fn install_barriers(pool: &PgPool, activity: i64) -> Result<()> {
    // AFTER INSERT holds the parent lock and an inserted, uncommitted marker.
    // BEFORE UPDATE prevents any report mutation until the marker snapshot.
    let ddl = format!(
        r#"
        CREATE FUNCTION workflow.pg_report_isolation_cancel_gate() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            PERFORM pg_advisory_xact_lock({GATE_NAMESPACE}, {CANCEL_GATE});
            RETURN NEW;
        END $$;
        CREATE TRIGGER pg_report_isolation_cancel AFTER INSERT ON workflow.events
        FOR EACH ROW WHEN (NEW.workflow_id = 'isolation-current'
            AND NEW.event_type = 'WorkflowCancelRequested')
        EXECUTE FUNCTION workflow.pg_report_isolation_cancel_gate();
        CREATE FUNCTION workflow.pg_report_isolation_update_gate() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            PERFORM pg_advisory_xact_lock({GATE_NAMESPACE}, {UPDATE_GATE});
            RETURN NEW;
        END $$;
        CREATE TRIGGER pg_report_isolation_update BEFORE UPDATE ON workflow.activities
        FOR EACH ROW WHEN (OLD.id = {activity})
        EXECUTE FUNCTION workflow.pg_report_isolation_update_gate();
    "#
    );
    sqlx::raw_sql(&ddl).execute(pool).await?;
    Ok(())
}

async fn observe_wait(
    pool: &PgPool,
    target: &Session,
    blocker: i32,
    query: &str,
    gate: Option<i32>,
) -> Result<()> {
    loop {
        // Exact SQL, backend incarnation, database and direct blocker, not an
        // unrelated query containing "workflow". Each poll is an autocommit read.
        let observed: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (SELECT 1 FROM pg_stat_activity a
                WHERE a.pid = $1 AND a.backend_start::text = $2 AND a.datname = $3
                  AND a.state = 'active' AND a.wait_event_type = 'Lock'
                  AND regexp_replace(btrim(a.query), '\s+', ' ', 'g') = $4
                  AND $5 = ANY(pg_blocking_pids(a.pid))
                  AND ($6::int IS NULL OR (a.wait_event = 'advisory'
                    AND EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid = a.pid
                        AND l.locktype = 'advisory' AND NOT l.granted
                        AND l.classid::bigint = $7::bigint AND l.objid::bigint = $6::bigint
                        AND l.objsubid = 2)
                    AND EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid = $5
                        AND l.locktype = 'advisory' AND l.granted
                        AND l.classid::bigint = $7::bigint AND l.objid::bigint = $6::bigint
                        AND l.objsubid = 2))))
        "#,
        )
        .bind(target.pid)
        .bind(&target.started)
        .bind(&target.database)
        .bind(query)
        .bind(blocker)
        .bind(gate)
        .bind(i64::from(GATE_NAMESPACE))
        .fetch_one(pool)
        .await?;
        if observed {
            eprintln!(
                "isolation barrier observed: target={target:?} blocker={blocker} gate={gate:?} query={query}"
            );
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
}
