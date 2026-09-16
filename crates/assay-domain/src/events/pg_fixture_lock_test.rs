//! Linux/real-PostgreSQL lock-cooperation regression for the actual fixture.
//! The configured role must be able to create/drop a fresh owned database.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use futures_util::FutureExt;
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::{initialize_event_schema, test_db_url};
use crate::engine::{PgEngineSchema, SCHEMA_MIGRATION_LOCK, acquire_schema_lock};

const OP_BOUND: Duration = Duration::from_secs(30);
const OBSERVE_BOUND: Duration = Duration::from_secs(10);
const CASE_BOUND: Duration = Duration::from_secs(90);
const STOP_BOUND: Duration = Duration::from_secs(5);
type Job = JoinHandle<Result<()>>;

async fn bounded<F, T, E>(label: &str, future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, E>>,
    E: Into<anyhow::Error>,
{
    timeout(OP_BOUND, future)
        .await
        .with_context(|| format!("{label}: deadline exceeded"))?
        .map_err(|error| -> anyhow::Error { error.into() })
        .with_context(|| label.to_owned())
}

async fn open_pool(options: PgConnectOptions, role: &str) -> Result<PgPool> {
    bounded(
        "connect configured PostgreSQL pool",
        PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .max_lifetime(None)
            .idle_timeout(None)
            .acquire_timeout(STOP_BOUND)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET statement_timeout = '20s'")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options.application_name(role)),
    )
    .await
}

async fn pool_pid(pool: &PgPool) -> Result<i32> {
    bounded(
        "read backend identity",
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(pool),
    )
    .await
}

async fn finish_job(slot: &mut Option<Job>, label: &str) -> Result<()> {
    let job = slot.as_mut().context("missing owned worker task")?;
    match timeout(OP_BOUND, job).await {
        Ok(joined) => {
            // Remove only after completion. A timeout must retain the handle
            // so teardown can abort and join it rather than detach it.
            slot.take();
            joined.with_context(|| format!("{label}: task panicked or cancelled"))??;
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("{label}: deadline exceeded")),
    }
}

#[derive(Clone, Copy, Debug)]
struct BackendIds {
    blocker: i32,
    fixture: i32,
    migrator: i32,
    observer: i32,
}

struct ScratchCase {
    admin: PgPool,
    options: PgConnectOptions,
    name: String,
    owns_name: bool,
    creator: Option<PoolConnection<Postgres>>,
    creator_identity: Option<(i32, String)>,
    pools: Vec<PgPool>,
    blocker: Option<Transaction<'static, Postgres>>,
    fixture: Option<Job>,
    migrator: Option<Job>,
}

impl ScratchCase {
    async fn new(url: &str) -> Result<Self> {
        let options = PgConnectOptions::from_str(url).context("parse configured PG test URL")?;
        let admin = open_pool(options.clone(), "fixture-lock-admin").await?;
        Ok(Self {
            admin,
            options,
            name: format!("assay_test_fixture_{}", uuid::Uuid::now_v7().simple()),
            owns_name: false,
            creator: None,
            creator_identity: None,
            pools: Vec::new(),
            blocker: None,
            fixture: None,
            migrator: None,
        })
    }

    async fn create_database(&mut self) -> Result<()> {
        let exists: bool = bounded(
            "reject pre-existing scratch name",
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(&self.name)
                .fetch_one(&self.admin),
        )
        .await?;
        ensure!(
            !exists,
            "generated database name already exists; it is not owned"
        );
        let creator_pool = open_pool(self.options.clone(), "fixture-lock-creator").await?;
        self.pools.push(creator_pool.clone());
        self.creator = Some(bounded("pin database creator", creator_pool.acquire()).await?);
        let creator = self.creator.as_mut().context("missing pinned creator")?;
        self.creator_identity = Some(
            bounded(
                "identify database creator session",
                sqlx::query_as(
                    "SELECT pg_backend_pid(), backend_start::text FROM pg_stat_activity
                    WHERE pid = pg_backend_pid()",
                )
                .fetch_one(&mut **creator),
            )
            .await?,
        );
        let creator_pid = self
            .creator_identity
            .as_ref()
            .context("missing creator identity")?
            .0;
        let controller_pid = pool_pid(&self.admin).await?;
        ensure!(
            creator_pid != controller_pid,
            "creator and controller share a backend"
        );
        eprintln!(
            "fixture-lock creator={creator_pid} controller={controller_pid} database={}",
            self.name
        );
        // This random, checked name belongs to this creation attempt. Record
        // it BEFORE the await: CREATE may commit even if its response is lost.
        // An explicit duplicate_database response revokes that ownership.
        self.owns_name = true;
        let result = bounded(
            "create owned scratch database",
            sqlx::query(&format!(
                "CREATE DATABASE \"{}\" TEMPLATE template0",
                self.name
            ))
            .execute(&mut **creator),
        )
        .await;
        if let Err(error) = &result {
            let duplicate = error.chain().any(|cause| {
                cause
                    .downcast_ref::<sqlx::Error>()
                    .and_then(|error| error.as_database_error())
                    .and_then(|error| error.code())
                    .is_some_and(|code| code == "42P04")
            });
            if duplicate {
                self.owns_name = false;
            }
        }
        result?;
        Ok(())
    }

    async fn role_pool(&mut self, role: &str) -> Result<PgPool> {
        let pool = open_pool(self.options.clone().database(&self.name), role).await?;
        self.pools.push(pool.clone());
        let actual: String = bounded(
            "verify scratch database selection",
            sqlx::query_scalar("SELECT current_database()").fetch_one(&pool),
        )
        .await?;
        ensure!(
            actual == self.name,
            "connection is not in the owned scratch database"
        );
        Ok(pool)
    }

    async fn exercise(&mut self) -> Result<()> {
        self.create_database().await?;
        let fixture_pool = self.role_pool("fixture-lock-worker").await?;
        let engine_pool = self.role_pool("fixture-lock-engine").await?;
        let observer = self.role_pool("fixture-lock-observer").await?;
        let blocker_pool = self.role_pool("fixture-lock-blocker").await?;
        let fresh: bool = bounded(
            "verify fresh scratch database",
            sqlx::query_scalar("SELECT to_regnamespace('engine') IS NULL").fetch_one(&observer),
        )
        .await?;
        ensure!(
            fresh,
            "scratch database unexpectedly already contains engine schema"
        );
        let mut fixture_connection = bounded("pin fixture backend", fixture_pool.acquire()).await?;
        let fixture_pid: i32 = bounded(
            "identify pinned fixture backend",
            sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *fixture_connection),
        )
        .await?;
        self.blocker = Some(bounded("begin controlling transaction", blocker_pool.begin()).await?);
        let blocker = self
            .blocker
            .as_mut()
            .context("missing controlling transaction")?;
        let blocker_pid = bounded(
            "identify controlling backend",
            sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut **blocker),
        )
        .await?;
        bounded("hold shared schema lock", acquire_schema_lock(blocker)).await?;
        let ids = BackendIds {
            blocker: blocker_pid,
            fixture: fixture_pid,
            migrator: pool_pid(&engine_pool).await?,
            observer: pool_pid(&observer).await?,
        };
        let mut unique = [ids.blocker, ids.fixture, ids.migrator, ids.observer];
        unique.sort_unstable();
        ensure!(
            unique.windows(2).all(|pair| pair[0] != pair[1]),
            "backend identities overlap"
        );
        eprintln!("fixture-lock database={} backends={ids:?}", self.name);
        self.fixture = Some(tokio::spawn(async move {
            initialize_event_schema(&mut fixture_connection).await;
            let after: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *fixture_connection)
                .await?;
            ensure!(after == ids.fixture, "fixture backend identity changed");
            Ok(())
        }));
        let migration_pool = engine_pool.clone();
        self.migrator = Some(tokio::spawn(async move {
            ensure!(
                pool_pid(&migration_pool).await? == ids.migrator,
                "migrator backend replaced"
            );
            PgEngineSchema::new(migration_pool.clone())
                .migrate()
                .await?;
            ensure!(
                pool_pid(&migration_pool).await? == ids.migrator,
                "migrator backend replaced"
            );
            Ok(())
        }));
        timeout(OBSERVE_BOUND, self.observe_cooperation(&observer, ids))
            .await
            .context("no positive shared-lock observation before deadline")??;
        bounded(
            "release controlling lock",
            self.blocker.take().context("missing blocker")?.rollback(),
        )
        .await?;
        finish_job(&mut self.fixture, "fixture initialization").await?;
        finish_job(&mut self.migrator, "engine migration").await?;
        ensure!(
            pool_pid(&fixture_pool).await? == ids.fixture,
            "fixture backend replaced"
        );
        let mut connection = bounded("pin fixture for idempotence", fixture_pool.acquire()).await?;
        bounded("idempotent fixture initialization", async {
            initialize_event_schema(&mut connection).await;
            Ok::<(), anyhow::Error>(())
        })
        .await?;
        drop(connection);
        bounded(
            "idempotent engine migration",
            PgEngineSchema::new(engine_pool.clone()).migrate(),
        )
        .await?;
        verify_round_trips(&observer, &engine_pool).await
    }

    async fn observe_cooperation(&mut self, observer: &PgPool, ids: BackendIds) -> Result<()> {
        loop {
            if self
                .fixture
                .as_ref()
                .context("missing fixture task")?
                .is_finished()
            {
                finish_job(&mut self.fixture, "fixture before lock release").await?;
                bail!(
                    "LOCK_CONTRACT_RED: fixture completed before the controlling lock was released"
                );
            }
            if self
                .migrator
                .as_ref()
                .context("missing migrator task")?
                .is_finished()
            {
                finish_job(&mut self.migrator, "migrator before lock release").await?;
                bail!("engine migrator completed before the controlling lock was released");
            }
            let fixture_waits = observes_wait(observer, ids, ids.fixture).await?;
            let engine_waits = observes_wait(observer, ids, ids.migrator).await?;
            if fixture_waits && engine_waits {
                ensure!(
                    !self
                        .fixture
                        .as_ref()
                        .context("missing fixture task")?
                        .is_finished()
                        && !self
                            .migrator
                            .as_ref()
                            .context("missing migrator task")?
                            .is_finished(),
                    "a worker completed during the positive lock observation"
                );
                eprintln!(
                    "observed both known workers waiting on blocker={} with no engine schema",
                    ids.blocker
                );
                return Ok(());
            }
            // Yield is not the proof: the pg_locks/pg_blocking_pids predicate is.
            tokio::task::yield_now().await;
        }
    }

    async fn stop_creator(&self) -> Result<()> {
        let Some((pid, started)) = &self.creator_identity else {
            return Ok(()); // CREATE cannot start before this identity is saved.
        };
        // The controller is a different connection. Cancelled client futures
        // do not prove that CREATE stopped on the server. Match backend_start
        // as well as PID so a recycled unrelated PID cannot be signalled.
        let _terminated: Option<bool> = bounded(
            "stop only the known database creator",
            sqlx::query_scalar(
                "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity
                    WHERE pid = $1 AND backend_start = $2::timestamptz
                        AND usename = current_user AND pid <> pg_backend_pid()",
            )
            .bind(pid)
            .bind(started)
            .fetch_optional(&self.admin),
        )
        .await?;
        timeout(OBSERVE_BOUND, async {
            loop {
                let gone: bool = bounded(
                    "confirm database creator SQL has stopped",
                    sqlx::query_scalar(
                        "SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity
                            WHERE pid = $1 AND backend_start = $2::timestamptz)",
                    )
                    .bind(pid)
                    .bind(started)
                    .fetch_one(&self.admin),
                )
                .await?;
                if gone {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("creator backend did not stop before cleanup deadline")??;
        Ok(())
    }

    async fn cleanup(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(transaction) = self.blocker.take() {
            match timeout(STOP_BOUND, transaction.rollback()).await {
                Ok(Ok(())) => {}
                other => errors.push(format!("blocker rollback unconfirmed: {other:?}")),
            }
        }
        for (label, slot) in [
            ("fixture", &mut self.fixture),
            ("migrator", &mut self.migrator),
        ] {
            if let Some(mut job) = slot.take() {
                job.abort();
                match timeout(STOP_BOUND, &mut job).await {
                    Ok(Ok(Ok(()))) => {}
                    Ok(Err(error)) if error.is_cancelled() => {}
                    other => errors.push(format!("{label} abort/join unconfirmed: {other:?}")),
                }
            }
        }
        let creator_stopped = self.stop_creator().await;
        if let Err(error) = &creator_stopped {
            errors.push(format!("creator cessation unconfirmed: {error:#}"));
        }
        // The creator connection stays pinned until after the independent
        // stop/readback above, even when CREATE's client future was cancelled.
        self.creator.take();
        if timeout(
            STOP_BOUND,
            futures_util::future::join_all(self.pools.iter().map(PgPool::close)),
        )
        .await
        .is_err()
        {
            errors.push("scratch pool close deadline exceeded".to_owned());
        }
        if self.owns_name && creator_stopped.is_ok() {
            let result = bounded(
                "drop only the owned scratch database",
                sqlx::query(&format!(
                    "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                    self.name
                ))
                .execute(&self.admin),
            )
            .await;
            match result {
                Ok(_) => {
                    let absent: Result<bool> = bounded(
                        "confirm owned database was removed",
                        sqlx::query_scalar(
                            "SELECT NOT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
                        )
                        .bind(&self.name)
                        .fetch_one(&self.admin),
                    )
                    .await;
                    match absent {
                        Ok(true) => {
                            self.owns_name = false;
                            eprintln!("confirmed cleanup of owned database={}", self.name);
                        }
                        other => {
                            errors.push(format!("owned database absence unconfirmed: {other:?}"))
                        }
                    }
                }
                Err(error) => errors.push(format!("owned database cleanup failed: {error:#}")),
            }
        }
        if self.owns_name {
            errors.push(format!("owned database remains unconfirmed: {}", self.name));
        }
        if timeout(STOP_BOUND, self.admin.close()).await.is_err() {
            errors.push("admin pool close deadline exceeded".to_owned());
        }
        ensure!(
            errors.is_empty(),
            "cleanup for {} was not confirmed: {}",
            self.name,
            errors.join("; ")
        );
        Ok(())
    }
}

async fn observes_wait(observer: &PgPool, ids: BackendIds, worker: i32) -> Result<bool> {
    let (observer_pid, schema_exists, waiting): (i32, bool, bool) = bounded(
        "observe exact advisory lock ownership",
        sqlx::query_as(
            "SELECT pg_backend_pid(), to_regnamespace('engine') IS NOT NULL,
                EXISTS(SELECT 1 FROM pg_locks waiting
                    JOIN pg_locks held ON held.locktype = waiting.locktype
                        AND held.database = waiting.database
                        AND held.classid = waiting.classid
                        AND held.objid = waiting.objid
                        AND held.objsubid = waiting.objsubid
                    JOIN pg_stat_activity activity ON activity.pid = waiting.pid
                    WHERE waiting.pid = $1 AND NOT waiting.granted
                        AND held.pid = $2 AND held.granted
                        AND waiting.locktype = 'advisory' AND waiting.objsubid = 1
                        AND waiting.classid::bigint = $3 AND waiting.objid::bigint = $4
                        AND waiting.mode = 'ExclusiveLock' AND held.mode = 'ExclusiveLock'
                        AND activity.wait_event_type = 'Lock' AND activity.wait_event = 'advisory'
                        AND $2 = ANY(pg_blocking_pids($1)))",
        )
        .bind(worker)
        .bind(ids.blocker)
        .bind((SCHEMA_MIGRATION_LOCK >> 32) & 0xffff_ffff)
        .bind(SCHEMA_MIGRATION_LOCK & 0xffff_ffff)
        .fetch_one(observer),
    )
    .await?;
    ensure!(observer_pid == ids.observer, "observer backend replaced");
    ensure!(
        !schema_exists,
        "LOCK_CONTRACT_RED: engine schema visible before controlling lock release"
    );
    Ok(waiting)
}

async fn verify_round_trips(observer: &PgPool, engine_pool: &PgPool) -> Result<()> {
    let complete: bool = bounded(
        "verify both initializers' objects",
        sqlx::query_scalar(
            "SELECT to_regnamespace('engine') IS NOT NULL
                AND to_regclass('engine.events') IS NOT NULL
                AND to_regclass('engine.idx_engine_events_ns_id') IS NOT NULL
                AND to_regclass('engine.migrations') IS NOT NULL
                AND to_regclass('engine.modules') IS NOT NULL
                AND to_regclass('engine.audit') IS NOT NULL
                AND to_regclass('engine.instances') IS NOT NULL",
        )
        .fetch_one(observer),
    )
    .await?;
    ensure!(complete, "a fixture or engine object is missing");
    let id: i64 = bounded(
        "insert fixture event",
        sqlx::query_scalar(
            "INSERT INTO engine.events(namespace, subsystem, kind, payload)
                VALUES ('lock-regression', 'workflow', 'probe', '{\"checked\":true}'::jsonb)
                RETURNING id",
        )
        .fetch_one(observer),
    )
    .await?;
    let payload: serde_json::Value = bounded(
        "read fixture event",
        sqlx::query_scalar("SELECT payload FROM engine.events WHERE id = $1")
            .bind(id)
            .fetch_one(observer),
    )
    .await?;
    ensure!(
        payload == serde_json::json!({"checked": true}),
        "event round trip changed payload"
    );
    let schema = PgEngineSchema::new(engine_pool.clone());
    bounded(
        "write module round trip",
        schema.upsert_module("lock-regression", Some("test"), true),
    )
    .await?;
    let modules = bounded("read module round trip", schema.list_modules()).await?;
    ensure!(
        modules
            .iter()
            .any(|module| module.name == "lock-regression" && module.enabled),
        "module round trip failed"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fixture_bootstrap_cooperates_with_engine_migration() {
    let url =
        test_db_url().expect("Linux PG regression requires TEST_DATABASE_URL or ASSAY_PG_TEST_URL");
    let mut case = ScratchCase::new(&url)
        .await
        .expect("connect to configured PG test service");
    eprintln!("fixture-lock candidate database={}", case.name);
    // Preserve cleanup on ordinary assertion/panic paths as well as SQL errors.
    let outcome = match timeout(CASE_BOUND, AssertUnwindSafe(case.exercise()).catch_unwind()).await
    {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(anyhow::anyhow!("regression body panicked; cleanup follows")),
        Err(error) => Err(anyhow::anyhow!(
            "regression body deadline exceeded: {error}"
        )),
    };
    let cleanup = case.cleanup().await;
    assert!(cleanup.is_ok(), "run={outcome:?}; cleanup={cleanup:?}");
    assert!(
        outcome.is_ok(),
        "fixture/engine shared-lock contract failed: {outcome:#?}"
    );
}
