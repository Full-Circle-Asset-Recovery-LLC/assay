//! Private UUID database ownership and bounded, best-effort-complete cleanup.
#![cfg(all(feature = "backend-postgres", target_os = "linux"))]
use anyhow::{Context, Result, anyhow, ensure};
use futures_util::FutureExt;
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;
use std::time::Duration;
use tokio::task::JoinHandle;

pub const LIMIT: Duration = Duration::from_secs(15);

type CreatorIdentity = (i32, String, String);

pub struct Fixture {
    pub name: String,
    pub admin: Option<PgPool>,
    pub observer: Option<PgPool>,
    pub reporter: Option<PgPool>,
    pub canceller: Option<PgPool>,
    pub barriers: Option<PgPool>,
    pub cancel_gate: Option<Transaction<'static, Postgres>>,
    pub update_gate: Option<Transaction<'static, Postgres>>,
    pub cancel_worker: Option<JoinHandle<Result<i64>>>,
    pub report_worker: Option<JoinHandle<Result<bool>>>,
    creator_pool: Option<PgPool>,
    creator: Option<PoolConnection<Postgres>>,
    creator_identity: Option<CreatorIdentity>,
    creator_ceased: bool,
    owns_candidate: bool,
    creation_started: bool,
    created: bool,
    database_oid: Option<i64>,
}

impl Fixture {
    pub fn new() -> Self {
        let mut bytes: [u8; 16] = rand::random();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        Self {
            name: format!("assay_test_{uuid}"),
            admin: None,
            observer: None,
            reporter: None,
            canceller: None,
            barriers: None,
            cancel_gate: None,
            update_gate: None,
            cancel_worker: None,
            report_worker: None,
            creator_pool: None,
            creator: None,
            creator_identity: None,
            creator_ceased: false,
            owns_candidate: false,
            creation_started: false,
            created: false,
            database_oid: None,
        }
    }

    pub async fn setup(&mut self) -> Result<()> {
        validate_name(&self.name)?;
        let url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required; this regression never starts a server")?;
        ensure!(!url.trim().is_empty(), "TEST_DATABASE_URL must be nonempty");
        let options = PgConnectOptions::from_str(&url)?;
        self.admin = Some(pool(options.clone(), 1));
        self.creator_pool = Some(pool(options.clone(), 1));
        self.creator = Some(
            bounded(
                "pin CREATE backend",
                self.creator_pool
                    .as_ref()
                    .context("creator pool missing")?
                    .acquire(),
            )
            .await?,
        );
        self.creator_identity = Some(
            bounded(
                "record CREATE backend identity",
                sqlx::query_as(
                    "SELECT pid, extract(epoch FROM backend_start)::text, datname
             FROM pg_stat_activity WHERE pid = pg_backend_pid()",
                )
                .fetch_one(&mut **self.creator.as_mut().context("creator missing")?),
            )
            .await?,
        );
        let exists: bool = bounded(
            "candidate absence before CREATE",
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(&self.name)
                .fetch_one(self.admin.as_ref().context("admin missing")?),
        )
        .await?;
        ensure!(
            !exists,
            "UUID database candidate already exists; no ownership acquired"
        );
        // Record candidate ownership before awaiting CREATE. Lost ACK is not
        // evidence of absence: cleanup first proves this exact backend ceased.
        self.owns_candidate = true;
        self.creation_started = true;
        let creation = bounded(
            "create owned database",
            sqlx::query(&format!(
                "CREATE DATABASE \"{}\" TEMPLATE template0",
                self.name
            ))
            .execute(&mut **self.creator.as_mut().context("creator missing")?),
        )
        .await;
        if let Err(error) = &creation
            && error
                .downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .and_then(|error| error.code())
                .as_deref()
                == Some("42P04")
        {
            // A concurrently-created duplicate is never ours to destroy.
            self.owns_candidate = false;
        }
        creation?;
        self.created = true;
        self.database_oid = Some(
            bounded(
                "read database identity",
                sqlx::query_scalar("SELECT oid::bigint FROM pg_database WHERE datname = $1")
                    .bind(&self.name)
                    .fetch_one(self.admin.as_ref().context("admin missing")?),
            )
            .await?,
        );
        let options = options.database(&self.name);
        self.observer = Some(pool(options.clone(), 1));
        self.barriers = Some(pool(options.clone(), 2));
        self.reporter = Some(pool(options.clone(), 1));
        self.canceller = Some(pool(options, 1));
        Ok(())
    }

    pub fn observer(&self) -> Result<&PgPool> {
        self.observer.as_ref().context("observer pool missing")
    }

    async fn cease_creator(&mut self) -> Result<()> {
        let Some((pid, started, database)) = &self.creator_identity else {
            ensure!(
                !self.creation_started,
                "CREATE started without creator identity"
            );
            self.creator_ceased = true;
            return Ok(());
        };
        let admin = self.admin.as_ref().context("admin missing")?;
        // Exception to the owned-database filter: only our pinned CREATE backend
        // lives in the admin database. Never terminate by admin database name alone.
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
            WHERE pid = $1 AND extract(epoch FROM backend_start)::text = $2 AND datname = $3
              AND pid <> pg_backend_pid()",
        )
        .bind(pid)
        .bind(started)
        .bind(database)
        .execute(admin)
        .await?;
        loop {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE pid = $1 AND extract(epoch FROM backend_start)::text = $2 AND datname = $3)",
            )
            .bind(pid)
            .bind(started)
            .bind(database)
            .fetch_one(admin)
            .await?;
            if !exists {
                self.creator_ceased = true;
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    }

    async fn resolve_owned_database(&mut self) -> Result<()> {
        validate_name(&self.name)?;
        ensure!(
            self.creator_ceased,
            "creator cessation not proven; refusing database probe"
        );
        ensure!(
            self.owns_candidate && self.creation_started,
            "no candidate ownership receipt"
        );
        let oid: Option<i64> =
            sqlx::query_scalar("SELECT oid::bigint FROM pg_database WHERE datname = $1")
                .bind(&self.name)
                .fetch_optional(self.admin.as_ref().context("admin missing")?)
                .await?;
        if let (Some(expected), Some(actual)) = (self.database_oid, oid) {
            ensure!(expected == actual, "owned database identity changed");
        }
        self.database_oid = oid;
        self.created = oid.is_some();
        Ok(())
    }

    async fn terminate_owned_sessions(&self) -> Result<()> {
        self.require_owned_database()?;
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
            WHERE datname = $1 AND datid::bigint = $2 AND pid <> pg_backend_pid()",
        )
        .bind(&self.name)
        .bind(self.database_oid)
        .execute(self.admin.as_ref().context("admin missing")?)
        .await?;
        Ok(())
    }

    fn require_owned_database(&self) -> Result<()> {
        validate_name(&self.name)?;
        ensure!(
            self.creator_ceased
                && self.owns_candidate
                && self.creation_started
                && self.created
                && self.database_oid.is_some(),
            "unproven database ownership"
        );
        Ok(())
    }

    async fn drop_owned_database(&mut self) -> Result<()> {
        self.require_owned_database()?;
        let admin = self.admin.as_ref().context("admin missing")?;
        let oid: Option<i64> =
            sqlx::query_scalar("SELECT oid::bigint FROM pg_database WHERE datname = $1")
                .bind(&self.name)
                .fetch_optional(admin)
                .await?;
        ensure!(
            oid == self.database_oid,
            "database ownership changed before DROP"
        );
        sqlx::query(&format!("DROP DATABASE \"{}\"", self.name))
            .execute(admin)
            .await?;
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(&self.name)
                .fetch_one(admin)
                .await?;
        ensure!(!exists, "owned database still exists after DROP");
        self.created = false;
        eprintln!("confirmed cleanup of owned database={}", self.name);
        Ok(())
    }

    pub async fn cleanup(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        self.release_and_stop(&mut errors).await;
        cleanup_step(
            &mut errors,
            "cease exact CREATE backend",
            self.cease_creator(),
        )
        .await;
        let mut ownership_resolved = false;
        if self.creator_ceased && self.owns_candidate && self.creation_started {
            cleanup_step(
                &mut errors,
                "resolve CREATE result after creator cessation",
                async {
                    self.resolve_owned_database().await?;
                    ownership_resolved = true;
                    Ok(())
                },
            )
            .await;
        }
        if ownership_resolved && self.created {
            cleanup_step(
                &mut errors,
                "terminate owned sessions",
                self.terminate_owned_sessions(),
            )
            .await;
        }
        self.close_owned_pools(&mut errors).await;
        // Retry worker cessation after session termination; preserve earlier failures.
        stop_worker(&mut self.cancel_worker, "canceller final", &mut errors).await;
        stop_worker(&mut self.report_worker, "reporter final", &mut errors).await;
        if ownership_resolved && self.created {
            cleanup_step(
                &mut errors,
                "drop owned database",
                self.drop_owned_database(),
            )
            .await;
        }
        if let Some(admin) = &self.admin {
            cleanup_step(&mut errors, "close admin pool", async {
                admin.close().await;
                Ok(())
            })
            .await;
        }
        if self.cancel_worker.is_some() || self.report_worker.is_some() {
            errors.push("worker cessation not verified".into());
        }
        if self.creation_started
            && (!self.creator_ceased || (self.owns_candidate && !ownership_resolved))
        {
            errors.push("database cleanup could not prove final ownership/absence".into());
        }
        errors
    }

    async fn release_and_stop(&mut self, errors: &mut Vec<String>) {
        if let Some(gate) = self.cancel_gate.take() {
            cleanup_step(errors, "rollback cancellation gate", async {
                Ok(gate.rollback().await?)
            })
            .await;
        }
        if let Some(gate) = self.update_gate.take() {
            cleanup_step(errors, "rollback update gate", async {
                Ok(gate.rollback().await?)
            })
            .await;
        }
        stop_worker(&mut self.cancel_worker, "canceller", errors).await;
        stop_worker(&mut self.report_worker, "reporter", errors).await;
    }

    async fn close_owned_pools(&mut self, errors: &mut Vec<String>) {
        if let Some(creator) = self.creator.take() {
            cleanup_step(errors, "close pinned creator connection", async {
                Ok(creator.close().await?)
            })
            .await;
        }
        for pool in [
            &self.reporter,
            &self.canceller,
            &self.observer,
            &self.barriers,
            &self.creator_pool,
        ]
        .into_iter()
        .flatten()
        {
            cleanup_step(errors, "close owned pool", async {
                pool.close().await;
                Ok(())
            })
            .await;
        }
    }
}

fn pool(options: PgConnectOptions, max: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(0)
        .idle_timeout(None)
        .max_lifetime(None)
        .acquire_timeout(LIMIT)
        .after_connect(|connection, _| Box::pin(async move {
            let (default, current): (String, String) = sqlx::query_as(
                "SELECT current_setting('default_transaction_isolation'), current_setting('transaction_isolation')")
                .fetch_one(connection).await?;
            if default != "read committed" || current != "read committed" {
                return Err(sqlx::Error::Protocol(
                    "isolation fixture requires READ COMMITTED defaults before reporter override".into()));
            }
            Ok(())
        }))
        .connect_lazy_with(options)
}

fn validate_name(name: &str) -> Result<()> {
    let uuid = name
        .strip_prefix("assay_test_")
        .context("foreign database prefix")?;
    ensure!(uuid.len() == 36, "invalid UUID database length");
    for (index, byte) in uuid.bytes().enumerate() {
        let valid = if [8, 13, 18, 23].contains(&index) {
            byte == b'-'
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        };
        ensure!(valid, "invalid UUID database character");
    }
    ensure!(uuid.as_bytes()[14] == b'4', "not UUID v4");
    ensure!(
        b"89ab".contains(&uuid.as_bytes()[19]),
        "not RFC UUID variant"
    );
    Ok(())
}

pub async fn bounded<T, E>(
    label: &str,
    future: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    tokio::time::timeout(LIMIT, future)
        .await
        .with_context(|| format!("{label} timed out"))?
        .map_err(Into::into)
        .with_context(|| label.to_owned())
}

async fn cleanup_step(
    errors: &mut Vec<String>,
    label: &str,
    future: impl Future<Output = Result<()>>,
) {
    match AssertUnwindSafe(tokio::time::timeout(LIMIT, future))
        .catch_unwind()
        .await
    {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => errors.push(format!("{label}: {error:#}")),
        Ok(Err(_)) => errors.push(format!("{label}: timed out")),
        Err(_) => errors.push(format!("{label}: panicked")),
    }
}

async fn stop_worker<T: Send + 'static>(
    slot: &mut Option<JoinHandle<Result<T>>>,
    label: &str,
    errors: &mut Vec<String>,
) {
    let Some(worker) = slot.as_mut() else {
        return;
    };
    worker.abort();
    let mut ceased = false;
    cleanup_step(errors, label, async {
        let result = worker.await;
        ceased = true;
        match result {
            Ok(_) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(anyhow!("worker panicked: {error}")),
        }
    })
    .await;
    if ceased {
        *slot = None;
    }
}

pub async fn finish_worker<T>(
    slot: &mut Option<JoinHandle<Result<T>>>,
    label: &str,
) -> Result<Result<T>> {
    // Await by reference so timeout cannot detach a worker from fixture ownership.
    let worker = slot.as_mut().context("worker missing")?;
    let result = tokio::time::timeout(LIMIT, worker)
        .await
        .with_context(|| format!("{label} timed out"))?;
    *slot = None;
    result.with_context(|| format!("{label} join failed"))
}
