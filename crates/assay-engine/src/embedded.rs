//! Embedded-mode entrypoints for `assay-engine`.
//!
//! Use case: a parent binary wants to compose engine into its own
//! [`axum::Router`] rather than running engine standalone via
//! [`crate::run`].
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use assay_engine::embedded;
//! use assay_engine::config::EngineConfig;
//! use std::path::Path;
//!
//! let cfg = EngineConfig::from_file(Path::new("engine.toml"))?;
//! let engine = embedded::build(cfg).await?;
//! // Mount engine.router on parent's listener
//! // Use engine.pool for parent's queries (engine confines its
//! //   writes to its own schemas)
//! # let _ = engine;
//! # Ok(())
//! # }
//! ```
//!
//! The standalone [`crate::run`] is implemented as a thin wrapper
//! around [`build`] + a serve loop; standalone behaviour is unchanged.
//!
//! # Compared to the previous (now-closed) PR exposing four
//! # `pub fn build_*_ctx_*` helpers
//!
//! Embedded mode is a first-class concept here: one type, one
//! function, one symmetric `migrate` helper. Internal ctx-builders
//! (`build_auth_ctx_{pg,sqlite}`, `build_vault_ctx_{pg,sqlite}`)
//! stay `pub(crate)` — they are implementation details. Preconditions
//! that prevent operator lockout (no operator users + no admin
//! api-keys + no external issuers) are enforced inside [`build`] and
//! cannot be skipped.

use std::sync::Arc;

use assay_dashboard::{DashboardCtx, WhitelabelConfig};
use assay_domain::events::EngineEventBus;
use assay_workflow::{WorkflowCtx, WorkflowStore};

use crate::config::EngineConfig;
use crate::init::EngineBoot;
use crate::state::EngineState;

/// Engine composed for embedding into a parent binary. See module
/// docs.
///
/// Marked `#[non_exhaustive]` so future fields (graceful-shutdown
/// handle, metrics handle, …) can be added without breaking
/// downstream pattern-matching.
#[non_exhaustive]
pub struct EmbeddedEngine {
    /// Engine's [`axum::Router`]. Mount on parent's listener at root,
    /// or under a sub-path. URL surface includes:
    ///   - `/api/v1/engine/*` — engine + per-module APIs
    ///   - `/auth/*` — OIDC spec endpoints (when auth module enabled)
    ///   - `/api/v1/vault/*` — vault APIs (when vault module enabled)
    ///   - `/workflow/`, `/auth/console`, `/engine/console`,
    ///     `/vault/console` — assay-dashboard SPAs
    pub router: axum::Router,

    /// Backend-typed pool engine's modules use. SQLite callers receive
    /// a guarded pool whose clones retain runtime lock authority.
    /// Engine confines writes to its own schemas
    /// (`engine.*`, `workflow.*`, `auth.*`, `vault.*` on PG; per-
    /// module `.db` files on sqlite via ATTACH).
    pub pool: EmbeddedPool,

    /// This engine instance's `engine.instances` row id. Surface in
    /// parent's introspection endpoints if useful.
    pub instance_id: uuid::Uuid,

    /// Names of modules attached/enabled at boot. Mirrors
    /// `EngineState::modules` but cloned out so the parent doesn't
    /// need to keep an `Arc<EngineState>` around.
    pub modules: Vec<String>,

    /// `assay-engine` crate version.
    pub engine_version: &'static str,

    /// Held for the full lifetime of every persistent SQLite engine so
    /// embedded and standalone users contend with offline administration.
    _runtime_authority: Option<Arc<crate::process_lock::RuntimeAuthority>>,
}

/// Backend-typed pool. Engine's internal code paths are backend-
/// specific (PG advisory locks, SQLite ATTACH for multi-module DB
/// files); we expose typed pools so downstream can dispatch on the
/// variant explicitly rather than guess.
///
/// Marked `#[non_exhaustive]` so future backends (e.g., MySQL) can
/// be added without breaking exhaustive matches.
#[non_exhaustive]
pub enum EmbeddedPool {
    #[cfg(feature = "backend-postgres")]
    Postgres(sqlx::PgPool),
    #[cfg(feature = "backend-sqlite")]
    Sqlite(GuardedSqlitePool),
}

#[cfg(feature = "backend-sqlite")]
#[derive(Clone)]
pub struct GuardedSqlitePool {
    pool: sqlx::SqlitePool,
    runtime_authority: Option<Arc<crate::process_lock::RuntimeAuthority>>,
}

#[cfg(feature = "backend-sqlite")]
impl GuardedSqlitePool {
    fn new(
        pool: sqlx::SqlitePool,
        runtime_authority: Option<Arc<crate::process_lock::RuntimeAuthority>>,
    ) -> Self {
        Self {
            pool,
            runtime_authority,
        }
    }

    /// Acquire a connection that independently retains the runtime lock.
    pub async fn acquire(&self) -> Result<GuardedSqliteConnection, sqlx::Error> {
        Ok(GuardedSqliteConnection {
            connection: self.pool.acquire().await?,
            runtime_authority: self.runtime_authority.clone(),
        })
    }
}

#[cfg(feature = "backend-sqlite")]
pub struct GuardedSqliteConnection {
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    #[allow(dead_code)]
    runtime_authority: Option<Arc<crate::process_lock::RuntimeAuthority>>,
}

#[cfg(feature = "backend-sqlite")]
impl std::ops::Deref for GuardedSqliteConnection {
    type Target = sqlx::SqliteConnection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

#[cfg(feature = "backend-sqlite")]
impl std::ops::DerefMut for GuardedSqliteConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

/// Build engine for embedding. Internally:
///
///   1. Open pool against `cfg.backend` via [`EngineBoot::run`]
///      (which also runs engine + per-module schema migrations).
///   2. Bootstrap module contexts (auth, vault, workflow).
///   3. **Enforce preconditions** — refuse to start when auth is on
///      and the deployment has no operator users, no admin api-keys,
///      and no external OIDC issuers (would lock the operator out).
///   4. Compose [`axum::Router`] via [`crate::server::build_app`].
///   5. Spawn engine's background tasks (events outbox cleanup;
///      module-specific schedulers spawn during ctx construction).
///
/// Returns `Err` on any of: pool-open failure, migration failure,
/// ctx-build failure, precondition failure. The `Err` carries a
/// helpful operator-facing message when the cause is configuration.
pub async fn build(mut cfg: EngineConfig) -> anyhow::Result<EmbeddedEngine> {
    let process_lock = process_lock_for_config(&cfg)?;
    let runtime_authority = process_lock.map(crate::process_lock::RuntimeAuthority::new);
    if let Some(anchored) = runtime_authority
        .as_ref()
        .and_then(|authority| authority.anchored_data_dir())
    {
        cfg.backend.anchor_sqlite_data_dir(&anchored);
    }
    let boot = EngineBoot::run(&cfg, runtime_authority.as_ref()).await?;
    match boot {
        #[cfg(feature = "backend-postgres")]
        EngineBoot::Postgres(b) => build_pg(cfg, b, None).await,
        #[cfg(feature = "backend-sqlite")]
        EngineBoot::Sqlite(b) => build_sqlite(cfg, b, runtime_authority).await,
    }
}

#[cfg(feature = "backend-postgres")]
async fn build_pg(
    cfg: EngineConfig,
    b: crate::init::PgBoot,
    runtime_authority: Option<Arc<crate::process_lock::RuntimeAuthority>>,
) -> anyhow::Result<EmbeddedEngine> {
    let store = assay_workflow::PostgresStore::from_pool(b.pool.clone())
        .await
        .map_err(|e| anyhow::anyhow!("workflow store (pg): {e}"))?;
    let auth_ctx = crate::build_auth_ctx_pg(&cfg, &b.pool).await?;
    #[cfg(feature = "vault")]
    let vault_ctx = crate::build_vault_ctx_pg(&b.modules, &b.pool).await?;
    #[cfg(not(feature = "vault"))]
    let vault_ctx: Option<()> = None;

    compose(
        cfg,
        store,
        b.bus,
        b.modules,
        b.instance_id,
        Some(auth_ctx),
        vault_ctx,
        EmbeddedPool::Postgres(b.pool),
        runtime_authority,
    )
    .await
}

#[cfg(feature = "backend-sqlite")]
async fn build_sqlite(
    cfg: EngineConfig,
    b: crate::init::SqliteBoot,
    runtime_authority: Option<Arc<crate::process_lock::RuntimeAuthority>>,
) -> anyhow::Result<EmbeddedEngine> {
    let store = assay_workflow::SqliteStore::from_attached_pool(b.pool.clone())
        .await
        .map_err(|e| anyhow::anyhow!("workflow store (sqlite): {e}"))?;
    let auth_ctx = crate::build_auth_ctx_sqlite(&cfg, &b.pool).await?;
    #[cfg(feature = "vault")]
    let vault_ctx = crate::build_vault_ctx_sqlite(&b.modules, &b.pool).await?;
    #[cfg(not(feature = "vault"))]
    let vault_ctx: Option<()> = None;

    compose(
        cfg,
        store,
        b.bus,
        b.modules,
        b.instance_id,
        Some(auth_ctx),
        vault_ctx,
        EmbeddedPool::Sqlite(GuardedSqlitePool::new(b.pool, runtime_authority.clone())),
        runtime_authority,
    )
    .await
}

/// Common composition step shared between PG + SQLite paths.
///
/// Mirrors the body of the previous private `run_with_store` (now
/// removed) minus the final `server::serve` call: builds the Lua-
/// VM-equivalent state container, spawns the engine_events cleanup
/// task, and constructs the [`axum::Router`]. The caller (this
/// module's `build`, or the standalone `run` wrapper) decides what
/// to do with the resulting router.
//
// 8 args (1 over clippy's default limit) — splitting them into a
// struct just to placate the lint adds boilerplate without making
// the call sites clearer (each call site is a single-use match
// arm). Allow the lint here.
#[allow(clippy::too_many_arguments)]
async fn compose<S: WorkflowStore + Clone + 'static>(
    cfg: EngineConfig,
    store: S,
    bus: Arc<dyn EngineEventBus>,
    modules: Vec<String>,
    instance_id: uuid::Uuid,
    mut auth_ctx: Option<assay_auth::AuthCtx>,
    #[cfg(feature = "vault")] vault_ctx: Option<assay_vault::VaultCtx>,
    #[cfg(not(feature = "vault"))] _vault_ctx: Option<()>,
    pool: EmbeddedPool,
    runtime_authority: Option<Arc<crate::process_lock::RuntimeAuthority>>,
) -> anyhow::Result<EmbeddedEngine> {
    #[cfg(feature = "auth-recovery")]
    if let Some(authority) = runtime_authority.as_ref()
        && let Some(auth) = auth_ctx.take()
    {
        auth_ctx = Some(auth.with_recovery_runtime_guard(authority.lock_guard()));
    }
    // Precondition: refuse to start when auth is on and no operator
    // user / api-key / external issuer is configured. Same logic as
    // the previous run_with_store, lifted unchanged.
    if let Some(auth) = auth_ctx.as_ref() {
        let user_count = auth
            .users
            .count_users(None)
            .await
            .map_err(|e| anyhow::anyhow!("count auth.users: {e}"))?;
        if user_count == 0
            && cfg.auth.admin_api_keys.is_empty()
            && cfg.auth.external_issuers().is_empty()
        {
            anyhow::bail!(
                "engine refuses to start: no operator users exist, \
                 `auth.admin_api_keys` is empty, and no external issuers \
                 are configured. Either run `assay-engine bootstrap-admin \
                 --email <e> --password <p>` to seed the first user, add \
                 at least one entry to `auth.admin_api_keys` in \
                 engine.toml as a break-glass, or configure \
                 `[[auth.external_issuers]]` with an upstream OIDC \
                 provider (e.g. Hydra) that mints the JWTs your callers \
                 forward."
            );
        }
    }

    let workflow_runtime_guard = runtime_authority
        .as_ref()
        .map(|authority| authority.lock_guard());
    let workflow_ctx =
        WorkflowCtx::start_with_runtime_guard(Arc::new(store), workflow_runtime_guard)
            .with_binary_version(env!("CARGO_PKG_VERSION"))
            .with_event_bus(assay_workflow::events::WorkflowEventBus::new(Arc::clone(
                &bus,
            )));
    let workflow_ctx: Arc<WorkflowCtx<S>> = Arc::new(workflow_ctx);

    // Hourly sweep of the engine_events outbox. Detached — the handle
    // lives for the process lifetime; nothing to await for clean
    // shutdown (prune is idempotent, missed tick is fine).
    if let Some(authority) = runtime_authority.as_ref() {
        let mut guard = authority.task_guard();
        let cleanup_bus = Arc::clone(&bus);
        let ttl = cfg.engine_events_ttl_secs;
        tokio::spawn(async move {
            tokio::select! {
                _ = assay_workflow::events_cleanup::run_events_cleanup(
                    cleanup_bus,
                    std::time::Duration::from_secs(3600),
                    ttl,
                ) => {}
                _ = guard.cancelled() => {}
            }
        });
    } else {
        tokio::spawn(assay_workflow::events_cleanup::run_events_cleanup(
            Arc::clone(&bus),
            std::time::Duration::from_secs(3600),
            cfg.engine_events_ttl_secs,
        ));
    }

    let whitelabel = Arc::new(WhitelabelConfig::from_env());
    let asset_version = env!("CARGO_PKG_VERSION").to_string();
    let dashboard_ctx = Arc::new(DashboardCtx::new(whitelabel, asset_version));
    let admin_api_keys = Arc::new(cfg.auth.admin_api_keys.clone());
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let engine_config = Arc::new(cfg);

    let state = EngineState {
        workflow: workflow_ctx,
        dashboard: dashboard_ctx,
        auth: auth_ctx,
        #[cfg(feature = "vault")]
        vault: vault_ctx,
        admin_api_keys,
        modules: Arc::new(modules.clone()),
        instance_id,
        engine_version: env!("CARGO_PKG_VERSION"),
        started_at,
        engine_config,
        runtime_authority: runtime_authority.clone(),
    };

    let router = crate::server::build_app(state);

    Ok(EmbeddedEngine {
        router,
        pool,
        instance_id,
        modules,
        engine_version: env!("CARGO_PKG_VERSION"),
        _runtime_authority: runtime_authority,
    })
}

/// Run engine + per-module schema migrations against the configured
/// backend. No runtime state is built, no background tasks are
/// spawned. Idempotent — calling on an up-to-date schema is a no-op.
///
/// Used by parent binaries that want a `migrate` subcommand without
/// booting workflow scheduler / vault unseal / etc. Equivalent to
/// `EngineBoot::run(cfg).await?;` with a more discoverable name.
pub async fn migrate(cfg: &EngineConfig) -> anyhow::Result<()> {
    let process_lock = process_lock_for_config(cfg)?;
    let runtime_authority = process_lock.map(crate::process_lock::RuntimeAuthority::new);
    let mut anchored_cfg = cfg.clone();
    if let Some(anchored) = runtime_authority
        .as_ref()
        .and_then(|authority| authority.anchored_data_dir())
    {
        anchored_cfg.backend.anchor_sqlite_data_dir(&anchored);
    }
    let _boot = EngineBoot::run(&anchored_cfg, runtime_authority.as_ref()).await?;
    Ok(())
}

fn process_lock_for_config(
    cfg: &EngineConfig,
) -> anyhow::Result<Option<crate::process_lock::ProcessLock>> {
    match cfg.backend.sqlite_data_dir() {
        Some(data_dir) if data_dir != ":memory:" => Ok(Some(
            crate::process_lock::ProcessLock::acquire(std::path::Path::new(&data_dir))?,
        )),
        _ => Ok(None),
    }
}
