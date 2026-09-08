//! KEK rotation — re-wrap every persisted DEK against a fresh KEK.
//!
//! Plan 17 §"Crypto choices": "KEK rotation is a separate explicit
//! operation (re-wrap every DEK); not automatic."
//!
//! SQLite procedure (PostgreSQL rotation is fail-closed until it has a
//! distributed writer drain and peer KEK reload protocol):
//! 1. Generate a fresh 32-byte KEK; mint its content-addressed kid.
//! 2. Persist a new `vault.kek_metadata` row with the same
//!    `sealing_method` as the active row (rotation does not change
//!    sealing topology — that's a separate operation).
//! 3. For every row in `vault.kv` whose `kek_kid` matches the
//!    previous active KEK: unwrap the wrapped_dek with the old KEK,
//!    re-wrap with the new KEK, UPDATE in place. Skip destroyed rows
//!    (their wrapped_dek is intentionally empty).
//! 4. Same for `vault.transit_versions`.
//! 5. Commit the metadata insert and all re-wraps as one transaction.
//! 6. Replace the in-memory KekHandle while still holding the exclusive
//!    operation gate. The gate has drained every old-handle operation,
//!    so subsequent requests use the new KEK.
//!
//! Collections are NOT rewrapped: collection keys are E2E (X25519-
//! wrapped to each member's pubkey), the server never sees the
//! plaintext, the master KEK isn't involved at the server side.
//!
//! Atomicity: the new metadata row and every re-wrap are committed in
//! one transaction. A failure leaves the old metadata and every wrapped
//! row unchanged; only after commit does the runtime expose the new KEK.

use crate::crypto::aead::{KEY_LEN, random_dek};
use crate::crypto::env_seal::{METHOD_ENV, SealKey};
use crate::crypto::kek::{KekHandle, WrappedDek};
use crate::crypto::kek_store::METHOD_PLAINTEXT;
use crate::crypto::seal_state::SealState;
use crate::crypto::sealing::SealingMethod;
use crate::error::{Result, VaultError};

/// Outcome of a single rotate pass.
#[derive(Debug)]
#[non_exhaustive]
pub struct RotationReport {
    pub old_kid: String,
    pub new_kid: String,
    pub kv_rewrapped: u64,
    pub transit_rewrapped: u64,
}

/// Rotate the KEK on a Postgres-backed vault.
#[cfg(feature = "backend-postgres")]
pub async fn rotate_postgres(
    _pool: &sqlx::PgPool,
    _seal_state: &SealState,
    _seal: Option<&SealKey>,
) -> Result<RotationReport> {
    Err(VaultError::Invalid(
        "PostgreSQL KEK rotation requires a distributed writer drain and peer KEK reload; rotation is disabled"
            .into(),
    ))
}

/// How a rotated KEK is stored. Rotation must not silently downgrade a
/// sealed store to plaintext, so the new row is sealed whenever the
/// caller holds the seal key.
fn seal_new_kek(
    method: &SealingMethod,
    kid: &str,
    key: &[u8; crate::crypto::aead::KEY_LEN],
    seal: Option<&SealKey>,
) -> Result<(&'static str, Vec<u8>)> {
    match (method, seal) {
        (SealingMethod::Plaintext, None) => Ok((METHOD_PLAINTEXT, key.to_vec())),
        (SealingMethod::EnvKey, Some(seal)) => Ok((METHOD_ENV, seal.seal(kid, key)?)),
        _ => Err(rotation_method_error(method, seal)),
    }
}

fn validate_rotation_method(method: &SealingMethod, seal: Option<&SealKey>) -> Result<()> {
    match (method, seal) {
        (SealingMethod::Plaintext, None) | (SealingMethod::EnvKey, Some(_)) => Ok(()),
        _ => Err(rotation_method_error(method, seal)),
    }
}

fn rotation_method_error(method: &SealingMethod, seal: Option<&SealKey>) -> VaultError {
    let detail = match (method, seal.is_some()) {
        (SealingMethod::Shamir { .. }, _) => {
            "Shamir KEK rotation is unsupported; refusing to downgrade sealing"
        }
        (SealingMethod::Plaintext, true) => {
            "plaintext KEK rotation cannot change the sealing method"
        }
        (SealingMethod::EnvKey, false) => {
            "environment-sealed KEK rotation requires the environment seal key"
        }
        _ => "KEK rotation does not support the active sealing method",
    };
    VaultError::Invalid(detail.into())
}

/// SQLite mirror.
#[cfg(feature = "backend-sqlite")]
pub async fn rotate_sqlite(
    pool: &sqlx::SqlitePool,
    seal_state: &SealState,
    seal: Option<&SealKey>,
) -> Result<RotationReport> {
    let method = seal_state.status().method;
    validate_rotation_method(&method, seal)?;
    let _rotation = seal_state.begin_rotation().await;
    let old_kek = seal_state.require_unsealed()?;
    let new_key = random_dek();
    let new_kid = mint_kid(&new_key);
    let new_kek = KekHandle::from_bytes(new_kid.clone(), new_key);

    let (method, blob) = seal_new_kek(&method, &new_kid, &new_key, seal)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| VaultError::Backend(anyhow::anyhow!("begin KEK rotation: {e}")))?;
    sqlx::query(
        "INSERT INTO vault.kek_metadata
            (kid, sealing_method, sealed, sealed_blob, sealed_at, unsealed_at, created_at)
         VALUES (?, ?, 0, ?, NULL, ?, ?)",
    )
    .bind(&new_kid)
    .bind(method)
    .bind(blob)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| VaultError::Backend(anyhow::anyhow!("insert new kek_metadata: {e}")))?;

    let kv_rewrapped = rewrap_kv_sqlite(&mut tx, &old_kek, &new_kek).await?;
    let transit_rewrapped = rewrap_transit_sqlite(&mut tx, &old_kek, &new_kek).await?;
    tx.commit()
        .await
        .map_err(|e| VaultError::Backend(anyhow::anyhow!("commit KEK rotation: {e}")))?;

    seal_state.set_unsealed(new_kid.clone(), new_kek);

    Ok(RotationReport {
        old_kid: old_kek.kid().to_string(),
        new_kid,
        kv_rewrapped,
        transit_rewrapped,
    })
}

#[cfg(feature = "backend-sqlite")]
async fn rewrap_kv_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    old: &KekHandle,
    new: &KekHandle,
) -> Result<u64> {
    let mut count = 0u64;
    loop {
        let batch: Vec<(String, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT path, version, wrapped_dek
               FROM vault.kv
              WHERE kek_kid = ? AND destroyed = 0
              ORDER BY path, version
              LIMIT 500",
        )
        .bind(old.kid())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| VaultError::Backend(anyhow::anyhow!("kv rewrap select: {e}")))?;
        if batch.is_empty() {
            break;
        }
        for (path, version, wrapped_dek) in &batch {
            let dek = old.unwrap_dek(&WrappedDek::from_bytes(wrapped_dek.clone()))?;
            let rewrapped = new.wrap_dek(&dek)?;
            let changed = sqlx::query(
                "UPDATE vault.kv
                    SET wrapped_dek = ?, kek_kid = ?
                  WHERE path = ? AND version = ? AND kek_kid = ?",
            )
            .bind(rewrapped.as_bytes())
            .bind(new.kid())
            .bind(path)
            .bind(version)
            .bind(old.kid())
            .execute(&mut **tx)
            .await
            .map_err(|e| VaultError::Backend(anyhow::anyhow!("kv rewrap update: {e}")))?
            .rows_affected();
            if changed != 1 {
                return Err(VaultError::Backend(anyhow::anyhow!(
                    "kv rewrap update changed {changed} rows for {path}/v{version}"
                )));
            }
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(feature = "backend-sqlite")]
async fn rewrap_transit_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    old: &KekHandle,
    new: &KekHandle,
) -> Result<u64> {
    let mut count = 0u64;
    loop {
        let batch: Vec<(String, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT name, version, key_wrapped
               FROM vault.transit_versions
              WHERE kek_kid = ?
              ORDER BY name, version
              LIMIT 500",
        )
        .bind(old.kid())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| VaultError::Backend(anyhow::anyhow!("transit rewrap select: {e}")))?;
        if batch.is_empty() {
            break;
        }
        for (name, version, key_wrapped) in &batch {
            let dek = old.unwrap_dek(&WrappedDek::from_bytes(key_wrapped.clone()))?;
            let rewrapped = new.wrap_dek(&dek)?;
            let changed = sqlx::query(
                "UPDATE vault.transit_versions
                    SET key_wrapped = ?, kek_kid = ?
                  WHERE name = ? AND version = ? AND kek_kid = ?",
            )
            .bind(rewrapped.as_bytes())
            .bind(new.kid())
            .bind(name)
            .bind(version)
            .bind(old.kid())
            .execute(&mut **tx)
            .await
            .map_err(|e| VaultError::Backend(anyhow::anyhow!("transit rewrap update: {e}")))?
            .rows_affected();
            if changed != 1 {
                return Err(VaultError::Backend(anyhow::anyhow!(
                    "transit rewrap update changed {changed} rows for {name}/v{version}"
                )));
            }
            count += 1;
        }
    }
    Ok(count)
}

fn mint_kid(key: &[u8; KEY_LEN]) -> String {
    crate::crypto::kek::mint_kid(key)
}

// Suppress dead-code lint on SealingMethod when only one backend is on.
#[allow(dead_code)]
type _Phase2RotateRef = SealingMethod;

#[cfg(test)]
#[cfg(feature = "backend-sqlite")]
mod tests {
    use super::*;
    use crate::kv::{KvMeta, KvRow, KvStore};
    use crate::store::sqlite::SqliteKvStore;
    use async_trait::async_trait;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use sqlx::{Executor, SqlitePool};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[derive(Clone)]
    struct PausingKvStore {
        inner: SqliteKvStore,
        entered: Arc<Semaphore>,
        release: Arc<Semaphore>,
    }

    #[async_trait]
    impl KvStore for PausingKvStore {
        async fn put_row(
            &self,
            path: &str,
            ciphertext: &[u8],
            nonce: &[u8],
            wrapped_dek: &[u8],
            kek_kid: &str,
            custom_md: &serde_json::Value,
        ) -> Result<i64> {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            self.inner
                .put_row(path, ciphertext, nonce, wrapped_dek, kek_kid, custom_md)
                .await
        }

        async fn get_row(&self, path: &str, version: i64) -> Result<Option<KvRow>> {
            self.inner.get_row(path, version).await
        }

        async fn get_latest_row(&self, path: &str) -> Result<Option<KvRow>> {
            self.inner.get_latest_row(path).await
        }

        async fn list_meta(&self, prefix: &str) -> Result<Vec<KvMeta>> {
            self.inner.list_meta(prefix).await
        }

        async fn read_meta(&self, path: &str) -> Result<Option<KvMeta>> {
            self.inner.read_meta(path).await
        }

        async fn soft_delete(&self, path: &str, version: i64, deleted_at: f64) -> Result<bool> {
            self.inner.soft_delete(path, version, deleted_at).await
        }

        async fn destroy(&self, path: &str, version: i64) -> Result<bool> {
            self.inner.destroy(path, version).await
        }

        async fn undelete(&self, path: &str, version: i64) -> Result<bool> {
            self.inner.undelete(path, version).await
        }
    }

    async fn boot_pool() -> SqlitePool {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let suffix = format!(
            "{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let v = format!("file:assay_rot_v_{suffix}?mode=memory&cache=shared");
        let e = format!("file:assay_rot_e_{suffix}?mode=memory&cache=shared");
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _| {
                let v = v.clone();
                let e = e.clone();
                Box::pin(async move {
                    conn.execute(format!("ATTACH DATABASE '{e}' AS engine").as_str())
                        .await?;
                    conn.execute(format!("ATTACH DATABASE '{v}' AS vault").as_str())
                        .await?;
                    Ok(())
                })
            })
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS engine.migrations (
                module TEXT NOT NULL, version INTEGER NOT NULL,
                PRIMARY KEY (module, version)
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        crate::schema::migrate_sqlite(&pool).await.unwrap();
        pool
    }

    async fn boot_seeded_state(pool: &SqlitePool) -> SealState {
        use crate::crypto::kek_store::{ActiveKek, load_or_init_active_sqlite};

        match load_or_init_active_sqlite(pool, None).await.unwrap() {
            ActiveKek::Plaintext { kid, handle } => {
                SealState::unsealed(SealingMethod::Plaintext, kid, handle)
            }
            _ => panic!("fresh SQLite vault should seed a plaintext KEK"),
        }
    }

    #[cfg(feature = "backend-postgres")]
    #[tokio::test]
    async fn postgres_rotation_fails_before_database_access_or_state_change() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

        let pool = PgPoolOptions::new().connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(1)
                .database("must_not_connect"),
        );
        let kek = KekHandle::generate_ephemeral();
        let old_kid = kek.kid().to_string();
        let state = SealState::unsealed(SealingMethod::Plaintext, old_kid.clone(), kek);

        let error = rotate_postgres(&pool, &state, None).await.unwrap_err();
        assert!(
            error.to_string().contains("distributed writer drain"),
            "{error}"
        );
        assert_eq!(state.status().kid.as_deref(), Some(old_kid.as_str()));
        assert!(!state.status().sealed);
    }

    #[tokio::test]
    async fn rotate_re_wraps_kv_rows() {
        use crate::KvService;
        use crate::store::sqlite::SqliteKvStore;

        let pool = boot_pool().await;
        let kek = KekHandle::generate_ephemeral();
        let seal_state =
            SealState::unsealed(SealingMethod::Plaintext, kek.kid().to_string(), kek.clone());
        let svc = KvService::new(SqliteKvStore::new(pool.clone()), seal_state.clone());
        // Write a few rows.
        svc.put("k1", b"v1", serde_json::json!({})).await.unwrap();
        svc.put("k2", b"v2", serde_json::json!({})).await.unwrap();
        svc.put("k3", b"v3", serde_json::json!({})).await.unwrap();
        // Rotate.
        let report = rotate_sqlite(&pool, &seal_state, None).await.unwrap();
        assert_eq!(report.kv_rewrapped, 3);
        assert_ne!(report.old_kid, report.new_kid);
        // Reads still succeed (the seal_state was updated to the new KEK).
        let r = svc.get("k1", None).await.unwrap();
        assert_eq!(r.plaintext, b"v1");
        let r = svc.get("k2", None).await.unwrap();
        assert_eq!(r.plaintext, b"v2");
        let r = svc.get("k3", None).await.unwrap();
        assert_eq!(r.plaintext, b"v3");
    }

    #[tokio::test]
    async fn rotation_failure_after_metadata_insert_rolls_back_the_new_kek() {
        use crate::crypto::kek_store::{ActiveKek, load_or_init_active_sqlite};

        let pool = boot_pool().await;
        let seal_state = boot_seeded_state(&pool).await;
        let old_kid = seal_state.status().kid.unwrap();
        sqlx::query("ALTER TABLE vault.kv RENAME TO kv_unavailable")
            .execute(&pool)
            .await
            .unwrap();

        let err = rotate_sqlite(&pool, &seal_state, None).await.unwrap_err();
        assert!(err.to_string().contains("kv rewrap select"), "{err}");
        assert_eq!(seal_state.status().kid.as_deref(), Some(old_kid.as_str()));
        let metadata_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault.kek_metadata")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            metadata_rows, 1,
            "failed rotation must roll back its KEK row"
        );

        sqlx::query("ALTER TABLE vault.kv_unavailable RENAME TO kv")
            .execute(&pool)
            .await
            .unwrap();
        let restarted = load_or_init_active_sqlite(&pool, None).await.unwrap();
        match restarted {
            ActiveKek::Plaintext { kid, .. } => assert_eq!(kid, old_kid),
            _ => panic!("restart should load the original plaintext KEK"),
        }
    }

    #[tokio::test]
    async fn rotation_failure_after_row_updates_rolls_back_all_data_and_restart_reads() {
        use crate::KvService;
        use crate::TransitService;
        use crate::crypto::kek_store::{ActiveKek, load_or_init_active_sqlite};
        use crate::store::sqlite::{SqliteKvStore, SqliteTransitStore};

        let pool = boot_pool().await;
        let seal_state = boot_seeded_state(&pool).await;
        let old_kid = seal_state.status().kid.unwrap();
        let kv = KvService::new(SqliteKvStore::new(pool.clone()), seal_state.clone());
        kv.put("a", b"first", serde_json::json!({})).await.unwrap();
        kv.put("b", b"second", serde_json::json!({})).await.unwrap();
        let transit =
            TransitService::new(SqliteTransitStore::new(pool.clone()), seal_state.clone());
        transit.create_key("alpha", None).await.unwrap();
        transit.create_key("beta", None).await.unwrap();
        let alpha_ciphertext = transit.encrypt("alpha", b"alpha-value").await.unwrap();
        let beta_ciphertext = transit.encrypt("beta", b"beta-value").await.unwrap();

        sqlx::query(
            "CREATE TRIGGER vault.fail_second_transit_rewrap
             BEFORE UPDATE OF kek_kid ON transit_versions
             WHEN OLD.name = 'beta' AND NEW.kek_kid != OLD.kek_kid
             BEGIN SELECT RAISE(ABORT, 'injected transit rewrap failure'); END",
        )
        .execute(&pool)
        .await
        .unwrap();

        let err = rotate_sqlite(&pool, &seal_state, None).await.unwrap_err();
        assert!(err.to_string().contains("transit rewrap update"), "{err}");
        assert_eq!(seal_state.status().kid.as_deref(), Some(old_kid.as_str()));
        let metadata_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault.kek_metadata")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            metadata_rows, 1,
            "failed rotation must roll back its KEK row"
        );
        let old_kv_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vault.kv WHERE kek_kid = ?")
                .bind(&old_kid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(old_kv_rows, 2, "every KV re-wrap must roll back");
        let old_transit_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vault.transit_versions WHERE kek_kid = ?")
                .bind(&old_kid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(old_transit_rows, 2, "every transit re-wrap must roll back");

        sqlx::query("DROP TRIGGER vault.fail_second_transit_rewrap")
            .execute(&pool)
            .await
            .unwrap();
        let restarted_state = match load_or_init_active_sqlite(&pool, None).await.unwrap() {
            ActiveKek::Plaintext { kid, handle } => {
                assert_eq!(kid, old_kid);
                SealState::unsealed(SealingMethod::Plaintext, kid, handle)
            }
            _ => panic!("restart should load the original plaintext KEK"),
        };
        let restarted_kv =
            KvService::new(SqliteKvStore::new(pool.clone()), restarted_state.clone());
        assert_eq!(
            restarted_kv.get("a", None).await.unwrap().plaintext,
            b"first"
        );
        assert_eq!(
            restarted_kv.get("b", None).await.unwrap().plaintext,
            b"second"
        );
        let restarted_transit =
            TransitService::new(SqliteTransitStore::new(pool.clone()), restarted_state);
        assert_eq!(
            restarted_transit
                .decrypt("alpha", &alpha_ciphertext)
                .await
                .unwrap(),
            b"alpha-value"
        );
        assert_eq!(
            restarted_transit
                .decrypt("beta", &beta_ciphertext)
                .await
                .unwrap(),
            b"beta-value"
        );
    }

    #[tokio::test]
    async fn writer_with_old_handle_finishes_before_rotation_and_is_rewrapped() {
        use crate::KvService;
        use crate::crypto::kek_store::{ActiveKek, load_or_init_active_sqlite};

        let pool = boot_pool().await;
        let seal_state = boot_seeded_state(&pool).await;
        let old_kid = seal_state.status().kid.unwrap();
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let kv = KvService::new(
            PausingKvStore {
                inner: SqliteKvStore::new(pool.clone()),
                entered: entered.clone(),
                release: release.clone(),
            },
            seal_state.clone(),
        );

        let writer = tokio::spawn(async move {
            kv.put("concurrent", b"survives rotation", serde_json::json!({}))
                .await
        });
        entered.acquire().await.unwrap().forget();

        let rotation_pool = pool.clone();
        let rotation_state = seal_state.clone();
        let rotation =
            tokio::spawn(async move { rotate_sqlite(&rotation_pool, &rotation_state, None).await });
        tokio::task::yield_now().await;
        assert!(
            !rotation.is_finished(),
            "rotation must wait for the active writer"
        );

        release.add_permits(1);
        writer.await.unwrap().unwrap();
        let report = rotation.await.unwrap().unwrap();
        assert_ne!(report.new_kid, old_kid);

        let old_rows: i64 = sqlx::query_scalar(
            "SELECT
                (SELECT COUNT(*) FROM vault.kv WHERE kek_kid = ?) +
                (SELECT COUNT(*) FROM vault.transit_versions WHERE kek_kid = ?)",
        )
        .bind(&old_kid)
        .bind(&old_kid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            old_rows, 0,
            "rotation must leave no operational row on the old KEK"
        );

        let restarted_state = match load_or_init_active_sqlite(&pool, None).await.unwrap() {
            ActiveKek::Plaintext { kid, handle } => {
                assert_eq!(kid, report.new_kid);
                SealState::unsealed(SealingMethod::Plaintext, kid, handle)
            }
            _ => panic!("restart should load the rotated plaintext KEK"),
        };
        let restarted = KvService::new(SqliteKvStore::new(pool), restarted_state);
        assert_eq!(
            restarted.get("concurrent", None).await.unwrap().plaintext,
            b"survives rotation"
        );
    }

    #[tokio::test]
    async fn environment_rotation_preserves_the_environment_method() {
        let pool = boot_pool().await;
        let old = KekHandle::generate_ephemeral();
        let seal_state = SealState::unsealed(SealingMethod::EnvKey, old.kid().to_string(), old);
        let seal =
            SealKey::derive("environment-seal-key-with-at-least-thirty-two-characters").unwrap();

        let report = rotate_sqlite(&pool, &seal_state, Some(&seal))
            .await
            .unwrap();
        let method: String =
            sqlx::query_scalar("SELECT sealing_method FROM vault.kek_metadata WHERE kid = ?")
                .bind(report.new_kid)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(method, METHOD_ENV);
        assert_eq!(seal_state.status().method, SealingMethod::EnvKey);
    }

    #[tokio::test]
    async fn rotation_rejects_a_method_or_key_mismatch_before_writing() {
        let pool = boot_pool().await;
        let seal =
            SealKey::derive("environment-seal-key-with-at-least-thirty-two-characters").unwrap();

        for (method, supplied_seal) in [
            (SealingMethod::Plaintext, Some(&seal)),
            (SealingMethod::EnvKey, None),
        ] {
            let old = KekHandle::generate_ephemeral();
            let state = SealState::unsealed(method, old.kid().to_string(), old);
            assert!(rotate_sqlite(&pool, &state, supplied_seal).await.is_err());
        }

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault.kek_metadata")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "a rejected rotation must not persist a KEK");
    }

    #[cfg(feature = "vault-sealing-shamir")]
    #[tokio::test]
    async fn rotation_rejects_shamir_instead_of_downgrading_it() {
        let pool = boot_pool().await;
        let key = [7u8; KEY_LEN];
        let kid = mint_kid(&key);
        let state = SealState::sealed_shamir(kid.clone(), [9u8; 32], 3, 5);
        state.set_unsealed(kid, KekHandle::from_bytes(mint_kid(&key), key));

        let err = rotate_sqlite(&pool, &state, None).await.unwrap_err();
        assert!(err.to_string().contains("Shamir"), "{err}");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault.kek_metadata")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "Shamir rejection must happen before persistence");
    }
}
