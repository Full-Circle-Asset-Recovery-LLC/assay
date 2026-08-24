//! KEK persistence — load the active KEK from `vault.kek_metadata` or
//! generate a fresh one on first boot.
//!
//! ## Phase 1 stance
//!
//! Phase 1 ships `sealing_method = 'plaintext'` only — the KEK lives in
//! `kek_metadata.sealed_blob` as raw bytes. Engine boot logs a WARN so
//! operators know vault is running unsealed and that Phase 2 is the path
//! to real sealing.
//!
//! ## Phase 2 plug-in shape
//!
//! Phase 2 will add `load_with_unseal` variants that take an
//! `UnsealMaterial` enum (Shamir shares, KMS handle, HSM session). The
//! Phase 1 loader stays usable for the plaintext path indefinitely so
//! tests don't need to set up KMS.

use anyhow::Context;

use crate::crypto::aead::{KEY_LEN, random_dek};
use crate::crypto::kek::KekHandle;

/// Sealing method — the column value in `vault.kek_metadata`.
pub const METHOD_PLAINTEXT: &str = "plaintext";
pub const METHOD_SHAMIR: &str = "shamir";
pub const OPERATIONAL_TABLES: &[&str] = &[
    "kv_meta",
    "kv",
    "transit_keys",
    "transit_versions",
    "leases",
    "vaults",
    "collections",
    "collection_members",
    "items",
    "folders",
    "share_revoked",
    "unseal_shares",
    "audit_sinks",
];

/// Outcome of [`load_active_*`] — fully describes the at-rest state so
/// engine boot can construct the right [`crate::crypto::seal_state::SealState`].
#[non_exhaustive]
pub enum ActiveKek {
    /// Plaintext sealing (Phase 1 placeholder). The KEK is in memory.
    Plaintext { kid: String, handle: KekHandle },
    /// Shamir-sealed. The engine cannot use the vault until the
    /// operator submits `threshold` shares.
    Shamir {
        kid: String,
        threshold: u8,
        shares_count: u8,
        kek_digest: [u8; 32],
    },
}

#[cfg(feature = "vault-sealing-shamir")]
use crate::crypto::sealing::shamir::{Share, split_kek};

/// Load the active KEK or generate one on first boot.
///
/// "Active" = the row with the most recent `created_at`. If no row
/// exists, a fresh 32-byte KEK is minted, persisted with
/// `sealing_method = 'plaintext'`, and returned.
///
/// The returned handle holds the unsealed bytes in memory; persisting
/// them in plaintext is the explicit Phase 1 trade-off.
#[cfg(feature = "backend-postgres")]
pub async fn load_or_init_postgres(pool: &sqlx::PgPool) -> anyhow::Result<KekHandle> {
    let existing: Option<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT kid, sealing_method, sealed_blob
           FROM vault.kek_metadata
          ORDER BY created_at DESC
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("read vault.kek_metadata")?;

    if let Some((kid, method, blob)) = existing {
        let key = parse_plaintext_blob(&method, &blob)
            .with_context(|| format!("unwrap KEK kid={kid}"))?;
        warn_if_plaintext(&kid, &method);
        return Ok(KekHandle::from_bytes(kid, key));
    }

    let key = random_dek();
    let handle = KekHandle::from_bytes(content_addressed_kid(&key), key);
    sqlx::query(
        "INSERT INTO vault.kek_metadata
            (kid, sealing_method, sealed, sealed_blob, sealed_at, unsealed_at)
         VALUES ($1, $2, FALSE, $3, NULL, EXTRACT(EPOCH FROM NOW()))",
    )
    .bind(handle.kid())
    .bind(METHOD_PLAINTEXT)
    .bind(key.as_slice())
    .execute(pool)
    .await
    .context("seed vault.kek_metadata")?;
    warn_first_boot_plaintext(handle.kid());
    Ok(handle)
}

/// SQLite mirror of [`load_or_init_postgres`].
#[cfg(feature = "backend-sqlite")]
pub async fn load_or_init_sqlite(pool: &sqlx::SqlitePool) -> anyhow::Result<KekHandle> {
    let existing: Option<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT kid, sealing_method, sealed_blob
           FROM vault.kek_metadata
          ORDER BY created_at DESC
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("read vault.kek_metadata")?;

    if let Some((kid, method, blob)) = existing {
        let key = parse_plaintext_blob(&method, &blob)
            .with_context(|| format!("unwrap KEK kid={kid}"))?;
        warn_if_plaintext(&kid, &method);
        return Ok(KekHandle::from_bytes(kid, key));
    }

    let key = random_dek();
    let handle = KekHandle::from_bytes(content_addressed_kid(&key), key);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    sqlx::query(
        "INSERT INTO vault.kek_metadata
            (kid, sealing_method, sealed, sealed_blob, sealed_at, unsealed_at, created_at)
         VALUES (?, ?, 0, ?, NULL, ?, ?)",
    )
    .bind(handle.kid())
    .bind(METHOD_PLAINTEXT)
    .bind(key.as_slice())
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .context("seed vault.kek_metadata")?;
    warn_first_boot_plaintext(handle.kid());
    Ok(handle)
}

fn parse_plaintext_blob(method: &str, blob: &[u8]) -> anyhow::Result<[u8; KEY_LEN]> {
    if method != METHOD_PLAINTEXT {
        anyhow::bail!(
            "parse_plaintext_blob called for sealing_method = '{method}'; \
             this is a code bug — non-plaintext methods take a different code path"
        );
    }
    if blob.len() != KEY_LEN {
        anyhow::bail!(
            "plaintext KEK blob is {} bytes; expected {KEY_LEN}",
            blob.len()
        );
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(blob);
    Ok(key)
}

/// One row from vault.kek_metadata as queried by the load_active_*
/// helpers. Tuple alias keeps clippy::type-complexity happy without
/// adding a real DTO.
#[cfg(feature = "backend-sqlite")]
type SqliteKekRow = (
    String,
    String,
    Vec<u8>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
);

#[cfg(feature = "backend-postgres")]
type PgKekRow = (
    String,
    String,
    Vec<u8>,
    Option<i32>,
    Option<i32>,
    Option<Vec<u8>>,
);

fn parse_digest(kid: &str, digest: Option<Vec<u8>>) -> anyhow::Result<[u8; 32]> {
    let digest =
        digest.ok_or_else(|| anyhow::anyhow!("shamir-sealed kid={kid} missing kek_digest"))?;
    digest.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "shamir-sealed kid={kid} kek_digest is {} bytes; expected 32",
            v.len()
        )
    })
}

fn validate_shamir_params(
    kid: &str,
    threshold: Option<i64>,
    shares_count: Option<i64>,
) -> anyhow::Result<(u8, u8)> {
    let threshold = threshold
        .ok_or_else(|| anyhow::anyhow!("shamir-sealed kid={kid} missing share_threshold"))?;
    let shares_count = shares_count
        .ok_or_else(|| anyhow::anyhow!("shamir-sealed kid={kid} missing share_count"))?;
    if (threshold, shares_count) != (3, 5) {
        anyhow::bail!(
            "shamir-sealed kid={kid} has unsupported parameters {threshold}-of-{shares_count}; expected 3-of-5"
        );
    }
    Ok((3, 5))
}

/// Read the active row from `vault.kek_metadata`, returning the parsed
/// state. Phase-2 entrypoint that distinguishes plaintext from
/// shamir-sealed installations. Caller hands the result to
/// [`crate::crypto::seal_state::SealState`] to build the runtime state.
#[cfg(feature = "backend-sqlite")]
pub async fn load_active_sqlite(pool: &sqlx::SqlitePool) -> anyhow::Result<Option<ActiveKek>> {
    let row: Option<SqliteKekRow> = sqlx::query_as(
        "SELECT kid, sealing_method, sealed_blob, share_threshold, share_count, kek_digest
           FROM vault.kek_metadata
          ORDER BY created_at DESC
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("read vault.kek_metadata")?;

    let Some((kid, method, blob, threshold, shares_count, digest)) = row else {
        return Ok(None);
    };
    match method.as_str() {
        METHOD_PLAINTEXT => {
            let key = parse_plaintext_blob(&method, &blob)
                .with_context(|| format!("unwrap plaintext KEK kid={kid}"))?;
            warn_if_plaintext(&kid, &method);
            Ok(Some(ActiveKek::Plaintext {
                kid: kid.clone(),
                handle: KekHandle::from_bytes(kid, key),
            }))
        }
        METHOD_SHAMIR => {
            let kek_digest = parse_digest(&kid, digest)?;
            let (threshold, shares_count) = validate_shamir_params(&kid, threshold, shares_count)?;
            Ok(Some(ActiveKek::Shamir {
                kid,
                threshold,
                shares_count,
                kek_digest,
            }))
        }
        other => anyhow::bail!(
            "vault.kek_metadata.sealing_method = '{other}' is not yet supported; \
             current build handles plaintext + shamir"
        ),
    }
}

#[cfg(feature = "backend-postgres")]
pub async fn load_active_postgres(pool: &sqlx::PgPool) -> anyhow::Result<Option<ActiveKek>> {
    let row: Option<PgKekRow> = sqlx::query_as(
        "SELECT kid, sealing_method, sealed_blob, share_threshold, share_count, kek_digest
           FROM vault.kek_metadata
          ORDER BY created_at DESC
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("read vault.kek_metadata")?;

    let Some((kid, method, blob, threshold, shares_count, digest)) = row else {
        return Ok(None);
    };
    match method.as_str() {
        METHOD_PLAINTEXT => {
            let key = parse_plaintext_blob(&method, &blob)
                .with_context(|| format!("unwrap plaintext KEK kid={kid}"))?;
            warn_if_plaintext(&kid, &method);
            Ok(Some(ActiveKek::Plaintext {
                kid: kid.clone(),
                handle: KekHandle::from_bytes(kid, key),
            }))
        }
        METHOD_SHAMIR => {
            let kek_digest = parse_digest(&kid, digest)?;
            let (threshold, shares_count) = validate_shamir_params(
                &kid,
                threshold.map(i64::from),
                shares_count.map(i64::from),
            )?;
            Ok(Some(ActiveKek::Shamir {
                kid,
                threshold,
                shares_count,
                kek_digest,
            }))
        }
        other => anyhow::bail!(
            "vault.kek_metadata.sealing_method = '{other}' is not yet supported; \
             current build handles plaintext + shamir"
        ),
    }
}

/// Init a fresh Shamir-sealed KEK. Generates 32 random bytes, splits
/// them into `shares_count` Shamir shares (any `threshold` reconstruct),
/// persists the metadata row with `sealed_blob = ''`, and returns the
/// shares to the operator. The shares are returned ONCE — the engine
/// does not retain a copy. Operators MUST distribute and store them
/// securely (typically among trusted humans).
///
/// Returns the new kid + the raw share bytes. Each share is the binary
/// `sharks::Share` representation; operators submit these verbatim to
/// `/sys/unseal`.
///
/// The caller is responsible for clearing prior `kek_metadata` rows
/// when rotating from plaintext sealing — Phase 2 ships init-from-empty
/// and init-replacing-plaintext only; cross-method KEK rotation
/// (re-wrapping every existing DEK to the new KEK) lands later.
#[cfg(all(feature = "backend-sqlite", feature = "vault-sealing-shamir"))]
pub async fn init_shamir_sqlite(
    pool: &sqlx::SqlitePool,
    threshold: u8,
    shares_count: u8,
) -> anyhow::Result<(String, [u8; 32], Vec<Share>)> {
    if (threshold, shares_count) != (3, 5) {
        anyhow::bail!("first-release shamir parameters must be threshold=3, shares_count=5");
    }
    let mut conn = pool
        .acquire()
        .await
        .context("acquire sqlite init connection")?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .context("begin exclusive shamir init")?;
    let occupied: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM vault.kek_metadata) +
                (SELECT COUNT(*) FROM vault.kv_meta) +
                (SELECT COUNT(*) FROM vault.kv) +
                (SELECT COUNT(*) FROM vault.transit_keys) +
                (SELECT COUNT(*) FROM vault.transit_versions) +
                (SELECT COUNT(*) FROM vault.leases) +
                (SELECT COUNT(*) FROM vault.vaults) +
                (SELECT COUNT(*) FROM vault.collections) +
                (SELECT COUNT(*) FROM vault.collection_members) +
                (SELECT COUNT(*) FROM vault.items) +
                (SELECT COUNT(*) FROM vault.folders) +
                (SELECT COUNT(*) FROM vault.share_revoked) +
                (SELECT COUNT(*) FROM vault.unseal_shares) +
                (SELECT COUNT(*) FROM vault.audit_sinks)",
    )
    .fetch_one(&mut *conn)
    .await
    .context("inspect pristine vault")?;
    if occupied != 0 {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        anyhow::bail!(
            "online shamir init requires a pristine vault with no KEK, KV, or transit rows"
        );
    }
    let mut key = random_dek();
    let kid = content_addressed_kid(&key);
    let digest = full_kek_digest(&key);
    let shares =
        split_kek(&key, threshold, shares_count).map_err(|e| anyhow::anyhow!("split_kek: {e}"))?;
    key.fill(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    sqlx::query(
        "INSERT INTO vault.kek_metadata
            (kid, sealing_method, sealed, sealed_blob, kek_digest, share_threshold, share_count, sealed_at, unsealed_at, created_at)
         VALUES (?, ?, 1, x'', ?, ?, ?, ?, NULL, ?)",
    )
    .bind(&kid)
    .bind(METHOD_SHAMIR)
    .bind(digest.as_slice())
    .bind(threshold as i64)
    .bind(shares_count as i64)
    .bind(now)
    .bind(now)
    .execute(&mut *conn)
    .await
    .context("insert shamir kek_metadata row")?;
    sqlx::query("COMMIT")
        .execute(&mut *conn)
        .await
        .context("commit shamir init")?;
    tracing::info!(
        target: "assay-vault",
        kid = %kid, threshold, shares_count,
        "vault sealed with shamir; operator must store the returned shares"
    );
    Ok((kid, digest, shares))
}

#[cfg(all(feature = "backend-postgres", feature = "vault-sealing-shamir"))]
pub async fn init_shamir_postgres(
    _pool: &sqlx::PgPool,
    threshold: u8,
    shares_count: u8,
) -> anyhow::Result<(String, [u8; 32], Vec<Share>)> {
    if (threshold, shares_count) != (3, 5) {
        anyhow::bail!("first-release shamir parameters must be threshold=3, shares_count=5");
    }
    anyhow::bail!("Postgres Shamir initialization is not supported in the first release")
}

/// Mark a kek_metadata row as sealed/unsealed in the DB. The runtime
/// [`crate::crypto::seal_state::SealState`] is the source of truth for
/// in-memory state; this is the audit / reboot signal.
#[cfg(feature = "backend-sqlite")]
pub async fn set_sealed_flag_sqlite(
    pool: &sqlx::SqlitePool,
    kid: &str,
    sealed: bool,
) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let q = if sealed {
        "UPDATE vault.kek_metadata SET sealed = 1, sealed_at = ? WHERE kid = ?"
    } else {
        "UPDATE vault.kek_metadata SET sealed = 0, unsealed_at = ? WHERE kid = ?"
    };
    let result = sqlx::query(q)
        .bind(now)
        .bind(kid)
        .execute(pool)
        .await
        .context("update sealed flag")?;
    if result.rows_affected() != 1 {
        anyhow::bail!("sealed flag update matched no KEK row for kid={kid}");
    }
    Ok(())
}

#[cfg(feature = "backend-postgres")]
pub async fn set_sealed_flag_postgres(
    pool: &sqlx::PgPool,
    kid: &str,
    sealed: bool,
) -> anyhow::Result<()> {
    let q = if sealed {
        "UPDATE vault.kek_metadata SET sealed = TRUE, sealed_at = EXTRACT(EPOCH FROM NOW()) WHERE kid = $1"
    } else {
        "UPDATE vault.kek_metadata SET sealed = FALSE, unsealed_at = EXTRACT(EPOCH FROM NOW()) WHERE kid = $1"
    };
    let result = sqlx::query(q)
        .bind(kid)
        .execute(pool)
        .await
        .context("update sealed flag")?;
    if result.rows_affected() != 1 {
        anyhow::bail!("sealed flag update matched no KEK row for kid={kid}");
    }
    Ok(())
}

fn content_addressed_kid(key: &[u8; KEY_LEN]) -> String {
    let d = full_kek_digest(key);
    format!("kek-{}", data_encoding::HEXLOWER_PERMISSIVE.encode(&d[..8]))
}

pub fn full_kek_digest(key: &[u8; KEY_LEN]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"assay-vault/kek-kid/v1");
    h.update(key);
    h.finalize().into()
}

fn warn_if_plaintext(kid: &str, method: &str) {
    if method == METHOD_PLAINTEXT {
        tracing::warn!(
            target: "assay-vault",
            kid, method,
            "vault running with plaintext KEK at rest. Move to shamir / kms / hsm sealing in Phase 2 — \
             see plan 17 §S7."
        );
    }
}

fn warn_first_boot_plaintext(kid: &str) {
    tracing::warn!(
        target: "assay-vault",
        kid,
        "first-boot plaintext KEK persisted. Phase 1 placeholder; rotate to a real sealing method as \
         Phase 2 lands."
    );
}

#[cfg(all(test, feature = "backend-sqlite"))]
mod tests {
    use super::*;
    use sqlx::Executor;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    async fn boot_pool() -> sqlx::SqlitePool {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let suffix = format!(
            "{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let v = format!("file:assay_kek_v_{suffix}?mode=memory&cache=shared");
        let e = format!("file:assay_kek_e_{suffix}?mode=memory&cache=shared");
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
                module  TEXT NOT NULL,
                version INTEGER NOT NULL,
                PRIMARY KEY (module, version)
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        crate::schema::migrate_sqlite(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn first_boot_seeds_kek() {
        let pool = boot_pool().await;
        let h1 = load_or_init_sqlite(&pool).await.unwrap();
        let h2 = load_or_init_sqlite(&pool).await.unwrap();
        // Same kid both times — second call loads, doesn't re-seed.
        assert_eq!(h1.kid(), h2.kid());
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault.kek_metadata")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 1, "second load must not insert a new row");
    }

    #[tokio::test]
    async fn rejects_unknown_sealing_method() {
        let pool = boot_pool().await;
        sqlx::query(
            "INSERT INTO vault.kek_metadata
                (kid, sealing_method, sealed, sealed_blob, created_at)
             VALUES ('kek-x', 'kms-aws', 1, x'', 0.0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let res = load_or_init_sqlite(&pool).await;
        assert!(
            res.is_err(),
            "non-plaintext sealing must be rejected in Phase 1"
        );
    }

    #[tokio::test]
    async fn rejects_truncated_plaintext_blob() {
        let pool = boot_pool().await;
        sqlx::query(
            "INSERT INTO vault.kek_metadata
                (kid, sealing_method, sealed, sealed_blob, created_at)
             VALUES ('kek-y', 'plaintext', 0, x'beef', 0.0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(load_or_init_sqlite(&pool).await.is_err());
    }

    #[cfg(feature = "vault-sealing-shamir")]
    #[tokio::test]
    async fn shamir_init_is_sealed_and_loads_as_active_without_secret_material() {
        let pool = boot_pool().await;
        let (kid, _, shares) = init_shamir_sqlite(&pool, 3, 5).await.unwrap();
        assert_eq!(shares.len(), 5);

        let row: (i64, Vec<u8>, Vec<u8>, Option<f64>, Option<f64>) = sqlx::query_as(
            "SELECT sealed, sealed_blob, kek_digest, sealed_at, unsealed_at
               FROM vault.kek_metadata WHERE kid = ?",
        )
        .bind(&kid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, 1);
        assert!(row.1.is_empty());
        assert_eq!(row.2.len(), 32);
        assert!(row.3.is_some());
        assert!(row.4.is_none());

        match load_active_sqlite(&pool).await.unwrap().unwrap() {
            ActiveKek::Shamir {
                kid: loaded,
                threshold,
                shares_count,
                kek_digest,
            } => {
                assert_eq!(loaded, kid);
                assert_eq!((threshold, shares_count), (3, 5));
                assert_eq!(kek_digest.len(), 32);
            }
            ActiveKek::Plaintext { .. } => panic!("expected shamir"),
        }
    }

    #[cfg(feature = "vault-sealing-shamir")]
    #[tokio::test]
    async fn shamir_online_init_refuses_plaintext_nonempty_and_repeat() {
        let pool = boot_pool().await;
        load_or_init_sqlite(&pool).await.unwrap();
        assert!(init_shamir_sqlite(&pool, 3, 5).await.is_err());

        sqlx::query("DELETE FROM vault.kek_metadata")
            .execute(&pool)
            .await
            .unwrap();
        init_shamir_sqlite(&pool, 3, 5).await.unwrap();
        assert!(init_shamir_sqlite(&pool, 3, 5).await.is_err());
    }

    #[cfg(feature = "vault-sealing-shamir")]
    #[tokio::test]
    async fn concurrent_online_init_has_exactly_one_winner() {
        let pool = boot_pool().await;
        let (a, b) = tokio::join!(
            init_shamir_sqlite(&pool, 3, 5),
            init_shamir_sqlite(&pool, 3, 5)
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault.kek_metadata")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn active_loader_rejects_unknown_method() {
        let pool = boot_pool().await;
        sqlx::query(
            "INSERT INTO vault.kek_metadata
                (kid, sealing_method, sealed, sealed_blob, created_at)
             VALUES ('unknown', 'future-method', 1, x'', 1.0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(load_active_sqlite(&pool).await.is_err());
    }

    #[tokio::test]
    async fn active_loader_rejects_noncanonical_shamir_parameters() {
        let pool = boot_pool().await;
        sqlx::query(
            "INSERT INTO vault.kek_metadata
                (kid, sealing_method, sealed, sealed_blob, kek_digest, share_threshold, share_count, created_at)
             VALUES ('bad-shamir', 'shamir', 1, x'', zeroblob(32), 2, 5, 1.0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(load_active_sqlite(&pool).await.is_err());
    }

    #[tokio::test]
    async fn sealed_flag_update_rejects_unknown_kid() {
        let pool = boot_pool().await;
        assert!(
            set_sealed_flag_sqlite(&pool, "missing", true)
                .await
                .is_err()
        );
    }

    #[test]
    fn operational_emptiness_contract_is_complete_and_biscuit_is_independent() {
        assert_eq!(
            OPERATIONAL_TABLES,
            &[
                "kv_meta",
                "kv",
                "transit_keys",
                "transit_versions",
                "leases",
                "vaults",
                "collections",
                "collection_members",
                "items",
                "folders",
                "share_revoked",
                "unseal_shares",
                "audit_sinks",
            ]
        );
        assert!(!OPERATIONAL_TABLES.contains(&"biscuit_root_keys"));
    }

    #[cfg(feature = "vault-sealing-shamir")]
    #[tokio::test]
    async fn restart_starts_sealed_and_same_shares_restore_kv_and_transit() {
        use crate::crypto::seal_state::SealState;
        use crate::kv::KvService;
        use crate::store::sqlite::{SqliteKvStore, SqliteTransitStore};
        use crate::transit::TransitService;

        let pool = boot_pool().await;
        let (kid, digest, shares) = init_shamir_sqlite(&pool, 3, 5).await.unwrap();
        let first = SealState::sealed_shamir(kid.clone(), digest, 3, 5);
        for share in &shares[..3] {
            if let crate::crypto::seal_state::ShareSubmission::Ready(pending) =
                first.submit_shamir_share(share.0.clone()).unwrap()
            {
                first.activate_pending(pending).unwrap();
            }
        }
        let kv = KvService::new(SqliteKvStore::new(pool.clone()), first.clone());
        let transit = TransitService::new(SqliteTransitStore::new(pool.clone()), first);
        kv.put("sentinel", b"same-kek", serde_json::json!({}))
            .await
            .unwrap();
        transit.create_key("sentinel", None).await.unwrap();
        let envelope = transit.encrypt("sentinel", b"same-kek").await.unwrap();

        let restarted = match load_active_sqlite(&pool).await.unwrap().unwrap() {
            ActiveKek::Shamir {
                kid,
                threshold,
                shares_count,
                kek_digest,
            } => SealState::sealed_shamir(kid, kek_digest, threshold, shares_count),
            _ => panic!("expected shamir"),
        };
        let kv2 = KvService::new(SqliteKvStore::new(pool.clone()), restarted.clone());
        let transit2 =
            TransitService::new(SqliteTransitStore::new(pool.clone()), restarted.clone());
        assert!(kv2.get("sentinel", None).await.is_err());
        assert!(transit2.decrypt("sentinel", &envelope).await.is_err());
        for share in &shares[..3] {
            if let crate::crypto::seal_state::ShareSubmission::Ready(pending) =
                restarted.submit_shamir_share(share.0.clone()).unwrap()
            {
                restarted.activate_pending(pending).unwrap();
            }
        }
        assert_eq!(
            kv2.get("sentinel", None).await.unwrap().plaintext,
            b"same-kek"
        );
        assert_eq!(
            transit2.decrypt("sentinel", &envelope).await.unwrap(),
            b"same-kek"
        );
    }
}
