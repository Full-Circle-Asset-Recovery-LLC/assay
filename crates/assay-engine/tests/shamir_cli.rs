#![cfg(all(feature = "backend-sqlite", feature = "vault-sealing-shamir"))]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use assay_vault::crypto::kek_store::load_or_init_sqlite;
use sqlx::Executor;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

async fn fixture() -> (tempfile::TempDir, std::path::PathBuf, sqlx::SqlitePool) {
    let tmp = tempfile::tempdir().unwrap();
    let engine = tmp.path().join("engine.db");
    let vault = tmp.path().join("vault.db");
    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);
    let engine_for_attach = engine.clone();
    let vault_for_attach = vault.clone();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let vault = vault_for_attach.clone();
            let engine = engine_for_attach.clone();
            Box::pin(async move {
                conn.execute(format!("ATTACH DATABASE '{}' AS engine", engine.display()).as_str())
                    .await?;
                conn.execute(format!("ATTACH DATABASE '{}' AS vault", vault.display()).as_str())
                    .await?;
                Ok(())
            })
        })
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE engine.instances (id TEXT PRIMARY KEY, last_heartbeat REAL NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    // The vault migration expects this attached engine table name.
    sqlx::query("CREATE TABLE engine.migrations (module TEXT, version INTEGER, PRIMARY KEY(module, version))")
        .execute(&pool)
        .await
        .unwrap();
    assay_vault::schema::migrate_sqlite(&pool).await.unwrap();
    load_or_init_sqlite(&pool).await.unwrap();

    let config = tmp.path().join("engine.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nbind_addr='127.0.0.1:0'\n[backend]\ntype='sqlite'\ndata_dir='{}'\n",
            tmp.path().display()
        ),
    )
    .unwrap();
    (tmp, config, pool)
}

#[tokio::test]
async fn offline_init_replaces_plaintext_once_and_writes_private_bundle() {
    let (_tmp, config, pool) = fixture().await;
    let out = config.parent().unwrap().join("shares.json");
    let old_kek: Vec<u8> = sqlx::query_scalar("SELECT sealed_blob FROM vault.kek_metadata")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;
    let engine_check = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(config.parent().unwrap().join("engine.db"))
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM instances")
        .fetch_one(&engine_check)
        .await
        .unwrap();
    engine_check.close().await;
    let result = Command::new(env!("CARGO_BIN_EXE_assay-engine"))
        .args(["vault", "init-shamir", "--config"])
        .arg(&config)
        .args(["--threshold", "3", "--shares", "5", "--shares-out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(!stdout.contains("shares_b64"));
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bundle: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(bundle["threshold"], 3);
    assert_eq!(bundle["shares_b64"].as_array().unwrap().len(), 5);

    let vault_path = config.parent().unwrap().join("vault.db");
    let verify = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(vault_path)
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let rows: Vec<(String, i64, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT sealing_method, sealed, sealed_blob, kek_digest FROM kek_metadata")
            .fetch_all(&verify)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "shamir");
    assert_eq!(rows[0].1, 1);
    assert!(rows[0].2.is_empty());
    assert_eq!(rows[0].3.len(), 32);
    for path in [
        config.parent().unwrap().join("vault.db"),
        config.parent().unwrap().join("vault.db-wal"),
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            assert!(!bytes.windows(old_kek.len()).any(|w| w == old_kek));
            for share in bundle["shares_b64"].as_array().unwrap() {
                let encoded = share.as_str().unwrap().as_bytes();
                assert!(!bytes.windows(encoded.len()).any(|w| w == encoded));
            }
        }
    }

    let before = std::fs::read(&out).unwrap();
    let repeated = Command::new(env!("CARGO_BIN_EXE_assay-engine"))
        .args(["vault", "init-shamir", "--config"])
        .arg(&config)
        .args(["--threshold", "3", "--shares", "5", "--shares-out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(!repeated.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), before);
}

#[tokio::test]
async fn offline_init_rolls_back_when_bundle_cannot_be_created() {
    let (_tmp, config, pool) = fixture().await;
    let out = config.parent().unwrap().join("occupied.json");
    std::fs::write(&out, b"sentinel").unwrap();
    pool.close().await;
    let result = Command::new(env!("CARGO_BIN_EXE_assay-engine"))
        .args(["vault", "init-shamir", "--config"])
        .arg(&config)
        .args(["--threshold", "3", "--shares", "5", "--shares-out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), b"sentinel");

    let verify = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(config.parent().unwrap().join("vault.db"))
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let method: String = sqlx::query_scalar("SELECT sealing_method FROM kek_metadata")
        .fetch_one(&verify)
        .await
        .unwrap();
    assert_eq!(method, "plaintext");
}

#[tokio::test]
async fn offline_init_refuses_a_fresh_engine_instance_without_artifacts() {
    let (_tmp, config, pool) = fixture().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    sqlx::query("INSERT INTO engine.instances (id, last_heartbeat) VALUES ('live', ?)")
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let out = config.parent().unwrap().join("must-not-exist.json");
    let result = Command::new(env!("CARGO_BIN_EXE_assay-engine"))
        .args(["vault", "init-shamir", "--config"])
        .arg(&config)
        .args(["--threshold", "3", "--shares", "5", "--shares-out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
}
