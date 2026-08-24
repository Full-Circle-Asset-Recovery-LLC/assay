#![cfg(all(feature = "backend-sqlite", feature = "vault-sealing-shamir"))]

use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use assay_vault::crypto::kek_store::load_or_init_sqlite;
use sqlx::Executor;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

fn sha256(path: &std::path::Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

fn write_backup_manifest(config: &std::path::Path) -> std::path::PathBuf {
    let root = config.parent().unwrap();
    let backup = root.join("rollback-baseline");
    std::fs::create_dir_all(&backup).unwrap();
    std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o700)).unwrap();
    let generation = "fixture-generation-1";
    let binary = backup.join("assay-engine");
    let baseline_source = std::env::var_os("ASSAY_TEST_BASELINE_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_assay-engine").into());
    let version_output = Command::new(&baseline_source)
        .arg("--version")
        .output()
        .unwrap();
    assert!(version_output.status.success());
    let version = String::from_utf8(version_output.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    if !binary.exists() {
        std::fs::copy(&baseline_source, &binary).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut sqlite_snapshot = Vec::new();
    let mut databases = std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("db"))
        .collect::<Vec<_>>();
    databases.sort();
    for source in databases {
        let name = source.file_name().unwrap().to_string_lossy().into_owned();
        let snapshot = backup.join(name);
        if !snapshot.exists() {
            std::fs::copy(&source, &snapshot).unwrap();
            std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        sqlite_snapshot.push(serde_json::json!({
            "name": source.file_name().unwrap().to_string_lossy(),
            "path": snapshot,
            "sha256": sha256(&snapshot),
            "generation_id": generation,
        }));
    }
    let manifest = backup.join("manifest.json");
    if !manifest.exists() {
        std::fs::write(
            &manifest,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "generation_id": generation,
                "authorized_operator_ids": ["operator-test"],
                "plaintext_kek_backup_acknowledged": true,
                "baseline_binary": {
                    "path": binary,
                    "sha256": sha256(&binary),
                    "generation_id": generation,
                    "version": version,
                },
                "sqlite_snapshot": sqlite_snapshot,
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    manifest
}

fn authorized_command(config: &std::path::Path, out: &std::path::Path) -> Command {
    let manifest = write_backup_manifest(config);
    let mut command = Command::new(env!("CARGO_BIN_EXE_assay-engine"));
    command
        .args(["vault", "init-shamir", "--config"])
        .arg(config)
        .args(["--threshold", "3", "--shares", "5", "--shares-out"])
        .arg(out)
        .args(["--operator-id", "operator-test", "--backup-manifest"])
        .arg(manifest);
    command
}

fn journal_path(out: &std::path::Path) -> std::path::PathBuf {
    let mut value = out.as_os_str().to_os_string();
    value.push(".transition.json");
    value.into()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn configure_server(config: &std::path::Path, port: u16) {
    let current = std::fs::read_to_string(config).unwrap();
    let updated = current.replace(
        "bind_addr='127.0.0.1:0'",
        &format!("bind_addr='127.0.0.1:{port}'"),
    );
    std::fs::write(
        config,
        format!(
            "{updated}\n[auth]\nadmin_api_keys=['synthetic-test-key']\n[logging]\nlevel='error'\nformat='pretty'\n"
        ),
    )
    .unwrap();
}

fn spawn_engine(config: &std::path::Path) -> Child {
    spawn_binary(
        std::path::Path::new(env!("CARGO_BIN_EXE_assay-engine")),
        config,
    )
}

fn spawn_binary(binary: &std::path::Path, config: &std::path::Path) -> Child {
    Command::new(binary)
        .args(["serve", "--config"])
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

async fn wait_ready(client: &reqwest::Client, child: &mut Child, port: u16) {
    use std::io::Read as _;

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(response) = client
            .get(format!(
                "http://127.0.0.1:{port}/api/v1/engine/workflow/health"
            ))
            .send()
            .await
            && response.status().is_success()
        {
            return;
        }
        if let Some(exit) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("engine exited before ready ({exit}): {stderr}");
        }
        assert!(Instant::now() < deadline, "engine did not become ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn unseal(
    client: &reqwest::Client,
    port: u16,
    shares: &[serde_json::Value],
) -> serde_json::Value {
    let mut status = serde_json::Value::Null;
    for share in shares {
        let response = client
            .post(format!("http://127.0.0.1:{port}/api/v1/vault/sys/unseal"))
            .bearer_auth("synthetic-test-key")
            .json(&serde_json::json!({ "share_b64": share }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        status = response.json().await.unwrap();
    }
    status
}

async fn fixture() -> (tempfile::TempDir, std::path::PathBuf, sqlx::SqlitePool) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
        "CREATE TABLE engine.instances (
            id TEXT PRIMARY KEY,
            started_at REAL NOT NULL DEFAULT (CAST(strftime('%s','now') AS REAL)),
            last_heartbeat REAL NOT NULL DEFAULT (CAST(strftime('%s','now') AS REAL)),
            namespaces TEXT NOT NULL DEFAULT '[]',
            version TEXT
        )",
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
async fn offline_init_requires_operator_identity_and_backup_manifest() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let result = Command::new(env!("CARGO_BIN_EXE_assay-engine"))
        .args(["vault", "init-shamir", "--config"])
        .arg(&config)
        .args(["--threshold", "3", "--shares", "5", "--shares-out"])
        .arg(&out)
        .output()
        .unwrap();

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("--operator-id"), "stderr: {stderr}");
    assert!(stderr.contains("--backup-manifest"), "stderr: {stderr}");
    assert!(!out.exists());
}

#[tokio::test]
async fn offline_init_rejects_invalid_or_mixed_generation_backup_manifest() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let manifest = write_backup_manifest(&config);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    value["sqlite_snapshot"][0]["sha256"] = serde_json::Value::String("00".repeat(32));
    value["sqlite_snapshot"][1]["generation_id"] =
        serde_json::Value::String("different-generation".into());
    std::fs::write(&manifest, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let result = authorized_command(&config, &out).output().unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("checksum") || stderr.contains("generation"),
        "stderr: {stderr}"
    );
}

#[tokio::test]
async fn offline_init_rejects_operator_not_authorized_by_backup_manifest() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let manifest = write_backup_manifest(&config);
    let result = Command::new(env!("CARGO_BIN_EXE_assay-engine"))
        .args(["vault", "init-shamir", "--config"])
        .arg(&config)
        .args(["--threshold", "3", "--shares", "5", "--shares-out"])
        .arg(&out)
        .args(["--operator-id", "intruder", "--backup-manifest"])
        .arg(manifest)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("not authorized"),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[tokio::test]
async fn offline_init_rejects_unprotected_backup_manifest() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let manifest = write_backup_manifest(&config);
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
    let result = authorized_command(&config, &out).output().unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
}

#[tokio::test]
async fn offline_init_rejects_live_database_as_its_own_rollback_snapshot() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let manifest = write_backup_manifest(&config);
    let live_engine = config.parent().unwrap().join("engine.db");
    std::fs::set_permissions(&live_engine, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    let engine_entry = value["sqlite_snapshot"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["name"] == "engine.db")
        .unwrap();
    engine_entry["path"] = serde_json::Value::String(live_engine.display().to_string());
    std::fs::write(&manifest, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let result = authorized_command(&config, &out).output().unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
}

#[tokio::test]
async fn offline_init_rejects_relative_or_non_private_share_output_parent() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let root = config.parent().unwrap();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = root.join("shares.json");
    let result = authorized_command(&config, &out).output().unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
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
    let result = authorized_command(&config, &out).output().unwrap();
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
    let repeated = authorized_command(&config, &out).output().unwrap();
    assert!(!repeated.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), before);
}

#[tokio::test]
async fn committed_transition_has_complete_non_secret_audit_receipt() {
    let (_tmp, config, pool) = fixture().await;
    let old_kid: String = sqlx::query_scalar("SELECT kid FROM vault.kek_metadata")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let manifest = write_backup_manifest(&config);
    let result = authorized_command(&config, &out).output().unwrap();
    assert!(result.status.success());

    let verify = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(config.parent().unwrap().join("vault.db"))
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let row: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        String,
        i64,
    ) = sqlx::query_as(
        "SELECT transition_id, old_kid, new_kid, old_method, new_method,
                    operator_id, backup_ref, share_threshold, share_count, outcome,
                    plaintext_backup_acknowledged
               FROM sealing_transition_audit",
    )
    .fetch_one(&verify)
    .await
    .unwrap();
    assert!(!row.0.is_empty());
    assert_eq!(row.1, old_kid);
    assert_eq!(row.2, old_kid);
    assert_eq!(row.3, "plaintext");
    assert_eq!(row.4, "shamir");
    assert_eq!(row.5, "operator-test");
    assert_eq!(row.6, manifest.display().to_string());
    assert_eq!(row.7, 3);
    assert_eq!(row.8, 5);
    assert_eq!(row.9, "committed");
    assert_eq!(row.10, 1);
    let bundle_digest: String =
        sqlx::query_scalar("SELECT bundle_digest FROM sealing_transition_audit")
            .fetch_one(&verify)
            .await
            .unwrap();
    assert_eq!(bundle_digest, sha256(&out));
}

#[tokio::test]
async fn sigkill_recovery_removes_prepared_bundle_but_retains_committed_bundle() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let killed = authorized_command(&config, &out)
        .env("ASSAY_TEST_SHAMIR_KILL_POINT", "bundle-fsynced-precommit")
        .output()
        .unwrap();
    assert!(!killed.status.success());
    assert!(out.exists());
    let prepared: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal_path(&out)).unwrap()).unwrap();
    assert_eq!(prepared["phase"], "prepared");

    let recovered = authorized_command(&config, &out).output().unwrap();
    assert!(recovered.status.success());
    let committed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal_path(&out)).unwrap()).unwrap();
    assert_eq!(committed["phase"], "committed");

    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let killed = authorized_command(&config, &out)
        .env("ASSAY_TEST_SHAMIR_KILL_POINT", "postcommit")
        .output()
        .unwrap();
    assert!(!killed.status.success());
    assert!(out.exists());
    let committed_bytes = std::fs::read(&out).unwrap();
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal_path(&out)).unwrap()).unwrap();
    assert_eq!(journal["phase"], "committed");
    let recovered = authorized_command(&config, &out).output().unwrap();
    assert!(recovered.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), committed_bytes);
}

#[tokio::test]
async fn sigkill_after_prepared_journal_before_bundle_recovers_without_orphans() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("shares.json");
    let killed = authorized_command(&config, &out)
        .env("ASSAY_TEST_SHAMIR_KILL_POINT", "journal-fsynced-prebundle")
        .output()
        .unwrap();
    assert!(!killed.status.success());
    assert!(!out.exists());
    assert!(journal_path(&out).exists());
    let recovered = authorized_command(&config, &out).output().unwrap();
    assert!(recovered.status.success());
    assert!(out.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn real_engine_restart_requires_fresh_shares_and_preserves_vault_data() {
    let (_tmp, config, pool) = fixture().await;
    let old_kek: Vec<u8> = sqlx::query_scalar("SELECT sealed_blob FROM vault.kek_metadata")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;
    let port = free_port();
    configure_server(&config, port);
    let out = config.parent().unwrap().join("shares.json");
    let result = authorized_command(&config, &out).output().unwrap();
    assert!(result.status.success());
    let cli_stdout = result.stdout;
    let cli_stderr = result.stderr;
    let bundle: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let shares = bundle["shares_b64"].as_array().unwrap();
    use base64::Engine as _;
    let mut secret_needles = vec![old_kek];
    for share in shares {
        secret_needles.push(
            base64::engine::general_purpose::STANDARD
                .decode(share.as_str().unwrap())
                .unwrap(),
        );
        secret_needles.push(share.as_str().unwrap().as_bytes().to_vec());
    }
    std::fs::remove_file(&out).unwrap();
    std::fs::remove_dir_all(config.parent().unwrap().join("rollback-baseline")).unwrap();
    let client = reqwest::Client::default();
    let base = format!("http://127.0.0.1:{port}");

    let mut engine = spawn_engine(&config);
    wait_ready(&client, &mut engine, port).await;
    let status: serde_json::Value = client
        .get(format!("{base}/api/v1/vault/sys/seal-status"))
        .bearer_auth("synthetic-test-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["sealed"], true);
    assert_eq!(status["shares_progress"], 0);
    assert_eq!(
        client
            .put(format!("{base}/api/v1/vault/kv/sentinel"))
            .bearer_auth("synthetic-test-key")
            .json(&serde_json::json!({ "data": "must-wait-for-unseal" }))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        client
            .post(format!("{base}/api/v1/vault/transit/encrypt/sentinel"))
            .bearer_auth("synthetic-test-key")
            .json(&serde_json::json!({ "plaintext_b64": "cmVqZWN0ZWQ=" }))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        client
            .get(format!("{base}/api/v1/engine/auth/admin/users"))
            .bearer_auth("synthetic-test-key")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let status = unseal(&client, port, &shares[..2]).await;
    assert_eq!(status["sealed"], true);
    assert_eq!(status["shares_progress"], 2);
    assert!(
        client
            .get(format!("{base}/api/v1/engine/workflow/health"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert_eq!(
        client
            .get(format!("{base}/api/v1/engine/auth/admin/users"))
            .bearer_auth("synthetic-test-key")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let status = unseal(&client, port, &shares[2..3]).await;
    assert_eq!(status["sealed"], false);

    let response = client
        .put(format!("{base}/api/v1/vault/kv/sentinel"))
        .bearer_auth("synthetic-test-key")
        .json(&serde_json::json!({ "data": "restart-safe-value" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(
        client
            .post(format!("{base}/api/v1/vault/transit/keys/sentinel"))
            .bearer_auth("synthetic-test-key")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let encrypted: serde_json::Value = client
        .post(format!("{base}/api/v1/vault/transit/encrypt/sentinel"))
        .bearer_auth("synthetic-test-key")
        .json(&serde_json::json!({ "plaintext_b64": "cmVzdGFydC1zYWZl" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ciphertext = encrypted["ciphertext"].as_str().unwrap().to_owned();
    engine.kill().unwrap();
    let first_output = engine.wait_with_output().unwrap();
    assert!(first_output.stdout.is_empty());

    let mut engine = spawn_engine(&config);
    wait_ready(&client, &mut engine, port).await;
    let status: serde_json::Value = client
        .get(format!("{base}/api/v1/vault/sys/seal-status"))
        .bearer_auth("synthetic-test-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["sealed"], true);
    assert_eq!(status["shares_progress"], 0);
    assert_eq!(
        client
            .get(format!("{base}/api/v1/engine/auth/admin/users"))
            .bearer_auth("synthetic-test-key")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let status = unseal(&client, port, &shares[2..5]).await;
    assert_eq!(status["sealed"], false);
    let value: serde_json::Value = client
        .get(format!("{base}/api/v1/vault/kv/sentinel"))
        .bearer_auth("synthetic-test-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value["data"], "restart-safe-value");
    let decrypted: serde_json::Value = client
        .post(format!("{base}/api/v1/vault/transit/decrypt/sentinel"))
        .bearer_auth("synthetic-test-key")
        .json(&serde_json::json!({ "ciphertext": ciphertext }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(decrypted["plaintext_b64"], "cmVzdGFydC1zYWZl");
    engine.kill().unwrap();
    let second_output = engine.wait_with_output().unwrap();
    assert!(second_output.stdout.is_empty());

    let mut observed = Vec::new();
    observed.extend_from_slice(&cli_stdout);
    observed.extend_from_slice(&cli_stderr);
    observed.extend_from_slice(&first_output.stdout);
    observed.extend_from_slice(&first_output.stderr);
    observed.extend_from_slice(&second_output.stdout);
    observed.extend_from_slice(&second_output.stderr);
    for entry in walk_files(config.parent().unwrap()) {
        observed.extend_from_slice(&std::fs::read(entry).unwrap());
    }
    for secret in secret_needles {
        assert!(
            !observed
                .windows(secret.len())
                .any(|window| window == secret),
            "secret material leaked into a log or durable artifact"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn paired_rollback_restores_baseline_binary_and_database_generation() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let port = free_port();
    configure_server(&config, port);
    let baseline_source = std::env::var_os("ASSAY_TEST_BASELINE_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_assay-engine").into());
    let client = reqwest::Client::default();
    let base = format!("http://127.0.0.1:{port}");

    let mut baseline = spawn_binary(&baseline_source, &config);
    wait_ready(&client, &mut baseline, port).await;
    let started_response = client
        .post(format!("{base}/api/v1/engine/workflow/workflows"))
        .bearer_auth("synthetic-test-key")
        .json(&serde_json::json!({
            "workflow_type": "RollbackSentinel",
            "workflow_id": "rollback-sentinel",
            "input": { "generation": "baseline" },
            "task_queue": "main"
        }))
        .send()
        .await
        .unwrap();
    let started_status = started_response.status();
    let started_text = started_response.text().await.unwrap();
    assert_eq!(started_status, 201, "body: {started_text}");
    let started: serde_json::Value = serde_json::from_str(&started_text).unwrap();
    assert_eq!(started["workflow_id"], "rollback-sentinel");
    baseline.kill().unwrap();
    baseline.wait().unwrap();

    let engine_db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(config.parent().unwrap().join("engine.db"))
                .create_if_missing(false),
        )
        .await
        .unwrap();
    sqlx::query("DELETE FROM instances")
        .execute(&engine_db)
        .await
        .unwrap();
    engine_db.close().await;

    let out = config.parent().unwrap().join("shares.json");
    let manifest_path = write_backup_manifest(&config);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let baseline_binary_backup =
        std::path::PathBuf::from(manifest["baseline_binary"]["path"].as_str().unwrap());
    let transition = authorized_command(&config, &out).output().unwrap();
    assert!(transition.status.success());
    let share_bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    use base64::Engine as _;
    let mut share_needles = Vec::new();
    for share in share_bundle["shares_b64"].as_array().unwrap() {
        share_needles.push(share.as_str().unwrap().as_bytes().to_vec());
        share_needles.push(
            base64::engine::general_purpose::STANDARD
                .decode(share.as_str().unwrap())
                .unwrap(),
        );
    }

    for database in manifest["sqlite_snapshot"].as_array().unwrap() {
        let name = database["name"].as_str().unwrap();
        let snapshot = std::path::PathBuf::from(database["path"].as_str().unwrap());
        std::fs::copy(snapshot, config.parent().unwrap().join(name)).unwrap();
    }
    for entry in std::fs::read_dir(config.parent().unwrap()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if name.ends_with("-wal") || name.ends_with("-shm") {
            std::fs::remove_file(path).unwrap();
        }
    }

    let restored_binary = config.parent().unwrap().join("restored-assay-engine");
    std::fs::copy(&baseline_binary_backup, &restored_binary).unwrap();
    std::fs::set_permissions(&restored_binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut restored = spawn_binary(&restored_binary, &config);
    wait_ready(&client, &mut restored, port).await;
    let sentinel: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/engine/workflow/workflows/rollback-sentinel"
        ))
        .bearer_auth("synthetic-test-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sentinel["id"], "rollback-sentinel");
    restored.kill().unwrap();
    restored.wait().unwrap();
    std::fs::remove_file(restored_binary).unwrap();
    std::fs::remove_file(&out).unwrap();
    std::fs::remove_file(journal_path(&out)).unwrap();
    std::fs::remove_file(transition_completion_path_for_test(&out)).unwrap();
    std::fs::remove_dir_all(config.parent().unwrap().join("rollback-baseline")).unwrap();
    let mut remaining = Vec::new();
    for path in walk_files(config.parent().unwrap()) {
        remaining.extend_from_slice(&std::fs::read(path).unwrap());
    }
    for share in share_needles {
        assert!(
            !remaining.windows(share.len()).any(|window| window == share),
            "share material remained after rollback staging cleanup"
        );
    }
}

fn transition_completion_path_for_test(out: &std::path::Path) -> std::path::PathBuf {
    let mut value = out.as_os_str().to_os_string();
    value.push(".transition.complete");
    value.into()
}

fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    files
}

#[tokio::test]
async fn offline_init_rolls_back_when_bundle_cannot_be_created() {
    let (_tmp, config, pool) = fixture().await;
    let out = config.parent().unwrap().join("occupied.json");
    std::fs::write(&out, b"sentinel").unwrap();
    pool.close().await;
    let result = authorized_command(&config, &out).output().unwrap();
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
    let result = authorized_command(&config, &out).output().unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
}

#[tokio::test]
async fn injected_failures_rollback_before_commit_and_retain_bundle_after_commit() {
    for point in ["after-update", "after-write"] {
        let (_tmp, config, pool) = fixture().await;
        pool.close().await;
        let out = config.parent().unwrap().join(format!("{point}.json"));
        let result = authorized_command(&config, &out)
            .env("ASSAY_TEST_SHAMIR_FAIL_POINT", point)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!out.exists());
        assert!(!journal_path(&out).exists());
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

    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let out = config.parent().unwrap().join("after-commit.json");
    let result = authorized_command(&config, &out)
        .env("ASSAY_TEST_SHAMIR_FAIL_POINT", "after-commit")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        out.exists(),
        "committed transition must retain its share bundle"
    );
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
    assert_eq!(method, "shamir");
}

#[tokio::test]
async fn offline_init_refuses_process_lifetime_lock_even_without_heartbeat() {
    let (_tmp, config, pool) = fixture().await;
    pool.close().await;
    let _lock = assay_engine::process_lock::ProcessLock::acquire(config.parent().unwrap()).unwrap();
    let out = config.parent().unwrap().join("locked.json");
    let result = authorized_command(&config, &out).output().unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("process holds"));
}
