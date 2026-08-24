//! Standalone assay-engine binary.
//!
//! Loads a TOML config, connects to the backend, runs migrations via
//! `{Postgres,Sqlite}Store::new` (which migrate on first connect), and
//! serves the composed router on the configured port.
//!
//! First-time setup is done from the assay-lua client — see
//! `examples/init/init.lua` for the canonical bootstrap script that
//! seeds Zanzibar namespaces, creates the admin user, and writes the
//! operator-grant tuples in one shot using `auth.admin_api_keys` as
//! the break-glass.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Parser, Debug)]
#[command(name = "assay-engine", version, about = "Assay workflow + auth engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Run the HTTP server from a TOML config file.
    Serve {
        /// Path to the TOML config file.
        #[arg(long, short, env = "ASSAY_ENGINE_CONFIG")]
        config: PathBuf,
    },
    /// Offline vault administration.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
enum VaultCommand {
    /// Replace the sole plaintext KEK in an empty SQLite vault with Shamir 3-of-5 sealing.
    InitShamir {
        #[arg(long, short, env = "ASSAY_ENGINE_CONFIG")]
        config: PathBuf,
        #[arg(long)]
        threshold: u8,
        #[arg(long)]
        shares: u8,
        #[arg(long)]
        shares_out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config } => {
            let cfg = match assay_engine::EngineConfig::from_file(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e:#}");
                    return ExitCode::from(2);
                }
            };
            init_tracing(&cfg.logging.level, &cfg.logging.format);
            if let Err(e) = assay_engine::run(cfg).await {
                eprintln!("engine error: {e:#}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Command::Vault {
            command:
                VaultCommand::InitShamir {
                    config,
                    threshold,
                    shares,
                    shares_out,
                },
        } => match offline_init_shamir(&config, threshold, shares, &shares_out).await {
            Ok(kid) => {
                println!(
                    "shamir initialized: path={} shares={} kid={}",
                    shares_out.display(),
                    shares,
                    kid
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("vault init-shamir error: {e:#}");
                ExitCode::from(1)
            }
        },
    }
}

async fn offline_init_shamir(
    config_path: &std::path::Path,
    threshold: u8,
    shares_count: u8,
    shares_out: &std::path::Path,
) -> anyhow::Result<String> {
    use anyhow::Context;
    use assay_engine::BackendConfig;
    use assay_vault::crypto::sealing::shamir::split_kek;
    use sqlx::Executor;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    #[cfg(debug_assertions)]
    let injected_failure = std::env::var("ASSAY_TEST_SHAMIR_FAIL_POINT").ok();
    #[cfg(not(debug_assertions))]
    let injected_failure: Option<String> = None;

    if (threshold, shares_count) != (3, 5) {
        anyhow::bail!("first-release Shamir initialization requires --threshold 3 --shares 5");
    }
    let cfg = assay_engine::EngineConfig::from_file(config_path)?;
    let data_dir = match cfg.backend {
        BackendConfig::Sqlite { .. } => cfg
            .backend
            .sqlite_data_dir()
            .ok_or_else(|| anyhow::anyhow!("SQLite data directory missing"))?,
        BackendConfig::Postgres { .. } => {
            anyhow::bail!("offline Shamir initialization supports SQLite only; Postgres is refused")
        }
        _ => anyhow::bail!("backend not supported by offline Shamir initialization"),
    };
    if data_dir == ":memory:" {
        anyhow::bail!("offline Shamir initialization requires persistent SQLite files");
    }
    let _process_lock =
        assay_engine::process_lock::ProcessLock::acquire(std::path::Path::new(&data_dir))?;
    let engine_path = std::path::Path::new(&data_dir).join("engine.db");
    let vault_path = std::path::Path::new(&data_dir).join("vault.db");
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let engine_path = engine_path.clone();
            let vault_path = vault_path.clone();
            Box::pin(async move {
                conn.execute(
                    format!(
                        "ATTACH DATABASE 'file:{}?mode=rw' AS engine",
                        engine_path.display()
                    )
                    .as_str(),
                )
                .await?;
                conn.execute(
                    format!(
                        "ATTACH DATABASE 'file:{}?mode=rw' AS vault",
                        vault_path.display()
                    )
                    .as_str(),
                )
                .await?;
                Ok(())
            })
        })
        .connect_with(opts)
        .await
        .context("open isolated SQLite vault")?;
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut *conn)
        .await
        .context("acquire exclusive SQLite vault transaction")?;

    let result: anyhow::Result<(String, Vec<Vec<u8>>)> = async {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let live: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM engine.instances WHERE last_heartbeat >= ?")
                .bind(now - 10.0)
                .fetch_one(&mut *conn)
                .await
                .with_context(|| format!("check live engine instances in {data_dir}"))?;
        if live != 0 {
            anyhow::bail!("a live engine instance is registered; stop it before offline migration");
        }
        let operational: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM vault.kv_meta) +
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
        .context("check operational vault emptiness")?;
        if operational != 0 {
            anyhow::bail!("offline Shamir initialization requires an operationally empty vault");
        }
        let rows: Vec<(String, String, Vec<u8>)> =
            sqlx::query_as("SELECT kid, sealing_method, sealed_blob FROM vault.kek_metadata")
                .fetch_all(&mut *conn)
                .await?;
        if rows.len() != 1 || rows[0].1 != "plaintext" || rows[0].2.len() != 32 {
            anyhow::bail!("expected exactly one valid plaintext KEK source row");
        }
        let (kid, _, mut blob) = rows.into_iter().next().expect("one row checked above");
        let mut key = [0u8; 32];
        key.copy_from_slice(&blob);
        blob.fill(0);
        let digest = assay_vault::crypto::kek_store::full_kek_digest(&key);
        let mut shares = split_kek(&key, threshold, shares_count)
            .map_err(|e| anyhow::anyhow!("split KEK: {e}"))?;
        key.fill(0);

        sqlx::query(
            "UPDATE vault.kek_metadata
                SET sealing_method='shamir', sealed=1, sealed_blob=x'', kek_digest=?,
                    share_threshold=3, share_count=5, sealed_at=?, unsealed_at=NULL
              WHERE kid=? AND sealing_method='plaintext'",
        )
        .bind(digest.as_slice())
        .bind(now)
        .bind(&kid)
        .execute(&mut *conn)
        .await
        .context("stage Shamir metadata transition")?;
        let bytes = shares.iter().map(|s| s.0.clone()).collect::<Vec<_>>();
        for share in &mut shares {
            share.0.fill(0);
        }
        if injected_failure.as_deref() == Some("after-update") {
            let mut bytes = bytes;
            for share in &mut bytes {
                share.fill(0);
            }
            anyhow::bail!("injected failure after metadata update");
        }
        Ok((kid, bytes))
    }
    .await;

    let (kid, mut share_bytes) = match result {
        Ok(value) => value,
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(e);
        }
    };
    let mut encoded = share_bytes
        .iter()
        .map(|s| assay_vault::crypto::sealing::shamir::encode_share_base64(s))
        .collect::<Vec<_>>();
    #[derive(serde::Serialize)]
    struct ShareBundle<'a> {
        version: u8,
        kid: &'a str,
        threshold: u8,
        shares_count: u8,
        shares_b64: &'a [String],
    }
    let mut bundle = serde_json::to_vec_pretty(&ShareBundle {
        version: 1,
        kid: &kid,
        threshold,
        shares_count,
        shares_b64: &encoded,
    })?;
    let mut created_output = false;
    let file_result = (|| -> anyhow::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(shares_out)
            .context("create shares-out exclusively")?;
        created_output = true;
        file.write_all(&bundle)?;
        file.sync_all()?;
        if let Some(parent) = shares_out.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    for share in &mut share_bytes {
        share.fill(0);
    }
    for value in &mut encoded {
        let len = value.len();
        value.clear();
        value.extend(std::iter::repeat_n('\0', len));
    }
    bundle.fill(0);
    if let Err(e) = file_result {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        if created_output {
            let _ = std::fs::remove_file(shares_out);
        }
        return Err(e);
    }
    if injected_failure.as_deref() == Some("after-write") {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        if created_output {
            let _ = std::fs::remove_file(shares_out);
        }
        anyhow::bail!("injected failure after bundle write");
    }
    if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
        let _ = std::fs::remove_file(shares_out);
        return Err(anyhow::anyhow!("commit Shamir transition: {e}"));
    }
    if injected_failure.as_deref() == Some("after-commit") {
        anyhow::bail!("injected failure after committed Shamir transition");
    }
    Ok(kid)
}

fn init_tracing(level: &str, format: &str) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let builder = fmt().with_env_filter(filter);
    match format {
        "json" => builder.json().init(),
        _ => builder.init(),
    }
}
