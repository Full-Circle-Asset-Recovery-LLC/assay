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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    version: u8,
    generation_id: String,
    authorized_operator_ids: Vec<String>,
    plaintext_kek_backup_acknowledged: bool,
    baseline_binary: BackupArtifact,
    sqlite_snapshot: Vec<BackupDatabase>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupArtifact {
    path: PathBuf,
    sha256: String,
    generation_id: String,
    version: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupDatabase {
    name: String,
    path: PathBuf,
    sha256: String,
    generation_id: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionJournal {
    version: u8,
    transition_id: String,
    phase: String,
    old_kid: String,
    new_kid: String,
    operator_id: String,
    backup_ref: String,
    bundle_digest: String,
    share_threshold: u8,
    share_count: u8,
}

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
        /// Stable identity of the operator authorizing the offline transition.
        #[arg(long)]
        operator_id: String,
        /// Checksummed rollback manifest for the baseline binary and SQLite snapshot.
        #[arg(long)]
        backup_manifest: PathBuf,
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
                    operator_id,
                    backup_manifest,
                },
        } => match offline_init_shamir(
            &config,
            threshold,
            shares,
            &shares_out,
            &operator_id,
            &backup_manifest,
        )
        .await
        {
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
    operator_id: &str,
    backup_manifest: &std::path::Path,
) -> anyhow::Result<String> {
    use anyhow::Context;
    use assay_engine::BackendConfig;
    use assay_vault::crypto::sealing::shamir::split_kek;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    #[cfg(debug_assertions)]
    let injected_failure = std::env::var("ASSAY_TEST_SHAMIR_FAIL_POINT").ok();
    #[cfg(not(debug_assertions))]
    let injected_failure: Option<String> = None;

    if (threshold, shares_count) != (3, 5) {
        anyhow::bail!("first-release Shamir initialization requires --threshold 3 --shares 5");
    }
    if operator_id.trim().is_empty() {
        anyhow::bail!("--operator-id must be non-empty");
    }
    if !backup_manifest.is_file() {
        anyhow::bail!("--backup-manifest must identify a readable manifest file");
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
    let data_dir_path = std::path::Path::new(&data_dir);
    validate_share_output(shares_out)?;
    let recovery_journal = read_transition_journal(shares_out)?;
    validate_backup_manifest(
        backup_manifest,
        data_dir_path,
        operator_id,
        recovery_journal.is_none(),
    )?;
    let _process_lock = assay_engine::process_lock::ProcessLock::acquire(data_dir_path)?;
    let engine_path = data_dir_path.join("engine.db");
    let vault_path = data_dir_path.join("vault.db");
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let engine_path = engine_path.clone();
            let vault_path = vault_path.clone();
            Box::pin(async move {
                let engine_uri = format!("file:{}?mode=rw", engine_path.display());
                let vault_uri = format!("file:{}?mode=rw", vault_path.display());
                sqlx::query("ATTACH DATABASE ? AS engine")
                    .bind(engine_uri)
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("ATTACH DATABASE ? AS vault")
                    .bind(vault_uri)
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(opts)
        .await
        .context("open isolated SQLite vault")?;
    let mut conn = pool.acquire().await?;
    if let Some(mut journal) = recovery_journal {
        validate_recovery_journal(&journal, shares_out, operator_id, backup_manifest)?;
        let active: (String, String) =
            sqlx::query_as("SELECT kid, sealing_method FROM vault.kek_metadata")
                .fetch_one(&mut *conn)
                .await
                .context("inspect interrupted Shamir transition")?;
        match (journal.phase.as_str(), active.1.as_str()) {
            ("prepared", "plaintext") => {
                if shares_out.exists() {
                    std::fs::remove_file(shares_out)
                        .context("remove orphan prepared share bundle")?;
                }
                std::fs::remove_file(transition_journal_path(shares_out))
                    .context("remove orphan prepared transition journal")?;
                validate_backup_manifest(backup_manifest, data_dir_path, operator_id, true)?;
            }
            ("prepared", "shamir") => {
                if active.0 != journal.new_kid {
                    anyhow::bail!("prepared journal does not match committed vault KEK");
                }
                journal.phase = "committed".into();
                write_transition_journal(shares_out, &journal, false)?;
                write_transition_completion(shares_out)?;
                return Ok(active.0);
            }
            ("committed", "shamir") => {
                if active.0 != journal.new_kid {
                    anyhow::bail!("committed journal does not match active vault KEK");
                }
                if transition_completion_path(shares_out).exists() {
                    anyhow::bail!("Shamir transition is already complete");
                }
                write_transition_completion(shares_out)?;
                return Ok(active.0);
            }
            _ => anyhow::bail!("transition journal and vault state are inconsistent"),
        }
    }
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut *conn)
        .await
        .context("acquire exclusive SQLite vault transaction")?;

    let result: anyhow::Result<(String, Vec<Vec<u8>>, String)> = async {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let live: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM engine.instances WHERE last_heartbeat >= ?")
                .bind(now - 60.0)
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
        let old_kid = kid.clone();
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
        Ok((kid, bytes, old_kid))
    }
    .await;

    let (kid, mut share_bytes, old_kid) = match result {
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
    let bundle_digest = sha256_bytes(&bundle);
    let transition_id = uuid::Uuid::now_v7().to_string();
    let mut journal = TransitionJournal {
        version: 1,
        transition_id: transition_id.clone(),
        phase: "prepared".into(),
        old_kid,
        new_kid: kid.clone(),
        operator_id: operator_id.to_owned(),
        backup_ref: backup_manifest.display().to_string(),
        bundle_digest: bundle_digest.clone(),
        share_threshold: threshold,
        share_count: shares_count,
    };
    let mut created_output = false;
    let file_result = (|| -> anyhow::Result<()> {
        write_transition_journal(shares_out, &journal, true)?;
        #[cfg(debug_assertions)]
        maybe_sigkill("journal-fsynced-prebundle");
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
        let _ = std::fs::remove_file(transition_journal_path(shares_out));
        return Err(e);
    }
    if injected_failure.as_deref() == Some("after-write") {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        if created_output {
            let _ = std::fs::remove_file(shares_out);
        }
        let _ = std::fs::remove_file(transition_journal_path(shares_out));
        anyhow::bail!("injected failure after bundle write");
    }
    #[cfg(debug_assertions)]
    maybe_sigkill("bundle-fsynced-precommit");
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS vault.sealing_transition_audit (
            transition_id TEXT PRIMARY KEY,
            old_kid TEXT NOT NULL,
            new_kid TEXT NOT NULL,
            old_method TEXT NOT NULL,
            new_method TEXT NOT NULL,
            operator_id TEXT NOT NULL,
            backup_ref TEXT NOT NULL,
            bundle_digest TEXT NOT NULL,
            share_threshold INTEGER NOT NULL,
            share_count INTEGER NOT NULL,
            plaintext_backup_acknowledged INTEGER NOT NULL,
            outcome TEXT NOT NULL,
            created_at REAL NOT NULL
        )",
    )
    .execute(&mut *conn)
    .await
    .context("create transition audit table")?;
    sqlx::query(
        "INSERT INTO vault.sealing_transition_audit
            (transition_id, old_kid, new_kid, old_method, new_method, operator_id,
             backup_ref, bundle_digest, share_threshold, share_count,
             plaintext_backup_acknowledged, outcome, created_at)
         VALUES (?, ?, ?, 'plaintext', 'shamir', ?, ?, ?, ?, ?, 1, 'committed', ?)",
    )
    .bind(&transition_id)
    .bind(&journal.old_kid)
    .bind(&journal.new_kid)
    .bind(operator_id)
    .bind(backup_manifest.display().to_string())
    .bind(&bundle_digest)
    .bind(i64::from(threshold))
    .bind(i64::from(shares_count))
    .bind(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
    )
    .execute(&mut *conn)
    .await
    .context("write transition audit receipt")?;
    if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
        let _ = std::fs::remove_file(shares_out);
        let _ = std::fs::remove_file(transition_journal_path(shares_out));
        return Err(anyhow::anyhow!("commit Shamir transition: {e}"));
    }
    journal.phase = "committed".into();
    write_transition_journal(shares_out, &journal, false)?;
    #[cfg(debug_assertions)]
    maybe_sigkill("postcommit");
    write_transition_completion(shares_out)?;
    if injected_failure.as_deref() == Some("after-commit") {
        anyhow::bail!("injected failure after committed Shamir transition");
    }
    Ok(kid)
}

fn transition_journal_path(shares_out: &std::path::Path) -> PathBuf {
    let mut value = shares_out.as_os_str().to_os_string();
    value.push(".transition.json");
    value.into()
}

fn transition_completion_path(shares_out: &std::path::Path) -> PathBuf {
    let mut value = shares_out.as_os_str().to_os_string();
    value.push(".transition.complete");
    value.into()
}

fn write_transition_completion(shares_out: &std::path::Path) -> anyhow::Result<()> {
    let path = transition_completion_path(shares_out);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(&path)?;
    file.sync_all()?;
    std::fs::File::open(path.parent().expect("completion marker has parent"))?.sync_all()?;
    Ok(())
}

fn read_transition_journal(
    shares_out: &std::path::Path,
) -> anyhow::Result<Option<TransitionJournal>> {
    let path = transition_journal_path(shares_out);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|error| {
            anyhow::anyhow!("parse transition recovery journal: {error}")
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn validate_recovery_journal(
    journal: &TransitionJournal,
    shares_out: &std::path::Path,
    operator_id: &str,
    backup_manifest: &std::path::Path,
) -> anyhow::Result<()> {
    if journal.version != 1
        || !matches!(journal.phase.as_str(), "prepared" | "committed")
        || journal.operator_id != operator_id
        || journal.backup_ref != backup_manifest.display().to_string()
        || journal.share_threshold != 3
        || journal.share_count != 5
    {
        anyhow::bail!("transition recovery journal does not match this operation");
    }
    match std::fs::read(shares_out) {
        Ok(bytes) => {
            if sha256_bytes(&bytes) != journal.bundle_digest {
                anyhow::bail!("transition share bundle checksum mismatch");
            }
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound && journal.phase == "prepared" => {}
        Err(error) => return Err(anyhow::anyhow!("read transition share bundle: {error}")),
    }
    Ok(())
}

fn write_transition_journal(
    shares_out: &std::path::Path,
    journal: &TransitionJournal,
    create_new: bool,
) -> anyhow::Result<()> {
    let path = transition_journal_path(shares_out);
    if create_new && path.exists() {
        anyhow::bail!("transition recovery journal already exists");
    }
    let mut temporary_name = path.as_os_str().to_os_string();
    temporary_name.push(format!(".{}.tmp", journal.transition_id));
    let temporary_path = PathBuf::from(temporary_name);
    let bytes = serde_json::to_vec_pretty(journal)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary_path, &path)?;
    std::fs::File::open(path.parent().expect("journal has parent"))?.sync_all()?;
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(debug_assertions)]
fn maybe_sigkill(point: &str) {
    if std::env::var("ASSAY_TEST_SHAMIR_KILL_POINT").as_deref() == Ok(point) {
        // SAFETY: sending SIGKILL to our own PID is intentional in the
        // subprocess-only crash-recovery tests and cannot affect another process.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
    }
}

fn validate_share_output(shares_out: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    if !shares_out.is_absolute() {
        anyhow::bail!("--shares-out must be an absolute canonical path");
    }
    let parent = shares_out
        .parent()
        .ok_or_else(|| anyhow::anyhow!("--shares-out has no parent directory"))?;
    let canonical_parent = parent
        .canonicalize()
        .context("canonicalize shares-out parent")?;
    if canonical_parent != parent {
        anyhow::bail!("--shares-out parent must not contain symlinks or traversal");
    }
    let metadata = std::fs::symlink_metadata(parent).context("inspect shares-out parent")?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("--shares-out parent must be a real directory");
    }
    #[cfg(unix)]
    {
        let operator_uid = std::fs::metadata("/proc/self")?.uid();
        if metadata.uid() != operator_uid {
            anyhow::bail!("--shares-out parent must be owned by the operator");
        }
        if metadata.mode() & 0o077 != 0 {
            anyhow::bail!("--shares-out parent must be private (mode 0700 or stricter)");
        }
    }
    Ok(())
}

fn validate_backup_manifest(
    manifest_path: &std::path::Path,
    data_dir: &std::path::Path,
    operator_id: &str,
    require_live_match: bool,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};

    fn digest_file(path: &std::path::Path) -> anyhow::Result<String> {
        use std::fmt::Write as _;
        use std::io::Read as _;
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let mut encoded = String::with_capacity(64);
        for byte in hasher.finalize() {
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(encoded)
    }

    if !manifest_path.is_absolute() {
        anyhow::bail!("--backup-manifest must be an absolute path");
    }
    let canonical_manifest = manifest_path
        .canonicalize()
        .context("canonicalize backup manifest")?;
    if canonical_manifest != manifest_path {
        anyhow::bail!("--backup-manifest must be canonical and must not be a symlink");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(manifest_path)?;
        let operator_uid = std::fs::metadata("/proc/self")?.uid();
        if metadata.uid() != operator_uid || metadata.mode() & 0o077 != 0 {
            anyhow::bail!("--backup-manifest must be operator-owned and private");
        }
    }
    let bytes = std::fs::read(manifest_path).context("read backup manifest")?;
    let manifest: BackupManifest =
        serde_json::from_slice(&bytes).context("parse backup manifest")?;
    if manifest.version != 1 || manifest.generation_id.trim().is_empty() {
        anyhow::bail!("unsupported or incomplete backup manifest");
    }
    if !manifest.plaintext_kek_backup_acknowledged {
        anyhow::bail!(
            "operator must acknowledge that the rollback snapshot contains the plaintext KEK"
        );
    }
    if !manifest
        .authorized_operator_ids
        .iter()
        .any(|authorized| authorized == operator_id)
    {
        anyhow::bail!("operator is not authorized by the backup manifest");
    }
    if manifest.baseline_binary.generation_id != manifest.generation_id {
        anyhow::bail!("baseline binary and database snapshot generations do not match");
    }
    validate_private_backup_artifact(&manifest.baseline_binary.path, "baseline binary")?;
    if digest_file(&manifest.baseline_binary.path)? != manifest.baseline_binary.sha256 {
        anyhow::bail!("baseline binary checksum mismatch");
    }
    if manifest.baseline_binary.version != env!("CARGO_PKG_VERSION") {
        anyhow::bail!("baseline binary version does not match this transition");
    }

    let mut entries = BTreeMap::new();
    for database in manifest.sqlite_snapshot {
        if database.generation_id != manifest.generation_id {
            anyhow::bail!("mixed database generations in backup manifest");
        }
        if database.path.file_name().and_then(|name| name.to_str()) != Some(&database.name) {
            anyhow::bail!("backup database name does not match its path");
        }
        if database.path.canonicalize()? == data_dir.join(&database.name).canonicalize()? {
            anyhow::bail!("live database cannot serve as its own rollback snapshot");
        }
        validate_private_backup_artifact(&database.path, "backup database")?;
        if digest_file(&database.path)? != database.sha256 {
            anyhow::bail!("backup database checksum mismatch for {}", database.name);
        }
        if entries.insert(database.name, database.path).is_some() {
            anyhow::bail!("duplicate database in backup manifest");
        }
    }
    let live_names = std::fs::read_dir(data_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("db"))
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<BTreeSet<_>>();
    let backup_names = entries.keys().cloned().collect::<BTreeSet<_>>();
    if live_names != backup_names
        || !live_names.contains("engine.db")
        || !live_names.contains("vault.db")
    {
        anyhow::bail!("backup manifest is not a complete SQLite snapshot");
    }
    if require_live_match {
        for (name, snapshot_path) in entries {
            if digest_file(&data_dir.join(&name))? != digest_file(&snapshot_path)? {
                anyhow::bail!("backup snapshot does not match live database generation for {name}");
            }
        }
    }
    Ok(())
}

fn validate_private_backup_artifact(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute()
        || path
            .canonicalize()
            .with_context(|| format!("canonicalize {label}"))?
            != path
    {
        anyhow::bail!("{label} must be an absolute canonical non-symlink path");
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!("{label} must be a regular file");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    #[cfg(unix)]
    {
        let operator_uid = std::fs::metadata("/proc/self")?.uid();
        if metadata.uid() != operator_uid || metadata.mode() & 0o077 != 0 {
            anyhow::bail!("{label} must be operator-owned and mode 0600 or stricter");
        }
        if parent_metadata.uid() != operator_uid || parent_metadata.mode() & 0o077 != 0 {
            anyhow::bail!("{label} parent must be operator-owned and mode 0700 or stricter");
        }
    }
    Ok(())
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
