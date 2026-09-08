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

const TRUSTED_BASELINE_VERSION: &str = "0.5.15";
const TRUSTED_BASELINE_SOURCE_COMMIT: &str = "3977f552391917874589530d0d23094559e68e29";

fn trusted_baseline_sha256() -> anyhow::Result<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok("eebe897ff3868fce51724931b98cff9e09c241294ed3dc46a3d8e8813a68657a")
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok("b58bd08fa25626d4fce2758d2e871dce4027c5f238d374e040d7ac164a33e7a0")
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        anyhow::bail!(
            "offline Shamir initialization has no trusted v0.5.15 baseline for this target"
        )
    }
}

#[cfg(unix)]
fn current_uid() -> libc::uid_t {
    // SAFETY: geteuid reads process credentials and has no preconditions.
    unsafe { libc::geteuid() }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    version: u8,
    generation_id: String,
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
    source_commit: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupDatabase {
    name: String,
    path: PathBuf,
    sha256: String,
    generation_id: String,
}

#[derive(Clone)]
struct BackupReceipt {
    manifest_digest: String,
    generation: String,
    baseline_binary_digest: String,
    database_artifact_digests: String,
}

struct PreparedShares {
    kid: String,
    shares: zeroize::Zeroizing<Vec<Vec<u8>>>,
    old_kid: String,
    schema_migrated: bool,
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
    manifest_digest: String,
    backup_generation: String,
    baseline_binary_digest: String,
    database_artifact_digests: String,
    bundle_digest: String,
    share_threshold: u8,
    share_count: u8,
    #[serde(default)]
    schema_migrated: bool,
}

#[derive(sqlx::FromRow)]
struct TransitionAuditRow {
    transition_id: String,
    old_kid: String,
    new_kid: String,
    operator_id: String,
    backup_ref: String,
    manifest_digest: String,
    backup_generation: String,
    baseline_binary_digest: String,
    database_artifact_digests: String,
    bundle_digest: String,
    share_threshold: i64,
    share_count: i64,
    plaintext_backup_acknowledged: i64,
    outcome: String,
    schema_migrated: i64,
}

#[cfg(unix)]
struct AnchoredOutput {
    dir: std::fs::File,
    bundle: std::ffi::CString,
    journal: std::ffi::CString,
    completion: std::ffi::CString,
}

#[cfg(unix)]
impl AnchoredOutput {
    fn open(shares_out: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        validate_share_output_parent(shares_out)?;
        let parent = shares_out.parent().expect("validated parent");
        let parent_c = std::ffi::CString::new(parent.as_os_str().as_bytes())?;
        // SAFETY: parent_c is NUL-terminated and flags request an owned directory fd.
        let fd = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fd was just returned by open and ownership transfers to File.
        let dir = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: held fd is valid and stat points to writable memory.
        if unsafe { libc::fstat(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("inspect opened shares-out parent");
        }
        // SAFETY: fstat succeeded.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o077 != 0
        {
            anyhow::bail!("opened shares-out parent must be operator-owned mode 0700 or stricter");
        }
        let bundle_os = shares_out.file_name().expect("validated filename");
        let bundle = std::ffi::CString::new(bundle_os.as_bytes())?;
        let mut journal_os = bundle_os.to_os_string();
        journal_os.push(".transition.json");
        let journal = std::ffi::CString::new(journal_os.as_bytes())?;
        let mut completion_os = bundle_os.to_os_string();
        completion_os.push(".transition.complete");
        let completion = std::ffi::CString::new(completion_os.as_bytes())?;
        Ok(Self {
            dir,
            bundle,
            journal,
            completion,
        })
    }

    fn exists(&self, name: &std::ffi::CStr) -> anyhow::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: dir fd and name are valid; stat points to writable memory.
        let result = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error.into())
        }
    }

    fn read(&self, name: &std::ffi::CStr) -> anyhow::Result<Vec<u8>> {
        use std::io::Read as _;
        use std::os::fd::{AsRawFd, FromRawFd};
        // SAFETY: dir fd and name are valid; returned fd is owned below.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fd is newly owned by this call.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn write_new(&self, name: &std::ffi::CStr, bytes: &[u8]) -> anyhow::Result<()> {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd, FromRawFd};
        // SAFETY: dir fd and name are valid; O_EXCL + O_NOFOLLOW prevent replacement/following.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fd is newly owned by this call.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.sync_all()?;
        self.dir.sync_all()?;
        Ok(())
    }

    fn remove(&self, name: &std::ffi::CStr, missing_ok: bool) -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: dir fd and name are valid and unlinkat stays beneath the held dir.
        let result = unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            self.dir.sync_all()?;
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if missing_ok && error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error.into())
        }
    }

    fn atomic_write(
        &self,
        target: &std::ffi::CStr,
        bytes: &[u8],
        unique: &str,
        create_new: bool,
    ) -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        let mut temp = target.to_bytes().to_vec();
        temp.extend_from_slice(format!(".{unique}.tmp").as_bytes());
        let temp = std::ffi::CString::new(temp)?;
        if create_new && self.exists(target)? {
            anyhow::bail!("anchored output already exists");
        }
        self.write_new(&temp, bytes)?;
        // SAFETY: both names are relative to the same held directory fd.
        let result = unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                temp.as_ptr(),
                self.dir.as_raw_fd(),
                target.as_ptr(),
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            let _ = self.remove(&temp, true);
            return Err(error.into());
        }
        self.dir.sync_all()?;
        Ok(())
    }

    fn validate_private_bundle(&self) -> anyhow::Result<Vec<u8>> {
        use std::os::fd::AsRawFd;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: dir fd, name and output pointer are valid.
        let result = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                self.bundle.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fstatat succeeded and initialized stat.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o077 != 0
        {
            anyhow::bail!("share bundle is not an operator-owned private regular file");
        }
        self.read(&self.bundle)
    }
}

#[cfg(not(unix))]
struct AnchoredOutput {
    bundle: std::ffi::CString,
    journal: std::ffi::CString,
    completion: std::ffi::CString,
}

#[cfg(not(unix))]
impl AnchoredOutput {
    fn open(_: &std::path::Path) -> anyhow::Result<Self> {
        anyhow::bail!("offline Shamir initialization requires Unix dirfd safety primitives")
    }
    fn exists(&self, _: &std::ffi::CStr) -> anyhow::Result<bool> {
        anyhow::bail!("offline Shamir initialization is unavailable on this platform")
    }
    fn read(&self, _: &std::ffi::CStr) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("offline Shamir initialization is unavailable on this platform")
    }
    fn write_new(&self, _: &std::ffi::CStr, _: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("offline Shamir initialization is unavailable on this platform")
    }
    fn remove(&self, _: &std::ffi::CStr, _: bool) -> anyhow::Result<()> {
        anyhow::bail!("offline Shamir initialization is unavailable on this platform")
    }
    fn atomic_write(&self, _: &std::ffi::CStr, _: &[u8], _: &str, _: bool) -> anyhow::Result<()> {
        anyhow::bail!("offline Shamir initialization is unavailable on this platform")
    }
    fn validate_private_bundle(&self) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("offline Shamir initialization is unavailable on this platform")
    }
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
    /// Copy a stopped SQLite store into an empty Postgres one.
    #[cfg(all(feature = "backend-postgres", feature = "backend-sqlite"))]
    Migrate {
        /// SQLite data directory, as `sqlite:<dir>` or a bare path.
        #[arg(long)]
        from: String,
        /// Target Postgres URL, holding no engine data.
        #[arg(long)]
        to: String,
        /// Print the plan and row counts; write nothing.
        #[arg(long)]
        dry_run: bool,
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
        #[cfg(all(feature = "backend-postgres", feature = "backend-sqlite"))]
        Command::Migrate { from, to, dry_run } => migrate(&from, &to, dry_run).await,
    }
}

#[cfg(all(feature = "backend-postgres", feature = "backend-sqlite"))]
async fn migrate(from: &str, to: &str, dry_run: bool) -> ExitCode {
    use assay_engine::migrate::{Plan, parse_source, parse_target};

    // The report is the output; sqlx logs every `IF NOT EXISTS` notice
    // the schema bootstrap raises, which is noise around it.
    init_tracing("info,sqlx=warn", "pretty");
    let plan = match (parse_source(from), parse_target(to)) {
        (Ok(source_dir), Ok(target_url)) => Plan {
            source_dir,
            target_url,
            dry_run,
        },
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("migrate: {e:#}");
            return ExitCode::from(2);
        }
    };
    match assay_engine::migrate::run(plan).await {
        Ok(report) => {
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("migrate failed: {e:#}");
            ExitCode::from(1)
        }
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
    use zeroize::Zeroizing;

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
    let trusted_operator_id = trusted_operator_id()?;
    if operator_id != trusted_operator_id {
        anyhow::bail!("--operator-id does not match the OS operator identity");
    }
    let operator_id = trusted_operator_id.as_str();
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
    let configured_data_dir = std::path::Path::new(&data_dir);
    let _process_lock = assay_engine::process_lock::ProcessLock::acquire(configured_data_dir)?;
    let anchored_data_dir = _process_lock
        .anchored_data_dir()
        .unwrap_or_else(|| configured_data_dir.to_path_buf());
    let data_dir_path = anchored_data_dir.as_path();
    validate_checkpointed_sqlite_generation(data_dir_path)
        .context("validate checkpointed SQLite generation")?;
    let output = AnchoredOutput::open(shares_out).context("anchor Shamir output directory")?;
    #[cfg(debug_assertions)]
    maybe_pause_after_output_anchor()?;
    let recovery_journal =
        read_transition_journal(&output).context("read Shamir transition journal")?;
    let backup_receipt =
        validate_backup_manifest(backup_manifest, data_dir_path, recovery_journal.is_none())
            .context("validate rollback backup manifest")?;
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
        validate_recovery_journal_identity(
            &journal,
            operator_id,
            backup_manifest,
            &backup_receipt,
        )?;
        let active: (String, String) =
            sqlx::query_as("SELECT kid, sealing_method FROM vault.kek_metadata")
                .fetch_one(&mut *conn)
                .await
                .context("inspect interrupted Shamir transition")?;
        match (journal.phase.as_str(), active.1.as_str()) {
            ("prepared", "plaintext") => {
                output
                    .remove(&output.bundle, true)
                    .context("remove orphan prepared share bundle")?;
                output
                    .remove(&output.journal, false)
                    .context("remove orphan prepared transition journal")?;
                let _ = validate_backup_manifest(backup_manifest, data_dir_path, true)?;
            }
            ("prepared", "shamir") => {
                if active.0 != journal.new_kid {
                    anyhow::bail!("prepared journal does not match committed vault KEK");
                }
                validate_transition_audit_receipt(&mut conn, &journal).await?;
                validate_recovery_bundle(&output, &journal).map_err(|error| {
                    anyhow::anyhow!("stranded transition requires paired rollback: {error}")
                })?;
                journal.phase = "committed".into();
                write_transition_journal(&output, &journal, false)?;
                write_transition_completion(&output)?;
                return Ok(active.0);
            }
            ("committed", "shamir") => {
                if active.0 != journal.new_kid {
                    anyhow::bail!("committed journal does not match active vault KEK");
                }
                if output.exists(&output.completion)? {
                    anyhow::bail!("Shamir transition is already complete");
                }
                validate_transition_audit_receipt(&mut conn, &journal).await?;
                validate_recovery_bundle(&output, &journal).map_err(|error| {
                    anyhow::anyhow!("stranded transition requires paired rollback: {error}")
                })?;
                write_transition_completion(&output)?;
                return Ok(active.0);
            }
            _ => anyhow::bail!("transition journal and vault state are inconsistent"),
        }
    }
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut *conn)
        .await
        .context("acquire exclusive SQLite vault transaction")?;

    let result: anyhow::Result<PreparedShares> = async {
        let schema_migrated = migrate_vault_schema_in_transaction(&mut conn).await?;
        if injected_failure.as_deref() == Some("after-schema-migration") {
            anyhow::bail!("injected failure after schema migration");
        }
        #[cfg(debug_assertions)]
        maybe_sigkill("after-schema-ddl-pretransition");
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
        let (kid, _, blob) = rows.into_iter().next().expect("one row checked above");
        let blob = Zeroizing::new(blob);
        let old_kid = kid.clone();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&blob);
        let digest = assay_vault::crypto::kek_store::full_kek_digest(&key);
        let shares = split_kek(&key, threshold, shares_count)
            .map_err(|e| anyhow::anyhow!("split KEK: {e}"))?;

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
        let bytes = Zeroizing::new(shares.iter().map(|s| s.0.clone()).collect::<Vec<_>>());
        if injected_failure.as_deref() == Some("after-update") {
            anyhow::bail!("injected failure after metadata update");
        }
        Ok(PreparedShares {
            kid,
            shares: bytes,
            old_kid,
            schema_migrated,
        })
    }
    .await;

    let PreparedShares {
        kid,
        shares: share_bytes,
        old_kid,
        schema_migrated,
    } = match result {
        Ok(value) => value,
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(e);
        }
    };
    let encoded = Zeroizing::new(
        share_bytes
            .iter()
            .map(|s| assay_vault::crypto::sealing::shamir::encode_share_base64(s))
            .collect::<Vec<_>>(),
    );
    #[derive(serde::Serialize)]
    struct ShareBundle<'a> {
        version: u8,
        kid: &'a str,
        threshold: u8,
        shares_count: u8,
        shares_b64: &'a [String],
    }
    let bundle = Zeroizing::new(serde_json::to_vec_pretty(&ShareBundle {
        version: 1,
        kid: &kid,
        threshold,
        shares_count,
        shares_b64: &encoded,
    })?);
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
        manifest_digest: backup_receipt.manifest_digest.clone(),
        backup_generation: backup_receipt.generation.clone(),
        baseline_binary_digest: backup_receipt.baseline_binary_digest.clone(),
        database_artifact_digests: backup_receipt.database_artifact_digests.clone(),
        bundle_digest: bundle_digest.clone(),
        share_threshold: threshold,
        share_count: shares_count,
        schema_migrated,
    };
    let mut created_output = false;
    let file_result = (|| -> anyhow::Result<()> {
        write_transition_journal(&output, &journal, true)?;
        #[cfg(debug_assertions)]
        maybe_sigkill("journal-fsynced-prebundle");
        output
            .write_new(&output.bundle, &bundle)
            .context("create shares-out exclusively")?;
        created_output = true;
        Ok(())
    })();
    if let Err(e) = file_result {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        if created_output {
            let _ = output.remove(&output.bundle, true);
        }
        let _ = output.remove(&output.journal, true);
        return Err(e);
    }
    if injected_failure.as_deref() == Some("after-write") {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        if created_output {
            let _ = output.remove(&output.bundle, true);
        }
        let _ = output.remove(&output.journal, true);
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
            manifest_digest TEXT NOT NULL,
            backup_generation TEXT NOT NULL,
            baseline_binary_digest TEXT NOT NULL,
            database_artifact_digests TEXT NOT NULL,
            bundle_digest TEXT NOT NULL,
            share_threshold INTEGER NOT NULL,
            share_count INTEGER NOT NULL,
            plaintext_backup_acknowledged INTEGER NOT NULL,
            schema_migrated INTEGER NOT NULL,
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
             backup_ref, manifest_digest, backup_generation, baseline_binary_digest,
             database_artifact_digests, bundle_digest, share_threshold, share_count,
             plaintext_backup_acknowledged, schema_migrated, outcome, created_at)
         VALUES (?, ?, ?, 'plaintext', 'shamir', ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'committed', ?)",
    )
    .bind(&transition_id)
    .bind(&journal.old_kid)
    .bind(&journal.new_kid)
    .bind(operator_id)
    .bind(backup_manifest.display().to_string())
    .bind(&backup_receipt.manifest_digest)
    .bind(&backup_receipt.generation)
    .bind(&backup_receipt.baseline_binary_digest)
    .bind(&backup_receipt.database_artifact_digests)
    .bind(&bundle_digest)
    .bind(i64::from(threshold))
    .bind(i64::from(shares_count))
    .bind(i64::from(schema_migrated))
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
        let _ = output.remove(&output.bundle, true);
        let _ = output.remove(&output.journal, true);
        return Err(anyhow::anyhow!("commit Shamir transition: {e}"));
    }
    #[cfg(debug_assertions)]
    maybe_sigkill("db-committed-prejournal");
    journal.phase = "committed".into();
    write_transition_journal(&output, &journal, false)?;
    #[cfg(debug_assertions)]
    maybe_sigkill("postcommit");
    write_transition_completion(&output)?;
    if injected_failure.as_deref() == Some("after-commit") {
        anyhow::bail!("injected failure after committed Shamir transition");
    }
    Ok(kid)
}

async fn validate_transition_audit_receipt(
    conn: &mut sqlx::SqliteConnection,
    journal: &TransitionJournal,
) -> anyhow::Result<()> {
    let has_schema_migrated: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM vault.pragma_table_info('sealing_transition_audit')
            WHERE name='schema_migrated'
        )",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|error| anyhow::anyhow!("inspect transition audit receipt schema: {error}"))?;
    let schema_expression = if has_schema_migrated {
        "schema_migrated"
    } else {
        "0 AS schema_migrated"
    };
    let query = format!(
        "SELECT transition_id, old_kid, new_kid, operator_id, backup_ref,
                manifest_digest, backup_generation, baseline_binary_digest,
                database_artifact_digests, bundle_digest, share_threshold,
                share_count, plaintext_backup_acknowledged, outcome,
                {schema_expression}
           FROM vault.sealing_transition_audit
          WHERE transition_id=?"
    );
    let row: TransitionAuditRow = sqlx::query_as(&query)
        .bind(&journal.transition_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|error| anyhow::anyhow!("read transition audit receipt: {error}"))?;
    if row.transition_id != journal.transition_id
        || row.old_kid != journal.old_kid
        || row.new_kid != journal.new_kid
        || row.operator_id != journal.operator_id
        || row.backup_ref != journal.backup_ref
        || row.manifest_digest != journal.manifest_digest
        || row.backup_generation != journal.backup_generation
        || row.baseline_binary_digest != journal.baseline_binary_digest
        || row.database_artifact_digests != journal.database_artifact_digests
        || row.bundle_digest != journal.bundle_digest
        || row.share_threshold != i64::from(journal.share_threshold)
        || row.share_count != i64::from(journal.share_count)
        || row.plaintext_backup_acknowledged != 1
        || row.outcome != "committed"
        || row.schema_migrated != i64::from(journal.schema_migrated)
    {
        anyhow::bail!("transition audit receipt mismatch; paired rollback is required");
    }
    Ok(())
}

async fn migrate_vault_schema_in_transaction(
    conn: &mut sqlx::SqliteConnection,
) -> anyhow::Result<bool> {
    use anyhow::Context as _;

    let had_kek_digest: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM vault.pragma_table_info('kek_metadata')
            WHERE name='kek_digest'
        )",
    )
    .fetch_one(&mut *conn)
    .await
    .context("inspect legacy vault KEK schema")?;
    let had_schema_migrated: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM vault.pragma_table_info('sealing_transition_audit')
            WHERE name='schema_migrated'
        )",
    )
    .fetch_one(&mut *conn)
    .await
    .context("inspect legacy vault transition audit schema")?;

    for (label, statement) in assay_vault::schema::SQLITE_DDL_V1 {
        sqlx::query(statement)
            .execute(&mut *conn)
            .await
            .with_context(|| format!("vault offline sqlite migrate: {label}"))?;
    }
    if !had_kek_digest {
        sqlx::query("ALTER TABLE vault.kek_metadata ADD COLUMN kek_digest BLOB")
            .execute(&mut *conn)
            .await
            .context("vault offline sqlite migrate: add kek_digest")?;
    }
    let has_schema_migrated_now: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM vault.pragma_table_info('sealing_transition_audit')
            WHERE name='schema_migrated'
        )",
    )
    .fetch_one(&mut *conn)
    .await
    .context("inspect migrated vault transition audit schema")?;
    if !has_schema_migrated_now {
        sqlx::query(
            "ALTER TABLE vault.sealing_transition_audit
             ADD COLUMN schema_migrated INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&mut *conn)
        .await
        .context("vault offline sqlite migrate: add schema_migrated receipt")?;
    }
    sqlx::query("INSERT OR IGNORE INTO engine.migrations (module, version) VALUES (?, ?)")
        .bind(assay_vault::schema::MODULE_NAME)
        .bind(assay_vault::schema::MIGRATION_VERSION)
        .execute(&mut *conn)
        .await
        .context("record offline vault schema migration")?;
    Ok(!had_kek_digest || !had_schema_migrated)
}

fn validate_checkpointed_sqlite_generation(data_dir: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Read as _;

    let mut databases = Vec::new();
    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".db-wal") || name.ends_with(".db-shm") {
            anyhow::bail!(
                "SQLite backup generation is not checkpointed; remove WAL/SHM only after a clean service stop and checkpoint"
            );
        }
        if entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("db")
        {
            databases.push(entry.path());
        }
    }
    databases.sort();
    for database in databases {
        let mut header = [0u8; 20];
        std::fs::File::open(&database)?.read_exact(&mut header)?;
        if &header[..16] != b"SQLite format 3\0" {
            anyhow::bail!("{} is not a valid SQLite database", database.display());
        }
        if (header[18], header[19]) != (1, 1) {
            anyhow::bail!(
                "SQLite database {} must persist journal_mode=DELETE before offline Shamir initialization; header write/read versions are {}/{}",
                database.display(),
                header[18],
                header[19]
            );
        }
    }
    Ok(())
}

fn trusted_operator_id() -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        Ok(format!("uid:{}", current_uid()))
    }
    #[cfg(not(unix))]
    anyhow::bail!("offline Shamir initialization requires an OS-derived operator identity")
}

fn write_transition_completion(output: &AnchoredOutput) -> anyhow::Result<()> {
    output.write_new(&output.completion, &[])
}

fn read_transition_journal(output: &AnchoredOutput) -> anyhow::Result<Option<TransitionJournal>> {
    if !output.exists(&output.journal)? {
        return Ok(None);
    }
    let bytes = output.read(&output.journal)?;
    Ok(Some(serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!("parse transition recovery journal: {error}")
    })?))
}

fn validate_recovery_journal_identity(
    journal: &TransitionJournal,
    operator_id: &str,
    backup_manifest: &std::path::Path,
    backup_receipt: &BackupReceipt,
) -> anyhow::Result<()> {
    if journal.version != 1
        || !matches!(journal.phase.as_str(), "prepared" | "committed")
        || journal.operator_id != operator_id
        || journal.backup_ref != backup_manifest.display().to_string()
        || journal.manifest_digest != backup_receipt.manifest_digest
        || journal.backup_generation != backup_receipt.generation
        || journal.baseline_binary_digest != backup_receipt.baseline_binary_digest
        || journal.database_artifact_digests != backup_receipt.database_artifact_digests
        || journal.share_threshold != 3
        || journal.share_count != 5
    {
        anyhow::bail!("transition recovery journal does not match this operation");
    }
    Ok(())
}

fn validate_recovery_bundle(
    output: &AnchoredOutput,
    journal: &TransitionJournal,
) -> anyhow::Result<()> {
    let bytes = output.validate_private_bundle()?;
    if sha256_bytes(&bytes) != journal.bundle_digest {
        anyhow::bail!("share bundle checksum mismatch");
    }
    Ok(())
}

fn write_transition_journal(
    output: &AnchoredOutput,
    journal: &TransitionJournal,
    create_new: bool,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(journal)?;
    output.atomic_write(&output.journal, &bytes, &journal.transition_id, create_new)
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

#[cfg(debug_assertions)]
fn maybe_pause_after_output_anchor() -> anyhow::Result<()> {
    let (Ok(ready), Ok(resume)) = (
        std::env::var("ASSAY_TEST_SHAMIR_ANCHOR_READY"),
        std::env::var("ASSAY_TEST_SHAMIR_ANCHOR_RESUME"),
    ) else {
        return Ok(());
    };
    std::fs::write(&ready, b"ready")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !std::path::Path::new(&resume).exists() {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting at anchored output test boundary");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_share_output_parent(shares_out: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    if !shares_out.is_absolute() {
        anyhow::bail!("--shares-out must be an absolute canonical path");
    }
    let parent = shares_out
        .parent()
        .ok_or_else(|| anyhow::anyhow!("--shares-out has no parent directory"))?;
    if shares_out.file_name().is_none() {
        anyhow::bail!("--shares-out must include a file name");
    }
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
        let operator_uid = current_uid();
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
    require_live_match: bool,
) -> anyhow::Result<BackupReceipt> {
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
        let operator_uid = current_uid();
        if metadata.uid() != operator_uid || metadata.mode() & 0o077 != 0 {
            anyhow::bail!("--backup-manifest must be operator-owned and private");
        }
    }
    let bytes = std::fs::read(manifest_path).context("read backup manifest")?;
    let manifest_digest = sha256_bytes(&bytes);
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
    if manifest.baseline_binary.generation_id != manifest.generation_id {
        anyhow::bail!("baseline binary and database snapshot generations do not match");
    }
    validate_private_backup_artifact(&manifest.baseline_binary.path, "baseline binary")?;
    if digest_file(&manifest.baseline_binary.path)? != manifest.baseline_binary.sha256 {
        anyhow::bail!("baseline binary checksum mismatch");
    }
    if manifest.baseline_binary.version != TRUSTED_BASELINE_VERSION
        || manifest.baseline_binary.source_commit != TRUSTED_BASELINE_SOURCE_COMMIT
        || manifest.baseline_binary.sha256 != trusted_baseline_sha256()?
    {
        anyhow::bail!("baseline binary does not match the trusted release attestation");
    }

    let baseline_binary_digest = manifest.baseline_binary.sha256.clone();
    let generation = manifest.generation_id.clone();
    let mut entries = BTreeMap::new();
    let mut artifact_digests = BTreeMap::new();
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
        artifact_digests.insert(database.name.clone(), database.sha256.clone());
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
    Ok(BackupReceipt {
        manifest_digest,
        generation,
        baseline_binary_digest,
        database_artifact_digests: serde_json::to_string(&artifact_digests)?,
    })
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
        let operator_uid = current_uid();
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
