use std::fs::{File, OpenOptions};
use std::path::Path;

use anyhow::Context;

pub struct ProcessLock {
    _file: File,
}

impl ProcessLock {
    pub fn acquire(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir).context("create SQLite data directory for lock")?;
        let path = data_dir.join("assay-engine.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .context("open assay-engine process lock")?;
        file.try_lock().with_context(|| {
            format!(
                "another assay-engine process holds the SQLite lock {}",
                path.display()
            )
        })?;
        Ok(Self { _file: file })
    }
}
