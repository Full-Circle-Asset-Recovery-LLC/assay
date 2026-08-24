use std::fs::File;
use std::path::Path;

use anyhow::Context;

pub struct RuntimeAuthority {
    process_lock: std::sync::Arc<ProcessLock>,
    cancel: tokio::sync::watch::Sender<bool>,
}

pub struct RuntimeTaskGuard {
    _process_lock: std::sync::Arc<ProcessLock>,
    cancel: tokio::sync::watch::Receiver<bool>,
}

impl RuntimeAuthority {
    pub fn new(process_lock: ProcessLock) -> std::sync::Arc<Self> {
        let (cancel, _) = tokio::sync::watch::channel(false);
        std::sync::Arc::new(Self {
            process_lock: std::sync::Arc::new(process_lock),
            cancel,
        })
    }

    pub fn anchored_data_dir(&self) -> Option<std::path::PathBuf> {
        self.process_lock.anchored_data_dir()
    }

    pub fn task_guard(&self) -> RuntimeTaskGuard {
        RuntimeTaskGuard {
            _process_lock: std::sync::Arc::clone(&self.process_lock),
            cancel: self.cancel.subscribe(),
        }
    }

    pub fn lock_guard(&self) -> std::sync::Arc<dyn Send + Sync> {
        std::sync::Arc::clone(&self.process_lock) as std::sync::Arc<dyn Send + Sync>
    }
}

impl Drop for RuntimeAuthority {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
    }
}

impl RuntimeTaskGuard {
    pub async fn cancelled(&mut self) {
        while !*self.cancel.borrow() {
            if self.cancel.changed().await.is_err() {
                break;
            }
        }
    }
}

pub struct ProcessLock {
    _file: File,
    #[cfg(unix)]
    data_dir: File,
}

impl ProcessLock {
    pub fn acquire(data_dir: &Path) -> anyhow::Result<Self> {
        let existed = match std::fs::symlink_metadata(data_dir) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error).context("inspect SQLite data directory for lock"),
        };
        if !existed {
            #[cfg(unix)]
            {
                let dir = Self::create_missing_unix(data_dir)?;
                return Self::acquire_unix(data_dir, Some(dir));
            }
            #[cfg(not(unix))]
            std::fs::create_dir(data_dir).context("create SQLite data directory for lock")?;
        }
        #[cfg(unix)]
        {
            Self::acquire_unix(data_dir, None)
        }
        #[cfg(not(unix))]
        {
            use std::fs::OpenOptions;
            let path = data_dir.join("assay-engine.lock");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
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

    #[cfg(unix)]
    fn create_missing_unix(data_dir: &Path) -> anyhow::Result<File> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let (parent, name) = if data_dir.is_absolute() {
            if data_dir
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                anyhow::bail!("SQLite data directory traversal is refused");
            }
            let parent = data_dir
                .parent()
                .ok_or_else(|| anyhow::anyhow!("missing SQLite data directory has no parent"))?
                .to_path_buf();
            if parent.canonicalize()? != parent {
                anyhow::bail!("SQLite data directory parent must be canonical and non-symlinked");
            }
            let name = data_dir
                .file_name()
                .ok_or_else(|| {
                    anyhow::anyhow!("missing SQLite data directory has no final component")
                })?
                .to_os_string();
            (parent, name)
        } else {
            let normal = data_dir
                .components()
                .filter_map(|component| match component {
                    std::path::Component::CurDir => None,
                    std::path::Component::Normal(value) => Some(Ok(value.to_os_string())),
                    std::path::Component::ParentDir => Some(Err(anyhow::anyhow!(
                        "SQLite data directory traversal is refused"
                    ))),
                    _ => Some(Err(anyhow::anyhow!(
                        "relative SQLite data directory must be one final component"
                    ))),
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if normal.len() != 1 {
                anyhow::bail!("relative SQLite data directory must be one final component");
            }
            (std::env::current_dir()?.canonicalize()?, normal[0].clone())
        };
        let parent_c = std::ffi::CString::new(parent.as_os_str().as_bytes())?;
        let name_c = std::ffi::CString::new(name.as_bytes())?;
        // SAFETY: canonical parent path is NUL-terminated; returned fd is owned below.
        let parent_fd = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if parent_fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("open SQLite data directory parent");
        }
        // SAFETY: parent_fd is newly owned.
        let parent_file = unsafe { File::from_raw_fd(parent_fd) };
        Self::validate_trusted_parent(&parent_file)?;
        // SAFETY: parent fd and final-component name are valid.
        if unsafe { libc::mkdirat(parent_file.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error()).context("mkdirat SQLite data directory");
        }
        // SAFETY: parent fd and final-component name are valid; no symlink following.
        let dir_fd = unsafe {
            libc::openat(
                parent_file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dir_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("openat SQLite data directory");
        }
        // SAFETY: dir_fd is newly owned.
        let dir = unsafe { File::from_raw_fd(dir_fd) };
        // SAFETY: dir fd is valid; explicit mode is independent of umask.
        if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error()).context("fchmod SQLite data directory");
        }
        Self::validate_private_directory(&dir, "SQLite data directory")?;
        parent_file
            .sync_all()
            .context("fsync SQLite data directory parent")?;
        Ok(dir)
    }

    #[cfg(unix)]
    fn validate_private_directory(dir: &File, label: &str) -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is valid and stat points to writable memory.
        if unsafe { libc::fstat(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("inspect {label}"));
        }
        // SAFETY: fstat succeeded.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o077 != 0
        {
            anyhow::bail!("{label} must be operator-owned mode 0700 or stricter");
        }
        Ok(())
    }

    #[cfg(unix)]
    fn validate_trusted_parent(parent: &File) -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is valid and stat points to writable memory.
        if unsafe { libc::fstat(parent.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("inspect SQLite data directory trusted parent");
        }
        // SAFETY: fstat succeeded.
        let stat = unsafe { stat.assume_init() };
        let effective_uid = unsafe { libc::geteuid() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || (stat.st_uid != effective_uid && stat.st_uid != 0)
            || stat.st_mode & 0o022 != 0
        {
            anyhow::bail!(
                "SQLite data directory trusted parent must be a non-group/world-writable directory owned by the operator or root"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    fn acquire_unix(data_dir: &Path, opened_dir: Option<File>) -> anyhow::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let dir = match opened_dir {
            Some(dir) => dir,
            None => {
                let path = std::ffi::CString::new(data_dir.as_os_str().as_bytes())?;
                // SAFETY: path is NUL-terminated; returned fd is owned below.
                let dir_fd = unsafe {
                    libc::open(
                        path.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if dir_fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("open SQLite data directory");
                }
                // SAFETY: dir_fd is newly owned by this call.
                unsafe { File::from_raw_fd(dir_fd) }
            }
        };
        Self::validate_private_directory(&dir, "SQLite data directory")?;
        let lock_name = c"assay-engine.lock";
        // SAFETY: directory fd and constant relative name are valid.
        let lock_fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                lock_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if lock_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open assay-engine process lock");
        }
        // SAFETY: lock_fd is newly owned by this call.
        let file = unsafe { File::from_raw_fd(lock_fd) };
        let mut lock_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: file fd is valid and lock_stat points to writable memory.
        if unsafe { libc::fstat(file.as_raw_fd(), lock_stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("inspect assay-engine process lock");
        }
        // SAFETY: fstat succeeded.
        let lock_stat = unsafe { lock_stat.assume_init() };
        if lock_stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || lock_stat.st_uid != unsafe { libc::geteuid() }
            || lock_stat.st_mode & 0o077 != 0
        {
            anyhow::bail!("assay-engine process lock must be operator-owned mode 0600 or stricter");
        }
        file.try_lock().with_context(|| {
            format!(
                "another assay-engine process holds the SQLite lock {}/assay-engine.lock",
                data_dir.display()
            )
        })?;
        Ok(Self {
            _file: file,
            data_dir: dir,
        })
    }

    pub fn anchored_data_dir(&self) -> Option<std::path::PathBuf> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            Some(format!("/proc/self/fd/{}", self.data_dir.as_raw_fd()).into())
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn anchored_directory_survives_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock = ProcessLock::acquire(&data).unwrap();
        let anchored = lock.anchored_data_dir().unwrap();
        let original = temp.path().join("original");
        std::fs::rename(&data, &original).unwrap();
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(anchored.join("sentinel"), b"anchored").unwrap();
        assert_eq!(
            std::fs::read(original.join("sentinel")).unwrap(),
            b"anchored"
        );
        assert!(!data.join("sentinel").exists());
    }

    #[test]
    fn public_or_symlinked_data_directory_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let public = temp.path().join("public");
        std::fs::create_dir(&public).unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ProcessLock::acquire(&public).is_err());

        let private = temp.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = temp.path().join("link");
        symlink(&private, &link).unwrap();
        assert!(ProcessLock::acquire(&link).is_err());
    }

    #[test]
    fn missing_data_directory_is_created_mode_0700_under_permissive_umask() {
        struct UmaskGuard(libc::mode_t);
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                // SAFETY: restoring this process's prior umask.
                unsafe { libc::umask(self.0) };
            }
        }

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let data = temp.path().join("missing-data");
        // SAFETY: test deliberately controls and restores the process umask.
        let old = unsafe { libc::umask(0o002) };
        let guard = UmaskGuard(old);
        let lock = ProcessLock::acquire(&data).unwrap();
        drop(guard);
        assert_eq!(
            std::fs::metadata(&data).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(lock);
    }

    #[test]
    fn missing_nested_or_symlinked_parent_is_rejected_under_umask_0002() {
        struct UmaskGuard(libc::mode_t);
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                // SAFETY: restoring this process's prior umask.
                unsafe { libc::umask(self.0) };
            }
        }
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: test deliberately controls and restores the process umask.
        let guard = UmaskGuard(unsafe { libc::umask(0o002) });
        assert!(ProcessLock::acquire(&temp.path().join("missing/child")).is_err());

        let real_parent = temp.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let linked_parent = temp.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(ProcessLock::acquire(&linked_parent.join("data")).is_err());
        drop(guard);
    }

    #[test]
    fn root_owned_nonwritable_system_parent_is_trusted() {
        let parent = File::open("/var/lib").unwrap();
        ProcessLock::validate_trusted_parent(&parent).unwrap();
    }
}
