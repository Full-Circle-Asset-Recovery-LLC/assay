use std::fs::File;
use std::path::Path;

use anyhow::Context;

pub struct ProcessLock {
    _file: File,
    #[cfg(unix)]
    data_dir: File,
}

impl ProcessLock {
    pub fn acquire(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir).context("create SQLite data directory for lock")?;
        #[cfg(unix)]
        {
            Self::acquire_unix(data_dir)
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
    fn acquire_unix(data_dir: &Path) -> anyhow::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let path = std::ffi::CString::new(data_dir.as_os_str().as_bytes())?;
        // SAFETY: path is NUL-terminated; returned fd is owned below.
        let dir_fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dir_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open SQLite data directory");
        }
        // SAFETY: dir_fd is newly owned by this call.
        let dir = unsafe { File::from_raw_fd(dir_fd) };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is valid and stat points to writable memory.
        if unsafe { libc::fstat(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("inspect SQLite data directory");
        }
        // SAFETY: fstat succeeded.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o077 != 0
        {
            anyhow::bail!("SQLite data directory must be operator-owned mode 0700 or stricter");
        }
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
}
