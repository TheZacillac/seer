//! Shared atomic-save plumbing for the `~/.seer` data stores (history,
//! watchlist, subdomain baselines).
//!
//! One envelope, three callers (each wired up by [`persisted_store!`]):
//! create the parent dir owner-only, write the serialized content to a
//! per-call-unique sibling temp file created owner-only, flush it to disk,
//! then `rename` over the target (atomic on POSIX, so a reader never sees a
//! torn file) and flush the directory entry. Extracted after the
//! per-call-unique temp-name fix had to be applied to multiple hand-copied
//! versions of this routine — each store picks its file and codec, the
//! envelope lives here.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Result, SeerError};

/// Implements the `~/.seer/<file>` persistence methods — `path`, `load`,
/// `load_from_path`, `save`, `save_to_path` — on a store type, as inherent
/// methods so front ends need no trait import. The store must be
/// `Default + Serialize + Deserialize`; the codec is `json` or `toml`:
///
/// ```text
/// crate::fsutil::persisted_store!(LookupHistory, "history.json", json, "history");
/// ```
///
/// `load` returns the default store when the file is missing or corrupt
/// (unparseable or not UTF-8), moving a corrupt file to a backup first
/// ([`load_or_back_up`]) so the next `save` cannot destroy the user's data;
/// any other read failure (permission denied, a directory in the way) is an
/// error and leaves the file alone. `save` publishes through
/// [`write_atomic_owner_only`], so a crash mid-write can never leave the store
/// truncated. The load → mutate → save cycle is *not* cross-process locked:
/// two concurrent writers are last-writer-wins (one side's change can be
/// lost, never corrupted). A cross-process advisory lock would close that
/// window; it is omitted to avoid a new dependency for a low-frequency case.
macro_rules! persisted_store {
    ($store:ty, $file:literal, json, $what:literal) => {
        $crate::fsutil::persisted_store!(@impl $store, $file, $what, serde_json, "json");
    };
    ($store:ty, $file:literal, toml, $what:literal) => {
        $crate::fsutil::persisted_store!(@impl $store, $file, $what, toml, "toml");
    };
    (@impl $store:ty, $file:literal, $what:literal, $codec:ident, $ext:literal) => {
        impl $store {
            #[doc = concat!("Returns the path to the store file (`~/.seer/", $file, "`).")]
            pub fn path() -> Option<std::path::PathBuf> {
                std::env::home_dir().map(|h| h.join(".seer").join($file))
            }

            /// Loads the store from disk, returning an empty store when the file
            /// is missing or corrupt (a corrupt file is backed up first).
            ///
            /// # Errors
            ///
            /// A read failure other than a missing file (permission denied, a
            /// directory at the path, an I/O error): the file is left in place,
            /// and callers must not save over what they could not read.
            pub fn load() -> $crate::error::Result<Self> {
                match Self::path() {
                    Some(path) => Self::load_from_path(&path),
                    None => Ok(Self::default()),
                }
            }

            /// [`Self::load`] from an explicit path — a test seam that avoids
            /// touching the real `~/.seer`.
            pub(crate) fn load_from_path(path: &std::path::Path) -> $crate::error::Result<Self> {
                $crate::fsutil::load_or_back_up(path, $what, |content| {
                    $codec::from_str(content).map_err(|e| e.to_string())
                })
            }

            /// Persists the store atomically (temp file + rename, owner-only).
            pub fn save(&self) -> $crate::error::Result<()> {
                let path = Self::path().ok_or_else(|| {
                    $crate::error::SeerError::ConfigError(
                        "Cannot determine home directory".to_string(),
                    )
                })?;
                self.save_to_path(&path)
            }

            /// [`Self::save`] to an explicit path (test seam, as `load_from_path`).
            pub(crate) fn save_to_path(&self, path: &std::path::Path) -> $crate::error::Result<()> {
                let content = $codec::to_string_pretty(self)
                    .map_err(|e| $crate::error::SeerError::ConfigError(e.to_string()))?;
                $crate::fsutil::write_atomic_owner_only(path, &content, $ext)
            }
        }
    };
}
pub(crate) use persisted_store;

/// Atomically publishes `content` at `path` with owner-only permissions.
///
/// `tmp_ext` is the target's extension (`"json"` / `"toml"`), kept in the
/// temp-file name so stray temps remain recognizable next to their store.
/// The parent directory is created `0o700` and the temp file is *created*
/// `0o600` (never briefly world-readable — the stores hold sensitive
/// reconnaissance metadata). The temp's data is flushed to disk before the
/// rename, so a crash cannot publish an empty or partial file under the
/// target name, and on Unix the directory is flushed after it, so the rename
/// itself survives a crash.
pub(crate) fn write_atomic_owner_only(path: &Path, content: &str, tmp_ext: &str) -> Result<()> {
    let io_err = |e: std::io::Error| SeerError::ConfigError(format!("{}: {e}", path.display()));
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent).map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let tmp_path = unique_tmp_path(path, tmp_ext);
    let write_tmp = || -> std::io::Result<()> {
        // A leftover from a crashed process that had the same PID would make
        // `create_new` fail; it is ours to replace.
        let _ = std::fs::remove_file(&tmp_path);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()
    };
    if let Err(e) = write_tmp().and_then(|()| std::fs::rename(&tmp_path, path)) {
        // A failed (e.g. ENOSPC, partially written) temp must not be left
        // behind: each failed save would otherwise orphan a new unique file.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(io_err(e));
    }
    // Persist the rename (best-effort: the data is already safe on disk).
    #[cfg(unix)]
    {
        if let Some(dir) = parent.and_then(|p| std::fs::File::open(p).ok()) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Loads a `~/.seer` store, never letting unreadable data be overwritten.
///
/// A missing file yields `T::default()`. Corrupt content — a parse error, or
/// invalid UTF-8 from a stray byte or a Latin-1 editor — moves the file to a
/// backup (`<name>.corrupt`, or a timestamped variant when that already
/// exists, so a second corruption never destroys the first backup) before
/// returning the default. Without the backup the caller's next `save` would
/// silently replace the user's data.
///
/// Any other read failure (permission denied, a directory at the path, an I/O
/// error) says nothing about the content, so the file is left where it is
/// and the failure is returned: backing it up and defaulting would lose a
/// healthy store to a transient or fixable problem.
pub(crate) fn load_or_back_up<T: Default>(
    path: &Path,
    what: &str,
    parse: impl FnOnce(&str) -> std::result::Result<T, String>,
) -> Result<T> {
    let failure = match std::fs::read(path) {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            Ok(content) => match parse(content) {
                Ok(value) => return Ok(value),
                Err(e) => e,
            },
            Err(e) => format!("not valid UTF-8: {e}"),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(e) => {
            return Err(SeerError::ConfigError(format!(
                "cannot read {what} file {}: {e}",
                path.display()
            )))
        }
    };

    let backup = backup_path(path);
    match std::fs::rename(path, &backup) {
        Ok(()) => tracing::warn!(
            path = %path.display(),
            backup = %backup.display(),
            error = %failure,
            "{what} file unreadable; moved to backup",
        ),
        Err(rename_err) => tracing::error!(
            path = %path.display(),
            error = %rename_err,
            "failed to back up unreadable {what}",
        ),
    }
    Ok(T::default())
}

/// `<path>.corrupt`, or `<path>.corrupt.<unix-seconds>[.<n>]` when a previous
/// backup already occupies that name.
fn backup_path(path: &Path) -> PathBuf {
    let first = path.with_extension("corrupt");
    if !first.exists() {
        return first;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut candidate = path.with_extension(format!("corrupt.{stamp}"));
    let mut n = 1u32;
    while candidate.exists() {
        candidate = path.with_extension(format!("corrupt.{stamp}.{n}"));
        n += 1;
    }
    candidate
}

/// A per-call-unique sibling temp path for an atomic save. The PID alone is
/// not unique enough: same-process concurrent saves are reachable (e.g. the
/// TUI's detached writes), and a shared temp path lets one writer truncate
/// the other's finished bytes before its rename — a torn rename that
/// publishes a corrupt file. A process-wide counter alongside the PID makes
/// every (process, call) pair unique.
fn unique_tmp_path(path: &Path, ext: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SAVE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = SAVE_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("{}.{}.{}.tmp", ext, std::process::id(), seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_store_is_backed_up_and_never_clobbers_a_prior_backup() {
        let dir = TmpDir::new("backup");
        std::fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("store.json");
        let parse = |c: &str| -> std::result::Result<Vec<u8>, String> {
            if c == "ok" {
                Ok(vec![1])
            } else {
                Err("bad".to_string())
            }
        };

        // Invalid UTF-8 is a *read* error, not a parse error — it used to
        // skip the backup entirely and the next save overwrote the data.
        std::fs::write(&path, [0xff, 0xfe, b'x']).unwrap();
        assert!(load_or_back_up(&path, "test", parse).unwrap().is_empty());
        assert!(!path.exists());
        let first = path.with_extension("corrupt");
        assert_eq!(std::fs::read(&first).unwrap(), vec![0xff, 0xfe, b'x']);

        // A second corruption gets its own backup.
        std::fs::write(&path, "garbage").unwrap();
        assert!(load_or_back_up(&path, "test", parse).unwrap().is_empty());
        assert_eq!(std::fs::read(&first).unwrap(), vec![0xff, 0xfe, b'x']);
        let backups = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("corrupt")
            })
            .count();
        assert_eq!(backups, 2);

        // Missing → default; readable + valid → parsed.
        assert!(load_or_back_up(&dir.0.join("missing.json"), "test", parse)
            .unwrap()
            .is_empty());
        std::fs::write(&path, "ok").unwrap();
        assert_eq!(load_or_back_up(&path, "test", parse).unwrap(), vec![1]);
    }

    /// Regression: any read error other than NotFound (EACCES, EISDIR) was
    /// treated as corruption and the path moved aside; the next save then
    /// replaced a healthy store. Such errors now propagate and touch nothing.
    #[test]
    fn a_read_error_is_returned_and_the_path_left_alone() {
        let dir = TmpDir::new("readerr");
        let path = dir.0.join("store.json");
        // A directory where the store should be: read fails with EISDIR.
        std::fs::create_dir_all(&path).unwrap();
        let parse = |_: &str| -> std::result::Result<Vec<u8>, String> { Ok(vec![1]) };
        let err = load_or_back_up(&path, "test", parse).expect_err("read error surfaces");
        assert!(err.to_string().contains("cannot read test file"), "{err}");
        assert!(path.is_dir(), "the path must not be moved aside");
        assert!(!path.with_extension("corrupt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_permission_denied_store_is_not_backed_up() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TmpDir::new("eacces");
        std::fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("store.json");
        std::fs::write(&path, "ok").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let parse = |_: &str| -> std::result::Result<Vec<u8>, String> { Ok(vec![1]) };
        let result = load_or_back_up(&path, "test", parse);
        // Root reads through 0o000; only assert when the read was refused.
        if std::fs::read(&path).is_err() {
            assert!(result.is_err());
            assert!(path.exists());
            assert!(!path.with_extension("corrupt").exists());
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    /// Unique scratch dir per test invocation, removed on drop.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "seer-fsutil-{}-{}-{}",
                tag,
                std::process::id(),
                n
            )))
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tmp_paths_are_unique_per_call_for_the_same_target() {
        let target = Path::new("/data/store.json");
        let first = unique_tmp_path(target, "json");
        let second = unique_tmp_path(target, "json");
        assert_ne!(first, second);
        for tmp in [&first, &second] {
            assert_eq!(tmp.parent(), target.parent());
            assert!(
                tmp.extension().is_some_and(|e| e == "tmp"),
                "got: {}",
                tmp.display()
            );
        }
    }

    #[test]
    fn write_replaces_content_atomically_without_leftover_temps() {
        let dir = TmpDir::new("replace");
        let target = dir.0.join("store.json");
        write_atomic_owner_only(&target, "{\"v\":1}", "json").expect("first write");
        write_atomic_owner_only(&target, "{\"v\":2}", "json").expect("second write");
        assert_eq!(
            std::fs::read_to_string(&target).expect("read back"),
            "{\"v\":2}"
        );
        // No stray temp files: the rename consumed every temp.
        let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
            .expect("list dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path() != target)
            .collect();
        assert!(leftovers.is_empty(), "leftovers: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn published_file_and_parent_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TmpDir::new("perms");
        let target = dir.0.join("nested").join("store.toml");
        write_atomic_owner_only(&target, "x = 1\n", "toml").expect("write");
        let file_mode = std::fs::metadata(&target)
            .expect("file meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "file mode: {file_mode:o}");
        let dir_mode = std::fs::metadata(target.parent().unwrap())
            .expect("dir meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "dir mode: {dir_mode:o}");
    }
}
