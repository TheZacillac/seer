//! Shared atomic-save plumbing for the `~/.seer` data stores (history,
//! watchlist, subdomain baselines).
//!
//! One envelope, three callers (each wired up by [`persisted_store!`]):
//! create the parent dir owner-only, write the serialized content to a
//! per-call-unique sibling temp file, restrict the temp file to owner-only,
//! then `rename` over the target (atomic on POSIX, so a reader never sees a
//! torn file). Extracted after the per-call-unique temp-name fix had to be
//! applied to multiple hand-copied versions of this routine — each store
//! picks its file and codec, the envelope lives here.

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
/// `load` returns the default store when the file is missing or unreadable,
/// moving an unreadable file to a backup first ([`load_or_back_up`]) so the
/// next `save` cannot destroy the user's data. `save` publishes through
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
            /// is missing or unreadable (an unreadable file is backed up first).
            pub fn load() -> Self {
                match Self::path() {
                    Some(path) => Self::load_from_path(&path),
                    None => Self::default(),
                }
            }

            /// [`Self::load`] from an explicit path — a test seam that avoids
            /// touching the real `~/.seer`.
            pub(crate) fn load_from_path(path: &std::path::Path) -> Self {
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
/// The parent directory is created `0o700` and the temp file is `chmod`ed
/// `0o600` *before* the rename, so the published file is never briefly
/// world-readable (the stores hold sensitive reconnaissance metadata).
pub(crate) fn write_atomic_owner_only(path: &Path, content: &str, tmp_ext: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let tmp_path = unique_tmp_path(path, tmp_ext);
    std::fs::write(&tmp_path, content).map_err(|e| {
        // A failed (e.g. ENOSPC, partially written) temp must not be left
        // behind: each failed save would otherwise orphan a new unique file.
        let _ = std::fs::remove_file(&tmp_path);
        SeerError::ConfigError(e.to_string())
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp_path, path).map_err(|e| {
        // Best-effort temp cleanup; surface the original rename error.
        let _ = std::fs::remove_file(&tmp_path);
        SeerError::ConfigError(e.to_string())
    })?;
    Ok(())
}

/// Loads a `~/.seer` store, never letting unreadable data be overwritten.
///
/// A missing file yields `T::default()`. Anything else that fails — a parse
/// error, but also a read error such as invalid UTF-8 from a stray byte or a
/// Latin-1 editor — moves the file to a backup (`<name>.corrupt`, or a
/// timestamped variant when that already exists, so a second corruption never
/// destroys the first backup) before returning the default. Without the
/// backup the caller's next `save` would silently replace the user's data.
pub(crate) fn load_or_back_up<T: Default>(
    path: &Path,
    what: &str,
    parse: impl FnOnce(&str) -> std::result::Result<T, String>,
) -> T {
    let failure = match std::fs::read_to_string(path) {
        Ok(content) => match parse(&content) {
            Ok(value) => return value,
            Err(e) => e,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return T::default(),
        Err(e) => e.to_string(),
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
    T::default()
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
        assert!(load_or_back_up(&path, "test", parse).is_empty());
        assert!(!path.exists());
        let first = path.with_extension("corrupt");
        assert_eq!(std::fs::read(&first).unwrap(), vec![0xff, 0xfe, b'x']);

        // A second corruption gets its own backup.
        std::fs::write(&path, "garbage").unwrap();
        assert!(load_or_back_up(&path, "test", parse).is_empty());
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
        assert!(load_or_back_up(&dir.0.join("missing.json"), "test", parse).is_empty());
        std::fs::write(&path, "ok").unwrap();
        assert_eq!(load_or_back_up(&path, "test", parse), vec![1]);
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
