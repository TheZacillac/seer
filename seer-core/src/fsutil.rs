//! Shared atomic-save plumbing for the `~/.seer` data stores (history,
//! watchlist, subdomain baselines).
//!
//! One envelope, three callers: create the parent dir owner-only, write the
//! serialized content to a per-call-unique sibling temp file, restrict the
//! temp file to owner-only, then `rename` over the target (atomic on POSIX,
//! so a reader never sees a torn file). Extracted after the per-call-unique
//! temp-name fix had to be applied to multiple hand-copied versions of this
//! routine — the serializers stay with the callers, the envelope lives here.

use std::path::{Path, PathBuf};

use crate::error::{Result, SeerError};

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
    std::fs::write(&tmp_path, content).map_err(|e| SeerError::ConfigError(e.to_string()))?;
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
