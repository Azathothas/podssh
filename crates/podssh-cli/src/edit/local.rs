//! The copy here of `podssh edit` (T-149): a new directory of mode 0700 in
//! the first cache directory that takes one, and in it the file, of mode
//! 0600, with the far file's name, so that an editor knows its kind by its
//! name or its extension.

use std::path::{Path, PathBuf};

use podssh_relay::cache::DIR_ENV;

use crate::exitmap::Fault;

/// The private directory of one run, and the copy's path in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    pub dir: PathBuf,
    pub file: PathBuf,
}

impl Local {
    /// A new private directory for the copy of the far file `far`, in the
    /// first cache directory that takes one. With none, the fault and why:
    /// 78 when `PODSSH_CACHE_DIR` is none, else 73.
    pub fn make(far: &str) -> Result<Local, (Fault, String)> {
        Local::make_in(&podssh_relay::cache::candidate_dirs(), far)
    }

    /// [`Local::make`] in the cache directories `dirs`.
    pub fn make_in(dirs: &[PathBuf], far: &str) -> Result<Local, (Fault, String)> {
        if dirs.is_empty() {
            return Err((Fault::Config, format!("{DIR_ENV} is none, so podssh has no private directory for the copy")));
        }
        let name = name_for(far, cfg!(windows));
        let mut refused = Vec::new();
        for parent in dirs {
            match make_dir(parent) {
                Ok(dir) => return Ok(Local { file: dir.join(&name), dir }),
                Err(e) => refused.push(format!("{}: {e}", parent.display())),
            }
        }
        Err((Fault::CantCreate, format!("no cache directory would take the copy ({})", refused.join("; "))))
    }

    /// Remove the directory and what is in it: the edit went, or the copy
    /// holds no change.
    pub fn remove(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A new directory of mode 0700 in `parent`, which is made private first, as
/// the cache's directories are; never one that exists.
fn make_dir(parent: &Path) -> std::io::Result<PathBuf> {
    podssh_relay::cache::private_dir(parent)?;
    let dir = parent.join(format!("edit-{:016x}", rand::random::<u64>()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    #[cfg(not(unix))]
    let _ = &mut builder;
    builder.create(&dir)?;
    // On Windows an access list of this user's own (T-274); on Unix the
    // mode again, whatever the umask took.
    if let Err(e) = podssh_relay::cache::private_dir(&dir) {
        let _ = std::fs::remove_dir(&dir);
        return Err(e);
    }
    Ok(dir)
}

/// The name of the copy here: the far file's name when it can be one here,
/// else `file` with its extension when that can be, else `file`.
pub fn name_for(far: &str, windows: bool) -> String {
    let name = far.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let fits = |n: &str| crate::cp::tree::check_name(n, windows).is_ok();
    if fits(name) {
        return name.to_string();
    }
    match name.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() && fits(&format!("file.{ext}")) => format!("file.{ext}"),
        _ => "file".to_string(),
    }
}

/// Make the copy this user's only: the fetch gave it the far file's mode,
/// which a far file that others may read has too. On Windows the
/// directory's access list holds it already.
pub fn private_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_copy_keeps_the_far_name_or_at_least_its_extension() {
        assert_eq!(name_for("/etc/nginx/nginx.conf", false), "nginx.conf");
        assert_eq!(name_for("notes.md", false), "notes.md");
        assert_eq!(name_for(".bashrc", false), ".bashrc");
        // Names that Windows cannot hold keep their extension there.
        assert_eq!(name_for("dir/a:b.txt", true), "file.txt");
        assert_eq!(name_for("dir/a:b.txt", false), "a:b.txt");
        assert_eq!(name_for("dir/CON.yaml", true), "file.yaml");
        assert_eq!(name_for("dir/what?", true), "file");
    }
}
