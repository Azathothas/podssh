//! The files of a conversation (T-099). A file that the peer offers touches
//! nothing until the user accepts it. Then its bytes go to a new temporary
//! file beside its path, and at its end it takes its name once its SHA-256
//! matched, never over a file that is there; when the digest did not match,
//! or the conversation ended first, the temporary file goes.

use std::path::{Path, PathBuf};

use podssh_core::chat::{record::MAX_CHUNK, safe_name};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Where an accepted file goes: into `to` when it is a directory (by the
/// offered name's safe last part), at `to` when it names a new file, else
/// into `dir`. A path that exists is refused: podssh writes over no file.
pub fn target(offered: &str, to: Option<&Path>, dir: &Path) -> Result<PathBuf, String> {
    let into = |d: &Path| {
        safe_name(offered)
            .map(|name| d.join(name))
            .ok_or_else(|| format!("the name {offered:?} cannot be written; /accept ID PATH names a path"))
    };
    let path = match to {
        Some(p) if p.is_dir() => into(p)?,
        Some(p) => p.to_path_buf(),
        None => into(dir)?,
    };
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(format!(
            "{} exists, and podssh writes over no file; /accept ID PATH names another",
            path.display()
        ));
    }
    Ok(path)
}

/// A file that the user accepted, as its bytes come.
pub struct Incoming {
    path: PathBuf,
    temp: PathBuf,
    file: tokio::fs::File,
}

impl Incoming {
    /// A new temporary file beside `path`, for the file `id`.
    pub async fn open(path: PathBuf, id: u64) -> Result<Incoming, String> {
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let temp = dir.join(format!(".{name}.podssh-{id}.part"));
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .await
            .map_err(|e| format!("{}: {e}", temp.display()))?;
        Ok(Incoming { path, temp, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.file.write_all(data).await.map_err(|e| format!("{}: {e}", self.temp.display()))
    }

    /// The end of the file: its name once whole, never over a file that came
    /// in the meantime; else the temporary file goes.
    pub async fn finish(mut self, whole: bool) -> Result<PathBuf, String> {
        let written = async {
            self.file.flush().await?;
            self.file.sync_all().await
        }
        .await;
        drop(self.file);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&self.temp);
            return Err(format!("{}: {e}", self.temp.display()));
        }
        if !whole {
            let _ = std::fs::remove_file(&self.temp);
            return Err("its SHA-256 did not match the offer's, and it was not kept".to_string());
        }
        // A hard link fails on a file that is there; a rename would not.
        let named = match std::fs::hard_link(&self.temp, &self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
            Err(_) if std::fs::symlink_metadata(&self.path).is_err() => std::fs::rename(&self.temp, &self.path),
            Err(e) => Err(e),
        };
        let _ = std::fs::remove_file(&self.temp);
        named.map(|()| self.path.clone()).map_err(|e| format!("{}: {e}", self.path.display()))
    }

    /// The conversation ended before the file: the temporary file goes.
    pub fn abandon(self) {
        drop(self.file);
        let _ = std::fs::remove_file(&self.temp);
    }
}

/// The size and SHA-256 of the file at `path`, read whole once.
pub async fn digest(path: &Path) -> Result<(u64, [u8; 32]), String> {
    let mut file = tokio::fs::File::open(path).await.map_err(|e| format!("{}: {e}", path.display()))?;
    let (mut hasher, mut size, mut buf) = (Sha256::new(), 0u64, vec![0u8; MAX_CHUNK]);
    loop {
        let n = file.read(&mut buf).await.map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            return Ok((size, hasher.finalize().into()));
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
}
