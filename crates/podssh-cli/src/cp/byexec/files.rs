//! The steps of a copy by exec that move a file, up and down. Each writes
//! under a temporary name, compares the digests, then renames. A failure
//! removes the temporary file, except a broken connection's: the next
//! attempt writes on in it (T-136), up with `cat >>`, down with `tail -c`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use podssh_ssh::exec;
use podssh_ssh::sftp::DATA_WAIT;
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::{command, failed, step_failed, Far, Kind};
use crate::cp::digest::{self, Sum};
use crate::cp::resume::{self, Progress};
use crate::cp::transfer::{self, Cause, Done, Failed};
use crate::exitmap::Fault;

/// A piece of a copy up: a multiple of 3, so that base64 pads only the last.
const PIECE: usize = 24 * 1024;

/// Fill `buf` from `reader`, short only at the end.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match reader.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

impl Far {
    /// Copy the local file `source` to `dest` on the server, or write on in
    /// the copy that `progress` holds.
    pub async fn up(
        &self,
        handle: &Connection,
        source: &str,
        dest: &str,
        many: bool,
        log: &Log,
        progress: &mut Progress,
    ) -> Result<Done, Failed> {
        let local = Path::new(source);
        let before = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        if !before.is_file() {
            return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
        }
        let name = local
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| failed(Fault::NoInput, format!("{source}: the name is not UTF-8")))?;
        let target = match &progress.target {
            Some(target) => target.clone(),
            None => self.target(handle, dest, name, many).await?,
        };
        // What came before the break is what the far file holds once its
        // writer, which the break may have left running, stops adding to it.
        let mut kept = None;
        if let Some(temp) = progress.temp.clone() {
            match self.settled(handle, &temp).await? {
                Some(size) if size <= before.len() => kept = Some((temp, size)),
                _ => self.remove(handle, &temp).await,
            }
        }
        let (temp, start) = match kept {
            Some((temp, size)) => {
                progress.offset = size;
                log.verbose(&format!("{source}: continuing {temp} at byte {size} by exec"));
                (temp, size)
            }
            None => {
                let (dir, leaf) = transfer::split_remote(&target);
                let temp = format!("{dir}{}", transfer::temp_name(leaf));
                progress.begin(&target, &temp);
                log.verbose(&format!("{source}: writing {temp} by exec"));
                (temp, 0)
            }
        };
        let script = match (start, self.raw) {
            (0, true) => "umask 077; set -C; exec cat > \"$1\"",
            (0, false) => "umask 077; set -C; exec base64 -d > \"$1\"",
            (_, true) => "exec cat >> \"$1\"",
            (_, false) => "exec base64 -d >> \"$1\"",
        };
        let cmd = command(script, &[&temp]).map_err(|why| failed(Fault::Usage, why))?;
        let copied = async {
            let mut file = std::fs::File::open(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
            let mut hasher = Sha256::new();
            resume::hash_prefix(&mut file, &mut hasher, start)
                .map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
            let mut sent = start;
            let raw = self.raw;
            let mut fill = |piece: &mut Vec<u8>| {
                let mut buf = vec![0u8; PIECE];
                let n = read_full(&mut file, &mut buf)?;
                hasher.update(&buf[..n]);
                sent += n as u64;
                // Sent, not yet known to be written: a break counts the far
                // file again before it goes on.
                progress.advance(sent);
                if raw {
                    piece.extend_from_slice(&buf[..n]);
                } else if n > 0 {
                    piece.extend_from_slice(base64::engine::general_purpose::STANDARD.encode(&buf[..n]).as_bytes());
                }
                Ok(())
            };
            let got = exec::send(handle, &cmd, DATA_WAIT, 4096, &mut fill, &mut |_| Ok(()))
                .await
                .map_err(|e| step_failed(&temp, e))?;
            if got.status != Some(0) {
                let why = String::from_utf8_lossy(&got.stderr);
                return Err(failed(
                    Fault::CantCreate,
                    format!("{temp}: the far side could not write it: {}", why.trim()),
                ));
            }
            let after = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
            if after.len() != sent || after.modified().ok() != before.modified().ok() {
                return Err(failed(Fault::NoInput, format!("{source}: the file changed while it was read")));
            }
            let sum: Sum = hasher.finalize().into();
            let (far, how) = self.digest(handle, &temp, sent).await?;
            transfer::compare(&sum, &far, &how, source)?;
            self.rename(handle, &temp, &target, Some(transfer::local_mode(&before))).await?;
            Ok(Done {
                source: source.into(),
                destination: target.clone(),
                bytes: sent,
                sum: Some(sum),
                verified_by: how,
                not_atomic: false,
                removed: None,
            })
        }
        .await;
        match &copied {
            // Only what the far file held at the start is known to be there;
            // the next attempt counts it again.
            Err(f) if f.cause == Cause::Broke => {
                progress.offset = start;
                progress.save();
            }
            Err(_) => {
                self.remove(handle, &temp).await;
                progress.clear();
            }
            Ok(_) => progress.clear(),
        }
        copied
    }

    /// Copy `source` on the server to the local `dest`, or write on in the
    /// copy that `progress` holds.
    pub async fn down(
        &self,
        handle: &Connection,
        source: &str,
        dest: &str,
        many: bool,
        log: &Log,
        progress: &mut Progress,
    ) -> Result<Done, Failed> {
        let size = match self.kind(handle, source).await? {
            Kind::File(n) => n,
            Kind::Missing => return Err(failed(Fault::NoInput, format!("{source}: no such file or directory"))),
            Kind::Unreadable => return Err(failed(Fault::NoInput, format!("{source}: permission denied"))),
            Kind::Dir | Kind::Other => {
                return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")))
            }
        };
        let (_, name) = transfer::split_remote(source.trim_end_matches('/'));
        if name.is_empty() || name == "." || name == ".." {
            return Err(failed(Fault::NoInput, format!("{source}: names no file")));
        }
        let target = match &progress.target {
            Some(target) => PathBuf::from(target),
            None => transfer::local_target(dest, name, many)?,
        };
        // Without `tail` no read starts past the first byte: start over.
        if !self.tools.contains("tail") {
            progress.offset = 0;
        }
        let (temp, file, start) = resume::local_temp(&target, size, progress)?;
        let shown = temp.display().to_string();
        log.verbose(&match start {
            0 => format!("{source}: writing {shown} by exec"),
            n => format!("{source}: continuing {shown} at byte {n} by exec"),
        });
        let mut out = Some(file);
        let copied = async {
            let mut hasher = Sha256::new();
            if let Some(f) = out.as_mut() {
                resume::hash_prefix(f, &mut hasher, start)
                    .map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
            }
            let mut came = start;
            self.read(handle, source, start, &mut |bytes| {
                hasher.update(bytes);
                out.as_mut().map_or(Ok(()), |f| f.write_all(bytes))?;
                came += bytes.len() as u64;
                progress.advance(came);
                Ok(())
            })
            .await?;
            if came != size {
                return Err(failed(Fault::SessionFault, format!("{source}: {came} bytes came, and wc -c gave {size}")));
            }
            if let Some(f) = out.take() {
                f.sync_all().map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
            }
            let sum: Sum = hasher.finalize().into();
            let on_disk = digest::of_file(&temp).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
            transfer::compare(&sum, &on_disk, "this disk", &shown)?;
            let (far, how) = self.digest(handle, source, size).await?;
            transfer::compare(&sum, &far, &how, source)?;
            std::fs::rename(&temp, &target)
                .map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", target.display())))?;
            Ok(Done {
                source: source.into(),
                destination: target.display().to_string(),
                bytes: came,
                sum: Some(sum),
                verified_by: how,
                not_atomic: false,
                removed: None,
            })
        }
        .await;
        drop(out);
        match &copied {
            Err(f) if f.cause == Cause::Broke => progress.save(),
            Err(_) => {
                let _ = std::fs::remove_file(&temp);
                progress.clear();
            }
            Ok(_) => progress.clear(),
        }
        copied
    }
}
