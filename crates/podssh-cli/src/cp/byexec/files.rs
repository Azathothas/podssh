//! The steps of a copy by exec that move a file, up and down. Each writes
//! under a temporary name, compares the digests, then renames; a failure
//! removes the temporary file.

use std::io::{Read, Write};
use std::path::Path;

use base64::Engine;
use podssh_ssh::exec;
use podssh_ssh::sftp::DATA_WAIT;
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::{command, failed, step_failed, Far, Kind};
use crate::cp::digest::{self, Sum};
use crate::cp::transfer::{self, Done, Failed};
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
    /// Copy the local file `source` to `dest` on the server.
    pub async fn up(
        &self,
        handle: &Connection,
        source: &str,
        dest: &str,
        many: bool,
        log: &Log,
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
        let target = self.target(handle, dest, name, many).await?;
        let (dir, leaf) = transfer::split_remote(&target);
        let temp = format!("{dir}{}", transfer::temp_name(leaf));
        let script = if self.raw {
            "umask 077; set -C; exec cat > \"$1\""
        } else {
            "umask 077; set -C; exec base64 -d > \"$1\""
        };
        let cmd = command(script, &[&temp]).map_err(|why| failed(Fault::Usage, why))?;
        log.verbose(&format!("{source}: writing {temp} by exec"));
        let copied = async {
            let mut file = std::fs::File::open(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
            let mut hasher = Sha256::new();
            let mut sent = 0u64;
            let raw = self.raw;
            let mut fill = |piece: &mut Vec<u8>| {
                let mut buf = vec![0u8; PIECE];
                let n = read_full(&mut file, &mut buf)?;
                hasher.update(&buf[..n]);
                sent += n as u64;
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
        if copied.is_err() {
            self.remove(handle, &temp).await;
        }
        copied
    }

    /// Copy `source` on the server to the local `dest`.
    pub async fn down(
        &self,
        handle: &Connection,
        source: &str,
        dest: &str,
        many: bool,
        log: &Log,
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
        let target = transfer::local_target(dest, name, many)?;
        let leaf = target.file_name().and_then(|n| n.to_str()).unwrap_or(name).to_string();
        let temp = target.with_file_name(transfer::temp_name(&leaf));
        let shown = temp.display().to_string();
        let mut out =
            Some(transfer::create_private(&temp).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?);
        log.verbose(&format!("{source}: writing {shown} by exec"));
        let copied = async {
            let mut hasher = Sha256::new();
            let came = self
                .read(handle, source, &mut |bytes| {
                    hasher.update(bytes);
                    out.as_mut().map_or(Ok(()), |f| f.write_all(bytes))
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
        if copied.is_err() {
            drop(out);
            let _ = std::fs::remove_file(&temp);
        }
        copied
    }
}
