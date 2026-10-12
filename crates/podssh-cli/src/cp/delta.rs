//! A copy that sends only the blocks that changed (T-142), with `--delta`,
//! over an older version of the same file on the other side. The blocks are
//! fixed, of [`BLOCK`]: the SHA-256 of each block of the far file comes from
//! one command over exec (`dd` into the server's digest tool), and that of
//! each local block is read here. The temporary file is made from the old
//! one where it is (`copy-data` inside the server, or a copy on this disk),
//! only the blocks that differ cross, and the size is set. The digest of the
//! whole file then decides, as for each copy: a difference falls back once to
//! a full copy, and says so. A server with no command, no `dd`, no digest
//! tool or no `copy-data` gets a full copy, and `-v` says why.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Pipeline, Reads, Sftp, Writes};
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::chunks::{read_at, write_at};
use super::digest::{self, Sum};
use super::meta::{self, Keep, Stamp};
use super::transfer::{self, Done, Failed, Side};
use crate::exitmap::Fault;

/// The bytes of each block.
pub const BLOCK: u64 = 1 << 20;

/// What a delta copy does: the blocks of the new file to send, by index,
/// those kept from the old one, and the new file's size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub send: Vec<u64>,
    pub kept: u64,
    pub size: u64,
}

impl Plan {
    /// The bytes that the blocks to send hold.
    pub fn bytes(&self) -> u64 {
        self.send.iter().map(|i| BLOCK.min(self.size - i * BLOCK)).sum()
    }
}

/// The plan for a new file of `size` bytes whose blocks have the digests
/// `new`, over an old file whose blocks have the digests `old`: each block
/// whose digest differs, or that the old file does not have, is sent; the
/// size then cuts what the old file has past it.
pub fn plan(new: &[Sum], old: &[Sum], size: u64) -> Plan {
    let send: Vec<u64> =
        new.iter().enumerate().filter(|(i, sum)| old.get(*i) != Some(*sum)).map(|(i, _)| i as u64).collect();
    let kept = new.len() as u64 - send.len() as u64;
    Plan { send, kept, size }
}

/// The digest of each block of the local file `path`.
pub fn local_blocks(path: &Path) -> std::io::Result<Vec<Sum>> {
    let mut file = std::fs::File::open(path)?;
    let mut sums = Vec::new();
    let mut buf = vec![0u8; BLOCK as usize];
    loop {
        let mut filled = 0;
        while filled < buf.len() {
            let n = file.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            return Ok(sums);
        }
        sums.push(Sha256::digest(&buf[..filled]).into());
        if filled < buf.len() {
            return Ok(sums);
        }
    }
}

/// For a POSIX shell: a marker line, then the digest of each block of `$1`,
/// `$2` blocks of 1 MiB, by the first digest tool that the server has.
const SCRIPT: &str = "command -v dd >/dev/null 2>&1 || exit 127; \
t=; for c in sha256sum shasum openssl; do command -v $c >/dev/null 2>&1 && { t=$c; break; }; done; \
[ -n \"$t\" ] || exit 127; echo podssh-blocks; i=0; \
while [ $i -lt \"$2\" ]; do dd if=\"$1\" bs=1048576 skip=$i count=1 2>/dev/null | \
case $t in sha256sum) sha256sum;; shasum) shasum -a 256;; *) openssl dgst -sha256 -r;; esac; \
i=$((i+1)); done";

/// The digests that [`SCRIPT`] printed after its marker, when there are
/// `blocks` of them.
fn read_blocks(stdout: &[u8], blocks: u64) -> Option<Vec<Sum>> {
    let text = String::from_utf8_lossy(stdout);
    let after = text.rsplit_once("podssh-blocks\n")?.1;
    let sums: Option<Vec<Sum>> =
        after.lines().map(|line| digest::from_hex(line.split_whitespace().next().unwrap_or(""))).collect();
    sums.filter(|s| s.len() as u64 == blocks)
}

/// The digest of each block of `path` on the server, of `size` bytes, by a
/// command over exec; `None` when the server runs none, or lacks a tool.
pub async fn far_blocks(handle: &Connection, path: &str, size: u64) -> Option<Vec<Sum>> {
    let word = podssh_ssh::exec::shell_word(path)?;
    let blocks = size.div_ceil(BLOCK);
    let command = format!("sh -c '{SCRIPT}' sh {word} {blocks}");
    // Each block is read once: 30 s, and 1 s more for each 32 MiB.
    let limit = Duration::from_secs(30 + size / (32 << 20));
    let got = podssh_ssh::exec::capture(handle, &command, limit, 4096 + 80 * blocks as usize).await.ok()?;
    if got.status != Some(0) {
        return None;
    }
    read_blocks(&got.stdout, blocks)
}

/// A copy up by blocks over the older `target` on the server: the copy's
/// result, or `None` when it goes in full (no command, no `copy-data`, or
/// digests that differ after the delta, each said at `-v` or as a note).
#[allow(clippy::too_many_arguments)]
pub async fn up(
    sftp: &Sftp,
    handle: &Connection,
    local: &Path,
    source: &str,
    target: &str,
    before: &std::fs::Metadata,
    pipe: Pipeline,
    keep: Keep,
    log: &Log,
) -> Result<Option<Done>, Failed> {
    let old = match sftp.stat(target).await {
        Ok(attrs) if attrs.is_regular() && attrs.size.unwrap_or(0) > 0 => attrs,
        _ => return Ok(None),
    };
    if !sftp.has("copy-data") {
        log.verbose(&format!("{source}: the server has no copy-data: a full copy"));
        return Ok(None);
    }
    let absolute = sftp.realpath(target).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
    let Some(far) = far_blocks(handle, &absolute, old.size.unwrap_or(0)).await else {
        log.verbose(&format!("{source}: the server gives no digest of a block: a full copy"));
        return Ok(None);
    };
    let near = local_blocks(local).map_err(|e| Failed::new(Fault::NoInput, format!("{source}: {e}")))?;
    let plan = plan(&near, &far, before.len());
    let (dir, leaf) = transfer::split_remote(target);
    let temp = format!("{dir}{}", transfer::temp_name(leaf));
    let made = async {
        // The temporary file is the old one, made inside the server.
        let attrs = FileAttributes { permissions: Some(0o600), ..FileAttributes::default() };
        let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
        let file = sftp.open_file(&temp, flags, attrs).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        let from = sftp
            .open_file(target, OpenFlags::READ, FileAttributes::default())
            .await
            .map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        let limit = podssh_ssh::sftp::DATA_WAIT + Duration::from_secs(old.size.unwrap_or(0) / (16 << 20));
        let copied = sftp.copy_data(&from, &file, limit).await;
        let _ = sftp.close(&from).await;
        copied.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        let reader = std::fs::File::open(local).map_err(|e| Failed::new(Fault::NoInput, format!("{source}: {e}")))?;
        for &i in &plan.send {
            let at = i * BLOCK;
            let mut writes = Writes::new(sftp, &file, at, pipe);
            let mut buf = vec![0u8; writes.block() as usize];
            let mut pos = at;
            let end = (at + BLOCK).min(plan.size);
            while pos < end {
                let want = ((end - pos) as usize).min(buf.len());
                let n = read_at(&reader, pos, &mut buf[..want])
                    .map_err(|e| Failed::new(Fault::NoInput, format!("{source}: {e}")))?;
                if n < want {
                    return Err(transfer::changed(source));
                }
                writes.send(buf[..n].to_vec()).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
                pos += n as u64;
            }
            writes.finish().await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        }
        let size = FileAttributes { size: Some(plan.size), ..FileAttributes::default() };
        sftp.setstat(&temp, size).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        sftp.fsync(&file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        sftp.close(&file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        Ok(())
    }
    .await;
    if let Err(failed) = made {
        let _ = sftp.remove(&temp).await;
        return Err(failed);
    }
    log.verbose(&said(source, &plan, near.len()));
    let after = std::fs::metadata(local).map_err(|e| Failed::new(Fault::NoInput, format!("{source}: {e}")))?;
    if after.len() != before.len() || after.modified().ok() != before.modified().ok() {
        let _ = sftp.remove(&temp).await;
        return Err(transfer::changed(source));
    }
    let sum = digest::of_file(local).map_err(|e| Failed::new(Fault::NoInput, format!("{source}: {e}")))?;
    let (far_sum, how) = transfer::far_digest(handle, sftp, &temp, plan.size, Side::Destination).await?;
    if far_sum != sum {
        let _ = sftp.remove(&temp).await;
        log.info(&format!("{source}: the digests differ after the delta ({how}): a full copy follows"));
        return Ok(None);
    }
    let stamp = Stamp::of_local(before);
    if let Err(failed) = meta::set_far(sftp, &temp, &stamp, keep, log).await {
        let _ = sftp.remove(&temp).await;
        return Err(failed);
    }
    let not_atomic = transfer::rename_onto(sftp, &temp, target, log).await?;
    meta::times_after_rename(sftp, target, &stamp, keep).await;
    Ok(Some(Done {
        source: source.into(),
        destination: target.to_string(),
        bytes: plan.size,
        sum: Some(sum),
        verified_by: how,
        not_atomic,
        removed: None,
    }))
}

/// What `-v` says of a delta: the blocks sent, of how many, and their bytes.
fn said(source: &str, plan: &Plan, blocks: usize) -> String {
    format!("{source}: delta: {} of {blocks} blocks sent, {} bytes", plan.send.len(), plan.bytes())
}

/// A copy down by blocks over the older local `target`: the copy's result,
/// or `None` when it goes in full.
#[allow(clippy::too_many_arguments)]
pub async fn down(
    sftp: &Sftp,
    handle: &Connection,
    source: &str,
    target: &Path,
    size: u64,
    stamp: &Stamp,
    pipe: Pipeline,
    keep: Keep,
    log: &Log,
) -> Result<Option<Done>, Failed> {
    if !std::fs::metadata(target).is_ok_and(|m| m.is_file() && m.len() > 0) {
        return Ok(None);
    }
    let absolute = sftp.realpath(source).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
    let Some(far) = far_blocks(handle, &absolute, size).await else {
        log.verbose(&format!("{source}: the server gives no digest of a block: a full copy"));
        return Ok(None);
    };
    let shown = target.display().to_string();
    let near = local_blocks(target).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
    let plan = plan(&far, &near, size);
    let leaf = target.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let temp: PathBuf = target.with_file_name(transfer::temp_name(leaf));
    let made = async {
        // The temporary file is the old one, copied on this disk.
        let out =
            transfer::create_private(&temp).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
        let mut old =
            std::fs::File::open(target).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
        std::io::copy(&mut old, &mut &out).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
        let file = sftp
            .open_file(source, OpenFlags::READ, FileAttributes::default())
            .await
            .map_err(|e| transfer::from_sftp(e, Side::Source))?;
        let fetched = async {
            for &i in &plan.send {
                let at = i * BLOCK;
                let end = (at + BLOCK).min(size);
                let mut reads = Reads::new(sftp, &file, at, pipe);
                let mut allow = |offset: u64, _: u32| offset < end;
                let mut pos = at;
                while pos < end {
                    match reads.next(&mut allow).await {
                        Ok(Some(data)) => {
                            let take = ((end - pos) as usize).min(data.len());
                            write_at(&out, pos, &data[..take])
                                .map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
                            pos += take as u64;
                        }
                        Ok(None) => return Err(transfer::changed(source)),
                        Err(e) => return Err(transfer::from_sftp(e, Side::Source)),
                    }
                }
            }
            Ok(())
        }
        .await;
        let _ = sftp.close(&file).await;
        fetched?;
        out.set_len(size)
            .and_then(|()| out.sync_all())
            .map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
        Ok(())
    }
    .await;
    if let Err(failed) = made {
        let _ = std::fs::remove_file(&temp);
        return Err(failed);
    }
    log.verbose(&said(source, &plan, far.len()));
    let sum = digest::of_file(&temp).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
    let (far_sum, how) = transfer::far_digest(handle, sftp, source, size, Side::Source).await?;
    if far_sum != sum {
        let _ = std::fs::remove_file(&temp);
        log.info(&format!("{source}: the digests differ after the delta ({how}): a full copy follows"));
        return Ok(None);
    }
    if let Err(failed) = meta::set_local(&temp, stamp, keep, log) {
        let _ = std::fs::remove_file(&temp);
        return Err(failed);
    }
    std::fs::rename(&temp, target).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
    Ok(Some(Done {
        source: source.into(),
        destination: shown,
        bytes: size,
        sum: Some(sum),
        verified_by: how,
        not_atomic: false,
        removed: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_s_digests_are_read_after_its_marker() {
        let one = "a".repeat(64);
        let two = "b".repeat(64);
        let out = format!("a banner\npodssh-blocks\n{one}  -\n{two} *stdin\n");
        let got = read_blocks(out.as_bytes(), 2).expect("two digests");
        assert_eq!(digest::hex(&got[0]), one);
        assert_eq!(digest::hex(&got[1]), two);
        assert_eq!(read_blocks(out.as_bytes(), 3), None, "a block missing");
        assert_eq!(read_blocks(b"podssh-blocks\nnot a digest\n", 1), None);
        assert_eq!(read_blocks(b"no marker\n", 0), None);
    }

    #[test]
    fn the_script_holds_no_single_quote() {
        assert!(!SCRIPT.contains('\''), "it goes between single quotes");
    }
}
