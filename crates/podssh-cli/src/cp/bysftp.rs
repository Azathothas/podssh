//! The SFTP road's copy of one file, up or down, and its continuation after a
//! broken connection (T-136): the temporary file stays, and the next attempt
//! writes on at the offset below which each byte is in it. The digest covers
//! the whole file, the bytes of each attempt. The reads and the writes go
//! with requests in flight together (T-140), as `pipe` says.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Reads, Sftp, Writes, IN_FLIGHT};
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::chunks;
use super::delta;
use super::digest::{self, Sum};
use super::link::Meter;
use super::pipe::Shape;
use super::resume::{self, Progress};
use super::transfer::{self, Cause, Done, Failed, Side};
use crate::exitmap::Fault;

fn failed(fault: Fault, message: String) -> Failed {
    Failed::new(fault, message)
}

/// What `-v` says of a copy's bytes: how many, in how long, and how fast,
/// before the far digest; `scripts` and the throughput method read it.
fn rate(source: &str, bytes: u64, took: std::time::Duration) -> String {
    let secs = took.as_secs_f64().max(1e-6);
    format!("{source}: {bytes} bytes in {secs:.3} s, {:.2} MiB/s", bytes as f64 / secs / f64::from(1 << 20))
}

/// Whether the relay session may carry `n` more bytes (T-137), with room for
/// a window of requests that are in flight and not yet counted: the failure
/// that says it may not.
fn spent(meter: &Meter, n: u64) -> Option<Failed> {
    meter.spent(n + u64::from(IN_FLIGHT))
}

/// Copy the local file `source` to `dest` on the server, or write on in the
/// copy that `progress` holds.
#[allow(clippy::too_many_arguments)]
pub async fn up(
    sftp: &Sftp,
    handle: &Connection,
    source: &str,
    dest: &str,
    many: bool,
    log: &Log,
    progress: &mut Progress,
    meter: &Meter,
    shape: Shape,
) -> Result<Done, Failed> {
    let pipe = shape.pipe;
    let local = Path::new(source);
    let before = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
    if !before.is_file() {
        return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
    }
    let name = local.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        failed(Fault::NoInput, format!("{source}: the name is not UTF-8, and SFTP names are text here"))
    })?;
    let target = match &progress.target {
        Some(target) => target.clone(),
        None => transfer::remote_target(sftp, dest, name, many).await?,
    };
    // Over an older version, only the blocks that changed (T-142); a copy
    // that broke goes on where it was instead.
    if shape.delta && progress.temp.is_none() {
        if let Some(done) = delta::up(sftp, handle, local, source, &target, &before, shape.pipe, log).await? {
            return Ok(done);
        }
    }
    // Write on in the temporary file when it holds the bytes below the offset.
    let mut kept = None;
    if let Some(temp) = progress.temp.clone() {
        let fits = progress.offset <= before.len()
            && sftp.stat(&temp).await.is_ok_and(|a| a.size.unwrap_or(0) >= progress.offset);
        if fits {
            kept = sftp.open_file(&temp, OpenFlags::WRITE, FileAttributes::default()).await.ok().map(|f| (temp, f));
        } else {
            let _ = sftp.remove(&temp).await;
        }
    }
    let (temp, file) = match kept {
        Some((temp, file)) => {
            log.verbose(&format!("{source}: continuing {temp} at byte {}", progress.offset));
            (temp, file)
        }
        None => {
            let (dir, leaf) = transfer::split_remote(&target);
            let temp = format!("{dir}{}", transfer::temp_name(leaf));
            let attrs = FileAttributes { permissions: Some(0o600), ..FileAttributes::default() };
            let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
            let file =
                sftp.open_file(&temp, flags, attrs).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
            progress.begin(&target, &temp);
            log.verbose(&format!("{source}: writing {temp}"));
            (temp, file)
        }
    };
    let chunked = shape.tasks > 1 && before.len() > chunks::CHUNK;
    let copied = async {
        if chunked {
            // Chunks at once, each over a session of its own (T-141); the
            // digest of the whole source after the last of them.
            let started = std::time::Instant::now();
            let tasks = shape.tasks;
            let each = chunks::share(pipe, tasks, meter.through_relay());
            log.verbose(&format!("{source}: chunks of {} bytes, {tasks} at once", chunks::CHUNK));
            chunks::up(handle, local, &temp, before.len(), tasks, each, progress, meter).await?;
            log.verbose(&rate(source, before.len(), started.elapsed()));
            let sum = digest::of_file(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
            return Ok((before.len(), sum));
        }
        progress.begin_sequential();
        let mut reader = std::fs::File::open(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        let mut hasher = Sha256::new();
        // The bytes that an earlier attempt sent are in the digest too.
        resume::hash_prefix(&mut reader, &mut hasher, progress.offset)
            .map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        let mut offset = progress.offset;
        let started = (std::time::Instant::now(), offset);
        let mut writes = Writes::new(sftp, &file, offset, pipe);
        log.verbose(&format!("{source}: writes of {} bytes, {} in flight", writes.block(), writes.depth()));
        let mut buf = vec![0u8; writes.block() as usize];
        let sent = loop {
            let n = match reader.read(&mut buf) {
                Ok(n) => n,
                Err(e) => break Err(failed(Fault::NoInput, format!("{source}: {e}"))),
            };
            if n == 0 {
                break Ok(());
            }
            if offset + n as u64 > before.len() {
                break Err(transfer::changed(source));
            }
            // Before the relay's limits, a new session goes on (T-137).
            if let Some(spent) = spent(meter, n as u64) {
                break Err(spent);
            }
            hasher.update(&buf[..n]);
            if let Err(e) = writes.send(buf[..n].to_vec()).await {
                break Err(transfer::from_sftp(e, Side::Destination));
            }
            offset += n as u64;
            progress.advance(writes.acked());
        };
        // Each write in flight ends first: the next attempt writes on at the
        // end of the part that the server acknowledged.
        let finished = writes.finish().await;
        progress.advance(writes.acked());
        sent?;
        finished.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        log.verbose(&rate(source, offset - started.1, started.0.elapsed()));
        Ok((offset, hasher.finalize().into()))
    }
    .await;
    let copied = match copied {
        Ok((offset, sum)) => {
            finish_up(sftp, handle, &file, local, source, &temp, &target, &before, offset, sum, log).await
        }
        Err(failed) => Err(failed),
    };
    match &copied {
        // The next connection writes on in it.
        Err(f) if f.cause == Cause::Broke => progress.save(),
        Err(f) if f.cause == Cause::Spent => {
            let _ = sftp.close(&file).await;
            progress.save();
        }
        Err(_) => {
            let _ = sftp.close(&file).await;
            let _ = sftp.remove(&temp).await;
            progress.clear();
        }
        Ok(_) => progress.clear(),
    }
    copied
}

/// The end of a copy up: the temporary file synced and closed, the source
/// unchanged, the digests equal, the mode set, and the rename.
#[allow(clippy::too_many_arguments)]
async fn finish_up(
    sftp: &Sftp,
    handle: &Connection,
    file: &podssh_ssh::sftp::FileHandle,
    local: &Path,
    source: &str,
    temp: &str,
    target: &str,
    before: &std::fs::Metadata,
    offset: u64,
    sum: Sum,
    log: &Log,
) -> Result<Done, Failed> {
    {
        sftp.fsync(file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        sftp.close(file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        let after = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        if after.len() != before.len() || after.modified().ok() != before.modified().ok() || after.len() != offset {
            return Err(transfer::changed(source));
        }
        let (far, how) = transfer::far_digest(handle, sftp, temp, offset, Side::Destination).await?;
        transfer::compare(&sum, &far, &how, source)?;
        let mode = FileAttributes { permissions: Some(transfer::local_mode(before)), ..FileAttributes::default() };
        sftp.setstat(temp, mode).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        let not_atomic = transfer::rename_onto(sftp, temp, target, log).await?;
        Ok(Done {
            source: source.into(),
            destination: target.to_string(),
            bytes: offset,
            sum: Some(sum),
            verified_by: how,
            not_atomic,
            removed: None,
        })
    }
}

/// Copy `source` on the server to the local `dest`, or write on in the copy
/// that `progress` holds.
#[allow(clippy::too_many_arguments)]
pub async fn down(
    sftp: &Sftp,
    handle: &Connection,
    source: &str,
    dest: &str,
    many: bool,
    log: &Log,
    progress: &mut Progress,
    meter: &Meter,
    shape: Shape,
) -> Result<Done, Failed> {
    let pipe = shape.pipe;
    let attrs = sftp.stat(source).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
    if !attrs.is_regular() {
        return Err(failed(Fault::NoInput, format!("{source}: not a regular file; podssh cp copies files")));
    }
    let (_, name) = transfer::split_remote(source.trim_end_matches('/'));
    if name.is_empty() || name == "." || name == ".." {
        return Err(failed(Fault::NoInput, format!("{source}: names no file")));
    }
    let target = match &progress.target {
        Some(target) => PathBuf::from(target),
        None => transfer::local_target(dest, name, many)?,
    };
    let size = attrs.size.unwrap_or(0);
    // Over an older version here, only the blocks that changed (T-142).
    if shape.delta && progress.temp.is_none() {
        if let Some(done) = delta::down(sftp, handle, source, &target, size, attrs.permissions, pipe, log).await? {
            return Ok(done);
        }
    }
    let chunked = shape.tasks > 1 && size > chunks::CHUNK;
    let (temp, file, start) = resume::local_temp(&target, size, progress, chunked)?;
    let shown = temp.display().to_string();
    log.verbose(&match start {
        0 => format!("{source}: writing {shown}"),
        n => format!("{source}: continuing {shown} at byte {n}"),
    });
    // An Option, so that the file is closed before it is read back and
    // renamed: Windows renames no open file.
    let mut out = Some(file);
    let copied: Result<Done, Failed> = async {
        if chunked {
            // Chunks at once, each over a session of its own (T-141); a file
            // that grew or shrank since the start fails, as it does in one
            // stream; the digest of the whole file after the last chunk.
            drop(out.take());
            let started = std::time::Instant::now();
            let tasks = shape.tasks;
            let each = chunks::share(pipe, tasks, meter.through_relay());
            log.verbose(&format!("{source}: chunks of {} bytes, {tasks} at once", chunks::CHUNK));
            chunks::down(handle, source, &temp, size, tasks, each, progress, meter).await?;
            log.verbose(&rate(source, size, started.elapsed()));
            match sftp.stat(source).await {
                Ok(now) if now.size == attrs.size => {}
                Ok(_) => return Err(transfer::changed(source)),
                Err(e) => return Err(transfer::from_sftp(e, Side::Source)),
            }
            let sum = digest::of_file(&temp).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
            let (far, how) = transfer::far_digest(handle, sftp, source, size, Side::Source).await?;
            transfer::compare(&sum, &far, &how, source)?;
            transfer::set_local_mode(&temp, attrs.permissions);
            std::fs::rename(&temp, &target)
                .map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", target.display())))?;
            return Ok(Done {
                source: source.into(),
                destination: target.display().to_string(),
                bytes: size,
                sum: Some(sum),
                verified_by: how,
                not_atomic: false,
                removed: None,
            });
        }
        progress.begin_sequential();
        let mut hasher = Sha256::new();
        if let Some(f) = out.as_mut() {
            resume::hash_prefix(f, &mut hasher, start)
                .map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        }
        let file = sftp
            .open_file(source, OpenFlags::READ, FileAttributes::default())
            .await
            .map_err(|e| transfer::from_sftp(e, Side::Source))?;
        let mut offset = start;
        // Past the size that the file had at the start, a second look at its
        // size tells a file that grows, which a read would follow while it
        // grows (T-267), from a file of /proc, which says 0 and has bytes.
        let mut looked = false;
        let started = std::time::Instant::now();
        let mut reads = Reads::new(sftp, &file, start, pipe);
        log.verbose(&format!("{source}: reads of {} bytes, {} in flight", reads.block(), reads.depth()));
        // A read below the size of the start goes out only while the relay
        // session may carry it (T-137); the failure that stopped them.
        let mut stopped = None;
        let read = loop {
            let next = {
                let mut allow = |at: u64, len: u32| {
                    if at >= size {
                        return true;
                    }
                    stopped = spent(meter, u64::from(len));
                    stopped.is_none()
                };
                reads.next(&mut allow).await
            };
            match next {
                Ok(Some(data)) => {
                    if !looked && offset + data.len() as u64 > size {
                        looked = true;
                        match sftp.stat(source).await {
                            Ok(now) if now.size == attrs.size => {}
                            Ok(_) => break Err(transfer::changed(source)),
                            Err(e) => break Err(transfer::from_sftp(e, Side::Source)),
                        }
                    }
                    hasher.update(&data);
                    if let Err(e) = out.as_mut().map_or(Ok(()), |f| f.write_all(&data)) {
                        break Err(failed(Fault::CantCreate, format!("{shown}: {e}")));
                    }
                    offset += data.len() as u64;
                    progress.advance(offset);
                }
                Ok(None) => break stopped.take().map_or(Ok(()), Err),
                Err(e) => break Err(transfer::from_sftp(e, Side::Source)),
            }
        };
        drop(reads);
        let _ = sftp.close(&file).await;
        read?;
        log.verbose(&rate(source, offset - start, started.elapsed()));
        if let Some(f) = out.take() {
            f.sync_all().map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        }
        let sum: Sum = hasher.finalize().into();
        let on_disk = digest::of_file(&temp).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        transfer::compare(&sum, &on_disk, "this disk", &shown)?;
        let (far, how) = transfer::far_digest(handle, sftp, source, offset, Side::Source).await?;
        transfer::compare(&sum, &far, &how, source)?;
        transfer::set_local_mode(&temp, attrs.permissions);
        std::fs::rename(&temp, &target).map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", target.display())))?;
        Ok(Done {
            source: source.into(),
            destination: target.display().to_string(),
            bytes: offset,
            sum: Some(sum),
            verified_by: how,
            not_atomic: false,
            removed: None,
        })
    }
    .await;
    drop(out);
    match &copied {
        Err(f) if matches!(f.cause, Cause::Broke | Cause::Spent) => progress.save(),
        Err(_) => {
            let _ = std::fs::remove_file(&temp);
            progress.clear();
        }
        Ok(_) => progress.clear(),
    }
    copied
}
