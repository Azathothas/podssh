//! The SFTP road's copy of one file, up or down, and its continuation after a
//! broken connection (T-136): the temporary file stays, and the next attempt
//! writes on at the offset below which each byte is in it. The digest covers
//! the whole file, the bytes of each attempt. The reads and the writes go
//! with requests in flight together (T-140), as `pipe` says. A block of zeros
//! of a sparse file is a hole, never sent (T-146, [`meta`]).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Reads, Sftp, Writes, IN_FLIGHT};
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::chunks;
use super::delta;
use super::digest::{self, Sum};
use super::in_place;
use super::link::Meter;
use super::meta::{self, Keep, Stamp};
use super::pipe::Shape;
use super::resume::{self, Progress};
use super::transfer::{self, Cause, Done, Failed, Side};
use super::{gauge, rate};
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
    if before.is_dir() {
        return Err(failed(Fault::NoInput, format!("{source}: a directory; -r copies it")));
    }
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
    if shape.inplace {
        in_place::check_far(sftp, &target).await?;
    }
    // Over an older version, only the blocks that changed (T-142); a copy
    // that broke goes on where it was instead.
    if shape.delta && progress.temp.is_none() {
        if let Some(done) = delta::up(sftp, handle, local, source, &target, &before, shape, log).await? {
            return Ok(done);
        }
    }
    let chunked = shape.tasks > 1 && before.len() > chunks::CHUNK;
    // Holes for the blocks of zeros of a sparse file, or of each file with
    // --sparse; not with chunks, which may write a block again (T-146), nor
    // into the destination itself, whose old bytes would stay (T-147).
    let holes = !chunked && !shape.inplace && (shape.keep.sparse || meta::is_sparse(&before));
    // Write on in the temporary file when it holds the bytes below the offset.
    let mut kept = None;
    if let Some(temp) = progress.temp.clone() {
        let far = sftp.stat(&temp).await.ok().and_then(|a| a.size);
        let fits = progress.offset <= before.len() && far.is_some_and(|size| holes || size >= progress.offset);
        // With holes the size becomes the offset: a hole at the end counts,
        // and what a write past it left goes, so the next hole reads as zeros.
        let size = FileAttributes { size: Some(progress.offset), ..FileAttributes::default() };
        let cut = fits && (!holes || sftp.setstat(&temp, size).await.is_ok());
        if cut {
            kept = sftp.open_file(&temp, OpenFlags::WRITE, FileAttributes::default()).await.ok().map(|f| (temp, f));
        } else if resume::is_temp(&temp) {
            let _ = sftp.remove(&temp).await;
        }
    }
    let (temp, file) = match kept {
        Some((temp, file)) => {
            log.verbose(&format!("{source}: continuing {temp} at byte {}", progress.offset));
            (temp, file)
        }
        None if shape.inplace => {
            let file = in_place::open_far(sftp, &target).await?;
            progress.begin(&target, &target);
            log.verbose(&format!("{source}: writing into {target} itself"));
            (target.clone(), file)
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
        let mut writes = Writes::new(sftp, &file, offset, rate::shaped(pipe, sftp.write_len()));
        log.verbose(&format!("{source}: writes of {} bytes, {} in flight", writes.block(), writes.depth()));
        let mut bar = gauge::Gauge::new(source, before.len(), offset);
        let block = writes.block() as usize;
        // With holes, reads of whole blocks of zeros, aligned in the file.
        let hole = meta::HOLE as usize;
        let unit = if holes { block.max(hole) / hole * hole } else { block };
        let mut buf = vec![0u8; unit];
        let sent = loop {
            let want = if holes { unit - (offset % meta::HOLE) as usize } else { unit };
            let n = match reader.read(&mut buf[..want]) {
                Ok(n) => n,
                Err(e) => break Err(failed(Fault::NoInput, format!("{source}: {e}"))),
            };
            if n == 0 {
                break Ok(());
            }
            if offset + n as u64 > before.len() {
                break Err(transfer::changed(source));
            }
            let runs = meta::runs(offset, &buf[..n], holes);
            let carried: usize = runs.iter().filter(|(hole, _)| !hole).map(|(_, r)| r.len()).sum();
            // Before the relay's limits, a new session goes on (T-137).
            if let Some(spent) = spent(meter, carried as u64) {
                break Err(spent);
            }
            hasher.update(&buf[..n]);
            rate::take(carried as u64).await;
            if let Err(e) = meta::send_runs(&mut writes, &buf[..n], runs, block).await {
                break Err(transfer::from_sftp(e, Side::Destination));
            }
            offset += n as u64;
            progress.advance(writes.acked());
            bar.set(offset);
        };
        bar.finish();
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
            let ends = Ends { offset, sum, keep: shape.keep, holes, inplace: shape.inplace, mode: shape.mode };
            finish_up(sftp, handle, &file, local, source, &temp, &target, &before, ends, log).await
        }
        Err(failed) => Err(failed),
    };
    let copied = copied.map_err(|f| if shape.inplace { in_place::damaged(f, &target) } else { f });
    match &copied {
        // The next connection writes on in it.
        Err(f) if f.cause == Cause::Broke => progress.save(),
        Err(f) if f.cause == Cause::Spent => {
            let _ = sftp.close(&file).await;
            progress.save();
        }
        Err(_) => {
            let _ = sftp.close(&file).await;
            if temp != target {
                let _ = sftp.remove(&temp).await;
            }
            progress.clear();
        }
        Ok(_) => progress.clear(),
    }
    copied
}

/// How a copy up ended: its bytes, their digest, what it keeps, whether it
/// left holes, and whether it wrote into the destination itself.
struct Ends {
    offset: u64,
    sum: Sum,
    keep: Keep,
    holes: bool,
    inplace: bool,
    /// The far file's mode that `podssh edit` keeps (T-149).
    mode: Option<u32>,
}

/// The end of a copy up: the temporary file synced and closed, its size set
/// after holes, the source unchanged, the digests equal, what the copy keeps
/// set, and the rename.
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
    ends: Ends,
    log: &Log,
) -> Result<Done, Failed> {
    let Ends { offset, sum, keep, holes, inplace, mode } = ends;
    {
        sftp.fsync(file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        sftp.close(file).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        // After holes, and into the destination itself, whose old bytes past
        // the new end go (T-147).
        if holes || inplace {
            let size = FileAttributes { size: Some(offset), ..FileAttributes::default() };
            sftp.setstat(temp, size).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
        }
        let after = std::fs::metadata(local).map_err(|e| failed(Fault::NoInput, format!("{source}: {e}")))?;
        if after.len() != before.len() || after.modified().ok() != before.modified().ok() || after.len() != offset {
            return Err(transfer::changed(source));
        }
        let (far, how) = transfer::far_digest(handle, sftp, temp, offset, Side::Destination).await?;
        transfer::compare(&sum, &far, &how, source)?;
        // The source's mode, or the far file's that `podssh edit` keeps.
        let mut stamp = Stamp::of_local(before);
        stamp.mode = mode.or(stamp.mode);
        meta::set_far(sftp, temp, &stamp, keep, log).await?;
        let mut not_atomic = false;
        if !inplace {
            not_atomic = transfer::rename_onto(sftp, temp, target, log).await?;
            meta::times_after_rename(sftp, target, &stamp, keep).await;
        }
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
    if attrs.is_dir() {
        return Err(failed(Fault::NoInput, format!("{source}: a directory; -r copies it")));
    }
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
    if shape.inplace {
        in_place::check_local(&target)?;
    }
    // Over an older version here, only the blocks that changed (T-142).
    let stamp = Stamp::of_far(&attrs, 0o777);
    if shape.delta && progress.temp.is_none() {
        if let Some(done) = delta::down(sftp, handle, source, &target, size, &stamp, shape, log).await? {
            return Ok(done);
        }
    }
    let chunked = shape.tasks > 1 && size > chunks::CHUNK;
    let (temp, file, start) = match shape.inplace {
        true => in_place::open_local(&target, progress)?,
        false => resume::local_temp(&target, size, progress, chunked)?,
    };
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
            if shape.inplace {
                let cut = std::fs::OpenOptions::new().write(true).open(&temp).and_then(|f| f.set_len(size));
                cut.map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
            }
            log.verbose(&rate(source, size, started.elapsed()));
            match sftp.stat(source).await {
                Ok(now) if now.size == attrs.size => {}
                Ok(_) => return Err(transfer::changed(source)),
                Err(e) => return Err(transfer::from_sftp(e, Side::Source)),
            }
            let sum = digest::of_file(&temp).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
            let (far, how) = transfer::far_digest(handle, sftp, source, size, Side::Source).await?;
            transfer::compare(&sum, &far, &how, source)?;
            meta::set_local(&temp, &stamp, shape.keep, log)?;
            if !shape.inplace {
                std::fs::rename(&temp, &target)
                    .map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", target.display())))?;
            }
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
        let mut reads = Reads::new(sftp, &file, start, rate::shaped(pipe, sftp.read_len()));
        let mut bar = gauge::Gauge::new(source, size, start);
        // --sparse: the blocks of zeros are holes here (T-146); not in the
        // destination itself, whose old bytes would stay.
        let mut holes = (shape.keep.sparse && !shape.inplace).then(|| meta::Holes::new(start));
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
                    let wrote = match (out.as_mut(), holes.as_mut()) {
                        (Some(f), Some(h)) => h.write(f, &data),
                        (Some(f), None) => f.write_all(&data),
                        (None, _) => Ok(()),
                    };
                    if let Err(e) = wrote {
                        break Err(failed(Fault::CantCreate, format!("{shown}: {e}")));
                    }
                    offset += data.len() as u64;
                    // What is on the disk: a block held for its hole is not.
                    progress.advance(holes.as_ref().map_or(offset, meta::Holes::done));
                    bar.set(offset);
                    rate::take(data.len() as u64).await;
                }
                Ok(None) => break stopped.take().map_or(Ok(()), Err),
                Err(e) => break Err(transfer::from_sftp(e, Side::Source)),
            }
        };
        drop(reads);
        bar.finish();
        let _ = sftp.close(&file).await;
        if let (Some(f), Some(h)) = (out.as_mut(), holes.as_mut()) {
            // After a failure the file reaches the offset of its record, a
            // hole at its end included; else what is held is written too.
            let ended = if read.is_err() { f.set_len(h.done()) } else { h.finish(f) };
            ended.map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        }
        read?;
        log.verbose(&rate(source, offset - start, started.elapsed()));
        if let Some(f) = out.take() {
            // Into the destination itself: its old bytes past the end go.
            let cut = if shape.inplace { f.set_len(offset) } else { Ok(()) };
            cut.and_then(|()| f.sync_all()).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        }
        let sum: Sum = hasher.finalize().into();
        let on_disk = digest::of_file(&temp).map_err(|e| failed(Fault::CantCreate, format!("{shown}: {e}")))?;
        transfer::compare(&sum, &on_disk, "this disk", &shown)?;
        let (far, how) = transfer::far_digest(handle, sftp, source, offset, Side::Source).await?;
        transfer::compare(&sum, &far, &how, source)?;
        meta::set_local(&temp, &stamp, shape.keep, log)?;
        if !shape.inplace {
            let renamed = std::fs::rename(&temp, &target);
            renamed.map_err(|e| failed(Fault::CantCreate, format!("{}: {e}", target.display())))?;
        }
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
    let copied = copied.map_err(|f| if shape.inplace { in_place::damaged(f, &shown) } else { f });
    match &copied {
        Err(f) if matches!(f.cause, Cause::Broke | Cause::Spent) => progress.save(),
        Err(_) => {
            if temp != target {
                let _ = std::fs::remove_file(&temp);
            }
            progress.clear();
        }
        Ok(_) => progress.clear(),
    }
    copied
}
