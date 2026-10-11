//! A copy in chunks over several channels of one connection (T-141). A file
//! of more than one chunk goes as chunks of [`CHUNK`] at fixed offsets, taken
//! in turn by up to K tasks (`--parallel K`), each with an SFTP session of its
//! own, so a channel and a window of its own, in the one SSH connection; each
//! writes its chunks into the temporary file at their offsets. The side file
//! keeps the start of each chunk that is done, so a copy that breaks goes on
//! with the others. The digest covers the whole file after the last chunk,
//! and nothing is renamed before it.
//!
//! Through the relay the tasks share the room of one session: [`RELAY_ROOM`]
//! in flight at most, below the 2 MiB queued that close it (`1013`,
//! `docs/relay.md`). A task takes a chunk only while the session may carry it
//! whole (T-137): when it may not, each task ends its chunk, and a new session
//! goes on with the chunks left.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Mutex;

use podssh_ssh::sftp::{FileAttributes, Limits, OpenFlags, Pipeline, Reads, Sftp, Writes, IN_FLIGHT};
use podssh_ssh::Connection;

use super::link::Meter;
use super::resume::Progress;
use super::transfer::{self, Failed, Side};
use crate::exitmap::Fault;

/// The bytes of each chunk.
pub const CHUNK: u64 = 8 << 20;
/// The tasks of one copy at most.
pub const MOST_TASKS: usize = 16;
/// Through the relay, the bytes in flight of all the tasks together.
pub const RELAY_ROOM: u32 = 3 * IN_FLIGHT;

/// The chunks of a file of `size` bytes, each `(start, length)`.
pub fn plan(size: u64, chunk: u64) -> Vec<(u64, u64)> {
    (0..size.div_ceil(chunk)).map(|i| (i * chunk, chunk.min(size - i * chunk))).collect()
}

/// The pipeline of each of `tasks` tasks: the room of one relay session
/// shared, or each its own window on a direct connection.
pub fn share(pipe: Pipeline, tasks: usize, relay: bool) -> Pipeline {
    let room = if relay { RELAY_ROOM / tasks.max(1) as u32 } else { IN_FLIGHT };
    Pipeline { in_flight: room.min(pipe.in_flight), ..pipe }
}

/// What the tasks share: the chunks left, the first failure, and the record.
struct Shared<'a> {
    queue: Mutex<VecDeque<(u64, u64)>>,
    stop: Mutex<Option<Failed>>,
    progress: Mutex<&'a mut Progress>,
    size: u64,
    meter: &'a Meter,
}

impl<'a> Shared<'a> {
    /// The chunks of `size` that `progress` does not hold yet, and the tasks
    /// for them: as many as asked, one for each chunk at most.
    fn new(size: u64, tasks: usize, progress: &'a mut Progress, meter: &'a Meter) -> (Shared<'a>, usize) {
        progress.begin_chunks(CHUNK);
        let todo: VecDeque<(u64, u64)> =
            plan(size, CHUNK).into_iter().filter(|(at, _)| !progress.has_chunk(*at)).collect();
        let tasks = tasks.clamp(1, MOST_TASKS).min(todo.len().max(1));
        let shared =
            Shared { queue: Mutex::new(todo), stop: Mutex::new(None), progress: Mutex::new(progress), size, meter };
        (shared, tasks)
    }

    /// The next chunk, while no task has failed and the relay session may
    /// carry it whole, with the room of the tasks' requests more.
    fn take(&self) -> Option<(u64, u64)> {
        if self.stop.lock().unwrap().is_some() {
            return None;
        }
        let mut queue = self.queue.lock().unwrap();
        let (at, len) = *queue.front()?;
        if let Some(spent) = self.meter.spent(len + u64::from(RELAY_ROOM)) {
            drop(queue);
            self.fail(spent);
            return None;
        }
        queue.pop_front();
        Some((at, len))
    }

    /// The first failure: each other task ends at the end of its chunk.
    fn fail(&self, failed: Failed) {
        self.stop.lock().unwrap().get_or_insert(failed);
    }

    fn done(&self, at: u64) {
        self.progress.lock().unwrap().finish_chunk(at, CHUNK, self.size);
    }

    /// Each task has ended: the first failure, or none.
    fn end(self) -> Result<(), Failed> {
        match self.stop.into_inner().unwrap() {
            Some(failed) => Err(failed),
            None => Ok(()),
        }
    }
}

/// Write `data` into `file` at `at`.
pub(super) fn write_at(file: &std::fs::File, at: u64, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_all_at(file, data, at)
    }
    #[cfg(windows)]
    {
        let mut done = 0;
        while done < data.len() {
            done += std::os::windows::fs::FileExt::seek_write(file, &data[done..], at + done as u64)?;
        }
        Ok(())
    }
}

/// Fill `buf` from `file` at `at`; the bytes read, fewer at its end.
pub(super) fn read_at(file: &std::fs::File, at: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(file, &mut buf[done..], at + done as u64)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(file, &mut buf[done..], at + done as u64)?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

/// Copy the chunks of `source` on the server into the local `temp`, with
/// `tasks` tasks, each with its own SFTP session on `handle`.
#[allow(clippy::too_many_arguments)]
pub async fn down(
    handle: &Connection,
    source: &str,
    temp: &Path,
    size: u64,
    tasks: usize,
    pipe: Pipeline,
    progress: &mut Progress,
    meter: &Meter,
) -> Result<(), Failed> {
    let shown = temp.display().to_string();
    let local = std::fs::OpenOptions::new()
        .write(true)
        .open(temp)
        .map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
    let (shared, tasks) = Shared::new(size, tasks, progress, meter);
    let each = (0..tasks).map(|_| down_task(handle, source, &local, &shown, &shared, pipe));
    futures_util::future::join_all(each).await;
    shared.end()
}

/// One task of [`down`]: chunks in turn, until none is left or one fails.
async fn down_task(
    handle: &Connection,
    source: &str,
    local: &std::fs::File,
    shown: &str,
    shared: &Shared<'_>,
    pipe: Pipeline,
) {
    let sftp = match Sftp::open(handle, Limits::default()).await {
        Ok(sftp) => sftp,
        Err(e) => return shared.fail(transfer::from_sftp(e, Side::Source)),
    };
    let file = match sftp.open_file(source, OpenFlags::READ, FileAttributes::default()).await {
        Ok(file) => file,
        Err(e) => return shared.fail(transfer::from_sftp(e, Side::Source)),
    };
    while let Some((at, len)) = shared.take() {
        let end = at + len;
        let mut reads = Reads::new(&sftp, &file, at, pipe);
        let mut pos = at;
        let mut allow = |offset: u64, _: u32| offset < end;
        let copied = loop {
            if pos >= end {
                break Ok(());
            }
            match reads.next(&mut allow).await {
                Ok(Some(data)) => {
                    let take = ((end - pos) as usize).min(data.len());
                    if let Err(e) = write_at(local, pos, &data[..take]) {
                        break Err(Failed::new(Fault::CantCreate, format!("{shown}: {e}")));
                    }
                    pos += take as u64;
                }
                // Shorter than its size at the start: it changed.
                Ok(None) => break Err(transfer::changed(source)),
                Err(e) => break Err(transfer::from_sftp(e, Side::Source)),
            }
        };
        drop(reads);
        match copied {
            Ok(()) => shared.done(at),
            Err(failed) => {
                shared.fail(failed);
                break;
            }
        }
    }
    let _ = sftp.close(&file).await;
    let _ = sftp.close_session();
}

/// Copy the chunks of the local `source` into `temp` on the server, with
/// `tasks` tasks, each with its own SFTP session on `handle`.
#[allow(clippy::too_many_arguments)]
pub async fn up(
    handle: &Connection,
    source: &Path,
    temp: &str,
    size: u64,
    tasks: usize,
    pipe: Pipeline,
    progress: &mut Progress,
    meter: &Meter,
) -> Result<(), Failed> {
    let shown = source.display().to_string();
    let local = std::fs::File::open(source).map_err(|e| Failed::new(Fault::NoInput, format!("{shown}: {e}")))?;
    let (shared, tasks) = Shared::new(size, tasks, progress, meter);
    let each = (0..tasks).map(|_| up_task(handle, &local, &shown, temp, &shared, pipe));
    futures_util::future::join_all(each).await;
    shared.end()
}

/// One task of [`up`]: chunks in turn, until none is left or one fails.
async fn up_task(
    handle: &Connection,
    local: &std::fs::File,
    shown: &str,
    temp: &str,
    shared: &Shared<'_>,
    pipe: Pipeline,
) {
    let sftp = match Sftp::open(handle, Limits::default()).await {
        Ok(sftp) => sftp,
        Err(e) => return shared.fail(transfer::from_sftp(e, Side::Destination)),
    };
    let file = match sftp.open_file(temp, OpenFlags::WRITE, FileAttributes::default()).await {
        Ok(file) => file,
        Err(e) => return shared.fail(transfer::from_sftp(e, Side::Destination)),
    };
    while let Some((at, len)) = shared.take() {
        let mut writes = Writes::new(&sftp, &file, at, pipe);
        let mut buf = vec![0u8; writes.block() as usize];
        let mut pos = at;
        let copied = loop {
            if pos >= at + len {
                break writes.finish().await.map(|_| ()).map_err(|e| transfer::from_sftp(e, Side::Destination));
            }
            let want = ((at + len - pos) as usize).min(buf.len());
            match read_at(local, pos, &mut buf[..want]) {
                Ok(n) if n == want => {}
                Ok(_) => break Err(transfer::changed(shown)),
                Err(e) => break Err(Failed::new(Fault::NoInput, format!("{shown}: {e}"))),
            }
            if let Err(e) = writes.send(buf[..want].to_vec()).await {
                break Err(transfer::from_sftp(e, Side::Destination));
            }
            pos += want as u64;
        };
        match copied {
            Ok(()) => shared.done(at),
            Err(failed) => {
                let _ = writes.finish().await;
                shared.fail(failed);
                break;
            }
        }
    }
    let _ = sftp.close(&file).await;
    let _ = sftp.close_session();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chunks_cover_the_file_once_each() {
        assert_eq!(plan(0, 8), Vec::<(u64, u64)>::new());
        assert_eq!(plan(8, 8), vec![(0, 8)]);
        assert_eq!(plan(20, 8), vec![(0, 8), (8, 8), (16, 4)]);
        let chunks = plan(100 * CHUNK + 5, CHUNK);
        assert_eq!(chunks.len(), 101);
        assert_eq!(chunks.iter().map(|c| c.1).sum::<u64>(), 100 * CHUNK + 5);
        assert!(chunks.windows(2).all(|w| w[0].0 + w[0].1 == w[1].0), "each starts where the one before ends");
    }

    #[test]
    fn the_tasks_share_the_room_of_a_relay_session() {
        let pipe = Pipeline::default();
        assert_eq!(share(pipe, 1, false).in_flight, IN_FLIGHT);
        assert_eq!(share(pipe, 4, false).in_flight, IN_FLIGHT, "each its own window, direct");
        assert_eq!(share(pipe, 1, true).in_flight, IN_FLIGHT);
        assert_eq!(share(pipe, 4, true).in_flight, RELAY_ROOM / 4);
        assert!(4 * u64::from(share(pipe, 4, true).in_flight) < 2 << 20, "below the 2 MiB that close a session");
    }
}
