//! Reads and writes in flight together, for a copy (T-140). A client that
//! waits for each reply before its next request moves one request a round
//! trip; through a proxy and the relay a round trip is long. Here up to
//! [`Pipeline::requests`] requests are in flight, and never more bytes than
//! [`IN_FLIGHT`], the SSH window that podssh gives a server: a download
//! never has more in flight than that window, whatever is asked, and an
//! upload keeps the same bound.
//!
//! **In order.** Replies may come in any order; each block is handed on in
//! the order of the file, so that a file is written front to back and the
//! part that the server acknowledged is always contiguous: a later attempt
//! writes on from its end (T-136), never from the far file's size, which a
//! write after a failed one can make larger.
//!
//! **A short read** leaves a gap: the rest of its block is asked for next,
//! before the blocks after it.
//!
//! **Each wait has a limit**: no reply within [`super::Limits::data`] is a
//! failure, as with one request at a time. The limit runs from the last
//! reply, not from each request's start, so that a request behind others on
//! a slow link is not failed for their bytes. After a failed request no new
//! one goes out; the others are waited for, within the same limit, and the
//! first failure in the file's order is the result.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures_util::stream::{FuturesOrdered, StreamExt};

use super::{read_reply, FileHandle, Sftp, SftpError};

/// The bytes in flight at most: the window that podssh gives a server. On
/// the relay's forward path, 2 MiB that wait for a slow receiver close the
/// session; a window of 512 KiB keeps far from that.
pub const IN_FLIGHT: u32 = crate::run::WINDOW;

/// The requests in flight at most, whatever is asked: OpenSSH's default for
/// `sftp -R`.
pub const MAX_REQUESTS: usize = 64;

/// The requests in flight of a copy that names none: as many as
/// [`IN_FLIGHT`] holds of the blocks.
pub const DEFAULT_REQUESTS: usize = MAX_REQUESTS;

/// How a copy uses its session: the requests in flight, and the bytes of
/// each read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pipeline {
    /// Requests in flight at once; 1 waits for each reply.
    pub requests: usize,
    /// The bytes of each request; 0 for the server's size
    /// ([`Sftp::read_len`], [`Sftp::write_len`]), which also bounds it.
    pub len: u32,
    /// The bytes in flight at most, [`IN_FLIGHT`] at most: less when the
    /// copy's tasks share the room of one relay session (T-141).
    pub in_flight: u32,
}

impl Default for Pipeline {
    fn default() -> Self {
        Pipeline { requests: DEFAULT_REQUESTS, len: 0, in_flight: IN_FLIGHT }
    }
}

impl Pipeline {
    /// The bytes of each request, under the server's `limit`.
    pub fn len_under(&self, limit: u32) -> u32 {
        match self.len {
            0 => limit,
            len => len.min(limit),
        }
    }

    /// The requests in flight for blocks of `len`: as many as asked, while
    /// their bytes stay within [`Pipeline::in_flight`] and [`IN_FLIGHT`]; one
    /// at least.
    pub fn depth(&self, len: u32) -> usize {
        let by_window = (self.in_flight.min(IN_FLIGHT) / len.max(1)).max(1) as usize;
        self.requests.clamp(1, MAX_REQUESTS).min(by_window)
    }
}

type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A read's place and its reply.
struct ReadReply {
    offset: u64,
    len: u32,
    got: Result<Option<Vec<u8>>, SftpError>,
}

/// The reads of one file, from an offset to its end, with requests in
/// flight together; each block comes out in the file's order.
pub struct Reads<'a> {
    sftp: &'a Sftp,
    file: &'a FileHandle,
    /// The offset of the next read to send.
    next: u64,
    len: u32,
    depth: usize,
    limit: Duration,
    inflight: FuturesOrdered<Pending<'a, ReadReply>>,
    /// The offset of each read in flight, the oldest first.
    offsets: VecDeque<u64>,
    /// No more reads to send: the end of the file, a failure, or a refusal of
    /// the caller.
    closed: bool,
}

impl<'a> Reads<'a> {
    /// Reads of `file` from `offset`, as `pipe` says.
    pub fn new(sftp: &'a Sftp, file: &'a FileHandle, offset: u64, pipe: Pipeline) -> Reads<'a> {
        let len = pipe.len_under(sftp.read_len());
        Reads {
            sftp,
            file,
            next: offset,
            len,
            depth: pipe.depth(len),
            limit: sftp.limits.data,
            inflight: FuturesOrdered::new(),
            offsets: VecDeque::new(),
            closed: false,
        }
    }

    /// The bytes of each read.
    pub fn block(&self) -> u32 {
        self.len
    }

    /// The requests that may be in flight.
    pub fn depth(&self) -> usize {
        self.depth
    }

    fn read_at(&self, offset: u64, len: u32) -> Pending<'a, ReadReply> {
        let (sftp, handle) = (self.sftp, self.file.0.clone());
        Box::pin(async move {
            let got = read_reply(offset, len, sftp.raw.read(handle, offset, len).await, sftp.limits.data);
            ReadReply { offset, len, got }
        })
    }

    /// The next block of the file, in its order: `None` at the end, or when
    /// the caller refused a read and each one sent has come. Before it waits,
    /// it sends reads up to the depth, each first offered to `allow` with its
    /// offset and its length; a refusal sends no more.
    pub async fn next(&mut self, allow: &mut dyn FnMut(u64, u32) -> bool) -> Result<Option<Vec<u8>>, SftpError> {
        while !self.closed && self.inflight.len() < self.depth {
            if !allow(self.next, self.len) {
                self.closed = true;
                break;
            }
            let read = self.read_at(self.next, self.len);
            self.inflight.push_back(read);
            self.offsets.push_back(self.next);
            self.next += u64::from(self.len);
        }
        let Some(reply) = self.wait().await? else { return Ok(None) };
        match reply.got {
            Ok(Some(data)) if !data.is_empty() => {
                let got = data.len() as u32;
                if got < reply.len {
                    // The rest of this block, before the blocks after it.
                    let at = reply.offset + u64::from(got);
                    let rest = self.read_at(at, reply.len - got);
                    self.inflight.push_front(rest);
                    self.offsets.push_front(at);
                }
                Ok(Some(data))
            }
            Ok(_) => {
                // The end of the file: the reads after it end there too.
                self.closed = true;
                self.drain().await;
                Ok(None)
            }
            Err(e) => {
                self.closed = true;
                self.drain().await;
                Err(e)
            }
        }
    }

    /// The oldest read's reply, within the limit; `None` with none in flight.
    async fn wait(&mut self) -> Result<Option<ReadReply>, SftpError> {
        let head = self.offsets.front().copied();
        match tokio::time::timeout(self.limit, self.inflight.next()).await {
            Ok(reply) => {
                self.offsets.pop_front();
                Ok(reply)
            }
            Err(_) => {
                self.closed = true;
                let what = format!("read at {}", head.unwrap_or(self.next));
                Err(SftpError::Timeout { what, limit: self.limit })
            }
        }
    }

    /// Wait for each read in flight, within the limit for each, and drop
    /// what they bring.
    async fn drain(&mut self) {
        while let Ok(Some(_)) = tokio::time::timeout(self.limit, self.inflight.next()).await {}
        self.offsets.clear();
    }
}

/// The writes of one file, from an offset on, with requests in flight
/// together.
pub struct Writes<'a> {
    sftp: &'a Sftp,
    file: &'a FileHandle,
    /// The offset of the next write.
    next: u64,
    /// The end of the part that the server acknowledged, with no gap below;
    /// the oldest write in flight starts here.
    acked: u64,
    len: u32,
    depth: usize,
    limit: Duration,
    inflight: FuturesOrdered<Pending<'a, (u64, Result<(), SftpError>)>>,
}

impl<'a> Writes<'a> {
    /// Writes of `file` from `offset`, as `pipe` says.
    pub fn new(sftp: &'a Sftp, file: &'a FileHandle, offset: u64, pipe: Pipeline) -> Writes<'a> {
        let len = pipe.len_under(sftp.write_len());
        Writes {
            sftp,
            file,
            next: offset,
            acked: offset,
            len,
            depth: pipe.depth(len),
            limit: sftp.limits.data,
            inflight: FuturesOrdered::new(),
        }
    }

    /// The bytes of each write: the caller's blocks are at most this long.
    pub fn block(&self) -> u32 {
        self.len
    }

    /// The requests that may be in flight.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The end of the part that the server acknowledged, with no gap below
    /// it: where a later attempt writes on.
    pub fn acked(&self) -> u64 {
        self.acked
    }

    /// Send `data`, at most [`Writes::block`] bytes, at the next offset, once
    /// a request in flight has room. The first failure ends the writes: the
    /// others in flight are waited for, and it is the result.
    pub async fn send(&mut self, data: Vec<u8>) -> Result<(), SftpError> {
        debug_assert!(data.len() <= self.len as usize);
        while self.inflight.len() >= self.depth {
            self.ack().await?;
        }
        let at = self.next;
        let end = at + data.len() as u64;
        self.next = end;
        let (sftp, handle) = (self.sftp, self.file.0.clone());
        self.inflight.push_back(Box::pin(async move {
            let wrote = sftp.raw.write(handle, at, data).await;
            (end, wrote.map(|_| ()).map_err(|e| SftpError::from_raw(&format!("write at {at}"), e, sftp.limits.data)))
        }));
        Ok(())
    }

    /// Wait for each write in flight: the end of the acknowledged part, or
    /// the first failure.
    pub async fn finish(&mut self) -> Result<u64, SftpError> {
        while !self.inflight.is_empty() {
            self.ack().await?;
        }
        Ok(self.acked)
    }

    /// The oldest write's reply, within the limit. A failure keeps the
    /// acknowledged part where it is, and waits for the others.
    async fn ack(&mut self) -> Result<(), SftpError> {
        let failed = match tokio::time::timeout(self.limit, self.inflight.next()).await {
            Ok(None) => return Ok(()),
            Ok(Some((end, Ok(())))) => {
                self.acked = end;
                return Ok(());
            }
            Ok(Some((_, Err(e)))) => e,
            Err(_) => SftpError::Timeout { what: format!("write at {}", self.acked), limit: self.limit },
        };
        while let Ok(Some(_)) = tokio::time::timeout(self.limit, self.inflight.next()).await {}
        Err(failed)
    }
}
