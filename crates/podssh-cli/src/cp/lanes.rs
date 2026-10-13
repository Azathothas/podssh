//! Several files at once over one connection (T-297). With `--parallel K`
//! and several files, up to K go together, each over an SFTP session of its
//! own in the one connection, the connection's own session among them; each
//! keeps its own record and side file (T-136). A break ends the files in
//! flight where they are, and the next connection goes on with each from its
//! record, as `session::attempts` goes on with one: at most [`TRIES`]
//! connections in a row with no new byte, the relay opener's backoff between
//! them. A file of more than one chunk waits, and goes after the others,
//! alone, in chunks (T-141), so that no more than K sessions share the
//! connection. The answers keep the order of the files.
//!
//! Through the relay the files share the room of one session, as chunks do
//! ([`chunks::share`]); each checks the session's budget before each request
//! (T-137), and a new session goes on with the files that it stopped.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use podssh_ssh::sftp::{Limits, Sftp};
use podssh_ssh::{Connection, Log};

use super::bysftp;
use super::chunks::{self, CHUNK};
use super::link::{self, Link, Meter, Road};
use super::operand::Operand;
use super::pipe::Shape;
use super::resume::{self, Before, Progress, TRIES};
use super::session::{attempts, shown, Answer};
use super::transfer::{Cause, Failed};
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// Whether `files` files go K at once over `link`: more than one, K above
/// 1, and SFTP; by exec each goes in one stream, in turn.
pub(super) fn fit(files: usize, shape: Shape, link: Option<&Link>) -> bool {
    files > 1 && shape.tasks > 1 && matches!(link.map(|l| &l.road), Some(Road::Sftp(_)))
}

/// What each attempt of the run needs besides its file.
struct Run<'a> {
    /// Each file: its source and its destination.
    files: &'a [(Operand, Operand)],
    /// Each destination is a directory of several sources.
    many: bool,
    log: &'a Log,
    /// The login and the port, for the names of the side files.
    server: String,
    port: u16,
}

/// One file, and what its copy has done.
struct Slot {
    /// Its place among the files.
    at: usize,
    /// Where its copy is, once its source was seen (T-136).
    progress: Option<Progress>,
    /// Its source as it was when its copy began.
    first: Option<Before>,
    /// Whether an attempt went on from an earlier one, and whether the copy
    /// started once more after digests that differ.
    continued: bool,
    restarted: bool,
    /// The most bytes that its record held after a connection.
    best: u64,
}

impl Slot {
    fn new(at: usize) -> Slot {
        Slot { at, progress: None, first: None, continued: false, restarted: false, best: 0 }
    }

    /// Whether the record holds more bytes than after each connection
    /// before.
    fn moved(&mut self) -> bool {
        let now = self.progress.as_ref().map_or(0, |p| p.offset);
        let moved = now > self.best;
        self.best = self.best.max(now);
        moved
    }
}

/// How one attempt at a file ended.
enum Step {
    /// Its answer: done, or a failure that a new connection cannot mend.
    Answer(Answer),
    /// The connection broke under it, or the relay session is spent: the
    /// next connection goes on with it.
    Again(Failed),
    /// More than one chunk: it goes after the others, in chunks.
    Large,
}

/// What the files of one connection share: those left, those that wait for
/// the next connection, the answers, the large files, and the first break.
#[derive(Default)]
struct Shared {
    queue: Mutex<VecDeque<Slot>>,
    again: Mutex<Vec<Slot>>,
    answers: Mutex<Vec<(usize, Answer)>>,
    large: Mutex<Vec<usize>>,
    stop: Mutex<Option<Failed>>,
}

impl Shared {
    /// The next file, until the connection broke or was spent.
    fn take(&self) -> Option<Slot> {
        if self.stop.lock().unwrap().is_some() {
            return None;
        }
        self.queue.lock().unwrap().pop_front()
    }
}

/// One SFTP session of the connection, and what each file over it uses.
struct Lane<'a> {
    sftp: &'a Sftp,
    handle: &'a Connection,
    meter: &'a Meter,
}

/// What one connection did, and why it ended early, if it did.
struct Ended {
    answers: Vec<(usize, Answer)>,
    large: Vec<usize>,
    /// The files that wait for the next connection, in their order.
    again: Vec<Slot>,
    stop: Option<Failed>,
}

/// Copy each of `files` (its source and its destination) over `link`, K at
/// once (`shape.tasks`), and over a new connection after each break: the
/// answer of each, in their order, or `None` for a file that no connection
/// was left to try. `link` is `None` when the last connection broke.
/// `many`: each destination is a directory of several sources.
pub(super) async fn files(
    link: &mut Option<Link>,
    resolved: &Resolved,
    files: &[(Operand, Operand)],
    many: bool,
    log: &Arc<Log>,
    shape: Shape,
) -> Vec<Option<Answer>> {
    let server = format!("{}@{}", resolved.options.user, resolved.options.destination.host);
    let run = Run { files, many, log, server, port: resolved.options.destination.port };
    let mut answers: Vec<Option<Answer>> = files.iter().map(|_| None).collect();
    let mut large = Vec::new();
    let mut waiting: Vec<Slot> = (0..files.len()).map(Slot::new).collect();
    let mut tries = 0u32;
    while !waiting.is_empty() {
        let current = match link.take() {
            Some(current) => current,
            None => match link::connect(resolved, log).await {
                Ok(current) => current,
                // The network, not an answer: try again, within the limit.
                Err(f) if f.fault == Fault::RelayUnreachable && tries < TRIES => {
                    tries += 1;
                    pause(waiting.len(), &f.message, tries, log).await;
                    continue;
                }
                Err(f) => {
                    for slot in waiting.drain(..) {
                        answers[slot.at] = Some(Err(f.clone()));
                    }
                    break;
                }
            },
        };
        // A new connection by exec: each file in one stream, in turn.
        if !matches!(current.road, Road::Sftp(_)) {
            *link = Some(current);
            large.extend(waiting.drain(..).map(|slot| slot.at));
            break;
        }
        let ended = round(&current, std::mem::take(&mut waiting), &run, shape).await;
        let mut moved = !ended.answers.is_empty();
        for (at, answer) in ended.answers {
            answers[at] = Some(answer);
        }
        large.extend(ended.large);
        waiting = ended.again;
        for slot in &mut waiting {
            moved |= slot.moved();
        }
        let Some(why) = ended.stop else {
            // Each file has its answer, or waits to go in chunks.
            *link = Some(current);
            continue;
        };
        current.close().await;
        // Near the relay's limits a new session goes on at once (T-137);
        // one that moved no byte still counts as an attempt.
        let spent = why.cause == Cause::Spent;
        if moved {
            tries = 0;
        }
        if !(spent && moved) {
            tries += 1;
        }
        if tries > TRIES {
            for slot in waiting.drain(..) {
                answers[slot.at] = Some(Err(why.clone()));
            }
            break;
        }
        if spent {
            log.verbose(&format!("{} files: {}; a new one goes on with them", waiting.len(), why.message));
        } else {
            pause(waiting.len(), &why.message, tries, log).await;
        }
    }
    // The files of more than one chunk, alone, in chunks (T-141); and each
    // file after a connection by exec.
    large.sort_unstable();
    for at in large {
        if link.is_none() {
            break;
        }
        let (source, dest) = &files[at];
        answers[at] = Some(attempts(link, resolved, source, dest, many, log, shape).await);
    }
    answers
}

/// Say why the files wait, then wait the relay opener's backoff.
async fn pause(files: usize, why: &str, tries: u32, log: &Log) {
    let wait = podssh_relay::open::backoff(tries);
    log.info(&format!("{files} files: {why}; a new connection in {:.1} s ({tries} of {TRIES})", wait.as_secs_f64()));
    tokio::time::sleep(wait).await;
}

/// The files of `waiting` over `link`, K at once: the connection's own SFTP
/// session and K - 1 more, as many as the server opens.
async fn round(link: &Link, waiting: Vec<Slot>, run: &Run<'_>, shape: Shape) -> Ended {
    let Road::Sftp(own) = &link.road else { unreachable!("several files at once go over SFTP") };
    let handle = link.handle();
    let wanted = shape.tasks.min(waiting.len()).max(1);
    let more = (1..wanted).map(|_| Sftp::open(handle, Limits::default()));
    let opened: Vec<Sftp> = futures_util::future::join_all(more).await.into_iter().filter_map(Result::ok).collect();
    let mut sessions = vec![own];
    sessions.extend(opened.iter());
    let lanes = sessions.len();
    if lanes < wanted {
        run.log.verbose(&format!("the server opened {lanes} of {wanted} SFTP sessions"));
    }
    run.log.verbose(&format!("{} files, {lanes} at once", waiting.len()));
    // Through the relay the lanes share the room of one session.
    let each = Shape { pipe: chunks::share(shape.pipe, lanes, link.meter.through_relay()), tasks: 1, ..shape };
    let shared = Shared { queue: Mutex::new(VecDeque::from(waiting)), ..Shared::default() };
    let meter = &link.meter;
    let all = sessions.iter().copied().map(|sftp| lane(Lane { sftp, handle, meter }, &shared, run, each));
    futures_util::future::join_all(all).await;
    for sftp in opened {
        let _ = sftp.close_session();
    }
    let Shared { queue, again, answers, large, stop } = shared;
    let mut again = again.into_inner().unwrap();
    // The files that no lane took wait too.
    again.extend(queue.into_inner().unwrap());
    again.sort_by_key(|slot| slot.at);
    Ended {
        answers: answers.into_inner().unwrap(),
        large: large.into_inner().unwrap(),
        again,
        stop: stop.into_inner().unwrap(),
    }
}

/// One lane: files in turn, until none is left or the connection broke.
async fn lane(lane: Lane<'_>, shared: &Shared, run: &Run<'_>, shape: Shape) {
    while let Some(mut slot) = shared.take() {
        match attempt(&lane, &mut slot, run, shape).await {
            Step::Answer(answer) => shared.answers.lock().unwrap().push((slot.at, answer)),
            Step::Large => shared.large.lock().unwrap().push(slot.at),
            // Each other lane ends its file, and takes no other.
            Step::Again(failed) => {
                shared.stop.lock().unwrap().get_or_insert(failed);
                shared.again.lock().unwrap().push(slot);
            }
        }
    }
}

/// The bytes of a source as it was seen.
fn size(before: &Before) -> u64 {
    match before {
        Before::Local { len, .. } => *len,
        Before::Sftp { size, .. } => size.unwrap_or(0),
        Before::Exec(_) => 0,
    }
}

/// One attempt at `slot`'s file over `lane`: its source as it is now, where
/// an earlier attempt or run left its copy, then the copy; once more from
/// the first byte when a copy that went on gives digests that differ.
async fn attempt(lane: &Lane<'_>, slot: &mut Slot, run: &Run<'_>, shape: Shape) -> Step {
    let (source, dest) = &run.files[slot.at];
    let log = run.log;
    loop {
        let now = match source {
            Operand::Local(path) => resume::local(path),
            Operand::Remote(far) => resume::far_over(lane.sftp, &far.path).await,
        };
        let now = match now {
            Ok(now) => now,
            Err(f) if f.cause == Cause::Broke => return Step::Again(f),
            Err(f) => return Step::Answer(Err(f)),
        };
        if size(&now) > CHUNK {
            return Step::Large;
        }
        match slot.progress.as_mut() {
            // Where an earlier run left this copy, when the source is as it
            // was then; a stale side file's temporary file goes.
            None => {
                let side = resume::side_name(&run.server, run.port, &shown(source), &shown(dest));
                let (loaded, stale) = Progress::load(side, now.key());
                if let Some(stale) = stale {
                    drop_temp(lane.sftp, source, &stale).await;
                }
                slot.progress = Some(loaded);
                slot.first = Some(now);
            }
            Some(p) if p.state != now.key() => {
                log.info(&format!("{}: the source changed since the copy began, so it starts over", shown(source)));
                if let Some(temp) = p.temp.clone() {
                    drop_temp(lane.sftp, source, &temp).await;
                }
                p.clear();
                p.state = now.key();
                slot.first = Some(now);
                slot.continued = false;
            }
            Some(_) => {}
        }
        let p = slot.progress.as_mut().expect("set above");
        slot.continued |= p.temp.is_some() && p.offset > 0;
        let (sftp, handle, meter, many) = (lane.sftp, lane.handle, lane.meter, run.many);
        let copied = match (source, dest) {
            (Operand::Local(path), Operand::Remote(to)) => {
                bysftp::up(sftp, handle, path, &to.path, many, log, p, meter, shape).await
            }
            (Operand::Remote(from), Operand::Local(to)) => {
                bysftp::down(sftp, handle, &from.path, to, many, log, p, meter, shape).await
            }
            _ => unreachable!("several files at once go up or down"),
        };
        match copied {
            Ok(done) => return Step::Answer(Ok((done, slot.first.take().expect("set at the first attempt")))),
            Err(f) if matches!(f.cause, Cause::Broke | Cause::Spent) => return Step::Again(f),
            // The digest covers the whole file: a copy that went on and
            // fails it starts once more from the first byte, then fails.
            Err(f) if f.cause == Cause::Digests && slot.continued && !slot.restarted => {
                log.info(&format!("{}; the copy starts once more from the first byte", f.message));
                slot.restarted = true;
                slot.continued = false;
            }
            Err(f) => return Step::Answer(Err(f)),
        }
    }
}

/// Remove a temporary file that a copy left and cannot continue: on the
/// server for a copy up, here for a copy down.
async fn drop_temp(sftp: &Sftp, source: &Operand, temp: &str) {
    // An --inplace copy's record names the destination itself (T-147).
    if !resume::is_temp(temp) {
        return;
    }
    match source {
        Operand::Local(_) => {
            let _ = sftp.remove(temp).await;
        }
        Operand::Remote(_) => {
            let _ = std::fs::remove_file(temp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_moved_when_its_record_holds_more_than_ever_before() {
        let mut slot = Slot::new(3);
        assert!(!slot.moved(), "no record yet");
        // A record of no cache directory: nothing is read or written.
        let (mut progress, _) = Progress::load_in(Vec::new(), "t.resume".into(), "state".into());
        progress.offset = 100;
        slot.progress = Some(progress);
        assert!(slot.moved());
        assert!(!slot.moved(), "the same bytes after the next connection");
        // A copy that starts over holds less: no new byte.
        slot.progress.as_mut().unwrap().offset = 40;
        assert!(!slot.moved());
        slot.progress.as_mut().unwrap().offset = 101;
        assert!(slot.moved());
    }

    #[test]
    fn a_source_of_more_than_one_chunk_waits_to_go_in_chunks() {
        let local = |len| Before::Local { len, modified: None, id: None };
        assert_eq!(size(&local(CHUNK)), CHUNK);
        assert!(size(&local(CHUNK + 1)) > CHUNK);
        assert_eq!(size(&Before::Sftp { size: Some(7), mtime: None }), 7);
        assert_eq!(size(&Before::Sftp { size: None, mtime: None }), 0);
    }
}
