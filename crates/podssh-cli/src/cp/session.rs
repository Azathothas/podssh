//! One session's files. A copy whose connection breaks goes on over a new
//! one, at its offset (T-136); `mv` removes each source once its copy is
//! verified (T-138).

use std::sync::Arc;

use podssh_ssh::Log;

use super::link::{self, Link, Road};
use super::moving::{self, After};
use super::operand::Operand;
use super::plan::{Direction, Plan};
use super::resume::{self, Before, Progress, TRIES};
use super::transfer::{self, Cause, Done, Failed};
use super::{bysftp, Outcome};
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// One connection, and each file of `plan` over it, with a new connection
/// after a break; `after` says what becomes of each source. `named` replaces
/// the source's name in the report (a copy across). A copy within one server
/// is `None` when the server has no `copy-data`.
pub(super) async fn session(
    plan: &Plan,
    resolved: &Resolved,
    log: &Arc<Log>,
    named: Option<String>,
    after: After,
) -> Option<Outcome> {
    let mut outcome = Outcome::default();
    let within = plan.direction == Direction::Across;
    // Within one server with no SFTP, the copy goes through this host, in
    // two sessions that each probe and say so.
    let first = match link::open(resolved, log, !within).await {
        Ok(Some(link)) => link,
        Ok(None) => return None,
        Err(failed) => {
            outcome.failed = Some((shown(&plan.sources[0]), failed));
            return Some(outcome);
        }
    };
    // Within one server, only copy-data spares this host the bytes.
    if within && !first.copies_within() {
        first.close().await;
        return None;
    }
    let mut link = Some(first);
    let many = plan.sources.len() > 1;
    for source in &plan.sources {
        let name = named.clone().unwrap_or_else(|| shown(source));
        let (mut done, before) = match attempts(&mut link, resolved, source, &plan.destination, many, log).await {
            Ok(pair) => pair,
            Err(failed) => {
                outcome.failed.get_or_insert((name, failed));
                // No connection is left for the next file.
                if link.is_none() {
                    break;
                }
                continue;
            }
        };
        if let Some(n) = &named {
            done.source = n.clone();
        }
        let mut kept = None;
        match (after, link.as_ref()) {
            (After::Remove, Some(current)) => {
                let removed = moving::finish(current, source, &before, &done).await;
                done.removed = Some(removed.is_ok());
                kept = removed.err();
            }
            (After::Remove, None) => {
                done.removed = Some(false);
                kept = Some(moving::not_removed(&name, "no connection was left"));
            }
            (After::Record, _) => outcome.recorded.push(before),
            (After::Keep, _) => {}
        }
        outcome.done.push(done);
        if let Some(failed) = kept {
            outcome.failed.get_or_insert((name, failed));
        }
    }
    if let Some(link) = link {
        link.close().await;
    }
    Some(outcome)
}

/// The copy of one file over `link`, and over a new connection after each
/// break, where it goes on at its offset: at most [`TRIES`] attempts in a row
/// with no new byte, the relay opener's backoff between them. A refused
/// login, a host key that changed, or any other answer ends it at once.
/// Gives the file done and its source as it was before the copy; `link` is
/// `None` when the last connection broke.
async fn attempts(
    link: &mut Option<Link>,
    resolved: &Resolved,
    source: &Operand,
    dest: &Operand,
    many: bool,
    log: &Arc<Log>,
) -> Result<(Done, Before), Failed> {
    let server = format!("{}@{}", resolved.options.user, resolved.options.destination.host);
    let side = resume::side_name(&server, resolved.options.destination.port, &shown(source), &shown(dest));
    let mut progress: Option<Progress> = None;
    let mut first: Option<Before> = None;
    let (mut tries, mut best) = (0u32, 0u64);
    let (mut continued, mut restarted) = (false, false);
    loop {
        let current = match link.take() {
            Some(current) => current,
            None => match link::connect(resolved, log).await {
                Ok(current) => current,
                // The network, not an answer: try again, within the limit.
                Err(f) if f.fault == Fault::RelayUnreachable && tries < TRIES => {
                    tries += 1;
                    pause(source, &f.message, tries, log).await;
                    continue;
                }
                Err(f) => return Err(f),
            },
        };
        let now = match resume::before(&current, source).await {
            Ok(now) => now,
            Err(f) if f.cause == Cause::Broke && tries < TRIES => {
                current.close().await;
                tries += 1;
                pause(source, &f.message, tries, log).await;
                continue;
            }
            Err(f) => {
                *link = Some(current);
                return Err(f);
            }
        };
        match progress.as_mut() {
            // Where an earlier run left this copy, when the source is as it
            // was then; a stale side file's temporary file goes.
            None => {
                let (loaded, stale) = Progress::load(side.clone(), now.key());
                if let Some(stale) = stale {
                    drop_temp(&current, source, dest, &stale).await;
                }
                progress = Some(loaded);
                first = Some(now);
            }
            Some(p) if p.state != now.key() => {
                log.info(&format!("{}: the source changed since the copy began, so it starts over", shown(source)));
                if let Some(temp) = p.temp.clone() {
                    drop_temp(&current, source, dest, &temp).await;
                }
                p.clear();
                p.state = now.key();
                first = Some(now);
                continued = false;
            }
            Some(_) => {}
        }
        let p = progress.as_mut().expect("set above");
        continued |= p.temp.is_some() && p.offset > 0;
        match copy(&current, source, dest, many, log, p).await {
            Ok(done) => {
                *link = Some(current);
                return Ok((done, first.take().expect("set at the first attempt")));
            }
            // Near the relay's limits: a new session at once, with no wait;
            // one that moves no byte still counts as an attempt.
            Err(f) if f.cause == Cause::Spent => {
                current.close().await;
                if p.offset > best {
                    best = p.offset;
                    tries = 0;
                } else {
                    tries += 1;
                    if tries > TRIES {
                        return Err(f);
                    }
                }
                continued = true;
                log.verbose(&format!("{}: {}; a new one goes on at byte {}", shown(source), f.message, p.offset));
            }
            Err(f) if f.cause == Cause::Broke => {
                current.close().await;
                if p.offset > best {
                    best = p.offset;
                    tries = 0;
                }
                tries += 1;
                if tries > TRIES {
                    return Err(f);
                }
                continued = true;
                pause(source, &f.message, tries, log).await;
            }
            // The digest covers the whole file: a continued copy that fails
            // it starts once more from the first byte, then fails.
            Err(f) if f.cause == Cause::Digests && continued && !restarted => {
                log.info(&format!("{}; the copy starts once more from the first byte", f.message));
                restarted = true;
                continued = false;
                *link = Some(current);
            }
            Err(f) => {
                *link = Some(current);
                return Err(f);
            }
        }
    }
}

/// Say why the copy waits, then wait the relay opener's backoff.
async fn pause(source: &Operand, why: &str, tries: u32, log: &Log) {
    let wait = podssh_relay::open::backoff(tries);
    log.info(&format!(
        "{}: {why}; a new connection in {:.1} s ({tries} of {TRIES})",
        shown(source),
        wait.as_secs_f64()
    ));
    tokio::time::sleep(wait).await;
}

/// Remove a temporary file that a copy left and cannot continue: on the
/// server for a copy up, here for a copy down.
async fn drop_temp(link: &Link, source: &Operand, dest: &Operand, temp: &str) {
    match (source, dest) {
        (Operand::Local(_), _) => match &link.road {
            Road::Sftp(sftp) => {
                let _ = sftp.remove(temp).await;
            }
            Road::Exec(far) => far.remove(link.handle(), temp).await,
        },
        (Operand::Remote(_), Operand::Local(_)) => {
            let _ = std::fs::remove_file(temp);
        }
        // A copy within one server keeps no temporary file between attempts.
        (Operand::Remote(_), Operand::Remote(_)) => {}
    }
}

/// Copy one file over `link`, by its road.
async fn copy(
    link: &Link,
    source: &Operand,
    dest: &Operand,
    many: bool,
    log: &Log,
    progress: &mut Progress,
) -> Result<Done, Failed> {
    let handle = link.handle();
    match (&link.road, source, dest) {
        (Road::Sftp(sftp), Operand::Local(path), Operand::Remote(dest)) => {
            bysftp::up(sftp, handle, path, &dest.path, many, log, progress, &link.meter).await
        }
        (Road::Sftp(sftp), Operand::Remote(src), Operand::Local(dest)) => {
            bysftp::down(sftp, handle, &src.path, dest, many, log, progress, &link.meter).await
        }
        (Road::Sftp(sftp), Operand::Remote(src), Operand::Remote(dest)) => {
            transfer::within(sftp, handle, &src.path, &dest.path, log).await
        }
        (Road::Exec(far), Operand::Local(path), Operand::Remote(dest)) => {
            far.up(handle, path, &dest.path, many, log, progress, &link.meter).await
        }
        (Road::Exec(far), Operand::Remote(src), Operand::Local(dest)) => {
            far.down(handle, &src.path, dest, many, log, progress, &link.meter).await
        }
        (Road::Exec(_), Operand::Remote(_), Operand::Remote(_)) => {
            unreachable!("a copy within one server by exec goes through this host")
        }
        (_, Operand::Local(_), Operand::Local(_)) => unreachable!("a plan has a server"),
    }
}

/// An operand as the report names it.
pub(super) fn shown(operand: &Operand) -> String {
    match operand {
        Operand::Local(p) => p.clone(),
        Operand::Remote(r) => r.path.clone(),
    }
}
