//! A copy or a move from one server to another, or within one server: a
//! module of its own so that `cp/mod.rs` stays short. Within one server a
//! move is the server's rename, and a copy on a server with `copy-data`
//! stays there; else down to a local temporary file, then up from it, one
//! connection at a time (`AGENTS.md`, rule 2), each copy verified; a move
//! then removes the source in a third. `--no-clobber` and `--update` look
//! at the second server, before any byte goes there (T-473).

use std::sync::Arc;

use podssh_ssh::Log;

use super::clobber::{Clobber, Mode};
use super::link;
use super::meta::Keep;
use super::moving::{self, After};
use super::operand::{Operand, Remote};
use super::pipe::Shape;
use super::plan::{Direction, Plan};
use super::resume::Before;
use super::session::session;
use super::transfer::{Done, Failed};
use super::Outcome;
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// Server to server, or within one server.
pub(super) async fn across(plan: &Plan, resolved: &[Resolved], log: &Arc<Log>, after: After) -> Outcome {
    let (Operand::Remote(from), Operand::Remote(to)) = (&plan.sources[0], &plan.destination) else {
        unreachable!("a copy across has a remote source and a remote destination")
    };
    let moving = after == After::Remove;
    if from.same_server(to) {
        if moving {
            if let Some(outcome) = rename_session(from, to, &resolved[0], plan.shape.clobber, log).await {
                return outcome;
            }
            log.info(&format!(
                "{}: the server could not rename it, so this is a copy, a digest check, then a delete; \
                 it is not atomic",
                from.path
            ));
        }
        if let Some(outcome) = session(plan, &resolved[0], log, None, after).await {
            return outcome;
        }
        log.verbose("the server has no copy-data: the copy goes through this host");
    }
    let name = from.path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
    let dir = std::env::temp_dir().join(format!("podssh-cp-{:016x}", rand::random::<u64>()));
    if let Err(e) = std::fs::create_dir(&dir) {
        let failed = Failed::new(Fault::CantCreate, format!("{}: {e}", dir.display()));
        return Outcome { failed: Some((from.path.clone(), failed)), ..Outcome::default() };
    }
    let local = dir.join(if name.is_empty() { "file" } else { &name });
    // The local copy is new, so its leg replaces nothing; under --update it
    // keeps the source's time, which the second leg's look compares.
    let shape = plan.shape;
    let update = shape.clobber.mode == Mode::Update;
    let keep = Keep { times: shape.keep.times || update, ..shape.keep };
    let first_shape = Shape { clobber: Clobber::default(), keep, ..shape };
    let leg = |source: Operand, destination: Operand, direction, shape| Plan {
        direction,
        sources: vec![source],
        destination,
        shape,
        tree: None,
    };
    let down =
        leg(Operand::Remote(from.clone()), Operand::Local(local.display().to_string()), Direction::Down, first_shape);
    let first = if moving { After::Record } else { After::Keep };
    let mut outcome = session(&down, &resolved[0], log, None, first).await.expect("a copy down needs no copy-data");
    let recorded = std::mem::take(&mut outcome.recorded);
    if outcome.failed.is_none() {
        // The local copy has the source's name, so a directory or an empty
        // path on the far side takes that name, as a copy up does.
        let up = leg(Operand::Local(local.display().to_string()), Operand::Remote(to.clone()), Direction::Up, shape);
        outcome = session(&up, &resolved[1], log, Some(from.path.clone()), After::Keep)
            .await
            .expect("a copy up needs no copy-data");
    }
    let _ = std::fs::remove_dir_all(&dir);
    // Down to this host, then up: the record counts its bytes both ways.
    outcome.through = true;
    // A file that the look kept is no copy: its source stays.
    let copied = outcome.done.last().cloned();
    if let (true, true, Some(before), Some(copied)) = (moving, outcome.failed.is_none(), recorded.first(), copied) {
        let removed = remove_session(from, before, &copied, &resolved[0], log).await;
        if let Some(done) = outcome.done.last_mut() {
            done.removed = Some(removed.is_ok());
        }
        if let Err(failed) = removed {
            outcome.failed = Some((from.path.clone(), failed));
        }
    }
    outcome
}

/// A move within one server: the server renames. `None` when it could not,
/// for a copy and a delete instead.
async fn rename_session(
    from: &Remote,
    to: &Remote,
    resolved: &Resolved,
    clobber: Clobber,
    log: &Arc<Log>,
) -> Option<Outcome> {
    let mut outcome = Outcome::default();
    let link = match link::connect(resolved, log).await {
        Ok(link) => link,
        Err(failed) => {
            outcome.failed = Some((from.path.clone(), failed));
            return Some(outcome);
        }
    };
    let result = moving::rename(&link, &from.path, &to.path, clobber, log).await;
    link.close().await;
    match result {
        Ok(Some(done)) => outcome.add(done),
        Ok(None) => return None,
        Err(failed) => outcome.failed = Some((from.path.clone(), failed)),
    }
    Some(outcome)
}

/// The last step of a move between servers: remove the source on its
/// server, when it is still what was copied.
async fn remove_session(
    from: &Remote,
    before: &Before,
    done: &Done,
    resolved: &Resolved,
    log: &Arc<Log>,
) -> Result<(), Failed> {
    let link = link::connect(resolved, log).await.map_err(|f| moving::not_removed(&from.path, &f.message))?;
    let removed = moving::remove_far(&link, &from.path, before, done).await;
    link.close().await;
    removed
}
