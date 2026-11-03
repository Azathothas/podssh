//! The answer of `podssh run --dry-run` (T-475): what the copy would change
//! and the command it would run, on stdout, with nothing changed on either
//! side and nothing run. The copy's looks only read, so the plan holds only
//! what changed, as the run would send it: a second dry run after a run and
//! one change names that file alone.

use std::io::Write;

use podssh_ssh::{Log, EXIT_FAILURE};

use super::Plan;
use crate::cp::sync::Synced;

/// The plan of a dry run on `out`: each far directory above the project's
/// that the run would make, the actions of the copy as `cp -r --dry-run`
/// says them, then `run cd DIR && COMMAND`. The paths that the excludes left
/// out are counted on stderr, as the summary of a run counts them. The
/// exit: 0, or 255 when the far side could not be read, with no plan.
pub(super) fn answer(plan: &Plan, parents: &[String], synced: &Synced, log: &Log, out: &mut dyn Write) -> i32 {
    if synced.failed.is_some() {
        // Each failure was said as it came; half a plan would read as all of it.
        log.error(&format!("the dry run could not read {}, so it gives no plan", plan.far.path));
        return EXIT_FAILURE;
    }
    let text = lines(plan, parents, &synced.plan);
    if out.write_all(text.as_bytes()).and_then(|()| out.flush()).is_err() {
        log.error("the plan could not be written to stdout");
        return EXIT_FAILURE;
    }
    if let Some(line) = left_out(synced.counts.left_out) {
        log.info(&line);
    }
    0
}

/// The text of the plan: a line for each action, the command last.
pub(super) fn lines(plan: &Plan, parents: &[String], actions: &[String]) -> String {
    let mut text = String::new();
    for dir in parents {
        text.push_str(&format!("mkdir {dir}\n"));
    }
    for line in actions {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&format!("run {}\n", plan.command));
    text
}

/// The line on stderr when the excludes left paths out, which `-v` names
/// each with its pattern; none when they left nothing out.
pub(super) fn left_out(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 path left out by the excludes; -v names it".into()),
        n => Some(format!("{n} paths left out by the excludes; -v names each")),
    }
}
