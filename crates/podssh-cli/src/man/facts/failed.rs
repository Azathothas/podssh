//! THE RELAY's items on a host that failed (T-059, T-563) and on the gate of
//! each relay host that the sessions of one process share (T-637), apart from
//! `facts.rs` for the length of that file; each number is read from the
//! constant the code uses.

use super::super::model::Block;
use super::{item, lit};

/// The record of the hosts that failed or opened lately, across runs.
pub(super) fn host() -> Block {
    item(
        vec![lit("A host that failed")],
        format!(
            "A relay host that failed with an error that another host can repair, or that said nothing \
             while a host after it opened, is tried last for {w} min, in each run and each mode, also in \
             a list that you named; a note says so, and no host is left out. So is a host whose last {} \
             sessions were cut on its side (the link lost, or the relay's close for it) within {} s of \
             their open, for {} min. A host that opened in the last {w} min, with no failure since and its \
             last session not cut, is tried before the others. The record is {} in the cache, for each \
             road apart; a host that opens keeps its entry, with no failure. podssh status and podssh \
             doctor show it.",
            podssh_relay::failures::STRIKES,
            podssh_relay::failures::SHORT.as_secs(),
            podssh_relay::failures::REST.as_secs() / 60,
            podssh_relay::failures::FILE,
            w = podssh_relay::failures::WINDOW.as_secs() / 60,
        ),
    )
}

/// The gate of each host in one process.
pub(super) fn gate() -> Block {
    use podssh_relay::gate::{FIRST_WAIT, LONGEST_WAIT, MOST_AT_ONCE, RETRY_AFTER_MOST};
    item(
        vec![lit("A process's sessions")],
        format!(
            "The sessions of one process that open against a relay host share a gate for it: while the host \
             gave no failure, up to {most} attempts at once; after a failure that another host could repair, none \
             for {first} s, then one probe at a time, each probe that fails doubling the wait up to {longest} \
             s, and any answer of the host (a session, a refusal by its policy, the relay's 502 for a target) \
             opens the gate again. A mint's Retry-After holds it longer, up to {retry} s. A session whose list \
             has a next host goes on to it at once, with a line, HOST: waits N s after a failure of this \
             process; trying the next host; at its last host it waits, which a line says too, as long as its \
             ConnectTimeout lets it. The wait is no attempt, and never counts as a host that did not answer. \
             Each new command starts with open gates; the record of failures carries what one run learned to \
             the next.",
            most = MOST_AT_ONCE,
            first = FIRST_WAIT.as_secs(),
            longest = LONGEST_WAIT.as_secs(),
            retry = RETRY_AFTER_MOST.as_secs(),
        ),
    )
}
