//! The manual's facts of the iroh road, which only a build with the feature
//! `iroh` has: its variables (T-165, T-359, T-350), and its items in THE
//! RELAY, its relays and the record of a node's home relay (T-350).

use super::super::model::Block;
#[cfg(feature = "iroh")]
use super::{item, lit};

/// The variables of the iroh road (T-165), which only a build with the
/// feature `iroh` reads.
#[cfg(feature = "iroh")]
pub(super) const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_IROH_RELAY"],
        "The iroh relays, as --iroh-relay: https://HOST[:PORT], separated by commas, in order. The flag \
          wins; an empty value is no value, and a bad one is a configuration error (78).",
    ),
    (
        &["PODSSH_IROH_UDP"],
        "off: the iroh road takes no direct path, and its relay carries each byte, as where UDP is refused. on: \
          UDP is used once a socket binds, with nothing sent, for a relay that runs no QUIC address discovery. \
          Else UDP is used once a datagram came back: a QUIC address discovery to the home relay within 6 s of \
          the start, before anything is dialled or served; with none, the relay carries each byte. -v says \
          which answer the road took, and at a session's end which path carried it; podssh doctor's line iroh \
          UDP out gives the answer.",
    ),
    (
        &["PODSSH_IROH_PKARR"],
        "The server of pkarr where a node of the iroh road keeps the record of its home relay, and where a \
          client asks for it: https://HOST[:PORT][/PATH], or off for none. Unset or empty, it is n0's when the \
          relays are n0's, and none else (see iroh record in THE RELAY). A bad value is a configuration error \
          (78).",
    ),
];

#[cfg(not(feature = "iroh"))]
pub(super) const VARIABLES: &[(&[&str], &str)] = &[];

/// The items of the iroh road in THE RELAY, in a build that has it.
#[cfg(feature = "iroh")]
pub(super) fn blocks() -> Vec<Block> {
    vec![relays(), record()]
}

#[cfg(not(feature = "iroh"))]
pub(super) fn blocks() -> Vec<Block> {
    Vec::new()
}

/// The relays of the iroh road (T-165).
#[cfg(feature = "iroh")]
fn relays() -> Block {
    use podssh_iroh::relays;
    item(
        vec![lit("iroh relays")],
        format!(
            "The iroh road (podssh node --iroh, podssh ssh iroh:TICKET) has relays of its own: {}, or those of \
             --iroh-relay or {}, the flag first. podssh asks /ping of each, in order, through the proxy, {} s \
             at most each, and the first that answers is the home relay; a node's ticket names it. A client \
             asks the relay of the ticket first. When none answers, iroh probes them all and takes the one \
             that answers fastest.",
            relays::DEFAULT.join(", "),
            relays::ENV,
            relays::PING_LIMIT.as_secs()
        ),
    )
}

/// The record of a node's home relay at a server of pkarr (T-350).
#[cfg(feature = "iroh")]
fn record() -> Block {
    use podssh_iroh::pkarr;
    item(
        vec![lit("iroh record")],
        format!(
            "A node of the iroh road keeps a record of its home relay, signed with its key, at a server of \
             pkarr: {n0} when its relays are n0's, else the one of {env}, and none with {env}=off. The record \
             names the relay alone, no address of the host; the node puts it through the proxy at its start, \
             again when its home relay changes, and each {minutes} minutes. A client whose ticket's relay does \
             not reach the node within {after} s (at once, when that relay does not answer /ping) asks for the \
             record, {limit} s at most, and dials the relay that it names too. A record that the node's key \
             did not sign is refused, and the connection checks the node's key either way. podssh ssh then \
             says the node's ticket at that relay.",
            n0 = pkarr::N0,
            env = pkarr::ENV,
            minutes = pkarr::REPUBLISH.as_secs() / 60,
            after = podssh_iroh::client::FIND_AFTER.as_secs(),
            limit = pkarr::LIMIT.as_secs(),
        ),
    )
}
