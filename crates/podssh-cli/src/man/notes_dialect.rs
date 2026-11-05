//! The notes of the dialect of the reverse road (T-643), for `node`,
//! `operator` and `relay`, apart from the others for the length of their
//! files.

/// A node's reading of its relay's dialect.
pub(super) const NODE: &str = "The node reads the dialect of the reverse road that its relay speaks, the version of \
     the relay's hello, and states its own on each upgrade, in the header X-Podssh-Proto; a hello with no version \
     is the dialect of before, 1, which the default relay and each podssh before it speak. A relay of a dialect \
     that this node does not read, by its hello or by its answer 426 to the node's upgrade, ends the node with exit \
     78 and one line that names both and the side to update (podssh update, where this node is the older one), and \
     the node does not connect again, as each new socket would meet the same; --restart does not start it again \
     either. This podssh and its relay role speak 1 alone, so nothing is refused until the dialect changes.";

/// An operator's reading of the relay's answer.
pub(super) const OPERATOR: &str = "A relay that answers the operator's upgrade with 426, as podssh relay serve \
     answers one of a dialect of the reverse road that it does not read, ends the run with exit 78 and the \
     relay's line, which names the side to update; a session of the resumable layer ends so at its next link, \
     and does not wait out the node's deadline.";

/// The relay's side, for `relay serve`.
pub(super) const RELAY: &str = "podssh relay serve reads the dialect of the reverse road that a node's or an \
     operator's upgrade states in the header X-Podssh-Proto: none is 1, the dialect of before, which each client \
     of the contract speaks, and podssh's own clients state 1. One that it does not read gets 426 with one line \
     that names both and the side to update, and its own in X-Podssh-Proto, once the pair's token passed, so that \
     a client with no token learns nothing of it, and before the pair's name is checked or a token that takes \
     one upgrade is spent; its hello to a node says its own as version. It reads 1 alone.";
