//! The notes of the sessions readied ahead (T-650), for `node` and `relay`,
//! apart from the others so that each file stays short.

/// The node's side: its flag, and what each spare costs it.
pub(super) const NODE: &str = "With --spares N, 0 to 16, the node asks its relay to keep up to N sessions open \
     and readied ahead for its operators, where the relay is podssh relay serve, whose hello offers it: an \
     operator's leg then takes one, with no open and ready to wait for and no open of the node's local side, \
     so a run of short connections to the node (a copy of many files, a loop of commands) waits for none. The \
     relay keeps N while they are taken, one after a minute in which no operator took one, and one more for \
     each operator that found none, never past the node's 64 sessions with its operators' counted, and never \
     one that an operator's session needs. Each spare is a session at rest on the node, drawn again each 15 \
     to 20 s, as the node's resumable layer and its end-to-end channel give a client 30 s from the session's \
     open: with them it costs a pipe and a task here, and TARGET sees nothing of it; with --plain --no-e2e it \
     is a connection to TARGET with nobody on it, which an sshd counts among those that have not logged in \
     (its MaxStartups, 10 by default), so keep N under that bound. A spare that TARGET refuses stops them \
     until the next minute. The node's line says once whether its relay keeps them; a relay of the contract \
     (the default relay) keeps none, and the node goes on as without the flag. --spares is for the pair's \
     road, and is refused with --iroh, --derp, --opentunnel, --quick-tunnel, --carrier and --temporary. \
     --install writes it into the service.";

/// The relay's side of it, for `relay serve`.
pub(super) const RELAY: &str = "Beside the contract, podssh relay serve keeps sessions readied ahead for a node \
     that asks, as podssh node --spares N asks: the node's hello offers them (\"spares\": true), and the \
     node's text frame {\"type\":\"spares\",\"want\":N} asks for N, 16 at most, 0 for none; a frame with no \
     whole number closes the node's socket with 1003 invalid spares frame. A node that says nothing gets \
     none. The role sends {\"type\":\"open\",\"id\":ID,\"spare\":true} for each, with the node's sessions \
     counted inside its 64, and takes no spare that the node has not readied. An operator's leg takes the \
     youngest readied one before it opens a session of its own: it hears ready at once, then the bytes that \
     the node sent on the spare (64 KiB at most, past which the spare closes), and its first byte goes to the \
     node with no open; a leg that finds none goes the way of before and asks for one more, up to N. A \
     minute in which no leg took one leaves one; a spare that waited 15 s closes and another is drawn; one \
     that the node refused stops them until the next minute; a leg that finds no room closes one; a halt \
     closes them, and a resume draws them again. A spare's close says why, and its id is a session's that \
     ended, for a frame on its way. Each take is a line reverse spare taken on stdout, in the place of \
     reverse open.";
