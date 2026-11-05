//! The notes of a node's upgrade in place (T-668, T-679), for `node` and
//! `update`, apart from the others so that each file stays short.

/// The node's upgrade in place.
pub(super) const NODE: &str = "SIGUSR2 asks a node to take the binary now at its path, as podssh update leaves \
     it, with its sessions: a node of the pair's road (with or without the transit road beside it), and one of \
     --iroh, --derp, --quick-tunnel, the Piping Server road or the OpenTunnel road, with the pair's road beside \
     it where it has one. The node first runs \
     that binary once, as podssh --version with PODSSH_HANDOVER=probe, for 10 s at most: a binary that does not \
     start, or does not say that it takes a node's sessions of this version, leaves the node as it is, and a line \
     says why. Else the node stops its socket as a stop does, each session's close saying that the node \
     upgrades; each link of the resumable layer stops at a record's end, each end-to-end channel between two \
     messages; and the node becomes the new binary in the same process (execve), with the same pid, words, \
     environment and scope of systemd, so a supervisor of --restart or a service manager sees no end. The new \
     binary keeps each session as one whose link was lost, with its offsets, its replay buffer, its channel's \
     keys and nonces and its tokens of one leg, and the very TCP connection to TARGET, then goes online; each \
     client resumes on a new leg as after any loss, and an sshd behind a roost never sees its connection end. \
     The sessions' state passes in anonymous memory (memfd on Linux, a POSIX shared object unlinked at once on \
     macOS, else a private file of the cache unlinked at once), never a path, and their sockets stay open \
     across the exec alone. A session that cannot move (a UDP flow, a target in this process, a channel that \
     does not stop within 10 s) waits as an ended one, and its client's resume hears the session's end with \
     why; a session of --plain, which has no layer, ends at the stop. A binary that does not start after the \
     probe gives the sessions back to this one, which serves on. Its lines say how many sessions went, and the \
     new binary's first lines how many it took. Each road's own connection is made again by the new binary, as \
     the same, so that each client finds the node where it was: the iroh road's endpoint and the DERP road's \
     home under the same key, so the ticket stays, also for a key of --ephemeral-key, which passes with the \
     sessions; the same door of the Piping Server, as its path is the pair's; the OpenTunnel road's tunnel kept \
     in the cache, under the same name (a tunnel that no directory of the cache took gets a new name, and the \
     node says so as it starts); and the quick tunnel's same name, as its credentials pass with the sessions and \
     the new binary registers it again with no request to Cloudflare's API (should the edge refuse it, the node \
     asks for a new tunnel, under a new name, which the clients of the sessions that came over do not hold). A \
     session of --iroh with --no-e2e, a pipe in this process, ends at its resume. A node of --quick-tunnel with \
     --relay, whose relay role's tokens and pairs live in its process, a node of --carrier and one of \
     --temporary ignore the signal and go on with their binary. Windows has no such signal: a node there takes \
     a new binary at its next start, its sessions ending as before.";

/// What `podssh update` does to the nodes that run.
pub(super) const UPDATE: &str = "Once the binary is replaced, each node of --detach of this user that takes the \
     signal of an upgrade (a node of each road but a carrier's, a temporary one and a quick tunnel's with the \
     relay role behind it, which says so beside its record in the cache's detached directory) is sent \
     SIGUSR2, while its run's lock is held and its record names its pid, and takes the new binary with its \
     sessions (see the notes of podssh node); a line names each. A node that is no run of \
     --detach, as a unit of systemd, takes it by the signal USR2, which kill or systemctl kill sends to its process or its unit; until then, and \
     after --rollback, a node goes on with its own binary.";
