//! The notes of the frp road (T-498): a node behind the user's own frps, as
//! an STCP service, and a client that visits it.

/// The note of `podssh node NAME TARGET --frp FILE`.
pub(super) const NODE: &str = "With --frp FILE, the node serves TARGET through the user's own frps, as an \
     frpc of it does, with no relay and no pair: it logs in with frps's token, registers an STCP service of \
     NAME (or of the file's name line) with the file's secret, which opens no public port, and sends a \
     heartbeat each 30 s. FILE is a private file of the user's, a line each: server frp://HOST[:PORT] (frp's \
     own TCP with TLS, port 7000 by default) or wss://HOST[:PORT][/PATH] (frp's WebSocket behind the user's \
     TLS front end, path /~!frp by default); token, frps's token; secret, the STCP service's secret; # starts \
     a comment. Neither the token nor the secret goes on argv or in a line. TLS is checked with the host's \
     trust, or --ca-file; there is no frp road in the clear. Each visitor's work connection is a link of the \
     resumable layer, with the end-to-end channel above it, so frps sees the service's name, the times and \
     the sizes, never the bytes, and frp's own encryption of the service stays off. The holder of the secret \
     reaches the node through frps, so the road needs a door: --allow, or the members of the net held here \
     when the node's key is one; never --plain, --no-e2e, --exit, a udp: TARGET or another road's flag (64). \
     A lost connection is made again, after 1 s and up to 30 s apart; a token that frps refuses ends the node \
     (69), in frps's words. With no --frp, PODSSH_FRP names the file.";

/// The note of `podssh ssh node://NAME` with `PODSSH_FRP`.
pub(super) const SSH: &str = "node://NAME with PODSSH_FRP=FILE, the node's own frp file, races the frp road \
     too, once each road before it failed: a connection of its own to frps for each link, by the same TLS, \
     and a visit to the STCP service of NAME, or of the file's name line, signed with the secret as frpc's \
     visitor signs it. The end-to-end channel checks the node's key by the pins of NAME, or --node-key, and \
     the resumable layer resumes a session on a new visit. A file that does not read is a configuration \
     error (78), which names its line and never its text.";
