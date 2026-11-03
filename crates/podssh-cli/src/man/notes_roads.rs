//! The notes of `podssh ssh` on the roads of Q66 to a server of the user's
//! own (T-441), apart from `notes_ssh`, which is full: [`SSH`] is its notes,
//! then these, joined when the binary is built; and the note of `proxy` on
//! the same road, as `notes` is full too.

use super::notes_ssh::SSH as OWN;

/// The notes of `podssh ssh`.
pub const SSH: &[&str] = &join::<{ OWN.len() + ROADS.len() }>(OWN, ROADS);

const ROADS: &[&str] = &[
    "--exit NAME starts the road to the first hop (the destination, or the first host of -J) at NAME, a node of \
     your net that lends its egress (see podssh node --exit), in place of the relay, as a Tailscale exit node \
     carries a device's traffic: the node dials the host from its own, on each of its roads that answers, raced as \
     for node://NAME, and the session resumes on any of them. The host travels in the end-to-end channel, so the \
     relay sees neither the host nor a byte; the node resolves it, checks each address (a public one, or one of \
     its ranges, as its net's policy lets this client) and dials those addresses alone. The host key is the \
     host's, under its own name, as on the relay. NAME is a member of the net, whose key the channel checks, and \
     the label of its pair here. A refusal of the node or of its net's policy says why, and ssh exits \
     255. --exit goes with no node://, iroh:, derp:, cf://, iap:// or eice:// destination, no --direct, no -4 \
     or -6, no --no-e2e and no road of another server (64). With --carrier ADDR, the exit is the node at the \
     other end of that stream, its one road, with no relay and no pair (see --carrier). podssh cp, scp and \
     sftp take it too.",
    "--wstunnel wss://HOST[:PORT] reaches the first hop through a server of erebe/wstunnel that you run \
     (wstunnel server wss://[::]:443), in place of the relay: podssh opens the WebSocket to it, through \
     HTTPS_PROXY when one is set, checked for HOST with podssh's trust (--ca-file), and its token names the \
     first hop as wstunnel's own client names it; the server dials it and carries the bytes. podssh speaks \
     the protocol of wstunnel 9.1 to 11 over its WebSocket, which each server serves beside its HTTP/2 on \
     one port: https:// and wts:// are refused (64), and ws:// has no TLS. What the server checks of a \
     client comes from --wstunnel-secret-file FILE (or PODSSH_WSTUNNEL_SECRET_FILE), a file of yours that \
     others cannot read: path-prefix PREFIX, the prefix that the server restricts its clients to; \
     credentials USER[:PASSWORD] or authorization VALUE, the Authorization that its restrictions match; or \
     one line, the prefix alone. With no file, podssh is the client of wstunnel's defaults, the prefix v1. \
     Over ws:// a secret goes to this host alone (64). The server refuses a tunnel with a 400 that names \
     no cause: podssh says it in the words of the version that sent it (a path prefix or an Authorization \
     that it does not take, a target that it does not allow, or one that it could not reach; its log names \
     which), and exits 77. An answer that is not wstunnel's is said so (69). Each frame is masked with a \
     key of zero, which the server reads the same whether it applies masks or not. PODSSH_WSTUNNEL names \
     the server where the command line names no other road; beside PODSSH_RELAY, PODSSH_FORWARDER or \
     PODSSH_VIA it is refused (78). A run has one road: --relay-host, --relay-failover, --direct, \
     --forwarder, --shadowsocks, --via, --vless, -4, -6, and a destination with a road of its own cannot go \
     with it (64). The host key of SSH protects the session, as on each road.",
];

/// The note of `podssh proxy --wstunnel`.
pub const PROXY_WSTUNNEL: &str =
    "podssh proxy --wstunnel wss://HOST[:PORT] carries the pipe through a wstunnel server that you run, \
     with no relay, as podssh ssh does (see its notes); PODSSH_WSTUNNEL names it too. The end of stdin \
     sends no Close, as a Close is no half-close: the target's bytes come until it closes.";

/// `a`, then `b`, as one array of `N`, their lengths' sum.
const fn join<const N: usize>(a: &[&'static str], b: &[&'static str]) -> [&'static str; N] {
    let mut out = [""; N];
    let mut i = 0;
    while i < a.len() {
        out[i] = a[i];
        i += 1;
    }
    let mut j = 0;
    while j < b.len() {
        out[a.len() + j] = b[j];
        j += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_notes_of_ssh_are_its_own_then_those_of_its_roads() {
        assert_eq!(super::SSH.len(), super::OWN.len() + super::ROADS.len());
        assert_eq!(super::SSH[..super::OWN.len()], *super::OWN);
        assert!(super::SSH.last().is_some_and(|n| n.starts_with("--wstunnel ")));
    }
}
