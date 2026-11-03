//! The notes of grants used once (T-226), for `node`, `operator`, `proxy`,
//! `ssh`, `pipe` and `relay`, apart from the others so that each file stays
//! short.

/// The node's door for grants, and its mint.
pub(super) const NODE: &str = "A node lets in an operator with a grant used once, also one whose key no \
     --allow names: an OpenSSH user certificate of the operator's key, which the end-to-end channel carries \
     from it, encrypted, so no relay sees it. Its issuer is the node's own key, or a key of --allow (or a \
     member of the net) for what that key may reach itself. Its principal is node: and the node's \
     fingerprint (node:SHA256:...), with /ROUTE for a route; it has a window, and the critical option \
     once@podssh. Before it dials, the node checks that the channel proved the certificate's key, the \
     issuer's signature, a user certificate, the principal, the window (5 minutes of skew), each critical \
     option, and the serials of --revoked FILE; then it records the grant as used, in grants-NAME of the \
     cache, synced, and only then lets the session in, so a second use of it is refused, also after a \
     restart, and a crash between the two spends it. A grant that leaks is worth nothing without its key. \
     The resumable layer carries the session on with no new check. podssh node NAME --grant-to KEY prints \
     one on stdout and serves nothing: the node's key signs it for KEY (ssh-ed25519 BASE64, or its 64 hex \
     digits), for its TARGET or for --grant-route ROUTE, for --grant-for TIME (1h by default), a random \
     serial; the operator gives it with podssh operator --grant FILE. An issuer of --allow makes one with \
     OpenSSH: ssh-keygen -s ISSUER -I ID -n node:SHA256:... -O clear -O critical:once@podssh -V +1h KEY.pub. \
     With PODSSH_CACHE_DIR=none no use can be recorded, and each grant is refused. A node with no --allow \
     and no net says that the pair's token alone is its door, which a TARGET that is not SSH has no other \
     gate behind.";

/// `operator --grant`.
pub(super) const OPERATOR: &str = "--grant FILE gives a grant used once, KEY-cert.pub of ssh-keygen -s or the \
     line of podssh node --grant-to, for this session: the end-to-end channel carries it to the node once \
     its key was checked, never a relay or a URL, and a URL in its place is refused (64), as is --no-e2e \
     beside it. A file that is no Ed25519 certificate is 78. The grant must name this operator's key \
     (client.key, or --client-key); a line says so when it names another, with this key in the form that \
     the issuer signs. A node that refuses the grant (used already, out of its window, or for another key, \
     node or route) is 77, its reasons in the node's log. A node of an earlier podssh reads no grant, and \
     ends the session in its handshake. Each grant lets in one session: a run that opens more sends it in \
     the first.";

/// `proxy node://NAME --grant`.
pub(super) const PROXY: &str = "node://NAME takes --grant FILE as podssh operator does: a grant used once, in \
     the end-to-end channel of the one session.";

/// `ssh node://NAME --grant`.
pub(super) const SSH: &str = "node://NAME with --grant FILE carries a grant used once, an OpenSSH certificate \
     of this client's key (client.key, or --client-key), in the end-to-end channel of the session, which a \
     node lets in once although no line of its allowlist names that key (see podssh node). A URL in its place, and \
     --no-e2e beside it, are refused (64); a destination that is no podssh end is too.";

/// `pipe --grant`.
pub(super) const PIPE: &str = "--grant FILE gives the first session of a node: side a grant used once, as \
     podssh operator --grant takes it; a pipe with no node: side refuses it (64), and a listening side's \
     later clients carry none.";

/// `relay pair --once`.
pub(super) const RELAY: &str = "podssh relay pair NAME --once asks the relay for a pair whose connect token \
     takes one upgrade alone: one operator's session, with no resume, after which the token is refused, \
     also by the status, so that a token that leaks from a log after its use is worth nothing. podssh relay \
     serve makes one, and offers it in its /relays.json; a relay that makes none is said so (69), and the \
     pair that it made is stopped. The node's token and the stop token stay as they are; --renew is refused \
     with it (64).";
