//! The notes of `--vless` (T-440) for `podssh ssh`, `podssh proxy` and
//! `podssh doctor`, apart from the others so that each file stays short.

pub const SSH_VLESS: &str = "--vless FILE reaches the first hop through VLESS servers that you run (Xray-core, \
     shoes, sing-box), in place of the relay: a server that takes the target in a short header and dials it, with \
     a user's ID in place of a token. FILE must be yours and closed to others (chmod 600), as a pair file is: each \
     line is a share link as panels and Xray-core's clients give it, vless://ID@HOST:PORT, then ?type=ws or \
     type=xhttp, security=tls, sni=, host=, path= and mode=, joined by &, and #TAG; # starts a comment. ID is a \
     UUID, or a word of 1 to 30 bytes, which Xray-core maps to one. type=ws carries the stream over a WebSocket \
     at the path; type=xhttp carries it over XHTTP's plain HTTP requests on HTTP/2, which pass where a proxy or a \
     front end refuses the WebSocket upgrade: mode=packet-up (a streamed GET down, and a numbered POST for each \
     chunk up, which auto takes, as Xray-core's client does with TLS), stream-up (a streamed GET down and one \
     streamed POST up) or stream-one (one POST, its body up and its answer down). security=tls is TLS to \
     HOST:PORT, through HTTPS_PROXY when one is set, checked for sni (else host, else HOST) with podssh's trust \
     (--ca-file); host gives the request's Host; with security=none XHTTP speaks HTTP/2 with no TLS. A server, \
     or a front end that ends TLS on the way, that chooses HTTP/1.1, or refuses HTTP/2 with no TLS, gets \
     packet-up and stream-up over HTTP/1.1 on two connections to it: the GET on one, the upload on a second, \
     opened only then (-v says \"on two connections\"); stream-one is refused there (proxy exits 78; ssh 255, \
     as for each first hop that it does not reach), as Go's server reads a request's whole body before it \
     answers. A flow (xtls-rprx-vision), REALITY, VLESS's encryption, type=tcp, and an extra setting \
     of XHTTP that changes its requests are refused by their names (78), and so is a line that cannot be read, \
     by its number and never its text. The servers are tried in the order of the file, and each waits up to \
     10 s for VLESS's answer, which comes with the server's version line: a server that ends the session before \
     it has refused the ID or could not reach the target, and gives way to the next; -v says which transport \
     carried the session. Xray-core holds a session to a private address with no word, unless the finalRules \
     of its freedom outbound allow it, and the wait ends with that said. The host key of SSH protects the session, as on each road: the server sees the \
     target's name and SSH's encrypted bytes. A run has one road: --relay-host, --relay-failover, --direct, \
     --forwarder, --shadowsocks, --via, --wstunnel, -4, -6, and a destination with a road of its own cannot go \
     with it (64).";

pub const PROXY_VLESS: &str = "podssh proxy --vless FILE carries the pipe through the VLESS servers of FILE, in \
     order, with no relay, as podssh ssh does (see its notes). A pipe's client may speak first, so a server that \
     says nothing for 3 s is taken; one that ends the session, or answers in another protocol, within them gives \
     way to the next. A WebSocket and packet-up have no half-close: the end of stdin ends nothing, and the \
     target's bytes come until the server ends; stream-up and stream-one end their upload.";

pub const DOCTOR_VLESS: &str = "With --vless FILE, the section vless gives a line for each server of FILE, and \
     for each mode of XHTTP where its link says auto (packet-up, stream-up, stream-one): the proxy of HTTPS_PROXY \
     that carried the TCP to it, if one did, the transport that carried the session and the time of VLESS's \
     answer, then a session to github.com port 22 through it, whose host key must be one that GitHub publishes. \
     A server that ends the session before its answer refused the ID, or could not reach the target.";
