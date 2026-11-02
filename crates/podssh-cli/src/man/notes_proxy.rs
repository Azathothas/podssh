//! The notes of `podssh proxy`, apart from `notes.rs` so that each file
//! stays short.

pub const PROXY: &[&str] = &[
    "podssh proxy sends stdin to the target through the relay, and the target's bytes to stdout. It is \
     not an SSH client. Its main use is as the ProxyCommand of OpenSSH: \
     ssh -o ProxyCommand='podssh proxy %h %p' user@host. It also carries each TCP protocol that a \
     program can speak over stdin and stdout.",
    "With OpenSSH, set -o ServerAliveInterval=60: the relay closes a session with no traffic (see THE \
     RELAY).",
    "The session ends when the target closes the connection or when stdout closes; both are a success. \
     An error is one line on stderr; the codes are in EXIT STATUS.",
    "HOST can be an IPv6 address, bare (as OpenSSH gives %h) or in brackets. In one word, the form is \
     [ADDRESS]:PORT. Through the relay, see the IPv6 note of ssh.",
    "Put -- before a HOST that a script did not write: podssh proxy -- \"$HOST\" 22. Else a HOST that \
     starts with - is read as a flag.",
    "podssh proxy iap://PROJECT/ZONE/INSTANCE:PORT and podssh proxy eice://ENDPOINT/ADDRESS:PORT carry the \
     pipe through a cloud's own tunnel to a VM, as podssh ssh does (see its notes), with no relay and no \
     relay flag; the port goes in the destination, 22 when none is given, and the destination takes no \
     user. As the ProxyCommand of OpenSSH: ssh -o \
     ProxyCommand='podssh proxy iap://my-project/us-central1-a/%h:%p' user@my-vm. On IAP the end of stdin \
     ends the session once its bytes went, as IAP has no half-close.",
    "podssh proxy warp://HOST:PORT carries the pipe inside WARP's tunnel, in a build with the feature warp \
     (each release binary), \
     as podssh ssh does (see its notes): ssh -o ProxyCommand='podssh proxy warp://%h:%p' user@host.",
    "podssh proxy tor://HOST:PORT carries the pipe through the Tor network, in a build with the feature \
     tor, as podssh ssh does (see its notes): ssh -o ProxyCommand='podssh proxy tor://%h:%p' user@host.",
    "podssh proxy --forwarder TEMPLATES carries the pipe through other products' WebSocket forwarders and \
     Wisp servers, in order, with no relay, as podssh ssh does (see its notes); PODSSH_FORWARDER gives them \
     too. The end of stdin sends no Close (nor Wisp's CLOSE), as a close is no half-close: the target's \
     bytes come until it closes. When each \
     relay host failed, the forwarders that podssh names follow, as for podssh ssh.",
    "podssh proxy --shadowsocks FILE carries the pipe through the Shadowsocks servers of FILE, in order, \
     with no relay, as podssh ssh does (see its notes). A pipe's client may speak first, so a server that \
     says nothing for 3 s is taken; one that closes, resets or answers with a chunk that does not open \
     within them gives way to the next. The end of stdin is TCP's half-close, which the server passes on: \
     the target's bytes come until it closes.",
    "podssh proxy --via https://[USER@]HOST[:PORT] carries the pipe through a forward proxy over TLS, with \
     no relay, as podssh ssh does (see its notes); PODSSH_VIA names it too. The end of stdin is the \
     tunnel's half-close (the end of the stream, on HTTP/2): the target's bytes come until it closes.",
    super::notes_vless::PROXY_VLESS,
    super::notes_roads::PROXY_WSTUNNEL,
    "podssh proxy --exit NAME HOST PORT carries the pipe from NAME, a node of your net that lends its egress \
     (see podssh node --exit and podssh exit), in place of the relay: the node resolves HOST, checks each of its \
     addresses and dials HOST PORT from its own host, over the pair kept under NAME, in the resumable layer and \
     the end-to-end channel. A refusal of the node, or of its net's policy, is one line on stderr; no byte of \
     stdout comes before the node reached the target.",
];
