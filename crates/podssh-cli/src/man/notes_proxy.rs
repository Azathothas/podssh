//! The notes of `podssh proxy`, apart from `notes.rs` so that each file
//! stays short.

pub const PROXY: &[&str] = &[
    "podssh proxy sends stdin to the target through the relay, and the target's bytes to stdout. It is \
     not an SSH client. Its main use is as the ProxyCommand of OpenSSH: \
     ssh -o ProxyCommand='podssh proxy %h %p' user@host. It also carries each TCP protocol that a \
     program can speak over stdin and stdout.",
    "podssh proxy has no direct road: it reaches the target through the relay, or through a road in the \
     relay's place. For the direct road, from this host through HTTPS_PROXY when one is set, the \
     ProxyCommand of OpenSSH is podssh pipe: ssh -o ProxyCommand='podssh pipe - tcp:%h:%p' user@host \
     (see podssh pipe).",
    "With OpenSSH, set -o ServerAliveInterval=60: the relay closes a session with no traffic (see THE \
     RELAY). Once nothing crossed for all but 30 s of the relay's idle cut, podssh proxy says so on \
     stderr, which OpenSSH shows; --idle-warn SECONDS sets that lead, and 0 turns it off.",
    "With PODSSH_RELAY_LAYER=yes, and a first relay host that offers it in its /relays.json (podssh relay \
     serve does), podssh proxy carries the session in the resumable layer, to that host alone: the relay \
     keeps its connection to the target while this host's link is lost, and a new link resumes the \
     session where it was, so that an OpenSSH session outlives a drop of this host's network, for 10 \
     minutes at most (T-173). Each loss and resume is a line on stderr. OpenSSH's SIGHUP at its exit ends \
     the session at the relay at once. A host that offers none takes the contract's road, with one line. \
     Where podssh can run on the server's side, a roost in front of its sshd (podssh node --sshd, see \
     podssh node) gives the same with no relay that keeps the session; this road is for an sshd where \
     nothing else runs.",
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
    super::notes_roads::PROXY_CLEARTEXT,
    "podssh proxy node://NAME[/ROUTE] is the pipe of podssh operator NAME[/ROUTE] (see its notes): stdin to \
     the node of the pair under the label NAME, and the bytes of its TARGET, or of its ROUTE, to stdout, with \
     the pair stored under NAME or that of --pair-file, the end-to-end channel and its flags --client-key, \
     --node-key and --no-e2e, --resume-deadline, --no-resume, and the same exit codes. As the ProxyCommand of OpenSSH: ssh \
     -o ProxyCommand='podssh proxy node://NAME' user@NAME. The node names the service, so a PORT is refused \
     (64), as are the relay's flags (--relay-host, --relay-failover), --forwarder, --shadowsocks, --via, \
     --vless, --wstunnel, --exit and --idle-warn, each of which takes the relay's place or speaks of it; \
     --relay-addr and --ca-file reach the pair's relay. The flags of a node with another target are refused \
     (64). A word that starts with node: and is no node://NAME is refused with the three forms of a node's \
     ProxyCommand: podssh proxy node://NAME, podssh operator NAME and podssh pipe - node:NAME; node:PORT stays \
     the host node and its port. With --carrier ADDR the node is at the other end of a stream that exists \
     already, with no relay and no pair, as podssh operator --carrier reaches it (see its notes), with its \
     checks and codes: ssh -o ProxyCommand=\"podssh proxy --carrier 'exec:ssh -T sandbox podssh node \
     --carrier stdio box 127.0.0.1:22' node://box\" user@box.",
    "--ConnectTimeout SECONDS, 1 to 86400, bounds the time from the start to the session's open, on each \
     road: the relay's answer (each host's dial, its TLS, the upgrade, and its dial of HOST), or the answer of \
     the road in the relay's place, and for node://NAME the steps of podssh operator. Each step keeps its own \
     limit too, and the first limit to pass ends the wait. Past the bound one line names the step that waited, \
     as: no relay host answered within 25 s (--ConnectTimeout), and the exit is 69. The bytes after the open \
     are never bounded: a pipe may wait. proxy takes no -o, so -o ConnectTimeout=N is refused (64); 0 is \
     refused too. --timeout DURATION is another name of the same bound, as a duration (30s, 2m, 1h) rounded \
     up to whole seconds, a day at most, and PODSSH_TIMEOUT gives it its default, held to a day, as for \
     podssh operator: the line past the bound names the one that set it, and --ConnectTimeout wins when \
     both are given.",
    "podssh proxy --exit NAME HOST PORT carries the pipe from NAME, a node of your net that lends its egress \
     (see podssh node --exit and podssh exit), in place of the relay: the node resolves HOST, checks each of its \
     addresses and dials HOST PORT from its own host, over the pair kept under NAME, in the resumable layer and \
     the end-to-end channel. A refusal of the node, or of its net's policy, is one line on stderr; no byte of \
     stdout comes before the node reached the target. With --carrier ADDR, the exit is the node at the other \
     end of a stream that exists already, with no relay and no pair (podssh node NAME --exit --carrier stdio): \
     exec:CMD, a program started with no shell, or fd:N (Unix); the net's rule of the exit holds as on each \
     road, and at the end the node hears a Close. stdio, --relay-addr and --ca-file are refused with it (64), \
     as stdin and stdout carry the pipe's bytes and the stream has no relay.",
    super::notes_grant::PROXY,
];
