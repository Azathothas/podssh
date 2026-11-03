//! The notes of `podssh pipe` (T-174 to T-177, T-181, T-168), of its proxy
//! `http-listen:` (T-367) and of its WebSockets (T-368), apart from the
//! others so that each file stays short.

pub const PIPE: &[&str] = &[
    "podssh pipe A B joins two byte streams, as socat does, with no listener unless one side asks for \
     one: what A gives goes to B, \
     and what B gives goes to A. Each address is KIND:REST: - or stdio (stdin and stdout), fd:N (a \
     descriptor that podssh inherited, 3 or more, on Unix), or exec:CMD (a program); relay:HOST:PORT \
     (TCP through the relay, as podssh proxy carries it), tcp:HOST:PORT (TCP from this host, through \
     HTTPS_PROXY when it is set), ssh:[USER@]HOP[,HOP...],HOST:PORT (TCP that the last SSH hop opens, \
     as -W asks), node:NAME (the TARGET of the node of a pair), udp:node:NAME (UDP through a node; see \
     below), iroh:TICKET (the TARGET of a node of the iroh road), unix-connect:PATH (a local socket; \
     @NAME in Linux's abstract namespace; on Windows a Unix socket or a named pipe, \\\\.\\pipe\\NAME), \
     or serial:PATH[,BAUD] (a serial line, on Unix). Both are checked before anything starts, and stdio \
     on both sides is refused.",
    "unix-listen:PATH (by the names of unix-connect:) and tcp-listen:[ADDR:]PORT (on 127.0.0.1, or on \
     ADDR, an address of this host; port 0 asks for a free one) listen, one side at most. The bind is \
     the probe: a host that refuses it gives 77, and the line names the error. A Unix socket is made \
     mode 0600 and takes only this user's programs: a client of another user is closed. A TCP port \
     takes each user of this host, and other hosts too when ADDR is not loopback; podssh says which. \
     The first client is joined to a new instance of the other side, then the listener closes and its \
     file goes; --keep-listening takes each client in turn, 8 at once, until SIGINT or SIGTERM, after \
     which the file goes too. A path that is a file and not a socket is kept (64), and a socket that \
     answers is another program's (69). PODSSH_LISTEN set to no turns listening off (78).",
    "--via https://[USER@]HOST[:PORT] carries tcp:HOST:PORT and the first hop of ssh: through a forward \
     proxy over TLS, as podssh ssh --via does (see its notes), with the credentials of --via-auth-file; \
     tcp: takes the flag alone, as PODSSH_VIA names a road in place of the relay.",
    "--detach sends a listening pipe into the background once it listens, as podssh ssh -f does (see its \
     notes): this program again, its log detached/pipe-PID.log in the cache; its other side may not be \
     stdio (64), as the background has neither stdin nor stdout. --detach-name NAME names it, and a second \
     start of a name that runs refuses (75); see podssh detached.",
    "http-listen:[ADDR:]PORT, as tcp-listen: takes it, or http-listen:PATH, a socket by the names of \
     unix-listen:, is an HTTP CONNECT proxy, for a program that knows only HTTPS_PROXY: set it to \
     http://127.0.0.1:PORT. Each CONNECT HOST:PORT opens the other side with that target, which the other \
     side names as %h:%p: relay:%h:%p, tcp:%h:%p or ssh:[USER@]HOP[,HOP...],%h:%p. A side with no %h and no \
     %p is read with its target, and podssh says the reading before it listens: ssh:HOPS alone takes \
     ,%h:%p at its end, each of its words a hop, and relay and tcp take :%h:%p. Another kind, as exec:, \
     stdio or node:, is refused (64): each CONNECT names its own target, which it does not take. A client \
     on a socket of http-listen:PATH needs one that speaks to a proxy there; curl's --unix-socket goes past \
     its --proxy. Each request is a road \
     of its own, 32 at once, until SIGINT or SIGTERM; podssh's line names the value of HTTPS_PROXY. The \
     client hears 200 once its road is open, so that it learns whether its target was reached; 403 when \
     a policy refuses the target, with its words (the relay's, an upstream proxy's, or an SSH server's \
     administratively prohibited); 502 with the reason of a dial that failed; 504 for one past its limit.",
    "A proxy takes CONNECT alone: another method gets 405, a request that is not HTTP/1.1 400 (505 for \
     HTTP/2), and a head over 16 KiB 431; nothing is dialed for them. With --proxy-auth-file FILE, a \
     private file of lines USER:PASSWORD, each client gives one of them in Proxy-Authorization (Basic), \
     which podssh checks first, in constant time: a request with none, or with a wrong one, gets 407 and a \
     challenge, and nothing is dialed. A port on an ADDR that is not loopback needs the file (64): other \
     hosts reach it, and each request spends this host's road. The bytes that a client sends after its \
     CONNECT, before the 200, go to the road once it is open.",
    "ws://HOST[:PORT]/PATH and wss://HOST[:PORT]/PATH are a WebSocket by the URL that a user copies, \
     reached through HTTPS_PROXY when it is set: wss: checks the certificate for HOST with the trust of \
     --ca-file, and ws: is in the clear, as tcp: is. No token goes on them; the path and its query are the \
     user's, and podssh's lines show the URL without its query. Bytes go out in binary frames, and text and \
     binary frames come in as bytes. At the end of this side's input podssh sends a Close, and what the \
     other end sends before its own Close still comes; the other end's Close ends the pipe, and a code other \
     than 1000 is on stderr with its reason (69). A refused upgrade gives its status: 77 for 401 and 403, \
     else 69.",
    "ws-listen:[ADDR:]PORT or ws-listen:PATH is a WebSocket server, by the rules of tcp-listen: and \
     unix-listen:, whose clients are joined to the other side as given. A client's upgrade is checked as \
     RFC 6455 asks (GET, Upgrade, Connection, version 13, a key of 16 bytes) and refused with its status \
     (405, 400, 426); a request with an Origin is a browser's, and is refused (403), so that no page that \
     the user opens reaches the other side. The other side opens before the client hears 101, and 502 when \
     it does not. podssh's frames are a server's, unmasked, and a client's unmasked frame closes the \
     session with 1002. One client by default, the first whose upgrade is good; --keep-listening takes \
     each in turn.",
    "The hops of ssh: log in as podssh ssh logs in: through the relay, or with --direct, with -i and \
     -o; an -o of a session (RequestTTY, RemoteCommand) is refused. node: takes the pair stored under \
     NAME, or the one of --pair-file. iroh: takes this client's key of --iroh-key, and the relays of \
     --iroh-relay after the ticket's.",
    "With --carrier ADDR, node:NAME and udp:node:NAME take the node at the other end of a stream that \
     exists already, with no relay and no pair, as podssh operator --carrier does (see its notes): exec:CMD, \
     a program that podssh starts with no shell, or fd:N (Unix); NAME is the label under which the node's \
     key is pinned. stdio is refused (64), as the pipe's own stdin and stdout are a side or none, and so are \
     --pair-file and a pipe with no node side. Each node side, and each client of a listening side, is a \
     session of its own on the one stream, which ends with the pipe: the node hears a Close, and the \
     program of exec: ends. The other side keeps its road, so podssh pipe tcp-listen:2222 node:box --carrier \
     'exec:ssh -T sandbox podssh node --carrier stdio box 127.0.0.1:22' --keep-listening gives a port here \
     for the node's sshd.",
    "exec:CMD starts the program with no shell: its words split at blanks, with single and double \
     quotes, and no variables, globs or escapes; exec:sh -c 'CMD' names a shell. The program gets one \
     end of a socketpair as its stdin and stdout, or two pipes where a socketpair is refused and on \
     Windows. Its stderr is podssh's.",
    "udp:node:NAME carries UDP through the node of the pair under NAME, whose TARGET is udp:HOST:PORT \
     (see podssh node): the relay carries TCP only, and this host sends no UDP. Each datagram is its \
     length in two bytes, big-endian, then its bytes, 65,507 at most; the other side gives and takes \
     that framing on stdin and stdout, a descriptor or a socket. A program of exec: beside it gets one \
     end of a Unix datagram socketpair as its stdin and stdout on Unix, which needs no bind: each \
     send is one datagram at the target, each receive one answer; where that is refused, and on \
     Windows, its stdin and stdout carry the framing. The node's session has no half-close: after the \
     end of this side's input it waits for answers until none came for 5 s. A datagram socket has no \
     end of input either: when the other side ends, the program gets 10 s to exit, then SIGTERM. A \
     length over 65,507 in the stream exits 65; a longer datagram of the program is counted and \
     dropped. Over the relay, datagrams wait for each other: a lost segment delays each later one.",
    "When one side's input ends, the other side gets the end of its input, and the other direction goes \
     on, so that a reply still comes back: tcp:, ssh: and unix-connect: pass it on as a half-close. The \
     relay has no half-close, so relay: sends nothing at the end of input, and the target's bytes come \
     until it closes, as a named pipe's do, whose listening side closes it at its end of input; node: \
     and iroh: end their session. With a node: side, SIGHUP, SIGTERM and SIGINT end the node's session \
     as an end of input does, so that the node keeps nothing of it, and the road's status is then 0 \
     when the node took the session (see podssh operator). --no-resume ends the session of each node:, \
     udp:node: and iroh: side with its link, as podssh operator --no-resume does, and a pipe with none of \
     them refuses it (64). The pipe ends when both \
     have ended, when a side's reader is gone, when a program has exited and its output has ended, or \
     when a road has ended. podssh waits for each program, as a shell does.",
    "A road that failed gives the exit status, as podssh proxy gives it: 69 for a road out of reach, 77 \
     for a refusal (of the relay, a proxy, a host key or a login) and 78 for a setting that cannot be \
     used. Else the status is the program's (B's when both are programs), 128 + N for a signal, 127 for \
     a program that is not found and 126 for one that cannot run; with neither, 0. 65 for a stream of \
     udp: that is not its framing.",
    "serial:PATH[,BAUD] opens a serial device of this host, such as /dev/ttyUSB0, at BAUD (115200 when \
     none is given; from 1200 to 4000000), with 8 data bits, no parity, 1 stop bit and no flow control, \
     in raw mode; a PATH with a comma takes a BAUD after it. The path must be a character device that is \
     a terminal (else 64), and one that this user may open: a refusal is 77 and says whose the device is, \
     as podssh assumes no group; another failure is 69. podssh holds the line alone while the pipe runs, \
     and puts its settings back at the end, also at SIGINT and SIGTERM, which then exit 130 and 143. The \
     line has no end: the end of the other side's input leaves it open, and the pipe ends when the other \
     side ends it, at a signal, or when the device fails (69). On Windows, serial: is refused (64).",
    "--ConnectTimeout SECONDS bounds the open of a node: or relay: side as podssh operator and podssh proxy \
     bound theirs, the other side's open with it, and never the bytes after it; past it one line names the \
     step that waited, and the exit is 69. Each hop of an ssh: side takes it as its own ConnectTimeout too \
     (the SSH handshake, and each answer while logging in), and alone where no side is node: or relay:. A \
     listening side refuses it (64), as each client opens a road long after the start, and so does a pipe \
     with no node:, relay: or ssh: side. --timeout DURATION is another name of it, a duration (30s, 2m, 1h) \
     rounded up to whole seconds, with the same refusals, and each ssh: hop's ConnectTimeout too; \
     --ConnectTimeout wins when both are given. PODSSH_TIMEOUT gives the bound of a node: or relay: side its \
     default where no side listens; it refuses no pipe, as it bounds whole runs of other commands, and is no \
     hop's ConnectTimeout.",
    "--exit NAME starts relay:HOST:PORT, and each relay:%h:%p of http-listen:, at NAME, a node of your net that \
     lends its egress (see podssh node --exit and podssh exit), in place of the relay, over the pair kept under \
     NAME: the node resolves HOST and dials it from its own host. A pipe with --exit and no relay: address is \
     refused (64).",
];
