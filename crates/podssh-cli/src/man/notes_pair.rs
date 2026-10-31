//! The notes of the two ends of the reverse road, `node` and `operator`,
//! apart from the others for the length of the file: the pair, the layer, a
//! roost (T-166), the end-to-end channel and its keys (T-087, T-088), the
//! iroh road, and the DERP road (T-379).

pub(super) const NODE: &[&str] = &[
    "podssh node serves TARGET, a TCP service, to the operators of the pair stored under NAME (see \
     podssh relay). Each session that an operator opens is one connection to TARGET, from this host, \
     through HTTPS_PROXY unless TARGET is on the loopback. podssh dials TARGET once at the start, and \
     exits when it cannot. It says online once the relay has its socket, and online again after a \
     loss: an operator reaches it from that line on.",
    "Each session runs the resumable layer: an operator that loses its link to the relay resumes the \
     session on a new link, and the node keeps the session and its connection to TARGET for 10 minutes \
     after a loss, or for the TIME of --resume-deadline, from 1 minute to 72 h, on each road: a laptop \
     that sleeps for a night needs 8h or more. The node names that time to each operator, which waits \
     as long, and its first line says it. A session kept longer keeps its replay buffers longer, and \
     the bound below holds. TARGET is dialled only once the operator's handshake is done. The node keeps at most \
     64 MiB of replay buffers (16 sessions with the default of PODSSH_REPLAY_BUFFER); a new session past \
     that ends at once with the reason. podssh ssh node:// and podssh operator speak the layer. For an \
     operator that does not, --plain carries each session's bytes as they are, TARGET dialled at the \
     start of the session: a lost link then ends the session. The node's first line names its mode.",
    "A roost: with --sshd, the node serves a standard sshd, TARGET, or 127.0.0.1:22 when no TARGET is \
     given. A normal server gets the resumable layer, and with --iroh the iroh road, this way: the roost \
     owns the TCP connection to sshd. Before the node goes online, it dials each TARGET and reads its \
     first line, which must be SSH's version line (SSH-2.0-...) within 10 s; else it exits, and names \
     TARGET and what came back: 78 for another service, 69 for no line or a close. The node's first \
     line gives the version line. Each session's connection to sshd, made after the layer's handshake, \
     is checked the same way, and a session whose TARGET does not answer as sshd ends at once with the \
     reason. The check takes no byte of the session: the client still reads sshd's line. podssh ssh \
     node://NAME keeps sshd's host key under node://NAME, the name that the user gives, as OpenSSH does \
     for a host behind a ProxyCommand.",
    "--temporary KEY is the node that podssh ssh --upgrade starts on its server (see podssh ssh): a roost \
     in front of the sshd that its SSH session came through (SSH_CONNECTION: on the loopback first, then \
     at the server's address), or of TARGET, with a pair that it makes on the relay of PODSSH_RELAY (else \
     the default) and that no file keeps, and a key for this run only. It lets in the client key KEY \
     alone. Once the relay takes the pair's sessions, it writes one line to stdout, the pair's connect \
     token and its own key, and on Unix leaves that SSH session: SIGHUP is ignored, and stdin, stdout and \
     stderr become /dev/null. It ends with its last session, or 10 minutes after its start with none, and \
     stops its pair. With it, --iroh, --derp, --pair-file, --plain, --no-e2e, the flags of the node's key, \
     and a route are refused (exit 64).",
    "Each session runs the end-to-end channel above the layer (Noise XX): the relay sees ciphertext \
     only, and the operator's key and the node's prove themselves in it. The node's key is a private \
     file in the cache (node-NAME.key, or iroh-node-NAME.key of an earlier podssh), or the file of \
     --key, made when it is missing; --ephemeral-key makes one for this run only. The node says its \
     fingerprint as it starts, and an operator pins it at the first sight. With --allow FILE, only the \
     operator keys of FILE come in, on each road: one key or fingerprint on each line, read again for \
     each session; a refused operator gets no byte of TARGET, and its key is said on stderr, as the \
     line to add. With no allowlist, each operator with the pair's connect token comes in, and its key \
     is said. TARGET is dialled only once the operator's key is let in. --no-e2e carries the bytes with \
     no channel, to operators run with --no-e2e too: the relay then sees them.",
    "Routes: podssh node lab 127.0.0.1:22 web=127.0.0.1:8080 db=127.0.0.1:5432 offers each TARGET \
     under its route, here web and db, a name of the form of a pair's, with one pair and one node for \
     all; the TARGET with no route is the one of an operator that names none. An operator names a route as NAME/ROUTE (podssh operator NAME/ROUTE, \
     podssh ssh node://NAME/ROUTE, iroh:TICKET/ROUTE), in the end-to-end channel, so the relay never \
     sees it and --no-e2e offers none. With --allow, a key reaches a route only when its line says so: \
     KEY routes=web,db, or routes=* for each; a key with no routes= reaches the TARGET with no route \
     alone. A route that the node does not have, or that the key may not use, is refused with the same \
     words, before any dial. With no allowlist, each operator may use each route. Each TARGET is \
     dialled once at the start.",
    "TARGET udp:HOST:PORT offers a UDP service, for a host that allows UDP: each session is one flow, \
     a UDP socket from this host to HOST:PORT, with each datagram after its length in two bytes in \
     the session's bytes, as podssh pipe udp:node:NAME carries them. The flow ends with its session, \
     or after 60 s with no datagram either way. Before it registers, the node opens a UDP socket to \
     TARGET and closes it, with nothing sent: a host that refuses UDP, as a sandbox does, exits 78, \
     and a name with no address 69. A UDP TARGET is the node's only one, with no route, and not on \
     the iroh road. A datagram of the target over 65,507 bytes is dropped, and the node says how \
     many when the flow ends.",
    "The node runs until Ctrl-C or SIGTERM (exit 0), or until the relay ends the pair: stopped, \
     expired, refused, or served by another node; each has its code in EXIT STATUS. A broken \
     connection to the relay is made again, after a growing wait. After a loss the relay can still \
     hold the old connection, and answer 409: the node then connects again for the time that it keeps \
     a session (10 minutes, or --resume-deadline), with a line for each 409. A 409 at the start means that another node \
     serves the pair. stdout stays empty; notes go to stderr.",
    "With --pair-file, the pair comes from FILE, in the form of the store, and the store is not used. \
     FILE must be a regular file of the user that nobody else can read.",
    "--install makes the node a service of this user, with no privilege, by the first way that a probe \
     finds: a user unit of systemd (podssh-node-NAME.service, enabled and started) when systemctl answers \
     for this user, else an @reboot line of the crontab when crontab answers; on Windows a task at the \
     user's logon (schtasks), never a Windows service. The service runs this binary by its absolute \
     path with the node's own TARGET and flags, each file by its absolute path, and --env-file: the \
     variables that the node reads (the proxy's, SSL_CERT_FILE, PODSSH_RELAY and the places of podssh's \
     files) go into node-NAME.env, a private file beside the pair, as a service has none of the shell's. \
     No token goes in it, nor on a command line: PODSSH_RELAY_TOKEN and the secrets of Cloudflare Access \
     are not carried, and the pair's tokens stay in the pair's file. A user unit runs while the user has \
     a session unless lingering is on, which podssh says and never changes. With no way, the command to \
     run at login is printed on stdout, and the exit is 69. With --temporary, --ephemeral-key or \
     --iroh-ephemeral, --install is refused (64), as is a pair that is not stored with neither --iroh \
     nor --derp, which serve with none (78). --uninstall \
     removes what --install wrote for NAME (the unit, stopped first, or the line of the crontab, or the \
     task, and the file of variables), and nothing else.",
    "--env-file FILE sets the variables of FILE before anything else: lines of the form name=value, and \
     # comments, each name a variable that podssh reads. FILE must be a private file of the user; a \
     token in it is refused (78), with its line.",
    "With --iroh, in a build with the feature iroh, as each release binary is, the node serves TARGET over the \
     iroh road, with no \
     pair: QUIC between keys, through an iroh relay and HTTPS_PROXY, and directly when UDP works. The \
     relays are n0's public ones, or those of --iroh-relay, and the first that answers is the node's \
     (see THE RELAY). The node's key is the same on both roads (see above); --iroh-key and \
     --iroh-ephemeral are --key and --ephemeral-key by their earlier names. When it starts, the node \
     prints its key's \
     fingerprint and its ticket (iroh:...) on stderr, and a new ticket when its home \
     relay changes; a client dials the ticket with podssh ssh iroh:TICKET. When the pair NAME is stored \
     and good, or --pair-file gives one, the node serves the pair's road too, with one keeper of \
     sessions for both: a session resumes on either road, and podssh ssh node://NAME --iroh-ticket \
     TICKET races them. When the pair's road ends, the node says why, and the iroh road goes on.",
    "A client of the iroh road gets in only when its key, or the key's fingerprint, is a line of the \
     file of --allow (or --iroh-allow, its earlier name), which \
     the node reads again for each connection, so a key added counts at once. With no such file, no \
     client gets in. Each refused key is said on stderr: it is the line to add. A session reaches TARGET \
     only after the layer's handshake, and resumes on a new link for 10 minutes, as on the relay.",
    "With --derp, the node serves TARGET over the DERP road, in each build: DERP's packets over a \
     WebSocket at wss://SERVER/derp, through HTTPS_PROXY, to Tailscale's free servers for tailcat \
     (tc301a.ipn.dev to tc304a.ipn.dev, which need no account and are rate-limited), or to the servers of \
     --derp-server or PODSSH_DERP_SERVER, under the resumable layer with an adapter that sends again what \
     a server drops. The node's home is the first server whose /derp/probe answers within 5 s, and its \
     key there is derived from the node's key, so its ticket (derp:...), which it prints on stderr, stays \
     while its home does; after 3 failed connections in a row to its home, the node calls the next server \
     of its list home that takes a connection, and prints the new ticket. A client dials the ticket with \
     podssh ssh derp:TICKET, or races it with podssh ssh node://NAME --derp-ticket TICKET. A DERP server \
     lets any key send, so the road needs --allow and the end-to-end channel: --no-e2e, --plain and a \
     udp: TARGET are refused with it (64), and so is --derp with no --allow. With the pair NAME stored \
     and good, or --pair-file, the node serves the pair's road too, and with --iroh the iroh road, with \
     one keeper of sessions for each road. A server sees each end's key on it, the sizes and the times; \
     the channel keeps the bytes from it.",
    "A node with no pair stored under NAME (or one that expired), no --iroh and no --plain, and an \
     allowlist, serves the DERP road unasked, by the operator's ruling Q50, and its first line says so; \
     PODSSH_DERP=no turns that off, and the node refuses as before (78). With no --allow, it refuses as \
     before too, as no client could come in.",
    "With --quick-tunnel, the node serves TARGET at https://NAME.trycloudflare.com, a quick tunnel of \
     Cloudflare's that podssh makes itself, with no pair, no account and no cloudflared. The name is new \
     each run, and is the one line on stdout. The node needs port 7844 of Cloudflare's edge: over QUIC \
     where no proxy is set and UDP gets there, as cloudflared does, else over HTTP/2 on TCP, directly or \
     through a proxy that allows it; QUIC that fails gives way to HTTP/2 for the run, and the node exits \
     69 when it reaches neither. Its line of the registration names the transport. A client in a cage \
     reaches the name on port 443. The name is public, so --allow FILE is needed: only an operator \
     whose key is a line of FILE reaches TARGET, through the end-to-end channel above the resumable \
     layer. A connection to the edge that is lost is made again, with the same name; at Ctrl-C the node \
     unregisters it. --iroh, --derp, --plain, --no-e2e, --pair-file, a route and a udp: TARGET are \
     refused with it (64).",
];

pub(super) const OPERATOR: &[&str] = &[
    "podssh operator NAME carries stdin to the node of the pair under the label NAME, and the bytes of \
     the node's TARGET to stdout, as podssh proxy carries a forward session. It is the ProxyCommand of \
     OpenSSH for a node: ssh -o ProxyCommand='podssh operator NAME' user@NAME.",
    "Before the node takes the session, up to 1 MiB of stdin is kept, and sent then. The session ends \
     when stdin ends or the node's TARGET closes; it exits 0 only when the node took the session. An \
     error is one line on stderr; the codes are in EXIT STATUS.",
    "With a node that offers the resumable layer, a lost link to the relay is replaced by a new one, \
     for as long as the node keeps the session (10 minutes, or its --resume-deadline), and the session \
     goes on where it was; one line on stderr tells of each loss and each resume. --resume-deadline \
     TIME waits at most TIME, never longer than the node keeps the session. A close that a new link \
     would only get again (a stopped or expired pair) ends the session. When the node forgot the \
     session, as after a sleep of this host longer than its deadline, the line says so, with how long \
     this side was away by the wall clock.",
    "With --pair-file, the pair comes from FILE, or its operator's part alone, as podssh relay pair \
     writes it for the operator, and the store is not used.",
    "The session runs the end-to-end channel (see podssh node). This operator's key is a private file \
     in the cache (client.key, or iroh-client.key of an earlier podssh), or the file of --client-key, \
     made when it is missing, and its fingerprint is said when it is new. The node's key is pinned at \
     its first sight in known-nodes, in the cache, one line for each label; a node whose key changed is \
     refused, with both fingerprints, the file and the line, and exit 77, and the pin is never \
     replaced. --node-key KEY expects that key, or fingerprint, instead, and reads and writes no pin. A \
     node that refuses this operator's key ends the session with exit 77, and the line names the key to \
     add to its allowlist. --no-e2e carries the bytes with no channel, to a node run with --no-e2e.",
    "NAME/ROUTE names a route of the node (see podssh node): the route travels in the end-to-end \
     channel, encrypted, and the node refuses one that it does not have, or that this operator's key \
     may not use, before it dials anything.",
];
