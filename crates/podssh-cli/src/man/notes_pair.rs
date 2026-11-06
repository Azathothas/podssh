//! The notes of the two ends of the reverse road, `node` and `operator`,
//! apart from the others for the length of the file: the pair, the layer, a
//! roost (T-166), the end-to-end channel and its keys (T-087, T-088), the
//! iroh road, the DERP road (T-379), and a carrier (T-595).

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
     64 MiB of replay buffers: a whole buffer for each session that can still fill one, with a link or \
     waiting for its operator (16 sessions with the default of PODSSH_REPLAY_BUFFER); for a session whose \
     TARGET ended and whose end went out, the bytes that the operator has not acknowledged; nothing for a \
     session that ended, whose operator had each byte but lost the link before it answered: its id alone \
     waits as long, and a resume of it hears the end. A new session past the 64 MiB ends at once with the \
     reason, which counts the sessions with a link and those waiting for their operator, and says when the \
     first of those is forgotten; the node says the same on stderr, once a minute at most, and once when \
     its buffers pass three quarters of the 64 MiB. An operator that asks for no resume (podssh operator \
     --no-resume, and the same flag of ssh, cp, scp, sftp, proxy and pipe) gets a session that the node \
     forgets as its link ends, which holds nothing after. podssh ssh node:// and podssh operator speak the layer. For an \
     operator that does not, --plain carries each session's bytes as they are, TARGET dialled at the \
     start of the session: a lost link then ends the session. On the default relay, which closes the \
     node's whole socket with 1003 for a frame of a session whose operator's link it lost (podssh relay \
     serve drops such a frame), one operator's lost link can end each --plain session of the node, where \
     the layer resumes each of its sessions; the node connects again at once after such a close (T-421). \
     The node's first line names its mode.",
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
    "A roost's sshd must run already: podssh brings none. When nothing listens at a TARGET on the \
     loopback, the roost exits 69, and after the dial's words says whether this host has an sshd, looked \
     for on PATH, then in /usr/sbin, /usr/local/sbin and /sbin (on Windows, the OpenSSH folder of \
     System32): where it is, and that nothing listens at TARGET (start it, or give the port that it \
     listens on); or that none is installed, with the command that installs one, from the first package \
     manager on PATH (apk, apt-get, dnf, yum, zypper, pacman, brew, pkg), with sudo first where the user \
     is not root and does not own the package manager's file, and sudo is on PATH (else the command says \
     as root; Homebrew never takes sudo). podssh names the command and runs none. A TARGET off the \
     loopback keeps the dial's words alone. podssh doctor's line sshd says the same before a roost \
     starts.",
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
     dialled once at the start. A node of the channel serves its shares too, routes that podssh share adds \
     and removes while it runs, read again for each session from node-NAME.shares in the cache or the file \
     of --shares FILE, each dialled at its session alone (see podssh share).",
    "TARGET udp:HOST:PORT offers a UDP service, for a host that allows UDP: each session is one flow, \
     a UDP socket from this host to HOST:PORT, with each datagram after its length in two bytes in \
     the session's bytes, as podssh pipe udp:node:NAME carries them. The flow ends with its session, \
     or after 60 s with no datagram either way. Before it registers, the node opens a UDP socket to \
     TARGET and closes it, with nothing sent: a host that refuses UDP, as a sandbox does, exits 78, \
     and a name with no address 69. A UDP TARGET is the node's only one, with no route, and not on \
     the iroh road. A datagram of the target over 65,507 bytes is dropped, and the node says how \
     many when the flow ends.",
    "The node runs until Ctrl-C or SIGTERM (exit 0), or until the relay ends the pair: stopped, \
     expired, refused, or served by another node; each has its code in EXIT STATUS. A pair lives 72 \
     hours at most: the node says its expiry 24 hours, 6 hours and 1 hour before it, with the command \
     that makes the next pair (podssh relay pair NAME, see podssh relay), and at the expiry it goes \
     on with the pair stored under NAME since, if one expires later; else it exits 77. A node of \
     --pair-file needs a new FILE and a new start. Where its relay renews pairs (podssh relay serve), \
     the node renews its own at the start of its last 24 hours instead, then each hour until it took, \
     with its tokens the same, and says each renewal; the store keeps the new expiry, and the lines \
     above are said only where the relay renews none. A stopped node deletes the stored pair only while it \
     is the node's own. A broken \
     connection to the relay is made again, and a line says how it ended: the relay is restarting \
     (1012, as podssh relay serve closes each socket before it stops), the link ended with no Close, \
     a fault of the node's bytes, or another close. The first try after a connection that served goes \
     at once, as none of these is an overload, and once each 10 s at most; each other try after a \
     growing wait, which the line names. After a loss the relay can still \
     hold the old connection, and answer 409: the node then connects again for the time that it keeps \
     a session (10 minutes, or --resume-deadline), with a line for each 409. A 409 at the start means that another node \
     serves the pair, or that the relay still holds the connection of the node that ran just before: the node \
     connects again for 30 s, with a line for each 409, then exits 69. stdout stays empty; notes go to stderr.",
    "With --pair-file, the pair comes from FILE, in the form of the store, and the store is not used. \
     FILE must be a regular file of the user that nobody else can read.",
    "--detach sends the node into the background once it is online (a quick tunnel's, once registered; \
     the iroh road's, once its ticket is said), as podssh ssh -f does (see its notes): this program again, \
     its log detached/node-PID.log in the cache. For a node that must outlive a logout or a reboot, \
     --install; --detach goes with no --install, --uninstall or --temporary (64). --detach-name NAME names \
     the run, and a second start of a name that runs refuses (75), where a second node of the pair would \
     meet the relay's 409; see podssh detached.",
    "--install makes the node a service of this user, with no privilege, which starts it again whenever \
     it ends, by the first way that a probe finds. A user unit of systemd (podssh-node-NAME.service, \
     enabled and started) when systemctl answers for this user: it restarts 5 s after each end with no \
     limit of starts, but not after 64 or 78, a refused command line or setting; 77, an expired pair, is \
     started again, so that a new pair is taken at the next start. Else a LaunchAgent \
     (~/Library/LaunchAgents/dev.podssh.node.NAME.plist, with KeepAlive and RunAtLoad), loaded with \
     launchctl bootstrap in the user's login session, when launchctl has one: it starts now, at each \
     login and 5 s after each end, and its lines go to node-NAME.log in the cache. Else two lines of the \
     crontab when crontab answers: one at boot, and one each 5 minutes that starts the node when it is \
     not running. On Windows a task (schtasks) at the user's logon and each 5 minutes while the user is \
     logged on, which also starts again a minute after a failure; never a Windows service, and no task \
     at boot, which need an administrator: after a reboot the task waits for the logon. The service runs \
     this binary by its absolute path with the node's own TARGET and flags, each file by its absolute \
     path, and --env-file: the variables that the node reads (the proxy's, SSL_CERT_FILE, PODSSH_RELAY \
     and the places of podssh's files) go into node-NAME.env, a private file beside the pair, as a \
     service has none of the shell's. No token goes in it, nor on a command line: PODSSH_RELAY_TOKEN and \
     the secrets of Cloudflare Access are not carried, and the pair's tokens stay in the pair's file. A \
     user unit runs while the user has a session unless lingering is on, which podssh says and never \
     changes. With no way, the command to run at login is printed on stdout, and the exit is 69. With \
     --temporary, --ephemeral-key or --iroh-ephemeral, --install is refused (64), as is a pair that is \
     not stored with neither --iroh nor --derp, which serve with none (78). A new --install replaces \
     what an earlier one made for NAME, by any way, so that two never start the node. --uninstall \
     removes what --install wrote for NAME (the unit, stopped first, the LaunchAgent, booted out first, \
     the lines of the crontab, or the task, and the files of its variables, its lock and its log), and \
     nothing else; a node that the crontab started goes on until it ends.",
    "--env-file FILE sets the variables of FILE before anything else: lines of the form name=value, and \
     # comments, each name a variable that podssh reads. FILE must be a private file of the user; a \
     token in it is refused (78), with its line. The run then holds a lock on FILE.lock, with its pid in \
     it, for as long as it runs: a second run with the same FILE (the crontab's each 5 minutes, or a \
     person's) ends at once with 0, and says so only on a terminal. A lock that this file system cannot \
     take is said, and the run goes on without one.",
    "With --iroh, in a build with the feature iroh, as each release binary is, the node serves TARGET over the \
     iroh road, with no \
     pair: QUIC between keys, through an iroh relay and HTTPS_PROXY, and directly when UDP works. The \
     relays are n0's public ones, or those of --iroh-relay, and the first that answers is the node's \
     (see THE RELAY). The node's key is the same on both roads (see above); --iroh-key and \
     --iroh-ephemeral are --key and --ephemeral-key by their earlier names. When it starts, the node \
     prints its key's \
     fingerprint and its ticket (iroh:...) on stderr, and a new ticket when its home \
     relay changes; a client dials the ticket with podssh ssh iroh:TICKET. On n0's relays, the node \
     also keeps a record of its roads at n0's server of pkarr, its home relay and, with --derp, its DERP \
     home, where a client with an older ticket, or with the node's key alone, finds them (see iroh \
     record in THE RELAY). When the pair NAME is stored \
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
     (tc301a.ipn.dev to tc304a.ipn.dev, which need no account and are rate-limited, and which Tailscale \
     may withdraw at any time), then to Tailscale's main fleet, which serves Tailscale's own clients and \
     which PODSSH_DERP_MAIN=no leaves out (see the public services in the notes of podssh ssh), or to the \
     servers of \
     --derp-server or PODSSH_DERP_SERVER, under the resumable layer with an adapter that sends again what \
     a server drops. The node's home is the first server whose /derp/probe answers within 5 s and whose \
     DERP handshake takes the node's key (a server that closes after it goes on to the next), and its \
     key there is derived from the node's key, so its ticket (derp:...), which it prints on stderr, stays \
     while its home does; after 3 failed connections in a row to its home, the node calls the next server \
     of its list home that takes a connection, and prints the new ticket. A client dials the ticket with \
     podssh ssh derp:TICKET, or races it with podssh ssh node://NAME --derp-ticket TICKET. A DERP server \
     lets any key send, so the road needs the end-to-end channel and a door for it: --allow, or a node key \
     that is a member of the net held here and in force (see podssh net), whose members are then the door \
     alone, on each road of the node, and the first line says so. --no-e2e, --plain and a udp: TARGET are \
     refused with it (64), and so is --derp with neither door, before the node's key is made. A node with no \
     --allow that leaves its net lets nobody in. With the pair NAME stored \
     and good, or --pair-file, the node serves the pair's road too, and with --iroh the iroh road, with \
     one keeper of sessions for each road. A server sees each end's key on it, the sizes and the times; \
     the channel keeps the bytes from it. With --iroh, the node's record of pkarr names its DERP home; \
     with no --iroh, in a build with the iroh road, it does too, at n0's server unless its variable names \
     another or off (see iroh record in THE RELAY).",
    "A node with no pair stored under NAME (or one that expired), no --iroh and no --plain, and a door \
     (an allowlist, or a key that the net held here names), serves the DERP road unasked, by the operator's \
     ruling Q50, and its first line says so; PODSSH_DERP=no turns that off, and the node refuses as before \
     (78). With neither door, it refuses as before too, as no client could come in.",
    "A node of the pair's road with the resumable layer and the end-to-end channel (no --plain, no \
     --no-e2e) and a TCP TARGET also waits for the pair's operators at a magic-wormhole transit relay \
     (T-436), Least Authority's wss://relay.mw.leastauthority.com, which needs no account, by the \
     operator's ruling Q65, or the relay of PODSSH_TRANSIT; PODSSH_TRANSIT=no turns it off. The token by \
     which the relay pairs the two ends, and a proof of the pair that each end gives the other, come from \
     the pair's connect token, so a side that knows the token alone, as the relay does, is refused before \
     the resumable layer. The node keeps one connection waiting there, opens the next at each meeting, \
     and keeps the sessions of both roads with one keeper, so that a session resumes on either; its line \
     names the relay. The relay sees the token, the sizes and the times; the channel keeps the bytes \
     from it. A node of --derp with a pair waits there too.",
    "A node of a pair has a road for a proxy that refuses the WebSocket upgrade: the Piping Server road, \
     through https://ppng.io, which needs no account, then https://piping.onrender.com where ppng.io fails, \
     or the server of PODSSH_PIPING alone. Once TARGET answered, the \
     node asks the relay for its socket with no token; where something on the way refuses the upgrade, \
     the node says so and serves the Piping Server road alone, unasked, by the operator's ruling Q65, \
     until the pair expires (77). It waits there with a GET at a door whose path comes from the pair's \
     secret; a client of the pair posts a hello there, and each end then sends its way of the link as a \
     POST and reads the other's as a GET, over HTTP/2 on one connection where the server offers it, else \
     over HTTP/1.1, through HTTPS_PROXY. Where a proxy holds a streamed body until its end, the link goes \
     in numbered pieces, a whole POST for each. PODSSH_PIPING=yes, or a server's https:// URL, serves the \
     road beside the pair's, with one keeper of sessions for both; PODSSH_PIPING=no turns it off. The road \
     runs the resumable layer and the end-to-end channel, so --plain, --no-e2e and a udp: TARGET keep the \
     node on the pair's road alone. The server sees the paths, the sizes and the times; the channel keeps \
     the bytes from it.",
    super::notes_pair::NODE_OPENTUNNEL,
    super::notes_frp::NODE,
    // Grants used once (T-226).
    super::notes_grant::NODE,
    // A person at the node's terminal, after its door (T-638).
    super::notes_ask::NODE,
    // The tokens of one leg, and the stop token's rotation (T-615).
    super::notes_legs::NODE,
    // The sessions that its relay readies ahead (T-650).
    super::notes_spares::NODE,
    // A node's upgrade in place, its sessions with it (T-668).
    super::notes_upgrade::NODE,
    // The dialect of the reverse road (T-643).
    super::notes_dialect::NODE,
    // A site that the relay role publishes by its name (T-649).
    super::notes_publish::NODE,
    "With --quick-tunnel, the node serves TARGET at https://NAME.trycloudflare.com, a quick tunnel of \
     Cloudflare's that podssh makes itself, with no pair, no account and no cloudflared. The name is new \
     each run, and is the one line on stdout. The node needs port 7844 of Cloudflare's edge, and races \
     its roads there: QUIC where no proxy is set, as cloudflared does, after a probe of UDP (one QUIC \
     packet, whose answer it waits 300 ms for); HTTP/2 on TCP, directly or through a proxy that allows \
     it; and HTTP/2 inside WARP's tunnel, in a build with the feature warp (see warp:// in the notes of \
     ssh: its device, and PODSSH_WARP_ACCEPT_TERMS), as a cage whose proxy allows port 443 alone reaches \
     the edge so; --warp puts WARP's tunnel first. Each road starts 2 s after the one before, or at once \
     when that one failed; the first that the edge registers is kept, and the others are closed. The \
     road that won goes first at the next connection, and the node exits 69 when no road reaches the \
     edge. Its line of the registration names the road and how long the race took, after a line for \
     each road that gave way. A client in a cage \
     reaches the name on port 443. The name is public, so the node needs a door: --allow FILE, and only \
     an operator whose key is a line of FILE reaches TARGET, through the end-to-end channel above the \
     resumable layer; or, with no --allow, a key of the node's that the net held here names, and only \
     the net's members come in (T-550), its first line saying so. With neither, it is refused (64). The node keeps two connections to the edge, each to its own region first, so that one stays \
     while the other is made again. On the edge's GOAWAY its visitors go on for up \
     to 90 s while a new connection, at once, takes the new ones. A \
     connection to the edge that is lost is made again, with the same name; at Ctrl-C the node \
     unregisters each. --iroh, --derp, --plain, --no-e2e, --pair-file, a route and a udp: TARGET are \
     refused with it (64). In a build with the iroh road, the node's record of pkarr names the tunnel, at \
     n0's server unless its variable names another or off, for a client with the node's key (see iroh \
     record in THE RELAY).",
    "With --quick-tunnel --relay, the node is its owner's relay too, with no listener: behind its tunnel \
     it serves the relay's forward and reverse roads, those of podssh relay serve, where a request of \
     another path than a visitor's would get 404: /health, /v1/mint, /connect/HOST/PORT, /relays.json, \
     /trace, /llms-full.txt and each path under /v1/. Its one line on stdout is the relay host: a client \
     reaches the relay with --relay-host https://NAME.trycloudflare.com, as it reaches another relay. With \
     no TARGET, the node is the relay alone, and each path is the relay's. It mints tokens, and makes \
     pairs, for the keys of --allow by default (the net's members, with no --allow), each by its signature of the relay's challenge, and a \
     signed request must name the tunnel; --mint keys:FILE names another list, --mint net the members of \
     the node's net, as its policy lets them reach relay:NAME (NAME the node's name in the net) or \
     relay:*, --mint anyone mints for each client, and --mint nobody for none. --pairs FILE keeps its \
     pairs across a restart, though the \
     tunnel's name is new each run; --allow-private dials non-public targets too, and --routes RANGES \
     those inside its ranges alone, as podssh relay serve --routes. The relay dials each \
     target from this host, as podssh relay serve does: through HTTPS_PROXY when it is set, the proxy \
     that the node's dial of the edge takes too. Each mint, upgrade and step of the reverse road \
     is a line on stderr, and Ctrl-C or SIGTERM first closes each socket of the reverse road with 1012.",
    "The name is asked of api.trycloudflare.com, which limits a host that made a few tunnels: when it \
     refuses for now (429, or a 5xx), the node asks again for up to 5 minutes, after its Retry-After \
     (seconds, or a date) or a growing wait, with a line for each wait, and Ctrl-C ends the wait (0). A \
     Retry-After past those 5 minutes, or a refusal that lasts them, ends the node at once with exit 75, \
     and the line says until when the API asks to wait; any other refusal exits 69. A text of \
     Cloudflare's API or edge is shown on one line, with no control character.",
    "podssh node NAME [TARGET] --exit lends this host's egress to the members of its net, as a Tailscale exit \
     node does: an operator names a target of its own (podssh ssh --exit NAME, podssh proxy --exit NAME, podssh \
     exit --listen), which travels in the end-to-end channel, and the node resolves its name here, checks \
     each address, and dials those addresses alone, never the name again, so that a name that resolves anew \
     elsewhere reaches nothing that was not checked. A public address needs a rule to exit:NAME (or exit:* or *) \
     of the net's policy; a private one, loopback, link-local or another that the relay refuses needs one of \
     podssh node --routes RANGES, ADDR/BITS or one address apart by commas (a prefix that sets bits past \
     it, as 10.0.0.5/8, is refused with the network that it names), and a rule to its address. A name \
     with one address that fails is refused whole. The net must give the node the role exit, signed by its \
     owner, else the node does not start (78); a key of --allow, or an operator of the connect token alone, \
     never reaches the exit. TARGET is then optional. It goes on the pair's, the iroh, the DERP, the transit and \
     the Piping Server roads, on a carrier (--carrier), and behind a quick tunnel (--quick-tunnel), whose \
     visitors are the keys of --allow or, with none, the net's members: podssh ssh --exit cf://HOST and the \
     copies reach it by the tunnel's name, which the node prints; podssh exit, proxy --exit and pipe --exit \
     reach an exit by its pair, iroh, DERP or a carrier, and refuse a cf:// name (64). --no-e2e, --temporary \
     and a udp: TARGET are refused with it (64).",
    "With --carrier ADDR, the node's one road is a stream that exists already, for a host whose every road out \
     is closed but that grants one channel, such as the exec channel of a platform's own SSH: stdio (or -), \
     the stdin and stdout that such a channel gives the program that it starts; fd:N, a descriptor that the \
     node inherited (Unix); or exec:CMD, a program that the node starts with no shell, as podssh pipe reads \
     these. The stream carries the node's socket of the reverse road, its WebSocket frames with no HTTP \
     before them, and its other end, podssh operator --carrier, or podssh proxy, ssh, cp, scp and sftp \
     with --carrier to node://NAME, serves the relay's side of that socket in its own process. No relay, no pair and no token: whoever holds the stream reached the node through what \
     carries it, so NAME is a label alone, for the node's key, and each operator comes in unless --allow \
     names its keys. The resumable layer, the end-to-end channel, the routes, a roost and a udp: TARGET are as \
     on the pair's road; the relay's limits (64 MiB a session, a pair's 72 hours) do not hold. The node \
     dials TARGET first, then sends one Ping, its first frame, and says online: the other end opens no \
     session before it. One stream is the node's life: at its end the sessions end, and the node exits 0 \
     after the other end's Close, or 69 for a stream that failed; a program of exec: is waited for 2 s, then \
     ended. --carrier stdio refuses a terminal on stdin (64), whose keys the node would read as frames. \
     --pair-file, --relay-addr, --ca-file, --iroh, --derp, --quick-tunnel, --relay, --temporary, --install, \
     --detach and the flags that go with them are refused with --carrier (64), as the stream is the node's \
     parent's. --exit goes with it: the client at the other end is podssh exit --listen ADDR:PORT --carrier ADDR \
     NAME, or podssh ssh, podssh proxy or podssh pipe with --exit NAME and --carrier, and the net's rule of the \
     exit holds as on each road, so a host whose one channel is a platform's exec channel gets egress through \
     its other end.",
];

pub(super) const OPERATOR: &[&str] = &[
    "podssh operator NAME carries stdin to the node of the pair under the label NAME, and the bytes of \
     the node's TARGET to stdout, as podssh proxy carries a forward session. It is the ProxyCommand of \
     OpenSSH for a node: ssh -o ProxyCommand='podssh operator NAME' user@NAME. podssh proxy node://NAME is \
     the same pipe, with the same flags and codes, by the form of a node that podssh ssh takes.",
    "Before the node takes the session, up to 1 MiB of stdin is kept, and sent then. The session ends \
     when stdin ends or the node's TARGET closes; it exits 0 only when the node took the session. An \
     error is one line on stderr; the codes are in EXIT STATUS.",
    "SIGHUP, SIGTERM and SIGINT (on Windows, Ctrl-C, Ctrl-Break and the close of the console) end the \
     session as the end of stdin does: OpenSSH ends its ProxyCommand with SIGHUP as it exits, and does \
     not wait for it. The node hears the session's end after the bytes on their way, and keeps nothing of \
     it; podssh waits 2 s at most for the node's answer, then exits, 0 when the node took the session. A \
     signal before the node took it ends the wait at once. A signal that podssh was started to ignore \
     (nohup, a detached run's SIGHUP) stays ignored.",
    "With a node that offers the resumable layer, a lost link to the relay is replaced by a new one, \
     for as long as the node keeps the session (10 minutes, or its --resume-deadline), and the session \
     goes on where it was; one line on stderr tells of each loss and each resume. --resume-deadline \
     TIME waits at most TIME, never longer than the node keeps the session. A close that a new link \
     would only get again (a stopped or expired pair) ends the session. When the node forgot the \
     session, as after a sleep of this host longer than its deadline, the line says so, with how long \
     this side was away by the wall clock.",
    "--no-resume asks the node, in the layer's handshake, to end the session with its link: no new link \
     replaces a lost one, and none goes beside it, and the node forgets the session and closes its \
     connection to TARGET as the link ends, so that its budget of replay buffers is free at once. A lost \
     link then ends the session, as on a node of podssh node --plain, with a line that says so, and the \
     relay's limits of a session end it too. A node of an earlier podssh, which does not know the ask, \
     keeps the session for its deadline as before, and a line says so; this side still does not resume it.",
    "With --pair-file, the pair comes from FILE, or its operator's part alone, as podssh relay pair \
     writes it for the operator, and the store is not used.",
    "--ConnectTimeout SECONDS, 1 to 86400, bounds the time from the start to the session's open: the \
     relay's answer, the node's ready, its first bytes, and the handshakes of the layer and of the \
     end-to-end channel. Each step keeps its own limit too (30 s for the relay, 20 s for ready), and the \
     first limit to pass ends the wait. Past the bound one line names the step that waited, as: the node \
     did not answer ready within 25 s (--ConnectTimeout), and the exit is 69. The bytes after the open are \
     never bounded. A node run as podssh node --plain sends its TARGET's first bytes as they come, and \
     the bound waits for them too: with a TARGET that speaks second, give none. operator takes no -o, so \
     -o ConnectTimeout=N is refused (64); 0 is refused too. --timeout DURATION is another name of the same \
     bound, as a duration (30s, 2m, 1h) rounded up to whole seconds, a day at most, and PODSSH_TIMEOUT gives \
     it its default, held to a day: the line past the bound names the one that set it, as within 25 s \
     (--timeout). --ConnectTimeout wins when both are given; none of them is ever required.",
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
    "With --carrier ADDR, the node is at the other end of a stream that exists already, with no relay and \
     no pair: exec:CMD, a program that podssh starts with no shell, such as the platform's own SSH into a \
     host whose every road out is closed, exec:'ssh -T sandbox podssh node --carrier stdio NAME TARGET'; or \
     fd:N, a descriptor that podssh inherited (Unix). stdio is refused (64): stdin and stdout carry the \
     session's bytes. This end serves the relay's side of the node's socket in its own process, waits up to \
     60 s for the node's first frame, then carries the session as on the pair's road, so OpenSSH reaches the \
     node's sshd with ssh -o ProxyCommand=\"podssh operator --carrier 'exec:ssh -T sandbox podssh node \
     --carrier stdio box 127.0.0.1:22' box\" user@box. NAME is a label alone, under which the node's key is \
     pinned at its first sight, so a stream that another key answers is refused (77). A stream of exec: \
     that is lost is started again for the next link of a resume; the node that it starts is a new one, \
     which knows no session of the one before, and the session ends with its reason. A stream of fd: has \
     one life. At the end the node hears a Close, and the program of exec: is waited for 5 s, then ended. \
     --ConnectTimeout bounds the open here too: the node's read of the stream, its ready, then the layer \
     and the channel. podssh proxy --carrier ADDR node://NAME is the same pipe. --pair-file, --relay-addr \
     and --ca-file are refused with --carrier (64).",
    // Grants used once (T-226).
    super::notes_grant::OPERATOR,
    // The tokens of one leg (T-615).
    super::notes_legs::OPERATOR,
    // The dialect of the reverse road (T-643).
    super::notes_dialect::OPERATOR,
];

/// The note of `ssh node://NAME --carrier ADDR` (T-595), beside operator's.
/// The OpenTunnel road of a node (T-531), apart from the notes above for
/// their length.
pub(super) const NODE_OPENTUNNEL: &str = "With --opentunnel, the node serves TARGET over the OpenTunnel road: \
     a blind TLS tunnel of https://opentunnel.xyz, which needs no account, or of the service of PODSSH_OPENTUNNEL. \
     The node makes one tunnel, ID.opentunnel.xyz, with a P-256 key and the CSR of its name that it makes itself, \
     and keeps the tunnel, its token and its key in a private file of the cache before the service orders its \
     certificate, so that each start keeps the same name and asks for no new certificate, of the 5 a day that the \
     service gives a tunnel. Its route is 26 random letters, so its name is ROUTE.ID.opentunnel.xyz, which the \
     line name says, with the command of a client; the node keeps a bridge to the service, a WebSocket through \
     HTTPS_PROXY, again after each loss, and TLS ends at the node with the tunnel's certificate: the service \
     sees the name, the times and the sizes, never the bytes. Anyone may connect to a tunnel's name, so the \
     road needs the end-to-end channel and a door: --allow, or the members of the net held here when the node's \
     key is one; never --plain, --no-e2e, --exit or a udp: TARGET (64). With the pair NAME, or --pair-file, the \
     node serves the pair's road beside it, with one keeper of sessions. A node with no pair, a door, and the \
     DERP road turned off (PODSSH_DERP=no) serves the road unasked, by the operator's ruling Q76, and its first \
     line says so; PODSSH_OPENTUNNEL=no turns the road off. The service's refusals are named: a token that it \
     no longer takes (a new tunnel is made, and said), a route that an earlier run holds (tried again), its \
     limit of 30 tunnels an hour from one address, with its wait.";

/// The OpenTunnel road of a client (T-531).
pub(super) const SSH_OPENTUNNEL: &str = "node://NAME with --opentunnel-name HOST races the OpenTunnel road too, \
     250 ms after the DERP road: HOST is the name that the node's line name says, ROUTE.ID.opentunnel.xyz. Each \
     link is TCP to HOST on port 443 through HTTPS_PROXY, then TLS by HOST, checked with the host's trust \
     (SSL_CERT_FILE, else the system's stores), with no WebSocket upgrade, so a proxy that refuses the upgrade \
     passes it, and so does one that ends TLS itself, whose CA the host trusts. The name is kept under NAME in the \
     cache (opentunnel-NAME.name), and a later run that gives none dials it only once each road before it \
     failed, the fallback of the operator's ruling Q76, which PODSSH_OPENTUNNEL=no turns off. The end-to-end \
     channel checks the node's key by the pins of NAME, or --node-key, so --no-e2e leaves the road out (64 \
     with --opentunnel-name).";

pub(super) const SSH_CARRIER: &str = "node://NAME with --carrier ADDR reaches the node at the other end of a \
     stream that exists already, as its one road, with no relay and no pair: exec:CMD, a program that podssh \
     starts with no shell, such as the platform's own SSH into a host whose every road out is closed, \
     exec:'ssh -T sandbox podssh node --carrier stdio NAME TARGET'; or fd:N, a descriptor that podssh \
     inherited (Unix). stdio is refused (64), as stdin and stdout are the session's. podssh serves the \
     relay's side of the node's socket in its own process, as podssh operator --carrier does, waits up to \
     60 s for the node's first frame, then runs the session in the resumable layer and the end-to-end \
     channel as on the pair's road, and no other road races it. NAME is a label alone, under which the \
     node's key is pinned at its first sight, so a stream that another key answers is refused; the host key \
     is recorded under node://NAME, as on each road. At the end the node hears a Close, and the program of \
     exec: is waited for 5 s, then ended. With --exit NAME in place of node://NAME, the exit is the node at \
     the other end of the stream (podssh node NAME --exit --carrier stdio), its one road: the destination, or \
     the first hop of -J, is a host that the exit dials from its own host, by the net's rule of the exit, and \
     the host key is the host's, as on each road: podssh ssh --exit gw --carrier 'exec:ssh -T gateway podssh \
     node gw --exit --carrier stdio' user@host.example. --pair-file, --relay-host, --relay-failover, \
     --relay-addr, --ca-file, --direct, --iroh-ticket, --derp-ticket, --derp-server, a server's road in the \
     relay's place and --upgrade are refused with it (64), and so is --carrier with a destination that is no \
     node and no --exit.";

/// The note of doctor's line sshd (T-590), beside the roost that it serves.
pub(super) const DOCTOR_SSHD: &str = "The line sshd is for a roost (podssh node --sshd): where this host has an \
     sshd, looked for as the roost looks (on PATH, then in /usr/sbin, /usr/local/sbin and /sbin), and what one \
     dial of 127.0.0.1:22 reads first within 2 s, judged as the roost judges it: its version line (present at \
     /usr/sbin/sshd; 127.0.0.1:22 answers SSH-2.0-...), nothing listening, or another first line. With no \
     sshd found, it names the command that installs one, as the roost does; podssh runs none. The dial is of \
     the loopback, so it is made with PODSSH_OFFLINE too. Each form is ok: a host with no roost needs no sshd.";
