//! The notes of `podssh ssh`, apart from the others so that each file stays
//! short.

pub const SSH: &[&str] = &[
    "podssh ssh reaches the host through the relay (see THE RELAY), or over TCP with --direct. It needs \
     no installed ssh, no pty and no user database entry.",
    "node://[user@]NAME reaches the node of the pair under the label NAME (see podssh node), through the \
     relay. Its host key is recorded and checked under the name node://NAME. --pair-file gives the pair, \
     or its operator's part, in a file. The session runs the end-to-end channel, with the node's key \
     pinned and this client's key, as podssh operator does: --node-key, --client-key and --no-e2e as \
     there; a changed node key, and a key that the node refuses, exit 255. iroh:TICKET runs the channel \
     too, to the key that the ticket names. A node has no port, and -J, -W and --direct cannot go with \
     it yet. \
     podssh sends nothing until the node's first bytes (30 s at most), to learn whether the node offers \
     the resumable layer; -v says whether it does. With the layer, a lost link to the relay is replaced \
     by a new one for 10 minutes, and the SSH session goes on where it was; one line on stderr tells of \
     each loss and each resume.",
    "iroh:TICKET, or user@iroh:TICKET, reaches a node of the iroh road (see podssh node), in a build with \
     the feature iroh. The ticket is the address that the node prints, not a credential: the node lets in \
     only the client keys of its allowlist. This client's key is made on first use, in the cache \
     (client.key, or iroh-client.key of an earlier podssh) or in the file of --iroh-key; podssh prints \
     its fingerprint when it is new, and when a node refuses it, as the line that the node's operator \
     adds. The host key is recorded and checked under \
     the name iroh:KEY, the node's key, which stays when the ticket changes. A node has no port, and -J, \
     -W and --direct cannot go with it yet. The session runs the resumable layer: a lost link is \
     replaced by a new one, for 10 minutes. podssh asks the ticket's relay first, then those of \
     --iroh-relay (see THE RELAY).",
    "cf://[user@]HOST reaches a service that Cloudflare's cloudflared publishes under HOST, the name of \
     a tunnel's ssh:// or tcp:// rule: over the WebSocket that cloudflared access tcp opens, through \
     HTTPS_PROXY when one is set, with no relay and no program of Cloudflare's. A name behind Cloudflare \
     Access needs a service token (PODSSH_CF_ACCESS_CLIENT_ID and PODSSH_CF_ACCESS_CLIENT_SECRET) or a \
     token made where its login runs (PODSSH_CF_ACCESS_TOKEN or PODSSH_CF_ACCESS_TOKEN_FILE); a refusal \
     of Access says so. The host key is recorded and checked under HOST. A tunnel has no port here, and \
     -J, -4, -6, HostName and --direct cannot go with it. podssh proxy cf://HOST is the same pipe.",
    "node://NAME with --iroh-ticket TICKET races the two roads to the node: the iroh road starts first, \
     the pair's road 250 ms later, or at once when the iroh road fails, and the first far end that \
     speaks carries the session; the other link ends before it sends anything, so it opens nothing at \
     the node's TARGET. Each resume races them again, and -v says which road answered first.",
    "Host keys are checked against the known_hosts files. On a terminal, podssh asks about an unknown \
     key. With no terminal and no SSH_ASKPASS, it refuses the key and names the remedy: \
     -o StrictHostKeyChecking=accept-new records a new key with no question. A changed key is always \
     refused, and podssh shows both fingerprints. Under accept-new and no, a user known_hosts file that \
     exists and cannot be read makes an unknown key a refusal, as a key recorded there is not seen. A \
     key that cannot be recorded (no HOME, UserKnownHostsFile none, a failed write) holds for this \
     connection only, and podssh says so. A host that a @cert-authority line names is asked for a host \
     certificate, accepted with no record when that CA signed it for this host and it is valid now, and \
     refused with the check that failed. Each hop of -J checks its own key, under its own name, \
     [HOST]:PORT off port 22; HostKeyAlias names the destination's key alone, with no port, as OpenSSH \
     files it. The settings of host keys and authentication of -o and -i hold for each hop, where \
     OpenSSH's command line holds for the destination only.",
    "Authentication tries the agent and the identity files, then keyboard-interactive and password. \
     Prompts go to the terminal or to SSH_ASKPASS. With -o BatchMode=yes, each prompt is an error.",
    "-t asks for a pty when there is a local terminal. -tt asks for one also when there is none, so \
     interactive programs work from a host with no pty. In a session with a pty, ~. at the start of a \
     line ends the session, and ~# lists the forwards of the session, with the connections and bytes of \
     each (see -e); with -v, the end of a run prints the same lines.",
    "--sudo runs the command as root with sudo -S, with no pty, and --su with su -c, in a pty: the password \
     is asked here, on the terminal or through SSH_ASKPASS, never taken from the command line. podssh \
     answers one prompt, holds its input until the command starts, and asks nothing when sudo asks \
     nothing; a second prompt, a wrong password, ends the input. The remote shell must read POSIX \
     quoting.",
    "--record FILE keeps what the session showed, with its timing, as asciicast v2, for podssh play: never \
     what was typed, and never the command line. The file is closed to others and never written over (exit \
     255); the output can hold a secret that a program printed.",
    "--persist runs the shell in tmux on the server, as tmux new-session -A -s NAME with a pty (NAME is \
     podssh, or the one of --persist-name). podssh looks for tmux after the login and refuses without \
     it (exit 255): a new shell after a lost link would look like the old one. When the link is lost \
     (no exit status; through the relay, a broken link or a close for its limits or its link to the \
     server), podssh connects again, 10 times at most in 5 minutes, and attaches the same session; one \
     that is gone is not started again. A connection that lasted less than 30 s starts no new count. \
     An exit status, a detach, ~., a refused host key or login, and Ctrl-C during the wait end the \
     run. The logins after the first ask nothing (as BatchMode=yes); a key that a passphrase opened \
     and a password that the server took are kept for the run. Keys typed meanwhile go to the \
     session after the attach. With a command, -W, -s, -T, node:// or iroh:, --persist is refused \
     (exit 64).",
    "-L [BIND:]PORT:HOST:HOSTPORT listens here, and each connection that it takes goes on from the \
     server; HOST:HOSTPORT may be a socket path on the server, and the listening side a socket path here \
     (mode 0600). -D [BIND:]PORT, or a socket path, is a SOCKS4, SOCKS4a and SOCKS5 proxy, CONNECT only \
     and no authentication; podssh answers a SOCKS client once the server opened its channel. A port with \
     no address listens on 127.0.0.1 and ::1, or with -g (GatewayPorts) on each address; localhost is \
     loopback, and an empty address or * each address, as in OpenSSH. Each listener is made before \
     anything connects: one that cannot be made ends the run (exit 255), with the system's words and \
     -W HOST:PORT, which needs none; PODSSH_LISTEN set to no turns listening off (exit 78). \
     ClearAllForwardings yes drops each forward, and -W implies it, as in OpenSSH. -W /PATH reaches a \
     Unix socket on the server, as OpenSSH's -W does.",
    "-R [BIND:]PORT:HOST:HOSTPORT asks the server to listen; each connection that it takes reaches \
     HOST:HOSTPORT from this host, as one more outbound connection, through HTTPS_PROXY when it is set, \
     within 20 s. A port of 0 lets the server choose, and podssh prints it. A forward that the server \
     refuses is a warning; with -o ExitOnForwardFailure=yes it ends the run (exit 255). A socket path and \
     the server's SOCKS proxy (-R [BIND:]PORT) are refused by name (exit 64).",
    "--persist -N keeps the forwards: no tmux runs, and after a loss, the server's own close too, podssh \
     connects again and asks for each -R again; -L and -D keep their listeners. A forward refused after \
     a loss is asked again for 2 minutes, as the server may hold its port for the old connection, then \
     refused as on the first connection (see ExitOnForwardFailure); a port that the server chose may \
     change, and the new one is printed. The logins after the first ask nothing, unless \
     SSH_ASKPASS_REQUIRE is force and SSH_ASKPASS names a program to ask. With no forward, or \
     --persist-name, -N with --persist is refused (exit 64).",
    "-A forwards the agent, off by default as in OpenSSH; -a turns it off, and the last of the two wins, \
     over the keyword ForwardAgent. podssh asks for it on the session, never on a jump host, and joins each \
     agent channel that the server opens to the agent that podssh logs in with (IdentityAgent, else \
     SSH_AUTH_SOCK); ForwardAgent with a path or $NAME names another agent. While the session lasts, the \
     server, and root on it, can use each key of the agent, though it cannot read one. podssh does not bind \
     the agent to the server's host key, as OpenSSH does, so the hosts that an agent limits a key to do \
     not hold over it. An agent channel that a server opens with no -A is refused, with a warning.",
    "-X and -Y forward X11 to the display of DISPLAY; -x turns it off, and the last of the three wins. The \
     server is given a spoofed cookie, and podssh puts the real one in each X11 channel's first packet. -Y \
     uses the cookie of XAUTHORITY or ~/.Xauthority, and gives the server's X clients full access; -X an \
     untrusted cookie that xauth makes, for ForwardX11Timeout, and with no xauth it is refused. With no \
     DISPLAY, no X server that answers, or no cookie that it takes, the run ends with 255 before anything \
     connects.",
    "-M with -S PATH (or ControlMaster and ControlPath) makes this run the control master, on Unix: other \
     runs with -S PATH go through its one connection, as with OpenSSH, whose ssh -O check and clients \
     work with it; a second -M asks before each request. -O check, forward, cancel, exit and stop speak to the \
     master. With no master there, a run connects alone, and ControlMaster auto makes it the master. \
     The socket is made mode 0600 before anything connects, and goes with the master. ControlPersist keeps \
     a -N master with no client for that long; podssh does not go to the background. On Windows, -M, -S \
     and -O are refused (exit 64).",
    "-P on ssh is the Tag of OpenSSH, which Match tagged reads, not a port; a tag that is a number gets \
     a note on stderr. On scp and sftp, -P is the port. Use -p for the port of ssh.",
    "-G prints the settings in effect, as ssh -G does: a line of keyword and value for each keyword of \
     OpenSSH that podssh applies, defaults included, then exits 0 with nothing opened. The defaults \
     that differ from OpenSSH's do on purpose: ServerAliveInterval and ConnectTimeout are 60, and no \
     identity file of a security key is tried. podssh's own settings, such as the relay hosts, print no \
     line, as OpenSSH knows no keyword for them.",
    "Paths in -i and in the IdentityFile, UserKnownHostsFile, GlobalKnownHostsFile, IdentityAgent and \
     ForwardAgent keywords take the tokens of OpenSSH: %% %C %d %h %i %j %k %L %l %n %p %r %u, with \
     OpenSSH's values. %u is the local user and %r the remote one. An unknown token is refused (exit 64). \
     ${NAME} in them is the variable NAME, which must be set (exit 64); a whole $NAME as IdentityAgent or \
     ForwardAgent is the variable that holds the path, and no agent when it is not set. -E FILE is opened \
     as typed.",
    "A repeated value follows OpenSSH: the first -p and -l, the last -e, -E and -F, and the first value \
     of each -o keyword. A second -J or -W is refused, and so is a second --relay-host, --relay-addr or \
     --ca-file: give several hops, hosts or addresses as one comma list.",
    "podssh sends keepalives (ServerAliveInterval), so the relay does not close an idle session. To a \
     node, the resumable layer keeps the link busy and finds a dead one, and SSH sends none unless \
     ServerAliveInterval is set: a keepalive with no answer would end a session that the layer carries \
     onto a new link.",
    "podssh reads options before and after the host, as OpenSSH does, so a host that a script did not \
     write can be read as a flag. Put -- before it: podssh ssh -- \"$HOST\" uptime. A host, or a \
     -o HostName=VALUE, that starts with - is refused (exit 64), as OpenSSH refuses it.",
    "An IPv6 address needs brackets only before a port: user@2001:db8::1 is port 22, and \
     user@[2001:db8::1]:2222 or -p 2222 gives another port. -4 or -6 with an address of the other family \
     is refused. The relay takes an IPv6 address, but when this version was measured, its way out \
     reached no IPv6 host: such a session ends at once, and podssh says so. --direct needs no relay.",
    "--result-file FILE writes one JSON object to FILE at the end of each run, also of one that failed \
     before it connected: schema, exit (the code that podssh exits with), status (the remote exit status, \
     or null), signal (its name and core_dumped, or null), end (status, signal, no-status, lost, escaped, \
     terminated, failed, or shared through a control master, which tells the exit code alone; null with no \
     session, as with -W), failure (connect, host-key, auth, forward, relay, session, usage, config or \
     not-built, or null), bytes (stdin, stdout and stderr, as they passed; null through a control master, \
     which carries them), duration_ms, and relay (its host, close_code and reason, or null with no relay). \
     stdout and stderr stay as they are; the command's output never goes into the file. A new file is made \
     for its owner alone; - is refused (exit 64). No file is written after a flag that podssh does not know, \
     which ends it before it reads the others, nor when a signal kills podssh: only a session on a terminal \
     ends at SIGTERM or SIGHUP, as terminated.",
];
