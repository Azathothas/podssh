//! The last notes of `podssh ssh` (`notes_ssh`), apart for the length of
//! that file.

pub(super) const MORE: &[&str] = &[
    "-A forwards the agent, off by default as in OpenSSH; -a turns it off, and the last of the two wins, \
     over the keyword ForwardAgent. podssh asks for it on the session, never on a jump host, and joins each \
     agent channel that the server opens to the agent that podssh logs in with (IdentityAgent, else \
     SSH_AUTH_SOCK); ForwardAgent with a path or $NAME names another agent. While the session lasts, the \
     server, and root on it, can use each key of the agent, though it cannot read one. podssh binds the \
     agent to the server's host key first, as OpenSSH does (session-bind@openssh.com), so an OpenSSH agent \
     keeps from the server each key that ssh-add limits to other hosts; an agent that refuses the bind \
     serves unbound. An agent channel that a server opens with no -A is refused, with a warning.",
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
     identity file of a security key is tried; each list of algorithms is what podssh will offer, its own \
     unless a keyword gave one. podssh's own settings, such as the relay hosts, print no line, as OpenSSH \
     knows no keyword for them.",
    "Ciphers, MACs, KexAlgorithms, HostKeyAlgorithms, PubkeyAcceptedAlgorithms and CASignatureAlgorithms \
     filter what podssh offers, as OpenSSH reads them: a list replaces podssh's own, one that starts with + \
     adds to it, with - takes from it, and with ^ puts its names first. A name that podssh does not speak \
     is left out, and -v says so; a list that leaves nothing is refused before anything connects (exit 64, \
     or 78 for a line of a file). The host key algorithms that known_hosts records for the host go first \
     within the list. RequiredRSASize is the least RSA key: a smaller key of the user is not offered, and a \
     smaller host key, or key of the CA of a host certificate, ends the connection (exit 255). The other \
     keywords of a restriction, which podssh does not apply, such as VerifyHostKeyDNS and BindAddress, get \
     one note when you give them, none for the system's ssh_config and none with -q; the keywords that \
     change nothing get a note at -v that names their place.",
    "Paths in -i and in the IdentityFile, UserKnownHostsFile, GlobalKnownHostsFile, IdentityAgent and \
     ForwardAgent keywords take the tokens of OpenSSH: %% %C %d %h %i %j %k %L %l %n %p %r %u, with \
     OpenSSH's values. %u is the local user and %r the remote one. An unknown token is refused (exit 64). \
     ${NAME} in them is the variable NAME, which must be set (exit 64); a whole $NAME as IdentityAgent or \
     ForwardAgent is the variable that holds the path, and no agent when it is not set. -E FILE is opened \
     as typed.",
    "A repeated value follows OpenSSH: the first -p and -l, the last -e, -E and -F, and the first value \
     of each -o keyword. A second -J or -W is refused, and so is a second --relay-host, --relay-addr or \
     --ca-file: give several hops, hosts or addresses as one comma list.",
    "ConnectTimeout bounds the SSH handshake and each answer of the server while podssh logs in. The time \
     that a question waits for its answer does not count, the question of a new host key included, which \
     runs inside the handshake: it has its own bound, 60 s when stdin, stdout and stderr are all redirected, \
     on a console of Windows too. A handshake that does not finish names what came: no byte, a line of \
     another service, or the server's version line and the last message of the key exchange each way; \
     through a node, also the bytes that its resumable layer and its end-to-end channel carried each way. \
     10 s in (through a node, 10 s after its layer opened), a handshake that has not finished says where it \
     is, once, and waits on; a question that nobody can see says that it waits, and its remedy.",
    "The version line that podssh sends is SSH-2.0-podssh_VERSION, each dash of the version written as an \
     underscore, as RFC 4253 allows none there: podssh names its own software, as each client does. A \
     server or a filter that lets in only the version lines of OpenSSH refuses it. podssh does not send \
     OpenSSH's line: a server reads the line to choose the quirks that it expects of a client (OpenSSH's \
     own server so treats its older versions), and podssh is not OpenSSH.",
    "Each later hop of -J is reached on a direct-tcpip channel of the hop before it, whose open has that \
     hop's ConnectTimeout. A hop that never answers the open, and a channel on which no byte of an SSH \
     server came within it, or that closed with none, are named so: the hop, and the target of its \
     channel, never a handshake of the destination. With -v, podssh says the open, and each 10 s while \
     nothing came.",
    "podssh sends keepalives (ServerAliveInterval), so the relay does not close an idle session. To a \
     node, the resumable layer keeps the link busy and finds a dead one, and SSH sends none unless \
     ServerAliveInterval is set: a keepalive with no answer would end a session that the layer carries \
     onto a new link. Through the relay a session carries 64 MiB at most, both ways together: once it \
     has carried 60 MiB (less under a relay's smaller limits, or PODSSH_SESSION_BUDGET), podssh says so \
     once (with -q, nothing); podssh cp copies more on new sessions. With keepalives off, or slower than \
     the relay's idle cut (180 s with no payload), podssh warns once 30 s before the cut, in the window's \
     title where the notice of a silent far end shows, else as a line on stderr, and again only after a \
     payload crossed; --idle-warn SECONDS sets the lead, and 0, or -q, turns it off. The warning sends \
     nothing.",
    "podssh reads options before and after the host, as OpenSSH does, so a host that a script did not \
     write can be read as a flag. Put -- before it: podssh ssh -- \"$HOST\" uptime. A host, or a \
     -o HostName=VALUE, that starts with - is refused (exit 64), as OpenSSH refuses it.",
    "An IPv6 address needs brackets only before a port: user@2001:db8::1 is port 22, and \
     user@[2001:db8::1]:2222 or -p 2222 gives another port. -4 or -6 with an address of the other family \
     is refused. The default relay takes an IPv6 address, but when this version was measured, its way out \
     reached no IPv6 host: it opens the session, then closes it at once (1011 target closed before \
     sending anything). podssh then tries the direct road once, as after a relay that failed, also under \
     -6, whose dial takes the name's IPv6 addresses alone; with a relay named, or PODSSH_DIRECT=no, it \
     ends, and the note names the roads that carry IPv6: a relay of yours on a host with IPv6 (podssh \
     relay serve, then --relay-host), a node with IPv6 egress (-J node://NAME), or warp://[ADDR]. podssh \
     relay serve dials an IPv6 target where its host routes IPv6 out, and refuses it before the upgrade \
     where it does not (502, this relay's host has no IPv6 route out), so that the next relay host is \
     tried at once. --direct needs no relay.",
    "--result-file FILE writes one JSON object to FILE at the end of each run, also of one that failed \
     before it connected: schema, exit (the code that podssh exits with), status (the remote exit status, \
     or null), signal (its name and core_dumped, or null), end (status, signal, no-status, lost, escaped, \
     terminated, detached, interrupted (Ctrl-C with no pty, and no end of the command), failed, or shared \
     through a control master, which tells the exit code alone; null with no \
     session, as with -W), failure (connect, host-key, auth, forward, relay, session, usage, config or \
     not-built, or null), bytes (stdin, stdout and stderr, as they passed; null through a control master, \
     which carries them), duration_ms, and relay (its host, close_code and reason, or null with no relay). \
     A link lost after the remote exit status and before the end of the output ends lost, with exit 255 \
     and the status kept. stdout and stderr stay as they are; the command's output never goes into the \
     file. A new file is made \
     for its owner alone; - is refused (exit 64). No file is written after a flag that podssh does not know, \
     which ends it before it reads the others, nor when a signal kills podssh: only a session on a terminal \
     ends at SIGTERM or SIGHUP, as terminated, and one with no pty at Ctrl-C, by the command's end or as \
     interrupted.",
    "--install NAME, with -N, --persist and a forward, makes the tunnel a service of this user, which \
     starts it again whenever it ends, as podssh node --install makes a node's, by the same ways: a user \
     unit of systemd (podssh-ssh-NAME.service), a LaunchAgent (dev.podssh.ssh.NAME), two lines of the \
     crontab, or a task of Windows. A server that only the tunnel reaches is locked out while it is down. \
     The service runs this program with the words of this command line but --install NAME, in this \
     directory, so that each relative path means what it meant; after ssh come BatchMode=yes, \
     ForkAfterAuthentication=no, ControlPath=none and ExitOnForwardFailure=yes, each after -o, which win \
     over the rest and over ssh_config, as nobody answers a prompt there, a run in the background or \
     through a master would leave the service, and a refused forward serves nothing until a new start; \
     then --env-file with ssh-NAME.env, the private file of the variables that it reads, with no token, \
     and --persist-forever, so that an outage of the relay never ends the tunnel between two starts. \
     The login needs a key with no passphrase, and the host key in known_hosts: run the same command \
     once in the foreground first. The command line is resolved first: a shell, a command, -W, -f, -G, \
     -O, --attach, --upgrade or --snippet is refused (64). So is a tunnel without --persist, or with no \
     forward. --uninstall NAME removes what --install NAME wrote, and nothing else. --env-file FILE \
     sets the variables of FILE first and holds FILE.lock while the run lasts, as for podssh node: a \
     second start of the same service ends at once with 0.",
];
