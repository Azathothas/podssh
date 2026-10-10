//! The notes of each command: what its flag table cannot say. The tests check
//! each flag, `-o` keyword and variable that a note names, so a note cannot
//! keep a name that the code has dropped. Numbers are not repeated here; the
//! tables that hold them are in the manual already.

/// The notes of the verb `name`, one paragraph each.
pub fn for_verb(name: &str) -> &'static [&'static str] {
    match name {
        "ssh" => SSH,
        "cp" => CP,
        "mv" => MV,
        "scp" => SCP,
        "sftp" => SFTP,
        "proxy" => PROXY,
        "pipe" => PIPE,
        "node" => NODE,
        "operator" => OPERATOR,
        "relay" => RELAY,
        "doctor" => DOCTOR,
        "status" => STATUS,
        "keygen" => KEYGEN,
        "man" => MAN,
        "ts" => TS,
        _ => &[],
    }
}

const SSH: &[&str] = &[
    "podssh ssh reaches the host through the relay (see THE RELAY), or over TCP with --direct. It needs \
     no installed ssh, no pty and no user database entry.",
    "node://[user@]NAME reaches the node of the pair under the label NAME (see podssh node), through the \
     relay. Its host key is recorded and checked under the name node://NAME. --pair-file gives the pair, \
     or its operator's part, in a file. A node has no port, and -J, -W and --direct cannot go with it yet. \
     podssh sends nothing until the node's first bytes (30 s at most), to learn whether the node offers \
     the resumable layer; -v says whether it does. With the layer, a lost link to the relay is replaced \
     by a new one for 10 minutes, and the SSH session goes on where it was; one line on stderr tells of \
     each loss and each resume.",
    "iroh:TICKET, or user@iroh:TICKET, reaches a node of the iroh road (see podssh node), in a build with \
     the feature iroh. The ticket is the address that the node prints, not a credential: the node lets in \
     only the client keys of its allowlist. This client's key is made on first use, in the cache \
     (iroh-client.key) or in the file of --iroh-key; podssh prints it when it is new, and when a node \
     refuses it, as the line that the node's operator adds. The host key is recorded and checked under \
     the name iroh:KEY, the node's key, which stays when the ticket changes. A node has no port, and -J, \
     -W and --direct cannot go with it yet. The session runs the resumable layer: a lost link is \
     replaced by a new one, for 10 minutes. podssh asks the ticket's relay first, then those of \
     --iroh-relay (see THE RELAY).",
    "node://NAME with --iroh-ticket TICKET races the two roads to the node: the iroh road starts first, \
     the pair's road 250 ms later, or at once when the iroh road fails, and the first far end that \
     speaks carries the session; the other link ends before it sends anything, so it opens nothing at \
     the node's TARGET. Each resume races them again, and -v says which road answered first.",
    "Host keys are checked against the known_hosts files. On a terminal, podssh asks about an unknown \
     key. With no terminal and no SSH_ASKPASS, it refuses the key and names the remedy: \
     -o StrictHostKeyChecking=accept-new records a new key with no question. A changed key is always \
     refused, and podssh shows both fingerprints.",
    "Authentication tries the agent and the identity files, then keyboard-interactive and password. \
     Prompts go to the terminal or to SSH_ASKPASS. With -o BatchMode=yes, each prompt is an error.",
    "-t asks for a pty when there is a local terminal. -tt asks for one also when there is none, so \
     interactive programs work from a host with no pty. In a session with a pty, ~. at the start of a \
     line ends the session (see -e).",
    "--persist runs the shell in tmux on the server, as tmux new-session -A -s NAME with a pty (NAME is \
     podssh, or the one of --persist-name). podssh looks for tmux after the login and refuses without \
     it (exit 255): a new shell after a lost link would look like the old one. When the link is lost \
     (no exit status; through the relay, a broken link or a close for its limits or its link to the \
     server), podssh connects again, 10 times at most in 5 minutes, and attaches the same session; one \
     that is gone is not started again. An exit status, a detach, ~., a refused host key or login, and \
     Ctrl-C during the wait end the run. The logins after the first ask nothing (as BatchMode=yes); a \
     key that a passphrase opened and a password that the server took are kept for the run. Keys \
     typed meanwhile go to the session after the attach. With a command, -W, -N, -s, -T, node:// or \
     iroh:, --persist is refused (exit 64).",
    "-L and -D are refused by name: podssh ssh opens no local listener yet. Use -W HOST:PORT, which \
     carries one connection over the session, or podssh pipe with tcp-listen: and ssh:.",
    "-R [BIND:]PORT:HOST:HOSTPORT asks the server to listen; each connection that it takes reaches \
     HOST:HOSTPORT from this host, as one more outbound connection, through HTTPS_PROXY when it is set, \
     within 20 s. A port of 0 lets the server choose, and podssh prints it. A forward that the server \
     refuses is a warning; with -o ExitOnForwardFailure=yes it ends the run (exit 255). A socket path and \
     the server's SOCKS proxy (-R [BIND:]PORT) are refused by name (exit 64).",
    "-P is the tag of OpenSSH on ssh, not a port, and podssh ignores it. On scp and sftp, -P is the port. \
     Use -p for the port of ssh.",
    "-G prints the settings in effect, as ssh -G does: a line of keyword and value for each keyword of \
     OpenSSH that podssh applies, defaults included, then exits 0 with nothing opened. The defaults \
     that differ from OpenSSH's do on purpose: ServerAliveInterval and ConnectTimeout are 60, and no \
     identity file of a security key is tried. podssh's own settings, such as the relay hosts, print no \
     line, as OpenSSH knows no keyword for them.",
    "Paths in -i and in the IdentityFile, UserKnownHostsFile, GlobalKnownHostsFile and IdentityAgent \
     keywords take the tokens of OpenSSH: %% %C %d %h %i %j %k %L %l %n %p %r %u, with OpenSSH's values. \
     %u is the local user and %r the remote one. An unknown token is refused (exit 64). -E FILE is opened \
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
];

const CP: &[&str] = &[
    "podssh cp copies files between this host and a server over SFTP, or by exec when the server has \
     no SFTP, through the relay (see THE RELAY) or over TCP with --direct, with the connection flags of podssh ssh: -o, -J, -i, -v and -q, and -P \
     for the port, as scp has it. An operand names a server when a : comes before any /: \
     [user@]host:path or [user@][IPV6]:path. ./a:b is a local file, and on Windows so is C:\\x. An \
     empty path, host:, is the login directory.",
    "The destination's name never holds a file that was not verified. The bytes go to \
     .NAME.podssh-RANDOM.part beside the destination, a new file of mode 0600. The SHA-256 of what was \
     sent is compared with the far side's; then the file takes the source's permission bits and is \
     renamed onto the destination, at once where the server has posix-rename. A failure removes the \
     temporary file and leaves the destination as it was.",
    "The far side's digest comes from sha256sum, shasum or openssl dgst on the server, when one runs \
     there; else podssh reads the file again over SFTP, which counts again against the relay's limits. \
     With --jsonl each file gives one JSON object: done, with the bytes, the SHA-256 and how the far \
     side was checked, or error, with the exit code.",
    "Several sources go into a directory. A copy from server to server goes through a temporary file on \
     this host, one connection at a time. -r and -p are refused by name: copying a directory, and \
     keeping the mode and the times, are not implemented yet.",
    "A server with no SFTP subsystem gets a copy by exec, and podssh says so. Each step is one command \
     with no pty, sh -c 'SCRIPT' sh PATH..., so the login shell only starts sh, and each path is one \
     quoted word; a path with a newline or a NUL is refused. A probe finds the far tools: cat, wc, mv \
     and rm are needed. The bytes go raw through cat when the 256 byte values come back unchanged, \
     else through base64. Each answer comes after a random marker, so text that a login prints first \
     is never data. The temporary name, the digests and the rename are as above; a copy down keeps \
     mode 0600. With no POSIX sh, or a needed tool missing, the copy exits 69 and names it.",
    "Each SFTP reply that carries no file data is waited for 30 s at most, and each read or write 60 s. \
     --timeout bounds the whole copy, the login included. The exit codes are the sysexits of \
     EXIT STATUS, as for podssh proxy.",
    "A copy goes on after a broken connection: the temporary file stays, and a new connection writes on \
     at the offset below which each byte is in it, 5 times in a row at most with no new byte, with a \
     backoff between them. A refused login, or a host key other than the first connection's, ends it. \
     The same command run again goes on too while the source is as it was: a private side file in the \
     cache directories keeps the offset, never a byte of the file. The digest covers the whole file.",
];

const SCP: &[&str] = &[
    "podssh scp takes the command line of OpenSSH's scp, and copies as podssh cp does: over SFTP, or by \
     exec when the server has no SFTP; under a temporary name, verified by its digest, then renamed.",
    "Each letter of OpenSSH's usage parses: -B is BatchMode=yes, -3, -s and -T are accepted and change \
     nothing, and the others that podssh does not carry are refused by name. An operand can be a URI, \
     scp://[user@]host[:port][/path]: its path is under the login directory, and // makes it absolute. \
     podssh scp takes no flag for a time limit, as OpenSSH's takes none; each wait of a copy has its own.",
];

const SFTP: &[&str] = &[
    "podssh sftp takes the command line of OpenSSH's sftp. With -b FILE, or -b - for stdin, it runs the \
     commands of FILE in order and prints each line first; a line that starts with @ is not printed, and \
     one that starts with - does not end the batch when it fails. Else, on a terminal, it asks at a \
     prompt; with no terminal and no -b it refuses (exit 64). A destination with the path of a file \
     fetches that file and ends; one with a directory starts there.",
    "The commands: get and put (with reget and reput, which are the same), rename, rm (with * and ? in \
     the last name), mkdir [-p], rmdir, ls [-la], cd, lcd, pwd, lpwd, chmod, df [-hi], help, version, and \
     bye, exit or quit. get and put copy as podssh cp does. The exit code is that of the first command \
     that ends the batch, as for podssh cp; a usage error is 64 where OpenSSH gives 1.",
];

const MV: &[&str] = &[
    "podssh mv moves files, with the operands and the flags of podssh cp. Within one server the server \
     renames, with posix-rename or by exec with mv -f, and no byte moves; a rename that the server fails \
     for a reason of its own, such as two file systems, becomes a copy and a delete, said first.",
    "Between hosts a move is not atomic, and podssh says so on stderr before any byte moves: the copy of \
     podssh cp, its digest check, then a delete of the source; between two servers a third connection \
     removes it. The source goes last, and only while it is still the file that was copied: the same \
     size and time of change, the same file, and the same bytes where a digest command runs there.",
    "A source that changed stays (exit 66). A delete that fails exits 70 and says that the copy is \
     complete and verified: the data is then in two places, never in none. One file named twice is \
     refused (exit 64). With --jsonl each done object says whether the source is gone: source_removed.",
];

const PROXY: &[&str] = &[
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
];

const PIPE: &[&str] = &[
    "podssh pipe A B joins two byte streams, as socat does, with no listener unless one side asks for \
     one: what A gives goes to B, \
     and what B gives goes to A. Each address is KIND:REST: - or stdio (stdin and stdout), fd:N (a \
     descriptor that podssh inherited, 3 or more, on Unix), or exec:CMD (a program); relay:HOST:PORT \
     (TCP through the relay, as podssh proxy carries it), tcp:HOST:PORT (TCP from this host, through \
     HTTPS_PROXY when it is set), ssh:[USER@]HOP[,HOP...],HOST:PORT (TCP that the last SSH hop opens, \
     as -W asks), node:NAME (the TARGET of the node of a pair), iroh:TICKET (the TARGET of a node of \
     the iroh road), or unix-connect:PATH (a local socket; @NAME in Linux's abstract namespace; on \
     Windows a Unix socket or a named pipe, \\\\.\\pipe\\NAME). Both are checked before anything \
     starts, and stdio on both sides is refused.",
    "unix-listen:PATH (by the names of unix-connect:) and tcp-listen:[ADDR:]PORT (on 127.0.0.1, or on \
     ADDR, an address of this host; port 0 asks for a free one) listen, one side at most. The bind is \
     the probe: a host that refuses it gives 77, and the line names the error. A Unix socket is made \
     mode 0600 and takes only this user's programs: a client of another user is closed. A TCP port \
     takes each user of this host, and other hosts too when ADDR is not loopback; podssh says which. \
     The first client is joined to a new instance of the other side, then the listener closes and its \
     file goes; --keep-listening takes each client in turn, 8 at once, until SIGINT or SIGTERM, after \
     which the file goes too. A path that is a file and not a socket is kept (64), and a socket that \
     answers is another program's (69). PODSSH_LISTEN set to no turns listening off (78).",
    "The hops of ssh: log in as podssh ssh logs in: through the relay, or with --direct, with -i and \
     -o; an -o of a session (RequestTTY, RemoteCommand) is refused. node: takes the pair stored under \
     NAME, or the one of --pair-file. iroh: takes this client's key of --iroh-key, and the relays of \
     --iroh-relay after the ticket's.",
    "exec:CMD starts the program with no shell: its words split at blanks, with single and double \
     quotes, and no variables, globs or escapes; exec:sh -c 'CMD' names a shell. The program gets one \
     end of a socketpair as its stdin and stdout, or two pipes where a socketpair is refused and on \
     Windows. Its stderr is podssh's.",
    "When one side's input ends, the other side gets the end of its input, and the other direction goes \
     on, so that a reply still comes back: tcp:, ssh: and unix-connect: pass it on as a half-close. The \
     relay has no half-close, so relay: sends nothing at the end of input, and the target's bytes come \
     until it closes, as a named pipe's do, whose listening side closes it at its end of input; node: \
     and iroh: end their session. The pipe ends when both \
     have ended, when a side's reader is gone, when a program has exited and its output has ended, or \
     when a road has ended. podssh waits for each program, as a shell does.",
    "A road that failed gives the exit status, as podssh proxy gives it: 69 for a road out of reach, 77 \
     for a refusal (of the relay, a proxy, a host key or a login) and 78 for a setting that cannot be \
     used. Else the status is the program's (B's when both are programs), 128 + N for a signal, 127 for \
     a program that is not found and 126 for one that cannot run; with neither, 0. The address serial: \
     is not built yet, and exits 70.",
];

const NODE: &[&str] = &[
    "podssh node serves TARGET, a TCP service, to the operators of the pair stored under NAME (see \
     podssh relay). Each session that an operator opens is one connection to TARGET, from this host, \
     through HTTPS_PROXY unless TARGET is on the loopback. podssh dials TARGET once at the start, and \
     exits when it cannot. It says online once the relay has its socket, and online again after a \
     loss: an operator reaches it from that line on.",
    "Each session runs the resumable layer: an operator that loses its link to the relay resumes the \
     session on a new link, and the node keeps the session and its connection to TARGET for 10 minutes \
     after a loss. TARGET is dialled only once the operator's handshake is done. The node keeps at most \
     64 MiB of replay buffers (16 sessions with the default of PODSSH_REPLAY_BUFFER); a new session past \
     that ends at once with the reason. podssh ssh node:// and podssh operator speak the layer. For an \
     operator that does not, --plain carries each session's bytes as they are, TARGET dialled at the \
     start of the session: a lost link then ends the session. The node's first line names its mode.",
    "The node runs until Ctrl-C or SIGTERM (exit 0), or until the relay ends the pair: stopped, \
     expired, refused, or served by another node; each has its code in EXIT STATUS. A broken \
     connection to the relay is made again, after a growing wait. After a loss the relay can still \
     hold the old connection, and answer 409: the node then connects again for 10 minutes, the time \
     that it keeps a session, with a line for each 409. A 409 at the start means that another node \
     serves the pair. stdout stays empty; notes go to stderr.",
    "With --pair-file, the pair comes from FILE, in the form of the store, and the store is not used. \
     FILE must be a regular file of the user that nobody else can read.",
    "With --iroh, in a build with the feature iroh, the node serves TARGET over the iroh road, with no \
     pair: QUIC between keys, through an iroh relay and HTTPS_PROXY, and directly when UDP works. The \
     relays are n0's public ones, or those of --iroh-relay, and the first that answers is the node's \
     (see THE RELAY). NAME labels the node's key, a private file in the cache (iroh-node-NAME.key), or the \
     file of --iroh-key, made when it is missing; --iroh-ephemeral makes a key for this run only. When it \
     starts, the node prints its key and its ticket (iroh:...) on stderr, and a new ticket when its home \
     relay changes; a client dials the ticket with podssh ssh iroh:TICKET. When the pair NAME is stored \
     and good, or --pair-file gives one, the node serves the pair's road too, with one keeper of \
     sessions for both: a session resumes on either road, and podssh ssh node://NAME --iroh-ticket \
     TICKET races them. When the pair's road ends, the node says why, and the iroh road goes on.",
    "A client of the iroh road gets in only when its key is a line of the file of --iroh-allow, which \
     the node reads again for each connection, so a key added counts at once. With no such file, no \
     client gets in. Each refused key is said on stderr: it is the line to add. A session reaches TARGET \
     only after the layer's handshake, and resumes on a new link for 10 minutes, as on the relay.",
];

const OPERATOR: &[&str] = &[
    "podssh operator NAME carries stdin to the node of the pair under the label NAME, and the bytes of \
     the node's TARGET to stdout, as podssh proxy carries a forward session. It is the ProxyCommand of \
     OpenSSH for a node: ssh -o ProxyCommand='podssh operator NAME' user@NAME.",
    "Before the node takes the session, up to 1 MiB of stdin is kept, and sent then. The session ends \
     when stdin ends or the node's TARGET closes; it exits 0 only when the node took the session. An \
     error is one line on stderr; the codes are in EXIT STATUS.",
    "With a node that offers the resumable layer, a lost link to the relay is replaced by a new one, \
     for 10 minutes, and the session goes on where it was; one line on stderr tells of each loss and \
     each resume. A close that a new link would only get again (a stopped or expired pair) ends the \
     session.",
    "With --pair-file, the pair comes from FILE, or its operator's part alone, as podssh relay pair \
     writes it for the operator, and the store is not used.",
];

const RELAY: &[&str] = &[
    "podssh relay pair NAME makes a pair on the relay and keeps it under the label NAME, in a private \
     file of the cache (see FILES). It prints the label and when the pair expires, 72 hours later, and \
     never a token. With --operator-file, the operator's part of the pair, its connect token alone, \
     goes to FILE, a new file that only its owner can read: give it to the operator by a channel that \
     you trust.",
    "A pair under NAME that has not expired is not replaced: stop it first with podssh relay revoke \
     NAME. revoke stops the pair on the relay and deletes the stored copy; when the relay cannot be \
     reached, the copy is kept, because its stop token is the one way to stop the pair before it \
     expires.",
    "podssh relay status NAME says whether the pair's node is online, and its sessions.",
    "podssh relay spec reads the relay's /health and its published document, /llms-full.txt, and checks \
     the document against the facts that podssh was built with (see RELAY FACTS). It prints ok, with the \
     document's lines, its digest and the version that the relay serves, or a FAIL line for each fact \
     that disagrees, and exits 1: the relay changed something that podssh depends on. With --document \
     FILE, it checks FILE and reads nothing from the network.",
    "status with no NAME, info and trace are not implemented yet (exit 70).",
];

const DOCTOR: &[&str] = &[
    "Each line is ok, FAIL or ????, the check, and what podssh found. ok: podssh can work with it; a \
     missing pty, listener, DNS or user database entry is ok, because podssh is made for them. FAIL: \
     something that podssh needs is broken. ????: the check could not run, and it does not fail the run.",
    "The checks: this host (the user database entry, where host keys and tokens can be written, /proc, \
     a pty, a socket bind that is closed at once, the directories that can run programs, the terminal); \
     the egress (the proxy setting, TLS and the trust store, what the proxy allows, the system resolver, \
     DNS over HTTPS); and the relay (each relay host, a token, a session to github.com port 22 that must \
     show the published host key of GitHub, and the clock).",
    "podssh doctor connects to the relay hosts and, through the relay, to github.com. The report goes to \
     stdout; the exit codes are in EXIT STATUS.",
    "With --full, the relay section adds login: podssh logs in to github.com through the relay as git, \
     with an Ed25519 key made for the check and never written, and GitHub refuses it. That shows that the \
     handshake, the host key (the one that forward identified) and the authentication path work. No pty \
     is asked for: GitHub refuses the key before a channel opens.",
    "With --json, the report is one JSON object on stdout when every check has run: schema (1), podssh, \
     os, arch, checks (each with section, check, status and detail; status is ok, FAIL or unknown) and \
     counts (ok, fail, unknown). The details are the text's, the exit code is the same, and nothing is \
     printed before the object.",
];

const STATUS: &[&str] = &[
    "podssh status writes one line of JSON on stdout and exits 0: schema, podssh, relays (each host and \
     port) and relays_from (--relay-host, PODSSH_RELAY, or the default and its pool), pool (cached, when \
     it was fetched, how many hosts), token (source: PODSSH_RELAY_TOKEN, cache or none; the relay that it \
     is for; when it expires; whether it can be used), proxy (the variable and HOST:PORT), offline, \
     attachment, stdin_tty and stdout_tty, and host for a destination (its name in known_hosts, whether \
     a key is recorded, the key types).",
    "It shows no token and no proxy credentials, opens no connection, asks no DNS and writes nothing. A \
     bad --relay-host or destination is a usage error (64), a bad PODSSH_RELAY a configuration error \
     (78). podssh doctor is the report that measures.",
];

const KEYGEN: &[&str] = &[
    "The keys are in the formats of OpenSSH. The private key has mode 0600 and never replaces a file \
     that exists; the public key goes to FILE.pub. podssh prints the SHA-256 fingerprint.",
    "podssh asks for the passphrase two times, on the terminal or through SSH_ASKPASS. -N '' makes a key \
     with no passphrase. A passphrase given with -N is refused, because each process on the host can \
     read a command line. With no terminal and no SSH_ASKPASS, podssh stops at once and names -N ''.",
    "DSA keys are refused: OpenSSH 10 removed them. The default comment is USER@HOST from the \
     environment, never from the user database.",
];

const MAN: &[&str] = &[
    "On a terminal, podssh man shows the manual through the program in PAGER; else through less, when \
     PATH has it and TERM names a terminal (not on Windows); else through its own pager (Enter: the next \
     page, q: quit). With --no-pager or --roff, or when stdin or stdout is not a terminal, the manual \
     goes to stdout with no pager.",
    "podssh man --roff > podssh.1 makes a man page; man -l podssh.1 shows it.",
    "podssh man --json writes the tables as one JSON object, for a program: the options, each command \
     (its availability, arguments and flags, each flag with its kind: supported, accepted, refused, and \
     what to type instead), the -o keywords, the variables, the files and the exit codes. --json SECTION \
     gives one command, or the table of environment, files or exit-status. It is never paged.",
    "The manual is the same in each environment: it shows no setting of this host.",
];

const TS: &[&str] = &[
    "Experimental. podssh ts joins a tailnet, with DERP over a WebSocket relay. The live test with two \
     nodes has not passed yet.",
    "With --jsonl, the status is one JSON object on one line: the event, the node-key prefix, the \
     tailnet IP and the home region, never a key. --jsonl is refused with -W, whose stdout is the \
     stream to the peer.",
    "Before the node starts, each mode is checked through the proxy (--ts-proxy, else the environment's), \
     each step in 8 s: tcp by a TLS handshake with a stock DERP server of Tailscale's default map, read \
     from login.tailscale.com, and relay by one with the relay host. --ts-mode auto takes the first of \
     tcp and relay whose check passed, and says which it passed over; a forced mode is checked alone. \
     With none ready, each check's reason is printed and the exit is 78.",
    "Each connection of the node, to the control server and to DERP, goes through the proxy of the checks, \
     with the no_proxy list of the environment; a URL with no port means port 80, as for each podssh \
     command. Credentials in --ts-proxy can be read in the list of processes, and podssh ts says so; \
     HTTPS_PROXY names the proxy as well.",
    "An ephemeral node (--ts-ephemeral) logs out at the end of the run, after an error too, in 5 s at \
     most and after the bound of --timeout: the tailnet then keeps no offline device. A node that is \
     not ephemeral never logs out, so its key, and the relay's allowlist entry for it, stay.",
    "A link that drops, to the control server or to DERP, is dialled again: after 1 s, 2 s, 4 s and so \
     on up to 30 s, each by a random factor, and from 1 s again after a link of 60 s; a DERP link that \
     answered a ping and then says nothing for 30 s is dead. A line on stderr says each drop and each \
     return. The relay's close 1008 \"not authorized\" ends the link, unless --ts-wait-allowlist is given.",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{verb_for, VERBS};
    use crate::ssh::keywords;

    /// The words of a note, split at spaces and at the punctuation around
    /// names (but not at `-`, `_` or `=`).
    fn words(note: &str) -> Vec<&str> {
        note.split(|c: char| c.is_whitespace() || "(),;:.'".contains(c)).filter(|w| !w.is_empty()).collect()
    }

    fn flag_exists(verb: &str, flag: &str) -> bool {
        let rows = |v: &str| verb_for(v).map(|v| v.flags).unwrap_or(&[]);
        let names = |r: &crate::flags::FlagRow| {
            let mut n = vec![format!("--{}", r.long)];
            if let Some(c) = r.short {
                n.push(format!("-{c}"));
            }
            n
        };
        // A note may also name a flag of ssh (OpenSSH's), and -tt is -t twice.
        flag == "-tt"
            || flag == "--help"
            || flag == "--"
            || rows(verb).iter().chain(rows("ssh")).any(|r| names(r).iter().any(|n| n == flag))
    }

    fn keyword_exists(name: &str) -> bool {
        keywords::known_names().chain(keywords::IGNORED.iter().copied()).any(|k| k.eq_ignore_ascii_case(name))
    }

    fn problems() -> Vec<String> {
        let variables: Vec<&str> = super::super::facts::variables().flat_map(|(n, _)| n.iter().copied()).collect();
        let mut out = Vec::new();
        for verb in VERBS {
            for note in for_verb(verb.name) {
                out.extend(problems_in(verb.name, note, &variables));
            }
        }
        out
    }

    fn problems_in(verb: &str, note: &str, variables: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        for w in words(note) {
            let flag_shaped = w.starts_with('-')
                && w.len() > 1
                && w.chars().nth(1).is_some_and(|c| c.is_ascii_alphanumeric() || c == '-');
            if flag_shaped && !w.contains('=') && !flag_exists(verb, w) {
                out.push(format!("{verb}: the flag {w} does not exist"));
            }
            if let Some((name, _)) = w.split_once('=') {
                if name.starts_with(|c: char| c.is_ascii_uppercase()) && !keyword_exists(name) {
                    out.push(format!("{verb}: the keyword {name} does not exist"));
                }
            }
            let variable_shaped = w.contains('_') && w.chars().all(|c| c.is_ascii_uppercase() || c == '_');
            if variable_shaped && !variables.contains(&w) {
                out.push(format!("{verb}: the variable {w} is not in ENVIRONMENT"));
            }
        }
        out
    }

    /// The note about -R says that the server listens (T-035), and neither
    /// borrows the cause of -L and -D nor offers -W.
    #[test]
    fn the_note_about_r_says_that_the_server_listens() {
        let sentences: Vec<&str> =
            for_verb("ssh").iter().flat_map(|n| n.split(". ")).filter(|s| s.contains("-R")).collect();
        assert!(!sentences.is_empty(), "{sentences:#?}");
        assert!(sentences[0].contains("asks the server to listen"), "{}", sentences[0]);
        for sentence in sentences {
            for word in ["never", "local listener", "-W", "not implemented"] {
                assert!(!sentence.contains(word), "{word}: {sentence}");
            }
        }
    }

    #[test]
    fn each_name_in_a_note_exists() {
        let p = problems();
        assert!(p.is_empty(), "{p:#?}");
    }

    /// The control: a note with a dropped flag, keyword or variable fails.
    #[test]
    fn a_planted_name_is_found() {
        let variables = ["SSH_ASKPASS"];
        let p = problems_in("ssh", "use --no-such-flag, -o NoSuchKeyword=yes and NO_SUCH_VAR", &variables);
        assert_eq!(p.len(), 3, "{p:#?}");
        assert!(problems_in("ssh", "use -W HOST:PORT, BatchMode=yes and SSH_ASKPASS", &variables).is_empty());
    }
}
