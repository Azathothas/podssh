//! The notes of each command: what its flag table cannot say. The tests check
//! each flag, `-o` keyword and variable that a note names, so a note cannot
//! keep a name that the code has dropped. Numbers are not repeated here; the
//! tables that hold them are in the manual already.

use super::notes_chat::CHAT;
use super::notes_config::CONFIG;
use super::notes_containers::CONTAINERS;
use super::notes_each::EACH;
use super::notes_edit::EDIT;
use super::notes_health::HEALTH;
use super::notes_job::JOB;
use super::notes_keygen::KEYGEN;
use super::notes_mcp::MCP;
use super::notes_pair::{NODE, OPERATOR};
use super::notes_ping::PING;
use super::notes_play::PLAY;
use super::notes_relay::RELAY;
use super::notes_run::RUN;
use super::notes_session::SESSION;
use super::notes_ssh::SSH;
use super::notes_update::UPDATE;

/// The notes of the verb `name`, one paragraph each.
pub fn for_verb(name: &str) -> &'static [&'static str] {
    match name {
        "ssh" => SSH,
        "each" => EACH,
        "containers" => CONTAINERS,
        "job" => JOB,
        "run" => RUN,
        "cp" => CP,
        "mv" => MV,
        "scp" => SCP,
        "sftp" => SFTP,
        "edit" => EDIT,
        "proxy" => PROXY,
        "pipe" => PIPE,
        "node" => NODE,
        "operator" => OPERATOR,
        "chat" => CHAT,
        "relay" => RELAY,
        "doctor" => DOCTOR,
        "status" => STATUS,
        "ping" => PING,
        "health" => HEALTH,
        "play" => PLAY,
        "update" => UPDATE,
        "config" => CONFIG,
        "mcp" => MCP,
        "session" => SESSION,
        "keygen" => KEYGEN,
        "man" => MAN,
        "ts" => TS,
        "agent" => AGENT,
        _ => &[],
    }
}

const CP: &[&str] = &[
    "podssh cp copies files between this host and a server over SFTP, or by exec when the server has \
     no SFTP, through the relay (see THE RELAY) or over TCP with --direct, with the connection flags of podssh ssh: -o, -J, -i, -v and -q, and -P \
     for the port, as scp has it. An operand names a server when a : comes before any /: \
     [user@]host:path or [user@][IPV6]:path. ./a:b is a local file, and on Windows so is C:\\x. An \
     empty path, host:, is the login directory.",
    "node://[user@]NAME[/ROUTE]:path is the node of the pair under the label NAME (see podssh node), \
     reached through its pair as podssh ssh node://NAME reaches it, and its route ROUTE; the path comes \
     after the first : after the name, and with none it is the login directory. --pair-file, \
     --client-key, --node-key and --no-e2e are those of podssh ssh. A port, -J or --direct cannot reach \
     a node (exit 64).",
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
     this host, one connection at a time. -r copies a directory and what it holds, each link as a link \
     (scp -r follows links).",
    "With --parallel K several files go K at once, each over an SFTP session of its own in the one \
     connection, and so do the files of a tree with -r; a file of more than 8 MiB goes after them, alone, \
     as chunks, K at once. Each file keeps its own side file, so after a broken connection each goes on \
     where it was. The report keeps the order of the sources, and the exit code is that of the first \
     failure in that order. The copy by exec goes one file at a time.",
    "A copy keeps the source's permission bits. -p keeps the access and the modification times too, \
     and with -r each directory's, set after its files; --owner keeps the owner and the group by number \
     where the side that writes may give a file away (root), and says where it could not. A block of 64 \
     KiB of zeros is a hole, never sent: up when the source has holes, both ways with --sparse. Within \
     one -r upload, two names of one file arrive as one file with two names (hardlink@openssh.com). \
     SFTP version 3 carries the times in whole seconds from 1970 to 2106, and no inode, extended \
     attribute or ACL: those, and a far source's hard links, are not kept.",
    "--inplace writes into the destination itself, with no temporary name and no rename: it keeps its \
     inode and hard links, and needs no room for a second copy. podssh says first that a copy that \
     fails leaves its destination damaged, and a failure says so. A destination that is a link or a \
     directory is refused (exit 64).",
    "A server with no SFTP subsystem gets a copy by exec, and podssh says so. Each step is one command \
     with no pty, sh -c 'SCRIPT' sh PATH..., so the login shell only starts sh, and each path is one \
     quoted word; a path with a newline or a NUL is refused. A probe finds the far tools: cat, wc, mv \
     and rm are needed. The bytes go raw through cat when the 256 byte values come back unchanged, \
     else through base64. Each answer comes after a random marker, so text that a login prints first \
     is never data. The temporary name, the digests and the rename are as above; a copy down keeps \
     mode 0600, or with -p or --owner what stat says of the far file; up, chmod, touch -t and chown set \
     what a copy keeps, where the server has them. With no POSIX sh, or a needed tool missing, the copy \
     exits 69 and names it.",
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
     exec when the server has no SFTP; under a temporary name, verified by its digest, then renamed. -p \
     keeps the times, as podssh cp -p does.",
    "Each letter of OpenSSH's usage parses: -B is BatchMode=yes, -3, -s and -T are accepted and change \
     nothing, and the others that podssh does not carry are refused by name. An operand can be a URI, \
     scp://[user@]host[:port][/path]: its path is under the login directory, and // makes it absolute. \
     An operand can name the node of a pair, node://[user@]NAME[/ROUTE]:path, as for podssh cp. \
     podssh scp takes no flag for a time limit, as OpenSSH's takes none; each wait of a copy has its own.",
];

const SFTP: &[&str] = &[
    "podssh sftp takes the command line of OpenSSH's sftp. With -b FILE, or -b - for stdin, it runs the \
     commands of FILE in order and prints each line first; a line that starts with @ is not printed, and \
     one that starts with - does not end the batch when it fails. Else, on a terminal, it asks at a \
     prompt; with no terminal and no -b it refuses (exit 64). A destination with the path of a file \
     fetches that file and ends; one with a directory starts there. The destination can be the node of a \
     pair, node://[user@]NAME[/ROUTE][:path], as for podssh cp.",
    "The commands: get and put (with reget and reput, which are the same), rename, rm (with * and ? in \
     the last name), mkdir [-p], rmdir, ls [-la], cd, lcd, pwd, lpwd, chmod, df [-hi], help, version, and \
     bye, exit or quit. get and put copy as podssh cp does; get -p and put -p, or each of them after \
     sftp -p, keep the times. get -r and put -r (or -R), or each of them after sftp -r, copy a directory \
     and what it holds as podssh cp -r does, each link as a link; an item that fails is said, the rest \
     goes on, and the command fails at its end. The exit code is that of the first command \
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
    "podssh proxy iap://PROJECT/ZONE/INSTANCE:PORT and podssh proxy eice://ENDPOINT/ADDRESS:PORT carry the \
     pipe through a cloud's own tunnel to a VM, as podssh ssh does (see its notes), with no relay and no \
     relay flag; the port goes in the destination, 22 when none is given, and the destination takes no \
     user. As the ProxyCommand of OpenSSH: ssh -o \
     ProxyCommand='podssh proxy iap://my-project/us-central1-a/%h:%p' user@my-vm. On IAP the end of stdin \
     ends the session once its bytes went, as IAP has no half-close.",
];

const PIPE: &[&str] = &[
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
    "The hops of ssh: log in as podssh ssh logs in: through the relay, or with --direct, with -i and \
     -o; an -o of a session (RequestTTY, RemoteCommand) is refused. node: takes the pair stored under \
     NAME, or the one of --pair-file. iroh: takes this client's key of --iroh-key, and the relays of \
     --iroh-relay after the ticket's.",
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
     and iroh: end their session. The pipe ends when both \
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
];

const DOCTOR: &[&str] = &[
    "Each line is ok, FAIL or ????, the check, and what podssh found. ok: podssh can work with it; a \
     missing pty, listener, DNS or user database entry is ok, because podssh is made for them. FAIL: \
     something that podssh needs is broken. ????: the check could not run, and it does not fail the run.",
    "The checks: this host (the user database entry, where host keys and tokens can be written, and \
     whether PODSSH_CACHE_DIR chose the place or is none, /proc, \
     a pty, a socket bind that is closed at once, the directories that can run programs, the terminal); \
     the egress (the proxy setting, TLS and the trust store, what the proxy allows, the system resolver, \
     the addresses of the cache, and DNS over HTTPS with the form that answered; on github.com port 22 only \
     the server's banner shows that plain ssh can leave, as a proxy can take the CONNECT and carry nothing); \
     and the relay (each relay host, with where its address came from: a pin, the system resolver, the \
     cache or DNS over HTTPS; a token, a session to github.com port 22 that must show the published host key \
     of GitHub, and the clock).",
    "Each CONNECT, and the direct TCP check, is tried nine times over a second or more: its line gives \
     the best time (the path's floor), the median, the 95th percentile and the jitter (the median change \
     from one try to the next), and the loss, the tries that timed out and those that broke counted \
     apart. A refusal is an answer, not a loss. A first try that timed out is not repeated, and no try \
     starts that could end more than 10 s after the first began.",
    "Through a proxy, the line IP CONNECT asks for an address, the first resolver of DNS over HTTPS, and \
     then its TLS for that address, as each other road asks for a name; the line egress takes names the \
     case: names and addresses, names only (a road to an address, as --direct to one, cannot leave), \
     addresses only, or neither. With no proxy, the same line comes of the direct TCP check and of DNS over \
     HTTPS, which reaches its resolvers by their addresses.",
    "A forward session whose upgrade fails says which of three ways: an answer other than 101 (its status \
     and its text: the relay or a hop refused), a 101 whose Sec-WebSocket-Accept is not the one of the \
     request's key (something between answered in the relay's place), or a valid 101 after which the \
     connection ends with no Close (something between drops the stream after the upgrade).",
    "podssh doctor connects to the relay hosts and, through the relay, to github.com. The report goes to \
     stdout; the exit codes are in EXIT STATUS. Its line UDP out says whether a node's quick tunnel takes \
     QUIC: with a proxy set it takes HTTP/2, as no proxy carries UDP, and nothing is sent.",
    "With --full, the relay section adds login: podssh logs in to github.com through the relay as git, \
     with an Ed25519 key made for the check and never written, and GitHub refuses it. That shows that the \
     handshake, the host key (the one that forward identified) and the authentication path work. No pty \
     is asked for: GitHub refuses the key before a channel opens. With no proxy set, --full also makes a \
     QUIC handshake with the quick tunnel's edge, Cloudflare's, as the node's first try makes one, and \
     closes it at once with nothing registered: UDP out then says whether it answered, and in what time.",
    "With --json, the report is one JSON object on stdout when every check has run: schema (1), podssh, \
     os, arch, checks (each with section, check, status and detail; status is ok, FAIL or unknown) and \
     counts (ok, fail, unknown). A check tried several times adds samples: tries, connected, best_ms, \
     median_ms, p95_ms and jitter_ms (null when no try connected), timed_out, broke, refused, and ms, the \
     time of each try that connected. The details are the text's, the exit code is the same, and nothing \
     is printed before the object.",
];

const STATUS: &[&str] = &[
    "podssh status writes one line of JSON on stdout and exits 0: schema, podssh, relays (each host and \
     port) and relays_from (--relay-host, PODSSH_RELAY, or the default and its pool), pool (cached, when \
     it was fetched, how many hosts), token (source: PODSSH_RELAY_TOKEN, cache or none; the relay that it \
     is for; when it expires; whether it can be used), cache (from: PODSSH_CACHE_DIR, none or default; \
     dirs: the directories in the order podssh tries them), proxy (the variable, HOST:PORT and the kind, \
     http or socks5), offline, \
     attachment, stdin_tty and stdout_tty, and host for a destination (its name in known_hosts, whether \
     a key is recorded, the key types).",
    "It shows no token and no proxy credentials, opens no connection, asks no DNS and writes nothing. A \
     bad --relay-host or destination is a usage error (64), a bad PODSSH_RELAY a configuration error \
     (78). podssh doctor is the report that measures.",
];

const AGENT: &[&str] = &[
    "podssh agent serves the agent protocol on a socket of mode 0600, in a new directory of mode 0700 of \
     XDG_RUNTIME_DIR or the temporary directory (on Windows a named pipe of this user), until SIGINT, SIGTERM or \
     SIGHUP, which remove both. It stays in the foreground: start it with &. It prints \
     the lines of SSH_AUTH_SOCK and of its pid, as ssh-agent -s does. A client of another user is closed. \
     PODSSH_LISTEN set to no refuses it (exit 78).",
    "add FILE (with -t SECONDS for a lifetime), list, remove FILE or --all, lock and unlock talk to the agent of \
     SSH_AUTH_SOCK, podssh's or OpenSSH's, as ssh-add does; a passphrase or a password is asked on the terminal or \
     through SSH_ASKPASS. Keys live in the agent's memory only. A key that asks for a confirmation of each use is \
     never used. list writes the size, the fingerprint and the type of each key, and exits 1 when there is none.",
    "The agent holds a key of a security key (ED25519-SK, ECDSA-SK) that add gives it, as ssh-add gives \
     one, and signs with it in the device: it asks for the touch on its own stderr, and asks a PIN only \
     through SSH_ASKPASS with SSH_ASKPASS_REQUIRE set to force, as it runs in the background. With no device, \
     it refuses the signature and says why.",
    "add-password [USER@]HOST[:PORT] and add-passphrase FILE (with -t SECONDS for a lifetime) give podssh's agent a \
     server's password or a key file's passphrase, from stdin when stdin is no terminal, else from the terminal or \
     SSH_ASKPASS, never from the command line; a passphrase must open its file. The agent keeps each in its memory \
     only, and tells it only to its own user. podssh ssh asks the agent of SSH_AUTH_SOCK before each prompt for a \
     password, a passphrase or a password of keyboard-interactive, also with BatchMode, and the agent forgets one \
     that a server refuses; -v names where a secret came from, never its value. podssh doctor says how many the \
     agent keeps, never which. A locked agent tells none.",
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
     command. The proxy is an HTTP CONNECT one, or a SOCKS5 one (socks5:// or socks5h://, port 1080), \
     which gets each host's name too. Credentials in --ts-proxy can be read in the list of processes, \
     and podssh ts says so; HTTPS_PROXY names the proxy as well.",
    "An ephemeral node (--ts-ephemeral) logs out at the end of the run, after an error too, in 5 s at \
     most and after the bound of --timeout: the tailnet then keeps no offline device. A node that is \
     not ephemeral never logs out, so its key, and the relay's allowlist entry for it, stay.",
    "A link that drops, to the control server or to DERP, is dialled again: after 1 s, 2 s, 4 s and so \
     on up to 30 s, each by a random factor, and from 1 s again after a link of 60 s; a DERP link that \
     answered a ping and then says nothing for 30 s is dead. A line on stderr says each drop and each \
     return. The relay's close 1008 \"not authorized\" ends the link, unless --ts-wait-allowlist is given.",
    "A node key that the relay refuses ends the run with exit 77, and the line says what the key \
     needs: at once, or at the end of --ts-wait-allowlist. In relay mode, the status line and -W wait, \
     within the same limit, for the relay's DERP link to come up.",
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
        // A note may also name a flag of ssh (OpenSSH's), and -tt is -t twice;
        // -KL, -KR and -KD are commands of the escape ~C (T-291), no flags.
        flag == "-tt"
            || flag == "--help"
            || flag == "--"
            || ["-KL", "-KR", "-KD"].contains(&flag)
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

    /// The note of what podssh reads from the terminal names each escape of
    /// the code, and no other (T-130): `~` and a key, with `~~`.
    #[test]
    fn the_terminal_note_names_each_escape() {
        let note = for_verb("ssh").iter().find(|n| n.contains("passes unchanged")).expect("the terminal's note");
        let named: std::collections::BTreeSet<char> = note
            .as_bytes()
            .windows(2)
            .filter(|w| w[0] == b'~' && w[1].is_ascii_graphic() && !b",;)".contains(&w[1]))
            .map(|w| w[1] as char)
            .collect();
        let mut escapes: std::collections::BTreeSet<char> =
            podssh_ssh::escape::ESCAPES.iter().map(|(key, ..)| *key as char).collect();
        escapes.insert('~');
        assert_eq!(named, escapes, "the note: {note}");
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
