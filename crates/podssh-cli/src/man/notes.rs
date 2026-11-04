//! The notes of each command: what its flag table cannot say. The tests check
//! each flag, `-o` keyword and variable that a note names, so a note cannot
//! keep a name that the code has dropped. Numbers are not repeated here; the
//! tables that hold them are in the manual already.

use super::notes_chat::CHAT;
use super::notes_config::CONFIG;
use super::notes_containers::CONTAINERS;
use super::notes_detached::DETACHED;
use super::notes_each::EACH;
use super::notes_edit::EDIT;
use super::notes_health::HEALTH;
use super::notes_job::JOB;
use super::notes_keygen::KEYGEN;
use super::notes_mcp::MCP;
use super::notes_net::{EXIT, NET};
use super::notes_pair::{NODE, OPERATOR};
use super::notes_ping::PING;
use super::notes_pipe::PIPE;
use super::notes_play::PLAY;
// proxy's own, apart for the length of this file (T-431).
use super::notes_proxy::PROXY;
use super::notes_relay::RELAY;
use super::notes_run::RUN;
use super::notes_session::SESSION;
// ssh's own notes, then those of its roads to a server of the user's (T-441).
use super::notes_roads::SSH;
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
        "net" => NET,
        "exit" => EXIT,
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
        "detached" => DETACHED,
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
     after the first : after the name, and with none it is the login directory. A member of the net (see \
     podssh net) is [user@]NAME:path by its name alone, read as podssh ssh NAME reads it, the net first. \
     --pair-file, --client-key, --node-key and --no-e2e are those of podssh ssh. A port, -J or --direct \
     cannot reach a node (exit 64). With --carrier ADDR, as for podssh ssh, the node is at the other end of \
     a stream that exists already, with no relay and no pair: each connection of the copy is a session of \
     its own on that one stream, which ends with the copy; each operand that is remote is then a node, or, \
     with --exit NAME, a host that the exit at the other end of the stream dials. \
     --no-resume, as for podssh ssh, ends each session with its link, and the node keeps nothing of it: a \
     copy cut so goes on over a new connection, at the offset of the copy, as after any broken connection.",
    "The destination's name never holds a file that was not verified. The bytes go to \
     .NAME.podssh-RANDOM.part beside the destination, a new file of mode 0600. The SHA-256 of what was \
     sent is compared with the far side's; then the file takes the source's permission bits and is \
     renamed onto the destination, at once where the server has posix-rename. A failure removes the \
     temporary file and leaves the destination as it was.",
    "The far side's digest comes from sha256sum, shasum or openssl dgst on the server, when one runs \
     there; else podssh reads the file again over SFTP, which counts again against the relay's limits. \
     With --jsonl each file gives one JSON object: done, with the bytes, the SHA-256 and how the far \
     side was checked, or error, with the exit code.",
    "At its end a run of podssh cp or mv says on one line what it did: the files copied and their bytes, \
     those that podssh run left as they were, those skipped, the paths that an exclude left out (each \
     named at -v with its pattern) and those that failed, how long it took and \
     its rate; also after a failure, before its error. -q silences it, and --jsonl gives a summary object \
     in its place. On a terminal one line shows the progress of the run: the file in flight, and with \
     several files their count. Where stderr is no terminal, a plain line comes each 10 s once the run \
     has passed 10 s, with no carriage return; PODSSH_PROGRESS=off and -q silence it.",
    "Several sources go into a directory. A copy from server to server goes through a temporary file on \
     this host, one connection at a time. -r copies a directory and what it holds, each link as a link \
     (scp -r follows links); it has no default excludes and reads no .podsshignore, where podssh run \
     leaves out target/, node_modules/, .git/ and what the project's .podsshignore names. A device, a \
     FIFO or a socket is not copied: one line says so, with --jsonl \
     a skipped object, and it is no failure, as OpenSSH's scp and sftp skip one. Each failure is said \
     once, when it comes; the rest goes on, and the exit code is the first failure's.",
    "Several files go at once, each over an SFTP session of its own in the one connection, and so do \
     the files of a tree with -r: as many as the row of --parallel says, or K with --parallel K, and one \
     at a time with --parallel 1. Through the relay each small file waits for its own round trips, so one \
     at a time takes their sum. A file of more than 8 MiB goes after them, alone: in one stream, or as \
     chunks, K at once, with --parallel K. Each file keeps its own side file, so after a broken \
     connection each goes on where it was. The report keeps the order of the sources, and the exit code \
     is that of the first failure in that order. The copy by exec goes one file at a time.",
    "--delta sends only the blocks of 1 MiB that changed, over an older version of the file on the other \
     side: one command on the server gives the digest of each of its blocks (dd and a digest tool), and \
     the temporary file is made from the old one there (copy-data, else cat). Where that cannot be, the \
     copy goes in full, and a line says why once for each file, without -v (-q silences it); a first \
     copy, with no older version, says it at -v. The copy by exec sends no delta, and says so. With \
     --jsonl the done object holds delta: the blocks, those sent and their bytes, or full and the reason.",
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
    "-n (--no-clobber) leaves a destination that is there as it is: the copy looks before any byte \
     goes, says DST: there, so not replaced, and counts a skip, with exit 0. A name that comes during \
     the copy stays too: the verified file takes its name by a hard link (hardlink@openssh.com, or ln \
     by exec), which never takes a name that is there; with no hard link the look is the guard, and -v \
     says so. -u (--update) copies a file only when its destination is missing, older, or of the same \
     second and another size, as rsync's -u does; a file that stays is said at -v. -b (--backup) keeps \
     the old destination at its name with the suffix ~, or that of --suffix, by a hard link before the \
     rename, so that the name is never missing, else by a rename first, which -v says; an older backup \
     there is replaced, and --delete never deletes a name with the suffix. -n with -b, and -b with \
     --inplace, are refused (exit 64). With --jsonl a file left out is a skipped object, its why exists \
     or not newer, and a done object holds backup; --dry-run says skip and backup.",
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
     --timeout bounds the whole copy, the login included (exit 75). With no terminal it is required, or \
     PODSSH_TIMEOUT in its place (exit 64 with neither): nobody may be there to stop a run that waits. \
     podssh scp and podssh sftp take it as a bound and need none, as OpenSSH's run in pipes with no \
     such flag, and ConnectTimeout bounds their login. The exit codes are the sysexits of EXIT STATUS, \
     as for podssh proxy.",
    "A copy goes on after a broken connection: the temporary file stays, and a new connection writes on \
     at the offset below which each byte is in it, 5 times in a row at most with no new byte, with a \
     backoff between them. A refused login, or a host key other than the first connection's, ends it. \
     The same command run again goes on too while the source is as it was: a private side file in the \
     cache directories, podssh-cp-*.resume (see FILES), keeps the offset, never a byte of the file. The \
     digest covers the whole file.",
    "--result-file FILE writes one JSON object to FILE at the end of each run, also of one refused before \
     it connected, a new file for its owner alone; - is refused (exit 64). Its keys are those of podssh \
     ssh --result-file in their meaning, with verb and error: schema, verb, exit, failure (connect, \
     relay, host-key or auth where the connection failed; copy for a source, a destination or a step \
     that the server refused; verify for digests that differ; session, timeout, interrupted, usage or \
     config; or null), error (its words), duration_ms, relay (host, close_code, reason, and sessions, the \
     relay sessions that the run opened), files (sent, unchanged, skipped, deleted and failed) and \
     transferred (up and down: the bytes of the files through this host, with --delta the blocks that \
     went, none for a rename or a hard link). bytes is null, as in podssh ssh it counts a command's \
     streams. After the --timeout, files and transferred are null. --jsonl keeps its events on stdout.",
];

const SCP: &[&str] = &[
    "podssh scp takes the command line of OpenSSH's scp, and copies as podssh cp does: over SFTP, or by \
     exec when the server has no SFTP; under a temporary name, verified by its digest, then renamed. -p \
     keeps the times, as podssh cp -p does. As OpenSSH's scp, it gives no summary at its end, and no \
     progress where stderr is no terminal.",
    "Each letter of OpenSSH's usage parses: -B is BatchMode=yes, -3, -s and -T are accepted and change \
     nothing, and the others that podssh does not carry are refused by name. An operand can be a URI, \
     scp://[user@]host[:port][/path]: its path is under the login directory, and // makes it absolute. \
     An operand can name a node as podssh cp does: node://[user@]NAME[/ROUTE]:path, or a member's NAME:path, \
     and with --carrier ADDR a node at the other end of a stream that exists already; --no-resume ends each \
     session with its link, as for podssh cp.",
    "--timeout DURATION, or PODSSH_TIMEOUT, bounds the whole run, the login included (exit 75), and is \
     never required, with no terminal either: a script runs OpenSSH's scp in a pipe with no such flag, \
     and each wait of a copy has its own limit, ConnectTimeout the login's (60 s by default). podssh cp \
     and podssh mv need it with no terminal, where nothing else bounds the whole run.",
    "--result-file FILE writes the object of podssh cp at the end, its verb scp; stdout and stderr stay \
     those of OpenSSH's scp.",
];

const SFTP: &[&str] = &[
    "podssh sftp takes the command line of OpenSSH's sftp. With -b FILE, or -b - for stdin, it runs the \
     commands of FILE in order and prints each line first; a line that starts with @ is not printed, and \
     one that starts with - does not end the batch when it fails. Else, on a terminal, it asks at a \
     prompt; with no terminal and no -b it refuses (exit 64). A destination with the path of a file \
     fetches that file and ends; one with a directory starts there. The destination can be the node of a \
     pair, node://[user@]NAME[/ROUTE][:path], or a member of the net by its name alone, as for podssh cp, \
     and with --carrier ADDR a node at the other end of a stream that exists already; --no-resume ends \
     the session with its link, as podssh ssh does. \
     --timeout DURATION, or PODSSH_TIMEOUT, bounds the whole run, the login and the batch included (exit \
     75), and is never required, as for podssh scp.",
    "The commands: get and put (with reget and reput, which are the same), rename, rm (with * and ? in \
     the last name), mkdir [-p], rmdir, ls [-1afhlnrSt], cd, lcd, pwd, lpwd, chmod, df [-hi], help, version, \
     and bye, exit or quit. get and put copy as podssh cp does; get -p and put -p, or each of them after \
     sftp -p, keep the times. get -r and put -r (or -R), or each of them after sftp -r, copy a directory \
     and what it holds as podssh cp -r does, each link as a link; an item that fails is said, the rest \
     goes on, and the command fails at its end. The exit code is that of the first command \
     that ends the batch, as for podssh cp; a usage error is 64 where OpenSSH gives 1.",
    "ls lists as OpenSSH's sftp does, with its switches [-1afhlnrSt]. With neither l nor 1 the names go \
     in columns of the terminal's width, else 80; 1 puts one name a line. l gives OpenSSH's long form: the \
     mode, ? for the link count, the owner and the group, the size, the time of change in the local zone \
     (the hour within half a year, else the year), then the name; for a directory, the server's own line \
     of each entry, unless the server names owners by number (users-groups-by-id@openssh.com), when \
     podssh makes the line with their names. n shows the numbers, h the sizes in K, M and G; t sorts the \
     newest first, S the largest first, r turns the order round, f keeps the server's, and a shows the \
     names that start with a dot.",
    "--result-file FILE writes one JSON object to FILE at the end, as podssh cp does, its verb sftp, with \
     commands (run and failed) and failed_command, the line of the batch whose failure ended it, as \
     written, or null; a fetch of the destination's file is one command. It has no files and no \
     transferred, and bytes is null.",
];

const MV: &[&str] = &[
    "podssh mv moves files, with the operands and the flags of podssh cp; with no terminal it needs \
     --timeout, as podssh cp does. Within one server the server \
     renames, with posix-rename or by exec with mv -f, and no byte moves; a rename that the server fails \
     for a reason of its own, such as two file systems, becomes a copy and a delete, said first.",
    "Between hosts a move is not atomic, and podssh says so on stderr before any byte moves: the copy of \
     podssh cp, its digest check, then a delete of the source; between two servers a third connection \
     removes it. The source goes last, and only while it is still the file that was copied: the same \
     size and time of change, the same file, and the same bytes where a digest command runs there.",
    "A source that changed stays (exit 66). A delete that fails exits 70 and says that the copy is \
     complete and verified: the data is then in two places, never in none. One file named twice is \
     refused (exit 64). With --jsonl each done object says whether the source is gone: source_removed.",
    "With -n or -u a source whose destination stays is not moved, and stays where it is; mv -r leaves it \
     with the directories that hold it. Within one server, -n moves by a hard link and the removal of \
     the source's name, so a name that came since the look stays; -b keeps the old destination as for \
     podssh cp.",
    "--result-file FILE writes the object of podssh cp at the end, its verb mv, with removed: the sources \
     that the move removed once their copy was verified.",
];

const DOCTOR: &[&str] = &[
    "Each line is ok, FAIL or ????, the check, and what podssh found. ok: podssh can work with it; a \
     missing pty, listener, DNS or user database entry is ok, because podssh is made for them. FAIL: \
     something that podssh needs is broken. ????: the check could not run, and it does not fail the run.",
    "The checks: this host (the user database entry, where host keys and tokens can be written, \
     whether PODSSH_CACHE_DIR chose the place or is none, and each usual place of the cache passed over \
     as another user's (see FILES), /proc, \
     a pty, a socket bind that is closed at once, the directories that can run programs, the terminal, \
     the sshd of a roost); \
     the egress (the proxy setting, TLS and the trust store, what the proxy allows, the system resolver, \
     the addresses of the cache, and DNS over HTTPS with the form that answered; on github.com port 22 only \
     the server's banner shows that plain ssh can leave, as a proxy can take the CONNECT and carry nothing); \
     and the relay (each relay host, with where its address came from: a pin, the system resolver, the \
     cache or DNS over HTTPS; a token, a session to github.com port 22 that must show the published host key \
     of GitHub, and the clock).",
    super::notes_pair::DOCTOR_SSHD,
    super::notes_doctor::DOCTOR_AT_ONCE,
    super::notes_doctor::DOCTOR_QUICK,
    super::notes_doctor::DOCTOR_DIAGNOSIS,
    super::notes_doctor::DOCTOR_IPV6,
    super::notes_doctor::DOCTOR_EXIT,
    super::notes_doctor::DOCTOR_STREAM,
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
     QUIC: with a proxy set it takes HTTP/2, as no proxy carries UDP, and nothing is sent. Its line edge \
     road says, with --full, which road over TCP reaches the edge, as the node tries them: port 7844 \
     directly or through the proxy, else, in a build with the feature warp and with a device of WARP kept, \
     inside WARP's tunnel; doctor registers no device, and keeps a new key of WARP's endpoint, read from \
     WARP's API, as a run of warp:// keeps it.",
    "With --full, the relay section adds login: podssh logs in to github.com through the relay as git, \
     with an Ed25519 key made for the check and never written, and GitHub refuses it. That shows that the \
     handshake, the host key (the one that forward identified) and the authentication path work. No pty \
     is asked for: GitHub refuses the key before a channel opens. With no proxy set, --full also sends \
     the node's probe of UDP to the quick tunnel's edge, Cloudflare's, one QUIC packet that the edge \
     answers with a Version Negotiation, waited for 300 ms; when it is answered, a QUIC handshake with the \
     edge, as the node's QUIC makes one, closed at once with nothing registered: UDP out then says what \
     answered, and in what time, or that the node skips QUIC and takes HTTP/2. \
     In a build with the feature tor, --full bootstraps Tor as a tor:// destination does (through the \
     proxy, its first hops on the ports of PODSSH_TOR_PORTS or the bridges of PODSSH_TOR_BRIDGES, the \
     network of PODSSH_TOR_NETWORK) and opens no stream: the line tor says how long it took, through which \
     bridges' transports, or why it failed.",
    "With --forwarder, PODSSH_FORWARDER or Forwarder of the settings file, the section forwarders gives a \
     line for each forwarder, in order: the upgrade, then a session to github.com port 22 through it, whose \
     host key must be one that GitHub publishes, as the relay's forward line asks; a forwarder that closes \
     before GitHub's bytes says its code and its reason. With none named, its line fallback says whether a \
     run whose relay hosts all failed tries the forwarders that podssh names (see podssh ssh); it asks none \
     of them, so it is ???? (unknown in --json), never ok.",
    "With --shadowsocks FILE, the section shadowsocks gives a line for the first server of FILE, a \
     subscription's first when the file starts with one (its list fetched or kept, as a run takes it): \
     the TCP through HTTPS_PROXY when one is set, the server's salt and first chunk with their time, then a \
     session to github.com port 22 through it, whose host key must be one that GitHub publishes. A server \
     that stays silent names the proxy as the likely cause when one carried the TCP, else the password \
     or the method.",
    "With --via URL or PODSSH_VIA, the section via gives a line for that forward proxy over TLS: the \
     proxy of HTTPS_PROXY that carried the TCP to it, if one did, the version of HTTP that it chose \
     (HTTP/2 or HTTP/1.1) and the time of its CONNECT, then a session to github.com port 22 through it, \
     whose host key must be one that GitHub publishes. A 407 says what the proxy asks for.",
    super::notes_vless::DOCTOR_VLESS,
    "With --json, the report is one JSON object on stdout when every check has run: schema (1), podssh, \
     os, arch, checks (each with section, check, status and detail; status is ok, FAIL or unknown), \
     counts (ok, fail, unknown) and diagnosis (each case after the counts; empty when none). A check tried \
     several times adds samples: tries, connected, best_ms, \
     median_ms, p95_ms and jitter_ms (null when no try connected), timed_out, broke, refused, and ms, the \
     time of each try that connected. The details are the text's, the exit code is the same, and nothing \
     is printed before the object.",
];

const STATUS: &[&str] = &[
    "podssh status writes one line of JSON on stdout and exits 0: schema, podssh, relays (each host and \
     port) and relays_from (--relay-host, PODSSH_RELAY, or the default and its pool), pool (cached, when \
     it was fetched, how many hosts), token (source: PODSSH_RELAY_TOKEN, cache or none; the relay that it \
     is for; when it expires; whether it can be used), cache (from: PODSSH_CACHE_DIR, none or default; \
     dirs: the directories in the order podssh tries them; passed: each usual place that is in another \
     user's tree, its dir and why, see FILES), proxy (the variable, HOST:PORT and the kind, \
     http or socks5), offline, \
     attachment, stdin_tty and stdout_tty, host for a destination (its name in known_hosts, whether \
     a key is recorded, the key types), session_log, relay_failures and relay_opened (the relay hosts \
     tried last and first: road, host, ago_s, and the reason or the opens), relay_rank (the rank kept: \
     age_s, this_egress, holds, named, source, relay rank or background, partial, first and hosts; null \
     with none), relay_order (rank, samples, pool or off), relay_rank_auto (whether a setting asks for a \
     rank in a session's background and which one, and when the last was made: asked, by, last_ms, \
     last_age_s, partial), open_files (soft, hard, \
     at_start, raised, refused: the limit of open files, which podssh raises at start; null on \
     Windows), and pairs: each stored pair's label, when it expires, whether it expired, and \
     next_now, whether podssh relay pair LABEL makes its next pair now.",
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
    "--ts-control-url https://HOST[:PORT] names another control server, such as headscale; plain http, \
     a path and a password are refused (64). The check of tcp then asks that server for its key, as the \
     node does first, and for its DERP map when it publishes one; headscale publishes none, and its \
     node reads its DERP servers after it registers. --ts-relay HOST:PORT pins relay mode to a DERP \
     server on another port. A test's control server of its own CA sets PODSSH_TS_TEST_CA_FILE, which \
     the node adds to its roots; podssh ts says when it is set.",
];

#[cfg(test)]
#[path = "notes_tests.rs"]
mod tests;
