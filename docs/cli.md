# Command line

`podssh man` is the reference for each command, argument, flag, `-o`
keyword, variable, file and exit code. The binary makes it from its own
tables, so it describes that binary and no other version. This page gives
the rules behind those tables, for people and agents who change them.

`podssh ssh` takes the command line of OpenSSH, so it can replace `ssh` in
scripts. The facts about OpenSSH on this page were measured with OpenSSH
10.3p1 and `ssh -G`, unless a line gives another source.

## The manual

- **The tables.** The flags of each command are in
  `crates/podssh-cli/src/flags.rs`, their arguments in `src/positionals.rs`,
  the `-o` keywords in `src/ssh/keywords.rs`, and the variables, files, relay
  facts, exit codes, notes and examples in `src/man/`. `--help` and
  `podssh man` read the same tables.
- **Change the table with the code, in the same commit.** The tests fail
  when the manual and the code disagree: a variable that the code reads and
  the manual does not name (or the reverse), a default that `resolve` does
  not use, an `-o` keyword that the parser handles differently, an example
  that the parser refuses, or a note that names a flag that is gone.
- **Text first.** `podssh man` writes plain text, so it needs no `man`,
  groff or pager. On a terminal it pages: `PAGER`, else `less` when `PATH`
  has it and `TERM` names a terminal (not on Windows), else its own pager.
  `--no-pager` writes to stdout; with no terminal there is no pager.
- **Roff second.** `podssh man --roff` writes a man(7) page with standard
  macros only. A macro defined in the page is read differently by different
  renderers: an `Fl` macro that used `\$*` printed blank flag names under
  groff and mandoc. The gate renders the page with both
  (`scripts/interop-man.sh`).
- **Data third.** `podssh man --json` writes the tables as one JSON object
  for a program (GitHub #10): the commands with their availability,
  arguments and flags, each flag with its kind and what to type instead;
  the `-o` keywords; the variables; the files; the exit codes. It reads the
  tables, not the text, so it keeps what the text drops. `--json SECTION`
  gives one command, or the table of `environment`, `files` or
  `exit-status`; a prose topic has no JSON form (exit 64), and neither has
  `--json --roff`.
- **No setting of the host.** The manual is the same bytes in each
  environment. It never shows a token or a credential.
- **A command that does not work says so.** `--help` and the manual mark a
  command that is not implemented, or not in this build. Its own `--help`
  and its section of the manual give the same sentence, and no option but
  `--help`: the options of a command that does nothing cannot be used.

## Options of `podssh ssh`

- **`-P` has a different meaning for each command.** For `ssh`, `-P` is a
  tag: `ssh -G -P mytag x` prints `tag mytag`, and `-P2222` keeps port 22
  and sets the tag 2222. For `scp` and `sftp`, `-P` is the port. Thus
  `podssh ssh -P TAG` accepts the tag, ignores it, and says on stderr that
  `-p` is the port. For `cp`, `mv`, `scp` and `sftp`, `-P` is the port.
- **No option is dropped silently.** An unknown flag is an error that names
  the nearest real flag (exit 64). A known flag with no value names the flag,
  in both spellings, and the value that it needs (exit 64). A dropped option
  can disable a security check without a message. OpenSSH exits 255 with
  `Bad configuration option` for an unknown `-o` keyword, before it connects.
  `podssh --help COMMAND` prints the help of COMMAND; each other word after
  `--help` or `--version` is refused (exit 64).
- **Destinations.** `node://[user@]NAME` is the node of the pair under the
  label NAME (T-084), reached through the relay, with its host key recorded
  under `node://NAME`, which no DNS name can be; `node:22` is still the host
  `node` on port 22. A node has no port, and `-J`, `-W` and `--direct` do
  not go with it yet (exit 64). To a node, podssh sends nothing until the
  node's first bytes, 30 s at most: a node that offers the resumable layer
  greets with its first record, and `-v` says whether it did (T-151,
  `docs/design.md` section 5). With the layer, a lost link to the relay is
  replaced by a new one for 10 minutes and the SSH session goes on where it
  was, with one line on stderr for each loss and each resume (T-153).
  `-J a,b` makes a chain of hops; `-J a -J b` is an error.
  `ssh host:2222` connects to a host named `host:2222` on port 22. The port
  form of OpenSSH is `ssh://user@host:2222`. podssh also accepts `host:PORT`,
  because its own "did you mean" message gives that form. A host name cannot
  contain `:`. An IPv6 address needs brackets only before a port:
  `user@2001:db8::1` is port 22, and podssh reads the port of
  `user@[2001:db8::1]:2222` as it reads `host:PORT` (OpenSSH reads a port
  there only in the `ssh://` form). `-4` or `-6` with an address of the
  other family is refused. `podssh proxy` takes the bare address that
  OpenSSH gives for `%h`. A host that starts with `-` is refused (exit 64),
  also as `-o HostName=`, as OpenSSH refuses it. podssh reads options before
  and after the destination, as OpenSSH does, so a script that passes a host
  that it did not write puts `--` before it: `podssh ssh -- "$HOST" COMMAND`,
  `podssh proxy -- "$HOST" PORT`.
- `-N` alone is valid. `-W HOST:PORT` is a stdio forward: no session, and
  exit when the forward fails. `-W` takes `HOST:PORT` or `[ADDR]:PORT` only:
  a value with no port is refused, as OpenSSH refuses it, and a path (a Unix
  socket on the server, for OpenSSH) is refused until T-040 (exit 64). A
  `-J` hop keeps its own reading, where a host alone is port 22. `-V` prints
  the version and does not connect.
- **`--persist` keeps the work through a lost link** (T-178), against a
  standard sshd, where the resumable layer cannot help. After the login,
  podssh looks for tmux (`command -v tmux`) and refuses without it (exit
  255): a new shell after a loss would look like the old one and have lost
  its state. The session is `tmux new-session -A -s NAME`, with a pty as
  `-tt` asks; NAME is `podssh`, or the one of `--persist-name` (letters,
  digits, `_` and `-`, 32 at most). A lost link is a session that ended
  with no exit status: with `--direct`, or through the relay when its link
  broke (the ping watcher) or it closed with 1001, 1006, 1009 or 1011. Then
  podssh connects again, 10 times at most within 5 minutes of the loss,
  after the jittered wait of the relay's failover, checks that the session
  is still there (`tmux has-session`), and attaches it. A session that is
  gone ends the run (255), as do an exit status, a detach of tmux (0), `~.`,
  a refused host key or login, and Ctrl-C during the wait. The logins after
  the first ask nothing (as `BatchMode=yes`): the input belongs to the
  session, and a key that a passphrase opened and a password that the
  server took are kept for the run. Keys typed during the wait go to the
  session after the attach, 64 KiB at most. With a command, `-W`, `-N`,
  `-s`, `-T`, `RemoteCommand`, `node://` or `iroh:`, `--persist` is a usage
  error (64). The first connection's failure is final, as without
  `--persist`.
- **A repeated value follows OpenSSH** (measured with `ssh -G`): the first
  `-p` and `-l`, the last `-e`, `-E` and `-F`, and the first value of each
  `-o` keyword. A second `-J` or `-W` is an error, as in OpenSSH. podssh's
  own `--relay-host`, `--relay-addr` and `--ca-file` may be given once: a
  comma list gives several hosts or addresses, and no relay or trust store
  is chosen by its place on the command line.
- Each flag in the usage of OpenSSH 10.3p1 has a row: supported, accepted
  with no effect (`-P`, `-g`), or refused by name with what to use instead.
  `tests/flag_table.rs` holds the reviewed set. A refusal with nothing to use
  instead says "Leave it out."
- **`%` tokens are OpenSSH's** (ssh_config(5); the values of
  `DEFAULT_CLIENT_PERCENT_EXPAND_ARGS` in OpenSSH 10.3p1). In `-i`,
  `IdentityFile`, `UserKnownHostsFile`, `GlobalKnownHostsFile` and
  `IdentityAgent`: `%%`, `%C` (the SHA-1 of `%l%h%p%r%j`), `%d`, `%h` (the
  host, lowercased unless it is an address), `%i` (the user id), `%j` (the
  host of the last jump), `%k` (`HostKeyAlias`, else `%n`), `%L`, `%l`
  (the local host name, and its first label for `%L`), `%n` (the host as
  typed), `%p`, `%r` (the remote user) and `%u` (the local user, from
  `USER`, `LOGNAME` or `USERNAME`). An unknown token, or one whose value
  podssh does not know, is refused (exit 64); OpenSSH refuses an unknown one
  too. `-E FILE` is opened with the name as typed, as OpenSSH opens it. The
  gate compares the tokens with `ssh -G`.

## Forwarding

- `-L` and `-D` need a local listener, so podssh refuses them. The refusal
  of `-L` gives `-W HOST:PORT`. For `-D`, `-W` is only a partial answer: a
  SOCKS proxy serves many connections, and `-W` serves one. T-038 adds
  both, with a listener that opens only after a probe allows the bind
  ([decisions.md](decisions.md), 2026-10-08).
- `-R` does not need a local listener: the server listens, and podssh
  connects out for each connection. It is not implemented yet. Its refusal
  must not say that podssh never binds. On the measured sandbox, a
  connection back to loopback is refused, so `-R` must go through the proxy
  or fail with a clear message.
- When a server refuses `tcpip-forward`, podssh gives the server's reason.
- Agent forwarding (`-A`) is not implemented yet. It is in the scope of
  podssh, off by default as in OpenSSH (T-036).

## A word with no subcommand

`podssh example.org` never connects. podssh selects a suggestion in two
steps:

1. The form of the word: `@`, `.` or `:` gives `Try: podssh ssh <word>`.
2. The edit distance, with an absolute limit and a shared two-letter prefix.

The edit distance alone suggests `doctor` for `example.org` and `cp` for
`xz`. The first step prevents this.

## `podssh cp`

`podssh cp SRC... DST` copies files between this host and a server over
SFTP (`crates/podssh-ssh/src/sftp/`), or by exec when the server has no
SFTP, through the relay or with `--direct`, with the connection flags of
`ssh` (`-o`, `-J`, `-i`, `-v`, `-q`) and `-P` for the port.

- An operand names a server when a `:` comes before any `/`, as scp reads
  it: `[user@]host:path` or `[user@][IPV6]:path`. `./a:b` is a local file;
  on Windows a drive letter (`C:\x`) is local. `host:` is the login
  directory. Two local operands, sources from both sides, or remote
  sources on two servers exit 64 before anything connects.
- **The destination's name never holds a file that was not verified.**
  The bytes go to `.NAME.podssh-RANDOM.part` beside the destination (a new
  file of mode 0600). The SHA-256 of what was sent is compared with the far
  side's; then the file takes the source's permission bits and is renamed
  onto the destination, at once with `posix-rename@openssh.com`. Without it,
  an existing destination is removed first, and podssh says that the
  replace was not atomic. A failure removes the temporary file.
- The far digest comes from `sha256sum`, `shasum -a 256` or
  `openssl dgst -sha256` over exec, when the server runs one; else from a
  second read over SFTP (`ForceCommand internal-sftp` runs no command).
  The size and the MAC of SSH alone miss a wrong offset, a short write, and
  a source that changed while it was read.
- Several sources go into a directory. A copy from server to server goes
  through a temporary file on this host, one connection at a time.
- `-r` and `-p` are refused by name until a copy of a directory (T-143)
  and the times (T-146) exist.
- **A server with no SFTP subsystem gets a copy by exec**
  (`crates/podssh-cli/src/cp/byexec.rs`), and podssh says so once. Each
  step is one command on a channel with no pty, `sh -c 'SCRIPT' sh PATH...`:
  the login shell, POSIX or not, only starts `sh`, and each path is one
  quoted word. A path with a newline or a NUL has no such word and is
  refused (64).
- A probe finds the far tools first: `cat`, `wc`, `mv` and `rm` are needed;
  `chmod`, `base64` and the digest tools are used when they are there. Then
  the 256 byte values go through `cat`. When they come back unchanged, the
  bytes go raw; else through `base64`, which adds a third to what counts
  against the relay, or the copy is refused. With no POSIX `sh`, or a
  needed tool missing, the copy exits 69 and names what is missing.
- Each answer comes after a random marker, so text that a login prints
  first (a start-up file, a `ForceCommand` banner) is never taken as data.
  The temporary name, the digests and the rename (`mv -f`, atomic on one
  file system) are those of the SFTP road. A copy down keeps mode 0600: no
  portable command reads the far file's mode. A copy within one server
  goes through this host. Each step with no file data waits 15 s at most.
- `--jsonl` prints one object per file: `{"event":"done", "source",
  "destination", "bytes", "sha256", "verified_by", "atomic"}`, or
  `{"event":"error", "source", "message", "code"}`.
- Each SFTP reply with no file data waits 30 s at most, each read or write
  60 s (T-133); `--timeout` bounds the whole copy, the login included.
- **A copy goes on after a broken connection**
  (`crates/podssh-cli/src/cp/resume.rs`): a relay close, a lost link or a
  step with no reply keeps the temporary file, and a new connection writes
  on at the offset below which each byte is in it; by exec, once the far
  file stands still (two sizes 2 s apart), up with `cat >>` and down with
  `tail -c`. At most 5 attempts in a row with no new byte, with the relay
  opener's backoff between them; a refused login, a host key other than
  the first connection's, or another answer ends it at once.
- The offset is kept across runs too, in a private side file of the cache
  directories (`podssh-cp-*.resume`, never a byte of the file): the same
  command, run again, goes on while the source is as it was; else it
  starts over and says so. The digest covers the whole file: a continued
  copy whose digests differ starts once more from the first byte, then
  fails.
- **Before the relay's limits** (64 MiB both ways, 12 h for each session),
  a copy opens a new session and goes on at its offset, with no wait: it
  counts each session's payload bytes and age against a budget of 60 MiB
  and 11 h 30 min (`docs/relay.md`, "Limits that users see";
  `PODSSH_SESSION_BUDGET` lowers the bytes). Each new connection meets the
  first one's host key, and logs in as the first did: a key that a
  passphrase opened, or a password that the server took, is kept in memory
  for the run, so no new question comes. `--direct` has no such limit.

## `podssh mv`

`podssh mv SRC... DST` moves files, with the operands and the flags of `cp`
(`crates/podssh-cli/src/cp/moving.rs`).

- **Within one server, the server renames**, and no byte moves:
  `posix-rename@openssh.com` (else the rule of `cp`: remove, then rename,
  said), or `mv -f` by exec. When the server fails the rename for a reason
  of its own (two file systems), the move is a copy and a delete, said
  first.
- **Between hosts a move is not atomic**, and podssh says so on stderr
  before any byte moves: the copy of `cp`, its digest check, then a delete
  of the source. Between two servers, a third connection removes it.
- **The source goes last**: after the digests matched and the rename onto
  the destination succeeded, and only while it is still the file that was
  copied: the same size and time of change; here the same file (the device
  and inode, or on Windows when it was made); by exec the same line of
  `ls -lnid`; and where a digest command runs on its side, the same bytes.
  A source that changed stays, and the move exits 66. A delete that fails
  exits 70 and says that the copy is complete and verified: the data is
  then in two places, never in none.
- One file named twice is refused (64): as typed, before anything connects
  (`host:a host:./a`), or by the server's answer (`realpath`, or `test -ef`
  by exec).
- `--jsonl` adds `"source_removed"` to each `done` object; a rename has no
  digest (`"sha256": null`) and `"verified_by": "rename"`.

## `podssh scp` and `podssh sftp`

Each takes the command line of OpenSSH's own (`crates/podssh-cli/src/flags/scp.rs`,
`crates/podssh-cli/src/sftp/`), and copies as `cp` does: over SFTP (or by
exec for `scp`), under a temporary name, verified by its digest, then
renamed.

- **Each letter of OpenSSH 10.3p1's usage parses**: supported, accepted
  with no effect (`scp -3`, `-s`, `-T`; `sftp -a`, `-f`, `-N`), or refused
  by name with what to use instead. `-s`, `-R` and `-B` are switches on
  `scp` and take a value on `sftp`, so each verb has its own table.
  `scp -B` is `BatchMode=yes`; `sftp -s NAME` names the subsystem.
- **A URI operand**, `scp://[user@]host[:port][/path]` (or `sftp://`), is
  read as OpenSSH's `parse_uri` reads it: the path after the first `/` is
  under the login directory, `//` makes it absolute, the user and the path
  are percent-decoded, and the port is that operand's own. `cp` and `mv`
  take URIs too.
- **No `--timeout`**, as OpenSSH's have none; each wait of a copy has its
  own limit. Usage errors are 64 where OpenSSH gives 1.
- **`sftp -b FILE`** (`-b -` for stdin) runs each line in order and prints
  it first; `@` before a command keeps the line from being printed, and `-`
  keeps its failure from ending the batch. Else, on a terminal, `sftp`
  asks at a prompt; with no terminal and no `-b` it refuses (64). A
  destination whose path names a file fetches it and ends.
- The commands: `get` and `put` (`reget` and `reput` are the same: a copy
  that broke goes on by itself), `rename`, `rm` (with `*` and `?` in the
  last name), `mkdir [-p]`, `rmdir`, `ls [-la]`, `cd`, `lcd`, `pwd`,
  `lpwd`, `chmod`, `df [-hi]` (`statvfs@openssh.com`), `help`, `version`,
  and `bye`. The local commands (`lls`, `lmkdir`, `!command`) and `ln`,
  `chown`, `chgrp` are refused by name.

## `podssh doctor`

`podssh man doctor` gives the checks. The rules behind them:

- `doctor` takes the relay settings of `ssh` and `proxy` (`--relay-host`,
  `--relay-addr`, `--ca-file` and their variables), so it checks the path
  that they use.
- `ok`: the check ran and podssh can work with the result. A condition that
  podssh is made for (no listener, no pty, no user database entry, no DNS)
  is a fact and gives `ok`.
- `FAIL`: something that podssh or one of its fallbacks needs is broken: a
  proxy setting that cannot be used, no place to record host keys, a relay
  host that does not answer, no token, a forward session that fails or
  meets the wrong host key, or a clock more than one hour wrong.
- `????`: the check could not run. It never counts as `ok`, and it never
  makes the run fail.
- Servers are identified by equality (GitHub's published host key), never
  by the form of a banner. A socket bind is closed at once and never
  listens. Proxy credentials and tokens are never shown.
- `--full` adds the check `login` (GitHub #13): a login to `github.com` as
  `git` through the relay, with an Ed25519 key made for the check, kept in
  memory and never written. GitHub refuses it, which is `ok`: the handshake,
  the host key (equal to the one that `forward` identified) and the
  authentication path work. Another host key, or a broken link, is `FAIL`.
  No pty request is tested (GitHub refuses the key before a channel), and
  the binary runs no OpenSSH: `scripts/sandbox-check.sh` keeps that step,
  and calls `doctor --full`.
- `--json` writes the same report as one JSON object, when every check has
  run (GitHub #9): `schema` (1), `podssh`, `os`, `arch`, `checks` (each
  with `section`, `check`, `status` and `detail`; `status` is `ok`, `FAIL`
  or `unknown`) and `counts`. The exit code does not change. `--json` is
  for a report that ends; `--jsonl` stays for the events of a long run.

## `podssh status`

`podssh status [--relay-host HOSTS] [--relay-addr HOST=IP] [[user@]host]`
writes one line of JSON and exits 0 (GitHub #11). It is the cheap call
before anything else; `podssh doctor` is the report that measures.

- The line: `schema`, `podssh`, `relays` and `relays_from`, `pool`,
  `token` (its source, the relay that it is for, its expiry, whether it can
  be used), `proxy`, `offline`, `attachment`, `stdin_tty`, `stdout_tty`,
  and `host` for a destination (its name in `known_hosts`, whether a key is
  recorded, the key types).
- It never holds a token: it reads the cache entry without its token field
  (`cache::peek`). It shows no proxy credentials, opens no connection, asks
  no DNS and writes nothing.
- A bad flag or destination is 64, a bad variable 78, as for `doctor`.

## `podssh keygen`

`podssh man keygen` gives the flags. The rules behind them:

- The `ssh-keygen` of OpenSSH does not run without a user database entry,
  so podssh makes keys itself, in the formats of OpenSSH.
- A private key is never written over an existing file.
- A passphrase given with `-N` is refused (exit 64), because each process
  on the host can read a command line. `-N ''` is accepted. With no
  terminal and no `SSH_ASKPASS`, podssh refuses at once and names `-N ''`;
  it does not wait.
- DSA is refused, because OpenSSH 10 removed it.
- The comment comes from the environment, never from the user database.

## `podssh node`, `podssh operator` and `podssh relay`

`podssh man node`, `podssh man operator` and `podssh man relay` give the
commands. The rules behind them:

- **A pair has a label.** The relay names a pair, and the name changes with
  each new pair. NAME is the user's label for the pair in the cache
  (`pair-NAME.json`, mode 0600), so a script stays the same.
  `relay pair NAME` makes and keeps one; `node NAME TARGET` serves it;
  `relay status NAME` asks whether its node is online; `relay revoke NAME`
  stops it and forgets it.
- **`relay spec` checks the relay, not a pair.** It reads the relay's
  `/health` and `/llms-full.txt`, or the file of `--document`, and checks
  the document against the facts that podssh was built with: exit 0 when
  each holds, 1 when one does not (the relay changed), 69 when the relay
  could not be read (T-060).
- **No token in the output.** `relay pair` prints the label and the expiry.
  The operator's part, the connect token alone, goes to the new private
  file of `--operator-file`; the node's token and the stop token stay in
  the store.
- **One pair for each label.** A pair that has not expired is not replaced:
  a second pair would leave the first with no holder, for up to 72 hours.
  When a new pair cannot be stored, or its operator file cannot be written,
  it is stopped at once. A relay that cannot be reached keeps the stored
  copy at `revoke`: its stop token is the one way to stop the pair before
  it expires.
- **`relay` has no `--timeout`.** Each request has a bound of 30 s, so a
  script needs no `--timeout` (T-058's decision). `--relay-host` names the
  control host: the first host of the list.
- **A node dials TARGET first,** once, and exits 69 when it cannot; else
  each operator would get a `reject`. It runs until Ctrl-C or SIGTERM
  (exit 0). Its stdout stays empty.
- **`node --plain`** carries each session's bytes as they are, with no
  resumable layer, for an operator that does not speak it (T-263): a lost
  link ends the session, as before T-153. The node's first line names its
  mode. The iroh road always runs the layer, so `--plain` with `--iroh` is
  refused (64).
- **The exit codes follow the faults of E24**
  (`crates/podssh-cli/src/exitmap.rs`): 69 for a relay or TARGET out of
  reach, a stopped pair, or a pair that another node serves; 77 for a
  refused or expired pair; 78 for no stored pair, or a node that cannot
  connect as it is set up; 70 for a fault of the node that the relay closed
  (`1003`, `1009`).
- **`--pair-file FILE`** uses a pair of the store's form, which must be a
  regular file of the user that nobody else can read, as ssh reads a key.
  The store is not used. For `operator` and `ssh node://NAME`, the operator's
  file of `relay pair --operator-file` will do.
- **`operator` is a byte pipe**, as `proxy` is: stdout carries the node's
  bytes and nothing else, and it exits 0 only when the node took the
  session. Its codes are those of `node`. `ssh node://NAME` runs the SSH
  client over the same leg, and keeps the codes of OpenSSH (255).
- **`node --iroh` needs no pair** (T-163, a build with the feature
  `iroh`). NAME labels the node's key (`iroh-node-NAME.key` in the cache,
  or the file of `--iroh-key`; `--iroh-ephemeral` keeps none). The node
  prints its key and its ticket on stderr. A client's key gets in only from
  the file of `--iroh-allow`; with no such file, none does. `ssh
  iroh:TICKET` dials the ticket with this user's key (`iroh-client.key`, or
  `--iroh-key`), prints the key when it is new and when a node refuses it,
  and records the host key under `iroh:` and the node's key. A flag of the
  iroh road with no `--iroh`, or `--iroh-key` with no iroh destination, is
  a usage error (64); in a build without the feature, `--iroh` and an iroh
  destination exit 70 and name the feature.
- **`node --iroh` with a pair serves both roads** (T-164), with one keeper,
  and `ssh node://NAME --iroh-ticket TICKET` races them: the iroh road
  first, the pair's road after 250 ms or when the iroh road fails, the first
  far end that speaks wins, again at each resume. `--iroh-ticket` with
  another destination is a usage error (64).
- **A link can drop.** The relay's side ends a socket of the reverse road
  at random, with no Close (T-255). `operator` and `ssh node://NAME` then
  say that the link ended with no Close, or that the node's link ended
  (`1011 node disconnected`), and that a new session may work: the node
  connects again by itself. `operator` exits 69.

## `podssh pipe`

`podssh man pipe` gives the command (T-174). The rules behind it:

- **No listener unless one side asks for one.** `podssh pipe A B` joins
  two byte streams that exist already: stdin and stdout (`-` or `stdio`), a
  descriptor that the caller opened (`fd:N`, 3 or more, on Unix), a program
  (`exec:CMD`), or a road (T-175): `relay:HOST:PORT`, `tcp:HOST:PORT`,
  `ssh:[USER@]HOP[,HOP...],HOST:PORT`, `node:NAME` and `iroh:TICKET`; or a
  local socket (T-176), `unix-connect:PATH`; or, on one side at most, a
  listener (T-177): `unix-listen:PATH` or `tcp-listen:[ADDR:]PORT`. Both
  addresses are checked before anything starts; an unknown kind is a usage
  error (64) that lists the kinds, and `serial:`, the kind of a later
  entry, exits 70.
- **A listener only when asked, and only where a probe allows it** (the
  operator's ruling of 2026-10-08). `PODSSH_LISTEN=no` turns listening off:
  a listening address then exits 78 before any bind. The bind itself is
  the probe: a host that refuses it gives 77, and the line names the error
  and the addresses that need no listener; another failure gives 69.
  `unix-listen:PATH` takes the names of `unix-connect:`; a socket's file is
  made mode 0600 (umask 0177, as ssh-agent makes its socket), and a client
  of another user is closed before a byte passes (`SO_PEERCRED`, or on
  Windows the user of the client's process token), which also guards
  `@NAME`, which has no file. `tcp-listen:PORT` listens on 127.0.0.1 and
  `tcp-listen:ADDR:PORT` on an IP address of this host (`[::1]`, or
  `localhost`); a TCP port takes each user of this host, and other hosts
  too when ADDR is not loopback, and podssh says which; port 0 asks the
  system for a free port, and the line names it. The first client is
  joined to a new instance of the other side, which opens only then; the
  listener closes, and its file goes, as soon as the client connects, and
  the pipe ends with that session's status. `--keep-listening` takes each
  client in turn, 8 at once, each with its own instance of the other side
  (a new relay session, a new program), until SIGINT or SIGTERM. A signal
  removes the socket's file, and podssh exits with 128 and its number. A
  path that is a file and not a socket is kept (64); a socket that answers
  is another program's (69); one that nobody serves is replaced. A named
  pipe has no half-close: its listening side closes it at the end of its
  input, and the client reads the rest, then its end.
- **A local socket, by its name.** `unix-connect:PATH` connects, which the
  rule of no listener allows; `@NAME` is Linux's abstract namespace. A name
  that does not fit a socket's address is refused first (64). A missing
  socket, or one that nobody serves, exits 69, and one that this user may
  not use 77; each line names the path and the error. On Windows, a
  `\\.\pipe\` path is a named pipe, and another path an AF_UNIX socket
  (Windows 10 1803 and later), each tried when the pipe starts: where one
  fails, the line says why (the operator's ruling of 2026-10-08).
- **The roads, as the other commands take them.** `relay:` is what
  `podssh proxy` carries: since T-175, proxy runs the pipe of `stdio` and
  `relay:`, with its words and codes. `tcp:` dials as `ssh --direct` does.
  The hops of `ssh:` log in as `podssh ssh` does, with `-i`, `-o`
  (a keyword of a session, such as `RequestTTY`, is refused) and `--direct`;
  `node:` takes the pair of the label or of `--pair-file`; `iroh:` the key
  of `--iroh-key` and the relays of `--iroh-relay`.
- **No shell.** `exec:` splits its words with single and double quotes
  only, as podssh assumes no shell; `exec:sh -c 'CMD'` names one. The child
  gets one end of a socketpair as its stdin and stdout, so that the end of
  its input is a half-close, or two pipes where a socketpair is refused (a
  sandbox's seccomp) and on Windows. Its stderr is podssh's.
- **Half-close, as `podssh proxy` does.** When one side's input ends, the
  other side's write half is shut, and the other direction goes on: a reply
  still comes back. `tcp:`, `ssh:` and `unix-connect:` pass it on as TCP,
  SSH and a socket do; the relay has no half-close, so `relay:` sends no
  Close, and the target's bytes come until it closes, as a named pipe's do;
  `node:` and `iroh:` end their session, whose layer has no half-close. A writer whose reader is gone ends the pipe; a
  program that exited after its output ended ends it too, and so does a
  road that ended, as the other side's input may never end. podssh waits
  for each program, as a shell does.
- **The exit status.** A road that failed gives it, as `podssh proxy` gives
  it: 69 for a road out of reach, 77 for a refusal (the relay, a proxy, a
  host key, a login) and 78 for a setting that cannot be used. Else the
  program's, B's when both are programs, 128 + N for a signal, 127 for a
  program that is not found and 126 for one that cannot run; with neither,
  0.

## Exit codes

`podssh man exit-status` gives each code. The rules behind them:

- A usage error is 64 (`EX_USAGE`) for each command, before podssh does
  anything. A configuration error is 78 (`EX_CONFIG`): a variable of the
  environment that cannot be used, such as `PODSSH_RELAY` or
  `PODSSH_RELAY_ADDR` (also for `podssh ssh`). The same value as a flag is a
  usage error. The shell statuses 1 and 2 are not used for these, because a
  script cannot tell them from other programs' failures.
- `podssh ssh` uses the codes of OpenSSH, so it can replace `ssh` in
  scripts: the remote status unchanged (0 and 127 included), and 255 for a
  failure of podssh. A remote command stopped by a signal gives 128 plus the
  signal number (OpenSSH gives 255), and podssh names the signal on stderr.
- `podssh proxy` is not an SSH client: its failures use sysexits (64 to 78).
- `podssh cp` and `podssh mv` use sysexits too: 64 a usage error, 66 a
  source that is missing or cannot be read (for `mv`, also one that changed
  during the move), 69 no connection, or neither SFTP nor a copy by exec,
  70 digests that differ or a session that broke (the destination is
  unchanged), or a verified move whose source could not be removed, 73 a
  destination that cannot be written, 75 the `--timeout` passed, 77 a login
  or a host key refused, 78 a setting of the environment.
- A command that is not implemented exits 70. It never exits 0.
- A closed stdout (EPIPE) ends the session cleanly.

## Prompts and time limits

- Prompts (host key, passphrase, password, keyboard-interactive) go to the
  controlling terminal, as with OpenSSH. Thus
  `echo x | podssh ssh host cat` can still ask for a password.
  `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE` works as in OpenSSH.
- With no terminal and no askpass program, a prompt becomes a refusal that
  names the remedy. For an unknown host key: its fingerprint and
  `-o StrictHostKeyChecking=accept-new`. For a password: a key file.
- podssh asks on `/dev/tty` only when the kernel names it as the controlling
  terminal: the descriptor is a terminal of this process's session, and
  `/proc/self/stat` (when it can be read) names a terminal. In a measured
  sandbox, `/dev/tty` opened with no controlling terminal, and a read
  blocked for ever.
- When stdin, stdout and stderr are all redirected, a prompt on the terminal
  waits 60 s at most (`terminal::UNWATCHED_PROMPT`), then refuses with the
  remedy. A person at the terminal can still answer; a terminal that nobody
  watches does not stop podssh for ever.
- `-o BatchMode=yes` makes each prompt a refusal.
- A changed host key is refused, also on a terminal.
- A duration is parsed as a whole string. A malformed duration is an error,
  never zero. A time limit applies to the whole operation, not only to the
  dial.
- `PODSSH_TIMEOUT` gives `--timeout` its default, for each command that has
  the flag (GitHub #12): the flag wins, and an empty value is no value. A
  bad value of the variable exits 78 and names it; a bad `--timeout` exits
  64. It never bounds `ssh` or `proxy`, which have no `--timeout`. A command
  that is not implemented exits 70 first.
- `ConnectTimeout` (60 s by default) limits the SSH handshake, and each
  answer of the server while podssh logs in: a server that stalls after the
  key exchange ends the run with 255 and names the request that it did not
  answer. A prompt runs before its request, and the time that the agent
  spends signing (`ssh-add -c`) does not count.

## `ssh_config` (milestone M8)

podssh does not read `ssh_config` yet. These are the rules of OpenSSH,
measured with `ssh -G`:

- The first value obtained wins, from top to bottom. The most specific block
  does not win.
- A negated pattern excludes the host from that block only.
- `IdentityFile` and `-i` add up; they do not replace each other.
- `Include` is expanded where it appears, with globs in sorted order. A
  relative `Include` starts from `~/.ssh` (user file) or `/etc/ssh` (system
  file), not from the directory of the file that includes it.
- `*` matches across dots.
- `Match` never overrides a value that is already set. podssh must refuse
  `Match` by name, not skip it, because `Match` can change the host that
  podssh connects to.
- A missing `-F` file is an error (255), and `-F` stops the reading of each
  other configuration file. A missing `~/.ssh/config` is not an error.

NOTE: In its recommended parsing mode, `ssh2-config` 0.8.1 drops
`ProxyCommand` and `StrictHostKeyChecking` silently (read 2026-10-01). Do not
use it.
