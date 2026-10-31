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
  `podssh ssh -P TAG` sets the tag that `Match tagged` reads (T-045), and a
  tag that is a number gets a note on stderr that `-p` is the port. For
  `cp`, `mv`, `scp` and `sftp`, `-P` is the port.
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
  replaced by a new one for as long as the node keeps the session (10
  minutes, or the node's `--resume-deadline`), and the SSH session goes on
  where it was, with one line on stderr for each loss and each resume
  (T-153). `--resume-deadline TIME` waits at most TIME, never longer than
  the node keeps the session; when the node forgot the session, as after a
  sleep of this host longer than its deadline, the line says so, with how
  long this side was away by the wall clock (T-306). A link that goes
  silent gets a spare link beside it once the node has not answered for
  3 s, which resumes the session when it greets first: a new address of
  this host costs seconds, not the 30 s after which a silent link is dead
  (T-305); `-v` says each spare link, and `PODSSH_SPARE_LINKS=no` turns
  them off. The iroh road opens none, as its QUIC carries the session
  across a new address by itself.
  `-J a,b` makes a chain of hops; `-J a -J b` is an error. Each hop checks
  its own host key, filed under its own name: `host`, or `[host]:port` off
  port 22 (T-030). `HostKeyAlias` names the destination's key alone, as it
  is and with no port, as OpenSSH files it. Each hop reads the blocks of
  `ssh_config` for its own name, as OpenSSH's jump host does, and logs in as
  its own `user@`, its `User`, else the local user (T-290; see
  `ssh_config`). The settings of host keys, authentication, keys and time
  of `-o` and `-i` hold for each hop too; OpenSSH applies its command line
  to the destination only (its jump process gets `-l`, `-p`, `-J`, `-F` and
  `-v`).
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
  exit when the forward fails. `-W` takes `HOST:PORT`, `[ADDR]:PORT`, or
  `/PATH`, a Unix socket on the server (T-040), which the server opens as
  `direct-streamlocal@openssh.com`, as OpenSSH's `-W /PATH` does; through a
  control master too. A value with no port is refused, as OpenSSH refuses
  it, and so is a relative path (exit 64); a server that refuses the socket
  (`AllowStreamLocalForwarding no`) gives its reason, and 255. In Git Bash,
  `MSYS_NO_PATHCONV=1` keeps a path as it is typed. A `-J` hop keeps its own
  reading, where a host alone is port 22. `-V` prints the version and does
  not connect.
- **`cf://[user@]HOST` is a service that `cloudflared` publishes (T-264).**
  HOST is the DNS name of a tunnel's `ssh://` or `tcp://` rule. podssh opens
  the WebSocket to `wss://HOST/` that `cloudflared access tcp` opens, with
  its upgrade, through `HTTPS_PROXY` when one is set: no relay, and no
  program of Cloudflare's. A name behind Cloudflare Access needs a service
  token, `PODSSH_CF_ACCESS_CLIENT_ID` and `PODSSH_CF_ACCESS_CLIENT_SECRET`
  (both or neither), or a token that `cloudflared access token
  -app=https://HOST` made where its login runs, in `PODSSH_CF_ACCESS_TOKEN`
  or the file of `PODSSH_CF_ACCESS_TOKEN_FILE`; each goes in its header,
  never in a URL, and a bad one exits 78 (255 for `ssh`) naming the
  variable, never the value. A refusal of Access (a redirect to its login
  page, 401 or 403) names those variables and exits 77, another refusal 69.
  The host key is recorded under HOST. A tunnel has no port here; `-J`,
  `-4`, `-6`, `HostName` and `--direct` are refused (64). `-J cf://HOST`
  makes a tunnel the first hop of a chain (T-347): the run's road reaches the
  tunnel, and the hops after it, and the destination with its own port, run
  in its `direct-tcpip` channels, so a jump host whose sshd a tunnel publishes
  (`cloudflared` or `podssh node --quick-tunnel`) reaches the rest. A
  tunnel after the first hop is refused (64): a hop inside an SSH channel has
  no road to Cloudflare's edge. `podssh proxy
  cf://HOST` is the same pipe, with no PORT and no relay flag. Each message
  up is at most 16 KiB, as the origin cuts a longer one; podssh sends no
  Ping, as the origin answers one outside the lock of its writes; and the
  end of the stream, with no Close, is the end of the session.
  A podssh node behind HOST (`podssh node --quick-tunnel`, T-300) sends the
  resumable layer's `GREETING` first, where cloudflared's SSH service
  speaks SSH first: the session then runs in the layer, with the
  end-to-end channel above it, and a new WebSocket to HOST carries it after
  each lost one, as on `node://`. The node's key is the one of
  `--node-key` (the key that the node prints as it starts), else it is
  pinned under `cf://HOST` at its first sight: a quick tunnel's name lives
  one run of its node, so the pin guards that run's later sessions, and
  `--node-key` the first. `--client-key` applies as on `node://`, and no
  key of this client is made before the far end greets as a node;
  `--node-key` with a far end that greets with no layer is refused (255;
  77 for a copy), and `--no-e2e` with `cf://` (64), as a quick tunnel's
  node always runs the channel. SSH's keepalives are off there unless
  `ServerAliveInterval` is given, as the layer's heartbeat finds a dead
  link, and the run waits up to 5 s after SSH for the layer's `CLOSE`.
  `podssh proxy cf://HOST` carries the bytes as they are, so OpenSSH's
  `ProxyCommand` reaches cloudflared's services only.
- **`PODSSH_MPTCP=yes` asks for Multipath TCP on the direct road** (T-172),
  on Linux, and only on request. With `--direct` and no proxy, each attempt
  asks the kernel for a socket of `IPPROTO_MPTCP`: where the server speaks
  MPTCP too, the connection can go on over another network of this host
  when one goes, where the host's path manager has an endpoint on each.
  Where `/proc/sys/net/mptcp/enabled` is not 1, where the kernel or a
  sandbox refuses the socket, through a proxy (MPTCP would reach the proxy
  only), and on another system, the connection is plain TCP, the same
  stream; `-v` says which, and on Linux 5.16 and later whether the server
  took MPTCP. The relay's road never asks for it. It is a variable, not a
  flag or an `-o` keyword, so that each command that reaches its first hop
  as `ssh --direct` does (`cp`, `mv`, `scp`, `sftp`, `edit`, `ping`, the
  hops of `pipe ssh:`) reads it, and OpenSSH has no keyword for it. Another
  value than yes or no is refused before the connection (78; 255 for
  `ssh`).
- **`--host-key-fingerprint SHA256:B64[,...]` accepts only the keys that it
  names** (T-031), for a script that got the server's fingerprint from its
  operator and has no `known_hosts`: under each `StrictHostKeyChecking`,
  `accept-new` included, another key is refused with exit 255 and both
  fingerprints, and the named key is accepted and recorded nowhere. A
  revoked or a changed key in `known_hosts` is refused first. The
  fingerprint is the one that `ssh-keygen -l` prints; a value that is not
  one, or a second flag, is a usage error (64). It holds for the
  destination only: `-J` hops keep `known_hosts`. OpenSSH has no keyword
  for it, so it is a flag, not an `-o` keyword that would break a file
  that OpenSSH also reads.
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
  after the jittered wait of the relay's failover (a connection that lasted
  less than 30 s starts no new count: a link that falls again and again
  gives up, T-042), checks that the session
  is still there (`tmux has-session`), and attaches it. A session that is
  gone ends the run (255), as do an exit status, a detach of tmux (0), `~.`,
  a refused host key or login, and Ctrl-C during the wait. The logins after
  the first ask nothing (as `BatchMode=yes`): the input belongs to the
  session, and a key that a passphrase opened and a password that the
  server took are kept for the run. Keys typed during the wait go to the
  session after the attach, 64 KiB at most. With a command, `-W`, `-s`,
  `-T`, `RemoteCommand`, `node://` or `iroh:`, `--persist` is a usage error
  (64). The first connection's failure is final, as without `--persist`.
- **`--persist -N` keeps the forwards through a lost link** (T-042), as a
  tunnel that must last: no tmux runs. After a loss podssh connects again,
  as above, and asks the server for each `-R` again; `-L` and `-D` keep
  their listeners, which serve on the new connection. The server's own close
  is a loss too, as a forward keeps nothing on the server that its restart
  would lose; a close of the relay that would come again (1008, 1013) ends
  the run. After a loss, a forward that the server refuses is asked again,
  with the same wait, for 2 minutes at most, as the server may hold its
  port until it sees the old connection dead; then it is refused as on the
  first connection: a warning, or with `ExitOnForwardFailure` the end of the
  run (255). A port that the server chose (`-R 0:...`) can change, and
  podssh prints the new one. Each loss is a line on stderr that names the
  hop that broke, and each return a line. The logins after the first ask
  nothing (as `BatchMode=yes`), unless `SSH_ASKPASS_REQUIRE=force` names a
  program of `SSH_ASKPASS` to ask. With `-N` and no forward, or with
  `--persist-name`, it is a usage error (64).
- **`--attach NAME DEST` joins a shell that the far end keeps** (T-158),
  from a new podssh process or from another host; `--attach DEST` with no
  other word lists the kept shells, one on each line, and exits 0. Only a
  far end of `node://NAME` that names `keep.v1` in the resumable layer
  keeps shells: another destination is a usage error (64), and a far end
  that keeps none ends the run with 255 before a session opens. In a
  session with a pty there, `~d` asks the far end to keep the shell,
  prints the name that it keeps it as, and exits 0; elsewhere `~d` goes to
  the server as typed ([terminal.md](terminal.md), "Detach and attach
  again"). The far end gives a shell to one client at a time: `--take`
  takes it from the client that has it, whose session ends. It refuses an
  attach from inside the shell itself, which `PODSSH_SHELL_ID` names. Its
  refusal is its words on stderr and its exit status. With a command,
  `-N`, `-W`, `-s`, `-T`, `RemoteCommand` or `--persist`, `--attach` is a
  usage error (64), and a control master does not carry it.
- **`--upgrade` moves the session to a better road** (T-167), when the
  server has a podssh. The login is as each run's, on the forward road or
  with `--direct`; then podssh runs `podssh --version` there (10 s) and,
  when a line `podssh VERSION` comes back, `podssh node --temporary KEY` in
  the same SSH session, KEY being the fingerprint of this client's key
  (`client.key` in the cache, or `--client-key`). That node stands in front
  of the sshd of its session (a roost, T-166), makes a pair that no file
  keeps, and writes one line on its stdout: the pair's relay, name, connect
  token and expiry, and its own key. The SSH channel carries that line,
  encrypted, so the token crosses the relay only inside SSH, and it is on
  no argv. podssh opens the operator's leg to the pair, reads the node's
  greeting (no layer, no move), and logs in again through the node with the
  resumable layer and the end-to-end channel, which must find the node's
  key of the line. The host key is the same, under DEST's own name, so
  `known_hosts` needs no change, and no `-J` hop is used again. The first
  connection closes once the second login is done; until then, a failure
  of the move (no podssh, no line within 60 s, no layer, a failed second
  login) is one note on stderr, and the session runs on the first
  connection. The logins after the first ask nothing. podssh never copies
  itself to the server: a podssh must be on the `PATH` of a command that
  sshd runs. The node ends with its last session, or 10 minutes after its
  start with none, and stops its pair. On Unix it leaves its SSH session
  (SIGHUP ignored, its standard streams to `/dev/null`), so that the end of
  the first connection does not end it; on Windows it cannot, says so in its
  line, and the first connection stays open while the session runs.
  `--upgrade` with `node://`, `iroh:`, `cf://`, `--persist`, `-R` or `-O`
  is a usage error (64); `ControlPath` has no effect with it. The move takes
  the pair's road alone: the iroh road to the node, raced with it as T-164
  races them, is not built yet (T-167's Decision).
- **Ctrl-C with no remote pty sends `signal INT` to the command** (T-293),
  in a session that runs a command or a shell: podssh waits 2 s for the
  command's end, whose signal or status is the exit code, and a second
  Ctrl-C, or the end of the wait, ends podssh with 130. **`--no-signal`**
  keeps OpenSSH's behaviour: no request, and Ctrl-C ends podssh at once
  ([terminal.md](terminal.md), "Ctrl-C with no remote pty").
- **`--result-file FILE` writes the result of the run as JSON** (T-054), at
  its end, also when it failed before it connected, so that a script tells
  the remote command's status from a failure of podssh with no parsing of
  stderr: `schema`, `exit` (the code that podssh exits with), `status` (the
  remote exit status, or null), `signal` (`name` and `core_dumped`, or
  null), `end` (`status`, `signal`, `no-status`, `lost`, `escaped`,
  `terminated`, `detached`, `interrupted`, `failed`, or `shared`; null with no session, as with `-W`),
  `failure` (`connect`, `host-key`, `auth`, `forward`, `relay`, `session`,
  `usage`, `config` or `not-built`, or null: `connect` also when podssh got
  no session for another cause), `bytes` (`stdin`, `stdout`
  and `stderr`, as they passed), `duration_ms`, and `relay` (`host`,
  `close_code` and `reason`, or null with no relay). A signal ends with
  128 + its number, as in OpenSSH, and `status` is then null. `-N` ends
  `lost` when the server or the network ends the connection. A run through
  a control master (T-039) ends `shared`: the master tells the exit code
  alone, a status or 128 + a signal, and carries the bytes, which are then
  null. stdout and stderr stay byte for byte as they are: the command's
  output never goes into the file. A new file is made for its owner alone
  (mode 0600 on Unix); `-` is refused (64), as stdout is the command's. A
  file that cannot be written is a line on stderr, and the exit code stays
  the run's. No file is written after a flag that podssh does not know,
  which ends it before it reads the others (64), nor when a signal kills
  podssh, as it kills OpenSSH's `ssh`: only a session on a terminal ends at
  SIGTERM or SIGHUP, as `terminated`, and writes it.
- **`--sudo` and `--su` run the remote command as root** (T-032), with the
  password asked here, on the terminal or through `SSH_ASKPASS`, never on
  the command line. `--sudo` sends `sudo -S -k -p PROMPT -- sh -c '...'`
  with no pty, PROMPT a marker of this run, and the command prints a second
  marker as it starts: podssh answers that prompt once, holds its own input
  until the command starts, and removes both markers from the output. With
  a `NOPASSWD` rule there is no prompt, and podssh asks nothing. A second
  prompt is a refused password: podssh ends the input, and sudo exits with
  its refusal. `--su` sends `su -c '...'` in a pty, as su reads a terminal
  alone; its prompt is its output that ends with no newline before the
  command starts, and that output is shown only when su refuses. The
  remote shell must read POSIX quoting. When neither a prompt nor the
  command's start comes within 30 s, podssh stops with 255. Each needs a
  command; `--sudo` with `-t`, `--su` with `-T`, or both at once, are usage
  errors (64). Such a run makes a connection of its own, with no
  `ControlPath`, and with `BatchMode` a prompt ends the input.
- **`--record FILE` keeps what the session showed** (T-033), with its
  timing, in an asciicast v2 file that `podssh play` and asciinema play
  again: the header (version 2, the terminal's size, the time of the start
  and `TERM`), then an `o` event for each output and an `r` event for each
  new size. The file is made as the run starts, closed to others (mode
  0600, or an access list of its own on Windows), and never over a file
  that exists (255); `-G` makes none. Nothing typed is recorded, and the
  header holds no command line, which can hold a secret; the output can
  hold one (a key that was printed, a password that a program echoed). A
  character cut between two reads is written whole. `-N`, `-W` and
  `--persist` cannot go with it (64), and such a run makes a connection of
  its own, with no `ControlPath`.
- **`--expect TEXT --send KEYS` are rules of a session with a pty**
  (T-191), for a host that wants keys after the login: a menu, a banner to
  confirm, a second shell. Each rule waits for TEXT, a literal text as the
  terminal shows it, in the output that came after the match of the rule
  before it (64 KiB at most), then sends KEYS, where `\r`, `\n`, `\t`, `\\`
  and `\xNN` are read; the pairs come in order, each `--expect` with its
  `--send` after it (64 else). Until the last rule sent its keys, podssh
  holds its own input, so that no key typed here comes between them. Each
  rule waits `--expect-timeout` (30 s; a time as `--timeout` takes it);
  when it sees no match, the session ends with 255, and the message names
  the rule and its text. A session with no pty (no `-t` with no terminal
  here, or a server that grants none) runs nothing and ends with 255; `-T`,
  `-N`, `-W`, `-s`, `--sudo`, `--su` and `--persist` cannot go with the
  rules (64), and such a run makes a connection of its own, with no
  `ControlPath`. Each process of this host can read the command line, so
  KEYS are no place for a password, which comes through `SSH_ASKPASS`.
  Tasks before and after a connection are the shell's: `cmd && podssh ssh
  host; cmd`. podssh adds no `--before` or `--after`.
- **`LocalCommand` runs here after the login** (T-191), only with
  `PermitLocalCommand yes`, as OpenSSH runs it: after the login and before
  the session, with `SHELL -c COMMAND`, else `/bin/sh -c COMMAND` when it is
  there, else 78 before anything connects. Its `%` tokens are those of
  `RemoteCommand`, and `%T` is `NONE`, as podssh opens no tunnel; `-G`
  prints it as given, as OpenSSH expands it only as it runs it. podssh
  waits for its end; its exit status is said with `-v` and changes nothing,
  as in OpenSSH. Its input is none, as the session reads stdin next; with
  `-W`, its stdout goes to stderr, as stdout carries the stream. It runs
  once in a run: a try after a drop of the relay (T-025) does not run it
  again, and `--persist` runs it after its first login alone. Only `podssh
  ssh` runs it: `each`, `containers`, `cp` and the other commands that log
  in run none, as OpenSSH's `scp` and `sftp` pass `PermitLocalCommand=no`
  to their `ssh`; a client of a control master runs none, as OpenSSH's.
- **`~#` lists the forwards of the session** (T-041), in a session with a
  pty, as OpenSSH's `~#` lists its connections: for each `-L`, `-D`, `-R`
  and `-W`, as it was written, the connections it carried, those open and
  those that failed, and the bytes toward the server and from it, counted as
  they pass. With `-v` the end of a run prints the same lines. A forward
  asked for again on a new connection (`--persist`) keeps its counts. A
  forward that `~C` stopped stays in the list, with `; closed` at the end
  of its line.
- **`~C` adds and stops forwards in a running session** (T-291), in a
  session with a pty, as OpenSSH's `~C` does. It opens OpenSSH's command
  line, `ssh> `, and reads one line from the session's own keys; no key of
  the line reaches the server, and the keys after its Enter go to the
  session. The commands are OpenSSH's, with the `-` optional and a space
  after the letter optional:
  - `-L SPEC`, `-D SPEC` and `-R SPEC` add a forward, with a spec as the
    command line reads it. The listeners of `-L` and `-D` are made as those
    of the command line are: the same probe, the same addresses, `-g`,
    `PODSSH_LISTEN`; one that cannot be made says why, and the session goes
    on. `-R` asks the server, and podssh waits 20 s at most for its answer:
    `Forwarding port.` once the server took the forward, or OpenSSH's
    warning when it refused. OpenSSH says `Forwarding port.` before the
    answer.
  - `-KL [BIND:]PORT`, `-KD [BIND:]PORT` and `-KR [BIND:]PORT` stop a
    forward; `-KL` and `-KD` also take a socket path. A port with no address
    names each listener of that port; `localhost` names those on loopback.
    A closed listener takes no new connection, and the connections that it
    took go on, as in OpenSSH. `-KR` sends `cancel-tcpip-forward` for the
    port that the server listens on (the one it chose, for a port of 0),
    and a channel for that port is refused from then on.
  - `help`, `-h` or `?` lists the commands; an empty line, Ctrl-C and
    Ctrl-D do nothing. Another line is refused with OpenSSH's words
    (`Invalid command.`, `Bad forwarding close specification.`); a line
    that starts with `!` runs no local command (OpenSSH's
    `PermitLocalCommand`).

  The forwards that `~C` adds last as long as the connection, and those
  that it stops stay stopped: a new connection of `--persist` asks only for
  the forwards of the command line that `~C` did not stop, and keeps a
  listener that `~C` closed closed. A session through a control master has
  no `~C`, as a client of OpenSSH's master has none: the key goes to the
  server as typed.
- **`-G` prints the settings in effect** (T-046), as OpenSSH's `ssh -G`
  does: a line of `keyword value` for each keyword of OpenSSH that podssh
  applies, with the defaults, in OpenSSH's order and spelling (`true` and
  `false` where OpenSSH writes them), then exit 0 with nothing opened: no
  relay, no token. A script can compare the two line by line. The defaults
  that differ do on purpose: `serveraliveinterval 60` (the relay's idle
  cut) and `connecttimeout 60`. podssh tries the `_sk` identity files too,
  as OpenSSH does: a key of a security key signs in its device (T-229).
  podssh's own settings (relay hosts, `--ca-file`)
  print no line, as OpenSSH knows no such keyword; `podssh status` shows
  them.
- **A repeated value follows OpenSSH** (measured with `ssh -G`): the first
  `-p` and `-l`, the last `-e`, `-E` and `-F`, and the first value of each
  `-o` keyword. A second `-J` or `-W` is an error, as in OpenSSH. podssh's
  own `--relay-host`, `--relay-addr` and `--ca-file` may be given once: a
  comma list gives several hosts or addresses, and no relay or trust store
  is chosen by its place on the command line.
- Each flag in the usage of OpenSSH 10.3p1 has a row: supported, accepted
  with no effect (such as `scp -3`), or refused by name with what to use
  instead.
  `tests/flag_table.rs` holds the reviewed set. A refusal with nothing to use
  instead says "Leave it out."
- **`%` tokens are OpenSSH's** (ssh_config(5); the values of
  `DEFAULT_CLIENT_PERCENT_EXPAND_ARGS` in OpenSSH 10.3p1). In `-i`,
  `IdentityFile`, `UserKnownHostsFile`, `GlobalKnownHostsFile`,
  `IdentityAgent` and `ForwardAgent`: `%%`, `%C` (the SHA-1 of `%l%h%p%r%j`), `%d`, `%h` (the
  host, lowercased unless it is an address), `%i` (the user id), `%j` (the
  host of the last jump), `%k` (`HostKeyAlias`, else `%n`), `%L`, `%l`
  (the local host name, and its first label for `%L`), `%n` (the host as
  typed), `%p`, `%r` (the remote user) and `%u` (the local user, from
  `USER`, `LOGNAME` or `USERNAME`). An unknown token, or one whose value
  podssh does not know, is refused (exit 64); OpenSSH refuses an unknown one
  too. `RemoteCommand` takes the same tokens, and `User` from `-o` or from a
  file takes them but `%C` and `%r`; `-l` and `user@host` take none, as in
  OpenSSH (T-273). `HostKeyAlias` is lowercased, as OpenSSH lowercases it.
  `-E FILE` is opened with the name as typed, as OpenSSH opens it. The gate
  compares the tokens with `ssh -G`.
- **`${NAME}` in those paths is a variable**, in the same pass as the
  tokens, so a variable's value takes no token; a variable that is not set
  is refused (exit 64), as OpenSSH 10.3p1 refuses it (T-036). A whole
  `$NAME` as the value of `IdentityAgent` or `ForwardAgent` is OpenSSH's
  older form: the variable that holds the path, and no agent when it is not
  set; `-G` prints it as given. Elsewhere `$NAME` is part of a file name.

## Forwarding

- `-L` and `-D` (T-038) listen here, as the operator ruled
  ([decisions.md](decisions.md), 2026-10-08): a listener that the user
  asks for, made before anything connects; the bind and the listen are the
  probe. One that cannot be made ends the run (255) with the system's words
  and `-W HOST:PORT`, which needs none; `PODSSH_LISTEN=no` refuses each
  (78), as for `podssh pipe` and `podssh agent`.
- The forms are OpenSSH's `parse_forward`: `-L [bind_address:]port:host:hostport`,
  `-L [bind_address:]port:remote_socket`, `-L local_socket:host:hostport`,
  `-L local_socket:remote_socket`; `-D [bind_address:]port` and, beyond
  OpenSSH, `-D local_socket`; `-o LocalForward` with a space between the
  two sides, and `-o DynamicForward`. A field in brackets is taken as it
  is, a backslash makes the next character plain, a field with a `/` is a
  socket path, and `${NAME}` is a variable. A port of 0, and a port that
  is not a number, are refused (OpenSSH also looks a name up in the
  services database).
- The address: a port with no address listens on 127.0.0.1 and ::1, or with
  `-g` or `GatewayPorts yes` on 0.0.0.0 and ::; `localhost` is loopback,
  `""` and `*` each address, another is that address, as OpenSSH's
  `channel_fwd_bind_addr` chooses for a client. One of two addresses may
  fail, not both. A TCP port takes each local user, and other hosts when
  it is not loopback, which podssh says without `-v`. A socket path is the
  listener of `podssh pipe unix-listen:`: mode 0600, a client of another
  user is closed, and a socket that nobody serves is removed first.
- Each connection goes to the destination over a new channel:
  `direct-tcpip` with the client's address as its originator, or
  `direct-streamlocal@openssh.com` to a socket on the server. `-D` speaks
  SOCKS4, SOCKS4a and SOCKS5 with CONNECT and no authentication, and
  answers once the server opened the channel, with the reason of a refusal
  (OpenSSH answers first); BIND, UDP ASSOCIATE and authentication are
  refused. The channels of many connections open at the same time; a
  server may take 60 s to open one, and a SOCKS client 30 s to ask.
- `ClearAllForwardings yes` drops each `-L`, `-D` and `-R`, and `-W`
  implies it, as in OpenSSH. `-G` prints `clearallforwardings`,
  `gatewayports`, `dynamicforward` and `localforward` as OpenSSH 10.3p1
  does.
- `-R [bind_address:]port:host:hostport` (T-035) needs no local listener:
  the server listens, and podssh connects out for each connection that it
  takes, as one more outbound connection, through `HTTPS_PROXY` when it is
  set and within 20 s. On the measured sandbox a connection back to
  loopback is refused; podssh then closes that channel, and says why on
  stderr. `-o RemoteForward=[bind_address:]port host:hostport` is the same,
  and each one is kept. A port of 0 lets the server choose, and podssh
  prints it, as OpenSSH does. A socket path, and the server's SOCKS proxy
  (`-R [bind_address:]port`), are refused by name (exit 64).
- A server that refuses `tcpip-forward` gives no reason (RFC 4254, section
  4, has no field for one), so podssh names the port: a warning, or with
  `-o ExitOnForwardFailure=yes` the end of the run (exit 255). A channel
  that the server opens for a port that podssh did not ask for is refused.
- `-A` forwards the agent (T-036), off by default as in OpenSSH; `-a`
  turns it off, and the last of the two wins, over `-o ForwardAgent`, whose
  first value wins. podssh asks for it on the destination's session
  (`auth-agent-req@openssh.com`) before the shell or the command, never on
  a jump host of `-J`, and joins each agent channel that the server then
  opens to a new connection to the agent: the one that podssh logs in with
  (`IdentityAgent`, else `SSH_AUTH_SOCK`; on Windows also OpenSSH's named
  pipe, then Pageant), as OpenSSH forwards the agent of `IdentityAgent`, or
  the one of `-o ForwardAgent=PATH` or `$NAME`. It is one more connection
  to a local socket or pipe; nothing listens. An agent that does not answer
  within 10 s refuses that channel, and podssh says so once.
- **The risk:** while the session lasts, the server, and root on it, can
  use each key of the agent, though it cannot read one. Before the server's
  first byte on each agent channel, podssh binds the agent to the server's
  host key, as OpenSSH does (`session-bind@openssh.com`, T-279: the host
  key, the session identifier and the server's signature of it, from the
  first key exchange, which russh 0.65.0 gives the client, T-356), so an
  OpenSSH agent hides and refuses each key that
  `ssh-add -h` limits to other hosts. An agent that refuses the bind (one
  that knows no extension: Pageant, `podssh agent`) serves the channel
  unbound, as with OpenSSH, and `-v` says so; one that does not answer it
  within 30 s refuses the channel. Forward only to a server that you trust, or
  use `-J`, which needs no agent on the server. `podssh scp`, `podssh sftp`
  and `podssh cp` run nothing on the server that would use an agent:
  their `-A` is accepted and forwards none.
- A channel that the server opens for the agent with no `-A`, or on a jump
  host, is refused as administratively prohibited, with a warning, as
  OpenSSH refuses it. A server that refuses the request says so, and the
  session goes on without the agent.
- `-X` and `-Y` forward X11 (T-037) to the display that `DISPLAY` names,
  off by default; `-x` turns it off, and the last of the three wins, over
  `-o ForwardX11`. The server listens; for each `x11` channel that it opens,
  podssh connects to the local X server (`:N` is the socket
  `/tmp/.X11-unix/XN`, on Windows TCP port 6000+N; `HOST:N` is TCP port
  6000+N of HOST), as one more local connection, and puts the real cookie in
  place of a spoofed one: the server is given a random cookie of the same
  length (`x11-req`), never the real one, and a channel whose X client sends
  another is closed. `-Y` uses the cookie of the authority file
  (`XAUTHORITY`, else `~/.Xauthority`, read by podssh itself), and gives the
  server's X clients the access of each local one. `-X` uses an untrusted
  cookie that `xauth` makes (`XAuthLocation`, else `xauth` in `PATH`), which
  lasts `ForwardX11Timeout` (20 minutes), after which a new X11 channel is
  refused; with no `xauth`, `-X` is refused, naming `-Y`.
  `ForwardX11Trusted yes` makes `-X` act as `-Y`. Before anything connects,
  podssh checks `DISPLAY`, that its X server answers, and that there is a
  cookie, or that the X server takes a connection with none (as VcXsrv and
  X410 do with access control off); a check that fails ends the run with
  255 and its reason, where OpenSSH goes on with no X11. X11 goes on a
  session alone (with `-N` or `-W` it is not asked), on the destination
  alone, never on a jump host, and such a run makes a connection of its
  own, with no `ControlPath`. **The risk:** with `-Y`, a program on the
  server can read what you type in each X window and draw in each; forward
  only to a server that you trust.

## Connection sharing

`-M`, `-S`, `-O`, `ControlMaster`, `ControlPath` and `ControlPersist`
(T-039), on Unix: OpenSSH's control socket and its protocol
(`PROTOCOL.mux` version 4), so OpenSSH's `ssh -O check` and its clients
work with a podssh master, and podssh's client with an OpenSSH master. A
client passes its stdin, stdout and stderr to the master (SCM_RIGHTS),
which Windows cannot: there `-M`, `-S` and `-O` are refused (64), and the
keywords have no effect.

- A master: `-M` (`-MM` asks), or `ControlMaster yes`, `ask`, `auto` or
  `autoask` with `ControlPath` or `-S`. The socket is made before anything
  connects, as `-L` is: `podssh pipe`'s socket of mode 0600, after a
  socket that nobody serves is removed; a client of another user is closed
  (root may use it, as in OpenSSH); the socket goes when the master ends.
  A socket that cannot be made refuses the run with `-M` (255), and with
  `auto` it is said and the run connects alone; `PODSSH_LISTEN=no`
  refuses a master as each listener.
- A client: `-S PATH`, or `ControlPath` with `ControlMaster no`, `auto` or
  `autoask`. When a master answers, the run goes through it: its `-L`,
  `-D` and `-R` first, as OpenSSH's client sends them, then its session or
  its `-W`; with `-N`, the forwards stay with the master and the run ends.
  When none answers, the run connects alone, and with `auto` it becomes the
  master. A session with a pty puts the local terminal in raw mode and
  relays SIGWINCH to the master, which reads the new size from the terminal
  it holds; the exit code is the master's EXIT_MESSAGE, or 255 with none.
- The master serves sessions (a pty, the environment, a subsystem, the
  escape character of the client), `-W`, `-O check`, `exit` (the master
  ends with 0), `stop` (no new client; the socket goes), and `forward` and
  `cancel` of `-L`, `-D` and `-R`, which it serves on its own connection.
  `-O proxy` is refused. `ControlMaster ask` confirms each request that
  changes something on the terminal or through `SSH_ASKPASS`.
- `ControlPersist yes|TIME` keeps a `-N` master for that long with no
  client (`0` is forever, as in OpenSSH). podssh does not go to the
  background, so a master with its own session ends with it, once its
  clients' sessions have ended: start a lasting master with
  `podssh ssh -M -N -S PATH HOST &`. `--persist` does not take part.
- Every client shares the master's one relay session, and its limits
  (`docs/relay.md`); a drop of the master ends each client's session.
- Read from OpenSSH 10.3p1's own bytes (`scripts/mux-capture.py`): each
  `bool` of `PROTOCOL.mux` is a `uint32`, and the port of a stdio forward
  a `uint32`, not the string that the document says.

## `podssh each`

`podssh each [OPTIONS] HOSTS [--] COMMAND...` runs one command on each host
of a list (T-183, `crates/podssh-cli/src/each/`). It is a verb of its own:
`podssh ssh` keeps the command line and the exit codes of OpenSSH for one
host, and a list of hosts changes both.

- **The hosts** are a comma list of `[user@]host[:port]`, each named in
  the output as it is written. A host named twice runs once. Each one is
  resolved as `podssh ssh` resolves a destination, with the `Host` blocks of
  `ssh_config` for that host, before anything connects: a bad host fails
  the whole run with 64, and nothing has run anywhere.
- **Braces and groups** (T-184, `crates/podssh-cli/src/hosts.rs`) are
  expanded first, so that a shell that has no braces (dash, cmd,
  PowerShell) and a settings file can name many hosts. An item takes the
  braces of bash, in bash's order: `PREFIX{A..B}SUFFIX` (numbers, with the
  zero padding of the wider of A and B when either starts with 0, as
  `{01..12}`; or letters, `{a..c}`), `{A..B..N}` with a step,
  `{a,b,c}` (an empty item gives the rest alone), and each nested. `@NAME`
  is a group of the settings file (below), whose hosts are a list of the
  same kind and can name groups. A word gives 1000 hosts at most; more,
  none, an empty host, a range that runs backwards (bash would count down),
  braces that hold nothing or neither a list nor a range, a blank inside
  braces, and a group that is not there are usage errors (64). Square
  brackets stay an IPv6 literal (T-007), as in `pdsh` they would be a
  range: braces are what users of bash and csshw know. `podssh ssh` takes a
  pattern that gives one host, such as a group of one, and refuses one
  that gives more, with 64 and `podssh each` in the message. The settings
  for each host stay in the `Host` blocks of `ssh_config` (T-043): a group
  is a list of names, never their settings.
- **The options** are those of `ssh` that make sense for many hosts: `-p`
  and `-l` (for each host that names none), `-i`, `-o`, `-F`, `-J`, `-v`,
  `-q`, `--direct` and the relay's. `--parallel N` runs at most N hosts at
  once (8 by default, 64 at most), each on a connection of its own, in one
  process and one runtime, on the road and the SSH client of `ssh`: no
  second client. `--snippet NAME` and `--yes` run a command of the
  settings file on each host (see "Snippets").
- **No terminal, no input, no question.** Each session has no pty (`-T`)
  and reads no stdin (`-n`). `BatchMode` is on: an unknown host key
  refuses its host and gives its fingerprint and
  `-o StrictHostKeyChecking=accept-new`; a password is never asked. The
  keys that `accept-new` records go in one at a time, also within the
  process (T-029 covers two processes). A `SessionType` of `ssh_config`
  that asks for no command is refused (64), and so is a `node://` or
  `iroh:` destination; the forwards, X11 and the control socket of
  `ssh_config` are not used, and `-v` says so.
- **One relay token.** Through the relay, a token is read or minted once,
  before the hosts start, so that each host reads the one that the cache
  keeps: the relay sees one mint, not one for each host (it allows 120
  attempts with no token a minute for each address). With
  `PODSSH_CACHE_DIR=none`, each host mints its own.
- **The output.** The far output of each host goes through a sink in place
  of the process's streams (`podssh_ssh::io::Sink`): each line becomes
  `HOST: LINE` on stdout or stderr, as the host wrote it, and one writer
  puts each line whole, so that no host's line cuts another's; a line of
  more than 64 KiB comes in pieces, each with its label, and a last line
  with no newline gets one. podssh's own messages of a host are
  `podssh: HOST: ...`, each line of them, and a note or a warning that each
  host has is said once. With `--output-dir DIR`, the bytes go unchanged to
  `DIR/HOST.out` and `DIR/HOST.err`, and the status to `DIR/HOST.status` at
  the host's end; nothing of theirs goes to stdout. A byte of HOST other
  than a letter, a digit, `.`, `_`, `-` and `@` is `%XX` in a file's name,
  and two hosts whose files would differ only in case are refused (64).
  The files are made before anything connects (73 when they cannot be),
  with no status file left from an earlier run: a host with none did not
  run.
- **The exit status** is the largest status of the hosts: 0 only when each
  host gave 0, and 255 for a host that could not connect or log in, or
  whose session ended with no status. `--fail-fast` starts no new host after
  a failure (a status other than 0, or no session); the hosts that run end
  as they end. A summary on stderr gives each host and its status, or why
  it has none; `-q` leaves it out.
- A host's session is not tried again after a drop of the relay, as
  `ssh`'s is (T-025): the phase of a try is the process's, and many
  sessions share it.

### The broadcast: `--interactive`

`podssh each --interactive [OPTIONS] HOSTS` opens a shell on each host,
and sends each line that the user types to the hosts of the selection
(T-185, `crates/podssh-cli/src/each/broadcast/`). It is the line mode of
csshw and of the `synchronize-panes` of tmux, with no panes and no full
screen: podssh is a CLI (`docs/decisions.md`, Q6). A broadcast mistake
costs once for each host, so the broadcast has a stop that acts at once.

- **The shells.** Each host gets a shell with no pty (`-T`), on the road
  and the SSH client of `ssh`, as a command of `each` does; each host is
  open at the same time, 64 at most. A `RemoteCommand` of `ssh_config` is
  not used (`-v` says so), and a `SessionType` that asks for no shell is
  refused (64). A COMMAND, `--parallel`, `--fail-fast` and `--output-dir`
  are refused (64).
- **The local terminal keeps its normal mode.** Its own line discipline
  echoes and edits the line, and podssh reads whole lines. Each line goes,
  with a newline, into the queue of each selected host; the CR of a
  console's CR LF goes. The output of each host comes as `HOST: LINE`, as
  for a command, and podssh's own words come as `podssh: ...` on stderr.
- **The commands of podssh** are the lines that start with `:`: `:all`,
  `:none`, `:only HOST...`, `:list`, `:intr` and `:help`. A word of
  `:only` takes the braces and the groups of HOSTS, and names a host by its
  label, or by its label without `USER@`; a word that names no host
  changes nothing. A line that starts with `::` goes to the hosts with one
  `:` less.
- **The emergency stop** is a key that the terminal turns into a signal,
  so that it acts at once, also while a line is half typed: `Ctrl-\`
  (SIGQUIT) on Unix, Ctrl-Break (`CTRL_BREAK_EVENT`) on Windows. The
  terminal drops the line that is half typed. podssh then selects no host,
  and drops each line that waits in a queue, a line that waits for its
  second Enter, and what it read and did not act on yet; it says
  "broadcast stopped; :all starts it again". A line that a session has
  taken is sent: it is in the SSH channel, or it is the one line that the
  session sends now. The stop is armed before anything connects, also when
  SIGQUIT was ignored at the start (a script's `&` leaves it so); where it
  cannot be armed, podssh exits 78.
- **`--stop-key KEY`** moves the stop to another control key on Unix, as
  `^X` or `Ctrl-X` (T-322), for a user of dtach or abduco, which take
  Ctrl-\ for their own detach: the terminal's QUIT character is that key
  for the run, so the terminal still raises SIGQUIT and drops the half
  line, and the old character comes back on each way out. A key that the
  terminal keeps (INTR, EOF, SUSP, ERASE, KILL, the ends of a line) and
  anything but one control key are refused (64); so is the flag on
  Windows, where Ctrl-Break is the stop. The banner and `:help` name the
  key in effect. With stdin not a terminal there is no key, and the stop is
  `kill -QUIT`.
- **Ctrl-C goes to no host.** While the input goes on, podssh says what to
  type instead: `:intr` sends `signal INT` (RFC 4254, section 6.9) to each
  selected host, and a server may ignore it (`docs/terminal.md`, "Ctrl-C
  with no remote pty"). At the end of the input (Ctrl-D; Ctrl-Z on
  Windows), each shell reads what waits for it, then its end; Ctrl-C then
  cuts the hosts whose shell still runs, each with 130.
- **`--confirm`.** A line for more than one host waits for a second Enter
  (an empty line); another line drops it, with a word.
- **The queues.** Each host has a queue of 64 KiB: the lines that its
  session has not taken. A session takes a line only when it can send it,
  so a host that reads slowly fills its queue. A line that does not fit
  does not go to that host: the host leaves the selection, podssh names it,
  and the summary counts the lines that did not reach it. No byte that the
  user typed is dropped with no word.
- **The exit status** is the largest status of the shells, as for a
  command: 255 for a host with no session.

## Snippets

A snippet is a command that the settings file keeps, with placeholders for
the values that change (T-187, `crates/podssh-cli/src/snippets.rs`).
`podssh ssh --snippet NAME [user@]host [WORD...]` and
`podssh each --snippet NAME HOSTS [WORD...]` run it in place of a command.

- **The table.** After a line `[snippets]` of the settings file (below),
  each line is `NAME COMMAND`, or `NAME = COMMAND`. A name is as a group's.
  A command in double quotes, with none inside, loses them: a `#` that
  starts a word outside double quotes starts a comment, as in `ssh_config`.
- **The placeholders.** `{{host}}` is the host that podssh connects to,
  after `HostName` (OpenSSH's `%h`); `{{user}}` is the user; `{{port}}` is
  the port; `{{1}}` to `{{9}}` are the words after the host. The words must
  be as many as the highest `{{N}}`: a word that no placeholder takes would
  be a command of its own, and is refused (64). Blanks inside the braces
  are allowed. A `{{` that starts no name, as `{{.Names}}` of a Go
  template, is text, and `\{{` gives `{{`. An unknown name is the file's
  fault (78, with its line), as each bad line of the file is.
- **The quoting.** Each value goes in quoted for a POSIX shell, as one word
  that runs nothing: a value of letters, digits and `@%+:,./_-` as it is,
  else in single quotes, each `'` as `'\''`. A `=` and a `~` are quoted,
  as zsh and each shell read them first. A placeholder inside the
  command's own single or double quotes would undo the quotes of podssh,
  so the file refuses it (78), and a quote that does not close too. A
  template for another shell (cmd, PowerShell) must not put a placeholder
  inside its own quotes.
- **The question.** The command line is resolved as each one is; then the
  values go in, and the whole command is shown before anything connects:
  `the snippet NAME runs this on HOST:` and the command, each control
  character as its escape. podssh asks `Run it? [y/N]` on the terminal or
  through `SSH_ASKPASS`, and the question holds the command, as stderr can
  go elsewhere; only `y` or `yes` runs it. With `--yes` it runs with no
  question, and the command goes to stderr (not with `-q`). With nobody to
  ask (no terminal and no `SSH_ASKPASS`), or with `BatchMode`, and no
  `--yes`, the command is shown and the run is refused (64). Each other
  answer, Ctrl-D and a failed askpass program refuse it too (64). `-G`
  asks nothing and runs nothing.
- **`podssh each`** shows each host with its command, or the command once
  when it is the same on each host, and asks once for all the hosts,
  before a file of `--output-dir` is made. `BatchMode` in the
  `ssh_config` blocks of one host forbids the question.
- **The command line.** `--snippet` given twice, `--yes` with no
  `--snippet`, a name that the file does not have, and `-N`, `-s`, `-W` or
  `-O` with `--snippet` are refused (64), and so is a `SessionType` of
  `ssh_config` that asks for no command. `Match command` sees the command
  as written, with its placeholders. `--persist` and `--attach` refuse a
  snippet, as they refuse a command; `--sudo` and `--su` run it as root.
- The gate's `scripts/interop-snippets.sh` gives the values `a'b` and
  `x; touch MARK` to OpenSSH and Dropbear: each comes back unchanged, and
  MARK is never made.

## The host picker

`podssh ssh` with no destination is a usage error (64). When stdin and
stdout are both terminals, a person is there, and podssh first offers the
literal `Host` names of `ssh_config` (T-188,
`crates/podssh-cli/src/ssh/picker.rs`):

- The names come from the files that a run reads (`-F`, else
  `PODSSH_SSH_CONFIG`, else `~/.ssh/config` and the system's file), in
  their order, each once, and from each `Include` whose block holds for any
  host: outside each block, or after `Host *`. A pattern (`*`, `?`) and a
  negated name are not names, and `known_hosts` is not read, as its names
  can be hashed.
- Each name has a number. A number picks its name; other text narrows the
  list to the names that hold it, case set aside. An empty line, the end of
  input and a terminal that fails pick none (64). A number outside the list
  and a text that no name holds are said, and the question comes again, 20
  times at most.
- The name picked takes the path of a typed destination: its `Host`
  blocks, the relay or `--direct`, and the rest of the command line.
- With no name to list, or with stdin or stdout not a terminal, nothing is
  read, and the run refuses with 64 and `missing destination`, as before:
  a script still gets its usage error. A test that calls `dispatch::run`
  has no terminal, so it never sees the picker.

## `podssh containers`

`podssh containers [OPTIONS] [user@]host` lists the containers of a host,
each with the `podssh ssh` command that enters it (T-190,
`crates/podssh-cli/src/containers/`). It is a verb, not a form of the
destination: `node://` and `cf://` name a road to an SSH server, and a
container is a command on the server, which `podssh ssh -t HOST -- docker
exec -it NAME sh` already says in OpenSSH's words.

- **One login, one script.** podssh logs in as `ssh` does, through the
  relay or with `--direct`, with `-p`, `-l`, `-i`, `-o`, `-F` and `-J`, and
  runs one command with no pty: `sh -c 'SCRIPT'`, so that a login shell
  that is not POSIX (csh, fish) only starts `sh`. The script looks for
  docker, podman and kubectl with `command -v`, on the `PATH` of a command,
  and runs the list of each that it finds: `docker ps` and `podman ps` with
  the format `{{.Names}}`, and `kubectl get pods -o name` in the current
  context and namespace, with `--request-timeout=20s`. `--tool` asks one
  tool alone. A program runs only where the probe found it (AGENTS.md,
  section 5, rule 3): none here, and none there that `sh` did not find.
- **Marks.** A line `podssh-containers TOOL` comes before each tool's list
  on stdout and on stderr, `podssh-containers end TOOL STATUS` after it,
  and `podssh-containers done` at the end. Text before the first mark (a
  start-up file, a banner) is dropped; a list with no last mark was cut,
  and is not believed (69). The list waits 60 s at most, and podssh reads
  1 MiB of it at most.
- **Names.** A name is taken when it has letters, digits, `_`, `.` and `-`
  alone, a letter or a digit first, and 253 bytes at most, as Docker,
  Podman and Kubernetes name them; kubectl's has `pod/` first. Such a word
  is one word to each shell, so the command that carries it cannot be read
  as two. A name of another form is left out, and named on stderr (65).
- **The lines.** Each line on stdout is the tool, the name, padded, and
  `podssh ssh -t FLAGS HOST -- TOOL exec -it NAME sh` (`kubectl exec -it
  pod/NAME -- sh`), with the connection flags that were given; a value that
  is not one plain word is in single quotes. A tool that fails (no access
  to docker's socket, a cluster that does not answer) gives its lines of
  stderr, `podssh: TOOL: ...`, and its status; the other tools go on.
- **`--exec NAME`** enters NAME on the same connection, after the list:
  a password is asked once. The first tool, in the order docker, podman,
  kubectl, whose whole list holds NAME runs its exec with the program of
  `--shell` (`sh` by default; one word of letters, digits, `_`, `.`, `-`
  and `/`). `pod/` may be left out of a pod's name. With a terminal here,
  or with `-tt`, the session has a pty and the tool gets `-it`; with none,
  `-i` alone, as docker refuses `-t` when its input is not a terminal. A
  name that two tools list (docker and podman, or a `docker` that runs
  podman) is said on stderr, and `--tool` enters the other.
- **The exit status:** 0 when each tool gave its whole list; 65 when a
  name was left out; 69 when the host has none of the tools, one failed,
  the list was cut, or `--exec` names no container that a whole list has;
  255 when the connection or the login failed, or the list did not end in
  time. With `--exec`, the status of the session, as `ssh` gives it. A
  usage error is 64 before anything connects: a value of `--exec`,
  `--shell` or `--tool` that is not one, `--shell` or `-t` with no
  `--exec`, a word after the host, and a `node://` or `iroh:` destination.
  The forwards, X11 and the control socket of `ssh_config` are not used,
  and `-v` says so.
- `podssh pipe exec:` (T-174) carries the streams of `docker exec -i`, and
  Docker's contexts here are not used: they connect with OpenSSH, not with
  podssh.

## `podssh run`

`podssh run [OPTIONS] [user@]host[:DIR] [--] COMMAND...` copies a project to
a host, then runs a command in it, with the command's exit status (T-192,
`crates/podssh-cli/src/run_cmd/`).

- **The project** is the working directory, or `--from DIR`. The far
  directory is the DIR of `host:DIR` (a relative DIR, and `~/`, are under
  the home directory; `scp://[user@]host[:port]/DIR` works too), else
  `~/.podssh/run/NAME`, NAME the name of the project here. A parent that is
  not there is made, with mode 0700. The home directory itself and the root
  are refused (64). The connection flags are those of `ssh`, and the `Host`
  blocks of `ssh_config` apply.
- **The copy is that of `podssh cp -r -p`**
  (`crates/podssh-cli/src/cp/sync.rs`): each file to a temporary name,
  verified by its digest, then renamed, with its times kept; a new
  connection after a break, and a new relay session before its limits. It
  goes onto the far directory itself, also when the directory is there,
  and a file whose size and time of change (to the second) are the far
  file's is not sent again: a second run with no change sends no file. It
  goes over SFTP, as a directory of `cp -r` does. `target/`,
  `node_modules/` and `.git/` never go, at any depth, nor what the
  project's `.podsshignore` (a pattern a line, as the file of
  `--exclude-from`), `--exclude` and `--exclude-from` leave out. Nothing on
  the far side is removed. `-v` says the files sent and those not sent
  again: `DIR: files sent N, unchanged M`.
- **Then the command** runs on the same connection, as `podssh ssh` runs
  one: `cd 'DIR' && COMMAND`, DIR in single quotes for a POSIX shell, the
  words of COMMAND joined with spaces as OpenSSH joins them, with stdin and
  no pty. When the relay session has less than 16 MiB left after the copy,
  the command runs on a new session.
- **The exit status** is the command's, with the rules of `podssh ssh`;
  a copy that failed exits 255 and runs nothing. 64 and 78 come before
  anything connects.

## `podssh job`

`podssh job [OPTIONS] SUBCOMMAND HOST [ID [DIR]] [-- COMMAND...]` keeps jobs
on a far host that go on after the connection ends (T-193), and a queue of
them (T-197; `crates/podssh-cli/src/job/`).

- **The host** is a plain POSIX host, reached as `podssh ssh` reaches a
  destination, with the connection flags of `ssh` (`-p`, `-l`, `-i`, `-o`,
  `-F`, `-J`, `-v`, `-q`, `--direct` and the relay's) and the `Host` blocks
  of `ssh_config`. A `node://` or `iroh:` destination is refused (64).
- **Nothing of podssh runs on the host** but a POSIX sh script,
  `crates/podssh-cli/src/job/far.sh`. Each call sends it on the stdin of
  `sh -c 'INSTALL' sh MARKER ACTION ARG...`, and the host keeps it as
  `~/.podssh/jobs/jobs.sh`, mode 0600 in a directory of mode 0700: a new
  name, then a rename, so that a reader never reads half of it. The login
  shell, POSIX or not, only starts `sh`, and each word is one quoted word,
  as for the copy by exec of `cp`. The answer comes after a random marker,
  so that text which a login prints first is never read as an answer.
- **tmux holds each job.** tmux is probed, never assumed (`AGENTS.md`,
  section 5, rule 1), as for `--persist` (T-178). `start HOST -- COMMAND`
  makes the job's directory `~/.podssh/jobs/MILLIS-ID` (the time of the
  start in milliseconds, then 8 random hex digits), and starts
  `tmux new-session -d -s podssh-job-ID`, which runs the command in `sh`,
  in the home directory, with no input. The output and the errors go to the
  file `out` of that directory, and the exit status to `status` at the end.
  Then podssh prints the ID on stdout. With no tmux on `PATH`, `start` exits
  255 and names tmux, and nothing starts. The command must follow `--`, so
  that no word of it is read as a flag of podssh, and a command with a
  newline or a NUL has no word for a far shell (64 for each).
- `list HOST` prints a line for each job, in the order of their starts:
  the ID, the state (`queued`; `running`; `done`; or `lost`, when neither
  the job's tmux session nor its status is there, as after a restart),
  the exit status (`-` while there is none) and the command. `log HOST ID`
  writes the job's output to stdout as it comes, also after the job's end.
  `stop HOST ID` ends the tmux session of that exact name,
  `-t =podssh-job-ID`, never one whose name only starts so, and removes the
  job's directory with its output.
- **The queue lives on the far host** (T-197), so that the client can stop
  at any time and needs no listener to wait (`docs/decisions.md`, Q7: no
  logic of GPUs and no list of devices; the slots are the only limit).
  `submit HOST -- COMMAND` makes the job's directory with the state
  `queued`, and starts the runner, `tmux new-session -d -s podssh-runner`,
  unless one runs: the name of the session is the lock, so that no second
  runner starts. The runner, the far script itself, starts the oldest
  queued job (the names sort by the time of the submit) while fewer jobs
  run on the host than the slots, and checks again each second; with
  nothing queued and nothing running, it gives its name up, looks once
  more, and ends, so that a submit at that moment starts a runner of its
  own. `--slots N` (1 to 64) sets the slots, which stay for the next
  submits; 1 until one sets them. A job of `start` runs at once, and counts
  against the slots. A list or a state that finds a queued job and no
  runner, as after a restart of tmux's server, starts one.
- **A list of hosts for `submit`**, with the braces and the groups of
  `podssh each` (T-184): one `list` of each host gives its jobs queued or
  running, the host with the fewest gets the job, the first of the list on
  a tie, and stdout gives `HOST ID`. A host that does not answer is left
  out, and said; with none, nothing is queued (255).
- `wait HOST ID` reads the job's state every 5 s, each read a call of its
  own, and exits with the job's status, or 255 for a job that is lost.
  After a lost connection it connects again, 5 times in a row at most,
  with the backoff of the relay opener; a host that does not answer the
  first connection is 255 at once. `--timeout DURATION` exits 75 when the
  job has not ended by then; the job runs on.
- `fetch HOST ID [DIR]` copies the job's output to `DIR/out`, as `podssh cp`
  copies a file (over SFTP, or by exec; a temporary name, the digests, a
  rename; a new connection after a break), and with `--files GLOB` each
  regular file of that pattern of sh, in the home directory of the host, to
  `DIR/files` by its path. DIR is `./podssh-job-ID` by default. A pattern
  with an absolute path or a `..` is refused (64), and so is each path that
  has no place under `DIR/files`. A job that is queued or running is not
  fetched, as its output is not whole yet (75). `list --json` gives one
  JSON object: `host`, and `jobs`, each with `id`, `state`, `status` (null
  while there is none), `started_ms` and `command`.
- **The exit status** is that of `podssh ssh`: 0; 64 for a usage error and
  78 for a setting, before anything connects; 255 when the host cannot be
  reached or logged in to, has no tmux, has no job of that ID, or gives no
  answer. `wait` gives the job's status; 75 when its `--timeout` passed,
  and when `fetch` finds the job queued or running.

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
- **A node of a pair** (T-296): `node://[user@]NAME[/ROUTE]:path` is the
  node of the pair under the label NAME, reached through its pair as
  `podssh ssh node://NAME` reaches it (`crates/podssh-cli/src/ssh/node.rs`,
  `reach`): the operator's leg, the resumable layer when the node offers
  it, the end-to-end channel, and the host key under `node://NAME`. The
  path comes after the first `:` after the name, as a `/` there names a
  route (T-089); with no `:`, it is the login directory. `--pair-file`,
  `--client-key`, `--node-key` and `--no-e2e` are those of `ssh`. A port,
  `-J` and `--direct` cannot reach a node, and exit 64 before anything
  connects. The session carries no relay budget of its own: the layer
  moves it to a new leg before the relay's limits (T-155), and a node in
  plain mode that the relay cuts is a broken connection, which the copy
  goes on after. `scp` and `mv` take the same operand, and `sftp` the
  destination `node://[user@]NAME[/ROUTE][:path]`.
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
- **Requests in flight** (T-140): on the SFTP road, the reads and the
  writes of a copy go with up to 64 requests in flight, each of the
  server's size (`limits@openssh.com`, else 32 KiB), and never more than
  512 KiB in flight, the window that podssh gives a server: of OpenSSH's
  255 KiB, two. Replies may come in any order; each block is written in
  the file's order, so a copy that breaks goes on from the end of the part
  that the server acknowledged, and a short read is asked again for its
  rest. No reply within 60 s of the last one is a failure. The second read
  of a far digest goes the same way. `-v` says the size and the requests
  of each copy, and its rate before the digest. `scp -X` and `sftp -R`,
  `-B` and `-X` set them.
- **`--parallel K`** (T-141): a file of more than one chunk of 8 MiB goes
  as chunks at fixed offsets, K at once (1 to 16; default 1), each over an
  SFTP session of its own, so a channel and a window of its own, in the one
  connection; each writes its chunks into the temporary file at their
  offsets. The side file keeps the chunks that are done, so a copy that
  breaks goes on with the others. The digest covers the whole file after
  the last chunk, and nothing is renamed before it. Through the relay the
  tasks share 1.5 MiB in flight, below the 2 MiB queued that close a
  session, and a task takes a chunk only while the session may carry it
  whole. The copy by exec goes in one stream, and `-v` says so.
- **Several files with `--parallel K`** (T-297): the sources of the command
  line, and the files of a tree with `-r`, go K at once, each over an SFTP
  session of its own in the one connection; the connection's own session
  is one of the K. A server that opens fewer sessions gets fewer files at
  once, and `-v` says so. Each file goes as one copy goes: its temporary
  name, its side file, its digest and its rename. A file of more than one
  chunk waits, and goes after the others, alone, in chunks. A broken
  connection ends the files in flight where they are; the next connection
  goes on with each from its side file, at most 5 times in a row with no
  new byte, as for one file. Through the relay the files share 1.5 MiB in
  flight, as the chunks do. The report keeps the order of the sources, and
  the exit code is that of the first failure in that order. `mv` removes
  each source after the copies. The copy by exec goes one file at a time.
- **`--delta`** (T-142): over an older version of the same file on the
  other side, only the blocks of 1 MiB that changed go. The SHA-256 of each
  far block comes from one command over exec (`dd` into `sha256sum`,
  `shasum` or `openssl`), that of each local block is read here. The
  temporary file is made from the old one where it is (`copy-data` inside
  the server for a copy up, a copy on this disk for a copy down), only the
  blocks that differ cross, and the size is set. The digest of the whole
  file then decides: a difference falls back once to a full copy, and says
  so. A server with no command, no `dd`, no digest tool, or for a copy up
  no `copy-data`, gets a full copy, and `-v` says why; `-v` says the blocks
  sent and their bytes. A copy that broke goes on in full where it was. The
  full copy stays the default.
- **`-r`** (T-143) copies a directory and what it holds, depth first with
  `lstat`, 64 levels at most: each file as one copy goes (a temporary name,
  the digest, the rename), each symbolic link as a link, and a device, a
  FIFO or a socket skipped with a note; a directory gets its mode after its
  files. `scp -r` follows links, as OpenSSH's does, and refuses a loop.
  Each name that a far listing gives must be one component: `.`, `..`, a
  `/` or a NUL, and here on Windows a `\`, a `:`, a device's name or a
  trailing dot or space, are refused (70), so nothing is written outside
  the target. Into a directory that exists the copy goes under it, with the
  source's name; else it is the destination. An item that fails is
  reported, the rest goes on, and the exit is not zero. `--exclude PATTERN`
  (repeatable; `*` and `?` within a name; with a `/`, from the root of the
  copy) and `--exclude-from FILE` (a pattern a line; `#` starts a comment)
  leave paths out; `--dry-run` says each action (`mkdir`, `copy`, `link`,
  `skip`; with `--jsonl` an object each) and changes nothing. `mv -r`
  removes the source once each item of it is copied. A directory goes up or
  down, over SFTP, not between two servers.
- **What a copy keeps** (T-146, `crates/podssh-cli/src/cp/meta.rs`): the
  source's permission bits always. `-p` keeps the access and the
  modification times too (`scp -p`, `sftp -p`, `get -p` and `put -p` as
  well), and with `-r` each directory's, set after its files; `--owner`
  keeps the owner and the group by number where the side that writes may
  give a file away (root), and says once where it could not. Each is set
  on the temporary file before the rename; a side that refuses the mode or
  the times fails the copy, and the destination stays as it was. Where a
  server's rename changes the times (Cygwin's sets the access time), they
  are set once more after it. A block of 64 KiB of zeros, aligned in the
  file, is a hole, never sent, and the size is set at the end: up when the
  source has holes (fewer blocks than its size, or the sparse attribute on
  Windows), and both ways with `--sparse`; not with `--parallel` or
  `--delta`, which may write a block again. Within one `-r` upload, two
  names of one file (one device and inode; on Windows one volume and file
  index) arrive as one file with two names, by `hardlink@openssh.com`, else
  as two files, said once. SFTP
  version 3 carries the times in whole seconds from 1970 to 2106 and no
  inode, extended attribute or ACL: those, a far source's hard links, and
  the owner on Windows are not kept.
- **`--inplace`** (T-147, `crates/podssh-cli/src/cp/in_place.rs`) writes
  into the destination itself, with no temporary name and no rename: the
  file keeps its inode, so its other hard links and each program that
  holds it open see the new bytes, no second copy needs room, and no name
  is added to its directory. It is opened with no truncation, written, and
  cut to the source's size; the digests are compared as for each copy.
  podssh says first, on stderr, that a copy that fails leaves its
  destination damaged, and each failure after the first write names the
  destination as damaged (a mismatch exits 70). A destination that is a
  symbolic link or a directory is refused (64), here before anything
  connects. A copy that broke goes on at its offset in the destination;
  with `--delta` only the changed blocks are written into it, and no
  `copy-data` is needed; `mv` removes the source only after the check. By
  exec, the first attempt writes with `cat >` (a truncation keeps the
  inode) and a later one appends. No holes are made in place.
- **Progress, an interruption and a limit** (T-145). On stderr, when it is
  a terminal and `-q` is not given, one line that a carriage return
  rewrites, 4 times a second at most: the name, the bytes of the total,
  the percent, the rate and the time left; nothing in a pipe
  (`PODSSH_PROGRESS=line` or `off` sets the line on or off). With
  `--jsonl`, a `progress` object on stdout each second, before the `done`
  one. The first SIGINT or SIGTERM (Ctrl-C on Windows) ends the copy in
  flight, keeps the temporary file and its side file, names them, and
  exits 130; the same command then goes on from them; a second signal ends
  podssh at once. `-l LIMIT` (`cp`, `mv`, `scp`, `sftp`) is OpenSSH's, in
  Kbit/s: a token bucket before each request, requests of 10 s of bytes at
  most, and about one second of them in flight.
- **`--delete`** (T-144), with `-r`, makes the copy's root a mirror: what
  it holds and the source lacks goes, a directory after what it holds, at
  the end of the run and only when each copy of the run succeeded; after a
  failed copy nothing goes, and stderr says so. An excluded name never
  goes, nor the file that a link names (the link goes). A root of a file
  system and the home directory are refused as the root (64). `--dry-run`
  lists each `delete`; at the end stderr gives the number of deletes, and
  `-v` and `--jsonl` give each one.
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
  portable command reads the far file's mode; with `-p` or `--owner`,
  `stat` gives it (GNU's and BusyBox's `-c`, else BSD's `-f`), where the
  server has one. Up, `chown`, `chmod` and `touch -t` (in UTC) set what a
  copy keeps on the temporary file before `mv`. A copy within one server
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
- **The requests in flight and their size** (T-140): `sftp -R COUNT` and
  `-B BYTES`, and `-X nrequests=COUNT` and `-X buffer=BYTES` of both, as
  OpenSSH reads them (`K`, `M` and `G` scale a size; the last of each
  wins). A count is 1 or more, and a size 1 to 256K bytes; out of range is
  a usage error (64) that names the flag. podssh keeps 64 requests and 512
  KiB in flight at most, and the size within the server's limit.
- **A URI operand**, `scp://[user@]host[:port][/path]` (or `sftp://`), is
  read as OpenSSH's `parse_uri` reads it: the path after the first `/` is
  under the login directory, `//` makes it absolute, the user and the path
  are percent-decoded, and the port is that operand's own. `cp` and `mv`
  take URIs too.
- **A node of a pair** (T-296): an operand of `scp`,
  `node://[user@]NAME[/ROUTE]:path`, and a destination of `sftp`,
  `node://[user@]NAME[/ROUTE][:path]`, reach the node as `cp` reaches it;
  `-P`, `-J` and `--direct` with a node exit 64.
- **No `--timeout`**, as OpenSSH's have none; each wait of a copy has its
  own limit. Usage errors are 64 where OpenSSH gives 1.
- **`sftp -b FILE`** (`-b -` for stdin) runs each line in order and prints
  it first; `@` before a command keeps the line from being printed, and `-`
  keeps its failure from ending the batch. Else, on a terminal, `sftp`
  asks at a prompt; with no terminal and no `-b` it refuses (64). A
  destination whose path names a file fetches it and ends.
- The commands: `get` and `put` (`reget` and `reput` are the same: a copy
  that broke goes on by itself; `-p` keeps the times, as `sftp -p` does
  for each), `rename`, `rm` (with `*` and `?` in the
  last name), `mkdir [-p]`, `rmdir`, `ls [-la]`, `cd`, `lcd`, `pwd`,
  `lpwd`, `chmod`, `df [-hi]` (`statvfs@openssh.com`), `help`, `version`,
  and `bye`. The local commands (`lls`, `lmkdir`, `!command`) and `ln`,
  `chown`, `chgrp` are refused by name.
- **`get -r` and `put -r`** (or `-R`; each `get` and `put` after `sftp
  -r`) copy a directory with T-143's walk, its checks of names and its copy
  of each file (`crates/podssh-cli/src/cp/tree_conn.rs`): each link as a
  link, a device, a FIFO or a socket skipped with a note, each directory's
  mode (and with `-p` its times) after its files, and a name of a far
  listing that is not one component refused. Into a directory that exists
  the tree goes under it, with its own name; else it takes the name given.
  The batch prints its line once, as for one file; an item that fails is
  said, the rest goes on, and the command fails at its end with the first
  failure's code. Each file goes over the batch's session, as a `get` or a
  `put` does: a broken session ends the command, and no side file is kept.
  Several sources that a pattern names (`get -r dir*`) each go under the
  local directory, with their own names.

## `podssh edit`

`podssh edit [user@]host:PATH` changes one file of a server in an editor
here (`crates/podssh-cli/src/edit/`), with the connection flags of `cp`
and no `--timeout`: a person decides how long an edit takes.

- **The fetch** is the copy down of `cp` (a temporary name, the digests, a
  rename; a new connection after a break), into a new directory of mode
  0700 in the cache directories (`edit-RANDOM`), as a file of mode 0600
  with the far file's name, so that the editor knows its kind by its name
  or its extension; a name that this system cannot hold becomes `file` with
  the extension. podssh records the far file's size and time of change (by
  exec, the line of `ls -lnid`), its SHA-256 and its mode.
- **No session while a person edits.** The connection closes before the
  editor starts: no relay session waits, so its idle limit (180 s) and its
  12 h cap cannot end an edit, and a lost link costs nothing. The second
  connection meets the first one's host key and logs in as the first did,
  with no second question (T-136, T-137).
- **The editor** is `VISUAL`, else `EDITOR`, else `vi` when a probe finds
  it on `PATH` (`AGENTS.md`, rule 3); with none, the exit is 78 and the
  message names `EDITOR`. A value is a program and its words, split at
  blanks with no shell, or one program whose path has a blank. The editor
  runs on this terminal: `edit` needs a terminal on stdin and stdout (else
  64, checked after the editor's choice, so that a test with no terminal
  reaches both refusals). While it runs, SIGINT and SIGQUIT are ignored
  here (on Windows a listener holds Ctrl-C), so the keys are the editor's.
  An editor whose program returns while its window stays open leaves no
  change when it returns, and the copy goes: give it its flag to wait, as
  `code --wait`.
- **The check before the send.** A copy whose SHA-256 did not change sends
  nothing (exit 0). Else a new connection compares the far file with the
  record: its size and time of change (by exec, the line of `ls -lnid`),
  then its SHA-256 (`sha256sum` over exec, else a second read), as a write
  in the same second keeps the size and the time. When the far file
  changed, nothing is sent and the exit is 73: a change made there is never
  overwritten. The check and the rename are a moment apart; no lock of
  SFTP version 3 closes that moment.
- **The send** is the copy up of `cp`, with the far file's mode on the
  temporary file before the rename, so the name never has another mode.
  `Shape::mode` carries it to both roads; without a mode from the server,
  the file gets the copy's mode, and podssh says so.
- **A symbolic link stays a link**: over SFTP, `lstat` finds it and
  `realpath` names the file that the edit changes; by exec, where no
  portable command names that file, a link is refused (66).
- **The copy here** goes after a success. After a failure it stays and is
  named when it holds a change, and goes when it holds none. An editor that
  ends with a status other than 0 sends nothing, and `edit` exits with that
  status (128 + N for signal N). The first SIGINT or SIGTERM while a file
  moves ends the run with 130: during the fetch nothing stays here; during
  the send the copy stays, named, with the far side's partial copy.

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
  by the form of a banner. The lines `listen AF_INET` and `listen AF_UNIX`
  bind a socket (127.0.0.1 port 0; a file of mode 0600 in the temporary
  directory, and on Linux an abstract name), listen once with a backlog of
  1, accept nothing and close it at once; each says what the bind and the
  listen did, and which listeners of podssh can or cannot listen here (`-L`
  and `-D` on a port or a path, `pipe tcp-listen:` and `unix-listen:`, the
  control socket of `-M`, `podssh agent` and `podssh session`). A refusal is
  `ok`: no road needs a listener. With `PODSSH_LISTEN=no` no listen is
  tried, and the line says so. Proxy credentials and tokens are never shown.
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
- Each probe that connects (each `CONNECT`, and `direct TCP`) is tried nine
  times, 125 ms apart (GitHub #54, T-324): one time cannot tell a path that
  refuses from one that was slow, nor a steady path from a lossy one. The
  line gives the best time (the floor), the median, the 95th percentile, the
  jitter (the median change from one try to the next) and the loss, the
  timeouts and the other breaks counted apart; a refusal is an answer, not a
  loss. `--json` gives the same as `samples`. A first try that timed out is
  not repeated, a later try waits four times the first try's time (3 s to
  8 s), and none starts that could end more than 10 s after the first: a path
  that does not answer never holds `doctor` for minutes. Only the probes of
  TCP are sampled: the relay's `/health`, its upgrade and the SSH handshake
  stay one each, as each is a request to the relay's Worker and a session
  to GitHub.
- A forward session whose upgrade fails names one of three failures, each
  with its own way out: an answer other than `101` (its status and its text:
  the relay or a hop refused), a `101` whose `Sec-WebSocket-Accept` is not
  the one of the request's key (something between answered in the relay's
  place), and a valid `101` after which the connection ends with no Close
  (something between drops the stream after the upgrade). A Close from the
  relay is the relay's own end, with its code and its reason.

## `podssh status`

`podssh status [--relay-host HOSTS] [--relay-addr HOST=IP] [[user@]host]`
writes one line of JSON and exits 0 (GitHub #11). It is the cheap call
before anything else; `podssh doctor` is the report that measures.

- The line: `schema`, `podssh`, `relays` and `relays_from`, `settings`
  (the path of podssh's settings file, or null), `pool`,
  `token` (its source, the relay that it is for, its expiry, whether it can
  be used), `proxy` (the variable, `HOST:PORT` and the kind, `http` or
  `socks5`), `offline`, `attachment`, `stdin_tty`, `stdout_tty`,
  and `host` for a destination (its name in `known_hosts`, whether a key is
  recorded, the key types); `session_log` (T-056) and `relay_failures`, the
  relay hosts that each run tries last now, with `ago_s` and the `reason`
  (T-059).
- It never holds a token: it reads the cache entry without its token field
  (`cache::peek`). It shows no proxy credentials, opens no connection, asks
  no DNS and writes nothing.
- A bad flag or destination is 64, a bad variable 78, as for `doctor`.

## `podssh ping`

`podssh ping [OPTIONS] [[user@]host]` is a short check of the path (T-053,
GitHub #23): the time of each step, the round trip, and the throughput.

- With no destination, the relay leg of each relay host: the token (from
  `PODSSH_RELAY_TOKEN`, the cache, or minted), DNS and TCP or CONNECT
  through the proxy, TLS, and the WebSocket upgrade, which the relay
  answers once it reached the target, each with its time; then `--count`
  WebSocket pings (10 by default, at most 100), each with its sequence and
  its send time in its payload and matched to its pong, as the minimum,
  p50, p95 and maximum. A ping with no pong in 5 s is lost; a leg with no
  pong at all fails.
- The leg's target is `--target HOST:PORT`, else `github.com:22`, the
  reference that `podssh doctor` reaches too. It is never the destination:
  its server would see a connection that sends no SSH bytes, and OpenSSH's
  `PerSourcePenalties` (9.8 and later) count those against the relay's
  address, which other users share.
- With a destination, the run is resolved as `podssh ssh` resolves it
  (`ssh_config`, `-J`, `-i`, `-o`, `--direct`). Through the relay, the legs
  come first; then the time to log in (through the pool and the failover of
  `ssh`, with the relay's steps to the destination), the echo of one byte
  at a time through `cat`, `--count` times after one that is not counted
  (the first can wait for the shell to start `cat`), and the throughput
  down with `head -c SIZE /dev/zero` and up with `cat > /dev/null`, each
  line naming its command. These programs are an assumption about the host, so they
  run only for a destination.
- `--size` is 8 MiB each way by default, and at most 30 MiB, so that both
  ways stay under the relay's 64 MiB for one session (`docs/relay.md`).
- Each step has a limit: 20 s for a step to the relay, 60 s for a wait of a
  measure, and 600 s for the whole run. A program that the host lacks ends
  the run with its status (127), never with a hang, also when the status
  comes before the server's reply to the command.
- `--json` writes one JSON object when the run ends, in the shape of
  `doctor --json`: `schema` (1), `podssh`, `count`, `size`, `relays` (each
  with its steps in milliseconds, `pings` with `min_ms`, `p50_ms`, `p95_ms`
  and `max_ms`, `pings_lost` and `error`), `destination` and `exit`.
- 0 when the path works: a relay host gave its measures, or each measure
  through the destination has its number. 64 for a bad flag, before
  anything connects; 69 when no relay host answered, or with
  `PODSSH_OFFLINE`. With a destination: the code of `podssh ssh` when it
  cannot be reached or logged in to, the status of a remote program that
  failed, and 255 for a measure that broke.

## `podssh health`

`podssh health [OPTIONS] [user@]host` gives the facts of the far host
(T-189): its load and CPUs, the busy share of the CPUs, its memory and
swap, its uptime, the bytes of each network interface, the use of its
disks, and its processes. It only reads: it never stops or changes a
process.

- The host is resolved, reached and logged in to as `podssh ssh` does it
  (`ssh_config`, `-J`, `-i`, `-o`, the relay or `--direct`). Then one exec
  runs a fixed script, as `sh -c 'SCRIPT' sh`, so that a login shell of
  fish or csh only starts `sh`. No text of the user goes into the script.
- The script reads `loadavg`, `uptime`, `meminfo`, `stat` and `net/dev` of
  `/proc` with the shell's `read`, and counts the processes with a glob of
  the shell. It runs `sleep 1` and a second read of `stat`, `uptime` and
  `net/dev` only where `command -v` finds `sleep`, and `df -P -k` of the
  root and the home only where it finds `df`: a host with neither gives no
  rate, no busy share and no disk, and the other facts.
- The available memory is the kernel's `MemAvailable`. A kernel before
  3.14 has none: then the free memory, the buffers and the cache stand for
  it, and the line and the JSON say that it is an estimate. The rates are
  the difference of two samples over the seconds between them, by the
  host's own `/proc/uptime`. A name that the host gives (an interface, a
  mount, a file system) has the controls of a terminal taken out.
- A host with no `/proc` gives the name that `uname -s` prints (when it has
  `uname`) and "no facts for this system", with exit 0.
- One line for each fact on stdout; with `--json`, one JSON object, also
  after a failure, in the shape of `doctor --json`: `schema` (1),
  `podssh`, `destination`, `system`, `load`, `cpus`, `cpu_busy_percent`,
  `interval_s`, `memory` (in KiB, with `available_estimated`), `uptime_s`,
  `network` (each `interface` with `rx_bytes`, `tx_bytes`, `rx_per_s` and
  `tx_per_s`), `disks`, `processes`, `error` and `exit`.
- The exit codes of `podssh ssh`: 0 with the facts; 255 when the host
  cannot be reached or logged in to, has no `sh`, or gave none of the
  script's lines; 64 and 78 before anything connects. The script has 30 s,
  and the whole run 120 s.

## `podssh keygen`

`podssh man keygen` gives the flags. The rules behind them:

- The `ssh-keygen` of OpenSSH does not run without a user database entry,
  so podssh makes keys itself, in the formats of OpenSSH.
- A new key is never written over an existing file.
- Only its owner may open the private key: mode 0600, and on Windows an
  access list of its own for the user, SYSTEM and the Administrators, with
  nothing from the directory above, as OpenSSH's `ssh-keygen` makes it;
  OpenSSH for Windows refuses a key that others may open. Each may read
  `FILE.pub`, and only its owner may change it (mode 0644; on Windows,
  Everyone reads it). A missing directory is made private (T-288).
- `-p` changes the passphrase of the key in `-f FILE`, and `-c` its comment,
  in the key and in `FILE.pub` (T-018). The file is replaced only with the
  same key: the new text goes to a new private file beside it, which is
  read back, opened with the new passphrase and compared by its public
  key, and only then renamed over the file. No copy of the old file is
  kept: it holds the key under the passphrase that the user wants gone.
- `-p` and `-c` read each format that `podssh ssh -i` reads, and write the
  format of OpenSSH, as `ssh-keygen -p` does. Measured with keys that
  OpenSSH's `ssh-keygen -m` made: PEM (RSA, also encrypted, and ECDSA) and
  PKCS#8 became keys of OpenSSH with the same public key, and so did the
  keys of PuTTY. An encrypted key of each format is asked for (T-287).
- A passphrase given with `-N` or `-P` is refused (exit 64), because each
  process on the host can read a command line. `-N ''` and `-P ''` are
  accepted. With no terminal and no `SSH_ASKPASS`, podssh refuses at once
  and names `-N ''` (and `-P ''` for `-p` and `-c`); it does not wait.
- `-F HOST`, `-R HOST` and `-H` find, remove and hash the lines of a
  `known_hosts` file (`-f FILE`, else `~/.ssh/known_hosts`), with the lines
  and the messages of OpenSSH's `ssh-keygen` (T-019); a host on another port
  than 22 is `[HOST]:PORT`. `-R` and `-H` keep the old text in `FILE.old`,
  and put the new one in place whole, under the lock of `podssh ssh`: a run
  that waited for it meanwhile writes its line to the new file. Each line
  that is not changed stays byte for byte. Two calls differ from OpenSSH's,
  so that nothing is lost: `-R` keeps a line that names the host through a
  wildcard, as its key is for other hosts too, and says so; and a line that
  is no line of a host key stays as it is, where OpenSSH refuses to rewrite
  the file.
- `-Y sign`, `verify`, `check-novalidate`, `find-principals` and
  `match-principals` make and check SSH signatures (PROTOCOL.sshsig) as
  `ssh-keygen -Y` does, with its lines and messages (T-020); git's signing
  with SSH keys calls them. `sign` signs each FILE to `FILE.sig`, never over
  one, or standard input to standard output; the agent signs when it holds
  the key of `-f` (with `-U`, the agent alone), else the private key in
  `-f`. An RSA key signs with SHA-512 through aws-lc-rs. `verify` reads an
  allowed-signers file with its `namespaces=`, `valid-after=` and
  `valid-before=`, and a failure exits 1 where OpenSSH exits 255; `-r`, a
  revocation list, is refused.
- `-Y sign -f KEY-cert.pub` signs with a certificate, as OpenSSH's does:
  the private key is KEY (the path without `-cert.pub`, or `.pub`), or the
  agent's, and the signature carries the certificate (T-289). `-f KEY`
  signs with the plain key even when `KEY-cert.pub` is beside it, as
  OpenSSH reads `KEY.pub` there. A `cert-authority` line of the allowed
  signers allows such a signature when its key is the certificate's CA and
  the certificate is a user certificate, valid at the time (or
  `-O verify-time=`), that lists the principal of `-I` (with no wildcard);
  a refusal says OpenSSH's `FILE:N: certificate not authorized: REASON`.
  A plain line of the key does not allow it, and a `cert-authority` line
  allows no plain signature, as OpenSSH compares the types.
  `find-principals` prints the principals of the certificate that the
  line's patterns match, `check-novalidate` and `verify` name the key
  `ED25519-CERT` (or the type's), and `-O print-pubkey` prints the
  certificate. As in OpenSSH, the critical options of the certificate are
  not read: they restrict a login, not a signature.
- `-s CA -I ID` certifies each FILE, a public key, into `FILE-cert.pub`
  (PROTOCOL.certkeys), and `-L` prints a certificate, with the lines and the
  messages of `ssh-keygen` (T-021): `-n` the principals, `-V` the validity
  (`+52w`, or FROM:TO of `+TIME`, `-TIME`, `YYYYMMDD[HHMM[SS]][Z]`, `always`
  and `forever`), `-z` the serial, `-h` a host certificate, `-O` its
  options (`clear`, the `permit-` and `no-` flags, `force-command=`,
  `source-address=`, `verify-required`, `extension:` and `critical:`), `-U`
  a CA in the agent, and `-t rsa-sha2-256` the signature of an RSA CA
  (SHA-512 by default, through aws-lc-rs). As OpenSSH does, a certificate
  replaces the one that is there: it is public, and made again at each
  renewal. A failure exits 1 where OpenSSH exits 255; `-D` (PKCS#11) is
  refused.
- `-e` prints a public key in the format of `-m`: RFC4716 (the default),
  PKCS8 or PEM; `-i` reads one and prints it as a line of OpenSSH; `-m PEM`
  or `-m PKCS8` with a new key or `-p` writes the private key in that format,
  encrypted as OpenSSH encrypts it (T-022). An Ed25519 key has a form of
  RFC 4716 only: `-e` refuses the others by name, and a new key or `-p`
  keeps OpenSSH's format and says so, as `ssh-keygen` writes it. `-i`
  imports public keys only: podssh never prints a private key. `-y` and
  `-l` read a key in each format that `podssh ssh -i` reads, and ask for its
  passphrase.
- `-t ed25519-sk` and `-t ecdsa-sk` make a key in a security key (FIDO2),
  as OpenSSH's `ssh-keygen` does (T-229). The device keeps the key; the
  file holds the device's handle of it, the application and the flags, in
  the format of OpenSSH (PROTOCOL.u2f), and needs the device for each
  signature. `-O resident`, `-O verify-required` (the device's PIN at each
  use), `-O no-touch-required`, `-O application=ssh:NAME` and
  `-O user=NAME` are those of `ssh-keygen`; `-O device=PATH` names a
  device on Linux. `-O challenge=` and `-O write-attestation=` are
  refused: podssh keeps no attestation of the device. The probe comes
  first: with no device that podssh may reach, `keygen` names the reason
  and exits 1, before it asks a passphrase or writes a file. See
  "Security keys" below.
- DSA is refused, because OpenSSH 10 removed it.
- An RSA key is made by aws-lc-rs, whose RSA is constant-time, never by the
  `rsa` crate, whose private-key operations are not (RUSTSEC-2023-0071, the
  Marvin attack): 2048, 3072 (the default), 4096 or 8192 bits, the sizes
  that aws-lc-rs makes (T-257).
- The comment comes from the environment, never from the user database.

### Security keys

A key of a security key (`sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com`) signs in its FIDO2 device: the key
never leaves it, and each signature needs a touch (T-229). podssh makes
such a key (`podssh keygen`), signs a login with its file (`podssh ssh -i`,
and the default files `id_ecdsa_sk` and `id_ed25519_sk`), and holds one in
`podssh agent`. Each use probes the way to the device first, and never
assumes one:

- On Linux, podssh speaks CTAP2 over the kernel's raw HID devices,
  `/dev/hidraw*`, in its own code: the framing of CTAPHID, CBOR, and the
  PIN protocol one. The probe keeps the devices whose report descriptor is
  a FIDO device's, read in sysfs, else from the device, and that this user
  may open; most systems give that access through a udev rule
  (`TAG+="uaccess"`). A device that speaks U2F only (CTAP1) is refused.
  With several devices, `keygen` asks for one (`-O device=PATH` or
  `PODSSH_SK_DEVICE`), and a signature goes to the device that holds the
  key, which each device tells at once with no touch.
- On Windows, podssh asks the WebAuthn API of the system (`webauthn.dll`,
  of Windows 10 1903 and later), loaded at run time; Windows shows its own
  dialog for the touch and the PIN, and needs no right of an
  administrator. A session with no window for that dialog is refused.
- On each other system (macOS among them) podssh has no way to the device
  and says so; a key that an agent holds (OpenSSH's `ssh-agent`, with its
  own helper) still signs through the agent.
- A device has 30 s for an operation, the touch included; then podssh
  cancels it and says that nobody touched the key. The touch is no
  question: `BatchMode` does not stop it, and forbids only the question of
  the PIN of a key made with `verify-required`. The time of the device
  does not count against `ConnectTimeout`. The server is asked first
  whether it takes the key, so a key that it does not take asks for no
  touch.
- With no device, a login skips the key before the server sees it: `-v`
  says why, and so does the message of a login that fails. A device that
  does not sign (no touch, a wrong PIN) lets the next key go on.
- `PODSSH_SK_DEVICE` names the device on Linux (a path of
  `/dev/hidraw*`); `none` turns security keys off on each system.
- The signature that podssh sends is OpenSSH's (PROTOCOL.u2f): the
  device's signature, then the flags and the counter that the device
  signed. The tests check it against signatures that OpenSSH made, the
  vectors of ssh-key 0.7.0-rc.11.

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
- **The relay's own state, with nothing but the binary (T-058).**
  `relay status` with no NAME asks each relay host for its `/health`, one
  after the other, a line for each as it answers (the code that `doctor`
  uses, in `podssh-relay`): 0 when a host answered, 69 when none did.
  `relay info [HOST PORT]` reads the first host's `/relays.json`: the edge
  that this host reaches, the pool best first, the limits, and with a
  target the URL that the relay chooses for it. `relay trace HOST PORT`
  asks the first host to dial the target and read its first line: the
  verdict, the address dialed, the times and the banner, cleaned to one
  line. The token goes in `X-Relay-Token`, never in the URL, and a cached
  token that the relay refuses is minted again once. The target is checked
  first, so no text can add a query parameter. 0 when the trace ran, 69
  when the relay would not dial the target (a blocked range, a name with
  no address), 77 when it refused the token. On the relay's VPC road a
  closed port also connects, so the verdict (`live`, or
  `silent-or-unreachable` for a target that sent nothing) is the answer,
  not the connection. The caller's address and place, which `/trace` also
  sends, are never shown. `--json` gives each answer as one object: each
  host, the relay's `/relays.json` as it came, or its view of the target.
- **A node as a service, with no privilege (T-121).** `node NAME TARGET
  --install` probes for a way that this user may use: a user unit of
  systemd when `systemctl --user` answers, else an `@reboot` line of the
  crontab when `crontab -l` answers, and on Windows a task at the user's
  logon, made from XML by `schtasks`, as a logon trigger of a user with no
  privilege must name that user and run with its token; never a Windows
  service. With none, the command to run at login, and 69. The service runs
  the binary by its absolute path with the node's TARGET and flags, and
  `--env-file`: a service starts with none of the shell's variables, and a
  node behind a proxy reaches no relay without them, so the variables that
  the node reads go into `node-NAME.env`, a private file beside the pair.
  No token goes into it or on a command line: the pair's tokens stay in
  `pair-NAME.json`, and `PODSSH_RELAY_TOKEN` and the secrets of Cloudflare
  Access are not carried (a proxy's password is, in the private file, as a
  proxy that asks for one is not reached without it). The unit restarts
  10 s after a failure, but not after 64, 77 or 78, which no restart
  changes; an expired pair is one of them. podssh says whether lingering is
  on, and never runs `loginctl`. `--uninstall` removes the unit (stopped
  first), the line of the crontab with its mark, or the task, and the file
  of variables: what `--install` wrote, and nothing else. `podssh serve` has
  no command yet (the operator holds it, Q32); it takes the same module
  when it comes.
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
- **`relay` has no `--timeout`.** Each request has a bound: 30 s for the
  pairs, 10 s for `/health` and `/relays.json` and 30 s for a trace, and
  `status`, `info` and `trace` 120 s in all, so a script needs no
  `--timeout` (T-058's decision). `status` asks each host of
  `--relay-host`; `pair`, `info` and `trace` use the first, the control
  host.
- **Routes (T-089).** `node NAME [TARGET] ROUTE=TARGET...` offers each
  TARGET under its ROUTE, with one pair and one node: a route has the form
  of a pair's name, and a TARGET with no route is the one of an operator
  that names none. The operator names one as `NAME/ROUTE`: `podssh operator
  lab/web`, `podssh ssh node://user@lab/web`, `podssh ssh
  user@iroh:TICKET/web`. The route travels in the end-to-end channel, in
  the operator's encrypted proof of its key, so the relay never sees it,
  and `--no-e2e` offers none (64). With `--allow FILE`, a key reaches a
  route only when its line says so, after the key: `SHA256:... routes=web,db
  laptop`, or `routes=*` for each; a line with no `routes=` reaches the
  TARGET with no route alone, as before, and a list that is not one makes
  its line a bad one. The node checks the route after the key, before it
  dials: a route that it does not have, and one that the key may not use,
  are refused with the same words, so that an operator learns no route
  that it may not use. With no allowlist, each operator with the pair's
  connect token may use each route. The known hosts keep a route's host key
  under `node://NAME/ROUTE`. `pipe`'s `node:` and `iroh:` addresses name no
  route yet.
- **A node dials TARGET first,** once, and exits 69 when it cannot; else
  each operator would get a `reject`. With routes, each TARGET is dialled
  once. It says `online` once the relay has
  its socket, and `online again` after a loss: an operator reaches it from
  that line on, not from the first (T-271). It runs until Ctrl-C or SIGTERM
  (exit 0). Its stdout stays empty.
- **A roost is `node --sshd`** (T-166): a node in front of a standard
  sshd, TARGET, or `127.0.0.1:22` when none is given, so that a normal
  server gets the resumable layer and, with `--iroh`, the iroh road. Before
  it goes online, it dials each TARGET and reads the first line, which must
  be SSH's version line (`SSH-2.0-`, or `SSH-1.99-`; RFC 4253, section 4.2)
  within 10 s; else it exits, and names TARGET and what came back: 78 for
  another service, 69 for no line or a close. The node's first line gives
  each version line. Each session's connection to sshd, made after the
  layer's handshake, is checked the same way: a session whose TARGET no
  longer answers as sshd ends at once with the reason. The check peeks and
  takes no byte, so the client reads sshd's line itself. `ssh node://NAME`
  keeps sshd's host key under `node://NAME`, the name that the user gives,
  as OpenSSH keeps a host's behind a `ProxyCommand`; not under the address
  of sshd behind the roost, which each roost shares (`127.0.0.1`).
- **`node --temporary KEY` is the far end of `ssh --upgrade`** (T-167),
  which starts it in its own SSH session on the server: a roost in front of
  the sshd of `SSH_CONNECTION` (on the loopback first, then at the server's
  address), or of TARGET; a pair made on the relay of `PODSSH_RELAY`, else
  the default, and kept in no file; a key for this run only; and the client
  key KEY alone let in. Its one line on stdout, `podssh-upgrade/1` and
  JSON, goes out once the relay takes the pair's sessions. It ends with
  its last session, or 10 minutes after its start with none, and stops its
  pair. With it, `--iroh`, `--pair-file`, `--plain`, `--no-e2e`, the flags
  of the node's key and a route are usage errors (64).
- **`node --plain`** carries each session's bytes as they are, with no
  resumable layer, for an operator that does not speak it (T-263): a lost
  link ends the session, as before T-153. The node's first line names its
  mode. The iroh road always runs the layer, so `--plain` with `--iroh` is
  refused (64).
- **`node --resume-deadline TIME`** keeps a session whose link is lost for
  TIME in place of 10 minutes (T-306), on each road: `90s`, `30m`, `8h` or
  `3d`, from 1 minute to 72 h, the longest life of a pair; a bad TIME, or
  one with `--plain` or `--temporary`, is refused (64). The node names the
  time to each operator in the layer's `GREETING`, and its first line says
  it. An operator waits as long; with `--resume-deadline` of its own
  (`ssh`, `operator`), at most that. A session kept longer holds its replay
  buffers longer; the node's bound of 64 MiB holds.
- **`node NAME udp:HOST:PORT` offers a UDP service** (T-168), on a host that
  allows UDP: the relay carries TCP only, so the datagrams leave from the
  node. Each session is one flow, a UDP socket from the node's host to
  HOST:PORT, with each datagram after its length (two bytes, big-endian) in
  the session's bytes; the flow ends with its session, or after 60 s with
  no datagram either way. Before it registers, the node opens a UDP socket
  to TARGET and closes it, with nothing sent: a host that refuses UDP (a
  sandbox's EPERM) exits 78, a name with no address 69. A UDP TARGET is the
  node's only one: a second TARGET, a route of UDP and `--iroh` are usage
  errors (64). The client is `pipe`'s `udp:node:NAME`; `operator` carries
  the same framing on stdin and stdout.
- **`node NAME TARGET --quick-tunnel` serves TARGET at
  `https://NAME.trycloudflare.com`** (T-300), a quick tunnel of
  Cloudflare's that podssh makes itself: no pair, no account and no
  `cloudflared`. The name is new each run, and the one line on stdout. The
  node asks `api.trycloudflare.com` for the tunnel (through `HTTPS_PROXY`
  when it is set), then reaches the edge on port 7844: over QUIC where no
  proxy is set and UDP gets there, as cloudflared does (T-301), else over
  HTTP/2 on TCP, directly or through a proxy that allows it; QUIC that fails
  gives way to HTTP/2 for the rest of the run, and the node exits 69 when it
  reaches neither. It registers its connection on the first stream, and its
  line of the registration names the transport; each visitor's WebSocket is
  one link of the resumable layer. The name is public, so `--allow FILE` is
  needed: only an operator whose key is in FILE reaches TARGET, through
  the end-to-end channel. A lost connection to the edge is made again with
  the same name, and Ctrl-C unregisters it. `--iroh`, `--plain`,
  `--no-e2e`, `--pair-file`, a route and a UDP TARGET are refused with it
  (64). The client is `podssh ssh cf://NAME.trycloudflare.com`, or `cp`,
  `each` and the other commands of a destination on that road: it tells the
  node apart by the layer's greeting (`cf://[user@]HOST`, above). The node
  prints its key as it starts, for the client's `--node-key`.
- **The exit codes follow the faults of E24**
  (`crates/podssh-cli/src/exitmap.rs`): 69 for a relay or TARGET out of
  reach, a stopped pair, or a pair that another node serves; 77 for a
  refused or expired pair, a node key that differs from its pin or from
  `--node-key`, and an operator key that the node's allowlist refuses; 78
  for no stored pair, a node that cannot connect as it is set up, or a
  roost whose TARGET is another service; 70 for
  a fault of the node that the relay closed (`1003`, `1009`), or a failure
  of the end-to-end channel.
- **Each session runs the end-to-end channel** (T-088): Noise XX above the
  resumable layer, on both roads, in which each end proves its key
  (T-087). The node's key is `node-NAME.key` in the cache, or the file of
  `--key`; `--ephemeral-key` keeps none. The node says its fingerprint as it
  starts, and `--allow FILE` lets in only the operator keys of FILE, read
  again for each session. A client's key is `client.key`, or the file of
  `--client-key`. The operator pins the node's key at its first sight in
  `known-nodes`, and refuses a changed key with both fingerprints; `--node-key
  KEY` names the key instead, and reads and writes no pin. `--no-e2e`,
  given at both ends, carries the bytes with no channel. A conflict of these
  flags (`--key` with `--iroh-key`, `--node-key` with `--no-e2e`) is a usage
  error (64), before anything is read.
- **`--pair-file FILE`** uses a pair of the store's form, which must be a
  regular file of the user that nobody else can read, as ssh reads a key.
  The store is not used. For `operator` and `ssh node://NAME`, the operator's
  file of `relay pair --operator-file` will do.
- **`operator` is a byte pipe**, as `proxy` is: stdout carries the node's
  bytes and nothing else, and it exits 0 only when the node took the
  session. Its codes are those of `node`. `ssh node://NAME` runs the SSH
  client over the same leg, and keeps the codes of OpenSSH (255).
- **`node --iroh` needs no pair** (T-163, a build with the feature
  `iroh`). Its key is the node's key of each road (`--iroh-key` and
  `--iroh-ephemeral` are `--key` and `--ephemeral-key` by their earlier
  names). The node prints its key's fingerprint and its ticket on stderr. A
  client's key gets in only from the file of `--allow` (or `--iroh-allow`);
  with no such file, none does. `ssh iroh:TICKET` dials the ticket with this
  user's key (`client.key`, or `--client-key`), prints its fingerprint when
  it is new and when a node refuses it, and records the host key under
  `iroh:` and the node's key in hex. `--iroh-relay` with no `--iroh`, and
  the flags of the channel with a destination that is no podssh end, are
  usage errors (64); in a build without the feature, `--iroh` and an iroh
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
  `ssh:[USER@]HOP[,HOP...],HOST:PORT`, `node:NAME`, `udp:node:NAME` (T-168)
  and `iroh:TICKET`; or a local socket (T-176), `unix-connect:PATH`; or a
  serial line (T-181), `serial:PATH[,BAUD]`; or, on one side at most, a
  listener (T-177): `unix-listen:PATH` or `tcp-listen:[ADDR:]PORT`. Both
  addresses are checked before anything starts; an unknown kind is a usage
  error (64) that lists the kinds.
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
- **A serial line is a stream too** (the operator's ruling of 2026-10-08,
  T-181). `serial:PATH[,BAUD]` opens a device such as `/dev/ttyUSB0` at
  BAUD, one of the speeds that Linux names from 1200 to 4000000 (115200 when
  none is given), with 8 data bits, no parity, 1 stop bit and no flow
  control, in raw mode, with the modem's lines ignored; the text after the
  last comma is BAUD. The attempt is the probe: a path that is not a
  character device, or one that is no terminal (`/dev/null`), exits 64;
  an open that this user may not make exits 77, and the line gives the
  device's mode, uid and gid, as podssh assumes no group such as
  `dialout`; another failure exits 69 with the error. The open has
  `O_NOCTTY` and `O_NONBLOCK`, so it never takes a controlling terminal
  nor waits for a carrier; `TIOCEXCL` then holds the line alone. Its
  settings are saved first and go back on each way out: when the pipe
  ends, at SIGINT and SIGTERM (130 and 143), and in the panic hook. A
  line has no half-close and no end: the end of the other side's input
  leaves it open, and the pipe ends when the other side ends it, at a
  signal, or when the device fails (a read or a write that fails, 69).
  On Windows, `serial:COM3` exits 64: a COM port is not built yet.
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
- **UDP through a node, with no UDP here** (T-168). `udp:node:NAME` is the
  session to the node of the pair under NAME, whose TARGET is
  `udp:HOST:PORT`: this host sends no UDP and binds nothing, and the relay
  carries TCP. In the session, each datagram is its length (two bytes,
  big-endian) then its bytes, 65,507 at most, one flow for each session;
  the other side gives and takes that framing on stdin and stdout, a
  descriptor or a socket. A length over 65,507 is refused (65), with the
  reason. `exec:` beside it gets one end of an AF_UNIX `SOCK_DGRAM`
  socketpair as its stdin and stdout on Unix, which needs no bind: each
  send is one datagram at the target and each receive one answer, and a
  datagram over 65,507 bytes is counted and dropped. Where the socketpair
  is refused, and on Windows, which has none, its stdin and stdout carry
  the framing, and a line says so where it was refused. The node's session
  is opened first, so a program does not start when it fails. The session
  has no half-close, so after the end of this side's input it waits for
  answers until none came for 5 s. A datagram socket has no end of input:
  when the other side ends, the program gets 10 s to exit, then SIGTERM,
  then 10 s more and SIGKILL; its status is the pipe's. `udp:HOST:PORT`
  here is a usage error (64) that names the node's form. A local UDP
  listener is not made.
- **The exit status.** A road that failed gives it, as `podssh proxy` gives
  it: 69 for a road out of reach, 77 for a refusal (the relay, a proxy, a
  host key, a login) and 78 for a setting that cannot be used; 65 for a
  stream of `udp:` that is not its framing. Else the program's, B's when
  both are programs, 128 + N for a signal, 127 for a program that is not
  found and 126 for one that cannot run; with neither, 0.

## `podssh agent`

An SSH agent inside podssh (T-034), for a host with no `ssh-agent` and no
OpenSSH program that runs; one binary, as the operator ruled (Q5).

- `podssh agent` serves the agent protocol (russh's agent server) until
  SIGINT, SIGTERM or SIGHUP, and stays in the foreground: start it with
  `&`. It prints `SSH_AUTH_SOCK=PATH; export SSH_AUTH_SOCK;` and
  `echo Agent pid N;`, as `ssh-agent -s` does. The socket is `agent.sock`
  in a new directory of mode 0700 in `XDG_RUNTIME_DIR` or the temporary
  directory, made mode 0600; a client of another uid is closed; both go at
  the end. On Windows it is the named pipe
  `\\.\pipe\podssh-agent-USER-PID`, which takes only processes of this
  user. `--socket PATH` names another place. It binds through the listener
  of `podssh pipe`: `PODSSH_LISTEN=no` refuses it (78), and a host that
  refuses the bind gets the reason and the ways with no agent: key files
  with `-i`, whose passphrase is asked on the terminal or through
  `SSH_ASKPASS`.
- `podssh agent add FILE...` sends each key, its passphrase asked on the
  terminal or through `SSH_ASKPASS` (`-t SECONDS`, `--lifetime`: the key
  leaves after that); `list` writes a line for each key as `ssh-add -l`
  does (1 when there is none); `remove FILE...` or `remove --all`; `lock`
  (the password asked twice) and `unlock`. They talk to the agent of
  `SSH_AUTH_SOCK`, so they work with OpenSSH's agent too, and OpenSSH's
  `ssh` and `ssh-add` work with podssh's.
- Keys stay in the agent's memory only. A key added for a confirmation of
  each use (`ssh-add -c`) is refused as it is added: nobody can confirm one,
  and russh's agent server would sign with it unasked (T-284). russh's
  agent keeps no comment of a key, so `list` shows the size, the
  fingerprint and the type. podssh agent keeps no RSA key (T-257): russh's
  agent server would sign with it through the `rsa` crate, which is not
  constant-time, so `podssh agent add` of an RSA key fails with the reason
  (exit 70); OpenSSH's `ssh-agent` keeps one.
- A key of a security key (T-229) is kept by the front of the agent, as
  russh's agent server cannot sign with one: `podssh agent add` and
  OpenSSH's `ssh-add` give it (with the constraint
  `sk-provider@openssh.com`, which names OpenSSH's helper; podssh reaches
  the device its own way, whatever it names), `list` and `ssh-add -l` show
  it with its comment, and a signature with it goes to the device. The
  agent says the touch on its own stderr, and `podssh ssh` says it too. A
  key made with `verify-required` gets its PIN only through `SSH_ASKPASS`
  with `SSH_ASKPASS_REQUIRE=force`: the agent runs in the background, where
  a read of the terminal would stop it. With no device, the agent answers
  FAILURE and says why on its stderr.
- A store of credentials (T-228): `podssh agent add-password
  [USER@]HOST[:PORT]` keeps a server's password, under the user, host and
  port that `podssh ssh` logs in with (its ssh_config read), and
  `add-passphrase FILE` the passphrase of a key file that the agent does not
  hold, once it opens the file. The secret comes from stdin when stdin is no
  terminal, else from the terminal or `SSH_ASKPASS`; never from the command
  line. `-t SECONDS` ends it. Only podssh's agent keeps them, in its memory,
  and tells them to its own user only. `podssh ssh` asks the agent of
  `SSH_AUTH_SOCK` (none with `IdentityAgent none`) before each prompt for a
  key file's passphrase, a password, or the password that keyboard-interactive
  asks for with one prompt with no echo; `BatchMode` forbids the prompt, not
  the question. A secret that a server or a key file refuses is forgotten,
  and never tried twice. `-v` names where a secret came from, never its
  value; `podssh doctor` says how many the agent keeps, never which; a
  locked agent tells none.
- The agent protocol carries them in its extension message (27,
  draft-miller-ssh-agent, section 3.8), under these names, which podssh
  agent answers before russh's server: `store@podssh` (kind, name, secret,
  a lifetime in seconds or 0), `lookup@podssh` (kind, name: SUCCESS, a
  byte 1 and the secret, or a byte 0), `forget@podssh` (kind, name) and
  `count@podssh` (SUCCESS and a count). A kind is `password`, whose name is
  `USER@HOST:PORT`, the host in lower case, or `passphrase`, whose name is
  the key file's absolute path. Another agent answers FAILURE or
  EXTENSION_FAILURE (28), or closes the connection: podssh reads each as an
  agent with no store, and goes on to the prompt. On Windows, with no
  `SSH_AUTH_SOCK` and no OpenSSH agent, podssh asks Pageant only when its
  window is there.
- Exit codes: 0; 1 (`list`, no key); 64 a usage error; 65 a passphrase
  that does not open its file, or a file that needs none; 66 a key file
  that cannot be read, or no secret came; 69 no agent answers at
  `SSH_AUTH_SOCK`, or it keeps no passwords; 70 the agent refused a
  request; 73 the agent's directory could not be made; 77 a passphrase or
  password that was wrong or did not come; 78 `PODSSH_LISTEN=no`; 129, 130
  or 143 at the signal that ends the agent.

## `podssh chat`

`podssh man chat` gives the command, and [irc.md](irc.md) the protocol. The
rules behind it:

- **Two podssh ends, one road.** One side waits, `chat --listen NAME`, as
  the node of the pair NAME; the other reaches it, `chat NAME` (or
  `node:NAME`, `node://NAME`), as its operator. With `--iroh`, the side that
  waits serves the iroh road too, as `node --iroh` does, and the other
  reaches its ticket, `chat iroh:TICKET`. A rendezvous where both sides dial
  lost: the relay's contract has none.
- **Always the channel.** Chat runs the end-to-end channel of T-088 with the
  keys of T-087, and has no `--no-e2e`: the relay never reads a message.
  The flags of the keys are those of `node` (`--key`, `--ephemeral-key`,
  `--allow`) at the side that waits, and of `operator` (`--client-key`,
  `--node-key`) at the side that reaches; a flag of the other side is a
  usage error.
- **Lines in, lines out.** stdin and stdout carry lines, so that a script or
  an agent can talk; there is no TUI. A line that starts with `/` is a
  command, and `//` sends a literal `/`. Notices go to stderr, and
  `--jsonl` puts each event on stdout as one JSON object.
- **A file only once accepted.** `/accept`, or `--accept-dir` for a script,
  is the only way a file is written, under a temporary name, checked
  against its SHA-256, then given its name, never over a file that is there.
- **The one thing of a script.** `--send`, `--sendfile` and `--file` each
  give a run its one thing, and at most one is given. `--timeout` is
  required with no terminal: a run that waits for a peer has nobody to stop
  it.
- **IRC second.** `--irc SERVER` talks in a channel of a network, with TLS
  inside the relay stream unless `--irc-plaintext` names the risk, and over
  TCP with `--direct`, as `ssh --direct`; the flags of the roads' keys do
  not go with it, and PEER is the channel. The server and each user of the
  channel read the messages; a file goes between two nicks alone.
- **Nothing lost unsaid.** A message that the peer did not acknowledge is
  said when its conversation ends, and the exit is then 69. The lines that
  wait for a peer stay in memory, 1000 lines or 1 MiB at most.

## `podssh play`

`podssh play [OPTIONS] FILE` (T-033) writes the output of a recording again,
on stdout, with its timing: a file of `podssh ssh --record`, or another
asciicast v2 file. `--speed FACTOR` plays it faster or slower, and
`--idle-limit SECONDS` cuts each wait to that many seconds, as the file's
`idle_time_limit` does when it has one. An event of another kind than
output (`r`, `i`, `m`) is passed over. A file of another version, and a
line that is no event, are refused (exit 1, the line named); a missing
FILE and a bad value are usage errors (64). The name is not `replay`, which
is one edit from `relay` and would confuse the suggestion of a mistyped
command. A recording sends its control sequences to the terminal again:
play only a file that you trust.

## `podssh config`

`podssh config import ansible FILE` (T-047) prints a `Host` block of
`ssh_config` for each host of an Ansible inventory in its INI form (FILE,
or `-` for stdin), and a summary on stderr. It writes no file: you add what
it printed, as `podssh config import ansible hosts.ini >> ~/.ssh/config`.
The inventory is read as Ansible's `ini` plugin reads it, which
`tests/config_import.rs` checks against what Ansible itself made of a
fixture: hosts before any section are ungrouped, `[G:vars]` and
`[G:children]` give a group's variables and children, `host:PORT` gives a
port, and a range names several hosts (`www[01:03]`, `db-[a:c]`,
`n[1:9:2]`). A host's variables are those of `all`, then of its groups from
the farthest parent to the nearest, then its own line's, the later winning.
`ansible_host`, `ansible_port`, `ansible_user` and
`ansible_ssh_private_key_file` give `HostName`, `Port`, `User` and
`IdentityFile`; of a variable and its `ansible_ssh_` name, the latter wins,
as Ansible's ssh connection takes it.
The `-o` options of `ansible_ssh_common_args` and `ansible_ssh_extra_args`,
which Ansible gives to ssh after those, follow as lines of the block, and
`-J` as `ProxyJump`; `ProxyCommand` and the other keywords that run a
command, and each other flag, are named in a comment, with no value.

A password or a passphrase (a variable whose name holds `pass`) is never
imported and never printed: the summary counts it. A host whose
`ansible_connection` is not `ssh` gets a comment and no block. A host name
that a `Host` line cannot hold (a space, `*`, `?`, `!`, `"` or `#`) is refused by
name on stderr. A bad line ends the run with its number (65); a file that
cannot be read gives 66.

`podssh config import putty`, `mobaxterm` and `remmina` (T-292), and
`mremoteng` (T-327), read the saved sessions of those programs, and are
tested on exports that each program wrote and that were published under a
license that this repository can hold (`tests/fixtures/sessions/THIRD-PARTY.md`;
mRemoteNG's own test files under the GPL-2.0 by the ruling of Q46,
`tests/fixtures/mremoteng/NOTICE.md`), kept byte for byte:

- **PuTTY**: a `.reg` file of `Software\SimonTatham\PuTTY\Sessions`, as
  `regedit` and `reg export` write it (UTF-16LE with its mark, UTF-8, or the
  ANSI of `REGEDIT4`, the key's name in any case), or the session files of
  PuTTY on Unix, one file or their directory, each name `%XX` escaped.
  `Default Settings` is the template, never a host. `user@host` in
  `HostName` gives `User`, as PuTTY reads it. A `.ppk` key is a comment, as
  ssh cannot read PuTTY's format; an SSH proxy (method 6) is `ProxyJump`;
  `ProxyPassword` is counted; `Environment`, a local proxy command and the
  other proxies are comments with no value.
- **MobaXterm**: an `.mxtsessions` export, or `MobaXterm.ini`. Each line of
  a bookmark is `NAME= #ICON#TYPE%FIELD...`; for SSH (type 0) the fields
  give the host, the port, the user and the gateways (`ProxyJump`), and
  MobaXterm's escapes (`__PIPE__`, `__PTVIRG__` and the others) are undone.
  A command after the login, a proxy and a key path in MobaXterm's own form
  are comments; each entry of `[Passwords]` and `[Sesspass]` is counted.
  The text is UTF-8, else Windows-1252.
- **Remmina**: one `.remmina` profile, or each of a directory.
  `protocol=SSH` makes a block; `server` (`host`, `host:port`, `[v6]:port`)
  gives `HostName` and `Port`; `name` is the label and `group` the folder.
  Each secret, `.` for the keyring or an encrypted blob, is counted; a value
  of a template such as `%Host%` is no host.
- **mRemoteNG**: `confCons.xml`, or an export of it. Each `Node` of
  `Type="Connection"` is a session in the folders (`Type="Container"`)
  above it; `Protocol="SSH2"` makes a block, `SSH1` and each other protocol
  a comment. A field that a node inherits (`InheritUsername`, `InheritPort`
  and the others, `True` or `true`) comes from the nearest folder above it
  that has its own, as mRemoteNG takes it. `SSHTunnelConnectionName` gives
  `ProxyJump` through the connection of that name, its own tunnel first; a
  tunnel that is no SSH connection of the file, or a loop, is a comment.
  A PuTTY session other than `Default Settings`, and `SSHOptions`, are
  comments with no value. Each password (`Password`, `VNCProxyPassword`,
  `RDGatewayPassword`), encrypted with the user's master password, is
  counted, never decrypted. A file encrypted whole (`FullFileEncryption`)
  is refused by name (65): in mRemoteNG, turn that off and save, or export
  the connections, and import that file.

A session's label becomes the name of its block, each run of characters
that a `Host` line cannot hold made one `-`, with the label itself in a
comment above it, and a second label of the same name gets `-2`. FinalShell
and Termius, and Ansible's YAML, are refused by name (64) until a real export
of each, under such a license, is at hand to test against (T-328):
FinalShell and Termius have no export.

## `podssh mcp`

`podssh mcp` (T-055) is a server of the Model Context Protocol on stdin and
stdout, for an agent whose MCP client starts it: each line of stdin is one
JSON-RPC 2.0 message and each line of stdout one answer, as the protocol's
stdio transport has them, and podssh's own words go to stderr. It serves a
client of the revision 2026-07-28, whose requests name their version in
`_meta` (`server/discover`, `tools/list`, `tools/call`), and one that opens
with `initialize` (the revisions 2025-11-25, 2025-06-18, 2025-03-26 and
2024-11-05; `ping` too). It ends at the end of stdin: the calls then in
flight have 2 s to end, and end with their children after it; SIGTERM,
SIGINT and SIGHUP, or Ctrl-C and the close of the console on Windows, end
them at once.

The tools:

- **`ssh_exec`** runs one command on a host: `destination` (`[user@]host`)
  and `command`, and at will `stdin` (text), `timeout_seconds` (1 to 3600,
  default 60) and `host_key_fingerprint`. Its result (`structuredContent`,
  and the same JSON as text) has `exit` (podssh's exit code), `status`,
  `signal`, `end` and `failure` as `--result-file` gives them (T-054),
  `stdout` and `stderr` (at most 1 MiB each; `truncated` says that more
  came; output that is not UTF-8 comes as base64, as its `_encoding` says),
  `timed_out` and `duration_ms`. A status that is not 0 is the command's:
  `isError` is true only when podssh failed, or the limit passed.
- **`status`**, **`doctor`** and **`man`** give the JSON of `podssh
  status` (with a `destination`, which must be allowed), `podssh doctor
  --json` (with `full`) and `podssh man --json` (with a `section`).

**The risk, and the hosts allowed.** An agent with `ssh_exec` runs commands
on each allowed host as you, with your keys and your `ssh_config`. The words
of a call come from a model, and text that the model read can ask it for a
command or for a host. So `ssh_exec` reaches no host unless
`--allow-host PATTERN` lets it in, and is not offered with none. A pattern
is `[USER@]HOST` with `*` and `?`, as a `Host` line has them; `!PATTERN`
excludes what it matches; a pattern with `USER@` lets in only a destination
that names that user. The host is matched as the call names it, with no
regard to case, before the `HostName` of your configuration: name each
host, or the fewest patterns that hold them. A destination is a host with
no port and no path: they come from your configuration.

Each call runs `podssh ssh` again, as a child with pipes, so that a
session's output never reaches the protocol's stdout and calls run at once
(four, and the others wait). The child gets `-o BatchMode=yes` (no prompt,
ever), `-o StrictHostKeyChecking=yes` (a host whose key `known_hosts` does
not hold is refused, unless `host_key_fingerprint` names its key, as
`--host-key-fingerprint` does), `-o ClearAllForwardings=yes`,
`-o ForwardAgent=no`, `-o ForwardX11=no`, `-o ControlMaster=no`,
`-o ControlPath=none`, `-T` and `-e none`, before `-F FILE` and
`--direct` when `podssh mcp` has them: the first value of a keyword holds,
so a file cannot undo these. A call past its limit, or one that the client
cancels (`notifications/cancelled`), ends with its child; a cancelled call
gets no answer.

`podssh mcp` exits 0 at the end of stdin, 64 for a pattern that is not one
(empty, with a space or a comma, or `USER@` with no host), and 78 for a
`-F` file that does not exist.

## `podssh session`

`podssh session` (T-186) keeps one SSH session with a pty between the calls
of an agent, which runs one command at a time and must not wait for a
shell to end: it opens the session once, types into it, waits until its
output stops, and reads its screen, each with a call of its own.

- `podssh session start NAME [OPTIONS] HOST [COMMAND]` runs `podssh session
  serve` in the background: this binary again, which leaves the session of
  its starter (`setsid`; on Windows a process with no console), logs in as
  `podssh ssh` does, with its connection flags and the `Host` blocks of
  ssh_config, and holds a session with a pty: the login shell, or COMMAND.
  It is the one SSH client of podssh, on each of its roads. `start` returns
  once the request of the session went to the server, after the login and
  the pty, with the path of the socket on stdout. What the session's podssh
  says until then comes on stderr, and when it ends first, its exit code is
  `start`'s: 255 for a connection or a login that failed, 77 for a bind
  that this host refuses. When the session is not ready within `--timeout`
  (60 s), it is stopped, and `start` exits 75. A name that runs already is
  refused (69).
- The session's podssh reads no terminal. A prompt has none: a key's
  passphrase comes from `podssh agent` or `SSH_ASKPASS`, and a new host
  key needs `StrictHostKeyChecking=accept-new` or a `known_hosts` that has
  it. The pty's size is that of `COLUMNS` and `LINES`, else 80 by 24. No
  forward, no X11 and no control socket of ssh_config is used (said with
  `-v`).
- `send NAME TEXT` types TEXT, then Enter (a carriage return), which
  `--no-enter` leaves out. In TEXT, `\r`, `\n`, `\t`, `\e` (Escape), `\xNN`
  (`\x03` is Ctrl-C) and `\\` give the bytes that they name; each other `\`
  is refused, so a path of Windows writes each `\` twice. `send NAME` with
  no TEXT types stdin as it is, 512 KiB at most: a password goes so, and
  never stands in a command line, which each process of the host can read.
- `wait NAME` returns when the output has stopped for `--idle` (2 s by
  default), counted from the later of the last output and the last send:
  a wait right after a send waits for what the send brings. Output that
  stops inside an escape sequence or a UTF-8 character has not stopped,
  until the grammar of T-221 calls the sequence broken (10 s). With
  `--match TEXT` it returns when TEXT comes in the output since the last
  send, with the terminal's sequences and control bytes taken out (a colour
  between two letters hides no match); with both, the first that comes. It
  writes `idle` or `match` on stdout. The echo of the line that `send`
  typed is output too: match a text that only the command writes. It exits
  75 when `--timeout` (60 s) passes first, and 69 when the session ended
  first, with its status.
- `capture NAME` writes the screen, as a terminal of the pty's size shows
  it after the session's output: its rows, with no blank at their ends and
  no empty row at the end, as `tmux capture-pane` gives them. The model is
  the one of the terminal oracle (T-200), `vt100`, pure Rust. `--raw`
  writes the last 64 KiB of the output as it came, from a place where a
  terminal can start to read it: the ring of T-221, never inside a
  sequence or a character.
- `stop NAME` ends the session and its podssh. `list` writes a line for
  each session of the cache that answers: its name, `running` or `ended`
  and the status, and its host, with a tab between them.
- The session's podssh ends at `stop`, 60 s after its session ended (so
  that its last screen and its status can be read), after an hour with no
  request, or at SIGINT, SIGTERM or SIGHUP. `podssh session serve NAME
  [OPTIONS] HOST` is that podssh in the foreground, for a program that keeps
  it itself: one line of JSON on stdout when it is ready, and its messages
  on stderr; `--detach`, which `start` gives it, writes nothing more on
  stdout and stderr after that line, so that a program that reads them to
  their end does not wait for it.

**The socket.** `start` and `serve` listen, as the operator allowed (Q1):
on `NAME.sock` in the directory `sessions` of the first usable directory of
the cache (FILES), made with mode 0700, through the listener of `podssh
pipe` (T-177): the socket is made mode 0600, and a client of another user
is closed before a byte of it is read; on Windows it is an AF_UNIX socket
whose clients must run as this user. `--socket PATH` names another place:
also `\\.\pipe\NAME` on Windows, and `@NAME` in Linux's abstract namespace,
which has no file and where the check of the user is the guard. No TCP: a
request types into a shell, and a TCP peer's user cannot be read. The bind
is the probe: a host that refuses it gets the reason, and `start` exits 77;
`PODSSH_LISTEN=no` refuses `start` and `serve` before any bind (78), and
so does `PODSSH_CACHE_DIR=none` with no `--socket`. A client looks for NAME
in each directory of the cache, in its order.

**The risk.** Each program that runs as you can type into the session and
read its screen, as it can use your keys. The socket carries no key,
password or token: the session's podssh logs in with what `podssh ssh`
would use, and a request carries text to type.

**The protocol** of the socket, for a program that speaks to it itself:
one JSON line for each request and one for each answer, with the version
first (`"schema":1`). A request has the session's `name` and its `op`:
`info`; `send`, with `text`, or `bytes` in base64; `wait`, with `idle_ms`,
`match` and `timeout_ms`; `capture`, with `raw`; `stop`. An answer has
`ok`, and the fields of its operation (`screen`, `cursor`, `rows` and
`cols`; or `bytes`; `by`; `state` and `status`), or `code`, the exit code
that the client gives, and `error`. A line of another schema, or another
session's name, is refused (64).

Exit codes: 0; 64 a usage error; 69 no session of that name answers, or it
ended; 70 an answer that this podssh cannot read; 75 the `--timeout` passed
first; 77 the bind refused; 78 `PODSSH_LISTEN=no`, or no directory for the
socket; 255 the connection or the login of `start` failed.

## podssh's settings file

A file states podssh's own settings once (T-048), below the flags and the
variables and above the built-in defaults: `RelayHost` (as `--relay-host`
and `PODSSH_RELAY`), `RelayAddr` (as `--relay-addr` and `PODSSH_RELAY_ADDR`;
each line adds to the flag's and the variable's pins), `RelayFailover` (as
`--relay-failover`), `CaFile` (as `--ca-file` and `SSL_CERT_FILE`; `~` is
the home) and `SessionLog` (as `PODSSH_SESSION_LOG`, below). It has `Keyword value` lines, `Keyword=value` too, and `#`
comments, read as an `ssh_config` line is; the first value of a keyword
wins. The file is the one that `PODSSH_SETTINGS` names, an absolute path
that must exist (`none` reads none); else the first that exists of
`$XDG_CONFIG_HOME/podssh/settings` (`~/.config/podssh/settings`, and
`%APPDATA%\podssh\settings` on Windows) and `podssh.settings` beside the
binary. It is never read from the working directory or `/tmp`, as a file
that names relay hosts decides where tokens go. A symbolic link, a file of
another user than you or root, one that others can change, an unknown
keyword and a bad value are refused (78, with the file and the line) by each
command that reaches the relay. podssh never writes the file, and no
keyword holds a token. `podssh status` gives its path as `settings` and
`relays_from: "the settings file"`, and `podssh doctor` names it.

After a line `[groups]`, to the next table or the end of the file, each line is
`NAME HOSTS` (or `NAME=HOSTS`): a group of hosts for `podssh each`, named
`@NAME` (T-184). A name has letters, digits, `.`, `_` and `-`, and does
not start with `.` or `-`; its hosts are a word of `podssh each`, with
commas or blanks between items, braces, and other groups. The settings
come before the table: a line of the table that is a setting's keyword is
refused, and so are a group given twice, another table, and a group that
names one that is not there or itself, through others or not (78, with
its line), as each bad line of the file is.

After a line `[snippets]`, each line is `NAME COMMAND`: a command for
`--snippet NAME` (T-187, "Snippets" above). The two tables can come in
either order; a table other than `[groups]` and `[snippets]` is refused.

## The log of the sessions

When the user asks for it, podssh keeps a line for each session of this
host (T-056): `PODSSH_SESSION_LOG=1` (or `yes`) keeps it in the cache, as
`sessions.jsonl` in the first directory of the cache that takes it; an
absolute path keeps it in that file; `0` or `no` keeps none, also over
`SessionLog` in the settings file, which takes the same values. It is off
by default, and another value is refused (78) before anything connects.

Each run of `podssh ssh` and `podssh proxy` that named a destination adds
one JSON line at its end: `start` (UTC), `duration_ms`, `verb`, `host`,
`port`, `via` (the relay host, or `direct`, `node`, `iroh`, `cloudflare`,
or `relay` when no relay host answered), `end`, `exit`, `failure` and
`bytes` as `--result-file` has them (T-054; a proxy ends `closed` or
`failed`), and the relay's `close_code`. A line never holds a command, an
environment value, a token or a password; an `-O` request, `-G` and a usage
error add none.

The file has mode 0600 (on Windows, an access list of its own), is opened
to append with no symbolic link followed, and takes each line in one write,
so that two runs at once give two whole lines. A file that is another
user's, or that others can read, is refused, and the run says so on stderr
with its exit code unchanged. At 1 MiB the file becomes `sessions.1.jsonl`
(the name with `.1` before its extension), and a new file starts.
`podssh status` gives the file and the last line, in short, as
`session_log`.

## The report of a failure

When podssh itself fails, it gives a report of the failure to a program
that the user names in `PODSSH_ERROR_PROGRAM` (T-195): a script that files
a ticket, or a tool that asks an AI for the cause. podssh calls no AI
service and no network address for this; the program decides what to do
with the report (`docs/decisions.md`, 2026-10-08).

- **The program.** podssh starts it as it starts `SSH_ASKPASS`: by its
  name, with no shell and no argument. A variable, and no flag, so that it
  reaches each command, also `podssh proxy` under the `ProxyCommand` of
  OpenSSH. The program's environment has no `PODSSH_ERROR_PROGRAM`, so a
  podssh that it runs starts no program of its own, and no credential
  variable (`PODSSH_RELAY_TOKEN` and the tokens of Cloudflare Access); the
  proxy variables stay, for a program that needs the proxy. Its stdout and
  stderr go to podssh's stderr, as stdout is data. After 30 s podssh stops
  it. Its status is ignored, and podssh's exit code does not change. A
  program that does not start gives one line on stderr.
- **When.** Only when podssh itself fails: each exit code that is not 0,
  but a status that podssh passes on and a stop that the user asked for.
  The code path decides, not the number. `podssh ssh` passes on the remote
  command's status (255 too) and a session's end with no status: each
  run whose `--result-file` has no `failure`. `podssh each` passes on the
  statuses of its hosts when each host had a session; `podssh ping` the
  status of the remote program of a measure; `podssh pipe` a child's
  status; `podssh edit` the editor's. 130 and 143, which podssh gives after
  SIGINT and SIGTERM, start no program.
- **The report.** One JSON object and a line break on the program's stdin:
  `schema` (1), `podssh` (the version), `os`, `arch`, `verb` (the
  command's canonical name, or null for a word that names no command),
  `exit`, `messages` and `relay`. `messages` holds the last 64 lines of
  podssh's own messages, 16 KiB at most, each line 2048 bytes at most:
  what podssh wrote to stderr, or to the file of `-E`, and the errors that
  `-q` hides. `relay` is the relay host of the run with its `close_code`
  and `reason`, or null. The lines that `podssh node`, `operator`, `chat`,
  `pipe` and `agent` write while they serve are not kept; a server's banner
  and the bytes of a session never are.
- **No credential.** A report never holds a token, a proxy URL or its
  password, a key, the environment, the command line as typed, or a byte
  of a session. podssh's messages hold none (`SECURITY.md`), and each line
  also goes through a mask: the value of each credential variable and of
  each proxy variable, with its user and its password, becomes `<hidden>`,
  so does the user and password of each URL, and the controls of a
  terminal are dropped, as in the lines of `podssh doctor`.

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
- `podssh chat` uses sysexits too: 0 when each message was acknowledged
  and the one thing of `--send` or `--file` is done, 64 a usage error, 66 a
  file of `--file` or `--sendfile` that cannot be read, 69 the relay out of
  reach, or a message with no acknowledgement, 70 a peer that broke the
  protocol, a failed channel, or a file that arrived damaged, 73 a missing
  `--accept-dir`, 75 the `--timeout` passed, or the peer talks with
  another, 77 a key or a pair refused, or the file of `--file` declined, 78
  a setting or a pair that cannot be used.
- `podssh ping` gives 69 when no relay host answers, and with a
  destination the codes of `podssh ssh`: 255 for a failure of podssh, and
  the status of the remote program of a measure (127 when the host lacks
  it).
- `podssh each` gives the largest status of its hosts: 0 only when each
  host gave 0, and 255 for a host with no session; 64 and 78 come before
  anything connects, and 73 when a file of `--output-dir` cannot be made.
- `podssh session` uses sysexits: 69 no session of that name, or one that
  ended; 75 a `--timeout` that passed; 77 a bind that the host refuses; 78
  `PODSSH_LISTEN=no`; and `start` gives 255 for a connection or a login
  that failed, as `podssh ssh` does.
- `podssh run` gives the status of its command, as `podssh ssh` gives it,
  and 255 when the copy failed, which runs nothing.
- `podssh job` uses the codes of `podssh ssh`: 255 for a failure of podssh,
  a host with no tmux or no such job among them. `job wait` gives the job's
  status, and 75 when its `--timeout` passed; `job fetch` gives 75 for a
  job that has not ended.
- A command that is not implemented exits 70. It never exits 0.
- A drop of the relay before any request reached the destination is tried
  again (T-025): during the SSH handshake or the login, before the
  command, the shell, the subsystem, `-W`'s connection, `-R`'s forwards or
  `-N`'s wait. A drop of the link to the relay goes to the next relay
  host, and one of the relay's link to the target tries once more (by the
  close, as `docs/relay.md` classifies it). A close at the relay's limits
  (1001, 1009) or for a backlog (1013), and each drop after a request, end
  the run with 255 as before: a command never runs twice. Each try says
  why on stderr, with the backoff of a failed upgrade; a try after the
  first asks nothing (a key that a passphrase opened and a password that
  the server took are used again), so a login that needs a prompt stops.
  The tries are at most `ConnectionAttempts` times the relay hosts.
- `podssh ssh` never ends as a success with no exit status (T-026). When
  stdout closes (EPIPE), podssh stops writing, sends the end of input, and
  waits 5 s at most for the status: it gives that status, or 255 with a
  note. `-N` ends only when the server or the network ends it: 255, with
  the server's words when it sent some. `-W` gives 0 when the far end
  closes and when stdout closes, and 255 when the connection died. These
  are the codes of OpenSSH's `ssh`, and the gate compares both clients
  (`scripts/interop-status.sh`). A status above 255 gives 255: OpenSSH passes the
  value to `exit()`, where 256 reads as 0.

## Prompts and time limits

- Prompts (host key, passphrase, password, keyboard-interactive) go to the
  controlling terminal, as with OpenSSH. Thus
  `echo x | podssh ssh host cat` can still ask for a password.
  `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE` works as in OpenSSH.
- A key file is read in the format of OpenSSH, PEM (RSA or ECDSA), PKCS#8 or
  PuTTY, and its passphrase is asked when it is encrypted, in each of them
  (T-287): a PEM key of AES-128-CBC, AES-192-CBC, AES-256-CBC or
  DES-EDE3-CBC, as OpenSSH's `ssh-keygen -m PEM` and OpenSSL write them; a
  PKCS#8 key of PBES2, with PBKDF2 or scrypt, as `ssh-keygen -m PKCS8` and
  OpenSSL's `-v2` write them; and an encrypted PuTTY key. A key that no
  passphrase would open (DSA, a PEM key of another cipher, a PKCS#8 key of
  PBES1 or of a scheme of PKCS#12) is skipped before the question, and
  podssh says why.
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
  So it is under `StrictHostKeyChecking=no`, where OpenSSH warns, turns off
  passwords and forwarding, and logs in with a key (T-225).
- A host that a `@cert-authority` line names is asked for a host
  certificate (T-027), which is checked as OpenSSH checks it: from a CA of
  such a line, signed, within its validity window, a host certificate,
  with the host (or `HostKeyAlias`) as a principal, and no critical option.
  Then it is accepted, also under `StrictHostKeyChecking=yes`, and nothing
  is recorded. A certificate that fails a check is refused with the check
  (an expired one names this host's clock, which `podssh doctor` checks),
  and one from a CA that no line names is checked as its plain key. podssh
  asks for a principal where OpenSSH takes a certificate with none.
- Under `accept-new` and `no`, a key that podssh cannot verify is refused
  (T-028): one that no readable file knows while a user `known_hosts` file
  exists and cannot be read (a directory, a FIFO, no permission), as a key
  recorded there is not seen. OpenSSH reads a directory there as empty, and
  logs in (T-225). A key that is accepted and not recorded
  (`HOME` is not set, `UserKnownHostsFile none`, or the write failed) holds
  for this connection only, and podssh says so: the next run cannot tell a
  changed key from a new one. `UserKnownHostsFile /dev/null` reads as empty.
- Two runs that meet a new host at once record its key once (T-029): the
  first user file is locked for the write, and read again under the lock. A
  second key of the type that another run recorded meanwhile is refused as
  changed. The lock refuses no reader, OpenSSH included: an advisory `flock`
  on Unix, and on Windows one byte past any end of the file.
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
  spends signing (`ssh-add -c`) does not count, nor does the time of a
  security key, whose touch has 30 s (T-229).

## `ssh_config` (milestone M8)

`podssh ssh` reads `~/.ssh/config` and then the system's file
(`/etc/ssh/ssh_config`, `%ProgramData%\ssh\ssh_config` on Windows), or only
the file of `-F FILE`, or of `PODSSH_SSH_CONFIG` when `-F` is not given;
`-F none` reads no file (T-043, T-044).
So do `cp`, `mv`, `scp`, `sftp` and the `ssh:` address of `pipe`, which reach
a host as `podssh ssh` does. A line goes through the same parser as `-o`,
and an error names the file and the line. The command line beats the file:
`-l`, `-o User` and `user@host`, then the file's `User`; `-p`, `-o Port` and
`host:PORT`, then the file's `Port`. A missing `-F` file exits 78; a missing
`~/.ssh/config` is no error. On Unix, `~/.ssh/config` must be the user's or
root's, and no one else may change it, checked on the file that a link
names; a file that `-F` names is the user's choice, and is not checked.
`ProxyCommand podssh proxy %h %p`, which a user of OpenSSH writes for
podssh, is accepted, as `podssh ssh` takes that road anyway. `Include` is
read where it stands, with each file that it reads checked as
`~/.ssh/config` is. A `Match` line starts a block that applies when each of
its criteria holds (T-045): `all`, `host`, `originalhost`, `user`,
`localuser`, `tagged`, `command`, `sessiontype`, `version` (it matches
`OpenSSH_10.3p1`, the release whose reading podssh follows), `final` and
`canonical`, each with `!`, and each with a comma list of patterns but the
last two and `all`. `Match exec` and `Match localnetwork` are refused by
name with the file and the line (78), and run nothing, where they would
decide the block: podssh runs no program for a configuration, and probes no
interface. `Tag` and `-P` set the tag of `Match tagged`. The keywords of the GSSAPI patch of Debian and Fedora
(`GSSAPIKexAlgorithms` in Fedora's crypto policy) are accepted with no
effect, as podssh has no GSSAPI.

Each hop of `-J` or `ProxyJump` reads the blocks of its own name, as
OpenSSH's jump host does (T-290): its `HostName`, `Port`, `User`,
`IdentityFile`, `HostKeyAlias` and the settings of its host keys and login.
Its `user@` and `:PORT` beat the file; with neither a `user@` nor a `User`,
the hop logs in as the local user, never as the destination's: `-l`, `-p`
and the destination's blocks are the destination's alone. The `ProxyJump` of
the first hop of a list puts its own chain before it; a later hop's is not
read, as OpenSSH gives that hop the hops before it as its `-J`. A chain that
comes back to a hop is refused (64), and so is one of more than 16 hops. The
settings of host keys, authentication, keys and time of `-o` and `-i` hold
for each hop too, where OpenSSH's command line holds for the destination
only.

These are the rules of OpenSSH 10.3p1, measured with `ssh -G`, and podssh
follows them; `crates/podssh-cli/tests/ssh_config_file.rs`,
`crates/podssh-cli/tests/ssh_config_include.rs` and
`crates/podssh-cli/tests/ssh_config_match.rs` hold OpenSSH's results:

- The first value obtained wins, from top to bottom. The most specific block
  does not win.
- A `Host` pattern matches the host as typed, with its case: `Host MyHost`
  does not apply to `myhost`. A negated pattern excludes the host from that
  block only, and a line of negated patterns alone matches nothing.
- `IdentityFile` and `-i` add up; they do not replace each other.
- A `#` that starts a word outside double quotes starts a comment, also
  after a value.
- `IgnoreUnknown` holds for the keywords after it. Only the first one
  counts, and `-o IgnoreUnknown` beats the file's.
- `HostName` takes `%h`, the host as typed, and `%%`; another token is an
  error. The result is lowercased.
- `Include` is expanded where it appears, its arguments in order and the
  names of a glob sorted; a wildcard may be in a directory part too. A
  relative `Include` starts from `~/.ssh` (a user's file, also one of `-F`)
  or `/etc/ssh` (the system's), not from the directory of the file that
  includes it. It takes `~` and each `%` token but `%T`, with the values of
  the moment: `%p` the port of `-p` or of an earlier `Port`, else 22; `%r`
  the user of `-l` or of an earlier `User`, else the local user; `%h` an
  earlier `HostName` as written, else the host as typed.
- A file that an `Include` reads is checked as `~/.ssh/config` is, also
  from a file of `-F`. A missing file is no error, and a directory that a
  glob names is skipped. A `Host` line in an included file holds to the end
  of that file. A chain of more than 16 includes is an error.
- `*` matches across dots.
- `Match` never overrides a value that is already set. Its block applies
  when each criterion holds. `host` and `originalhost` match with no regard
  to case, the others with it, and `criterion=patterns` reads as `criterion
  patterns`. `host` is the host after a `HostName` read so far, also one
  that a `Match` block set; `user` is the user of `-l`, `-o User` or
  `user@host`, else of a `User` read so far, else the local user; `tagged`
  with no tag, and `command` with no command, match `""`. `RemoteCommand` is
  no command for `command` and `sessiontype`. `all` stands alone, or after
  one criterion: `Match all host h` is an error.
- A `Match` with `final` and no `!`, also one whose other criterion fails,
  asks for a final pass: each file is read again, `Host` lines and `Match
  host` see the host after `HostName`, lowercased, `final` and `canonical`
  hold, and the blocks that apply then fill what is still unset; a
  `HostName` in that pass is not taken. A `HostName` alone asks for no final
  pass, and with none `canonical` never holds. A key file and a forward
  given twice are kept once, `SendEnv` adds up, and the first `SetEnv` line
  holds whole.
- Debian 13 starts its system file with `Include
  /etc/ssh/ssh_config.d/*.conf`; Fedora 42 includes its crypto policy from a
  `Match final all` block.
- A missing `-F` file is an error (255), and `-F` stops the reading of each
  other configuration file. A missing `~/.ssh/config` is not an error.
- `~/.ssh/config` that is another user's than the user's or root's, or that
  the group or others can change, is an error; a link is followed. A file
  of `-F` is not checked.

One difference, on purpose: OpenSSH checks each line, also in a block that
does not apply. podssh reads only the blocks that apply, as it refuses some
keywords that OpenSSH runs (`LocalForward`), and a block for another host
must not stop each connection.

NOTE: In its recommended parsing mode, `ssh2-config` 0.8.1 drops
`ProxyCommand` and `StrictHostKeyChecking` silently (read 2026-10-01). Do not
use it.
