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
  long this side was away by the wall clock (T-306).
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
  `-4`, `-6`, `HostName` and `--direct` are refused (64). `podssh proxy
  cf://HOST` is the same pipe, with no PORT and no relay flag. Each message
  up is at most 16 KiB, as the origin cuts a longer one; podssh sends no
  Ping, as the origin answers one outside the lock of its writes; and the
  end of the stream, with no Close, is the end of the session.
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
- **`--result-file FILE` writes the result of the run as JSON** (T-054), at
  its end, also when it failed before it connected, so that a script tells
  the remote command's status from a failure of podssh with no parsing of
  stderr: `schema`, `exit` (the code that podssh exits with), `status` (the
  remote exit status, or null), `signal` (`name` and `core_dumped`, or
  null), `end` (`status`, `signal`, `no-status`, `lost`, `escaped`,
  `terminated`, `detached`, `failed`, or `shared`; null with no session, as with `-W`),
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
- **`~#` lists the forwards of the session** (T-041), in a session with a
  pty, as OpenSSH's `~#` lists its connections: for each `-L`, `-D`, `-R`
  and `-W`, as it was written, the connections it carried, those open and
  those that failed, and the bytes toward the server and from it, counted as
  they pass. With `-v` the end of a run prints the same lines. A forward
  asked for again on a new connection (`--persist`) keeps its counts.
- **`-G` prints the settings in effect** (T-046), as OpenSSH's `ssh -G`
  does: a line of `keyword value` for each keyword of OpenSSH that podssh
  applies, with the defaults, in OpenSSH's order and spelling (`true` and
  `false` where OpenSSH writes them), then exit 0 with nothing opened: no
  relay, no token. A script can compare the two line by line. The defaults
  that differ do on purpose: `serveraliveinterval 60` (the relay's idle
  cut) and `connecttimeout 60`, and podssh tries no `_sk` identity file, as
  it has no security keys. podssh's own settings (relay hosts, `--ca-file`)
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
  use each key of the agent, though it cannot read one. podssh does not
  bind the agent to the server's host key (OpenSSH's
  `session-bind@openssh.com`: russh keeps no copy of the server's signature
  of the key exchange, T-279), so the limits that `ssh-add -h` sets do not
  hold over podssh's forward. Forward only to a server that you trust, or
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
  second client.
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
  `valid-before=`, and a failure exits 1 where OpenSSH exits 255. A
  signature made with a certificate, and `cert-authority` lines, are not
  read yet (T-289); `-r`, a revocation list, is refused.
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
- DSA is refused, because OpenSSH 10 removed it.
- An RSA key is made by aws-lc-rs, whose RSA is constant-time, never by the
  `rsa` crate, whose private-key operations are not (RUSTSEC-2023-0071, the
  Marvin attack): 2048, 3072 (the default), 4096 or 8192 bits, the sizes
  that aws-lc-rs makes (T-257).
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
cannot be read gives 66. The formats of PuTTY, MobaXterm, Remmina,
FinalShell, mRemoteNG and Termius, and Ansible's YAML, are refused by name
(64) until a real export of each is at hand to test against (T-292).

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

After a line `[groups]`, to the end of the file, each line is
`NAME HOSTS` (or `NAME=HOSTS`): a group of hosts for `podssh each`, named
`@NAME` (T-184). A name has letters, digits, `.`, `_` and `-`, and does
not start with `.` or `-`; its hosts are a word of `podssh each`, with
commas or blanks between items, braces, and other groups. The settings
come before the table: a line of the table that is a setting's keyword is
refused, and so are a group given twice, another table, and a group that
names one that is not there or itself, through others or not (78, with
its line), as each bad line of the file is.

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
  recorded there is not seen. A key that is accepted and not recorded
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
  spends signing (`ssh-add -c`) does not count.

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
