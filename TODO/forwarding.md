Forwarding in `podssh ssh`: remote forwards, the agent, X11, local forwards
and connection sharing (a local listener after a probe, as the operator
ruled on 2026-10-08), streams to Unix sockets on the server, and the state
of the forwards of a session.

# T-035: `-R`: remote forwarding, each connection made out through the proxy

**Source:** `docs/ROADMAP.md:244-245` (M8) and `docs/cli.md:100-105`; the
VLOD-ZDOV/quic-ssh report in GitHub #22 (item 7) and the cubic-vm/cubic
report in GitHub #23 (item 7). Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`ssh -R` lets a server reach a service on the client's side. podssh refuses
`-R` and `-o RemoteForward`. Unlike `-L`, `-R` needs no local listener: the
server listens, and the client connects out for each connection.

## Premise

- Measured, offline (`PODSSH_OFFLINE=1`):
  `podssh ssh -R 8080:localhost:80 example.invalid` gives "-R SPEC is
  refused. Use -W HOST:PORT instead. remote forwarding is not in the first
  release.", exit 64. `-o 'RemoteForward=8080 localhost:80'` gives "remote
  forwarding is not implemented yet", exit 64.
- Read: the row and the refusals are `crates/podssh-cli/src/flags.rs:194-195`,
  `crates/podssh-cli/src/ssh/options.rs:148` and
  `crates/podssh-cli/src/ssh/keywords.rs:81`. `-W` is not a substitute: it
  carries the other direction.
- Read: the manual's note says "-L, -R and -D are refused by name: podssh
  never listens on a port" (`crates/podssh-cli/src/man/notes.rs` lines 31-32
  at `25ab0e7`), but `docs/cli.md:100-102` says that the refusal of `-R` must
  not say that.
- Read: russh 0.64.1 has `Handle::tcpip_forward`, and its default handler
  accepts each `forwarded-tcpip` channel that a server opens. podssh's handler
  does not override it (`crates/podssh-ssh/src/handler.rs` lines 44-88 at
  `8d668b7`).
- Read: `dial` goes through `HTTPS_PROXY`, but never for a loopback target
  (`crates/podssh-ws/src/dial.rs:138-147`,
  `crates/podssh-ws/src/dial.rs:204-227`). On the measured sandbox, a direct
  connection to loopback is refused (`docs/target-environment.md:22`).
- Read: a refused `tcpip-forward` gets SSH_MSG_REQUEST_FAILURE, which has no
  reason field (RFC 4254, section 4). So `docs/cli.md:105` ("podssh gives the
  server's reason") cannot hold as written.

## Approach

1. Parse the specs of OpenSSH, `[bind:]port:host:hostport`, from `-R` and
   from `-o RemoteForward`. Refuse by name the forms with a socket path and
   the remote SOCKS form (`-R [bind:]port`) until a later step.
2. After the login, send `tcpip-forward` for each spec. Print a port that the
   server chose, as OpenSSH does. Honour `ExitOnForwardFailure`, which is
   ignored today (`crates/podssh-cli/src/ssh/keywords.rs:66`): a refused
   forward then ends the run with 255.
3. In the handler, accept a `forwarded-tcpip` channel only for an address and
   a port that podssh asked for, and reject the rest. Dial the spec's target
   with `podssh_ws::dial::dial` and `ProxyChoice::FromEnvironment`, as
   `--direct` does (`crates/podssh-cli/src/ssh/mod.rs:133-138`), with the
   limit of 20 s (`crates/podssh-relay/src/open.rs:23-25`).
4. Copy both ways. Pass EOF on in each direction, and close both ends on an
   error. The SSH window is the flow control.
5. A failed dial closes that channel only, and says why on stderr: the
   proxy's answer, or the error of a refused loopback connection.
6. Change the `-R` row to supported and the keyword to honoured. T-230
   corrected the texts of the `-R` refusal (the help and the manual's note
   at `crates/podssh-cli/src/man/notes.rs:31-33`). Change the test that
   asserts the refusal (`crates/podssh-cli/tests/flag_table.rs:67-86`).
   Update `docs/cli.md:93-107` (correct line 78) and `docs/STATUS.md`.
7. Pitfalls: each forwarded connection is one more outbound connection, made
   under the proxy rule of `AGENTS.md:177-182`; say so in the help. The relay's
   64 MiB and 12 h cover all the forwarded connections of a session
   together.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- remote_forward
cargo test -p podssh-ssh -- forwarded_channel
sh scripts/dev.sh check
```

The first test parses the TCP forms, and refuses the socket and SOCKS forms
by name with exit 64. The second runs a russh server in the process over a
pipe; it opens a `forwarded-tcpip` channel for a port that podssh did not
ask for, and podssh rejects it. In the gate, `scripts/interop.sh` runs
`-N -R 127.0.0.1:2290:127.0.0.1:2203` against OpenSSH on port 2201, then
reads Dropbear's banner from port 2290. With `-o ExitOnForwardFailure=yes`
and `-R 22:127.0.0.1:2203`, OpenSSH refuses the port (podtest is not root):
exit 255, and the message names the forward. Planted defect: accept a
channel for any port, and the second test fails.

## Correction

2026-10-08, T-230: the texts that the Premise measured changed. Now
`podssh ssh -R 8080:localhost:80 example.invalid` gives "-R SPEC is
refused. Leave it out." and "remote forwarding is not implemented yet.",
exit 64, as `-o RemoteForward` does; it names no `-W`. The manual's note
gives `-R` a sentence of its own (`crates/podssh-cli/src/man/notes.rs:31-33`).
The rest of the Premise holds.

2026-10-08, T-237: podssh's handler now refuses each channel that the
server opens, as administratively prohibited, in one place: `unasked` in
`crates/podssh-ssh/src/handler.rs`. This entry accepts its own kind there,
only for its own requests, and reads an accepted channel at once or closes
it (`SECURITY.md`, "Design rules").

# T-036: `-A`: agent forwarding, off by default as in OpenSSH

**Source:** the operator's ruling of 2026-10-08 on Q2: implement `-A`, off by
default as in OpenSSH (`docs/decisions.md`). The l0ng-ai/tty7 report in
GitHub #20 (item 9, "keep the refusal explicit"; read in the report). Read
and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A user who logs in to a host, and from there to a second host with a key
that stays on the first machine, needs agent forwarding. podssh refuses `-A`
and points to `-J`. `-J` covers the common case, but not a program on the
remote host that must use the key, such as `git` on a build host.

## Premise

- Measured, offline: `podssh ssh -A example.invalid true` gives "-A is
  refused. Use -J HOST (log in through the jump host) instead. agent
  forwarding is not supported.", exit 64
  (`crates/podssh-cli/src/flags.rs:198-199`).
- Measured, offline: `-o ForwardAgent=yes` is accepted with no effect; only
  `-v` says so ("-o ForwardAgent has no effect in podssh"). The keyword is
  in `IGNORED` (`crates/podssh-cli/src/ssh/keywords.rs:66`). So the flag
  refuses, and the keyword is silent.
- Read: podssh already connects to the local agent to log in: `SSH_AUTH_SOCK`
  on Unix; the named pipe of the OpenSSH agent, then Pageant, on Windows
  (`crates/podssh-ssh/src/keys.rs:259-290`). That is a connection, not a
  listener.
- Read: russh 0.64.1 has `Channel::agent_forward`
  (`auth-agent-req@openssh.com`), and its default handler accepts an
  `auth-agent@openssh.com` channel from the server. podssh's handler does not
  override it (`crates/podssh-ssh/src/handler.rs` lines 44-88 at `8d668b7`). No agent is
  connected to such a channel today, so nothing leaks; OpenSSH refuses such
  a channel and warns.
- Read: `docs/cli.md` (section "Forwarding") said that `-A` is not in the
  scope of podssh; the ruling replaces that sentence.

## Approach

1. `-A` and `-o ForwardAgent=yes|no|PATH` turn the forward on; it is off by
   default. Move `ForwardAgent` from `IGNORED` to `HONOURED`
   (`crates/podssh-cli/src/ssh/keywords.rs:23-74`). Change the help of `-a`
   (`crates/podssh-cli/src/flags.rs:180-181`).
2. On the destination's session channel, send `auth-agent-req@openssh.com`
   before the shell or exec request (`crates/podssh-ssh/src/session.rs:61-75`).
   Never to a jump hop.
3. In the handler, accept `auth-agent@openssh.com` only when `-A` was given
   for this connection. For each such channel, connect to the agent with the
   code of `crates/podssh-ssh/src/keys.rs:259-290`, then copy bytes. Reject
   the channel without `-A`, and warn, as OpenSSH does.
4. Write the rule and the risk in the manual's notes and in `docs/cli.md`
   (section "Forwarding"): while the session lasts, root on the server can
   use the agent's keys.
5. The agent can be OpenSSH's or `podssh agent` (T-034): both are reached
   through `SSH_AUTH_SOCK`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- agent_channel
sh scripts/dev.sh check
```

The unit test runs a russh server in the process: an agent channel without
`-A` is rejected; with `-A`, its bytes reach a stand-in agent. In the gate,
`scripts/interop.sh` starts `ssh-agent` with `$W/id_rsa` and runs
`-A ... 'ssh-add -l'`: exit 0, and the output has the key's fingerprint.
Without `-A`, `ssh-add -l` exits 2. Planted defect: accept the channel
without `-A`, and the unit test fails.

## Correction

2026-10-08, T-237: podssh's handler now refuses each channel that the
server opens, as administratively prohibited, in one place: `unasked` in
`crates/podssh-ssh/src/handler.rs`. This entry accepts its own kind there,
only for its own requests, and reads an accepted channel at once or closes
it (`SECURITY.md`, "Design rules").

# T-037: `-X` and `-Y`: X11 forwarding to the display that `DISPLAY` names

**Source:** the refusal by name since `0c93a7c` (T-016, GitHub #5). Read and
measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A user with a local X server cannot run a remote graphical program over
podssh: `-X` and `-Y` are refused. X11 forwarding needs no local listener:
the server listens, and the client connects to the local X server for each
X11 channel.

## Premise

- Measured, offline: `podssh ssh -X example.invalid true` gives "-X is
  refused. Leave it out. X11 forwarding is not supported.", exit 64; `-Y`
  the same (`crates/podssh-cli/src/flags.rs:227-230`).
- Measured, offline: `-o ForwardX11=yes` is accepted with no effect, as
  `ForwardAgent` is. Read: `ForwardX11Trusted`, `ForwardX11Timeout` and
  `XAuthLocation` are ignored too (`crates/podssh-cli/src/ssh/keywords.rs:61-74`).
- Read: russh 0.64.1 has `Channel::request_x11` (`x11-req`), and its default
  handler accepts each `x11` channel. podssh's handler does not override it
  (`crates/podssh-ssh/src/handler.rs` lines 44-88 at `8d668b7`).
- The X server's address comes from `DISPLAY`: `:N` is the socket
  `/tmp/.X11-unix/XN` (on Linux, also an abstract socket), and `HOST:N` is
  TCP port 6000+N. The cookie is in the file that `XAUTHORITY` names, else
  in `~/.Xauthority`.

## Approach

1. Probe before the connection: `DISPLAY` is set, its socket or port
   answers, and the authority file has a `MIT-MAGIC-COOKIE-1` cookie for it.
   podssh reads that file itself (its format is simple), so it needs no
   `xauth`. When a probe fails, refuse with the reason before anything
   connects (exit 255).
2. Send `x11-req` on the session channel with a random cookie of the same
   length (the spoofed cookie of OpenSSH), never the real one.
3. In the handler, accept an `x11` channel only when X11 was asked for.
   Connect to the local X server, check that the first packet carries the
   spoofed cookie, put the real cookie in its place, then copy bytes.
4. `-Y` (trusted) uses the real cookie. `-X` (untrusted) needs a cookie that
   the X server makes (`xauth generate ... untrusted`): run `xauth` only when
   a probe finds it (`XAuthLocation`, or `PATH`), as `AGENTS.md:183-187`
   allows. Else refuse `-X`, and name `-Y`.
5. Move `ForwardX11`, `ForwardX11Trusted`, `ForwardX11Timeout` and
   `XAuthLocation` to `HONOURED`. Change the help of `-x`
   (`crates/podssh-cli/src/flags.rs:178-179`).
6. On Windows, a `DISPLAY` such as `localhost:0` (VcXsrv, X410) is TCP port
   6000. The X server's connection is local and named by the user, as the
   agent's connection is (`crates/podssh-ssh/src/keys.rs:259-290`).

## Decision

Recommendation: refuse before the connection when the probe fails. podssh's
rule is an error that tells what to do, never a silent fallback
(`docs/target-environment.md:90-92`). The alternative, OpenSSH's way (a debug
line, then a session with no X11), lost: the user asked for X11 and would
not see why it is missing.

The second fork, `-X` with no `xauth`: recommendation: refuse it and name
`-Y`. The alternative, to give trusted access under `-X`, lost: it gives more
than the user asked for, and says nothing.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- x11
sh scripts/dev.sh check
```

The unit test reads an authority file made in the test, swaps the spoofed
cookie in a first packet, and rejects an `x11` channel that nobody asked for
(a russh server in the process). In the gate, `scripts/interop.sh` starts
`Xvfb :9` with a cookie, sets `X11Forwarding yes` on a test sshd that has
`xauth`, and runs `-Y ... 'xdpyinfo >/dev/null && echo x11-ok'` with
`DISPLAY=:9`: the output is `x11-ok`, exit 0. With `DISPLAY` unset: the
refusal, exit 255. Planted defect: send the real cookie in `x11-req`, and a
check that the server's `xauth list` holds the spoofed cookie fails.

## Correction

2026-10-08, T-237: podssh's handler now refuses each channel that the
server opens, as administratively prohibited, in one place: `unasked` in
`crates/podssh-ssh/src/handler.rs`. This entry accepts its own kind there,
only for its own requests, and reads an accepted channel at once or closes
it (`SECURITY.md`, "Design rules").

# T-038: `-L` and `-D` when a probe shows that a local bind is allowed

**Source:** the operator's ruling of 2026-10-08 on Q1 (`docs/decisions.md`):
a local listener when the user asks for it and a probe at run time allows
the bind; loopback and AF_UNIX by default; an address that the user sets;
listening that the user can turn off; the same refusal where the probe
fails. Also `docs/cli.md:95-99`; the totoshko88/RustConn report in GitHub
#24 (item 3) and the OthmaneBlial/MobaRust report in GitHub #21 (item 3);
sandbox A of T-001 (`bind` refused for AF_INET, allowed for AF_UNIX).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`-L` (a local port to a remote service) and `-D` (a local SOCKS proxy) are
the forwards that users know best. podssh refuses both, also on hosts that
allow a listener. Sandbox A refused `bind` for AF_INET and allowed it for
AF_UNIX.

## Premise

- Measured, offline: `-L 8080:localhost:80` and `-D 1080` are refused with
  "podssh never binds a listener", exit 64
  (`crates/podssh-cli/src/flags.rs:192-197`). Read: `-o LocalForward` and
  `-o DynamicForward` too (`crates/podssh-cli/src/ssh/options.rs:145-147`).
- Read: `AGENTS.md:177-182` (no bind, no listen),
  `docs/target-environment.md:74-78` (rule 3), `SECURITY.md:56-59` ("Nothing
  listens") and `README.md:36` state the rule from before the ruling.
  `docs/design.md:252-254` already allows a local listener for `pipe` after
  a probe.
- Read: the Podman box refuses each `bind` (`scripts/box/seccomp.json:5-10`),
  so it tests the refusal.
- Read: `podssh doctor` binds and closes without `listen()`
  (`crates/podssh-cli/src/doctor/unix.rs:137-164`,
  `crates/podssh-cli/src/doctor/unix.rs:169-186`). A seccomp filter can allow
  `bind` and refuse `listen`, so the probe for `-L` must also listen once.
- Read: the remote end exists: `forward::open` opens `direct-tcpip`
  (`crates/podssh-ssh/src/forward.rs:11-18`).

## Approach

1. Listen only when the user asks (`-L`, `-D`). Probe at the start of the
   run: bind and listen on the address asked for (loopback or an AF_UNIX
   path, by default), and keep that socket. When the probe fails, refuse
   before anything connects, with the probe's error and `-W HOST:PORT`, as
   today.
2. `-L [bind:]port:host:hostport` and `-L PATH:host:hostport`: for each
   accepted connection, open `direct-tcpip` with `forward::open`, and copy
   bytes.
3. `-D [bind:]port` and `-D PATH`: SOCKS4, SOCKS4a and SOCKS5, with CONNECT
   only and no authentication; one `direct-tcpip` channel for each request.
   Refuse BIND and UDP ASSOCIATE.
4. The user sets the address as in OpenSSH: the `bind_address` of the spec,
   and a wildcard address only with `-g` or `GatewayPorts yes`, which have no
   effect today (`crates/podssh-cli/src/flags.rs:185-186`,
   `crates/podssh-cli/src/ssh/keywords.rs:67`). Remove an AF_UNIX socket at
   exit; with `StreamLocalBindUnlink`, remove a stale one first.
5. The user turns listening off: `-o ClearAllForwardings=yes` for one run
   (OpenSSH's keyword, ignored today,
   `crates/podssh-cli/src/ssh/keywords.rs:64`), and for a whole host a
   variable that refuses each local listener (`-L`, `-D`, T-039, T-034). Add
   it to `VARIABLES` in `crates/podssh-cli/src/man/facts.rs`.
6. In the same commit, change the rows, the keywords, the note at
   `crates/podssh-cli/src/man/notes.rs:31-33`, the test at
   `crates/podssh-cli/tests/flag_table.rs:67-86`, and the documents that the
   Premise quotes.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- local_forward
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The first test parses the forms of `-L` and `-D`. In the gate,
`-N -L 127.0.0.1:2280:127.0.0.1:2203` gives Dropbear's banner on port 2280,
`-L $W/l.sock:127.0.0.1:2203` gives it on the socket, and a SOCKS5 client in
Python reaches 127.0.0.1:2203 through `-D 127.0.0.1:2281`. In the box, where
`bind` is refused, `-L` on 127.0.0.1 is refused before anything connects,
with the probe's error, exit 255. With the variable of step 5 set, `-L` is
refused on any host. Planted defect: skip the probe, and the check in the
box fails.

# T-039: Connection sharing: `ControlMaster`, `ControlPath`, `-O` and `-S` over an AF_UNIX socket

**Source:** the operator's ruling of 2026-10-08 on Q1 (`docs/decisions.md`;
a local listener when the user asks for it and a probe allows the bind).
The lablup/bssh report in GitHub #18, #20 and #22 (item 9,
`lablup/bssh:src/ssh/control/`, the `-O` commands and the meaning of `-S`);
the sleepinginsummer/agent-ssh-cli report in GitHub #21 (item 4, a pool of
connections and `stop-daemon`); the ImKKingshuk/USBoverSSH report in GitHub
#25 (item 3, a connection pool). Read in the reports. Measured here on
`3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Each run of `podssh ssh` makes a new relay session, a new key exchange and a
new login. A script that runs many short commands pays this each time.
OpenSSH shares one connection through a control socket (`-M`, `-S`, `-O`,
`ControlMaster`, `ControlPath`, `ControlPersist`).

## Premise

- Measured, offline: `-M`, `-S /tmp/ctl` and `-O check` are refused with
  "podssh keeps no control master: each run is one connection", exit 64
  (`crates/podssh-cli/src/flags.rs:217-222`).
- Measured, offline: `-o ControlMaster=auto -o ControlPath=/tmp/c` is
  accepted with no effect; only `-v` says so
  (`crates/podssh-cli/src/ssh/keywords.rs:65`). A script that sets them still
  works, with one connection for each run.
- Read: a control socket is a listener. `AGENTS.md:177-182` forbids it in the
  words from before the ruling. Sandbox A allowed a bind for AF_UNIX
  (T-001); the Podman box refuses each `bind`
  (`scripts/box/seccomp.json:5-10`).
- Read: the relay's limits apply to the shared connection: all the sessions
  of a master share one 64 MiB and one 12 h (`docs/relay.md:109-115`).

## Approach

1. Listen only when the user asks: `-M`, or `ControlMaster yes|auto|autoask`
   with `ControlPath`. After a probe (bind and listen on the AF_UNIX path,
   mode 0600, in a directory of mode 0700), the first run becomes the master
   and serves new sessions on the socket. When the probe fails, refuse with
   its reason, as today; with `ControlMaster auto`, say it and connect alone.
   The variable of T-038 (step 5) refuses the master on a whole host.
2. A client run with `-S PATH`, or with `ControlPath` and
   `ControlMaster auto`, asks the master for a session, a `-W` stream or a
   forward. When no master answers, it connects alone, as OpenSSH does.
3. `-O check|exit|stop|forward|cancel`. `ControlPersist` keeps the master
   after its last session, for a limited time.
4. Unix only: the session's stdin, stdout and stderr go to the master as
   file descriptors (SCM_RIGHTS). On Windows, refuse with a clear message.
5. Pitfalls: remove a stale socket when nothing answers; say in the manual
   that the master's relay session reaches 64 MiB for all clients together;
   a drop of the master ends each client, and the message of T-024 names it.

## Decision

Recommendation: the protocol of OpenSSH's control socket (`PROTOCOL.mux` in
OpenSSH's source), so that `ssh -O check` and the scripts that use it work
with a podssh master. The alternative, a podssh protocol, lost: it serves
podssh clients only, and the `-O` commands would need a second meaning.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- mux_protocol
sh scripts/dev.sh check
```

The unit test encodes and decodes each message of the control protocol
against bytes captured from OpenSSH's `ssh -M` and `ssh -O check`. In the
gate, a master `-M -N -S $W/ctl` serves `podssh ssh -S $W/ctl ... 'exit 3'`
(exit 3), and the stand-in relay's log shows one upgrade for both runs. The
`ssh -O check` of OpenSSH answers `Master running` for the podssh master. In
the box (`scripts/test_in_box.sh`), `-M` is refused with the probe's reason.
Planted defect: let the client open its own relay session, and the log shows
two upgrades.

# T-040: `-W` to a Unix socket on the server (streamlocal)

**Source:** the ImKKingshuk/USBoverSSH report in GitHub #25 (item 9, Unix
socket forwarding over SSH); GitHub #26 ("a name for AF_UNIX streams"). Read
in the reports. Measured here on `3ee70dc`, and with OpenSSH 10.3p1.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A service on the server that listens only on a Unix socket (a database, a
container engine) cannot be reached with `podssh ssh -W`. Also, podssh reads
`-W /path/to/socket` as a TCP host named `/path/to/socket` on port 22, where
OpenSSH reads a socket path.

## Premise

Measured, offline, with `MSYS_NO_PATHCONV=1` and `PODSSH_OFFLINE=1`:

- `podssh ssh -v -W /tmp/sock example.invalid` passes the parse and reaches
  the connection step (exit 255 only because of `PODSSH_OFFLINE`).
  `-W /tmp/sock:22` too. `-W db.internal`, with no port, is read as port 22.
- OpenSSH 10.3p1, which does not connect with `-G`:
  `ssh -F /dev/null -G -W /tmp/sock example.invalid` exits 0, so OpenSSH
  accepts a path. `ssh -F /dev/null -G -W foo example.invalid` exits 255 with
  `Bad stdio forwarding specification 'foo'`: OpenSSH needs a port.

Read:

- `request` parses the value of `-W` with `parse_hop`
  (`crates/podssh-cli/src/ssh/resolve.rs:297-306`), which reads a value with
  no `:` as a host on port 22 (`crates/podssh-cli/src/ssh/resolve.rs:336-349`).
- russh 0.64.1 has `Handle::channel_open_direct_streamlocal` (the channel
  `direct-streamlocal@openssh.com`). podssh opens only `direct-tcpip`
  (`crates/podssh-ssh/src/forward.rs:11-18`).

## Approach

1. T-239 refuses a path and a value with no port now (M3). This entry turns
   the refusal of a path into the streamlocal channel. Add a kind of target
   to `Request::StdioForward` (`crates/podssh-ssh/src/options.rs:67-68`).
2. Open a socket with `channel_open_direct_streamlocal` in
   `crates/podssh-ssh/src/forward.rs`, and use the copy loop of `stdio`
   (`crates/podssh-ssh/src/forward.rs:20-81`) for both kinds.
3. A server that refuses the channel (OpenSSH with
   `AllowStreamLocalForwarding no`) gives its reason, and 255, as for TCP.
4. Change the help of the `-W` row (`crates/podssh-cli/src/flags.rs:139-140`)
   and `docs/cli.md:68-69`, and add an example to the manual. A local socket
   is the work of T-176 (`pipe`).

## Decision

Recommendation: OpenSSH's own spelling, `-W /path`, which OpenSSH accepts
(measured above). A command line then means the same in both clients, which
`docs/cli.md:8-10` promises. The alternative, a podssh prefix such as
`unix:/path`, lost: no other client reads it, and podssh would still read
`-W /path` differently from OpenSSH.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- stdio_forward_socket
sh scripts/dev.sh check
```

The first test parses `/tmp/s`, `host:5432` and `[::1]:5432`, and refuses
`foo` with exit 64. In the gate, `scripts/interop.sh` starts a Unix echo
server in Python on the server's side, and pipes `ping` through
`-W $W/echo.sock`: the output is `ping`, exit 0. Planted defect: read a path
as a TCP host again, and the gate's check fails with the server's error.

# T-041: The forwards of a session: a list and byte counts

**Source:** the OthmaneBlial/MobaRust report in GitHub #21 (item 3, state and
byte counts, a stop action), the rssh-org/rssh report in GitHub #24 (item 3,
statistics in real time), and the yituorou/meatshell report in GitHub #21
(item 6, a tunnel panel). Read in the reports.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

When a session carries forwards (`-R` from T-035, `-W`, later `-L`), the user
cannot see which ones are open, how many connections each carried, or how
many bytes moved.

## Premise

Read: today the only forward is `-W` (`crates/podssh-ssh/src/forward.rs:20-81`),
and it counts nothing. The escapes are `~.`, `~R`, `~?` and `~~`
(`crates/podssh-ssh/src/escape.rs:1-13`); OpenSSH also has `~#`, which lists
the forwarded connections. `podssh status` (T-051) runs in another process,
so it cannot see the forwards of a session without a state file or a
listener.

## Approach

1. Count, for each forward: the connections opened, closed and failed, and
   the bytes in each direction. Keep the counters in the forward's own task;
   put no lock on the data path.
2. Add `~#` to the escapes (`crates/podssh-ssh/src/escape.rs:7-13`) and to its
   help (`crates/podssh-ssh/src/escape.rs:72-80`): one line for each forward,
   with its counts.
3. At the end of a session, with `-v`, print one line for each forward. Do
   not call it "Transferred": OpenSSH's line of that name counts the bytes of
   the whole connection.
4. A stop action (OpenSSH's `~C` with `-KR`) is a later step: it needs the
   command line of `~C`.
5. Give the counts to the machine-readable result of T-054 when it exists.
   This entry depends on T-035.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- forward_counts
sh scripts/dev.sh check
```

The unit test copies a known number of bytes through a forward task, and
reads its counters. In the gate, a run with `-v`, `-W` and 262144 bytes up
prints a line with 262144 bytes sent, and `scripts/interop-pty.py` types
`~#` in a session with a `-R` forward and reads the list. Planted defect:
count each chunk twice, and the unit test fails.

# T-042: `-R` forwards come back after a drop

**Source:** the Petyok/SSHub report in GitHub #22 (item 4, a tunnel
keep-alive that connects dropped forwards again, with exponential backoff).
Read in the report.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A session that only carries forwards (`podssh ssh -N -R ...`) stays down
after the relay drops it. The user must notice it and start it again. A
remote forward is often a service that must last, and the relay drops some
sessions (GitHub #17).

## Premise

Read: a drop ends the run with 255 (`crates/podssh-ssh/src/run.rs:38-47`,
`crates/podssh-ssh/src/run.rs:97-105`). `podssh_relay::open` fails over and
backs off with jitter, but only before a session exists
(`crates/podssh-relay/src/open.rs:174-213`,
`crates/podssh-relay/src/open.rs:263-277`). With `-N`, no command runs, so a
new connection has no side effect on the server. `docs/design.md:204-209`
puts a new connection with a new login in layer 3, for a standard sshd.
T-153 (M6) resumes a session when both ends run podssh.

## Approach

1. Only for `-N` with one `-R` or more, and only on request: a podssh flag,
   shared with `--persist` of T-178 (which attaches `tmux` again).
2. After a drop: wait with the jittered backoff of `open` (1 s, doubled up to
   30 s), open a new relay session with failover, log in again, check the
   host key as before, and send each `tcpip-forward` again.
3. Log in again only with no person: keys and the agent. A prompt needs
   `SSH_ASKPASS`; else stop, as `BatchMode` does.
4. The old listener on the server can hold the port until the server sees
   that the old connection is dead. Repeat a refused `tcpip-forward` with the
   backoff for 2 minutes at most, then stop with the message of T-035. A port
   that the server chose (port 0) can change: print the new one.
5. Print each drop and each return on stderr, with the hop that T-024 names.
   This entry depends on T-035.

## Prove

```sh
sh scripts/dev.sh check
```

In the fault harness (`scripts/interop-faults.sh`), a run with the new flag,
`--relay-host` set to `relay-kill` then `relay-a`, and
`-N -R 127.0.0.1:2291:127.0.0.1:2203` carries a connection to port 2291.
Then the stand-in relay `relay-kill` stops, as at
`scripts/interop-faults.sh:152-162`. Within 60 s, a new connection to port
2291 reads Dropbear's banner again. Planted defect: no new connection, and
the second read fails.

# T-239: `-W` with a path, or with no port, is read as a TCP host on port 22

**Source:** found while writing T-040 (2026-10-08). Measured here on
`3ee70dc`, and against OpenSSH 10.3p1 with `ssh -G`, which does not connect.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`podssh ssh -W /run/db.sock host` asks the server for a TCP connection to a
host named `/run/db.sock` on port 22, where OpenSSH reads a socket path.
`podssh ssh -W db.internal host` connects to port 22, where OpenSSH refuses
a value with no port. Each form changes the meaning of an OpenSSH command
line, with no message.

## Premise

Measured, offline, with `MSYS_NO_PATHCONV=1`. `PODSSH_OFFLINE=1` stops podssh
at the connection step (exit 255), after the parse:

| `-W` value | OpenSSH 10.3p1 (`ssh -F /dev/null -G`) | podssh |
| --- | --- | --- |
| `/tmp/sock` | accepted (a socket path) | accepted: TCP host `/tmp/sock`, port 22 |
| `/tmp/sock:22` | accepted | accepted: TCP host `/tmp/sock`, port 22 |
| `db.internal` | `Bad stdio forwarding specification 'db.internal'`, exit 255 | accepted: port 22 |
| `5432` | accepted (its meaning is not measured) | accepted: TCP host `5432`, port 22 |
| `db.internal:5432`, `[::1]:5432` | accepted | accepted |

Read: `request` parses the value with `parse_hop`
(`crates/podssh-cli/src/ssh/resolve.rs:297-306`), which reads a value with no
`:` as a host on port 22, and splits a value at its one `:`
(`crates/podssh-cli/src/ssh/resolve.rs:336-349`). `forward::open` opens
`direct-tcpip` only (`crates/podssh-ssh/src/forward.rs:11-18`).

## Approach

1. In `request`, before `parse_hop`: refuse a value that holds a `/` with
   exit 64: "-W PATH: a Unix socket on the server is not supported yet".
   T-040 turns this refusal into the streamlocal channel.
2. Refuse a value with no port (no `:` outside brackets) with exit 64:
   "-W db.internal: expected HOST:PORT", as OpenSSH refuses it. This also
   refuses `-W 5432`, whose meaning in OpenSSH is not known here.
3. Keep `HOST:PORT` and `[v6]:PORT`. A `-J` hop keeps its own parse, where a
   host alone means port 22, as in OpenSSH.
4. Add the rule to `docs/cli.md:68-69`. The help of the `-W` row
   (`crates/podssh-cli/src/flags.rs:139-140`) already says `HOST:PORT`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- stdio_forward_form
PODSSH_OFFLINE=1 target/debug/podssh ssh -W db.internal example.invalid </dev/null; echo "exit=$?"
```

The test, in `crates/podssh-cli/tests/ssh_args.rs`, refuses `/tmp/sock`,
`/tmp/sock:22`, `db.internal` and `5432` with exit 64 and a message that
names the form, and accepts `db.internal:5432` and `[::1]:5432`. The binary
prints the refusal and exits 64, before anything connects. Planted defect:
remove the check of step 2, and the test fails for `db.internal`.
