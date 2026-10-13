Forwarding in `podssh ssh`: remote forwards, the agent, X11, local forwards
and connection sharing (a local listener after a probe, as the operator
ruled on 2026-10-08), streams to Unix sockets on the server, and the state
of the forwards of a session.

# T-035: `-R`: remote forwarding, each connection made out through the proxy

**Source:** `docs/ROADMAP.md:251-252` (M8) and `docs/cli.md`, lines 153-158 at `a9299c4`; the
VLOD-ZDOV/quic-ssh report in GitHub #22 (item 7) and the cubic-vm/cubic
report in GitHub #23 (item 7). Read and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

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
- Read: the row and the refusals are `crates/podssh-cli/src/flags.rs`, lines 206-207 at `a9299c4`,
  `crates/podssh-cli/src/ssh/options.rs`, line 162 at `a9299c4` and
  `crates/podssh-cli/src/ssh/keywords.rs`, line 85 at `a9299c4`. `-W` is not a substitute: it
  carries the other direction.
- Read: the manual's note says "-L, -R and -D are refused by name: podssh
  never listens on a port" (`crates/podssh-cli/src/man/notes.rs` lines 31-32
  at `25ab0e7`), but `docs/cli.md`, lines 153-155 at `a9299c4` says that the refusal of `-R` must
  not say that.
- Read: russh 0.64.1 has `Handle::tcpip_forward`, and its default handler
  accepts each `forwarded-tcpip` channel that a server opens. podssh's handler
  does not override it (`crates/podssh-ssh/src/handler.rs` lines 44-88 at
  `8d668b7`).
- Read: `dial` goes through `HTTPS_PROXY`, but never for a loopback target
  (`crates/podssh-ws/src/dial.rs:103-109`,
  `crates/podssh-ws/src/dial.rs:151-197`). On the measured sandbox, a direct
  connection to loopback is refused (`docs/target-environment.md:22`).
- Read: a refused `tcpip-forward` gets SSH_MSG_REQUEST_FAILURE, which has no
  reason field (RFC 4254, section 4). So `docs/cli.md`, line 158 at `a9299c4` ("podssh gives the
  server's reason") cannot hold as written.

## Approach

1. Parse the specs of OpenSSH, `[bind:]port:host:hostport`, from `-R` and
   from `-o RemoteForward`. Refuse by name the forms with a socket path and
   the remote SOCKS form (`-R [bind:]port`) until a later step.
2. After the login, send `tcpip-forward` for each spec. Print a port that the
   server chose, as OpenSSH does. Honour `ExitOnForwardFailure`, which is
   ignored today (`crates/podssh-cli/src/ssh/keywords.rs`, line 69 at `a9299c4`): a refused
   forward then ends the run with 255.
3. In the handler, accept a `forwarded-tcpip` channel only for an address and
   a port that podssh asked for, and reject the rest. Dial the spec's target
   with `podssh_ws::dial::dial` and `ProxyChoice::FromEnvironment`, as
   `--direct` does (`crates/podssh-cli/src/ssh/transport.rs:159-165`), with the
   limit of 20 s (`crates/podssh-relay/src/open.rs:28-30`).
4. Copy both ways. Pass EOF on in each direction, and close both ends on an
   error. The SSH window is the flow control.
5. A failed dial closes that channel only, and says why on stderr: the
   proxy's answer, or the error of a refused loopback connection.
6. Change the `-R` row to supported and the keyword to honoured. T-230
   corrected the texts of the `-R` refusal (the help and the manual's note
   at `crates/podssh-cli/src/man/notes.rs`, lines 70-72 at `a9299c4`). Change the test that
   asserts the refusal (`crates/podssh-cli/tests/flag_table.rs`, lines 82-101 at `a9299c4`).
   Update `docs/cli.md`, lines 146-160 at `a9299c4` (correct line 78 at `e8bbd4d`) and `docs/STATUS.md`.
7. Pitfalls: each forwarded connection is one more outbound connection, made
   under the proxy rule of `AGENTS.md:226-231`; say so in the help. The relay's
   64 MiB and 12 h cover all the forwarded connections of a session
   together.

## Decision

2026-10-10, in the work:
- The forwards are asked in the login of the destination (`crates/podssh-ssh/src/run.rs`), where
  the handler that must find them is made: no signature of the client changes, and `--persist`
  asks again after each new connection. A forward that the server refuses with
  `ExitOnForwardFailure` is `HopError::Forward`, which `cp` and `pipe ssh:` map as an unreachable
  far end; they ask for no forward.
- The bind address is kept as given (`RemoteForward::bind`, an `Option`), so `-G` prints it as
  OpenSSH does; the address sent is OpenSSH's (`sent_address`): `localhost` for none, the empty
  string for an empty one or `*`.
- A channel's forward is found by the port that the server names, and by its address only
  between two forwards on one port: a server may name its own address.
- `-G` prints `exitonforwardfailure` and each `remoteforward`, where and as OpenSSH 10.3p1
  prints them (captured in the build image): a port alone when no address was given, each host
  in brackets.

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
gives `-R` a sentence of its own (`crates/podssh-cli/src/man/notes.rs`, lines 70-72 at `a9299c4`).
The rest of the Premise holds.

2026-10-08, T-237: podssh's handler now refuses each channel that the
server opens, as administratively prohibited, in one place: `unasked` in
`crates/podssh-ssh/src/handler.rs`. This entry accepts its own kind there,
only for its own requests, and reads an accepted channel at once or closes
it (`SECURITY.md`, "Design rules").

2026-10-10, CI at `c0cdd2b` (run 38029691616): the check of the Prove that
`-R 22:127.0.0.1:2203` is refused failed in the job `gate (release)`. Its
Docker lets a user bind a port under 1024, so OpenSSH gave the forward,
and the check waited for its limit (exit 143); in the build image of the
developer machine the kernel refused the port. The check now asks for port
2291, which `PermitListen 2290` of the server on port 2201 refuses whatever
the kernel allows (`scripts/interop.sh`). In CI at `28eab6b` (run 38033483197):
interop 222 passed, 0 failed.

## Done

2026-10-10. `-R [bind_address:]port:host:hostport` and `-o RemoteForward=[bind_address:]port
host:hostport` work: after the login, podssh asks the destination for each forward
(`crates/podssh-ssh/src/remote.rs`), prints a port that the server chose, and accepts a
`forwarded-tcpip` channel only for a forward that the server took; it dials the target with
`podssh_ws::dial` and `ProxyChoice::FromEnvironment` within 20 s, and copies both ways with each
end of input passed on; a failed dial closes that channel only, and says why
(`crates/podssh-ssh/src/handler.rs`). A refused forward is a warning, and with
`-o ExitOnForwardFailure=yes`, now honoured, the end of the run with 255. The specs are parsed in
`crates/podssh-cli/src/ssh/forward.rs`; a socket path and the server's SOCKS proxy are refused
by name, with 64. The `-R` row is supported, the keywords honoured, and the help, the manual's
note, `docs/cli.md` and `-G` say so; the two tests of T-230 that held the words of the refusal
now hold that the server listens, with no `-W` and no local listener.
- Native, Windows 11: `cargo test -p podssh-cli --test ssh_args -- remote_forward`, 1 passed (the
  TCP forms, the command line's first, and seven refusals with 64); the spec parser's unit tests,
  2 passed; `cargo test -p podssh-ssh -- forwarded_channel`, 2 passed, against a russh server in
  the process over a pipe (a channel for the port that the server chose reaches an echo target and
  back whole; one for another port is refused; a target that is down closes its channel), and
  `a_refused_forward_warns_or_ends_the_run`. Planted, a channel accepted for any port: the first
  test fails. `--test ssh_config`, 3 passed, with OpenSSH 10.3p1's lines for four forwards and
  `ExitOnForwardFailure`. clippy with no warning. `cargo test --workspace`: 1152 passed, 0
  failed, 38 ignored.
- In the build image, `scripts/interop.sh` with the two new checks: 218 passed, 0 failed: OpenSSH's port 2290 reached Dropbear's banner through podssh, and `-R 22:127.0.0.1:2203` with `ExitOnForwardFailure=yes` exited 255 and named the port (OpenSSH 10.3p1 and Dropbear, a debug build, 2026-10-10).

# T-036: `-A`: agent forwarding, off by default as in OpenSSH

**Source:** the operator's ruling of 2026-10-08 on Q2: implement `-A`, off by
default as in OpenSSH (`docs/decisions.md`). The l0ng-ai/tty7 report in
GitHub #20 (item 9, "keep the refusal explicit"; read in the report). Read
and measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A user who logs in to a host, and from there to a second host with a key
that stays on the first machine, needs agent forwarding. podssh refuses `-A`
and points to `-J`. `-J` covers the common case, but not a program on the
remote host that must use the key, such as `git` on a build host.

## Premise

- Measured, offline: `podssh ssh -A example.invalid true` gives "-A is
  refused. Use -J HOST (log in through the jump host) instead. agent
  forwarding is not supported.", exit 64
  (`crates/podssh-cli/src/flags.rs`, lines 218-219 at `3408de9`).
- Measured, offline: `-o ForwardAgent=yes` is accepted with no effect; only
  `-v` says so ("-o ForwardAgent has no effect in podssh"). The keyword is
  in `IGNORED` (`crates/podssh-cli/src/ssh/keywords.rs`, line 72 at `3408de9`). So the flag
  refuses, and the keyword is silent.
- Read: podssh already connects to the local agent to log in: `SSH_AUTH_SOCK`
  on Unix; the named pipe of the OpenSSH agent, then Pageant, on Windows
  (`crates/podssh-ssh/src/keys.rs:334-371`, `connect_agent`). That is a
  connection, not a listener.
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
   (`crates/podssh-cli/src/ssh/keywords.rs:25-98`). Change the help of `-a`
   (`crates/podssh-cli/src/flags.rs:218-219`, the row `no-agent-forwarding`).
2. On the destination's session channel, send `auth-agent-req@openssh.com`
   before the shell or exec request (`crates/podssh-ssh/src/session.rs:111-135`).
   Never to a jump hop.
3. In the handler, accept `auth-agent@openssh.com` only when `-A` was given
   for this connection. For each such channel, connect to the agent with the
   code of `crates/podssh-ssh/src/keys.rs:334-371` (`connect_agent`), then copy bytes. Reject
   the channel without `-A`, and warn, as OpenSSH does.
4. Write the rule and the risk in the manual's notes and in `docs/cli.md`
   (section "Forwarding"): while the session lasts, root on the server can
   use the agent's keys.
5. The agent can be OpenSSH's or `podssh agent` (T-034): both are reached
   through `SSH_AUTH_SOCK`.

## Decision

2026-10-11.

- `yes` forwards the agent that podssh logs in with: `IdentityAgent`, else
  `SSH_AUTH_SOCK` (on Windows also OpenSSH's named pipe, then Pageant).
  OpenSSH sets `SSH_AUTH_SOCK` to `IdentityAgent` before it forwards, so
  this is its rule. Lost: always `SSH_AUTH_SOCK`, which would forward
  another agent than the one the user named.
- The flags win over `-o ForwardAgent`, and the last of `-A` and `-a` wins
  (clap's index of each), as OpenSSH sets the option at each flag. A path
  given to `ForwardAgent` is kept apart from yes and no, as in OpenSSH:
  `-A -o ForwardAgent=PATH` forwards PATH. Lost: `-a` always wins, which
  is simpler but not OpenSSH's.
- A whole `$NAME` is the variable that holds the path, as ssh_config(5)
  says; `${NAME}` in a path is a variable for each path keyword, as
  OpenSSH 10.3p1 expands it, measured with its `ssh -G` (an unset one is
  refused, 64). OpenSSH's own `-G` keeps a whole `$NAME`, and so does
  podssh's.
- The request asks for a reply, and a refusal is said; OpenSSH asks for
  none and says nothing. Lost: silence, which leaves a user with `-A` and a
  server that refuses it with no clue.
- `podssh scp -A` and `podssh sftp -A` are accepted with no effect (T-139
  refused them, "agent forwarding is not supported", no longer true): a
  copy runs nothing on the server that would use an agent, and their
  connections take no agent channel even with `-o ForwardAgent=yes`.
- No `session-bind@openssh.com`: russh keeps neither the session
  identifier nor the server's signature where a client can read them.
  T-279 holds the work; `SECURITY.md` and `docs/cli.md` say what it means.

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

## Done

2026-10-11. `-A` forwards the agent (`crates/podssh-ssh/src/agent_forward.rs`):

- `Options::forward_agent` (an `Agent`, `Off` by default) is set for the
  destination alone; `run::connect` gives each jump hop's handler
  `Agent::Off`. `session::attach` sends `auth-agent-req@openssh.com`
  before the shell, the command or the subsystem when it is on.
- The handler accepts an agent channel only when it is on: a task of its
  own connects to the agent with `keys::connect_agent` (10 s at most),
  accepts, and copies both ways; once one side ends, the other gets an end,
  then 5 s, then both close, so a named pipe, with no half-close, does not
  outlive its channel. An agent that cannot be reached refuses the channel
  (connect failed), said once at info and then with `-v`. With no `-A`,
  `unasked` refuses it as before, with the warning.
- The command line: `-A` is a supported flag, `-a` turns it off, the last
  wins; `ForwardAgent` moved from `IGNORED` to `HONOURED`
  (`yes|no|PATH|$NAME`, default no); `-G` prints `forwardagent` before
  `connecttimeout`, as OpenSSH 10.3p1 does (its captured lines in
  `tests/ssh_config.rs` and `tests/ssh_config_file.rs` gained the line).
  `crates/podssh-cli/src/ssh/agents.rs` reads `IdentityAgent` and
  `ForwardAgent`; `Tokens::expand` expands `${NAME}` in each path keyword.
- Documents: `docs/cli.md` (the tokens, and "Forwarding" with the risk),
  the manual's notes, `SECURITY.md` (Known gaps), T-279 for the bind.

Prove, native, Windows: `cargo test -p podssh-ssh -- agent_channel`, 5
passed: with `-A` the request comes before the exec and the stand-in
agent's answer reaches the server, whose request reached the agent, and the
agent's connection ends with its channel; without `-A` the channel is
refused as administratively prohibited, with the warning; a jump hop with
`-A` refuses it; an agent that is not there refuses it as connect failed,
and says so; the splice closes a side with no half-close after the grace.
Plants: accepting with no `-A`, forwarding to a jump hop, no request, and
no close after the grace each failed a test. `cargo test -p podssh-cli
--test ssh_agent_forward`, 7 passed (the default, the last of `-A` and
`-a`, the flags over the keyword, a path with its tokens, `$NAME`, yes as
`IdentityAgent`, `${NAME}` in a path); plants: the keyword over the flags,
the first flag winning, on by default, `$NAME` read as a path, `${NAME}`
not expanded, and yes forwarding `SSH_AUTH_SOCK` over `IdentityAgent`, each
failed a test.

In the build image (`sh scripts/dev.sh run`, a musl build): the five tests of `agent_channel` passed on Linux too (a Unix socket, which half-closes, so the agent's connection ended at once), and `cargo test -p podssh-cli --test ssh_agent_forward --test ssh_config --test scp_args` passed; `scripts/interop.sh` 259 passed, 0 failed, with the cases of `scripts/interop-agent.sh` against OpenSSH 10.3p1's sshd and agent: with `-A` OpenSSH's `ssh-add -l` on the server listed the key of OpenSSH's `ssh-agent` (exit 0), and through `-J` too; without `-A`, and with `-A -a`, it found no agent (exit 2); `-o ForwardAgent=PATH` with no `SSH_AUTH_SOCK` forwarded that agent; and `podssh agent` (T-034) forwarded with `-A` showed its key on the server. Nothing waits for T-251.

# T-037: `-X` and `-Y`: X11 forwarding to the display that `DISPLAY` names

**Source:** the refusal by name since `0c93a7c` (T-016, GitHub #5). Read and
measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A user with a local X server cannot run a remote graphical program over
podssh: `-X` and `-Y` are refused. X11 forwarding needs no local listener:
the server listens, and the client connects to the local X server for each
X11 channel.

## Premise

- Measured, offline: `podssh ssh -X example.invalid true` gives "-X is
  refused. Leave it out. X11 forwarding is not supported.", exit 64; `-Y`
  the same (`crates/podssh-cli/src/flags.rs`, lines 259-262 at `e58ebcd`).
- Measured, offline: `-o ForwardX11=yes` is accepted with no effect, as
  `ForwardAgent` is. Read: `ForwardX11Trusted`, `ForwardX11Timeout` and
  `XAuthLocation` are ignored too (`crates/podssh-cli/src/ssh/keywords.rs:84-98`).
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
   a probe finds it (`XAuthLocation`, or `PATH`), as `AGENTS.md:232-236`
   allows. Else refuse `-X`, and name `-Y`.
5. Move `ForwardX11`, `ForwardX11Trusted`, `ForwardX11Timeout` and
   `XAuthLocation` to `HONOURED`. Change the help of `-x`
   (`crates/podssh-cli/src/flags.rs:213-214`).
6. On Windows, a `DISPLAY` such as `localhost:0` (VcXsrv, X410) is TCP port
   6000. The X server's connection is local and named by the user, as the
   agent's connection is (`crates/podssh-ssh/src/keys.rs:334-371`, `connect_agent`).

## Decision

Recommendation: refuse before the connection when the probe fails. podssh's
rule is an error that tells what to do, never a silent fallback
(`docs/target-environment.md:91-93`). The alternative, OpenSSH's way (a debug
line, then a session with no X11), lost: the user asked for X11 and would
not see why it is missing.

The second fork, `-X` with no `xauth`: recommendation: refuse it and name
`-Y`. The alternative, to give trusted access under `-X`, lost: it gives more
than the user asked for, and says nothing.

Taken, with these calls made in the work (2026-10-11). With no cookie for the
display, the probe asks the X server for a connection with none, and when it
takes one (VcXsrv and X410 with access control off, on Windows) the channels
carry none; else the run is refused, as decided. The last of `-X`, `-Y` and
`-x` wins, and `-Y` also sets `ForwardX11Trusted`, as `ssh.c` does; `-X`'s
cookie lasts `ForwardX11Timeout` and a minute more (`xauth ... timeout`), as
OpenSSH asks, and after the timeout a new X11 channel is refused. X11 is asked
for on a session alone, never with `-N` or `-W`, where OpenSSH asks for none
either, and on the destination alone; such a run makes a connection of its
own, as a master's session would not ask. A first packet with another cookie
closes its channel. A Linux abstract socket is not tried: the socket of the
file system alone.

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

## Done

2026-10-11. The display, the authority file, the probe, the request and the
swap of the cookie in `crates/podssh-ssh/src/x11.rs:1-339`; the session asks
(`crates/podssh-ssh/src/session.rs:100-102`) and the handler joins an `x11`
channel when the destination's run asked
(`crates/podssh-ssh/src/handler.rs:263-276`). The plan and the probe of the
command line in `crates/podssh-cli/src/ssh/x11.rs:1-153`, the flags at
`crates/podssh-cli/src/flags.rs:267-270`, and the keywords, honoured now, at
`crates/podssh-cli/src/ssh/keywords.rs:44-46` and
`crates/podssh-cli/src/ssh/keywords.rs:78`.
- `cargo test -p podssh-ssh --lib -- x11`: 4 passed: `DISPLAY` as Xlib reads
  it, the cookie of a display in an authority file, the real cookie in the
  first packet in both byte orders (none for an X server that takes none, and
  another cookie refused), and the end of `-X`'s time.
- `cargo test -p podssh-cli --test ssh_x11`: 3 passed: the plan of the flags
  and keywords; the probe's refusals (no `DISPLAY`, `-X` with no `xauth`
  naming `-Y`, no cookie for an X server that wants one); and against the
  test's server, which opens an `x11` channel back, a fake X server on the
  loopback got the real cookie while the server had a spoofed one. Planted,
  each restored: the real cookie in `x11-req` (the Prove's plant) failed the
  channel's test; the first packet passed on as it came failed it and the
  swap's unit test.
- `scripts/interop-x11.sh:1-61`, a new harness of four checks against
  OpenSSH's sshd with `X11Forwarding` and an Xvfb in the box: `x11.trusted`
  (`xdpyinfo` through `-Y`), `x11.spoofed` (the server's `xauth list` holds
  no real cookie), `x11.untrusted` (`-X`, env-allowed for an Xvfb with no
  SECURITY extension) and `x11.no_display`. The gate runs them at this push.
- At `f2631b4` the gate passed `x11.trusted`, `x11.spoofed` and
  `x11.no_display`, and failed `x11.untrusted`: the Xvfb refused the
  untrusted cookie of `xauth` that podssh put in place ("Invalid
  MIT-MAGIC-COOKIE-1 key"). The check now asks first, with no podssh, whether
  this Xvfb takes an untrusted cookie of `xauth` at all
  (`scripts/interop-x11.sh:37-51`): env when it does not, a failure when it
  does and podssh's `-X` fails.
- `docs/cli.md:453-476`, a note of the manual and the variable `XAUTHORITY`
  say what the flags do, and the risk of `-Y`.
- `cargo test -p podssh-ssh`: 155 passed; `cargo test -p podssh-cli`:
  577 passed, 0 failed, 31 ignored; clippy; rustfmt.

# T-038: `-L` and `-D` when a probe shows that a local bind is allowed

**Source:** the operator's ruling of 2026-10-08 on Q1 (`docs/decisions.md`):
a local listener when the user asks for it and a probe at run time allows
the bind; loopback and AF_UNIX by default; an address that the user sets;
listening that the user can turn off; the same refusal where the probe
fails. Also `docs/cli.md`, lines 168-172 at `97146aa`; the totoshko88/RustConn report in GitHub
#24 (item 3) and the OthmaneBlial/MobaRust report in GitHub #21 (item 3);
sandbox A of T-001 (`bind` refused for AF_INET, allowed for AF_UNIX).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`-L` (a local port to a remote service) and `-D` (a local SOCKS proxy) are
the forwards that users know best. podssh refuses both, also on hosts that
allow a listener. Sandbox A refused `bind` for AF_INET and allowed it for
AF_UNIX.

## Premise

- Measured, offline: `-L 8080:localhost:80` and `-D 1080` are refused with
  "podssh never binds a listener", exit 64
  (`crates/podssh-cli/src/flags.rs`, lines 215-220 at `97146aa`). Read: `-o LocalForward` and
  `-o DynamicForward` too (`crates/podssh-cli/src/ssh/options.rs`, lines 185-189 at `97146aa`).
- Read: `AGENTS.md:226-231` (no bind, no listen),
  `docs/target-environment.md:74-78` (rule 3), `SECURITY.md:94-114` ("Nothing
  listens") and `README.md:38-45` state the rule from before the ruling.
  `docs/design.md:709-711` already allows a local listener for `pipe` after
  a probe.
- Read: the Podman box refuses each `bind` (`scripts/box/seccomp.json:5-10`),
  so it tests the refusal.
- Read: `podssh doctor` binds and closes without `listen()`
  (`crates/podssh-cli/src/doctor/unix.rs:137-164`,
  `crates/podssh-cli/src/doctor/unix.rs:169-186`). A seccomp filter can allow
  `bind` and refuse `listen`, so the probe for `-L` must also listen once.
- Read: the remote end exists: `forward::open` opens `direct-tcpip`
  (`crates/podssh-ssh/src/forward.rs:13-22`).

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
   effect today (`crates/podssh-cli/src/flags.rs`, lines 208-209 at `97146aa`,
   `crates/podssh-cli/src/ssh/keywords.rs`, line 76 at `97146aa`). Remove an AF_UNIX socket at
   exit; with `StreamLocalBindUnlink`, remove a stale one first.
5. The user turns listening off: `-o ClearAllForwardings=yes` for one run
   (OpenSSH's keyword, ignored today,
   `crates/podssh-cli/src/ssh/keywords.rs`, line 73 at `97146aa`), and for a whole host a
   variable that refuses each local listener (`-L`, `-D`, T-039, T-034). Add
   it to `VARIABLES` in `crates/podssh-cli/src/man/facts.rs`.
6. In the same commit, change the rows, the keywords, the note at
   `crates/podssh-cli/src/man/notes.rs`, lines 85-86 at `97146aa`, the test at
   `crates/podssh-cli/tests/flag_table.rs:82-101`, and the documents that the
   Premise quotes.

## Decision

2026-10-11.

- The address follows OpenSSH's `channel_fwd_bind_addr` for a client, not
  step 4's "a wildcard address only with `-g`": a port with no address is
  loopback, or each address with `-g`/`GatewayPorts yes`; an explicit `*`
  or empty address is each address with no `-g`, as in OpenSSH, because
  the user named it; `localhost` is loopback. Loopback is 127.0.0.1 and
  ::1, each bound, one of them allowed to fail. Lost: `*` only with `-g`,
  which would refuse an OpenSSH command line that works.
- A listener that cannot be made ends the run before anything connects,
  with exit 255 (the Prove's), the system's words and `-W HOST:PORT`: the
  operator's "the same refusal where the probe fails". OpenSSH warns and
  goes on unless `ExitOnForwardFailure`; a `-N` run would then sit with
  nothing to do. `PODSSH_LISTEN=no` (step 5's variable, already that of
  `podssh pipe` and `podssh agent`) refuses with 78.
- `-D` answers a SOCKS client once the server opened the channel, with the
  reason of a refusal (5 connect failed, 2 prohibited); OpenSSH answers
  success first. A server may take 60 s to open, a client 30 s to ask.
- A socket path on either side is carried: `direct-streamlocal@openssh.com`
  to a socket on the server (russh has it), and `podssh pipe`'s
  `unix-listen:` here, which removes a socket that nobody serves, so
  `StreamLocalBindUnlink` stays a keyword with no effect. `-D PATH` goes
  beyond OpenSSH: a sandbox that refuses AF_INET binds may allow AF_UNIX.
- `ClearAllForwardings yes` drops `-R` too, and `-W` implies it, as in
  OpenSSH: before this, `podssh ssh -W` with `-R` asked for the forward.
- The listeners live in the CLI, which binds them; `podssh-ssh` serves
  `Arc<dyn Listen>` and binds nothing (`crates/podssh-ssh/src/local.rs`).

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

## Correction

2026-10-10 (T-177): `podssh pipe` listens now, on `unix-listen:` and
`tcp-listen:`, after the probe of the bind
(`crates/podssh-cli/src/pipe/listen.rs`), which `-L` and `-D` can share.
The refusals of `-L` and `-D` say "podssh ssh opens no local listener yet"
and name `podssh pipe tcp-listen:` (`crates/podssh-cli/src/flags.rs`, lines 215-220 at `97146aa`,
`crates/podssh-cli/src/ssh/options.rs`, lines 185-189 at `97146aa`). `SECURITY.md:94-114` and
`README.md:38-45` state the ruling now, as `AGENTS.md:226-231` and
`docs/target-environment.md:74-78` did already.

## Done

2026-10-11. `-L` and `-D` listen here, after the probe:

- `crates/podssh-cli/src/ssh/local_spec.rs` reads the specs as OpenSSH's
  `parse_forward` (brackets, `\`, a `/` makes a path, `${NAME}`, no port
  0) and prints the lines of `-G` as OpenSSH 10.3p1 does, measured with
  its `ssh -G` in the build image; `forwards` keeps the command line's
  first, then the keywords', and clears all with `ClearAllForwardings` or
  `-W`. `crates/podssh-cli/src/ssh/local_bind.rs` makes each listener
  before anything connects (TCP on its addresses; a socket through
  `podssh pipe`'s listener, whose `accept` now takes any callback, so its
  future is `Send` when the callback is).
- `crates/podssh-ssh/src/local.rs` serves them on the destination's
  connection for as long as it lasts: with the session, with `-N` (which
  now also waits on `closed`), and on each connection of `--persist`; the
  channels open at the same time, each connection copied in a task of its
  own. `crates/podssh-ssh/src/socks.rs` reads SOCKS4, SOCKS4a and SOCKS5
  requests and writes the answers.
- The command line: `-L`, `-D` and `-g` are supported; `LocalForward`,
  `DynamicForward`, `GatewayPorts` and `ClearAllForwardings` are honoured
  keywords; `-G` prints `clearallforwardings`, `gatewayports`,
  `dynamicforward` and `localforward`. The tests that used `-L` as the
  example of a refused flag use `-w TUN`, which still names `-W`. The
  manual's note, `docs/cli.md` ("Forwarding"), `SECURITY.md` ("Nothing
  listens"), README and the listener scan of `scripts/check-repo.py` say
  so.

Prove, native, Windows: `cargo test -p podssh-ssh -- local:: socks::`, 12
passed against russh's server in the process (each connection of `-L` to
its target with its originator, a socket of the server through
streamlocal, SOCKS5 and SOCKS4a through `-D`, the server's refusal said to
a SOCKS client as 5 and 2 and a connection of `-L` closed, serving that
ends with its listeners, `closed`); `cargo test -p podssh-cli --lib`
(the forms and their `-G` lines, the addresses), and `--test
ssh_local_forward`, 4 passed through the binary to the test's SSH server
(`-N -L` twice to a target, `-N -D` with SOCKS5, a port taken refuses with
255 and `PODSSH_LISTEN=no` with 78 with nothing connected, `-W` clears
`-L`); `tests/ssh_config.rs` and `tests/ssh_config_file.rs` hold the new
lines of OpenSSH's `-G`. Plants: a listener that fails skipped, SOCKS
answered before the channel, `-W` keeping the forwards, a wildcard default,
a listening port of 0 taken, and `-N` serving nothing, each failed a test.

In the build image (`sh scripts/dev.sh run`, a debug build): the tests of `local::`, `socks::` and `ssh_local_forward` passed on Linux, with the socket of `-L` made mode 0600 (5 passed); `scripts/interop.sh` 265 passed, 0 failed, with `scripts/interop-local.sh` against OpenSSH 10.3p1's sshd: `-N -L 127.0.0.1:2280:127.0.0.1:2203` gave Dropbear's banner, and so did a socket of `-L` (mode 0600); curl through `-D 127.0.0.1:2281` reached Dropbear with `--socks5-hostname` and `--socks4a`; `PODSSH_LISTEN=no` refused `-L` with 78. A run before it failed at random on an ECDSA login: OpenSSH's `PerSourcePenalties`, which each test sshd now turns off (`docs/STATUS.md`).

Waits for T-251: the box (`scripts/test_in_box.sh`), where each bind is
refused: `-L` on 127.0.0.1 must refuse before anything connects with the
probe's error and 255, and the Prove's plant (skip the probe) must fail
there.

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
**Status:** done

## Problem

Each run of `podssh ssh` makes a new relay session, a new key exchange and a
new login. A script that runs many short commands pays this each time.
OpenSSH shares one connection through a control socket (`-M`, `-S`, `-O`,
`ControlMaster`, `ControlPath`, `ControlPersist`).

## Premise

- Measured, offline: `-M`, `-S /tmp/ctl` and `-O check` are refused with
  "podssh keeps no control master: each run is one connection", exit 64
  (`crates/podssh-cli/src/flags.rs`, lines 240-245 at `5fb9c1e`).
- Measured, offline: `-o ControlMaster=auto -o ControlPath=/tmp/c` is
  accepted with no effect; only `-v` says so
  (`crates/podssh-cli/src/ssh/keywords.rs`, line 78 at `5fb9c1e`). A script that sets them still
  works, with one connection for each run.
- Read: a control socket is a listener. `AGENTS.md:226-231` forbids it in the
  words from before the ruling. Sandbox A allowed a bind for AF_UNIX
  (T-001); the Podman box refuses each `bind`
  (`scripts/box/seccomp.json:5-10`).
- Read: the relay's limits apply to the shared connection: all the sessions
  of a master share one 64 MiB and one 12 h (`docs/relay.md:156-162`).

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

2026-10-11, while doing it:

- No master in the background. OpenSSH forks a master with its own
  session away for `ControlPersist`; podssh does not go to the background,
  and starting itself again as a helper is the helper process that rule 3
  of `AGENTS.md` forbids. So `ControlPersist` keeps a `-N` master with no
  client for its time (0 and yes forever), and a master with its own
  session ends with it, after the sessions of its clients, as OpenSSH's
  master waits for them; the manual and `docs/cli.md` say to start a
  lasting master with `-M -N &`. Lost: a fork, or a second podssh process.
- The wire as OpenSSH 10.3p1 writes it, read from its bytes, over the
  document: each `bool` is a `uint32`, and the port of
  `MUX_C_NEW_STDIO_FWD` a `uint32`; SESSION_OPENED comes once the session's
  request is answered (OpenSSH sends it once the requests are sent), so a
  refused one is a FAILURE the client can name.
- A client run's `-L`, `-D` and `-R` go to the master first, as OpenSSH's
  client sends them, and a `-N` client then ends: its forwards stay with
  the master. `-O proxy` is refused: podssh's client speaks no SSH
  connection protocol of its own.
- `ControlMaster ask` and `autoask` confirm each request that changes
  something (a session, a stdio forward, a forward, `exit`, `stop`) through
  the prompt of passwords, on the terminal or through `SSH_ASKPASS`;
  nobody to ask is a refusal.
- On Windows, `-M`, `-S` and `-O` are refused with exit 64; the three
  keywords, which an OpenSSH configuration often holds, have no effect,
  said with `-v`. `--persist` does not take part: its loop would need a
  new master for each link.

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

## Done

2026-10-11. Connection sharing on Unix, with OpenSSH's control protocol:

- `crates/podssh-ssh/src/mux/`: `proto.rs` (each message, both ways),
  `wire.rs` (packets read exactly; each descriptor with its byte, as
  OpenSSH's `mm_send_fd`), `master.rs` (the accept loop, a client of this
  user or root only, `-O check`, `exit`, `stop`, the forwards with `fwd.rs`,
  `ControlPersist`, `ask`), `msession.rs` (a session on the passed
  descriptors: a pty from the client's terminal, its modes and size, a
  window change at each SIGWINCH relayed to the master, the escape
  character, TTY_ALLOC_FAIL and EXIT_MESSAGE; and a stdio forward),
  `afd.rs` (a passed descriptor polled, its flags put back after; a
  regular file on blocking threads), `client.rs` (a session with this
  process's stdin, stdout and stderr, raw mode, SIGWINCH to the master;
  a stdio forward; the `-O` requests). `run_inner` serves a master beside
  the session, `-W` or `-N`.
- The command line: `-M` (counted), `-S`, `-O` and the keywords
  `ControlMaster`, `ControlPath` and `ControlPersist` (OpenSSH's time
  format); `-G` prints `controlmaster`, `controlpath` and `controlpersist`
  where OpenSSH 10.3p1 does. `crates/podssh-cli/src/ssh/control.rs` and
  `control_unix.rs` start a run: an `-O` request; a run through a master
  that answers; or this run as the master, its socket made before anything
  connects by `podssh pipe`'s listener (`control_socket`). The listener's
  `bind` and `accept` take any callback now, so a master's futures are
  `Send`.
- `scripts/mux-capture.py` relays a control socket and logs each message:
  the bytes of `proto_tests.rs` came from OpenSSH's own client and master.
- Documents: `docs/cli.md` ("Connection sharing"), the manual's note,
  `SECURITY.md`, the flags' help; the listener scan of
  `scripts/check-repo.py` allows the master's socket.

Prove, native, Windows: `cargo test -p podssh-ssh -- mux_protocol`, 4
passed (the codec on OpenSSH's bytes), and `cargo test -p podssh-cli --test
ssh_control` (the refusal of `-M`, `-S` and `-O` with 64, nothing
connected). In the build image (`sh scripts/dev.sh run`, a debug build),
2026-10-11: `cargo test -p podssh-ssh --lib -- mux`, 9 passed (descriptors
across a socket, a master with a session on pipes whose flags it put back,
a stdio forward, `-O forward` and `cancel` of a remote and a local
forward, `-O stop`, `-O exit`, `ControlPersist`); `cargo test -p podssh-cli
--test ssh_control`, 3 passed: a `-M -N -S` master served two runs with
their status and output over one TCP connection, `-O check` named its pid,
`-O exit` ended it with 0 and its socket went; with `ControlPath` and no
master a run connected alone, and with `ControlMaster auto` it was the
master of a second run; `-O check` with no master gave 255. `cargo clippy`
of both crates, with no warning. Plants, in the image: the client
connecting alone (two connections where one was due), a `bool` written as
one byte, the flags left non-blocking, the socket left after the master,
and the client taking no exit message, each failed a test.
`scripts/interop.sh` 278 passed, 0 failed, with
`scripts/interop-control.sh` against OpenSSH 10.3p1: its `ssh -O check`
found a podssh master, its client went through it with exit 3 and got a
pty, podssh's client and `-W` went through it, its `-O exit` ended it with
0; podssh's `-O check` found an OpenSSH master, podssh's client went
through it with exit 4 and its output, and podssh's `-O exit` ended it.

Waits for T-251: the box (`scripts/test_in_box.sh`), where each bind is
refused: `-M` must refuse with the probe's reason.

# T-040: `-W` to a Unix socket on the server (streamlocal)

**Source:** the ImKKingshuk/USBoverSSH report in GitHub #25 (item 9, Unix
socket forwarding over SSH); GitHub #26 ("a name for AF_UNIX streams"). Read
in the reports. Measured here on `3ee70dc`, and with OpenSSH 10.3p1.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

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
  (`crates/podssh-cli/src/ssh/hop.rs`, lines 81-91 at `f6af943`), which reads a value with
  no `:` as a host on port 22 (`crates/podssh-cli/src/ssh/hop.rs:41-54`).
- russh 0.64.1 has `Handle::channel_open_direct_streamlocal` (the channel
  `direct-streamlocal@openssh.com`). podssh opens only `direct-tcpip`
  (`crates/podssh-ssh/src/forward.rs:13-22`).

## Approach

1. T-239 refuses a path and a value with no port now (M3). This entry turns
   the refusal of a path into the streamlocal channel. Add a kind of target
   to `Request::StdioForward` (`crates/podssh-ssh/src/options.rs`, lines 67-68 at `f6af943`).
2. Open a socket with `channel_open_direct_streamlocal` in
   `crates/podssh-ssh/src/forward.rs`, and use the copy loop of `stdio`
   (`crates/podssh-ssh/src/forward.rs:39-110`) for both kinds.
3. A server that refuses the channel (OpenSSH with
   `AllowStreamLocalForwarding no`) gives its reason, and 255, as for TCP.
4. Change the help of the `-W` row (`crates/podssh-cli/src/flags.rs:139-140`)
   and `docs/cli.md:96-105` (T-239 refuses a path there until this entry), and
   add an example to the manual. A local socket
   is the work of T-176 (`pipe`).

## Decision

Recommendation: OpenSSH's own spelling, `-W /path`, which OpenSSH accepts
(measured above). A command line then means the same in both clients, which
`docs/cli.md:8-10` promises. The alternative, a podssh prefix such as
`unix:/path`, lost: no other client reads it, and podssh would still read
`-W /path` differently from OpenSSH.

Taken, with these calls made in the work (2026-10-11). A value that starts
with `/` is a socket's path, whole, as OpenSSH reads a lone path; a value
with a `/` elsewhere is refused (64). Through a control master the path goes
as OpenSSH's client sends it, with the port `PORT_STREAMLOCAL`, and the master
opens the socket. In Git Bash, `MSYS_NO_PATHCONV=1` keeps the path as typed;
the docs say so.

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

## Done

2026-10-11. The target of `-W` is `StdioTarget`, TCP or a socket
(`crates/podssh-ssh/src/options.rs:164-181`), opened by `open_target`
(`crates/podssh-ssh/src/forward.rs:24-37`); through a control master
(`crates/podssh-ssh/src/mux/client.rs:177-192`,
`crates/podssh-ssh/src/mux/msession.rs:253-260`). The command line reads a
path at `crates/podssh-cli/src/ssh/hop.rs:86-89`, and the row of `-W` says so
(`crates/podssh-cli/src/flags.rs:139-140`).
- `cargo test -p podssh-cli --test ssh_stdio_socket`: 2 passed. The test of
  the Prove, `stdio_forward_socket_or_host_and_port`, is in this file, as
  `ssh_args.rs` reached 500 lines: `/tmp/s`, a socket's path with a `:` in it,
  `host:5432` and `[::1]:5432` are read, and `foo`, `tmp/sock` and the other
  forms with no port are refused with 64. Against the test's server, `-W
  /echo` sends back what stdin gave, and a socket that the server refuses ends
  with 255 and names the socket. Planted, a path not read as a socket (the
  Prove's plant): the test of the reading failed; restored. In the build
  image the tests of the mux, with the socket's form, passed.
- `scripts/interop-stdio.sh:1-47`, a new harness of two checks against
  OpenSSH's sshd: `stdio.socket` (a Python echo server on a Unix socket of the
  box answers `ping`) and `stdio.socket_refused`. The gate runs them at this
  push.
- `docs/cli.md:96-105`, a note and an example of the manual.
- `cargo test -p podssh-ssh`: 155 passed; `cargo test -p podssh-cli`:
  578 passed, 0 failed, 31 ignored; clippy; rustfmt.

# T-041: The forwards of a session: a list and byte counts

**Source:** the OthmaneBlial/MobaRust report in GitHub #21 (item 3, state and
byte counts, a stop action), the rssh-org/rssh report in GitHub #24 (item 3,
statistics in real time), and the yituorou/meatshell report in GitHub #21
(item 6, a tunnel panel). Read in the reports.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

When a session carries forwards (`-R` from T-035, `-W`, later `-L`), the user
cannot see which ones are open, how many connections each carried, or how
many bytes moved.

## Premise

Read: today the only forward is `-W` (`crates/podssh-ssh/src/forward.rs:39-110`),
and it counts nothing. The escapes are `~.`, `~R`, `~?` and `~~`
(`crates/podssh-ssh/src/escape.rs:1-25`); OpenSSH also has `~#`, which lists
the forwarded connections. `podssh status` (T-051) runs in another process,
so it cannot see the forwards of a session without a state file or a
listener.

## Approach

1. Count, for each forward: the connections opened, closed and failed, and
   the bytes in each direction. Keep the counters in the forward's own task;
   put no lock on the data path.
2. Add `~#` to the escapes (`crates/podssh-ssh/src/escape.rs:11-25`) and to its
   help (`crates/podssh-ssh/src/escape.rs:137-145`): one line for each forward,
   with its counts.
3. At the end of a session, with `-v`, print one line for each forward. Do
   not call it "Transferred": OpenSSH's line of that name counts the bytes of
   the whole connection.
4. A stop action (OpenSSH's `~C` with `-KR`) is a later step: it needs the
   command line of `~C`.
5. Give the counts to the machine-readable result of T-054 when it exists.
   This entry depends on T-035.

## Decision

Taken, with these calls made in the work (2026-10-11). The bytes are counted
as they are read, on atomics, so that `~#` shows a connection that is still
open; no lock is on the data path. The table is the process's, as a process
runs one chain of connections, and a forward asked for again on a new
connection (`--persist`) keeps its counts. Each forward is listed from its
start, under the name the user wrote (`-L` and `-D` as given, `-R` and `-W`
rebuilt from their parts), with no connection yet. The channels of X11 and of
the agent are not listed: the user asked for no forward there. The stop
action of step 4 is T-291.

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

## Done

2026-10-11. The counts, the table and the listing in
`crates/podssh-ssh/src/tally.rs:1-193`; `-L` and `-D` count at
`crates/podssh-ssh/src/local.rs:156-162`, `crates/podssh-ssh/src/local.rs:254` and
`crates/podssh-ssh/src/local.rs:278`, `-R` at
`crates/podssh-ssh/src/remote.rs:109`, `crates/podssh-ssh/src/remote.rs:166`
and `crates/podssh-ssh/src/remote.rs:178`, `-W` at
`crates/podssh-ssh/src/forward.rs:42` and
`crates/podssh-ssh/src/forward.rs:53`; `~#` at
`crates/podssh-ssh/src/escape.rs:98` and `crates/podssh-ssh/src/io.rs:211`,
and the lines of `-v` at `crates/podssh-ssh/src/run.rs:258`.
- `cargo test -p podssh-ssh -- forward_counts`: 3 passed: 262144 bytes up and
  1000 down through a forward's copy, counted once, with one connection; one
  name, one forward, across connections and a failure; the listing in the
  order of first use; `~#` asked and named in `~?`. Planted, each chunk
  counted twice (the Prove's plant): the first test failed; restored.
- `cargo test -p podssh-cli --test ssh_stdio_socket`: 2 passed: against the
  test's server, `-v -W` to a TCP echo server of the test ends with the line
  `-W 127.0.0.1:PORT: 1 connection (0 open, 0 failed), 262144 bytes up, 262144
  bytes down`, and a socket that the server refused with `1 failed`.
- In the gate at this push: `stdio.counts` (`scripts/interop-stdio.sh`, `-v
  -W` through OpenSSH's sshd to a TCP echo server, 262144 bytes each way) and
  `pty.forwards` (`scripts/interop-pty.py`, `~#` in a session with `-R
  0:127.0.0.1:2201`).
- `docs/cli.md:290-297` and the manual's note of `-t` say what `~#` and `-v`
  print.
- `cargo test -p podssh-ssh`: 158 passed; `cargo test -p podssh-cli`:
  578 passed, 0 failed, 31 ignored; clippy; rustfmt.
- Correction, the same day: at `8d2187c` the gate did not build on Linux.
  `crates/podssh-ssh/src/mux/msession.rs`, which Unix builds alone, matched
  the escapes with no `~#`, and the build on Windows never compiled it. The
  repair: the session of a client of a control master lists the master's
  forwards with `~#`, as OpenSSH's `~#` lists the master's connections, and
  its `~?` names it (`crates/podssh-ssh/src/mux/msession.rs:32-34` and
  `crates/podssh-ssh/src/mux/msession.rs:162-167`). In the build image
  (`sh scripts/dev.sh run`), `cargo clippy --all-targets -p podssh-ssh -p
  podssh-cli -- -D warnings` passed.
- Correction: at `f80e7f3` the gate failed both checks of this entry, each
  for its harness. `stdio.counts`: `wait_ports` took the one connection that
  the echo server of port 2215 accepted, so podssh's was refused; the
  server now serves each connection in turn. `pty.forwards`: OpenSSH's
  `PermitListen 2290` refused `-R 0`, so `~#` had no forward to list; the
  check asks for port 2290.

# T-042: `-R` forwards come back after a drop

**Source:** the Petyok/SSHub report in GitHub #22 (item 4, a tunnel
keep-alive that connects dropped forwards again, with exponential backoff).
Read in the report.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A session that only carries forwards (`podssh ssh -N -R ...`) stays down
after the relay drops it. The user must notice it and start it again. A
remote forward is often a service that must last, and the relay drops some
sessions (GitHub #17).

## Premise

Read: a drop ends the run with 255 (`crates/podssh-ssh/src/run.rs:62-78`,
`crates/podssh-ssh/src/run.rs:207-249`). `podssh_relay::open` fails over and
backs off with jitter, but only before a session exists
(`crates/podssh-relay/src/open.rs:188-247`,
`crates/podssh-relay/src/open.rs:349-363`). With `-N`, no command runs, so a
new connection has no side effect on the server. `docs/design.md:414-421`
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

## Decision

Taken, with these calls made in the work (2026-10-11).

- The flag is `--persist`, as step 1 asks: with `-N` (or `SessionType=none`)
  no tmux runs, and the forwards come back. `-L` and `-D` are taken too, and
  not `-R` alone: their listeners are bound once, before anything connects
  (T-038), and serve on each new connection, so that refusing them would be
  a rule with no reason. `-N` with no forward exits 64 (nothing would come
  back), and so does `--persist-name` with `-N`, as no tmux runs.
- The server's own close (the relay's 1000, or a disconnect) is a loss too
  in this mode: a forward keeps nothing on the server that its restart would
  lose, and a server that restarted is the case where a tunnel must come
  back. A close of the relay that would come again (1008, 1013 and the
  others that T-178 does not repair) ends the run with the lines of T-024.
  With tmux, the classes of T-178 stay.
- A connection that lasted less than 30 s (`STEADY`; autossh's gate time is
  30 s too) starts no new round of 10 attempts within 5 minutes: a link that
  falls again and again gives up, as one that cannot connect does, where
  each loss started a new round. This holds for tmux too, whose loop could
  connect again for ever, a second apart, under a link that fell at once.
- A forward that the server refuses after a loss is asked again in the same
  connection, with the jittered wait of `open` (1 s, doubled up to 30 s),
  for 2 minutes from the first refusal (`FORWARDS_AGAIN`); the forwards
  that the server took serve meanwhile, and `-L` and `-D` serve after it,
  their clients waiting in the listener's queue. Then the line of T-035: a
  warning, or with `ExitOnForwardFailure` the end of the run (255). The
  first connection asks once, as without `--persist`, and with tmux a
  refused forward stays as T-178 left it: asking again would hold the
  attach.
- The logins after the first run in batch mode, as with tmux, and use the
  login that the run kept (T-136); with `SSH_ASKPASS_REQUIRE=force` and
  `SSH_ASKPASS`, its program may still ask, as no input belongs to a
  session here and the program asks no person at a terminal.
- Each loss is the first line of T-024, which names the hop that broke,
  with the wait and the attempt; each return is "connected to HOST again;
  its forwards serve again", and a port that the server chose is printed
  for each connection. With `-v`, the counts of the forwards (T-041) close
  a run of `--persist`, over all its connections.

## Prove

```sh
sh scripts/dev.sh check
```

In the fault harness (`scripts/interop-faults.sh`), a run with the new flag,
`--relay-host` set to `relay-kill` then `relay-a`, and
`-N -R 127.0.0.1:2291:127.0.0.1:2203` carries a connection to port 2291.
Then the stand-in relay `relay-kill` stops, as at
`scripts/interop-faults.sh:240-250`. Within 60 s, a new connection to port
2291 reads Dropbear's banner again. Planted defect: no new connection, and
the second read fails.

## Done

2026-10-11. `podssh ssh --persist -N` keeps the forwards through a lost
link: the mode at `crates/podssh-cli/src/ssh/persist.rs:38-45` and
`crates/podssh-cli/src/ssh/persist.rs:95-106`; each connection in
`crates/podssh-ssh/src/persist.rs:94-133`, which asks for the forwards,
serves `-L` and `-D`, and tells a loss from an end
(`crates/podssh-ssh/src/persist.rs:57-62`); a refused `-R` asked again in
`crates/podssh-ssh/src/remote.rs:46-116`, as `Options::forwards_again` says
(`crates/podssh-ssh/src/options.rs:305-314`), which the loop sets after the
first loss (`crates/podssh-cli/src/ssh/persist.rs:163-172`); the rule of
`STEADY` at `crates/podssh-cli/src/ssh/persist.rs:142-148`.
- `cargo test -p podssh-cli --test persist`: 5 passed. The new test runs
  `--direct --persist -N -R 2291:127.0.0.1:PORT` against the test's server
  (`tests/tmux_harness`, which now takes forwards): a channel of the
  forward reads the target's line; the server drops the link; podssh
  connects again, its first request for the forward is refused, as by a
  server that still holds the port, and asked again; a channel through the
  new connection reads the line again. Two connections, three requests.
- `cargo test -p podssh-ssh -- remote:: persist::`: 9 passed, 3 of them new:
  a forward refused twice after a loss is asked until the server takes it,
  with a line for each wait, and once with no loss, as before; one refused
  for the whole time ends as T-035 says, a warning or with
  `ExitOnForwardFailure` the end of the run; the classes of an end of `-N`.
- `cargo test -p podssh-cli --test ssh_args -- persist`: `-N` with `-R` or
  `-L`, and `SessionType=none` with `-D`, keep the forwards, with no pty;
  `-N` with no forward and `--persist-name` with `-N` exit 64.
- Planted, each restored: no new connection (`forwards_lost` never holds),
  the Prove's plant: the test of the drop failed with no "connecting again";
  a refused forward never asked again: the two new tests of `remote` and the
  test of the drop failed.
- In the build image (`sh scripts/dev.sh run`), `cargo clippy --all-targets
  -p podssh-ssh -p podssh-cli -- -D warnings` passed.
- In the gate at this push: `faults.persist.tunnel`
  (`scripts/interop-faults.sh:288-328`): `--persist -N -R
  127.0.0.1:2290:127.0.0.1:2203` through the stand-in relays `relay-tunnel`
  and `relay-a`; port 2290 reads Dropbear's banner, `relay-tunnel` is
  killed, and within 60 s port 2290 reads it again through the next.
  Port 2291, which the Prove names, is the one that `PermitListen` refuses
  for T-035's check of a refusal.
- Correction, 2026-10-12: at `4b2f621` and `ec7f018` the gate failed this
  check: the run's first login was refused (`Permission denied ()`), and
  port 2290 answered all the same, through the podssh of T-035's check,
  which the gate had left running: a function run with `&` is a shell of
  its own, and `kill` ended that shell alone. The same podssh made OpenSSH
  refuse port 2290 to `pty.forwards` (T-041). `p` of `scripts/interop.sh`
  and `r` of `scripts/interop-faults.sh` now take `as_job=exec`, so that
  podssh is the job's own process, and the two runs in the background use
  it. In the build image, the whole of `scripts/interop.sh`, with a debug
  build, then passed this check and `pty.forwards`. Why the login was
  refused in CI is not known.
- `docs/cli.md`, the manual's notes of `--persist`, `docs/design.md` and
  the bounds of `docs/architecture.md` say what `--persist -N` does.
- `cargo test -p podssh-ssh`: 161 passed; `cargo test -p podssh-cli`:
  579 passed, 0 failed, 31 ignored; clippy; rustfmt.

# T-239: `-W` with a path, or with no port, is read as a TCP host on port 22

**Source:** found while writing T-040 (2026-10-08). Measured here on
`3ee70dc`, and against OpenSSH 10.3p1 with `ssh -G`, which does not connect.
**Category:** defect
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** done

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
(`crates/podssh-cli/src/ssh/resolve.rs`, lines 472-482 at `97146aa`), which reads a value with no
`:` as a host on port 22, and splits a value at its one `:`
(`crates/podssh-cli/src/ssh/hop.rs:41-54`). `forward::open` opens
`direct-tcpip` only (`crates/podssh-ssh/src/forward.rs:13-22`).

## Approach

1. In `request`, before `parse_hop`: refuse a value that holds a `/` with
   exit 64: "-W PATH: a Unix socket on the server is not supported yet".
   T-040 turns this refusal into the streamlocal channel.
2. Refuse a value with no port (no `:` outside brackets) with exit 64:
   "-W db.internal: expected HOST:PORT", as OpenSSH refuses it. This also
   refuses `-W 5432`, whose meaning in OpenSSH is not known here.
3. Keep `HOST:PORT` and `[v6]:PORT`. A `-J` hop keeps its own parse, where a
   host alone means port 22, as in OpenSSH.
4. Add the rule to `docs/cli.md:96-105`. The help of the `-W` row
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

## Done

2026-10-08, in the commit "-W takes HOST:PORT, as OpenSSH reads it".

- `stdio_forward_form` in `crates/podssh-cli/src/ssh/resolve.rs` runs
  before `parse_hop` for `-W`: a value with a `/` is refused ("a Unix socket
  on the server is not supported yet"), and so is a value with no port
  ("expected HOST:PORT"), also `db.internal:` and `[::1]`. A bare IPv6
  address, with more than one `:` and no brackets, is refused too, with the
  form to use: its port would otherwise be read as 22, the same defect. A
  `-J` hop keeps its own reading. `docs/cli.md` gives the rule.
- The test `the_request_follows_the_flags` asserted that `-W db` is port
  22; it now asserts the refusal.
- Prove: `cargo test -p podssh-cli --test ssh_args -- stdio_forward_form`
  passed: `/tmp/sock`, `/tmp/sock:22`, `db.internal`, `5432`, `db.internal:`,
  `[::1]` and `2001:db8::1` are refused with exit 64 and a message that
  names the form; `db.internal:5432` and `[::1]:5432` are accepted; a `-J`
  host alone stays port 22. The binary: `podssh ssh -W db.internal
  example.invalid` printed "podssh ssh: -W db.internal: expected HOST:PORT"
  and exited 64; `-W db.internal:5432` reached the offline stop (255).
- Plant: the check of step 2 removed; the test failed for `db.internal`,
  which became `StdioForward { host: "db.internal", port: 22 }`.

# T-279: `-A` binds the forwarded agent to the server's host key, as OpenSSH does

**Source:** found in T-036 (2026-10-11): OpenSSH's client sends
`session-bind@openssh.com` on each forwarded agent connection; podssh
cannot, and an agent's destination constraints (`ssh-add -h`) then do not
hold over podssh's forward.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An OpenSSH agent limits a key added with `ssh-add -h` to the hosts that it
names. It learns which host a connection serves from the client's
`session-bind@openssh.com` request: the server's host key, the session
identifier (the exchange hash of the first key exchange), the server's
signature of it, and whether the connection is forwarded. A connection with
no bind is taken as local use, so each constrained key is usable over it.
podssh's forward (T-036) sends no bind: a server that the user reached with
`-A` can use a key that `ssh-add -h` kept from it.

## Premise

- Read: russh 0.64.1 keeps the session identifier inside its key exchange
  (`KexCause::session_id` in its `src/kex/mod.rs`, not public to a client)
  and keeps no copy of the server's signature from the reply of the key
  exchange. podssh's handler sees the host key (`check_server_key`), but
  neither of the other two (`crates/podssh-ssh/src/handler.rs`).
- Read: podssh joins each agent channel to the agent with no request of
  its own first (`crates/podssh-ssh/src/agent_forward.rs`).
- Measured in T-036: OpenSSH 10.3p1's agent takes an unbound connection as
  local (its `identity_permitted` returns early when the socket has no
  bind), as its source says; `SECURITY.md` and `docs/cli.md` state the gap.

## Approach

1. Get the session identifier and the server's signature out of russh:
   ask russh upstream for both (an issue or a pull request at
   Eugeny/russh), or carry a small patch of russh in `vendor/` as
   `vendor/tailscale-rs` is carried, with its patch in `vendor/patches/`.
   Write the choice in `## Decision`.
2. In `crates/podssh-ssh/src/agent_forward.rs`, before the first byte of
   the server, send the agent `SSH_AGENTC_EXTENSION` with
   `session-bind@openssh.com`: the host key, the session identifier, the
   signature and `is_forwarding` true; a refusal of the agent (an agent
   that knows no extension) is logged with `-v`, and the channel goes on,
   as OpenSSH goes on.
3. `SECURITY.md` and `docs/cli.md` drop the gap.

## Decision

2026-10-12, in the work.

- A patch of russh, carried in `vendor/russh` with
  `vendor/patches/russh/0001-session-binding.patch`, in the place of the
  release through `[patch.crates-io]` (the root `Cargo.toml` and
  `fuzz/Cargo.toml`), and excluded from the workspace. The version stays
  0.64.1. Lost: asking upstream first (warp-tech/russh, once
  Eugeny/russh): an issue or a pull request is a public act, which is the
  operator's, and its release has no date; the patch goes once a release
  gives a client both (`vendor/README.md` says how). Lost too: the
  exchange hash computed outside russh, from the plain text of the first
  exchange and the shared secret that `kex_done` gives: it would repeat the
  hash of each exchange of russh, and a new one would drop the bind with
  no sign.
- What the patch keeps: `client::SessionBinding`, the host key and the
  signature as the server sent them (a certificate whole, as OpenSSH sends
  its `initial_hostkey`) and the session identifier, from the first
  exchange of a client only; `client::Session::session_binding` gives it,
  and podssh's handler reads it in `kex_done`, which russh calls before the
  host key's check. Lost: a new argument of `kex_done`, which changes
  russh's API; a request through `Handle`, a message to the session's task
  for a value that never changes.
- The bind goes once the agent is connected, before the channel is
  accepted, so before any byte of the server, as OpenSSH binds before it
  makes the channel. Its answer is read whole, within 30 s (`BIND_LIMIT`):
  an OpenSSH agent that asks its user to confirm a use of a key for another
  client answers nothing meanwhile.
- Any answer but SSH_AGENT_SUCCESS is a refusal: the channel goes on
  unbound, with a line of `-v`, as OpenSSH goes on (Pageant and
  `podssh agent` answer SSH_AGENT_FAILURE). No answer within the limit, a
  hang-up or a broken frame refuses the channel (connect failed), said once
  and then with `-v`. Lost: going on unbound over a second connection,
  which would give a busy OpenSSH agent an unbound connection, and so each
  limited key to the server; OpenSSH's wait with no limit, which holds the
  server's channel for ever.
- A connection with no binding (the `none` exchange, which russh signs
  nothing in) serves unbound, with a line of `-v`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh -- agent_channel
```

The unit test's stand-in agent reads the bind first, and checks the
signature against the host key. In the gate, `scripts/interop.sh` adds a
key to OpenSSH's `ssh-agent` with `ssh-add -h` for another host, and
`podssh ssh -A ... 'ssh-add -l'` lists no usable key for this one (OpenSSH
refuses its use). Planted defect: send no bind, and the unit test fails.

## Done

2026-10-13. `-A` binds the agent to the server's host key before each
agent channel (`session-bind@openssh.com`, `is_forwarding` true):

- `vendor/russh` is russh 0.64.1 as published, with one patch
  (`vendor/patches/russh/0001-session-binding.patch`, which `patch -p1`
  applies to the published crate to give this tree byte for byte): the
  client's key exchange keeps `SessionBinding` at its first exchange, and
  `Session::session_binding` gives it. `Cargo.lock` and `fuzz/Cargo.lock`
  name russh with no source and no checksum, as a path package;
  `vendor/README.md`, the map of `AGENTS.md` and `.github/dependabot.yml`
  say so.
- `crates/podssh-ssh/src/handler.rs`: `kex_done` gives the binding to the
  agent's `Forward`. `crates/podssh-ssh/src/agent_bind.rs` frames the bind
  as OpenSSH's `ssh_agent_bind_hostkey` does and reads the agent's answer
  whole; `crates/podssh-ssh/src/agent_forward.rs` sends it before it
  accepts the channel, and refuses the channel when no answer comes.
- `SECURITY.md` (Known gaps), `docs/cli.md` ("Forwarding") and the
  manual's note of `-A` say that the agent is bound, and that an agent that
  refuses the bind serves unbound.
- Tests: `agent_channel_binds_the_agent_to_the_host_key_first` (the
  stand-in agent reads the bind before the server's request: the server's
  Ed25519 host key, as sent, verifies its signature of the session
  identifier, and `is_forwarding` is 1),
  `agent_channel_goes_on_when_the_agent_refuses_the_bind` (an agent that
  answers SSH_AGENT_FAILURE still serves the server's request, and its
  refusal never reaches the server), and in `agent_bind.rs`
  `agent_channel_bind_is_framed_as_openssh_frames_it` and
  `agent_channel_bind_reads_the_whole_answer`; the stand-in agent of the
  five tests of T-036 answers a bind first. `cargo test -p podssh-ssh --
  agent_channel`: 9 passed on Windows 11 and 9 in the build image.
  Planted, no bind kept from the key exchange (the Prove's plant): the
  test of the bind and the test of a refused bind failed; restored, 9
  passed. The functions that send the bind are `bind_agent` and
  `set_binding`: a function named `bind` read as a socket's bind to the
  listener check of `scripts/check-repo.py`.
- `patch -p1` of `vendor/patches/russh/0001-session-binding.patch` on
  russh 0.64.1 from the registry gave `vendor/russh` file for file
  (`diff -r`). `cargo deny` passed, with russh as a path package.
- The workspace's tests (`cargo test --workspace --no-fail-fast`, Windows
  11): 1942 passed, and 3 failed on the merge itself: the manual's check of
  names read `ssh-add -h` in the note of `-A` as a flag of podssh, its scan
  of variables read the string `"SSH_AGENTC_EXTENSION"` of a test as a
  variable, and the record's counts; the note says "ssh-add" alone now,
  the test's message is a sentence, and the counts are made again.
- In the build image, the steps `lint` and `release` (2026-10-13): green;
  interop 507 passed, 0 failed, 1 env; `agent` 26 of 26, with
  `agent.openssh.add_h`, `agent.openssh.bound` and `agent.openssh.bound_key`
  (OpenSSH 10.3p1's `ssh-agent`: through `podssh ssh -A`, the server of
  port 2201 saw id_rsa and not id_ecdsa, which `ssh-add -h
  elsewhere.invalid` keeps for that host).
- Waits for T-251: the gate's plant (no bind: id_ecdsa is listed on the
  server), and whether CI's TruffleHog reads each test key of russh's own
  source (`vendor/russh/src/keys/`) as a note.
- Not done here: podssh's own login through the agent sends no bind
  (`is_forwarding` false), which OpenSSH's client also sends.

# T-291: The escape `~C`: add and stop the forwards of a running session

**Source:** the work of T-041 (2026-10-11), its step 4; the OthmaneBlial/MobaRust
report in GitHub #21 (item 3, a stop action). Read in the report and in ssh(1).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The forwards of a session are fixed as it starts: a user cannot add a `-L`
or a `-R` to a running session, nor stop one that is no longer wanted, as
OpenSSH's escape `~C` allows. `~#` (T-041) lists the forwards and their
counts, and cannot change them.

## Premise

Read: the escapes are `~.`, `~R`, `~#`, `~?` and `~~`
(`crates/podssh-ssh/src/escape.rs:13-25`). The listeners of `-L` and `-D` are
served from the start of the session (`crates/podssh-ssh/src/local.rs:152-181`),
and `-R` is asked for after the login (`crates/podssh-ssh/src/remote.rs:46-111`).
ssh(1), ESCAPE CHARACTERS: `~C` opens a command line that takes `-L`, `-R`,
`-D`, `-KL`, `-KR` and `-KD` (read in the manual, not measured here).

## Approach

1. `~C` reads one line on the terminal, as a prompt does, with OpenSSH's
   commands; `help` lists them, and another word is refused with a line.
2. `-L` and `-D`: bind a new listener as T-038 binds one, and serve it on
   the session's connection; `-KL PORT` and `-KD PORT` close its listener,
   and the connections that it carried go on, as in OpenSSH.
3. `-R`: `tcpip-forward`, as T-035 asks; `-KR [BIND:]PORT`:
   `cancel-tcpip-forward`.
4. `~#` lists the forwards so changed; `~?` names `~C`.

## Decision

2026-10-13, in the work.

- The line is read from the session's own keys, with the question of
  ZMODEM (`crates/podssh-ssh/src/zmodem/ask.rs:54`), in raw mode, and the
  keys after its Enter in the same read go back to the session
  (`crates/podssh-ssh/src/io/input.rs:57`). Lost: OpenSSH's way, which
  leaves raw mode and reads the terminal with `read_passphrase`: podssh's
  input task already reads stdin, and a second reader would take keys from
  it (and wait on a Windows console). No key of the line reaches the
  server.
- podssh-ssh binds nothing: the caller gives `Options::command_line`, a
  `Forwarder` (`crates/podssh-ssh/src/escape_command.rs:141`) that reads a
  spec as its command line reads one and makes the listeners of `-L` and
  `-D` with the same probe (`crates/podssh-cli/src/ssh/local_bind.rs:243`),
  as the binder of a control master does. Lost: a bind inside podssh-ssh,
  which would break the rule of the crate and repeat the probe; a closure
  type as the master's `Binder`, which has no place for the reading of `-R`.
- `~C` is an escape only where the caller gives a `Forwarder`
  (`podssh ssh`), and not in a session that a control master carries, as
  OpenSSH offers no `~C` to a client of its master: there `~C` goes to the
  server as typed (`crates/podssh-ssh/src/mux/msession.rs:173`). Lost: a
  `~C` of a client sent as `-O forward` to the master, which OpenSSH does
  not do.
- `-R` and `-KR` wait for the server's answer, 20 s at most
  (`crates/podssh-ssh/src/escape_run.rs:32`), and "Forwarding port." comes
  after the server took the forward. OpenSSH prints it before the answer
  and prints a warning later; podssh's way tells the user at once, and the
  session's keys wait as they wait for the line. Lost: an answer read on a
  task that outlives the line, which needs a second place to print from.
- `-KL` and `-KD` find the listeners in a table of the forwards that serve
  now (`crates/podssh-ssh/src/local.rs:187`), for the whole process, as the
  counts of `~#` are: the forwards of the command line serve beside the
  session, outside its pump. A port with no address names each listener of
  that port, `localhost` those on loopback, `*` and an empty address each
  one (`crates/podssh-ssh/src/escape_command.rs:52`). A closed listener
  ends its accept at once; the connections that it took go on, as in
  OpenSSH. `~#` says closed when no listener of the forward is left.
  `-KR` finds the forward by the port that the server listens on (the one
  it chose for a port of 0) and, when one is given, the address sent
  (`crates/podssh-ssh/src/remote.rs:122`).
- The forwards that `~C` adds belong to the connection, and those that it
  stops stay stopped: a new connection of `--persist` asks only for the
  forwards of the command line that `~C` did not stop
  (`crates/podssh-ssh/src/remote.rs:53`, `crates/podssh-ssh/src/tally.rs:104`),
  and a listener that `~C` closed stays closed. Lost: asking again for each
  forward of the command line, which would bring back a forward that the
  user stopped; keeping the forwards of `~C` for later connections, which
  OpenSSH, with no `--persist`, has no rule for.
- The words are OpenSSH's ("Forwarding port.", "Canceled forwarding",
  "Unknown port forwarding.", "Invalid command.", "Bad forwarding close
  specification."), on podssh's lines; the name of the forward follows
  "Canceled forwarding". A line that starts with `!` is refused with a line
  that says that podssh runs no local command; OpenSSH says
  "Invalid command." when `PermitLocalCommand` is off, which podssh does not
  read.
- The manual's check of names lets `-KL`, `-KR` and `-KD` through by name
  (`flag_exists` in `crates/podssh-cli/src/man/notes.rs`): they are
  commands of `~C`, not flags, and the note writes them as OpenSSH writes
  them.

## Prove

```sh
cargo test -p podssh-ssh -- escape_command
sh scripts/dev.sh check
```

The unit test parses each command of `~C`, and refuses another. In the gate,
`scripts/interop-pty.py` adds a `-R` with `~C`, the server's port answers,
then `-KR` closes it, and the port refuses. Plant: ignore `-KR`; the check
of the refusal fails.

## Correction

2026-10-13. When the work started (at `c7dd479`), the escapes were also
`~d` (T-158, where the far end keeps shells) and `~Z` (T-148), in the same
table as the five that the Premise names. `~C` joins that table after
`~.`, as in OpenSSH's help (`crates/podssh-ssh/src/escape.rs:33`).

## Done

2026-10-13. `~C` opens OpenSSH's command line in
a session with a pty:

- `crates/podssh-ssh/src/escape.rs`: `~C` in the table, offered with
  `with_command_line` (`crates/podssh-ssh/src/escape.rs:63`); the keys after
  it in the same read start the line (`crates/podssh-ssh/src/escape.rs:109`).
- `crates/podssh-ssh/src/escape_command.rs`: the line as OpenSSH's
  `process_cmdline` reads it (`crates/podssh-ssh/src/escape_command.rs:82`),
  its help, and the `Forwarder` of the caller.
- `crates/podssh-ssh/src/escape_run.rs`: the line read from the session's
  keys (`crates/podssh-ssh/src/escape_run.rs:82`), and each command on the
  session's connection (`crates/podssh-ssh/src/escape_run.rs:114`): `-L`
  and `-D` serve beside the session in its pump (`Added`), `-R` and `-KR`
  ask the server (`crates/podssh-ssh/src/escape_run.rs:166` and
  `crates/podssh-ssh/src/escape_run.rs:191`), `-KL` and `-KD` close
  listeners (`crates/podssh-ssh/src/local.rs:217`).
- `crates/podssh-ssh/src/local.rs`: `Listen` says where it listens, and
  can be closed; the table of the forwards that serve. `remote.rs`:
  `cancel`, and a forward that `~C` stopped is not asked for again.
  `tally.rs`: `; closed` on the line of `~#`. `zmodem/ask.rs`: the keys
  after an answer. `io/input.rs` (the input of a run, as on `main`):
  `unread`. `io.rs`, `session.rs`, `options.rs`: the caller's `Forwarder`
  to the pump.
- `crates/podssh-cli/src/ssh/local_bind.rs`: the TCP listener and the
  socket of `-L` and `-D` can be closed (`crates/podssh-cli/src/ssh/local_bind.rs:137`
  and `crates/podssh-cli/src/ssh/local_bind.rs:184`), and the `Forwarder`
  of `podssh ssh`, which `crates/podssh-cli/src/ssh/mod.rs:198` gives to
  each session.
- The manual: the note of the terminal names `~C`, and a note of its own
  (`crates/podssh-cli/src/man/notes_ssh.rs:131`); `docs/cli.md` ("`~C`
  adds and stops forwards") and `docs/terminal.md` ("What podssh reads
  from the terminal").
- Tests, `cargo test -p podssh-ssh -- escape_command` (8): the commands of
  OpenSSH and the refusals (`escape_command_tests.rs`, 4), `~C` in a read
  (`escape.rs`), the keys given back (`io/input.rs`), and against a russh
  server in the process (`escape_run_tests.rs`, 2): `-R` asks, `-KR` lets
  go, a channel for the port is then refused, `~#` says closed, and a new
  connection does not ask again; `-L` serves until `-KL` closes its
  listener. 8 passed on Windows 11 and in the build image. `cargo test -p
  podssh-cli --lib -- a_closed_listener man::notes`: 5 passed on both.
  Planted, each restored: `-KR` ignored (the Prove's plant: the arm of
  `Order::Cancel(Kind::Remote, ..)` does nothing) and no filter in
  `remote::request` each failed
  `escape_command_r_asks_the_server_and_kr_lets_it_go`; `Tcp::close`
  that signals nothing failed `a_closed_listener_takes_no_connection`.
  podssh-ssh and podssh-cli together: 989 passed, 0 failed.
- In the build image, the steps `lint` and `release` (2026-10-13): green,
  clippy 1.99 clean; interop 509 passed, 0 failed, 1 env; the `pty`
  harness 15 of 15 with `pty.command_line` (`~C -R
  127.0.0.1:2290:127.0.0.1:2201` against OpenSSH's sshd of port 2201: the
  port gave sshd's banner, then `-KR` and the port refused) and
  `pty.command_line.local` (`~C -L` on a free port, the banner, then `-KL`
  and the port refused). Dropbear has no check of `~C`: the pty harness
  runs against OpenSSH only.
- The merge kept, beside `~C`, the sink of `podssh each` (T-183) and the
  Ctrl-C of T-293 in `io.rs` and `session.rs`.
