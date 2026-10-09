The work of milestone M7, `podssh pipe` and `--persist`, and the backlog of
streams that `pipe` can carry: desktop streams and Telnet, a published HTTP
service, serial devices and USB/IP. The design is `docs/design.md:370-405`;
the milestone is `docs/ROADMAP.md:227-236`.

# T-174: `podssh pipe A B` with local addresses

**Source:** ROADMAP M7 (`docs/ROADMAP.md:229-233`), `docs/design.md:387-405`;
GitHub #26 (Nemo-010, 2026-10-08). Measured here on `3ee70dc`.
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

To join two byte streams, a script has only `podssh proxy`: stdin and stdout
to a target of the relay. podssh cannot join a local program, an inherited
descriptor and a stream, as socat does. This entry makes `podssh pipe A B`:
the verb, the address grammar, the copy loop, and the local addresses `-`,
`stdio`, `fd:N` and `exec:CMD`. T-175 adds the remote addresses, T-176
`unix-connect:`, and T-177 the listeners.

## Premise

- Measured: `PODSSH_OFFLINE=1 podssh pipe stdio relay:example.org:80` exits
  64 with `podssh: unknown subcommand 'pipe'.` The verb table has no `pipe`
  row (`crates/podssh-cli/src/flags.rs:398-429`).
- Read: the only pump is `crates/podssh-cli/src/proxy.rs:186-281`. At the end
  of input it stops sending and keeps receiving
  (`crates/podssh-cli/src/proxy.rs:8-11`). T-101 is the opposite defect in
  `crates/podssh-ts/src/pipe.rs`; the new pump must not repeat it.
- Read: `exec:` starts the user's own program. The operator accepted it on
  2026-10-08 (`docs/decisions.md`). On sandbox A, `/tmp` and `$HOME`
  do not run programs (`docs/STATUS.md:166`).

## Approach

1. The verb: a `pipe` row in `crates/podssh-cli/src/flags.rs:398-429`, two
   required positionals (`crates/podssh-cli/src/positionals.rs:7-92`), a
   `Parsed::Pipe` variant (`crates/podssh-cli/src/parsed.rs:8-135`), a
   dispatch arm, and `pipe` in `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:110-113`). No `--timeout` row: the
   gate at `crates/podssh-cli/src/dispatch.rs:211-229` would require it.
2. The grammar, in a new crates/podssh-cli/src/pipe/address.rs: `KIND:REST`.
   An unknown kind exits 64 and lists the kinds. `-` is `stdio`; `stdio` on
   both sides exits 64. Invariant: both addresses are valid before anything
   starts.
3. Move the pump of `crates/podssh-cli/src/proxy.rs:186-247` to
   crates/podssh-cli/src/pipe/pump.rs, over two duplex ends, with its rules:
   reads of 32 KiB; an end of input half-closes the other side (a shutdown
   of the write side, never a drop, or the reply is lost), and the other
   direction goes on; a reader that is gone ends the pipe with 0
   (`crates/podssh-cli/src/proxy.rs:272-275`). Keep
   `runtime.shutdown_background()` (`crates/podssh-cli/src/proxy.rs:92-94`).
   This is the one path: T-175 moves `podssh proxy` onto it.
4. `fd:N` (Unix): `fcntl(F_GETFD)` first. A closed N, or N below 3, exits 64.
   On Windows, `fd:` exits 64.
5. `exec:CMD`: split the words with single and double quotes, with no
   variables, globs or backslash escapes (a Windows path keeps its `\`). The
   child gets one end of a socketpair; when that fails (EPERM, EACCES,
   ENOSYS), two pipes; Windows uses pipes. stderr is shared. When the other
   side ends, the child gets the end of input, and podssh waits for it as a
   shell waits. Add the `process` feature of tokio to podssh-cli
   (`Cargo.toml:71-73` lacks it; `crates/podssh-ssh/Cargo.toml:20` has it).
6. The exit status: the child's, and 128 + N for a signal; with two children,
   B's. A program that is not found gives 127, one that cannot run 126, as a
   shell gives. With no child, a clean end gives 0.
7. In the same commit: `docs/cli.md`, the notes
   (`crates/podssh-cli/src/man/notes.rs:7-25`), two examples
   (`crates/podssh-cli/src/man/examples.rs:8-73`; its test at
   `crates/podssh-cli/src/man/examples.rs:196-206` learns the new variant),
   `docs/design.md:389-397`, `docs/STATUS.md`. Each file stays under 500
   lines (`AGENTS.md:198-199`).

## Decision

Recommendation: `exec:` splits the words itself and starts no shell, because
podssh must not assume a shell (`AGENTS.md:182-183`), and the user can name one
(`exec:sh -c 'CMD'`). The alternative, a `system:` address through
`/bin/sh -c` as in socat, lost: Windows and some images have no `/bin/sh`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli pipe::            # grammar, quoting, two stdio, the socketpair fallback (injected EPERM)
cargo test -p podssh-cli --test pipe       # the real binary, with itself as the child
cargo test -p podssh-cli --test flag_table # the verb has its dispatch arm
sh scripts/dev.sh check                    # interop.sh: the Linux cases below
```

The new crates/podssh-cli/tests/pipe.rs needs no other tool, also on
Windows: `exec:` of `podssh man --no-pager` gives the manual and 0, `exec:` of
`podssh man nonsense` gives 64, and a closed `fd:9` gives 64. In the gate,
`scripts/interop.sh` sends 5,000,000 random bytes through
`pipe stdio exec:cat` with equal digests, reads `fd:3` from a file, and gets
7 from `exec:sh -c 'exit 7'`. Plant: drop the child's status (always 0); the
checks for 7 and 64 must fail.

# T-175: `podssh pipe` with remote addresses

**Source:** ROADMAP M7 (`docs/ROADMAP.md:229-233`), `docs/design.md:394-397`;
GitHub #26 (Nemo-010, 2026-10-08); the RustConn report in GitHub #24 (one
address model across roads; read in the report, not verified here).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

After T-174, `podssh pipe` joins local ends only. The remote addresses of the
design are `relay:HOST:PORT`, `ssh:[USER@]BASTION,HOST:PORT`,
`node:NAME[,PORT]` and `iroh:TICKET`. Without them, a script cannot join a
local program to a target, and `podssh proxy` stays a second pump.

## Premise

- Read: `podssh proxy` is the `relay:` address today. It opens the session
  with `crates/podssh-relay/src/open.rs:180-212` and pumps it
  (`crates/podssh-cli/src/proxy.rs:45-96`).
- Read: `crates/podssh-ssh/src/relay_stream.rs:118-122` sends Close 1000 when
  its write side ends. That is right for SSH and wrong for a pipe: the relay
  has no half-close (`docs/relay.md:74-80`), so a Close cuts a reply on its
  way. Measured live for proxy: the full reply after stdin closed
  (`docs/STATUS.md:108`).
- Read: `-W` opens its stream with `crates/podssh-ssh/src/forward.rs:12-20`
  after the hops of `crates/podssh-ssh/src/run.rs:109-116`, but that code is
  private and gives only an exit code.
- Read: `TODO/issues.md` (#26) says that a binary protocol through `-W` is
  measured. Only exec is measured with digests (`docs/STATUS.md:69`); `-W`
  was checked with a banner of 16 bytes (`scripts/interop.sh:215-216`).
- Read: `node:` needs T-084 (M4) and `iroh:` needs T-163 (M6); both are done
  before M7 starts.

## Approach

1. One adapter per kind, in crates/podssh-cli/src/pipe/remote.rs: it opens
   its road and gives a duplex stream and, at the end, a close reason. The
   pump does not know the road (`docs/architecture.md:99-101`).
2. `relay:HOST:PORT`: parse as `crates/podssh-cli/src/proxy.rs:100-110` does;
   open with `crates/podssh-relay/src/open.rs:180-212`. Keep the rules of
   proxy: no Close at the end of input, the ping watcher
   (`crates/podssh-cli/src/proxy.rs:190-195`), empty frames dropped. IPv6
   literals follow T-007.
3. Move `podssh proxy` onto the pipe: `run_proxy`
   (`crates/podssh-cli/src/proxy.rs:45-96`) runs `stdio` and `relay:`. Keep
   its exit codes and messages (`crates/podssh-cli/src/proxy.rs:158-171`,
   `crates/podssh-cli/src/proxy.rs:249-281`).
4. `ssh:[USER@]HOP[,HOP...],HOST:PORT`: the last item is the target, each
   other item a hop, read as `-J` reads it
   (`crates/podssh-cli/src/ssh/resolve.rs:135-139`,
   `crates/podssh-cli/src/ssh/resolve.rs:390-438`). Make
   `crates/podssh-ssh/src/run.rs:109-116` a public `connect_chain` that `-W`
   and the pipe both use; keep each handle alive until the pipe ends. The
   options: `-i`, `-o NAME=VALUE` through
   `crates/podssh-cli/src/ssh/options.rs:55-172` (a keyword of a session,
   such as `RequestTTY` or `RemoteCommand`, exits 64), `--direct`,
   `--relay-host`, `--relay-addr` and `--ca-file`.
5. `node:NAME` after T-084, and `iroh:TICKET` after T-163: one adapter and
   one test each. If T-163 makes a ticket a credential, read it from a file
   (`iroh:@FILE`), never from argv.
6. Exit codes: sysexits, as `podssh proxy` (`docs/cli.md:403`): 69; 77 for a
   refusal (the relay, the proxy, a host key, the authentication); 78. Give
   `crates/podssh-ssh/src/run.rs:153-211` a typed error, so that 77 is not
   guessed from a message.
7. In the same commit: `docs/cli.md`, `docs/design.md:389-397`, the notes,
   the examples, `docs/STATUS.md`.

## Decision

Recommendation: add `tcp:HOST:PORT`, the direct road through `HTTPS_PROXY`
with `crates/podssh-ws/src/dial.rs:207-222`, because `ssh --direct` uses the
same dialer and socat users expect it. The alternative, no direct address,
lost: a host with egress would then have only `relay:`, and its 64 MiB limit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test proxy           # proxy is unchanged on the shared path
cargo test -p podssh-cli --test pipe -- remote  # the grammar; PODSSH_OFFLINE=1 gives 69
sh scripts/dev.sh check                         # interop.sh and interop-faults.sh: the cases below
printf 'HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n' | podssh pipe stdio relay:example.com:80  # live, on request
```

In the gate: `relay:` goes through the stand-in relay. `ssh:` goes through
OpenSSH to a digest server on 127.0.0.1 (it reads to the end of input, then
sends the SHA-256): 5,000,000 bytes give equal digests, which also measures
the path of `-W`. A late reply: a target sends 1 s after it accepts, and
`pipe stdio relay:` with stdin at its end gets the bytes. Plant: send a
Close at the end of input, as `crates/podssh-ssh/src/relay_stream.rs:118-122`
does; the late-reply check must fail.

## Correction

2026-10-09 (T-081): the relay does not cut a reply at a client's Close. It
stops the client's bytes to the target, but the target's bytes still come,
until the target closes or is idle for 15 s; then its Close is `1000 client
half-closed, target idle for 15s` (`docs/relay.md:67-73`, measured with
`python scripts/capture-close.py --client-close`). A Close is a half-close for
a reply that comes within 15 s of silence; a target that waits for the end of
its input sees no end.

2026-10-09 (T-133): the hop chain is a public function now,
`podssh_ssh::run::connect_hops` (`crates/podssh-ssh/src/run.rs:105-118`): it
returns each handle, authenticated, for `ssh` and for SFTP. So the Premise's
"that code is private" no longer holds, and the step that makes it a public
`connect_chain` is done under that name.

2026-10-09 (T-134): step 6 is done for the hops: `connect` and
`connect_hops` return `podssh_ssh::run::HopError` (unreachable, the host key,
or the login refused, from `podssh_ssh::auth::AuthError`), so 77 is not
guessed from a message; `podssh cp` maps it so.

# T-176: `podssh pipe` with `unix-connect:PATH`

**Source:** ROADMAP M7 (`docs/ROADMAP.md:229-233`); GitHub #26 ("a name for
AF_UNIX streams"), from the USBoverSSH report in GitHub #25
(`ImKKingshuk/USBoverSSH:usboverssh/src/tunnel.rs`; read in the report, not
verified here).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

Many local services listen on a Unix socket: a database, a container
runtime, an agent. podssh cannot join one to another stream. A connect is
not a listener, so `docs/target-environment.md:74-78` allows it.

## Premise

- Measured: `podssh proxy unix-connect:/tmp/x.sock 1` exits 64
  (`':' is not allowed`): no command takes a socket path.
- Read: podssh connects to a Unix socket only for the agent
  (`crates/podssh-ssh/src/keys.rs:275-286`); on Windows the agent is a
  named pipe (`crates/podssh-ssh/src/keys.rs:287-303`).
- Read: `sun_path` holds 104 to 108 bytes, and doctor refuses a longer name
  before the call (`crates/podssh-cli/src/doctor/unix.rs:189-198`,
  `crates/podssh-cli/src/doctor/unix.rs:210-212`).
- Read: sandbox A allows an AF_UNIX bind (`docs/STATUS.md:166`); a connect
  was not measured. The attempt is the probe, and its errno is the message.

## Approach

1. `unix-connect:PATH` in the grammar of T-174; on Linux also
   `unix-connect:@NAME` for the abstract namespace, which doctor also probes
   (`crates/podssh-cli/src/doctor/unix.rs:178-185`).
2. Check the length before the call (exit 64). Connect with the `UnixStream`
   of tokio. ENOENT and ECONNREFUSED exit 69, EACCES 77; each message names
   the path and the errno.
3. At the end of input, shut down the write side, so that a server that
   answers after the end of input still answers.
4. On Windows: AF_UNIX (Windows 10 1803 and later) and named pipes, each
   after a probe at run time; where one fails, exit 69 with the reason
   (the operator's ruling of 2026-10-08).
5. T-040 gives the remote form: a socket on the server, through `-W`.
6. In the same commit: `docs/cli.md`, `docs/design.md:393`, the notes,
   `docs/STATUS.md`. With T-174 and T-175 done, the first item of ROADMAP M7
   is done.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test pipe -- unix
```

On Unix, a server that the test makes reads to the end of input, then sends
the SHA-256 of what it read: 1,000,000 bytes give equal digests. A missing
path exits 69 and names it; a path of 200 bytes exits 64. On Windows, the
address exits 64. Plant: drop the shutdown at the end of input; the server
never answers, and the test fails at its limit of 10 s.

# T-177: `podssh pipe` with a local listener after a probe

**Source:** ROADMAP M7 (`docs/ROADMAP.md:232-233`), `docs/design.md:399-405`;
GitHub #26 (a local-only mode, as the `--local` of bunflared; read in the
report, not verified here); sandbox A of T-001.
**Category:** feature
**Milestone:** M7
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Desktop clients, browsers and database clients call `connect()` themselves:
they need a local port or socket (`docs/design.md:402-405`). podssh refuses
each listener. The design allows one for `pipe`, locally, after a probe
shows that an AF_UNIX or loopback bind works (`docs/design.md:399-401`).

## Premise

- Read: the operator ruled on 2026-10-08 (`docs/decisions.md`): a local
  listener is allowed when the user asks for it and a probe at run time
  allows the bind. The default is loopback and AF_UNIX; the user can
  configure the address and can turn listening off.
- Read: five documents still say that podssh never listens:
  `AGENTS.md:184-189`, `docs/architecture.md:102-112`,
  `docs/target-environment.md:74-78`, `SECURITY.md:69-75`, `README.md:37-40`.
- Read: sandbox A refuses an AF_INET bind and allows an AF_UNIX bind
  (`docs/STATUS.md:166`). The box refuses each `bind`, AF_UNIX too
  (`scripts/box/seccomp.json:5-10`), so it gives the refused case.
- Read: doctor binds, closes, and never listens
  (`crates/podssh-cli/src/doctor/unix.rs:137-231`). A bind that works does
  not prove that `listen()` works.

## Approach

1. Addresses `unix-listen:PATH` (on Linux also `@NAME`), and
   `tcp-listen:PORT`, which listens on 127.0.0.1. `tcp-listen:ADDR:PORT`
   listens on the address that the user gives (`[::1]`, or another); an
   address that is not loopback prints one line: other hosts can connect.
2. podssh listens only for a `-listen:` address that the user gives.
   `PODSSH_LISTEN=no` turns listening off: each such address then exits 78
   before any bind. Add the variable to `VARIABLES`
   (`crates/podssh-cli/src/man/facts.rs:45-122`); the settings file of T-048
   can set the same.
3. The attempt is the probe: socket, bind, listen. EACCES or EPERM exits 77
   with the errno and an address that needs no listener; another error exits
   69. Each failure path removes the socket file.
4. Access: bind under umask 077 (mode 0600). Check the uid of each peer
   (`SO_PEERCRED` on Linux, `getpeereid` elsewhere), and close a peer of
   another uid. A TCP listener cannot check its peer: print one line that
   each local user can connect.
5. A path that exists and is not a socket exits 64. A socket is removed only
   when a connect to it is refused (stale). The file is removed at exit,
   also after SIGINT and SIGTERM.
6. One connection, then the pipe ends with its status. `--keep-listening`
   accepts again, each connection with a new instance of the other address
   (a new relay session), 8 at once at most.
7. Move the bind code of `crates/podssh-cli/src/doctor/unix.rs:200-231` to a
   module that doctor and pipe share; doctor stays bind-and-close. In the
   same commit, change each sentence that says podssh never listens: the
   five documents, `crates/podssh-cli/src/help.rs:213-214`,
   `crates/podssh-cli/src/man/notes.rs:46-48`, the reasons of the `-L` and
   `-D` rows (`crates/podssh-cli/src/flags.rs:194-199`; keep `-W HOST:PORT`
   as what to use, which `crates/podssh-cli/tests/flag_table.rs:82-101`
   asserts), `crates/podssh-cli/src/ssh/keywords.rs:83-84`,
   `crates/podssh-cli/src/ssh/options.rs:157-159`,
   `crates/podssh-cli/src/doctor/unix.rs:164` and
   `crates/podssh-cli/src/doctor/unix.rs:186`.
8. `unix-listen:` with `exec:` is the local-only mode that GitHub #26 asks
   for: nothing leaves the host. T-038, T-039 and T-186 use this code.

## Decision

Recommendation: one connection by default, because a listener that stays
after its first use is a service that the user can forget. The alternative,
a listener that stays until Ctrl-C (the `fork` of socat), lost as the
default; it is the flag `--keep-listening`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test pipe -- listen
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh >box.log 2>&1; grep -q 'unix-listen exit=77' box.log
```

The test (Unix) joins `unix-listen:` to `exec:`, connects as a client, and
checks the bytes and the mode 0600; an injected EACCES exits 77 and leaves
no file; `PODSSH_LISTEN=no` exits 78 and binds nothing. In the gate, `tcp-listen:127.0.0.1` with `exec:cat` gives equal
digests, and a client of another uid (`su podtest`) is closed. A new step of
`scripts/sandbox-check.sh` (limit 5 s) records the refusal in the box.
Plant: bind with no umask; the check of the mode must fail.

# T-178: `--persist`: connect again and attach `tmux` again

**Source:** ROADMAP M7 (`docs/ROADMAP.md:234-236`), `docs/design.md:221-231`;
GitHub #19 (a lasting terminal through `tmux`, from the slingshot report:
`ado11231/slingshot:crates/slingshot-agent/src/jobs.rs`; read in the
report, not verified here).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

When the relay drops a session, `podssh ssh` exits 255 and the remote shell
is gone (`docs/design.md:188`). Against a standard sshd only one end runs
podssh, so the layer of M6 cannot help (`docs/design.md:221-223`). The
cheapest repair: connect again, and attach a `tmux` session that kept
running on the server (`docs/design.md:224-226`).

## Premise

- Measured: `podssh ssh --persist host` exits 64 (`unknown flag '--persist'`).
- Read: a lost link is `End::Lost` (`crates/podssh-ssh/src/io.rs:24-25`),
  an error at `crates/podssh-ssh/src/session.rs:103`. An exit status, a
  close with no status, and `~.` are other ends
  (`crates/podssh-ssh/src/session.rs:100-102`). Raw mode is entered once for
  each session (`crates/podssh-ssh/src/session.rs:80-96`).
- Read: the relay ends a session at 64 MiB (1009) or 12 h (1001)
  (`docs/relay.md:184-190`). Sandbox A measured the cap at 67,107,943 bytes,
  and one close `1011` in 180 short sessions (`docs/STATUS.md:174-175`).
- Read: tmux is never assumed (`docs/target-environment.md:90-92`).

## Approach

1. Flags `--persist` and `--persist-name NAME` (default `podssh`; letters,
   digits, `_` and `-`, 32 at most) in `crates/podssh-cli/src/flags.rs:112-235`.
   With a command, `-W`, `-N`, `-s` or `RemoteCommand`, exit 64.
2. The probe, after the login: one exec runs `command -v tmux`. No tmux:
   exit 255 with "the server has no tmux on PATH; --persist needs it". T-193
   uses the same function.
3. The session runs `tmux new-session -A -s NAME` with a pty, as `-tt` does.
   `-A` attaches when the session exists; that makes a second run safe.
4. A loop around `crates/podssh-cli/src/ssh/mod.rs:78-106`. Connect again
   only for a lost link: `End::Lost`, the ping watcher, or the relay's 1001,
   1006, 1009 or 1011. Never after an exit status, `~.`, a detach of tmux
   (exit 0), or a failure of the host key or the authentication.
5. Between attempts: leave raw mode, print one line for each attempt, and
   wait with `crates/podssh-relay/src/open.rs:270-276` (jittered, 30 s at
   most); 10 attempts or 5 minutes at most. Ctrl-C stops the wait with 255.
   Keys typed meanwhile wait in a queue of 64 KiB, and go after the attach.
6. Each attempt checks the host key with the same policy, and uses the
   cached token. A prompt with no terminal ends the loop
   (`docs/cli.md:420-422`). After the attach, send the window size again.
7. In the same commit: `docs/cli.md`, the notes of ssh
   (`crates/podssh-cli/src/man/notes.rs:27-69`), `docs/design.md:224-226`,
   `docs/STATUS.md`, and tmux in the interop image
   (`scripts/interop.sh:32-33`). T-025 shares the classes of close codes;
   T-153 replaces this loop when both ends run podssh.

## Decision

Recommendation: refuse `--persist` when the probe finds no tmux, because a
new shell after a drop looks like the old one and has lost its state: a
silent change of behaviour (`docs/target-environment.md:90-92`). The
alternative, a new shell with a warning, lost for that reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- persist   # each refusal exits 64, and nothing connects
sh scripts/dev.sh check                               # interop-faults.sh: the drop below
```

In `scripts/interop-faults.sh`, `--persist -tt` goes through two stand-in
relays. The input sets `MARK=kept`; the harness kills the first stand-in, as
`scripts/interop-faults.sh:152-162` does; the input then runs `echo M=$MARK`
and `tmux kill-session`. The output has `M=kept`, and the exit is 0. With
tmux moved off `PATH`, the exit is 255 and names tmux. Plant: start tmux
without `-A`; the second attach fails, and the check must fail.

# T-179: Desktop streams and Telnet through `proxy` and `pipe`

**Source:** GitHub #26 (desktop streams: GPU-Share,
`arjun988/GPU-Share:crates/gpumesh-core/src/desktop.rs`; MobaRust; the
protocol matrix of RustConn); GitHub #21 (meatshell and MobaRust: RDP, VNC,
Telnet and serial through external clients). Read in the reports, not
verified here.
**Category:** docs
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Users ask how to carry RDP, VNC and Telnet. The documents show SSH and one
HTTP request (`README.md:116-121`). They do not say which clients work with
no listener, or that the relay ends a desktop stream after 64 MiB.

## Premise

- Read: a byte pipe carries each TCP protocol
  (`crates/podssh-cli/src/man/notes.rs:140-144`); a client that calls
  `connect()` itself needs a listener (`docs/design.md:402-405`), which
  T-177 adds where a probe allows it.
- Read: 64 MiB for each session, both directions together
  (`docs/relay.md:127`), then Close 1009 (`docs/relay.md:188`); public
  targets only (`docs/relay.md:129`). Through the proxy of sandbox A: 0.5 to
  0.7 MB/s (`docs/STATUS.md:173`).
- Not measured: no RDP, VNC or Telnet client ran through podssh. Each claim
  about a client below is to verify.

## Approach

1. Measure three forms in the interop container, with a VNC server that
   Alpine packages (to verify: `tigervnc`); its first bytes are the RFB
   version line.
   - a. OpenSSH listens, and podssh carries:
     `ssh -o ProxyCommand='podssh proxy %h %p' -L 5901:127.0.0.1:5901 user@host`.
     It works today where a bind works.
   - b. `podssh pipe tcp-listen:127.0.0.1:5901 ssh:user@host,127.0.0.1:5901`
     (T-175, T-177).
   - c. No listener (sandbox A): only a client that runs a command as its
     transport. Name each client that can, after a check. The `-via` of
     TigerVNC starts `ssh -L` itself, so it needs a bind.
2. Measure the bytes per minute of an idle and of a busy desktop, so that
   the text can say how long a session lasts before 1009.
3. Telnet: `podssh proxy HOST 23` carries the bytes, but a person needs a
   client that answers the IAC options: form a or b with
   `telnet 127.0.0.1 PORT`.
4. Write a table "Other TCP protocols" after `README.md:116-121`: the
   protocol, what works now, what needs a listener, the 64 MiB limit. Add
   form a to `crates/podssh-cli/src/man/examples.rs:8-73`; its ProxyCommand
   parses (`crates/podssh-cli/src/man/examples.rs:173-180`). Link the table
   from `docs/design.md:402-405`.
5. No code. Record the measurements in `docs/STATUS.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli man::examples     # the new example parses with the real parser
grep -n '^### Other TCP protocols' README.md
python scripts/check-repo.py               # the links of the new table
```

A row of `docs/STATUS.md` gives the RFB line seen through form a, with the
date. Plant: write the example with `-L` given to `podssh ssh`; the test of
the examples must refuse it.

# T-180: Publish a local HTTP service at `https://NAME` through the relay

**Source:** GitHub #26 (Nemo-010, 2026-10-08); the reports in GitHub #18:
warren (`willykeenan/warren:docs/protocol.md`), bunflared
(`mirkobozzetto/bunflared:src/proxy.rs`, `mirkobozzetto/bunflared:src/ports.rs`)
and sandhole. Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** blocked

## Problem

A developer in a sandbox runs a web application and wants a URL for it. The
relay carries TCP to public targets and reverse sessions to named nodes
(`docs/relay.md:234-276`). It has no endpoint that takes public HTTPS for a
name, and podssh alone cannot add one.

## Premise

- Read: the relay is the operator's Cloudflare Worker, another project, and
  its document is the contract (`docs/relay.md:3-16`). It has no publish
  endpoint (`docs/relay.md:58-85`, `docs/relay.md:234-292`).
- Read: on the measured sandbox, `connect()` to loopback fails with EACCES
  (`docs/target-environment.md:22`). A node there cannot reach a server on
  127.0.0.1; it can reach a Unix socket (T-176) or a program (`exec:`,
  T-174).
- Read in the reports: warren publishes at `https://NAME.RELAY` with
  WebSocket upgrades, and TLS ends at its relay; bunflared maps several ports
  and finds local listeners; expiring and password links are open issues of
  bunflared.

## Approach

When the relay's operator adds the endpoint:

1. The relay's operator publishes it in the contract first: a name, a public
   host name, and each incoming connection as a reverse session
   (`open {id}`, `ready {id}`; `docs/relay.md:242-262`).
2. podssh uses the node runner (T-079) and `podssh node` (T-083):
   `podssh node NAME TARGET --publish`, TARGET each address of T-174 to
   T-176. podssh parses no HTTP: the bytes pass, WebSocket upgrades too.
3. podssh prints the URL and one line: "TLS ends at the relay; the relay can
   read this traffic." (the rule of warren, read in the report).
4. Expiry and passwords are options of the relay; podssh passes them and
   never prints a token. Port discovery comes later: it reads
   `/proc/net/tcp` only where `/proc` exists.
5. In the same commit: `docs/relay.md`, `docs/reverse.md`,
   `SECURITY.md:21-31` (what the relay sees), the notes, `docs/STATUS.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh check   # interop-faults.sh: the stand-in relay with the endpoint
```

`scripts/fake-relay.py` serves the endpoint as the contract gives it.
`curl --resolve` to the published name returns the body of a server on a
Unix socket, a WebSocket upgrade echoes, and stderr has the line about TLS.
Plant: hold each connection until a full HTTP header arrives; the WebSocket
check must fail.

## Blocker

The relay's operator: an endpoint that publishes a local HTTP service. The operator ruled on 2026-10-08 that the relay stays separate (`docs/decisions.md`).

# T-181: A `serial:` address for a local serial device

**Source:** GitHub #21 (MobaRust, `OthmaneBlial/MobaRust:crates/mobarust-serial/`;
meatshell: serial sessions through external clients); GitHub #23 (cubic: a
serial console when SSH fails). Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A user wants to script a serial console (a board on `/dev/ttyUSB0`), or to
reach it from another host. With T-174, only `fd:N` of a device that another
program opened and set up is possible. podssh sets no speed and no raw mode
on a serial line.

## Premise

- Read: the binary already sets termios through `libc` for the local
  terminal: save, `cfmakeraw`, restore on drop and in a panic hook
  (`crates/podssh-ssh/src/terminal/unix.rs:30-76`).
- Read: the operator ruled on 2026-10-08 that devices and workloads are
  streams (`docs/decisions.md`): a serial line is one more address of
  `pipe`, not a new kind of road.

## Approach

1. `serial:PATH[,BAUD]` in the grammar of T-174. BAUD from a fixed table,
   1200 to 4000000, default 115200; 8 data bits, no parity, 1 stop bit, no
   flow control.
2. The probe: the path is a character device, an `open` with `O_NOCTTY` and
   `O_NONBLOCK` works, `isatty` is true; then `TIOCEXCL`. Not a device: exit
   64. Another failure: 69 with the errno. Never assume a `dialout` group.
3. Save the termios; set raw mode, the speed, `CLOCAL` and `CREAD`, VMIN 1
   and VTIME 0. Restore on each exit path and in the panic hook, as
   `crates/podssh-ssh/src/terminal/unix.rs:63-76` does.
4. Windows (`serial:COM3[,BAUD]` with `SetCommState`) is a second step;
   until then it exits 64 with the reason.
5. In the same commit: `docs/cli.md`, the notes, one example
   (`podssh pipe serial:/dev/ttyUSB0,115200 stdio`), `docs/STATUS.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test pipe -- serial
```

On Linux, a pty pair from `openpty` stands in for the device: bytes go both
ways, and `tcgetattr` before and after gives equal settings. `/dev/null`
exits 64. Plant: skip the restore; the comparison of the settings must fail.

# T-182: USB/IP devices through `podssh pipe`: a tested recipe, with no driver in podssh

**Source:** GitHub #25 (the USBoverSSH report: USB/IP over an SSH channel,
`ImKKingshuk/USBoverSSH:usboverssh/src/protocol.rs`; read in the report, not
verified here); GitHub #26; the operator's ruling of 2026-10-08 that devices
and workloads are streams (`docs/decisions.md`).
**Category:** docs
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A user wants a USB device of one host to appear on another. USB/IP does this
with kernel modules on both hosts and one TCP connection (port 3240). podssh
can carry that connection, but no document says how, with which address,
and with which limits.

## Premise

- Read in the report (not verified here): USBoverSSH carries USB/IP over an
  SSH exec channel, and says that USB/IP needs kernel modules on the server.
- Read: an exec channel carries binary data with equal digests
  (`docs/STATUS.md:69`), and `pipe` carries a TCP stream (T-174, T-175).
- Read: through the relay, a session ends at 64 MiB (`docs/relay.md:127`);
  the traffic of a USB disk reaches that in seconds.
- Read: podssh cannot load a module or attach a device, and never assumes a
  privilege (`AGENTS.md:182-183`). The recipe uses the user's own `usbip` and
  its privileges.

## Approach

1. The recipe: `usbipd` runs on the server. On the client, run
   `podssh pipe tcp-listen:127.0.0.1:3240 ssh:me@usbhost,127.0.0.1:3240`
   (T-175, T-177), then `usbip attach -r 127.0.0.1 -b BUSID` as root. podssh
   needs no privilege; `usbip` does.
2. Use `ssh:`, never `relay:` to a public `usbipd`: USB/IP is not encrypted,
   and the relay would see the traffic of the device (`SECURITY.md:21-31`).
   Through the relay, the session ends at 64 MiB with 1009, and the device
   goes away; `--direct` avoids the relay where a direct road exists.
3. Measure the recipe on two Linux hosts that have the modules (the
   operator's machines): the attach, a read from the device, the detach.
4. Write the recipe and its limits as a row of the table "Other TCP
   protocols" of T-179 (or in the Approach of T-179 when the table does not
   exist yet). Record the measurement in `docs/STATUS.md`.
5. No driver: USB/IP inside podssh would need kernel modules and root.

## Prove

```sh
grep -n 'USB/IP.*64 MiB' README.md   # the row and its limit
python scripts/check-repo.py         # the links of the table
```

A row of `docs/STATUS.md` gives `usbip port` on the client after the attach,
with the date and the commands. Plant: delete "64 MiB" from the row; the
first command must fail.
