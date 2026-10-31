The work of milestone M7, `podssh pipe` and `--persist`, and the backlog of
streams that `pipe` can carry: desktop streams and Telnet, a published HTTP
service, serial devices and USB/IP. The design is `docs/design.md:886-954`;
the milestone is `docs/ROADMAP.md:231-240`.

# T-174: `podssh pipe A B` with local addresses

**Source:** ROADMAP M7 (`docs/ROADMAP.md:233-237`), `docs/design.md:903-954`;
GitHub #26 (Nemo-010, 2026-10-08). Measured here on `3ee70dc`.
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** done

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
  row (`crates/podssh-cli/src/flags.rs:353-412`).
- Read: the only pump is `crates/podssh-cli/src/pipe/relay.rs:104-230`. At the end
  of input it stops sending and keeps receiving
  (`crates/podssh-cli/src/proxy.rs:8-11`). T-101 is the opposite defect in
  `crates/podssh-ts/src/pipe.rs`; the new pump must not repeat it.
- Read: `exec:` starts the user's own program. The operator accepted it on
  2026-10-08 (`docs/decisions.md`). On sandbox A, `/tmp` and `$HOME`
  do not run programs (`docs/STATUS.md:282`).

## Approach

1. The verb: a `pipe` row in `crates/podssh-cli/src/flags.rs:353-412`, two
   required positionals (`crates/podssh-cli/src/positionals.rs:7-237`), a
   `Parsed::Pipe` variant (`crates/podssh-cli/src/parsed.rs:8-169`), a
   dispatch arm, and `pipe` in `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:110-140`). No `--timeout` row: the
   gate at `crates/podssh-cli/src/dispatch.rs:252-270` would require it.
2. The grammar, in a new crates/podssh-cli/src/pipe/address.rs: `KIND:REST`.
   An unknown kind exits 64 and lists the kinds. `-` is `stdio`; `stdio` on
   both sides exits 64. Invariant: both addresses are valid before anything
   starts.
3. Move the pump of `crates/podssh-cli/src/pipe/relay.rs:104-190` to
   crates/podssh-cli/src/pipe/pump.rs, over two duplex ends, with its rules:
   reads of 32 KiB; an end of input half-closes the other side (a shutdown
   of the write side, never a drop, or the reply is lost), and the other
   direction goes on; a reader that is gone ends the pipe with 0
   (`crates/podssh-cli/src/pipe/relay.rs:222-226`). Keep
   `runtime.shutdown_background()` (`crates/podssh-cli/src/proxy.rs:138-140`).
   This is the one path: T-175 moves `podssh proxy` onto it.
4. `fd:N` (Unix): `fcntl(F_GETFD)` first. A closed N, or N below 3, exits 64.
   On Windows, `fd:` exits 64.
5. `exec:CMD`: split the words with single and double quotes, with no
   variables, globs or backslash escapes (a Windows path keeps its `\`). The
   child gets one end of a socketpair; when that fails (EPERM, EACCES,
   ENOSYS), two pipes; Windows uses pipes. stderr is shared. When the other
   side ends, the child gets the end of input, and podssh waits for it as a
   shell waits. Add the `process` feature of tokio to podssh-cli
   (`Cargo.toml:80-82` lacks it; `crates/podssh-ssh/Cargo.toml:22` has it).
6. The exit status: the child's, and 128 + N for a signal; with two children,
   B's. A program that is not found gives 127, one that cannot run 126, as a
   shell gives. With no child, a clean end gives 0.
7. In the same commit: `docs/cli.md`, the notes
   (`crates/podssh-cli/src/man/notes.rs:26-59`), two examples
   (`crates/podssh-cli/src/man/examples.rs:8-228`; its test at
   `crates/podssh-cli/src/man/examples.rs:351-374` learns the new variant),
   `docs/design.md:905-914`, `docs/STATUS.md`. Each file stays under 500
   lines (`AGENTS.md:269-270`).

## Decision

Recommendation: `exec:` splits the words itself and starts no shell, because
podssh must not assume a shell (`AGENTS.md:250-251`), and the user can name one
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

## Done

2026-10-10. Measured first: `pipe` was an unknown subcommand (64). Now
`podssh pipe A B` joins two byte streams with the local addresses: `-` and
`stdio`, `fd:N` (Unix, 3 or more, checked with `fcntl`) and `exec:CMD`
(words split with quotes and no shell; a socketpair, else two pipes, and
pipes on Windows). The grammar is in
`crates/podssh-cli/src/pipe/address.rs`, the pump in
`crates/podssh-cli/src/pipe/pump.rs`, the ends in
`crates/podssh-cli/src/pipe/local.rs`. Both addresses are checked before
anything starts, and the kinds of later entries (`relay:`, `ssh:`, `node:`,
`iroh:`, `unix-connect:`, `unix-listen:`, `tcp-listen:`, `serial:`) exit
70. The end of one side's input half-closes the other side, and the reply
still comes back; a writer whose reader is gone ends the pipe, and so does
a child that exited after its output ended. The exit status is the child's,
B's of two, 128 + N for a signal, 127 and 126 as a shell gives them. The
pump of `podssh proxy` stays until T-175 moves it onto this one.
- Native, Windows: `cargo test -p podssh-cli pipe::`, 7 passed (the
  grammar, quoting, two stdio, the pump's half-close and a reader that is
  gone); `--test pipe`, 4 passed, with podssh itself as the child (the
  manual through `exec:` and 0, `man nonsense` and 64, B's status of two
  children, 127, each address checked first, a descriptor that is not open
  and 64); `--test flag_table`. Planted, a status that is always 0 fails
  the check of 64. `cargo test --workspace`: 1083 passed, 0 failed, 37
  ignored.
- Linux, in the build image (`sh scripts/dev.sh run`): clippy with no
  warning, and 10 unit tests, with the socketpair, its fallback to pipes on
  an injected EPERM, 127 and a closed descriptor. A first run found that
  the feature `fs` of tokio was missing for `fd:N`.
- `scripts/interop-pipe.sh` in the gate's step `release`: 5,000,000 bytes
  through `exec:cat`, `fd:3` from a file, 7 from `exec:sh -c 'exit 7'`, and
  143 from a signal; its result at the push goes into `docs/STATUS.md`.
- CI, the run of `0522c84` (38005063675): the step `release`, interop 207
  passed, 0 failed, with the four cases of the pipe; each job passed.

# T-175: `podssh pipe` with remote addresses

**Source:** ROADMAP M7 (`docs/ROADMAP.md:233-237`), `docs/design.md:910-914`;
GitHub #26 (Nemo-010, 2026-10-08); the RustConn report in GitHub #24 (one
address model across roads; read in the report, not verified here).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

After T-174, `podssh pipe` joins local ends only. The remote addresses of the
design are `relay:HOST:PORT`, `ssh:[USER@]BASTION,HOST:PORT`,
`node:NAME[,PORT]` and `iroh:TICKET`. Without them, a script cannot join a
local program to a target, and `podssh proxy` stays a second pump.

## Premise

- Read: `podssh proxy` is the `relay:` address today. It opens the session
  with `crates/podssh-relay/src/open.rs:200-277` and pumps it
  (`crates/podssh-cli/src/proxy.rs:47-142`).
- Read: `crates/podssh-ssh/src/relay_stream.rs:198-201` sends Close 1000 when
  its write side ends. That is right for SSH and wrong for a pipe: the relay
  has no half-close (`docs/relay.md:129-135`), so a Close cuts a reply on its
  way. Measured live for proxy: the full reply after stdin closed
  (`docs/STATUS.md:210`).
- Read: `-W` opens its stream with `crates/podssh-ssh/src/forward.rs:14-22`
  after the hops of `crates/podssh-ssh/src/run.rs:156-169`, but that code is
  private and gives only an exit code.
- Read: `TODO/issues.md` (#26) says that a binary protocol through `-W` is
  measured. Only exec is measured with digests (`docs/STATUS.md:90`); `-W`
  was checked with a banner of 16 bytes (`scripts/interop.sh:355-357`).
- Read: `node:` needs T-084 (M4) and `iroh:` needs T-163 (M6); both are done
  before M7 starts.

## Approach

1. One adapter per kind, in crates/podssh-cli/src/pipe/remote.rs: it opens
   its road and gives a duplex stream and, at the end, a close reason. The
   pump does not know the road (`docs/architecture.md:144-146`).
2. `relay:HOST:PORT`: parse as `crates/podssh-cli/src/proxy.rs:207-217` does;
   open with `crates/podssh-relay/src/open.rs:200-277`. Keep the rules of
   proxy: no Close at the end of input, the ping watcher
   (`crates/podssh-cli/src/pipe/relay.rs:129-131`), empty frames dropped. IPv6
   literals follow T-007.
3. Move `podssh proxy` onto the pipe: `run_proxy`
   (`crates/podssh-cli/src/proxy.rs:47-142`) runs `stdio` and `relay:`. Keep
   its exit codes and messages (`crates/podssh-cli/src/proxy.rs:278-291`,
   `crates/podssh-cli/src/pipe/relay.rs:200-230`).
4. `ssh:[USER@]HOP[,HOP...],HOST:PORT`: the last item is the target, each
   other item a hop, read as `-J` reads it
   (`crates/podssh-cli/src/ssh/resolve.rs:232-236`,
   `crates/podssh-cli/src/ssh/hop.rs:30-78`). Make
   `crates/podssh-ssh/src/run.rs:156-169` a public `connect_chain` that `-W`
   and the pipe both use; keep each handle alive until the pipe ends. The
   options: `-i`, `-o NAME=VALUE` through
   `crates/podssh-cli/src/ssh/options.rs:87-255` (a keyword of a session,
   such as `RequestTTY` or `RemoteCommand`, exits 64), `--direct`,
   `--relay-host`, `--relay-addr` and `--ca-file`.
5. `node:NAME` after T-084, and `iroh:TICKET` after T-163: one adapter and
   one test each. If T-163 makes a ticket a credential, read it from a file
   (`iroh:@FILE`), never from argv.
6. Exit codes: sysexits, as `podssh proxy` (`docs/cli.md:2712`): 69; 77 for a
   refusal (the relay, the proxy, a host key, the authentication); 78. Give
   `crates/podssh-ssh/src/run.rs:332-412` a typed error, so that 77 is not
   guessed from a message.
7. In the same commit: `docs/cli.md`, `docs/design.md:905-914`, the notes,
   the examples, `docs/STATUS.md`.

## Decision

Recommendation: add `tcp:HOST:PORT`, the direct road through `HTTPS_PROXY`
with `crates/podssh-ws/src/dial.rs`, lines 199-242 at `927eb24`, because `ssh --direct` uses the
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
Close at the end of input, as `crates/podssh-ssh/src/relay_stream.rs:198-201`
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
`podssh_ssh::run::connect_hops` (`crates/podssh-ssh/src/run.rs:151-171`): it
returns each handle, authenticated, for `ssh` and for SFTP. So the Premise's
"that code is private" no longer holds, and the step that makes it a public
`connect_chain` is done under that name.

2026-10-09 (T-134): step 6 is done for the hops: `connect` and
`connect_hops` return `podssh_ssh::run::HopError` (unreachable, the host key,
or the login refused, from `podssh_ssh::auth::AuthError`), so 77 is not
guessed from a message; `podssh cp` maps it so.

## Done

2026-10-10. `podssh pipe` has the remote addresses, each an end of the one
pump: `relay:HOST:PORT` (`crates/podssh-cli/src/pipe/relay.rs`: no Close at
the end of input, the ping watcher, the empty frames dropped, and the end
of the session ends the pipe); `tcp:HOST:PORT`, the direct road of the
Decision (`crates/podssh-cli/src/pipe/remote.rs`);
`ssh:[USER@]HOP[,HOP...],HOST:PORT` (`crates/podssh-cli/src/pipe/ssh.rs`:
the hops as `-J` reads them, `connect_hops`, then `forward::open` from the
last; an `-o` of a session exits 64, a host key or a login refused 77);
`node:NAME` (`crates/podssh-cli/src/pipe/node.rs`: the operator's leg and
the layer, judged as `podssh operator` judges); and `iroh:TICKET`
(`crates/podssh-cli/src/pipe/iroh.rs`, with the dial that `podssh ssh iroh:`
sets up, now shared). `podssh proxy` runs the pipe of `stdio` and `relay:`,
with its words and codes. An end of the pump has a last word (a road that
ended ends the pipe) and an ending (what is still open is closed, and a road
that failed gives the code: 69, 77 or 78). The flags of `pipe` take the ids
of `ssh`'s: `-i`, `-o`, `-v`, `-q`, the relay's, `--direct`, `--pair-file`,
`--iroh-key` and `--iroh-relay`.
- Native, Windows: `--test pipe_remote`, 5 passed (a reply after the end of
  input through `relay:` and through `podssh proxy`; `tcp:` and `ssh:` pass
  the end of input on, `ssh:` with `--direct` to the tests' SSH server,
  which now opens direct-tcpip channels; `node:` over the stand-in relay's
  reverse road; `PODSSH_OFFLINE` gives 69); `--features iroh-test --test
  pipe_iroh` (a line there and back over the iroh road); `--test proxy`
  unchanged; the unit tests of the grammar and of the keywords of a session.
  Planted, a Close at the end of input fails the late-reply check.
  `cargo test --workspace`: 1091 passed, 0 failed, 37
  ignored; with `iroh-test`, 394 passed.
- Linux, in the build image (`sh scripts/dev.sh run`): clippy with no
  warning, and the tests of the pipe and of proxy.
- `scripts/interop-pipe.sh` in the gate's step `release`: the late reply
  through the stand-in relay with `relay:` and with `proxy`, and 5,000,000
  bytes through OpenSSH with `ssh:` to a digest server. Each passed in CI at
  b20de13 (2026-10-10; `docs/STATUS.md`).

# T-176: `podssh pipe` with `unix-connect:PATH`

**Source:** ROADMAP M7 (`docs/ROADMAP.md:233-237`); GitHub #26 ("a name for
AF_UNIX streams"), from the USBoverSSH report in GitHub #25
(`ImKKingshuk/USBoverSSH:usboverssh/src/tunnel.rs`; read in the report, not
verified here).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

Many local services listen on a Unix socket: a database, a container
runtime, an agent. podssh cannot join one to another stream. A connect is
not a listener, so `docs/target-environment.md:84-88` allows it.

## Premise

- Measured: `podssh proxy unix-connect:/tmp/x.sock 1` exits 64
  (`':' is not allowed`): no command takes a socket path.
- Read: podssh connects to a Unix socket only for the agent
  (`crates/podssh-ssh/src/keys.rs:392-405`, `connect_agent`); on Windows the agent is a
  named pipe (`crates/podssh-ssh/src/keys.rs:406-427`).
- Read: `sun_path` holds 104 to 108 bytes, and doctor refuses a longer name
  before the call (`crates/podssh-cli/src/doctor/unix.rs:204-213`,
  `crates/podssh-cli/src/doctor/unix.rs:227-232`).
- Read: sandbox A allows an AF_UNIX bind (`docs/STATUS.md:282`); a connect
  was not measured. The attempt is the probe, and its errno is the message.

## Approach

1. `unix-connect:PATH` in the grammar of T-174; on Linux also
   `unix-connect:@NAME` for the abstract namespace, which doctor also probes
   (`crates/podssh-cli/src/doctor/unix.rs` lines 178-185 at `48a8744`).
2. Check the length before the call (exit 64). Connect with the `UnixStream`
   of tokio. ENOENT and ECONNREFUSED exit 69, EACCES 77; each message names
   the path and the errno.
3. At the end of input, shut down the write side, so that a server that
   answers after the end of input still answers.
4. On Windows: AF_UNIX (Windows 10 1803 and later) and named pipes, each
   after a probe at run time; where one fails, exit 69 with the reason
   (the operator's ruling of 2026-10-08).
5. T-040 gives the remote form: a socket on the server, through `-W`.
6. In the same commit: `docs/cli.md`, `docs/design.md:909`, the notes,
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

## Correction

2026-10-10: the Prove's "On Windows, the address exits 64" was written
before the operator's ruling of 2026-10-08 (Q24, `docs/decisions.md:38`),
which step 4 of the Approach follows: on Windows, `unix-connect:` reaches
an AF_UNIX socket or a named pipe (`\\.\pipe\NAME`), each tried when the
pipe starts. So the Prove on Windows is the one of Unix, through an AF_UNIX
socket, and a named pipe's greeting comes through too. A named pipe has no
half-close: its server's bytes come until it closes.

## Done

2026-10-10. `unix-connect:PATH` is an address of `podssh pipe`
(`crates/podssh-cli/src/pipe/unix.rs`). A name that does not fit a socket's
address (107 bytes on Linux and Windows, 103 elsewhere) exits 64 before the
call; `@NAME` is Linux's abstract namespace, and exits 64 elsewhere. The
connect's error names the path: 69 for a missing socket or one that nobody
serves, 77 for one that this user may not use. At the end of input, the
write side is shut down. On Windows, a `\\.\pipe\` path is a named pipe
(a pipe whose instances are busy is asked again for 5 s), and another path
an AF_UNIX socket by WinSock (`windows-sys`, which tokio already builds),
whose shutdown is the half-close. With T-174 and T-175, the first item of
ROADMAP M7 is done; T-040 gives the remote form.
- Native, Windows 11: `cargo test -p podssh-cli --test pipe`, 7 passed:
  1,000,000 bytes through an AF_UNIX socket to a server that reads to the
  end of its input gave its digest back; a missing socket exits 69 and
  names its path; a name of 200 bytes exits 64; a named pipe's greeting
  came through. The unit tests of the names and of the codes. Planted, no
  shutdown at the end of input: the digest test failed at its limit ("no
  end within 10 s"). `cargo test --workspace`: 1097 passed, 0 failed,
  37 ignored.
- Linux, in the build image (`sh scripts/dev.sh run`): clippy with no
  warning; the tests of the pipe through a Unix socket, and `@NAME` in the
  abstract namespace.
- CI at `41507c9` (run 38009651835): each workflow passed; the job
  `windows` on `windows-2025` ran the three tests of Windows, AF_UNIX and
  the named pipe among them.

# T-177: `podssh pipe` with a local listener after a probe

**Source:** ROADMAP M7 (`docs/ROADMAP.md:236-237`), `docs/design.md:948-954`;
GitHub #26 (a local-only mode, as the `--local` of bunflared; read in the
report, not verified here); sandbox A of T-001.
**Category:** feature
**Milestone:** M7
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Desktop clients, browsers and database clients call `connect()` themselves:
they need a local port or socket (`docs/design.md:951-954`). podssh refuses
each listener. The design allows one for `pipe`, locally, after a probe
shows that an AF_UNIX or loopback bind works (`docs/design.md:948-950`).

## Premise

- Read: the operator ruled on 2026-10-08 (`docs/decisions.md`): a local
  listener is allowed when the user asks for it and a probe at run time
  allows the bind. The default is loopback and AF_UNIX; the user can
  configure the address and can turn listening off.
- Read: five documents still say that podssh never listens:
  `AGENTS.md:252-258`, `docs/architecture.md:147-162`,
  `docs/target-environment.md:84-88`, `SECURITY.md:129-156`, `README.md:42-51`.
- Read: sandbox A refuses an AF_INET bind and allows an AF_UNIX bind
  (`docs/STATUS.md:282`). The box refuses each `bind`, AF_UNIX too
  (`scripts/box/seccomp.json:5-10`), so it gives the refused case.
- Read: doctor binds, closes, and never listens
  (`crates/podssh-cli/src/doctor/unix.rs` lines 137-231 at `48a8744`). A bind that works does
  not prove that `listen()` works.

## Approach

1. Addresses `unix-listen:PATH` (on Linux also `@NAME`), and
   `tcp-listen:PORT`, which listens on 127.0.0.1. `tcp-listen:ADDR:PORT`
   listens on the address that the user gives (`[::1]`, or another); an
   address that is not loopback prints one line: other hosts can connect.
2. podssh listens only for a `-listen:` address that the user gives.
   `PODSSH_LISTEN=no` turns listening off: each such address then exits 78
   before any bind. Add the variable to `VARIABLES`
   (`crates/podssh-cli/src/man/facts.rs:45-260`); the settings file of T-048
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
7. Move the bind code of `crates/podssh-cli/src/doctor/unix.rs` lines 200-231 at `48a8744` to a
   module that doctor and pipe share; doctor stays bind-and-close. In the
   same commit, change each sentence that says podssh never listens: the
   five documents, `crates/podssh-cli/src/help.rs`, lines 213-214 at `a9299c4`,
   `crates/podssh-cli/src/man/notes.rs`, lines 70-72 at `a9299c4`, the reasons of the `-L` and
   `-D` rows (`crates/podssh-cli/src/flags.rs`, lines 215-220 at `97146aa`; keep `-W HOST:PORT`
   as what to use, which `crates/podssh-cli/tests/flag_table.rs:82-101`
   asserts), `crates/podssh-cli/src/ssh/keywords.rs`, lines 91-92 at `97146aa`,
   `crates/podssh-cli/src/ssh/options.rs`, lines 185-189 at `97146aa`,
   `crates/podssh-cli/src/doctor/unix.rs` line 164 at `48a8744` and
   `crates/podssh-cli/src/doctor/unix.rs` line 186 at `48a8744`.
8. `unix-listen:` with `exec:` is the local-only mode that GitHub #26 asks
   for: nothing leaves the host. T-038, T-039 and T-186 use this code.

## Decision

Recommendation: one connection by default, because a listener that stays
after its first use is a service that the user can forget. The alternative,
a listener that stays until Ctrl-C (the `fork` of socat), lost as the
default; it is the flag `--keep-listening`.

2026-10-10: one side may listen, and two listeners exit 64: their clients
would come in no order that joins them. On Windows `unix-listen:` makes an
AF_UNIX socket, or a named pipe for `\\.\pipe\NAME`, and the peer check
is the user of the client's process token (`SIO_AF_UNIX_GETPEERPID`,
`GetNamedPipeClientProcessId`); a client whose user cannot be read is
closed. The alternative, no `unix-listen:` on Windows, lost: the operator
ruled for both kinds of socket there (Q24). A named pipe has no
half-close, so its listening side closes it at the end of its input, and
the client reads the rest; `unix-connect:` reads until the server closes
(T-176), so podssh at both ends of a pipe ends. The listener's lines
(where it listens, a client that connected or was closed) follow `-q`; a
failure's line is always written, as the pipe's other failures are. A
signal ends `--keep-listening` with 128 and its number, as it ends the
mode of one client.

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

## Correction

2026-10-10: three of the five documents already say what the ruling
allows: `AGENTS.md:252-258`, `docs/architecture.md:147-162` and
`docs/target-environment.md:84-88` name a listener that the user asks for,
after a probe. `SECURITY.md` and `README.md` still said that nothing
listens, and change here. Step 4's umask 077 makes a socket's file mode
0700 on Linux, as a socket is made 0777 less the umask; umask 0177, as
ssh-agent makes its socket, gives the 0600 that step 4 asks for. Step 7:
the listener binds with the standard library's `UnixListener::bind` and
`bind_addr`, which build the address, so doctor keeps its own probe, and
only the code of Windows builds a `SOCKADDR_UN`, in one function that
`unix-connect:` and `unix-listen:` share
(`crates/podssh-cli/src/pipe/unix.rs`).

## Done

2026-10-10. `podssh pipe` listens on `unix-listen:PATH` and
`tcp-listen:[ADDR:]PORT` (`crates/podssh-cli/src/pipe/listen.rs`,
`crates/podssh-cli/src/pipe/listen_win.rs` on Windows,
`crates/podssh-cli/src/pipe/serve.rs`).
- The bind is the probe: 77 for a host that refuses it, with the error and
  the addresses that need no listener; 69 else; `PODSSH_LISTEN=no` gives 78
  before any bind. A socket's file is made mode 0600 and goes when the
  listener drops: at the end, and at SIGINT and SIGTERM, after which podssh
  exits with 128 and the signal's number. A client of another user is
  closed (`peer_cred`, or on Windows the client's token user). A path that
  is not a socket is kept (64), a socket that answers is another's (69),
  and one that nobody serves is replaced. A TCP port says who can connect.
- One client by default; `--keep-listening` takes each in turn, 8 at once,
  each with its own instance of the other side. On Windows one thread
  accepts on an AF_UNIX socket for the listener's life, and a named pipe's
  next instance is made before a client is handed on, so a wait that is
  given up loses no client.
- Where podssh said that it never listens, it now says where it does:
  `SECURITY.md`, `README.md`, the help of `ssh`, the note and the rows of
  `-L` and `-D` (`-W HOST:PORT` stays what to use), the refusals of
  `LocalForward` and `DynamicForward`, and doctor's two lines;
  `PODSSH_LISTEN` is in ENVIRONMENT, and an example joins a local port to a
  service behind an SSH hop.
- Native, Windows 11: `cargo test -p podssh-cli --test pipe_listen`, 6
  passed, and 10 runs in a row: podssh at both ends through a TCP port, an
  AF_UNIX socket and a named pipe, bytes both ways and each end of input;
  `PODSSH_LISTEN=no`; a file kept and a live socket refused;
  `--keep-listening` with two clients, each with its own program. The unit
  tests of the grammar, of the codes and of a token's user. `cargo test
  --workspace`: 1114 passed, 0 failed, 37 ignored.
- Linux, in the build image (`sh scripts/dev.sh run`): clippy with no
  warning; `--test pipe_listen`, 8 passed, with the mode 0600, `@NAME`, a
  stale socket replaced, and SIGTERM giving 143 and removing the file.
  Planted, the bind with no umask: the check of the mode failed (0755).
- The gate (`scripts/interop-pipe.sh`): `tcp-listen:` with `exec:cat` and
  equal digests, and a client of another user (`su podtest`) closed at
  `@NAME` while this user's is served. At `a220c13` (run 38016375327) both
  failed before they began: they ran after the pipe section had removed its
  directory. The removal is the section's last step since T-271's commit,
  and at that push, `9460b4e` (run 38019504447), both passed. The box's step
  (`scripts/sandbox-check.sh`, `unix-listen exit=77`) runs with the checks of
  the release (T-251).

# T-178: `--persist`: connect again and attach `tmux` again

**Source:** ROADMAP M7 (`docs/ROADMAP.md:238-240`), `docs/design.md:611-628`;
GitHub #19 (a lasting terminal through `tmux`, from the slingshot report:
`ado11231/slingshot:crates/slingshot-agent/src/jobs.rs`; read in the
report, not verified here).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

When the relay drops a session, `podssh ssh` exits 255 and the remote shell
is gone (`docs/design.md:578`). Against a standard sshd only one end runs
podssh, so the layer of M6 cannot help (`docs/design.md:611-613`). The
cheapest repair: connect again, and attach a `tmux` session that kept
running on the server (`docs/design.md:614-618`).

## Premise

- Measured: `podssh ssh --persist host` exits 64 (`unknown flag '--persist'`).
- Read: a lost link is `End::Lost` (`crates/podssh-ssh/src/io.rs:42-43`),
  an error at `crates/podssh-ssh/src/session.rs:42`. An exit status, a
  close with no status, and `~.` are other ends
  (`crates/podssh-ssh/src/session.rs:39-41`). Raw mode is entered once for
  each session (`crates/podssh-ssh/src/session.rs:149-208`).
- Read: the relay ends a session at 64 MiB (1009) or 12 h (1001)
  (`docs/relay.md:249-255`). Sandbox A measured the cap at 67,107,943 bytes,
  and one close `1011` in 180 short sessions (`docs/STATUS.md:290-291`).
- Read: tmux is never assumed (`docs/target-environment.md:101-103`).

## Approach

1. Flags `--persist` and `--persist-name NAME` (default `podssh`; letters,
   digits, `_` and `-`, 32 at most) in `crates/podssh-cli/src/flags.rs:112-282`.
   With a command, `-W`, `-N`, `-s` or `RemoteCommand`, exit 64.
2. The probe, after the login: one exec runs `command -v tmux`. No tmux:
   exit 255 with "the server has no tmux on PATH; --persist needs it". T-193
   uses the same function.
3. The session runs `tmux new-session -A -s NAME` with a pty, as `-tt` does.
   `-A` attaches when the session exists; that makes a second run safe.
4. A loop around `crates/podssh-cli/src/ssh/mod.rs`, lines 99-126 at `97146aa`. Connect again
   only for a lost link: `End::Lost`, the ping watcher, or the relay's 1001,
   1006, 1009 or 1011. Never after an exit status, `~.`, a detach of tmux
   (exit 0), or a failure of the host key or the authentication.
5. Between attempts: leave raw mode, print one line for each attempt, and
   wait with `crates/podssh-relay/src/open.rs:387-393` (jittered, 30 s at
   most); 10 attempts or 5 minutes at most. Ctrl-C stops the wait with 255.
   Keys typed meanwhile wait in a queue of 64 KiB, and go after the attach.
6. Each attempt checks the host key with the same policy, and uses the
   cached token. A prompt with no terminal ends the loop
   (`docs/cli.md:2783-2785`). After the attach, send the window size again.
7. In the same commit: `docs/cli.md`, the notes of ssh
   (`crates/podssh-cli/src/man/notes_ssh.rs:4-332`), `docs/design.md:614-618`,
   `docs/STATUS.md`, and tmux in the interop image
   (`scripts/interop.sh:24-25`). T-025 shares the classes of close codes;
   T-153 replaces this loop when both ends run podssh.

## Decision

Recommendation: refuse `--persist` when the probe finds no tmux, because a
new shell after a drop looks like the old one and has lost its state: a
silent change of behaviour (`docs/target-environment.md:101-103`). The
alternative, a new shell with a warning, lost for that reason.

2026-10-10, for the same reason: after a loss, `tmux has-session -t =NAME`
runs before the attach; a session that is gone ends the run with 255, and
no new one starts. The alternative, `new-session -A` alone, would start a
new shell after a server that restarted.

2026-10-10: the connections after the first attach log in with no prompt
(`BatchMode`), as the input belongs to the session, and a prompt that read
the terminal would race the task that reads it. A key that a passphrase
opened and a password that the server took are kept for the run (T-136),
so they log in again. The alternative, a prompt after each loss, lost: its
answer could go to the session.

2026-10-10: `--persist` with `node://` or `iroh:` exits 64: the resumable
layer keeps those sessions (T-153). With `-T` or `RequestTTY=no` it exits
64 too, as tmux needs a pseudo-terminal. The first connection's failure is
final, as without `--persist`: the loop starts at the first attach.
Ctrl-C outside raw mode, also during the wait, ends the run with 255.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- persist   # each refusal exits 64, and nothing connects
sh scripts/dev.sh check                               # interop-faults.sh: the drop below
```

In `scripts/interop-faults.sh`, `--persist -tt` goes through two stand-in
relays. The input sets `MARK=kept`; the harness kills the first stand-in, as
`scripts/interop-faults.sh:273-283` does; the input then runs `echo M=$MARK`
and `tmux kill-session`. The output has `M=kept`, and the exit is 0. With
tmux moved off `PATH`, the exit is 255 and names tmux. Plant: start tmux
without `-A`; the second attach fails, and the check must fail.

## Done

2026-10-10. `podssh ssh --persist` runs the shell in tmux on the server,
and after a lost link connects again and attaches the same session
(`crates/podssh-cli/src/ssh/persist.rs`: the checks and the loop;
`crates/podssh-ssh/src/persist.rs`: one connection).
- The flags `--persist` and `--persist-name NAME` (`podssh` by default;
  letters, digits, `_` and `-`, 32 at most). With a command, `-W`, `-N`,
  `-s`, `RemoteCommand`, `SessionType`, `-T`, `RequestTTY=no`, `node://` or
  `iroh:`, and `--persist-name` alone, exit 64 before anything connects.
- After the first login, `command -v tmux`; with no tmux, exit 255 and
  "the server has no tmux on PATH; --persist needs it". The session is
  `tmux new-session -A -s NAME` with a pty, as `-tt` asks; each attach asks
  for the pty with the window's size of that moment.
- A lost link is a session that ended with no status, with no relay
  (`--direct`), a relay link that failed (the ping watcher), or the
  relay's 1001, 1006, 1009 or 1011. An exit status, a detach (0), `~.`, a
  refused host key or login, and the server's close (1000) end the run.
- Between attempts: raw mode is left, one line for each attempt, the wait
  of `podssh_relay::open::backoff` (jittered, 30 s at most), 10 attempts
  within 5 minutes of the loss; Ctrl-C stops the wait with 255. The input
  is one for the run (`podssh_ssh::io::Input`), so keys typed meanwhile go
  after the attach, 64 KiB at most. After a loss, `tmux has-session -t
  =NAME` runs first: a session that is gone ends the run with 255. The
  logins after the first run in batch mode, with the login of the run kept
  (T-136).
- Native, Windows 11: `cargo test -p podssh-cli --test ssh_args --
  persist`: each refusal exits 64. `--test persist`, 4 passed, `--direct`
  to a stand-in for tmux on a russh server in the test process
  (`tests/tmux_harness`): a link dropped under the session connects again
  and attaches the same session, whose variable is still set (two
  connections, two attaches, exit 0); a session that ends with a status
  connects no more; no tmux gives 255 and names it; a session gone after
  the loss gives 255, and none starts. Planted, a `link_lost` that never
  holds fails the test of the attach. The classes of a lost link have a
  unit test. `cargo test --workspace`: 1105 passed, 0 failed, 37
  ignored.
- Linux, in the build image (`sh scripts/dev.sh run`): clippy with no
  warning; the same tests.
- `scripts/interop-faults.sh` in the gate's step `release`, with tmux in
  the image: `--persist` through two stand-in relays to OpenSSH, the first
  killed under the session; then tmux off `PATH`. Both passed in CI at
  `9ae8d4a` (run 38013370692: interop 212 passed, 0 failed, 2 more than
  before); the plant (tmux without `-A`) waits for T-251.

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
**Status:** done

## Problem

Users ask how to carry RDP, VNC and Telnet. The documents show SSH and one
HTTP request (`README.md:181-186`). They do not say which clients work with
no listener, or that the relay ends a desktop stream after 64 MiB.

## Premise

- Read: a byte pipe carries each TCP protocol
  (`crates/podssh-cli/src/man/notes.rs:159-163`); a client that calls
  `connect()` itself needs a listener (`docs/design.md:951-954`), which
  T-177 adds where a probe allows it.
- Read: 64 MiB for each session, both directions together
  (`docs/relay.md:192`), then Close 1009 (`docs/relay.md:253`); public
  targets only (`docs/relay.md:194`). Through the proxy of sandbox A: 0.5 to
  0.7 MB/s (`docs/STATUS.md:289`).
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
4. Write a table "Other TCP protocols" after `README.md:181-186`: the
   protocol, what works now, what needs a listener, the 64 MiB limit. Add
   form a to `crates/podssh-cli/src/man/examples.rs:8-228`; its ProxyCommand
   parses (`crates/podssh-cli/src/man/examples.rs:328-335`). Link the table
   from `docs/design.md:951-954`.
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

## Correction

2026-10-12: the Prove's plant no longer fails. T-038 made `-L` a flag of
`podssh ssh` (`crates/podssh-cli/src/flags.rs:240` says "forward-local"),
so an example with `podssh ssh -L 5901:127.0.0.1:5901 user@host` parses. The
plant that the test of the examples must refuse gives `-L` to the
ProxyCommand's `podssh proxy`, which has no such flag:
`ssh -o ProxyCommand='podssh proxy -L 5901:127.0.0.1:5901 %h %p' user@host`.

2026-10-12: step 1c named no client that can run with no listener. Two
were found by their manuals (read on 2026-10-12, not run here): SSVNC's
`ssvncviewer exec=COMMAND` runs COMMAND and speaks RFB on its stdio, and
TigerVNC's `vncviewer` takes a Unix socket's path (its synopsis,
`vncviewer [options] [unix socket]`). The second still needs a listener,
but an AF_UNIX one, which sandbox A allows where it refuses AF_INET
(`docs/STATUS.md:279`); there OpenSSH's form a fails before it binds, as
`ssh` finds no entry for the user (`docs/STATUS.md:284`).

## Done

2026-10-12. What was made:
- `README.md`, a section `### Other TCP protocols` after "Relay limits": a
  table of VNC, RDP and Telnet (what works with no listener, with a local
  listener, and the limits: 64 MiB through the relay, which is 21 full
  screens of 1024x768 at 32 bits with no compression; plain text, so
  `ssh:` and never `relay:`), then the commands of each form, and that a
  listener takes one client unless `--keep-listening`.
- The manual's example of form a, in
  `crates/podssh-cli/src/man/examples.rs`: OpenSSH's `ssh` with
  `-N -L 5901:127.0.0.1:5901` and `podssh proxy %h %p` as its
  ProxyCommand. `docs/design.md:910` links the table.
- `scripts/interop-desktop.sh`, sourced by `scripts/interop.sh` after
  `scripts/interop-pipe.sh`, with 7 checks (the harness `desktop`, floor 7,
  in `scripts/interop-baseline.txt`): TigerVNC's `Xvnc` and BusyBox's
  `telnetd` behind OpenSSH on 127.0.0.1; form a through the stand-in relay
  (`desktop.vnc.proxy_command`); form b on a TCP port
  (`desktop.vnc.pipe_tcp_listen`); form c, a client that runs
  `podssh pipe stdio ssh:` through the stand-in relay, to the server's
  ServerInit (`desktop.vnc.command`); TigerVNC's viewer at a
  `unix-listen:` socket (`desktop.vnc.viewer_unix_listen`); the bytes of an
  idle and of a busy desktop (`desktop.vnc.rate`); Telnet's first byte
  through a raw pipe (`desktop.telnet.options`) and BusyBox's `telnet`
  through form b (`desktop.telnet.client`). The packages `tigervnc`,
  `tigervnc-client`, `busybox-extras` and `xsetroot` join the image's
  `apk add` (`scripts/interop.sh:25`); each is in Alpine v3.22 and edge
  (pkgs.alpinelinux.org, read on 2026-10-12).
- `docs/STATUS.md`, a section "Other TCP protocols, measured", whose
  rows say that the gate's first run fills them in.

The calls made where the Approach left a choice:
- The table follows "Relay limits", not `README.md:180-185` at once: the
  paragraphs after those lines (chat, the variables, the tokens) would fall
  under its heading, and the table cites the limits above it.
- Form c's client is the harness's own (`rfb.py`, about 40 lines of
  Python), as Alpine packages no viewer that runs a command: it does what
  `ssvncviewer exec=` does, with podssh as the command.
- The viewer in the gate is TigerVNC's, at a `unix-listen:` socket, as
  that is the form for a host like sandbox A.
- The rate is TigerVNC's viewer's, on the loopback, counted by a relay of
  the harness on the server's side (`podssh pipe` prints no byte count),
  after the first 5 s of each run of 20 s, and scaled to a minute: idle,
  then a screen of new noise 4 times a second (two random bitmaps of
  1024x768, set in turn as the root window's pattern with `xsetroot`).
  Noise does not compress, so the busy rate is near the most that a screen
  of that size changes; a viewer that measures a slow road may pick a
  lossy encoding and send less. A run of 20 s keeps the gate short.
- The example puts `-N -L` before the ProxyCommand: the start of the
  manual keeps three first steps, and its filter takes each command that
  starts with "ssh -o ProxyCommand='podssh proxy"
  (`crates/podssh-cli/src/man/examples.rs:231`). It has no
  `ServerAliveInterval`, so that its line stays within rustfmt's 120
  columns; the note of proxy asks for it
  (`crates/podssh-cli/src/man/notes.rs:164`).
- Form b runs with `--direct`, as `scripts/interop-pipe.sh` runs `ssh:`;
  forms a and c go through the stand-in relay.
- The citations of `crates/podssh-cli/src/man/examples.rs` in
  `TODO/cli.md`, `TODO/pipe.md` and `TODO/reverse.md` were moved by hand,
  4 lines, as `cargo todo remap` would move them.

The gate's first run (CI, 3224a88, the step `release`): 6 of the 7 checks
of `scripts/interop-desktop.sh` passed, and `docs/STATUS.md` has their
lines. `desktop.vnc.rate` failed: in each of its two runs the meter counted
56 bytes down (the version, the security types, the result and the
ServerInit) and 14 up, and the connection ended within 0.2 s. In the build
image, with no podssh, TigerVNC's viewer 1.16.2 quit the same way, after
"Unable to find fonts"; with `font-dejavu` it stayed until its timeout.
`font-dejavu` joins the image's `apk add`. With it, the run of cad2885
(CI, the step `release`, 478 passed and none failed) passed each of the 7:
`desktop.vnc.rate` gave an idle desktop 0 bytes a minute and a busy one
23,060,488, so 64 MiB lasts 2.9 minutes busy; `docs/STATUS.md` has them.

What ran:
- Native here: `cargo test -p podssh-cli --lib man::examples` with the new
  example, 4 passed; the plant of the Correction (`-L` given to the
  ProxyCommand's `podssh proxy`) fails the test of the examples with
  "unknown flag '-L'", and was taken out; the whole lib suite, 278 passed.
  The Prove's `grep` finds the heading, `README.md:219`;
  `python scripts/check-repo.py`: each check ok, the doc links too;
  `python scripts/check-scripts.py`: 44 scripts LF and parse under dash.
- An RDP client and server, and each client through the live relay, did
  not run: the table says "not measured" for RDP.
- 2026-10-30, later: `desktop.vnc.rate` failed once in CI's step `release`
  at `711f18f` (run 41075369339) and passed at the commits around it: the
  meter held one line, the idle view's (400 bytes, 15.2 s), and none of the
  busy view's. The meter writes a connection's line when the connection
  ends, up to 5 s after the viewer's, and the harness read the log at once.
  It now waits for each line, 15 s at most. Under dash, against a stand-in
  meter that writes late: the wait ended with each line, and gave up after
  15 s with none; `dash -n` and shellcheck as before. CI's next runs of the
  step show it.

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
(`docs/relay.md:307-349`). It has no endpoint that takes public HTTPS for a
name, and podssh alone cannot add one.

## Premise

- Read: the relay is the operator's Cloudflare Worker, another project, and
  its document is the contract (`docs/relay.md:3-16`). It has no publish
  endpoint (`docs/relay.md:113-150`, `docs/relay.md:307-371`).
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
   (`open {id}`, `ready {id}`; `docs/relay.md:315-335`).
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
**Status:** done

## Problem

A user wants to script a serial console (a board on `/dev/ttyUSB0`), or to
reach it from another host. With T-174, only `fd:N` of a device that another
program opened and set up is possible. podssh sets no speed and no raw mode
on a serial line.

## Premise

- Read: the binary already sets termios through `libc` for the local
  terminal: save, `cfmakeraw`, restore on drop and in a panic hook
  (`crates/podssh-ssh/src/terminal/unix.rs:35-81`).
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
   `crates/podssh-ssh/src/terminal/unix.rs:68-81` does.
4. Windows (`serial:COM3[,BAUD]` with `SetCommState`) is a second step;
   until then it exits 64 with the reason.
5. In the same commit: `docs/cli.md`, the notes, one example
   (`podssh pipe serial:/dev/ttyUSB0,115200 stdio`), `docs/STATUS.md`.

## Decision

2026-10-12: an open that this user may not make (EACCES, EPERM) exits 77,
as `unix-connect:` gives for a socket of another user (T-176), and the line
gives the device's mode, uid and gid, so that the user sees which group
opens it; each other failure exits 69, as step 2 says. 69 for a refusal
lost: a script could not tell a missing device from one that needs a group.

2026-10-12: with a serial line on a side, `podssh pipe` catches SIGINT and
SIGTERM, which would kill it with the line still raw: the ends drop, the
settings go back, and podssh exits 130 or 143, as a listener does (T-177).
A line has no end of its own, so a signal is how a session at a terminal
ends, and the end of the other side's input leaves the line open. The
line's output is its last word: a read or a write that fails (an adapter
pulled out) ends the pipe with 69 and the error, rather than a wait for
the other side's input.

2026-10-12: BAUD is the text after the last comma, so a PATH with a comma
takes a BAUD after it. The table is the speeds that Linux names, from 1200
to 4000000; another Unix gives the number to `cfsetspeed`, and a device
that refuses it gives 69 at `tcsetattr`. The settings go back with
`TCSADRAIN`, so that the bytes written go out at the speed they were
written at, and in the panic hook with `TCSANOW`; `TIOCNXCL` follows.

2026-10-12: the Prove's pty pair is made with `posix_openpt`, `grantpt`,
`unlockpt` and `ptsname_r`, which `openpty` calls: they are in the C
library itself, where `openpty` is in libutil on an older glibc, and the
pty harness of the tests (T-158) makes its pty so.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test pipe -- serial
```

On Linux, a pty pair from `openpty` stands in for the device: bytes go both
ways, and `tcgetattr` before and after gives equal settings. `/dev/null`
exits 64. Plant: skip the restore; the comparison of the settings must fail.

## Done

2026-10-12. Written as a draft beside T-168, then merged over it.
`serial:PATH[,BAUD]` is an address of `podssh pipe` on Unix.
- The grammar (`crates/podssh-cli/src/pipe/address.rs`): BAUD from the
  table, 115200 when none is given; a BAUD not in it, an empty PATH, and on
  Windows each `serial:` exit 64 before anything starts. The kinds of later
  entries are gone from the grammar, as `serial:` was the last.
- The line (`crates/podssh-cli/src/pipe/serial.rs`): a character device
  that is a terminal, opened with `O_NOCTTY` and `O_NONBLOCK`, then
  `TIOCEXCL`; the settings saved, then raw at BAUD, 8 data bits, no parity,
  1 stop bit, no flow control, `CLOCAL` and `CREAD`, VMIN 1 and VTIME 0;
  read and written through tokio's `AsyncFd`; the settings and `TIOCNXCL`
  back when the line drops, and in a panic hook set once for the process.
  `crates/podssh-cli/src/pipe/mod.rs`: SIGINT and SIGTERM end a pipe with a
  serial line through the listener's `Interrupt`
  (`crates/podssh-cli/src/pipe/serve.rs`).
- The manual (the notes of `pipe`, an example), `docs/cli.md`,
  `docs/design.md` section 6, `docs/STATUS.md`.
- Tests: `cargo test -p podssh-cli --test pipe -- serial`, on Linux, with a
  pty of the test as the device: the bytes go both ways at 57600 baud, the
  line is raw at the speed asked for, a second open gets EBUSY (for a user
  that is not root), and after SIGTERM (143) the settings equal those
  before; with `exec:` of `podssh --version` on the other side the pipe
  ends by itself, the program's bytes reach the device, and the settings
  equal those before; `/dev/null` and a file exit 64, a missing device 69.
  The table row of `each_address_is_checked_before_anything_starts` now
  gives 64 for a BAUD not in the table (Unix) and for `serial:` on Windows.
  The unit tests of the grammar, of the codes of a refused open, and of
  the table against Linux's speeds, by
  `cargo test -p podssh-cli --lib -- pipe::`. Results: in the build image
  (Alpine, as root), `--test pipe` 10 passed (the 3 of `serial` among them) and the unit tests of `pipe::`
  24 passed; here (Windows 11) `--test pipe` 7 passed and the lib suite 279
  passed, with the Linux tests not built; `cargo clippy -p podssh-cli
  --all-targets -- -D warnings` clean in both. The plant of the Prove, a
  drop that skips the restore: both comparisons of the settings failed in the build image (`serial_settings_come_back_when_the_other_side_ends` and `serial_bytes_go_both_ways_and_the_settings_come_back_at_a_signal`), and the plant was taken out.
- Waiting for the operator's hardware: a real serial device (a board on
  `/dev/ttyUSB0`). The COM port of Windows (`SetCommState`), step 4's
  second step, is not built: `serial:` exits 64 there and says so.

# T-182: USB/IP devices through `podssh pipe`: a tested recipe, with no driver in podssh

**Source:** GitHub #25 (the USBoverSSH report: USB/IP over an SSH channel,
`ImKKingshuk/USBoverSSH:usboverssh/src/protocol.rs`; read in the report, not
verified here); GitHub #26; the operator's ruling of 2026-10-08 that devices
and workloads are streams (`docs/decisions.md`).
**Category:** docs
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A user wants a USB device of one host to appear on another. USB/IP does this
with kernel modules on both hosts and one TCP connection (port 3240). podssh
can carry that connection, but no document says how, with which address,
and with which limits.

## Premise

- Read in the report (not verified here): USBoverSSH carries USB/IP over an
  SSH exec channel, and says that USB/IP needs kernel modules on the server.
- Read: an exec channel carries binary data with equal digests
  (`docs/STATUS.md:90`), and `pipe` carries a TCP stream (T-174, T-175).
- Read: through the relay, a session ends at 64 MiB (`docs/relay.md:192`);
  the traffic of a USB disk reaches that in seconds.
- Read: podssh cannot load a module or attach a device, and never assumes a
  privilege (`AGENTS.md:250-251`). The recipe uses the user's own `usbip` and
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

## Done

2026-10-12. What was made:
- `README.md`, the row "USB/IP (port 3240)" of the table "Other TCP
  protocols" of T-179 (`README.md:237`): the recipe, `usbip` with root
  and the modules (`usbip-host` on the server, `vhci-hcd` on the client)
  and podssh with neither, 64 MiB through the relay and then 1009, and
  `ssh:`, never `relay:` to a public `usbipd`, as USB/IP is not
  encrypted. Below the table, the recipe's commands, and the paragraph
  that says why it needs `--keep-listening` and that the device stays
  while the session lasts.
- `scripts/interop-usbip.sh`, sourced by `scripts/interop.sh` after
  `scripts/interop-desktop.sh` (the harness `usbip`, floor 1, in
  `scripts/interop-baseline.txt`): the recipe as far as the list of the
  server's devices. `podssh pipe tcp-listen:127.0.0.1:3240` reaches a
  stand-in of `usbipd` through OpenSSH with `ssh:`, and the real
  `usbip list -r 127.0.0.1` must list its device 1-1, while the stand-in reads
  the request of version 0x0111 and code `OP_REQ_DEVLIST`
  (`usbip.list_remote`). The package `linux-tools-usbip` joins the
  image's `apk add` (`scripts/interop.sh:25`); it is in Alpine v3.22 and
  edge (pkgs.alpinelinux.org, read on 2026-10-12).
- `docs/STATUS.md`, two rows in "Other TCP protocols, measured", with
  UNVERIFIED where the results go.

The calls made where the Approach left a choice:
- A check in the gate, which the Approach did not name: the list is the
  part of the recipe that needs no module, as `usbip list -r` only dials
  TCP and sends `OP_REQ_DEVLIST`
  (`torvalds/linux:tools/usb/usbip/src/usbip_list.c`, read on
  2026-10-12). The stand-in's reply has the layout of
  `torvalds/linux:tools/usb/usbip/src/usbip_network.h` and
  `torvalds/linux:tools/usb/usbip/libsrc/usbip_common.h` (a device of 312
  bytes, then 4 bytes for each interface), with the version that
  `torvalds/linux:tools/usb/usbip/configure.ac` defines, 0x00000111, as
  the client refuses another.
- The recipe adds `--keep-listening` to step 1's command: a listener
  takes one client, and `usbip list -r` and `usbip attach -r` connect
  once each. It keeps the local port 3240, so `usbip` needs no
  `--tcp-port`.
- `usbip attach` hands its TCP socket to the kernel
  (`usbip_vhci_attach_device(port, sockfd, ...)` in
  `torvalds/linux:tools/usb/usbip/src/usbip_attach.c`), so the device's
  traffic passes podssh for as long as the pipe's session lasts; the
  README says so. `usbip` dials TCP only, so a host that refuses an
  AF_INET bind, as sandbox A does (`docs/STATUS.md:279`), cannot run the
  recipe, nor can one without the modules.
- The row states the limit by the throughput measured through sandbox A's
  proxy (`docs/STATUS.md:286`): 64 MiB is about 2 minutes of reads at
  0.5 to 0.7 MB/s.

What waits:
- Step 3, the attach, a read from the device, `usbip port` and the
  detach on two Linux hosts with the modules: it waits for the operator's
  machines (or the tailnet hosts of `docs/STATUS.md`, if they have the
  modules and a device): UNVERIFIED.

What ran:
- Native here: the Prove's `grep` finds the row, `README.md:237`;
  `python scripts/check-repo.py`: each check ok, the doc links too.
- In the build image (Alpine, `linux-tools-usbip`), with no module: the
  harness's stand-in of `usbipd` on a port of its own, and the real
  `usbip --tcp-port PORT list -r 127.0.0.1` without podssh. usbip listed
  "1-1: unknown vendor : unknown product (1d6b:0104)" with the stand-in's
  path and the interface (08/06/50), and exited 0; the stand-in read the
  request `0111800500000000`. The image has no `usb.ids`, so usbip says
  that it could not open it, and names no vendor.
- In CI (cad2885, the gate's step `release`): `usbip.list_remote` passed,
  "usbip list -r through pipe tcp-listen:127.0.0.1:3240 and ssh: lists
  the device 1-1".
  Planted, "64 MiB" deleted from the row in a copy of `README.md`: the
  `grep` found nothing and exited 1.


# T-282: On Windows a session that `--persist` attaches again waits for a key

**Source:** CI, the run of `5a88857` (2026-10-11): the job `windows` failed
`a_lost_link_attaches_the_same_tmux_session_again` of
`crates/podssh-cli/tests/persist.rs`, which passed in the runs before and
after it; on Windows, 1 of 30 runs of the test binary failed, six at once.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

After a lost link, `podssh ssh --persist` connected again and logged
"attaching the tmux session podssh again", and then the session did not
attach: the test typed its next line after that log line, and waited 30 s
for the answer. Where stdin is a pipe on Windows, as under MSYS2's mintty,
a session attached again waited until the user typed. A check that fails at
random hides a real failure.

## Premise

Read: the input outlives a session, and its task reads stdin from the first
session on (`crates/podssh-ssh/src/io/input.rs:62`); each session asks whether
stdin is a terminal before its pty request
(`crates/podssh-ssh/src/session.rs:69`). std's answer on Windows, for a
handle that is no console, asks a pipe's name (`GetFileInformationByHandleEx`
with `FileNameInfo`, the check for an MSYS2 pty), and the name of a pipe
opened for synchronous reads waits while another thread's read of it is
pending. Measured on 2026-10-11, with a program of 20 lines whose thread
reads a piped stdin: `GetFileType` and `GetConsoleMode` answered at once,
and `is_terminal` after 2.5 s, when the parent wrote a line. In the test,
the line typed after the log line ended the pending read, and the question
was answered; the task then read again, and when its read took the pipe
before the waiting question did, the question waited for a line that the
test never typed.

## Approach

Ask once whether stdin is a terminal, and keep the answer; the input's task
asks before it reads. After the loss, the test types nothing until the
second session is attached, so that the defect fails each run, not one run
in thirty.

## Prove

```sh
cargo test -p podssh-cli --test persist
```

With the test's wait and without the repair, the test fails each run on
Windows ("no \"[podssh] attached\" on stdout" after 30 s). With the repair,
runs of the test binary, six at once, all pass.

## Done

2026-10-11. `crates/podssh-ssh/src/terminal/mod.rs:58-61`:
`stdin_is_terminal` asks once and keeps the answer;
`crates/podssh-ssh/src/io/input.rs:105`: the input's task asks before it reads.
`crates/podssh-cli/tests/persist.rs:223`: after the loss, the test waits for
the second "[podssh] attached" before it types. Without the repair the test
failed (exit 101, after 31.4 s); with it, `cargo test -p podssh-cli --test
persist`: 4 passed, and 48 runs of the test binary, six at once: 48 passed,
the slowest in 1.66 s.

# T-367: `http-listen:`: `podssh pipe` as an HTTP CONNECT proxy, for programs that know only `HTTPS_PROXY`

**Source:** GitHub #75 (Nemo-010, 2026-10-31).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

podssh can use an HTTP CONNECT proxy, and cannot be one. Most programs in a container (pip, npm,
cargo, git) read `HTTPS_PROXY` and send CONNECT; some of them speak no SOCKS, or only with more
setup, so `-D` does not serve them, and a cage often cannot run a proxy of another project. A
listener of `podssh pipe` that answers CONNECT, and joins each request to a road of podssh with
the request's target, would be the proxy that such a program points at.

## Premise

- Read: podssh-ws reads HTTP responses only: one request of its own and the response to it
  (`crates/podssh-ws/src/http.rs:1-3`), with `read_response` and `parse_head`, which reads a
  status line (`:80-125`). Nothing reads a request.
- Read: no kind of `pipe` answers HTTP (`crates/podssh-cli/src/pipe/address.rs:75-97`); two kinds
  listen, and one side at most (`:59-73`, `:121-123`).
- Read: a listener of `pipe` binds only an address that the user gives, never with
  `PODSSH_LISTEN=no` (78), and its bind is the probe; a socket is made mode 0600, and a client of
  another user is closed (`crates/podssh-cli/src/pipe/listen.rs:1-13`, `:28-39`, `:82-95`). It
  takes one client by default, and with `--keep-listening` each client in turn, 8 at once at most,
  each joined to a new instance of the other side (`crates/podssh-cli/src/pipe/serve.rs:1-11`).
- Read: the operator allows a listener that the user asks for, when a probe allows the bind, on
  loopback or AF_UNIX by default (`docs/decisions.md:36`; `docs/architecture.md:147-154`); the
  gate's scan of listeners allows the listener of `pipe` (`scripts/check-repo.py:79-103`).
- Read: the SOCKS side of `-D` answers once the server's channel opened, so that a client learns
  whether its target was reached (`crates/podssh-ssh/src/socks.rs:1-5`). The relay refuses a target
  of its policy with a `403` that names it, `not in the ALLOW list` (`docs/relay.md:176-178`).
- Read: a secret of the resumable layer is compared in constant time
  (`crates/podssh-relay/src/session/secret.rs:247-251`).

## Approach

1. A kind `http-listen:[ADDR:]PORT`, and `http-listen:PATH` for a socket, bound by
   `Listener::bind` with each rule of `tcp-listen:` and `unix-listen:` (T-177). It keeps listening,
   as with `--keep-listening`.
2. The other side names its target as `%h:%p`: `relay:%h:%p`, `tcp:%h:%p` (through `HTTPS_PROXY`),
   or `ssh:[USER@]HOP[,HOP...],%h:%p`; each request fills it in. Another side is refused (64).
3. A reader of requests in podssh-ws, beside `read_response`: the request line and its headers
   within 16 KiB, as for a response's head. It takes `CONNECT HOST:PORT HTTP/1.1` (and `HTTP/1.0`),
   the target checked as each target is (`check_target`). Another method gets `405` and nothing is
   dialed; `Upgrade` is not taken.
4. `200 Connection Established` once the other side opened; else a `403` with the relay's words
   for a target of its policy, a `502` with the reason of a failed dial, a `504` for a dial past
   its limit.
5. With a credential file that the user names (private, as the relay's token file):
   `Proxy-Authorization: Basic`, compared in constant time. A request without it, or with a wrong
   one, gets `407` with a `Proxy-Authenticate: Basic` challenge, and nothing is dialed. An address
   that is not loopback needs the file: without it, the listener is refused (64).
6. The manual, the help, `docs/cli.md`, and the comment of the gate's scan of listeners
   (`http-listen:` beside `tcp-listen:`).

## Decision

- A kind of `pipe`, as #75 asks, not a verb: `pipe` joins two streams with one listener at most,
  and here the listener's other side takes its target from each request. Lost: a new verb, which
  would repeat the rules of the listener; `-D` that answers HTTP too, which serves one road only,
  the SSH destination's, and is not OpenSSH's.
- `%h:%p` names the request's target, as `ProxyCommand` names the host and the port in OpenSSH.
  Lost: `*`, which a shell can expand.
- CONNECT only, as #75 asks. A request in absolute form (`GET http://...`, a proxy request for
  plain HTTP) gets `405`: to carry it, podssh would rewrite HTTP, a second protocol on the port.
  Lost: such requests carried, for a program that fetches `http://` URLs; it can fetch `https://`
  through CONNECT.
- An address that is not loopback needs the credential file, where `tcp-listen:` only says that
  other hosts can connect: scanners find an open CONNECT proxy, and each of its clients would spend
  the user's relay token. Lost: a warning alone, as `-D` with `-g` gives, which is OpenSSH's
  behaviour for `-D`.
- The reader of requests serves T-368 (`ws-listen:`) too; whichever is done first writes it.
- The checks in this order: the credentials, then the method, then the target, so that a client
  with no credential learns nothing of the proxy but its challenge. Lost: the method first, which
  tells such a client what the proxy takes.
- A proxy takes 32 tunnels at once, where `--keep-listening` takes 8: a program behind a proxy
  opens several connections at a time (npm up to 15, pip 10), and each further one would wait in the
  backlog until a tunnel ended. Lost: 8, which stalls such a program; no bound, with which one client
  opens sessions of the road without end.
- The status line carries the words after its phrase (`403 Forbidden: ... not in the ALLOW
  list`), and the body repeats them: Python's `http.client`, under pip, shows the status line of a
  refused tunnel ("Tunnel connection failed: 403 ..."), and curl only its status. Lost: the
  standard phrase alone, which hides the relay's reason from pip's user.
- The bytes that a client sends after its CONNECT and before the answer are the tunnel's, and go
  to the road once it is open. Lost: dropping them, which breaks a client that sends its TLS hello
  at once.
- One request on each connection: a refusal shuts the write half, reads what the client still
  sends for 2 s, then closes, as a close with bytes unread is a reset that can lose the answer.
  Lost: keep-alive after a 407, for which a second request on one connection is a request to
  smuggle past the reader; curl and the others open a new connection.
- A line may end with a bare LF (RFC 9112 section 2.2 allows it), and a bare CR, a space before a
  colon and a folded line are refused (400). Lost: CRLF alone, which refuses a request typed with
  `nc`; obs-fold joined with a space, which a second reader may read otherwise.
- The file of credentials holds lines `USER:PASSWORD` in clear, read as a pair's file is
  (`podssh_relay::cache::read_private`: this user's, which nobody else can read, else 78);
  podssh keeps the SHA-256 of each and compares the client's with each one, all of them, with no
  branch on a byte. Lost: the base64 token compared as text, which a client's base64 with no
  padding fails; the hashes of `htpasswd`, which need a crypt that podssh has not.
- `http-listen:PATH` is a path when it holds a `/` (on Windows also a `\`) or begins with `@`; a
  bare name is refused, and the line gives its `./` form. Lost: a bare name taken as a path, which
  binds a file for a typo of a port (`http-listen:808O`).
- `%h:%p` is the target, once and last, of `relay:`, `tcp:` or `ssh:` alone. Lost: a fixed port
  (`relay:%h:443`), which serves no program that `HTTPS_PROXY` drives; `exec:` with `%h` and `%p`,
  as `ProxyCommand` takes them, which #75 does not ask for.
- With `ssh:`, each request logs in anew, as each client of `--keep-listening` opens its own
  instance of the other side. Lost: one SSH connection with a channel for each tunnel, as
  `podssh ssh -D` keeps one for its SOCKS clients; that is `-D`'s.
- The stand-in relay has a mode `policy` (`scripts/fake-relay.py`), which answers each upgrade
  `403` with `not in the ALLOW list`, as the live relay answers a target of its policy, so that the
  403 of the proxy is tested against the relay's own shape.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib http
cargo test -p podssh-cli --test pipe_listen
cargo test -p podssh-cli --test pipe_http
```

curl, software that podssh did not write, through `http-listen:` with `relay:%h:%p` to a stand-in
relay: `curl -x http://127.0.0.1:PORT` fetches a page over TLS from a test server, and its bytes
equal those of a direct fetch; with `ssh:` to a test sshd, a CONNECT to its port 22 gets the
banner. A `GET /` gets `405`, and the stand-in sees no dial; a request with no credential, or a
wrong one, gets `407` with `Proxy-Authenticate`, and no dial; `PODSSH_LISTEN=no` exits 78 before
any bind; an address that is not loopback with no credential file exits 64. Planted: a listener
that dials before it checks the credential; the test of `407` fails. Live:
`git ls-remote https://github.com/Azathothas/podssh` with `HTTPS_PROXY` at the listener and the
live relay behind it.

## Correction

2026-10-31: three citations of the Premise name other lines, as they did when the entry was
written (read at `8207d29`). The ruling on a listener that the user asks for is
`docs/decisions.md:41`; `docs/decisions.md:36` is the ruling on `exec:`. The relay's `403` of its
policy is `docs/relay.md:181-183`; `docs/relay.md:176-178` is the form of a token and its header.
The rest reads as cited. Nothing in the Approach changes.

## Done

2026-10-31: drafted (branch `draft-pipe`, `6b43718`), then merged and measured.

- `http-listen:[ADDR:]PORT` and `http-listen:PATH` (`crates/podssh-cli/src/pipe/web.rs`), bound
  by `Listener::bind` with the rules of `tcp-listen:` and `unix-listen:`
  (`crates/podssh-cli/src/pipe/serve.rs`); a proxy always keeps listening, 32 at once, and its
  first line names the value of `HTTPS_PROXY`. The other side is a template of `%h:%p`
  (`relay:`, `tcp:`, `ssh:`), checked with a target before anything starts; `%h:%p` beside
  another side is refused (64).
- The reader of requests, `podssh_ws::http::request` (`crates/podssh-ws/src/http/request.rs`):
  the head within 16 KiB (431), a bare LF taken, a bare CR, a space before a colon, a folded line
  and a control byte refused (400), another version 505; `connect_target` checks `HOST:PORT` and
  `[IPV6]:PORT` with `check_target`; `refusal` writes a status with its words on one line, and
  `established` the `200` with no length. T-368 and T-369 read their requests with it.
- Each client (`crates/podssh-cli/src/pipe/http_listen.rs`): its request within 30 s (408), its
  credentials (407 with `Proxy-Authenticate: Basic realm="podssh"`), CONNECT alone (405 with
  `Allow: CONNECT`), no content, its target (400); then the road, through
  `crates/podssh-cli/src/pipe/gateway.rs`: 403 for a policy (the relay's words, an upstream
  proxy's 403, an SSH server's `AdministrativelyProhibited`), 504 for a limit, 502 else; `200` only
  once the road is open, then the bytes that came after the request. A refusal closes the
  connection after its answer.
- `--proxy-auth-file FILE` (`crates/podssh-cli/src/pipe/credentials.rs`): a private file of
  `USER:PASSWORD` lines, the SHA-256 of each kept and compared in constant time; needed for an
  address that is not loopback (64), and refused beside a side that is no proxy (64).
- The manual (`crates/podssh-cli/src/man/notes_pipe.rs`, where `pipe`'s notes moved from
  `notes.rs`; an example; `PODSSH_LISTEN`'s fact), the help, doctor's table of listeners,
  `docs/cli.md`, `README.md`, `SECURITY.md`, `docs/design.md`, and the comment of the scan of
  listeners in `scripts/check-repo.py`. The stand-in relay's mode `policy`.
- Measured at the merge (2026-10-31): `cargo test -p podssh-ws --lib http`, 9 passed (the
  reader); `--test rfc6455`, 25. `cargo test -p podssh-cli --lib pipe::`, 33 passed (the grammar of
  `web`, the credentials, the statuses of `gateway`, the order of the checks); `--lib doctor`, 37;
  `--lib man`, 55; `--test flag_table`, 9; `--test pipe_listen`, 8, `http-listen:` under
  `PODSSH_LISTEN=no` among them.
- `cargo test -p podssh-cli --test pipe_http`, 6 passed, curl 8 of this host as the client: a page
  of 256 KiB over TLS through `tcp:%h:%p` and through `relay:%h:%p` to the stand-in relay, equal to a
  direct fetch; 502 for a target that the stand-in cannot reach; 403 with `ALLOW list` in curl's
  lines and in podssh's from the stand-in's mode `policy`; the banner of the test's sshd through
  `ssh:` to its own port; 405 for a GET and 407 with its challenge for no credential and a wrong
  one, with no connection at the target, then 200 with the right one; 78, 64, and 78 for a file
  that others can read.
- Planted, the credentials' check skipped: the test of 405 and 407 failed, curl reaching the
  target.
- Live, `cargo test -p podssh-cli --test pipe_http -- --ignored live_git`: `git ls-remote` of this
  repository's HEAD through the proxy and the live relay, from this cloud session's host through
  its own proxy, passed.
- clippy named an explicit deref in `pipe/address.rs`; clean after it.

# T-368: `ws:`, `wss:` and `ws-listen:` as addresses of `podssh pipe`

**Source:** GitHub #76 (Nemo-010, 2026-10-31).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

podssh-ws speaks RFC 6455 only to the relay and to the services that `cloudflared` publishes. A
WebSocket of another service cannot be a side of `pipe`, and podssh cannot listen as one, so a
user who needs `websocat` must bring it, and a cage may not run it.

## Premise

- Read: the kinds of `pipe` have no WebSocket (`crates/podssh-cli/src/pipe/address.rs:75-97`); the
  relay is reached by `relay:HOST:PORT`, whose path is the relay's forward path (`:139-145`), and
  `tcp:HOST:PORT` carries bytes in the clear to any host that the user names (`:27-28`).
- Read: the endpoint of the client is a host, a port and a path
  (`crates/podssh-ws/src/client.rs:40-47`); `validate` refuses a query other than the relay's
  knobs, as a query goes into the logs of proxies (`:66-105`); `connect` takes a token and sends it
  in `X-Relay-Token` (`:159-182`); the name of the certificate has no bypass (`:55-57`); the upgrade
  is generic over its stream (`:207-213`).
- Read: the token never goes in a URL, and the request has no query
  (`crates/podssh-ws/src/handshake.rs:1-8`); `accept_key` gives the server's value (`:62`), tested
  on the vector of RFC 6455 (`crates/podssh-ws/tests/rfc6455.rs:259`).
- Read: the codec of frames takes its role, and never writes a masked frame of a server
  (`crates/podssh-ws/src/frame.rs:61-70`); a session is generic over its stream
  (`crates/podssh-ws/src/session.rs:36`).
- Read: plain `ws://` goes to the loopback only, for tests, behind the feature `plain-ws`, which
  the binary never enables, as the relay's token over plain TCP must not leave the host
  (`crates/podssh-ws/src/plain.rs:1-6`).
- Read: the rules of a listener of `pipe` (`crates/podssh-cli/src/pipe/listen.rs:1-13`; T-177).

## Approach

1. `wss://HOST[:PORT]/PATH` and `ws://HOST[:PORT]/PATH`, the URL as a user writes it: TLS checked
   for HOST with podssh's trust, or plain TCP; through `HTTPS_PROXY`, as each road. No token is ever
   sent on them. The path and its query are the user's; podssh's own lines show the URL without
   its query.
2. A dial in podssh-ws with no token: `connect` keeps its token for the relay, and `validate` its
   rule for the relay's path; the new dial refuses CR, LF and a space in the path.
3. Bytes go out in binary frames; text and binary frames come in as bytes; a close gives its code
   and its reason on stderr.
4. `ws-listen:[ADDR:]PORT` and `ws-listen:PATH`, bound by `Listener::bind`: the reader of requests
   of T-367, a check of `Upgrade: websocket`, `Connection: Upgrade`, version 13 and the key, then
   `101` with `accept_key`, and frames as `Role::Server`. An unmasked frame from a client closes
   with 1002. Each client is joined to the other side as given.
5. The manual, the help and `docs/cli.md`: `ws:` is in the clear, as `tcp:` is.

## Decision

- `ws:` reaches any host that the user names, with no token: `tcp:` carries the same bytes in the
  clear already, and the rule of `plain-ws` is for the relay's token, which never goes on `ws:`.
  Lost: `ws:` to the loopback only, which keeps no secret that `tcp:` does not already give away.
- The form of a URL (`wss://host/path`), not #76's `wss:HOST:PORT/PATH`: a user copies a URL, as
  for `websocat`.
- `ws-listen:` takes no target from the request: each client goes to the other side as given.
  Lost: a target from the URL, which would make podssh a public forwarder of the kind of T-369's,
  that is a relay, and the relay stays a separate project (`docs/decisions.md:41`).
- No `wss-listen:`: a server of TLS needs a certificate and a key of the user's, and #76 does not
  ask for it.
- The reader of requests is T-367's; whichever is done first writes it. The dial with no token
  serves T-369 too.
- At the end of this side's input a Close 1000 goes out, and what the other end sends before its
  own Close still comes; the other end's Close is answered at once and ends the pipe, as RFC 6455
  section 5.5.1 asks the answer "as soon as practical". Lost: no Close, as `relay:` sends none,
  with which a server that waits for more never ends the pipe; the other end's Close taken as a
  half-close, sending on until this side's input ends, which holds a terminal's pipe open after
  the server closed it.
- A Close of 1000, or the end of the connection after this side's Close, is a clean end (0); any
  other code is the pipe's failure (69), with the code and the reason. Lost: 1001 as a clean end,
  which hides a server that went away under the session.
- The session pings every 10 s and bounds each read at 90 s, as on the relay's road: a server
  answers a Ping (RFC 6455 section 5.5.2), so only a dead link meets the bound. Lost: no bound,
  which never ends a link that died with no word.
- The URL: a user or a password in it is refused (64), a byte that is not ASCII percent-encoded, a
  fragment not sent, the port in `Host` only when it is not the scheme's own (RFC 6455 section
  4.1), and `User-Agent: podssh/VERSION`, as on the road of `cloudflared`; the request names no
  `Origin`. Lost: a user and a password sent as Basic, which puts a credential in a URL and in argv.
- `ws-listen:` refuses a request with an `Origin` (403): a browser sends one with each WebSocket,
  and any page that the user opens could else reach the other side, a shell of `exec:` among them.
  Lost: each Origin taken; a flag that names the origins allowed, which #76 does not ask for.
- `ws-listen:` opens the other side before it answers 101, and a client hears 502 when it did not
  open, as `http-listen:` answers 200 only once its road is open. Lost: 101 at once, after which a
  failure is a close alone.
- One client by default, the first whose upgrade is good: a refused request is no session, and
  the listener waits for the next. Lost: the first connection, which a port scanner or a stray
  request would use up.
- The server's session is `RelaySession` with a role (`as_server`), and its errors name the other
  end (`naming`), the relay's words unchanged by default: one reader, one writer and one reassembly
  of fragments for both sides. The writer and the reader of frames for a role are in
  `crates/podssh-ws/src/wire.rs`. Lost: a second session for the server, which would repeat the
  reassembly, the Pings and the closing handshake.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test rfc6455
cargo test -p podssh-cli --test pipe_ws
```

Against websocat, software that podssh did not write, in Podman or in the build image:
`podssh pipe stdio ws://HOST:PORT/` to its server that echoes gets each line back; websocat as
the client of `ws-listen:` reaches a test server through `tcp:`, 1 MiB each way with equal
digests; `wss://` to a stand-in with a certificate for another name is refused. A stand-in client
that sends an unmasked frame gets the close 1002. `PODSSH_LISTEN=no` exits 78 before any bind.
Planted: the server's frames encoded as `Role::Client`; the test of the masks fails.

## Correction

2026-10-31: two citations name other lines, as they did when the entry was written (read at
`8207d29`). The role of the codec is `crates/podssh-ws/src/frame.rs:74-83`, and `encode` ignores a
key of a server's at `:85-88`; `crates/podssh-ws/src/frame.rs:61-70` holds the markers of a length
and `Frame`. The relay stays a separate project at `docs/decisions.md:46`; `docs/decisions.md:41`
is the ruling on a listener that the user asks for. Nothing in the Approach changes.

## Done

2026-10-31: drafted (branch `draft-pipe`, `f3f6a77`), then merged and measured.

- `ws://` and `wss://` (`crates/podssh-cli/src/pipe/ws.rs`): the URL as `podssh_ws::url` reads
  it (`crates/podssh-ws/src/url.rs`), dialed with no token through `HTTPS_PROXY`, TLS checked for
  HOST with `--ca-file`'s trust; the form `wss:HOST:PORT/PATH`, a user or a password, CR, LF, a
  space and a control character refused (64); podssh's lines show the URL without its query.
  Binary frames out, text and binary frames in as bytes, a Close at the end of input, the other
  end's Close the end, a code other than 1000 on stderr and 69; a refused upgrade 77 for 401 and
  403, else 69. T-369 dials its forwarders with `podssh_ws::url::dial`.
- `ws-listen:[ADDR:]PORT` and `ws-listen:PATH` (`crates/podssh-cli/src/pipe/ws_listen.rs`), bound by
  `Listener::bind`; the request read by T-367's reader and checked by `podssh_ws::server`
  (`crates/podssh-ws/src/server.rs`: 405, 400, 426, a key of 16 bytes, 403 for an `Origin`); the
  other side opened, then `101` with `Sec-WebSocket-Accept`, or 502; the session as
  `Role::Server` (`RelaySession::as_server`), whose unmasked frame of a client closes with 1002.
- The manual (`crates/podssh-cli/src/man/notes_pipe.rs`, an example, `PODSSH_LISTEN`'s fact), the
  help, doctor's table of listeners, `docs/cli.md`, `README.md`, `SECURITY.md`, `docs/design.md`
  and the comment of the scan of listeners in `scripts/check-repo.py`.
- Measured at the merge (2026-10-31): `cargo test -p podssh-ws --test rfc6455`, 27 passed (a
  server masks nothing, takes masked frames, and closes on an unmasked one with 1002; its 101
  carries the accept of section 1.3's key); `--lib url::`, 3; `--lib server::`, 2.
- `cargo test -p podssh-cli --test pipe_ws`, 5 passed, with websocat 1.14.0 (its static release
  for x86-64 Linux, fetched into `.work/` and put on the PATH, as the cloud session's host has none):
  websocat's echo server through `ws://`; websocat as the client of `ws-listen:` to a test server
  through `tcp:`, 1 MiB each way with equal digests; `wss://localhost` to a certificate of
  127.0.0.1 refused, and `wss://127.0.0.1` reaching its upgrade with the query sent and not shown;
  426 and 403 for a request that is no upgrade and a browser's, then 101, a masked frame echoed
  unmasked and an unmasked one closed with 1002 (exit 69); a server's text and binary frames as
  bytes and its Close 4000 on stderr (69), and 1000 (0), with no `X-Relay-Token` and no `Origin`
  sent.
- `--test pipe_listen`, 8 passed (`ws-listen:` under `PODSSH_LISTEN=no`, 78); `--lib pipe::`, 34;
  `--lib doctor`, 37; `--lib man`, 55; `--test flag_table`, 9; `--test pipe_http`, 6, again.
- Planted, the server's frames encoded as `Role::Client`: `pipe_ws`'s test of the 1002 and its run
  of 1 MiB with websocat failed, and `rfc6455`'s test of a server's masks.
- At the merge: the session's field `peer`, the name of the other end in an error, met T-344's
  `peer`, the address of the connection; the name is `peer_name` now, and each keeps its method.
  `ws_listen::first` was public with a private argument's type, now `pub(super)`; clippy clean.
