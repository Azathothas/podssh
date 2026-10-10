The work of milestone M7, `podssh pipe` and `--persist`, and the backlog of
streams that `pipe` can carry: desktop streams and Telnet, a published HTTP
service, serial devices and USB/IP. The design is `docs/design.md:401-443`;
the milestone is `docs/ROADMAP.md:231-240`.

# T-174: `podssh pipe A B` with local addresses

**Source:** ROADMAP M7 (`docs/ROADMAP.md:233-237`), `docs/design.md:418-443`;
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
  row (`crates/podssh-cli/src/flags.rs:396-429`).
- Read: the only pump is `crates/podssh-cli/src/pipe/relay.rs:86-205`. At the end
  of input it stops sending and keeps receiving
  (`crates/podssh-cli/src/proxy.rs:8-11`). T-101 is the opposite defect in
  `crates/podssh-ts/src/pipe.rs`; the new pump must not repeat it.
- Read: `exec:` starts the user's own program. The operator accepted it on
  2026-10-08 (`docs/decisions.md`). On sandbox A, `/tmp` and `$HOME`
  do not run programs (`docs/STATUS.md:174`).

## Approach

1. The verb: a `pipe` row in `crates/podssh-cli/src/flags.rs:396-429`, two
   required positionals (`crates/podssh-cli/src/positionals.rs:7-105`), a
   `Parsed::Pipe` variant (`crates/podssh-cli/src/parsed.rs:8-139`), a
   dispatch arm, and `pipe` in `DISPATCHED`
   (`crates/podssh-cli/tests/flag_table.rs:107-110`). No `--timeout` row: the
   gate at `crates/podssh-cli/src/dispatch.rs:213-231` would require it.
2. The grammar, in a new crates/podssh-cli/src/pipe/address.rs: `KIND:REST`.
   An unknown kind exits 64 and lists the kinds. `-` is `stdio`; `stdio` on
   both sides exits 64. Invariant: both addresses are valid before anything
   starts.
3. Move the pump of `crates/podssh-cli/src/pipe/relay.rs:86-168` to
   crates/podssh-cli/src/pipe/pump.rs, over two duplex ends, with its rules:
   reads of 32 KiB; an end of input half-closes the other side (a shutdown
   of the write side, never a drop, or the reply is lost), and the other
   direction goes on; a reader that is gone ends the pipe with 0
   (`crates/podssh-cli/src/pipe/relay.rs:197-201`). Keep
   `runtime.shutdown_background()` (`crates/podssh-cli/src/proxy.rs:90-92`).
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
   (`crates/podssh-cli/src/man/notes.rs:10-30`), two examples
   (`crates/podssh-cli/src/man/examples.rs:8-90`; its test at
   `crates/podssh-cli/src/man/examples.rs:213-224` learns the new variant),
   `docs/design.md:420-428`, `docs/STATUS.md`. Each file stays under 500
   lines (`AGENTS.md:206-207`).

## Decision

Recommendation: `exec:` splits the words itself and starts no shell, because
podssh must not assume a shell (`AGENTS.md:190-191`), and the user can name one
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

**Source:** ROADMAP M7 (`docs/ROADMAP.md:233-237`), `docs/design.md:425-428`;
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
  with `crates/podssh-relay/src/open.rs:180-212` and pumps it
  (`crates/podssh-cli/src/proxy.rs:43-94`).
- Read: `crates/podssh-ssh/src/relay_stream.rs:133-136` sends Close 1000 when
  its write side ends. That is right for SSH and wrong for a pipe: the relay
  has no half-close (`docs/relay.md:74-80`), so a Close cuts a reply on its
  way. Measured live for proxy: the full reply after stdin closed
  (`docs/STATUS.md:116`).
- Read: `-W` opens its stream with `crates/podssh-ssh/src/forward.rs:12-20`
  after the hops of `crates/podssh-ssh/src/run.rs:113-120`, but that code is
  private and gives only an exit code.
- Read: `TODO/issues.md` (#26) says that a binary protocol through `-W` is
  measured. Only exec is measured with digests (`docs/STATUS.md:70`); `-W`
  was checked with a banner of 16 bytes (`scripts/interop.sh:268-269`).
- Read: `node:` needs T-084 (M4) and `iroh:` needs T-163 (M6); both are done
  before M7 starts.

## Approach

1. One adapter per kind, in crates/podssh-cli/src/pipe/remote.rs: it opens
   its road and gives a duplex stream and, at the end, a close reason. The
   pump does not know the road (`docs/architecture.md:99-101`).
2. `relay:HOST:PORT`: parse as `crates/podssh-cli/src/proxy.rs:98-108` does;
   open with `crates/podssh-relay/src/open.rs:180-212`. Keep the rules of
   proxy: no Close at the end of input, the ping watcher
   (`crates/podssh-cli/src/pipe/relay.rs:111-113`), empty frames dropped. IPv6
   literals follow T-007.
3. Move `podssh proxy` onto the pipe: `run_proxy`
   (`crates/podssh-cli/src/proxy.rs:43-94`) runs `stdio` and `relay:`. Keep
   its exit codes and messages (`crates/podssh-cli/src/proxy.rs:160-173`,
   `crates/podssh-cli/src/pipe/relay.rs:178-205`).
4. `ssh:[USER@]HOP[,HOP...],HOST:PORT`: the last item is the target, each
   other item a hop, read as `-J` reads it
   (`crates/podssh-cli/src/ssh/resolve.rs:180-184`,
   `crates/podssh-cli/src/ssh/hop.rs:29-77`). Make
   `crates/podssh-ssh/src/run.rs:113-120` a public `connect_chain` that `-W`
   and the pipe both use; keep each handle alive until the pipe ends. The
   options: `-i`, `-o NAME=VALUE` through
   `crates/podssh-cli/src/ssh/options.rs:61-192` (a keyword of a session,
   such as `RequestTTY` or `RemoteCommand`, exits 64), `--direct`,
   `--relay-host`, `--relay-addr` and `--ca-file`.
5. `node:NAME` after T-084, and `iroh:TICKET` after T-163: one adapter and
   one test each. If T-163 makes a ticket a credential, read it from a file
   (`iroh:@FILE`), never from argv.
6. Exit codes: sysexits, as `podssh proxy` (`docs/cli.md:592`): 69; 77 for a
   refusal (the relay, the proxy, a host key, the authentication); 78. Give
   `crates/podssh-ssh/src/run.rs:157-221` a typed error, so that 77 is not
   guessed from a message.
7. In the same commit: `docs/cli.md`, `docs/design.md:420-428`, the notes,
   the examples, `docs/STATUS.md`.

## Decision

Recommendation: add `tcp:HOST:PORT`, the direct road through `HTTPS_PROXY`
with `crates/podssh-ws/src/dial.rs:227-242`, because `ssh --direct` uses the
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
Close at the end of input, as `crates/podssh-ssh/src/relay_stream.rs:133-136`
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
`podssh_ssh::run::connect_hops` (`crates/podssh-ssh/src/run.rs:109-122`): it
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
- Read: sandbox A allows an AF_UNIX bind (`docs/STATUS.md:174`); a connect
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
6. In the same commit: `docs/cli.md`, `docs/design.md:424`, the notes,
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
before the operator's ruling of 2026-10-08 (Q24, `docs/decisions.md:23`),
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

**Source:** ROADMAP M7 (`docs/ROADMAP.md:236-237`), `docs/design.md:437-443`;
GitHub #26 (a local-only mode, as the `--local` of bunflared; read in the
report, not verified here); sandbox A of T-001.
**Category:** feature
**Milestone:** M7
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Desktop clients, browsers and database clients call `connect()` themselves:
they need a local port or socket (`docs/design.md:440-443`). podssh refuses
each listener. The design allows one for `pipe`, locally, after a probe
shows that an AF_UNIX or loopback bind works (`docs/design.md:437-439`).

## Premise

- Read: the operator ruled on 2026-10-08 (`docs/decisions.md`): a local
  listener is allowed when the user asks for it and a probe at run time
  allows the bind. The default is loopback and AF_UNIX; the user can
  configure the address and can turn listening off.
- Read: five documents still say that podssh never listens:
  `AGENTS.md:192-197`, `docs/architecture.md:102-112`,
  `docs/target-environment.md:74-78`, `SECURITY.md:78-88`, `README.md:37-42`.
- Read: sandbox A refuses an AF_INET bind and allows an AF_UNIX bind
  (`docs/STATUS.md:174`). The box refuses each `bind`, AF_UNIX too
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
   (`crates/podssh-cli/src/man/facts.rs:45-134`); the settings file of T-048
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
   five documents, `crates/podssh-cli/src/help.rs`, lines 213-214 at `a9299c4`,
   `crates/podssh-cli/src/man/notes.rs`, lines 70-72 at `a9299c4`, the reasons of the `-L` and
   `-D` rows (`crates/podssh-cli/src/flags.rs:210-215`; keep `-W HOST:PORT`
   as what to use, which `crates/podssh-cli/tests/flag_table.rs:82-98`
   asserts), `crates/podssh-cli/src/ssh/keywords.rs:88-89`,
   `crates/podssh-cli/src/ssh/options.rs:172-176`,
   `crates/podssh-cli/src/doctor/unix.rs:164` and
   `crates/podssh-cli/src/doctor/unix.rs:186`.
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
allows: `AGENTS.md:192-197`, `docs/architecture.md:102-112` and
`docs/target-environment.md:74-78` name a listener that the user asks for,
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

**Source:** ROADMAP M7 (`docs/ROADMAP.md:238-240`), `docs/design.md:238-248`;
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
is gone (`docs/design.md:205`). Against a standard sshd only one end runs
podssh, so the layer of M6 cannot help (`docs/design.md:238-240`). The
cheapest repair: connect again, and attach a `tmux` session that kept
running on the server (`docs/design.md:241-243`).

## Premise

- Measured: `podssh ssh --persist host` exits 64 (`unknown flag '--persist'`).
- Read: a lost link is `End::Lost` (`crates/podssh-ssh/src/io.rs:26-27`),
  an error at `crates/podssh-ssh/src/session.rs:35`. An exit status, a
  close with no status, and `~.` are other ends
  (`crates/podssh-ssh/src/session.rs:32-34`). Raw mode is entered once for
  each session (`crates/podssh-ssh/src/session.rs:104-120`).
- Read: the relay ends a session at 64 MiB (1009) or 12 h (1001)
  (`docs/relay.md:184-190`). Sandbox A measured the cap at 67,107,943 bytes,
  and one close `1011` in 180 short sessions (`docs/STATUS.md:182-183`).
- Read: tmux is never assumed (`docs/target-environment.md:90-92`).

## Approach

1. Flags `--persist` and `--persist-name NAME` (default `podssh`; letters,
   digits, `_` and `-`, 32 at most) in `crates/podssh-cli/src/flags.rs:112-251`.
   With a command, `-W`, `-N`, `-s` or `RemoteCommand`, exit 64.
2. The probe, after the login: one exec runs `command -v tmux`. No tmux:
   exit 255 with "the server has no tmux on PATH; --persist needs it". T-193
   uses the same function.
3. The session runs `tmux new-session -A -s NAME` with a pty, as `-tt` does.
   `-A` attaches when the session exists; that makes a second run safe.
4. A loop around `crates/podssh-cli/src/ssh/mod.rs:97-134`. Connect again
   only for a lost link: `End::Lost`, the ping watcher, or the relay's 1001,
   1006, 1009 or 1011. Never after an exit status, `~.`, a detach of tmux
   (exit 0), or a failure of the host key or the authentication.
5. Between attempts: leave raw mode, print one line for each attempt, and
   wait with `crates/podssh-relay/src/open.rs:270-276` (jittered, 30 s at
   most); 10 attempts or 5 minutes at most. Ctrl-C stops the wait with 255.
   Keys typed meanwhile wait in a queue of 64 KiB, and go after the attach.
6. Each attempt checks the host key with the same policy, and uses the
   cached token. A prompt with no terminal ends the loop
   (`docs/cli.md:617-619`). After the attach, send the window size again.
7. In the same commit: `docs/cli.md`, the notes of ssh
   (`crates/podssh-cli/src/man/notes.rs:32-111`), `docs/design.md:241-243`,
   `docs/STATUS.md`, and tmux in the interop image
   (`scripts/interop.sh:32-33`). T-025 shares the classes of close codes;
   T-153 replaces this loop when both ends run podssh.

## Decision

Recommendation: refuse `--persist` when the probe finds no tmux, because a
new shell after a drop looks like the old one and has lost its state: a
silent change of behaviour (`docs/target-environment.md:90-92`). The
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
`scripts/interop-faults.sh:158-168` does; the input then runs `echo M=$MARK`
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
**Status:** open

## Problem

Users ask how to carry RDP, VNC and Telnet. The documents show SSH and one
HTTP request (`README.md:118-123`). They do not say which clients work with
no listener, or that the relay ends a desktop stream after 64 MiB.

## Premise

- Read: a byte pipe carries each TCP protocol
  (`crates/podssh-cli/src/man/notes.rs:182-186`); a client that calls
  `connect()` itself needs a listener (`docs/design.md:440-443`), which
  T-177 adds where a probe allows it.
- Read: 64 MiB for each session, both directions together
  (`docs/relay.md:127`), then Close 1009 (`docs/relay.md:188`); public
  targets only (`docs/relay.md:129`). Through the proxy of sandbox A: 0.5 to
  0.7 MB/s (`docs/STATUS.md:181`).
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
4. Write a table "Other TCP protocols" after `README.md:118-123`: the
   protocol, what works now, what needs a listener, the 64 MiB limit. Add
   form a to `crates/podssh-cli/src/man/examples.rs:8-90`; its ProxyCommand
   parses (`crates/podssh-cli/src/man/examples.rs:190-197`). Link the table
   from `docs/design.md:440-443`.
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
  (`docs/STATUS.md:70`), and `pipe` carries a TCP stream (T-174, T-175).
- Read: through the relay, a session ends at 64 MiB (`docs/relay.md:127`);
  the traffic of a USB disk reaches that in seconds.
- Read: podssh cannot load a module or attach a device, and never assumes a
  privilege (`AGENTS.md:190-191`). The recipe uses the user's own `usbip` and
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
