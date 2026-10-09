This file holds the work for `podssh serve`: the SSH server in the process for
a host whose only egress is the relay (milestone M5, `docs/ROADMAP.md:175-202`),
and the server features in the backlog. No server code exists yet. T-107
decides where it goes, and each later entry builds on it. T-222 finds the
shell that T-108 runs.

# T-107: `podssh serve`: the russh server, its host key in a state file, and authorized keys

**Source:** `docs/ROADMAP.md:177-182` (M5), `docs/design.md:151-155`; GitHub #20
(Nemo-010, 2026-10-08: bssh-server and tty7 as references).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podssh gets out of a cage, but not into one: no SSH server runs there, and
the siblings needed a patched dropbear and shims. This entry gives the server
core: the handshake, a host key that does not change, and key authentication.

## Premise

- Measured on `3ee70dc`: `timeout 20 target/debug/podssh.exe serve </dev/null`
  prints "unknown subcommand 'serve'" and exits 64.
- Read: no source in `crates/` uses `russh::server`. russh 0.64.1 builds its
  server module on each target except wasm, with no feature
  (`Eugeny/russh:russh/src/lib_inner.rs`, lines 69-70 at `22c3b88`), so
  `crates/podssh-ssh/Cargo.toml:18` has it. `run_stream` serves one
  connection over any stream, as `crates/podssh-ssh/src/run.rs:31-36` does.
  To reuse: `crates/podssh-ssh/src/keygen.rs:60-130` (a key, mode 0600, never
  over a file), `crates/podssh-ssh/src/known_hosts.rs:136-139` (a key line),
  `crates/podssh-relay/src/cache.rs:58-73` (the directories).

## Approach

1. Add crates/podssh-ssh/src/server/ (see Decision), files under 500 lines,
   with one entry point that takes a stream. Invariant: it never listens.
   Each request handler answers: russh's defaults send no reply, and a client
   waits (podssh: 30 s, `crates/podssh-ssh/src/session.rs:18-21`).
2. russh settings: `publickey` only (the default also offers `password`);
   the 512 KiB window of `crates/podssh-ssh/src/run.rs:25-29`; no inactivity
   cut (russh: 600 s); a keepalive every 60 s (`docs/relay.md:162`).
3. Host key: `--host-key FILE`, else a file in the first usable directory of
   the cache chain, made with `keygen::generate` and `keygen::write_pair`.
   Invariant: never overwritten; the loser of a `create_new` race reads the
   winner's key. Print the fingerprint; warn when the directory is temporary.
4. Authorized keys: `--authorized-key KEY` and `--authorized-keys FILE`, else
   `$HOME/.ssh/authorized_keys`. Lines with options wait for T-114. No usable
   key: exit 78. Invariant: no setting accepts each key. `auth_publickey`
   compares `key_data()`; the login name selects nothing.
5. The verb: rows in `crates/podssh-cli/src/flags.rs:412-443` and
   `crates/podssh-cli/src/positionals.rs:8-84`, an arm beside
   `crates/podssh-cli/src/dispatch.rs:192-247`, the manual, `docs/cli.md`,
   `docs/STATUS.md`. The first source is `--stdio`, as `sshd -i`: OpenSSH
   then tests serve in the gate through `ProxyCommand`, with no listener.
   `podssh serve NAME` follows on the node runner of T-079. Windows: exit 70.

## Decision

Recommendation: the server goes in crates/podssh-ssh/src/server/, and only
the command line in crates/podssh-cli/src/serve.rs. `docs/design.md:28-30`
gives `podssh-ssh` the "russh client and server"; the crate links aws-lc
already (`crates/podssh-ssh/Cargo.toml:12-18`), holds the helpers to reuse,
and is read by the variable test (`crates/podssh-cli/src/man/facts.rs:240-241`).
A new crate lost: it repeats the russh dependency and its C exception, and
makes the helpers public. `podssh-cli` lost: it is the command line.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_auth
sh scripts/dev.sh check
HOME=/nonexistent timeout 20 "$BIN" serve --stdio </dev/null; test $? -eq 78
```

crates/podssh-ssh/tests/serve_auth.rs reads key lines (good, bad, options);
two starts at once keep one host key. The gate runs scripts/interop-serve.sh:
OpenSSH's `ssh -N` with `ProxyCommand='podssh serve --stdio ...'` stays up
with an authorized key, and gets `Permission denied (publickey)` with
another; a restart keeps the host key. A planted `auth_publickey` that
accepts each key fails. With no key, the static binary (`$BIN`) exits 78.

# T-108: `podssh serve`: exec, a shell and the environment, as the sandbox's user

**Source:** `docs/ROADMAP.md:177-182` ("It supplies exec"),
`docs/target-environment.md:37-44`; GitHub #20 (Nemo-010, 2026-10-08).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

After T-107 a client can log in, but each session channel is refused. A user
expects a command and a shell to work as with sshd: the exit status, stdout
and stderr apart, and an environment that a cage can give.

## Premise

- Read: russh calls `exec_request`, `shell_request` and `env_request`, and
  the handler must answer each (`Eugeny/russh:russh/src/server/mod.rs`,
  lines 601-667). russh also gives each data message to the kept `Channel`,
  and waits when 100 wait unread (`Eugeny/russh:russh/src/server/encrypted.rs`,
  lines 1350-1356): an unread channel stops the whole connection.
- Read: the client side to match is `crates/podssh-ssh/src/io.rs:104-138`;
  `crates/podssh-ssh/src/signals.rs:26-64` maps names to numbers only;
  `tokio` with `process` is a dependency (`crates/podssh-ssh/Cargo.toml:20`).

## Approach

1. `channel_open_session` accepts; each request gets success or failure.
   Read each kept `Channel` on its own task (stdin, EOF, `signal`).
2. The program: the shell that T-222 finds at the session start. With none,
   the request fails, and T-222's line goes to the channel's stderr. exec
   runs `SHELL -c COMMAND`; a shell runs as a login shell (argv[0] `-sh`).
3. The child: pipes for stdin, stdout and stderr; a new session (`setsid` in
   `pre_exec`); the working directory `HOME` when it exists, else `/`.
4. Environment: see Decision. `env` requests: only names that match
   `--accept-env PATTERN` (default `LANG`, `LC_*`), with the wildcard of
   `crates/podssh-ssh/src/known_hosts.rs:178-201`. Never `LD_*`, `PATH`,
   `HOME`, `SHELL`, `ENV`, `BASH_ENV` or `IFS`, whatever the pattern.
5. Output: stdout as data and stderr as extended data 1, through each
   channel's writer (T-118). After the child exits, read its pipes to their
   end within a stated limit: a background job can hold a pipe open.
6. The end: `exit-status`, or `exit-signal` with the SSH name and the core
   flag, then EOF and close. Invariant: one of the two always comes before
   the close (T-026 is the client side). Add the number-to-name direction
   to `crates/podssh-ssh/src/signals.rs:26-64`: one table, both ways.
7. A `signal` request (RFC 4254, section 6.9): `kill(-pgid, number)`. Same
   commit: `docs/cli.md` (the environment rules), the serve notes,
   `docs/STATUS.md`.

## Decision

Recommendation: the child gets serve's own environment minus podssh's
credentials (`PODSSH_RELAY_TOKEN`, the node's tokens), plus `USER`,
`LOGNAME`, `HOME`, `SHELL`, `TERM` and the accepted `env` requests. A cage's
environment holds what no login database gives again: `HTTPS_PROXY`, `PATH`.
A fresh environment, as sshd builds one, lost: the shell would have no proxy.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_exec
sh scripts/dev.sh check
```

crates/podssh-ssh/tests/serve_exec.rs checks the environment filter and the
order of exit-status, EOF and close. In the gate, scripts/interop-serve.sh
drives OpenSSH's `ssh` through `podssh serve --stdio`: exit statuses 3, 0, 1
and 127; a command killed by TERM; stdout and stderr apart; 5,000,000 bytes
up and back with one digest; `SetEnv LANG=C.UTF-8` arrives, `SetEnv LD_PRELOAD=x`
does not. With `PODSSH_RELAY_TOKEN` set for serve, the child's `env` lacks
it; a planted serve that passes its whole environment fails that check.

# T-109: `podssh serve`: direct-tcpip into the cage

**Source:** `docs/ROADMAP.md:177-182` ("direct-tcpip into the cage").
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

An operator often needs a TCP service inside the cage: a database, a
development server, the next SSH hop. Without `direct-tcpip`, `ssh -W` and
`-J` through `podssh serve` fail with "administratively prohibited", which
tells the user nothing.

## Premise

- Read: russh refuses a channel type that has no handler: the dropped reply
  handle sends `AdministrativelyProhibited`
  (`Eugeny/russh:russh/src/lib_inner.rs`, lines 570-620). A refusal can carry
  a reason with `ChannelOpenFailure::Other`.
- Read: the dialer to reuse: `crates/podssh-ws/src/dial.rs:186-204` (a time
  limit; `HTTPS_PROXY` when it is set) and
  `crates/podssh-ws/src/dial.rs:138-144` (loopback never through a proxy).
  The client copies a forward with half-close in
  `crates/podssh-ssh/src/forward.rs:22-83`.
- Read: in the measured sandbox, `connect()` to loopback failed with `EACCES`
  (`docs/target-environment.md:22`). Such a refusal must reach the client
  with its reason.

## Approach

1. Implement `channel_open_direct_tcpip`: dial with
   `podssh_ws::dial::dial(host, port, &ProxyChoice::FromEnvironment, limit)`.
   Do not add a second dialer.
2. On success, accept, then copy between `channel.into_stream()` and the TCP
   stream in both directions. An EOF in one direction keeps the other open,
   as `crates/podssh-ssh/src/forward.rs:22-83` does.
3. On failure, reject with code 2 (connect failed) and the dial error in
   words: the errno, or the proxy's status and reason.
4. Limits: 20 s for the dial; a stated maximum of open forwards for each
   connection, with `ResourceShortage` past it.
5. `--no-forwarding` refuses each forward (for one key: T-114). Add it to
   `crates/podssh-cli/src/flags.rs` and the manual.

Pitfalls: `direct-streamlocal@openssh.com` (AF_UNIX) stays refused here; T-040
is the client side. A host name that `check_name` refuses
(`crates/podssh-ws/src/dial.rs:321-330`) gets that reason, not a generic one.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_forward
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_forward.rs checks the reason text
of a refused dial and the forward limit. In the gate, scripts/interop-serve.sh
gives OpenSSH a `Host serve` block whose `ProxyCommand` runs
`podssh serve --stdio`: `ssh -W 127.0.0.1:2203 serve` reads Dropbear's banner;
`ssh -J serve -p 2201 podtest@127.0.0.1 'exit 5'` exits 5 through OpenSSH's
sshd; `ssh -W 127.0.0.1:1 serve` exits 255 and shows "Connection refused". A
planted rejection with no reason fails that last check.

# T-110: `podssh serve`: a real pty when `/dev/ptmx` exists

**Source:** `docs/ROADMAP.md:183-188`, `docs/design.md:156-160`,
`docs/terminal.md:48-58`; GitHub #20 (bound every PTY wait).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

An interactive shell, `vi`, `less` and Ctrl-C need a pty on the server side.
Without one, `ssh -t` to a node gets a shell with no prompt and no job
control. Many hosts that run `podssh serve` have `/dev/ptmx`; serve must use
it there.

## Premise

- Read: russh gives `pty_request` the terminal name, the size and the modes,
  and gives `window_change_request` each new size; both expect an answer
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 531-541 and 717-726).
- Read: the client sends its termios as RFC 4254 modes
  (`crates/podssh-ssh/src/terminal/unix.rs:81-153`). That table is the one to
  read in reverse on the server; a second table would drift.
- Read: doctor already opens a pty to test the host
  (`crates/podssh-cli/src/doctor/unix.rs:78-134`). The client continues
  without a pty when the server refuses (`crates/podssh-ssh/src/session.rs:44-57`).
- Read: the measured sandbox has no `/dev/ptmx` and no `/dev/pts`
  (`docs/target-environment.md:26`); there, T-111 applies.

## Approach

1. Move the pty code of `crates/podssh-cli/src/doctor/unix.rs:78-134` into
   the server module, with `O_CLOEXEC`, and let doctor call it. Try
   `/dev/ptmx`, then `/dev/pts/ptmx`, at each `pty-req`; never keep the
   result for the next session. Failure: T-111, or failure until T-111 exists.
2. Apply the request's modes to the slave: move the table of
   `crates/podssh-ssh/src/terminal/unix.rs:81-153` to a shared module and
   read it both ways. Skip a mode that the kernel refuses.
3. Size: `TIOCSWINSZ` on the master from `pty-req` and each `window-change`.
   A zero size becomes 80x24 (`docs/terminal.md:51-52`).
4. The child: `setsid`, `ioctl(TIOCSCTTY)`, the slave on descriptors 0 to 2,
   then exec, in `pre_exec`. The parent closes its copy of the slave, or the
   master never sees the end. `TERM` from the request (empty:
   `xterm-256color`, as `crates/podssh-ssh/src/terminal/mod.rs:87-92`);
   `SSH_TTY` names the slave.
5. I/O: the master is read without blocking through tokio's `AsyncFd`; output
   goes through the channel's writer (T-118). `EIO` after the child is gone
   is the end of the output, not an error.
6. The end: wait for the child, read the master to its end within a time
   limit (GitHub #20), then `exit-status` or `exit-signal`, EOF and close. A
   lost connection closes the master, and the kernel hangs up the session.
7. Unix only: on Windows a `pty-req` gets failure. Same commit: the serve
   notes, `docs/terminal.md` (the server side), `docs/STATUS.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_pty
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_pty.rs applies modes and sizes to
a real pty and reads them back. In the gate, the pty driver
`scripts/interop-pty.py` gets a mode that runs OpenSSH's `ssh -t` against
`podssh serve --stdio`: size, resize, Ctrl-C, `vi`, `less`, `top`, an exit
status and `~.`. The `-tt` cases of `scripts/interop.sh:240-268` run against
serve too. A planted serve that skips `TIOCSWINSZ` fails the size check.

# T-111: `podssh serve` with no `/dev/ptmx`: the line discipline, and Ctrl-C to the child's process group

**Source:** `docs/ROADMAP.md:183-188`, `docs/design.md:156-160`,
`docs/decisions.md:43`; GitHub #20 (fux line-discipline notes).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

The measured cage has no `/dev/ptmx` (`docs/target-environment.md:26`). There
a shell on pipes gives no echo, no editing and no prompt, and Ctrl-C reaches
nothing. Only the server side can turn Ctrl-C into a signal for the child's
process group (`docs/design.md:156-160`). Without it, a user cannot stop a
command, and the session must end.

## Premise

- Read: `crates/podssh-terminal` holds podbox's echo, editing and history
  rules (`docs/terminal.md:81-102`), and reports Ctrl-C and Ctrl-\ as
  `Event::Signal` (`crates/podssh-terminal/src/echo.rs:312-314`). No command
  uses it, and it has the defects T-125 to T-129, which come first.
- Read: the crate refuses to add `\r` before `\n`
  (`crates/podssh-terminal/src/echo.rs:31-37`,
  `crates/podssh-terminal/src/passthrough.rs:56-74`). Here the child writes
  to a pipe and the client's terminal is raw: the case where a lone `\n`
  must become `\r\n` (`docs/terminal.md:129-132`).
- Read: a signal to the group also stops a shell that does not catch it
  (`crates/podssh-terminal/src/session.rs:36-46`). Not measured yet: which
  shell mode survives.

## Approach

1. Selection: when the pty probe of T-110 fails, or with `--pty line`
   (values `auto`, `line`, `no`), answer the `pty-req` with success and run
   the session through `podssh-terminal` in serve (the server facts of
   T-125). Add the C-free crate to `crates/podssh-ssh/Cargo.toml`.
2. The child: pipes, its own session (`setsid`), so its group id is its pid.
   Start the shell so that SIGINT to the group stops the foreground command
   and not the shell. Measure `sh -i` with an empty `PS1` (an interactive
   shell catches SIGINT; its children get the default) with BusyBox `sh`,
   `dash` and `bash`. The discipline prints the prompt.
3. Keys from the channel go to `Session::on_local_bytes`: `ToRemote` to the
   child's stdin, `ToLocal` to the channel, `Signal(Int)` and `Signal(Quit)`
   to `kill(-pgid, SIGINT)` and `kill(-pgid, SIGQUIT)`, `Eof` closes stdin.
4. The child's output: a lone `\n` becomes `\r\n`; output during an edit
   redraws the line (T-129). The width comes from `pty-req` and
   `window-change` (T-126).
5. A full-screen program cannot run without a tty. When a submitted line
   starts with `vi`, `less`, `top` or `nano`, write one line on stderr
   ("needs a pty; this host has no /dev/ptmx"), then run it. T-248 studies
   how serve gives such programs a tty.
6. A `signal` request goes to the same group (T-108). Same commit:
   `docs/terminal.md`, the serve notes, `docs/STATUS.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_line
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test file crates/podssh-ssh/tests/serve_line.rs uses `--pty line`: Ctrl-C
ends `sleep 30` within 5 s, the next line runs, and output lines end in CR
LF. The gate runs the same through OpenSSH's `ssh -tt`, in the shape of
`scripts/interop.sh:249-258`: `AFTER-5` and exit 9 within 15 s. In the box
(no `/dev/ptmx`), a new step drives `podssh serve --stdio` with
`podman exec -i` from OpenSSH on the host. A planted serve that signals the
shell's pid and not its group fails the 15 s check.

# T-112: An SFTP server in `podssh serve`

**Source:** `docs/ROADMAP.md:189`, `docs/design.md:161-165`; GitHub #20
(tty7 issue #1126: bound every SFTP wait); GitHub #21 (bssh pipelined SFTP).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A cage has no `sftp-server`, `scp` or `rsync`, so files cannot move in or out
with standard tools. OpenSSH's `sftp`, and `scp` in its SFTP mode (the
default since OpenSSH 9.0), need an SFTP subsystem on the server.
`podssh cp` needs one too (T-134).

## Premise

- Read: no SFTP code exists, and `Cargo.lock` has no `russh-sftp`.
  `docs/ROADMAP.md:189` names `russh-sftp` for the client and the server.
- Read: russh gives a channel as a byte stream (`Channel::into_stream`), and
  `subsystem_request` must answer (`Eugeny/russh:russh/src/server/mod.rs`,
  lines 686-696 at `22c3b88`).
- Read: the client reaches an SFTP subsystem already: `-s sftp` gets
  `SSH_FXP_VERSION` from OpenSSH's `sftp-server` (`scripts/interop.sh:220-227`).
- Read in the report of GitHub #20, not verified here: tty7 issue #1126 is an
  SFTP wait that did not end; GitHub #15 is the same class in podssh.

## Approach

1. Add `russh-sftp` to `crates/podssh-ssh/Cargo.toml`, with a pinned version
   and a permissive license (podssh is 0BSD). Record the size cost in
   `docs/STATUS.md`.
2. `subsystem_request("sftp")`: success, then run the SFTP server on
   `channel.into_stream()`. Each other name gets failure.
3. A file-system handler in crates/podssh-ssh/src/server/sftp/: relative
   paths start at `HOME`, as OpenSSH's `sftp-server` does. Support open,
   read, write, close, stat, lstat, fstat, setstat, opendir, readdir,
   remove, mkdir, rmdir, rename, realpath, readlink and symlink, and the
   extensions `posix-rename@openssh.com` and `fsync@openssh.com` for T-134.
4. Invariants: each file-system call runs on a blocking thread with a time
   limit; past it, the reply is a failure with the reason, and the handle
   closes (a FIFO or a dead mount must not stop the session). At most 256
   handles and 256 KiB for each read; the memory of a session is bounded.
5. A cage has no chroot (`docs/target-environment.md:19`): the server reaches
   what the process user reaches. Say so in the manual.
6. `scp -O` (the old protocol) runs `scp -t` by exec and needs an `scp`
   program in the cage. Say that it fails with 127 there.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_sftp
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_sftp.rs checks the paths, the
handle limit and the time limit: a FIFO with no writer fails within the
limit. In the gate, scripts/interop-serve.sh runs OpenSSH's `sftp -b` through
`podssh serve --stdio`: a 5,000,000-byte put and get with equal SHA-256
digests, then mkdir, rename, rm and ls; `scp` up and down with equal digests.
A planted write handler that drops the last byte fails the digest check.

# T-113: M5 exit: a usable shell and 200 MiB each way from a sealed sandbox

**Source:** `docs/ROADMAP.md:198-202` (the exit criteria of M5).
**Category:** measurement
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

M5 ends with a measurement on a real host, not with passing unit tests. The
criterion: from a sealed sandbox (no ptmx, no passwd, no bind), an operator
gets a shell where `vi`, `less` and Ctrl-C work, and copies 200 MiB in and
out with matching digests.

## Premise

- Read: `podssh serve` runs in the sandbox as a node (T-107 on the runner of
  T-079), and the operator connects through the relay (T-084).
- Read: `vi`, `less` and `top` need a real pty (`docs/terminal.md:123-127`).
  The measured sandboxes have no `/dev/ptmx` (`docs/target-environment.md:26`,
  `docs/STATUS.md:151`). With no pty device, no podssh code can give the child
  a tty: shims are excluded (`docs/decisions.md:42`).
- Read: one relay session carries 64 MiB, both directions together
  (`docs/relay.md:163`; measured: `docs/STATUS.md:159`). 200 MiB each way
  needs the new sessions of T-137.
- Read: the box matches the sandbox, except the `EACCES` on loopback
  `connect()` (`scripts/test_in_box.sh:19-26`).

## Approach

1. Preconditions: T-107 to T-112, T-117, T-118, T-222, T-248 (with the work
   that it names) and T-133 to T-138 are done.
2. In the box first: a new step in `scripts/test_in_box.sh` starts
   `podssh serve NAME` in the box, and the host connects as the operator
   through the live relay.
3. The shell: `vi`, `less` and Ctrl-C work through the tty that T-248 gives
   where `/dev/ptmx` is missing (see Decision). Ctrl-C stops `sleep 30`, and
   the session continues.
4. The copy: 200 MiB of random data in, then out, with `podssh cp`. Compare
   SHA-256 at both ends, and count the relay sessions used.
5. Then the operator's real sandbox, with the same steps (the procedure of
   T-001).
6. Record each result with its date and command in `docs/STATUS.md`.

## Decision

Ruling of the operator (Q11, 2026-10-08): the exit criterion stays as it is,
with `vi`, `less` and Ctrl-C in a sealed sandbox. T-248 decides how a tty
exists where `/dev/ptmx` is missing, and this entry measures with the route
that T-248 chooses.

## Prove

```sh
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
grep -n 'podssh serve' docs/STATUS.md
```

The box run exits 0 when each serve step passes: `vi`, `less`, Ctrl-C, the
session that continues, and two 200 MiB copies with equal digests. The grep
shows the rows recorded for the box and for the real sandbox, with their
dates.

## Correction

The premise that no podssh code can give the child a tty where `/dev/ptmx` is
missing is too strong. The operator allows two routes, each after a probe at
run time (Q11, 2026-10-08), and T-248 studies them. The ban on `LD_PRELOAD`
stays (`docs/decisions.md:42`).

# T-114: `podssh serve`: access rules for each key and command

**Source:** GitHub #21 (agent-ssh-cli: command allow and deny lists);
GitHub #18 (sandhole: forwarding restrictions; iroh-ssh issue #47: a
hardened service); GitHub #19 (slingshot: a key for each client).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

After T-107, each authorized key gets everything: a shell, each command, each
forward and a pty. An operator who gives a CI job or an agent one key cannot
limit it to one command or one port. T-107 skips each key line with options,
so a key with limits cannot be used at all.

## Premise

- Read: T-107 skips option lines, so that no key is used without its limits.
  OpenSSH's `authorized_keys` options are the format that users know
  (sshd(8), section "AUTHORIZED_KEYS FILE FORMAT").
- Read: the patterns of `from=` are those of `known_hosts`, which
  `crates/podssh-ssh/src/known_hosts.rs:142-165` matches (negation included).
- Read: on the reverse road, serve does not know the client's address: the
  stream comes from the relay (`docs/relay.md:209-233`).
- Read in the reports of GitHub #21 and #18, not verified here: agent-ssh-cli
  checks regex lists before exec; sandhole limits local forwarding.

## Approach

1. Parse the options field: options separated by commas, quoted values with
   `\"`. Invariant: a line with an unknown or malformed option is skipped
   with a log line; it is never used without the option.
2. Support `restrict`, `command="..."` (forced; `SSH_ORIGINAL_COMMAND` holds
   the client's command), `no-pty` and `pty`, `no-port-forwarding` and
   `port-forwarding`, `permitopen="host:port"` (T-109), `from="patterns"`,
   and `expiry-time="YYYYMMDD[HHMM[SS]]"`. Accept `no-agent-forwarding` and
   `no-X11-forwarding` with no change: serve offers neither.
3. `from=` with no client address (the reverse road) never matches, so the
   key is refused there. It matches on a listener (T-124).
4. Refuse by name `environment=`, `tunnel=`, `principals=`, `cert-authority`
   and `permitlisten=` (see Decision).
5. Apply the rules where each request is answered (T-108 to T-112). Log a
   refusal with the fingerprint and the rule.
6. Same commit: `docs/cli.md` (the supported options), the serve notes.

## Decision

Recommendation: OpenSSH's options, not podssh's own regex lists. A regex list
of commands is easy to pass with shell syntax (`cmd; other`), while
`command=` with a wrapper is the known pattern, and users have such files.
`environment=` and `permitlisten=` stay refused until a need is recorded: the
first sets variables that T-108 filters, and the second needs a listener.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_options
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_options.rs parses the option
examples of sshd(8) and skips malformed lines. In the gate, OpenSSH through
`podssh serve --stdio`: `command="echo forced"` runs `echo forced` for each
request and sets `SSH_ORIGINAL_COMMAND`; `no-pty` gives `ssh -tt` no pty;
`permitopen="127.0.0.1:2201"` lets `-W 127.0.0.1:2201` through and refuses
`-W 127.0.0.1:2203`; `restrict` refuses a pty and a forward; a past
`expiry-time` refuses the key. A planted parser that ignores `restrict` fails
the pty check.

# T-115: `podssh serve`: a TOTP second factor

**Source:** GitHub #18 (VLOD-ZDOV/quic-ssh `src/totp.rs`: TOTP with no PAM).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A key file that leaks gives full access to a node. Some operators want a
second factor, as sshd with PAM gives, but a cage has no PAM. A time-based
one-time code (TOTP) needs only a shared secret and a clock.

## Premise

- Read: russh supports a second method after the first: a key accepted with
  partial success, then `auth_keyboard_interactive`
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 175-208 and 309-318).
- Read: podssh's client answers keyboard-interactive after a partial success
  (`crates/podssh-ssh/src/auth.rs:104-111`,
  `crates/podssh-ssh/src/auth.rs:151-204`), through the terminal or
  `SSH_ASKPASS`.
- Read: HMAC and SHA-1 are dependencies already
  (`crates/podssh-ssh/Cargo.toml:23-24`).
- Read in the report of GitHub #18, not verified here: quic-ssh has TOTP in
  `VLOD-ZDOV/quic-ssh:src/totp.rs`.

## Approach

1. `--totp FILE`: the secret (base32) in a file of mode 0600. serve refuses
   to start when others can read the file. Never print the secret.
2. `--totp-new FILE` writes a new secret (`create_new`, mode 0600) and prints
   only the path; the user loads the file into an authenticator. Invariant:
   no secret in output, logs or argv.
3. Authentication: a good key gives partial success with
   `keyboard-interactive` next; one prompt "One-time code: " with no echo;
   RFC 6238 (HMAC-SHA-1, 30 s, 6 digits), one step of clock skew each way.
4. Refuse a code that was used in its step (a replay). Count the failures of
   each key, and wait longer after each one.
5. Same commit: the flags in `crates/podssh-cli/src/flags.rs`, the manual,
   `docs/cli.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_totp
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_totp.rs checks the SHA-1 vectors
of RFC 6238 appendix B, the skew window and the replay refusal. In the gate,
OpenSSH's client gets the code from `SSH_ASKPASS` that runs
`oathtool --totp -b` (an Alpine package), so the code does not come from
podssh: the login works, a second use of the same code is refused, and a
wrong code is refused. A planted check that ignores the step fails the
replay test.

# T-116: `podssh serve`: an audit log

**Source:** GitHub #25 (ImKKingshuk/USBoverSSH `usboverssh/src/audit.rs`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The owner of a node cannot see who logged in, with which key, and what each
session did. sshd writes this to the system log, but a cage often has no
syslog and no `/var`. A record must not leak secrets or session data.

## Premise

- Read: podssh's log goes to stderr or to a file
  (`crates/podssh-ssh/src/log.rs:23-33`), as lines with no structure.
- Read: `serde_json` is a workspace dependency (`Cargo.toml:101`), but not a
  dependency of `podssh-ssh` yet.
- Read in the report of GitHub #25, not verified here: USBoverSSH writes an
  audit log of connection events.

## Approach

1. `--audit-log FILE`: one JSON object for each line, appended, mode 0600;
   off by default. Fields: the time (UTC, RFC 3339), the event, the session
   number, the key fingerprint, the request (shell, exec, subsystem, forward
   target), the exit status or signal, the bytes each way, the duration.
2. Events: authentication accepted and refused (fingerprint, method), a
   session start and end, a forward opened or refused, serve's start and
   stop.
3. Invariants: never key material, tokens, environment values or session
   data. The command line of an exec is written only with `--audit-commands`,
   because a command line can hold a password.
4. A failed write (a full disk) is reported once on stderr, and never stops
   a session.
5. Same commit: the flags, the manual, `docs/cli.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_audit
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_audit.rs reads each line as JSON
and checks the fields of each event. In the gate, a session through
`podssh serve --stdio --audit-log FILE` runs `echo SECRET-MARKER`: the file
has the login and the exit status, and `grep -c SECRET-MARKER` on it prints 0.
With `--audit-commands` it prints 1. A planted log of each command line by
default fails the first count. A file that cannot be written does not stop
the session.

# T-117: `podssh serve`: a clean stop, and SIGHUP reads the settings again

**Source:** GitHub #20 and GitHub #19 (gold-silver-copper/fux: a clean server
lifecycle); GitHub #22 (Petyok/SSHub: hot reload).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

A node that stops must not leave shells behind, and must not cut sessions
with no word. An operator who adds a key must not have to restart the node:
a restart ends each session on it (`docs/design.md:191-194`).

## Premise

- Read: the client ends its session properly on SIGTERM and SIGHUP
  (`crates/podssh-ssh/src/io.rs:229-262`). The server has no such handling.
- Read: russh can end a connection with a reason: `Handle::disconnect`
  (`Eugeny/russh:russh/src/server/session.rs`, line 457 at `22c3b88`).
- Read: in `--stdio` mode one process serves one connection. The node mode
  (`podssh serve NAME`, after T-079) serves many, so a reload matters there.

## Approach

1. SIGTERM and SIGINT: take no new session (the node leaves the relay
   cleanly, T-079). Send each connection a disconnect with the reason
   "podssh serve is stopping", and SIGHUP to each child's process group.
   Wait 5 s at most, then SIGKILL. Exit 0.
2. SIGHUP: read the authorized keys and the settings files again. New
   connections use the new set; open sessions continue. A file that does not
   parse keeps the old set and logs one line. Invariant: a reload never gives
   access that the new files do not give, and never drops a session.
3. A second SIGTERM during the stop sends SIGKILL at once.
4. Same commit: the exit codes and messages in the serve section of the
   manual, `docs/cli.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_lifecycle
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_lifecycle.rs serves two streams
in memory from one server: a reload adds a key for the second stream and
keeps the first session; a broken file keeps the old keys. In the gate,
OpenSSH's client runs `sleep 100` through `podssh serve --stdio`; a SIGTERM to
serve ends the client within 5 s with the reason, and `pgrep -f 'sleep 100'`
then finds nothing. A planted stop with no SIGHUP to the group fails that
last check.

# T-118: `podssh serve`: a slow client cannot stall a pty or fill the memory

**Source:** GitHub #20 (gold-silver-copper/fux `tests/pressure.rs`: bound the
queue; detach on a failed write).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

A program in the cage can write faster than the relay and the client read
(`yes`, a large `cat`). If serve reads the pty or the pipe faster than it
sends, its memory grows until the cage stops it. A client that stops reading
must slow the child down, and a client that is gone must end the session.

## Premise

- Read: russh keeps data past the peer's window in a list for each channel
  (`Eugeny/russh:russh/src/session.rs`, lines 591-612). While any channel has
  such data, the session loop takes no message from `Handle`
  (`Eugeny/russh:russh/src/server/session.rs`, lines 676-700 and 791): one
  slow channel then stops the other channels of that connection.
- Read: a channel's writer waits for that channel's own window
  (`Eugeny/russh:russh/src/channels/io/tx.rs`, lines 82-105).
- Read: russh opens the window again when half of it has arrived, whether or
  not the program read it (`Eugeny/russh:russh/src/session.rs`, lines
  305-330). A child that does not read its stdin is held only by the channel
  buffer of 100 messages (T-108).
- Read: the comment on the SSH window said that the relay drops a frame
  past 1 MiB with 1011 (`crates/podssh-ssh/src/run.rs` lines 25-29 at
  `80f20bf`); `docs/relay.md:176-180` says that it closes with 1013 at
  2 MiB. T-024 corrected the comment; T-062 measures whether the relay's
  check operates.

## Approach

1. Output (the pty, stdout, stderr): write only through each channel's
   writer (`make_writer`, `make_writer_ext(Some(1))`); never `Session::data`
   in a loop. Read the child again only after the last chunk was written.
   Invariant: for each channel, serve holds one read buffer (32 KiB) past
   the window.
2. A stalled client then stops the reads, the pty or pipe buffer fills, and
   the kernel blocks the child's write. That is the flow control.
3. A failed write (the client is gone) ends the channel: close the master or
   the pipes, and send SIGHUP to the child's group.
4. Input: copy each channel into the child on its own task, with a stated
   cap. Measure whether a child that never reads stalls the other channels
   of its connection; if it does, write an entry for it with the russh lines,
   and close only that channel past the cap.
5. State the bounds in the serve notes and in `docs/STATUS.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_pressure
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_pressure.rs runs `yes` on a pty
with a client that reads nothing for 20 s: serve's resident memory (`VmRSS`
in `/proc/self/status`) grows by less than 8 MiB, and the session then
continues. In the gate, OpenSSH's client runs `yes` through
`podssh serve --stdio` with a reader that stops for 20 s: the same bound
holds, and a killed client ends `yes` within 5 s. A planted `Session::data`
loop fails the memory bound.

# T-119: `podssh serve`: the MOTD and `~/.hushlogin`

**Source:** GitHub #19 (menhera-org/ssh-obi: the MOTD before the login shell,
and `~/.hushlogin`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

sshd shows the message of the day before an interactive login shell, and
skips it when `~/.hushlogin` exists. Users expect the same from a node: for
example, a notice that the host is a sandbox that expires.

## Premise

- Read: T-108 starts a login shell, and nothing prints before it.
- Read: a cage may have no `/etc/motd` and no `/var`
  (`docs/target-environment.md:16-29`); serve reads only what exists.
- Read: podssh already makes server text safe for a terminal:
  `crates/podssh-ssh/src/handler.rs:88-91` uses `podssh_ws::text::multi_line`.
- Read in the report of GitHub #19, not verified here: ssh-obi prints the
  MOTD before the login shell and honours `~/.hushlogin`.

## Approach

1. For a shell request with a pty (or the line discipline of T-111), print
   the file of `--motd FILE`, else `/etc/motd` when it can be read, before
   the shell starts. Never for exec or a subsystem.
2. Skip it when `$HOME/.hushlogin` exists (the home from `HOME`).
3. Limits: 64 KiB at most; control characters other than tab and newline
   are removed with `podssh_ws::text::multi_line`.
4. Same commit: the flag in `crates/podssh-cli/src/flags.rs`, the manual.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_motd
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_motd.rs checks the cap and the
removed control characters. In the gate, with a `--motd` file, an interactive
`ssh -tt` session shows it before the first prompt; an exec session does not;
with `$HOME/.hushlogin`, the shell does not. A planted serve that prints it
for exec fails the second check.

# T-120: `podssh serve`: shell integration marks, when asked

**Source:** GitHub #20 (l0ng-ai/tty7
`l0ng-ai/tty7:crates/tty7-core/src/daemon/shell_integration.rs`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Terminals use OSC 133 marks (prompt, command, output, exit status) and OSC 7
(the working directory) to jump between commands and to open a new tab in
the same directory. Over a node, the shell sends no marks unless its start
files add them, and many cage images have none.

## Premise

- Read: in the line discipline mode (T-111), serve prints the prompt and
  sees each submitted line (`crates/podssh-terminal/src/echo.rs:246-256`),
  so it knows where each mark goes.
- Read: with a real pty (T-110), only the shell knows; it needs hooks in its
  start files.
- Read in the report of GitHub #20, not verified here: tty7 adds shell
  integration when a pane starts.

## Approach

1. `--shell-integration`, off by default.
2. Line discipline mode: write `OSC 133;A` before the prompt, `B` after it,
   `C` when a line is submitted, and `D` when the next prompt comes. With no
   help from the shell, the exit status is not known: write `D` with none.
3. Real pty: start `bash` with `--rcfile` set to a temporary file that reads
   `~/.bashrc` and adds the hooks; start `zsh` with `ZDOTDIR` set to a
   temporary directory that reads the user's files. Other shells get no
   marks. Invariant: never write the user's own start files.
4. Remove the temporary files when the session ends.
5. Same commit: the flag, the manual, `docs/terminal.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_marks
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_marks.rs checks the bytes of the
marks in the line discipline mode. In the gate, `ssh -tt` through
`podssh serve --stdio --shell-integration` to `bash` shows `ESC ] 133;A` and
`ESC ] 7;file://` in the output, and the SHA-256 of `~/.bashrc` is the same
before and after. Without the flag, no mark appears. A planted run that
appends to `~/.bashrc` fails the digest check.

# T-121: Install `podssh serve` or `podssh node` as a service with no privileges

**Source:** GitHub #20 (l0ng-ai/tty7: a one-time install with no privileges);
GitHub #18 (adonm/zuko `zuko install`; rustonbsd/iroh-ssh: a Linux and
Windows service).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A node that must outlive a logout or a reboot needs a service. The usual ways
(`systemctl enable`, a Windows service) need root or an administrator. A user
with no privileges needs a way that the host allows, found by a probe.

## Premise

- Read: podssh never assumes a tool or a privilege; it starts a program only
  when a probe found it (`AGENTS.md:176-188`).
- Read: a credential never goes on argv or into output (`AGENTS.md:153-156`).
  The command line of a unit file is argv, so it must hold no token.
- Read in the reports of GitHub #20 and #18, not verified here: tty7, zuko
  and iroh-ssh install services, and iroh-ssh adds a firewall rule (which
  needs privileges).

## Approach

1. `--install` and `--uninstall` for `serve` and `node`; settle the names in
   `crates/podssh-cli/src/flags.rs`.
2. Probe in order: `systemctl --user` answers (then a user unit in
   `~/.config/systemd/user/`, and `systemctl --user enable --now`); a
   `crontab` program (an `@reboot` line); else print the command to run at
   login, and exit 69. Windows: `schtasks` with a task at logon, which needs
   no administrator; never a Windows service.
3. The unit or task runs the binary at its absolute path with the node name.
   The tokens stay in the 0600 state file of T-078. Invariant: no credential
   in the unit file, the crontab or the task's command line.
4. A user unit stops at logout unless lingering is on. Say so, and never run
   `loginctl` for the user.
5. `--uninstall` removes exactly what `--install` wrote, and nothing else.
6. Same commit: the manual, `docs/cli.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_install
```

The test file crates/podssh-cli/tests/serve_install.rs writes the unit, the
crontab line and the task XML into a temporary home with fake probe answers.
Each holds the absolute path and the name, and none holds the token that the
test puts in the environment. `--uninstall` leaves the home as it was. A
planted unit with the token on its command line fails. A run on a host with
systemd is recorded in `docs/STATUS.md`.

# T-122: `podssh serve`: each pty child in its own transient scope when systemd is there

**Source:** GitHub #20 and GitHub #19 (menhera-org/ssh-obi `src/systemd.rs`:
no systemd assumption).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

On a host with systemd, the children of a service live in the service's
cgroup. A stop of the `podssh serve` unit (T-121) then stops each user's shell
too, and their memory counts against serve. sshd moves each session to its
own scope; serve does nothing like it.

## Premise

- Read: podssh must not assume systemd, and starts a program only when a probe
  found it (`AGENTS.md:176-188`, `docs/target-environment.md:90-92`).
- Read: T-110 and T-111 start each child with `setsid`, in serve's cgroup.
- Read in the report of GitHub #19, not verified here: ssh-obi moves its pty
  children into a transient scope when systemd is there, and works without
  it.

## Approach

1. Probe once at the start of serve: `systemd-run` on `PATH`, and
   `systemctl --user is-system-running` answers within 2 s.
2. When both pass, start each pty child through
   `systemd-run --user --scope --unit=podssh-serve-<session> -- SHELL ...`.
   The scope keeps the child's process tree; `setsid` and the controlling
   tty work as before.
3. When the probe fails, start the child directly, as now, with one log line
   at the start. Invariant: no session fails because systemd is absent or
   slow.
4. A failure of `systemd-run` for one session falls back to a direct start,
   with one log line.
5. Same commit: the serve notes, `docs/STATUS.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_scope
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test file crates/podssh-ssh/tests/serve_scope.rs checks the command line
that is built, and the fallback when the probe fails. The box has no systemd,
so its serve steps show that sessions work and the log names the fallback. On
a host with systemd, `systemctl --user list-units 'podssh-serve-*'` lists the
scope of an open session; that run is recorded in `docs/STATUS.md`.

# T-123: `podssh serve` accepts `tcpip-forward` from a standard `ssh -R`

**Source:** GitHub #18 (EpicEric/sandhole: reverse proxying through a stock
`ssh -R`, with no other software on the client).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A user who runs `ssh -R 8080:localhost:3000 node` expects a port of the node
to reach the user's local service. In a cage, `podssh serve` cannot do it in
the usual way: the server must listen, and the cage refuses `bind`. Today the
default of russh refuses each `tcpip-forward` with no reason.

## Premise

- Read: the default `tcpip_forward` of russh answers false
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 771-779).
- Read: the cage refuses `bind` (`docs/target-environment.md:25`; the box:
  `scripts/box/probe.sh:86-91`). The operator's ruling on Q1 (2026-10-08)
  allows a listener only when the user asks and a probe allows the bind.
- Read: `docs/design.md:269-271` allows a listener on the far side. The relay
  is a listener that podssh does not run: a node name takes operator
  sessions (`docs/relay.md:209-233`).
- Read in the report of GitHub #18, not verified here: sandhole publishes
  services through a stock `ssh -R`.

## Approach

1. No bind in the cage. Answer `tcpip-forward` with a new pair at the relay
   (T-078). Each operator session on that name opens a `forwarded-tcpip`
   channel to the client, toward the address and port of the request.
   Invariant: serve binds no socket for `-R`.
2. Answer success, with a port number for a request of port 0. Give the relay
   name in serve's log, and on stderr of the client's session when one is
   open. Measure what OpenSSH shows of an `SSH_MSG_DEBUG` with
   `always_display` set.
3. `cancel-tcpip-forward` stops the pair (`POST /v1/stop`, T-078). The tokens
   of the pair never go to output.
4. A real listener on the node only when serve's user turns it on and the
   bind probe of T-124 passes (loopback by default); else the pair of step 1.
5. Limits: a stated number of forwards for each connection; each forward
   ends with its connection.
6. Same commit: `docs/cli.md`, the serve notes.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_remote_forward
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_remote_forward -- --ignored
```

The first runs the mapping from a request to a pair and a channel, against a
stand-in relay in memory. The second uses the live relay: OpenSSH's
`ssh -R 0:127.0.0.1:2201` through `podssh serve --stdio`, then
`podssh operator NAME` reads the banner of the client's port 2201. A planted
serve that binds a socket fails a check that counts the open sockets of serve.

# T-124: `podssh serve --listen`: SSH on a TCP port on a host that allows it

**Source:** GitHub #18 (EpicEric/sandhole `src/config.rs`, lines 197-210:
`connect_ssh_on_https_port`; VLOD-ZDOV/quic-ssh: TLS over TCP on one port);
the operator's ruling on Q1 (2026-10-08).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Outside a cage, an operator may want `podssh serve` as a plain SSH server: on
a VM with no sshd, or on a network that lets only port 443 in. Without
`--listen`, serve reaches clients only through `--stdio` and the relay.

## Premise

- Read: the operator ruled on Q1 (2026-10-08): a local listener is allowed
  when the user asks for it and a probe at run time allows the bind. The
  default is loopback and AF_UNIX; the user can set the address and can turn
  listening off. The rules still say that podssh never listens
  (`AGENTS.md:178-183`, `docs/architecture.md:101-108`).
- Read: russh has the listener: `Server::run_on_socket` and `run_on_address`
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 900-1010 at `22c3b88`). doctor binds a
  TCP and an AF_UNIX socket to test the host, and closes them at once
  (`crates/podssh-cli/src/doctor/unix.rs:137-188`).
- Read in the report of GitHub #18, not verified here: sandhole can take SSH
  on its HTTPS port, and quic-ssh falls back to TLS over TCP on one port.

## Approach

1. The probe first. Before each bind, run doctor's bind probe for that exact
   address. When it fails, exit 69 with one line that names the address, the
   errno and the remedy, for example "cannot listen on 127.0.0.1:2222: bind
   refused (Permission denied); use --stdio or podssh serve NAME". Invariant:
   no listener without the flag and a probe that passed.
2. `--listen ADDR`, which can be given more than once: `PORT` alone is
   loopback, `unix:PATH` is AF_UNIX, and another address only when the user
   writes it. Listening is off unless asked; `--no-listen` turns off a
   listener that a settings file asks for (T-048).
3. Each accepted connection goes to the entry point of `--stdio` (T-107).
   `from=` of T-114 now has a client address to match.
4. Limits: a cap on connections at once and on connections that have not
   authenticated, and russh's constant rejection time.
5. Later step: SSH and TLS on one port. Read the first bytes: `SSH-2.0-` goes
   to SSH; a TLS ClientHello (0x16) is refused.
6. Same commit: the flags, the manual, `docs/cli.md`, and the rules in
   `AGENTS.md:178-183` and `docs/architecture.md:101-108`, which then name this
   exception and the ruling.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_listen
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test file crates/podssh-ssh/tests/serve_listen.rs binds loopback port 0
and an AF_UNIX path, and checks the connection caps. In the gate, OpenSSH's
`ssh -p PORT` logs in to `podssh serve --listen PORT`. In the box, where the
seccomp filter refuses `bind`, a new step shows that serve exits 69 with the
line that names the address and the errno. A planted serve that binds before
the probe, or with no `--listen`, fails a check of its open sockets.

# T-222: `podssh serve` finds a shell with no passwd entry and no `/etc/shells`, and names each candidate that failed (GitHub #32)

**Source:** GitHub #32 (2026-10-08); each claim read again here on the tree
of 2026-10-08 (code at `3ee70dc`).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`podssh serve` runs with no passwd entry and no `/etc/shells`
(`docs/ROADMAP.md:177-182`), so no user database names a shell. A shell that
does not exist lets the login succeed, then ends the session at once, with
no reason (`docs/target-environment.md:63-64`).

## Premise

- Read: no source in `crates/` reads `SHELL` or selects a shell; `serve` is
  not a verb (`crates/podssh-cli/src/flags.rs:412-443`). The line numbers in
  the report are older; the content is at the lines given here.
- Read: the report says that `docs/cli.md` records why podssh does not call
  `getpwuid`. It does not; that record is `docs/target-environment.md:37-44`.
- Read: a sandbox mounts `/tmp` and `$HOME` noexec (`docs/STATUS.md:151`):
  the mode bits pass there, the exec fails, and `access(X_OK)` fails. doctor
  runs a real copy, as "only a real attempt tells them apart"
  (`crates/podssh-cli/src/doctor/host.rs:157-159`).
- Read in the report, not verified here: `rssh-org/rssh:src-tauri/src/terminal/pty.rs`
  checks the exec bit; a directory `sh` and a data file `dash` pass `exists()`.

## Approach

1. A function in crates/podssh-ssh/src/server/shell.rs gives the shell, or
   each failure. Order: the named shell (`--shell PATH`, or a later field of
   the pairing record of T-078), `SHELL`, then `/bin/sh`, `/usr/bin/sh`,
   `/bin/bash`, `/usr/bin/bash`, `/bin/ash` and `/bin/dash`.
2. Each candidate: an absolute path, a regular file after its links, and
   `faccessat(X_OK, AT_EACCESS)`; `exists()` is not the test. Read access is
   not needed. A spawn that still fails (`ENOEXEC`, a missing loader) fails
   that candidate, and the next one is tried.
3. One line names each failure and why, for example
   `SHELL=/x: not executable (noexec mount); /bin/bash: no such file`.
4. Probe at each session start, with no cache: the answer can change in the
   same image (`docs/target-environment.md:90-92`). Probe at the start of
   serve too (see Decision).
5. doctor gets a `shell` line in its host checks
   (`crates/podssh-cli/src/doctor/host.rs:10-25`) from the same function.
6. T-108 runs the result. Never call `getpwuid`. Same commit: `--shell` in
   `crates/podssh-cli/src/flags.rs`, `SHELL` in
   `crates/podssh-cli/src/man/facts.rs:45-109`, `docs/cli.md`.

## Decision

Recommendation: a shell that the operator names is strict: when it fails,
serve refuses (exit 78 at the start, failure for a session) and uses no
other. `SHELL` and the list fall back in order, and the line names each
failure, so no probe changes the behaviour in silence
(`docs/target-environment.md:90-92`). At the start, no usable shell is exit
78, unless `--no-shell` says that the node serves only SFTP and forwards.
Starting with a warning lost: that is the login that ends at once.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_shell
sh scripts/dev.sh check
"$BIN" serve --stdio --authorized-keys ak --shell /nonexistent </dev/null 2>err; test $? -eq 78
grep -q '/nonexistent: no such file' err
```

crates/podssh-ssh/tests/serve_shell.rs gives the function a directory `sh`,
a data file `dash` (mode 0644), a data file with mode 0755 (the spawn fails),
a link to a missing file and a good shell: each failure is named, and the
good shell wins. A planted `exists()` test fails the directory case. In the
gate, a copy of `/bin/sh` in `/dev/shm` (noexec: `docs/STATUS.md:118`) is
refused as `--shell`. The static binary (`$BIN`) refuses a missing named shell.

# T-248: A tty for `podssh serve` where `/dev/ptmx` is missing: a new devpts instance, or a tty in user space

**Source:** the operator's ruling of 2026-10-08 on T-113 (`docs/decisions.md`):
the exit criterion of M5 keeps `vi`, `less` and Ctrl-C, and two routes to a
tty are allowed after a probe; "the boxes don't have user namespaces, but
sure if it works". The study of rio-vt in the same session found that a VT
library cannot give a child a tty.
**Category:** research
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

In a cage with no `/dev/ptmx`, `podssh serve` can give a child only pipes.
For the child, `isatty()` is false, termios calls fail, no SIGWINCH comes, and
there is no job control. `vi`, `less` and `top` do not work, and the exit
criterion of M5 (T-113) needs them.

## Premise

- Read: `podssh doctor` asks for a pty with `posix_openpt`
  (`crates/podssh-cli/src/doctor/unix.rs:78-93`). Both real sandboxes have no
  `/dev/ptmx` (`docs/STATUS.md:151`), and the target has no `/dev/pts`
  (`docs/target-environment.md:26`).
- Read: the box and the sandboxes run with `NoNewPrivs=1` and a seccomp
  filter (`docs/STATUS.md:130`). With `NoNewPrivs=1`, a process can add a
  filter of its own; a filter is inherited by each child.
- Read, not measured here: for a program, a tty is the success of the tty
  `ioctl` calls on its descriptors. musl's `isatty` calls `TIOCGWINSZ`;
  glibc's calls `TCGETS`.
- Not measured: whether a sandbox allows `unshare(CLONE_NEWUSER)`, a devpts
  mount in that namespace, seccomp user notification, `process_vm_writev` to
  a child, or `ptrace` of a child. The operator: the boxes have no user
  namespaces.

## Approach

1. Probes, each one line in `podssh doctor` and a check at the start of
   `podssh serve`, each in a child process that exits at once:
   - route 1: `unshare(CLONE_NEWUSER | CLONE_NEWNS)`, a private tmpfs, a
     devpts mount with `newinstance` on it, then `ptmx` from that mount;
   - route 2a: a filter that returns `SECCOMP_RET_USER_NOTIF` for `ioctl`
     only, its notification descriptor, and `process_vm_writev` into the
     child;
   - route 2b: `PTRACE_TRACEME` with a filter that returns
     `SECCOMP_RET_TRACE` for `ioctl` only.
2. Route 1: when its probe passes, the child runs in the new namespaces with
   a pty of the new instance. The rest is T-110.
3. Route 2: the child's descriptors 0, 1 and 2 are pipes. podssh answers the
   tty calls on them: `TCGETS`, `TCSETS`, `TCSETSW`, `TCSETSF`,
   `TIOCGWINSZ`, `TIOCSWINSZ`, `TIOCGPGRP`, `TIOCSPGRP`, `TIOCSCTTY`,
   `TIOCNOTTY`, `TIOCGSID`, `FIONREAD`, `TCFLSH`, `TCXONC` and `TIOCOUTQ`.
   Each other call goes on to the kernel. Invariant: podssh puts no code into
   the child, and it answers only for the descriptors that it gave.
4. The answered termios state drives the line discipline of
   `podssh-terminal`: canonical mode, echo, `ISIG`, `VMIN` and `VTIME`
   (T-111, after T-125 to T-129). A window change sends SIGWINCH to the
   foreground process group. Ctrl-C, Ctrl-Z and Ctrl-\ send SIGINT, SIGTSTP
   and SIGQUIT to that group.
5. Name what still fails: `ttyname()` (a pipe has no tty name), a program
   that opens `/dev/tty`, and a child that clears the filter (it cannot: a
   seccomp filter cannot be removed).
6. Measure each route in the box, with both profiles of T-245, and in both
   real sandboxes: `vi`, `less`, `top`, Ctrl-C, Ctrl-Z and a window change.
   Write the results in `docs/STATUS.md`, the order of the routes in
   `docs/decisions.md`, and the entries for the implementation.

## Decision

Recommendation: route 1 first where its probe passes, because it is a real
pty with no emulation. Route 2 where route 1 fails: user notification first
(only `ioctl` stops the child), `ptrace` as the fallback. `LD_PRELOAD` lost:
the decisions forbid it, and it does nothing to a static binary.

## Prove

```sh
podssh doctor                                      # one line for each route: ok, or the errno
cargo test -p podssh-terminal                      # the termios model and the line discipline
cargo test -p podssh-cli --test serve_tty          # a child under route 2: test -t 0, stty size
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test in the box runs `vi`, `less` and `top` through `podssh serve
--stdio` with no `/dev/ptmx`, and reads the screen of each. Planted defect:
answer `TCGETS` with an error; `test -t 0` in the child then fails, and the
test fails.
