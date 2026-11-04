File copy: the SFTP client in the process, `podssh cp` and `podssh mv`, the
command lines of `scp` and `sftp`, and the copy features of the backlog.
T-133 to T-139 are milestone M5; T-140 to T-150 wait until the operator
schedules them. Each entry keeps one invariant: each SFTP request, each exec
step and each open of a session has a time limit.

# T-133: An SFTP client in the process, the base of `cp`

**Source:** ROADMAP M5 ("SFTP in the process"), `docs/design.md:629-633`;
GitHub #20 (Nemo-010, 2026-10-08: "Bound every SFTP/PTY wait", after tty7's
issue 1126).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh has no SFTP client. `podssh ssh -s host sftp` passes bytes, but no
podssh code speaks the protocol, so `cp`, `mv`, `scp` and `sftp` have no
base. A client that waits for a reply with no limit can stop a script for
ever (tty7's issue 1126, read in GitHub #20; GitHub #15 was this class).

## Premise

- Read, at `61eceeb`: no line of `Cargo.lock` contains `sftp`; `podssh-ssh`
  has `russh` 0.64.1 only (`crates/podssh-ssh/Cargo.toml` line 18,
  `Cargo.lock` lines 3020-3022).
- Read, at `61eceeb`: the subsystem request exists
  (`crates/podssh-ssh/src/session.rs` lines 68-71); `wait_reply` counts 30 s
  of silence as a refusal (`crates/podssh-ssh/src/session.rs` lines
  111-123). The handshake has a limit (`crates/podssh-ssh/src/run.rs` lines
  144-150); the authentication after it has none
  (`crates/podssh-ssh/src/run.rs` line 166).
- Measured on 2026-10-08, offline: the `sftp-server` of OpenSSH 10.3p1 (Git
  for Windows), driven over its stdin and stdout, answers version 3 with the
  `@openssh.com` extensions posix-rename, statvfs, fstatvfs, hardlink,
  fsync, lsetstat, limits, expand-path and users-groups-by-id, and with
  `copy-data` and `home-directory`. Its limits: packets of 262144 bytes,
  reads and writes of 261120 bytes, 3195 handles. No extension gives a
  digest.
- Read: that server exits at the end of its input without its last reply
  (`scripts/interop.sh:368-370`).

## Approach

1. Read `russh-sftp` before it enters `Cargo.lock`: version, license,
   minimum Rust (1.89 at most, `crates/podssh-ssh/Cargo.toml:8`), no C, and
   a limit for one request. Record the result in `docs/STATUS.md`.
2. A new module crates/podssh-ssh/src/sftp/ (files of 500 lines or fewer):
   a session channel, `subsystem sftp` through `wait_reply` (made
   `pub(crate)`), then SFTP on the channel's stream. A refused subsystem is
   the typed error `NoSftp`, the only error that T-135 falls back on.
3. Move the hop chain of `crates/podssh-ssh/src/run.rs` lines 78-91 at
   `61eceeb` into one function that returns the handles, for `session::run` and
   for SFTP.
4. Invariant: no request and no step of the open waits without a limit.
   Three named constants, shown by the manual: 30 s for a metadata reply (as
   `REPLY_WAIT`), 60 s with no data acknowledged (`docs/design.md:653`),
   and the `--timeout` deadline over all, authentication included. Wrap a
   call in `tokio::time::timeout` where the crate has no limit.
5. Size the requests from `limits@openssh.com`, else 32 KiB. Keep the
   extension list for T-134.
6. Each `SSH_FX_*` status gives a sentence with the path; the server's text
   goes through `podssh_ws::text::one_line`
   (`crates/podssh-ssh/src/io/msg.rs:47`).
7. No EOF before the last reply. Fail at once on a reply id that no request
   has, and on a `READ` reply longer than its request.

## Decision

Recommendation: `russh-sftp`, as ROADMAP M5 names it, with a limit on each
call. A client of SFTP version 3 written in `podssh-ssh` replaces it only
when step 1 finds a blocker: a request that cannot be limited, C code, a
minimum Rust above 1.89, or no requests in flight together (bssh patches
its copy for that, read in GitHub #21). Our own client lost as the first
choice: a second protocol implementation to fuzz (T-198) and to test.

2026-10-09, step 1 read: `russh-sftp` 3.0.1 (Apache-2.0) has no blocker. It
is pure Rust; its new crates are `dashmap`, `serde_bytes`,
`crossbeam-utils`, `parking_lot_core` and a second `hashbrown` (0.14), and
`gloo-timers` and `redox_syscall` only for wasm32 and Redox. It declares no
minimum Rust, and builds on 1.89 in the gate's `msrv_ssh` step. Each request
has a limit (`request_timeout_secs`, whole seconds), and requests are in
flight together (a map of the waiting ones). So `russh-sftp`, as the
recommendation says. Its limit is one for each session, so the module sets
it to the data limit (60 s), and puts the 30 s of a metadata reply around
each such call itself.

## Prove

```sh
cargo test -p podssh-ssh --test sftp_client             # OpenSSH's sftp-server, over pipes
cargo test -p podssh-ssh --test sftp_client -- silent   # a peer that never answers
sh scripts/dev.sh check                                 # the same tests in the gate
```

The new crates/podssh-ssh/tests/sftp_client.rs runs the `sftp-server` that
`PODSSH_TEST_SFTP_SERVER` names; the gate installs `openssh-sftp-server`
before its test step and sets it, and a name with no program fails. Each
request agrees with the files on disk; each `silent` request fails within
its limit plus 1 s. Plant: remove one limit; the test must then fail on its
own outer limit of 10 s.

## Correction

2026-10-09. **Step 7's unknown reply id**: `russh-sftp` drops a reply whose
id no request waits for, since it may answer a request that timed out; the
module cannot see it. The request that waited for the reply fails at its own
limit, not at once. The rest of step 7 holds: the end of input goes to the
server only after each reply (`Sftp::close_session` takes the session), and a
`READ` reply longer than its request fails. **Step 4's manual**: the module
names its limits (`METADATA_WAIT`, `DATA_WAIT`), and a command's deadline is
its own `--timeout`; no command opens SFTP yet, so the manual names them
with `cp` (T-134). **The Prove's `-- silent`** runs the three tests of a peer
that never answers; the tests of a long `READ` reply and of a peer that
leaves run with the others.

## Done

2026-10-09, in the commit "podssh-ssh has an SFTP client, with a limit on
each step".

- `crates/podssh-ssh/src/sftp/`: `Sftp::open` asks a new session channel
  for the `sftp` subsystem through `session::wait_reply` (now `pub(crate)`),
  and a refusal or no answer is `SftpError::NoSftp`; `Sftp::over` runs the
  version exchange on any stream, and reads `limits@openssh.com` (requests
  of the server's size, else 32 KiB, never over 255 KiB). `stat`, `lstat`,
  `realpath`, `open_file`, `close`, `read`, `write`, `fsync`, `remove`,
  `rename` (over the target with `posix-rename@openssh.com`), `mkdir`,
  `rmdir`, `read_dir` and `close_session`, each within its limit.
  `SftpError` gives each status a sentence with the path, and the server's
  text on one line.
- `run.rs`: `connect_hops`, the hop chain in one function, for `ssh` and
  for SFTP. `Cargo.toml` and `Cargo.lock`: `russh-sftp` 3.0.1.
- `scripts/gate.sh`: the `ssh` step installs `openssh-sftp-server` and names
  it in `PODSSH_TEST_SFTP_SERVER`; CI's Windows job names the copy of Git
  for Windows.
- `docs/STATUS.md`, `docs/design.md` (the reliability table) and the map of
  `AGENTS.md`.
- Prove: `cargo test -p podssh-ssh --test sftp_client`: 8 passed, with Git
  for Windows' `sftp-server`; a `PODSSH_TEST_SFTP_SERVER` with no program
  there fails. `cargo test -p podssh-ssh --test sftp_client -- silent`: 3
  passed. Plants, each restored: `stat` with a limit of an hour failed its
  test after 3.0 s, at the library's own limit; no limit at all failed on
  the test's own limit of 10 s; a long `READ` reply accepted failed its
  test. `sh scripts/gate.sh lint msrv_ssh ssh` in the build image: green,
  the `ssh` step with Alpine's `sftp-server` named.

# T-134: `podssh cp` over SFTP: a temporary name, the digest, then a rename

**Source:** ROADMAP M5 (`podssh cp` and `podssh mv`), `docs/design.md:629-633`;
GitHub #21 (Nemo-010, 2026-10-08: agent-ssh-cli verifies, then renames;
syq's integrity checks and atomic replacement; read in the issue).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`podssh cp` parses its command line and does nothing (exit 70). A host with
no user database entry cannot run OpenSSH's `scp` either
(`docs/target-environment.md:40-44`). A copy that stops half way must never
leave a short or wrong file under the destination's name.

## Premise

- Measured on `3ee70dc`, offline, with no terminal:
  `podssh cp --timeout 30s a b` exits 70 ("'cp' is not implemented yet;
  nothing was done."); with no `--timeout`, 64 comes first (T-008). With no
  path, `podssh cp --timeout 30s` also exits 70, where 64 is right.
- Read, at `6483366`: `crates/podssh-cli/src/flags.rs` lines 240-259 mark `-P`, `-p`, `-i`,
  `-r`, `-F`, `--jsonl` and `--timeout` as supported; the parser keeps only
  `--timeout` and `--jsonl` (`crates/podssh-cli/src/tree.rs` lines 351-365),
  and dispatch drops the duration (`crates/podssh-cli/src/dispatch.rs`
  lines 213-223).
- Measured (T-133's offline probe): `SSH_FXP_RENAME` onto an existing file
  fails with status 4; `posix-rename@openssh.com` replaces the file.

## Approach

1. `CpArgs` in a new module crates/podssh-cli/src/cp/, read as `SshArgs` is
   (`crates/podssh-cli/src/ssh/args.rs:241-379`). An operand is remote when a
   `:` comes before any `/`; on Windows, `C:\x` is local. Fewer than two
   operands, or none remote, exit 64.
2. Build an `SshArgs` (host, `-P` as the port, `-i`, `-o`) for
   `crate::ssh::resolve::resolve`
   (`crates/podssh-cli/src/ssh/resolve.rs:130-500`), so `-F` follows the rule
   of `ssh`. Add `-o`, `-J`, `-v`, `-q` and the relay rows of `ssh`
   (`--relay-host`, `--relay-addr`, `--ca-file`, `--direct`) to `CP_FLAGS`.
3. Split `crates/podssh-cli/src/ssh/mod.rs` lines 73-151 at `6483366` so that the relay (with
   failover) or `--direct` gives T-133 a stream. The parsed `--timeout` is
   the deadline of the whole copy.
4. Upload: write `.NAME.podssh-RANDOM.part` beside the destination, created
   exclusive with mode 0600; `fsync@openssh.com` when offered; the digest
   check (Decision); the source's permission bits; then
   `posix-rename@openssh.com`. Without it, `SSH_FXP_RENAME`; when the
   destination exists, remove it first and say that the replace was not
   atomic.
5. Download: the same name beside the local destination (`create_new`, mode
   0600), `sync_all`, the digest check, `std::fs::rename`.
6. Remote to remote: `copy-data` on one host; else through a local
   temporary file, one connection at a time (`AGENTS.md` rule 2).
7. Invariant: the destination's name never holds an unverified file. A
   failure removes the temporary file (T-136 keeps it) and exits non-zero.
8. `-r` and `-p` refuse by name until T-143 and T-146 (no option is dropped
   silently, `docs/cli.md:56-60`). `--jsonl` gives one `done` (bytes,
   SHA-256) or `error` object for each file.
9. Exit codes as `proxy`: 64, then the faults of
   `crates/podssh-cli/src/exitmap.rs` lines 103-118 at `6483366`; a digest that differs is 70
   and names both digests.
10. Same commit: the `cp` row of `VERB_OWNER`
    (`crates/podssh-cli/src/flags.rs` line 456 at `6483366`) goes and
    `DISPATCHED` (`crates/podssh-cli/tests/flag_table.rs` lines 92-93 at
    `6483366`) gets `cp`; update `crates/podssh-cli/tests/binary_streams.rs`
    lines 169-180 at `6483366`, the manual,
    `docs/cli.md` and `docs/STATUS.md:107`.

## Decision

Recommendation: compare the SHA-256 of both ends before the rename. The far
digest comes, in this order, from a request of podssh's own (T-150), a
digest command that a probe finds over exec (`sha256sum`, `shasum -a 256`,
`openssl dgst -sha256`), or a second read of the far file, which counts
again against the relay's 64 MiB (T-137). The size and the MAC of SSH alone
lost: they miss a wrong offset, a short write, and a source that changed
while it was read.

2026-10-09, the rest of it. **Exit codes**: the faults of `exitmap.rs`
gain three sysexits rows for `cp`: 66 (`EX_NOINPUT`, a source missing or
unreadable), 73 (`EX_CANTCREAT`, a destination that cannot be written) and
75 (`EX_TEMPFAIL`, the `--timeout` passed); a login or a host key refused is
77 (`Auth`), no connection or no SFTP 69, digests that differ or a broken
session 70. Only the faults that were there lost: a missing file would be
69 or 70, which a script cannot tell from a dead network or a corrupted
copy. **The far digest** comes from one exec of a small `sh` script that
names the first of `sha256sum`, `shasum` and `openssl` and runs it on the
absolute path (`realpath`), quoted for the login shell; a refusal, no tool,
a path with a newline, or an answer that is not 64 hex digits falls back to
a second read. **Within one server** with `copy-data`, the server copies
and both digests are taken there; without it, or on two servers, the copy
goes through a temporary directory here, one connection after the other.
**One positional**: `cp a` reaches `cp`'s own message ("give a source and
a destination") instead of clap's count error; `mv` keeps the count until
T-138.

## Prove

```sh
cargo test -p podssh-cli --test cp_args          # operands, -P, drive letters, refusals
cargo test -p podssh-cli --test binary_streams   # cp no longer exits 70
sh scripts/dev.sh check                          # scripts/interop-cp.sh in the gate
```

The new crates/podssh-cli/tests/cp_args.rs checks each operand form and each
refusal (64, nothing attempted). The new scripts/interop-cp.sh, sourced by
`scripts/interop.sh` like `scripts/interop-faults.sh`, copies 0, 1, 262145
and 5,000,000 bytes both ways against OpenSSH, also over an existing file,
and compares `sha256sum` on both sides. Plant: an sftp subsystem that flips
one data byte; `podssh cp` must exit 70 and leave the destination as it was.

## Correction

2026-10-09. **The parts that this entry needed and did not name**:
`podssh-ssh` says why a hop failed (`run::HopError`: unreachable, the host
key, or the login refused, from `auth::AuthError`), so that `cp` can exit 77
or 69; `podssh_ssh::exec::capture` runs a command for a short answer, with a
limit; `Sftp` gained `setstat`, `has` and `copy_data`. **Step 3 is
`ssh/transport.rs`**: `reach` returns the first hop's stream, and `ssh` runs
on it as before. **`flags.rs` was at 497 lines**: `cp`'s rows moved to
`flags/copy.rs`. **The Prove's
`cargo test -p podssh-cli --test binary_streams`** no longer finds a `cp`
that exits 70: a piped `cp` meets the `--timeout` gate (64), and with one,
offline, it exits 69.

## Done

2026-10-09, in the commit "podssh cp copies files over SFTP, verified by
SHA-256 before they take the destination's name".

- `crates/podssh-cli/src/cp/`: `operand.rs` (scp's rule of the colon,
  brackets for IPv6, a drive letter local on Windows), `plan.rs` (up, down
  or across, and each usage refusal), `transfer.rs` (the temporary name, the
  digests, the permission bits, the rename; `up`, `down` and `within`),
  `digest.rs` (the far digest by a command or by a second read), `mod.rs`
  (the connection, the `--timeout` deadline, `--jsonl`, the exit codes).
- `crates/podssh-cli/src/ssh/transport.rs`, `flags/copy.rs` (with `-o`, `-J`,
  `-v`, `-q`, `--relay-host`, `--relay-addr`, `--ca-file` and `--direct`;
  `-r` and `-p` refused by name), `tree.rs`, `parsed.rs`, `dispatch.rs`,
  `positionals.rs`, `exitmap.rs` (66, 73, 75), the manual (`notes.rs`,
  `data.rs`), `VERB_OWNER` without `cp`.
- `podssh-ssh`: `run::HopError`, `auth::AuthError`, `exec.rs`,
  `Connection`, `run::disconnect_all`, and `Sftp::setstat`, `has` and
  `copy_data`.
- Tests: `tests/cp_args.rs` (each refusal 64 with nothing attempted, each
  operand form that names a server goes on to connect, `-r` and `-p`, `-F`,
  the drive letter, `--jsonl`), 13 unit tests of `cp`, two of `exec`; the
  tests that pinned `cp` as not implemented now pin the gate and the
  connection. `scripts/interop-cp.sh`, sourced by `scripts/interop.sh`.
- `docs/cli.md` (a section of `cp`, its exit codes), `docs/STATUS.md`,
  `README.md` and `AGENTS.md`.
- Prove: `cargo test -p podssh-cli --test cp_args`: 6 passed.
  `cargo test -p podssh-cli --test binary_streams`: 7 passed. In the gate's
  `release` step, `scripts/interop-cp.sh` against OpenSSH's `sftp-server`:
  each of its 22 cases passed (`interop: 125 passed, 0 failed`), the two
  planted defects among them: a byte flipped up and a byte flipped down
  each exited 70 and left the destination as it was. `sh scripts/gate.sh
  lint msrv_ssh ssh release` in the build image: green.

# T-135: `podssh cp` by exec when the server has no SFTP

**Source:** ROADMAP M5 ("an exec transfer as the fallback for minimal
servers"; "Do not assume POSIX tools or an interactive shell"),
`docs/design.md:629-633`; GitHub #18 (zuko's file server, read in the issue).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Some servers have no SFTP subsystem: an sshd with no `Subsystem` line,
Dropbear with no `sftp-server`, an image with a shell and little else.
There T-134 stops with "no SFTP". The far host can also lack the tools that
a script expects, and its login shell may not be a POSIX shell.

## Premise

- Read: an exec with no pty carries bytes unchanged: 262144, 262145 and
  5,000,000 bytes up and back with equal digests on OpenSSH and Dropbear
  (`docs/STATUS.md:147`, `scripts/interop.sh:139-154`), and 300 KB up and
  5 MB down through the relay (`docs/STATUS.md:151`).
- Read: a command goes as one string, never as a shell request
  (`crates/podssh-ssh/src/options.rs:63-64`), with no pty when stdin is not
  a terminal (`crates/podssh-ssh/src/session.rs:77-87`).
- Read: the gate's Dropbear has no SFTP setting (`scripts/interop.sh:83-85`);
  whether it finds an `sftp-server` is not measured.
- Not measured: the login shell runs the command, so a start-up file that
  prints text puts that text before the data.

## Approach

1. Fall back only on T-133's `NoSftp`, and say so once on stderr.
2. Probe in one exec (limit 15 s): `sh -c` prints a random marker, then
   `command -v` for `cat`, `wc`, `tail`, `mv`, `rm`, `chmod`, `base64`,
   `sha256sum`, `shasum` and `openssl`. Each later step is
   `sh -c 'SCRIPT' sh PATHS`, so the login shell only starts `sh`. With no
   `sh` or no `cat`, refuse and name what is missing.
3. Invariant: each step is one channel with no pty and a limit: 15 s for a
   probe, a size or a rename; T-133's progress limit for data; the
   `--timeout` deadline over all.
4. Upload: `umask 077; cat > "$1"` into T-134's temporary name, EOF, then
   the exit status (not 0 fails the copy). Download: the step prints the
   marker, then runs `cat -- "$1"`; podssh drops what comes before the
   marker and checks the length against `wc -c`.
5. Clean bytes: before the first data step, send the 256 byte values
   through `cat` and compare. When they differ, use `base64` on the far
   side, or refuse when there is none.
6. Digest: the first of `sha256sum`, `shasum -a 256` and
   `openssl dgst -sha256` that the probe found, else a second read (T-134).
   Then `mv -f -- "$1" "$2"`.
7. Quote each path for the far shell; refuse a newline or a NUL in a path.
   Test a space, a quote, a leading `-` and a name that is not UTF-8.

A server that refuses exec but has SFTP (`ForceCommand internal-sftp`)
never reaches this road. A far `cat` can still run after a drop (T-136).

## Decision

Recommendation: raw `cat` over a channel with no pty, and `base64` only
when step 5 fails. `docs/design.md:630` names both tools; raw bytes are
measured clean, and `base64` adds a third to the bytes that count against
the relay's 64 MiB and needs a tool that not each host has. `base64` for
each copy lost on both counts.

2026-10-09, the rest of it. **The tools needed** are `cat`, `wc`, `mv` and
`rm`; without one, the copy exits 69 and names it. Only `cat` lost: with no
`mv` there is no rename, and T-134's invariant cannot hold. **A copy down
keeps mode 0600**: no portable command gives a file's mode (`stat -c` is
GNU's and BusyBox's, `stat -f` BSD's), and reading `ls -l` lost as fragile;
T-146 (`-p`) may take it up. **A copy within one server** goes through this
host, as the SFTP road does without `copy-data`; a far `cp` would need a
check of its own. **The check of the bytes** runs once for each session,
through the same `sh -c` and marker as the data; a check before each file
lost: what a channel changes is the server's, not the file's.

## Prove

```sh
cargo test -p podssh-cli --test cp_exec    # the probe's parser, the quoting, the marker
sh scripts/dev.sh check                    # scripts/interop-cp.sh: the exec cases
```

In the gate, an OpenSSH server with no `Subsystem` line, and Dropbear, take
uploads and downloads of 0, 1 and 5,000,000 bytes with equal digests, and
`-v` names the exec road. A server whose `ForceCommand` prints a line before
it runs the command still gives equal digests. Plant: skip the marker; that
case must then fail on its digest.

## Correction

2026-10-09. **The second Premise cites `session.rs`**, which the copy by
exec never reaches: `podssh_ssh::exec` opens its own channels and asks for
no pty, whatever stdin is. **T-134's `exec::capture` keeps the whole
answer in memory**, which a file must not: `crates/podssh-ssh/src/exec.rs`
gained `receive` (stdout to a sink, each piece within the data limit) and
`send` (stdin in pieces, then EOF). **Step 2's refusal** names four tools,
not `cat` alone (Decision); `tail` is probed for T-136 and not used yet.
**Step 4's upload** adds `set -C`, so that the temporary name is created
exclusive, as on the SFTP road. **Step 6's rename** is
`chmod MODE -- TEMP && exec mv -f -- TEMP TARGET` when the server has
`chmod`, for the source's permission bits. **The far digest command** gets
`./NAME` for a relative path, so that a name with a leading `-` is no
option of the tool. **T-134 read the digest command's answer from its
first line**, which a `ForceCommand` banner takes:
`crates/podssh-cli/src/cp/digest.rs` now reads the line that names a tool
and the digest after it. **The Prove's servers with no SFTP** gained a
third: one whose output goes through `tr '\r' '\n'`, so that the check of
the bytes fails and the copy goes through `base64`; nothing else in the
gate reaches that road. **`byexec.rs` passed 500 lines**: the steps that
move a file are in `crates/podssh-cli/src/cp/byexec/files.rs`.

## Done

2026-10-09, in the commit "podssh cp copies by exec when the server has no
SFTP, raw through cat or through base64".

- `crates/podssh-cli/src/cp/byexec.rs`: the probe (a random marker, then
  `command -v` for each tool), each step as `sh -c 'SCRIPT' sh ARGS` with
  each argument one quoted word, `Strip` (what comes before the marker is
  dropped), the check of the 256 byte values and `base64` when it fails,
  the kind and size of a far path, the far digest (a command, else a second
  read), the rename (`chmod`, then `mv -f`, never onto a directory) and the
  removal of a temporary file. `crates/podssh-cli/src/cp/byexec/files.rs`:
  up and down, with T-134's temporary name and digests.
- `crates/podssh-cli/src/cp/mod.rs`: SFTP, or on `NoSftp` the exec road,
  said once; within one server with no SFTP, the copy goes through this
  host. `digest.rs` reads the digest command's answer after a banner.
- `crates/podssh-ssh/src/exec.rs`: `receive` and `send`, each wait bounded;
  `capture` has an overall limit.
- Tests: `tests/cp_exec.rs` (6) and a unit test of `digest.rs`.
  `scripts/interop-cp.sh`: three sshd with no SFTP (plain, a banner, output
  through `tr`) and Dropbear, each size both ways; names with a space, a
  quote and a leading `-`; a copy within one server; a directory at the
  target's name (73) and a far file that cannot be read (66), on both
  roads; a name that is not UTF-8 (64).
- `docs/cli.md`, the manual (`notes.rs`, `data.rs`), `README.md`,
  `docs/STATUS.md` (a section for `cp`, with T-134's results too); a
  Correction in T-148, whose Premise this changes.
- Prove: `cargo test -p podssh-cli --test cp_exec`: 6 passed. In the build
  image, `sh scripts/gate.sh lint msrv_ssh ssh release`: green; interop
  160 passed, 0 failed, each exec case among them; `-v` named raw `cat`
  on the plain and banner servers and `base64` on the one through `tr`;
  Dropbear found Alpine's `sftp-server`, and its cases went over SFTP.
  Planted, each alone on the image's copy of the tree with
  `gate.sh release`: with the bytes before the marker passed on as data,
  each copy down by exec exits 70 before its rename (13 cases fail), and
  no temporary file stays; with the check of the 256 byte values skipped,
  the copy down of 5,000,000 bytes through `tr` exits 70 on its digest,
  and the road checks of that server fail (4 cases).

# T-136: `podssh cp` continues from an offset after a drop

**Source:** ROADMAP M5 ("Continue from an offset after a drop"),
`docs/design.md:631-632`; GitHub #21 (agent-ssh-cli's `.part` and
`.part.meta`, parsync's resume, syq's partial file; read in the issue);
GitHub #17 (talaria0101, 2026-10-08: drops that repeat on one target).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A dropped relay session ends a copy, and a new run sends the whole file
again. On a link that drops every few minutes, a large file never arrives.
GitHub #17 measured one drop (`1011`) in 180 short sessions from one edge
(`docs/STATUS.md:416`), and drops that came back 3 times of 3 on one target.

## Premise

- Read: today a drop ends the session with the relay's reason, and nothing
  continues (`docs/design.md:649-657`).
- Read: SFTP reads and writes name their offset, so a copy can continue at
  any offset. The far file's size is no proof: with requests in flight
  (T-140), a later write can land while an earlier one fails.
- Read: the cache directories keep private files of mode 0600
  (`crates/podssh-relay/src/cache.rs`, lines 62-76 at `4dd52f8`,
  `crates/podssh-relay/src/cache.rs:142-186`).
- Read: after a drop, the relay closes the target's TCP connection within
  15 s (`docs/design.md:659-662`), so a far `cat` can write for a while.

## Approach

1. A side file in the cache directories, named by a hash of user, host,
   port and both paths: the source's size and mtime, the temporary name,
   and the offset below which each write was acknowledged. Never the bytes.
2. Within a run: after a relay close, a lost connection or a failed
   request, open a new session (T-137's path) and continue at the offset.
   Check first that the host key is the one of the first session (pin it in
   memory, `crates/podssh-ssh/src/handler.rs:155-185`), and that the source's
   size and mtime are the same; else start over and say so.
3. Invariant: the attempts are bounded. At most 5 in a row with no new
   acknowledged byte, with `podssh_relay::open::backoff`
   (`crates/podssh-relay/src/open.rs:410-418`). Stop at once on a refused
   authentication, a changed host key, a policy refusal or the `--timeout`
   deadline.
4. Across runs: the same command continues when the side file matches the
   source, and the temporary file is at least as long as the offset.
5. Exec road (T-135): before an append, wait until the far size is stable
   (two `wc -c` reads 2 s apart, 30 s at most). Then `cat >> "$1"` up, or
   `tail -c +N` down.
6. The digest of T-134 covers the whole file. A mismatch after a continued
   copy starts once more from offset 0, then fails.
7. Remove the side file after success, and when its source no longer
   matches. The manual and `docs/cli.md` say what continues, and where the
   side file is.

## Decision

Recommendation: continue across runs by default when the side file matches;
the final digest catches a wrong continue. A flag for it (as `sftp -a`)
lost for `cp`: a script that runs the same copy again after a drop would
start from zero each time. `podssh sftp -a` keeps OpenSSH's meaning (T-139).

2026-10-09, the rest of it. **A break** is what a new connection can mend:
an SFTP request whose channel closed or that got no reply, an exec channel
that ended with neither its close nor an exit status, or one with no
message within its limit. A status, a protocol error and digests that
differ are answers, and end the copy as before. **A new connection that
fails** for the network (69) counts as an attempt; a refused login or a
host key other than the first one (77) ends the copy. The first connection
is not tried again: the relay opener already fails over between hosts.
**The side file** is written at the start, each 4 MiB and at each break,
each time with an `fsync`; each 1 MiB lost on the cost of so many. It lives
with the relay tokens, private. **By exec**, the offset after a break is
the far file's size once it stands still, never what was sent: a far `cat`
may have taken less. **A copy within one server** by `copy-data` starts
over after a break: one request has no offset to give. **A copy that runs
out of attempts** keeps its temporary file, which the side file names, for
the next run; each other failure removes it, as T-134 says.

## Prove

```sh
cargo test -p podssh-cli --test cp_resume   # side file: match, changed source, stale
sh scripts/dev.sh check                     # interop-cp.sh through scripts/fake-relay.py
```

The stand-in relay's `close:BYTES:CODE` mode
(`scripts/fake-relay.py:403-431`) ends each session after 1,500,000 bytes
from the target with `1011`. A 5,000,000-byte download must finish over 4
sessions or more with equal digests, and `-v` names each offset. A new mode
that counts both directions does the same for an upload. A run stopped with
SIGINT and started again continues at an offset above 0. Plant: continue
one byte late; the digest check must fail the copy.

## Correction

2026-10-09. **"T-137's path"** (step 2) is `link::connect`
(`crates/podssh-cli/src/cp/link.rs`), which T-138 made; T-137 has not run.
**The host key pin** is `podssh_ssh::hostkey::Pin`, through
`Options::host_key_pin`, for the destination only. **Two defects of
podssh-ssh hid a break**, found through the stand-in relay that cuts: a
channel that ended with no exit status was a normal end
(`crates/podssh-ssh/src/exec.rs`), and russh-sftp's "sender dropped" was a
protocol error (`crates/podssh-ssh/src/sftp/error.rs`); both are a lost
connection now. **A defect of T-138**: a message of `mv` held 14 spaces
where a line continuation was lost; repaired here. **The Prove's
`--test cp_resume`** is the unit tests of
`crates/podssh-cli/src/cp/resume.rs`, run by
`cargo test -p podssh-cli --lib resume`: the module is private to `cp`.
**The new mode** of the stand-in
relay is `closeall:BYTES:CODE`. **The SIGINT case** starts podssh through
`python3`, which puts back SIGINT's default: a job that `sh` starts in the
background ignores SIGINT. **`transfer.rs` would pass 500 lines**: the SFTP
road's up and down are in `crates/podssh-cli/src/cp/bysftp.rs`, and the
session in `crates/podssh-cli/src/cp/session.rs`.

## Done

2026-10-09, in the commit "podssh cp goes on after a broken connection, at
the offset of the copy, in this run or the next".

- `crates/podssh-cli/src/cp/resume.rs`: the source's state, the progress
  of a copy and its side file, and the local temporary file of a copy down.
  `crates/podssh-cli/src/cp/session.rs`: the attempts at each file, with a
  new connection after each break. `crates/podssh-cli/src/cp/bysftp.rs`:
  the SFTP road's up and down, which write on at an offset; by exec, the
  far file's size once it stands still, `cat >>` and `tail -c`.
- `podssh-ssh`: `hostkey::Pin` through `Options::host_key_pin`; `exec.rs`
  and `sftp/error.rs` name a connection that was lost.
- `scripts/fake-relay.py` (`closeall:`) and `scripts/interop-resume.sh`.
- `docs/cli.md`, `docs/design.md`, the manual (the notes of `cp`, FILES).
- Prove, native: `cargo test -p podssh-cli --lib resume`: 6 passed (the
  side file of the same source, of a changed one and of another file; its
  writes each 4 MiB; the prefix in the digest; podssh's temporary names);
  the tests of the pin and of the errors of a session that ended;
  `cargo test --no-fail-fast`: 914 passed, 0 failed, 20 ignored. In the
  build image, before the operator's decision of 2026-10-09: a first run of
  `gate.sh lint msrv_ssh ssh release` found the two defects of `podssh-ssh`
  that the Correction names, and the exec road went on through both relays
  that cut, 3 times each way, with equal digests. The second run, after
  the repairs: green, interop 184 passed, 0 failed; each road went on 3
  times each way with equal digests, a copy that SIGINT stopped (exit 130)
  went on at an offset when run again, and no temporary or side file
  stayed.
- Waits for T-251 (the decision of 2026-10-09): the plant of the Prove
  (continue one byte late; the digest must fail it).

# T-137: `podssh cp` opens a new relay session before the relay's limits

**Source:** ROADMAP M5 ("Open a new relay session before the limits of the
relay (64 MiB, 12 h)"), `docs/relay.md:448-456`; the KTM sandbox report of
2026-10-08 (`report-podssh-sandbox-KTM-2026-10-08.txt`, not in the
repository).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The relay ends a session after 64 MiB in both directions together, or after
12 h (`docs/relay.md:453-454`). A larger copy breaks in a request with
`1009 session byte cap`. T-136 continues after it, but each cut costs a
broken SSH connection, a wait and an error line, and on the exec road an
old writer can race the new one.

## Premise

- Read: the pinned contract gives the same caps
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:233-235`).
- Measured in the KTM sandbox (`docs/STATUS.md:415`; the 99 s are in the
  report): `podssh proxy` received 67,107,943 bytes, then the relay closed
  with `1009 session byte cap`, 921 bytes short of 64 MiB on that side.
- Read: `podssh-relay` has a constant for the idle cut only
  (`crates/podssh-relay/src/relay.rs:19-21`); `podssh-core` has its own for
  IRC, with a budget of 60 MiB and the reason for the margin
  (`crates/podssh-core/src/irc/limits.rs:88-95`).
- Read: the relay stream sees each payload byte both ways
  (`crates/podssh-ssh/src/relay_stream.rs:226`,
  `crates/podssh-ssh/src/relay_stream.rs:255-267`). Each new SSH
  connection asks again for a passphrase or a password
  (`crates/podssh-ssh/src/keys.rs:301-363`,
  `crates/podssh-ssh/src/auth.rs:328-389`).

## Approach

1. The caps (64 MiB, 12 h) and podssh's budgets (60 MiB of payload both
   ways; 11 h 30 min) go in `crates/podssh-relay/src/relay.rs`, beside
   `RELAY_IDLE_SECS`. A variable `PODSSH_SESSION_BUDGET` can lower the byte
   budget (a relay with smaller caps, the tests), never raise it; add it to
   `crates/podssh-cli/src/man/facts.rs:46-300`.
2. Count the payload bytes both ways in the relay stream (an atomic counter
   beside `RelayStatus`), and keep the session's start time.
3. Invariant: no session passes a budget. Before a data request that would
   pass one: end the request in flight, close the SFTP handle (or send EOF
   on the exec road), close the session, open a new one, and continue at
   the offset (T-136). Close, then open: one connection at a time
   (`AGENTS.md` rule 2).
4. Keep the key or the password that worked in memory (`Zeroizing`) for
   this run only, and offer it first on the next session.
5. Only the relay transport counts: `--direct` has no cap. With `-J`, the
   one relay session carries the whole chain.
6. A "Session limits" item in the manual's relay section
   (`crates/podssh-cli/src/man/facts.rs:320-488`), from the constants;
   `docs/relay.md` and `docs/cli.md`. T-155 does the same for the
   resumable layer of M6; this entry needs no M6 work.

## Decision

Recommendation: a budget of 60 MiB counted by podssh, as `podssh-core`
uses for IRC: the relay counts bytes that podssh has not yet received, and
can hold 2 MiB queued (`docs/relay.md:522`). Waiting for `1009` (T-136
alone) lost: each cut breaks a request in flight. Credentials stay in
memory for the run, never on disk; asking again lost: a 200 MiB copy would
ask four times, and with no terminal it could not ask at all.

2026-10-09, the rest of it. **The check** comes before each data request:
an SFTP write or read, a piece of a copy up by exec, or a piece that a far
`cat` sends down; each with 64 KiB of room for the framing of SSH and SFTP.
**A spent session** ends the attempt with its own cause, and the copy goes
on over a new session at once, with no wait and no attempt counted, unless
the attempt moved no byte. **`PODSSH_SESSION_BUDGET`** takes a whole number
of bytes of 1 MiB or more; a smaller or other value is ignored, so a typing
error cannot make each request a new session. **The memory of a login**
keeps the decrypted key and the password, never the passphrase, in podssh's
own process, wiped on drop; it forgets a password that the server no longer
takes.

## Prove

```sh
cargo test -p podssh-relay -- budget       # the caps and the budgets, in order
cargo test -p podssh-ssh -- relay_count    # the counter sees both directions
sh scripts/dev.sh check                    # interop-cp.sh through a small cap
```

A new stand-in relay mode closes with `1009` at 4,000,000 bytes counted in
both directions, as the relay counts (`docs/relay.md:454`). With
`PODSSH_SESSION_BUDGET=3000000`, an upload and a download of 10,000,000
bytes finish with equal digests, no `1009` on stderr, and 4 sessions or
more. Plant: count one direction only; the upload then meets `1009`.

## Correction

2026-10-09. **Step 3's "close the SFTP handle (or send EOF on the exec
road)"**: by exec, the copy stops sending and closes the session; the far
`cat` ends with it, and the next attempt waits until the far file stands
still (T-136). **The Prove's mode** of the stand-in relay is T-136's
`closeall:BYTES:CODE`. **Step 4 also needed a type** in `podssh-ssh`:
`crates/podssh-ssh/src/remember.rs`, through `Options::remembered`.
**Clippy's limit of 7 arguments**: the four functions that copy a file take
the meter as an eighth, and say so with an `allow`, as `podssh-ws` does.

## Done

2026-10-09, in the commit "podssh cp opens a new relay session before the
relay's limits, and logs in as the first session did".

- `crates/podssh-relay/src/relay.rs`: the caps (64 MiB, 12 h), podssh's
  budgets (60 MiB, 11 h 30 min) and `byte_budget`, with
  `PODSSH_SESSION_BUDGET`. `crates/podssh-ssh/src/relay_stream.rs`: the
  status counts the payload bytes both ways, and the session's age.
- `crates/podssh-cli/src/cp/link.rs`: the `Meter` of each link; the four
  functions that copy a file check it before each data request, and
  `crates/podssh-cli/src/cp/session.rs` opens a new session at once when a
  session is spent.
- `crates/podssh-ssh/src/remember.rs`: the key that a passphrase opened and
  the password that the server took, for the run; `keys.rs` and `auth.rs`
  offer them first.
- `scripts/interop-resume.sh`: 10,000,000 bytes up and down with a budget
  of 3,000,000 through a stand-in relay that ends each session at 4,000,000
  bytes with 1009; and an encrypted key over the sessions that a relay cuts,
  with a count of the questions.
- The manual (`PODSSH_SESSION_BUDGET`; "Session limits" in THE RELAY),
  `docs/relay.md` and `docs/cli.md`.
- Prove, native: `cargo test -p podssh-relay -- budget`: 2 passed;
  `cargo test -p podssh-ssh -- relay_count`: 1 passed (1000 bytes out, a
  keepalive and 500 bytes in count 1500); the tests of the meter and of the
  memory of a login; `cargo test --no-fail-fast`: 919 passed, 0 failed, 20 ignored.
- Waits for T-251 (the decision of 2026-10-09): the run in the build image
  of the cases of `scripts/interop-resume.sh` above (CI runs them at each
  push), and the plant of the Prove (count one direction only; the upload
  must then meet 1009).

# T-138: `podssh mv`: copy, verify, delete, and say first that it is not atomic

**Source:** ROADMAP M5 ("Across hosts, `mv` is copy, verify, delete; podssh
says first that it is not atomic"); the description of `mv` in
`crates/podssh-cli/src/flags.rs:404-405`.
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh mv` exits 70 today. A move between two hosts cannot be atomic: if
podssh stops between the copy and the delete, the file is in two places; if
it deletes before the copy is complete and correct, the file is lost. The
user must know this before the move starts.

## Premise

- Measured on `3ee70dc`, offline: `podssh mv --timeout 30s a b` exits 70
  (`'mv' is not implemented yet; nothing was done.`).
- Read: `mv` shares `CP_FLAGS` (`crates/podssh-cli/src/flags.rs:404-405`),
  so the operands and options of T-134 apply.
- Measured (T-133's offline probe): `posix-rename@openssh.com` replaces in
  one step; `SSH_FXP_RENAME` refuses an existing target.
- Read: the attributes of SFTP version 3 carry no inode number, so a `stat`
  cannot show that two paths name one file.

## Approach

1. Same host, port and user: rename with `posix-rename@openssh.com`, which
   is atomic; without it, T-134's rule. No byte moves.
2. Across hosts: before any byte moves, one line on stderr, for example:
   "podssh mv: SRC and DST are on different hosts: this is a copy, a digest
   check, then a delete of SRC; it is not atomic." Then T-134's copy.
3. Invariant: the source goes only after the digests matched, the rename to
   the destination succeeded, and a new `stat` of the source equals the one
   taken before the copy (size and mtime). Else keep it, exit non-zero, and
   say why.
4. Refuse (exit 64, nothing done) when both operands name one file: the
   same host, port and user, and the same `REALPATH` (locally,
   `std::fs::canonicalize`).
5. A delete that fails after a verified copy: exit 70 with "the copy is
   complete and verified; SRC was not removed: REASON". The data is then in
   two places, never in none.
6. Directories wait for T-143 (exit 64); two local paths exit 64 (T-134).
7. Same commit: the `mv` row of `VERB_OWNER`
   (`crates/podssh-cli/src/flags.rs` line 436 at `8848781`), the manual,
   `docs/cli.md` and `docs/STATUS.md:124`.

## Decision

2026-10-09. **Exit codes**: a source that changed during the move is 66,
the code that T-134 gives a file that changed while it was read; a delete
that fails after a verified copy is 70, as step 5 says. **The notice** goes
through the log at its normal level, so `-q` silences it as it silences
each message of podssh; a line that `-q` cannot silence lost, as `-q` says
"no messages from podssh itself". Within one server there is no notice,
unless the server could not rename. **One file named twice** is found as
typed before anything connects, then by the server's own answer
(`realpath`, or `test -ef` by exec); `std::fs::canonicalize` has no use
here, as no move has both operands on this host. **Within one server by
exec**, `mv -f` renames, and moves across two file systems by itself; a
copy through this host lost, as it carries bytes that the server can move
alone. **A rename that SFTP fails with `SSH_FX_FAILURE`** (two file
systems) becomes a copy and a delete, said first; the other statuses (no
such file, permission denied) are the move's answer.

## Prove

```sh
cargo test -p podssh-cli --test cp_args -- mv   # one file named twice, two local paths
sh scripts/dev.sh check                         # scripts/interop-cp.sh: the mv cases
```

In the gate, moves up and down remove the source only after equal digests.
The notice is the first line on stderr, before the `-v` line that opens the
transfer. `mv host:a host:./a` exits 64 and `a` stays as it was. A source
that grows during a 50 MB move through the stand-in relay stays, and the
exit is not zero. Plant: delete before the digest check; with the server of
T-134 that flips a byte, the source is then lost and the test fails.

## Correction

2026-10-09. **Step 3's stat** is more than the size and the time of
change: here the same file (the device and inode; on Windows, when it was
made), by exec the same line of `ls -lnid` (its time has minutes only, so
the inode is in it), and the same bytes where a digest command runs on the
source's side. **Step 6**: a directory exits 66, as for `cp` ("not a
regular file"): a far path is known only after the connection, and 64 says
that podssh did nothing. **A move between two servers** removes the source
in a third connection, after the copy up. **`--jsonl`** adds
`source_removed` to each `done` object, and a rename has no digest. **The
Prove's growing source** needs no stand-in relay: a writer that appends
while the move runs, over `--direct` to the gate's OpenSSH, meets T-134's
check of the size and time after the read. **The Prove's plant** is the
digest comparison that always agrees (`crates/podssh-cli/src/cp/transfer.rs`),
which removes the source with no verified copy, as a delete before the
check would. **`binary_streams.rs`** used `mv a` for clap's count error;
since `mv` takes any count, as `cp` does, no verb has one, and
`crates/podssh-cli/src/refuse.rs` tests that message.

## Done

2026-10-09, in the commit "podssh mv moves files: a rename within one
server, else a verified copy and then the delete".

- `crates/podssh-cli/src/cp/moving.rs`: the notice, one file named twice
  (as typed, then by the server), the state of a source before its copy,
  its removal only while it is still that file, and the rename within one
  server, with the fallback to a copy and a delete.
- `crates/podssh-cli/src/cp/link.rs`: the connection and its road, out of
  the session, so that a rename or a delete opens its own. `mod.rs`:
  `run_cp` for both verbs, `source_removed` in `--jsonl`, and the sessions
  that copy, rename and remove. `transfer.rs`: `Done` has `removed` and a
  digest that a rename has not; `byexec.rs`: `listing`, `same_file` and
  `delete`.
- `mv` takes any count of paths, as `cp` does; `VERB_OWNER` keeps `chat`.
- Tests: `cp_args.rs` (each refusal, one file named twice, the notice as
  the first line, and none with `-q` or within one server), 3 unit tests of
  `moving.rs` and one of `refuse.rs`; `non_interactive.rs`, `flag_table.rs`
  and `binary_streams.rs` as `mv` works. `scripts/interop-mv.sh`, sourced
  by `scripts/interop-cp.sh`.
- `docs/cli.md` (a section of `mv`, its exit codes), the manual (`MV`, the
  exit rows), `README.md`, `AGENTS.md` and `docs/STATUS.md`.
- Prove: `cargo test -p podssh-cli --test cp_args -- mv`: 2 passed. In the
  build image, `sh scripts/gate.sh lint msrv_ssh ssh release`: green;
  interop 178 passed, 0 failed, the 18 cases of `mv` among them: up and
  down on SFTP and by exec, each source gone after equal digests and the
  notice first on stderr; a rename within one server, with no notice; one
  file named twice, 64; through the flipping server, 70 each way and the
  source stays; a source that grows, 66 and it stays; a source that cannot
  be removed, 70 and the data in both places; server to server; `--jsonl`.
  Planted on the image's copy of the tree, the digest comparison that
  always agrees: the move up through the flipping server exits 0 and its
  source is lost, and that case fails; the move down exits 66, because the
  far source's bytes, read again before the delete, differ from the copy's.

# T-139: `podssh scp` and `podssh sftp` with the command lines of OpenSSH

**Source:** `docs/cli.md:50-55` (`-P` is the port for `scp` and `sftp`);
GitHub #23 (cubic's `scp` command) and GitHub #22 (the port forms of copy
tools), read in the issues; the usage of OpenSSH 10.3p1, measured here.
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

`podssh scp` and `podssh sftp` are other names of `cp`, with `cp`'s flags.
`scp -o Port=2222 a host:b` and `sftp -b batch host` get "unknown flag"
(exit 64), and `podssh sftp host` is refused because `cp` wants two paths.
Where podssh must replace them, OpenSSH's own `scp` and `sftp` cannot run
(no user database entry, `docs/target-environment.md:40-44`).

## Premise

- Measured on `3ee70dc`, offline, with no terminal:
  `podssh scp --timeout 30s -o Port=2222 a host:b` exits 64 with
  `unknown flag '-o'`, and so do `-J`, `-q`, `-3` and `sftp -b`.
  `podssh sftp --timeout 30s user@host` exits 64 with "podssh cp: the right
  number of arguments was not given." (it names `cp`).
- Measured on 2026-10-08, offline: the usage of OpenSSH 10.3p1 (Git for
  Windows; both exit 1 on a usage error). `scp` has the switches
  `-346ABCOpqRrsTv` and the values `-c -D -F -i -J -l -o -P -S -X`; `sftp`
  has the switches `-46AaCfNpqrv` and the values
  `-B -b -c -D -F -i -J -l -o -P -R -S -s -X`.
- Read: `-s`, `-R` and `-B` are switches on `scp` and take a value on
  `sftp`; one table cannot hold both, as `-P` showed for `ssh` and `cp`
  (`crates/podssh-cli/src/tree.rs:7-12`). Tests pin the names
  (`crates/podssh-cli/tests/tree.rs` line 48 at `bf42e84`,
  `crates/podssh-cli/tests/plants.rs` lines 209-216 at `bf42e84`,
  `crates/podssh-cli/src/suggest.rs` lines 310-311 at `bf42e84`).

## Approach

1. `scp` and `sftp` become verbs with their own tables (`SCP_FLAGS`,
   `SFTP_FLAGS`, `crates/podssh-cli/src/flags.rs`); `cp` keeps the name `cp`
   only. Each letter above has a row: supported, accepted, or refused by
   name with what to use instead, as T-016 did for `ssh`; reviewed sets as
   `SSH_SHORT_FLAGS` (`crates/podssh-cli/tests/flag_table.rs:13-29`).
2. Supported on T-134's path: `-P`, `-i`, `-o`, `-J`, `-F`, `-4`, `-6`,
   `-C`, `-q`, `-v`; on `scp`, `-B` (`BatchMode=yes`); on `sftp`, `-b`
   (step 5), `-f` (`fsync@openssh.com`), `-s NAME` (the subsystem) and
   `-N`. Refused until their entries: `-r` (T-143), `-p` (T-146), `-l`
   (T-145), `-a` (T-136), `-X`, and `-B` and `-R` on `sftp` (T-140).
3. Refused by name: `-S`, `-D`, `-O` (podssh uses SFTP or T-135), `-A`
   (T-036), `-c` (as on `ssh`), and `-R` on `scp` (it needs `scp` and a key
   on the first host). Accepted with no effect: `-T`, `-s` on `scp`, and
   `-3` (podssh copies between two hosts through itself).
4. Operands as OpenSSH reads them: `[user@]host:[path]`, the `scp://` and
   `sftp://` forms with a port, `[v6]:path` (T-007); a `:` after a `/` is
   local.
5. `sftp -b FILE` (or `-b -`): `get`, `put`, `reget`, `reput`, `rename`,
   `rm`, `mkdir`, `rmdir`, `ls`, `cd`, `lcd`, `pwd`, `lpwd`, `chmod`, `df`,
   `bye`; a leading `-` goes on after an error. The same commands at a
   prompt on a terminal; with no terminal and no `-b`, exit 64.
6. Same commit: `crates/podssh-cli/src/help.rs:234-273`, the manual and its
   examples, `docs/cli.md`.

## Decision

Recommendation: `scp` and `sftp` get no `--timeout` row, as in OpenSSH, so
the gate of `crates/podssh-cli/src/dispatch.rs:322-343` skips them; T-133's
limits keep each wait finite. Usage errors stay 64 (`docs/cli.md:5131-5134`)
where OpenSSH gives 1; a script that tests for "not zero" works with both.
`--timeout` required with no terminal, as for `cp`, lost: each script that
runs `scp` in a pipe would exit 64 under `podssh scp`.

## Prove

```sh
cargo test -p podssh-cli --test flag_table   # the reviewed letters of scp and sftp
cargo test -p podssh-cli --test scp_args     # operands, URIs, -P, refusals by name
sh scripts/dev.sh check                      # interop-cp.sh: podssh scp and sftp -b
```

No letter of the two usage lines gives "unknown flag". In the gate,
`podssh scp -P 2201` copies with equal digests, and an `sftp -b` batch
leaves the same files as OpenSSH's own `sftp` with the same batch (the
image has the client since T-238, `openssh-client-default` at
`scripts/interop.sh:24-25`). Plant: remove one row; the
reviewed-set test must fail.

## Correction

2026-10-09. **`-a` on `sftp`** (step 2) is accepted, not refused: since
T-136 a copy goes on by itself from its own side file, which is what `-a`
asks. **`-f` and `-N`** are accepted too: podssh flushes each file where
the server can, and its batch is not quiet. **`scp -B`** is `BatchMode=yes`
through the options of `ssh`. **Step 4's URIs** are read as OpenSSH's
`parse_uri` reads them (read in its `misc.c`): the path after the first
`/` is under the login directory and `//` makes it absolute; the user and
the path are percent-decoded; the port is the operand's own, so two ports
are two servers. `cp` and `mv` take URIs too. **Step 5** adds `help`,
`version`, `exit` and `quit`, patterns in the last name of `rm` and `get`,
and `df` through `statvfs@openssh.com`
(`crates/podssh-ssh/src/sftp/mod.rs`); `reget` and `reput` are `get` and
`put`, which go on by themselves. The local commands and `ln`, `chown`,
`chgrp` are refused by name. **`sftp -s`** names a subsystem; a path to a
server program is not run. **The help of a refusal** listed each verb on a
line, so its test's limit of 18 lines now follows the count of the verbs.

## Done

2026-10-09, in the commit "podssh scp and podssh sftp take the command
lines of OpenSSH's".

- `crates/podssh-cli/src/flags/scp.rs`: `SCP_FLAGS` and `SFTP_FLAGS`, a row
  for each letter of OpenSSH 10.3p1's usage; `scp` and `sftp` are verbs of
  their own, and `cp` has no alias.
- `crates/podssh-cli/src/cp/operand.rs`: `scp://` and `sftp://` operands
  with a port; `run_cp` names the verb that the user typed.
- `crates/podssh-cli/src/sftp/`: the destination, the batch and the prompt
  (`mod.rs`), the lines and their commands (`commands.rs`), and each
  command against the session (`run.rs`); `get` and `put` copy through
  `crates/podssh-cli/src/cp/bysftp.rs`. `crates/podssh-cli/src/cp/link.rs`
  opens a session for SFTP only, on a named subsystem.
- `podssh-ssh`: `Sftp::open_named` and `Sftp::statvfs`.
- Tests: `tests/scp_args.rs` (each refused letter of both verbs, by name;
  the supported and accepted letters, URIs and `--direct` go on to connect
  with no `--timeout`; `sftp` with no destination, with no terminal and no
  `-b`, and with a batch that cannot be read); the reviewed letter sets in
  `tests/flag_table.rs`; unit tests of the URIs, the lines, the quoting,
  the patterns and the long listing. The tests that pinned `scp` and `sftp`
  as names of `cp` now pin the verbs. `scripts/interop-sftp.sh`, sourced by
  `scripts/interop-cp.sh`: `scp -B` up, `scp` from a URI down, an `sftp -b`
  batch of each command with `-` and `@`, a batch that a failed command
  ends, and a destination that names a file.
- The manual (the notes of `scp` and `sftp`), `docs/cli.md`, `README.md`,
  `AGENTS.md` and `docs/STATUS.md`.
- Prove, native: `cargo test -p podssh-cli --test flag_table`: 7 passed;
  `cargo test -p podssh-cli --test scp_args`: 5 passed;
  `cargo test --no-fail-fast`: 932 passed, 0 failed, 20 ignored.
- Waits for T-251 (the decision of 2026-10-09): `scripts/interop-sftp.sh`
  in the build image (CI runs it at each push), its comparison with
  OpenSSH's own `sftp` on the same batch, and the plant (remove one row;
  the reviewed-set test must fail).

# T-140: Pipelined SFTP

**Source:** GitHub #21 and GitHub #18 (lablup/bssh: 255 KiB chunks, up to
64 requests in flight,
`lablup/bssh:crates/bssh-russh-sftp/patches/pipelined-file-io.patch`, read
in the issues).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A client that waits for each reply before it sends the next request moves
one request per round trip. Through a CONNECT proxy and the relay a round
trip is long, so such a copy uses a small part of what the path carries.

## Premise

- Measured (T-133's offline probe): OpenSSH's `sftp-server` takes reads and
  writes of 261120 bytes, the 255 KiB that bssh uses.
- Read: podssh gives the server an SSH window of 512 KiB
  (`crates/podssh-ssh/src/run.rs:30`), so a download has 512 KiB in flight
  at most, whatever the number of requests: two reads of 255 KiB fill it.
- Read: the comment on the window quoted a row of the reverse close codes
  (1 MiB queued, `1011`, a dropped frame;
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). T-024
  corrected it to the forward path's rule
  (`crates/podssh-ssh/src/run.rs:26-29`): `docs/relay.md:533-545` gives
  2 MiB, `1013` and no drop. The window can grow only after that is
  settled; T-062 measures the `1013`.
- Measured in two sandboxes (`docs/STATUS.md:414`): 20 MiB through the
  relay with `podssh proxy` (no SSH window in the path) at 0.5 to 0.7 MB/s
  through a CONNECT proxy, and 1.8 to 6.9 MiB/s with no proxy. SFTP through
  the relay is not measured.

## Approach

1. Measure first, with T-157's committed method: a get and a put of 20 MiB
   through the relay with 1, 2, 4 and 16 requests in flight, of 32 KiB and
   of 255 KiB. Record the figures in `docs/STATUS.md`.
2. Keep up to N requests in flight, N from that measurement. Invariant: the
   bytes in flight never pass our window (download) or the server's window
   (upload).
3. Replies can come in any order. T-136's offset is the end of the
   contiguous acknowledged part, never the far file's size.
4. After a failed request, send no new one; wait for the others within
   T-133's reply limit, then report the first error.
5. `podssh sftp -R` and `-B` (T-139) set N and the size.

## Decision

2026-10-12, the calls made in the work:

- The requests in flight are in `crates/podssh-ssh/src/sftp/pipeline.rs`
  (`Reads`, `Writes`, `Pipeline`), which `cp`, `mv`, `scp`, `sftp` and the
  second read of a far digest use. Each block comes out in the file's
  order (a queue in the order of the requests), so the part that a write
  acknowledged is always contiguous, and the next attempt writes on at its
  end; a short read asks for its rest before the blocks after it.
- The limit of each wait runs from the last reply, not from each request's
  start: a request behind others on a slow link is not failed for their
  bytes. russh-sftp's own limit on each request, from its start, is then a
  backstop of 64 times the limit, which each wait of podssh bounds first.
- The bound is 512 KiB in flight both ways, the window that podssh gives a
  server (`crates/podssh-ssh/src/run.rs:30`). The server's window, which
  an upload's invariant names, is not known through russh; russh never
  sends past it, so a write beyond it waits in podssh, not on the wire.
- The default is OpenSSH's: 64 requests, each of the server's size, as many
  as the window holds: 2 of OpenSSH's 255 KiB, 16 of 32 KiB. The
  measurement through a round trip of 100 ms gives 2.74 / 1.77 MiB/s for 2
  x 255 KiB and 3.39 / 1.84 for 16 x 32 KiB, so the server's size stays.
- The relay's meter (T-137) passes a request only while the session may
  carry its bytes and a window more, which the requests in flight may still
  bring.
- The measurement went through the stand-in relay with 50 ms each way, not
  the live relay: `podssh sftp` reads `node://NAME` as the host `node`, and
  the live relay reaches the test's server only as a node; T-296, new, makes
  `cp`, `scp` and `sftp` name a node, and its Prove runs the cell. The
  test's SSH server gained the subsystem `sftp` (OpenSSH's `sftp-server`).
- The tests are in `crates/podssh-ssh/tests/sftp_pipeline.rs`, not
  `sftp_client.rs`, which would pass 500 lines; their names hold
  `pipelined` and `window`. `sftp -R`, `-B` and `-X`, and `scp -X`, take
  OpenSSH's forms.

## Prove

```sh
cargo test -p podssh-ssh --test sftp_client -- pipelined   # replies out of order, equal digests
cargo test -p podssh-ssh --test sftp_client -- window      # never above 512 KiB in flight
```

The pipelined test reorders the replies of a real `sftp-server` through a
stream double and compares the digests. The window test counts the bytes in
flight. A new row of `docs/STATUS.md` gives the throughput for each N.
Plant: take the offset from the far file's size; a test with one failed
early write then fails its digest.

## Done

2026-10-12. `crates/podssh-ssh/src/sftp/pipeline.rs`, used by
`crates/podssh-cli/src/cp/bysftp.rs` and `crates/podssh-cli/src/cp/digest.rs`;
the flags in `crates/podssh-cli/src/flags/scp.rs`, read by
`crates/podssh-cli/src/cp/pipe.rs`. `cargo test -p podssh-ssh --test
sftp_pipeline`: 5 passed, against Git for Windows' `sftp-server` through a
double that reorders, cuts and fails replies: copies through replies out of
order agree with the disk (more than 10 replies out of order, more than 2
requests in flight); a short read is asked again for its rest; never more
than 512 KiB in flight, and 16 or 4 requests of 32 KiB as asked; one request
at a time when asked; a failed write leaves the acknowledged part at the
end of the write before it while the far file is longer, and a second
attempt from there makes the file whole. `cargo test -p podssh-cli --test
copy_pipeline`: 2 passed (`cp` up and down, and `sftp` put and get with
`-R`, `-B` and `-X`, against the test's server, whose subsystem `sftp` runs
`sftp-server`); `--test scp_args`: 6 passed, with refusals that name the
flag. Planted defects: the acknowledged part taken from the far end after
a failure (the test of the failed write failed: 294912 for 32768); blocks
handed on as their replies came (the test of replies out of order failed).
The measurement: `docs/STATUS.md`, "Throughput, measured": through a round
trip of 100 ms, 0.22 MiB/s with one request of 32 KiB, 2.74 / 1.77 with the
default for OpenSSH. The live relay's figure waits for T-296.

# T-141: Parallel transfer in chunks

**Source:** GitHub #21 (parsync: parallel transfer in chunks with a chosen
concurrency, `AlpinDale/parsync:src/sync.rs`, read in the issue).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

One stream carries one copy at a time, and one relay session carries 60 MiB
at most (T-137). A large file, or many small files, take the time of one
stream.

## Premise

- Read: `AGENTS.md` rule 2 allows one outbound connection. Several channels
  in one SSH connection keep the rule; several relay sessions at once do
  not. The operator accepted more than one outbound connection for the iroh
  road (`docs/design.md:1355-1358`), and on 2026-10-08 for one copy when the
  user asks (`docs/decisions.md`).
- Read: the cap of 64 MiB is for each session (`docs/relay.md:454`).
- Not measured: whether one relay session, or the path itself, limits the
  rate. T-157 measures it.

## Approach

1. Split a file into chunks of 8 MiB at fixed offsets. Each chunk is a task
   with its own SFTP handle, or its own exec channel (T-135), in the one SSH
   connection.
2. At most K tasks (`--parallel K`); K is 1 until a measurement shows a
   gain.
3. Each task writes into T-134's temporary file at its offset. T-136's side
   file keeps a map of the finished chunks.
4. Invariant: the digest of T-134 covers the whole file after the last
   chunk; no rename before it.
5. Many small files: the same K tasks, one file each.
6. T-137's budget counts the whole connection: a new session waits until
   each task ends its chunk.

## Decision

Recommendation: parallel channels in one connection first. Several relay
sessions at once are allowed when the user asks (the operator's ruling of 2026-10-08): a
flag sets the number, and the default is 1. Add that flag after a
measurement (T-157) shows the gain of the channels.

2026-10-12, the calls made in the work:

- The tasks are in `crates/podssh-cli/src/cp/chunks.rs`: each opens an SFTP
  session of its own, so a channel and a window of its own, in the one
  connection, and takes chunks of 8 MiB in turn; a chunk that a task ends
  goes into the side file at once (`Progress::finish_chunk`), whose offset
  moves over the chunks done next to it.
- Through the relay the tasks share 1.5 MiB in flight, three windows,
  below the 2 MiB queued that close a session (`1013`): each task keeps
  1.5 MiB / K. On a direct connection each keeps its own 512 KiB.
- A task takes a chunk only while the relay session may carry it whole,
  with the tasks' room more; then each task ends its chunk, and the next
  session goes on with the chunks left (T-137).
- The digest of a copy up is read from the source after the last chunk, and
  the source must be as it was; a copy down hashes the temporary file.
- The measurement shows a gain (1.55 times down, 1.34 times up through the
  stand-in with 50 ms each way, at K = 4): the flag is there, and the
  default stays 1, as the Decision said; several channels are the user's
  choice.
- The copy by exec goes in one stream and says so: writing at an offset
  needs `dd`, which the probe of T-135 does not ask for.
- Many small files with K tasks (step 5) need the retries of one file
  (`crates/podssh-cli/src/cp/session.rs`, `attempts`) to run for several
  files on one connection at once: T-297, new.

## Prove

```sh
cargo test -p podssh-cli --test cp_parallel   # the chunk plan, the map, chunks out of order
sh scripts/dev.sh check                       # interop-cp.sh: --parallel 4, equal digests
```

A row of `docs/STATUS.md` gives the throughput with K = 1 and K = 4 by
T-157's method. Plant: give two chunks the same offset; the digest check
must fail.

## Done

2026-10-12. `crates/podssh-cli/src/cp/chunks.rs`, from
`crates/podssh-cli/src/cp/bysftp.rs` when `--parallel K` (K > 1) meets a file
of more than one chunk; the map of chunks in `crates/podssh-cli/src/cp/resume.rs`.
`cargo test -p podssh-cli --test cp_parallel`: 2 passed: 25 MiB and a part
go up with 4 tasks and down with 3, and agree with the disk, against the
test's server and its `sftp-server`; a file of one chunk goes in one stream;
`--parallel 0`, `17` and `x` are refused (64). The unit tests: the chunk
plan covers the file once; the tasks share the room of a relay session; the
map of chunks done out of order moves the offset and survives a new run.
In the build image, `scripts/interop.sh` against OpenSSH: `cp.parallel.up`,
`cp.parallel.down` (25000000 bytes, equal digests) and `cp.parallel.flip`
(the subsystem that flips a byte: exit 70, the destination as it was).
Planted defect: two chunks at one offset; the copy up failed, "the digests
differ", and the destination was not changed. The measurement:
`docs/STATUS.md`, "Throughput, measured". Step 5 is T-297.

# T-142: Delta copy: only the blocks that changed

**Source:** GitHub #21 (parsync's signature, matcher and patch,
`AlpinDale/parsync:src/delta/`, read in the issue).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** done

## Problem

A copy over an older version of the same file sends each byte again.
Through the relay that costs a new session for each 60 MiB (T-137), at 0.5
to 0.7 MB/s in the KTM sandbox (`docs/STATUS.md:414`).

## Premise

- Measured (T-133's offline probe): OpenSSH's `sftp-server` offers no digest
  of a range, and offers `copy-data`, a copy inside the server.
- Read: a rolling delta (moved and inserted data) needs code on both sides:
  signatures where the old file is, matching where the new one is. Against
  a standard server, podssh controls one side only.
- Read: the exec road runs a digest tool on the far side after a probe
  (T-135).

## Approach

1. Fixed blocks of 1 MiB, with a standard server: get the SHA-256 of each
   block of the old file (exec: `dd if=F bs=1048576 skip=N count=1` into
   the probed digest tool, or T-150's request), compare them with the local
   blocks, and plan the blocks to send.
2. Make the temporary file from the old one inside the server
   (`copy-data`), write only the changed blocks, set the size, then T-134's
   digest check and rename.
3. A rolling delta only between two podssh ends (T-150), where podssh runs
   on both sides.
4. `--delta` turns it on; the full copy stays the default until a
   measurement shows the gain.
5. Invariant: the digest of the whole file decides. A mismatch after a
   delta falls back once to a full copy, and says so.

## Decision

Recommendation: fixed blocks with a standard server, and a rolling delta
only between podssh ends. A probed `rsync` on the far side lost: podssh
would have to speak rsync's large protocol, which changes between versions,
where fixed blocks need only `dd` and a digest tool.

2026-10-12, the calls made in the work: `crates/podssh-cli/src/cp/delta.rs`.
One command reads each far block, a loop of `dd` into the first digest
tool that the server has, after a marker line, so that a banner of the
login is never taken for a digest; a command per block would cost a round
trip each. The far file's digests and the local ones make the plan; for a
copy down the old version is the local file, copied on this disk into the
temporary file. A copy that broke goes on in full where it was (its side
file), not by blocks. The rolling delta between podssh ends (step 3) is
T-150's, which is parked. The measurement shows the gain in bytes (1 MiB of
20 sent), but `--delta` needs exec, `dd` and, up, `copy-data`, and reads
the whole far file: the full copy stays the default, and the flag is the
user's choice.

## Prove

```sh
cargo test -p podssh-cli --test cp_delta   # the plan: equal, changed, grown and shrunk files
sh scripts/dev.sh check                    # interop-cp.sh: 20 MiB with 1 MiB changed
```

In the gate, the second copy of the changed file sends less than 3 MiB of
payload (T-137's counter, shown at `-v`), and the digests are equal. Plant:
compare the blocks by size only; the changed block is then not sent, and
the final digest check must fail the copy.

## Correction

The plant's last words assumed no fallback. With step 5's fallback, the
digest check fails the delta, and a full copy follows and succeeds: the
check of the gate fails on that ("a full copy follows"), not on the copy's
exit.

## Done

2026-10-12. `cargo test -p podssh-cli --test cp_delta`: 5 passed (an equal
file sends no block; a changed block is the only one sent; a grown file
sends its new blocks and its changed last one; a shrunk file keeps its
blocks and its size cuts the rest; the local blocks are the digest of each
MiB); the unit tests read the script's digests after its marker and keep
the script free of a single quote. In the build image, `scripts/interop.sh`
against OpenSSH: `cp.delta.up`, 1048576 bytes sent of 20 MiB, and
`cp.delta.down`, 1048576 bytes fetched, each with equal digests and no full
copy. Planted defect: blocks compared by their presence only; both checks
failed, as no block went and a full copy followed. `-v` says the blocks
sent and their bytes; `docs/cli.md` and `docs/STATUS.md` say the rest.

# T-143: Copy directories: `-r`, `--exclude`, an ignore file, `--dry-run`

**Source:** the `-r` row (`crates/podssh-cli/src/flags/copy.rs:46-47`);
GitHub #21 (syq's `--dry-run`, parsync's `--exclude`, slingshot's copy with
no build output) and GitHub #18 (quic-ssh's `qsh cp -r`), read in the
issues.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

T-134 copies files, not trees. A tree needs a shell loop, which a cage may
not have. `-r` is a row of the table today; T-134 makes it refuse until
this entry, so that it is never a flag that does nothing.

## Premise

- Read, at `6483366`: `-r` is supported in `crates/podssh-cli/src/flags.rs`
  lines 251-252, and nothing reads it (`crates/podssh-cli/src/tree.rs`
  lines 351-365).
- Read: SFTP version 3 has `OPENDIR`, `READDIR`, `MKDIR`, `LSTAT`,
  `READLINK` and `SYMLINK`.
- Not verified here: OpenSSH's `scp` once wrote files that a malicious
  server named (CVE-2019-6111); a client must check each name that it gets.

## Approach

1. Walk the source depth first with `lstat`, 64 levels at most. Locally,
   refuse a directory seen twice (the same device and inode): a loop.
2. Invariant: each name from `READDIR` is one component. Refuse `.`, `..`,
   a `/`, a NUL, and on Windows `\`, `:` and device names. Nothing is
   written outside the target.
3. Copy a symbolic link as a link (Decision). Skip devices, FIFOs and
   sockets with a note; the exit is then not zero.
4. Each file goes through T-134 (temporary name, digest, rename). A
   directory gets its mode after its files.
5. `--exclude PATTERN` (repeatable) and `--exclude-from FILE`: `*` and `?`
   inside one component; a pattern with a `/` matches the path from the
   root of the copy; `*` never matches `/`.
6. `--dry-run`: one line on stdout for each action (`mkdir`, `copy`,
   `skip`, and T-144's `delete`), or `--jsonl` objects. It reads the far
   side and changes nothing.
7. After an error in the tree, go on with the other files, report each
   error, and exit non-zero at the end, as `scp` does.
8. The `-r` row works again; the manual and `docs/cli.md`.

## Decision

Recommendation: copy symbolic links as links in `cp`; `podssh scp -r`
follows them, as OpenSSH's `scp -r` does (its manual says so; not measured
here), with the loop check. Following links in `cp` lost: a link to `/`
copies the whole host. The ignore file is read only when `--exclude-from`
names it. A fixed file name read on each run lost: it changes what is
copied with no word on the command line.

## Prove

```sh
cargo test -p podssh-cli --test cp_tree   # the walk, the names, the patterns, the dry run
sh scripts/dev.sh check                   # interop-cp.sh: a tree up and down
```

The fixture tree has levels, an empty directory, a link, a FIFO and names
with a space; the `sha256sum` lists of both trees are equal. `--dry-run`
leaves both trees as they were. A wrapped `sftp-server` that sends `../x`
in `READDIR` is refused, and nothing is written outside the target. Plant:
drop the name check; that case must then fail.

## Correction

2026-10-09 (T-134): `-r` is refused by name now
(`crates/podssh-cli/src/flags/copy.rs:46-47`), and `podssh cp` copies files
(`crates/podssh-cli/src/cp/`): this entry builds on its temporary name, its
digest check and its rename for each file of a tree.

2026-11-02 (GitHub #105): step 3's "the exit is then not zero", which the
Decision gives "as `scp` does", holds for OpenSSH's `scp -O` alone. Read in
OpenSSH 10.2p1 (`openssh/openssh-portable:sftp-client.c` at the tag
`V_10_2_P1`, `upload_dir_internal` and `download_dir_internal`): `scp -r` in
its SFTP mode, the default since OpenSSH 9.0, and `sftp`'s `put -r` and
`get -r` log a device, a FIFO or a socket as "not a regular file" and go on
with no failure. T-476 makes such a skip no failure.

## Done

2026-10-12. `crates/podssh-cli/src/cp/tree.rs` (the walks, the names, the
patterns) and `crates/podssh-cli/src/cp/tree_copy.rs` (each item, through
the copy of one file with its continuation after a break). The calls made:
a far listing's `.` and `..` are passed over and each other name that is
not one component is refused before any `lstat` (70); a directory comes
before what it holds; into a directory that exists the copy goes under it;
a loop is found by canonical paths here and `realpath` there, also with no
link followed (a junction); a link on the server is made with SFTP's
`symlink` in OpenSSH's order of its two paths, and one here on Windows
needs the right to make it, else it is reported; a tree goes up or down
over SFTP only; `mv -r` removes the source after a tree copied whole; a
directory without `-r` says "a directory; -r copies it". `sftp`'s own `-r`
(its `get -r` and `put -r`) stays refused by name: T-298, new.
`cargo test -p podssh-cli --test cp_tree`: 3 passed (a tree up, into a new
name, and down, under a directory that exists, equal to the source; a dry
run says `mkdir`, `copy` and the paths and changes nothing; `--exclude` of
a name and of a path from the root; `mv -r`; a listing that names
`../escape` refused with nothing written outside the target and the rest
of the tree there; the tree flags need `-r`); the unit tests of the names,
the patterns, an exclude file and a local walk. In the build image against
OpenSSH: `cp.tree.dry_run`, `cp.tree.up` (a link a link, a FIFO skipped and
an exit not zero, the lists of digests equal) and `cp.tree.down`. Planted
defect: no check of the names; the test of `../escape` failed.

# T-144: `podssh cp --delete`: make the target a mirror

**Source:** GitHub #21 (parsync's `--delete`, its PR 12, read in the issue).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

After T-143, a second `cp -r` adds and replaces files, but it keeps the
files that the source no longer has. A mirror needs deletes, and a wrong
delete loses data that no command can bring back.

## Premise

- Read: no podssh command deletes on a far host today; T-138 deletes one
  source, after a verified copy.
- Read: T-143's `--dry-run` shows each action before it runs, and its name
  checks keep each path inside the target.

## Approach

1. `--delete` needs `-r` and a directory as the target; else exit 64.
2. Invariant: deletes run only after each copy of the run succeeded and was
   verified. One failed copy means no delete at all: say that nothing was
   deleted, and exit non-zero.
3. Delete only what the source lacks, inside the walked tree. Never delete
   an excluded name (T-143). Remove a link, never the file it points to.
4. Refuse a target that is the root of a file system or the home directory
   (exit 64).
5. `--dry-run --delete` lists each `delete` line. At the end, stderr gives
   the number of deletes; `-v` and `--jsonl` give each one.
6. The manual and `docs/cli.md`.

## Prove

```sh
cargo test -p podssh-cli --test cp_tree -- delete   # the plan, the refusals, root targets
sh scripts/dev.sh check                              # interop-cp.sh: the --delete cases
```

The fixture target has extra files, an excluded file, and a link to a file
outside it: after `--delete`, only the extra files are gone. When one copy
fails (a source file that cannot be read), nothing is deleted. Plant:
delete before the copies; the failing case must then fail the test.

## Done

2026-10-12. `crates/podssh-cli/src/cp/tree.rs` (`to_delete`) and
`crates/podssh-cli/src/cp/tree_copy.rs` (`finish_deletes`). The calls made:
the deletes of each tree wait for the end of the run, and go only when no
copy of the run failed; the target's walk follows no link, and leaves out
what the patterns name and what it cannot list; the root of a copy is
refused when it is a root of a file system or the home directory, here or
on the server (`realpath`), before anything is copied; a delete that fails
is reported, and the others go on. A tree copied again over itself keeps a
link that names the same, and replaces what else is at a link's name (the
gate's mirror check found that SFTP's `symlink` does not overwrite). `cargo test -p podssh-cli --test cp_tree
-- delete`: 3 passed (a mirror up with a dry run first, and down; nothing
deleted after a failed copy; the login directory refused, and `--delete`
without `-r`); the unit test of the deletes' order. In the build image
against OpenSSH: `cp.delete.mirror` and `cp.delete.failed`. Planted defect:
deletes after a failed copy; that test failed.

# T-145: Progress, cancellation and a bandwidth limit for copies

**Source:** GitHub #21 (MobaRust's progress and cancellation) and GitHub #25
(a bandwidth limit; syq's `greaber/syq:src/bwlimit/` in GitHub #19), read
in the issues; the `-l limit` of OpenSSH's `scp` and `sftp` (T-139).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A copy through the relay can take minutes (0.5 to 0.7 MB/s in the KTM
sandbox, `docs/STATUS.md:414`). podssh would show no progress, a Ctrl-C
would leave a temporary file with no word, and one copy can take the whole
uplink of a shared host.

## Premise

- Read: stdout carries answers only, and messages go to stderr
  (`crates/podssh-cli/src/dispatch.rs:3-7`). `cp` has a `--jsonl` row
  (`crates/podssh-cli/src/flags/copy.rs:60-61`).
- Read: `podssh ssh` handles SIGTERM and SIGHUP only with a raw terminal
  (`crates/podssh-ssh/src/terminal/termination.rs:26-93`); no copy code exists yet.
- Measured (T-139): the `scp` and `sftp` of OpenSSH 10.3p1 take
  `-l limit`. OpenSSH's manual gives the unit as Kbit/s (not read here).

## Approach

1. Progress on stderr only when stderr is a terminal: one line, rewritten
   with a carriage return, 4 times a second at most (name, bytes, percent,
   rate, time left). `-q` turns it off. Nothing in a pipe.
2. `--jsonl`: a `progress` object each second, besides T-134's `done` and
   `error`.
3. Cancellation: the first SIGINT or SIGTERM ends the request in flight,
   closes the handles, keeps the temporary file and the side file (T-136),
   names them, and exits 130. A second signal exits at once. On Windows,
   the same with Ctrl-C.
4. `-l LIMIT` in Kbit/s, as in OpenSSH: a token bucket before each data
   request. For a download it also keeps fewer requests in flight.
5. Invariant: the request size follows the limit, so that each request
   ends well inside T-133's progress limit of 60 s.
6. The manual and `docs/cli.md`.

## Decision

Recommendation: on Ctrl-C, keep the partial file for a continue (T-136),
and print its name so that the user can remove it. Removing it at once
lost: the bytes already sent would be sent again. `-l` on `cp` uses the
unit of OpenSSH (Kbit/s), so one number means the same on `cp` and `scp`.

## Prove

```sh
cargo test -p podssh-cli --test cp_progress   # the line, the rate, the token bucket
sh scripts/dev.sh check                       # interop-cp.sh: -l, SIGINT, a pipe
```

In the gate, `-l 8000` on 5,000,000 bytes takes 4.5 s or more. SIGINT
after 1 s exits 130, the temporary and side files exist, and a second run
continues. A copy in a pipe writes nothing to stdout. Plant: write the
progress to stdout; the pipe case must then fail.

## Correction

2026-10-09 (T-134): the copy code exists now
(`crates/podssh-cli/src/cp/`): with `--jsonl`, each file gives one `done` or
`error` object; the events of progress are this entry's.

2026-10-12. CI at `ebde017` failed the bucket's test in the three gate
jobs: the test made its bucket, then read the clock again, and the time
between the two gave the bucket bytes, so the first wait was a little under
250 ms. The bucket now takes the instant that it starts at
(`Bucket::of_kbits_at`), and the test gives it its own; the interop checks
`cp.limit` (5.1 s) and `cp.interrupt` passed in that run.

## Done

2026-10-12. `crates/podssh-cli/src/cp/gauge.rs` (the line and the
`progress` objects), `crates/podssh-cli/src/cp/rate.rs` (the token bucket
of `-l`, which the run's copies share, with requests of 10 s of bytes at
most and about one second of them in flight), and the interruption in
`crates/podssh-cli/src/cp/mod.rs` (`interrupted`), which names the copy's
temporary file and side file from the record that `Progress::save`
keeps. The calls made: `PODSSH_PROGRESS=line` or `off` sets the line on or
off, so that a test can show that it never reaches stdout; the line counts
the bytes of this run, not those that an earlier attempt brought; `-l`
waits in the copy's loops, before each write and after each read, which
also keeps fewer reads in flight; `sftp -l` and `scp -l` take it too.
`cargo test -p podssh-cli --test cp_progress`: 3 passed here (the line,
the rate and the time left; the bucket and the sizes under a limit; a copy
under `-l 8000` that takes 1.4 s or more, its line on stderr only, its
`progress` objects with `--jsonl`, and `-l 0` refused); the test of SIGINT
runs on Unix (130, the partial copy named, the next run goes on). In the
build image against OpenSSH: `cp.limit` (5,000,000 bytes in 4.5 s or more,
nothing on stdout) and `cp.interrupt`. Planted defect: the line on stdout;
the test of the pipe failed.

# T-146: Keep the metadata of a copy

**Source:** the `-p` row (`crates/podssh-cli/src/flags/copy.rs:22-23`);
GitHub #21 (syq's metadata: hard links, ACLs, extended attributes, sparse
files, ownership, its pull requests 777 and 778; read in the issue).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

`scp -p` keeps the mode and the times of a file. `podssh cp -p` parses and
does nothing (T-134 makes it refuse until this entry). Other metadata (the
owner, hard links, the holes of sparse files) is lost with no word.

## Premise

- Read, at `6483366`: `-p` is supported in `crates/podssh-cli/src/flags.rs`
  lines 247-248, and nothing reads it (`crates/podssh-cli/src/tree.rs`
  lines 351-365).
- Read: the attributes of SFTP version 3 carry the size, uid, gid,
  permissions, atime and mtime; no ctime.
- Measured (T-133's offline probe): OpenSSH's server offers
  `hardlink@openssh.com` and `lsetstat@openssh.com`, and no request for
  extended attributes or ACLs.

## Approach

1. `-p`: set the permission bits, the access time and the modification
   time on the temporary file, before the rename. SFTP: `FSETSTAT`;
   locally: `set_permissions` and `File::set_times`; exec road: `chmod`
   and `touch -t`.
2. The owner only with `--owner`, and only when the far user is uid 0; else
   a note says that the owner was not kept.
3. Hard links inside one `-r` upload: two local names with one device and
   inode arrive as one file and a `hardlink@openssh.com` link. A far source
   shows no inode in SFTP version 3.
4. Sparse files: do not write a block of 64 KiB that is all zero, and set
   the size at the end; the far file then has holes where its file system
   allows them.
5. Extended attributes and ACLs are not kept; the manual says so.
6. The manual lists what `-p` keeps and what nothing keeps; the `-p` row
   works again.

## Decision

Recommendation: the mode and the times first (as `scp -p`), then sparse
files and hard links, and the owner only on request. Extended attributes
and ACLs lost for now: no field of SFTP version 3 carries them, and a claim
that podssh keeps them would be false.

## Prove

```sh
cargo test -p podssh-cli --test cp_meta   # the attribute plan for each option
sh scripts/dev.sh check                   # interop-cp.sh: -p, sparse files, hard links
```

In the gate, `stat -c '%a %Y'` is equal on both sides after `-p`. A sparse
file of 100 MiB with 1 MiB of data uses less than 2 MiB on the far side
(`du`). Two hard-linked names arrive as one inode. Plant: drop the mtime;
the `stat` check must then fail.

## Correction

2026-10-09 (T-134): `-p` is refused by name now
(`crates/podssh-cli/src/flags/copy.rs:22-23`); a copy keeps the source's
permission bits already, and this entry adds the times and the rest.

## Done

2026-10-12. `crates/podssh-cli/src/cp/meta.rs` (what a copy keeps: the
plan of the attributes, their setting on each side, the holes, the hard
links), `crates/podssh-cli/src/cp/byexec/keep.rs` (the copy by exec's:
`chown`, `chmod` and `touch -t` in UTC up, `stat` down), and in
`podssh-ssh` `Sftp::hardlink` and `Writes::skip`. `-p` works for `cp`,
`mv`, `scp` and `sftp` (`sftp -p`, `get -p`, `put -p`), on each road, up,
down and within one server, and with `-r` for each directory, set after
its files; `--owner` and `--sparse` are new rows of `cp` and `mv`. The
calls made: (1) `--owner` asks the side that writes to set the owner, and
says so when it refuses, in place of asking first whether the far user is
root: a user who is not root may still give a file its own group, and the
refusal is the same answer. (2) Holes up when the source has them (fewer
blocks than its size, or Windows's sparse attribute), and both ways with
`--sparse`: holes in each block of zeros of a file that has none would
give away the blocks that a program reserved, which GNU `cp`'s
`--sparse=auto` avoids too; none with `--parallel` or `--delta`, which may
write a block again, and none by exec. (3) Measured here: the
`sftp-server` of Git for Windows (Cygwin) sets a file's access time at a
rename, and at a stat, which reads the file's first bytes; so with `-p`
the times are read back after the rename and set again when they differ,
and the access time of a far source on such a server cannot be read as it
was. (4) On Windows a source's hard links are found by the volume's serial
number and the file's index (`GetFileInformationByHandle`), as the
device and the inode on Unix. `cargo test -p podssh-cli --test cp_meta`: 7
passed here (the plan of each option; `-p` up and down, the copy's own
time without it, the mode; each directory of a tree; `scp -p`, `put -p`,
`get -p` and `sftp -p`; `--sparse` each way, with each byte; two
hard-linked names as one file, and again over itself, with no temporary
name left; `--owner`); `cargo test -p podssh-ssh --test sftp_pipeline`: 7
passed (a hole is never written and counts as acknowledged, also with
replies out of order; `hardlink@openssh.com`). In the build image against OpenSSH (`scripts/interop-keep.sh`): `keep.times.up.sftp`, `keep.times.down.sftp`, `keep.times.up.exec`, `keep.times.without`, `keep.times.dirs`, `keep.sparse.up` and `keep.sparse.down` (a sparse file of 100 MiB with 1 MiB of data took 1024 KiB on each side), `keep.hardlink` (one inode) and `keep.owner.up` and `keep.owner.down` passed; `keep.times.down.exec` found the access time moved, as BusyBox's `wc -c` read the file before `stat` did: `stat` comes first now, and that check waits for CI's gate. The Unix branches of `cp_meta` in the build image, as root: 7 passed. Planted
defects: a local file's modification time dropped from its stamp: the
three tests of `-p` failed; dropped from the plan of the attributes only:
its test and the tree's failed, and the copy of a file kept its time
through the check after the rename.

2026-10-30, later: on the arm64 Mac of T-218's trial (run 41074530703) the
test of `--sparse` found each copy fully allocated (4231168 bytes of
4228901), where the Intel Mac and Linux kept the holes; the copies were made
by seeks past the end, by podssh down and by OpenSSH's `sftp-server` up. The
test now makes the sparse source first, and checks the holes only where the
source itself has them, so that a file system that keeps no hole is not
taken for a defect of podssh; each byte is checked everywhere. Linux:
`cp_meta` sparse passed, with the holes checked. The next run on the arm64
Mac (41077717450) passed with the holes checked: the same code, so the count
of blocks moves there. Each file is now synced before its blocks are
counted, as a file system may count the room that it keeps for writes not
flushed yet.

# T-147: `podssh cp --inplace`

**Source:** GitHub #21 (syq's atomic replacement and its explicit
`--inplace`, `greaber/syq:docs/reference.md`, read in the issue).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

T-134 writes a temporary file and renames it. That needs space for a second
copy, gives the destination a new inode (a hard link, or a process that
holds the file open, keeps the old file), and fails in a directory where
podssh may write the file but not add a name.

## Premise

- Read: T-134's rule writes beside the destination, then renames; a rename
  gives the name a new inode.
- Measured (T-133's offline probe): `posix-rename@openssh.com` replaces in
  one step on OpenSSH's server; `--inplace` does not use it.

## Approach

1. `--inplace` writes into the destination itself: open with no truncate,
   write, then set the size to the source's at the end.
2. Say first, on stderr, that a failure leaves the destination damaged.
3. Invariant: T-134's digest check still runs. A mismatch exits non-zero
   and says that the destination is damaged, never that it is unchanged.
4. Refuse a destination that is a symbolic link (exit 64): the write would
   go through the link.
5. T-136 continues at the verified offset in the destination; with T-142,
   only the changed blocks are written.
6. With `mv` (T-138), the source goes only after the check, as before.
7. The manual and `docs/cli.md`.

## Prove

```sh
cargo test -p podssh-cli --test cp_args -- inplace   # refusals: a link, a directory
sh scripts/dev.sh check                              # interop-cp.sh: the --inplace cases
```

In the gate, `stat -c %i` of the destination is equal before and after,
and the digests are equal. With T-134's server that flips a byte, the exit
is not zero and the message says that the destination is damaged. Plant:
write to a temporary name and rename; the inode check must then fail.

## Done

2026-10-12. `crates/podssh-cli/src/cp/in_place.rs` (the refusals, the
open with no truncation here and on the server, the message of a damaged
destination, and the check before a copy down connects), and `--inplace`
on each road: `bysftp.rs` up and down, in chunks too, `delta.rs` (the
changed blocks go into the destination, and no `copy-data` is needed),
`transfer::within`, and the copy by exec (`byexec/files.rs`: a first
attempt with `cat >`, whose truncation keeps the inode, a later one with
`cat >>`, a link refused by `test -L`, and no `mv` at the end). The calls
made: (1) a temporary file that is the destination is never removed: a
failure, a stale record (`session::drop_temp` now removes only podssh's
temporary names) and a source that changed leave it, and each failure
after the first write says that it is damaged, in place of "the
destination was not changed". (2) The notice is said once a run, before
the first byte, as `mv`'s is. (3) A local destination that is a link or a
directory is refused before anything connects, so a test without a server
shows it. (4) No holes in place: the destination's old bytes would stay in
them. `cargo test -p podssh-cli --test cp_inplace`: 2 passed here (up and
down over a longer old file, a second hard-linked name sees the new bytes,
without `--inplace` it keeps the old ones; `--delta` and `mv`), and the
test of a link refused runs on Unix; `--test cp_args`: 9 passed, with the
refusals of a directory (and, on Unix, a link) before anything connects.
The gate's checks (`scripts/interop-inplace.sh`: the same inode by `stat`
on each road and each way, a flipped byte that exits 70 and names the
destination damaged, a link refused) and the planted defect wait for
T-251.

# T-148: ZMODEM in a terminal session

**Source:** GitHub #21 (meatshell: ZMODEM `sz` and `rz` inside the
terminal, a copy that needs no SFTP; read in the issue).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Some servers give a shell and nothing else: no SFTP, and exec refused (a
jump host or a menu behind `ForceCommand`). There a file can cross only
inside the terminal session. lrzsz's `sz` and `rz` do that with ZMODEM,
which needs support in the terminal client.

## Premise

- Read: `podssh ssh` writes the remote output to stdout as it comes
  (`crates/podssh-ssh/src/io/msg.rs:11-30`) and passes the local keys through
  the escape filter (`crates/podssh-ssh/src/io.rs:218-277`). Nothing looks
  for a ZMODEM header.
- Not verified here: ZMODEM escapes its control bytes, so it crosses a pty;
  whether a ZMODEM crate in pure Rust exists and is maintained.
- Read: T-135's exec road covers each server that allows exec.

## Approach

1. In a session with a pty and a local terminal, watch the output for the
   start of `sz` (`**`, ZDLE, `B00`). Ask on the terminal whether to
   receive, and where. With no terminal, never receive.
2. Receive with T-134's rule: a temporary name, the CRC of each frame and
   the length, then the rename. Never write over a file without asking.
3. Send: when `rz` starts on the far side, ask for a local file; also a new
   escape command in `crates/podssh-ssh/src/escape.rs`.
4. Invariant: each wait for a frame has a limit (10 s), with the retries
   that the protocol defines; then the transfer ends and the session goes
   on.
5. Pure Rust in `podssh-ssh`; the manual and `docs/terminal.md`.

## Decision

Recommendation: do this last among the copy roads, when a server is found
that gives a shell and refuses both SFTP and exec. Until then T-135 covers
each server with exec. Starting it now lost: a ZMODEM implementation is
large, and no measured server needs this road yet.

## Prove

```sh
cargo test -p podssh-ssh --test zmodem   # the header search, frames, CRC, limits
sh scripts/dev.sh check                  # a pty session with lrzsz in the gate
```

The gate adds `lrzsz`. A scripted pty session (as `scripts/interop-pty.py`
drives one) runs `sz FILE`, answers yes, and the file arrives with an equal
digest; `rz` gets a local file the same way; with no terminal, nothing is
written. Plant: receive with no question; the no-terminal case must then
fail.

## Correction

2026-10-09 (T-135). **The third Premise is too broad**: the exec road needs
a POSIX `sh` that the login shell can start, and `cat`, `wc`, `mv` and `rm`
on the server; without them it exits 69 and names what is missing. A
server that runs commands in another shell, or lacks one of those tools,
allows exec and still has neither road: such a server is the one that the
Decision waits for.

2026-10-12. **The second Premise, read.** ZMODEM escapes ZDLE, 020, 0220,
021, 0221, 023 and 0223, and its receiver ignores XON and XOFF (the spec's
section 7.2, "The ZMODEM Inter Application File Transfer Protocol", Chuck
Forsberg, 1988); lrzsz's `sz` and `rz` set their pty raw, so each other
byte crosses as it is. A ZMODEM crate in pure Rust exists and is
maintained: `zmodem2` (MIT OR Apache-2.0, sans-IO, 0.7.3 on 2026-10-10,
read on crates.io and docs.rs); the Done says why podssh has its own.

2026-10-12. **The Prove's "The gate adds `lrzsz`" does not hold.**
pkgs.alpinelinux.org lists no package `lrzsz`, and no file `sz`, `rz`, `lsz`
or `lrz`, in edge (main, community and testing) or in v3.18 (read on
2026-10-12; not measured in the build image). `scripts/interop.sh` therefore
tries `apk add lrzsz` apart from its other packages, and the ZMODEM checks
of `scripts/interop-pty.py` print `env` without it; the baseline allows
that. Until the build image has `sz` and `rz` (built from lrzsz's source,
or another package), those checks do not run.

## Done

2026-10-12. ZMODEM in `crates/podssh-ssh/src/zmodem/`: `wire.rs` (the
CRCs, the escapes, hex and binary headers, subpackets), `read.rs` (the
reader of headers and subpackets, a byte at a time), `detect.rs` (the start
of `sz` and `rz` in the output, with its CRC), `receive.rs` and `send.rs`
(the two sides, sans-IO), `files.rs` (the check of a name, T-134's
temporary name and rename, the file to send), `ask.rs` (the line of a
question), and `session.rs` with `session/acts.rs` (`Zmodem`, which joins
them to a session). The pump (`crates/podssh-ssh/src/io.rs`) gives it the
output, the keys and the time, and sends what it has; the session
(`crates/podssh-ssh/src/session.rs`) makes one only with a raw terminal and
a terminal on stdout. The window's size and the signals moved from `io.rs`
to `crates/podssh-ssh/src/terminal/watch.rs`, so that `io.rs` stays under
500 lines. The escape `~Z` (`crates/podssh-ssh/src/escape.rs`); the
variable `PODSSH_ZMODEM` (`off`); the manual's notes of `ssh` and its
ENVIRONMENT; `docs/terminal.md` ("ZMODEM in a session").

The calls made where the Approach left a choice:

- podssh's own code, not `zmodem2`: its minor versions 0.2 to 0.7 came
  from 2025-09 to 2026-06, each free to change its API, and it would bring
  `hex` and `thiserror` 1 into the library; the part that one file each way
  needs is about 2,300 lines here with their comments, and its tests check
  it against vectors from the spec.
- The question reads its keys from the session's input task, not from the
  terminal a second time: that task holds a read of stdin, and a second
  reader would take keys from it. While a question is open the far side
  waits (`sz` sends ZRQINIT again, `rz` ZRINIT), and what it sends meanwhile
  is dropped.
- Receive asks for a directory: Enter takes the last one (the current
  directory at first), a path changes it, Ctrl-C refuses. A name that is
  taken asks again, `[y/N]`; the answer `y` replaces it. A name counts by
  its last component, checked as T-143 checks a far listing. The file gets
  the server's time, and its mode without the write bits of the group and
  others.
- Send: the key `~Z`, which no escape of OpenSSH uses (`~C` is T-291's,
  `~d` T-158's). It asks for the file, then types `rz` and Enter, as the
  spec lets a sender do (8.1). ZFILE has no option of management, so that
  the far `rz` keeps its own rule for a name that exists.
- ZRINIT's flags are those of lrzsz's `rz` (0x23: full duplex, I/O during
  the disk's work, CRC-32); subpackets of 1024 bytes; a stream with ZCRCG,
  and ZCRCW where the receiver gives a buffer.
- Each wait 10 s, 4 waits ("40 seconds total", 8.1), then the cancel
  sequence; the same ZRPOS 4 times also ends it. Ctrl-C during a transfer
  cancels it, and each other key is dropped. A file of 4 GiB or more is
  refused, and a command from the server (ZCOMMAND) never runs.
- A start counts only with its 14 hex digits and their CRC; the bytes of a
  start that a message cut wait 100 ms at most.
- Through a control master, `~Z` says that ZMODEM works in a session of its
  own.

`cargo test -p podssh-ssh --test zmodem`: 20 passed here and in the build image (the CRCs'
check values; hex headers equal to what lrzsz prints, `B0100000023be50`
and `B00000000000000`; binary headers, escapes and subpackets equal to
vectors computed apart from this code from the spec's rules; each byte
value with each frame end and each CRC; a changed byte fails the CRC; five
CAN cancel and four do not; the detector with text around a start, a bad
CRC, a cut start and the hold; ZFILE's data; the names; 70,001 bytes
between the two sides; each wait and its tries, 40 s in all; ZRPOS for a
wrong position and for a bad CRC, and a ZEOF at another position ignored;
no watcher with no terminal; the session asks, then receives into the
directory given with no temporary file left; a name that is taken replaced
only after `y`; a refusal; a command refused; Ctrl-C keeps nothing; the
session sends the file named to `rz`). `cargo test -p podssh-ssh --lib
escape` and `cargo test -p podssh-cli --lib man`: passed. The gate's
check (`scripts/interop-pty.py`, `pty.zmodem.*`: `sz`, a refusal, `rz`,
`~Z`, and no terminal) and the planted defect (receive with no question;
`pty.zmodem.no_terminal` must then fail) wait for T-251, and for `sz` and
`rz` in the build image (Correction).

# T-149: `podssh edit HOST:PATH`

**Source:** GitHub #21 (MobaRust: work on remote files, with a check for
remote changes before the save; read in the issue).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

To change one file on a far host from a cage, a user copies it down, edits
it, and copies it back. Meanwhile someone can change the file on the far
host, and the copy back then destroys that change with no word.

## Premise

- Read: podssh starts another program only when the user names it or a
  probe found it (`AGENTS.md` rule 3). `podssh man` finds `less` with a
  probe (`crates/podssh-cli/src/pager.rs:96`) and runs it with
  `run_program` (`crates/podssh-cli/src/pager.rs:134`).
- Read: `VISUAL` and `EDITOR` are not in the manual's variables
  (`crates/podssh-cli/src/man/facts.rs:46-300`).
- Read: the relay cuts a session after 180 s with no payload
  (`crates/podssh-relay/src/relay.rs:19-21`); an editor stays open longer.

## Approach

1. A new verb `edit` in `VERBS` (`crates/podssh-cli/src/flags.rs:372-436`),
   with the connection flags that T-134 gives `cp`. It needs a terminal on
   stdin and stdout; else exit 64.
2. Download with T-134 into a new directory of mode 0700 in the cache
   directories (`crates/podssh-relay/src/cache/dirs.rs:136-241`), as a file of
   mode 0600 that keeps the far name's extension. Record the far size,
   mtime and SHA-256.
3. Close the session while the editor runs (Decision).
4. The editor: `VISUAL`, then `EDITOR`, then `vi` when a probe finds it on
   `PATH`; else exit 78 and name `EDITOR`. No time limit: a person decides.
5. The same digest after the editor: nothing to send. Else connect again,
   stat and hash the far file. When it changed since step 2, keep the local
   copy, name it, and exit non-zero. Else upload with T-134, and keep the
   far mode.
6. Remove the local copy after success; keep it and name it after a
   failure.
7. Add `VISUAL` and `EDITOR` to `VARIABLES`; the manual and `docs/cli.md`.

## Decision

Recommendation: no session stays open while a person edits: no idle cut,
no 12 h cap, no connection held. T-137 keeps the credential in memory, so
the second open asks nothing. A session kept open with keepalives lost: it
holds a relay session for nothing, and it still fails when the link drops.

## Prove

```sh
cargo test -p podssh-cli --test edit_args   # the terminal and editor rules, refusals
sh scripts/dev.sh check                     # interop-cp.sh: the podssh edit cases
```

With `EDITOR` set to a script that adds a line, the far file gets the line
and the digests are equal. When the script first changes the far file
through `podssh ssh`, podssh refuses, keeps the local copy and exits
non-zero. Plant: skip the check of step 5; that case must then fail.

## Done

2026-10-12. `crates/podssh-cli/src/edit/` (`mod.rs`: the steps and their
exit codes; `editor.rs`: the choice of the editor and its run; `local.rs`:
the private directory and the copy; `far.rs`: the fetch, the check and the
send, each through the copy of one file of `cp`, `session::attempts`), the
rows of `crates/podssh-cli/src/flags/edit.rs`, and `Shape::mode`
(`crates/podssh-cli/src/cp/pipe.rs`), which gives a copy up the far file's
mode on its temporary file, before the rename, on both roads. The calls
made: the copy keeps the far file's whole name, not only its extension, as
an editor reads a name such as `.bashrc` too, and a name that this system
cannot hold becomes `file` with the extension; the editor is chosen before
the terminal is checked, so that a test of the binary with no terminal
reaches both refusals; a value of `VISUAL` or `EDITOR` is split at blanks
with no shell, as `PAGER` is, unless it names a file, as a Windows path
with a blank does; an editor that ends with a status other than 0 sends
nothing, and podssh exits with that status (128 + N for a signal), as
`vim`'s `:cq` asks; after a failure the copy here stays, named, only when
it holds a change; `PODSSH_CACHE_DIR=none` refuses with 78, as it keeps no
file; a far file that changed is 73, as the destination of the send may
not be written; the mode of a far file by exec is read from its line of
`ls -lnid`; a symbolic link is resolved over SFTP (`lstat`, then
`realpath`) and the file that it names is edited, as T-134's rename would
put a file in the link's place, and by exec a link is refused (66), as no
portable command names its file; while the editor runs, SIGINT and SIGQUIT
are ignored with `sigaction`, so that tokio's handler comes back whole
(`crates/podssh-cli/src/pager.rs`, whose `Interrupts` the pager shares),
and on Windows a listener holds Ctrl-C; the first SIGINT or SIGTERM while
a file moves ends the run with 130. `cargo test -p podssh-cli --test
edit_args`: 5 passed here (a bad operand, no editor, 78 naming `EDITOR`, no
terminal, 64, the help with the connection flags and no `--timeout`, and
the choice of the editor); the unit tests of `edit::` (the operand, the
choice and the words of an editor, the name of the copy, the mode in a
line of `ls -lnid`, the hints of a copy): 6 passed; their Unix branches
(`sigaction`, the mode of the directory) passed clippy and the tests in the
build image. The gate's cases
(`scripts/interop-edit.sh`, sourced by `scripts/interop-cp.sh`: an
`EDITOR` script that adds a line, over SFTP and by exec, with the far mode
kept; no change; a far change made first through `podssh ssh`, refused
with 73 and the copy named; an editor that fails; a link) and the planted
defect wait for T-251.

# T-150: A copy protocol between two podssh ends

**Source:** GitHub #18 (zuko's `files` server, `adonm/zuko:src/files.rs`)
and GitHub #21 (parsync's internal helper,
`AlpinDale/parsync:src/remote_helper.rs`), read in the issues;
`docs/design.md:1360-1366`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

SFTP version 3 gives no digest of a file or of a range, and no list of
blocks. With a standard server, T-134 pays for that with a second read or a
probe of the far tools. When both ends run podssh (`podssh serve` with its
SFTP server, T-112; `podssh node`, T-083), podssh controls both sides and
can do better.

## Premise

- Measured (T-133's offline probe): OpenSSH's server offers no digest
  request; it names its own requests `NAME@openssh.com`.
- Read: `podssh serve` will have an SFTP server in the process (T-112).
- Read: both roads between podssh ends carry the same `cp`
  (`docs/design.md:1360-1366`).

## Approach

1. Add requests to T-112's SFTP server, under a domain that the operator
   chooses: the SHA-256 of a byte range, and the digests of the blocks of a
   range (for T-142).
2. T-133's client uses them only when the server's version reply lists
   them; else T-134's rules. Standard clients see a normal SFTP server.
3. Invariant: each request has T-133's reply limit, which grows with the
   size of the range (the server reads at the speed of its disk).
4. Write the wire format in `docs/design.md`, and add the requests to the
   fuzz targets (T-198).
5. Test both ways: podssh's client against `podssh serve`, and OpenSSH's
   `sftp` against `podssh serve`.

## Decision

Recommendation: requests of podssh's own inside SFTP, not a new protocol.
The SFTP server is in M5 (T-112), the client exists (T-133), and standard
tools keep working. A protocol of its own lost: a second wire format to
version, fuzz and test, which no standard tool can use.

## Prove

```sh
cargo test -p podssh-ssh --test sftp_extensions   # the requests, their limits, the fallback
sh scripts/dev.sh check                           # interop-cp.sh against podssh serve
```

In the gate, `podssh cp` to `podssh serve` checks its digest with no second
read (T-137's counter shows one transfer), and OpenSSH's `sftp` against
`podssh serve` still works. Plant: a server that lists the request and
returns a wrong digest; the copy must then fail with exit 70.

## Start condition

T-112 is done: `podssh serve` has an SFTP server.

# T-267: A copy follows a source that grows, and does not end

**Source:** CI, the run of `a22e3ec` (2026-10-09): the gate's step
`release` failed three checks of `scripts/interop-cp.sh` and the scripts
that it sources (194 passed, 3 failed), with a change that touched no code
of the copy.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The check "mv of a source that grows" (`scripts/interop-mv.sh:82-93`)
ended at its `--timeout` of 120 s, exit 75 in place of 66, and the
temporary file that it left on the server failed two later checks. The
same check passed in the runs before, with the same copy: a check that
fails at random hides a real failure. And a copy of a file that another
program writes on, such as a log, need not end at all.

## Premise

Read at `a22e3ec`: the copy up over SFTP reads the source until a read
gives no byte (`crates/podssh-cli/src/cp/bysftp.rs:174-200`), and each read
waits for the server's answer to the write before it. The check's writer
adds a byte to the source in a loop, so a read gives no byte only when the
writer adds none for a whole round trip: when the runner does not schedule
it. The check after the read gives 66 to a source whose size moved
(`crates/podssh-cli/src/cp/finish.rs:72-75`), but only once the read
ends. The copy up by exec reads the same way
(`crates/podssh-cli/src/cp/byexec/files.rs:139-165`); the copies down read
the far file until it ends, over SFTP
(`crates/podssh-cli/src/cp/bysftp.rs:359-398`) and with `cat`
(`crates/podssh-cli/src/cp/byexec.rs:332-369`); and so do the far digests
that read the file again (`crates/podssh-cli/src/cp/digest.rs:78-109`,
`crates/podssh-cli/src/cp/byexec.rs:303-330`).

## Approach

1. A copy reads what the source held at the start, and stops with 66, "the
   file changed while it was read", at the first byte past it: the result
   that the check after the read gives such a source anyway, now at once.
2. Down over SFTP, a second look at the far size at that byte: a file of
   `/proc` says 0 and has bytes, and its size stands, so its copy goes on
   as before.
3. The far digest by reading stops one byte past the copy's size: a far
   file that grows ends the read, and its digest differs.
4. Checks in `scripts/interop-cp.sh`: a source that grows, up on each road
   (ports 2201 and 2207) and down on each (2201, 2206, 2207 and 2209): 66,
   and no copy. A native test of the digest by reading, against OpenSSH's
   `sftp-server`.

## Prove

```sh
cargo test -p podssh-cli --lib cp::digest   # the digest by reading stops one byte past the copy
sh scripts/dev.sh check                     # interop-cp.sh and interop-mv.sh, in the build image
```

CI's step `release` passes "mv of a source that grows", the new checks of
a source that grows, and the checks of a temporary file, at the push of the
repair and at the pushes after it. Plant: the digest by reading with no
bound fails the native test.

## Done

2026-10-10. Each road of the copy reads what the source held at the start,
and stops with 66, "the file changed while it was read", at the first byte
past it: up over SFTP (`crates/podssh-cli/src/cp/bysftp.rs:174-200`) and by
exec (`crates/podssh-cli/src/cp/byexec/files.rs:139-165`); down by exec
past the size that `wc -c` gave; down over SFTP after a second look at the
far size, so that a file of `/proc` goes on as before. The far digest by
reading, over SFTP and by exec, stops one byte past the copy's size. One
function, `changed` in `crates/podssh-cli/src/cp/transfer.rs`, gives the
message on each road.
- Native: `cargo test -p podssh-cli --lib cp::digest`, 5 passed, the new
  test against Git for Windows' `sftp-server`; planted, the digest by
  reading with no bound fails it. `cargo test --workspace`: 1066 passed,
  0 failed, 30 ignored.
- The new checks of `scripts/interop-cp.sh`, and "mv of a source that
  grows", run in CI's step `release` at the push of the repair; its result
  goes into `docs/STATUS.md`.
- CI, the run of `5557c62` (37992184997), the first whose gate pulled its
  image (the runs of `a6ef7ba` and `b932993` met Docker Hub's refusal,
  T-268): the step `release`, interop 203 passed, 0 failed; each of the six
  new checks of a source that grows gives 66 and no copy, "mv of a source
  that grows" gives 66, and no temporary file stays. The whole run passed.

# T-296: `cp`, `scp` and `sftp` to a node

**Source:** T-140: the throughput method's SFTP cell on the reverse road
(`crates/podssh-cli/tests/throughput_live.rs`), which `podssh sftp` cannot
reach.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

`podssh ssh node://[user@]NAME` reaches the node of a pair through the
relay (T-084), but `podssh cp`, `scp` and `sftp` read `node://user@NAME` as
the host `node`. A user cannot copy a file to or from a node, and the
throughput of SFTP through the live relay cannot be measured: the live
relay reaches the test's server only as a node.

## Premise

- Measured (T-140, 2026-10-12): `podssh sftp -b BATCH node://tester@LABEL`
  exits 69 with "podssh: node: no connection to the server".
- Read: `crates/podssh-cli/src/cp/operand.rs` reads `[user@]host:path` and
  the URIs `scp://` and `sftp://`; `crates/podssh-cli/src/sftp/mod.rs`
  reads its destination with it. `ssh` resolves `node://` in
  `crates/podssh-cli/src/ssh/resolve.rs`.
- Read: `node://NAME/ROUTE` names a route of a node (T-089), so a path
  after the first `/` would mean two things.

## Approach

1. An operand `node://[user@]NAME[/ROUTE]:PATH` for `cp`, `mv` and `scp`,
   the path after the first `:` after the name, and a destination
   `node://[user@]NAME[/ROUTE][:PATH]` for `sftp`: the server is the node,
   reached as `ssh node://` reaches it.
2. A port, `-J` and `--direct` with a node are refused, as for `ssh`
   (exit 64).
3. The throughput method's SFTP cell on the reverse road runs; its figures
   go into `docs/STATUS.md` beside those of T-140.
4. `docs/cli.md` and the manual say it.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test node_copy
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test throughput_live -- --ignored --nocapture sftp_throughput
```

Through the stand-in relay and a pair, as `tests/node_routes.rs` runs them,
`cp` up and down and `sftp` get and put to a node agree with the disk; a
route is taken; a port with a node is refused. The second command measures
through the live relay. Planted defect: a node operand read as a host; the
first test fails.

## Done

2026-10-13. An operand `node://[user@]NAME[/ROUTE]:PATH` for `cp`, `mv`
and `scp`, and a destination `node://[user@]NAME[/ROUTE][:PATH]` for
`sftp`, read in `crates/podssh-cli/src/cp/operand.rs` (a `Remote` that is
a node, whose `destination` is the form that `ssh` resolves, so the label,
the route, the user and each refusal are those of `ssh node://`). The
copy's link (`crates/podssh-cli/src/cp/link.rs`, `hops`) reaches a node
through `reach` in `crates/podssh-cli/src/ssh/node.rs`: the pair and the
channel of T-088, taken as `pipe node:` takes them (the pair first, so a
copy that cannot go makes no key of this client), then a task that
carries the stream over the operator's leg, in the resumable layer when
the node offers it, with a new leg after each lost one, as `pipe node:`
carries its bytes; SSH and SFTP run on that stream as on the first hop of
any road, and the host key is kept under `node://NAME[/ROUTE]`. A port,
`-J` and `--direct` with a node are refused where `ssh` refuses them,
before anything connects (64).

The calls made where the Approach left a choice:

- With no `:` after the name, the path is the login directory, as `host:`
  is; `node://` always names a node, never a local path.
- `--pair-file`, `--client-key`, `--node-key` and `--no-e2e` are rows of
  `cp`, `mv`, `scp` and `sftp` too (`crates/podssh-cli/src/flags/copy.rs`,
  `crates/podssh-cli/src/flags/scp.rs`), in the words of `ssh`'s, so that a
  pair in an operator's file can be named: without them a copy reaches only
  the pairs stored under their label. `--iroh-ticket` is not: the race of
  two roads is the runner of `ssh` alone.
- A copy's session to a node has no relay meter (T-137): the layer moves
  it to a new leg before the relay's limits (T-155), and a node in plain
  mode that the relay cuts is a break, which the copy goes on after
  (T-136).
- A leg that the relay refuses before it starts gives the copy its code
  (69, 77 or 78), as `pipe node:` does. A carriage that fails later is said
  by its task, as `podssh operator` judges it (the channel's refusal, the
  leg's end), and the SSH side sees its stream end.
- Only the copy's link reaches a node: `podssh ping` and `pipe`'s `ssh:`
  call `ssh::transport::reach`, which still refuses a `node://`
  destination. `podssh edit` reads its operand with the same function as
  `cp`, so it reaches a node stored under its label too.

The manual (the notes of `cp`, `scp` and `sftp`, the help of `sftp`'s
destination, and an example of `scp` with an operator's file),
`docs/cli.md` and `docs/STATUS.md`. Tests: `cargo test -p podssh-cli
--test node_copy`:
`a_node_operand_names_its_pair_and_a_port_with_a_node_is_refused`
(offline: with no pair under the label, `cp`, `scp` and `sftp` exit 78 and
name the node and the remedy; with one, 69 at `PODSSH_OFFLINE` and no
token shown; no key of the client made; a port, `-o Port`, `-J`,
`--direct` and a bad route, 64) and
`copies_reach_a_node_and_its_route_through_the_stand_in_relay` (a node in
front of the test's server, with the route `other` to a second server:
`cp` up and down, `scp` up, `sftp`'s put and get, each equal to the
source, and a copy and a get through the route in the second server's
directory; it says that it did not run with no Python, no openssl or no
`sftp-server`): 3 passed on Windows 11, 2026-10-13. The unit tests of
`cp::operand` (a node, its route and the path after the first `:`) and of
`sftp`'s destination: passed. Planted, `node://` read as a host: both tests
failed; restored, they passed. The SFTP cell of the reverse road through
the live relay (`PODSSH_THROUGHPUT_MIB=1 cargo test -p podssh-cli --test
throughput_live -- --ignored --nocapture sftp_throughput`, 2026-10-13, 1
MiB a copy, 12 MiB through the relay): `sftp` to a node, with the layer,
put 0.13 to 1.30 MiB/s and got 0.13 to 0.71 MiB/s, by the requests in
flight (1 to 64 of 32768 bytes, and 1 or 2 of 261120); the run of 20 MiB a
copy moves more than 100 MiB through the live relay and waits for T-251.

# T-297: `cp --parallel K` copies several small files at once

**Source:** T-141, step 5 ("many small files: the same K tasks, one file
each").
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

`cp --parallel K` copies one file of more than a chunk as K chunks at once
(T-141), but many small files still go one after the other, each waiting
for its own round trips. A tree of small files through the relay takes the
sum of their latencies.

## Premise

- Read: `crates/podssh-cli/src/cp/session.rs`, `session` copies each source
  in turn through `attempts`, which owns the connection (`link: &mut
  Option<Link>`) to connect again after a break.
- Read: T-141's tasks each open an SFTP session of their own in one
  connection (`crates/podssh-cli/src/cp/chunks.rs`).

## Approach

1. With K > 1 and several sources, copy up to K files at once on the one
   connection, each over an SFTP session of its own, each with its own side
   file; a file of more than a chunk still goes in chunks.
2. A break ends the files in flight where they are; the next connection
   goes on with each from its side file, as one file does now.
3. The report keeps the order of the sources, and the first failure's code.

## Decision

2026-10-13, the calls made in the work:

- **The sessions.** The files go over the connection's own SFTP session
  and K - 1 more, so that K sessions at most share the connection, as the
  Prove counts them. A session that the server does not open is not a
  failure: fewer files go at once, and `-v` says so. OpenSSH opens 10
  sessions on one connection by default (`MaxSessions`), and the far
  digest of each file opens an exec channel too; a digest command that
  cannot start falls back to a second read, as before. K + 1 sessions lost:
  more than K at once. A copy that fails when a session is refused lost: a
  server with fewer sessions than K would fail each copy.
- **A file of more than one chunk** waits, and goes after the others,
  alone, in chunks with the K tasks of T-141, through `session::attempts`.
  Each file's size comes from the look at its source that each attempt
  makes first, so no request is added. Chunks inside a lane lost: up to
  2K - 1 sessions at once, and more than the relay's room in flight. A look
  at each far size before the run, to sort the files, lost: a round trip
  for each file, the cost that this entry removes. One stream in its lane
  lost: slower than T-141's chunks for a large file.
- **The files of a tree** (`cp -r`) go K at once too, though the Approach
  names the sources: the Problem is a tree of small files, the case that
  gains the most. They wait during the walk, which still makes each
  directory and link in its order, and go before each directory's mode is
  set and before `--delete` and `mv -r` look at what was copied. Another
  name of a file that waits sends the files that wait first, so that it
  becomes a hard link to the copy (T-146). `sftp`'s `get -r` and `put -r`
  (T-298) still copy one file at a time over the batch's one session.
- **A break** ends the attempt of each file in flight; no file starts
  after it on that connection. The next connection goes on with each file
  from its record (in memory in the run, and from its side file in the
  next run), at most 5 connections in a row with no new byte in any file
  and no file done, with the relay opener's backoff between them; a
  refused login or another host key ends each file that waits, as for one
  file. A count for each file lost: the files share each connection, so a
  connection that fails, fails each of them.
- **Through the relay** the files share 1.5 MiB in flight, as T-141's
  chunks do (`chunks::share`), and each request checks the session's
  budget (T-137). The K files can pass the budget by K requests at most,
  each of 255 KiB at most: within the 4 MiB between podssh's budget and the
  relay's cap. A session that is spent ends the attempt of each file in
  flight, and a new one goes on at once.
- **The report** takes each answer in the order of the sources: the first
  failure in that order sets the code, not the first in time. `mv` removes
  each source after the copies, in that order, over the connection's own
  session.
- **An interruption** names each partial copy and its side file: the
  record of the copies in progress is a list now
  (`crates/podssh-cli/src/cp/resume.rs`, `each_current`).
- **By exec** each file goes in one stream, in turn, as T-141's chunks do:
  writing at an offset needs `dd`, which T-135's probe does not ask for.
- **The test's server** counts the SFTP sessions of each connection, and
  keeps the most (`crates/podssh-cli/tests/ssh_harness/watch.rs`). The
  break is a cut of the first connection of a user `cut-N-...` after N
  bytes of SFTP input; a refusal of each later login of that user ends a
  run at the cut, for the test of the next run.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test cp_parallel -- small
```

Against the test's server, 50 small files with `--parallel 8` arrive, each
equal to its source, with at most 8 SFTP sessions at once (the server
counts them); the report lists them in their order. Planted defect: two
files into one temporary name; a digest check fails.

## Done

2026-10-13.

- `crates/podssh-cli/src/cp/lanes.rs`: the files K at once, each over an
  SFTP session of its own, each attempt as `session::attempts` makes one
  (the look at the source, the record, the copy, once more from the first
  byte after digests that differ), the files that wait for the next
  connection, and the files of more than one chunk after them.
- `crates/podssh-cli/src/cp/session.rs`: the sources that are files wait,
  then go K at once (each tree after the files named before it); each
  answer goes into the outcome in the order of the sources (`settle`, also
  for one file at a time). `crates/podssh-cli/src/cp/tree_conn.rs` and
  `crates/podssh-cli/src/cp/tree_copy.rs`: the files of a tree.
  `crates/podssh-cli/src/cp/resume.rs`: the look at a far source over a
  given session, and the list of the copies in progress;
  `crates/podssh-cli/src/cp/mod.rs`: the words of an interruption.
- The row of `--parallel` (`crates/podssh-cli/src/flags/copy.rs`), a note of
  `cp` in the manual, `docs/cli.md` and `docs/STATUS.md`.
- Tests, `cargo test -p podssh-cli --test cp_parallel -- small`: 6
  passed on Windows 11. Six tests: 50 files up and back down, 8 at once, at most 8
  SFTP sessions at once and 2 or more, one connection, the report in the
  order of the sources, nothing left; a file of two chunks among 6 goes
  after them in chunks, the report in order; a connection cut after
  1,500,000 bytes, 2 files or more go on where they were over the next
  connection; a run that ends at the cut (the next login refused), then
  the same command goes on from each side file whose temporary file is
  there; the first failure in the order of the sources sets the code (73
  at the rename of the first file onto a directory, though the sixth is
  missing, 66, and fails first), each other file copied; a tree of 36
  files up and down, 8 at once. The unit tests of `lanes.rs` (a file moved
  when its record holds more than before; a source of more than one chunk
  waits): 2 passed. The other tests of `cp_parallel`, `cp_tree`,
  `cp_progress`, `copy_pipeline` and `node_copy`, which go through the
  changed `session.rs`, `tree_copy.rs` and `resume.rs`: passed;
  `cargo test -p podssh-cli`, 788 passed, 0 failed. Clippy refused two
  dereferences that Rust does itself and two `drain(..).collect()` of a
  whole vector, which `std::mem::take` does now.
- Planted defect, two files into one temporary name: in
  `crates/podssh-cli/src/cp/bysftp.rs`, the temporary name of a copy up
  becomes one for its directory (`format!("{dir}.podssh-plant.part")`),
  opened without `EXCLUDE`; the files at once then write one file, and a
  digest check fails (70), or a rename finds no file (73). With `EXCLUDE`
  kept, the second open fails (73): the tests catch both. Planted, the
  one name opened without `EXCLUDE`: the six tests failed; restored, they
  passed.
- In the build image, 2026-10-13: the steps `lint` and `release`, green
  (clippy 1.99 clean; interop 526 passed, `cp` 80 of 80, `mv` 18, `sftp`
  5); and against OpenSSH's `sftp-server` on Linux
  (`PODSSH_TEST_SFTP_SERVER=/usr/lib/ssh/sftp-server`), `cp_parallel` 8,
  `copy_pipeline` 6, `node_copy` 3 and `cp_tree` 3 passed.
- Two repairs after the merge (2026-10-13). The test server's
  `crates/podssh-cli/tests/ssh_harness/mod.rs` had 507 lines with this
  entry's hooks, and the commit of the entry went out so: the state of a
  connection, `Far`, is in `crates/podssh-cli/tests/ssh_harness/far.rs`
  now. And a run of the whole suite failed
  `small_files_go_on_after_a_break_over_the_next_connection` once: a
  temporary file of the first connection stayed in the far directory, as
  the side file named it only once the server had made it, and the cut
  came between the two. The side file names it first now
  (`crates/podssh-cli/src/cp/bysftp.rs`), so the next attempt goes on in
  it or removes it; the test passed 20 runs in a row, and
  `cargo test -p podssh-cli` 788.
- The rate of many small files through the relay by T-157's method, which
  waited for T-251: measured 2026-11-01 (`throughput_live`,
  `cp_small_files_by_tasks`; `docs/STATUS.md`): with one task under a file
  a second through the relay, T-417. The Prove names no interop harness.
# T-298: `sftp`'s `-r`: `get -r` and `put -r` of a directory

**Source:** T-143: `podssh cp -r` copies trees; `sftp -r` and the `-r` of
`get` and `put` stay refused by name (`crates/podssh-cli/src/flags/scp.rs`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

OpenSSH's `sftp -r` and the `-r` of its `get` and `put` copy directories.
`podssh sftp` refuses both by name, so a batch of OpenSSH's that copies a
tree fails here.

## Premise

- Read: `crates/podssh-cli/src/cp/tree_copy.rs` copies a tree over one
  connection (T-143); `podssh sftp`'s `get` and `put` copy one file each
  (`crates/podssh-cli/src/sftp/run.rs`).

## Approach

1. `sftp -r`, and `get -r` and `put -r` (also `-R`), copy a directory with
   T-143's walk, its checks of names and its copy of each file.
2. The batch's line and the report are as for one file; an item that fails
   is reported, and the command fails at its end.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test copy_pipeline -- tree
```

A batch `put -r dir` and `get -r dir back` against the test's server
copies the tree both ways, equal to the source. Planted defect: `-r`
ignored; the test fails on the directory.

## Done

2026-10-13. `get -r` and `put -r` (also `-R`, and each `get` and `put`
after `sftp -r`, whose row is supported now in
`crates/podssh-cli/src/flags/scp.rs`) copy a directory with T-143's own
code: `tree_copy::copy` walks it, checks each name of a far listing, makes
each directory and link, copies each file, and sets each directory's mode
(and with `-p` its times) after its files. The connection of a tree's copy
is a `Conn` (`crates/podssh-cli/src/cp/tree_conn.rs`): `cp -r`'s connects
again after a break (`session::attempts`), as before; `sftp`'s is the
batch's one session, each file copied by `session::copy`, as its `get` and
`put` copy one. `crates/podssh-cli/src/sftp/commands.rs` reads the switch,
`crates/podssh-cli/src/sftp/run.rs` sends a directory to
`tree_conn::over_session`, and `crates/podssh-cli/src/cp/tree_copy.rs`
takes the `Conn` in place of the connection and its settings.

The calls made where the Approach left a choice:

- Each file of `sftp`'s tree goes over the batch's session, with no side
  file and no new connection after a break: a broken session ends the
  command, as it ends a `get`. A new connection would open the subsystem
  `sftp`, not the one that `-s NAME` named.
- A link is copied as a link, as `cp -r` copies one (T-143's Decision: a
  link to `/` that a walk follows copies the whole host); the source named
  on the line is followed when it is a link to a directory, as `get` and
  `put` follow it. OpenSSH's `sftp` was not read here for its rule.
- The batch prints its line once for the tree (`Fetching SRC to DST`,
  `Uploading SRC to DST`), as for one file; `-v` says each file. Each item
  that fails is said by the walk at once, and the rest goes on; the
  command's own error then names the tree once, with the first failure's
  code, so that no failure is said twice.
- Into a directory that exists the tree goes under it, with its own name;
  else it takes the name given, as `cp -r` places a tree. Several sources
  of one pattern each go under the local directory.

The manual (the notes of `sftp`), the `help` of `sftp`'s commands,
`docs/cli.md` and `docs/STATUS.md`. Tests: `cargo test -p podssh-cli
--test copy_pipeline -- tree`, `sftp_puts_and_gets_a_tree_with_r` (one
batch `put -r dir far` and
`get -R far back`, each tree equal to the source with its empty directory
and names with a space; `sftp -r` and `put dir into` under a directory
that exists; without either, `put dir` ends the batch with 66): 1 passed
on Windows 11.
The unit test of the lines (`get -r`, `reget -pR`, `put -R`, and `-x`
refused) and `--test scp_args` (`sftp -r` goes on to connect, and is no
more among the refused letters): passed. Planted, `-r` ignored: the
test failed, as the first batch exited 66; restored, it passed. `cargo test -p podssh-cli`: 780 passed, 0 failed. Clippy
refused three dereferences that Rust does itself in `crates/podssh-cli/src/cp/tree_conn.rs`;
they are gone. Nothing of the Prove
waits for T-251.

# T-417: `cp` spends some 14 round trips on each small file, so a tree of small files crawls through the relay

**Source:** T-251's measurement of many small files, 2026-11-01 (`cargo test -p podssh-cli --test
throughput_live -- --ignored --nocapture cp_small_files_by_tasks`), which T-297 left to it.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`cp -r` of a tree of small files goes at under a file a second through the relay with the default
of one task: 200 files of 16 KiB did not go up to a node of the live relay within `cp`'s 300 s.
Each file waits for each of its steps in turn, so its round trips, not its bytes, set the time.
A user who copies a source tree, a directory of configuration or a mailbox through the relay
waits minutes for what one archive would carry in seconds.

## Premise

- Read: a file up waits in turn for the target's stat, the temporary file's stat, its open, each
  write, `fsync`, its close, the far digest over an exec channel of its own (an open, an exec, a
  reply and a close), the times, the rename and the times again
  (`crates/podssh-cli/src/cp/bysftp.rs:50-134` and the end of a copy up, now
  `crates/podssh-cli/src/cp/finish.rs:36-107`).
- Measured (this cloud session, 2026-11-01): through the stand-in relay with 50 ms each way, 0.7
  files a second each way with one task, about 14 round trips a file; 4.6 up and 3.2 down with 8.
  Through the live relay to a node: with one task, `cp --timeout 300s` passed before the 200 went
  up (exit 75); with 8, 4.6 up and 1.6 down.

## Approach

Measure each step's round trips first, with `-v` and a count of the SFTP requests of a file. Then,
for a file that one write carries: no stat of a temporary file that no side file names; the far
digest of a small file by a read back in the same SFTP session, or one exec of `sha256sum` for a
batch of the lane's files, in place of an exec channel for each; and more tasks by default when
the sources hold many files (8 fit OpenSSH's 10 sessions a connection). Each change against the
same measurement, and the suites of `cp`.

## Decision

2026-11-01, the calls made in the work:

- **The far digest stays a check that the SFTP server does not answer.** A small file's digest
  read back through the handle that wrote it would save its realpath and a command's channel, but
  the planted subsystem of `scripts/interop-cp.sh`, which flips one byte of the first write and
  of the first read, undoes its own flip on that read, and a corrupt file would pass. The
  command's digest reads the disk through another program, so it stays first, and the read
  again stays its fallback. Lost: the read back of a file of 256 KiB or less (written, and
  removed before the commit).
- **Its round trips overlap others instead.** The server acknowledged each write, so the far
  digest's command reads the bytes as they stay: a copy up starts it beside `fsync` and the
  close, and a copy down beside the close. After holes, or into the destination itself, the size
  is set first, and the digest waits as before.
- **The default of one task stays** (T-141's Decision: several channels are the user's choice,
  after the operator's ruling of 2026-10-08 on several sessions). The lanes already give six
  times the files a second with 8 (T-297); the manual says so.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cp_parallel
cargo test -p podssh-cli --test cp_meta --test cp_inplace
cargo test -p podssh-cli --test throughput_live -- --ignored --nocapture cp_small_files_by_tasks
```

## Correction

2026-11-01: a new copy makes no stat of a temporary file: only one that goes on in a temporary file
that its side file names looks at it (`crates/podssh-cli/src/cp/bysftp.rs:106-117`). The round trips
of a file up, on a server with a digest command: the target's stat, the open, the write, `fsync`,
the close, the realpath and the command's channel (some three), the mode, the rename. On the
throughput run's server, which runs no command, the channel is refused and a second read follows
(an open, a read, a close): the 14 measured.

## Done

2026-11-01: the far digest's command starts beside `fsync` and the close of a copy up, and beside
the close of a copy down (`crates/podssh-cli/src/cp/finish.rs`, the end of a copy up moved out of
`bysftp.rs`, which held 498 lines). A tree of 50 files or more that go one at a time over SFTP
says once that `--parallel 8` copies 8 at once (`crates/podssh-cli/src/cp/tree_conn.rs`), and the
manual says why. `tests/cp_tree.rs`, `a_tree_of_many_files_one_at_a_time_names_parallel` (60
files: said once up and once down, not with `--parallel 4`, not for a few files): passed; planted,
a threshold of 50,000: failed. Planted, the digest begun before the size is set in place: the
test of `cp --inplace` failed. The suites of `cp` (`cp_parallel`, `copy_pipeline`, `cp_delta`,
`cp_exec`, `cp_inplace`, `cp_meta`, `cp_progress`, `cp_tree`, `node_copy`, `cp_args`, and the unit
tests of `cp::`) passed. The measurement again (`cp_small_files_by_tasks`): through the stand-in
relay with 50 ms each way, 0.8 up and 0.7 down a second with one task (0.7 and 0.7 before), 5.3
and 3.4 with 8 (4.6 and 3.2); to a node of the live relay with 8 tasks, 4.7 and 1.5 (4.6 and 1.6),
and with one task the 200 files still outlast `cp`'s 300 s. Several tasks stay the lever, now
named where it is wanted; the default stays one task (the Decision).

# T-470: `cp --delta` sends the whole file with no word when the server cannot take a delta

**Source:** GitHub #87 (Nemo-010, 2026-11-02, with `podssh 1.0.0 (35a0d19d)`).
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A user gives `--delta` to send less through a slow relay. When the server cannot take a delta,
the copy sends the whole file and says why only at `-v`. The issue changed 13 bytes of a file of
5 MiB on a Go SFTP server with no `copy-data`: the copy sent all 5,242,880 bytes, in the time of a
full copy, and said nothing. After the run, the user cannot tell whether the delta helped.

## Premise

- Read: each reason of a server for a full copy is said with `Log::verbose`, at `-v` alone: no
  `copy-data` for a copy up (`crates/podssh-cli/src/cp/delta.rs`, lines 137-140 at `582b1bf`),
  and no digest of a block, up and down (lines 142-145 and 270-273 there). Only digests that differ
  after a delta are said at the default level (lines 223 and 339 there).
- Read: `Log::info` writes at the default level, and `Log::verbose` at `-v` and above
  (`crates/podssh-ssh/src/log.rs:52-58`); `-q` silences both.
- Read: a copy that goes on in the temporary file of an earlier attempt goes in full, with no word
  (`crates/podssh-cli/src/cp/bysftp.rs`, lines 81 and 262 at `582b1bf`), as `docs/cli.md` said
  (line 1729 at `582b1bf`). The copy by exec,
  for a server with no SFTP, does not read `--delta`: `crates/podssh-cli/src/cp/byexec.rs` names no
  delta, so the flag does nothing there, and nothing says so.
- Read: a copy up makes its temporary file from the old one with `copy-data` alone
  (`crates/podssh-cli/src/cp/delta.rs`, lines 155-170 at `582b1bf`), though the delta already runs
  a command on the server for the digests of the far blocks (lines 101-114 there), and a command
  could make that copy too.
  The issue's server offers `hardlink@openssh.com` and `posix-rename@openssh.com`, and no
  `copy-data` (the issue; not measured here); OpenSSH's `sftp-server` offers `copy-data` (T-142).
- Read: the `done` object of `--jsonl` has no field for a delta
  (`crates/podssh-cli/src/cp/report.rs`, lines 43-51 at `582b1bf`).

## Approach

1. Each reason why `--delta` gives a full copy is one line at the default level, once for each
   file, that names the reason and says that the whole file goes: "SRC: the server has no
   copy-data and runs no command: this copy sends the whole file". The reasons: no `copy-data` and
   no command; no command, `dd` or digest tool for the blocks; a copy by exec; a copy that goes on
   from an earlier attempt. A destination that is not there, or is empty, stays at `-v`: it has no
   older version, and a full first copy is what the user expects.
2. On a server with a command and no `copy-data`, a copy up makes its temporary file from the old
   one there: the file is made over SFTP as now (mode 0600, `CREATE` and `EXCLUDE`), then one
   command fills it (`cat -- OLD > TEMP`, each path one quoted word, as
   `podssh_ssh::exec::shell_word` gives it), so no byte of the old file crosses. Then the blocks
   that differ, the size, the digest and the rename, as now. The order: `copy-data`, the command,
   a full copy.
3. With `--jsonl`, the `done` object of each copy with `--delta` gains `"delta"`:
   `{"blocks": N, "sent": K, "bytes": B}` after a delta, or `{"full": "REASON"}` after a full copy.
4. The row of `--delta` (`crates/podssh-cli/src/flags/copy.rs:44-45`), the manual,
   `docs/cli.md:2112-2123` and `docs/STATUS.md`.

## Decision

- The line is a note, not a refusal: the full copy is still a correct and verified copy, and a
  refusal would fail a copy that works. Lost: the silence of today; an exit that is not zero,
  which would fail each script that gives `--delta` to a server without `copy-data`.
- The temporary file is made over SFTP, then filled by the command: `EXCLUDE` makes the name the
  copy's own, as now, so the command writes into no name that it did not make. A command that
  makes the file too lost: whether `set -C` opens with `O_EXCL` is the far shell's choice, and
  podssh does not know that shell (Inferred). Lost too: a read of the far blocks over SFTP, to
  hash them here, which brings the old file down whole, as many bytes through the relay as the
  full copy sends up.

The calls of the draft (2026-11-02), each for the operator to confirm (Q86):

- The command is `sh -c 'cat -- "$1" >| "$2" && echo podssh-copied' sh OLD TEMP`, as the digests
  of the blocks wrap theirs in `sh -c`, so that a login shell that is not POSIX's still runs it;
  `>|` writes over the file that SFTP made also where `noclobber` is set; and the copy counts only
  with its marker and with the size that SFTP then reads, as the test's server answers a command
  that it does not know with a greeting and 0. Lost: `>` alone, which a `noclobber` refuses; the
  status alone, which would leave a temporary file of no bytes, whose blocks would then differ.
- The digests of the far blocks come first, then the copy of the old file: with no command there,
  nothing could make the temporary file either, and the line names both (`no-copy-data`).
- The reason is kept for the file in the progress record (`Progress::delta_why`): a second
  attempt after a broken connection says nothing more, and its `done` object keeps the first
  reason, not `resumed`. Lost: a line on each attempt.
- The copy by exec looks at the far file once (one command) when `--delta` is given, so that a
  first copy stays at `-v`. Lost: the line at the default level for each copy by exec.
- Each file of a tree says its own line, as item 1 says: a tree of many files on a server with no
  `copy-data` and no command gives a line for each. Lost: one line for the run, which T-472's
  summary may give later.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cp_delta
cargo test -p podssh-cli --lib cp::delta
sh scripts/dev.sh check   # interop-cp.sh: --delta against a subsystem with no copy-data
```

`cp_delta` gains tests against the test's server whose commands run in sh
(`crates/podssh-cli/tests/ssh_harness/serve.rs:42`), with a user whose subsystem leaves
`copy-data` out of its version reply (new, beside the user `evil-...` of
`crates/podssh-cli/tests/ssh_harness/sftp.rs`): over an older file of 5 MiB with 13 bytes
changed, a copy up with `--delta` sends one block of five, by the command's copy, and the digests
are equal; with the command refused as well, the copy goes in full, exits 0, and stderr says once,
with no `-v`, that the whole file goes; with `-q`, nothing; with `--jsonl`, the `done` object
holds `"delta"`. In the gate, `scripts/interop-cp.sh` checks the same through OpenSSH, with a
subsystem that drops `copy-data` from the version reply, made as its subsystem that flips a byte
is made. Planted defect: the note back at `-v`; the test with no `-v` fails.

## Correction

2026-11-02: the checks through OpenSSH are in `scripts/interop-delta.sh`, which
`scripts/interop-cp.sh` sources while its servers run, as it sources `scripts/interop-sftp.sh`:
`scripts/interop-cp.sh` holds 476 lines, and the 500-line rule holds for scripts too. The test's
server of `ssh_harness::start` does not refuse a command it does not know: it answers it with a
greeting and 0. So "the command refused as well" is that server, whose answer holds no marker,
and the copy of the old file needs one (the Decision).

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session on
2026-11-03.

- `crates/podssh-cli/src/cp/delta/note.rs` (new): the reasons (`Full`: `no-older-file`,
  `no-copy-data`, `no-block-digests`, `no-far-copy`, `resumed`, `by-exec`, `digests-differ`), the
  `delta` of a result (`Delta`), its JSON, the line, and `full`, which says the line once for a
  file, at `-v` for a first copy and at the default level else, and keeps the first reason. Its
  unit tests: a word for each reason, the line's form, the JSON, once for a file.
- `crates/podssh-cli/src/cp/delta.rs`: `up` and `down` give the copy done or the reason; with no
  `copy-data`, `from_old` makes the temporary file over SFTP (0600, `CREATE` and `EXCLUDE`) and one
  command fills it from the old one by their absolute paths, with a marker and a check of the size;
  `-v` says so. The `done` of a delta holds the blocks, those sent and their bytes.
- `crates/podssh-cli/src/cp/bysftp.rs`: each reason for a full copy, a copy that goes on from an
  earlier attempt included, is said by `full`, and goes into the file's `done`.
  `crates/podssh-cli/src/cp/byexec/files.rs`: with `--delta`, the copy by exec says that it sends
  no delta (at `-v` for a first copy). `Done::delta` (`crates/podssh-cli/src/cp/transfer.rs`) and
  `Progress::delta_why` (`crates/podssh-cli/src/cp/resume.rs`, kept out of the side file); the
  `done` object of `--jsonl` gains `delta` (`crates/podssh-cli/src/cp/report.rs`).
- The row of `--delta`, the notes of `cp` (`crates/podssh-cli/src/man/notes.rs`), `docs/cli.md`
  (the paragraph of `--delta` and the objects of `--jsonl`), and the row of `podssh cp` in
  `docs/STATUS.md`.
- `crates/podssh-cli/tests/cp_delta.rs`: with no `copy-data` (the user `nocopy-...`,
  `crates/podssh-cli/tests/ssh_harness/sftp.rs`), on the server of `start_shell` (Unix) a copy up
  of 5 MiB with 13 bytes changed sends one block of five through the command's copy, and its
  `done` says so; on the server of `start`, the whole file goes, exit 0, the line once with no
  `-v`, none with `-q`, `no-copy-data` with `--jsonl`, and a first copy says nothing with no `-v`.
- `scripts/interop-delta.sh` (new, sourced by `scripts/interop-cp.sh`): OpenSSH on 2214 with a
  subsystem that drops `copy-data` from its version reply, and on 2216 with the same as its
  `ForceCommand` (no command runs): `delta.command`, `delta.no_command`, `.quiet` and `.jsonl`, and
  their two `sshd`; the harness `delta`, 6 checks, floor 6, in `scripts/interop-baseline.txt`.
- Planted defects: `scripts/plants/t470-note-at-v.plant` (group `cli-tests`, with OpenSSH's
  `sftp-server` added in its SETUP: the test with no `-v` must fail) and
  `scripts/plants/t470-note-at-v-interop.plant` (group `copy`: `delta.no_command` must fail), one
  patch: the line at `-v` alone.
- The merge: `cargo test -p podssh-cli --test cp_delta` (Unix), 7 passed; `cargo test -p
  podssh-cli --lib cp::`, 69 passed. The plant `t470-note-at-v`, its patch applied and its RUN run
  by hand (its SETUP is `apk` of the build image, and this host has OpenSSH's `sftp-server`):
  caught, `with_no_copy_data_and_no_command_the_whole_file_goes_and_one_line_says_why` failed.
  rustfmt of `podssh-cli` (a list of `note.rs`'s test) and clippy of `podssh-cli` with
  `-D warnings`, all targets: clean. `cargo todo remap` from the tree before the draft, in place
  of its port.
- Waits for the build image, which this host's Docker did not run: `scripts/interop-delta.sh`
  (`delta.*`), in the gate's step `release` at each push, and the plant `t470-note-at-v-interop`
  (group `copy`), through `plants.yml` on a runner.
# T-471: `sftp`'s `ls -l` is not OpenSSH's long form, and five switches of its `ls` do nothing

**Source:** GitHub #89 (Nemo-010, 2026-11-02, with `podssh 1.0.0 (35a0d19d)`).
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

`podssh sftp` says that it works "as OpenSSH's sftp", but its `ls -l` prints the mode, the size
and the name alone: no link count, owner, group or time. A script that reads the long form by its
columns (`awk '{print $3, $4}'`) reads the wrong ones. `ls` also takes `-f`, `-h`, `-r`, `-S` and
`-t`, as OpenSSH's does, and does nothing with them: a batch that sorts by time gets the order of
the names, with no word.

## Premise

- Read: a long line is the type, the nine bits of the mode, the size and the name
  (`crates/podssh-cli/src/sftp/run.rs`, lines 294-310 at `582b1bf`). The type is `d`, `-`, or
  else `?`, so a link, a FIFO, a device and a socket each show `?`, and the set-id and sticky bits
  are not shown. Its unit test holds that form (lines 343-346 there). The file has 352 lines.
- Read: `ls` takes `-1afhlnrSt` and keeps `l`, `n` and `a` alone
  (`crates/podssh-cli/src/sftp/commands.rs`, lines 201-205 at `582b1bf`): `-n` is `-l`, and `-f`,
  `-h`, `-r`, `-S` and `-t` do nothing. `docs/cli.md` (line 1916 at `582b1bf`) names `ls [-la]`.
- Read: the about of `sftp` says "as OpenSSH's sftp" (`crates/podssh-cli/src/flags.rs:403`); the
  issue names it the README's.
- Read: `Sftp::read_dir` keeps the name and the attributes of each entry, and drops the long name
  that the server sends with each (`crates/podssh-ssh/src/sftp/mod.rs`, lines 71-78 and 426-441
  at `582b1bf`); russh-sftp 3.0.1's `File` holds it as `longname`.
- Read, in OpenSSH 10.2p1 (`openssh/openssh-portable:sftp.c` and
  `openssh/openssh-portable:sftp-common.c`, at the tag `V_10_2_P1`, the functions `do_ls_dir`,
  `do_globbed_ls` and `ls_file`): `ls -l` of a directory prints the long name of each entry as the
  server sent it, unless `-n` or `-h` is given or the server offers
  `users-groups-by-id@openssh.com`. Then, and for `ls -l` of a file or a pattern, `ls_file` makes
  the line from the attributes: the mode as `strmode` gives it, `?` for the link count of a remote
  file, the owner and the group by name from that extension, else by number, each 8 wide at
  least, the size 8 wide, the time as `%b %e %H:%M` within the last six months, else as
  `%b %e  %Y`, in the local zone, then the name. Without `-l` or `-1`, the names go in columns of
  the terminal's width, else of 80.
- Inferred from that source, not measured: for the issue's one file, OpenSSH's `sftp` prints `?`
  for the link count and, on the issue's server, which offers no
  `users-groups-by-id@openssh.com`, `0` for the owner and the group; the issue's line is the
  server's long name.
- Read: `chrono`, with its local zone, is a dependency of `podssh-ssh` already
  (`crates/podssh-ssh/Cargo.toml:66`, `crates/podssh-ssh/src/sshsig.rs:16`).

## Approach

1. `Sftp::read_dir` keeps the long name of each entry (empty when the server sent none).
2. `ls -l` of a directory prints each long name, as OpenSSH does, when the server sent them,
   offers no `users-groups-by-id@openssh.com`, and neither `-n` nor `-h` is given. Else, and for a
   file or a pattern, a line made as `ls_file` makes it: the type letter of each kind (`-`, `d`,
   `l`, `p`, `s`, `c`, `b`) and the set-id and sticky bits, `?` for the link count, the owner and
   the group by name from `users-groups-by-id@openssh.com` (asked once for the ids of a listing),
   else or with `-n` by number, the size (with `-h` scaled as OpenSSH's `fmt_scaled` scales it),
   the time in the local zone, and the name, with OpenSSH's widths.
3. The other switches as OpenSSH's: `-a` the names that start with a dot, `-f` no sort, `-r` the
   reverse order, `-S` by size, `-t` by time of change, `-1` one name a line; without `-l` or
   `-1`, the names in columns, as OpenSSH's.
4. The listing goes into a module of its own, so that `crates/podssh-cli/src/sftp/run.rs` stays
   well under 500 lines. The `help` of `sftp`'s commands, the manual, `docs/cli.md:2412-2418` and
   `docs/STATUS.md`.

## Decision

The calls of the draft (2026-11-02), each for the operator to confirm (Q86):

- `-n` shows the numbers also where the server could name them, as OpenSSH 10.4p1 to 10.6p1 do
  (`openssh/openssh-portable` commit a9cb2e30d3 of 2026-06-29, "fix 'ls -n', which was still
  displaying user/group names"). Lost: the names of 10.2p1 and 10.3p1, which upstream calls a
  defect and which a script that asks for numbers cannot read. So the gate does not set `ls -ln`
  beside the image's OpenSSH, which may be 10.3p1; it checks the numbers alone.
- An entry that came with no long name gets the line that podssh makes. Lost: the empty line that
  OpenSSH prints for it (`do_ls_dir` prints `longname` as it is), which a reader of columns cannot
  use.
- The width of the columns is that of the terminal on stdin, as OpenSSH asks it (`TIOCGWINSZ` of
  `fileno(stdin)`). Lost: podssh's own order (stdout, stdin, stderr) of `terminal::size`, which
  gives another width where stdout is a different terminal.
- A pattern is read in the last name only, as the other commands of the session read one (T-139),
  with one matcher for all. Lost: OpenSSH's glob in each name and its braces (`GLOB_BRACE`), which
  no command of `podssh sftp` takes today; a pattern in a middle name is a path that is not there,
  and fails with 66.
- A reply of `users-groups-by-id@openssh.com` that is a status, or that is not of its form, shows
  the numbers with no word, where OpenSSH logs one error line. Lost: a failed `ls` for a listing
  that is still right with the numbers.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib sftp::
cargo test -p podssh-cli --lib sftp::
cargo test -p podssh-cli --test copy_pipeline -- sftp_ls
sh scripts/dev.sh check   # interop-sftp.sh: podssh's ls lines beside OpenSSH's sftp's
```

The unit tests: the line of a file, a directory, a link, a FIFO, the set-id bits, a time of the
last six months and an older one, an owner longer than 8, and `-h`. `sftp_ls` (new) runs one
batch against the test's server (OpenSSH's `sftp-server`, which sends long names and, in 10.2p1,
offers `users-groups-by-id@openssh.com`; `openssh/openssh-portable:sftp-server.c` at the tag
`V_10_2_P1`): `ls -l` of a directory and of a file give seven columns, `?` for the link count, and
the owner and the group by name; `ls -ln` by number; `ls -lt`, `ls -lS` and `ls -lr` their orders;
with the extension hidden from the version reply (a user of the test's server, as T-470 makes
one), `ls -l` of a directory gives the server's long names. In the gate,
`scripts/interop-sftp.sh` runs the same batch through OpenSSH's `sftp` and through `podssh sftp`
against one server, with `TZ=UTC` for both, and the lines must be equal. Planted defect: the owner
left out of a line that the form of `ls_file` makes; the comparison fails.

## Correction

2026-11-02, read in `openssh/openssh-portable` at `V_10_2_P1`, `V_10_3_P1` to `V_10_6_P1` and
`master` (through web.pkgforge.dev's fetch and forge services):
- In 10.2p1 and 10.3p1, `ls -n` still shows the names on a server that offers
  `users-groups-by-id@openssh.com`: `do_ls_dir` and `do_globbed_ls` of `sftp.c` give `ls_file`
  `ruser_name` and `rgroup_name` whatever the switch, and the names that the extension fetched
  come back (`sftp-usergroup.c`). Commit a9cb2e30d3 (2026-06-29) passes no name with `-n`; 10.4p1 to
  10.6p1 hold it. The Premise's "else or with `-n` by number" holds from 10.4p1 on.
- `ls_file` and the code of `ls` are the same from 10.2p1 to 10.6p1 but for `path_strip`, which
  10.6p1 lets return the path whole for an empty strip. `master` (`sftp-common.c` 1.38,
  2026-10-30) writes `error` for a size that `fmt_scaled` cannot write; the releases print what
  their buffer holds.
- OpenSSH sorts with `qsort`. musl's, in the gate's Alpine, is not stable, so two entries of one
  time or one size come in an order that no stable sort copies; the gate's comparison sorts by time
  and by size only in a directory whose files differ in both.
- `get_remote_user_groups_from_dirents` asks the server for the names before each listing, also
  with no `-l`; podssh asks only for a long line that it makes, with the same output.

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session the
same day.

- `Sftp::read_dir` keeps each entry's long name (`Entry::longname`; empty when the server sent
  none), in `crates/podssh-ssh/src/sftp/mod.rs`.
- `crates/podssh-ssh/src/sftp/long.rs` (new): the line of `ls_file`, with `strmode`'s letter of
  each kind and its set-id and sticky bits, `?`, the owner and the group padded to 8 bytes as
  printf pads, the size as `%8llu` or, with `-h`, as `fmt_scaled` (ported with its rounding), and
  the time as `%b %e %H:%M` within half a year and not ahead, else `%b %e  %Y`, in the local zone
  (chrono). Its unit tests: a file and a directory against lines written by hand from `ls_file`'s
  format, each kind's letter and the special bits, the times on both sides of the half year and
  one ahead, an owner longer than 8, a name of two bytes, and `-h` from `0B` to `8.0E`.
- `crates/podssh-ssh/src/sftp/names.rs` (new): `users-groups-by-id@openssh.com` at version `1`,
  as OpenSSH's client takes it: one request for the ids of a listing, an empty name read as
  none (the number shows), a status read as no names. Its unit tests: the request's bytes and the
  reply's form, also cut short.
- `crates/podssh-cli/src/sftp/listing.rs` (new; `ls` and its line left
  `crates/podssh-cli/src/sftp/run.rs`, now 309 lines): the switches in their order as
  `parse_ls_flags` reads them; a directory as `do_ls_dir` (the server's lines unless the extension,
  `-n` or `-h`); a path or a pattern as `do_globbed_ls` (one directory lists what it holds, else
  each match gets the made line; each path cut as `path_strip` cuts it; a directory marked with
  `/`; a leading dot matched only by a dot, `.` and `..` too); the orders; the columns as OpenSSH
  counts them. `Command::Ls` holds the switches (`crates/podssh-cli/src/sftp/commands.rs`), and
  its `help` line names them.
- The notes of `sftp` (`crates/podssh-cli/src/man/notes.rs`), `docs/cli.md` (the paragraph after
  the commands) and the row of `podssh sftp` in `docs/STATUS.md`.
- `crates/podssh-cli/tests/copy_pipeline.rs`, `sftp_ls_gives_openssh_s_long_form_and_orders`
  (Unix): against OpenSSH's `sftp-server`, the batch of the Prove's paragraph above, as the user
  `u`, then as `noids-u`, whose version reply loses `users-groups-by-id@openssh.com`
  (`crates/podssh-cli/tests/ssh_harness/sftp.rs`, `Mangle`, beside the `../escape` of `evil-`).
- `scripts/interop-sftp.sh`: `sftp.ls.same_as_openssh` (one batch of 17 lines through OpenSSH's
  `sftp` and `podssh sftp`, `cmp` of their stdout, in UTC) and `sftp.ls.numeric`; the harness
  `sftp` has 7 checks and a floor of 7 (`scripts/interop-baseline.txt`).
- Planted defects: `scripts/plants/t471-ls-owner-left-out.plant` (group `copy`: the interop's
  comparison must fail) and `scripts/plants/t471-ls-owner-unit.plant` (group `cli-tests`: the
  unit test of a file's line must fail), one patch: the owner made 8 spaces.
- The merge: `cargo test -p podssh-ssh --lib sftp::`, 9 passed; `cargo test -p podssh-cli --lib
  sftp::`, 9 passed; `cargo test -p podssh-cli --test copy_pipeline` (Unix) against this host's
  OpenSSH 9.6p1 `sftp-server`, 4 passed, `sftp_ls_gives_openssh_s_long_form_and_orders` among
  them. `sh scripts/plant-each.sh --here t471-ls-owner-unit`: caught, the test of a file and a
  directory failed. rustfmt of `podssh-ssh` (one closure of `sftp/mod.rs` wrapped) and clippy of
  `podssh-ssh` and `podssh-cli` with `-D warnings`, all targets: clean. `cargo todo remap` from
  the tree before the draft of each file that it changed, in place of its moves by hand.
- Waits for the build image, which this host's Docker did not run: `scripts/interop-sftp.sh`'s
  `sftp.ls.same_as_openssh` and `sftp.ls.numeric` beside OpenSSH's own `sftp`, in the gate's step
  `release` of CI at each push, and the plant `t471-ls-owner-left-out` (group `copy`), through
  `plants.yml` on a runner.
# T-472: `cp`, `mv` and `run` say nothing of what they did without `-v`, and nothing in a pipe while a copy runs

**Source:** GitHub #90 (Nemo-010, 2026-11-02, measured with `podssh 1.0.0 (35a0d19d)` at about 2
MiB/s through the relay).
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

At the default level, a copy that succeeds says nothing: not what it sent, nor what it left as it
was, nor how long it took. A second `podssh run` that sent one file and left two says so at `-v`
alone. And where stderr is a pipe, as for an agent in a cage, a copy of 70 MiB at 2 MiB/s is 35 s
with no word, which reads as a hang.

## Premise

- Read: at its end, a run of `cp` or `mv` says each file done at `-v` alone
  (`crates/podssh-cli/src/cp/report.rs:36-73`, `:71`), and at the default level only the number of
  deletes (`:33-35`) and a failure. `run` says "files sent N, unchanged M" at `-v` alone
  (`crates/podssh-cli/src/run_cmd/mod.rs`, line 226 at `010abe1`), the line that its test reads
  (`crates/podssh-cli/tests/run_far.rs`, lines 17-20 there).
- Read: the progress line is drawn only when stderr is a terminal and `-q` is not given, unless
  `PODSSH_PROGRESS=line` (`crates/podssh-cli/src/cp/gauge.rs`, lines 23-37 at `010abe1`): T-145's
  Approach chose nothing in a pipe.
- Read: a gauge is made only by the SFTP road's copy of one file in one stream
  (`crates/podssh-cli/src/cp/bysftp.rs:168`, `:351`). The chunks of `--parallel`
  (`crates/podssh-cli/src/cp/chunks.rs`) and the copy by exec (`crates/podssh-cli/src/cp/byexec.rs`)
  draw none, and each file of a tree draws a line of its own, with no count of the run's files.
- Read: the counts that a summary needs are in the run's `Outcome` already: the files done with
  their bytes, the files left as they were, and the deletes
  (`crates/podssh-cli/src/cp/outcome.rs:15-46`, where T-476 moved it from `cp/mod.rs`).

## Approach

1. One summary line at the end of each run of `cp`, `mv` and `run`'s copy, at the default level
   (`-q` silences it), also after a failure, before its error: "3 copied (3.1 MiB), 2 unchanged,
   1 skipped, 1 failed, in 12.0 s (264.5 KiB/s)"; each count of zero is left out but the first.
   With `--jsonl`, a `summary` object on stdout in its place. The skips are those of T-476 and
   T-473.
2. Where stderr is no terminal, a plain line (no carriage return, no escape) at the default level
   each 10 s, once the run has passed 10 s: the run's files done of its files, its bytes, its
   rate, and the file in flight. A run shorter than 10 s writes none. `-q` and
   `PODSSH_PROGRESS=off` silence it; `PODSSH_PROGRESS=line` keeps the line of a terminal, as now.
3. One gauge for the run, fed by each road: one stream, the chunks of `--parallel`, the files K at
   once (one line for the run, not one for each lane), and the copy by exec (the bytes as its
   command takes them). On a terminal, the line names the file in flight and, with several files,
   the run's count.
4. `run` says its summary before the command starts, on stderr, so that the command's stdout stays
   its own; with T-475, the paths that the ignores left out.
5. `scp` and `sftp` keep the output of OpenSSH's, with no summary. The manual,
   `docs/cli.md:2230-2270`, `docs/STATUS.md`, and `crates/podssh-cli/tests/run_far.rs`, which reads
   the summary in place of the line of `-v`.

## Decision

- The summary is at the default level: it is the one fact that a user of a sync wants, the run has
  counted it already, and `-q` still gives a silent run. `scp` keeps OpenSSH's output, as its users
  and their scripts read it. Lost: the summary at `-v` (today); the summary on stdout, which holds
  answers alone (the plan of a dry run, `--jsonl`).
- In a pipe, a plain line each 10 s, and only past 10 s: T-145 kept the line out of a pipe, where
  its carriage returns would make a log of lines that overwrite each other; a plain line, rare and
  late, keeps a short copy silent and shows that a long one lives. Lost: the terminal's line in a
  pipe; a line at each 10 percent, which on a slow link can be minutes apart.
- 2026-11-03, the draft: the summary says "copied" for `mv` too: it counts the copies, each
  verified, and a source that a move did not remove is a failure, said when it came and counted.
  Lost: "moved", which `mv -r` cannot count for each file, as it removes its tree at the end.
- No summary after the `--timeout` (75), whose records went with the run's future, so that a
  summary would say "0 copied"; nor after an interruption (130), whose line names what stays; nor
  for a dry run, whose plan on stdout is its answer; nor for `scp` and `sftp` (step 5). Lost: a
  summary of what a run did before its `--timeout`, which needs the run's records outside its
  future (a change of `session` and of the copy between servers).
- The plain line in a pipe is for `cp`, `mv` and `run` alone: `scp` and `sftp` keep OpenSSH's
  output, which writes nothing there (step 5), `edit`'s copies are its own, and `job`'s streams are
  the jobs'. A control character of a name is a `?` on either line, so that the line stays one
  line and holds no escape, as a far name can hold one. With `--jsonl` the `progress` objects stay
  one for each file each second, as T-145 made them; the run's counts are in the summary.
- Step 4's paths that the ignores left out wait for T-475, which lists them.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cp_progress
cargo test -p podssh-cli --test cp_tree
cargo test -p podssh-cli --test run_far
```

Against the test's server: a copy of three files in a pipe ends with one summary line on stderr
and nothing on stdout, and none with `-q`; `--jsonl` gives one `summary` object; a copy under `-l`
that lasts 12 s gives one progress line or more in the pipe, with no carriage return, and a copy
of 1 s none; a tree under `--parallel 4` draws one line for the run (`PODSSH_PROGRESS=line`).
`run_far` reads "3 copied", then "0 copied, 3 unchanged", then "1 copied, 2 unchanged", with no
`-v`. Planted defect: the summary at `-v`; the test with no `-v` fails.

## Done

2026-11-03, drafted after T-474's draft, then merged and run by the main session the same day:

- `crates/podssh-cli/src/cp/summary.rs`, new: the counts of a run (copied and their bytes,
  unchanged, skipped, failed), its line and its `summary` object, with unit tests of each.
  `crates/podssh-cli/src/cp/report.rs`: the summary after the objects and before the error that
  nothing said yet, as a line at the default level or with `--jsonl` an object.
  `crates/podssh-cli/src/cp/mod.rs`: the run's start, and no summary for `scp`, a dry run or a run
  that the `--timeout` ended (the Decision).
- `crates/podssh-cli/src/cp/gauge.rs`: one gauge for the run (its files, its bytes, its files in
  flight), which each file's gauge feeds; `Mode::Plain` for a pipe, chosen by `cp`, `mv` and `run`
  alone; the terminal's line names the file in flight and, with several files, the run's count;
  the plain line each 10 s once the run has passed 10 s; a control character of a name is a `?`.
  Unit tests of the choice of the mode and of the lines. The calls of `init` in
  `crates/podssh-cli/src/edit/mod.rs`, `crates/podssh-cli/src/job/mod.rs` and
  `crates/podssh-cli/src/sftp/mod.rs` write no plain line.
- Each road feeds it: `crates/podssh-cli/src/cp/chunks.rs` (a gauge for the file, which each task
  adds to), `crates/podssh-cli/src/cp/byexec/files.rs` (up and down, the bytes as the command
  takes them), and the files at once through each file's own gauge. The count of files:
  `crates/podssh-cli/src/cp/session.rs` (each source of the command line) and
  `crates/podssh-cli/src/cp/tree_copy.rs` (each tree once walked; a file that `run` leaves as it
  was, or a second name by a hard link, passes).
- `podssh run`: `crates/podssh-cli/src/cp/sync.rs` gives the copy's counts and its first failure;
  `crates/podssh-cli/src/run_cmd/mod.rs` says the summary before the command starts, and before
  the error of a copy that failed, in place of the line of `-v`.
- The manual (`crates/podssh-cli/src/man/notes.rs`: `cp`'s summary and progress, `scp` with none;
  `crates/podssh-cli/src/man/notes_run.rs`; `crates/podssh-cli/src/man/facts.rs`, the row of
  `PODSSH_PROGRESS`), `docs/cli.md` (the progress, the summary, and `run`'s copy, which names
  T-474's files at once too), and a row of `docs/STATUS.md`.
- Tests: `crates/podssh-cli/tests/cp_progress.rs`, against the test's server and OpenSSH's
  `sftp-server`, 7 passed: `a_run_in_a_pipe_ends_with_one_summary_line` (three files, no `-v`:
  one summary line, nothing on stdout; none with `-q`; one `summary` object, the last, with
  `--jsonl`; a missing source counted); `a_long_copy_in_a_pipe_says_that_it_lives_and_a_short_one_does_not`
  (12 s under `-l`: a plain line or more, no carriage return and no escape; 1 s: none);
  `the_files_of_a_tree_at_once_draw_one_line_for_the_run` (8 files under `--parallel 4` and
  `PODSSH_PROGRESS=line`: each line drawn holds `of 8 files`). `run_far` reads the summary with
  no `-v`: 1 passed. `cp_args`, with `jsonl_reports_a_failure_as_one_error_object_then_the_summary`:
  9 passed. The other suites: `cp_tree` 8, `cp_parallel` 9, `copy_pipeline` 4, `cp_delta` 7,
  `cp_exec` 6, `cp_inplace` 3, `cp_meta` 7, `node_copy` 3, `run` 2, `scp_args` 6, `edit_args` 5,
  `job` 3, `job_far` 2, `job_queue` 3, `man_page` 10 and `flag_table` 9 passed; the whole lib, 696.
  The merge moved the tests of `crates/podssh-cli/src/man/notes.rs` into `notes_tests.rs`, as the
  draft's lines and the check of curl's flags took it to 505 lines.
- Planted, the summary at `-v` (`scripts/plants/t472-summary-at-v.patch`): its SETUP installs with
  `apk`, so it ran by hand, the patch applied, then taken off: caught,
  `a_run_in_a_pipe_ends_with_one_summary_line` failed.
- Runs in the gate's interop at the push: `scripts/interop-cp.sh`'s `cp.jsonl` (the `done` object,
  then the `summary`) and `scripts/interop-run.sh`'s `run.again` (the summary with no `-v`). The
  gate at `2e3dcec` (run 41613214239) found `scripts/interop-mv.sh`'s `mv.jsonl`, which the draft
  left at one line: it now reads the `done` object first, then the `summary`.

# T-473: `cp` and `mv` have no `--no-clobber`, `--update` or `--backup`

**Source:** GitHub #95 (Nemo-010, 2026-11-02, verified with `podssh 1.0.0 (35a0d19d)`).
**Category:** feature
**Milestone:** none
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A copy always replaces its destination, with exit 0 and no word. A user who deploys cannot ask
podssh to leave a live file alone, a user who syncs cannot ask it to skip a far file that is newer,
and nobody can keep the old file beside the new one. `--inplace` and `--delta` write over the
destination too.

## Premise

- Measured in the issue: `cp -n`, `--no-clobber`, `-u` and `--backup` are each an unknown flag,
  and a second copy of a changed file replaces the far one with exit 0 and nothing on stderr.
  Read: `CP_FLAGS` has no such row (`crates/podssh-cli/src/flags/copy.rs`, lines 10-82 at
  `38f424c`), and each copy
  ends with a rename over its destination (`crates/podssh-cli/src/cp/transfer.rs:207-226`), by
  `posix-rename@openssh.com` where the server has it
  (`crates/podssh-ssh/src/sftp/mod.rs:414-423`).
- Read: `hardlink@openssh.com` gives a file a second name
  (`crates/podssh-ssh/src/sftp/mod.rs:341-351`, which T-146 uses in
  `crates/podssh-cli/src/cp/meta.rs:373-396`). A hard link is never made over a name that is there
  (POSIX `link()`; Inferred for each server), so it can put a verified file at a name that must
  not be replaced, also when that name came during the copy. Not read here: what each server does
  with SFTP's own rename onto a name that is there.
- Read: OpenSSH's `scp` has none of these flags (its usage, T-139). rsync's manual
  (`RsyncProject/rsync:rsync.1.md` at `v3.4.1`): `--update` skips a file whose destination is
  newer, and copies one whose time is equal when the sizes differ; `--backup` keeps the old file
  with the suffix `~` (`--suffix`), and with `--delete` protects the names with that suffix from
  deletion.
- Read: `run`'s check of a file that did not change compares the size and the time of change in
  whole seconds, as SFTP version 3 carries them (`crates/podssh-cli/src/cp/tree_items.rs:22-30`,
  where T-476 moved it from `tree_copy.rs`).

## Approach

1. Flags of `cp` and `mv` (`scp` keeps OpenSSH's table): `--no-clobber` (`-n`), `--update`
   (`-u`), and `--backup` (`-b`) with `--suffix SUFFIX` (default `~`, as GNU `cp` and rsync have
   it). `--no-clobber` with `--backup` is refused (64), as GNU `cp` refuses it; `--backup` with
   `--inplace` is refused (64), as a copy in place keeps no old file.
2. `--no-clobber`: a destination file that is there stays as it is. The copy looks first, before
   any byte goes, and says it once at the default level ("DST: there, so not replaced"). A name
   that comes during the copy stays too: the verified temporary file takes the name by a hard link
   (`hardlink@openssh.com`; here `std::fs::hard_link`), which refuses a name that is there, and
   then the temporary name goes. With no hard link, the look is the guard, and `-v` says so.
   `mv -n` keeps each source that it did not copy. By exec, `ln` (POSIX), else the look.
3. `--update`: a file goes when its destination is missing, when the source's time of change is
   later, or when the times are equal and the sizes differ, as rsync's does; the times in whole
   seconds, as `run` compares them. A file that does not go is said at `-v`.
4. `--backup`: the old file stays at its name with the suffix. Before the rename, a hard link of
   the old file takes that name (an older backup there goes first), so that the destination's name
   is never missing; with no hard link, a rename of the old file first, and `-v` says that the name
   is missing for that moment. With `--delete`, a name that ends with the suffix is never deleted,
   as rsync protects its backups.
5. Each skip counts in T-472's summary and is a `skipped` object with `--jsonl` (its `"why"`:
   `exists` or `not newer`); `--dry-run` says `skip SRC: exists`, `skip SRC: not newer` and
   `backup DST -> DST~`; the `done` object of a copy with a backup gains `"backup"`.
6. The rows, the manual, `docs/cli.md` and `docs/STATUS.md`.

## Decision

- The names are GNU `cp`'s and rsync's, as OpenSSH's `scp` has none: a user of a sync knows them.
  The exit is 0 after a skip that the user asked for.
- A hard link is the guard of `--no-clobber` and the way of `--backup`: it never takes a name that
  is there, and it leaves the old file where it is until the rename. Lost: a look, then the rename
  (a file that comes between the two is replaced); SFTP's own rename, which version 3 says refuses
  a name that is there, but whose answer on other servers was not read.

The calls of the draft (2026-11-03):

- `-n` with `-u` is `-n`: a name that is there stays, whatever its time, as GNU `cp` reads
  `--update=none`. Lost: a refusal of the pair, which a script that sets both for safety would
  meet.
- `--suffix` with no `-b` is refused (64), and so is a suffix that is empty or holds a `/`, a `\`
  or a NUL: an empty one names the destination itself, and one with a `/` another directory.
  Lost: `--suffix` taken as `-b` too, as GNU `cp -S` is; `--suffix` alone ignored, as rsync
  ignores it with no `--backup`.
- `--update` with no time to compare (a copy by exec on a server with no `stat`) copies the file,
  and says so at the default level. Lost: a skip, which would leave a file out of date with exit
  0 and no failure, the copy a user who asks for `-u` wants.
- A link of a tree under `-n` or `-u` is made only where its name is missing, or names the same
  already; anything else there stays, a skip `exists`. Under `-b` the old name takes the suffix
  by a rename. Lost: `-u` comparing a link's time, which the walk does not keep.
- With `--inplace`, `-n` keeps the look as its guard: the bytes go into the name itself, which no
  hard link can guard. Lost: a refusal of the pair; an exclusive create of the first open, which
  a copy that goes on would meet at its own file.
- A copy that goes on from a record of an attempt before does not look again: it looked at its
  first attempt, and under `-n` the hard link still guards the name at the end.
- Between two servers the look is at the second, before any byte goes there, after the first leg
  came here; under `-u` the first leg keeps the source's time on the local copy, which the look
  compares. Lost: a look at the second server before the first leg, one more connection
  (`AGENTS.md`, rule 2).
- `mv` within one server: under `-n`, a hard link of the source at the destination's name, then
  the source's name goes, so a name that came since the look stays; under `-b`, the backup, then
  the server's rename. By exec, `ln` is not probed: the script tries it, and with no link made
  (no `ln`, a file system with none) the look is the guard, as on the SFTP road.
- `across`, `rename_session` and `remove_session` moved from `cp/mod.rs` to
  `crates/podssh-cli/src/cp/across.rs`, so that `cp/mod.rs` stays under 500 lines; the tests of
  `cp_tree` that the Prove names are in `crates/podssh-cli/tests/cp_tree_clobber/mod.rs`, a module
  of `cp_tree`, whose server and helpers it takes, as `cp_tree.rs` is near 500.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cp_args
cargo test -p podssh-cli --test cp_tree -- clobber
cargo test -p podssh-cli --lib cp::
```

`cp_args`: `-n` with `-b`, and `-b` with `--inplace`, exit 64 before anything connects, and
`scp -n` is refused, as OpenSSH's `scp` has no `-n`. A new test of `cp_tree`, against the test's
server (OpenSSH's `sftp-server`), up and down: with `-n`, a destination that is there stays, the
copy exits 0 and says so once, and a destination written while a copy under `-l` runs stays too;
with `-u`, an older destination is replaced, a newer one stays, and one of the same time and
another size is replaced; with `-b`, the old file is at `NAME~` and the new one at `NAME`, and
`--delete` leaves `NAME~`; each also in `--dry-run` and in `--jsonl`. Planted defect: the rename
in place of the hard link for `-n`; the check of a name written during the copy fails.

## Done

2026-11-03, drafted by an agent and merged here; the results are the merge's.

- `crates/podssh-cli/src/cp/clobber.rs` (new): the rule (`Mode`: replace, keep, update; the
  suffix of `--backup`) from the command line, with its refusals; the look before any byte goes
  (`before_far`, `before_local`, `judged`, `decide`), which says `DST: there, so not replaced` at
  the default level and a skip of `-u` at `-v`; the placing of a verified file (`place_far`,
  `place_local`, `link_far`, `backup_far`, `done_here`): a hard link under `-n`, the old file at
  the suffix under `-b`; the names that `--delete` keeps (`protect`); a dry run's `skip` and
  `backup` (`planned`, `dry_up`, `dry_down`). Its unit tests in
  `crates/podssh-cli/src/cp/clobber_tests.rs`: the refusals, `decide`, `protect`, the dry run's
  actions, and the placing here (a name that came stays, a missing one is taken, the old file at
  the suffix): 7 passed (`--lib cp::clobber`).
- `crates/podssh-cli/src/cp/pipe.rs`: `Shape::clobber`. `crates/podssh-cli/src/cp/transfer.rs`:
  `Done` gains `backup` and `skipped`, and derives `Default`; `within` looks and places.
  `crates/podssh-cli/src/cp/bysftp.rs`, `crates/podssh-cli/src/cp/finish.rs` and
  `crates/podssh-cli/src/cp/delta.rs`: the look before the first byte, then the placing in place of
  the rename, up and down. `crates/podssh-cli/src/cp/meta.rs`: `hard_link` places by the rule.
- The copy by exec: `crates/podssh-cli/src/cp/byexec/files.rs` looks (`Far::seen`, the far size
  and with `-u` `stat`'s time) and places; `crates/podssh-cli/src/cp/byexec/keep.rs`: the rename's
  script ends with `ln` under `-n` (a name there stays, a copy's temporary file goes, a moved
  source stays; no link made, `mv` after the look), or with the backup by `ln -f`, else `mv`.
  Its test runs both ends under this host's `sh` and `ln` (Unix): `--lib cp::byexec`, 3 passed.
- `crates/podssh-cli/src/cp/moving.rs`: a move within one server looks, keeps the old file, and
  under `-n` moves by a hard link. `crates/podssh-cli/src/cp/across.rs` (new, from `cp/mod.rs`):
  the copy between servers, whose first leg keeps the source's time under `-u`.
- `crates/podssh-cli/src/cp/outcome.rs`: `add` (a file left out is a skip, with its why) and
  `left`; `crates/podssh-cli/src/cp/session.rs`, `crates/podssh-cli/src/cp/tree_conn.rs` and
  `crates/podssh-cli/src/cp/tree_copy.rs` take it, and `mv` keeps a source left out.
  `crates/podssh-cli/src/cp/tree_items.rs`: a link under the rule, another name of a file
  (`second_name`), and `mv -r`, which leaves each file left out with the directories that hold
  it. `crates/podssh-cli/src/cp/report.rs`: `backup` in a dry run and in the `done` object.
  `crates/podssh-cli/src/cp/summary.rs`: the count's comment.
- `crates/podssh-cli/src/cp/mod.rs`: `CpArgs`'s four fields and the rule into the shape.
  `crates/podssh-cli/src/flags/copy.rs`: the rows of `-n`, `-u`, `-b` and `--suffix`.
  `crates/podssh-cli/src/man/notes.rs`: a note of `cp` and one of `mv`. `docs/cli.md`: a paragraph
  of `podssh cp`, the summary, `--jsonl`, and `podssh mv`. `docs/STATUS.md`: a row.
- Tests: `crates/podssh-cli/tests/cp_args.rs`,
  `no_clobber_update_and_backup_refuse_what_does_not_go_together` (the refusals, 64, each flag
  alone going on to connect, 69, and `scp -n`, 64): `cp_args` 10 passed.
  `crates/podssh-cli/tests/cp_tree_clobber/mod.rs` (a module of `cp_tree`): the four tests of the
  Prove's paragraph, `clobber_no_clobber_keeps_a_destination_up_and_down`,
  `clobber_a_name_written_during_the_copy_stays` (a copy of 40,000 bytes under `-l 64`, the
  destination written once its temporary file is seen), `clobber_update_copies_only_what_is_newer`
  and `clobber_backup_keeps_the_old_file_beside_the_new`: 4 passed against the test's server and
  OpenSSH's `sftp-server` (`cp_tree` 12). The other suites of `cp`, whose output with no new flag
  does not change: `cp_delta` 7, `cp_exec` 6, `cp_inplace` 3, `cp_meta` 7, `cp_parallel` 9,
  `cp_progress` 7, `scp_args` 6; `--lib cp::` 104, the lib 724; `man_page` 10, `flag_table` 9,
  `man_flag_parity` 6, `man_json` 4.
- Planted defect: `scripts/plants/t473-rename-for-no-clobber.patch` and `.plant` (group
  `cli-tests`, OpenSSH's `sftp-server` in its SETUP, as T-476's): `-n` places by the rename, as
  with no flag; the test of a name written during the copy must fail. `git apply --check` of the
  patch: passed. Its run, by hand (this host has `sftp-server`): the test of a name written during the copy failed.
- The merge: the draft's new argument of `remove_local` (the sources left out) was missing in its
  unit test, and clippy asked to elide `holding`'s lifetime; clippy, all targets, `-D warnings`:
  clean; rustfmt: clean.
  `scripts/interop-cp.sh` and `scripts/interop-mv.sh` read no new output, as nothing changes with
  no new flag.

# T-474: `cp` copies many small files one at a time unless `--parallel` is given

**Source:** GitHub #100 (Nemo-010, 2026-11-02, measured with `podssh 1.0.0 (35a0d19d)` through
the relay, at some 172 ms of echo latency), and its comment of the same day.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

Through the relay, each small file waits for its own round trips, so a tree of small files takes
their sum. `--parallel 8` takes 6 to 12 times less time, but a user who does not know the flag
waits minutes: 100 files of 2 bytes took 210 s with the default.

## Premise

- Read: `--parallel` is 1 when it is not given (`crates/podssh-cli/src/cp/pipe.rs`, lines 38-44
  at `477b47c`), and files go K at once only with K above 1 (`crates/podssh-cli/src/cp/lanes.rs`,
  lines 33-37 there). A tree of 50 files or more that goes one at a time says once that
  `--parallel 8` copies 8 at once (`crates/podssh-cli/src/cp/tree_conn.rs`, lines 26-28 and 74-87
  there). One K sets both the files at once and the chunks of one large file
  (`crates/podssh-cli/src/flags/copy.rs`, lines 27-28 there).
- Measured in the issue, each tree equal to its source: 12 files of 40 KB, 28 s one at a time and
  8 s with `--parallel 6`; 20 files of 20 KB, 48.9 s and 10.0 s; 100 files of 2 bytes, 210 s, 32 s
  with 8, and 18 s with 16. T-417 measured 0.8 files a second up with one, and 5.3 with 8, through
  the stand-in relay with 50 ms each way.
- Read: T-141 and T-417 kept the default of 1 as their own call ("several channels are the user's
  choice"), after the operator's ruling Q23. Its row reads: several relay sessions for one copy
  when the user asks, a flag sets the number, the default is 1, and
  `docs/decisions.md:72` says "Several channels in one connection come first". The files K at
  once are channels of one connection (T-297), not relay sessions. T-141's Approach kept K at 1
  "until a measurement shows a gain".
- Read: a server that opens fewer sessions gets fewer files at once, with no failure, and through
  the relay the files share 1.5 MiB in flight (T-297's Decision). OpenSSH opens 10 sessions on one
  connection by default, and the far digest of each file opens an exec channel beside its SFTP
  session; a digest that cannot start falls back to a second read (T-297, T-417).

## Approach

1. When the command line gives no `--parallel`, the files of a run over SFTP (several sources, a
   tree with `-r`, and `run`'s copy) go K at once, K the smaller of their number and a default
   that step 3 sets, from 4 to 8. `--parallel 1` keeps one at a time; `--parallel K` sets K, as
   now.
2. The default is for files alone: a file of more than one chunk goes in one stream unless
   `--parallel` is given, as no measurement through the live relay shows that chunks gain by
   default (T-141 measured 1.34 to 1.55 times through the stand-in). So the shape of a copy keeps
   two numbers: the files at once, and the chunks of one file.
3. The measurement, by T-157's method (`throughput_live`, `cp_small_files_by_tasks`), through the
   stand-in relay and the live relay, with K of 4, 6 and 8: the files a second, and the far
   digests that fell back to a second read. The default is the K with the most files a second
   whose digests do not fall back on OpenSSH's 10 sessions.
4. T-417's line about `--parallel` is not said when the default applies, nor after
   `--parallel 1`, which the user chose.
5. The row of `--parallel` names the default; the manual, README.md (its copies, with the
   measured numbers), `docs/cli.md:2077-2111` and `docs/STATUS.md`.

## Decision

- Q23 does not hold this default, so the entry is not blocked: the ruling sets the default of
  relay sessions, and puts several channels in one connection first; the files K at once are such
  channels, over one outbound connection (rule 2 of `AGENTS.md`). The default of 1 was T-141's
  call, until a measurement showed the gain; the issue's measurements through the live relay show
  3.5 to 11.7 times. If the operator reads Q23 as the default of `--parallel` too, a question goes
  to `TODO/PROGRESS.md`, with this default as its recommendation, and the entry is blocked.
- Lost: K of 16, the issue's fastest, which is more than OpenSSH's 10 sessions, so that the server
  refuses some lanes and the digests of others fall back to a second read; a K that follows the
  measured round trip, of which there is none before the first file.
- 2026-11-03, the draft: the default is 4 until step 3's measurement runs. Each file holds its
  SFTP session and, for its far digest, an exec channel beside it (T-417), so K files hold 2K
  channels at most; of the K that step 3 measures, only 4 stays within OpenSSH's 10 sessions of one
  connection, the rule of step 3. A compile-time check holds the constant to it
  (`crates/podssh-cli/src/cp/pipe.rs`, `FILES_AT_ONCE`). If the measurement shows 6 or 8 with no
  digest read again on OpenSSH, the constant, its row and the documents move to it. Lost: 5, the
  most that fits 10 channels, which step 3 does not measure; 8, the issue's count, by its 2K of 16
  channels.
- `scp` takes the default too: it copies as `cp` does, under OpenSSH's command line, which has no
  flag for it, and a user of `scp` through the relay waits as a user of `cp` did. `sftp`'s batch,
  `edit` and `job`'s fetch keep one file at a time (`Shape::default()`), as each copies the files
  that its commands name, one at a time. Lost: `scp` one at a time, as OpenSSH's own copies.
- T-417's line (a tree of 50 files or more one at a time names `--parallel 8`) goes, as step 4
  asks: with the default no tree goes one at a time but after `--parallel 1`, which the user chose.
  Its test in `crates/podssh-cli/tests/cp_tree.rs` now reads that no line names the flag.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cp_parallel
cargo test -p podssh-cli --test cp_tree
cargo test -p podssh-cli --test throughput_live -- --ignored --nocapture cp_small_files_by_tasks
```

Against the test's server, which counts the SFTP sessions of each connection
(`crates/podssh-cli/tests/ssh_harness/watch.rs:89`): a tree of 20 small files with no
`--parallel` has two sessions or more at once, and the default at most; with `--parallel 1`, one,
and no line about `--parallel`; one file of 25 MiB with no `--parallel` goes in one stream.
Planted defect: the default back to 1; the first check fails.

## Done

2026-11-03, drafted, then merged and run by the main session the same day:

- `crates/podssh-cli/src/cp/pipe.rs`: `Shape` holds two numbers, `files` (the files at once) and
  `tasks` (the chunks of one file); `Shape::default()` keeps one of each, for `edit`, `job` and
  `sftp`'s batch. `FILES_AT_ONCE` is 4 (the Decision), held by a compile-time check to 2K channels
  within OpenSSH's 10; `at_once` gives `(4, 1)` with no `--parallel` and `(K, K)` with
  `--parallel K`. A unit test reads both, and that the row of `--parallel` names the default.
- `crates/podssh-cli/src/cp/mod.rs`: `cp` and `mv` take the shape of `at_once`; `cp::FILES_AT_ONCE`
  is public, for the tests. `crates/podssh-cli/src/cp/sync.rs`: `podssh run`'s copy takes the
  default.
- `crates/podssh-cli/src/cp/lanes.rs`: the lanes follow `shape.files`, not `shape.tasks`; a file of
  more than one chunk still goes after them, alone, in chunks only with `--parallel`.
- `crates/podssh-cli/src/cp/tree_conn.rs`: T-417's line and its threshold go; `batches` takes the
  shape alone (`crates/podssh-cli/src/cp/tree_copy.rs` calls it so). `crates/podssh-cli/src/cp/session.rs`:
  comments.
- The row of `--parallel` (`crates/podssh-cli/src/flags/copy.rs`), the notes of `cp` and `run`
  (`crates/podssh-cli/src/man/notes.rs`, `crates/podssh-cli/src/man/notes_run.rs`), `docs/cli.md`,
  README.md (an example of a tree, and the issue's numbers), and `docs/STATUS.md` (the row of
  `podssh cp`, a row of its own, and T-417's paragraph).
- Tests: `crates/podssh-cli/tests/cp_parallel.rs`, `small_files_go_at_once_with_no_parallel`
  (against the watched server and OpenSSH's `sftp-server`: a tree of 20 small files with no
  `--parallel`, between 2 and the default SFTP sessions at once on one connection and no line
  that names the flag; 20 sources down, the same; `--parallel 1`, one session and no line; one file
  of 25 MiB, one session and no chunks), with the rest of `cp_parallel`: 9 passed.
  `crates/podssh-cli/tests/cp_tree.rs`, `a_tree_of_many_files_names_no_flag` in place of T-417's
  test, with the rest: 8 passed. `cargo test -p podssh-cli --lib cp::`, 91 passed; `--lib man::`,
  37 passed. The other suites of `cp`, whose files of several sources and trees now go 4 at once:
  `copy_pipeline` 4, `cp_delta` 7, `cp_exec` 6, `cp_inplace` 3, `cp_meta` 7, `cp_progress` 4,
  `node_copy` 3, `cp_args` 9, `run_far` 1, `edit_args` 5, `run` 2 and `scp_args` 6 passed.
- The measurement (`cargo test -p podssh-cli --test throughput_live -- --ignored
  cp_small_files_by_tasks`, 2026-11-03, 2,339 s), 200 files of 16 KiB up and back down, files a
  second, and the far digests read again:

  | Cell | Tasks | Up | Down | Digests read again |
  | --- | --- | --- | --- | --- |
  | the stand-in relay, 50 ms each way | 1 | 0.8 | 0.7 | 400 |
  | the stand-in relay, 50 ms each way | 4 | 2.9 | 2.2 | 400 |
  | the stand-in relay, 50 ms each way | 6 | 4.0 | 2.8 | 400 |
  | the stand-in relay, 50 ms each way | 8 | 5.1 | 3.2 | 400 |
  | the stand-in relay, 50 ms each way | default (4) | 2.9 | 2.2 | 400 |
  | a node of the live relay, with the layer | 1 | failed: the 200 did not go within the run's time, as T-417 saw | | |
  | a node of the live relay, with the layer | 4 | 2.8 | 1.3 | 600 |
  | a node of the live relay, with the layer | 6 | 4.5 | 1.5 | 600 |
  | a node of the live relay, with the layer | 8 | 5.6 | 2.0 | 600 |
  | a node of the live relay, with the layer | default (4) | 3.4 | 1.3 | 600 |

  The default, 4, copies 3.6 times as many files a second as one at a time through the stand-in,
  and makes the node's run finish. 6 and 8 go faster still. Each file of each cell read its far
  digest a second time, one at a time too: the test's server (`tests/ssh_harness`) answers the
  commands that the tests name and runs no shell, so the digest's `sh -c` never answers there,
  and the second read is podssh's way for such a server; the column says nothing of the files at
  once. The Decision stands, as 6 and 8 would hold more than the 10 sessions of OpenSSH's
  MaxSessions.
- Planted, the default back to one at a time (`scripts/plants/t474-default-one.patch`): its SETUP
  installs with `apk`, so it ran by hand here, the patch applied, then taken off: caught,
  `small_files_go_at_once_with_no_parallel` failed.
- Waits for the build image (Q88): `scripts/interop-cp.sh` and `scripts/interop-faults.sh`, whose
  copies of several files and trees now go 4 at once against OpenSSH's sshd; the gate's interop
  runs them at the push.

# T-476: `cp -r` says its first failure twice, and exits 66 for a device, FIFO or socket that it skips by design

**Source:** GitHub #105 (Nemo-010, 2026-11-02, verified with `podssh 1.0.0 (35a0d19d)`).
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A tree with two FIFOs gives three lines for two skips, and exits 66, the code of a source that is
missing or cannot be read, though the rest of the tree copied and the row of `-r` calls the FIFO a
skip. A project with a log pipe or a server's socket in it then fails each `cp -r`, which a CI
step reads as a failure, and each `podssh run`, which then runs no command.

## Premise

- Read: an item of a tree that fails is said at once, and the first is kept for the exit
  (`crates/podssh-cli/src/cp/tree_copy.rs`, lines 66-71 at `582b1bf`); at the end, `report` says
  the kept failure again (`crates/podssh-cli/src/cp/report.rs`, lines 69-80 there, line 79). So
  the first failure of a tree is said twice. The issue reads the line said again as the last skip;
  its own output shows `ft/p1`, the first.
- Read, not measured: a list of sources keeps its first failure and says none when it comes
  (`crates/podssh-cli/src/cp/session.rs`, lines 136-141 at `582b1bf`), so the second failure of a
  list is never said, and `--jsonl` gives one `error` object for a run (`report.rs`, lines 69-78
  there).
- Read: a device, a FIFO or a socket of a tree is an `Item::Skip`
  (`crates/podssh-cli/src/cp/tree.rs`, lines 233 and 301 at `582b1bf`), and each skip is a failure
  with the code 66 (`crates/podssh-cli/src/cp/tree_copy.rs`, lines 243-251 and 374-383 there), "a
  source that is missing or cannot be read" (`crates/podssh-cli/src/cp/mod.rs:13-14`). T-143 chose
  it (its Approach, item 3, and its Decision, "as `scp` does"), and the comment of `Item::Skip`
  said so (`tree.rs`, lines 56-57 at `582b1bf`). The row of `-r` says "a device, FIFO or socket
  skipped with a note" (`crates/podssh-cli/src/flags/copy.rs:46-47`).
- Read, in OpenSSH 10.2p1 (`openssh/openssh-portable:sftp-client.c` at the tag `V_10_2_P1`, the
  functions `upload_dir_internal` and `download_dir_internal`): `scp -r` in its SFTP mode, the
  default since OpenSSH 9.0, and `sftp`'s `put -r` and `get -r` log "not a regular file" for such
  a file and go on, with no failure. The old protocol, `scp -O`, counts it as an error and exits 1
  (`openssh/openssh-portable:scp.c`, the functions `source` and `run_err`). So T-143's "as `scp`
  does" holds for `scp -O` alone.
- Read: `--delete` never deletes the name of an item that the source skipped
  (`crates/podssh-cli/src/cp/tree.rs`, lines 140-155 at `582b1bf`), and the check
  `cp.delete.failed` took its failed copy from a FIFO (`scripts/interop-cp.sh`, lines 150-157
  there).

## Approach

1. Each failure is said once, when it comes: `report` says the kept failure only when nothing said
   it before (one file, a connection that failed); the files of a list are said as a tree's are;
   with `--jsonl`, one `error` object for each failure. The exit code stays the first failure's,
   in the order of the sources (T-297).
2. A device, a FIFO or a socket is not copied, and is no failure: one line at the default level
   that names its kind ("SRC: not copied: a FIFO"), a `skipped` object with `--jsonl`, a count in
   T-472's summary, and `skip` in `--dry-run`, as now. The exit stays 0 when nothing else failed.
   `mv -r` removes what it copied, and leaves the special file and the directories that hold it.
   `--delete` goes on, and never deletes the skipped name. `podssh run`, and `sftp`'s `put -r` and
   `get -r`, take the same rule.
3. The other skips stay failures, with their codes: a loop, a depth past 64 levels, a listing or a
   link that cannot be read, a name that is not UTF-8, and a refused name (70).
4. The comments that say that a skip makes the exit not zero
   (`crates/podssh-cli/src/cp/tree.rs:57-58`, and the module comment of
   `crates/podssh-cli/src/cp/tree_copy.rs`), the row of `-r`, the manual, `docs/cli.md:2133-2149`,
   `docs/STATUS.md`, and `scripts/interop-cp.sh`: `cp.tree.up` asks for 0 and the note once, and
   `cp.delete.failed` takes its failed copy from a far directory at the name of a source file (the
   rename onto it fails, 73, as T-297's test makes one fail).

## Decision

- A special file that `-r` cannot copy is a skip, not a failure: OpenSSH's own `scp` and `sftp`
  treat it so, the row of `-r` calls it a skip, and a sync with a FIFO or a socket in its tree must
  not fail at each run. Lost: 66, documented (a project with a socket in it could then never
  `run`); a code of its own for a skip (sysexits has none, and a script reads 0 or not 0); a
  `--strict` flag (`--jsonl`'s `skipped` objects let a script decide); a FIFO made as a FIFO on
  the other side (SFTP version 3 has no request that makes one; Inferred).

The calls of the draft (2026-11-02), each for the operator to confirm (Q86):

- This reverses T-143's call of a skip as a failure (66), as item 2 says; `docs/decisions.md`
  holds no row of it, so no ruling is changed.
- A special file is an item of its own (`Item::Special`, with its kind read from the mode: a
  FIFO, a socket, a character or a block device, else a special file), so that the other skips
  stay failures with no test of their words. Lost: a skip that a text marks as a special one.
- The `skipped` object of `--jsonl` is `{"event":"skipped","source":SRC,"why":"a FIFO"}`, the
  kind as the line says it. Lost: a word of its own (`fifo`); T-473's skips may take theirs.
- `mv -r` leaves each directory that holds a special file, at any depth, and says once that each
  special file stays with them; the rest of the source goes. Lost: the first failed `rmdir` that
  ends the removal, as today, which would leave each other part of the tree too.
- `Outcome` moved to `crates/podssh-cli/src/cp/outcome.rs`, and the steps on one name of
  `tree_copy.rs` to `crates/podssh-cli/src/cp/tree_items.rs`, so that `cp/mod.rs` (497 lines) and
  `tree_copy.rs` (499) stay under 500.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cp_tree -- special
cargo test -p podssh-cli --test cp_parallel
sh scripts/dev.sh check   # interop-cp.sh: cp.tree.up and cp.delete.failed, as item 4 says
```

A new test of `cp_tree` (Unix), against the test's server (OpenSSH's `sftp-server`): a tree with
a file and two FIFOs (`libc::mkfifo`) goes up and down, exits 0, names each FIFO once on stderr
and no line twice, and copies the file; with `--jsonl`, two `skipped` objects; with `-q`, nothing
on stderr and exit 0. A tree with a name that is not UTF-8 still exits not 0, and says it once.
Two missing sources of one command line are each said once, and the exit is 66. Planted defect:
`report` says the kept failure again; the check of one line each fails.

## Correction

2026-11-02: item 4's failure for `cp.delete.failed` does not fail. A tree's file goes to its own
target path, and `transfer::remote_target` puts a file into a directory that is there at that
name, so a far directory at the name of a source file takes the file (T-297's test fails only as
its destination ends with `/`). The check takes its failure from a far directory that the login
may not write, made by the gate's root (73). `cp_tree`'s `delete_after_a_failed_copy_deletes_nothing`
took its failure from a FIFO on Unix too; it now takes it from a far file where the source has a
directory, whose `mkdir` fails also for root.

## Done

Drafted 2026-11-02 by an agent, which built nothing; merged and measured by the main session on
2026-11-03.

- `crates/podssh-cli/src/cp/outcome.rs` (new, from `cp/mod.rs`): `Outcome::fail` says a failure
  at once and keeps the first for the code, each later one for `--jsonl`; `said` tells `report`
  that the first was said. `report` (`crates/podssh-cli/src/cp/report.rs`) says the first failure
  only when nothing said it, and with `--jsonl` gives an `error` object for each failure and a
  `skipped` object for each special file. A list of sources says each failure when it comes
  (`settle`, `crates/podssh-cli/src/cp/session.rs`), as a tree does (`tree_copy::failed`).
- `crates/podssh-cli/src/cp/tree.rs`: `Item::Special` and its kind (`Special`), from the local
  walk's file type and the far walk's mode; `not_copied`, which `--delete` reads. Its unit tests:
  the kinds by mode, and `to_delete` with a special file and a skip.
- `crates/podssh-cli/src/cp/tree_copy.rs`: a special file is said once at the default level
  ("SRC: not copied: a FIFO"), kept for `--jsonl`, and `skip` in a dry run; no failure, so `mv -r`
  and `--delete` go on. `crates/podssh-cli/src/cp/tree_items.rs` (new, from `tree_copy.rs`):
  `mv -r` leaves a special file and the directories that hold it, and says so once; its unit tests.
  `podssh run` and `sftp`'s `put -r` and `get -r` take the same walk.
- The row of `-r`, the notes of `cp`, `docs/cli.md` (the paragraph of `-r`, the objects of
  `--jsonl`, `get -r` and `put -r`), and the row of `podssh cp` in `docs/STATUS.md`.
- `crates/podssh-cli/tests/cp_tree.rs`: `special_files_are_skipped_once_each_with_exit_0` (Unix),
  the Prove's paragraph above; `delete_after_a_failed_copy_deletes_nothing` takes its failure
  from a far file at a directory's name (the Correction).
- `scripts/interop-cp.sh`: `cp.tree.up` asks for 0, the FIFO's note once and no line twice;
  `cp.delete.failed` asks for 73 from a far directory that the login may not write.
- Planted defect: `scripts/plants/t476-said-twice.plant` (group `cli-tests`, with OpenSSH's
  `sftp-server` added in its SETUP): `report` says the first failure again; the new test fails.
- The merge: `cargo test -p podssh-cli --test cp_tree` (Unix, against OpenSSH's `sftp-server`), 8
  passed, `special_files_are_skipped_once_each_with_exit_0` among them; `--test cp_parallel`, 8
  passed; `--lib cp::`, 73 passed. The plant `t476-said-twice`, its patch applied and its RUN run
  by hand (its SETUP is `apk` of the build image): caught, the test of special files failed.
  rustfmt and clippy of `podssh-cli` with `-D warnings`, all targets: clean. `cargo todo remap`
  from the tree before the draft, in place of its port.
- Waits for the build image, which this host's Docker did not run: `scripts/interop-cp.sh`'s
  `cp.tree.up` and `cp.delete.failed`, in the gate's step `release` at each push.
# T-508: `scp` and `sftp` take no `--timeout`, where `cp` and `mv` need one with no terminal, and no manual says why

**Source:** the report of the operator's testing agents on `v1.0.0` (`35a0d19`), 2026-11-02 (T-500's
Source): its issue 08 (`08-timeout-inconsistent.md`) and its ledger's L-12, L-13 and L-30. With
stdin and stdout pipes, `cp` and `mv` exit 64 and ask for `--timeout`; `scp` and `sftp -b` run;
`scp --timeout 30s` and `sftp --timeout 30s` exit 64 with "unknown flag". `scp` to a server that
sends its version line and then nothing was still running when killed at 30 s. Related: GitHub #6
(T-008) and #12 (T-012), both closed. Read at `01e371e`.
**Category:** feature
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A script that drives the four copy verbs must give `--timeout` to two of them and must not give it
to the other two; no manual says that the split is a choice, or why.

## Premise

- Read: the gate asks for `--timeout` with no terminal of each verb whose table has the flag
  (`crates/podssh-cli/src/dispatch.rs:300-324`, `crates/podssh-cli/src/non_interactive.rs:191-215`);
  `cp` and `mv` have it (`crates/podssh-cli/src/flags/copy.rs:63-64`), and `scp` and `sftp` have
  none, by T-139's Decision: as in OpenSSH, so that a script that runs `scp` in a pipe does not exit
  64, with ConnectTimeout and T-133's limits on each wait.
- Inferred, against the report's evidence: a server that sends its version line and then nothing
  holds the handshake, which ConnectTimeout bounds, 60 s by default
  (`crates/podssh-cli/src/ssh/keywords.rs:39-40`); the report killed `scp` at 30 s, before it.
- Read (L-30): `PODSSH_TIMEOUT` is the default of `--timeout` "for each command that has the flag"
  (`crates/podssh-cli/src/man/facts.rs:108-111`), as the report found; met.
- Read (L-13): the gate runs at the dispatch, before a verb reads its operands
  (`crates/podssh-cli/src/dispatch.rs:300-324`), so with no terminal `cp DIR HOST:` with no `-r`
  gets 64 for the missing `--timeout` first, and on a terminal 66.

## Approach

1. `scp` and `sftp` take `--timeout DURATION`, with `PODSSH_TIMEOUT` as its default, as a bound of
   the whole run (75 when it passes, as `cp`'s); it is never required, so T-139's Decision stands.
   The gate reads a field of the row that bounds and does not require, so that the table still
   decides.
2. The notes of `cp`, `mv`, `scp` and `sftp` say the rule and why: `cp` and `mv` need a bound with
   no terminal; `scp` and `sftp` take one and need none, as OpenSSH's tools run in pipes with no
   such flag, and ConnectTimeout bounds their login.
3. The order of L-13 stays: an error of the command line before a fault of the files.
4. Tests in `crates/podssh-cli/tests/scp_args.rs`: `scp --timeout 30s` and `sftp --timeout 30s -b`
   with no terminal go on to connect (no 64); a server of the test that sends its version line and
   then nothing ends `scp --timeout 2s` with 75 within 5 s, and, with no `--timeout`,
   `-o ConnectTimeout=3` ends it with 255 within 10 s.

## Decision

Recommendation, for the operator to rule: the flag on all four, required on two (the report's
first way, with T-139's reason kept). Lost: required on all four, as each script that runs `scp` in
a pipe would exit 64 (T-139); required on none, which drops the gate of T-008 and T-012 that the
testers of #6 and #12 asked for. L-13's order: a usage error comes before the work in each verb,
so that nothing is done by half.

**Ruled, Q72 (2026-11-02):** `scp` and `sftp` take `--timeout` as an optional bound, `PODSSH_TIMEOUT` as its default, never required; `cp` and `mv` keep theirs.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test scp_args -- timeout
cargo test -p podssh-cli --test non_interactive
```

Planted: the new field read as required: the test of `scp` with no terminal fails with 64.

## Correction

2026-11-03, the draft: item 4's 255 is `ssh`'s code. `podssh scp` exits with `cp`'s sysexits
(EXIT STATUS), and a handshake that ConnectTimeout ends is a hop that could not be reached
(`crates/podssh-ssh/src/run.rs:409` says "Err(timed_out) => return Err(HopError::Unreachable(timed_out)),"),
which a copy takes as a server that cannot be reached, 69
(`crates/podssh-cli/src/cp/link.rs:233`). Read, not measured; the test asks for 69 within 10 s.
The field of the row is `FlagRow::optional` (`crates/podssh-cli/src/flags.rs`), set by
`optional(row(...))` on the row of `--timeout` of `scp` and `sftp`, and false on each other row.

## Done

2026-11-03, drafted by an agent and merged here; the results are the merge's.

- `crates/podssh-cli/src/flags.rs`: `FlagRow::optional`, and `optional`, the row as a bound that is
  never required. `crates/podssh-cli/src/flags/scp.rs`: one row of `--timeout`, in `SCP_FLAGS` and
  `SFTP_FLAGS`, `optional`; the module's comment.
- `crates/podssh-cli/src/dispatch.rs`: the gate takes the row of `--timeout`: an `optional` one
  gives the flag, else `PODSSH_TIMEOUT`, else no bound, with a terminal or not; any other row is
  required with no terminal, as before. `sftp` gets the bound.
  `crates/podssh-cli/src/non_interactive.rs`: `optional_timeout`, which refuses a bad flag (64) and
  a bad variable (78) as `require_timeout_or_env` does. `crates/podssh-cli/src/sftp/mod.rs`:
  `run_sftp` bounds the whole run, the login and the batch, and says "the --timeout of N s
  passed" with 75. `scp` takes the bound of `cp`'s run (`run_cp`'s `deadline`), unchanged.
- `crates/podssh-cli/src/man/notes.rs`: the notes of `cp` (the rule, and why `scp` and `sftp` need
  none), `mv`, `scp` (a note of its own in place of "takes no flag for a time limit") and `sftp`.
  `docs/cli.md`: the bullet of `scp` and `sftp` in place of "No `--timeout`", and the bullet of
  `cp`'s limits. `docs/STATUS.md`: a row.
- Tests: `crates/podssh-cli/tests/scp_args.rs`, `timeout_is_a_bound_that_scp_and_sftp_never_require`
  (offline, no terminal: `scp --timeout 30s`, `scp`, `sftp --timeout 30s -b` and `sftp -b` 69;
  `--timeout 30x` and `0` 64; `PODSSH_TIMEOUT=30x` 78, `30s` 69; `cp` with neither 64) and
  `timeout_ends_scp_and_sftp_at_a_server_that_says_nothing` (a listener of the test on the
  loopback that sends `SSH-2.0-...` and then nothing: `scp --timeout 2s` 75 within 5 s, with "the
  --timeout of 2 s passed"; `sftp --timeout 2s -b` 75 within 5 s; `scp -o ConnectTimeout=3` 69
  within 10 s), each process killed past its limit: passed (`scp_args -- timeout`, 3, with
  `scp_goes_on_to_connect_with_its_own_letters_and_no_timeout`; `scp_args` 8).
  `crates/podssh-cli/tests/non_interactive.rs`, `an_optional_timeout_bounds_and_is_never_required`
  and `scp_and_sftp_pass_the_gate_with_no_timeout` (with neither, `scp` and `sftp` say what their
  command line lacks, never the gate): passed (`non_interactive` 17).
- Planted defect: `scripts/plants/t508-optional-required.patch` and `.plant` (group `cli-tests`, no
  SETUP, offline): the gate's arm of an `optional` row taken out, so each row is required;
  `timeout_is_a_bound_that_scp_and_sftp_never_require` must fail with 64. `git apply --check` of
  the patch: passed. Its run (`sh scripts/plant-each.sh --here`): caught.
- The merge: rustfmt and clippy (all targets, `-D warnings`) clean; the lib 746, `man_page` 10,
  `flag_table` 9, `man_flag_parity` 6, `man_json` 4. `scripts/interop-sftp.sh` runs `scp` and `sftp` with no
  `--timeout`, which still needs none.

# T-510: `edit` with no terminal refuses an editor that needs none, and a copy kept after a conflict stays for ever

**Source:** the report of 2026-11-02 (T-500's Source): its ledger's L-15 and L-16. `podssh edit`
with stdin and stdout not a terminal exits 64 whatever `EDITOR` is, and works under
`script -qec`; after a conflict (73) the copy stays in `edit-HASH` of the cache, which nothing
removes. Read at `01e371e`.
**Category:** feature
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

An agent cannot use `edit`'s check of the far file, by which a change on the server is never lost,
with an editor that is a script (`sed -i`); it must copy down and up with `cp`, with no check. Each
conflict leaves a directory in the cache with no end.

## Premise

- Read, against the report's order: the editor is chosen first, and the terminal checked after it
  (`crates/podssh-cli/src/edit/mod.rs`, lines 90-98 at `0548810`): with no terminal, each editor is
  refused, whatever it is.
- Read: the editor runs on the copy with podssh's own terminal
  (`crates/podssh-cli/src/edit/editor.rs`, line 89 at `0548810`); the check of the far file and the
  copy up need no terminal (`crates/podssh-cli/src/edit/mod.rs`, lines 1-12 there).
- Read: a copy that holds a change stays and is named, by design
  (`crates/podssh-cli/src/edit/mod.rs`, lines 9-12 and 154 at `0548810`), in a new directory of the
  cache for each run (`crates/podssh-cli/src/edit/local.rs`, lines 52-54 there).

## Approach

1. `edit --no-terminal` runs the editor with no terminal: its stdin `/dev/null` and its stdout on
   podssh's stderr, so that `EDITOR='sed -i s/a/b/'` works; `--timeout` bounds the editor's run,
   and the gate asks for it with no terminal, as for `cp`. With no terminal and no flag, the
   refusal names the flag.
2. After a conflict, the line names the directory to remove after the merge: "your copy stays at
   P; rm -r DIR once you merged it".
3. A later `edit` says once that copies kept for more than 7 days are in the cache, with their
   directory; it removes none.
4. Tests in `crates/podssh-cli/tests/edit_args.rs` and against the harness: `--no-terminal` with
   an editor of the test that adds a line: the far file has it, 0; the far file changed meanwhile:
   73, and the copy kept; no `--timeout` with no terminal: 64.

## Decision

A flag, not a guess from `EDITOR`: podssh cannot tell an editor that needs a terminal from one that
does not, and `vi` with no terminal waits for ever. Lost: the editor run with no terminal whenever
there is none. A kept copy is never removed by podssh: each holds a change of the user's.

The calls of the draft (2026-11-03):

- `edit` has a dispatch of its own (`Parsed::Edit`), which the gate of `cp` does not see, so the
  rule is `edit`'s, in the gate's words: with `--no-terminal` and no terminal,
  `require_timeout_or_env`, as for `cp` (64, and 78 for a bad `PODSSH_TIMEOUT`). The refusal of no
  terminal comes first and names `--no-terminal`, so a run with neither flag is told of the flag
  that it lacks, not of a bound for a mode it did not ask for.
- `--timeout` without `--no-terminal` is refused (64), and `PODSSH_TIMEOUT` is read with
  `--no-terminal` alone: on a terminal a person decides how long an edit takes (T-149), and a
  `PODSSH_TIMEOUT` that a script set for `cp` must not end a person's edit. Lost: the bound on a
  terminal too.
- The bound covers the editor's run only, as item 1 says; the fetch and the send keep their own
  limits. When it passes, or the first SIGINT or SIGTERM comes, podssh ends the editor, on Unix
  with its process group, which it gets at its start, so that what a script started dies too
  and holds stderr open no more; the exit is 75, or 130; a copy that holds a change stays,
  named, and one with none goes. Lost: the editor's own process alone (a shell's `sleep` lives
  on and holds podssh's stderr).
- The line of a kept copy names its directory after each failure that keeps one, not after a
  conflict alone, in one helper: each such copy needs the same removal.
- The age of a kept copy is that of the newest file in its `edit-*` directory, else of the
  directory; the line is at the default level, so `-q` silences it.
- `scripts/interop-edit.sh`: `kept` reads the path before `; rm -r`, `edit.far_changed` asks for
  the directory in the line, and a new check, `edit.no_terminal_script`, runs the script editor
  with `--no-terminal` against OpenSSH, with no pty (`scripts/interop-baseline.txt`, the floor 9).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test edit_args
cargo test -p podssh-cli --lib edit
```

Planted: `--no-terminal` that still checks the terminal: the test of the editor of the test fails
with 64.

## Done

2026-11-03, drafted by an agent and merged here; the results are the merge's.

- `crates/podssh-cli/src/edit/mod.rs`: `EditArgs` gains `no_terminal` and `timeout`; `how_of`
  gives how the editor runs, or the refusal (the Decision's order); the run passes it to the
  editor, takes `Ended` (75 and 130 with a copy kept or gone), names the directory of a kept copy
  (`rm -r DIR once you merged it`), and says the kept copies older than 7 days; its unit test,
  `no_terminal_takes_a_bound_and_a_terminal_takes_none`: passed (`--lib edit` 8).
- `crates/podssh-cli/src/edit/editor.rs`: `How` and `Ended`; with no terminal the editor gets
  `Stdio::null()` and podssh's stderr for its stdout, on Unix a process group of its own, and a
  wait of 50 ms steps until its end, the bound or the first SIGINT or SIGTERM, which kill the
  group. `crates/podssh-cli/src/edit/local.rs`: `stale`, `stale_line` and `STALE`, and their test,
  `a_kept_copy_older_than_seven_days_is_named_and_stays`: passed.
- `crates/podssh-cli/src/flags/edit.rs`: the rows of `--no-terminal` and `--timeout`.
  `crates/podssh-cli/src/man/notes_edit.rs`: a note of `--no-terminal`, and the kept copies.
  `crates/podssh-cli/src/man/facts.rs`: `PODSSH_TIMEOUT` is `edit`'s with `--no-terminal` alone.
  `docs/cli.md`: the section of `podssh edit`. `docs/STATUS.md`: a row.
- Tests: `crates/podssh-cli/tests/edit_args.rs`, offline: `with_no_terminal_it_is_64` asks for the
  flag's name; `no_terminal_needs_a_bound_and_gets_past_the_terminal` (64 with no bound, 64 for
  `30x`, 78 for a bad `PODSSH_TIMEOUT`, 64 for `--timeout` alone, and with a bound past the
  terminal to the copy's directory, 78 of `PODSSH_CACHE_DIR=none`);
  `the_help_shows_the_connection_flags_and_no_terminal` in place of
  `the_help_shows_the_connection_flags_and_no_timeout`. Against the test's server and OpenSSH's
  `sftp-server` (Unix): `no_terminal_runs_an_editor_that_is_a_script`, the editor `sh SCRIPT`: a
  line added, 0, stdout empty, no copy left; the far file changed by the script meanwhile, 73,
  the far file as the script left it, the copy kept and its directory named; `sleep 30` under
  `--timeout 2s`, 75 within 20 s: `edit_args` 7 passed, these among them.
- `scripts/interop-edit.sh` and `scripts/interop-baseline.txt`, as the Decision says; `podssh-todo
  interop`: 733 ids meet the baseline. Their run: the gate's interop (the build image).
- Planted defect: `scripts/plants/t510-terminal-still-checked.patch` and `.plant` (group
  `cli-tests`, no SETUP, offline): `how_of` refuses each run with no terminal first;
  `no_terminal_needs_a_bound_and_gets_past_the_terminal` must fail. `git apply --check` of the
  patch: passed. Its run (`sh scripts/plant-each.sh --here`): caught.
- The merge: rustfmt and clippy (all targets, `-D warnings`) clean; the lib 748, `man_page` 10,
  `flag_table` 9, `man_flag_parity` 6, `man_json` 4.
