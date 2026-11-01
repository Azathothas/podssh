File copy: the SFTP client in the process, `podssh cp` and `podssh mv`, the
command lines of `scp` and `sftp`, and the copy features of the backlog.
T-133 to T-139 are milestone M5; T-140 to T-150 wait until the operator
schedules them. Each entry keeps one invariant: each SFTP request, each exec
step and each open of a session has a time limit.

# T-133: An SFTP client in the process, the base of `cp`

**Source:** ROADMAP M5 ("SFTP in the process"), `docs/design.md:625-629`;
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
  (`scripts/interop.sh:364-366`).

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
   `REPLY_WAIT`), 60 s with no data acknowledged (`docs/design.md:649`),
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

**Source:** ROADMAP M5 (`podssh cp` and `podssh mv`), `docs/design.md:625-629`;
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
   (`crates/podssh-cli/src/ssh/args.rs:203-330`). An operand is remote when a
   `:` comes before any `/`; on Windows, `C:\x` is local. Fewer than two
   operands, or none remote, exit 64.
2. Build an `SshArgs` (host, `-P` as the port, `-i`, `-o`) for
   `crate::ssh::resolve::resolve`
   (`crates/podssh-cli/src/ssh/resolve.rs:120-497`), so `-F` follows the rule
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
    `docs/cli.md` and `docs/STATUS.md:71`.

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
`docs/design.md:625-629`; GitHub #18 (zuko's file server, read in the issue).
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
  (`docs/STATUS.md:92`, `scripts/interop.sh:139-154`), and 300 KB up and
  5 MB down through the relay (`docs/STATUS.md:96`).
- Read: a command goes as one string, never as a shell request
  (`crates/podssh-ssh/src/options.rs:63-64`), with no pty when stdin is not
  a terminal (`crates/podssh-ssh/src/session.rs:70-80`).
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
when step 5 fails. `docs/design.md:626` names both tools; raw bytes are
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
`docs/design.md:627-628`; GitHub #21 (agent-ssh-cli's `.part` and
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
(`docs/STATUS.md:306`), and drops that came back 3 times of 3 on one target.

## Premise

- Read: today a drop ends the session with the relay's reason, and nothing
  continues (`docs/design.md:645-653`).
- Read: SFTP reads and writes name their offset, so a copy can continue at
  any offset. The far file's size is no proof: with requests in flight
  (T-140), a later write can land while an earlier one fails.
- Read: the cache directories keep private files of mode 0600
  (`crates/podssh-relay/src/cache.rs`, lines 62-76 at `4dd52f8`,
  `crates/podssh-relay/src/cache.rs:129-173`).
- Read: after a drop, the relay closes the target's TCP connection within
  15 s (`docs/design.md:655-658`), so a far `cat` can write for a while.

## Approach

1. A side file in the cache directories, named by a hash of user, host,
   port and both paths: the source's size and mtime, the temporary name,
   and the offset below which each write was acknowledged. Never the bytes.
2. Within a run: after a relay close, a lost connection or a failed
   request, open a new session (T-137's path) and continue at the offset.
   Check first that the host key is the one of the first session (pin it in
   memory, `crates/podssh-ssh/src/handler.rs:124-146`), and that the source's
   size and mtime are the same; else start over and say so.
3. Invariant: the attempts are bounded. At most 5 in a row with no new
   acknowledged byte, with `podssh_relay::open::backoff`
   (`crates/podssh-relay/src/open.rs:385-393`). Stop at once on a refused
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
(`scripts/fake-relay.py:360-388`) ends each session after 1,500,000 bytes
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
relay (64 MiB, 12 h)"), `docs/relay.md:194-202`; the KTM sandbox report of
2026-10-08 (`report-podssh-sandbox-KTM-2026-10-08.txt`, not in the
repository).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The relay ends a session after 64 MiB in both directions together, or after
12 h (`docs/relay.md:199-200`). A larger copy breaks in a request with
`1009 session byte cap`. T-136 continues after it, but each cut costs a
broken SSH connection, a wait and an error line, and on the exec road an
old writer can race the new one.

## Premise

- Read: the pinned contract gives the same caps
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:233-235`).
- Measured in the KTM sandbox (`docs/STATUS.md:305`; the 99 s are in the
  report): `podssh proxy` received 67,107,943 bytes, then the relay closed
  with `1009 session byte cap`, 921 bytes short of 64 MiB on that side.
- Read: `podssh-relay` has a constant for the idle cut only
  (`crates/podssh-relay/src/relay.rs:19-21`); `podssh-core` has its own for
  IRC, with a budget of 60 MiB and the reason for the margin
  (`crates/podssh-core/src/irc/limits.rs:88-95`).
- Read: the relay stream sees each payload byte both ways
  (`crates/podssh-ssh/src/relay_stream.rs:213`,
  `crates/podssh-ssh/src/relay_stream.rs:240-252`). Each new SSH
  connection asks again for a passphrase or a password
  (`crates/podssh-ssh/src/keys.rs:283-345`,
  `crates/podssh-ssh/src/auth.rs:266-327`).

## Approach

1. The caps (64 MiB, 12 h) and podssh's budgets (60 MiB of payload both
   ways; 11 h 30 min) go in `crates/podssh-relay/src/relay.rs`, beside
   `RELAY_IDLE_SECS`. A variable `PODSSH_SESSION_BUDGET` can lower the byte
   budget (a relay with smaller caps, the tests), never raise it; add it to
   `crates/podssh-cli/src/man/facts.rs:45-282`.
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
   (`crates/podssh-cli/src/man/facts.rs:302-457`), from the constants;
   `docs/relay.md` and `docs/cli.md`. T-155 does the same for the
   resumable layer of M6; this entry needs no M6 work.

## Decision

Recommendation: a budget of 60 MiB counted by podssh, as `podssh-core`
uses for IRC: the relay counts bytes that podssh has not yet received, and
can hold 2 MiB queued (`docs/relay.md:266`). Waiting for `1009` (T-136
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
both directions, as the relay counts (`docs/relay.md:200`). With
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
`crates/podssh-cli/src/flags.rs:393-394`.
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
- Read: `mv` shares `CP_FLAGS` (`crates/podssh-cli/src/flags.rs:393-394`),
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
   `docs/cli.md` and `docs/STATUS.md:72`.

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
6. Same commit: `crates/podssh-cli/src/help.rs:234-291`, the manual and its
   examples, `docs/cli.md`.

## Decision

Recommendation: `scp` and `sftp` get no `--timeout` row, as in OpenSSH, so
the gate of `crates/podssh-cli/src/dispatch.rs:281-299` skips them; T-133's
limits keep each wait finite. Usage errors stay 64 (`docs/cli.md:3184-3187`)
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
  (`crates/podssh-ssh/src/run.rs:29`), so a download has 512 KiB in flight
  at most, whatever the number of requests: two reads of 255 KiB fill it.
- Read: the comment on the window quoted a row of the reverse close codes
  (1 MiB queued, `1011`, a dropped frame;
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). T-024
  corrected it to the forward path's rule
  (`crates/podssh-ssh/src/run.rs:25-28`): `docs/relay.md:277-289` gives
  2 MiB, `1013` and no drop. The window can grow only after that is
  settled; T-062 measures the `1013`.
- Measured in two sandboxes (`docs/STATUS.md:304`): 20 MiB through the
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
  server (`crates/podssh-ssh/src/run.rs:29`). The server's window, which
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
  road (`docs/design.md:1233-1236`), and on 2026-10-08 for one copy when the
  user asks (`docs/decisions.md`).
- Read: the cap of 64 MiB is for each session (`docs/relay.md:200`).
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
to 0.7 MB/s in the KTM sandbox (`docs/STATUS.md:304`).

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

**Source:** the `-r` row (`crates/podssh-cli/src/flags/copy.rs:31-32`);
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
(`crates/podssh-cli/src/flags/copy.rs:31-32`), and `podssh cp` copies files
(`crates/podssh-cli/src/cp/`): this entry builds on its temporary name, its
digest check and its rename for each file of a tree.

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
sandbox, `docs/STATUS.md:304`). podssh would show no progress, a Ctrl-C
would leave a temporary file with no word, and one copy can take the whole
uplink of a shared host.

## Premise

- Read: stdout carries answers only, and messages go to stderr
  (`crates/podssh-cli/src/dispatch.rs:3-7`). `cp` has a `--jsonl` row
  (`crates/podssh-cli/src/flags/copy.rs:45-46`).
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

**Source:** the `-p` row (`crates/podssh-cli/src/flags/copy.rs:17-18`);
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
(`crates/podssh-cli/src/flags/copy.rs:17-18`); a copy keeps the source's
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
  the escape filter (`crates/podssh-ssh/src/io.rs:198-257`). Nothing looks
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
  (`crates/podssh-cli/src/man/facts.rs:45-282`).
- Read: the relay cuts a session after 180 s with no payload
  (`crates/podssh-relay/src/relay.rs:19-21`); an editor stays open longer.

## Approach

1. A new verb `edit` in `VERBS` (`crates/podssh-cli/src/flags.rs:366-427`),
   with the connection flags that T-134 gives `cp`. It needs a terminal on
   stdin and stdout; else exit 64.
2. Download with T-134 into a new directory of mode 0700 in the cache
   directories (`crates/podssh-relay/src/cache/dirs.rs:50-87`), as a file of
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
`docs/design.md:1238-1244`.
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
  (`docs/design.md:1238-1244`).

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
gives no byte (`crates/podssh-cli/src/cp/bysftp.rs:160-186`), and each read
waits for the server's answer to the write before it. The check's writer
adds a byte to the source in a loop, so a read gives no byte only when the
writer adds none for a whole round trip: when the runner does not schedule
it. The check after the read gives 66 to a source whose size moved
(`crates/podssh-cli/src/cp/bysftp.rs:263-266`), but only once the read
ends. The copy up by exec reads the same way
(`crates/podssh-cli/src/cp/byexec/files.rs:119-144`); the copies down read
the far file until it ends, over SFTP
(`crates/podssh-cli/src/cp/bysftp.rs:408-447`) and with `cat`
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
past it: up over SFTP (`crates/podssh-cli/src/cp/bysftp.rs:160-186`) and by
exec (`crates/podssh-cli/src/cp/byexec/files.rs:119-144`); down by exec
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
- Waits for T-251: the rate of many small files through the relay by
  T-157's method. The Prove names no interop harness.
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
