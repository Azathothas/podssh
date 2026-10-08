The work of milestone M3: the run in a real sandbox, and the defects that
the sandbox runs found in podssh and in its own tools.

# T-001: Measure podssh in the operator's real sandbox

**Source:** ROADMAP M3 ("Measured in the operator's real sandbox"), and the
exit criteria of M1 and M2 that point to it. Measured by the operator's agents
on 2026-10-08 in two sandboxes; their reports are outside the repository
(`report-podssh-sandbox-KTM-2026-10-08.txt`, `report-podssh-3a88e1d-20261008.txt`).
**Category:** measurement
**Milestone:** M3
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

The beta waits for a run in a real constrained sandbox. Before 2026-10-08,
only a Podman box built to the profile of such a sandbox was measured
(`scripts/test_in_box.sh`).

## Premise

Measured by the operator's agents, in two sandboxes of different kinds. Each
ran `scripts/sandbox-check.sh` (doctor, proxy, keygen, ssh, and OpenSSH with
podssh as its `ProxyCommand`), the failover check, a throughput check, and
recorded the facts of the host.

## Approach

1. Run `sh scripts/sandbox-check.sh` in the sandbox, with no argument (it
   builds podssh) or with the path of a binary.
2. Run the failover check: a first relay host on a refused port, then the
   default host.
3. Record the facts of the host and the results in `docs/STATUS.md`.

## Prove

```sh
sh scripts/sandbox-check.sh /path/to/podssh   # in the sandbox
( printf 'SSH-2.0-check\r\n'; sleep 2; printf '\000\000\000\000\000\000\000\000'; sleep 3 ) |
    timeout 120 podssh proxy --relay-host tcp.ssh.relay.ajam.dev:9,tcp.ssh.relay.ajam.dev github.com 22
```

The first command shows `26 ok, 0 FAIL` from `doctor` and the expected exit
of each step. The second exits 0 with GitHub's banner, and names the refused
first host on stderr.

## Done

2026-10-08. Recorded in `docs/STATUS.md`, section "In the operator's real
sandboxes".

- **Sandbox A** (edge KTM): Linux 7.2.9 x86_64, uid 0 with no `/etc/passwd`.
  Egress only through an HTTP CONNECT proxy given in the environment. No DNS,
  no direct TCP, `bind` refused for AF_INET and allowed for AF_UNIX, no
  `/dev/ptmx`, `/tmp` and `$HOME` noexec, and a `/dev/tty` that opens with no
  controlling terminal. podssh built from `4853e6c` (a glibc build; the static
  musl artifact of CI run 37745692511 was used for the measurements of GitHub
  #15, #16 and #17). `podssh doctor`: 26 ok, 0 FAIL, 0 ????, exit 0. `proxy
  github.com 22`: GitHub's banner, exit 0. `keygen`: exit 0. `ssh -T
  git@github.com`: exit 255 with the relay's close `1011 write failed: Network
  connection lost` (T-024, T-025). `ssh -tt`: exit 255, `Permission denied
  (publickey)`, as expected. OpenSSH as the client: `No user exists for uid
  0`, because OpenSSH needs a user database entry (T-006). Failover: exit 0,
  GitHub's banner, and the proxy's `403 not on the egress allowlist` for port
  9 named. 20 MiB through the relay: 0.5 to 0.7 MB/s (2 runs). 100 MB: 67,107,943
  bytes, then `1009 session byte cap`, as the relay's contract says.
- **Sandbox B** (Artix Linux): Linux 7.2.2 x86_64, uid 966 with no passwd
  entry, no proxy, and `connect()` refused with EACCES for each port except
  443. No `/dev/ptmx`, `/dev/tty` not a controlling terminal, `TERM=dumb`.
  podssh built from `3a88e1d`. `doctor`: 26 ok, 0 FAIL, 0 ????, exit 0.
  `proxy`: the banner, exit 0. `keygen` exit 0, `ssh` and `ssh -tt` exit 255
  with `Permission denied (publickey)`. OpenSSH: `No user exists for uid
  966`. Failover: exit 0, the banner, and port 9 named with `Permission denied
  (os error 13)`. 20 MB through the relay: 1.8 to 6.9 MiB/s (4 runs).
- The M3 exit criterion "`podssh ssh` and `podssh proxy` work from the
  operator's real sandbox, also when one relay host cannot be reached" is met
  in both sandboxes.
- Not run there: interactive programs over `-tt` (T-004), the prompt fix of
  `eacd94e` (T-005), and `podssh ts`.

# T-003: Decide how the compiled-in root certificates get updates in released binaries

**Source:** ROADMAP M3, open question.
**Category:** research
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

A released binary keeps the Mozilla roots that it was built with. A root that
Mozilla removes stays trusted in old binaries, and a new root that the relay's
certificate chain needs is missing from them.

## Premise

Read: the trust store starts with the compiled-in roots and adds the system
bundles (`crates/podssh-ws/src/tls.rs:37`, `crates/podssh-ws/src/tls.rs:59-64`).
`--ca-file` or `SSL_CERT_FILE` replaces them, and a `podssh-ca.pem` next to the
binary is read (`crates/podssh-ws/src/bundle.rs:22-38`). The roots come from
the crate `webpki-roots` (`Cargo.toml:95`). `podssh doctor` prints the number
of compiled-in roots, not their date.

## Approach

1. Add `webpki-roots` to the Dependabot configuration (T-205). Before
   `v1.0.0`, new roots go into the one release (T-250); after it, a change
   of the roots makes a patch release (the operator, 2026-10-08).
2. Make `podssh doctor` print the version of the compiled-in roots, and say
   when they are older than 12 months.
3. State the rule in `docs/architecture.md` and in the manual's notes: a
   system bundle or `--ca-file` comes before the compiled-in roots for
   revocations.

## Decision

Recommendation: releases that follow the roots, and a doctor line with
their age. The alternative, a download of roots at run time, lost: it needs
a trust anchor to download them, and it adds a connection.

## Prove

```sh
cargo test -p podssh-cli --test doctor
target/debug/podssh doctor | grep 'compiled-in roots'
```

The doctor line names the roots' version, and a test plants an old date and
expects the warning.

# T-004: Interactive use over `-tt` from a box like the sandbox: vi, less, top and Ctrl-C

**Source:** ROADMAP M2, exit criterion "The same from the operator's real
sandbox". The sandbox report of 2026-10-08 says that it was not run. The
operator's ruling of 2026-10-08: measure it in the box; a run in a real
sandbox follows the release (`docs/decisions.md`).
**Category:** measurement
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

An interactive session over `-tt` from a host with no `/dev/ptmx` is measured
against local servers in the gate, and in a Windows console. It was not run
from a real sandbox, where the agent drives podssh over pipes.

## Premise

Read: `-tt` asks the server for a pty and needs nothing local
(`docs/terminal.md`). The gate runs `-tt` over pipes with Ctrl-C, `vi` and the
`PermitTTY=no` fallback (`scripts/interop.sh`). The sandboxes of T-001 have no
`/dev/ptmx` and no controlling terminal.

## Approach

1. In the box (`scripts/test_in_box.sh`), with a server that grants a pty
   and has `vi`, `less` and `top` (railway.new through the live relay, with
   a throwaway key), write keys to `podssh ssh -tt` through a pipe with
   pauses.
2. Edit and save a file in `vi`; page a file in `less` and quit; run `top`
   and quit; stop `sleep 30` with Ctrl-C; end with `exit 7`.
3. Record the output markers and the exit status in `docs/STATUS.md`.

## Prove

```sh
( sleep 3; printf 'vi /tmp/podssh-tt\r'; sleep 2; printf 'ihello\033:wq\r'; sleep 2
  printf 'less /etc/services\r'; sleep 2; printf 'q'; sleep 1; printf 'top\r'; sleep 3; printf 'q'
  sleep 1; printf 'cat /tmp/podssh-tt; sleep 30\r'; sleep 3; printf '\003'; sleep 1; printf 'exit 7\r'
) | timeout 120 podssh ssh -tt -i KEY USER@HOST >/tmp/tt.out 2>/tmp/tt.err; echo "exit=$?"
grep -c hello /tmp/tt.out
```

The exit status is 7, the file holds `hello`, and Ctrl-C stopped `sleep`
before 30 s.

# T-005: A prompt never waits for ever on a `/dev/tty` with nobody behind it (GitHub #15)

**Source:** GitHub #15 (talaria0101, 2026-10-08), measured in sandbox A of
T-001 with the static musl artifact of CI run 37745692511.
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`podssh keygen` with no `-N`, no terminal and no `SSH_ASKPASS` waited for
ever, with no output and nothing written (exit 124 under `timeout 40`). The
same check decides the host-key, password and passphrase prompts of `podssh
ssh`. `docs/cli.md` promised a refusal that names `-N ''`.

## Premise

Measured by the reporter: in that sandbox, `open("/dev/tty", O_RDWR)`
succeeds with no controlling terminal (`ps` shows `TT ?`), `isatty` is false
for descriptors 0, 1 and 2, and a read of one byte blocks for the whole bound.
Read: before `eacd94e`, the prompt trusted `/dev/tty` when it could open it.

## Approach

Done in `eacd94e`:

1. `crates/podssh-ssh/src/terminal/ctty.rs:17-47` trusts `/dev/tty` only when
   the kernel names it: `isatty`, the same session (`tcgetsid` equal to
   `getsid(0)`), and `tty_nr` not 0 in `/proc/self/stat`.
2. `crates/podssh-ssh/src/prompt.rs:78-92` asks only on that terminal.
3. With stdin, stdout and stderr all redirected, a prompt on the terminal
   waits 60 s at most (`crates/podssh-ssh/src/terminal/mod.rs:62-68`), then
   refuses with the remedy (`crates/podssh-ssh/src/terminal/unix.rs:163-229`).

Owed: the measurement in the box, with a `/dev/tty` that opens with no
controlling terminal (a pty of the host bound to `/dev/tty` in the
container), with a binary built at or after `eacd94e` (the operator's ruling of 2026-10-08).
Then close GitHub #15. A run in a real sandbox follows the release.

## Prove

```sh
cargo test -p podssh-ssh
env -u SSH_ASKPASS -u SSH_ASKPASS_REQUIRE timeout 90 podssh keygen -t ed25519 -f /tmp/k </dev/null; echo "exit=$?"
ls /tmp/k
```

On Linux, the tests of `ctty` and of the deadline pass. In the box, the
keygen command exits 1 at once with the refusal that names `-N ''`, and
`/tmp/k` does not exist.

## Done

2026-10-08. The repair is commit `eacd94e`. The measurement in the box is
the commit "The box has the sandbox's dead /dev/tty; T-005 measured there".

- `cargo test -p podssh-ssh` passed on Linux in CI run 37756964230, with the
  tests `a_tty_the_kernel_does_not_name_is_not_trusted`,
  `a_read_with_a_deadline_stops_when_nobody_answers` and
  `an_answer_in_time_is_read`.
- The box has the `/dev/tty` of the target sandbox now:
  `scripts/box/deadtty.py` holds a pty with nobody at its master on the
  Podman host, and `scripts/test_in_box.sh` binds its slave at `/dev/tty`.
  `scripts/box/probe.sh` checks it: in the box, "opens, no byte within 5 s,
  no controlling terminal"; planted (the same box with no bound tty),
  `DIFFERS` with "No such device or address", exit 1.
- `scripts/sandbox-check.sh` has the step "a prompt with nobody to answer
  it", under `setsid`. In the box, with the gate's static binary of
  `4bf0c26` (CI run 37783671123): `podssh keygen` with no `-N` and no
  `SSH_ASKPASS` exits 1 after 0 s with "there is no terminal and no
  SSH_ASKPASS to ask for a passphrase; use -N '' for a key without one", and
  writes no key. `podssh ssh -o StrictHostKeyChecking=ask` to `github.com`
  with no `known_hosts` exits 255 after 1 s, with GitHub's fingerprint and
  `accept-new`. The run exits 0.
- The planted control: the gate's binary of `d0b16a3`, before `eacd94e`, in
  the same box. `keygen` waits until `timeout` stops it at 90 s (exit 143);
  `ssh` waits until its 60 s handshake limit ("the SSH handshake did not
  finish within 60 s"). Both steps print `FAIL`, and the run exits 1.
- Found on the way: on Windows, each podman command wrote the Podman
  machine's host key to a file named `NUL` in the current directory.
  `scripts/test_in_box.sh` now runs podman from its own work directory.
- A run in a real sandbox follows the release (`TODO/PROGRESS.md`,
  "Operator actions").

# T-006: `scripts/sandbox-check.sh` exits 0 when its steps fail, and ignores `CARGO_TARGET_DIR` (GitHub #28)

**Source:** GitHub #28 (talaria0101, 2026-10-08), and the sandbox report of
T-001 (its notes N1 and N3).
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The script that makes the sandbox record always exits 0. When
`CARGO_TARGET_DIR` is set, the build succeeds, each later step fails with
exit 127 (`target/release/podssh: not found`), and the script still exits 0.
On a host with no `ssh`, the OpenSSH step goes away with no word. On a host
with no user database entry, the OpenSSH step prints `No user exists for uid
0` and exit 255, which reads like a failure of podssh.

## Premise

Read: the path of the built binary is fixed (`scripts/sandbox-check.sh`
line 41 at `4bf0c26`); each step prints its exit code and goes on; the
OpenSSH step runs only when `ssh` exists (line 70 at `4bf0c26`); the last
line is `exit 0`.
`scripts/test_in_box.sh` runs this script in the box, so the box's result has
the same defect. Measured by the reporter, with eleven `exit=127` lines in a
run that exited 0.

## Approach

1. Find the binary where cargo put it: `${CARGO_TARGET_DIR:-target}`, or the
   `target_directory` of `cargo metadata`. Run it once (`--version`) before
   the steps, and exit 1 when it does not run.
2. Give each step its expected result (doctor 0; proxy 0 and a line that
   starts with `SSH-2.0-`; keygen 0; `ssh` and `ssh -tt` 255 with `Permission
   denied (publickey)`), and print `ok` or `FAIL` for each.
3. A step that cannot run here prints `skip` and the reason: no `ssh`, or
   OpenSSH that refuses with `No user exists for uid`. A skip does not fail
   the run.
4. Exit 1 when a step failed, else 0.
5. In `docs/development.md`, say how to build in a sandbox where `/tmp` or
   `$HOME` is noexec, `CARGO_HOME` cannot be written, or `/tmp` is small: set
   `CARGO_HOME`, `CARGO_TARGET_DIR` and `TMPDIR` to a directory that `podssh
   doctor` names as able to run programs.

T-052 moves these checks into the binary; this entry keeps the script honest
until then.

## Prove

```sh
sh scripts/sandbox-check.sh /bin/false; echo "exit=$?"
CARGO_TARGET_DIR=/tmp/podssh-target sh scripts/sandbox-check.sh; echo "exit=$?"
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh; echo "exit=$?"
```

The first exits 1 (the binary does not run). The second builds into
`/tmp/podssh-target`, finds the binary, and exits 0 on a host where the steps
pass. In the box, the run exits 0, and a planted step failure (a binary that
exits 3 for `doctor`) makes it exit 1.

## Correction

2026-10-08, read at `4bf0c26`: the script had no `exit 0` line. It ended with
the OpenSSH step, so it exited with the status of its last command, which was
0 in each run. The defect of the Problem holds.

## Done

2026-10-08, in the commit "sandbox-check.sh: each step has a verdict, and a
failed step fails the run". Each step prints `ok` or `FAIL` against its
expected result, or `skip` with the reason (no `ssh`; OpenSSH with no user
entry; the prompt steps on Windows, where podssh asks on the console). The
binary runs once (`--version`) before the steps. A last line counts the
verdicts, and the script exits 1 when a step failed.

- `sh scripts/sandbox-check.sh /bin/false`: "FAIL the binary: /bin/false
  --version exits 1", exit 1, before any step.
- `CARGO_TARGET_DIR=/tmp/podssh-target sh scripts/sandbox-check.sh` on
  Windows (Git Bash, native cargo 1.98.0): the release build went into that
  directory, the script found the binary there, and printed 6 ok, 0 FAIL,
  2 skip (the two prompt steps), exit 0.
- `sh scripts/test_in_box.sh` with the gate's binary of `4bf0c26`: 7 ok,
  0 FAIL, 1 skip (OpenSSH: "No user exists for uid 0"), exit 0.
- Planted, in the box: the same binary behind a wrapper whose `doctor`
  exits 3: "FAIL doctor: exit 3", 6 ok, 1 skip, and the box exits 1.
- `docs/development.md` says how to build in a sandbox where `/tmp` or
  `$HOME` is `noexec`, `CARGO_HOME` cannot be written, or `/tmp` is small.
