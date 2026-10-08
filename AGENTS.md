# AGENTS.md

Read this file first. It tells you what podssh is, which documents to read
for your task, and the rules for all work on this repository. It is for
agents and for people.

## 1. What podssh is

podssh is one static Rust binary. It carries SSH, or another TCP stream,
through a WebSocket relay on port 443. It is for hosts whose only way out is
HTTPS, often through an HTTP CONNECT proxy.

These commands work: `podssh ssh`, `podssh proxy`, `podssh doctor`,
`podssh keygen` and `podssh man`. The other commands refuse with exit
code 70.

## 2. Start procedure

You have no memory of earlier sessions. The files in this repository are the
only record. Do these steps at the start of each session.

1. Read [README.md](README.md).
2. Read [docs/STATUS.md](docs/STATUS.md). It gives the measured state.
3. Read [docs/ROADMAP.md](docs/ROADMAP.md). Find the first item that is not
   done (`- [ ]`) in the current milestone. That item is your task, unless
   the operator gives you a different task.
4. Read [docs/decisions.md](docs/decisions.md). Do not change a decision. If
   a decision seems wrong, ask the operator.
5. Find your task in section 3. Read the documents in its row.

## 3. Documents for each task

| Task | Read |
| --- | --- |
| Build, test, or run the gate | [docs/development.md](docs/development.md) |
| Measure podssh in a sandbox, or in a box like one | [docs/development.md](docs/development.md) (section "A box like the target sandbox"), [docs/target-environment.md](docs/target-environment.md) |
| Make a release | [docs/development.md](docs/development.md) (section "Release builds"), [docs/releases/](docs/releases/) |
| Change the command line, `doctor` or `keygen` | [docs/cli.md](docs/cli.md), `crates/podssh-cli/src/flags.rs` |
| Change the SSH client | [docs/cli.md](docs/cli.md), `crates/podssh-ssh/` |
| Change the terminal behaviour | [docs/terminal.md](docs/terminal.md) |
| Change the relay selection, tokens or failover | [docs/relay.md](docs/relay.md), `crates/podssh-relay/` |
| Change TLS, proxies or DNS | [docs/architecture.md](docs/architecture.md), `crates/podssh-ws/` |
| Work on reverse mode (milestone M4) | [docs/reverse.md](docs/reverse.md), [docs/design.md](docs/design.md) |
| Work on IRC | [docs/irc.md](docs/irc.md) |
| Work on Tailscale | [docs/tailscale.md](docs/tailscale.md) |
| Repair a known defect | [docs/defects.md](docs/defects.md) |
| Know where podssh goes, and why | [docs/design.md](docs/design.md) |
| Know the security model | [SECURITY.md](SECURITY.md) |

## 4. Safety

CAUTION: Builds can use all the memory of this machine. On 2026-10-07, three
builds at the same time almost stopped it.

1. Set `CARGO_BUILD_JOBS=4` before each cargo command.
2. Run one build at a time. Do not start a container build while another
   build runs.
3. For daily work, build natively: `cargo build`, `cargo test`.
4. For the Linux gate and the static binary, use `sh scripts/dev.sh check`.
   It limits its jobs and runs one at a time.
5. Use `--features ts` only for work on Tailscale.

CAUTION: A `wsl.exe` command acts on each WSL distribution of this machine.
Do not call `wsl.exe`. Do not use `wsl --shutdown`, `--terminate` or
`--unregister`. Use `scripts/dev.sh` for Linux work. Use
`scripts/test_in_box.sh` for the Podman box.

WARNING: A relay token and a private key are credentials. Do not put a
credential in output, logs, URLs, argv, commits or issues. Mint a relay
token, use it and discard it in one shell. Do not read or print the `.env/`
directory.

## 5. Rules for the code

These rules come from [docs/decisions.md](docs/decisions.md).

1. Do not assume that the client host has a privilege, a tool or a setup.
   Probe it at runtime. Do not use a capability that was not probed.
2. Make one outbound connection, through `HTTPS_PROXY` when it is set. Do
   not bind, listen, or use loopback helpers. (`podssh doctor` binds a
   socket to test the host, and closes it without listening.)
3. Do not use `LD_PRELOAD` or helper processes.
4. Do not put C code in the library crates: `podssh-ws`, `podssh-relay`,
   `podssh-transport`, `podssh-core`, `podssh-terminal` and `podssh-probe`.
   The binary links aws-lc for SSH (`russh`).
5. Keep each source file at 500 lines or fewer. Split a longer file. Do not
   remove comments to make a file shorter.
6. Write comments that tell why, in few words. Do not write `⛔`, session
   history, or document line numbers in the code.
7. Prefer redundancy and fallbacks to minimal code.
8. Repair a defect that you find in the same session. If you cannot, add it
   to [docs/defects.md](docs/defects.md).

## 6. Procedure for a change

1. Do one ROADMAP item at a time. Complete it to its exit criteria.
2. Test protocol code against software that podssh did not write: OpenSSH,
   Dropbear, a real IRC server, the live relay, or bytes captured from one.
3. Trust a new check only after it fails on a planted defect and passes on
   correct input.
4. Read each exit code directly, not through a pipe. Put a time limit on
   each network wait and on each process wait.
5. Before each commit, run `python scripts/check-repo.py` and the tests.
6. In the same commit, record the result in
   [docs/STATUS.md](docs/STATUS.md) with the date and the command that
   measured it. Mark the ROADMAP item done.
7. Commit on `main`. Attribute the commit to the operator only. Do not add
   co-author lines.
8. Push only verified work. Do not rewrite published history. CI runs the
   gate on each push.
9. Do not change the line endings of a file that you do not otherwise
   change.
10. Do not change the files in `.tmp/`. They are read-only copies of other
    projects. Make sure that a copy exists before you use it.

## 7. Map

| Path | Contents |
| --- | --- |
| `crates/podssh-cli` | The `podssh` binary: arguments, help, man page, dispatch, `proxy`, `ssh` options, `doctor`, `keygen` |
| `crates/podssh-ssh` | The SSH client on `russh`: the relay stream, `known_hosts`, authentication, prompts, terminal, exit codes, key generation |
| `crates/podssh-relay` | Relay hosts, the pool, failover, tokens, the forward opener |
| `crates/podssh-ws` | TLS (podssh's own pure-Rust rustls provider), proxies, DNS fallbacks, the WebSocket client |
| `crates/podssh-transport` | Relay framing for the forward, node and operator legs |
| `crates/podssh-core` | Sans-IO protocol code: `irc/` |
| `crates/podssh-terminal` | A line discipline (not used yet) |
| `crates/podssh-probe` | Facts about the relay document (tests only) |
| `crates/podssh-ts` | The Tailscale adapter (feature `ts`) |
| `vendor/tailscale-rs` | A fork with local patches (`vendor/patches/`). It is outside the workspace and the 500-line rule. |
| `scripts/dev.sh`, `scripts/gate.sh` | Container runs, and the build gate that CI also runs |
| `scripts/interop*.sh`, `scripts/interop-pty.py`, `scripts/interop-conpty.py` | Tests against OpenSSH and Dropbear, faults, and terminals on Linux and Windows |
| `scripts/test_in_box.sh`, `scripts/box/`, `scripts/sandbox-check.sh` | The Podman box like the target sandbox, and the measurement for a sandbox |
| `scripts/check-*.py`, `scripts/plant.sh` | Repository checks, and the planted-defect check of the gate |
| `docs/` | The documents: STATUS, ROADMAP, decisions, defects and topic pages |
