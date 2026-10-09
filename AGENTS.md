# AGENTS.md

Read this file first. It tells you what podssh is, which documents to read
for your task, and the rules for all work on this repository. It is for
agents and for people.

## 1. What podssh is

podssh is one static Rust binary. It carries SSH, or another TCP stream,
through a WebSocket relay on port 443. It is for hosts whose only way out is
HTTPS, often through an HTTP CONNECT proxy.

These commands work: `podssh ssh`, `podssh proxy`, `podssh cp` (files),
`podssh doctor`, `podssh keygen`, `podssh man`, `podssh status`,
`podssh node`, `podssh operator` and `podssh relay` (`pair`, `revoke`,
`status NAME` and `spec`). The other commands refuse with exit code 70.

## 2. How a session works

You have no memory of earlier sessions. The files in this repository are the
only record. A session can start with the prompt "Read AGENTS.md in full and
follow it" and nothing more: this file is then your whole instruction.

**Work unattended.** The operator's standing instruction (2026-10-08,
[docs/decisions.md](docs/decisions.md)): work for as long as you can. Do not
stop to ask, and do not wait for a reply. Stop only when the operator
interrupts you, or when the goal is reached.

**The goal.** Each entry of `TODO/` is done, except the entries that wait
for the relay's operator. Each test passes, and the gate is green in CI.
`v1.0.0`, the first stable release, is published and verified from end to
end (T-250, T-251). It is the one release: no beta, and no release between
entries.

### At the start of a session

1. Read [README.md](README.md), [docs/STATUS.md](docs/STATUS.md) (the
   measured state) and [docs/decisions.md](docs/decisions.md) (the
   operator's decisions).
2. Read [TODO/PROGRESS.md](TODO/PROGRESS.md) (the state, the baseline and
   the only work order) and [TODO/RULES.md](TODO/RULES.md) (how the record
   is kept). [docs/ROADMAP.md](docs/ROADMAP.md) gives the milestones and
   their exit criteria.
3. Measure the baseline again: `cargo todo check`,
   `python scripts/check-repo.py` and the tests
   ([docs/development.md](docs/development.md)). Read the last CI run
   (`gh run list`). A failure that the record does not know is your first
   task.
4. Read the GitHub issues and comments that are newer than
   [TODO/issues.md](TODO/issues.md), and make each new request an entry
   ([TODO/RULES.md](TODO/RULES.md)).
5. If an entry is `partial`, continue it first. Its notes say what is done.

### The loop

Take the first entry of the work order that is not done and not blocked.

1. Read the entry, and the documents of its area (section 3). Verify its
   Premise at the cited lines. If the Premise is wrong, write a
   `## Correction`, and change the Approach to match.
2. Before a long step, set the entry to `partial`, and write in it what is
   done. A compaction of your context, or a crash, then loses nothing.
3. Do the work as section 6 says, and run the entry's Prove.
4. Close the entry in place, record the result in
   [docs/STATUS.md](docs/STATUS.md), then commit and push (section 6).
5. When each entry of a GitHub issue is done, comment on the issue with the
   commits and a short summary, and close it
   ([TODO/RULES.md](TODO/RULES.md)).
6. Read the result of the last CI run, and the new GitHub issues and
   comments. A failed run is the next task; a new request becomes an entry.
7. Take the next entry.

After a compaction of your context, read this file again, then
`TODO/PROGRESS.md` and the entry that is `partial`.

### When you need a decision

- Look in [docs/decisions.md](docs/decisions.md) and in the entry's
  `## Decision`, and follow them.
- Else make a defensible call. Write it in the entry's `## Decision`, with
  each alternative that lost and why. Then continue.
- A change of a policy in `docs/decisions.md` belongs to the operator. Write
  a question with a recommendation in `TODO/PROGRESS.md`, set the entry to
  `blocked`, and take the next entry. A row whose facts your own work
  changed (a list of crates, an exception that your work removes) you
  correct yourself; move the old text to "Superseded".
- When somebody outside must act, set the entry to `blocked`, write a
  `## Blocker` that names who, and take the next entry. Do not work on the
  entries that wait for the relay's operator (`TODO/PROGRESS.md`).
- Never close an entry as out of scope or as "won't fix".

### Releases

- One release only, at the end: `v1.0.0`, when each other entry is done,
  except the relay's (T-250). Make no release before it: a release run
  takes CI from the work.
- Check it from end to end with no human (T-251): before the tag, on the
  gate's artifact of the last push and a local build; then tag `v1.0.0`
  once; then check the published files. A defect found after the tag goes
  into `v1.0.1`.
- Run the release workflow only in M9: once by hand before the tag, and once
  for the tag. An entry before M9 leaves its check of that workflow to the
  run by hand.
- [docs/development.md](docs/development.md) (section "Release builds")
  tells how to build and publish.

### The end

When the goal is reached, print a summary of the session (what was done,
the commits, the checks, the releases) and stop. The record is already
current.

## 3. Documents for each task

| Task | Read |
| --- | --- |
| Look up a command, flag, `-o` keyword, variable, file or exit code | `podssh man` (in the repository: `cargo run -q -p podssh-cli -- man --no-pager`) |
| Build, test, or run the gate | [docs/development.md](docs/development.md) |
| Measure podssh in a sandbox, or in a box like one | [docs/development.md](docs/development.md) (section "A box like the target sandbox"), [docs/target-environment.md](docs/target-environment.md) |
| Make a release | [docs/development.md](docs/development.md) (section "Release builds"), [docs/releases/](docs/releases/), T-250 and T-251 (`v1.0.0`) |
| Change the command line, `doctor`, `keygen` or the manual | [docs/cli.md](docs/cli.md) (section "The manual"), `crates/podssh-cli/src/flags.rs`, `crates/podssh-cli/src/man/` |
| Change the SSH client | [docs/cli.md](docs/cli.md), `crates/podssh-ssh/` |
| Change the terminal behaviour | [docs/terminal.md](docs/terminal.md) |
| Change the relay selection, tokens or failover | [docs/relay.md](docs/relay.md), `crates/podssh-relay/` |
| Change TLS, proxies or DNS | [docs/architecture.md](docs/architecture.md), `crates/podssh-ws/` |
| Work on reverse mode (milestone M4) | [docs/reverse.md](docs/reverse.md), [docs/design.md](docs/design.md) |
| Work on IRC | [docs/irc.md](docs/irc.md) |
| Work on Tailscale | [docs/tailscale.md](docs/tailscale.md) |
| Repair a known defect, or do any open work | [TODO/PROGRESS.md](TODO/PROGRESS.md) (the order), [TODO/INDEX.md](TODO/INDEX.md) (each entry) |
| File, close or reorder work; a GitHub issue | [TODO/RULES.md](TODO/RULES.md), [TODO/issues.md](TODO/issues.md), `cargo todo` (`crates/podssh-todo`) |
| Know where podssh goes, and why | [docs/design.md](docs/design.md) |
| Know the security model | [SECURITY.md](SECURITY.md) |

## 4. Safety

CAUTION: Builds can use all the memory of this machine. On 2026-10-07, three
builds at the same time almost stopped it.

1. Set `CARGO_BUILD_JOBS=4` before each cargo command.
2. Run one build at a time. Do not start a container build while another
   build runs. This holds for subagents too: at most one of them builds at a
   time.
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

WARNING: GitHub is public. Push only verified work to `main`. Publish the
releases that section 2 names, and comment on and close issues as
[TODO/RULES.md](TODO/RULES.md) says. Do not force-push, and do not delete a
tag or a release. Do not write a local user name, host name or path of the
operator's machine into a file of the repository.

Test targets that a session may use (the operator, 2026-10-08): the live
relay, railway.new, GitHub's SSH endpoint, the two tailnet hosts of
[docs/STATUS.md](docs/STATUS.md) (with `--direct`), the Podman box
(`scripts/test_in_box.sh`) and GitHub Actions. Use throwaway keys, and
delete them after the test. Keep keys and scratch files in `.work/`, which
git ignores, or outside the repository. Never print the claim URL of
railway.new.

## 5. Rules for the code

These rules come from [docs/decisions.md](docs/decisions.md).

1. Do not assume that the client host has a privilege, a tool or a setup.
   Probe it at runtime. Do not use a capability that was not probed.
2. Make one outbound connection, through `HTTPS_PROXY` when it is set. Do
   not bind, listen, or use loopback helpers. (`podssh doctor` binds a
   socket to test the host, and closes it without listening.) Two
   exceptions, by the decisions of 2026-10-08: a listener that the user asks
   for, when a probe at run time allows the bind; and a race between relay
   hosts, which can open a second connection for a short time.
3. Do not use `LD_PRELOAD` or shims in other processes. Start another
   program only when the user names it (`SSH_ASKPASS`, `PAGER`) or a probe
   found it (`less` for `podssh man` on a terminal). A tty in user space for
   a child of `podssh serve` is not a shim: podssh answers the child's tty
   system calls from its own process (decision of 2026-10-08, T-248).
4. Do not put C code in the library crates: `podssh-ws`, `podssh-relay`,
   `podssh-core`, `podssh-terminal` and `podssh-probe`.
   The binary links aws-lc for SSH (`russh`).
5. Keep each source file at 500 lines or fewer. Split a longer file. Do not
   remove comments to make a file shorter.
6. Write comments that tell why, in few words. Do not write `⛔`, session
   history, or document line numbers in the code.
7. Prefer redundancy and fallbacks to minimal code.
8. Repair a defect that you find in the same session. If you cannot, write
   an entry for it in `TODO/` ([TODO/RULES.md](TODO/RULES.md)).

## 6. Procedure for a change

1. Do one entry of `TODO/` at a time. Complete it until its Prove passes.
2. Test protocol code against software that podssh did not write: OpenSSH,
   Dropbear, a real IRC server, the live relay, or bytes captured from one.
3. Trust a new check only after it fails on a planted defect and passes on
   correct input.
4. Read each exit code directly, not through a pipe. Put a time limit on
   each network wait and on each process wait.
5. Before each commit, run `python scripts/check-repo.py`,
   `cargo todo check` and the tests.
6. In the same commit, record the result in
   [docs/STATUS.md](docs/STATUS.md) with the date and the command that
   measured it. Close the entry in place: write its `## Done`, then run
   `cargo todo set T-NNN done`, which also updates the counts.
7. Commit on `main`. Attribute the commit to the operator only. Do not add
   co-author lines.
8. Push only verified work. Do not rewrite published history. CI runs the
   gate on each push.
9. Do not change the line endings of a file that you do not otherwise
   change.
10. Do not change the files in `.tmp/`. They are read-only copies of other
    projects. Make sure that a copy exists before you use it.
11. When you edit a document or a file that entries of `TODO/` cite at a
    line, move those citations in the same change: `cargo todo remap FILE`
    ([TODO/RULES.md](TODO/RULES.md)).

## 7. Map

| Path | Contents |
| --- | --- |
| `crates/podssh-cli` | The `podssh` binary: arguments, help, the manual and its tables (`src/man/`), the pager, dispatch, `proxy`, `ssh` options, `doctor`, `keygen` |
| `crates/podssh-ssh` | The SSH client on `russh`: the relay stream, `known_hosts`, authentication, prompts, terminal, exit codes, key generation, the SFTP client (`sftp/`) |
| `crates/podssh-relay` | Relay hosts, the pool, failover, tokens, the forward opener; the pairs, the codecs and the runners of the reverse road; the blocking facade for podbox |
| `crates/podssh-ws` | TLS (podssh's own pure-Rust rustls provider), proxies, DNS fallbacks, the WebSocket client |
| `crates/podssh-core` | Sans-IO protocol code: `irc/` |
| `crates/podssh-terminal` | A line discipline (not used yet) |
| `crates/podssh-probe` | Facts about the relay document (tests only) |
| `crates/podssh-ts` | The Tailscale adapter (feature `ts`) |
| `crates/podssh-todo` | The checker of the work record: `cargo todo check` (the gate runs it), `cargo todo set`, `counts`, `next` |
| `vendor/tailscale-rs` | A fork with local patches (`vendor/patches/`). It is outside the workspace and the 500-line rule. |
| `scripts/dev.sh` (with `scripts/dev-wsl.sh`), `scripts/gate.sh` | Container runs, and the build gate that CI also runs |
| `scripts/interop*.sh`, `scripts/interop-pty.py`, `scripts/interop-conpty.py` | Tests against OpenSSH and Dropbear, faults, groff and mandoc (`interop-man.sh`), and terminals on Linux and Windows |
| `scripts/test_in_box.sh`, `scripts/box/`, `scripts/sandbox-check.sh` | The Podman box like the target sandbox, and the measurement for a sandbox |
| `scripts/check-*.py`, `scripts/plant.sh` | Repository checks, and the planted-defect check of the gate |
| `docs/` | The documents: STATUS, ROADMAP, decisions and topic pages |
| `TODO/` | The work record: the progress record with the work order, the index, the entries by area, the map of GitHub issues, the rules |
