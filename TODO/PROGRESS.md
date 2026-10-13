# Progress

The current state, the measured baseline, and the only work order. A closed
entry keeps its proof in the entry; this page keeps no history (git does).

## State

- **The record.** The work is in `TODO/` since 2026-10-08 (T-204). Each open
  item of `docs/ROADMAP.md`, each row of the former defects page, each
  GitHub issue and the two sandbox reports of 2026-10-08 is an entry or part
  of one. `TODO/issues.md` maps the GitHub issues. The writers of the
  entries read the code at each cited line, and found more defects; each is
  an entry (T-230 to T-248).
- **M3.** Done on 2026-10-09: measured in two real sandboxes (T-001), each
  defect that the sandbox runs found is repaired, and the interactive
  session runs in the box (T-004). There is one release only: `v1.0.0`, at
  the end (T-250).
- **GitHub.** 36 issues on 2026-10-08. #1, #4, #5 and #16 are closed by their
  commits (T-014, T-015, T-016, T-017). #15 is repaired in `eacd94e`,
  measured in the box, and closed (T-005). The feature requests #18 to #26 are
  split into entries. The requests #29 to #36 came later the same day; each
  is an entry (T-027, and T-220 to T-227). The operator ruled on the
  twelve questions of scope and design the same day (`docs/decisions.md`).
- **The mode of work.** Since 2026-10-08, each session runs unattended
  toward `v1.0.0` (`AGENTS.md`, section 2; `docs/decisions.md`). Since
  2026-10-09, an entry closes with the native tests; the runs in the build
  image and the planted defects wait for T-251 (`docs/decisions.md`).
- **The branch.** The record was added in `22c3b88` and `e275d36` on
  2026-10-08, and CI passed for both (runs 37777359030 and 37777669130).
- **The resumable layer (2026-10-09).** T-262 is repaired: the test of
  T-153 that cut a session at random points and failed in CI at `7797b2a`
  passes 20 runs in a row, with a test for each of its causes. T-154 is
  done in the same commit, and T-155 after it; their live tests of more
  than 5 minutes or 100 MiB wait for T-251. The operator settled Q31 to Q37 on 2026-10-09
  (`docs/decisions.md`). A copy of the tree before T-262 is at the local ref
  `refs/checkpoints/2026-10-09`, a backup only: never pushed, never merged.
- **M6 (2026-10-10).** Its exit is met on the loopback (T-156): a session
  survives a stopped relay host, a new address of its client and a stall of
  3 minutes, on the resumable layer and on the iroh road; the gate's step
  `m6` runs the checks at each push. T-263 is the last entry of M6.

- **Drafts (2026-10-13).** Since 2026-10-12 agents draft entries in local
  worktrees (`.claude/worktrees/`, excluded from git) on local branches
  `worktree-agent-*`, never pushed; they do not build. The main session
  merges a draft, builds it, runs its tests and plants, fills each
  UNVERIFIED and closes the entry (T-179 to T-184, T-200, T-202, T-221 and T-293 so). Waiting to
  be merged, in the order of the index:

  | Entry | Branch (`worktree-agent-` and) | Commit | State |
  | --- | --- | --- | --- |
  | T-225 | `a224e69d322ba513a` | `acda386` | drafted; `scripts/interop.sh` is at 499 lines in it; OpenSSH's codes in its table are read in OpenSSH's source, not run |
  | T-232, T-235, T-242 | `a1c2c734bcf87dace` | `b53a24f`, `ffeb741`, `b641ecb` | drafted |
  | T-279 | `a3f4d829458070a37` | `c7dd479` | drafted; its `bind(` in `agent_bind.rs`, `agent_forward.rs` and `handler.rs` fails the listener check of `scripts/check-repo.py` |
  | T-291 | `a3f4d829458070a37` | `c7dd479..8eb10ff` | drafted (the WIP `fb8c9bb` finished); `io/input.rs` meets main's file of T-183 |
  | T-280, T-281 | `a9e4d07db05c47c4f` | `91097a6`, `510cd29` | drafted; T-280 carries a patch of iroh-relay 1.3.0 in `vendor/` with `[patch.crates-io]`, as iroh lets no caller dial; T-281 is the fork's patch 0022; the lock must be made again |
  | T-289 | `a266ef3fe863b08d2` | `3224a88..9772dea` | drafted (the WIP `0c8ed9d` finished); `scripts/interop-baseline.txt` conflicts: keep both floors |
  | T-229 | `a266ef3fe863b08d2` | `9772dea..954d5ab` | drafted, on T-289; CTAP2 over hidraw on Linux, WebAuthn on Windows, a key in software for the tests; `sk_signature` uses ssh-key's published vectors (its Correction); the run with a real key waits for the operator; library code prints with `eprintln!` in `sshsig.rs` and `sk/agent.rs`, to review |
  | T-296, T-298 | `aa043fb59ecd7bdb2` | `57485b7`, `bc8a9ce` | drafted |
  | T-297 | `aa043fb59ecd7bdb2` | `bc8a9ce..429dd0b` | drafted, on T-298; it also copies the files of a tree of `cp -r` at once (its Decision) |
  | T-187, T-188 | `a56cc4d17c82784aa` | `a38421b..e206acd`, `e206acd..78fc010` | drafted (the WIP `0473ad2` finished); its harness of snippets is sourced by `scripts/interop-each.sh`; a declined snippet and no pick exit 64 |
  | T-306, T-302, T-305 | `afbe1f388cda562f1` | `bda737c`, `949623b`, `17b4e31` (one each, on `905f92c`) | drafted; T-302 adds a new entry (the notice on the forward road), with the counts by hand; new variables `PODSSH_SPARE_LINKS` and `PODSSH_TITLE_STACK`; spare links off in the library, on in the commands |
  | T-193, T-197, T-192 | `a3f5849c868ae85c1` | `24b9f6e..d95181c`, `d95181c..0e6f48c`, `0e6f48c..a36b0ef` | drafted; `podssh job` (tmux on the far host, probed) and `podssh run`; the far tests need tmux and `sftp-server`, else they say "did not run" and pass; T-192 must call T-195's `not_a_failure` when both are in; T-193's step 3 waits for `podssh serve` |
  | T-195, T-189 | `a75061d0db98a3897` | `e4bcd06..e0b09c2`, `e0b09c2..9d3a6e4` | drafted, on `e4bcd06`; T-195 is `PODSSH_ERROR_PROGRAM`, and a command that passes a remote status on (T-192's `run`) must call `not_a_failure`; T-189 is `podssh health`, its two fixtures of `/proc` written by hand (capture real ones in the build image); `tests/ssh_harness/mod.rs` reaches 500 lines |
  | T-190, T-191 | `aca311167dd1d2e52` | on `61e55d1` | being drafted |

  A row "being drafted" is an agent of a session that may have stopped:
  its branch's last commit says WIP or DRAFT. The next merge is T-225, then the others
  in the order of this table.

  Not drafted yet: T-185 and T-186. CI: the gate passed at
  `24b9f6e` (run 38331509229), and its step `release` at `cad2885` (478
  checks, the desktop's, `usbip` and `each` among them).

## Baseline

Measured on 2026-10-09 after T-060, on Windows 11 with native cargo 1.98.0
and `CARGO_BUILD_JOBS=4`:

- `cargo test --workspace --no-fail-fast`, again at `905f92c`
  (2026-10-13): 1887 passed, 1 failed, 54 ignored (the live tests, and the
  checks of faults and of the exit of M6). The failure was a test of T-042
  that depends on time; it is repaired, and passed 20 runs in a row. With the feature `iroh` and the test
  relay, `cargo test -p podssh-iroh -p podssh-cli --features
  podssh-cli/iroh-test`, with the same: 468 passed, 0 failed, 29 ignored.
  With the feature `ts`, `cargo test -p podssh-ts -p podssh-cli --features
  podssh-cli/ts`, after T-099: 520 passed, 0 failed, 25 ignored.
  CI's gate passed at `14f6cde` (run 38073235063); at `8cf2587` three steps
  failed on directories that a test left (run 38074648006), repaired in
  `c29fa82`.
- `cargo test -p podssh-relay --all-features --no-fail-fast`, after T-270:
  181 passed, 0 failed, 14 ignored (the live tests).
- `sh scripts/dev.sh check` (after T-212): green; interop 103 of 103. The steps that
  later changes touched, each alone in the build image after them: green.
- `cargo test -p podssh-todo` (2026-10-11): 77 passed: 15 unit tests, 37
  plant tests (35 planted disagreements and two controls), 15 tests of the
  remap, 2 of `--base`, 7 tests of the writer, and the test of this record.
- `cargo todo check`: the record agrees. `python scripts/check-repo.py`: ok.
- `cargo clippy -p podssh-todo --all-targets -- -D warnings`: no warning.

## Counts

`TODO/INDEX.md` holds 303 entries: 49 open, 0 partial, 25 blocked, 229 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit,
then take the next one. Each session runs unattended until the goal of
`AGENTS.md` (section 2) is reached or the operator interrupts it.

**After M3 and before M4 (the operator's ruling of 2026-10-08):**
the surface for agents: done.

**M4:** T-085 (the exit measurement) is on hold (Q32).

**Now:** the `backlog` entries, in the order of `TODO/INDEX.md` ("The
order, and the argument for it"): M3 to M8 are done, but for the entries on
hold and those of the relay's operator. The P2 entries are done, but for
those of M9 and the parked ones; now the P3 entries: first the drafts of
"State" above, merged one at a time, then the entries not drafted yet.

**Then** M9: T-218, T-210 and T-211, then T-251 (the check, and its run
before the tag), and last T-250 (the one release). Between entries: the
`none` entries, the highest priority first.

**Skip** the entries that wait for the relay's operator (status
`blocked`): T-086, T-106, T-169, T-173, T-180, T-226, T-253 and T-255;
and the entries that the operator holds (status `blocked`, Q32): T-085,
T-107 to T-113, T-117, T-118, T-213, T-222, T-245 and T-248; and the work
parked behind them (T-114, T-115, T-116, T-119, T-120, T-122, T-123,
T-124, T-150, T-159, T-160, T-161, T-303 and T-304, "Parked open work"),
which waits as they wait; and the entries that wait for an answer of the
operator: T-292 (Q41), T-062 (Q42) and T-299 (Q43), with T-300 and T-301
parked behind T-299.

## Parked open work

These entries stay open in the index. The condition in each entry tells when
it can start.

| Entry | Start condition |
| --- | --- |
| T-150 | T-112 is done: `podssh serve` has an SFTP server |
| T-114 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-115 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-116 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-119 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-120 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-122 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-123 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-124 | T-107 to T-112 are done: `podssh serve` exists (the operator holds them, Q32) |
| T-159 | T-107, T-108, T-110 and T-117 are done: `podssh serve` runs a shell on a pty, and stops its process group (the operator holds them, Q32) |
| T-160 | T-107 and T-110 are done: `podssh serve` runs a shell on a pty, which reports the input's offset and the ECHO flag (the operator holds them, Q32) |
| T-161 | T-159 is done: a far end keeps a shell, its ring and its pty after the client leaves |
| T-300 | T-299 is done: the edge's ports are measured, with the operator's leave (Q43) |
| T-301 | T-300 is done: the connector of a quick tunnel over HTTP/2 |
| T-303 | T-110 is done: `podssh serve` has a pty (the operator holds it, Q32); and T-161 has a model of the far end's screen |
| T-304 | T-303 is done: frames of the screen exist |
| T-250 | Each entry is done, except the relay's, and the gate is green |
| T-251 | Each entry is done, except the relay's; it runs before the tag of T-250 |

## Questions for the operator

The operator ruled on the questions of the triage (Q1 to Q12) and of the
unattended session (Q13 to Q28) on 2026-10-08; the rulings are in
`docs/decisions.md`. A new question goes here, with its number, the entries
that it blocks (status `blocked`) and a recommendation; the session then
takes the next entry. Nothing is closed as out of scope until the operator
rules.

The operator settled Q31 to Q37 on 2026-10-09.

The operator settled Q38 to Q40 on 2026-10-10 (`docs/decisions.md`): the
throughput run may reach n0's iroh relays with about 500 MiB a direction in
each cell, and the operator's SSH host (T-157, run in T-251); the IRC client
may be tested on undernet, libera and OFTC (T-091 to T-098, T-252); and a
session passes the files of `.env/` to podssh by their paths, never printing
them (T-100 to T-105, T-240, T-241).

Q41 (2026-10-12, blocks T-292): `podssh config import` reads an Ansible
inventory (T-047); each other format must be read from a real export of its
program, and none of those programs is here. Recommendation: send one
export of each (PuTTY, MobaXterm, Remmina, FinalShell, mRemoteNG, Termius),
each with a host that has a password; or allow a session to download PuTTY
and MobaXterm's portable build to make them.

Q42 (2026-10-12, blocks T-062): whether the relay's backpressure close
(1013) operates needs a target that sends much data fast through the
relay's forward path, read slowly. From this host no allowed target does:
railway.new refuses an anonymous visitor, GitHub's SSH endpoint sends its
banner only, and `PODSSH_THROUGHPUT_SSH` is not set here. Recommendation:
set `PODSSH_THROUGHPUT_SSH` and `PODSSH_THROUGHPUT_KEY` where a session
runs, and allow this measurement on that host (less than 64 MiB, and 5
minutes); or name another target.

Q43 (2026-10-12, blocks T-299; T-300 and T-301 wait for it): the research
of T-170 found that the connector of a quick tunnel reaches Cloudflare's
edge on port 7844, by QUIC or by HTTP/2 over TLS, and never through a proxy
(`docs/design.md`, section 2). To measure which ports and roads reach the
edge needs targets that `AGENTS.md` does not list: `api.trycloudflare.com`
(one quick tunnel at a time, a few minutes each) and the tunnel edge
(`region1.v2.argotunnel.com` and `region2.v2.argotunnel.com`, ports 7844
and 443); and a release of `cloudflared` as a reference, never a road. The
operator kept a tunnel that podssh makes as research (Q33). Cloudflare's
terms (section 7) forbid getting at its services by means that it did not
make available on purpose; whether a connector of podssh's own is such a
means is the operator's call. Recommendation: allow the targets and
cloudflared for T-299, with a throwaway origin and short runs, and decide
on T-300 with its result.

## Operator actions

None blocks a session. At any time: requiring the status `all` of the
workflow `build` for `main`, if the operator wants a required check (T-212);
`main` requires none today.

After the release:

- A run of T-004 and T-005 in a real sandbox, with the brief of
  `scripts/sandbox-check.sh`.
- Pinning the facade of `podssh-relay` in podbox (T-081, T-085).

As the relay's operator: a mailbox for pairing (T-086), the node keys of
the Tailscale test (T-106), a self-hosted relay (T-169), resumption in the
relay (T-173), a publish endpoint (T-180), signed pairing grants (T-226),
an IPv6 route out of the relay (T-253), and the cause of the drops of
reverse sockets (T-255).
