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

## Baseline

Measured on 2026-10-09 after T-060, on Windows 11 with native cargo 1.98.0
and `CARGO_BUILD_JOBS=4`:

- `cargo test --workspace --no-fail-fast`, again after T-102 (2026-10-10):
  1198 passed, 0 failed, 39 ignored (the live tests, and the checks of
  faults and of the exit of M6). With the feature `iroh` and the test
  relay, `cargo test -p podssh-iroh -p podssh-cli --features
  podssh-cli/iroh-test`, after T-175: 394 passed, 0 failed, 29 ignored.
  With the feature `ts`, `cargo test -p podssh-ts -p podssh-cli --features
  podssh-cli/ts`, after T-102: 467 passed, 0 failed, 25 ignored.
  CI's gate passed at `9460b4e` (T-271; run 38019504447).
- `cargo test -p podssh-relay --all-features --no-fail-fast`, after T-270:
  181 passed, 0 failed, 14 ignored (the live tests).
- `sh scripts/dev.sh check` (after T-212): green; interop 103 of 103. The steps that
  later changes touched, each alone in the build image after them: green.
- `cargo test -p podssh-todo`: 71 passed: 15 unit tests, 37 plant tests (35
  planted disagreements and two controls), 11 tests of the remap, 7 tests of
  the writer, and the test of this record.
- `cargo todo check`: the record agrees. `python scripts/check-repo.py`: ok.
- `cargo clippy -p podssh-todo --all-targets -- -D warnings`: no warning.

## Counts

`TODO/INDEX.md` holds 272 entries: 117 open, 0 partial, 22 blocked, 133 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit,
then take the next one. Each session runs unattended until the goal of
`AGENTS.md` (section 2) is reached or the operator interrupts it.

**After M3 and before M4 (the operator's ruling of 2026-10-08):**
the surface for agents: done.

**M4:** T-085 (the exit measurement) is on hold (Q32).

**Then** M5, M6, M7 and M8, each in the order of `TODO/INDEX.md` ("The
order, and the argument for it"); then each `backlog` entry, in the order
of the index; then M9: T-218, T-210 and T-211, then T-251 (the check, and
its run before the tag), and last T-250 (the one release). Between milestone
entries: the `none` entries of `TODO/repo.md`, the highest priority first.

**Skip** the entries that wait for the relay's operator (status
`blocked`): T-086, T-106, T-169, T-173, T-180, T-226, T-253 and T-255;
and the entries that the operator holds (status `blocked`, Q32): T-085,
T-107 to T-113, T-117, T-118, T-213, T-222, T-245 and T-248.

## Parked open work

These entries stay open in the index. The condition in each entry tells when
it can start.

| Entry | Start condition |
| --- | --- |
| T-150 | T-112 is done: `podssh serve` has an SFTP server |
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

**Q38 (2026-10-10, T-157, for its live run in T-251).** Which targets may
the throughput method reach? The test targets of `AGENTS.md` (section 4)
are the live relay, railway.new, GitHub's SSH endpoint, the two tailnet
hosts, the Podman box and GitHub Actions. T-157's cells also need (a) a
public SSH server that runs `head` and `cat` for the forward road and the
direct road, and (b) n0's public iroh relays, the iroh road's default
(2026-10-08). Recommendation: allow (b), the road's own default, for runs of
20 MiB each way, 5 runs a cell; for (a), a host of the operator's, named in
`PODSSH_THROUGHPUT_SSH` where the run is made, as the tailnet hosts are
named in `docs/STATUS.md`. Until the operator rules, the method runs those
cells only when their variable is set, and none of them is set in a
session: T-157 closes with its native tests, and its live run waits for
T-251 and this answer.

**Q39 (2026-10-10, T-091 to T-098, T-252).** May a session test the IRC
client on public networks? The Proves of T-091 to T-098 run
`examples/live_irc.rs` against undernet, libera and OFTC through the live
relay, and these are not among the test targets of `AGENTS.md` (section 4).
Recommendation: allow undernet, which accepted the relay on 2026-10-07, and
libera and OFTC to measure whether they still refuse it, each run short, with
a throwaway nick and no channel but a throwaway one. Until the operator
rules, each of those entries closes with its native tests and a run against
real servers on the loopback of the build image (ngircd, and others that
Alpine packages); their live runs wait for T-251 and this answer.

**Q40 (2026-10-10, T-100 to T-105, T-240, T-241).** Which file may a
session pass to `podssh ts --ts-auth-key-file` for the live runs of the
Tailscale entries? The key is in `.env/`, which `AGENTS.md` (section 4)
forbids a session to read or print, and no document names the file.
Recommendation: name the path in `docs/tailscale.md`, with the rule that a
session passes it to podssh and never reads it; podssh reads it into memory
that it clears (T-241). Until the operator rules, each of those entries
closes with its native tests, and its live run waits for T-251 and this
answer.

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
