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
  toward `v1.0.0` (`AGENTS.md`, section 2; `docs/decisions.md`).
- **The branch.** The record was added in `22c3b88` and `e275d36` on
  2026-10-08, and CI passed for both (runs 37777359030 and 37777669130).

## Baseline

Measured on 2026-10-09 after T-084, on Windows 11 with native cargo 1.98.0
and `CARGO_BUILD_JOBS=4`:

- `cargo test --no-fail-fast`: 850 passed, 0 failed, 12 ignored (the live
  tests).
- `sh scripts/dev.sh check` (after T-051): green; interop 103 of 103.
- `cargo test -p podssh-todo`: 65 passed: 12 unit tests, 34 plant tests (33
  planted disagreements and the control), 11 tests of the remap, 7 tests of
  the writer, and the test of this record.
- `cargo todo check`: the record agrees. `python scripts/check-repo.py`: ok.
- `cargo clippy -p podssh-todo --all-targets -- -D warnings`: no warning.

## Counts

`TODO/INDEX.md` holds 251 entries: 193 open, 0 partial, 7 blocked, 51 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit,
then take the next one. Each session runs unattended until the goal of
`AGENTS.md` (section 2) is reached or the operator interrupts it.

**After M3 and before M4 (the operator's ruling of 2026-10-08):**
the surface for agents: done.

**M4, in this order:** T-082, T-074, T-077; T-061; T-085 (the exit measurement).

**Then** M5, M6, M7 and M8, each in the order of `TODO/INDEX.md` ("The
order, and the argument for it"); then each `backlog` entry, in the order
of the index; then M9: T-218, T-210 and T-211, then T-251 (the check, and
its run before the tag), and last T-250 (the one release). Between milestone
entries: the `none` entries of `TODO/repo.md`, the highest priority first.

**Skip** the entries that wait for the relay's operator (status
`blocked`): T-086, T-106, T-169, T-173, T-180, T-226 and T-253.

## Parked open work

These entries stay open in the index. The condition in each entry tells when
it can start.

| Entry | Start condition |
| --- | --- |
| T-085 | M3 is done, and T-078 to T-084 are done |
| T-150 | T-112 is done: `podssh serve` has an SFTP server |
| T-250 | Each entry is done, except the relay's, and the gate is green |
| T-251 | Each entry is done, except the relay's; it runs before the tag of T-250 |

## Questions for the operator

None is open. The operator ruled on the questions of the triage (Q1 to Q12)
and of the unattended session (Q13 to Q28) on 2026-10-08; the rulings are in
`docs/decisions.md`. A new question goes here, with its number, the entries
that it blocks (status `blocked`) and a recommendation; the session then
takes the next entry. Nothing is closed as out of scope until the operator
rules.

## Operator actions

None blocks a session. After the release:

- A run of T-004 and T-005 in a real sandbox, with the brief of
  `scripts/sandbox-check.sh`.
- Pinning the facade of `podssh-relay` in podbox (T-081, T-085).

As the relay's operator: a mailbox for pairing (T-086), the node keys of
the Tailscale test (T-106), a self-hosted relay (T-169), resumption in the
relay (T-173), a publish endpoint (T-180), signed pairing grants (T-226),
and an IPv6 route out of the relay (T-253).
