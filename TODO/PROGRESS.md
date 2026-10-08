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
- **The beta (M3).** Measured in two real sandboxes on 2026-10-08 (T-001,
  done). The sandbox runs found defects in podssh and in the measurement
  script. The work order below does them before the tag (T-002).
- **GitHub.** 36 issues on 2026-10-08. #1, #4, #5 and #16 are closed by their
  commits (T-014, T-015, T-016, T-017). #15 is repaired in `eacd94e` and waits
  for a measurement in a sandbox (T-005). The feature requests #18 to #26 are
  split into entries. The requests #29 to #36 came later the same day; each
  is an entry (T-027, and T-220 to T-227). The operator ruled on the
  twelve questions of scope and design the same day (`docs/decisions.md`).
- **The branch.** `main` at `3ee70dc` was pushed on 2026-10-08, and CI passed
  (run 37759061384). The commit that adds this record comes after it.

## Baseline

Measured at the end of the session of 2026-10-08, on Windows 11 with native
cargo 1.98.0 and `CARGO_BUILD_JOBS=4`:

- `cargo test --no-fail-fast`: 707 passed, 0 failed, 5 ignored (the live
  tests).
- `cargo test -p podssh-todo`: 45 passed: 7 unit tests, 30 plant tests (29
  planted disagreements and the control), 7 tests of the writer, and the
  test of this record.
- `cargo todo check`: the record agrees. `python scripts/check-repo.py`: ok.
- `cargo clippy -p podssh-todo --all-targets -- -D warnings`: no warning.

## Counts

`TODO/INDEX.md` holds 247 entries: 236 open, 1 partial, 3 blocked, 7 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit,
then take the next one.

**M3, before the tag:**

1. T-006: make `scripts/sandbox-check.sh` report what it measured, so the
   next sandbox run is a record.
2. The P1 defects: T-007 (bracketed IPv6 literals, which `docs/cli.md`
   documents) and T-057 (a token can go to a relay host that did not mint
   it).
3. The small defects that a beta user meets first: T-008, T-009, T-010,
   T-011, T-023, T-024, T-230, T-231, T-233, T-234, T-236, T-237, T-238 and
   T-239.
4. T-003: the decision about the compiled-in roots.
5. One session in a real sandbox for T-005 and T-004 (see "Parked open
   work").
6. T-002: the release, with the operator's go.

**After the beta and before M4 (the operator's ruling of 2026-10-08):**
the surface for agents: T-049, T-050, T-012, T-052 and T-051.

**M4, in this order:** T-071, T-072, T-073, T-075, T-076 (the transport
defects that the reverse road uses); T-063, T-065, T-064; T-066, T-069,
T-068; T-078, T-079, T-080, T-081; T-083, T-084; T-082, T-074, T-077; T-061;
T-085 (the exit measurement).

**Then** M5, M6, M7 and M8, each in the order of `TODO/INDEX.md` ("The
order, and the argument for it"). Between milestone entries: the `none`
entries of `TODO/repo.md`, the highest priority first.

## Parked open work

These entries stay open in the index. The condition in each entry tells when
it can start.

| Entry | Start condition |
| --- | --- |
| T-002 | The operator's go for the tag, after the M3 entries above |
| T-004, T-005 | A session in a real sandbox, with a server account that grants a pty |
| T-085 | M3 is done, T-078 to T-084 are done, and the operator of podbox agrees to pin `podssh-relay` |
| T-086 | The relay's operator adds a mailbox endpoint, or the operator chooses the fallback of the entry |
| T-099 | The operator starts chat |
| T-106 | The operator adds the node keys to the relay's allowlist |
| T-150 | T-112 is done: `podssh serve` has an SFTP server |
| T-173 | M6 is done (T-156) |

## Questions for the operator

None is open. The operator ruled on the twelve questions of the triage (Q1
to Q12) on 2026-10-08; the rulings are in `docs/decisions.md`. A new question
goes here, with its number, the entries that it blocks (status `blocked`)
and a recommendation. Nothing is closed as out of scope until the operator
rules.

## Operator actions

- The tag of the beta (T-002).
- A session in a real sandbox for T-004 and T-005.
- The allowlist entries for the Tailscale test (T-106).
- Comments on the GitHub issues that name their entries, and the closure of
  #15 after T-005 (`TODO/issues.md`).
- As the relay's operator: a self-hosted relay (T-169), an endpoint that
  publishes a local HTTP service (T-180), and signed pairing grants that are
  used once (T-226). These entries wait for the relay project.
