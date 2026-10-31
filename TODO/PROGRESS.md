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

- **The session of 2026-10-30, in a Claude Code cloud container.** The
  operator allowed betas again (`docs/decisions.md`): `v1.0.0-beta.N`
  before `v1.0.0` (T-309). The container is ready by `scripts/cloud-setup.sh`,
  and `scripts/dev.sh` reaches the build image through its Docker or Podman
  (T-310). podssh works there through the agent proxy (T-311). The CI's job
  `deny` was red from 2026-10-15 (T-312), and the native tests met three
  causes of the test or of the place, none of podssh (T-313, T-314, T-315).
  `v1.0.0-beta.1` was published from that session (T-309): its git may not
  push a tag, so the release workflow publishes from a run by hand. GitHub
  #14, #21, #23 and #26 are closed. The gate's steps m6 and release were
  red from `472adff`, as T-318 sent the runs of the fault checks around
  their stand-in proxy, and the job secrets from `95ef7a3`, as TruffleHog
  took a placeholder for a credential; both are repaired (T-318's Done).
- **Drafts (2026-10-13).** Since 2026-10-12 agents draft entries in local
  worktrees (`.claude/worktrees/`, excluded from git) on local branches
  `worktree-agent-*`, never pushed; they do not build. The main session
  merges a draft, builds it, runs its tests and plants, fills each
  UNVERIFIED and closes the entry (T-179 to T-184, T-200, T-202, T-221, T-225, T-232, T-235, T-242, T-279, T-280, T-229, T-281, T-289, T-291, T-293, T-187 to T-191, T-195, T-296, T-297 and T-298 so, T-185, merged in
  `d1c5bd1` and measured on 2026-10-30, and T-186, T-193, T-197, T-192,
  T-306, T-302 and T-305, merged on 2026-10-30). No draft waits to be
  merged. The operator pushed each branch to GitHub as
  `draft/worktree-agent-*` on 2026-10-30; each draft of the four is in
  `main` now, so those branches and the worktrees on the operator's machine
  can go.

  CI: the gate passed at
  `24b9f6e` (run 38331509229), and its step `release` at `cad2885` (478
  checks, the desktop's, `usbip` and `each` among them). At `d0dbb59` (run
  41103062568) the step `release` failed on `job.queue.choose` of T-197,
  whose two servers share one user and so one queue; the check now has a
  user of its own on Dropbear (T-197's Done).

## Baseline

Measured on 2026-10-30 in a Claude Code cloud container (Linux x86_64,
Rust 1.99.0, `CARGO_BUILD_JOBS=4`), at `9b6dda2`: `cargo test --no-fail-fast`
2028 passed, 20 failed, 55 ignored, in 22 min 43 s, with groff stopped by
hand after 13 minutes (T-314). Each failure is of the test or of the place:
16 tests take the machine's proxy (T-313), and 4 live handshakes dial past it
into an egress that intercepts TLS (T-315). `cargo todo check` and
`python scripts/check-repo.py`: ok.

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

`TODO/INDEX.md` holds 333 entries: 17 open, 1 partial, 28 blocked, 287 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit,
then take the next one. Each session runs unattended until the goal of
`AGENTS.md` (section 2) is reached or the operator interrupts it.

**After M3 and before M4 (the operator's ruling of 2026-10-08):**
the surface for agents: done.

**M4:** T-085 (the exit measurement) is on hold (Q32).

**First (2026-10-31):** `v1.0.0-beta.2` is published, a prerelease at
`f7f97a5`, with the provenance of each binary and the signature of
`SHA256SUMS`, each proven on the published files (`docs/STATUS.md`). The next
beta follows the next batch of repairs that the testers should test again,
at most one a day.

**Now:** the `backlog` entries, in the order of `TODO/INDEX.md` ("The
order, and the argument for it"): M3 to M8 are done, but for the entries on
hold and those of the relay's operator. The P2 entries are done, but for
those of M9 and the parked ones; now the P3 entries that no draft holds:
the drafts of "State" above are merged.

**Then** M9: T-334, which T-251 runs, then T-251 (the check, and its run
before the tag), and last T-250 (the one release). Between
entries: the `none` entries, the highest priority first.

**Skip** the entries that wait for the relay's operator (status
`blocked`): T-086, T-106, T-169, T-173, T-180, T-226, T-253, T-255,
T-319, T-321, T-325, T-326, T-336 and T-346; and the entries that the operator holds (status
`blocked`, Q32):
T-085, T-107 to T-113, T-117, T-118, T-213, T-222, T-245 and T-248; and the work
parked behind them (T-114, T-115, T-116, T-119, T-120, T-122, T-123,
T-124, T-150, T-159, T-160, T-161, T-303 and T-304, "Parked open work"),
which waits as they wait; and the entries that wait for the operator:
T-328 (an export of FinalShell and of Termius: a known gap, which
`v1.0.0` does not wait for); and the entries that wait for the
operator's ruling on Q49 to Q52: T-346 (Q49, then the relay's operator),
T-348, T-349 and T-350 (Q50), T-351 (Q51), T-352 and T-353 (Q52).

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

The operator settled Q41 and Q43 on 2026-10-30, kept Q42 and the holds of
Q32, and allowed betas (`docs/decisions.md`): T-292 uses export files that
their programs wrote and that are published; T-299 runs in GitHub Actions.

The operator settled Q44 to Q47 on 2026-10-30 (`docs/decisions.md`): the
split HTTP road may open its second connection (T-319, which waits for the
relay's endpoints); the cleartext road on port 443 runs last, with a token
for one session (T-326, which waits for the relay's endpoint); mRemoteNG's
GPL test files may live beside their notice (T-327; FinalShell and Termius
moved to T-328, which waits for exports); and podssh builds its quick
tunnel (T-300).

The operator settled Q48 on 2026-10-31 (`docs/decisions.md`): podssh is a
client first, and no legacy constraint holds it back, so the library crates'
minimum Rust rises with their dependencies (T-333). The same day the operator
kept immutable releases off for `v1.0.0`, left T-328 as a known gap, and asked
for a study of local stand-ins for the live checks that need the operator's
hosts. After it, the operator settled Q42: the relay's own loop is T-062's
target, and the throughput run's forward cell goes through it at 100 MiB a
direction; and a headscale stand-in replaces the runs with the operator's
tailnet for `v1.0.0` (T-334).

Q49 (2026-10-31, blocks T-346): the audit of hardcoded assumptions of
2026-10-31 found that each road of the release binaries but `--direct`
reaches one relay deployment, on Cloudflare, under one domain: the default
host and the six seeds of the pool are names under `ssh.relay.ajam.dev`,
and a host of `/relays.json` outside that domain is dropped
(`crates/podssh-relay/src/pool.rs:82-95`). A binary copied into a cage is
not updated (Q48), so no binary in the field can move to another
deployment if the domain lapses or Cloudflare stops. The question: may a
binary take relay hosts outside `ssh.relay.ajam.dev` from a `/relays.json`
signed by a key compiled into it, and should the default be a list of
deployments on more than one provider? Recommendation: yes, with an
offline Ed25519 key that the relay's operator holds (two keys compiled in,
the current one and the next), the signature checked before any host of
the document is used, and an unsigned document kept to the parent domain,
as today. T-346 then waits for the relay's operator alone: the keys, the
signed document and a second deployment (`docs/relay-operator.md`, item
14).

Q50 (2026-10-31, blocks T-348, T-349 and T-350): the study of carriers of
2026-10-31 (`docs/carriers.md`) ranks two carriers of the reverse road that
need no relay of the operator's: iroh through n0's public relays first,
and DERP through Tailscale's relays for tailcat second. (a) The release
binaries have no iroh road: the release builds with no feature
(`.github/workflows/release.yml:113`), and the feature brings about 200
crates, and C outside the library crates as russh does
(`crates/podssh-cli/Cargo.toml:28-31`). The row of 2026-10-08 says that
iroh "is a road that the user must select" (`docs/decisions.md:41`), and
says nothing of the release binaries. (b) The same row makes n0's public
relays the default of the iroh road; n0 says that they are for
"development and hobby use only", and tailcat's README offers "our free
rate-limited DERP relays" to tailcat, which has no accounts; neither names
other clients. (c) Tailscale's post on tailcat asks for contact about
other uses, and n0 sells relays. The questions: (a) may the release
binaries carry the iroh road; (b) may a node and a client with no pair try
n0's relays and tailcat's fleet when the user did not ask for them (a
fallback of `podssh node` and `ssh node://`), or only when asked; (c) does
the operator ask Tailscale and n0 first? Recommendation: (a) yes, by Q48's
ruling that a capability comes first; (b) only when the user asks, until
their operators agree; (c) yes.

Q51 (2026-10-31, blocks T-351): after `-J cf://HOST` (T-347), the same
study ranks the tunnels of clouds for the forward road: GCP IAP's TCP
forwarding and AWS's EC2 Instance Connect Endpoint reach a VM of the
user's, which then reaches the target. Each needs the user's cloud
account, a VM or an instance, and a token in a file. IAP sends its token
in a Bearer header. EICE's URL is presigned with SigV4 for 60 s, and its
query carries an access key id and a signature: a credential in a URL,
against the rule that credentials never go in URLs
(`docs/architecture.md:145-147`; for the relay's tokens, "never in a URL",
`docs/decisions.md:36`). The question: may podssh have roads that need the
user's cloud account and a token file, and may EICE's URL carry its
credential? Recommendation: IAP yes, its token read from a file that the
user names (private, as the relay's token) and sent in a header only; EICE
no, while its credential rides in its URL.

Q52 (2026-10-31, blocks T-352 and T-353): two carriers of the forward road
need no setup of the user's. WARP is Cloudflare's own network: its open
clients speak a closed API that they reverse-engineered, and pose as
Cloudflare's app ("WARP for Android"), while Cloudflare's Application
Terms license "the Application" only, forbid to reverse engineer it, and
let Cloudflare "block certain kinds of usage"
(https://www.cloudflare.com/application/terms/, 2024-10-18); it also fails
behind a proxy that re-terminates TLS. Q47 read the quick tunnel's terms
as allowing a client other than cloudflared (`docs/decisions.md:15`); WARP
differs, as its client poses as Cloudflare's own. Tor through Arti is an
anonymous fallback, and slow: arti-client 0.47 brings C (its default
compression, SQLite), as the features `ts` and `iroh` bring C. The
questions: may podssh have a WARP road, and may a feature crate bring Tor
through Arti with its C? Recommendation: Tor yes, as a feature crate
`podssh-tor`, as `podssh-iroh` is one; WARP no, unless the operator reads
the terms otherwise.

A yes to Q50, Q51 or Q52 makes the entries that it unblocks work before
`v1.0.0` (T-250), unless the ruling says that they come after it.

## Operator actions

None blocks a session. At any time: requiring the status `all` of the
workflow `build` for `main`, if the operator wants a required check (T-212);
`main` requires none today.

Dependabot's updates reach `main` through a session (the operator,
2026-10-30, `docs/decisions.md`). Azathothas/podssh#53 (the group of 11
updates) fails the gate's step iroh (run 41075421658): the iroh road
through a SOCKS5 proxy in `ALL_PROXY` never comes online
(`crates/podssh-iroh/tests/proxy_env.rs`,
`a_socks5_proxy_in_all_proxy_reaches_the_relay_by_name`), where `main`
passes it; a session finds why, repairs it, and commits the updates.

After the release:

- A run of T-004 and T-005 in a real sandbox, with the brief of
  `scripts/sandbox-check.sh`.
- Pinning the facade of `podssh-relay` in podbox (T-081, T-085).

As the relay's operator: a mailbox for pairing (T-086), the node keys of
the Tailscale test (T-106), a self-hosted relay (T-169), resumption in the
relay (T-173), a publish endpoint (T-180), signed pairing grants (T-226),
an IPv6 route out of the relay (T-253), the cause of the drops of
reverse sockets (T-255), a bound on what the relay holds for a slow
client (T-336), and a signed `/relays.json` with a second deployment
(T-346, after the operator's ruling on Q49).
