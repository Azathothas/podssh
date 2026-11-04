# Progress

The current state, the measured baseline, and the only work order. A closed
entry keeps its proof in the entry; this page keeps no history (git does).

## State

- **Checkpoint, 2026-11-04, about 14:00 UTC: a new cloud session, after the operator's rulings.**
  1. **The gate at `909e4f5`** failed on two causes of the place, none of podssh: macOS could not
     resolve `static.crates.io` (its job is run again), and TruffleHog could not verify five test
     keys of russh on the branch `draft/worktree-agent-t460-ssh` and read them "unknown"
     (`.github/secrets-allow.txt` now lists each test key of that copy and of ssh-key's).
  2. **`v1.1.0-beta.2`** goes out now (Q98) from the newest green commit of `main`: move
     `beta/v1.1.0-beta.2` to it by a fast-forward (no force); run `release.yml` by hand on that
     branch; run `scripts/release-short.sh BINARY --net` on its x86_64 binary; publish with
     `release.yml` and `publish=v1.1.0-beta.2`; then `release-proofs.yml` and `update-live.yml`; then
     mark each `unreleased` row of `docs/STATUS.md` up to that commit, and add the commit to the
     list of releases in `scripts/check-repo.py`, as beta.1's record did (`15819f9`).
     `v1.1.0-beta.3` follows at the end of the night with the night's work (Q98).
  3. **GitHub #126 to #148** (Nemo-010, 2026-11-04) are new: each becomes an entry (Q100), #126
     first, a P1 defect; `TODO/github.txt` and `TODO/issues.md` map them with the triage.
  4. **osewa** (Q99): two agents study `rjyo/osewa`'s code and its paper; the gaps become entries
     ahead of the rest of M10, and the report goes to `docs/research/`.
  5. **Partial and watched:** T-465 (`pipe`'s end of input lost 2 runs in 50 on Windows and
     macOS; the probe of Windows' AF_UNIX lost none of 600, so the next step is a client in another
     process than its server, or a failure that says the time of each step); T-627 (a test of
     T-615 timed out once in the relay crate's suite; it says the role's events at its limit); T-319,
     T-321 and T-253 (their parts that wait for a runner, Q88).
  6. **The work order** (below): the testers' defects (#126 first), then osewa's entries, then
     item 2, T-106; item 3, T-433, T-180, T-434 and T-459 (a WIP branch, `draft/wip-459`
     (`b5f9a50`), untested).

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
  T-306, T-302 and T-305, merged on 2026-10-30; T-344, T-349, T-351, T-367, T-368 and T-350, merged on
  2026-10-31, and T-352 and T-374, merged and closed on 2026-10-31, and T-379, T-363, T-369 and T-370 on 2026-11-01). The operator pushed each branch to GitHub as
  `draft/worktree-agent-*` on 2026-10-30; each draft of the four is in
  `main` now, so those branches and the worktrees on the operator's machine
  can go, as can `draft/draft-dns` and `draft/draft-derp` (merged on
  2026-10-31), and `draft/draft-cloud`, `draft/draft-pipe`, `draft/draft-pkarr`,
  `draft/draft-warp`, `draft/draft-roads-cli` and `draft/draft-forwarder`, which this
  cloud session's git proxy would not delete.

  T-373's (`1be3e28`), T-334's (`4bddbb5`) and T-385's (`450654d`), drafted by
  agents of this cloud session, are merged, and their worktrees and branches
  are gone. T-251's planted defects, four drafts of agents (ssh, faults and
  multi; copy, pipe and cli; resume and roads; the box), joined on the
  branch `draft/t251-plants` (`e622607`), then carried onto `main` at
  `da543fd` as `draft/t251-plants-2`, and the release check of an agent
  (`draft/t251-release-check`, `54d172c`), are merged on 2026-11-01, after
  `plants.yml` and `box.yml` passed on that branch at `bb46515`; those three
  branches can go, as this session's git proxy would not delete them.

  On 2026-11-02, `draft-m10-corrections` (the Corrections of the 15 entries that waited for the
  relay's operator, after Q63, with `docs/relay-operator.md` and `docs/carriers.md`, Q64 and
  Q65), drafted by an agent of this cloud session, is merged, and its worktree and branch are
  gone. The same day, the drafts of agents of this session for T-443 and T-444 are merged (their
  node window test found a defect of the stand-in's new mode, repaired); T-439's is merged and closed
  (`via-interop.yml` passed against Caddy and squid), and T-436's is merged and closed (its
  live runs through Least Authority's relay passed; three first runs that met nobody are T-450);
  T-437's is merged and closed (its
  two servers, its live run through ppng.io; nwtgck's server answers a sender only once a byte
  came, so the mark now goes with the POST's head; the command-level run is T-451); T-438's is merged
  and closed (against wisp-server-python, and live through the demo server); T-429's is merged and
  closed. T-427's and T-448's are merged and closed. T-440's is merged and closed (three compile
  repairs; its XHTTP stand-in made the session for either request first, as Xray-core does; its
  interop's first run found that Xray-core blackholes a private target unless a final rule allows
  it, then 15 of 15). T-441's is merged onto it and closed (each list of roads took both, and
  `--vless` and `--wstunnel` refuse each other; 12 of 12 against wstunnel's own server). T-430's is merged and closed (the synopsis of `podssh
  net` was wider than the page). T-428's is merged and closed (live through Cloudflare's edge, run
  41440851652), T-447's is merged and closed (8 of 8 against Pebble), and T-454's is merged and
  closed (the merge gave the role behind a quick tunnel the visitor that the edge names, so that
  each visitor counts apart). `draft/worktree-agent-t430-net-policy`,
  `draft/worktree-agent-t428-quick-relay`, `-t447-acme` and `-t454-brake` can go. T-431, T-445 and T-452 are merged and closed, and
  `draft/worktree-agent-t431-exit` can go. These branches can go, as this
  session's git proxy would not delete them: `draft/worktree-agent-t429-net`,
  `draft/worktree-agent-t440-vless`, `draft/worktree-agent-t441-wstunnel`, `draft/draft-t427-t448`,
  and the merges' `draft/m10-merge-427`, `-429`, `-437`, `-438`, `-439`, `-440`, `-443-444` and
  `-448`.

  On 2026-11-02 an agent drafted the testers' defects of SSH, unbuilt, one commit each, on the
  local branch `worktree-agent-a7cc3c512bf98ec67`: T-460 to T-464 (T-463 a feature, by Q85), each
  merged and closed the same day. The branch and its worktree can go, and so can
  `worktree-agent-t460-ssh` (`818f7fe`) and `draft/worktree-agent-t460-ssh`.

  On 2026-11-03 the drafts of the testers' features, by agents of this cloud session, are merged
  and closed, one at a time: T-561 (`c5299c2`) and T-562 (`cde307f`) of WARP, with the live run
  41597035711; T-564 (`5b643b1`); T-489 (`ea2a70b`, live through the relay); T-483 (`7417676`); and
  T-488 (`f8eaeb4`). Their worktrees and local branches are gone; `draft/worktree-agent-af45a8be5552d1bf0`,
  `draft/worktree-agent-aad1db2c11baba50c` and `draft/worktree-agent-a3b8eb20dc7bccfa9` can go, as
  this session's git proxy would not delete them.

  On 2026-11-03 the third round of drafts is merged and closed, one at a time: T-475 (`535893e`),
  T-484 and T-486, OpenTunnel's road T-530 and T-531 (live run 41679059624), T-592 (`5c14126`) and
  T-596. Their worktrees and local branches are gone; their `draft/` branches on GitHub can go.
  The research of the operator's relay archive followed (`09f0c0d`): its four entries, with T-605
  partial, and `docs/research/relay-measurement.md`; `draft/relay-measure` can go.

  On 2026-11-03 a fourth round was drafted, unbuilt, one commit for each entry: T-614
  (`worktree-agent-afe7db2e2c9eeb0a3`, merged and closed, `e0a2496`); T-612 and T-613
  (`worktree-agent-ac366026bd4dfc2dc`, `6b76515` and `741e842`); T-455 and T-457
  (`worktree-agent-a78b0fb3db0c3f0c8`, `2454434` and `ac38d51`). Each is merged and closed, in that
  order (`5f0165b`, `a29abfc`, `3c30ce2` and T-457's), and their worktrees are gone; their
  `draft/` branches on GitHub can go.

  On 2026-11-03 a fifth round was drafted, unbuilt, one commit for each entry, each branch pushed
  as `draft/worktree-agent-*`: T-226 (`worktree-agent-ab46b7435cc875cd9`, `d4da618`, merged and closed); T-253
  (`worktree-agent-a6a21bc1a5b921742`, `330e6ed`, merged as partial on `draft/merge-253`,
  `5d0db76`, its tests of IPv6 on a runner); T-255 (`worktree-agent-ab9d837b93edc90b0`,
  `8f09eb3`, merged and closed); T-325 (`worktree-agent-ab532bbdaa9b8fe7b`, `fbda4ad`, merged and closed); T-608
  (`worktree-agent-ab7069457e3f92567`, `be90ae1`, merged and closed, `6060558`). Each is merged in
  that order, T-253 as partial on `main` (`5d0db76`); their worktrees and local branches are gone,
  and their `draft/` branches on GitHub, with `draft/merge-253`, can go.

  On 2026-11-04 a sixth round was drafted, unbuilt, one commit for each entry, each branch pushed as
  `draft/worktree-agent-*` (the agents stopped at a limit of use at 00:50 UTC and were resumed):
  T-326 (`worktree-agent-a8b2a4b9acf9c2a8f`, `27a97cf`, merged and closed); T-319
  (`worktree-agent-a39b6bc24832c974f`, `3739bcf`, a first part, merged, the entry partial); T-173
  (`worktree-agent-a935f48070b310b7c`, `6165bbc`, a first part, merged, the entry partial); T-551
  (`worktree-agent-a5583c3e8856c1e14`, `b4568a4`, merged and closed); T-086 (`worktree-agent-aae965649ba432a53`,
  `7a0c97f`, merged and closed). Each is merged in that order; their worktrees and local branches
  are gone, and their `draft/` branches on GitHub can go.

  On 2026-11-04 a seventh round was drafted, unbuilt, one commit for each entry, each branch pushed
  as `draft/worktree-agent-*`: T-616 (`worktree-agent-af68081e13f6b11f8`, `81bc6f2`, merged and
  closed); T-346 (`worktree-agent-a6730d81d38c2e802`, `363fcc1`, merged and closed); T-173's next part
  (`worktree-agent-ac6a1db72f01e3003`, `71dbd72`, merged, the entry partial for its live run and the road by
  default); T-321 (`worktree-agent-afc21daca5ecea253`,
  `4d7c7d0`, merged, the entry partial for Apache httpd's server, `each` over 8 hosts and the live run); T-615 (`worktree-agent-a3c0e12c59fd9dc1e`, `fe2bbaf`, after a stop at a limit of
  use, resumed; merged and closed). Each is merged; their worktrees and local branches are gone, and
  their `draft/` branches on GitHub can go.

  On 2026-11-04 an eighth round was drafted, unbuilt, one commit for each entry, each branch pushed
  as `draft/worktree-agent-*`: T-435 (`093970b`, merged and closed, `57faf83`); T-617 (`1cbdc10`,
  merged and closed, `00ba332`); T-618 and T-619 (`worktree-agent-a813dd96e40d4756b`, `9d04d4d` and
  `66eb08b`, merged and closed, `b750af3`; the live relay's document read once for T-619); T-620
  (`worktree-agent-a866bb2e35c2100ff`, `cc54c09`, merged and closed after `b750af3`). Their worktrees
  and local branches are gone, and their `draft/` branches on GitHub can go.

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

`TODO/INDEX.md` holds 592 entries: 91 open, 5 partial, 2 blocked, 494 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit,
then take the next one. Each session runs unattended until the goal of
`AGENTS.md` (section 2) is reached or the operator interrupts it.

**After M3 and before M4 (the operator's ruling of 2026-10-08):**
the surface for agents: done.

**M4:** T-085 (the exit measurement) is on hold (Q32).

**First (2026-11-02):** `v1.0.0-beta.4` is published, a prerelease at `4e79a1f` (01:59 UTC),
its files proven by `release-proofs.yml` (run 41375376913) and `update-live.yml` (run
41375379843); `v1.0.0` is tagged from `35a0d19` the same night, and the check of its published
files passed on 2026-11-03 (43 passed, 6 skipped).

**The operator's request of 2026-11-01:** `--detach` is in, `session start` asks its prompts on
the terminal, and both are measured on Windows and macOS in Actions (2026-11-01); since Q61 a
detached run leaves a login session's scope of systemd for one of its own.

**Now (2026-11-01):** the operator's request of 2026-11-01, two studies: of Nemo-010/d-mon, a
daemonizer, for a `--detach` that must never leave a server locked out, and of Azathothas/cfrs, its
code and its issues. Each of their findings is done (a line that fails to write no longer aborts a
detached node, `--persist-forever` never gives up, `--restart` starts a detached run again, a node
goes on with the next pair at its pair's expiry, a lock names each detached run, a hung run is
started again, the smaller gaps of `--detach` are closed; the quick tunnel races its roads, drains
a connection on the edge's GOAWAY, keeps its window in small frames and answers a push of
configuration over QUIC, and keeps two connections to the edge since Q62). Before them, a bulk session through a node and its moves on
the live relay are repaired, and the entries of the audit, the study and the issues
of 2026-10-31 (GitHub #59 to #63 and #69 to #76), each done. Each other `backlog` entry is done, but for those on hold, those of the relay's
operator and the parked ones.

**First tonight (2026-11-04, Q98 to Q100):** `v1.1.0-beta.2`; then GitHub #126, the testers' P1
defect; then the entries that the studies of osewa file (Q99); then GitHub #127 to #148 by their
priority, beside the order of M10 below (Q85, Q100); `v1.1.0-beta.3` at the end of the night.

**Next (2026-11-02): M10**, the mesh and the relay in podssh (Q63 to Q66, `docs/mesh.md`), in
this order:

0. A test that fails at random comes first: the relay suite's, named and repaired (done, 50 runs
   in a row here and on a runner).
1. The relay role (its certificate from ACME, its brake of mint and pair, the role behind a node's quick tunnel, the net's members' mint, the role's dial through `HTTPS_PROXY`, its bound on a slow reader's bytes and its planned stop are done): what the role serves:
   T-319 and T-321 (the resumable layer for a standard sshd, by default where the first host offers it, is done); `doctor`'s measure of a stream's path, the role's IPv6 targets,
   with `doctor`'s line of them, a client's lost link during a node's bulk, and the cleartext road
   on the relay's port are done.
2. The net (its policy, the record of each road, the DERP node of a member, the copies by a name, the quick tunnel's node with the net as its door, the grants used once, a copy's race of the roads, the pairing by a short code, a device's join by one, the signed list of deployments and the
   tokens of one leg, the hosts of the relay members, and the rotation at a node's next pair, are
   done): T-106.
3. Exit, routes, share and funnel (the exit, `doctor --exit` and the net's routes are done): T-433,
   T-180, then T-434 and T-459 (the status of the net, `ping` of a node and doctor's sections are done).
4. The public carriers of Q65 (T-451, then T-450 from the runs of `transit-live.yml`; the
   protocols of Q66 are done), XHTTP over HTTP/1.1 (T-456, Q67), then what the research of more services (done) filed: the protocols of
   servers that a user runs (T-490 and T-493, then T-491, T-492, T-494 and T-498), upterm's door
   (T-495) and a second Piping Server (T-497), T-496 and T-499 parked; then what the triage of the sweep of public relays
   (2026-11-02) filed, as Q74 to Q79 rule: OpenTunnel's road (Q76; done 2026-11-03),
   and the manual's word on the public services that podssh uses and the ones it never names
   (done 2026-11-03); T-532 is parked; then what the rulings Q74, Q75, Q77, Q78 and Q82 filed (2026-11-02),
   the P2 ones first: Tailscale's main DERP fleet after tailcat's (T-534), the public Wisp servers
   made for it (T-535), Pinggy (T-548) and the public proxy nodes (T-574); then the research of the
   overlay networks (T-536 to T-544), of the trackers (T-546) and of the pub/sub networks (T-547),
   and Nostr's meeting point (T-545, parked); the other last fallbacks of Q78 (T-549, T-565 to
   T-573 and T-575 to T-579; T-566, T-567 and T-575 parked); and the roads over UDP (T-580, T-581,
   T-582). These are features of a tester's report and of the sweep, done after the defects (Q85).
   Then what the archive of forward carriers (2026-11-04, `docs/research/forward-carriers.md`)
   filed: the rates of `ppng.io`'s road and of the Wisp demo server through podssh (T-625), TURN
   with RFC 6062 for a server that the user runs (T-621), the research of smee.io (T-623), of three
   hosted tunnels (T-624) and of I2P, Nym and cjdns (T-626), and the HTTP road's one-POST form
   (T-622, parked).
5. T-446: betas `v1.1.0-beta.N` after batches, and `v1.1.0` at the end.

Between entries: the `none` entries, the highest priority first, but for the testers' entries.

**The testers' defects go first, then their features** (Q84, Q85, the operator, 2026-11-02). The
defects of the issues of the testers of `v1.0.0` (GitHub #83 to #111) and of the testers' bundle
and relay sweep of 2026-11-02 come first among the `none` entries, the P1 ones before any other
(T-465, a test that failed once, 100 runs in a row passed since), each other one done and
merged; `v1.0.1` went out with them on 2026-11-03. The defects of GitHub #112 to #124 (triaged
on 2026-11-03) are done and go into `v1.1.0-beta.1`. Until podssh is stable the expensive checks wait (Q88). Their
features and documents (T-532,
and T-534 to T-549 and T-565 to T-582, which Q74, Q75, Q77, Q78
and Q82 filed; the features of #112 to #124 are done) follow, by priority, beside M10 (Q85); Dependabot's #119,
#120 and #122 are in `main` (2026-11-03), and #123 waits for an iroh-dns that takes simple-dns 0.13. Overnight a fork of
policy is decided and listed below for the operator to confirm (Q86). The drafts of 2026-11-03, both rounds, are merged. GitHub #125 (2026-11-03, `relay info`'s rank changes with the edge that answered) is done: the line says whose order it is; the research of the operator's relay archive is merged (2026-11-03). The operator's export of #125 (2026-11-04; GitHub has since deleted it) left two parts, both done: `relay info` names `relay rank` and the order that a run takes, and the remedy on the relay's side is an item of `docs/relay-operator.md`.

**The operator's request of 2026-11-03:** an archive of research on relays, read in
`docs/research/relay-measurement.md`: its harness, adapted to run podssh itself, is done
(2026-11-03, `scripts/relay-measure.py` and `relay-measure.yml`), and so is the rank of the relay
hosts on demand (`podssh relay rank`, 2026-11-03), and so is the default list's use of it, with
the samples of each race (2026-11-03), and so is a rank that podssh makes unasked, with
`RelayRank auto` alone (Q89, 2026-11-03).

**The holds are released** (Q92, the operator, 2026-11-03): T-085, T-107 to T-113, T-117,
T-118, T-213, T-222, T-245 and T-248 are open and go by their priority, M5's `podssh serve`
among them, after M10's entries of their priority; the work parked behind them ("Parked open
work") starts as its condition says. T-328 (a real export of FinalShell and of Termius) and
T-376 (the operator's throwaway cloud accounts for the live run of the roads of iap:// and
eice://) are no longer held, but still wait for those inputs, which only the operator has.

## Parked open work

These entries stay open in the index. The condition in each entry tells when
it can start.

| Entry | Start condition |
| --- | --- |
| T-150 | T-112 is done: `podssh serve` has an SFTP server |
| T-114 | T-107 to T-112 are done: `podssh serve` exists |
| T-115 | T-107 to T-112 are done: `podssh serve` exists |
| T-116 | T-107 to T-112 are done: `podssh serve` exists |
| T-119 | T-107 to T-112 are done: `podssh serve` exists |
| T-120 | T-107 to T-112 are done: `podssh serve` exists |
| T-122 | T-107 to T-112 are done: `podssh serve` exists |
| T-123 | T-107 to T-112 are done: `podssh serve` exists |
| T-124 | T-107 to T-112 are done: `podssh serve` exists |
| T-159 | T-107, T-108, T-110 and T-117 are done: `podssh serve` runs a shell on a pty, and stops its process group |
| T-160 | T-107 and T-110 are done: `podssh serve` runs a shell on a pty, which reports the input's offset and the ECHO flag |
| T-161 | T-159 is done: a far end keeps a shell, its ring and its pty after the client leaves |
| T-303 | T-110 is done: `podssh serve` has a pty; and T-161 has a model of the far end's screen |
| T-304 | T-303 is done: frames of the screen exist |
| T-532 | T-180 and T-530 are done: `podssh funnel` and OpenTunnel's link exist |
| T-496 | T-086 is done: the pairing's exchange exists over a mailbox |
| T-499 | draft-ietf-httpbis-connect-tcp is an RFC, and a server over HTTP/2 or HTTP/1.1 implements it |
| T-545 | T-086 is done: the pairing's exchange exists over a mailbox |
| T-566 | T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists |
| T-567 | T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists |
| T-575 | T-497 is done: the road has public servers in order |
| T-622 | T-319 is done: the HTTP road's split and serial forms exist |
| T-250 | Each entry is done, except the relay's, and the gate is green |
| T-251 | Each entry is done, except the relay's; it runs before the tag of T-250 |

## Questions for the operator

The operator ruled on the questions of the triage (Q1 to Q12) and of the
unattended session (Q13 to Q28) on 2026-10-08; the rulings are in
`docs/decisions.md`. A new question goes here, with its number, the entries
that it blocks (status `blocked`) and a recommendation; the session then
takes the next entry. Nothing is closed as out of scope until the operator
rules.

The operator settled Q89 to Q92 on 2026-11-03 (`docs/decisions.md`), each asked on its own: podssh
ranks relay hosts unasked only with `RelayRank auto` (Q89); the calls of Q86 stand but four
(Q90: T-574's built-in nodes, T-612, T-613 and T-614); four more live test targets (Q91: T-463,
T-548, T-578, T-531's weekly run); and the holds end (Q92), T-328 and T-376 waiting for their
inputs alone.

The operator settled Q93 to Q100 on 2026-11-04 (`docs/decisions.md`), each as recommended: the TURN
road's second connection (Q93), short live tests against smee.io, hostc, Tunnelmole and Sandhole
(Q94), TURN and the one-POST HTTP form outside `--forwarder` (Q95), and the two reads before a
session (Q96, Q97) are confirmed; `v1.1.0-beta.2` goes out at once and `v1.1.0-beta.3` at the end
of the night (Q98); the gaps that the studies of osewa find become entries ahead of the rest of
M10 (Q99); and GitHub #126 to #148 become entries, #126 first as a P1 defect (Q100).

The operator settled Q67 to Q84 on 2026-11-02 (`docs/decisions.md`), after the triage of the
testers' reports (GitHub #83 to #106, the bundle, the relay sweep) and of the drafts of M10:
XHTTP over HTTP/1.1 may open its second connection (Q67, T-456); the login name comes from
`PODSSH_USER`, the three variables, then the user database (Q68, T-500); the fallback to other
products' forwarders follows only a failure where no relay host answered about the target (Q69,
T-509); a file's `ProxyCommand` for each host stays refused with 78 (Q70, T-502); the keywords of
a restriction apply (Q71, T-505); `scp` and `sftp` take `--timeout` (Q72, T-508); `doctor` runs
its sections at once, with a flag that limits it (Q73, T-511); Tailscale's main DERP fleet after
tailcat's (Q74), the public Wisp servers made for it (Q75) and OpenTunnel (Q76) are tried as
fallbacks; podssh uses the fallbacks that exist, overlay networks and meeting points among them
(Q77), each service as a last fallback whatever its terms (Q78), and the repository names only
the hosts that podssh uses (Q79); the operator passes cfrs's defect on (Q80); a node with no iroh
road keeps its pkarr record at n0's server (Q81); roads over UDP where UDP passes (Q82); the
experience of an agent and of a human comes first, and the triages' calls stay (Q83); the
testers' defects go now (Q84). Later the same day: their features go too (Q85), a fork of policy
is decided overnight and listed for confirmation (Q86), and `v1.0.1` and the next beta go out
unattended (Q87).

**Ruled (Q90, the operator, 2026-11-03, each call asked on its own; `docs/decisions.md`):** the
calls below, made overnight under Q86, stand, but four that changed: T-574 ships a short list of
nodes re-checked before each release; T-586 gets `--no-resume` (T-612); T-589's commands take
`--timeout` as another name of `--ConnectTimeout` (T-613); and `ssh`, `proxy` and `pipe` take
`--exit` beside `--carrier` (T-614, after T-596). T-548, T-578 and T-463's live runs are
allowed (Q91), and Q89 is ruled: podssh ranks unasked only with `RelayRank auto`. The list, as
it was asked:

- T-548: short live tests against the services of Q77 and Q78 (Pinggy and the others), one
  Decision for all of them; if confirmed, `AGENTS.md`'s list of test targets names them.
- T-574: the binary names the public lists of proxy nodes but never a node, and skips a node that
  fronts another party's name or sits under a school's, a church's or a government's suffix.
- T-578: one short live run of an onion service on the public Tor network, more than Q60's one
  bootstrap and one stream.
- T-563 (done): a strike is only a session that the host's side cut (a lost link, the relay's
  Close of its link), so that two short sessions of a client do not rest a healthy host; a host
  that opened lately goes first with no note.
- T-560 (partial): a reset inside the tunnel is an answer, as a SYN-ACK is; IPv6's resolver for a
  device of IPv6 alone; 3 s for each try; the stand-in answers the probe at 1.1.1.1:443.
- T-505 (done): the host key algorithms that `known_hosts` records for a host go first within
  each list, also a list that replaces podssh's own (OpenSSH keeps such a list's order); podssh's
  own lists, which `+`, `-` and `^` start from, stay russh's, `ssh-rsa` (SHA-1) among them, not
  OpenSSH's defaults; a name that podssh does not speak is left out with a note at `-v`.
- T-503 (done): each host after the first, a later hop of `-J` and the destination behind it, is
  checked too, on each road, by the direct road's rule.
- T-476 (done): it reverses T-143's call of a skipped special file as a failure (66): a FIFO, a
  socket or a device is now a skip with exit 0, `{"event":"skipped",...}` in `--jsonl`; `mv -r`
  leaves each directory that holds one.
- T-470 (done): with no `copy-data`, `cp --delta` makes the temporary file by one command,
  `sh -c 'cat -- "$1" >| "$2" && echo podssh-copied'`, counted only with its marker and its size;
  the far blocks' digests come before that copy; a second attempt keeps the first reason.
- T-471 (done): `sftp`'s `ls -n` shows numbers also where the server could name them, as OpenSSH
  10.4p1 and later do; an entry with no long name gets podssh's line, not OpenSSH's empty one; the
  columns take the width of stdin's terminal, as OpenSSH's; a pattern in the last name only; a
  reply of the names' extension that is not of its form shows the numbers with no word.
- T-463 (done; its live run waits): the live run goes to the operator's server of
  `PODSSH_THROUGHPUT_SSH`, which Q38 names for the throughput run, for 3 minutes with nothing sent:
  no other test target gives a shell behind the relay's forward road. Recommendation: allow it, as
  a run lighter than the throughput run on the same server; podssh's own relay role measured it
  in its place.
- T-586: `operator` takes SIGHUP, SIGTERM and SIGINT as its application's end and closes the
  session (OpenSSH ends its ProxyCommand with SIGHUP); a node keeps a closed session as its id
  alone, charged nothing, and charges a closing one its unacknowledged bytes; no
  `--resume-deadline 0`, no `--no-resume`, no eviction of a waiting session; the budget's counts
  go in the refusal and the node's log, not in `detached list` or `relay status`.
- T-587: `proxy node://NAME[/ROUTE]` is the pipe of `operator NAME`, with its flags, and refuses a
  PORT; `operator` stays.
- T-589: `--ConnectTimeout SECONDS` on `operator`, `proxy` and `pipe`'s remote sides bounds the
  time to the session's open, never the bytes after it; not `--timeout`, not `PODSSH_TIMEOUT`.
- T-590: `doctor`'s line `sshd` dials 127.0.0.1:22 once and reads its first line, a note outside
  the count of failures; the roost's words name the package to install and run nothing.
- T-592: a renewal in podssh's relay role (`POST /v1/renew/<name>`, by the stop token) keeps the
  pair's three tokens, with no cap on renewals, and the node renews its own pair in its last 24 h
  where its relay renews. Its draft (partial) adds: each failed renewal gets the role's `403`, not
  a `404`; an operator past the end that its file names asks its relay's status once, with the
  trust of `SSL_CERT_FILE` or the settings, and is refused as before (77) offline or where the
  relay names no later end; a node of `--pair-file` renews too, and its file is not rewritten; a
  renewal that did not take is tried each hour; `relay pair --renew` refuses `--operator-file` and
  `--relay-host` (64).
- T-593: `XDG_CACHE_HOME` and `HOME/.cache` are the user's cache only when the uid owns them, else
  the passwd entry's home; a file kept in another user's home before is read there and said,
  never moved.
- T-594: `docs/STATUS.md` stays the page of `main`, each row marked with the first release that
  holds it or `unreleased`, held by a check of `scripts/check-repo.py`.
- T-595: one flag, `--carrier ADDR` (`stdio`, `fd:N`, `exec:CMD`), at the node and at its
  clients; the node's socket of the reverse road on the stream, the relay role's side of it in
  the client's process; the stream is the door, the end-to-end channel on by default. Its draft
  (partial) adds: the node's first frame is a Ping, and no session opens before it; a stream of
  `exec:` is started again once for each wait of a leg; `--exit` with `--carrier` is refused until
  T-596.
- T-596: `exit --listen --carrier` takes `stdio`, the one client of a carrier
  that does; the proxy starts its stream with its listener; a stream of `stdio` or `fd:N` ends the
  proxy (0) when its node leaves; Ctrl-C at the proxy ends the node (0); `ssh`, `proxy` and `pipe`
  keep refusing `--exit` beside `--carrier` (64).

**Confirmed (Q90):** T-503 checks each host after the first hop too (a later hop
of `-J`, and the destination behind it), on each road, by the direct road's rule, so that
`-J bastion 'a$b'` is refused with 64 where the relay road passed it to the jump host (its
`## Decision`).

The operator settled Q63 to Q66 on 2026-11-02 (`docs/decisions.md`), after the research of five
agents on the dependency on the relay's operator: podssh grows into a mesh of its user's own nodes
at parity with Tailscale (exit nodes, routes, share, funnel), and the relay becomes a role of
podssh itself, so that no entry waits for the relay's operator (Q63, milestone M10,
`docs/mesh.md`); Cloudflare's terms are accepted and are not raised again (Q64); the
magic-wormhole transit relay and mailboxes, Piping Server, the Wisp demo server and others that
fit may be tried unasked (Q65); podssh speaks HTTP CONNECT over TLS, VLESS and XHTTP, and
wstunnel's protocol as a client (Q66). The operator also had `v1.0.0` published at once, for the
testers, while sessions build M10.

The operator settled Q60 to Q62 on 2026-11-01 (`docs/decisions.md`), each as recommended: the
Tor road's live test may reach the public Tor network, with short runs, from GitHub Actions and a
session's own host (T-353); this binary started again at the user's request is no helper (rule 3
of `AGENTS.md`), and a detached run may ask the user's systemd for a scope (T-381); the quick
tunnel's node keeps a second connection to the edge, a fourth exception of rule 2 (T-414). The
operator also allowed `v1.0.0-beta.4` and then `v1.0.0` unattended, once the whole release check
passes.

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

The operator settled Q57 to Q59 on 2026-10-31 (`docs/decisions.md`): a
node on n0's relays publishes its record of pkarr to n0's server by default
(T-350); tailcat's DERP fleet may be tested live, short, from Actions and a
session's host, and a node with no pair serves the DERP road unasked
(T-349, T-379); WARP joins the release binaries once its live run passes
(T-352).

The operator settled Q44 to Q47 on 2026-10-30 (`docs/decisions.md`): the
split HTTP road may open its second connection (T-319, whose endpoints podssh's
relay role serves since Q63); the cleartext road on port 443 runs last, with a token
for one session (T-326, which podssh's relay role serves since Q63); mRemoteNG's
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

The operator settled Q49 to Q52 on 2026-10-31 (`docs/decisions.md`): a binary may
use relays outside `ssh.relay.ajam.dev` when they are compatible (T-346; relays that their users
bring and `podssh update`, T-375, make a signed list less pressing); the release binaries carry
the iroh road, with n0's public relays and Tailscale's tailcat fleet as an automatic fallback
(T-348 to T-350); roads through GCP IAP and AWS EICE, EICE's presigned URL an exception for that
URL alone, built against stand-ins first (T-351; the live run, T-376, waits for the operator's
accounts); and WARP's MASQUE road and Tor through Arti in a feature crate (T-352, T-353), WARP's
live test in Actions and on a session's host. The entries that they opened work before `v1.0.0`.

The operator settled Q53 and Q56 the same day (`docs/decisions.md`): `doctor` listens once on each
socket that it binds, accepts nothing and closes it at once, never with `PODSSH_LISTEN=no`
(T-358, with rule 2 of `AGENTS.md`, `SECURITY.md` and `docs/architecture.md`); and the three
public WebSocket forwarders of GitHub #59 are built in, each selected by a word, and tried when
each relay host fails, with live tests in GitHub Actions only (T-370, after T-369). Both work
before `v1.0.0`.

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

As the operator of the default relay, at any time and with no entry waiting: the notes of
`docs/relay-operator.md`, each of which podssh's own relay role does since Q63 (2026-11-02).
