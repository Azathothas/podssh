# Progress

The current state, the measured baseline, and the only work order. A closed
entry keeps its proof in the entry; this page keeps no history (git does).

## State

- **Checkpoint, 2026-11-06, about 03:00 UTC: the migration session is paused (the owner).** The
  next session starts fresh, with no memory and no messages to the sibling sessions.
  1. **Done in the migration (2026-11-05 to 06):** T-683 (`67c0768`, the name PodUtils/podssh);
     T-685 (`6514238`, `7d4753a`: no `msrv*` steps, no `CC=/nonexistent`, edition 2024, the static
     check `scripts/check-static.sh` with its plant); T-686 (`85d4e9d`, `publish.yml`, switch off);
     T-690 (`ccfef9e`, two regressions of `pod-proxy`); the audit of the record and the documents
     (`9d0623d`); the owner's rulings (`eea8c63`, `docs/decisions.md` 2026-11-06); the session
     protocol of PodUtils in `AGENTS.md` (section 2, "Talk with the other sessions of PodUtils").
  2. **T-684 is partial.** Taken by git tag: `pod-todo`, `pod-term`, `pod-identity`, `pod-core`,
     `pod-testkit` (v0.1.0), `pod-tls` (v0.2.0, `6ece2ff`), `pod-proxy` (v0.3.0, `a791553`), and
     `pod-dns` with `pod-services` (v0.4.0, taken on 2026-11-06 by the session of podssh's own work, as
     the owner's prompt asked; T-684's `## Done`); each tag at `v0.5.0` since (COORD-007), which also brought pod-proxy's fix of vectored
     writes (podcrates T-065) and removed the workaround `PodUtils/podssh:crates/podssh-ws/src/dial/bare.rs`
     of T-690. Next `pod-ws`, then the waves of Q101. The steps of a take are those of `AGENTS.md`
     ("Talk with the other sessions", item 4) and T-684's `## Done`: apply with `git apply --3way`,
     run each line of the `.run`, add clippy with the features `ts` and `tor` (podcrates' trial
     builds neither), `cargo todo remap Cargo.lock`, record in T-684 and `docs/STATUS.md`, commit,
     push, and write the commit as a COORD issue `(to podcrates)`. Who takes the hand-offs while no
     migration session runs is the owner's to say; a session of podssh's own work asks the owner.
  3. **Taken in v0.4.0, so worked on in PodUtils/podcrates (Rule Q3):** pod-dns (podssh-ws's
     resolver; `resolve.rs` stays as glue) and pod-services (each place of other parties' services in
     `PodUtils/podcrates:docs/research/services/podssh.md`: the lists of hosts, the probes, the live
     and watch workflows and their scripts and data files, `docs/decisions.md` 2026-11-05). Frozen
     now (fixes only, each written as a COORD issue `(to podcrates)`): what the next releases import,
     as the `repo PodUtils/podssh` blocks of `crates/*/SOURCES` in podcrates list it.
  4. **CI, 2026-11-06:** the gate passed each job at `285b0562` (run 42254589426: Linux, macOS,
     Windows, the release's static binary, `ts`, `tor`), after the takes of podcrates v0.4.0 and
     v0.5.0 and the drafts of the day; Actions start no workflow for this account's pushes, so each
     run is asked of the owner's agent (`docs/development.md`, "A run of GitHub Actions asked of the
     owner's agent"). Before it:
     the runs of `a791553` to `eea8c63` are red on the two regressions of T-690 (the step
     `ts`; the step `release`'s interop `resume.cut.up.sftp`) and on one-off failures (T-688). The run
     of `ccfef9e`, which repairs T-690, was running at the checkpoint: read it first. The daily
     `record-issues` is red: GitHub #107 (closed), the pull requests #149 and #150 and the COORD test
     #151 are not in `TODO/github.txt` and `TODO/issues.md`.
  5. **Waiting for the owner:** T-687 (crates.io: asked again only after the owner calls podssh
     stable). No release and no beta until the migration is done (T-446).

- **Checkpoint, 2026-11-05, about 00:30 UTC: the end of the night of 2026-11-04 (Q98 to Q100); items 7
    and 8 tell the move to PodUtils as it stood at the end of that morning.**
  1. **`v1.1.0-beta.2` is published** (from `dbd0fac`, 2026-11-04 18:48 UTC; its proofs passed).
     **`v1.1.0-beta.3` is published** (Q98), from `6d30328` at 01:30 UTC on 2026-11-05: made
     ready at `35e4932`, but the gate had been red since T-664 on three causes that the night read
     as the place's (the record of the keys that hosts took lost a change of logins at once, the
     stall's interop check looked for the old first request, and a WARP test inherited a reused
     port's memory); T-675 and T-676 repaired them (`0500af1`). Then its gate passed (run
     41940971099), the release workflow by hand on `beta/v1.1.0-beta.3` (run 41941007776),
     `scripts/release-short.sh BINARY --net` on a static build of `6d30328`, the publish (run
     41944902543) and the tag's run (41945306047); then `release-proofs.yml` (run 41949133180) and
     `update-live.yml` (run 41949136901) passed. `docs/STATUS.md` marks its 19 rows. The lesson: read each failed job's
     log before calling a red gate the place's.
  2. **GitHub #126 to #148** (Nemo-010) are T-628 to T-650 (Q100); done and closed: #126, #127,
     #128, #131, #132, #133, #134, #135, #136, #137, #138, #139, #140, #141, #142, #143, #144, #145,
     #146, #147, #148: each is closed but #129, whose T-631 waits for T-124.
  3. **osewa** (Q99, `docs/research/osewa.md`): T-660 to T-670, T-673. Done: T-661, T-663, T-664, T-667, T-669,
     T-673;
     partial: T-660 (iroh's and DERP's rows, osewa on a runner), T-662 (a copy through a shaped
     link), T-665 (the A/B run on a wide-area path), T-666 (the HTTP/2 part), T-670 (a far link's
     download while typing, a node's road on the slow link). Measured on the loopback (T-660's
     matrix): a key's echo beside a download is now about 100 to 140 ms on a cellular link
     (OpenSSH 1.6 s) and 0.4 to 0.8 s on a link of 1 Mbit/s (OpenSSH 16 s); a session resumes 1 s
     after a move; a cold connect is two round trips shorter than before and than OpenSSH's.
  4. **Partial and watched:** T-465, T-627, T-319, T-321 (as before), T-684 (item 7), and those of item 3.
  5. **The work order** (below): the move's open work (item 7), then the rest of osewa's entries
     (T-678 and the partial ones), then GitHub #127 to #148's open entries by priority, then M10's
     items 2 and 3 (T-106, T-180, T-434, T-459).
  6. **Two lessons of the night** (each in the paragraph of the drafts below): never commit while
     `scripts/plant-each.sh` runs; when the disk fills, remove `target/` whole.
  7. **The move to PodUtils (2026-11-05).** The repository is PodUtils/podssh and the shared crates
     go to PodUtils/podcrates (`docs/decisions.md`). No compatibility with the released binaries for
     now, and no bridge release (the operator). Done: T-683 (the name in the code, the manual, the
     workflows and the documents); T-685 (the gate has no step at a minimum Rust and no
     `CC=/nonexistent`; each crate is edition 2024 with Rust 1.97 from the workspace, moving to 1.99
     with `pod-tls`; `scripts/check-static.sh` checks the one rule, a static binary); T-686
     (`publish.yml`, its switch off). Partial: T-684. podssh takes each crate by a git tag of
     PodUtils/podcrates (Q101, Rule Q3): `pod-todo` (`crates/podssh-todo` is a wrapper, with
     `TODO/todo.toml`), `pod-term` (`podssh-terminal` is gone), `pod-identity` and `pod-core`
     (`podssh-relay`'s `identity` re-exports them) are taken; `pod-tls` (`podssh-ws`'s TLS, with thin
     wrappers) is taken; `pod-proxy` (`v0.3.0`) is taken too; `pod-dns` is being imported into podcrates, so
     `podssh-ws`'s `resolve.rs`, `resolve/` and its tests `doh_h2.rs`, `doh_names.rs`, `doh_wire.rs`,
     `live_doh.rs` take fixes only (each told to the podcrates session); next `pod-dns` and `pod-ws`, then the waves of Q101. An
     open entry whose code is in such a module has a `## Correction` of 2026-11-05 that names the
     crate. Settled 2026-11-06 (`docs/decisions.md`): no release and no beta until the migration is
     done, podssh stays beta until the owner calls it stable, crates.io is asked again after that
     (T-687, T-446); podvm takes the facade from `pod-relay` (T-085); T-689 is moot; a standing yes for
     COORD issues. The migration session applies podcrates' patches; a session of podssh's own work
     leaves T-684 to it. podbox is podvm.
  8. **Whatever is necessary, statically compiled (2026-11-05, the operator):** C, zig and the newest
     stable Rust in each crate (rule 4 of `AGENTS.md`); T-685 retired the checks of the old rules. An
     entry that says "no C" or "pure Rust" for a crate has a `## Correction` that reads it so.

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

  On 2026-11-06 one draft was made, unbuilt, by an agent of this cloud session: T-434
  (`worktree-agent-a28220759deade9a5`, branch `draft-t434`, `09dbd12`), merged and closed the same
  day; its worktree and branch are gone. Then T-456 (`draft-t456`, `34d1459`), merged and closed the
  same day; and T-180 (`draft-t180`, `7da08fe`), merged and closed the same day; then T-459
  (`draft-t459`, `8c085d46`), merged as partial the same day; and T-490 (`draft-t490`, `15743b03`),
  merged as partial the same day; and T-493 (`draft-t493`, `fb99826c`), merged and closed the same day;
  and T-492 (`draft-t492`, `9c2bf1d5`) and T-491 (`draft-t491`, `e95dd58f`), merged and closed the same day;
  T-495 (`draft-t495`, `f58eb5b5`), merged and closed the same day; T-498 (`draft-t498`, `6b6654ff`), merged as partial the same day.

  On 2026-11-04 an eighth round was drafted, unbuilt, one commit for each entry, each branch pushed
  as `draft/worktree-agent-*`: T-435 (`093970b`, merged and closed, `57faf83`); T-617 (`1cbdc10`,
  merged and closed, `00ba332`); T-618 and T-619 (`worktree-agent-a813dd96e40d4756b`, `9d04d4d` and
  `66eb08b`, merged and closed, `b750af3`; the live relay's document read once for T-619); T-620
  (`worktree-agent-a866bb2e35c2100ff`, `cc54c09`, merged and closed after `b750af3`). Their worktrees
  and local branches are gone, and their `draft/` branches on GitHub can go.

  On 2026-11-04 (evening and night) a ninth round was drafted by agents of this cloud session,
  unbuilt, each branch pushed as `draft/worktree-agent-*`: the triage of GitHub #127 to #148, T-660,
  T-661 and T-662, T-663, T-629 and T-635, T-630 and T-648, T-632, T-664, T-671 and T-647, T-639
  and T-645, T-634 and T-640, T-665 and T-666, and T-670: each merged, their worktrees gone.

  On 2026-11-05 a tenth round is drafted, unbuilt, one commit for each entry, each branch pushed
  as `draft/worktree-agent-*`: T-631 and T-674 (`68687d5`, merged: T-631 parked until T-124, T-674
  done), T-667 (`249f01f`, merged), T-636 (`034dc65`, merged), T-637 (`18b641c`, merged), T-641 (`dfa734e`, merged), T-646 (`d69b76f`, merged), T-668 (`8a39501`, merged; its follow-ups T-678 and T-679); T-660's run of `tc netem` with osewa
  (`cf91fcd`) is merged, its figures waiting for the workflow's first run.
  On 2026-11-05 at 04:20 UTC an eleventh round was drafted: T-643, T-644, T-638 and T-642, each
  merged (GitHub #141, #142, #136 and #140 closed), their worktrees gone. A lesson of the night: never amend a commit
  that was pushed, not even of a draft branch, as the push after it is a force-push (`draft/merge-668`
  was so pushed once, its one change the drop of an import); a new commit each time.
  At 06:15 UTC a twelfth round was drafted: T-649 and T-650 (GitHub #147 and #148), T-433
  (`podssh share`), each merged, and T-679 (a node's upgrade on its other roads,
  `09ed1ba`), merged in `bbac5dc`; no draft waits.
  On 2026-11-05 a thirteenth round, the audit of the record and the live documents after the move,
  was drafted and merged the same day (`cargo todo check` at the merge); its worktree is gone.
  A merge in progress waits on a local branch `merge-NNN` that tracks `draft/merge-NNN`, never on
  `main`. Two lessons of the night: never commit while `scripts/plant-each.sh` runs (a plant is
  applied in the tree then); and when the disk fills, remove `target/` whole, never files under
  `target/debug/deps` (cargo's records then name outputs that are gone).

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
- `cargo test -p podssh-todo` (2026-10-11; since 2026-11-05 the package is a wrapper of `pod-todo`
  of PodUtils/podcrates, whose tests are its own, T-684): 77 passed: 15 unit tests, 37
  plant tests (35 planted disagreements and two controls), 15 tests of the
  remap, 2 of `--base`, 7 tests of the writer, and the test of this record.
- `cargo todo check`: the record agrees. `python scripts/check-repo.py`: ok.
- `cargo clippy -p podssh-todo --all-targets -- -D warnings`: no warning.

## Counts

`TODO/INDEX.md` holds 648 entries: 78 open, 16 partial, 5 blocked, 549 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit,
then take the next one. Each session runs unattended until the goal of
`AGENTS.md` (section 2) is reached or the operator interrupts it.

**First (2026-11-05): the move to PodUtils.** T-684, partial, is continued first, as `AGENTS.md`
says: merge `pod-tls`, then take `pod-proxy`, `pod-dns` and `pod-ws` as the podcrates session hands
each over (Rule Q3 of `docs/decisions.md`: from the import, podssh changes that code for fixes only;
after podssh takes the crate, the work is done in PodUtils/podcrates). With it, the defects T-688 and
T-688, tests that fail on one platform, before any other work. T-687 waits for the owner (stable,
then a new question). Where a `## Correction` of 2026-11-05 says that the code of an entry is in a crate that
podssh has taken (`pod-tls` once merged, `pod-term`, `pod-todo`, `pod-identity`), that change is made
in PodUtils/podcrates, or asked there as an issue; the part of the entry that uses the crate stays
podssh's (T-111's serve, for one). A crate that podssh has not taken yet is changed here, as before,
and carried by the import. T-085 keeps its two boxes only (Q103: the facade goes with `pod-relay`).
T-446 waits: no beta and no release until the migration is done (Q104).

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

**First tonight (2026-11-04, Q98 to Q100):** `v1.1.0-beta.2` is out (GitHub #126, the testers'
P1 defect, is in it); then the entries that the studies of osewa filed (Q99,
`docs/research/osewa.md`), in this order: T-660 (measure what a user feels, first; its iroh and DERP rows),
T-662 (a copy through a shaped link; the SSH client's flow control and liveness in round trips are done), T-670, T-665,
T-666, their follow-up T-678, and what the netem run found, T-680 and T-681 (compression's figures, the rate on a lossy link, QUIC to the relay role and a node's upgrade in place on each road but Windows are done); then GitHub #127 to #148 (`TODO/issues.md`) by
their priority, beside the order of M10 below (Q85, Q100); `v1.1.0-beta.3` at the end of the night.

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
3. Exit, routes, share and funnel (the exit, `doctor --exit`, the net's routes and `podssh share` are done):
   T-459 (the funnel and a member that relays between two members are done; the status of the net, `ping` of a node and doctor's sections are done).
4. The public carriers of Q65 (the Piping Server road from end to end is done; T-450 from the runs of `transit-live.yml`; the
   protocols of Q66 are done), XHTTP over HTTP/1.1 (Q67, done), then what the research of more services (done) filed: the protocols of
   servers that a user runs (T-490, partial; Outline's servers are done; Shadowsocks 2022 is done; Trojan is done; NaiveProxy's server is done; then T-498 (partial) and T-693), upterm's door
   (done) and a second Piping Server (T-497), T-496 and T-499 parked; then what the triage of the sweep of public relays
   (2026-11-02) filed, as Q74 to Q79 rule: OpenTunnel's road (Q76; done 2026-11-03),
   and the manual's word on the public services that podssh uses and the ones it never names
   (done 2026-11-03); T-532 is parked; then what the rulings Q74, Q75, Q77, Q78 and Q82 filed (2026-11-02),
   the P2 ones first: Tailscale's main DERP fleet after tailcat's (T-534), the public Wisp servers
   made for it (T-535), Pinggy (T-548) and the public proxy nodes (T-574); then the research of the
   overlay networks (NetBird, Firezone, Cabal and Hyphanet are done; T-538 to T-542), of the trackers (T-546) and of the pub/sub networks (T-547),
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
T-672 (TLS tickets kept across runs) waits for a release of rustls that lets a client write one.

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
| T-631 | T-124 is done: `podssh serve --listen` exists |
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

**Q102, Q103, Q104 (2026-11-05): settled by the owner on 2026-11-06** (`docs/decisions.md`): no
release and no beta until the migration is done, podssh stays beta until the owner calls it stable,
and crates.io is asked again only then (Q102, Q104); podvm takes the facade from `pod-relay` (Q103).

**Q101 (2026-11-05): the crates of PodUtils/podcrates, agreed with podnet's session.** The operator
moves podssh to PodUtils/podssh (T-683) and puts the shared crates in PodUtils/podcrates (T-684);
podnet's session and this one agreed one list on 2026-11-05 (podnet's operator ruled that podnet's
WARP and Cloudflare adapters move there, and that podnet copies no podssh code). Recommendation:
accept it as written. **Settled 2026-11-05** by the owner's acts and rulings (`docs/decisions.md`,
"The crates of PodUtils/podcrates"): PodUtils/podcrates exists, its session builds the crates, and
`v0.1.0` is out; three rules of the list below changed: each crate may link C (T-685), declares
Rust 1.97 and edition 2024, and podssh takes it by a git tag of PodUtils/podcrates (Q1).

- Crates of podcrates (each name answered 404 at crates.io's index on 2026-11-05): `pod-todo`,
  `pod-testkit`, `pod-tls`, `pod-dns`, `pod-proxy`, `pod-ws`, `pod-identity`, `pod-term`,
  `pod-netstack`, `pod-wg`, `pod-relay`, `pod-relay-serve`, `pod-session`, `pod-e2e`,
  `pod-wormhole`, `pod-transit`, `pod-warp`, `pod-cloudflare`, `pod-derp`, `pod-acme`, `pod-egress`,
  `pod-iroh`, `pod-ts`, `pod-tor`, `pod-piping`, `pod-opentunnel`.
- Names held, no crate: `pod-wireguard`, `pod-quick`, `pod-udp`, `pod-mailbox`, `pod-reverse`,
  `podcrates`, `podutils`, `pod-utils`.
- Waves: 1, `pod-todo`, `pod-tls`, `pod-dns`, `pod-proxy`, `pod-ws`, `pod-identity`, `pod-term`, and
  `pod-testkit` with the russh harness; 2, `pod-netstack`, `pod-wg`, `pod-relay`, `pod-session`,
  `pod-e2e`; 3, `pod-warp` (with the stand-in edge into `pod-testkit`), `pod-cloudflare`,
  `pod-wormhole`, `pod-transit`; 4, `pod-relay-serve`, `pod-derp`, `pod-acme`, `pod-egress`,
  `pod-iroh`, `pod-ts` (with the headscale harness), `pod-tor`, `pod-piping`, `pod-opentunnel`.
- The rules of each crate (as changed on 2026-11-05 by T-685 and the owner's rulings; the first
  text said no C, crates.io only and Rust 1.89):
  no `podssh-ws` type; the binary passes a rustls `CryptoProvider` and a dialer; each crate may link
  C and declares Rust 1.97, edition 2024; podssh takes it by a git tag of PodUtils/podcrates, not
  from crates.io; podssh's pure-Rust provider and the RSA verifier (rsa 0.9) stay behind a feature
  of `pod-tls`; `pod-relay` keeps the `blocking` facade for podvm; a name of the wire may change,
  with no test against a released binary (the operator, 2026-11-05: no compatibility with the
  released binaries for now).
- Who builds: a new session in PodUtils/podcrates, fed by both repositories; neither podssh's
  session nor podnet's edits podcrates.
- podssh keeps: `podssh-cli`, `podssh-ssh` (it takes the patched russh and ssh-key), the IRC of
  `podssh-core`, `podssh-probe`. podnet keeps its CLI, `podnet-core`, `podnet-netns`,
  `podnet-vnet` and `podnet-serve`. Blocks T-684.

**For the operator to confirm (Q86), from the triage of GitHub #127 to #148 and the study of osewa
(2026-11-04)**; each call is in its entry's `## Decision`, and the work goes on with it:

- T-638 (#136): a forward token of the relay role stays good for each target that its policy
  dials, and a grant stays bound by its issuer's door (Q4, T-226); the issue calls both defects.
  Its draft (2026-11-05) asks the person of `--ask` after the door, never in its place: a yes lets
  in no key that the door refuses, where the issue asked that an approval alone let a device in.
- T-640 (#138): a node writes each line to the journal's own socket only when its stderr is that
  journal's stream already: not an outbound connection under rule 2.
- T-641 (#139): `doctor`'s line `nat` runs unasked against `stun.cloudflare.com:3478` and
  `stun.l.google.com:19302`, off with `PODSSH_STUN=no`.
- T-642 (#140): Encrypted Client Hello only when the user asks for it; the read of a name's HTTPS
  record before the session is then a read before a session, as Q96 and Q97 are.
- T-643 (#141): an operator that offers the net's document to a node that answers without it goes
  on, with a line that says so, where the issue asks for a refusal.
- T-644 (#142): `relay serve --sshd ADDR:PORT` dials the owner's sshd by the role's way out, the
  loopback and what `NO_PROXY` names directly and another address through `HTTPS_PROXY`, where its
  Approach had the dial always direct (rule 2); ADDR is an address, never a name; no limit, token
  or brake of the contract stands before the sshd, which sees each client as the role's address.
- T-649 (#147): a CA's validation (`acme-tls/1`) of a name that `relay serve --publish` publishes
  goes to its node, so that the node can prove the name, where the issue sends each validation to
  the role; PAIR is a pair's name, read at the start, so a new pair is published by a restart of the
  role with `--pairs FILE`; a visitor slower than its node meets the contract's bound of 1 MiB.
  Its draft (2026-11-05) is unbuilt.
- T-667 (osewa): QUIC and a TCP road race to one host for a short time, as the race between relay
  hosts does (rule 2), the loser closed at once; QUIC goes first, 300 ms ahead, to a role that
  offered it, where Q82 puts other projects' roads over UDP after TCP.

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

Dependabot's updates reach `main` through a session (the operator, 2026-10-30,
`docs/decisions.md`). The group of 11 that failed the gate's step iroh (Dependabot's #53) is in `main` (T-329).

After the release:

- A run of T-004 and T-005 in a real sandbox, with the brief of
  `scripts/sandbox-check.sh`.
- Pinning the facade of `podssh-relay` in podvm, formerly podbox (T-081, T-085): replaced by podvm taking
  `pod-relay`'s feature `blocking` by a tag (Q103, ruled 2026-11-06).

As the operator of the default relay, at any time and with no entry waiting: the notes of
`docs/relay-operator.md`, each of which podssh's own relay role does since Q63 (2026-11-02).
