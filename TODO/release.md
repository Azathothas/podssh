The first stable release, `v1.0.0` (milestone M9): its publication, and the
check of its published assets from end to end, with no human.

# T-250: Publish v1.0.0, the first stable release

**Source:** the operator's rulings of 2026-10-08 (`docs/decisions.md`): one
release only, `v1.0.0`, after every entry except the relay's; no beta, no
release between entries, and one tag, checked before and after.
**Category:** release
**Milestone:** M9
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

podssh has no release. Testers use the CI artifact of a push, and the work
of M3 to M8 and of the backlog reaches users only with a release.

## Premise

Read: `.github/workflows/release.yml` builds and checks the binaries, and
publishes them for a tag (`docs/development.md`, section "Release builds").
A release run is long, and it takes CI from the work: the operator wants one
release, at the end. Provenance (T-210), signed checksums (T-211) and the
new targets (T-218) are inputs.

## Approach

1. Inputs: each entry of `TODO/` is done, except the entries that wait for
   the relay's operator (`TODO/PROGRESS.md`); T-210, T-211 and T-218 are
   done; the gate is green; the check of T-251 passed before the tag.
2. Set the version to `1.0.0` in `Cargo.toml`. Write docs/releases/v1.0.0.md:
   what works, the targets, how to check a download, and the entries that
   wait for the relay. The draft notes of the dropped beta can help
   (`git show b1b111b:docs/releases/v0.1.0-beta.1.md`).
3. Tag `v1.0.0` once, and push the tag. Do not tag a candidate first: one
   release run only.
4. Run the check of T-251 on the published files. A defect found then is a
   new entry: repair it, and publish `v1.0.1` by the same steps.
5. Comment on and close each GitHub issue whose entries are done
   (`TODO/RULES.md`). Update the install lines of `README.md`,
   `docs/STATUS.md` and `TODO/PROGRESS.md`.

## Decision

The operator ruled on 2026-10-08: tag `v1.0.0` directly, checked before the
tag on the gate's artifact and a local build, and after it on the published
files; a defect found then goes into `v1.0.1`. A release candidate lost: it
costs one more release run.

## Prove

```sh
gh release view v1.0.0 -R Azathothas/podssh --json isPrerelease,assets --jq '.isPrerelease, (.assets | length)'
sh scripts/release-check.sh v1.0.0; echo "exit=$?"
```

The release is not a prerelease, and has a binary for each target,
`SHA256SUMS` and the signatures. The check of T-251 exits 0 on the published
files, and its result is in `docs/STATUS.md`.

## Start condition

Each entry of `TODO/` is done, except the entries that wait for the relay's
operator, the entries that the operator holds (Q32) and the work parked
behind them (`TODO/PROGRESS.md`), and the check of T-251 passed before the
tag.

# T-251: The check of a release from end to end, with no human

**Source:** the operator's rulings of 2026-10-08 (`docs/decisions.md`): what
"verified end to end" means, and that it runs before the tag and after it.
**Category:** measurement
**Milestone:** M9
**Priority:** P1
**Effort:** M
**Status:** partial

## Problem

The release workflow checks each binary's links and builds, and runs no
session. Nothing runs the binaries of a release against real servers before
users do.

## Premise

Read: the release workflow checks `NEEDED` and the interpreter with
`readelf`, and the C runtime with `dumpbin` (`.github/workflows/release.yml`).
The gate runs the binary against OpenSSH and Dropbear in a container, and
CI keeps the static binary of each push as an artifact (`scripts/gate.sh`).
The box models the target sandbox (`scripts/test_in_box.sh`).
`scripts/sandbox-check.sh` measures one host (T-006).

## Approach

1. A script, scripts/release-check.sh, with two sources of binaries: before
   the tag, the artifact of the gate's last push and a local Windows build
   (`--local`); after the tag, the published files of a tag (`TAG`), with
   `SHA256SUMS`, the Sigstore signatures (T-211) and the provenance (T-210)
   verified first. Each check has a time limit; read each exit code
   directly.
2. The checks:
   - the commands of `README.md`, and `podssh doctor` (exit 0);
   - `podssh proxy github.com 22`: GitHub's banner through the live relay;
   - `podssh ssh -T git@github.com` with a throwaway key: `Permission denied
     (publickey)` through the relay;
   - a session with a pty, and an exec, to railway.new through the relay, and
     to a tailnet host with `--direct` (throwaway keys);
   - the reverse road: two sessions at once from one box to a node in another
     box (the script of T-085);
   - `podssh serve` in the box: `vi`, `less` and Ctrl-C (the route of T-248);
   - `podssh cp` of 200 MiB each way, with equal digests;
   - a session that survives a killed relay connection (T-156);
   - `podssh pipe` with `stdio`, `exec:` and `unix-connect:`.
   - the live parts that the entries left to this check, each named in its
     `## Done`: among them the throughput run of T-157 with
     `PODSSH_THROUGHPUT_MIB=100` (500 MiB a direction in each cell, n0's iroh
     relays and the operator's SSH host: the operator, 2026-10-10, Q38), the
     IRC runs on undernet, libera and OFTC (Q39), the Tailscale runs with the
     auth key file of `.env/` (Q40), `scripts/chat-in-boxes.sh` (T-099), and
     `scripts/irc-in-image.sh` with its plant (T-252), whose step then joins
     the gate, and the exit status of an interactive login shell on a
     tailnet host with `--direct` (T-026): `exit 7` through `podssh ssh -tt`
     and through OpenSSH's `ssh -v -tt`, whose log names each `exit-status`
     request; its result corrects that row of `docs/STATUS.md`.
3. Hosts: this Windows host (the Windows binary, natively), a fresh Linux
   container, and the box like the target sandbox. The other targets: the
   short form (`--version`, `man --no-pager`, `keygen`, `proxy github.com
   22`) in the release run, on their own runners (T-218).
4. Record each result, with its source and the date, in `docs/STATUS.md`
   (a section "The release check").

## Decision

2026-11-01: the planted runs that the entries left to this check become files, one for each
plant: a file `ID.plant` in `scripts/plants/` (its entry, its group, the command of the check,
and the line that the failed run must print) with `ID.patch` beside it (the defect, a diff that
`git apply` takes) or a switch of its harness (`ENV`). `scripts/plant-each.sh` applies each, runs
its check with a time limit, reverts it, and passes only when each check failed and printed its
line; `.github/workflows/plants.yml` runs the groups in the build image (or, for a group named
`host...`, on the runner, for the box and the server images). Lost: the planted runs by hand,
edited and reverted in a session, which T-250 could not run again after the tag and which a
session's end loses half done; and a switch for each plant in the code, which would ship.

2026-11-01: the script of item 1, `scripts/release-check.sh`, with its catalog
(`scripts/release-check-catalog.sh`), its parts (`scripts/release-check-sources.sh`,
`scripts/release-check-here.sh`, `scripts/release-check-node.sh`, `scripts/release-check-actions.sh`)
and its reader of GitHub's public API (`scripts/release-check-api.py`):

- The sources. `--local --binary PATH`: the gate's static binary of the last push (the artifact
  `podssh-x86_64-unknown-linux-musl` of `.github/workflows/build.yml`; `gh run download` needs a
  login, so the script takes the file and fetches nothing), and a build of this host (`--build`
  PATH, else `cargo build --release` with the `RELEASE_FEATURES` of `.github/workflows/release.yml`);
  the tree is clean at the artifact's commit. `TAG`: the files of the release, from GitHub's
  download URLs as `README.md` fetches them (or `--dir DIR`, a copy). Then, before any binary runs:
  `SHA256SUMS` names the 8 binaries of the release once each; cosign checks its signature
  (`release.yml` at the tag); `sha256sum -c`; `gh attestation verify` of each binary with the
  bundle (`release.yml` at the tag, the tag's commit), as `.github/workflows/release-proofs.yml`
  does; the tag's commit from the API and from git agree; each Linux binary is static and of its
  machine. A missing cosign, gh or readelf is a FAIL. A row of the sources that fails stops the
  run: it prints "no check ran" and exits 1. That is the Prove's plant: a byte changed in a binary
  of `--dir` fails `sums.check`. Before the tag no `SHA256SUMS` exists: `sums.check` is a SKIP that
  records the artifact's digest and names T-250, unless `--sums FILE` gives one (the plant of
  `--local`). Lost: the digest of the artifact's zip from the API, which needs the zip, and so a
  login, and proves the zip, not the binary.
- One catalog of rows: the ID, the modes, the entry, the place, the limit and what makes it pass.
  A row that the run owed and did not make fails, so a check cannot drop out unseen, as the gate's
  steps cannot (`scripts/check-scripts.py`); `--list` prints the catalog. The states: PASS, FAIL,
  SKIP (only a row that the catalog marks, its reason naming the entry or question that holds it:
  T-248 and T-085, held by the operator, Q32; the operator's tailnet, Q40, where headscale stands
  in; the throughput run's direct cell, Q38), and ACTIONS.
- The ACTIONS rows: what GitHub's runners make (Windows and macOS, the box and the chat between
  boxes, WARP, Cloudflare's edge, the forwarders of GitHub #59, the live relay from GitHub's
  network, the planted defects, the 8 targets of the release, the proofs and `podssh update`). The
  script starts no run. A row with no `--actions-run NAME=ID` stays ACTIONS and says the command
  that starts its run. With one, the API's run and jobs, read with no token (gh's login only where
  the API refuses the address): the row passes only for a run of its workflow, completed, at the
  commit under check, whose named jobs each passed; a run of a tag's checks started on main counts
  once the release was published. Lost: starting the runs from the script, which needs a token
  that may start workflows and holds one process for up to an hour a run; and `gh run view`, which
  needs a login that a host may not have.
- The exit: 0 only when no row failed and each ACTIONS row was read; 1 when a row failed; 3 when
  none failed, but an ACTIONS row was not read or `--only` ran a part. Lost: 0 with ACTIONS rows
  listed, which a run that read no Windows result would pass.
- On this host, for each binary: `scripts/release-short.sh --net`, `scripts/sandbox-check.sh`
  (`doctor --full`, `proxy github.com 22`, `ssh -T` and `-tt` to GitHub's refusal, the prompts,
  OpenSSH with podssh as its ProxyCommand) and README's first steps. On the binary that ships (the
  artifact, or the published binary of this host's machine): `pipe` with `exec:cat` and with
  `unix-connect:` to a server of Python's; a pty and an exec to railway.new through the relay; a
  node of the live relay in front of this host's sshd, one session and then two at once, and `cp`
  of 200 MiB each way through it (the reverse road on one host: T-085's two boxes are held); a node
  of the iroh road through n0's relays (Q50); the same static binary in a fresh container of the
  box's Alpine on this host's network; `podssh update --check` after the tag; `podssh chat --irc`
  on OFTC, else libera, else undernet (Q39), where one network that takes the relay's address
  passes, as which networks take it is theirs to say (`docs/irc.md`); `scripts/irc-in-image.sh`
  in the build image; `scripts/ts-headscale.sh`, where exit 3 (only the live relay's three runs
  left to `actions.headscale`) passes; and T-157's throughput run at 100 MiB a run with n0's
  relay. The build of this host runs the first three: the live runs, each of minutes and of
  hundreds of MiB through the relay, run once, on the binary that ships. Lost: each run on each
  binary, twice the time and the relay's bytes for a build that ships nowhere.
- The runs that wait for undernet's route (T-095's pair, T-097's 1 MiB, T-098's idle session) run
  against ngircd in the build image, a server that podssh did not write; the public networks get
  the binary's one short run (Q39). undernet throttles the relay's one address (465, measured on
  2026-11-01).
- railway.new: its output holds a claim URL, so no line of it is shown or kept. Its refusal of an
  anonymous visitor fails the row, with that reason: a check that did not run is no pass.
- The forward cell of the throughput run through the relay's loop is a row of its own, which
  fails while `crates/podssh-cli/tests/throughput_live.rs` has no such cell.
- Each podssh of a check has a home and a cache of the run: its relay token is minted, used and
  removed with the scratch directory, and a pair is revoked at the end, also at an early exit. The
  table holds no path of the host: each path of the command line is PATH.

## Prove

```sh
sh scripts/release-check.sh --local; echo "exit=$?"
```

The script exits 0 only when each check passes on each host. Planted
defect: change one byte of a checked binary; the checksum step must fail,
and nothing runs. T-250 runs the same script on the published files.

## Start condition

Each entry of `TODO/` is done, except the entries that wait for the relay's
operator, the entries that the operator holds (Q32) and the work parked
behind them (`TODO/PROGRESS.md`).

## Correction

2026-10-09 (the operator's decision of that day, `docs/decisions.md`):
from T-136 on, an entry closes with the native tests, and the other parts
of its Prove wait for this entry. Before the release check, run them: the
whole gate in the build image (`sh scripts/dev.sh check`, the interop
against OpenSSH and Dropbear with it), then each planted defect that the
`## Done` of such an entry names as waiting. A failure is repaired, and its
entry gets a `## Correction`, before the tag.

2026-10-30 (T-218): the short form of item 3 is `scripts/release-short.sh
BINARY --net`, and each job of the release runs it on the binary's own
platform. The script of item 1 keeps the name scripts/release-check.sh.

2026-10-31, the operator's rulings of that day (`docs/decisions.md`) and the
study of stand-ins. The check runs from a cloud session, where item 3's
Windows host is not:

- the Windows and macOS parts run on GitHub's runners (windows-2025,
  macos-15), where the console checks already run (`.github/workflows/build.yml`),
  and the container parts (a fresh container, the box, `chat-in-boxes.sh`,
  `irc-in-image.sh`) with Podman here or on an ubuntu runner, from a workflow
  started by hand;
- the Tailscale runs and T-026's exit status run against T-334's headscale,
  in place of the operator's tailnet and the key of `.env/`;
- the throughput run's forward cell goes through the relay's loop of Q42 at
  100 MiB a direction, as a lower bound, and the direct cell is named as not
  run; T-335's repair comes first, so that the relay cells cross a relay;
- T-062 runs with the loop.

## Done

2026-11-01, partial: begun. `scripts/plant-each.sh` and `.github/workflows/plants.yml`, and the
first plants: `t360-record-row` (T-360, a row of `TODO/github.txt` removed: `cargo todo check`
names #62; caught here, `sh scripts/plant-each.sh --here t360-record-row`) and
`t252-irc-plaintext` (T-252, the harness's switch). The runner's own plants, here: a check that
passes with its plant is MISSED, a patch that no longer applies is STALE, a failure without the
named line is MISSED, and the runner then exits 1.

The live runs of T-154 and T-155 here (`cargo test -p podssh-cli --test node_live -- --ignored`,
2026-11-01): each overflowed its test thread's stack, 2 MiB, as the layer resumed; the binary runs
its dispatch on a thread of 16 MiB (`crates/podssh-cli/src/main.rs`), and the tests now run the
layer on a thread of that size (`on_the_binarys_stack`). Then T-155's run carried 200 MiB each way
whole in 720 s, but with 0 moves where the test wants 6: through this host's egress each link
ended after about 40 s ("the link ended with no word from the far end"), 20 times, each resumed
within 1 s, so no link came near the relay's 64 MiB. The run from GitHub's network decides it:
`relay-live.yml` takes `node_live` now.

T-154's live run here after the repair: `an_idle_session_through_a_node_lives_10_minutes` passed in
604 s, a session idle 600 s through a node and echoed after the wait, with 2 lines of loss and
resume.

The IRC runs through the live relay here (T-091 to T-098; Q39, short runs, a throwaway nick and
channel each): `live_irc --target irc.undernet.org` registered (no IRCv3, so no echo to prove a
message: exit 70, as `docs/irc.md` says of undernet); libera answered 465 on 6667 after its MOTD,
and K-lined the relay's address on 6697 (`podssh chat --irc`, "Closing Link: ... (K-Lined)"),
where it worked on 2026-10-10; OFTC on 6697 joined a throwaway channel and sent (no
`echo-message`, as before), and lost the link on 6667 before `001`. The live pair of T-095 then
got 465 from undernet for both of its clients, its throttle of one address. The pair, 1 MiB on
undernet (T-097) and the idle session of T-098 wait for a route whose address these networks
take.

2026-11-01, later, from a cloud session: the plants of `draft/t251-plants` carried onto `main` at
`da543fd` (`draft/t251-plants-2`), the plant of T-153 made again against `closes.rs` (T-410 moved
`ReopenSession`). `plants.yml` on it (run 41305692603): the groups each-a, each-b, cli-tests,
record, ssh-keys, ssh-pty, ts, resume, resume-cli, irc and host-chat passed on GitHub's runners,
each plant caught.

The box like the target sandbox does not run on GitHub's runner: its probe of `/dev/tty` waited 40
minutes there, so it never measured podssh (T-415, with a diagnosis). It runs in this session
instead, as the Correction of 2026-10-31 allows: the session's only way out is a TLS-reading
proxy on its loopback, so `scripts/test_in_box.sh` now builds the images on the host's network with
that proxy's CA, the box's proxy carries each CONNECT that its policy takes on to it
(`scripts/box/proxy.py --upstream`, through `scripts/box/forward.py` on the podman bridge), and
podssh in the box trusts that CA, which the run says; `scripts/box/build-podssh.sh` passes the
proxy and its CA into the build image. Then the box matched the sandbox on every property, and
each run passed here: default and nolisten, `sandbox-check: 14 ok, 0 FAIL, 1 skip`; tt, the exit
status 7, vi, less, top and Ctrl-C. The plants of the groups host-box and host-nolisten run here.

2026-11-01: `scripts/release-check.sh` and its parts (the Decision of 2026-11-01), merged from
`draft/t251-release-check`, the section "The release check" of `docs/STATUS.md`, and its run in
`docs/development.md` ("Release builds"). Measured in this cloud session, each part on its own;
no whole run yet, as the tag's commit does not exist:

- `--list`, `--list --local` and `--list v1.0.0-beta.3`: each row of the catalog, with the NAME of
  each ACTIONS row and the command that starts its run.
- The sources after a tag, on `v1.0.0-beta.3` with cosign v3.1.4 and gh: each of the 12 files,
  the release's kind (a prerelease, as the tag's form wants), the tag's commit `54d89a0` as git
  says, `sums.names`, the signature of `SHA256SUMS` by `release.yml` at the tag, 8 binaries against
  `SHA256SUMS`, the provenance of 8 of 8, and 4 of 4 Linux binaries static, each of its machine;
  then `update.check`: "podssh update would replace ... with podssh-x86_64-unknown-linux-musl of
  v1.0.0-beta.3". The plant, one byte of a binary changed: `sums.check` FAIL, "no check ran",
  exit 1.
- Before the tag, with `main`'s static binary built with release.yml's features (`iroh,warp`):
  `short`, `sandbox`, `readme`, `pipe`, `reverse.two`, `iroh.n0`, `container.short`,
  `container.sandbox` and `cp.200mib` passed. `railway` failed: railway.new refuses an anonymous
  visitor for now (not podssh's). `irc.live` failed: the relay's exit address is K-lined at libera,
  G-lined at undernet, and OFTC's TLS ended (not podssh's; T-252's harness in the build image is
  the IRC check). `irc.image`: `scripts/dev.sh run -- sh /work/scripts/irc-in-image.sh` passed,
  ngircd over plain text and TLS, 4 tests, in 4 min 47 s. `throughput` and `throughput.loop`: the
  run at 100 MiB with n0's `use1-1` passed in 3,087 s, the cell through the relay's own loop with
  its figures (`docs/STATUS.md`, "Throughput, measured"); the row now wants the cell's figures, not
  its name. `headscale`: `scripts/ts-headscale.sh` exited 3, as the row passes it, in 7 min: 11 passed
  (tcp and relay mode, 1 MiB each way, the bound, an ephemeral node, exit 7, a DERP link dropped and
  back, no key in any output), and the live relay's 3 left to `actions.headscale`, as this host's
  egress shows the relay with a certificate of its own CA, which the fork's roots do not hold.
- A run with no `--build` began `cargo build --release` in its own worktree, beside a measurement
  and on a nearly full disk; it was stopped. The release check's run passes `--build` or has the
  disk and the time of a release build.
- The ACTIONS rows against real runs: `box.yml` (run 41314911742) and `plants.yml` (run
  41315851930) at `bb46515` were read through the public API with their jobs' names (`box (tt)`,
  `plants (copy)`), and refused for a check at `d123501` ("it ran at bb46515, not d123501"), one
  job named while it still ran. The run of each ACTIONS row at the tag's commit is the run before
  the tag.

The merge left `scripts/interop-ptyrun.sh`, a part of `scripts/interop.sh` that printed
`ssh.pty.driver`, out of `scripts/interop-baseline.txt`, and the gate failed at `fff2252` on
`cargo test -p podssh-todo --test interop` (run 41323161424: record, release, Windows and macOS),
which the merge did not run here; each interop row of the release step passed. The part now only
runs the driver, a `support` file, and `interop.sh` prints the driver's line again.

The box runs on GitHub's runner since T-415: `box.yml` at `bb46515` (run 41314911742), default,
nolisten, tt and chat each passed; `plants.yml` at `bb46515` (run 41315851930): each of the 16
groups passed, so each plant was caught, host-box and host-nolisten among them.

2026-11-01, the runs before `v1.0.0-beta.4`'s tag: the ACTIONS rows at `889fda2` (the product code
of `1bafa9d`): update, service, doh, hop, forwarders, quick tunnel, WARP, relay's backpressure,
headscale and release passed; node_live failed on railway.new's limit (T-422). The local run at
`74974dd` (the dry run's static binary, run 41341493345, and a release build here): 17 passed, among
them throughput and its loop cell (p50 1.96 MiB/s), headscale (exit 3 as the row wants), irc.image,
reverse.two and iroh.n0; failed: `sandbox` and `container.sandbox` (T-424, a real defect, repaired),
`irc.live` (T-425), `cp.200mib` (this host's disk filled: "No space left on device"). The rows
again at `4e79a1f` (run 41346815789's binary and a build here): 16 passed, `sandbox` 15 ok and
`container.sandbox` 14 ok, `cp.200mib` 200 MiB up in 53 s and down in 76 s with equal digests;
`irc.live` failed (T-425's repair came after it); `railway` a SKIP (T-422).

# T-422: railway.new refuses anonymous visitors for hours, and two checks of the release fail on it

**Source:** the runs at `889fda2` (2026-11-01): `relay-live.yml` with `test=node_live` (run
41339253020), `ssh_to_a_node` failed, "railway.new limited this anonymous visitor (its exit 1)",
while the node dialled railway.new from GitHub's runner; and the release check's row `railway`
from this cloud session, through the relay, the same, as at each try since 2026-11-01 morning.
**Category:** defect
**Milestone:** M9
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The release check (T-251) passes only when each row does, and two of them wait on an outside
service's limit for anonymous visitors, which podssh cannot change: `v1.0.0` would wait on it.

## Premise

- Measured: `podssh ssh -T ... release-check@railway.new 'exit 3'` through the relay, from this
  session, exit 1 with railway.new's words of its limit (2026-11-01, 19:00 UTC); the node of
  `node_live` on GitHub's runner met the same, from another address.
- Read: `ssh_to_a_node` needs a server that runs `exit 3` for a key of the test behind the node,
  which OpenSSH's server on the node's own loopback is, as the release check's `reverse.two` row
  already uses (`scripts/release-check-node.sh`); the row `railway` needs a public server that runs
  a command for any key, through the forward road, which railway.new alone was.

## Approach

1. `ssh_to_a_node`: the node serves OpenSSH's server that the test starts on its loopback for this
   user and the throwaway key (`tests/live_harness/sshd.rs`); railway.new where no sshd is found.
   `relay-live.yml` installs `openssh-server` where the runner has none.
2. The row `railway`: railway.new's own words of its limit make the row a SKIP that says so and
   names where the exit status through the relay is checked (`reverse.two`, `actions.node`); any
   other failure stays a FAIL.

## Decision

2026-11-01: the row `railway` skips on railway.new's limit rather than waiting for it, since the
limit is an outside service's and comes back for hours; its two checks of the forward road's exit
status are not lost: `reverse.two` runs `exit 3` with a pty and without one through the live relay
against OpenSSH, and `actions.node` the same through a node from GitHub's network. Lost: a public
server of the operator's for the forward road (the SSH host of `PODSSH_THROUGHPUT_SSH` is allowed
for the throughput run alone, Q38), and a FAIL that waits for railway.new.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_live ssh_to_a_node -- --ignored --nocapture
sh scripts/release-check.sh --local --binary BINARY --build BUILD --only railway
```

Planted, an sshd without the test's key: `ssh_to_a_node` fails.

## Done

2026-11-01, here:

- `ssh_to_a_node` through the live relay against this host's OpenSSH: "podssh ssh node://root@lab
  'exit 3' (127.0.0.1:PORT): exit 3", and the SSH banner through `podssh operator`; passed in 6 s.
  Planted, the server's authorized keys not the test's: it failed, "the remote status through the
  node".
- `relay-live.yml` with `test=node_live` at `74974dd` (run 41341464543), from GitHub's network: 4
  passed; "podssh ssh node://runner@lab 'exit 3' (127.0.0.1:35735): exit 3", the banner through
  `podssh operator`, and 200 MiB each way through a node in 115 s with 8 moves.
- `irc.live` at `74974dd`: OFTC's TLS ended with no word ("tls handshake eof"), where a run at
  18:45 UTC was taken; libera K-lines and undernet G-lines the relay's address. The row tries OFTC
  three times, as its name gives one of several servers each time
  (`scripts/release-check-here.sh`).
- `sh scripts/release-check.sh --local --binary ... --build ... --only railway` at `74974dd`: `SKIP
  railway`, "railway.new refused this anonymous visitor, its limit (its words withheld): -tt: exit
  13; -T: exit 1; an outside refusal (T-422)"; the run's verdict INCOMPLETE, as `--only` gives.

# T-423: The test of a session's lock found it still held on macOS just after its holder went

**Source:** CI's job `macos` at `74974dd` (run 41341460569, 2026-11-01):
`session::tests::a_second_daemon_of_a_socket_is_refused_while_the_first_holds_it` failed at the
lock taken again after the first holder's drop: "another podssh session serves it (pid 20985)",
this process's own pid.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A test that fails at random keeps the gate red at the commit of a beta.

## Premise

- Read: the lock is `File::try_lock`, a `flock` on `w.sock.lock`
  (`crates/podssh-cli/src/node_install/lock.rs`); the test drops the first holder's `File`, then
  takes the lock again at once (`crates/podssh-cli/src/session/tests.rs`). The run on macOS found
  it held by this process; it passed at `0054e03` on macOS, and here 14 times of 14.
- Not located: no test of the library forks between an open and an exec (each spawn is a
  `posix_spawn` there), and the doctor's raw descriptors are each closed once.

## Approach

The test takes the lock again within 2 s of the drop, and fails with the holder's words after
them: a lock that stays held still fails it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib session::
```

Planted, the first holder kept: the test fails after 2 s.

## Done

2026-11-01: `cargo test -p podssh-cli --lib session::`: 14 passed. Planted, the first holder kept
alive (`let _kept = first`): it failed, "still held after its holder went: ... (pid ...)", in 2.1 s.
The cause on macOS is not located; the gate's job `macos` at the next push says whether it comes
again.

# T-424: `-M` leaves its control socket when its connection fails before the master serves

**Source:** the release check at `74974dd` (2026-11-01), its row `sandbox` and
`container.sandbox`: "FAIL the control socket of -M: it listened; the closed port gave 255 (want
255), and its socket went", a check that came with T-251's merge (`fff2252`).
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`podssh ssh -M -S PATH HOST` whose connection fails leaves the socket file at PATH: the next master
on that path meets a stale file, and OpenSSH, which makes its socket only after the login, leaves
none.

## Premise

- Measured: `podssh ssh -v --direct -p 9 -N -M -S T/ctl 127.0.0.1`: exit 255, and `T/ctl` still
  there, with the builds of `7855981` and `74974dd`.
- Read: the socket is made before anything connects (`be_master`,
  `crates/podssh-cli/src/ssh/control_unix.rs`), as `-L` binds first; the master's loop removes it
  (`crates/podssh-ssh/src/mux/master.rs`), and runs only once connected, so a run that fails first
  never removes it.

## Approach

A guard made after the start of connection sharing (`control::Unserved`): when the run ends with
its control still in the slot, never taken by a master, the socket's file goes.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_control
sh scripts/sandbox-check.sh BINARY
```

Planted, no guard: the new test fails.

## Done

2026-11-01: `crates/podssh-cli/src/ssh/control_unix.rs` (`Unserved`) and its guard in
`crates/podssh-cli/src/ssh/mod.rs`. `cargo test -p podssh-cli --test ssh_control`: 4 passed, with
`a_master_whose_connection_fails_leaves_no_socket` (a closed port: exit 255, "ControlMaster:
listening on", and no file left). Planted, the guard taken out: it failed, "the socket of a master
that never served is still there".

# T-425: The public IRC networks turn the relay's address away, and the release check's row irc.live fails on it

**Source:** the release check at `74974dd` and `4e79a1f` (2026-11-01): `irc.live` failed, "no
network took the run": OFTC ended TLS with no word (three tries at `4e79a1f`), libera K-lines the
relay's address, undernet G-lines it (DNSBL); OFTC took a run at 18:45 UTC the same day.
**Category:** defect
**Milestone:** M9
**Priority:** P1
**Effort:** S
**Status:** partial

## Problem

The release check passes only when each row does, and `irc.live` waits on the lists of three
networks that podssh does not keep: `v1.0.0` would wait on them.

## Premise

- Read: `docs/irc.md` says that libera, OFTC and tilde close before the welcome for the relay's
  addresses, and that "the relay's address changes with the networks' lists, not with podssh".
- Read: `irc.image` checks podssh's IRC client against ngircd over plain text and TLS
  (`scripts/irc-in-image.sh`), and passed at `74974dd`.

## Approach

When each try of `irc.live` ended before the welcome in the network's own words of a refusal
(`K-Lined`, `G-lined`, `DNSBL`, `banned`, or TLS ended before any line), the row is a SKIP that
says so and names `irc.image` and T-346 (a deployment on another provider, whose address the
networks may take); any other end of a try leaves a FAIL.

## Decision

2026-11-01: a SKIP on the networks' own refusal of the relay's address, as for railway.new's limit
(T-422): the client is checked against ngircd, and the networks' lists are theirs. Lost: a FAIL
that waits for three networks to change their lists.

## Prove

```sh
sh scripts/release-check.sh --local --binary BINARY --build BUILD --only irc.live
```

## Done

2026-11-01: `scripts/release-check-here.sh` (`c_irc_live`): each try's log is read for the words of
a refusal; with each try refused, `SKIP irc.live`. Run after the commit: below.

# T-415: On GitHub's runner the box's /dev/tty probe waits 40 minutes, so box.yml measures nothing

**Source:** the runs of `box.yml` and of `plants.yml`'s host groups for T-251, 2026-11-01
(runs 41285485857 and 41306712198).
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

On GitHub's ubuntu runner the box's probe of `/dev/tty` waits until the holder of the dead pty
ends, 40 minutes later, then reads an I/O error; the box then differs from the sandbox and
podssh is never measured in it. Each box run of `box.yml` and each plant of the groups `host-box`
and `host-nolisten` runs out of its time there, so the box can run only on a host like a cloud
session's (T-251).

## Premise

- Measured in `box.yml` at `2bc46dc` (run 41285485857): `DIFFERS /dev/tty box: dd: /dev/tty: I/O
  error`, 40 minutes after the box started.
- Measured by a diagnosis on the runner at `ed12dfd` (run 41306712198): rootful Podman, the box's
  seccomp profile, the dead pty bound at `/dev/tty` in `alpine:3`; after 3 s `dd` and busybox
  `timeout`'s watcher (in a session of its own) both sleep, nothing pending or blocked, SIGINT and
  SIGQUIT ignored; `dd` then waited until the holder ended at 120 s ("dd: /dev/tty: I/O error").
  Rootless Podman: `dd` exited 1 at once.
- Measured here (a cloud session, Linux 6.18, Podman 4.9.3, rootful), the same image, profile and
  command: `timeout 5` ended `dd` after 5 s (143), and the probe matched.

## Approach

Find why busybox `timeout`'s watcher never signals `dd` on the runner (its sleep, its `kill`, or
the pid it watches), from a diagnosis that prints the watcher's `/proc/PID/wchan`, its syscall
and `timeout`'s own exit; then a probe that does not depend on it (the shell's own background
`dd`, killed by the shell after 5 s), measured on the runner and here.

## Prove

```sh
# on GitHub's runner, from the workflow
gh workflow run box.yml -f run=default
```

## Correction

2026-11-01: busybox `timeout`'s watcher was not at fault, nor the shell's sleep. The probe that
killed `dd` itself (`b76a986`, run 41309639232) waited the same 40 minutes, and a diagnosis on
the runner (`71b183e`, run 41314338093: Ubuntu's kernel 7.0.0-1017-azure, rootful Podman 4.9.3)
showed why: inside the box, `kill -KILL` of its own `dd` failed with "Permission denied", and
`/proc/PID/wchan` read 0. Podman's default AppArmor profile does it, with no-new-privileges and no
capabilities: the same box with `--security-opt apparmor=unconfined` killed `dd` at once, as did a
plain container. This host has no AppArmor, so it never showed.

## Done

2026-11-01: `scripts/test_in_box.sh` and `scripts/chat-in-boxes.sh` run the box with
`--security-opt apparmor=unconfined` where `podman info` says that AppArmor is on, and say so; the
sandbox's record names no such profile, and no property that the box stands for depends on it.
`scripts/box/probe.sh` says a kill that the host refuses as a difference at once, and never waits
on it. `box.yml` on GitHub's runner at `bb46515` (run 41314911742): default (the box matched the
sandbox on every property; `doctor --full` 44 ok, 0 FAIL; `sandbox-check.sh` 14 ok, 0 FAIL, 1
skip), nolisten, tt and chat each passed, each in 5 to 8 minutes, where each ran out of its time
before. The chat run needed T-416 too.

# T-309: Publish the rolling betas `v1.0.0-beta.N`

**Source:** the operator, 2026-10-30 (`docs/decisions.md`, "Betas before
`v1.0.0`"): the testers in real sandboxes filed the issues from a beta, and
they test the current code only when a beta has it.
**Category:** release
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

GitHub has no release and no tag since the history was replaced
(`docs/decisions.md`, "The repository is public"). The testers are agents in
real sandboxes that download a binary: with no release, none of the work
since 2026-10-08 reaches them.

## Premise

- Read: `.github/workflows/release.yml` builds static musl binaries for
  x86_64 and aarch64 and a Windows binary, and publishes them with
  `SHA256SUMS` for a tag `vX.Y.Z[-pre]`, as a prerelease when the tag has a
  suffix. Its job `publish` has never run: each run so far was by hand.
- Read: the body of a release is the notes file and git-cliff's list of the
  commits since the previous tag (`cliff.toml`). With no previous tag the
  list is the whole history: 342 commits, whose first lines hold about
  118,000 characters, and GitHub refuses a body of more than 125,000.
- Read: nothing compares the tag with the version of the crates (`Cargo.toml`,
  `version = "0.1.0"`), which `podssh --version` prints.
- Read: the SSH banner carries the version
  (`crates/podssh-ssh/src/run_config.rs:62`), and RFC 4253, section 4.2, allows no
  `-` in its software version.

## Approach

1. The version `1.0.0-beta.N` in `Cargo.toml` and the lock files; the banner
   with `_` for each `-`.
2. The workflow: each commit's line cut to 200 characters (`cliff.toml`), a
   check that the body is under GitHub's limit, and a check that the binary
   of a tag names the tag's version.
3. The notes, docs/releases/v1.0.0-beta.N.md: what works, the assets, how
   to check a download, and what a beta does not have yet (T-210, T-211,
   T-218, T-251).
4. Before the tag: the gate green on the commit, the release workflow and the
   changelog workflow by hand on it, and the local checks of its binary
   (`--version`, static, `man`, `doctor`, `proxy` and `ssh` through the
   relay).
5. The tag once; then the same checks on the published files, and the result
   in `docs/STATUS.md`.

## Decision

2026-10-30: a Claude Code cloud session's git may push branches and not
tags: `git push origin v1.0.0-beta.1` got HTTP 403 five times, where each
push of `main` passed. The release workflow therefore takes the tag as an
input of a run by hand (`publish`), checks it against the version and that
it does not exist, and publishes with `gh release create --target`, which
makes the tag at the commit that the run built and checked. Lost: the
operator pushing the tag from a machine (a person in the loop, for each
beta); a run by hand that checks out another commit than its own (the
workflow and the code it releases apart).

## Prove

```sh
gh release view v1.0.0-beta.1 -R Azathothas/podssh --json isPrerelease,assets --jq '.isPrerelease, [.assets[].name]'
```

The release is a prerelease with the three binaries, `SHA256SUMS` and
`THIRD-PARTY-LICENSES.md`. Each sum checks; the x86_64 binary prints
`podssh 1.0.0-beta.1`, has no dynamic dependency, and passes `doctor` and a
login attempt through the relay.

## Done

2026-10-30: `v1.0.0-beta.1` is published, a prerelease at `5c8d423`
(https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.1, run
41054194363, at 12:26 UTC), and its files pass the Prove. The steps:

- The version `1.0.0-beta.1` in `Cargo.toml`; `cargo update -w` wrote it in
  `Cargo.lock` and `fuzz/Cargo.lock`, which also took tokio 1.54.1 and the
  `libc` of podssh-ws that it lacked.
- The banner is `SSH-2.0-podssh_1.0.0_beta.1`
  (`crates/podssh-ssh/src/run_config.rs:62`). `cargo test -p podssh-ssh --lib
  run::tests`: 6 passed, and the new test of the banner failed planted (the
  `-` kept: `SSH-2.0-podssh_1.0.0-beta.1`). `scripts/sandbox-check.sh:115`
  sent a `-` in its software version too: `podssh_sandbox_check` now.
- `cliff.toml`: each subject cut to 200 characters; after the cut, a name
  after `@` becomes code (the subjects hold `@NAME`, `@GROUP` and
  `@cert-authority`, which GitHub would read as mentions), then `#N` links.
  git-cliff 2.9.1, its release binary checked against its SHA-512: 343 of
  343 commits in 50,475 bytes, no mention outside code.
- `.github/workflows/release.yml`: each binary prints the version of
  `Cargo.toml`, and a tag must name it; the job `publish` runs by hand too,
  each step but `gh release create`, and keeps the files and the body as
  the artifact `release-dry-run`; the body stays under 120,000 bytes, else
  the list is cut at a line and is whole in `CHANGES.md`; git-cliff from
  `taiki-e/install-action`; `--verify-tag`. The comment on NASM said that
  aws-lc falls back without it: aws-lc-sys 0.45 stops (`builder/main.rs`,
  `use_prebuilt_nasm`) unless `AWS_LC_SYS_PREBUILT_NASM=1`. actionlint 1.7.7
  with shellcheck: clean. The body, made as the step makes it: 54,029 bytes;
  with the list three times, planted, 119,794 bytes and `CHANGES.md`.
- The notes: docs/releases/v1.0.0-beta.1.md.

- At `f5e06ca`: each job of the gate green (build, deny, secrets); by hand,
  the release workflow (run 41048945680: the three binaries, each printing
  `podssh 1.0.0-beta.1`; the job publish made `SHA256SUMS`,
  `THIRD-PARTY-LICENSES.md` and a body of 54,245 bytes, and its dry run's
  files), changelog and fuzz (10 s a target), each green. The x86_64 binary
  of that run, here: its sum, static-pie with no `NEEDED` and no `INTERP`,
  9,702,752 bytes, the manual (3701 lines, and the roff page), `doctor` 31
  ok, 0 FAIL, GitHub's banner through `podssh proxy` and the relay, and a
  login with a throwaway key refused (publickey, 255) after GitHub's Ed25519
  key was recorded.
- The tag was refused (HTTP 403; the Decision). The beta is published from
  a run by hand of the next commit, which carries T-316 as well.

- At `5c8d423`: each job of the gate green (build 16 of 16, deny, secrets);
  by hand, the release workflow's dry run (run 41051568231) and changelog,
  each green; its x86_64 binary passed the same local checks.
- The run that publishes (`publish=v1.0.0-beta.1`, run 41054194363) made the
  tag at `5c8d423` and the prerelease, with the three binaries, `SHA256SUMS`
  and `THIRD-PARTY-LICENSES.md`, and a body of 54,692 characters.
- The published files, by their public URLs, here: each of the five
  downloads; each sum checks; the x86_64 binary prints `podssh 1.0.0-beta.1`,
  is static-pie with no dynamic dependency, writes its manual (3702 lines),
  passes `doctor` (31 ok, 0 FAIL), carries GitHub's banner through `podssh
  proxy` and the relay, and a login with a throwaway key is refused
  (publickey, 255).
- The two Linux binaries of the run that publishes are the dry run's, byte
  for byte (equal sums); the Windows binary is not.
- The next betas follow the same steps (`docs/development.md`, "Release
  builds"), each after a batch of repairs that the testers should test
  again, at most one a day.

2026-10-31: `v1.0.0-beta.2` is published, a prerelease at `f7f97a5`
(https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.2, the tag's run 41147977814),
with eight binaries, their provenance and the signature of `SHA256SUMS` (T-210, T-211). `main`
held newer commits by then, so the run by hand with `publish` ran on a branch at `f7f97a5`
(`beta/v1.0.0-beta.2`): the job `tag` tags the commit of its run, whatever its branch. Its
files pass the Prove, and the proofs of `.github/workflows/release-proofs.yml` (`docs/STATUS.md`).

2026-11-01: `v1.0.0-beta.3` is published, a prerelease at `54d89a0`
(https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.3), by the run by hand with
`publish` on `main` (41261205053), whose job `tag` made the tag, and the tag's run (41261215707,
01:28 to 01:44 UTC), after the gate (run 41259529444), the dry run (41259544441) and the local
checks of its binary (`scripts/release-short.sh --net`) passed on that commit. Newer commits went
to `main` only once the dispatch was taken. Eight binaries, their provenance and the signature of
`SHA256SUMS`; iroh's road and WARP's in each (T-348, Q59). Its files pass the Prove. Here, by their
public URLs: the sums of the three that this host fetched; the x86_64 binary names `54d89a0`, is
static-pie, writes its manual (4850 lines), passes `doctor` (47 ok, 0 FAIL; the edge road waits for
`--full`), carries GitHub's banner through `podssh proxy` and the relay, and a login with a
throwaway key is refused (publickey, 255). Its `podssh update --check` names it the newest release,
and `podssh update --version v1.0.0-beta.2` on a copy checked beta.2's signed `SHA256SUMS` (the
workflow at the tag, Rekor's entry) and replaced the copy with beta.2's binary, byte for byte.
The proofs of `.github/workflows/release-proofs.yml` on a fresh runner (run 41262486970): `SHA256SUMS`
against each of the eight binaries; the provenance of each binary, and a changed copy refused
through the API and with `provenance.sigstore.json`; `SHA256SUMS` signed by the release workflow
at `refs/tags/v1.0.0-beta.3` (cosign 3.1.4 and 2.6.5; Rekor entry 3617465347), a changed copy and a
branch's identity refused; the short form on the published x86_64 binary; and that binary's
`podssh update` to its own release, which replaced it with its download.

# T-375: `podssh update`: the release for its own target, checked, in place of the binary

**Source:** the operator, 2026-10-31: "we will add self update soon", as an explicit command.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A binary that was copied into a sandbox is never updated (Q48): a fix such as russh 0.65.0's
(T-356) reaches no binary in the field until its user copies a new one by hand.

## Premise

- Read: the operator's decision of 2026-10-31: an explicit command that fetches the release for
  its own target through the proxy, checks the signed `SHA256SUMS` and the binary's sum, and
  replaces itself at once; it never runs on its own (`docs/decisions.md:27`).
- Inferred: the release publishes each binary with its provenance and a signed `SHA256SUMS`
  (T-210, T-211), which a client can check before it runs anything that it fetched.

## Approach

1. `podssh update`, and `podssh update --check`, which only says what it would do: the latest
   release (or `--version TAG`), through the proxy, with its `SHA256SUMS`, its signature and the
   asset of the binary's own target, named as `podssh --version` names its target.
2. The check, before anything is written: the signature of `SHA256SUMS`, then the asset's SHA-256
   against its line. The Decision chooses how the signature is checked with no C in the binary's
   path: Sigstore's bundle of the release (T-211), or a second signature by an Ed25519 key whose
   public half is compiled in.
3. The replacement: the new binary beside the old one, its mode copied, then a rename over the
   running file; on Windows, the running file is renamed aside first, and removed at the next run.
   A failure at any step leaves the old binary as it was.
4. Never on its own: no run of another command checks or installs a release.

## Decision

2026-10-31: Sigstore's bundle of the release (T-211), checked in podssh with no network and no C.
The release publishes it already, and it needs nothing of the operator; podssh checks, in
`crates/podssh-cli/src/update/sigstore.rs`: the digest of `SHA256SUMS`; the leaf's ECDSA signature
of the file; the leaf's chain to Fulcio's root, compiled in from Sigstore's trusted root
(`trust/fulcio.pem`), at the time that Rekor gives; the leaf's identity (code signing, the URI of
`release.yml` at the tag, and GitHub Actions as its token's issuer); Rekor's signed entry timestamp
with Rekor's key (`trust/rekor.pem`); and the entry's body against the file, the signature and the
leaf. The signatures are podssh-ws's own ECDSA; x509-parser reads the certificates, with no
feature, so no ring.

The alternative that lost: a second signature by an Ed25519 key whose public half is compiled in.
It needs a key that the operator makes and keeps as a secret of the workflow, whose loss stops each
update and whose leak signs any binary, and a second scheme beside Sigstore's. What Sigstore's
choice risks: when Sigstore rotates Fulcio's CA, or moves cosign to Rekor v2 (with no signed entry
timestamp), the binaries of before refuse the new releases; the refusal says to download by hand,
and the release workflow checks each published release with its own `podssh update --check`, so
the change shows on the day it comes.

The release: `--version TAG`, else the newest of GitHub's API, else of the releases' Atom feed
(redundancy: the API allows 60 calls an hour to an address with no token); a prerelease only when
this binary is one, as the tag says (`-` in it, which is how the workflow marks one); never older
than this build unless `--version` names it. The binary of the target: the release's for this
build's architecture and system, the musl one on Linux whatever this build's libc.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib update::
cargo test -p podssh-cli --test update
```

Against a stand-in release on the loopback: a binary replaced and run; a planted sum, a planted
signature and a binary of another target are each refused, the old binary left as it was. Live, in
Actions: a beta's binary updated to the next beta.

## Correction

2026-10-31: no release before `v1.0.0-beta.3` has `podssh update`, so the Prove's live form, a
beta's binary updated to the next beta, can run first in the proofs of the release after beta.3:
`release-proofs.yml` runs it for each release from then on (the published binary updated to its own
release, and the binary of the release before updated to it). Until then, the live test in Actions
is `update-live.yml`: a build of the commit replaces itself with a published release's binary on
Linux, macOS and Windows, where the running file is renamed aside.

## Done

2026-10-31, commits `5877a00` and `1a46970`: `podssh update`, `--check` and `--version TAG`; the
check of the release's Sigstore bundle with roots compiled in (`update/sigstore.rs`); the fetch
through the proxy with bounded redirects (`update/fetch.rs`); the release from GitHub's API, else
its Atom feed, in semver's order (`update/release.rs`); and the replacement by a rename, on
Windows with the running file renamed aside (`update/replace.rs`). `cargo test -p podssh-cli --lib
update::` passed 19 and `cargo test -p podssh-cli --test update` passed 9: beta.2's own bundle
verifies and each tampered copy is refused; against the stand-in, a file replaced with its mode
and a new inode, which ran, and each planted sum, signature, leaf (tag, issuer, time, use,
Fulcio), Rekor and target refused, the old binary as it was. Five planted defects each failed a
test; the first plant of the chain did not, as its test read a later check's words, and now reads
the chain's own. Live on this host through its proxy: a copy of the build replaced itself with
v1.0.0-beta.2's published binary, which ran. In Actions, `update-live.yml` run 41199118452: on
Linux, macOS and Windows a build of `1a46970` checked the release's signature with its own roots
and replaced itself with v1.0.0-beta.2's binary for its target (7.9 MiB on Windows, where the
running `podssh.exe` was renamed aside to `podssh.exe.old`; 6.2 MiB on macOS), which ran as
`podssh 1.0.0-beta.2 (f7f97a58...)`. Its first run (41197067974) found that macOS has no
`timeout(1)`, and the build's first run at `5877a00` that a Windows checkout turned the fixture's
LF into CRLF; each is repaired in `1a46970`. The beta-to-beta form runs in `release-proofs.yml`
from the release after `v1.0.0-beta.3` (the Correction).

# T-396: `podssh update` keeps the binary before it, and runs the new one once before it takes its place

**Source:** the operator, 2026-11-01: the study of Nemo-010/d-mon (T-389's Source); its eighth
finding.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

An update replaces the binary that the installed node runs; a new binary that does not start on
this host (a libc, a CPU feature, a defect) ends the node at its next restart, and nothing is left
to go back to.

## Premise

- Read, at `ea2bd4f`: on Unix the new file is renamed over the old, and no copy of the old stays
  (`crates/podssh-cli/src/update/replace.rs:95`).

## Approach

Before the rename: run the new file with `--version` (10 s), and refuse it when it fails or names
another version. Keep the old one as `podssh.prev` beside it. `podssh update --rollback` puts it
back. The supervisor of T-390 starts `podssh.prev` after 5 failed starts of the new binary in a
row within 2 minutes, with a line.

## Decision

- **The trial is `--version` of the new file, where it will run**, beside the old one, before
  anything of the old one moves (`crates/podssh-cli/src/update/trial.rs`): it starts the binary,
  its loader and libc, and its first line, `podssh VERSION`, must name the release asked for.
  Lost: a run of `podssh doctor` or of a node (each needs a network, and minutes); no run at all
  (the entry's Problem).
- **`podssh.prev` on Unix is a hard link to the old file, else a copy**, made before the rename
  that unlinks it (`crates/podssh-cli/src/update/keep.rs`): a link costs no space and no write. On
  Windows the running file, which only a rename may move, becomes `podssh.prev.exe`, the name with
  the extension that Windows runs; when that name is held by a running binary (a supervisor's
  fallback), the file goes to `podssh.exe.old` as before T-396, and the line says that nothing is
  kept. A copy that cannot be kept stops no update: the new binary ran here, and the line says that
  `--rollback` has none.
- **`--rollback` swaps the two**: the kept file over this binary in one rename, once it answered
  `--version` here, and this one kept in its place, so that nothing is lost and a second rollback
  goes forward. Lost: a rollback that deletes the newer binary. With nothing kept, 69; with a kept
  file that does not run, 65 and nothing changes.
- **The supervisor's half waits for T-390.** `update::keep::fallback(EXE)` gives `podssh.prev`
  when it is there and answers `--version`, and changes no file: the supervisor of T-390, after 5
  failed starts of the new binary in a row within 2 minutes, starts it with the same words and a
  line. T-390's Approach says so; this entry gives the function, and `replace::running` reads the
  path of a binary that an update replaced while it ran (`PATH (deleted)` on Linux), which the
  supervisor will be.
- **The tests on Windows**, where no small program of the test's own runs, give the stand-in
  release a trial that says the release's version (`Options::trial`); the real trial runs on each
  system on the podssh of this build, and on a file that is no program.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test update
cargo test -p podssh-cli --lib update::replace
cargo test -p podssh-cli --lib man::notes
```

## Done

2026-11-01: drafted (`worktree-agent-aac2458476d4808b9`), merged, built and run the same day; at the
merge the supervisor of T-390 took `keep::fallback` (below).

- The new file runs once as `podssh --version`, with no input, within 10 s, its exit code read
  directly, again for 5 s while another thread holds it open (ETXTBSY); a file that does not start,
  ends with another code, or names another version is removed and refused, 65
  (`crates/podssh-cli/src/update/trial.rs`, `crates/podssh-cli/src/update/replace.rs`).
- The old one is kept as `podssh.prev` (`podssh.prev.exe`), `podssh update --rollback` puts it back
  and keeps the other (`crates/podssh-cli/src/update/keep.rs`, `crates/podssh-cli/src/flags/update.rs`),
  `keep::fallback` names it for T-390; the manual's notes of `update` and its FILES; `docs/cli.md`;
  `docs/STATUS.md`.
- `cargo test -p podssh-cli --test update`: 16 passed (7 of them new, in
  `crates/podssh-cli/tests/update_keep/mod.rs`:
  `a_new_binary_that_does_not_run_here_is_refused_and_the_old_one_stays`,
  `a_new_binary_that_fails_or_names_another_version_is_refused`,
  `the_trial_reads_the_version_of_this_build`, `a_trial_that_does_not_end_is_killed_at_its_bound`,
  `rollback_puts_the_kept_binary_back_and_keeps_the_other`,
  `the_command_rolls_back_the_binary_that_runs_it`,
  `the_binary_before_an_update_is_kept_beside_it`; the release's stand-in binary answers
  `--version` now, and `the_newest_release_replaces_the_binary_which_then_runs` finds the kept one).
- `cargo test -p podssh-cli --lib update::`: 21 passed (`update::replace`'s 6, 2 of them new:
  `a_new_file_that_its_trial_refuses_leaves_the_old_binary_alone`,
  `the_kept_and_the_temporary_names_keep_the_extension`).
- Planted, each failed its tests: the trial skipped in `replace` (3 tests); the version not
  compared (2 tests); no `keep::keep` (2 tests). Clippy `-D warnings` here and for
  `x86_64-pc-windows-gnu`: clean.
- The supervisor of `--restart` (T-390): after 5 runs in a row that ended within 10 s of their
  start, it starts the binary that `keep::fallback` names, with a line
  (`crates/podssh-cli/src/detach/supervise.rs`, `falls_back`, its unit test passed). On Linux it
  starts its own image (`/proc/self/exe`) first, which an update does not replace; elsewhere the
  file at its path, which it does.
- Not measured: an update of a release's binary to the next one on each system (T-251's checks of
  a release), and the Windows half of the swap on a runner.
