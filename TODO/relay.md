This file holds the work on the relay client in `podssh-relay` and its commands: the token
cache, the relay diagnostics in the binary, the order and the overlap of attempts on relay
hosts, the `podssh-probe` crate, and two measurements of the relay itself. The relay's contract,
and how podssh selects hosts, are in `docs/relay.md`.

# T-057: The relay token is cached under the first configured host, not the host that minted it (GitHub #3)

**Source:** GitHub #3 (Nemo-010, 2026-10-08), measured by the reporter on the static release
and again on `3a88e1d`. Read again here on `3ee70dc`.
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

With a list of relay hosts, podssh caches a minted token under the first host of the list, also
when another host minted it. `PODSSH_RELAY=dead.invalid,tcp.ssh.relay.ajam.dev` leaves
`relay-token-dead.invalid.json`, and `doctor` says "a cached token for dead.invalid". A later
run sends that token to the first host, also when that host is of another relay deployment.

## Premise

The file name and the `doctor` line are the reporter's measurement (GitHub #3); not measured
here, because they need the network. Read on `3ee70dc` (the line numbers are those of
`2da855f`): `try_host` passes the first host as the cache key (`crates/podssh-relay/src/open.rs`
lines 218-219 at `37ace00`); `token::obtain` loads and stores by it (`crates/podssh-relay/src/token.rs` lines
105 and 110); a 403 removes the entry under it (`crates/podssh-relay/src/open.rs` lines
238-243). `doctor` uses and names the same key (`crates/podssh-cli/src/doctor/relay_checks.rs`
lines 144-150 at `37ace00`). `docs/relay.md` lines 43-45 at `37ace00` and `crates/podssh-relay/src/relay.rs` lines 36-37 at `37ace00`
make the first host the key on purpose. A pool host
gets a token only under the parent domain of the primary host, "because the token is sent to
them" (`crates/podssh-relay/src/pool.rs:7-8`, 75-80); a list from `--relay-host` or
`PODSSH_RELAY` has no such check. So, read and not measured: hosts A and B; A fails, B mints,
the token is stored under A; in the next run, A answers and gets B's token in `X-Relay-Token`
(`open.rs:220`, 235). When A is another deployment, its operator gets a valid token of B.

## Approach

1. Add `token_key(relay)` to `podssh-relay`: the default host for the default host and for each
   host that `pool::same_deployment(DEFAULT_RELAY_HOST, host)` accepts; else the host itself,
   with the port when it is not 443. `same_deployment` (`crates/podssh-relay/src/pool.rs:83-88`)
   is the one rule that already decides where a token may go.
2. Use the key of the host in use at each place: the load and the store through `MintContext`
   (`crates/podssh-relay/src/token.rs` lines 84-112 at `2da855f`), the removal after a 403
   (`crates/podssh-relay/src/open.rs:237-242`), and the token check of `doctor`
   (`crates/podssh-cli/src/doctor/relay_checks.rs` lines 142-165 at `2da855f`).
3. Store the minting host in the cache entry (`crates/podssh-relay/src/cache.rs:24-33`), with a
   serde default for old files. `doctor` says "a cached token minted at HOST (not shown)". Use
   an old entry only under the default key, where it was right.
4. Change in the same commit: `docs/relay.md` (lines 43-45 at `2da855f`), the comments at `relay.rs:36-37` and
   `token.rs:84-86`, the FILES text (`crates/podssh-cli/src/man/facts.rs` lines 124-135 at `332ee58`), and
   `docs/STATUS.md`.

## Decision

Recommendation: key by deployment. One token serves the hosts of the default deployment (a
pool host accepted the token of the default host: `docs/STATUS.md`, "`podssh proxy`, measured
live"), and no token goes to another deployment. The exact minting host lost: each pool host
would mint its own token, against the brake of 120 attempts a minute (`docs/relay.md:128`).
The decision said "one machine has one cached token"; on 2026-10-08 the operator ruled
"one for each relay deployment" (`docs/decisions.md:48`).

The session that did it (2026-10-08) made one call stricter than step 3: an old entry, with
no minting host, is not used at all, also under the default key. An old list that put the
default host first and failed over to another deployment cached that deployment's token under
the default key, so the default relay would get it. One more mint on each machine costs less.
Keeping old entries under the default key lost for that reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test cache   # new tests: token_key, old entries
sh scripts/dev.sh check                   # interop-faults: the file-name check
```

A unit test: `token_key` of a pool host is the default host; of another host, that host. In
`scripts/interop-faults.sh`, after the failover from a host that is down (lines 77-87 at `22c3b88`), with a
new `XDG_CACHE_HOME`: no `relay-token-relay-dead.test*` file, and one
`relay-token-relay-a.test*` file. Today's code is the planted defect: the check fails.

## Done

2026-10-08, in the commit "Relay tokens: one cache entry for each deployment, with the host
that minted it".

- `podssh_relay::token::token_key`: the default host for each host of the default
  deployment, else the host (with its port when it is not 443). `obtain` loads, stores and
  (in `try_host`, after a 403) removes under the key of the host in use; `MintContext` has no
  cache key any more.
- Each cache entry names the relay that minted it (`minted_at`); `usable` sends a cached
  token only under the key of that relay, and an old entry with no minting relay is not used
  (the Decision).
- `doctor` says "a cached token minted at HOST (not shown)". Live, on Windows: with an old
  entry in the cache, the first run said "minted at tcp.ssh.relay.ajam.dev and cached", the
  next "a cached token minted at tcp.ssh.relay.ajam.dev (not shown)". The same cache held a
  `relay-token-dead-host.invalid.json` from an earlier failover run (GitHub #3); it is never
  used now.
- `cargo test -p podssh-relay --test cache`: 12 passed, 4 of them new (the key for each kind
  of host; the rule for using a cached token; an old entry; the failover of GitHub #3).
- `scripts/interop-faults.sh` has the file check. Planted, with the gate's binary of
  `eaf9822` (before T-057): "token files after the failover: 1 for the dead host, 0 for
  relay-a.test", interop 98 passed and 1 failed. With this change, `sh scripts/dev.sh check`:
  green, interop 99 of 99 (12 faults).
- `cargo test --no-fail-fast` on Windows: 732 passed, 0 failed, 6 ignored.
- `docs/relay.md`, the FILES text of the manual and `docs/STATUS.md` say the same.

# T-058: `podssh relay status`, `info`, `spec` and `trace`

**Source:** `crates/podssh-cli/src/positionals.rs:47-53` (the subcommands that the parser
declares); `docs/relay.md:286-292`; the tester of sandbox A, who used `curl` and a minted token
on `/trace` (`report-podssh-sandbox-KTM-2026-10-08.txt`, outside the repository).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`podssh relay` is in the help but exits 70. To tell a relay problem from a target problem, the
tester needed `curl` and a token copied by hand. A host with only the binary cannot ask the
relay what it sees.

## Premise

Measured on `3ee70dc` (`PODSSH_OFFLINE=1`, stdin from `/dev/null`): `podssh relay status` exits
64 with the `--timeout` message that names `chat` (T-008); with `--timeout 5s`, it exits 70
("'relay' is not implemented yet; nothing was done."). Its help shows `--relay-host URL`
(`crates/podssh-cli/src/flags.rs` lines 315-316 at `af0a163`), not the `HOSTS` of the other commands (lines
169-170, 326-327, 337-338). Read: `/trace` needs a forward token in `X-Relay-Token`
(`docs/relay.md:177-178`). The `health` function of `doctor`
(`crates/podssh-cli/src/doctor/relay_checks.rs:82-138`) already makes a verified `/health`
request; `crates/podssh-relay/src/pool.rs:117-135` fetches `/relays.json`. `https_get` sends no
token header (`crates/podssh-ws/src/client.rs:271-282`); `https_request` takes headers (lines
282-303).

## Approach

1. `relay status`: `/health` on each host of the list. Move `health` into `podssh-relay`, so
   `doctor` and `relay` share one path, and podbox can use it.
2. `relay info [HOST PORT]`: `/relays.json?host=&port=`, the pool and the limits, read with
   `crates/podssh-relay/src/pool.rs:92-113`.
3. `relay spec`: the `/health` version and `/llms-full.txt`, checked against the pinned facts by
   `verdict_from` (`crates/podssh-probe/src/relay_facts.rs:276-290`), or `--document FILE`.
   This is T-060.
4. `relay trace HOST PORT`: `/trace` with `banner=1`, the token in the header and never in the
   URL (`docs/relay.md:113-115`). Check HOST with `relay::check_host`
   (`crates/podssh-ws/src/names.rs:10-24`), so no text can add a query parameter.
5. `pair` and `revoke`: refuse by name, and name M4 (T-078, T-083).
6. Flags as for `doctor` (`--relay-host HOSTS`, `--relay-addr`, `--ca-file`), and `--json`
   (T-049). Each request has the 10 s limit of `doctor`
   (`crates/podssh-cli/src/doctor/relay_checks.rs:27`), and the run has a limit too.
7. Remove the owner row (`crates/podssh-cli/src/flags.rs` line 442 at `af0a163`); change `DISPATCHED`, `usage_tail`
   (`crates/podssh-cli/src/help.rs:236`), the notes, `docs/relay.md:286-292` and
   `docs/STATUS.md`. `dispatch.rs` has 448 lines: put the verb in its own module.

## Decision

Recommendation: remove the `--timeout` and `--jsonl` rows of `relay`
(`crates/podssh-cli/src/flags.rs:307-318`), and bound each request in the code, as `doctor`
does. With the row, the gate of `crates/podssh-cli/src/dispatch.rs:213-231` stops
`podssh relay status` in each script that leaves `--timeout` out. Keeping the gate lost for that
reason: the command is bounded anyway.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay                     # new: refusals and bounds, offline
sh scripts/dev.sh check                                   # interop: the stand-in relay
cargo test -p podssh-cli --test relay_live -- --ignored   # the live relay, on request
```

`scripts/fake-relay.py` (it serves `/health` and the mint: `:76-84`) gets `/relays.json`,
`/trace` and `/llms-full.txt`. In the gate, `relay status` exits 0 with the stand-in's version;
`relay trace` sends `X-Relay-Token`, which the stand-in requires; a HOST of `a&b` exits 64 before
any connection. Planted defect: leave the header out; the stand-in answers 403, the test fails.

## Correction

2026-10-09 (T-083): `podssh relay` is dispatched now. `pair NAME`, `revoke NAME` and `status NAME`
work (step 5 is moot), and the owner row and the entry of `DISPATCHED` are done (step 7). Its
`--timeout` and `--jsonl` rows are gone, as the Decision here recommends, and its `--relay-host`
takes `HOSTS`, with `--relay-addr` and `--ca-file` (step 6). `status` with no NAME, `info`, `spec`
and `trace` exit 70 until this entry; `status` with NAME is the state of a pair, so step 1's form
is `status` with no NAME.

# T-059: A relay host that failed recently is tried last, also in the next run

**Source:** GitHub #25 (a circuit breaker,
`ImKKingshuk/USBoverSSH:usboverssh/src/circuit_breaker.rs`, read in the report, not verified
here; and talaria's comment: one drop in 180 short sessions). The cost of a silent host:
`docs/STATUS.md`, "Faults between podssh and the relay, measured".
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Each run tries the relay hosts in the same order. When the first host is down or silent, each
run waits for it before it tries the next host, up to 20 s for one step. A short process, such
as a `ProxyCommand` for each connection, pays this wait in each run.

## Premise

Read: `open` tries the hosts in the order of the list in each round
(`crates/podssh-relay/src/open.rs:192-209`), and keeps nothing between runs: a failure is a
note, and an entry of `Failure`. The limits are 20 s for each step and 45 s for each host (lines
25-29). Measured in the gate (`docs/STATUS.md`): a host that completes TLS and then says
nothing, and a host that does not start TLS, each cost the 20 s limit before the failover.

## Approach

1. After a host fails with an error that another host can repair (`another_host_may_help`,
   `crates/podssh-relay/src/open.rs:57-79`), write a record (host, time, class) into a private
   file `relay-failures-KEY.json` with `cache::store_file`
   (`crates/podssh-relay/src/cache.rs:144-160`). Remove the record when the host succeeds.
2. At the start of `open` (`crates/podssh-relay/src/open.rs:180-212`), move each host whose
   record is younger than a fixed window (10 min) to the end of the list, in its old order.
   Never remove a host: each host is still tried.
3. Record no error that each host would give (a policy refusal, a bad token in the
   environment): it says nothing about the host.
4. Print one note for each moved host: "trying HOST last: it failed N s ago (REASON)".
5. Ignore a record with a time in the future (a clock that moved).
6. `doctor` and `status` (T-051) show the records. State the window in THE RELAY section of the
   manual (`crates/podssh-cli/src/man/facts.rs:186-199`) and in `docs/relay.md:30-48`.
7. This is retry policy across runs. T-220 shortens the wait inside one run; the two work
   together.

## Decision

Recommendation: reorder a list from `--relay-host` or `PODSSH_RELAY` too. Its order is a
preference, the record expires, and the note says what changed. Both testers set their relay
hosts by hand, so they gain most. Reordering only the default list lost for that reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay   # new unit tests: the reorder and the record file
sh scripts/dev.sh check      # interop-faults: two runs with a silent first host
```

In `scripts/interop-faults.sh`, with a new `XDG_CACHE_HOME`: two runs with `relay-silent.test`
first and `relay-a.test` second, one host at a time (today's order, or the `serial` mode of
T-220). The first run takes 20 s or more; the second takes less than 10 s and prints the note;
both exit 0. A run with only the recorded host still tries it. Planted defect: ignore the
record; the second run takes 20 s, and the check fails.

# T-060: P1: no command uses `podssh-probe`

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row P1 (low);
`docs/STATUS.md`, Components. Read again here on `3ee70dc`.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

`podssh-probe` checks the relay's published document against pinned facts, but only its own
tests use it. CI checks the live document with a Python script that does the same work. Two
forms of one check can drift apart, and the crate costs build time for no command.

## Premise

Read on `3ee70dc`, the defect holds. No source, test or example of `podssh-cli` names
`podssh_probe`, although `crates/podssh-cli/Cargo.toml` line 31 at `cc386ce` declares the dependency. The crate
declares `libc` (`crates/podssh-probe/Cargo.toml` line 11 at `f8a94ca`), which none of its sources uses.
`crates/podssh-probe/src/facts.rs` lines 3-6 at `f8a94ca` name a "startup assertion" that no command runs;
`crates/podssh-probe/src/relay_facts.rs` lines 261-289 at `f8a94ca` are that unused startup part. CI runs
`scripts/check-relay-spec.py` live, with three plants (`.github/workflows/build.yml:174-191`).
The gate runs the crate's tests with no C compiler (`scripts/gate.sh:117-124`). The build image
has no Python (`crates/podssh-probe/src/facts.rs:14-19`), so the crate is the only form of the
check that the container gate can run.

## Approach

Do option (a) of the Decision:

1. `podssh relay spec` (T-058) calls `verdict_from` with the live `/health` version and
   `/llms-full.txt`, or with `--document FILE`.
2. Measure the size of the static binary before and after: the gate prints it, and
   `docs/STATUS.md` records 4,008,448 bytes. The crate brings `toml` and `regex` into the binary
   (`crates/podssh-probe/Cargo.toml:14-16`). Record both sizes.
3. Remove the unused `libc`. Make the "startup" comments true, or remove them.
4. Keep `scripts/check-relay-spec.py` as the second form, and add a CI step that requires the
   same verdict from both on the same document.
5. Change the `podssh-probe` row of `docs/STATUS.md` (Components) in the same commit.

## Decision

Recommendation (a): use the crate in `podssh relay spec`. A host with only the binary can then
tell a changed relay from a podssh defect, and the one facts file already serves both forms
(`crates/podssh-probe/src/facts.rs:31-32`, `scripts/check-relay-spec.py:5-10`). (b), keep it as
a crate for tests only or fold it into the tests of `podssh-relay`, lost: it leaves the problem
as it is. (c), remove the crate, lost: it removes the only form of the check that the container
gate can run.

2026-10-09, how `relay spec` reads: live, from the first host of the relay
list (`--relay-host`, `PODSSH_RELAY`, else the built-in relay), with the
proxy and the trust of the other relay commands and their 30 s bound for
each request; the facts file's `origin` stays the script's default. Its
exit codes: 0 when each fact holds; 1, as `doctor`'s for a failed check,
when one does not; 69, as for an unreachable relay, when the document was
not read (the script's 2: a check that did not run); 78 for a `--document`
that cannot be read. The step of CI that asks both for one verdict runs in
the job `release` of the gate, which has the static binary.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-probe
target/debug/podssh relay spec --document crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt
echo "exit=$?"
target/debug/podssh relay spec --document planted-copy.txt
echo "exit=$?"
```

The pinned copy exits 0. A copy with the node path renamed (the plant of
`crates/podssh-probe/tests/relay_facts.rs:106-110`) exits 1 and names the fact
`reverse-node-path`. `grep -rn podssh_probe crates/podssh-cli/src` finds the use.

## Correction

2026-10-09: T-247 removed `podssh-probe` from the dependencies of `podssh-cli`,
as no code used it, and `unused_crate_dependencies` now fails the build on a
dependency that no code uses. The command that uses `podssh-probe` adds it
back in its own commit.

2026-10-09: before this change, the static binary had 4,450,816 bytes (the
gate's run after T-217), not 4,008,448.

## Done

2026-10-09, in the commit "podssh relay spec checks the relay's document
against the facts that podssh was built with".

- `crates/podssh-cli/src/relay_spec.rs`: `podssh relay spec [--document
  FILE]`, with `verdict_from`; `relay_cmd.rs` dispatches it, and refuses a
  NAME after it and `--document` with another subcommand (64). The flag
  `--document`, the help, the manual (the notes of `relay`, and exit 1 in
  EXIT STATUS), `docs/cli.md`, `docs/relay.md`, `docs/development.md` and
  the list of commands in `AGENTS.md`.
- `crates/podssh-cli/Cargo.toml`: `podssh-probe` again, used.
  `crates/podssh-probe`: `libc` removed, unused; the comments of the
  "startup" half name `podssh relay spec`.
- `scripts/relay-spec-agree.py`, and its step in the job `release` of CI:
  the binary and `scripts/check-relay-spec.py` on the pinned copy, on a copy
  with the node path renamed, and on the live relay.
- Prove: `cargo test -p podssh-probe`: passes. `podssh relay spec --document`
  the pinned copy: `ok`, exit 0; the copy with the node path renamed: `FAIL
  reverse-node-path`, exit 1 (`cargo test -p podssh-cli --test relay_spec`:
  3 passed). Live: `ok`, each of the 7 facts, version `2026-10-03-r2`.
  `python scripts/relay-spec-agree.py target/debug/podssh.exe`: one verdict
  on each of the three, exit 0; with a facts file that drifted from the
  binary's, planted, they differ on the pinned copy, exit 1. `grep -rn
  podssh_probe crates/podssh-cli/src`: `relay_spec.rs`. The static binary:
  5,020,160 bytes, 569,344 bytes more.

# T-061: Measure whether the relay's idle cut applies to reverse sockets

**Source:** `docs/relay.md` lines 189-195 at `cd75137` ("Open questions"); ROADMAP M4.
**Category:** measurement
**Milestone:** M4
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

It is not known whether the relay closes a reverse socket, of a node or of an operator, after
180 s with no payload. The node runner (T-079) and the heartbeats of the resumable layer (T-154)
must keep a quiet session alive, and they depend on the answer.

## Premise

Not measured. On the forward path the cut is measured: 184 s with no traffic, while keepalives
every 60 s keep a session for 602 s (`docs/STATUS.md`, "`podssh proxy`, measured live"). The
pinned contract lists "idle sessions (180000 ms of payload inactivity; transport keepalives do
not reset this)" among its guards
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:233-234`), and says that the
reverse relay "hibernates idle sockets" (line 241 at `22c3b88`). `docs/reverse.md` lines 24-29 at `cd75137`, from dropssh: the
relay sends no keepalives on reverse sockets, and a quiet socket becomes dormant.

## Approach

1. A live test, ignored by default, in a new file crates/podssh-relay/tests/live_reverse.rs:
   `POST /v1/pair`; a node socket to `/v1/node/NAME`; an operator socket to `/v1/connect/NAME`;
   the node answers `open` with `ready`. Send `ready` with `RelaySession::send_text`
   (`crates/podssh-ws/src/session.rs:87-91`), which sends a real text frame; since T-071,
   `Leg::send_control` over `WsSocket` sends one too.
2. Three runs of 240 s: (a) no payload and no pings; (b) WebSocket pings every 20 s from both
   ends; (c) one byte of payload every 60 s. For each socket, record the time, the code and the
   reason of the close, or "open at 240 s".
3. At 240 s, send one byte each way: a hibernated socket can stay open and not deliver.
4. Stop the pair at the end (`POST /v1/stop/NAME`). Tokens go only in headers; never print one,
   and above all not the `stop_token` (`docs/reverse.md:135-144`).
5. Answer the question in `docs/relay.md` lines 189-195 at `cd75137`, record the result in `docs/STATUS.md` with
   the date and the command, and correct `docs/reverse.md` lines 24-29 at `cd75137` if the result differs.

## Decision

2026-10-09, before the runs:

1. The file is crates/podssh-relay/tests/reverse_idle_live.rs, after the other live tests
   (`pair_live.rs`, `reverse_live.rs`, `blocking_live.rs`). Lost: `live_reverse.rs`, a name that
   differs from `reverse_live.rs` only in its order.
2. One test for each run, so that each run makes and stops its own pair, and a failed run does not
   hide the others. They run one at a time (`--test-threads 1`): two runs at once could share a
   limit of the relay, which would change what is measured.
3. The test talks to the relay with `podssh_ws::connect` and the codecs of
   `podssh_relay::reverse`, not with the runners: the node runner pings every 10 s
   (`docs/reverse.md:28-36`), which would hide run (a).
4. The time of a close counts from the session's `ready`, about 0.2 s before the first byte each
   way, which is the last payload of runs (a) and (b).
5. The control asserts; runs (a) and (b) print what they measured, as either answer is a result.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_idle_live -- --ignored --nocapture --test-threads 1   # live, six runs, about 25 min
```

Each wait has a limit of 300 s, so the test ends with a result, never with a hang. Run (c) is
the control: its sockets must stay open and carry the bytes for 240 s. If they do not, the setup
is wrong, not the relay.

## Correction

2026-10-09: T-082 deleted `WsSocket` and `Leg` with `podssh-transport`, so step 1's second way to
send `ready` is gone. The test sends `ready` with `RelaySession::send_text`, built by
`control::ready`, as the node runner does. The Prove's command names the feature `pair`, which the
pairs need, and the file of Decision 1.

## Done

2026-10-09, in the commit "The reverse road has no idle cut, and drops at random".

- `crates/podssh-relay/tests/reverse_idle_live.rs`: six runs, one test each, each with its own pair,
  stopped at the end: (a) no payload and no Pings; (b) a Ping from each end every 20 s; (b1) from
  the node only; (b2) from the operator only; (d) from each end every 10 s, as the runners ping;
  (c) the control, a byte each way every 60 s. Round 2 added (b1), (b2) and (d), when round 1
  seemed to show that Pings caused a drop; round 2 showed that they do not.
- The answer: no idle cut. In each of the 4 quiet runs that no drop disturbed ((a) in round 1;
  (d), (b1) and (b2) in round 2), the session and both sockets were open at 240 s with no payload
  since the first byte, and then carried a byte each way. The relay sent no keepalive, and
  answered each Ping with a Pong. The control passed in rounds 1 and 3.
- The drops: in 6 of the 12 runs, the relay's side ended a socket's connection with no WebSocket
  Close, at 24.5 s to 212.4 s, also in the control of round 2 (53.1 s): the node's socket 5 times,
  the operator's 3 times, once both at the same moment. The relay saw each drop of one socket: it
  sent the operator `1011 node disconnected`, or the node a `close` of the session with no reason.
  No proxy was set, and the relay's certificate was its own (Google Trust Services WE1, for
  `ajam.dev`), so nothing on this machine stood between. T-255 measures the rate and the place.
- `docs/relay.md`: the question answered, the drops as a new open question, and the reverse path
  as podssh implements it (the section said that no command used it). `docs/reverse.md` (rule 8):
  a quiet socket is not dormant. `docs/STATUS.md` ("The relay", "Measure again").
- Prove: the command of the Prove. Round 1 (00:27 to 00:39 UTC): 3 passed. Round 2 (00:41 to 00:59
  UTC): 5 passed, 1 failed, the control, by the drop at 53.1 s. Round 3, (a), (d) and the control
  (01:01 to 01:11 UTC): 3 passed. The output of each round is kept outside the repository.
- Plant: the operator sends only its first byte. The control failed (`the control's last byte to
  the node`: `Some(false)`, exit 101) in a run that no drop disturbed. Restored, the file is the
  one of round 3.

# T-062: Measure whether the relay's backpressure close (1013) operates

**Source:** `docs/relay.md:201-205`; the reverse close table of the pinned contract
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`); the comment on the SSH
window (`crates/podssh-ssh/src/run.rs` lines 25-29 at `80f20bf`).
**Category:** measurement
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`docs/relay.md` says that the relay closes a forward session with 1013 when 2 MiB wait for a
slow receiver, and also that this check may not operate. The comment on podssh's SSH window
gives another rule: 1 MiB, 1011, and a dropped frame. The right window size depends on which
rule is true.

## Premise

Not measured. Read: `docs/relay.md:190` gives the forward codes `1013` `client receive backlog`
and `target write backlog` (2 MiB queued), read from the relay's source; `docs/relay.md:201-205`
says that no frame is dropped, and that the check reads `bufferedAmount`, which Workers may not
supply. The comment on the SSH window (`crates/podssh-ssh/src/run.rs` lines 25-29 at `80f20bf`)
said that the relay drops a frame when more than 1 MiB waits (`1011 relay backpressure`). That is
the reverse path's row of the contract ("Over 1 MiB queued for a slow receiver. Slow down; the
undelivered frame is dropped.", `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`),
so the comment applied a rule of the reverse path to the forward path.

## Approach

1. A live test, ignored by default, in a new file
   crates/podssh-relay/tests/live_backpressure.rs: a forward session to a target that sends
   much data fast, read at 16 KiB/s, with no SSH window in between. First check with the relay's
   `/trace` that the relay reaches the target: one target of the sandbox reports did not work
   from the relay's edge.
2. Record the close code and reason, the bytes received and the time. 1013
   `client receive backlog` means that the check operates; a slow, complete transfer means TCP
   backpressure through the relay.
3. Stay under the relay's limits: less than 64 MiB in total and 5 minutes. Use a target that the
   operator approves.
4. The other direction (`target write backlog`) needs a slow target; record it as not measured
   when none is at hand.
5. Write the result into the comment on the window (`crates/podssh-ssh/src/run.rs:25-29`) and
   into `docs/relay.md:201-205`. Change the window (512 KiB) only if the result asks for it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test live_backpressure -- --ignored --nocapture   # the live relay
```

The control: the same target, read at full speed, ends with 1000 `target closed` and the full
size, which shows that the target and the path work. The slow run then gives the answer, and
`docs/STATUS.md` records it with the date.

## Correction

2026-10-08, T-024: the comment on the SSH window now gives the forward path's rule that
`docs/relay.md:190` reads from the relay's source: `1013` when 2 MiB wait, and no frame dropped
(`crates/podssh-ssh/src/run.rs:25-28`). The two texts agree now. The question of this entry
stays: whether the relay's check operates at all (it reads `bufferedAmount`,
`docs/relay.md:201-205`).

# T-220: A silent first relay host costs a full dial before the next host is tried (GitHub #30)

**Source:** GitHub #30 (2026-10-08) and its correction (talaria0101: `notes` has four call
sites, not three), each claim read again here on `3ee70dc`. The operator's ruling on Q10
(2026-10-08): three modes, the staggered start by default, and a flag to choose.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podssh tries the relay hosts one at a time. A first host that accepts TCP and then says nothing
costs the full step limit, 20 s, before the second host gets an attempt. During that time, the
user sees nothing.

## Premise

Read on `3ee70dc`, as the issue says: a plain `for` loop over the hosts
(`crates/podssh-relay/src/open.rs:192-194`); `HOST_DEADLINE` 45 s (`:29`), `CONNECT_TIMEOUT`
20 s (`:25`). `notes` is declared at `:180` and `:215`; its four call sites are `:189` (the
round notice), `:193` (into `try_host`), `:201` (a failed host) and `:221` (the token cache). The session
returns with its host at `:197` (the issue says 192). The order of preference is built in
`crates/podssh-relay/src/relay.rs:83-101`. No `FuturesUnordered`, `JoinSet` or `join_all` is in
`podssh-relay` or `podssh-ws`. Measured in the gate (`docs/STATUS.md`, "Faults between podssh
and the relay, measured"): each silent-host fault costs 20 s. The issue calls rule 3 of
`docs/architecture.md` "no option dropped silently"; it is "One outbound connection, never a
listener" (lines 86-88 at `22c3b88`), and the ruling on Q10 allows more than one for a moment.

## Approach

1. `--relay-failover MODE` for `ssh`, `proxy` and `doctor`, and `PODSSH_RELAY_FAILOVER` (the
   flag wins). `staggered`, the default: start the next host when the attempt before it has not
   opened within a delay D, or at once when it fails; the first attempt that opens wins, and of
   two that opened, the earlier in the list. `parallel`: start each host at once; an attempt
   that opens waits at most D for each earlier host that still runs, then the earliest opened
   host wins. `serial`: one at a time, as now, with a 5 s step limit for a host that has a
   successor, and the full limit for the last host.
2. D starts at 2 s. An open includes the relay's dial of the target (`docs/relay.md:69-71`), so
   a slow target also starts the next host. Measure the open times through a proxy in the box,
   and record D in `docs/STATUS.md`.
3. Send a Close to each attempt that is not kept, at once. The relay then frees the target
   socket within 15 s (`docs/design.md:208-210`, `docs/relay.md:186`); the target still sees one
   short connection, because the relay dials it before the upgrade.
4. One mint at a time for each relay deployment (single flight, keyed as T-057 keys the cache),
   against the brake of `docs/relay.md:128`. When the minting attempt is the silent one, the next
   attempt mints at its own host after D.
5. An error that each host would give (`crates/podssh-relay/src/open.rs:57-79`) still stops the
   run, and stops the other attempts.
6. Each attempt keeps its own notes, given to `notes` in the order of the list; the round notice
   (line 186 at `22c3b88`) stays a note of the run. `Failure` keeps each error; `Opened.relay` and the log
   name the host that was kept. tokio's `select!` and `JoinSet` need no new crate and no C.
7. Add the flag to `SSH_FLAGS`, `PROXY_FLAGS` and `DOCTOR_FLAGS`
   (`crates/podssh-cli/src/flags.rs:112-241`, 323-343) and to `ONCE`
   (`crates/podssh-cli/src/ssh/args.rs:61-71`); the variable to VARIABLES and the modes to THE
   RELAY (`crates/podssh-cli/src/man/facts.rs:45-122`, 170-183); both to `docs/relay.md:30-48`.
8. T-059 orders the hosts across runs; this entry shortens the wait in one run. GitHub #25 asks
   for a circuit breaker: retry policy, not overlap.

## Decision

Recommendation: a flag and a variable, and no `-o` keyword: OpenSSH refuses an unknown keyword
in a file that it shares with podssh, and the relay flags already have this form. In `parallel`,
a plain ordered join lost: it waits for a silent first host, which is the fault; a wait of at
most D keeps the order for the hosts that answer.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay   # new unit tests: the start delay, the choice, the closes, one mint
cargo test -p podssh-cli     # the flag, the variable and the manual tables
sh scripts/dev.sh check      # interop-faults: the silent first hosts in each mode
```

In `scripts/interop-faults.sh` (lines 77-87 at `22c3b88`), the two silent-host cases fail over in less than
5 s in `staggered` and `parallel`, and in less than 10 s in `serial`. `scripts/fake-relay.py`
logs each mint and each Close: one mint, and a Close for each session not kept. An unknown mode
exits 64. Planted defect: keep the first attempt that opens, whatever its place; the test with
two attempts that open together fails.

# T-243: The user can choose the cache directory, and no directory is fixed in the code

**Source:** the operator's ruling of 2026-10-08 on the place of the cache: the user's cache
directory is right, "but be aware of non existent or write disallowed dirs, and do not hardcode
anything, and allow users to choose if needed". Read here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

podssh keeps its relay token, the relay's pool of hosts and other private files in a directory
that the user cannot choose, and one candidate is a fixed path (`/dev/shm`). A user whose cache
is on a shared or a full disk, or a sandbox where the usual places do not exist, cannot name
another place.

## Premise

Read on `3ee70dc`: `candidate_dirs` (`crates/podssh-relay/src/cache.rs:61-76`) gives the user's
cache directory (`LOCALAPPDATA` on Windows, else `XDG_CACHE_HOME`, else `HOME/.cache`, absolute
paths only: lines 286-299 at `22c3b88`), then `std::env::temp_dir()` with the user's tag (`:67-68`), then
the fixed `/dev/shm` on Unix (`:69-71`), then `.podssh` in the working directory (lines
62-64). A store falls through each directory that refuses it (`:151-160`). No variable or
flag names a directory. `doctor` probes the same list and names the first that can be written
(`crates/podssh-cli/src/doctor/host.rs:94-120`). VARIABLES and FILES give the list
(`crates/podssh-cli/src/man/facts.rs:105`, 108-113), a test fixes its shape (lines 365-377 at `22c3b88`), and
the module comment repeats it (`crates/podssh-relay/src/cache.rs:4-8`).

## Approach

1. `PODSSH_CACHE_DIR=DIR` names the first candidate. `PODSSH_CACHE_DIR=none` turns the cache
   off: a token is minted on each run, and `doctor` says so. A relative path is refused with a
   note, as `user_cache_dir` ignores one today (lines 289-293).
2. Derive each other candidate from the environment: the user's cache directory, as now; then
   `XDG_RUNTIME_DIR/podssh`, made for each user by the login session, in place of `/dev/shm`;
   then the platform's temporary directory (`std::env::temp_dir`) with the user's tag; then the
   working directory. No path literal stays in `cache.rs`.
3. Probe each as now: a missing directory is made with mode 0700
   (`crates/podssh-relay/src/cache.rs:315-332`), and one that refuses a write is skipped. When the
   directory of `PODSSH_CACHE_DIR` is skipped, say so once on stderr, with the reason.
4. Take the environment as a parameter, as `dial::proxy_from_vars` does
   (`crates/podssh-ws/src/dial.rs:159-173`), so that the tests can set it.
5. `doctor` names the directory in use and the variable that chose it; `status` (T-051) shows
   it; the settings file of T-048 can set it. The session log (T-056) and the failure records
   (T-059) use the same chain.
6. Change in the same commit: VARIABLES and FILES (`crates/podssh-cli/src/man/facts.rs:105`,
   108-113, 122-132), the test of lines 365-377 at `22c3b88`, the comment of `cache.rs`, and the `doctor`
   notes (`crates/podssh-cli/src/man/notes.rs:258-277`).

## Decision

Recommendation: a variable, and no flag. The cache belongs to the user and the host, not to one
command, and a variable also reaches the `podssh proxy` that OpenSSH starts as its
`ProxyCommand`, where a flag would have to go into each configuration line. A flag on `ssh`,
`proxy` and `doctor` lost for that reason. `std::env::temp_dir` gives `/tmp` when `TMPDIR` is
not set. The operator's ruling (2026-10-08): keep it; when `TMPDIR` is not set, resolve a
directory at run time first, and use the fixed fallbacks (`/tmp`, `/dev/shm`) last.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test cache   # new: the order, none, a refused directory, the scan
cargo test -p podssh-cli                  # the VARIABLES and FILES tests
sh scripts/dev.sh check                   # interop-faults: a token in PODSSH_CACHE_DIR
```

With a set environment: `PODSSH_CACHE_DIR` comes first, `none` gives no candidate, and
`XDG_RUNTIME_DIR` comes before the temporary directory. A scan of `cache.rs`, as
`crates/podssh-cli/src/man/facts.rs:330-354` scans source, finds no absolute path literal. In
the gate, the token file goes into a new `PODSSH_CACHE_DIR`; with a plain file there, the run
still exits 0 and names the refusal. Planted defect: put `/dev/shm` back; the scan fails.

# T-253: The relay's egress reaches no IPv6 host

**Source:** measured on 2026-10-08 while T-007 was done (GitHub #2): the
live test `ipv6_the_relay_takes_the_bare_literal`
(`crates/podssh-relay/tests/live.rs`) and probes of the live relay.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

No IPv6 host can be reached through the relay. podssh sends the address,
the relay takes it and upgrades the session, and then closes the session at
once with `1011 target closed before sending anything`. So an IPv6-only
host, and `-6`, cannot work through the relay.

## Premise

Measured on 2026-10-08 against `tcp.ssh.relay.ajam.dev` (version
`2026-10-03-r2`), with a token minted for the run:

- `/connect/2001:4860:4860::8888/853` (the bare address), with `%5B` and
  `%5D`, with raw brackets, and with `%3A` for each colon: each upgrades
  (101), and each session closes with that 1011 when the client sends its
  first bytes. `/trace?target=[2001:4860:4860::8888]:853` says
  `dialed_literal: true`, `address_family: 6`, `road: vpc`.
- The same host over IPv4 (`/connect/8.8.8.8/853`, and `dns.google` with
  `?family=4`): a TLS handshake with `dns.google` completes through the
  session, with its certificate verified.
- `www.google.com:80` with `?family=4`: an HTTP answer. With `?family=6`:
  101, then the same 1011. With `?family=6&path=direct`: `502 Bad Gateway`.
  `ipv6.google.com:80`, which has only an IPv6 address: 101, then 1011.

So the VPC road accepts an IPv6 dial and fails it at once, and the direct
road refuses it.

## Approach

1. The relay's operator gives the egress an IPv6 route, or makes the relay
   refuse an IPv6 target before the upgrade (a `502` with the reason), so
   that a client learns it at once.
2. Then in podssh: run the live test below and assert bytes from the
   target; update the IPv6 note of the manual
   (`crates/podssh-cli/src/man/notes.rs`), `docs/relay.md`, `README.md` and
   `docs/STATUS.md`. podssh already says what happened
   (`podssh_relay::relay::ipv6_note`).

## Prove

```sh
cargo test -p podssh-relay --test live -- --ignored ipv6 --nocapture
```

The test prints "bytes came back from the IPv6 host".

## Blocker

The relay's operator: the egress of the relay is work of the relay project.
The operator ruled on 2026-10-08 that the relay stays separate
(`docs/decisions.md`).

# T-255: The relay's side drops reverse sockets at random, with no Close

**Source:** the runs of T-061 on 2026-10-09 (`crates/podssh-relay/tests/reverse_idle_live.rs`).
**Category:** measurement
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

In 6 of 12 runs of 240 s, the relay's side ended a reverse socket's connection with no WebSocket
Close, at 24 s to 212 s, also while the session carried a byte each way every 60 s. An operator's
session then ends with exit 69 (`podssh operator`, `podssh ssh node://NAME`), and a node connects
again. It is not known how often this happens, whether forward sessions see it too, and whether
the cause is this machine's path or the relay.

## Premise

Measured on 2026-10-09 from this machine, 00:27 to 01:11 UTC, with no proxy and the relay's own
certificate (Google Trust Services WE1, for `ajam.dev`), by the command of T-061: the node's socket
dropped 5 times, the operator's 3 times, once both at the same moment. The relay saw each drop of
one socket: it sent the operator `1011 node disconnected`, or the node a `close` of the session
with no reason. Each drop read as the end of the TCP stream with no Close frame
(`SessionError::ClosedWithoutClose`). Runs with no frame at all, with Pings and with payload each
had drops, so the traffic does not cause them.

Read: on the forward path, keepalives every 60 s kept one session for 602 s
(`docs/STATUS.md:114`). That is one run, before 2026-10-09.

## Approach

1. A live test, ignored by default, in a new file crates/podssh-relay/tests/reverse_drops_live.rs:
   four pairs, each with a node's socket and an operator's session, held for 15 minutes with a Ping
   from each end every 10 s, as the runners do. Record the UTC time of each drop, the socket, and
   what the relay said to the other end. Stop each pair at the end.
2. Run it from this machine and, at the same time, from a GitHub Actions runner (a job started by
   hand with `workflow_dispatch`), so that two networks see the same relay. Drops at the same
   moments on both sides point to the relay (a restart of its code or of its objects); drops on one
   side only point to that side's path.
3. A forward session in the same run, for comparison, when one of the allowed targets keeps a quiet
   TCP connection open; else record it as not measured.
4. Record the rate and the place in `docs/relay.md` ("Open questions") and `docs/STATUS.md`. If the
   cause is the relay, write a `## Blocker` that names the relay's operator, with the evidence.
5. podssh's part, whatever the cause: the message of `podssh operator` for a drop says that the link
   ended with no Close, and that a new session may work. A node connects again (T-079). Resumable
   sessions (M6) carry a session over a drop.

## Decision

2026-10-09, before the paired runs:

1. The pairs' holders run on worker threads; the forward holder runs on the test's own task, as
   the notes of the forward opener are not `Send`.
2. A drop that the run plants is its check: pair 0 first drops its operator's socket with no Close,
   and its node must see the relay's `close` of the session within 15 s, or the run fails.
3. A drop is counted for each end that saw its connection end with no Close, after up to 5 s for
   the other end: the relay's `1011` can reach the operator before the node's own end is read.
4. The forward session goes to GitHub's SSH port, sends an SSH identification line, then stays
   quiet with a Ping every 10 s. GitHub's limit for a login and the relay's idle cut end it with a
   Close; those are ends, not drops, and the session is opened again.
5. The workflow `.github/workflows/reverse-drops.yml` runs only by hand, and takes the end time as
   an input, through the environment. Both runs end at the same time; the overlap is the
   comparison.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_drops_live -- --ignored --nocapture   # live, about 16 min
```

Each drop is printed with its UTC time; the run here and the run on the runner are compared by
time. A drop that the relay saw is told apart from one that it did not by the other end's frame.

## Blocker

The relay's operator: the drops are on the relay's side, and the relay is its own project (the
operator's ruling of 2026-10-08, `docs/decisions.md`). The evidence, measured on 2026-10-09:

- Two networks, the same end time, 01:31 to 02:05:38 UTC (`cargo test -p podssh-relay --features pair --test reverse_drops_live -- --ignored --nocapture`, here and in the
  workflow `.github/workflows/reverse-drops.yml`, run 37870123203): from this machine, 5 sessions
  over 2.3 hours of sessions and no drop; from a GitHub Actions runner, 6 sessions over 2.3 hours
  and one drop, at 02:01:01.872Z, when both sockets of one pair ended at once with no Close. This
  machine saw nothing at that moment, so it was not a restart of the whole relay. The planted drop
  of each run reached the node as the relay's `close` of the session.
- Before that, from this machine (T-061 and the trial of this entry, 00:27 to 01:28 UTC): 7 of the
  sessions held ended by a drop, in about 0.8 hour of sessions: about 9 an hour. So the drops come
  in bursts.
- Two kinds: one socket ends with no Close while the relay lives on, as it then tells the other end
  (`1011 node disconnected`, or a `close` of the session), 6 times; or both sockets of one pair end
  at once, as when the relay's object for the pair ends, 2 times (once from each network).
- The forward path, held beside them from both networks: 25 sessions over 1.2 hours, no drop; 22
  ended by the relay's idle cut at 180.3 s to 180.9 s, which Pings do not reset, and one by the
  relay's `1011 write failed: Network connection lost.` toward GitHub after 5.2 s.

What the relay's operator can do: read the relay's logs for the ends of reverse sockets in those
windows; send a Close (`1001` or `1012`) before a restart that the relay plans, so that a client
can tell it from a broken link; and keep reverse sockets across a restart of the pair's object,
where the platform allows it.

podssh's part is done (commit "A dropped link of the reverse road is named as one"): `podssh
operator` and `podssh ssh node://NAME` say that the link ended with no Close, or that the node's
link ended, and that a new session may work (`crates/podssh-cli/src/pairs.rs`, `session_end`,
with three unit tests, and a plant of the old wording that fails the first); a node connects again
by itself (T-079); resumable sessions (M6) carry a session over a drop.
