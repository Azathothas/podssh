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
   with the port when it is not 443. `same_deployment` (`crates/podssh-relay/src/pool.rs:148-153`)
   is the one rule that already decides where a token may go.
2. Use the key of the host in use at each place: the load and the store through `MintContext`
   (`crates/podssh-relay/src/token.rs` lines 84-112 at `2da855f`), the removal after a 403
   (`crates/podssh-relay/src/open.rs:389-398`), and the token check of `doctor`
   (`crates/podssh-cli/src/doctor/relay_checks.rs` lines 142-165 at `2da855f`).
3. Store the minting host in the cache entry (`crates/podssh-relay/src/cache.rs:47-56`), with a
   serde default for old files. `doctor` says "a cached token minted at HOST (not shown)". Use
   an old entry only under the default key, where it was right.
4. Change in the same commit: `docs/relay.md` (lines 43-45 at `2da855f`), the comments at `relay.rs:36-37` and
   `token.rs:84-86`, the FILES text (`crates/podssh-cli/src/man/facts.rs` lines 124-135 at `332ee58`), and
   `docs/STATUS.md`.

## Decision

Recommendation: key by deployment. One token serves the hosts of the default deployment (a
pool host accepted the token of the default host: `docs/STATUS.md`, "`podssh proxy`, measured
live"), and no token goes to another deployment. The exact minting host lost: each pool host
would mint its own token, against the brake of 120 attempts a minute (`docs/relay.md:476`).
The decision said "one machine has one cached token"; on 2026-10-08 the operator ruled
"one for each relay deployment" (`docs/decisions.md:98`).

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

**Source:** `crates/podssh-cli/src/positionals.rs`, lines 56-62 at `24f3e2a` (the subcommands that the parser
declares); `docs/relay.md`, lines 296-302 at `24f3e2a`; the tester of sandbox A, who used `curl` and a minted token
on `/trace` (`report-podssh-sandbox-KTM-2026-10-08.txt`, outside the repository).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

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
(`docs/relay.md:530-531`). The `health` function of `doctor`
(`crates/podssh-cli/src/doctor/relay_checks.rs:100-117`) already makes a verified `/health`
request; `crates/podssh-relay/src/pool.rs:182-208` fetches `/relays.json`. `https_get` sends no
token header (`crates/podssh-ws/src/client.rs:280-291`); `https_request` takes headers (lines
282-303).

## Approach

1. `relay status`: `/health` on each host of the list. Move `health` into `podssh-relay`, so
   `doctor` and `relay` share one path, and podbox can use it.
2. `relay info [HOST PORT]`: `/relays.json?host=&port=`, the pool and the limits, read with
   `crates/podssh-relay/src/pool.rs:157-178`.
3. `relay spec`: the `/health` version and `/llms-full.txt`, checked against the pinned facts by
   `verdict_from` (`crates/podssh-probe/src/relay_facts.rs:345-359`), or `--document FILE`.
   This is T-060.
4. `relay trace HOST PORT`: `/trace` with `banner=1`, the token in the header and never in the
   URL (`docs/relay.md:461-463`). Check HOST with `relay::check_host`
   (`crates/podssh-ws/src/names.rs:10-32`), so no text can add a query parameter.
5. `pair` and `revoke`: refuse by name, and name M4 (T-078, T-083).
6. Flags as for `doctor` (`--relay-host HOSTS`, `--relay-addr`, `--ca-file`), and `--json`
   (T-049). Each request has the 10 s limit of `doctor`
   (`crates/podssh-cli/src/doctor/relay_checks.rs:26`), and the run has a limit too.
7. Remove the owner row (`crates/podssh-cli/src/flags.rs` line 442 at `af0a163`); change `DISPATCHED`, `usage_tail`
   (`crates/podssh-cli/src/help.rs`, line 237 at `24f3e2a`), the notes, `docs/relay.md`, lines 296-302 at `24f3e2a`, and
   `docs/STATUS.md`. `dispatch.rs` has 448 lines: put the verb in its own module.

## Decision

Recommendation: remove the `--timeout` and `--jsonl` rows of `relay`
(`crates/podssh-cli/src/flags/relay.rs:9-103`), and bound each request in the code, as `doctor`
does. With the row, the gate of `crates/podssh-cli/src/dispatch.rs:345-366` stops
`podssh relay status` in each script that leaves `--timeout` out. Keeping the gate lost for that
reason: the command is bounded anyway.

Taken, with these calls made in the work (2026-10-11). The `/health` request is
`podssh_relay::health` now: it returns the facts (the version, the edge, the pause, the reverse
road, the TLS version, how the connection was made, the `Date`), `Health::line` words them, and
`doctor` adds its note of the measured version and its hint about the clock. `status` asks the
hosts one after the other, as `doctor` does: one outbound connection at a time (rule 2). It exits
0 when one host answers, as the pool fails over, and 69 when none does. `info` and `trace` use the
first host, as `pair` does. `trace` exits 0 when the relay ran the trace, whatever its verdict, 69
when the relay will not dial the target, and 77 when it refuses the token: on the relay's VPC road
a closed port connects too (measured below), so the connection says nothing, and a target that
sends nothing first (HTTP) is reachable and silent. An exit by the verdict lost for that reason.
The answer of `/trace` holds the caller's address and place; neither the lines nor the JSON show
them. The banner comes from any target, so it is cleaned to one line. With `--json`, each answer
is one object, as T-049 decides.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay                     # new: refusals and bounds, offline
sh scripts/dev.sh check                                   # interop: the stand-in relay
cargo test -p podssh-cli --test relay_live -- --ignored   # the live relay, on request
```

`scripts/fake-relay.py` (it serves `/health` and the mint: `:152-161`) gets `/relays.json`,
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

2026-10-11, measured on `24f3e2a` with `PODSSH_OFFLINE=1`: `relay status` exits 70 ("'relay
status' with no NAME, the relay's own state, is not implemented yet"), `relay info` 70, and
`relay trace github.com 22` 64 ("one word too many"), as a subcommand took one NAME; `--timeout`
is an unknown flag (64). `spec` is T-060's and done (step 3), and the tests of `spec` read
`--document`, so the stand-in needs no `/llms-full.txt`. `https_with_token` already sends a token
in a header (`crates/podssh-ws/src/client.rs:309-331`), for the pairing calls. On the live relay,
2026-10-11: `/trace` alone answers without a token with the caller's address, city, coordinates
and network; a target trace answers `target` with `ok`, `road`, `dialed`, `address_family`,
`connect_ms`, `first_byte_ms`, `bytes_seen`, `verdict` and `banner`, or `error` alone for a
target in a blocked range or a name with no address; `github.com:23` gives `ok: true`,
`connect_ms` 4 and the verdict `silent-or-unreachable`.

## Done

Done on 2026-10-11. `podssh relay status` with no NAME asks each relay host for its `/health`
(`crates/podssh-relay/src/health.rs`, which `doctor` now calls too), `relay info [HOST PORT]`
reads the first host's `/relays.json`, and `relay trace HOST PORT` has the first host dial a
target and read its first line, the token in `X-Relay-Token` (`crates/podssh-cli/src/relay_diag.rs`
and `relay_diag_text.rs`). `--json` gives each answer as one object. A bad target, a word too many
and a misplaced `--json` exit 64 before any connection; `PODSSH_OFFLINE` exits 69. The flags, the
help, the manual (`crates/podssh-cli/src/man/notes_relay.rs`, an example, the rows of EXIT STATUS),
`docs/cli.md`, `docs/relay.md` and `AGENTS.md` follow. `scripts/fake-relay.py` serves
`/relays.json` and `/trace` in the live relay's shapes, and refuses a target trace without the
token in its header (403) or with a token in the URL (400).

Prove, on Windows: `cargo test -p podssh-cli --test relay`, 8 passed through the stand-in relay
(Python and openssl are here): the refusals, with no connection to a relay host that counts them;
`PODSSH_OFFLINE`; `status` with a host that answers and one that is down (0), and with only the
one that is down (69); its JSON; `info` with the pool, the limits and the URL for a target, and
its JSON; `trace` of a target's first line, as two words and as one, and its JSON with no field of
the caller; 69 for a target that the stand-in cannot dial; 77 for a token that it refuses, which
is never shown. The unit tests of the lines (`relay_diag_text.rs`, on the live relay's shape) and
of `Health::line`. Planted, each caught by its assertion: the token header left out (the stand-in
answers 403), `status` that needs each host to answer, the caller's fields in the JSON of `trace`.
The test of `crates/podssh-cli/tests/node.rs` that wanted exit 70 now wants 69 offline. Live,
`cargo test -p podssh-cli --test relay_live -- --ignored`, 3 passed: the default relay's
`/health`, its pool for `github.com:22`, GitHub's banner through it, and 69 for `10.0.0.1:22`. The
suites of `podssh-cli` (524 passed) and `podssh-relay` with all features (223 passed). In the build
image, `scripts/interop.sh` 285 passed, 0 failed, with the new `scripts/interop-relay.sh`:
`status`, `info` and `trace` through the stand-in relay, OpenSSH's banner by a trace, and 64 for a
HOST of `a&b`.

# T-059: A relay host that failed recently is tried last, also in the next run

**Source:** GitHub #25 (a circuit breaker,
`ImKKingshuk/USBoverSSH:usboverssh/src/circuit_breaker.rs`, read in the report, not verified
here; and talaria's comment: one drop in 180 short sessions). The cost of a silent host:
`docs/STATUS.md`, "Faults between podssh and the relay, measured".
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Each run tries the relay hosts in the same order. When the first host is down or silent, each
run waits for it before it tries the next host, up to 20 s for one step. A short process, such
as a `ProxyCommand` for each connection, pays this wait in each run.

## Premise

Read: `open` tries the hosts in the order of the list in each round
(`crates/podssh-relay/src/open.rs:241-291`), and keeps nothing between runs: a failure is a
note, and an entry of `Failure`. The limits are 20 s for each step and 45 s for each host (lines
25-29). Measured in the gate (`docs/STATUS.md`): a host that completes TLS and then says
nothing, and a host that does not start TLS, each cost the 20 s limit before the failover.

## Approach

1. After a host fails with an error that another host can repair (`another_host_may_help`,
   `crates/podssh-relay/src/open.rs:71-93`), write a record (host, time, class) into a private
   file `relay-failures-KEY.json` with `cache::store_file`
   (`crates/podssh-relay/src/cache.rs:151-185`). Remove the record when the host succeeds.
2. At the start of `open` (`crates/podssh-relay/src/open.rs:212-298`), move each host whose
   record is younger than a fixed window (10 min) to the end of the list, in its old order.
   Never remove a host: each host is still tried.
3. Record no error that each host would give (a policy refusal, a bad token in the
   environment): it says nothing about the host.
4. Print one note for each moved host: "trying HOST last: it failed N s ago (REASON)".
5. Ignore a record with a time in the future (a clock that moved).
6. `doctor` and `status` (T-051) show the records. State the window in THE RELAY section of the
   manual (`crates/podssh-cli/src/man/facts.rs:349-362`) and in `docs/relay.md:107-152`.
7. This is retry policy across runs. T-220 shortens the wait inside one run; the two work
   together.

## Decision

Recommendation: reorder a list from `--relay-host` or `PODSSH_RELAY` too. Its order is a
preference, the record expires, and the note says what changed. Both testers set their relay
hosts by hand, so they gain most. Reordering only the default list lost for that reason.

2026-10-12, the calls made in the work:

- The failover of T-220 came after this entry: by default a silent first
  host now costs 2 s, not 20 s, as the next host starts after 2 s, and its
  attempt ends unfinished when the next one opens. So a host that said
  nothing while a host after it opened is recorded too (`failover::race`
  reports it), as one that failed is; without that, the record would save
  nothing in the default mode. A host that answered and lost the race is
  not recorded.
- One file, `relay-failures.json`, holds each host's entry, not one file
  for each deployment: a host's name is its key, and one file is read
  once at the start of a run. Two runs that write it at the same time
  keep the last one's: an entry lost costs one wait, no more.
- A 502 records nothing: the relay could not reach the target, which says
  nothing of the host; nor does an error that each host would give
  (`another_host_may_help`). The reason is a few words of podssh's own
  ("no answer within 45 s", "it answered 503", "TLS handshake timed out
  after 5 s"), never a target.
- A list of one host is never reordered, and gets no note. A record that
  cannot be written is ignored: it is a hint.
- `status` gives `relay_failures` (host, `ago_s`, reason), and `doctor` a
  line `failed relays` under "this host".
- The checks of T-220 in `scripts/interop-faults.sh` get a cache of their
  own each: in one cache, the record would move their silent first host
  last, and they would no longer test the mode.

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

## Done

2026-10-12. The record in `crates/podssh-relay/src/failures.rs:1-316`: its
file and window at `crates/podssh-relay/src/failures.rs:26-30`, its entries
at `crates/podssh-relay/src/failures.rs:114-220`, the order of a run and its
notes at `crates/podssh-relay/src/failures.rs:235-255`, and the reason of a
failure at `crates/podssh-relay/src/failures.rs:289-309`. `open` orders
the hosts at `crates/podssh-relay/src/open.rs:221-227` and keeps the record
after each round at `crates/podssh-relay/src/open.rs:266-273`; the race
gives the silent hosts at `crates/podssh-relay/src/failover.rs:245-248`.
`podssh status` at `crates/podssh-cli/src/status.rs:125-129`, `podssh
doctor` at `crates/podssh-cli/src/doctor/mod.rs:99-109`, THE RELAY in the
manual at `crates/podssh-cli/src/man/facts/failed.rs:11-28`, and
`docs/relay.md` and `docs/cli.md`.

The unit tests of `crates/podssh-relay/src/failures_tests.rs`, 5: a host
that failed 30 s ago goes last with its note, two keep their order, all
failed is the list as it was, and one alone is not moved; the window, and
a record from the future ignored; a round records a failure, clears the
host that opened and drops a stale entry, and writes nothing when nothing
changed; the reasons, and none for a 502, a policy, a token that each host
refuses, a proxy that wants credentials and the offline switch; the file
in a directory of the cache, and one that does not read is none. In
`crates/podssh-relay/tests/failover.rs`, on tokio's paused clock: a silent
host before the one kept is silent in `staggered` and in `parallel`, and
not one after it, one that failed, or one of a round with none kept.
Planted defect: an order that ignores the
record; the test of the order failed. The plant of the gate's check waits
for T-251, as each gate run over 5 minutes does. In the build image, `scripts/interop.sh`
with a debug build: 415 passed, 2 failed, the two of `limits`, whose
bound a debug build passes (as before this change); the new
`faults.recorded.reorder`: a run through a silent first host in `serial`,
then one that tried it last with its note and took 0 s;
`faults.recorded.still_tried`: a host that failed, alone in its list, is
tried; the checks of T-220, each with its cache, as before. Here, clippy of `podssh-relay` and `podssh-cli`: no warning; the
suites of `podssh-relay`, `podssh-cli` and `podssh-ssh`: 1034 passed, 0
failed, 45 ignored (the live tests).

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
`scripts/check-relay-spec.py` live, with three plants (`.github/workflows/build.yml:192-222`).
The gate runs the crate's tests with no C compiler (`scripts/gate.sh:163-180`). The build image
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
`crates/podssh-probe/tests/relay_facts.rs:109-113`) exits 1 and names the fact
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
   (`crates/podssh-ws/src/session.rs:235-239`), which sends a real text frame; since T-071,
   `Leg::send_control` over `WsSocket` sends one too.
2. Three runs of 240 s: (a) no payload and no pings; (b) WebSocket pings every 20 s from both
   ends; (c) one byte of payload every 60 s. For each socket, record the time, the code and the
   reason of the close, or "open at 240 s".
3. At 240 s, send one byte each way: a hibernated socket can stay open and not deliver.
4. Stop the pair at the end (`POST /v1/stop/NAME`). Tokens go only in headers; never print one,
   and above all not the `stop_token` (`docs/reverse.md:514-523`).
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
   (`docs/reverse.md:39-49`), which would hide run (a).
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

**Source:** `docs/relay.md:554-566`; the reverse close table of the pinned contract
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`); the comment on the SSH
window (`crates/podssh-ssh/src/run.rs` lines 25-29 at `80f20bf`).
**Category:** measurement
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

`docs/relay.md` says that the relay closes a forward session with 1013 when 2 MiB wait for a
slow receiver, and also that this check may not operate. The comment on podssh's SSH window
gives another rule: 1 MiB, 1011, and a dropped frame. The right window size depends on which
rule is true.

## Premise

Not measured. Read: `docs/relay.md:543` gives the forward codes `1013` `client receive backlog`
and `target write backlog` (2 MiB queued), read from the relay's source; `docs/relay.md:554-566`
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
5. Write the result into the comment on the window (`crates/podssh-ssh/src/run.rs:26-30`) and
   into `docs/relay.md:554-566`. Change the window (512 KiB) only if the result asks for it.

## Decision

2026-10-31, after the runs:

1. The window stays at 512 KiB (Approach, item 5). The result takes away
   the reason that the comment gave, a `1013` at 2 MiB; but the window is
   now the only bound on what the relay holds for an SSH session, and a
   relay whose check operated as its document says would close a session
   whose window is 2 MiB or more. Lost: 2 MiB, russh's default, faster on a
   long path and at the edge of the document's limit; a window that grows
   with the path's delay, which T-157's measurement of the speed comes
   before.
2. The stand-in relay's mode is `backlog:BYTES:RATE`, a real queue toward a
   client slower than the target, so that it checks the window against the
   relay's check as well as podssh's handling. Lost: `close:BYTES:1013` with
   the client's reason, which checks the handling only.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test live_backpressure -- --ignored --nocapture   # the live relay
```

The control: the same target, read at full speed, ends with 1000 `target closed` and the full
size, which shows that the target and the path work. The slow run then gives the answer, and
`docs/STATUS.md` records it with the date.

## Correction

2026-10-08, T-024: the comment on the SSH window now gives the forward path's rule that
`docs/relay.md:543` reads from the relay's source: `1013` when 2 MiB wait, and no frame dropped
(`crates/podssh-ssh/src/run.rs:26-29`). The two texts agree now. The question of this entry
stays: whether the relay's check operates at all (it reads `bufferedAmount`,
`docs/relay.md:554-566`).

2026-10-31. The blocker cleared: the operator made the relay's own loop the
target (Q42, `docs/decisions.md`). The target of item 1 is the relay
itself: a forward session to `tcp.ssh.relay.ajam.dev:443` that carries,
inside its TLS, the operator's leg of a pair of the reverse road, whose node
is `podssh node --plain` in front of a local source of 48 MiB; the outer
client reads at 16 KiB/s. `podssh relay trace tcp.ssh.relay.ajam.dev 443`
shows first that the relay dials itself. An outer 1013 means that the
forward check operates; an inner `1011 relay backpressure` of the reverse
road, or a slow and complete transfer, means that the forward road pushes
back through TCP. And podssh's own handling, against the stand-in relay: a
mode `backlog:BYTES` of `scripts/fake-relay.py`, which closes with 1013 once
that many bytes wait, shows the client's link lost and never tried again
(`crates/podssh-ssh/src/retry.rs`).

## Done

2026-10-31. The relay's check of a slow client does not operate; T-336
holds the relay's part. The live test is
`crates/podssh-relay/tests/live_backpressure.rs`: a pair whose node takes
its bytes from a local source; the operator's leg of the pair reaches the
relay through a CONNECT proxy of the test, whose upstream is a forward
session to the relay's own host and port 443, read at full speed (the
control) or at 16 KiB/s for 90 s, with the bytes that the node took
counted. `podssh relay trace tcp.ssh.relay.ajam.dev 443` showed first that
the relay dials itself (road `vpc`, 104.21.39.2). The operator ruled
during the work that the relay is theirs to use as much as needed
(`docs/decisions.md`), so it ran three times (`cargo test -p podssh-relay
--features pair --test live_backpressure -- --ignored --nocapture`, 108 s
each): twice from a cloud container, through its egress proxy, and once
from GitHub Actions, with no proxy (`.github/workflows/relay-live.yml`, run
41157016178).

- The control, 8 MiB: each byte reached the operator; the inner session
  ended `1000 close`, the outer `1000 target closed`, in 12.1 s to 13.4 s.
- The slow client, 24 MiB and then 48 MiB offered: no Close came in 90 s,
  neither the forward road's `1013` nor the reverse road's `1011`; the
  client read 1459616 to 1460244 bytes (15.8 KiB/s). The runs that counted
  saw the node give each of the 48 MiB within 15 s, from both networks:
  48872032 and 48871404 bytes more than the client read waited in the relay
  or its edge.
- podssh's handling: the stand-in relay's mode `backlog:BYTES:RATE`
  (`scripts/fake-relay.py`, its shaper moved to `scripts/fake_shape.py` to
  keep the file under 500 lines) sends at RATE from a queue with no bound
  and closes `1013 client receive backlog` once more than BYTES wait. Two
  cases of `crates/podssh-cli/tests/faults.rs` (`cargo test -p podssh-cli
  --test faults -- --ignored --test-threads 1 a_backlog the_window`, 2 of 2
  in 16 s): the close in the handshake ends the run with 255, names the
  close and what makes it, and is tried on no second host; and at
  256 KiB/s the window keeps what waits under 2 MiB, 4 MB whole. Each
  failed on its plant: 1013 out of the list that is never tried again (a
  try on the next relay host), and a window of 4 MiB (a `1013`, exit 255).
  The same two checks against OpenSSH are `faults.backlog` and
  `faults.window` of `scripts/interop-faults.sh`
  (`scripts/interop-baseline.txt`): both passed in the gate at `b1f75c9`
  (run 41158061448).
- The remedy of a `1013 client receive backlog` says what makes it, in
  place of `podssh doctor` (`crates/podssh-ws/src/session.rs`, with its
  unit test).
- The comment on the window (`crates/podssh-ssh/src/run.rs:26-30`),
  `docs/relay.md` ("Backpressure") and the limits of `docs/architecture.md`
  give the result; `docs/STATUS.md` records it.
- Not measured: the other direction (`target write backlog`), as no slow
  target was at hand (Approach, item 4).

# T-220: A silent first relay host costs a full dial before the next host is tried (GitHub #30)

**Source:** GitHub #30 (2026-10-08) and its correction (talaria0101: `notes` has four call
sites, not three), each claim read again here on `3ee70dc`. The operator's ruling on Q10
(2026-10-08): three modes, the staggered start by default, and a flag to choose.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh tries the relay hosts one at a time. A first host that accepts TCP and then says nothing
costs the full step limit, 20 s, before the second host gets an attempt. During that time, the
user sees nothing.

## Premise

Read, at `3214fa1`, as the issue says on `3ee70dc`: a plain `for` loop over the hosts
(`crates/podssh-relay/src/open.rs`, lines 192-194); `HOST_DEADLINE` 45 s (line 29),
`CONNECT_TIMEOUT` 20 s (line 25). `notes` is declared at line 180 and line 215; its four call
sites are line 189 (the round notice), line 193 (into `try_host`), line 201 (a failed host) and
line 221 (the token cache). The session returns with its host at line 197 (the issue says 192).
The order of preference is built in `crates/podssh-relay/src/relay.rs:107-125`. No
`FuturesUnordered`, `JoinSet` or `join_all` is in `podssh-relay` or `podssh-ws`. Measured in the gate (`docs/STATUS.md`, "Faults between podssh
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
2. D starts at 2 s. An open includes the relay's dial of the target (`docs/relay.md:362-364`), so
   a slow target also starts the next host. Measure the open times through a proxy in the box,
   and record D in `docs/STATUS.md`.
3. Send a Close to each attempt that is not kept, at once. The relay then frees the target
   socket within 15 s (`docs/design.md:659-661`, `docs/relay.md:539`); the target still sees one
   short connection, because the relay dials it before the upgrade.
4. One mint at a time for each relay deployment (single flight, keyed as T-057 keys the cache),
   against the brake of `docs/relay.md:476`. When the minting attempt is the silent one, the next
   attempt mints at its own host after D.
5. An error that each host would give (`crates/podssh-relay/src/open.rs:71-93`) still stops the
   run, and stops the other attempts.
6. Each attempt keeps its own notes, given to `notes` in the order of the list; the round notice
   (line 186 at `22c3b88`) stays a note of the run. `Failure` keeps each error; `Opened.relay` and the log
   name the host that was kept. tokio's `select!` and `JoinSet` need no new crate and no C.
7. Add the flag to `SSH_FLAGS`, `PROXY_FLAGS` and `DOCTOR_FLAGS`
   (`crates/podssh-cli/src/flags.rs:116-291`, 323-343) and to `ONCE`
   (`crates/podssh-cli/src/ssh/args.rs:183-222`); the variable to VARIABLES and the modes to THE
   RELAY (`crates/podssh-cli/src/man/facts.rs:46-300`, 170-183); both to `docs/relay.md:107-152`.
8. T-059 orders the hosts across runs; this entry shortens the wait in one run. GitHub #25 asks
   for a circuit breaker: retry policy, not overlap.

## Decision

Recommendation: a flag and a variable, and no `-o` keyword: OpenSSH refuses an unknown keyword
in a file that it shares with podssh, and the relay flags already have this form. In `parallel`,
a plain ordered join lost: it waits for a silent first host, which is the fault; a wait of at
most D keeps the order for the hosts that answer.

Taken, with these calls made in the work (2026-10-11). The scheduler is
`crates/podssh-relay/src/failover.rs`, generic over an attempt, so that its tests run attempts
that open, fail or say nothing on tokio's paused clock; `open` gives it the relay's attempts,
each a task of a `JoinSet` that owns its host and borrows nothing of the run. Of attempts that
ended in the same turn, the earliest in the list is kept. In `parallel` the wait for the hosts
before the first that opened is one `STAGGER` in all, not one for each host. An error that each
host would give also dismisses a session that opened in its turn, and it is the last error of
the run, which the exit code reads. The mint's turn is a lock for each key of the cache, held
while the token is read or minted. `ssh`, `proxy` and `doctor` take the flag; `chat`, `pipe`
and the other verbs read the variable. The blocking facade keeps the default, `staggered`, so
that no embedder's `Config` changes. The flag tables of the relay's own verbs moved to
`crates/podssh-cli/src/flags/relay.rs`, which keeps `flags.rs` within 500 lines. The stand-in
relay counts mints and Closes on stdout, and opens slowly with `slowopen:MS`, so that in
`parallel` the earlier host opens last and the later one is always the session closed.

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

## Done

2026-10-11. `--relay-failover MODE` and `PODSSH_RELAY_FAILOVER`: `staggered`, the default,
`parallel` and `serial`, for `ssh`, `proxy` and `doctor`; the variable for each verb that opens
the relay (`crates/podssh-cli/src/relay_settings.rs`). The scheduler is
`crates/podssh-relay/src/failover.rs`, which `open` runs in each round; one token is minted at a
time for each deployment, and each session that opened and is not kept gets a Close at once.
THE RELAY and VARIABLES of the manual and `docs/relay.md` describe the modes.
- `cargo test -p podssh-relay --test failover`: 11 passed, on the paused clock: the next host
  2 s after a silent one, or at once after a failure; the first that opens kept, and of two that
  opened in one turn the earlier in the list; the wait of `parallel` for an earlier host, and its
  end after 2 s; `serial` one host at a time; an error that each host would give ends the round,
  and no host starts after it; the notes in the order of the list; one mint at a time for each
  deployment. Planted: keep the first attempt that opens, wherever it is in the list; the test of
  two that open together failed, and so did the wait of `parallel`.
- `cargo test -p podssh-relay -p podssh-cli`: 746 passed, 0 failed, 45 ignored. A bad
  `PODSSH_RELAY_FAILOVER` exits 78 and names the variable, for `proxy`, `ssh` and `doctor`, and a
  bad `--relay-failover` exits 64 (`crates/podssh-cli/tests/proxy.rs`). Clippy with all
  features; `podssh-relay` checks on Rust 1.85.
- In the build image, the step `release`: interop 308 passed, 0 failed, and faults 32 of 32 at its
  floor. A first host that says nothing after TLS, or never starts TLS, gave the session through
  the next host in 2 s with `staggered` and with `parallel`, and in 5 s with `serial` (20 s each
  before). Two hosts of one deployment in `parallel`, the first opening 500 ms after the second,
  minted one token, kept the first host, and closed the second's session.
- The stagger: with `podssh ping --count 3` from this host to the live relay, each of four hosts
  opened (TCP, TLS, and the upgrade to `github.com:22`) in 179 to 791 ms; in the Podman box,
  through its proxy (`sh scripts/test_in_box.sh`, whose check now runs `podssh ping`, with the
  binary of CI at `3214fa1`), in 102 to 437 ms. A host that answers opens well within the stagger
  of 2 s, so it stays: a silent host costs 2 s, and a host that answers no host after it. The box's
  check gave 9 ok, 0 FAIL, 1 skip (OpenSSH with no user entry, as before), and its doctor 30 ok.

# T-243: The user can choose the cache directory, and no directory is fixed in the code

**Source:** the operator's ruling of 2026-10-08 on the place of the cache: the user's cache
directory is right, "but be aware of non existent or write disallowed dirs, and do not hardcode
anything, and allow users to choose if needed". Read here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

podssh keeps its relay token, the relay's pool of hosts and other private files in a directory
that the user cannot choose, and one candidate is a fixed path (`/dev/shm`). A user whose cache
is on a shared or a full disk, or a sandbox where the usual places do not exist, cannot name
another place.

## Premise

Read on `3ee70dc`: `candidate_dirs` (`crates/podssh-relay/src/cache.rs`, lines 61-76 at `4dd52f8`)
gives the user's
cache directory (`LOCALAPPDATA` on Windows, else `XDG_CACHE_HOME`, else `HOME/.cache`, absolute
paths only: lines 286-299 at `22c3b88`), then `std::env::temp_dir()` with the user's tag (lines
67-68 at `4dd52f8`), then the fixed `/dev/shm` on Unix (lines 69-71 there), then `.podssh` in the
working directory (lines 72-74 there). A store falls through each directory that refuses it
(lines 151-160 there). No variable or
flag names a directory. `doctor` probes the same list and names the first that can be written
(`crates/podssh-cli/src/doctor/host.rs:97-151`). VARIABLES and FILES give the list
(`crates/podssh-cli/src/man/facts.rs`, line 112 at `4dd52f8`, and the cache's text of FILES in
`crates/podssh-cli/src/man/data.rs`), a test fixes its shape (lines 365-377 at `22c3b88`), and
the module comment repeats it (`crates/podssh-relay/src/cache.rs`, lines 4-8 at `4dd52f8`).

## Approach

1. `PODSSH_CACHE_DIR=DIR` names the first candidate. `PODSSH_CACHE_DIR=none` turns the cache
   off: a token is minted on each run, and `doctor` says so. A relative path is refused with a
   note, as `user_cache_dir` ignores one today (lines 289-293).
2. Derive each other candidate from the environment: the user's cache directory, as now; then
   `XDG_RUNTIME_DIR/podssh`, made for each user by the login session, in place of `/dev/shm`;
   then the platform's temporary directory (`std::env::temp_dir`) with the user's tag; then the
   working directory. No path literal stays in `cache.rs`.
3. Probe each as now: a missing directory is made with mode 0700
   (`crates/podssh-relay/src/cache.rs:427-444`), and one that refuses a write is skipped. When the
   directory of `PODSSH_CACHE_DIR` is skipped, say so once on stderr, with the reason.
4. Take the environment as a parameter, as `dial::proxy_from_vars` does
   (`crates/podssh-ws/src/dial.rs:109-123`), so that the tests can set it.
5. `doctor` names the directory in use and the variable that chose it; `status` (T-051) shows
   it; the settings file of T-048 can set it. The session log (T-056) and the failure records
   (T-059) use the same chain.
6. Change in the same commit: VARIABLES and FILES (`crates/podssh-cli/src/man/facts.rs:211-225`,
   `crates/podssh-cli/src/man/data.rs:170-178`), the test of lines 365-377 at `22c3b88`, the comment
   of `cache.rs`, and the `doctor`
   notes (`crates/podssh-cli/src/man/notes.rs:251-334`).

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
`crates/podssh-cli/src/man/facts/tests.rs:14-51` scans source, finds no absolute path literal. In
the gate, the token file goes into a new `PODSSH_CACHE_DIR`; with a plain file there, the run
still exits 0 and names the refusal. Planted defect: put `/dev/shm` back; the scan fails.

## Correction

The Approach removes each path literal from `cache.rs`, and the Prove's scan
finds none. The operator's ruling of the same day, in the Decision and in
`docs/decisions.md`, keeps the fixed fallbacks: when no variable names the
temporary directory, podssh tries `/tmp` and `/dev/shm`, last. So the two
stay, in one list (`FIXED_TEMPORARY`), used only when `TMPDIR`, `TMP` and
`TEMP` name none; the scan reads each file of the cache's module and
allows exactly those two, in that one line. "Put `/dev/shm` back" means: as
a place before the temporary directory, as it was; the scan and the order
test then fail.

## Done

2026-10-11. The cache's places come from the environment
(`crates/podssh-relay/src/cache/dirs.rs`):

- `PODSSH_CACHE_DIR=DIR` (absolute) comes first; `none` gives no directory;
  a relative path is not used (`cache::Chosen`). Then the user's cache
  directory, `XDG_RUNTIME_DIR/podssh`, the temporary directory with the
  user's tag (`TMPDIR`, `TMP`, `TEMP`; Windows' own after them; Unix's
  fixed `/tmp` and `/dev/shm` only when none is set), and `.podssh` in the
  working directory. `candidate_dirs_from` takes the environment as a
  parameter, as the tests need.
- A store says why each directory before it refused the file
  (`store_noting`); a token stored elsewhere than the named directory, or
  with a relative `PODSSH_CACHE_DIR`, carries `cache_note`, said once on
  stderr (`open.rs`). With `none`, a token is minted on each run, with no
  warning, and a pair or other file is refused with the reason.
- `podssh doctor` names the variable that chose the directory, or says
  that the cache is off; `podssh status` shows `cache` (`from`, `dirs`).
  The settings file of T-048, the session log of T-056 and the failure
  records of T-059 are open; they take `candidate_dirs`, so the same chain.
- VARIABLES (`PODSSH_CACHE_DIR`, and `XDG_RUNTIME_DIR`, `TMP`, `TEMP`), FILES,
  the notes of `doctor` and `status`, the module's comment,
  `docs/relay.md` and `docs/target-environment.md` say the chain.

Prove, native, Windows: `cargo test -p podssh-relay --test cache`, 16
passed (the order, `none` and a relative path, a refused directory named in
the note, the scan; the fixed places' order is a test of Unix);
`cargo test -p podssh-cli`, the manual's tests and `--test status` (4
passed, `cache` with a named directory, `none` and the default). Planted,
each restored: `/dev/shm` put back before the temporary directory (the
Prove's plant) failed the scan and the order test; `none` ignored failed
its test.

Waits for T-251: the gate's case in `scripts/interop-faults.sh`, a token in
a new `PODSSH_CACHE_DIR`, and a plain file there.

# T-253: The relay's egress reaches no IPv6 host

**Source:** measured on 2026-10-08 while T-007 was done (GitHub #2): the
live test `ipv6_the_relay_takes_the_bare_literal`
(`crates/podssh-relay/tests/live.rs`) and probes of the live relay.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

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

## Decision

2026-11-03, the draft (each call with the alternatives that lost):

1. The role knows its host's way out to IPv6 by two probes at run time: the table of IPv6
   routes that Linux gives as a file (`/proc/net/ipv6_route`, read again each 30 s), whose
   longest usable prefix that covers an address decides, as the kernel's does; where no table
   can be read (macOS, Windows, a host with IPv6 off), its own dials: a direct one that met no
   route (no route, the network down, no address of the family) holds for a minute, and one
   that connected says that a route exists. The table wins over a dial, as a dial meets one
   address alone. Lost: a UDP `connect()` to a public address at the start, which sends nothing
   but opens a socket that the role does not need; a test dial of a public IPv6 host, a
   connection to a host that podssh does not use (rule 2 of `AGENTS.md`); a flag of the
   owner's, `--ipv6 no`, a surface for the one case that the probes miss, a route that drops
   what it takes, which the dial's limit of 10 s bounds already.
2. A name of both families keeps its IPv4 addresses on a host with no route, and only a target
   with no address left gets the `502`. The loopback, and an IPv4 address written as IPv6, are
   the host's own, never refused. Through the host's proxy (T-457) the role refuses nothing:
   the proxy's way out decides, and `/relays.json` says `null`. Lost: a refusal of the whole
   name, which would refuse a target that IPv4 reaches.
3. The `502` says `relay: cannot reach [ADDR]:PORT: this relay's host has no IPv6 route out`,
   words that the client shares (`podssh_relay::relay::NO_IPV6_ROUTE`) and that name no fault
   of the target's name, so that the client's opener tries the next relay host at once, with
   no change (`crates/podssh-relay/src/open.rs:89` says "!target_name_fails(body)"). This
   takes the place of Approach item 2's "a
   relay whose `/relays.json` says that it has IPv6 goes first": podssh keeps one
   `/relays.json` for each deployment, the first host's, so it cannot order the hosts of a
   list by theirs without a request to each host before each race (rule 2). The field serves a
   person and doctor's line (item 3).
4. The direct road after that `1011` is taken in `podssh ssh`'s run, where the try of the relay
   once more (T-025) is, at once and in its place (`crates/podssh-cli/src/ssh/mod.rs`, `tries`):
   the `1011` comes after the upgrade, which T-363's fallback in `reach_skipping` never sees.
   Lost: the same in each command that reaches its server as `ssh` does (`cp`, `each`, `job`
   and the others): none has a try after an upgrade, and each ends with the relay's lines, as
   before.
5. The direct road keeps the family of `-4` as of `-6`: one dial does both, and T-363's call 6
   ("the direct road cannot keep the family that the user asked for") no longer holds. Under
   `-4` or `-6` a name is resolved on this host by podssh's resolver (pins, the system's,
   DNS over HTTPS), and its addresses of that family are dialed in turn, through the proxy
   that the name takes, as addresses. Lost: `-6` alone, which keeps a rule whose reason is
   gone for `-4`; the name to the proxy, which keeps no family. A host with no DNS then fails
   that dial with its reason, and the relay's lines stay first.
6. The role's offline test dials a target of the test's on `::1` that sends OpenSSH's version
   line, not OpenSSH's sshd itself: an sshd that a test starts as a user who is not root needs
   its privilege separation and its `sshd-session` at the paths that it was built with, which
   a host may not give; the role reads none of the bytes that it carries. The role against
   OpenSSH is the interop of T-169 (`PODSSH_RELAY_UNDER_TEST=podssh`) in the build image, which
   waits until podssh is stable (Q88).
7. The client's test reaches the stand-in relay as the built-in relay, through the stand-in
   proxy's map of its name (`scripts/fake-proxy.py`), as a run that names no relay: the cells of
   `crates/podssh-cli/tests/faults.rs` name their relay with `--relay-host`, which is the relay
   alone and never falls back. The stand-in's certificate names the built-in relay too, and only
   the test's runs trust its CA. Lost: a mode of `faults.rs`, whose runs could not fall back.

## Prove

```sh
cargo test -p podssh-relay --test live -- --ignored ipv6 --nocapture
```

The test prints "bytes came back from the IPv6 host".

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator: the egress of the relay is work of the relay project.
> The operator ruled on 2026-10-08 that the relay stays separate
> (`docs/decisions.md`).

Lifted on 2026-11-02 by Q63: see below.

The Premise, a measurement of the default deployment, stands. Approach item 2 says that podssh
"already says what happened" (`crates/podssh-relay/src/relay.rs`, lines 204-207 at `d262613`):
true, but the direct road after the relay hosts (T-363) does not run in this case. It runs only
when no relay host opened a session, and never with `-4` or `-6` (`docs/cli.md`, lines 390-394
at `d262613`); here the relay opened (101), then closed with 1011.

By Q63 (2026-11-02, `docs/decisions.md`; docs/mesh.md, section 4) the relay is a role of podssh
itself, so this entry is podssh's work. podssh's relay role (T-169) dials a target's IPv6
address where its host has an IPv6 route, a dual-stack host, with the policy's IPv6 ranges
(unique-local, link-local, multicast, documentation, NAT64, 6to4); where its host has none, it
refuses an IPv6 target before the upgrade, with a `502` that says why.

What the client does (the research of 2026-11-02 on the client's side): an IPv6 target that a
relay upgraded and then closed with `1011 target closed before sending anything`, before any
byte, counts as one that the relay could not reach, so the direct road of T-363 runs, with its
line, also under `-6`; and the note names the roads that can carry IPv6 (a relay of the user's
that has it, a node with IPv6 egress as `-J node://NAME`, `warp://[ADDR]`, which is never tried
unasked, Q59).

The new Approach, in place of the one above:

1. podssh's relay role: `?family=6` and IPv6 literals dialed on a dual-stack host, else a `502`
   before the upgrade; a field of `/relays.json` says whether it has IPv6 egress.
2. The client: that 1011 for an IPv6 target runs the direct fallback of T-363, with its line,
   also under `-6`; a relay whose `/relays.json` says that it has IPv6 goes first for an IPv6
   target.
3. `doctor`: a line for IPv6 targets, through the default relay (none, measured on 2026-10-08),
   through a relay that the user names, and direct.
4. The manual's IPv6 note, `docs/relay.md`, `README.md` and `docs/STATUS.md`, as item 2 above
   says.
5. What `tcp.ssh.relay.ajam.dev` lacks here (an IPv6 route, or a `502` before the upgrade) is no
   blocker: a note of docs/relay-operator.md (item 3).

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test relay_serve_ipv6
cargo test -p podssh-cli --test faults
cargo test -p podssh-relay --test live -- --ignored ipv6 --nocapture
```

Offline: podssh's relay role on the loopback carries the banner of OpenSSH's sshd on `::1`, or
says that this host has no IPv6 and skips; with its IPv6 turned off, the target gets the `502`
before the upgrade; the stand-in, in a mode that upgrades and then closes with that 1011 for an
IPv6 target, sends the client to the direct road with its line, also under `-6`. Planted: the
fallback skipped under `-6`; its test fails. Live: the third command, pointed at
`podssh relay serve` on a host with IPv6 egress, prints "bytes came back from the IPv6 host"; a
host with none says so.

2026-11-03 (the drafting agent), read at `d262613`. The Premise of 2026-11-02 holds at its lines
then: `ipv6_note` gave the note, and the direct road ran only when no relay host opened a session,
never with `-4` or `-6` (`crates/podssh-cli/src/ssh/resolve.rs`, line 371 at `d262613`, its
`family.is_none()`). podssh's relay role dialed an IPv6 address already, as its policy's
addresses come of either family, and a direct dial with no route failed at once, before the
upgrade: a `502` whose words were the kernel's alone; with `?dial=lazy`, the upgrade came first,
then `1011 connect failed`.
The IPv6 note of the manual is in `crates/podssh-cli/src/man/notes_ssh_more.rs`, not in
`crates/podssh-cli/src/man/notes.rs`. Three changes of the Prove of 2026-11-02:

- `relay_serve_ipv6` builds only with the features `serve` and `plain-ws`, as
  `relay_serve_contract`; with none, it runs no test and passes.
- The client's check is `crates/podssh-cli/tests/ipv6_fallback.rs`, not a mode of
  `crates/podssh-cli/tests/faults.rs`, by Decision 7; its runs are not ignored, and say "did not
  run" where the host has no IPv6 loopback, no Python or no `openssl`. The planted fallback
  skipped under `-6` is caught by `crates/podssh-cli/tests/ssh_args.rs` too, which needs neither.
- The unit tests of the role's knowledge, of the client's words and of the line of the direct
  road join it.

The Prove, in place of the one of 2026-11-02:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_ipv6
cargo test -p podssh-relay --features serve --lib serve::
cargo test -p podssh-relay --lib relay::
cargo test -p podssh-cli --test ipv6_fallback
cargo test -p podssh-cli --test ssh_args
cargo test -p podssh-cli --lib ssh::transport
sh scripts/plant-each.sh --here t253-route-unchecked t253-no-fallback-under-6
cargo test -p podssh-relay --test live -- --ignored ipv6 --nocapture
```

## Done

2026-11-03, drafted (`DRAFT T-253`, unbuilt), merged at `5d0db76` on `draft/merge-253`. Items 1, 2,
4 and 5 of the Approach of 2026-11-02; item 3, `doctor`'s line, is not in this draft, as
`doctor`'s files are T-325's draft's at the same time, and the entry stays `partial` until it is
done.

- The role (`crates/podssh-relay/src/serve/ipv6.rs`, its tests in
  `crates/podssh-relay/src/serve/ipv6_tests.rs`): the knowledge of Decision 1, the plan of
  Decision 2 in the policy's `plan`, which `/connect/` and `/trace` ask before any dial; the
  dial's words for a fault of no route; `/relays.json`'s `"egress": {"ipv6", "known_by"}`.
- The client (`podssh_relay::relay`): `NO_IPV6_ROUTE`, `unreached_ipv6` and the note that
  names the roads with IPv6. `podssh ssh`: the direct road at once after a relay that reached no
  IPv6 host (`crates/podssh-cli/src/ssh/transport/after.rs`), with its line; the direct road of
  the family of `-4` or `-6`, after each relay host failed too.
- The stand-in relay's mode `v6close` (`scripts/fake-relay.py`), and the built-in relay's name in
  the stand-in's certificate (`crates/podssh-cli/tests/throughput_harness/cells.rs`).
- The manual (the IPv6 note, the direct road's note, `PODSSH_DIRECT`), `docs/cli.md`,
  `docs/relay.md` ("IPv6 targets", step 7, the role), `README.md`, `docs/relay-operator.md`
  (item 3) and `docs/STATUS.md`.

Measured, 2026-11-03, on this cloud container, whose kernel refuses each IPv6 socket (`Address
family not supported by protocol`), so each part of the IPv6 loopback said "did not run":

- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_ipv6`: 3 passed, 2 of
  them "did not run"; `--features serve --lib serve::`: 38 passed; `--lib relay::`: 13 passed.
- `cargo test -p podssh-cli --test ipv6_fallback`: 4 passed, 3 of them "did not run"; `--test
  ssh_args`: 36 passed; `--lib ssh::transport`: 6 passed.
- On a GitHub runner, whose loopback has `::1`, from `draft/merge-253` (`suite-repeat.yml`):
  `relay_serve_ipv6` 3 passed (run 41718299558), `ipv6_fallback` 4 passed in 1.01 s, where the
  same tests took 0.02 s here with each part skipped (run 41718304679).
- The role's other suites (`relay_serve_contract` 13, `relay_serve_reverse` 4,
  `relay_serve_backpressure` 3) and the CLI's `relay_serve` 14, `relay_rank` 4, `relay` 12 and
  `faults` 1 (12 ignored), each passed with the stand-in's new certificate.
- Planted (`sh scripts/plant-each.sh --here t253-route-unchecked t253-no-fallback-under-6`): 2
  caught.
- `cargo clippy` of both crates (`--features serve,plain-ws,quick` for the relay's) with `-D
  warnings`, and `cargo fmt --check`: clean. The gate runs `relay_serve_ipv6` beside the role's
  other tests now.

2026-11-03, item 3 of the Approach, after T-325's merge: `doctor`'s line `ipv6`
(`crates/podssh-cli/src/doctor/ipv6.rs`), in the section `relay` after the relay hosts' lines.
Through the first relay host that answered, one `GET /relays.json` over the path of its
`/health`: the role's `egress.ipv6` and `known_by` in words (yes; none, refused before the
upgrade; it cannot tell), or for a host of the default relay, which says nothing of it, its
egress when last measured; another relay that says nothing is unknown. Direct, by this host's own
probes, which send nothing: where a proxy takes a public IPv6 address (the client's own reading
of the variables), the proxy decides and is named by its address alone; else an IPv6 socket made
and closed, then the role's own reading of the table of routes (`Ipv6Out::out`, which
`/relays.json` now reads too). `ok` as a fact; `????` when no relay host answered or the document
cannot be read. The manual's note (`DOCTOR_IPV6`), `docs/cli.md` ("The line `ipv6`") and
`docs/relay.md` ("IPv6 targets") say so.

Measured, 2026-11-03, here:

- `cargo test -p podssh-cli --lib doctor::ipv6`: 2 passed (the relay's half of each word of the
  role, the default relay's silence, another relay's, a document that is not JSON or not 200;
  the direct half with a proxy, a bad proxy setting, a refused socket, each answer of the table).
- `cargo test -p podssh-cli --test doctor_ipv6`: 2 passed. Against the role on the loopback, its
  proxy variables emptied: the line is `ok`, and the role's word and doctor's own probes agree
  (here no IPv6 socket, so the role cannot tell: "nothing before a dial"). Against the stand-in,
  whose `/relays.json` has no `egress`: "unknown, as its /relays.json says nothing of IPv6".
- Planted (`sh scripts/plant-each.sh --here t253-doctor-word-unread`, the word `ipv6` unread):
  caught, `the_role_s_word_and_this_host_s_own_probes_agree` failed.
- `podssh doctor --quick` against the live relay, through this container's proxy: `ok ipv6
  through tcp.ssh.relay.ajam.dev: none when last measured, on 2026-11-03: each IPv6 target
  upgraded, then closed with 1011 (its /relays.json says nothing of IPv6); direct: through the
  proxy 127.0.0.1:PORT, whose way out decides`.
- The last command of the Prove, against the live relay (`cargo test -p podssh-relay --test live
  -- --ignored ipv6 --nocapture`): "the relay host tcp-azure-westus2.ssh.relay.ajam.dev took
  /connect/2001:4860:4860::8888/853", then "the relay closed the session (Some(1011) target closed
  before sending anything)", as on 2026-10-08.
- Each suite of `doctor` (`doctor` 13, `doctor_jobs` 3, `doctor_tls` 3, `doctor_upgrade` 3,
  `doctor_hop` 2, `doctor_sshd` 9, `doctor_stream` 2 with go-httpbin), the CLI's lib (817), the
  manual (`man_page` 6, `man_json` 4, `man_flag_parity` 11), the role's `--lib serve::` (52) and
  `relay_serve_ipv6` (3): passed. `cargo clippy` of both crates with `-D warnings`, and rustfmt:
  clean.

Waits: the last command of the Prove against `podssh relay serve` on a host with IPv6 egress
(none of this session's test targets has one; GitHub's runners have no IPv6 route out), and a
host with none, the role's `502` said (Q88). The role with OpenSSH's own sshd is the interop of
T-169 in the build image, which waits until podssh is stable (Q88; Decision 6).

# T-255: The relay's side drops reverse sockets at random, with no Close

**Source:** the runs of T-061 on 2026-10-09 (`crates/podssh-relay/tests/reverse_idle_live.rs`).
**Category:** measurement
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

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
(`docs/STATUS.md:353`). That is one run, before 2026-10-09.

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

2026-11-03, the drafting agent, for the new Approach of the Correction below:

6. The grace: a planned stop queues `1012 relay restarting` after the frames that wait for each
   socket, and waits 1 s (`STOP_GRACE`) for the writers; a socket that has not taken them by then
   gets it before them; the whole wait is the caller's limit (3 s in `relay serve`). Lost: the
   Close before what waits, as T-427 sent it (the sessions' last bytes are dropped, which a
   session of `--plain` loses for good); the whole limit for the queue (a slow peer then holds
   the stop, and gets no Close at all).
7. The role ends no socket before its peer answered the Close (RFC 6455, section 7.1.1): a
   second count of `outbox::Writers`, `Pairs::live`, holds each socket's own task, and the stop
   waits for it within the same limit. Lost: an end once each Close went out, as before (the
   runtime's end then resets each connection that still has bytes in its queue, and a peer whose
   system drops what it received at a reset, as Windows does, never reads the Close).
8. A node or an operator that comes during the stop gets `503 reverse: relay restarting` with
   `Retry-After: 1`, while `restart` runs only (a guard that its end, or its drop, lifts). Lost:
   no refusal (such a socket is cut with no Close when the process ends); a refusal for good (the
   role behind a quick tunnel, and the tests' role, go on after a `restart`).
9. The node's first try after a socket that served goes at once, and once each 10 s at most
   (`AT_ONCE_EVERY`), after any end that a reconnection answers: a restart, a drop, a fault of
   one frame (T-421 asks the same for a fault). "Served" is a socket whose upgrade succeeded.
   Lost: at once after a `1012` alone (a drop is no overload either); at once each time (a relay
   that takes each socket and drops it would get a loop of connections); a least time that the
   socket served (a socket of T-421's case can have served for less).
10. The node says how each socket that served ended, and when it connects again ("at once", or
    the wait): the relay restarting, a link with no Close, a fault of its bytes, another close.
    The fault's line keeps its words before "; connecting again". Lost: a line for `1012` alone
    (the drops of this entry then stay silent at the node, which only said `online again`).
11. The node's socket returns at once after the relay's Close or a broken link; its writer is
    waited for only after a stop of the caller's, whose last frames it sends. Lost: the wait of
    up to 5 s for each session's task, as before, which held the node's try after a `1012`.
12. The offline test keeps the role's listener across the restart, as a socket that a service
    manager holds, so that the node's first try waits in its queue for the role that comes back
    with the same file of pairs. Lost: a new bind of the same port (the first try may meet a
    refusal and its backoff, which hides "at once", and a port can be held by its old
    connections).
13. "At once" is checked by the node's line, which the same call that decides it writes, and by
    the time to `online again` under 1 s, a loose bound. Lost: a bound under the backoff's floor
    of 500 ms alone (it catches the plant by time, and can fail on a loaded host).
14. The live run takes podssh's own node and a session of the layer beside the raw sockets
    (`crates/podssh-relay/tests/drops_podssh/mod.rs`), on the test's task with the forward holder,
    and the relay of `PODSSH_LIVE_RELAY`, so that `scripts/relay-serve-live.sh` with `drops` runs
    it through the role on a runner; `reverse-drops.yml` takes `relay: default` or `role`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_drops_live -- --ignored --nocapture   # live, about 16 min
```

Each drop is printed with its UTC time; the run here and the run on the runner are compared by
time. A drop that the relay saw is told apart from one that it did not by the other end's frame.

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator: the drops are on the relay's side, and the relay is its own project (the
> operator's ruling of 2026-10-08, `docs/decisions.md`). The evidence, measured on 2026-10-09:
>
> - Two networks, the same end time, 01:31 to 02:05:38 UTC (`cargo test -p podssh-relay --features pair --test reverse_drops_live -- --ignored --nocapture`, here and in the
>   workflow `.github/workflows/reverse-drops.yml`, run 37870123203): from this machine, 5
>   sessions over 2.3 hours of sessions and no drop; from a GitHub Actions runner, 6 sessions over
>   2.3 hours and one drop, at 02:01:01.872Z, when both sockets of one pair ended at once with no
>   Close. This machine saw nothing at that moment, so it was not a restart of the whole relay.
>   The planted drop of each run reached the node as the relay's `close` of the session.
> - Before that, from this machine (T-061 and the trial of this entry, 00:27 to 01:28 UTC): 7 of
>   the sessions held ended by a drop, in about 0.8 hour of sessions: about 9 an hour. So the
>   drops come in bursts.
> - Two kinds: one socket ends with no Close while the relay lives on, as it then tells the other
>   end (`1011 node disconnected`, or a `close` of the session), 6 times; or both sockets of one
>   pair end at once, as when the relay's object for the pair ends, 2 times (once from each
>   network).
> - The forward path, held beside them from both networks: 25 sessions over 1.2 hours, no drop;
>   22 ended by the relay's idle cut at 180.3 s to 180.9 s, which Pings do not reset, and one by
>   the relay's `1011 write failed: Network connection lost.` toward GitHub after 5.2 s.
>
> What the relay's operator can do: read the relay's logs for the ends of reverse sockets in those
> windows; send a Close (`1001` or `1012`) before a restart that the relay plans, so that a client
> can tell it from a broken link; and keep reverse sockets across a restart of the pair's object,
> where the platform allows it.
>
> podssh's part is done (commit "A dropped link of the reverse road is named as one"): `podssh
> operator` and `podssh ssh node://NAME` say that the link ended with no Close, or that the node's
> link ended, and that a new session may work (`crates/podssh-cli/src/pairs.rs`, `session_end`,
> with three unit tests, and a plant of the old wording that fails the first); a node connects
> again by itself (T-079); resumable sessions (M6) carry a session over a drop.

Lifted on 2026-11-02 by Q63: see below. The evidence above stands.

The Premise holds. By Q63 (2026-11-02, `docs/decisions.md`; docs/mesh.md, section 4) the relay
is a role of podssh itself, so this entry is podssh's work. In podssh's relay role, the reverse
road of T-427, the relay's side of the drops is podssh's code: the role sends a Close (`1012`,
a restart) to each socket before a stop that it plans (a signal, a new binary), and no platform
under it restarts its objects. So the default deployment's drops are measured here, not repaired;
their repair there is a note.

What the client does (the research of 2026-11-02 on the client's side): measure again, as the
only paired run is of 2026-10-09 and the relay's platform may have changed since; test the
inference of T-336 that memory causes the drops, beside a slow reader; and count what a drop
costs. A node's first connection again after a socket that served goes at once, not after
`backoff(1)` (`crates/podssh-relay/src/reverse/node.rs`, line 255 at `d262613`). Since T-379 each resume races the
roads again (`crates/podssh-cli/src/ssh/roads.rs:1-14`), so a drop of the pair's socket can cost
a resume on the iroh or the DERP road, not a cut.

The new Approach, in place of the one above:

1. podssh's relay role (T-427): a Close with `1012` to each socket before a planned stop, after a
   grace for the sessions' last frames; the node and the operator read `1012` as a restart and
   connect again at once.
2. The node: its first connection again after a socket that served goes at once (with T-421).
3. The measurement: `reverse_drops_live.rs` from a session's host and `reverse-drops.yml` at the
   same end time, twice against the default relay, alone and beside the slow reader of
   `live_backpressure.rs`; then once against `podssh relay serve` on a runner, where a drop with
   no Close is the path's.
4. For each drop: the time until the node is online again, and until the operator's session
   resumed.
5. The results in `docs/relay.md` ("Open questions") and `docs/STATUS.md`; what the default
   deployment still lacks (the cause in its logs, a Close before its restarts) is no blocker: a
   note of docs/relay-operator.md (item 2).

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_restart
cargo test -p podssh-relay --features pair --test reverse_drops_live -- --ignored --nocapture   # live, about 16 min
```

Offline (`reverse_restart`, new): podssh's relay role, stopped as by a signal during two layered
sessions: each socket gets `1012` before its end, the node connects again at once, and the
sessions resume with equal digests. Planted: the Close skipped; the test fails. Live, as the
Prove above, from a session's host and a runner at the same end time, against the default relay
and against `podssh relay serve`; a live run of more than 5 minutes waits for the release checks
(T-446).

2026-11-03 (the drafting agent). Read, at `d262613`: T-427 sends `1012 relay restarting`
already, at Ctrl-C and SIGTERM of `podssh relay serve` and of the quick tunnel's node, but
before what waits for each socket (`Outbox::abort` in `Pairs::restart`,
`crates/podssh-relay/src/serve/reverse/pairs.rs`), and the role ends once each Close went out,
not once each peer answered it; a socket that comes during the stop joins. The node's try after
a socket that served still waits `backoff(1)` (`Next::Reconnect` in `run`,
`crates/podssh-relay/src/reverse/node.rs`), and its socket waits up to 5 s for its writer after
the relay's Close (`crates/podssh-relay/src/reverse/serve.rs`). So items 1 and 2 of the new
Approach are the grace, the wait for each answer, the refusal during the stop and the node's try
at once; item 3 needs podssh's own node in the live run for item 4, and a run through the role.

The new Prove's first command builds nothing with `--features pair`: the role and the plain
`ws://` of the loopback are the features `serve` and `plain-ws`, as for the role's other tests.
The Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test reverse_restart --test relay_serve_contract --test relay_serve_reverse
cargo test -p podssh-relay --features serve --lib serve::reverse
cargo test -p podssh-relay --features pair --lib reverse::node
cargo test -p podssh-cli --lib pairs
cargo test -p podssh-relay --features pair --test reverse_drops_live -- --ignored --nocapture   # live, about 16 min
```

Offline as above; planted, each of `scripts/plants/t255-*.plant` fails its test. Live, the last
command, from a session's host and with `reverse-drops.yml` at the same end time, against the
default relay twice (alone, and beside `live_backpressure.rs`), then with `relay: role`; its last
line, `T-255 podssh: ...`, gives the time until the node was online again and until the session
resumed, for each drop.

## Done

2026-11-03, drafted by an agent (`8f09eb3`), merged and built by the main session. Its new test
of the restart found a defect of the operator's leg that the draft could not see: a Close of the
relay that crossed a send that failed was said as `1006 the relay connection broke`, so a planned
stop read as a lost link in 4 runs of 6. The leg now reads, for 500 ms, a Close that came before
the link ended (`broken` in `crates/podssh-relay/src/reverse/operator.rs`); the test passed 20 runs
of 20 after it, and 40 of 40 in all.

- podssh's relay role (`crates/podssh-relay/src/serve/reverse/pairs.rs`, `Pairs::restart`): a
  planned stop queues `1012 relay restarting` after what waits for each socket, waits 1 s
  (`STOP_GRACE` of `crates/podssh-relay/src/serve/reverse/mod.rs`), then sends it before what
  still waits, to each socket again; then it waits for each socket's own task, which ends at its
  peer's answer (`Pairs::live`, a second count of `Writers` in
  `crates/podssh-relay/src/serve/reverse/outbox.rs`, held by the node's socket and each
  operator's leg). While it runs, `/v1/node/` and `/v1/connect/` answer `503 reverse: relay
  restarting` with `Retry-After: 1`. `podssh relay serve` and the quick tunnel's node call it as
  before, with their limit of 3 s.
- The node (`crates/podssh-relay/src/reverse/node.rs`): `again_at_once` and `ended_words`; the
  first try after a socket that served goes at once, once each 10 s at most, and each socket's
  end is a line with the wait (T-421's second item too). Its socket returns at once after the
  relay's Close or a broken link (`crates/podssh-relay/src/reverse/serve.rs`).
- `podssh operator` and `podssh ssh node://` name a `1012` (`session_end` of
  `crates/podssh-cli/src/pairs.rs`).
- Tests: `crates/podssh-relay/tests/reverse_restart.rs` (new): podssh's node and two sessions of
  the layer through the role, 2 MiB each way, the role stopped as at SIGTERM after the first
  half, and started again on its listener with its file of pairs: UNVERIFIED. Unit tests: the
  waiting frames before the `1012`, and a socket that took nothing past the grace
  (`pairs_tests.rs`); a join during the stop (`serve/reverse/mod.rs`); the try at once and the
  words of each end (`reverse/node.rs`); the words of a `1012` (`pairs.rs`): UNVERIFIED. The
  test of the planned stop in `relay_serve_contract.rs` reads both Closes while the stop runs, as
  the stop waits for their answers.
- The gate runs `--test reverse_restart` beside the role's other tests (`scripts/gate.sh`).
- The live run: `reverse_drops_live.rs` with podssh's own node and session
  (`crates/podssh-relay/tests/drops_podssh/mod.rs`) and the relay of `PODSSH_LIVE_RELAY`;
  `scripts/relay-serve-live.sh PODSSH drops`; `reverse-drops.yml` with `relay: role`.
- The manual (`notes_pair.rs`, `notes_relay.rs`), `docs/relay.md`, `docs/reverse.md`,
  `docs/cli.md`, `docs/relay-operator.md` (item 2) and `docs/STATUS.md`.

Results, 2026-11-03:

- `cargo test -p podssh-relay --features serve,plain-ws --test reverse_restart --test
  relay_serve_contract --test relay_serve_reverse`: 1, 13 and 4 passed; the node online again
  within the test's bound of "at once" after its line of the restart.
- `cargo test -p podssh-relay --features serve --lib serve::reverse`: 15 passed; `--features pair
  --lib reverse::node`: 2 passed; `cargo test -p podssh-cli --lib pairs`: 5 passed.
- The relay crate's targets of the reverse road, the channel and the pairs (`reverse_*`, `e2e*`,
  `pair*`, `relay_serve_*`), each passed after the repair of the leg; `-p podssh-cli --test
  relay_serve` 14, `--test relay_serve_node` 5, `--test operator` 12.
- `cargo clippy --locked --all-targets -p podssh-relay --features serve,plain-ws,quick,pair,grant
  -- -D warnings`, `-p podssh-cli`, and `cargo fmt --check`: clean.
- The plants `t255-close-skipped`, `t255-no-grace`, `t255-no-abort`, `t255-joins-during-stop`
  (its patch made again over T-226's guard beside it), `t255-backoff-back` and
  `t255-restart-words` (`sh scripts/plant-each.sh --here ID`): 6 caught.
Waits (Q88; a live run of more than 5 minutes, with the release checks, T-446): from a session's
host and `reverse-drops.yml` at the same end time, twice against the default relay, then with
`relay: role`, the rate and the place of the drops, and their cost.

# T-274: On Windows, the owner and the writers of a private file are not checked

**Source:** T-043 (2026-10-10): `~/.ssh/config` is checked on Unix only, as the files of the
cache are.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

On Windows podssh trusts the files of its cache (a relay token, the pool of hosts, a pair) and
`~/.ssh/config`, whoever owns them and whoever may change them. Another account that may write
one of them can choose the relay that podssh trusts, or the host that `podssh ssh` reaches.

## Premise

Read, at `32cae31`, as on `c0cdd2b`: on each system but Unix, `owned_and_private`
(`crates/podssh-relay/src/cache.rs`, lines 382-384) and `owned_and_unwritable`
(`crates/podssh-relay/src/cache/own.rs`, lines 136-139) return `true`; so does `owner_alone_writes`
(`crates/podssh-cli/src/ssh/config.rs`, lines 292-294) since T-043. Windows keeps the owner and
the writers of a file in its security descriptor, which podssh does not read.

## Approach

1. Read the owner and the access list of the opened file, through bindings with no C code of
   their own (`windows-sys`; verify that it is in the tree, and its version).
2. Accept the owner when it is the user, SYSTEM or the Administrators; refuse a file that another
   account may write, append to, or whose access list another account may change; for the cache,
   also one that another account may read. Measure what OpenSSH for Windows accepts, and follow it.
3. One function for the cache and for `~/.ssh/config`, with the reason in the refusal.

## Decision

Taken, with these calls made in the work (2026-10-11). One function, `podssh_relay::cache::closed`,
reads the opened file for the cache, the files of podssh's own (`read_own`), a pair file and
`~/.ssh/config` with each file that it includes; on Windows it reads the owner and the access list
through the handle, not the path again. The owner must be the user, SYSTEM, the Administrators or
TrustedInstaller. An entry that allows another principal to write, append, change an attribute,
delete, or change the access list or the owner refuses the file, and so do the generic write and
all; for a file that holds a secret, so does one that lets another principal read its data. A
deny entry, and an entry for the children alone (inherit-only), do not count; no access list at
all refuses. No account name is looked up, as that can wait on a domain controller: a principal
is named by its SID, and a few by their well-known names. Measured with OpenSSH for Windows 10.0p2
(`ssh -G -F` of a file that includes another, in a directory of `%LOCALAPPDATA%`): the included
file was read when the group Users may read it, and refused when it may write (W), append (AD)
or modify (M) it; one that inherits this host's `%TEMP%`, where a local group of a sandbox may
modify, was refused too. With (WDAC) alone OpenSSH read it; podssh refuses it, as the right to
change the access list is the right to give oneself write. podssh makes its own directories and
files with an access list of their own, which lets in the user, SYSTEM and the Administrators
alone: a directory whose list lets anyone else in gets a protected list, which its files then
inherit, and a new private file is made with its list in one call (`CreateFileW`), with no moment
open to others. The tests' scratch directories, made in the temporary directory, are made private
the same way (`cache::private_dir`), as this host's `%TEMP%` lets that group change each file
made in it. Left out: a path longer than `MAX_PATH` for a new private file, and SID history.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test cache
cargo test -p podssh-cli --test ssh_config_file
```

On Windows, also in CI on `windows-2025`: a file that the group Users may write is refused, and
the user's own file is read. Planted: a check that returns `true`; a test fails.

## Done

2026-10-11. On Windows `closed` (`crates/podssh-relay/src/cache.rs:462-488`) reads the owner and
the access list of the opened file (`crates/podssh-relay/src/cache/closed_win.rs:45-49`) and judges
them by the rules of the Decision (`crates/podssh-relay/src/cache/closed.rs:45-65`); podssh's
directories and files are made private (`crates/podssh-relay/src/cache/closed_win.rs:218-294`).
`SECURITY.md` and the manual's FILES say so.
- `cargo test -p podssh-relay --lib -- closed`: the 4 tests of the rules passed, on Windows: an
  owner that is the user, SYSTEM or the Administrators; another owner, and no list, refused; a
  writer refused for each right, and a reader for a secret; a deny entry, an inherit-only entry,
  and the right to read attributes alone let nobody in.
- `cargo test -p podssh-relay --test cache`: on Windows, podssh's own token file was read back, and
  ignored once the group Users (S-1-5-32-545) may read it; a list that the group may read was read
  as a file that others may read, and refused as a secret, naming the group; with (W), (AD) and
  (WDAC) it was refused; a directory that the group may modify was made private, and its file then
  read as a secret. `cargo test -p podssh-cli --test ssh_config_file`: the user's own file was read,
  and read again when the group may read it; when the group may write it, it exited 78, "bad owner
  or permissions", naming the group; with `-F` the same file was read.
- Planted: `closed` of Windows that takes each file; the three tests of Windows failed. `judge`
  that takes each list; two tests of the rules failed.
- The tests that wrote files into this host's `%TEMP%` (5 of `podssh-relay`, 10 of `podssh-cli`)
  failed on the check until their scratch directories were made private.
- `cargo test -p podssh-relay --all-features`: 243 passed, 0 failed, 16 ignored;
  `cargo test -p podssh-cli`: 537 passed, 0 failed, 31 ignored; clippy with all features, and of
  `podssh-relay` for Linux too. CI's job `windows` on `windows-2025` runs the tests at this push.

# T-323: A frame that `podssh ssh` sends to the relay stays under 64 KiB with room to spare

**Source:** the research of 2026-10-30 on Workers: workerd issue 7074 (open since 2026-08-20; Read
at `cloudflare/workerd`).
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The relay is a Cloudflare Worker that writes what a client sends to a TCP socket of `connect()`.
workerd issue 7074 reports that one `write()` of more than 65,536 bytes on such a socket resolves,
and that the next read then fails with `Error: Network connection lost.` ("Exactly 65,536 bytes
succeeds; 65,537 fails, every time"; production runtime only; chunking to 32 KiB or less is the
workaround). A relay that writes each frame as one `write()` would break on a frame above 65,536
bytes, and its frame cap is 262144. podssh's own forward frames are at the edge of that limit.
Whether the relay writes a frame as one `write()`, and whether its runtime has the bug, are not
known: the relay's source is not available to the repository.

## Premise

- Read, at `c00c9fd`: the stream that carries `podssh ssh` over the relay reads its pipe in chunks
  and sends each as one frame, with "const CHUNK: usize = 64 * 1024;" in
  crates/podssh-ssh/src/relay_stream.rs (line 33 at `c00c9fd`). That is exactly the largest write
  that the issue says passes. SSH packets are far smaller (russh's default packet size is 32 KiB,
  Inferred), but one read of the pipe can hold several.
- Read, at `c00c9fd`: the other forward senders already use 32 KiB: the relay leg of `podssh pipe`
  ("const CHUNK: usize = 32 * 1024;", crates/podssh-cli/src/pipe/relay.rs line 34 at `c00c9fd`) and
  the blocking facade for podbox ("const FRAME_PAYLOAD: usize = 32 * 1024;",
  crates/podssh-relay/src/blocking/forward.rs line 16 at `c00c9fd`).
- Read: `crates/podssh-ws/src/frame.rs:30` names the relay's cap, `FORWARD_MAX_FRAME`, which is
  262,144. The reverse road is not concerned: its node frames end in WebSockets, not in a socket of
  `connect()` (Inferred).
- Read in the issue: the failure shows only in the production runtime, not in a local one, and
  no Cloudflare comment answers it. Not measured by this repository: no test has reached the relay
  with a frame above 65,536 bytes, and one must not be sent to the live relay without the
  operator's leave.

## Approach

1. Make the chunk of `relay_stream.rs` 32 KiB, with a comment that says why (the write of a
   `connect()` socket at 64 KiB; the issue), beside the other forward senders. A frame then has
   half of the limit to spare.
2. Name the size once, in `crates/podssh-ws/src/frame.rs` next to `FORWARD_MAX_FRAME` (this entry
   decides the name), and use it in the three places, so that the next sender does not choose its own.
3. Check the speed that the smaller frame costs, with `podssh ping`'s throughput (T-053) through the
   live relay, before and after, in one short run (under 64 MiB).
4. `docs/relay.md`: a line that says podssh sends at most 32 KiB in a frame, and that the relay's
   cap is 262144. The question for the relay's operator: does the relay write a frame as one
   `write()`, and does its runtime have the issue's limit? It goes to the operator beside the
   questions of T-062 and T-255.

## Decision

Recommendation: 32 KiB, the size that the issue names as the workaround and that the other senders
use. 16 KiB lost: twice the frames for no gain that anything shows. Keeping 64 KiB lost: no room
for a sender that adds a byte, and the cost of the change is a measurement of speed that item 3
makes.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh relay_stream
```

A test through a stand-in relay that records each frame: 1 MiB written by the session reaches the
relay as frames of 32 KiB at most, and the bytes are equal. Planted defect: set the chunk back to
64 KiB; the test must fail.

## Done

2026-10-30. `FORWARD_SEND_PAYLOAD`, 32 KiB, beside `FORWARD_MAX_FRAME` in
`crates/podssh-ws/src/frame.rs`, is the one size of the three forward
senders: the stream of `podssh ssh` (`crates/podssh-ssh/src/relay_stream.rs`,
64 KiB before), the relay leg of `podssh pipe` and the blocking facade (32
KiB before, by their own constants). `docs/relay.md` says it, with the
question for the relay's operator.

- Linux, 2026-10-30: `cargo test -p podssh-ssh --lib relay_stream`, 4
  passed; the new test writes 1 MiB through the stream and reads it back
  from the stand-in relay's side in frames of 32 KiB at most, in order.
  clippy of podssh-ws, podssh-ssh, podssh-cli, and podssh-relay with its
  features `blocking` and `plain-ws`, and rustfmt clean.
- Planted: the chunk back to 64 KiB; the test failed ("a frame of 65536
  bytes"); restored, it passed.
- Live, through the relay from a Claude Code cloud container: `doctor` 31
  ok, its forward check through the relay with GitHub's published key, and a
  login to github.com refused with a throwaway key (publickey, 255).
- Waiting for T-251: the speed before and after through the live relay
  (`podssh ping` with a host to log in to; none here, `PODSSH_THROUGHPUT_SSH`
  is not set). Each frame's header is 14 bytes of 32 KiB, so the cost on the
  wire is under 0.1 %.

# T-336: The relay holds a slow client's bytes with no bound, and closes nothing

**Source:** the runs of T-062 on 2026-10-31
(`crates/podssh-relay/tests/live_backpressure.rs`; `.github/workflows/relay-live.yml`, run
41157016178).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A forward client that reads slowly makes the relay hold the bytes that come for it, with no
bound short of the session byte cap (64 MiB). The relay's document closes such a session at
2 MiB (`1013 client receive backlog`), and the reverse road's at 1 MiB (`1011 relay
backpressure`); neither closed. Inferred: a Worker's memory has a limit, so a few such sessions
in one isolate could end it, and with it each session that it carries. Whether the drops of
T-255 come from this is not known.

## Premise

Measured on 2026-10-31 by T-062, twice from a cloud container and once from GitHub's network:
through the relay's own loop, a pair's node gave the relay each of 48 MiB within 15 s, while the
outer forward client read 16 KiB/s. After 90 s the client had read 1.46 MB, and no Close had
come; 48.9 MB that it had not read had left the node, and the relay or its edge held them
(`docs/STATUS.md`, "The relay"). Read: the forward codes in `docs/relay.md:543` (2 MiB queued),
and the reverse row of the pinned contract
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`, 1 MiB). The forward check
reads `bufferedAmount`, which Workers may not supply (`docs/relay.md`, "Backpressure").

## Approach

1. The relay's operator finds where the bytes wait: the forward road's Worker, the reverse road's
   object, or the edge between the relay's egress and its own front, from a count of what each
   socket queued.
2. The relay bounds them: it stops reading the target, or the node's socket, while its limit
   waits for the client, or it closes with the documented code once the limit is passed; its
   contract says which.
3. podssh's side is done (T-062): an SSH session puts at most its window of 512 KiB at the relay,
   and podssh names a `1013`, says what makes it, and does not try again.
4. When the contract changes, run the Prove from here and in `relay-live.yml`, and record it.

## Decision

- 2026-11-03. The role's writes already waited for their reader, so no queue of its own grew; but
  the kernel grew the role's send buffer toward its limit (4 MiB on Linux), and a slow client then
  held about 5 MB of the host for its session (measured below). Each socket that the role accepts
  or dials now holds at most 128 KiB not yet sent (`TCP_NOTSENT_LOWAT`, Linux and Android), and
  TCP keeps the bytes in flight, so a fast reader's rate is not capped. Lost: a fixed send buffer
  (512 KiB caps a reader 100 ms away at 5 MB/s); a queue of 2 MiB that closes with `1013` (no
  queue forms to close on, and a Close would end a slow but live session that TCP slows); nothing
  (5 MB a slow session). The role's receive buffer from its target stays the kernel's (0.9 MB at
  most, measured): a fixed one caps a far target's rate.
- macOS and Windows keep their kernels' buffers: libc names the option for Linux and Android
  alone, and a constant of podssh's own that no test here can check would be a guess. Lost: the
  same bound there.
- A raw forward stream (Approach, item 4): left as it is. podssh's pump reads 32 KiB, then writes,
  so a slow local reader slows the relay through TCP; with podssh's role the stream holds a few
  hundred KiB at most. Lost: a local queue that ends the stream at 2 MiB, which would end a slow but
  live stream to spare a deployment the memory that its own check should bound.
- No SSH case in the live test (Approach, item 3): the role's bound holds for each stream, SSH or
  raw, and podssh's window keeps an SSH session at 512 KiB at any relay (T-062). Lost: a second
  live case of 90 s, which would show no more of the default deployment than the raw one does.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test live_backpressure -- --ignored --nocapture   # the live relay
```

The slow run's verdict names a `1013`, or the bytes past the node stay under 16 MiB.

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator: the relay's queues are work of the relay project (`docs/decisions.md`,
> 2026-10-08: the relay stays separate). The evidence is in this entry and in
> `docs/relay-operator.md`.

Lifted on 2026-11-02 by Q63: see below.

The Premise holds. By Q63 (2026-11-02, `docs/decisions.md`; docs/mesh.md, section 4) the relay
is a role of podssh itself, so this entry is podssh's work. In podssh's relay role a write that
waits bounds each queue: the forward road's `1013` at 2 MiB (T-169), the reverse road's
`1011 relay backpressure` at 1 MiB (T-427), which a Worker of the default deployment cannot
give, as its forward check reads `bufferedAmount`.

The research on the client's side (2026-11-02) found podssh's own part of the exposure, which
Approach item 3 above calls done. The layer's window on the pair's road is its replay capacity,
4 MiB by default and up to 16 MiB (`crates/podssh-relay/src/session/replay.rs:18-20`), and a node
takes twice that before it calls a local side stalled
(`crates/podssh-relay/src/reverse/layered.rs:99-104`): above the contract's 1 MiB on the reverse
road (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). Its repair is T-443.
And a raw forward stream (`podssh proxy`, `pipe relay:`) has no bound of podssh's: the pump
reads 32 KiB, then writes (`crates/podssh-cli/src/pipe/pump.rs:4-6`).

The new Approach, in place of the one above:

1. podssh's relay role bounds each queue: it stops reading the target, or the node's socket,
   while a client's queue is full, and closes with the documented code once the bound is
   passed (`1013` on the forward road; `1011 relay backpressure` on the reverse road, the
   undelivered frame dropped). Its copy of the contract says which.
2. The stand-in gains a mode that keeps the contract's 1 MiB on the reverse road, so that a test
   sees the `1011` that the default deployment does not send.
3. `live_backpressure.rs` gains an SSH case: `podssh ssh` through the relay's loop with a slow
   reader; the bytes past the far end stay under 512 KiB for each channel.
4. The layer's window under the bound is T-443. A raw forward stream that drains into a local
   queue of the contract's 2 MiB, then ends with the contract's words, waits for a Decision in
   this entry; the alternative: leave it, and the relay keeps paying for it.
5. What `tcp.ssh.relay.ajam.dev` lacks here is no blocker: a note of docs/relay-operator.md
   (item 1).

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test relay_serve_backpressure
cargo test -p podssh-relay --features pair --test live_backpressure -- --ignored --nocapture   # the live relay
```

Offline: through podssh's relay role on the loopback, the slow run of `live_backpressure.rs`
(48 MiB, a reader at 16 KiB/s) ends with the documented code, or the bytes past the node stay
under 2 MiB, on each road; the stand-in's new mode gives the reverse road's `1011` at 1 MiB.
Planted: the role's bound removed; the test fails. Live: the slow run against the default relay,
from a session's host and in `relay-live.yml`, recorded as a reading of that deployment; and
against `podssh relay serve` on a runner.

## Done

2026-11-03. podssh's relay role bounds what waits for a slow reader: each write waits for its
reader (T-169, T-427), and each socket that it accepts or dials holds at most 128 KiB not yet sent
(`crates/podssh-relay/src/serve/sockets.rs`, called by `podssh relay serve`'s accept and by the
forward road's dial).

- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_backpressure`: 3 passed
  (the bound, read back from the kernel, among them). A forward client read 16 KiB/s for 12 s through the role, from a target with 48 MiB to send:
  it read 228352 bytes, the target's socket took 606208, at most 377856 waited past the target,
  and no Close came. Before the bound, the same run left 4877312 bytes past the target: the role's
  send queue held 3697664, its receive queue 933888 and the target's 147297 (`/proc/net/tcp`
  during the run). The control at full speed carried 48 MiB and ended `1000 target closed`.
- The reverse road's bound, `1011 relay backpressure` at 1 MiB, is `relay_serve_reverse.rs`'s slow
  operator (T-427), and the stand-in's mode `strict:RATE` gives it (T-443): `--test
  relay_serve_reverse` 4 passed, `--test relay_serve_contract` 13, `--lib serve::` 34; `-p
  podssh-cli --test relay_serve` 14, `--test relay_serve_node` 5.
- Planted (`sh scripts/plant-each.sh --here t336-unsent-unbounded`, the bound not set): caught,
  5111808 bytes waited past the target.
- Live, from this session's host: `cargo test -p podssh-relay --features pair --test
  live_backpressure -- --ignored --nocapture`, passed (111 s). The control carried 8 MiB and ended
  `1000` at both levels; the slow client read 15.7 KiB/s for 90 s with no Close, and 48878136
  bytes more than it read had left the node: the default deployment still holds them, as on
  2026-10-31 (`docs/relay-operator.md`, item 1).
- `cargo clippy -p podssh-relay -p podssh-cli --all-targets -- -D warnings` and `cargo fmt --check`:
  clean.

Waits (Q88): the slow run against `podssh relay serve` on a runner, with a certificate of its own;
macOS and Windows keep their kernels' buffers (Decision).


# T-338: The relay's facts are read by their line, and only a push checks the live relay

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 4, and finding 1 for the
expiry of the relay's domain.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The check of the relay's contract reads each fact at one line of the relay's document. A line
that the relay inserts above a fact, with the fact unchanged, turns the gate red, and so does a
relay that cannot be read for a minute; a beta needs the gate green. Only a push runs the live
check, and after `v1.0.0` pushes become rare, so a change of the contract could go unseen.
Nothing watches the expiry of the relay's domain, on which each road but `--direct` depends.

## Premise

- Read: the reader takes exactly the line that a fact names
  (`crates/podssh-probe/src/relay_facts.rs` lines 75-84 at `8263b2f`), and asserts each fact on
  that line alone, with no search (lines 161-168 there).
- Read: `crates/podssh-probe/facts/relay-facts.toml:32-73` holds six facts, each by its line of
  the pinned document: the node's path and the operator's
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:23`, `:24`), "no subprotocol"
  (`:207`), binary frames (`:210`), the node's open timeout (`:190`) and the `1009` of a bad
  multiplex frame (`:182`); the relation reads `:182` too. Each fact stands under a heading of the
  document: "Exact addresses" (`:9`), "Reverse close codes" (`:160`) and "Protocol (for other
  clients)" (`:205`).
- Read: the job `checks` runs the live check, and fails on exit 1 (a changed fact) and on exit 2
  (a relay that cannot be read) alike (`.github/workflows/build.yml:192-222`);
  the gate's step `release` asks the binary and the script for one verdict, live (`:81-86`).
- Read: each of the eight build jobs of the release runs `podssh proxy github.com 22` through the
  live relay (`scripts/release-short.sh:109-115`, run at `.github/workflows/release.yml:144`, `:207`,
  `:279`, `:318` and `:412`; three of these run in a matrix of two). The audit counted seven
  jobs; the matrices give eight.
- Read: a beta needs the job `all` of the gate (`docs/decisions.md:63`). Citations of an older
  document of the relay were once off by 35 (`TODO/repo.md:2315-2318`).
- Read: no workflow checks the relay on a schedule: `relay-live.yml` runs by hand
  (`.github/workflows/relay-live.yml:14-23`), and `build.yml` on a push, a pull request or by hand
  (`.github/workflows/build.yml:9-13`).
- Read, by the audit through web.pkgforge.dev on 2026-10-31 (the registry's RDAP,
  https://pubapi.registry.google/rdap/domain/ajam.dev): `ajam.dev` expires on 2028-01-19, under
  Cloudflare's name servers, with no DNSSEC. No check reads the expiry. The relay's origin is the
  first key of the facts file (`crates/podssh-probe/facts/relay-facts.toml:1`).
- Inferred: a registrar that renews by itself keeps the date ahead; a lapse would stop each road
  but `--direct` for each user.

## Approach

1. Each fact of `relay-facts.toml` names its section, a heading of the relay's document, beside
   its `line`, which stays as a hint. The reader looks for the fact's text (`contains` or
   `pattern`) at the hint first, then in the whole section. Found at another line of its section:
   a pass, with a note that names the old line and the new one (`podssh relay spec` prints it, and
   `--json` gives it). Not in its section: a FAIL, as today. The relation's operands do the same.
2. The same in `scripts/check-relay-spec.py`; `scripts/relay-spec-agree.py` asks both for one
   verdict, with the notes.
3. Two plants: a document with one line inserted at its top passes, with a note for each fact; a
   document whose fact moved to another section fails. The plants of today still fail.
4. The live step of the gate tries an unreadable relay (exit 2) twice more, 60 s apart, before it
   fails; a changed fact (exit 1) fails at once.
5. A workflow `relay-watch.yml`, each day and by hand, with `contents: read` and `issues: write`:
   the live check; on exit 1 it opens one issue, titled with the pinned version and the facts that
   failed, unless an open issue has that title; on exit 2 three days in a row, one issue too. It
   mints no token.
6. In the same workflow, the domain of the facts file's origin: the `expiration` event of its
   RDAP record (the registry's RDAP server, then rdap.org as the fallback). It fails when the date
   is less than 90 days ahead; no answer is exit 2, never a pass.
7. `docs/relay.md` and `docs/development.md` name the watch, and what each exit means.

## Decision

The gate keeps the live check, as a relay that changed its contract must stop a release: a
second and a third try of exit 2 won over taking exit 2 out of the gate, which would let a beta
pass with the relay unread. A note for a moved line won over a silent pass, so that a session
moves the hints of the facts file by hand.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-probe --test relay_facts
python scripts/check-relay-spec.py --plant-moved-line      # exit 0, with a note for each fact
python scripts/check-relay-spec.py --plant-moved-section   # exit 1
gh workflow run relay-watch.yml
```

Planted: the search turned off, so that a fact is read at its line alone; the plant of the moved
line then fails. The check of the domain with a planted expiry 89 days ahead fails, and 91 days
ahead passes.

## Done

2026-10-31. A fact of the relay's document is read at its line, then in its
section, and a watch reads the relay and its domain each day:

- Each fact of `crates/podssh-probe/facts/relay-facts.toml`, and each operand
  of the relation, names its `section`, a heading of the relay's document by
  its first words ("Exact addresses", "Reverse close codes", "Protocol (for
  other clients)"); `line` stays as a hint. The reader looks at the hint
  first, then on each line of the section, which runs from its heading to the
  next heading of its level or above, a line in a fence of code being no
  heading (`crates/podssh-probe/src/relay_facts.rs`). Found at another line of
  its section: a pass, with a note; else a FAIL. `podssh relay spec` prints a
  `note FACT:` line for each, after the verdict.
- The same in `scripts/check-relay-spec.py`, the search in
  `scripts/relay_sections.py` (the script was at 451 lines); `--json` gives
  `moved`. `scripts/relay-spec-agree.py` asks both for one verdict on a copy
  with a line inserted at its top, and requires a note of each of the 7
  facts from both.
- Plants, each a test: a line at the top passes with one note for each fact
  (the relation's two operands in one), the node path's moved by one, to 24;
  the node path moved out of "Exact addresses" fails, though the document
  holds the same text under the reverse transport's heading; a fence whose
  line starts with `#` ends no section; the close codes' heading with another
  version still names its section. `cargo test -p podssh-probe`: 18 passed.
  Planted in the code, each failed the tests: the search turned off (3
  failed), no fences (1), the whole document in place of the section (3), the
  exact heading in place of its first words (3). `python
  scripts/check-relay-spec.py --plant-moved-line` exit 0 with 7 notes;
  `--plant-moved-section` exit 1; the three old plants exit 1; live, the
  same, and `relay-spec-agree.py` agreed on the pinned copy, the renamed
  path, the moved copy and the live relay (version 2026-10-03-r2, the pin).
- The live checks of CI try a relay that cannot be read (exit 2) twice more,
  60 s apart, and a changed fact fails at once: the job `checks`
  (`.github/workflows/build.yml`), with the two new plants, and the live
  comparison of `relay-spec-agree.py`. The step's function, against a
  stand-in that answered 2, 2, 0: passed on the third call; 2, 2, 2: failed
  with 2 after three; 1: failed at once.
- `.github/workflows/relay-watch.yml`, each day at 05:43 UTC and by hand
  (`contents: read`, `issues: write`, `actions: read` for the results of the
  runs before): the facts check, the domain's expiry, and the issues of
  `scripts/relay_watch.py`: a changed fact, titled with the pin and the facts;
  the document unread in three runs in a row; the domain within 90 days; its
  expiry unread in three runs in a row; each unless an open issue has its
  title. Its inputs `dry_run` and `plant` (`moved-section`, `unreadable`)
  prove each path with no issue. `python scripts/relay_watch.py --self-test`:
  8 cases passed; planted, two runs in a row in place of three, two failed.
- `scripts/check-domain.py`: the registry's RDAP server by IANA's bootstrap
  (`https://pubapi.registry.google/rdap/` for `.dev`), then rdap.org, for the
  shortest name under the origin's host that a server knows. On the record
  read through fetch.web.pkgforge.dev (`ajam.dev`, expiration
  2028-01-19T05:57:22.993Z): exit 0, 445 days ahead; `--plant-days 89` exit
  1, `90` and `91` exit 0; a record with no expiration exit 2. RDAP's servers
  are not a target of this session's tests: the script runs live in Actions.
- `docs/relay.md` and `docs/development.md` name the search, the notes, the
  retries, the watch and what each exit means.
- The watch by hand at `1d16bb4`, each with `dry_run`: plain (run
  41168076920), the live relay at the pin, 7 facts with no problem and no
  note, `ajam.dev` 445 days ahead by `https://pubapi.registry.google/rdap/`,
  its result kept, "nothing to open", green; `plant=moved-section` (run
  41168079191), it read the result before it and would open "relay-watch:
  the relay's document disagrees with the pin 2026-10-03-r2:
  reverse-node-path", kept no result, red; `plant=unreadable` (run
  41168085583), three tries 60 s apart, exit 2, "run 41168079191 kept no
  result", nothing to open after one unread run, red.


# T-342: The relay's limits are compiled in, and nothing compares them with `/relays.json`

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 7; GitHub #71 (Nemo-010,
2026-10-31), the fifth of its false statements, the comment of the facts file.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh holds the relay's limits as constants: the idle cut, the byte and time caps of a session,
and the frame cap of the forward road. If the relay raised its frame cap, the first larger frame
would end each session that receives one; if it lowered its byte cap, a copy would meet `1009` in
its middle. The facts file says that the frame cap is read from `/relays.json` and never compiled
in; the code compiles it in, and the live check never reads `/relays.json`.

## Premise

- Read: the idle cut (180 s), the byte cap (64 MiB), the time cap (12 h) and podssh's budgets
  under them (60 MiB, 11 h 30 min) are constants (`crates/podssh-relay/src/relay.rs:19-37`);
  `PODSSH_SESSION_BUDGET` lowers the byte budget and never raises it (`:39-73`).
- Read: the frame decoder refuses a received frame over 262144 bytes
  (`crates/podssh-ws/src/frame.rs:30`, `:221-231`), and the session then ends with a Close 1002
  (`crates/podssh-ws/src/session.rs:344`); a message is at most 16 MiB (`:33`).
- Read: `crates/podssh-probe/facts/relay-facts.toml` line 14 at `deacafd` said "Read from /relays.json at startup,
  never compiled in" of that cap. `crates/podssh-ws/src/frame.rs:30` compiles it in, and
  `podssh-core` takes it from the facts file at compile time
  (`crates/podssh-core/src/irc/limits.rs:3-9`). The live check fetches `/llms-full.txt` and
  `/health` alone (`scripts/check-relay-spec.py:399-400`); `:196-197` reads the cap from the
  facts file.
- Read: podssh fetches `/relays.json` at a mint for its pool, and keeps `pool[].host` alone
  (`crates/podssh-relay/src/pool.rs:155-246`). `podssh relay info` reads its `limits`
  (`connect_timeout_ms`, `idle_timeout_ms`, `max_session_ms`, `max_session_bytes` and
  `max_frame_bytes`; `crates/podssh-cli/src/relay_diag_text.rs:114-127`), and a test asserts a
  stand-in's `max_frame_bytes` of 262144 (`crates/podssh-cli/tests/relay.rs:261`).
- Read: to a node, the resumable layer resumes after the relay's `1009` at the cap
  (`docs/relay.md:496-502`); a forward session has no layer.

## Approach

1. The pool's cache keeps the `limits` object of the same `/relays.json`, with the time it was
   read: nothing more is fetched.
2. The budgets take the smaller of the compiled-in value and the cached one: the byte budget keeps
   its 4 MiB under a smaller `max_session_bytes`, the time budget its 30 min under
   `max_session_ms`, and the keepalive stays under `idle_timeout_ms`. A value that does not parse,
   or 0, is passed over with a note in `-v`.
3. The receive cap takes the larger of 262144 and `max_frame_bytes`, and never more than 16 MiB;
   what podssh sends stays `FORWARD_SEND_PAYLOAD` (T-323).
4. The live check (`scripts/check-relay-spec.py`, and `podssh relay spec`) fetches
   `/relays.json?host=github.com&port=22` too, and compares its `limits` with the facts file, which
   then holds each limit; a change fails, as a fact of the document does.
5. The comment of the facts file, and the same words on `Facts::forward_max_frame_bytes`
   (`crates/podssh-probe/src/facts.rs:39-43`), say what the code does: the cap is compiled in, the
   live check compares it, and a cached value can only widen what podssh takes in and narrow what
   it spends.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib pool
cargo test -p podssh-ws --lib frame
python scripts/check-relay-spec.py
```

Tests: a cached `max_session_bytes` of 32 MiB gives a byte budget of 28 MiB, and 128 MiB leaves
60 MiB; a cached `max_frame_bytes` of 524288 lets a received frame of that size in, and 32 MiB
still stops at 16 MiB. Planted: the larger value taken for the budget; the first test fails.

## Correction

Approach item 2's note in `-v` for a value that does not parse is not given: such a value never
reaches the cache, as `pool::parse_limits` leaves out what is missing, not a whole number, or 0,
and `podssh relay info` shows what the relay says. The budgets read the limits that the opener
records for the run from the cache of its primary (`pool::set_in_use`), as the meter of a copy
knows its relay status alone, not the relay's name; before the first session of a run, the
compiled-in values hold. `crates/podssh-ws/src/session.rs` was at 497 lines: the Close's helpers
and `ForwardClose` move to `close.rs`, re-exported where they were. Approach items 4 and 5: the
limits are in `crates/podssh-probe/facts/relay-limits.toml`, beside `relay-facts.toml`, as both
readers of `relay-facts.toml` refuse a table that they do not know; `scripts/check-relay-limits.py`
reads them, not `check-relay-spec.py`, which was at 498 lines; and `podssh relay spec` does not read
`/relays.json`, as `podssh relay info` prints its limits and the script runs in CI on each push and
each day.

## Done

2026-10-31. The live check at `deacafd`'s tree: `python3 scripts/check-relay-limits.py`
read the five limits of the live `/relays.json?host=github.com&port=22` (10000, 180000, 43200000,
67108864, 262144), each the facts' and the compiled-in constants'; done here:

- `podssh_relay::pool::Limits` and `parse_limits`: the `limits` of the same `/relays.json` that
  gives the pool, kept in its cache (`#[serde(default)]`, so a cache of an older podssh reads);
  `cached_limits`; the opener records them for the run (`set_in_use`, `in_use`) and gives each
  session the cap of `podssh_ws::frame::receive_cap`.
- `relay::byte_budget_under`, `time_budget`, `idle_secs`: under a smaller limit with the same
  margin, never above the compiled-in value; `byte_budget`, the meter of a copy and the keepalive's
  warning read the run's limits.
- `podssh_ws::frame::decode_capped`, `client::next_event_capped` and
  `RelaySession::set_receive_cap`: a received frame up to the relay's `max_frame_bytes`, never
  under 262144 and never over 16 MiB.
- Tests: the limits read and cached, an old cache, and the budgets (32 MiB gives 28 MiB, 128 MiB
  leaves 60 MiB, 6 h gives 5 h 30 min, an idle cut of 90 s holds, of 300 s does not;
  `cargo test -p podssh-relay --lib pool`, 6 passed); a frame of 524288 bytes refused at the
  forward cap and taken at the relay's, one byte over 16 MiB refused (`cargo test -p podssh-ws
  --lib frame`, 1 passed). Planted, the larger value taken for the budget: the test failed.
  podssh-ws and podssh-relay with `quick` and `pair`, 555 passed; clippy clean.
- `crates/podssh-probe/facts/relay-limits.toml`, the five limits of 2026-10-31, and
  `scripts/check-relay-limits.py`: live, exit 0; `--plant max_frame_bytes=524288`, exit 1 naming
  it; a document with one limit, four named and exit 1; one with no `limits`, exit 2. CI's checks
  run it with three tries for a relay that cannot be read, and its plant; the daily watch runs
  it. A test of podssh-relay ties the compiled constants to the file
  (`relay::tests::the_compiled_limits_are_the_facts_of_the_relays_limits`; planted, a fact of
  524288, failed). The comment of `relay-facts.toml` and `docs/relay.md` say what the code does.
  podssh-probe and podssh-core, 158 passed.
- 2026-10-31, after the close: GitHub #71 found the same false words on
  `Facts::forward_max_frame_bytes` (`crates/podssh-probe/src/facts.rs:39-43`), "never compiled
  in"; they now say what the comment of the facts file says. `cargo test -p podssh-probe`, 18
  passed.


# T-346: Relay hosts outside the default domain from a signed `/relays.json`, and a list of deployments

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 1 (its first two proposals:
a signed `/relays.json`, and a default of several deployments).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Each road of the release binaries but `--direct` reaches one relay deployment, on Cloudflare,
under one domain, `ajam.dev`. A release binary copied into a cage is not updated, and it takes no
relay host outside `ssh.relay.ajam.dev`. A lapse of the domain, an outage of Cloudflare, or a
proxy that blocks the name stops `ssh`, `proxy`, `cp`, `node` and `chat` for each user, and the
relay's operator has no way to move the binaries in the field to another deployment.

## Premise

- Read: the default host and the six seeds of the pool are names under `ssh.relay.ajam.dev`
  (`crates/podssh-relay/src/relay.rs:13`; `crates/podssh-relay/src/pool.rs:25-34`), and a host of
  `/relays.json` outside the default's parent domain is dropped
  (`crates/podssh-relay/src/pool.rs:144-157`).
- Read: the relay is a Worker of Cloudflare
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:5-7`); its pool names placements
  in regions of AWS, GCP and Azure, each a name of the same domain (`:30-68`). Inferred: each is a
  placement of the same Worker.
- Read: the pairs of the reverse road live on the control host alone
  (`crates/podssh-relay/src/pair.rs:1-4`; `docs/relay.md:648-653`). The audit cited
  `docs/relay.md:640-645`; the fact is at `:648-653`.
- Read: a release binary is uploaded or copied into its host, which cannot build it or download
  it (Q48, `docs/decisions.md:59`); a machine keeps one token for each deployment, and podssh
  "never sends a token to a deployment that did not mint it" (`docs/decisions.md:98`).
- Read, by the audit through web.pkgforge.dev on 2026-10-31
  (https://pubapi.registry.google/rdap/domain/ajam.dev): Cloudflare's name servers, no DNSSEC, an
  expiry on 2028-01-19.
- Inferred (the audit's reading, with no source kept): Cloudflare's outages of 2025-11-18 and
  2025-12-05 reached its whole network.
- Read: T-169 is a relay that its users host; no entry covers a second deployment of the
  operator's.

## Approach

podssh's side:

1. A signed document: the relay serves `/relays.json` with a detached Ed25519 signature over its
   exact bytes (in a header, or at `/relays.json.sig`; podssh reads both), and the document holds
   a `serial` and a `not_after`. The relay's operator chooses the form; this entry follows it.
2. Two public keys are compiled in, the current one and the next, each by its id; the private
   keys stay offline with the relay's operator.
3. podssh checks the signature before it uses any host of the document. A host outside the parent
   domain comes only from a signed document whose `not_after` is ahead and whose `serial` is not
   below the cached one; an unsigned or a badly signed document keeps today's rule. Each host
   still meets TLS on its own name.
4. The default becomes a list of deployments: today's first, then those that the signed document
   names. A token is minted at each deployment and sent to no other (T-057), and the hosts are
   tried in the ways of Q10 (`docs/decisions.md:77`).
5. The cache keeps the signed document and its signature, so that a binary keeps the other
   deployments when the old domain is gone.
6. `podssh relay status` and doctor name each deployment, and whether its pool was signed.

The relay's side is item 14 of `docs/relay-operator.md`: the keys, the signed document, and a
second deployment on another provider and under another domain.

## Decision

The operator's ruling of 2026-10-31 (Q49, `docs/decisions.md`): a binary may use relays outside `ssh.relay.ajam.dev` when they are compatible, and a token goes only to the deployment that minted it. Relays that their users bring (Azathothas/podssh#60) and `podssh update` (T-375) make the signed list less pressing: when this entry is taken up, its Approach is read again against them, and a signature of the document stays the relay's operator's (`docs/relay-operator.md`, item 14).

2026-11-04, the drafting agent: the calls of the draft, each weighed against `SECURITY.md` (the
relay sees the target and the volume, TLS is checked by name, a token goes only to its
deployment). The Correction below gives the Approach that they make.

- **One form, one verifier: an Ed25519 key's signature, in podssh-relay.** A list is signed by
  an Ed25519 key, the role's own or the operator's, and checked by `ed25519-dalek`'s strict
  verification, which the crate has already for the keys of the ends (T-087): pure Rust, no
  C, in the pool's own crate. Lost: Sigstore with a workflow's identity (the Correction of
  2026-11-02). Since Q63 the other deployments are podssh's own relay roles, on users' hosts,
  and a role has no workflow's OIDC token, so it could sign no list; the check of a bundle
  (x509, Fulcio's chain, Rekor's promise) is podssh-cli's, and the pool would take it as a
  function across crates for one caller; its fixture needs a run of a signing workflow, which
  no draft can make; and the default relay's Worker must serve the list in any form, which is
  the operator's change either way. Lost too: trust on first use of the key that a relay
  shows (a relay in the path, or a proxy that re-signs TLS with a CA in the trust store,
  would plant its own key, and the operator's next key could not be told from it), and trust
  by the TLS name of the host that served the list (today's trust, which a lapse of the domain
  hands to whoever takes the name over: the case of the Problem).
- **Where the signature goes: inside `/relays.json`, as its field `signed`.** `{"doc": TEXT,
  "key": HEX, "sig": BASE64}`: the document's exact text as a JSON string, so that no
  canonical form of JSON is needed and the signed bytes are the string's bytes; the key in
  64 hex digits; the signature of `podssh-relays/1`, a zero byte and the text, so that a
  signature of the key serves no other use of it (a key of a node signs the challenges of
  T-448 and the binding of the channel). An older client reads `pool` and `limits` as before.
  Lost: a header over the whole body (the body differs by request: `?host=&port=`, `egress`;
  the role would sign each answer, and a text that a request shapes; a proxy may drop a header;
  a static mirror cannot set one), and `/relays.json.sig` (a second request, a second
  connection in the background against rule 2 of `AGENTS.md`, and two fetches that a change
  between them sets apart).
- **The document's fields.** `podssh-relays` (the form, 1; another form is refused, so that a
  part that must not be skipped comes with a new form), `serial` (above 0), `issued` and
  `not_after` (seconds since 1970), and `deployments`: 1 to 16, each a `name` (as a member of a
  net is named) and 1 to 8 `hosts` (as `--relay-host` takes them); 8 KiB at most, so that the
  cache keeps 4 lists in one file under its bound of 64 KiB. Another field is ignored.
- **Which keys a binary trusts.** (1) `BUILT_IN`, compiled in by fingerprint: the keys of the
  default deployment's operator, none on 2026-11-04 (a question for the operator, in the
  report of the draft: two keys, the current and the next, kept offline). (2)
  `PODSSH_RELAY_KEYS` and the settings file's `RelayKeys` (each line adds), each key by its
  fingerprint or its hex; the settings file is already held to its owner, as it names relay
  hosts. (3) The key of each member of the net that this host holds with the role `relay`,
  while the document holds: the owner's signature vouches for it (Approach item 3). `none`
  in the variable trusts no key at all, those compiled in too: an off switch. A bad word of
  the variable or the file is 78, as each relay setting is.
- **How a token stays with the deployment that minted it.** `token::token_key` stays: a host
  outside the default's parent domain is cached under its own name (and port), so its token
  is minted there and sent nowhere else, and a host of the default's domain shares the
  default's, as before. The hosts of one deployment of a list do not share a token: a role's
  token is a secret of its run, and one more mint costs less than a token sent to the wrong
  host. A run with `PODSSH_RELAY_TOKEN` takes no other deployment, as that token is the
  default's.
- **What an unsigned or badly signed list does.** Today's rule: the pool keeps the hosts of the
  default's domain alone, nothing is kept, and a session says nothing (the refresh is in its
  background); `relay info` says why the list is not used. A list kept is checked again at
  each read, so a key no longer trusted, or a list past its end, stops counting at once; a
  kept list whose signature no longer verifies (a changed cache file) is no list.
- **The serial never goes back for a key**, also past a list's end, so that an old list
  cannot come back after a newer one ended. The role's serial is the time it signs, in
  seconds, and above its last when the clock went back during a run; a role started again
  with its clock behind signs below the serial that a client kept, which that client refuses
  until the clock passes it. Lost: a counter in a file of the role (one more file to keep,
  for what the clock gives).
- **A list's life**: a client refuses one whose `not_after` is more than 400 days after its
  `issued`, so that a key that leaked signs no list for ever; the role signs 90 days, and
  again each day, so that a cage that last refreshed months before the default's domain went
  still holds the other deployments. Lost: no bound, and a short life of days, which loses the
  other deployments in the very case of the Problem.
- **Their place in the default list**: after the default host and its three hosts of the
  pool, at most 4 hosts of other deployments, the first host of each deployment first; the
  record of failures (T-059) moves the default's hosts last once they fail, so the other
  deployments go first in an outage. A list that the user names takes none. Lost: before the
  pool (most sessions would leave the default while it works), and no bound (a hopeless run
  would grow long).
- **The role's key**: a key for this one job, `relay-list.key` in the cache or the file of
  `--list-key`, made when it is missing, and named by its fingerprint on the first line. The
  role signs the deployments of its flags alone: nothing of a request goes into the text, so
  the role is no oracle of signatures. It is given once to the role's documents, process-wide,
  as the net's documents are (`podssh_relay::e2e::net::install`), so that the places that build
  a `serve::Config` stay as they are. Lost: a field of `Config` (each harness changes).
- **Where a list is learned**: from the `/relays.json` that a run reads already, the pool's
  refresh in a session's background after a mint, with no request more, and `podssh relay
  info`, which keeps a list that holds. Lost: a request of its own, unasked (rule 2).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib pool
cargo test -p podssh-cli --test relay
```

With a test key: a signed document's host outside the domain is used; one changed byte, an old
`not_after`, a lower `serial` or an unknown id of a key keeps the parent domain alone. Planted:
the check of the signature skipped; the tests of the changed byte and of the unknown key fail.
Live, once the relay signs: `podssh relay status` names the second deployment.

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator (`docs/relay-operator.md`, item 14, which is optional for them): the form
> of the signed document (where the signature goes, its fields) and the public keys to compile
> in, or a word that no signed list comes. Read again against its Decision on 2026-10-31:
> `podssh update` (T-375, done) lets a binary in the field move to a release that names a new
> deployment wherever GitHub is reached, and a binary copied into a cage is copied again by its
> user; relays that their users bring are T-169's, which waits for the relay's operator too.
> podssh's side is then the check of item 3 and the list of item 4, against the form that the
> operator chose; written before that choice, it would follow a form that may not come.

Lifted on 2026-11-02 by Q63: see below.

The Premise holds at its lines. By Q63 (2026-11-02, `docs/decisions.md`; docs/mesh.md,
section 4) the relay is a role of podssh itself, so this entry is podssh's work, and the form of
the signed document is podssh's choice: the relays that users bring are podssh's own relay role
(T-169), and Q49 lets a binary use them. Two lists, each signed by a key that podssh's user or
podssh's release already trusts:

- For a net: the owner's signed document of the net (T-429) names the members that carry the
  relay role, with their hosts. A member takes a relay from it as it takes any member, and a
  token goes only to the deployment that minted it (Q49).
- For the public default: a `relays.json` of deployments, signed by a workflow of this
  repository with `cosign sign-blob --bundle`, and checked by the Sigstore verifier that
  `podssh update` already runs on `SHA256SUMS` (`crates/podssh-cli/src/update/mod.rs:278-290`,
  `crates/podssh-cli/src/update/sigstore.rs`), its identity widened from the release workflow to
  that workflow and its ref. No private key to keep offline, no new cryptography, and an
  unattended session can publish a new list. The document holds a `serial`, a `not_after` and a
  fixed `format` inside the signed bytes.

This replaces Approach items 1 and 2 above (a detached Ed25519 signature by the relay's operator,
and two keys compiled in).

The new Approach, in place of the one above:

1. The public list as above, a release asset at a fixed URL of the repository, mirrored at the
   relay hosts, and cached with its bundle. The verifier moves where `pool.rs` can call it, or
   the pool takes it as a function from `podssh-cli`.
2. Items 3 to 6 above hold: a host outside the parent domain only from a signed document whose
   `not_after` is ahead and whose `serial` is not below the cached one; a token only to the
   deployment that minted it; the cache; `podssh relay status` and `doctor` name each deployment,
   and whether its list was signed.
3. A net's relays come from its signed document (T-429), under the same rules.
4. A second deployment of the public default, on another provider and under another domain, is
   no blocker: a note of docs/relay-operator.md (item 14); podssh's relay role on a host of the
   operator's can be it.

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib pool
cargo test -p podssh-cli --test relay
```

Offline: a list and the bundle that a run of the signing workflow made with cosign, software
that podssh did not write, kept as a fixture as the tests of `podssh update` keep a release's
(`crates/podssh-cli/tests/update.rs`): its host outside the domain is used; one changed byte, an
old `not_after`, a lower `serial`, or another workflow's identity keeps the parent domain alone.
Planted: the check skipped; the test of the changed byte fails. Live: the workflow signs a list
that names `podssh relay serve` on a runner, and `podssh relay status` names it.

2026-11-04 (the drafting agent). The Premise holds at its lines, read again at `1ca77a1`: the
default host and the six seeds are names under `ssh.relay.ajam.dev`, a host of `/relays.json`
outside the default's parent domain is dropped, and `token::token_key` keeps a token for each
deployment, a host outside the default's domain under its own name and port. The Sigstore
form of the Correction of 2026-11-02 is replaced by an Ed25519 key's signature, as the
Decision of 2026-11-04 says: since Q63 the other deployments are podssh's own relay roles,
which no workflow signs for, and a bundle's verifier is podssh-cli's. This replaces items 1
and 3 of the Approach of 2026-11-02; its items 2 and 4 hold.

The Approach, in place of both above:

1. The form (`crates/podssh-relay/src/pool/signed.rs`): `/relays.json` carries `signed`,
   `{doc, key, sig}`, the document's exact text, its Ed25519 key and the key's signature of
   `podssh-relays/1`, a zero byte and the text; the document holds `podssh-relays` (1), a
   `serial`, `issued`, `not_after` and its `deployments`, each a name and its hosts.
2. The keys trusted: those compiled in (`BUILT_IN`, the default deployment's operator's),
   `PODSSH_RELAY_KEYS`, the settings file's `RelayKeys`, and each member of the net that
   carries the role `relay`; `none` trusts no key.
3. The check: a trusted key, its signature of the exact text, the form, a `not_after` ahead
   and a life of 400 days at most, and a serial not below the list kept of its key
   (`crates/podssh-relay/src/pool/kept.rs`); else today's rule, the parent domain alone.
4. The list of deployments: the default host and three hosts of its pool, then at most four
   hosts of the other deployments, each minting a token of its own; none for a list that the
   user names, nor with `PODSSH_RELAY_TOKEN`.
5. The cache: `relay-deployments.json`, the newest list of each key, checked again at each
   read; a list is learned from the pool's refresh after a mint and from `relay info`.
6. The words: `relay info` (the first host's list, kept when it holds), `relay status` and
   `status` (each deployment of the list, and whether its list was signed), `doctor` (a line
   `deployments`).
7. The role: `podssh relay serve --deployment NAME=HOSTS [--list-key FILE]` signs its list
   with a key of its own, and again each day, its fingerprint on its first line.
8. A second deployment of the public default, and its keys, stay the operator's
   (`docs/relay-operator.md`, item 14): no entry waits for them.

The Prove above holds, with the tests of the form, the cache and the role, and of the settings
file's keyword:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib pool
cargo test -p podssh-cli --test relay
cargo test -p podssh-cli --lib settings
```

With test keys made in the tests: a list of a trusted key names a host outside the domain,
which the default list takes; one changed byte (of the text, of the signature, of the cache
file), an old `not_after`, a lower `serial`, a key that is not trusted, and
`PODSSH_RELAY_KEYS=none` keep the parent domain alone. A list that OpenSSL signed, software
that podssh did not write, is taken, and refused once a byte changed. Against podssh's relay
role on the loopback: `relay info` keeps a trusted list, `status` lists its host, `relay
status` names the deployment as signed, and `ssh` reaches the test's server through that host,
which mints its own token; an untrusted key's list is not used. Planted: each check skipped
(the plants `t346-*` of `scripts/plants/`). Live: a role on a runner signs a list, and a client
that trusts its key reaches a server through it (waits, as Q88 lets a live run wait).

## Done

2026-11-04, drafted (`363fcc1`), merged and measured by the main session the same day, with no change
to the draft's code; the draft's change of form, from the Correction's Sigstore bundle to an Ed25519
signature that podssh's relay role makes itself, is kept: it changes no policy of
`docs/decisions.md`, a role has no workflow identity to sign with, and a test makes its own key.
The net's document does not name a relay member's hosts yet, so a client learns a role's list from
`relay info --relay-host` or a refresh of the pool that reaches it: T-617. The form, the check
and the cache in `crates/podssh-relay/src/pool/signed.rs` and `crates/podssh-relay/src/pool/kept.rs`,
the default list's other deployments (`relay::with_others`), the role's signed list
(`crates/podssh-relay/src/serve/docs.rs`, `crates/podssh-cli/src/relay_serve/list.rs`), the
keys and the words of the binary (`crates/podssh-cli/src/relay_deployments.rs`), `RelayKeys`,
the manual, `docs/relay.md`, `docs/relay-operator.md` (item 14), `docs/cli.md` and
`SECURITY.md`.

- `cargo test -p podssh-relay --lib pool`: 21 passed (the tests of `pool::signed::tests`, 11,
  and `relay::tests::the_pool_then_other_deployments_follow_the_default_host`, with the pool's
  own).
- `cargo test -p podssh-cli --test relay`: 14 passed, the two below ran and skipped nothing
  (`relay_signed::a_role_s_signed_list_names_a_deployment_outside_the_domain` and
  `relay_signed::a_list_that_openssl_signed_is_taken`, with the file's others).
- The CLI's whole `--lib`: 842 passed, `settings` (`RelayKeys` adds up, and a bad key names its
  line) and `man::` (the manual's notes, variables and flags) among them; `--test man_flag_parity`
  6, `--test flag_table` 9; `cargo test -p podssh-relay --features serve --lib serve::docs`: 3.
- Planted (`sh scripts/plant-each.sh --here t346-signature-skipped t346-key-untrusted
  t346-ended-kept t346-serial-back t346-token-given t346-named-joined t346-role-unsigned`):
  7 caught, each by the test that its plant names.
- clippy with `-D warnings` of `podssh-cli --all-targets` and of `podssh-relay --all-targets`, with
  no feature and with `serve,plain-ws,quick,pair,grant,piping,code`: clean; rustfmt: clean.
- Waits: the live run of a role on a runner (Q88), and the keys of the default deployment's
  operator, which `BUILT_IN` takes with a release (`docs/relay-operator.md`, item 14).
- 2026-11-04, after the gate of `537a156` (run 41784978197, the job `gate (libs)`): its tests
  left their cache directories in the temporary directory, which the gate refuses (T-272); each
  test's directories now go when the test ends. `cargo test -p podssh-relay`: no new
  `podssh-*` in the temporary directory, `pool::signed` 11 passed.

# T-407: A relay's Retry-After reaches a line as it came, with its terminal controls

**Source:** the draft of T-401 (2026-11-01), which made the quick tunnel's API text one line and
found the relay's own header of 429 not so.
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A relay that answers a mint or a pair with 429 gives a Retry-After, which podssh prints in its
line of the refusal as the header came: ESC, BEL and the rest of a terminal's controls included,
and of any length. A relay, or a proxy on the way, can so write to the user's terminal.

## Premise

- Read: `crates/podssh-relay/src/token.rs:210` and `crates/podssh-relay/src/pair.rs:274` took
  `response.header("retry-after")` as it was, and the lines of `TokenError::RateLimited` and
  `PairError::RateLimited` print it.
- Read: the body of a refusal goes through `Response::body_text`, which `one_line` makes safe
  (`crates/podssh-ws/src/http.rs`).

## Approach

`Response::header_text(name, max)`, a header made safe and cut as `body_text` makes the body;
the two 429s take it, 64 characters at most.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test http
cargo test -p podssh-relay
```

## Done

2026-11-01: `podssh_ws::http::Response::header_text` makes a header one line, with no control
character, cut to its length with an ellipsis; `body_text` shares its cut. The relay's 429 of a
mint (`token.rs`) and of a pair (`pair.rs`) take it, 64 characters at most. `cargo test -p
podssh-ws --test http`: passed, with the new
`a_header_shown_in_a_line_cannot_carry_terminal_controls` (ESC, BEL and a CSI out; the cut; an
absent header). Planted, `header_text` that returns the header as it came: that test failed.

# T-421: A client's lost link during a node's bulk closes the node's whole socket on the relay

**Source:** T-420 (2026-11-01): the stand-in, as strict as the live relay (T-412), closed the node's
socket with 1003 for a frame that was on its way when an operator's link was lost.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

When the link of one operator ends with no Close (a client's network lost, a proxy's RST) while
the node sends that session's bytes, the frames that were on their way meet an id that the relay
forgot, and the relay closes the node's whole socket with `1003 unknown session id`: each other
session of the node is cut too, and resumes only where the layer carries it (T-409, T-410).

## Premise

- Measured on the live relay (T-410): a frame of the node for an id that the relay forgot closed
  the node's socket with 1003, forwarded to each operator.
- Read: the node learns of an operator's loss only from the relay's `close {id}`
  (`crates/podssh-relay/src/reverse/serve.rs`), so it cannot hold such a frame back.

## Approach

The relay drops a frame of the node for an id that it closed in the last few seconds, as a frame
in flight, and keeps 1003 for an id that it never gave or closed long before. podssh needs no
change: its node already drops what comes for a closed session.

## Decision

2026-11-03, the main session (each call with the alternatives that lost):

1. The offline case of the Correction's Prove is a suite of its own,
   `crates/podssh-cli/tests/node_cut.rs`, not a case of `node_moves`: two relays (podssh's role,
   the strict stand-in), each with two sessions and a proxy that cuts one, where `node_moves`
   keeps its one move. Lost: a case in `node_moves`, which would mix a move and a cut in one file.
2. The stand-in tells the node of a lost link a second late (its mode `lateclose:1`,
   `scripts/fake_reverse.py`), as a relay far from its node, so that the node's frames for that
   session come after the relay forgot it each time: with the close at once, the race came in one
   run of two here. Lost: the close at once, which leaves the check to chance; a larger bulk,
   which makes the race likelier and never sure.
3. The planted defect (the backoff again at the first connection after a fault) is caught by the
   node's line, `connecting again at once` after the `1003`, not by the stall alone: the backoff
   adds 0.5 s to 1.5 s, less than the margin of the 3 s bound on a loaded runner. The bound stays,
   as the Correction's Prove says.
4. The role's case makes no race of its own on purpose: the role's grace has its contract test
   (`crates/podssh-relay/tests/relay_serve_contract.rs`), which sends such a frame each time, and
   here the case says that no `1003` reached the node when the race came or not. Lost: a setting
   of the role to tell its nodes late, a surface of the binary for a test alone.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_live -- --ignored
```

From GitHub's network (`relay-live.yml` with `test=node_live`), a client's link cut during a bulk
download through a node: the node's other session goes on, and no 1003 reaches it.

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator (`docs/relay-operator.md`, item 19): a change of the relay.

Lifted on 2026-11-02 by Q63: see below.

The Premise holds: the node learns of an operator's loss only from the relay's `close {id}`. By
Q63 (2026-11-02, `docs/decisions.md`; docs/mesh.md, section 4) the relay is a role of podssh
itself, so the relay's change of the Approach above is podssh's, in its relay role's reverse road
(T-427): a frame of the node for an id that it closed in the last few seconds is dropped as one
in flight, and `1003` stays for an id that it never gave or closed long before. The stand-in
already tells the two apart (`scripts/fake_reverse.py:293-305`), with a grace of 2 s.

What the client does (the research of 2026-11-02 on the client's side), where the default
deployment still closes the socket: make the cut cheap. A 1003 is no exit since T-409, and the
operator's layer resumes since T-410; but the node's first connection again after a fault waits
`backoff(1)`, 0.5 s to 1.5 s (`crates/podssh-relay/src/reverse/node.rs`, line 255 at `d262613`), though a 1003 is no
overload. Since T-379 a resume can land on the iroh or the DERP road
(`crates/podssh-cli/src/ssh/roads.rs:1-14`). The sessions of `node --plain` end with the socket,
and nothing says so.

The new Approach, in place of the one above:

1. podssh's relay role (T-427): a grace of 2 s, the stand-in's, for an id that it closed; such a
   frame is dropped and counted under `-v`; `1003` for the rest.
2. The node: its first connection again after a socket that served, closed for a fault, goes at
   once (with T-255).
3. The manual says that a lost operator can end each `--plain` session of a node on the default
   relay, and names the layer.
4. What `tcp.ssh.relay.ajam.dev` lacks here is no blocker: a note of docs/relay-operator.md
   (item 19).

The new Prove, in place of the one above:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_moves
cargo test -p podssh-cli --test node_live -- --ignored
```

Offline (`node_moves`, a new case): two layered sessions through one node and podssh's relay
role; an RST of one operator's link (`scripts/fake-proxy.py`) during 32 MiB down: no 1003, and
the other session goes on with equal digests. Against the stand-in in its strict mode the 1003
comes, and the other session's longest stall is under 3 s. Planted: the backoff back at the
first connection again; the stall check fails. Live, from GitHub's network (`relay-live.yml`
with `test=node_live`), against `podssh relay serve` on the runner: the node's other session goes
on, and no 1003 reaches it.

## Done

2026-11-03. Items 1, 2 and 4 of the Correction's Approach were in place: the role's grace of 2 s
for a frame of a session that it closed (`IN_FLIGHT`, `crates/podssh-relay/src/serve/reverse/pairs.rs`,
dropped and counted, with its contract test), the node's first connection again at once after a
socket that served (T-255, `again_at_once`), and item 19 of `docs/relay-operator.md`. Done now:

- Item 3: the manual's note of the node (`crates/podssh-cli/src/man/notes_pair.rs`) says that on
  the default relay one operator's lost link can end each `--plain` session of the node, that
  `podssh relay serve` drops such a frame, that the layer resumes its sessions, and that the node
  connects again at once.
- The offline case of the Prove (`crates/podssh-cli/tests/node_cut.rs`, Decision 1): two sessions
  of the layer through one node, 24 MiB and 48 MiB down from the tests' SSH server; the first
  through `scripts/fake-proxy.py`, which resets its link with RST at 6 MiB, the second straight to
  the relay and in its middle then. Each ends with exit 0 and each byte (`0x5a` each), the cut
  resumes, and the second never waits 3 s. Against podssh's relay role: no `1003` reaches the node.
  Against the stand-in in its mode `lateclose:1` (Decision 2): the `1003` comes, and the node's
  line says `connecting again at once`. The harness lets a test that makes the race on purpose
  claim the stand-in's lines of an unknown id (`Session::claim_unknown_ids`), which fail each other
  test's end.

Measured, 2026-11-03, here:

- `cargo test -p podssh-cli --test node_cut`: 2 passed (with the harness's own, 3), five runs in a
  row; the longest wait of the session that went on: 0.38 s to 0.51 s through the role, 0.97 s to
  1.54 s through the stand-in, whose 1003 came in each run. Each run takes about 90 s.
- Planted (`sh scripts/plant-each.sh --here t421-backoff-after-a-fault`): caught, "the node went
  again at once: podssh node: lab: the relay closed the node for a fault of this node: 1003 unknown
  session id; connecting again in 1.1 s".
- `cargo test -p podssh-cli --test node_moves`: passed with the harness's change; the manual
  (`--lib man::` 40, `man_page`); `cargo clippy -p podssh-cli --all-targets -D warnings` and
  rustfmt: clean.

Waits: the Prove's live run from GitHub's network against `podssh relay serve` on the runner
(`relay-live.yml` with `test=node_live`, whose suite has no cut of an operator's link; with the
checks of the release, Q88).

# T-563: The relay's record forgets a host that opens, and one road's failure moves the host on each road

**Source:** GitHub #110 (a tester, 2026-11-02).
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A host that opens and dies within seconds is ordered as a host that has worked for a week, as
the record keeps failures alone and forgets each success; and a failure on one road demotes the
same host on each other road, as the record is keyed by the host alone.

## Premise

Read, at `1769d79`, in `crates/podssh-relay/src/failures.rs`:

- line 29 says "pub struct Records {", one map of hosts.
- line 35 says "pub struct Record {": a time and a reason, no success.
- line 82 says "self.hosts.remove(host);": an open forgets the host.

## Approach

1. `Record` keeps the time of the last open and a count of opens; an open clears the reason and
   keeps the host. An open whose session lasted under 300 s is a strike, and two in a row rest the
   host 300 s.
2. The key is the road and the host, so that one road's verdict stays on that road.
3. `order` puts a host that opened lately before one that merely did not fail; `recent` says
   "opened 4 s ago" beside "failed 30 s ago".
4. The cache file is the same, mode 0600; a file of an older podssh, with no new field, reads as
   now (each field defaults).

## Decision

Fields with defaults in the one cache file, so an older podssh and a newer one share it. Lost: a
second file, a new permission story for no gain.

Calls of the draft (2026-11-02, Q86), with what lost:

- **For the operator to confirm (Q86): a strike is a session that its host's side cut, not each
  short session.** Taken as the Approach wrote it, two runs of `git fetch` through `ProxyCommand
  podssh proxy`, a few seconds each, would rest a host that works. A cut is the relay's Close for
  its link to podssh (`ForwardClose::Client`: no Close, `client send failed`, `client receive
  backlog`) or a link that failed with no Close; the target's end, the client's own, the relay's
  limits (1001, 1009) and a close that the relay's table does not list are none, and break the
  row. Lost: each short session, which rests a host for a command that was short; the relay's
  limits as strikes, which would rest a host for a session that carried its 64 MiB.
- **For the operator to confirm (Q86): a host that opened goes first with no note**, and keeps
  its place while it opens, its last session not cut; the host before it in the list starts 2 s
  after it in `staggered`, so it costs no wait while the first answers. Lost: a note in each run,
  which `podssh proxy` as a `ProxyCommand` would print at each connection for as long as the host
  works; the list's order among the hosts that did not fail, which is the defect.
- The WebSocket road's hosts stay under `hosts`, each other road under `roads`, by its name: an
  older podssh reads the WebSocket road's entries as before and skips the rest; `at_ms` and
  `reason` are written always, a host that opened with `at_ms` 0, which an older podssh reads as
  a failure long ago and drops. Lost: one map keyed by `ROAD HOST`, which an older podssh would
  keep as hosts that never match and never clear. Each run that opens now writes the file once (a
  few hundred bytes), where a run wrote it only when a failure changed; two runs at once keep the
  last one's, and an entry lost costs one wait, as before.
- The end of a session is told by the stream that SSH holds, when SSH lets it go: the relay leg
  sets its end before its pipe ends, so the end is known then. This covers each command that
  reaches its first hop as `podssh ssh` does (`cp`, `each`, `job`, `run`, `sftp` and the others);
  `podssh proxy` and the relay's end of `podssh pipe` tell it at their own end; `podssh chat`,
  `podssh doctor` and the blocking facade record their opens alone. Lost: a hook in the task of the
  relay stream of `podssh-ssh`, a callback in a struct for no gain; a task that polls the status.
- Two strikes in a row rest the host 300 s from the last; the row lasts across the opens between
  the cuts, as they are what makes it a row, and goes with the entry (10 min with no open, no
  failure and no strike).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib failures
```

A host that opened is kept and ordered first; two short sessions rest it; a failure of the iroh
road leaves the WebSocket road's order alone; an older file reads. Planted: the open that removes
the host again, and the test of the order fails.

## Correction

2026-11-02 (the drafting agent). The record is keyed by the host alone, as the Premise says, but
at `1769d79` one road alone writes and reads it: `open`, the relay's forward road over WebSocket
(`crates/podssh-relay/src/open.rs:222-273`), which `ssh`, `proxy`, `pipe`, `chat`, `doctor` and
the blocking facade share; `status` and `doctor` read it. No other road (iroh, DERP, a node's
pair, the forwarders) orders its hosts by it, so a failure on one road moves no host on another
road yet: the key by road keeps it so once a second road records (T-563 makes the place for it),
and the Prove's iroh road is a road that the test names. The Approach stands, with the calls of
the Decision: a strike is a session that its host's side cut (the first call).

## Done

Drafted 2026-11-02 by a drafting agent, which built nothing; merged and measured by the main
session on 2026-11-03.

- `crates/podssh-relay/src/failures.rs`: `Record` keeps `opened_ms`, `opens`, `strikes` and
  `struck_ms` beside `at_ms` and `reason`, each with its default
  (`crates/podssh-relay/src/failures.rs:53-71`); `Records` keeps the WebSocket road under `hosts`
  and each other road under `roads` (`crates/podssh-relay/src/failures.rs:41-51`); an open clears
  the failure and keeps the host (`crates/podssh-relay/src/failures.rs:167-190`); `Records::end`
  counts a cut within `SHORT` as a strike and breaks the row on each other end
  (`crates/podssh-relay/src/failures.rs:192-211`), and `ended` keeps it in the cache; `order` puts
  a host that opened lately first and one that failed or rests last, with its note
  (`crates/podssh-relay/src/failures.rs:231-255`); `recent` gives each road's hosts with what
  failed and what opened (`crates/podssh-relay/src/failures.rs:268-284`). `open` names the
  WebSocket road (`crates/podssh-relay/src/open.rs:223`, `crates/podssh-relay/src/open.rs:268`).
- `crates/podssh-cli/src/relay_ends.rs`: what a cut is (`cut_by`, `cut`), and `Told`, the relay
  stream that tells the record how its session ended once SSH lets it go, which
  `crates/podssh-cli/src/ssh/transport.rs:225` spawns. `podssh proxy`
  (`crates/podssh-cli/src/proxy.rs:411`) and the relay's end of `podssh pipe` (`carry_opened`)
  tell it at their end (`crates/podssh-cli/src/pipe/relay.rs:210-212`).
- `podssh status`: `relay_failures` names the road, and `relay_opened` gives the hosts that opened
  lately (`crates/podssh-cli/src/status.rs:225-232`); `podssh doctor`'s line `failed relays` says
  each host tried last, and a line `opened relays` those tried first
  (`crates/podssh-cli/src/doctor/mod.rs:285-313`). THE RELAY in the manual
  (`crates/podssh-cli/src/man/facts/failed.rs:11-28`), `docs/relay.md` (step 5 of the selection) and
  `docs/cli.md` (`podssh status`).
- Tests: in `crates/podssh-relay/src/failures_tests.rs`, the five of T-059 on the road, the round
  that keeps the host that opened, and `a_host_that_opened_lately_is_tried_first`,
  `two_short_sessions_in_a_row_rest_the_host`,
  `a_failure_on_one_road_leaves_the_other_road_s_order_alone`,
  `the_recent_entries_say_both_what_failed_and_what_opened`,
  `an_older_file_reads_and_an_older_podssh_reads_this_one`; in `relay_ends`,
  `only_an_end_on_the_host_s_side_is_a_cut`. `cargo test -p podssh-relay --lib failures`:
  10 passed. `cargo test -p podssh-cli --lib relay_ends`: 1 passed. `cargo test -p podssh-cli
  --test status`: 5 passed (the line has a new key, which no test reads). The relay's suite with
  the gate's features (`pair,quick,derp,serve,piping`): 526 passed, 22 ignored; `--test proxy`,
  10; `--test pipe`, 10; `--test doctor`, 13; `--lib man`, 66.
- Planted, `scripts/plants/t563-open-forgets.patch` (the open that removes its host again): the
  test of the order must fail: `sh scripts/plant-each.sh --here t563-open-forgets`, caught. `scripts/plants/t059-faults-recorded.patch` is made
  again for the new `order`; its patch applies (`git apply --check`); its run (`ssh-faults`, the build image):
  through `plants.yml` on a runner.
- Waits for the checks of the release (T-251): the gate's `faults.recorded.*` of
  `scripts/interop-faults.sh` in the build image, whose second run now finds `relay-a.test`
  first, as it opened in the first run, and `relay-silent.test` last with its note: the gate's step `release` at the push.
- The merge: T-463 had changed the relay's end of a pipe (`carry_watched`, the clock of the idle
  warning) where the draft changed it too (`carry_for`, the record): one `carried` takes both the
  host and the clock, and `carry_watched` takes the opened session, so `podssh proxy` keeps both.
  The manual's THE RELAY grew `man/facts.rs` to 501 lines: its EXIT STATUS went to
  `man/facts/exit.rs`. `cargo todo remap` from the tree before the draft; rustfmt and clippy of
  `podssh-relay` (also with the gate's features) and `podssh-cli` with `-D warnings`, all targets:
  clean.
- `docs/STATUS.md`: a row in "Build, tests, CI".
- 2026-11-03, the gate at the push (`7abebd2`, run 41562803113, its step `release`): `interop:
  610 passed, 3 failed`, each later push the same. `faults.proxy_502.failover`,
  `faults.persist.reattach` and `faults.persist.tunnel` each list `relay-a.test` second, and the
  tests before them had opened it, so it went first as this entry wants: no 502 for the first
  host, and the kill ended a host that carried nothing (`exit 0`, no `connecting again`). The
  order is this entry's; the three tests lean on the list's order, so each takes an empty record
  of its own (`RC`, as `faults.failover_mode.one_mint` does) and asserts what it asserted. With
  the dry run's static binary of `3bb42ea` in the build image, `INTEROP_ONLY=faults sh
  scripts/interop.sh BIN` (this cloud session's host, twice): the three passed, 130 passed and 1
  failed, `faults.stuck_write`, which this host fails apart from this entry (T-598).

# T-593: The cache follows `HOME` into another user's home: root's node key goes under that user's `.cache`, which podssh can make root's own

**Source:** GitHub #118 (a tester's agent, 2026-11-02): run as root with `HOME` set to another
account's home, as containers and notebooks do, `podssh node` wrote its key under that home's
`.cache/podssh`, mode 0600 and owned by root; the line of the node's start named the path and
the fingerprint. It asks for the cache from the passwd entry of the uid, or `HOME` only when the
uid owns it. Read at `3bb42ea`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

podssh's cache (the keys, the pins, the tokens, the logs of detached runs) goes to
`HOME/.cache/podssh` whoever owns `HOME`. Run as one user with the home of another, podssh puts
the first one's files in the second one's tree, which that user's tools take for their own; and
where that `.cache` is missing, podssh makes it, mode 0700 and owned by the running user, so the
home's owner can no longer use a cache of their own. A defect: the decision names "the user's
cache directory" (`docs/decisions.md:98`), and this one is another user's.

## Premise

- Read: the user's cache directory is `XDG_CACHE_HOME`, else `HOME/.cache`, and their owner is
  never read (`crates/podssh-relay/src/cache/dirs.rs` lines 67-74 at `3bb42ea`).
- Read: the cache's directory is made with each missing parent, mode 0700, and only the last one,
  `podssh`, is checked for its owner (`crates/podssh-relay/src/cache.rs` lines 389-398 at
  `3bb42ea`). Known: `std::fs::DirBuilder` with `recursive(true)` gives its mode to each directory
  that it makes, so a missing `.cache` in the other home becomes the running user's, closed to its
  owner.
- Read: a key is looked for in each directory of the list before one is made
  (`crates/podssh-relay/src/identity/file.rs` lines 97-110 at `3bb42ea`): a list without that home
  would make a new key, a new identity, for a node whose operators pinned the old one.
- Read: the tokens' row of the decisions names "the user's cache directory, the user's runtime
  directory, the temporary directory, the working directory" (`docs/decisions.md:98`); Q68 reads
  the effective uid's entry of `/etc/passwd` as a file, for the login name
  (`docs/decisions.md:38`, T-500).

## Approach

1. On Unix, `XDG_CACHE_HOME` and `HOME/.cache` are the user's cache only when the nearest of their
   directories that exists (the directory, else its parent, else `HOME`) belongs to the effective
   uid. Else the home of the effective uid's entry of `/etc/passwd` (read as a file, as T-500
   reads it), when the uid owns it, gives its `.cache` in their place; else the list goes on as
   now (the runtime directory, the temporary one, the working one).
2. No directory but `podssh` itself is made in another user's tree: a missing parent is made only
   under a directory that the uid owns.
3. A file that podssh kept in another user's home before stays where it is, and is read there (a
   key is an identity): a key, a pin or a token found there is used, and the run says once that it
   is in a directory of another user's home, and where to move it to keep it; podssh moves
   nothing.
4. `podssh status` and `doctor` name the cache's directory, and each one passed over with why.
5. The manual's FILES, `docs/architecture.md` (the cache), `docs/STATUS.md`.

## Decision

For the operator to confirm (Q86), a reading of "the user's cache directory" of the tokens' row:

- A home of another uid is not the user's; the passwd entry's home comes next, as OpenSSH finds
  `~/.ssh` by the passwd entry and not by `HOME` (Known). Lost: the passwd entry first, OpenSSH's
  rule, which would pass over a `HOME` that a user set to move podssh's files, as the tests and a
  cage with no passwd entry do; `/var/lib/podssh` or `/run` (the issue's other choice), places of
  the system that no package of podssh owns, after which the list already has the runtime and the
  temporary directories.
- A file there is read, never moved: a node keeps its identity under its operators' pins. Lost: a
  move, which puts a credential where the user did not look; and a refusal, which would stop a
  node that ran the day before.
- Windows keeps `LOCALAPPDATA` as it is: no report names a profile of another user there.

The draft's calls (2026-11-03), within that reading:

- The walk (Approach 1): each directory of the place that exists, from it up to `HOME` when the
  place is in it, else up to `/`, belongs to the uid or to root, as OpenSSH's StrictModes walks a
  key's path up to the home (its function `safe_path`, Known). Lost: the nearest
  existing directory alone, which keeps a `.cache` that an earlier run made root's in the other
  home, the very tree of #118; the uid alone, which passes over `/tmp` (the tests' `HOME`) and a
  home of root's that a service account has; a walk past the home, which passes over a home in a
  directory that another user shares.
- A missing directory above the cache's own is made only in a directory of the uid or of root
  (Approach 2 says the uid's): a user makes one in root's tree only where root lets everyone, as
  in `/tmp`. The cache's own directory is made in any directory that lets the uid in, as
  `PODSSH_CACHE_DIR` may name one. Lost: the uid's alone, which refuses `HOME=/tmp`.
- `XDG_CACHE_HOME` passed over, `HOME/.cache` is tried next, then the passwd entry's home; a home
  that names no other place guesses none. `XDG_RUNTIME_DIR` is walked too, as the XDG spec makes it
  the user's own: root with another user's runtime directory kept its files there as well. The
  temporary directory (shared by design, and tagged with the uid), the working directory (last, and
  where the user runs) and `PODSSH_CACHE_DIR` (the user's own choice) are not walked.
- The order of reading: the user's own places first, then each place passed over. podssh writes
  again in its own places a token, a pair that it renews and the pins; read first, the old copy
  would hide each. Lost: the old place at its own rank, which keeps the order of before when both
  hold a file of a name, and would never read a newer token or a renewed pair.
- What is read there: a key, the pins, a pair and a token, the files that are an identity or what
  an operator pinned. A new pin of pins found there goes into a copy of that file, with its lines,
  in the user's own cache, so no pin is lost and nothing more is written there. A refused token
  and a removed pair are also removed there, podssh's own files, so that they are not read again.
  The other files (the pool, the addresses, the record of failures, the logs and locks of detached
  runs, the sessions, the net's document, ACME's and Arti's state) are made again or come again,
  and are not read there.
- What is said: a node's start line on each road (the relay's, iroh's, DERP's, chat's) and the
  client's key (the channel's, the iroh road's) say once where a key read there is, why, and where
  to move it: into the user's own cache when there is one, else into a directory that
  `PODSSH_CACHE_DIR` names, as the runtime and temporary directories do not last. The library says
  nothing, as before; a token or pins read there are not said, and `status` (`cache.passed`) and
  `doctor` name the place.
- No passwd entry (a cage with no entry for the uid, `docker run --user N`): the list goes on with
  no user's cache, and the place passed over is still read. macOS reads `getpwuid_r` first, then
  the file, as T-500 does. `doctor` makes a directory to probe as the cache makes it, and removes
  each that it made, where before it made the parents with `create_dir_all` and left them.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test cache
cargo test -p podssh-relay --lib cache::
```

New tests (Unix), with the owner of each directory given to the list by the test, so that they
run as any user: `a_home_of_another_uid_is_passed_over_for_the_passwd_home`,
`no_parent_is_made_in_another_user_s_home` and `a_key_kept_there_before_is_read_and_said`. In the
box (`scripts/test_in_box.sh`), as root with `HOME` of another account: the node's key goes to
root's own cache. Planted: `t593-owner-unchecked` (the owner not read): the first two tests fail.

## Correction

Approach item 5 names `docs/architecture.md` for the cache: its place is written in
`docs/relay.md` (the paragraph of T-243, `docs/relay.md:243-251`), and `docs/architecture.md` says
nothing of it. The draft writes `docs/relay.md`, and `SECURITY.md` (the cache in its user's own
tree).

## Done

2026-11-03, drafted by an agent and merged here, after T-586 and T-588.

- `crates/podssh-relay/src/cache/owner.rs` (Unix): the owner of each directory, a symbolic link
  its own owner's when that is neither root nor its target's; the walk of `foreign` up to the home
  (else `/`), the uid's or root's; `make_dirs`, which makes a directory above the cache's own only
  in a directory of the uid or of root; the home of the uid's entry in `/etc/passwd`, read as a
  file (16 MiB at most, as T-500), and on macOS `getpwuid_r` first. `Host` gives the tests the
  uid, the owners and the user database.
- `crates/podssh-relay/src/cache/dirs.rs`: `Places` (the directories written, the user's cache,
  each place passed over and why), `places`, `places_from`, `places_with`, `read_dirs` and
  `kept_note`; `candidate_dirs` is `places().dirs`. `crates/podssh-relay/src/cache.rs`:
  `make_private_dir` makes its parents by `make_dirs`; `load`, `peek` and `remove` of a token read
  the places passed over last; `make_dirs` for `doctor`. `identity/file.rs` (`load_split`),
  `identity/pins.rs` (`check_split`, and the copy of pins found in a place passed over) and
  `pair.rs` (`load`, `labels`, `remove`) read them too.
- The CLI: the note at each node's start line (`channel.rs`, `node_iroh.rs`, `node_derp.rs`,
  `chat/listen.rs`) and at the client's key (`channel.rs`, `ssh/iroh/dial.rs`,
  `ssh/iroh/race.rs`); `status`'s `cache.passed`; `doctor`'s line `token cache`, which names each
  place passed over, makes its probe's directories as the cache does and removes each that it
  made. The manual: FILES (the cache) and the notes of `status`. `docs/relay.md`, `SECURITY.md`,
  `docs/STATUS.md`. The manual's test of the cache's directories takes a directory of its run's
  name under the temporary directory, whose owner is read now.
- Tests: `cache::owner::tests` (4, the walk and the passwd file, with the owners given and no
  file touched) and, in `crates/podssh-relay/tests/cache_owner/mod.rs` of the target `cache`, the
  three named: `cargo test -p podssh-relay --test cache`, 21 passed, as root here (the merge
  repaired the tests' other uid, `me - 1` evaluated for uid 0, and clippy's
  `cloned_ref_to_slice_refs`); `--lib cache::`, 8 passed. `cargo test -p podssh-cli --test status`
  (its `cache.passed`), `--test doctor`, `man_page`, `flag_table` and the lib: 5, 13, 10, 9 and 657
  passed. clippy of `podssh-relay` (also with the gate's features) and `podssh-cli` (also with
  `--features iroh`), all targets, `-D warnings`, and rustfmt: clean. macOS's `getpwuid_r` and
  Windows: the gate's jobs at the push.
- Planted: `scripts/plants/t593-owner-unchecked.plant` (the owner never read, `git apply --check`
  passed on the draft), `sh scripts/plant-each.sh --here t593-owner-unchecked`: caught
  (`a_home_of_another_uid_is_passed_over_for_the_passwd_home` failed).
- Waits until podssh is stable (Q88): the box as root with `HOME` of another account
  (`scripts/test_in_box.sh`), the node's key in root's own cache.

# T-610: `relay info` shows the relay's `rank` and `score_ms`, which change with the edge that answered, as an order

**Source:** GitHub #125 (aerrand-agent, 2026-11-03): three calls of `podssh relay info --json`
two seconds apart, from one host through one proxy, were answered by the edges NRT, SIN and ARN;
each of the 37 hosts changed its `rank` and its `score_ms` between the first and the third, and
the pool came back in another order. Against a measured upgrade through each host, Spearman's rho
of `score_ms` was -0.371: the host of rank 0 took 1,030 ms, and the fastest (575 ms) was at
rank 22.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`relay info` prints the relay's pool in the relay's order, with a field named `rank`, which reads
as podssh's advice; the relay computes it from the edge that served that one request, as its own
`policy.note` says ("probe /health on each host and keep the fastest for your path"), so two calls
disagree, and neither is about this host's path.

## Premise

- Read: `podssh relay info` prints the relay document's `pool` with its `rank` and `score_ms`
  (`crates/podssh-cli/src/relay_diag_text.rs`), in the relay's order.

## Approach

1. Say what the numbers are: the relay's estimate from the edge that answered, named
   (`you.edge_colo`), not a measurement of this host; with `--json`, the relay's fields unchanged
   beside it.
2. The order that podssh advises is a measured one: `relay status`, which measures each host
   now, and a rank on demand (the research of the operator's relay archive proposes one); the
   text says so, and points to them.

## Prove

```sh
cargo test -p podssh-cli --test relay_info
```

Two documents of the stand-in relay, answered by two edges with opposite ranks: each text names its
edge and says that the rank is the relay's estimate from it; planted, the line dropped: the test
fails.

## Correction

- 2026-11-03: the Prove's test file `relay_info` does not exist: `relay info`'s test is
  `info_gives_the_pool_the_limits_and_the_url_for_a_target` in `crates/podssh-cli/tests/relay.rs`,
  against the stand-in relay, which answers from one edge. The two edges with opposite ranks are a
  unit test of the text, `crates/podssh-cli/src/relay_diag_text.rs`, which reads the relay's JSON
  alone.

## Done

2026-11-03:

- `crates/podssh-cli/src/relay_diag_text.rs`: the pool's line says "in the relay's order", and
  that the rank and the score are the relay's estimate from the edge that answered (named when the
  document names it), which changes with the edge, not a measure of this host's path; after the
  pool, a line names `podssh relay status` (the hosts that podssh tries) and `podssh ping
  --relay-host HOST` (one), which measure from this host. `pool_order`, for `--json`.
- `crates/podssh-cli/src/relay_diag.rs`: `relay info --json` keeps the relay's document unchanged
  under `info` and adds `pool_order`: `{"by": "relay", "edge": ..., "measured_here": false}`, null
  with no pool.
- The manual's note of `relay info` (`crates/podssh-cli/src/man/notes_relay.rs`) and
  `docs/cli.md` say the same.
- Tests: `the_pool_is_the_relays_order_from_the_edge_that_answered` (two documents from NRT and
  SIN with opposite ranks: each line names its edge, the line of the measures follows the pool,
  `pool_order` names the edge; no edge: "the edge that answered"); the stand-in's test of `relay
  info` reads the new lines and `pool_order`. `cargo test -p podssh-cli --lib`: 781 passed;
  `--test relay`: 11 passed; `--test man_page --test man_flag_parity`: 6 and 12 passed; clippy
  `--all-targets -D warnings`: clean.
- Planted (`scripts/plants/t610-pool-as-advice.plant`, the old line "pool, best first"): `sh
  scripts/plant-each.sh --here t610-pool-as-advice`, caught.
- An order that podssh measures and keeps is T-606's (`podssh relay rank`), and its use by the
  default list T-607's; once they are done, the line names the rank too.
- 2026-11-03, after: the gate's step `release` failed at `e0a2496` and `5f0165b` (runs 41694485243
  and 41698555205): the interop check `relay.info` (`scripts/interop-relay.sh`) still read the old
  line `pool, best first: 1 hosts`. It now reads the new line of the pool and the line of the
  measures from this host; its greps were run here on the lines of that run's log.


# T-605: A harness that measures the relay hosts and the roads through podssh's own binary, adapted from the operator's archive of relay research

**Source:** The operator, 2026-11-03: an archive of relay research that the operator's agent
produced (`ff-relay`, under 0BSD), and the words "we should copy/adapt some of the
scripts/measurement harness, after improving them to fit our needs better". Read by a drafting
agent the same day: `docs/research/relay-measurement.md`.
**Category:** measurement
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

No repeatable measurement of podssh's relay hosts and roads exists. `podssh ping` measures the
default host and three alternates once, and `doctor` checks them; nothing measures each host of
the pool in rounds, keeps the figures as JSON, or runs by hand in GitHub Actions. The archive's
harness measures, but with a WebSocket client of its own, not podssh, and with defects that change
its results: cells that run at once and share one link, the dial counted in each rate, a Wisp
request never sent as Wisp, a proof of the write leg that holds for one kind of server, the proxy's
URL written into each result, and a download target that is no test target of `AGENTS.md`.

## Premise

- Read: `podssh ping` times the token, the dial, TLS and the upgrade of one host, then its
  WebSocket pings (`crates/podssh-cli/src/ping/relay.rs:102-150`), one host after another
  (`crates/podssh-cli/src/ping/mod.rs:167-172`), with `--json`.
- Read: `doctor`'s `forward` proves both legs by one of GitHub's published host keys
  (`crates/podssh-cli/src/doctor/relay_checks.rs:197-228`); `--quick` keeps the relay's sections and
  `--jobs 1` runs them one at a time (`crates/podssh-cli/src/flags/relay.rs:159-163`).
- Read: `podssh relay trace` asks the relay to dial a target and gives its own times
  (`crates/podssh-cli/src/relay_diag.rs:182-185`); `relay info` gives the pool
  (`crates/podssh-cli/src/relay_diag.rs:133-135`).
- Read: the archive's harness and its defects, each at its file
  (`docs/research/relay-measurement.md`, section 3); its license, 0BSD, as podssh's (`LICENSE`).
- Read: a session's test targets are the live relay, GitHub's SSH endpoint and the operator's
  server of `PODSSH_THROUGHPUT_SSH` (Q38), the forwarders of Q56 from GitHub Actions alone, short,
  and the Wisp demo server, short (`AGENTS.md`, section 4).

## Approach

1. `scripts/relay-measure.py`, with `scripts/relay_measure_lib.py` (the numbers and the rank) and
   `scripts/relay_measure_selftest.py` (offline, against a stand-in podssh), drafted with this
   entry: the stages `pool` (`ping --json --relay-host HOST --target T`), `trace` (`relay trace
   --json`), `forward` (`doctor --quick --json --jobs 1 --relay-host HOST`), `roads` (`doctor
   --quick --json` with a road's flags) and `dest` (`ping --json DEST`); one podssh at a time;
   rounds in a new random order from a seed that the result keeps; a limit on each run and a
   budget on the whole; one JSON result, and `--ci` for GitHub's step summary.
2. A workflow by hand only, .github/workflows/relay-measure.yml, from the draft in the report's
   section 7, with the pins of `.github/workflows/forwarder-live.yml`.
3. The stage `dest` in the workflow, with the operator's server of `PODSSH_THROUGHPUT_SSH` and its
   key from the repository's secrets, as the throughput run takes them; an input names it.
4. `docs/development.md`, "Live tests": the harness, its self-test and the workflow.
5. A short run from the session's host, then one of the workflow; the figures in
   `docs/STATUS.md`, and in the report what they say of its inferences (the 5 s of the resolver,
   with the CONNECT timed apart).

## Decision

- Each figure from podssh's binary, not from a client of the script's own: the archive's client
  measured what podssh does not do and broke what podssh does (Wisp's packets, binary bytes in
  text frames). Lost: the relays that podssh does not speak, which Q79 keeps unnamed in any case.
- One podssh at a time, with 250 ms between two: the archive's cells at once measured shares of
  one link. Lost: time; 37 hosts in 5 rounds take about 10 minutes.
- The write leg by `doctor`'s host key of GitHub, not by a KEXINIT after a version line, which a
  server that sends its KEXINIT unasked passes. Lost: a write leg to a target that is no SSH
  server, which podssh's sessions do not need.
- Python's standard library alone, as `scripts/capture-close.py`. Lost: nothing; the script
  speaks no protocol.
- The workflow is drafted in the report, not in `.github/`: the drafting agent's brief kept its
  changes to `docs/research/`, `TODO/` and `scripts/`.
- The drafting agent ran the offline self-test on 2026-11-03 (no network, no podssh): each check
  passed, and with `RELAY_MEASURE_PLANT=parallel` one failed, 7 runs overlapping. Each claim of
  what a stage measures through a real podssh is UNVERIFIED.

## Prove

```sh
python3 -I scripts/relay-measure.py --self-test
RELAY_MEASURE_PLANT=parallel python3 -I scripts/relay-measure.py --self-test   # must exit 1
export CARGO_BUILD_JOBS=4
cargo build -p podssh-cli --bin podssh
python3 -I scripts/relay-measure.py --podssh target/debug/podssh --stages pool,trace,forward \
    --hosts 4 --rounds 2 --out .work/relay-measure.json
gh workflow run relay-measure.yml --ref main -f hosts=all -f rounds=3
```

The self-test passes, and fails with the plant on two runs that overlap. The live run gives each of
four hosts two legs, two traces and GitHub's key, and its JSON holds no token, no proxy address and
no credential (a search of the file for each). The workflow passes and uploads its JSON.

## Correction

- 2026-11-03: step 3's Premise does not hold: no workflow takes the operator's server of
  `PODSSH_THROUGHPUT_SSH` or its key from the repository's secrets; the throughput run reads them
  from the operator's own environment (T-157). The workflow takes them from the secrets
  `PODSSH_THROUGHPUT_SSH` and `PODSSH_THROUGHPUT_KEY` when both are set, and leaves the stage out
  with a line when they are not. The stage itself is measured here against a throwaway sshd on
  the loopback by `--direct`, which needs no secret.

## Done

2026-11-03. The drafting agent's harness is merged (step 1 and the first half of step 5).

- `scripts/relay-measure.py`, `scripts/relay_measure_lib.py`, `scripts/relay_measure_selftest.py`:
  the harness as drafted. The live run below found that podssh's own leg names the proxy it went
  through (`"connect": "CONNECT through HOST:PORT"`, as `ping` tells its user), and that the
  harness kept that line in the result and printed it in the run's lines: 8 times in the result of
  4 hosts. The runner now reads each line of podssh with the proxy's URL, its host and port and
  its credentials replaced by "the proxy" (`lib.proxy_words`, `lib.scrub`), and the result is
  scrubbed once more before it is returned. The self-test's stand-in names its proxy as podssh
  does, in the leg and in a failure's line; two checks are new: the leg's line is kept with the
  proxy's words out, and the run's lines hold no proxy address.
- `python3 -I scripts/relay-measure.py --self-test`: each check passed;
  `RELAY_MEASURE_PLANT=parallel`: 1 failed, 7 overlaps, exit 1. With the stand-in that names its
  proxy and the harness unfixed: the check of the result failed.
- `scripts/plants/t605-proxy-in-lines.patch` and `.plant` (the runner's scrub left out):
  `sh scripts/plant-each.sh --here t605-proxy-in-lines`, caught (the check of the run's lines
  failed).
- Live, from the session's host through its proxy, 2026-11-03:
  `python3 -I scripts/relay-measure.py --podssh target/debug/podssh --stages pool,trace,forward
  --hosts 4 --rounds 2 --seed 605`: 22 runs of podssh, exit 0; each of 4 hosts opened 2 of 2, its
  trace answered, and GitHub's key came through it; open p50 335 ms (`tcp`), 538, 561 and 729 ms.
  The result holds no proxy address, no proxy URL, no JWT and no word `Bearer` (a search of the
  file for each); the run's lines hold no proxy address either.

Then, the same day (steps 2 to 4):

- `.github/workflows/relay-measure.yml` (new), by hand: the build, the self-test, then the stages
  of its inputs (`stages`, `hosts`, `rounds` from 1 to 20, `roads` separated by `;`), the JSON as
  an artifact and the rank in the step summary; `dest` with the two secrets, or left out with a
  line. Its shell, run here with its inputs set by hand: the arguments of each case, the key's
  file at 0600, and `rounds` of `abc` or `21` refused (2).
- The stage `dest` against a throwaway OpenSSH sshd on 127.0.0.1 with a throwaway key, by
  `--ping-road '--direct -p PORT'`, and the stage `roads` with `--relay-host
  tcp.ssh.relay.ajam.dev`: 3 runs of podssh, exit 0; the login 45 ms, 72.6 MiB/s down and
  158.0 MiB/s up on the loopback; the road's 33 checks, GitHub's key through the relay among
  them, ok but two that `--quick` leaves out (`unknown`). No proxy address in the result or the
  lines. The sshd and both keys are deleted.
- `docs/development.md`, "Live tests": the harness, its self-test, its stages and the workflow.

Step 5, the workflow (`relay-measure.yml` at `d629249`, run 41687172170, `hosts=all`, `rounds=2`,
stages `pool,trace,forward`): passed in 8 minutes with its build. The self-test passed on the
runner; 187 runs of podssh, none left out by the budget; each of the 37 hosts of the pool opened 2
of 2 and passed GitHub's key through it; the time to open, p50, went from 138 ms
(`tcp-mx-central-1`) and 187 ms (`tcp`) to 496 ms (`af-south-1`) and 988 ms (`ap-south-2`); the
ping, p50, from 25 to 296 ms. Within 50 ms the rank keeps the list's order, so `tcp` stays first
beside `tcp-mx-central-1`, as the tie rule says. The stage `dest` was not asked; the run says that
its secrets are not set. The JSON is the run's artifact.


# T-606: `podssh relay rank`: each relay host measured on demand, and the rank kept in the cache beside the record of failures

**Source:** The operator, 2026-11-03: "maybe even include it in podssh itself so it can rank relays
on demand and then use". The design is `docs/research/relay-measurement.md`, section 8.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh tries the default host and the first three hosts of its pool, in the order of
`/relays.json`, and never measures the other hosts of the pool. That order is the one of the edge
that answered at the last refresh, and its score did not agree with measured latency. A user cannot
ask podssh which hosts are best from this host, and podssh keeps no measured time of a host. The
archive of 2026-11-03 found each of the 37 hosts working, so the choice of three is a choice among
working hosts, which a measurement can make.

## Premise

- Read: `crates/podssh-relay/src/relay.rs:78` says "pub const MAX_ALTERNATES: usize = 3;", and the
  default list is the default host, then the pool in its order
  (`crates/podssh-relay/src/relay.rs:104-125`).
- Read: the alternates are the cached pool, in the order of `/relays.json`
  (`crates/podssh-relay/src/pool.rs:111-126`); `docs/relay.md:574-576` says that `/relays.json`
  ranks relays by the edge that answered, and that its `score_ms` did not agree with the measured
  latency.
- Read: `podssh ping`'s leg times the token, the dial, TLS and the upgrade of one host, and its
  WebSocket pings (`crates/podssh-cli/src/ping/relay.rs:102-150`), and `ping` runs the legs one after
  another (`crates/podssh-cli/src/ping/mod.rs:167-172`); the module is private to `ping`
  (`crates/podssh-cli/src/ping/mod.rs:9`).
- Read: the record of failures is a file of the cache, `crates/podssh-relay/src/failures.rs:27`
  says "pub const FILE: &str", and `order` keeps the list's order within each of its groups
  (`crates/podssh-relay/src/failures.rs:231-255`).
- Read: the subcommands of `podssh relay` (`crates/podssh-cli/src/relay_cmd.rs:159-190`), and
  `--json` goes with `status`, `info` and `trace` alone (`crates/podssh-cli/src/relay_cmd.rs:119-122`).
- Read: rule 2 of `AGENTS.md`, section 5: one outbound connection, through `HTTPS_PROXY` when it is
  set; its exceptions name no measurement of hosts.
- Read in the archive (`docs/research/relay-measurement.md`, section 4): 37 of 37 pool hosts opened
  and carried a key exchange, one sample each, eight at a time, through one proxy.

## Approach

1. A module of `podssh-relay`, crates/podssh-relay/src/rank.rs, pure, its tests in a file of their
   own: a probe (opened, the time to open as the dial, TLS and the upgrade, the token's time left
   out, the pings' p50, why it failed in the record's words); a host's figures (tries, opens, p50
   and p95 by nearest rank); the order of the report's section 7 (the share of failed probes, then
   the p50, then the p95; a tie within 50 ms or 10 % keeps the order before, so that one run's
   noise moves no host); and the file `relay-rank.json` in the cache, by
   the cache's own functions (mode 0600): schema 1, when, the egress (the first 16 hexadecimal
   digits of the SHA-256 of `HTTPS_PROXY`'s host and port, or `direct`; no credential, no name),
   the target, and the hosts in order with their figures.
2. crates/podssh-cli/src/relay_rank.rs: `podssh relay rank [--rounds N] [--count N] [--target
   HOST:PORT] [--json] [--cached] [--forget]`, with `--relay-host`, `--relay-addr` and `--ca-file`.
   The hosts: the list of `--relay-host`, else the default host and each host of the cached pool,
   with `/relays.json` read once first when no pool is cached, as `relay info` reads it. Each round
   in a new random order; each probe by `ping`'s leg (`pub(crate)`), with the deployment's token,
   one mint at most; 250 ms between two probes; the whole run within 10 minutes, a host not probed
   by then named. A line for each probe on stderr, the rank on stdout; `--json`, one object.
3. Exit: 0 when a host opened; 69 when none did, and with `PODSSH_OFFLINE` before any connection;
   64 for a bad flag. `--cached` prints the rank kept, its age and whether its egress is this one,
   and `--forget` removes it; neither connects.
4. `podssh status` names the rank's age, its egress and its first host, with no connection.
5. The manual (`crates/podssh-cli/src/man/notes_relay.rs`, `crates/podssh-cli/src/flags/relay.rs`),
   `docs/relay.md` ("How podssh selects relay hosts", "Diagnostics") and `docs/cli.md`.

## Decision

- On demand, one host at a time: rule 2's one connection holds, as for `ping` over its hosts and
  `doctor` over each host's `/health`. Lost: probes at once, which are faster, need an exception of
  rule 2, and skew the rank as the archive's cells at once did (the report, section 3); a rank that
  podssh makes unasked, which waits for the operator (the report, section 8, item 4).
- The time to open as the measure: it is what the race decides on, it needs no server, it costs a
  few KiB, and the relay's dial of the target is in it, as in a session. Lost: throughput, which
  needs a server and up to 64 MiB a host; the WebSocket ping alone, as which part of the relay
  answers it is not known (a column of the rank, not its key).
- `github.com:22` by default, never a session's destination: `ping`'s rule, as OpenSSH's
  PerSourcePenalties would count the probes against the relay's shared address
  (`crates/podssh-cli/src/ping/relay.rs:1-8`). Lost: a rank to the user's own target, which
  `--target` gives for a target that the user owns.
- A rank holds 24 h, for the egress that measured it. Lost: the 7 days of the pool's cache, as a
  host's network changes sooner than a pool.
- A file of its own, beside `relay-failures.json`: the record changes at each run, an older podssh
  reads it, and the rank changes on demand. Lost: one file for both.
- With `--relay-host`, the hosts of any deployment, each with its own token (T-057): a net's own
  relays rank the same way once a net names them (T-435).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib rank
cargo test -p podssh-cli --test relay_rank
target/debug/podssh relay rank --rounds 3 --json
python3 -I scripts/relay-measure.py --podssh target/debug/podssh --stages pool --hosts all --rounds 3
```

Offline, against two stand-in relays of `scripts/fake-relay.py` (`normal`, and `slowopen:600`):
the rank puts the fast one first, keeps its file with mode 0600 and no token, names a host that
fails, and `--cached` reads it back with no connection; with `PODSSH_OFFLINE`, 69. Planted: the
order by the last probe in place of the median; the test of a host that is slow once in three
fails. Live (the live relay is the operator's own): the rank of the pool, and the harness's order
of the same hosts in the same hour (T-605); the first three of each in `docs/STATUS.md`.

## Correction

- 2026-11-03: a probe whose upgrade the relay answered is opened, even when its pings fail after
  it: the time to open is the measure, and the pings are a column. The first run of the test,
  with a target that closed each connection after its line, counted each such probe as failed
  (`a ping could not be sent: Broken pipe`); the probe now keeps the open and leaves the ping's
  figure out, with a unit test of it.
- The Prove's `scripts/fake-relay.py` modes run under the test harness's own CA
  (`throughput_harness::Cell::fake_relay_mode`), two cells on one CA; the target of the probes in
  the test is a listener of the test that greets with SSH's line and holds the connection, as
  GitHub's port does.

## Done

2026-11-03:

- `crates/podssh-relay/src/rank.rs` (new, pure but for its file) with `rank_tests.rs`: `Probe`,
  `Figures` by nearest rank, `before` and `order` (the share of failed probes, the p50, the p95,
  a tie within 50 ms or 10 % keeping the order given, the rule of `scripts/relay_measure_lib.py`),
  `egress` (16 hexadecimal digits of the SHA-256 of the proxy's host and port, or `direct`),
  `Rank` (`holds` 24 h for its egress, `first`), and `relay-rank.json` by the cache's own
  functions, mode 0600.
- `crates/podssh-cli/src/relay_rank.rs` (new) with `relay_rank_tests.rs`: `podssh relay rank
  [--rounds N] [--count N] [--target HOST:PORT] [--json] [--cached] [--forget]`; the hosts named,
  else the default host and each host of its pool, the pool read once first when none is cached;
  rounds in a new random order, 250 ms apart, within 10 minutes, each probe `ping`'s leg
  (`crate::ping::relay`, now `pub(crate)`); a line for each probe on stderr; the rank on stdout or
  as one object; 0 when a host opened, 69 when none did or with `PODSSH_OFFLINE`, 64 for a bad
  flag. `--cached` and `--forget` connect nowhere. `podssh status` gives `relay_rank`.
- `crates/podssh-cli/src/relay_cmd.rs`: `RelayArgs::from_matches` (moved from `tree.rs`, which
  was at its 500 lines), the fields of `rank`, `--json` with `rank`, the flags of `rank` refused
  with another subcommand (64), `rank NAME` refused (64); `flags/relay.rs`, `positionals.rs`, the
  manual's notes (`notes_relay.rs`, the note of `status` in `notes.rs`), `docs/cli.md` and
  `docs/relay.md`.
- Tests: `cargo test -p podssh-relay --lib rank`: 7 passed (a host slow once in three keeps its
  place by its median; failures, then the median, then the p95; a tie; the egress; a day; the
  file). `cargo test -p podssh-cli --lib`: 785 passed. `cargo test -p podssh-cli --test
  relay_rank`: against two stand-ins named slow first (`slowopen:600`, `normal`) and a port that
  answers nothing, the fast one first, the slow one second, the dead one last with its words; a
  line for each of the 9 probes; the file private, with no token; `--cached` and `--cached
  --json` offline; `status`'s `relay_rank`; `--forget`, then `--cached` 69 and `relay_rank` null;
  offline 69 and seven refusals 64 with nothing reached. `--test relay --test status --test
  man_page --test man_flag_parity --test flag_table`: passed. Clippy `--all-targets -D warnings`
  of both crates: clean.
- Planted (`scripts/plants/t606-rank-by-last-probe.plant`, the order by the last probe): `sh
  scripts/plant-each.sh --here t606-rank-by-last-probe`, caught.
- Live, from this cloud session through its proxy, 2026-11-03 (`podssh relay rank --rounds 1
  --count 3`): 37 of 37 hosts opened, `tcp-us-east-1` first at 447 ms, the default host 32nd at
  972 ms in that round; `--cached` and `status` read it back. In the same hour, the harness of
  T-605 (`--stages pool --hosts all --rounds 1`) put `tcp`, `tcp-mx-central-1` and
  `tcp-azure-westus2` first (455, 451 and 501 ms), and a second rank `tcp-mx-central-1`,
  `tcp-us-east-2` and `tcp-azure-westus2` (459, 447 and 554 ms): one round from a host through a
  proxy moves the first hosts within the tie, which is why the default is 3 rounds and why T-607
  reads a rank only as a preference.


# T-607: The default list of relay hosts takes the rank: the best three of the pool in the rank's order, and samples of each session's own race

**Source:** The operator, 2026-11-03 ("... so it can rank relays on demand and then use"). The design
is `docs/research/relay-measurement.md`, section 8, items 2 and 3.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A rank that nothing reads changes nothing: the default list still takes the first three hosts of
`/relays.json`. And most users never run `podssh relay rank` (T-606), while each session's own race
times the hosts that it tries, and throws the times away.

## Premise

- Read: `crates/podssh-cli/src/relay_settings.rs:75`, where the default list took
  `pool::alternates` of the default host as `/relays.json` gave them: the one place where the default list
  takes its alternates, which `select_relays` puts after the default host
  (`crates/podssh-relay/src/relay.rs:104-125`).
- Read: `open` loads the record and orders the list by it, then races the hosts
  (`crates/podssh-relay/src/open.rs:221-227`, `crates/podssh-relay/src/open.rs:258`); each host's
  attempt is `attempt` (`crates/podssh-relay/src/open.rs:330-348`); the file has 473 lines.
- Read: the race gives the attempt kept, those that opened and were dismissed, and those that
  stayed silent (`crates/podssh-relay/src/failover.rs:88-101`).
- Read: the record's `order` puts a host that opened lately first and one that failed or rests
  last, each group in the order of the list (`crates/podssh-relay/src/failures.rs:231-255`), also
  for a list that the user named, whose order is a preference (`docs/relay.md:147-148`).
- Read: T-563's Done: the fault checks of the interop lean on the list's order, so each takes an
  empty record of its own.
- Read: the relay's keys of the settings file (`crates/podssh-cli/src/settings.rs:31-33`).
- Read: T-606 keeps the rank in `relay-rank.json`, with the egress that measured it.

## Approach

1. `podssh_relay::rank::alternates(primary, pool, now, egress)`: when a rank holds (under 24 h, of
   this egress), the hosts of the rank that opened, in its order, the default host among them at
   its place; else the pool ordered by the samples of item 2 where it has some; else the pool's
   order, as now. `relay_settings::relays_from` takes it, so the default list is the default host
   and the best three other hosts, in the rank's order (`select_relays` takes the order, and keeps
   the default host in the list).
2. Samples: `attempt` times its host from its start to the 101, the token's time left out; `open`
   gives the time of each attempt that opened, kept or dismissed, to `rank::seen`, which keeps the
   last 8 of each host, with when and the egress, in the rank's file. A failure gives no sample:
   the record keeps it. The code goes in the rank's module; `open.rs` gets the few lines of the
   call.
3. `PODSSH_RELAY_RANK=no`, and `RelayRank no` in the settings file, leave the rank and the samples
   out of the order (the samples are still kept); a list that the user named keeps its order, and
   the record still moves its hosts.
4. `podssh status`, and a line `relay rank` of `doctor` (its age, its egress, the list that it
   gives), say which order a run takes, and why.
5. The tests of failover, and the fault checks of `scripts/interop-faults.sh`, keep a cache of their
   own with no rank, as T-563's do.
6. The manual's THE RELAY, `docs/relay.md` (step 2 of the selection), `docs/cli.md`.

## Decision

- The default host stays in the default list, at its place in the rank. Lost: the four best hosts
  with no default (it is the deployment's control host, and the host that a report names; a rank
  goes stale in 24 h); the default host always first (the rank's gain is mostly the first host,
  which `staggered` keeps when it opens within 2 s).
- The rank orders the list, and the record moves hosts within it: a host that failed in the last
  10 minutes goes last whatever its rank. Lost: one score of both (a failure is an event and a rank
  a measure; T-563's order already says what a failure does).
- Samples of the race's own connections alone: they cost no connection, so rule 2 of `AGENTS.md`
  holds through the exception of the race between relay hosts. Lost: samples of each host of the
  pool, which need probes (T-606 on demand; unasked, the report's section 8, item 4).
- The samples order the list only where no rank holds. Lost: a mix of both, as a rank measures
  each host in rounds under one condition, and samples come from four hosts at most, each in its
  own run's conditions.
- A list that the user named keeps its order (`docs/relay.md`, step 5). Lost: the rank over it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib rank
cargo test -p podssh-relay --lib failures
cargo test -p podssh-cli --lib relay_settings
cargo test -p podssh-cli --test relay_rank
```

A rank that holds gives the default host and the best three others in its order; a rank of another
egress, or 25 h old, gives the pool's order; `PODSSH_RELAY_RANK=no` gives the pool's order; a host
that failed lately goes last over its rank; the samples order a pool where no rank holds (each of
these on `rank::alternates`, with a cache of the test's own). Against two stand-in relays
(`slowopen:600` and `normal`), a run of `podssh proxy --relay-failover parallel --relay-host
SLOW,FAST` keeps a sample of each, the slow one's 600 ms longer, and keeps their order, as the user
named it. Planted: `alternates` that ignores the egress; the test of a rank of another egress
fails. The fault checks of the interop: unchanged, in their run of the release (Q88).

## Correction

- The code is a module of its own, `podssh_relay::rank_list` (`alternates`, `placed`, `sample`,
  `keep`, `order_now`), not functions of `rank`: `rank.rs` is the measure and its file, and the
  order of a list is another concern. `rank::seen` is `rank_list::sample` (each attempt that
  opened, in `try_host`) and `rank_list::keep` (once after each race, in `open`).
- The samples order the pool of the default list's alternates (`relays_from`); only a rank moves
  the default host among them (`placed`, in `open`), as a sample comes from a run's own conditions.
  A sample is keyed by the host's name with its port when it is not 443 (`token::relay_name`), so
  that two stand-ins on one address keep their own.
- The doctor's line is the check `rank` of the relay section, ahead of the others: its word for
  the order (`rank`, `samples`, `pool` or `off`) and the list in that order. `podssh status`
  gives `relay_order`, the same word.
- Item 5 needs no change: the tests of failover and the fault checks already keep a cache of their
  own (T-563), so a rank of this machine never reaches them; and a rank places only the hosts that
  it names, which no stand-in is.

## Done

2026-11-03. The default list of relay hosts takes the rank that holds for this egress: the
default host and the best three other hosts of the pool, the default host at its place in the
rank, the record of failures still moving a host that failed lately to the end. Each race keeps
the time to open of each host that opened, the last 8 of each, with when and the egress, in the
rank's file; they order the pool where no rank holds, with no connection of their own. A named
list keeps its order. `PODSSH_RELAY_RANK=no` and `RelayRank no` give the pool's order;
`podssh status` gives `relay_order`, and `podssh doctor` a line `rank` with the list.

- `cargo test -p podssh-relay --lib rank`: 14 passed (7 of the rank, 7 of the list: a rank that
  holds, another egress, 25 h old, none and a named rank; the samples of this egress within a
  day; the default host at its place and a named list kept; a host that failed lately last over
  its rank; the last 8 samples; the switch).
- `cargo test -p podssh-relay --lib failures`: 11 passed. `cargo test -p podssh-cli --lib
  relay_settings`: 3 passed (`RelayRank no` alone turns it off). `cargo test -p podssh-cli
  --lib`: 795 passed.
- `cargo test -p podssh-cli --test relay_rank`: 4 passed. Against `slowopen:600` and `normal`,
  `podssh proxy --relay-failover parallel --relay-host SLOW,FAST` kept a sample of each, the
  slow one's at least 500 ms longer, of the egress `direct`, and no rank; `status` then says
  `samples`, and `off` with `PODSSH_RELAY_RANK=no`.
- The relay crate's whole suite, target by target since `open` changed: 68 targets, 576 passed,
  none failed. The tests of `doctor` (13), `doctor_jobs` (3), `status` (7), `settings` (5),
  `relay` (12) and the manual (21) passed.
- Planted: `sh scripts/plant-each.sh --here t607-egress-ignored` (`alternates` that ignores the
  egress): caught, the test of a rank of another egress failed.
- `cargo clippy -p podssh-relay -p podssh-cli --all-targets -- -D warnings`: clean.

Waits for the run of the release (Q88): the fault checks of the interop, unchanged.

# T-608: A rank that podssh makes unasked, in the background of a session, once a day for an egress

**Source:** The design of the rank (`docs/research/relay-measurement.md`, section 8, item 4),
after the operator's request of 2026-11-03.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Most users never run `podssh relay rank` (T-606), so its rank seldom holds, and the samples of
T-607 see the four hosts of the default list at most. A rank kept fresh with no request would put
the best hosts first for each user; but its probes are connections that the user did not ask for,
to hosts that the session does not use.

## Premise

- Read: `AGENTS.md:275-285`, rule 2: one outbound connection, and its four exceptions (a listener
  that the user asks for, the race between relay hosts, the split HTTP road of Q44, the quick
  tunnel's second connection of Q62); `docs/decisions.md:37` adds XHTTP's second connection (Q67).
  None covers a probe of a host that the session does not use.
- Read: the pool's refresh after a mint is a request of its own in the background
  (`crates/podssh-relay/src/open.rs:408-419`): one request to the host that minted, at most once in
  7 days.
- Read: the contract's `?dial=lazy` (`docs/relay.md:513-516`): the relay dials the target on the
  client's first byte, so a probe with it and no byte reaches no target.
- Read: Q83, the experience of a user first (`docs/decisions.md:21`), and Q73, `doctor`'s sections
  at once (`docs/decisions.md:31`).
- Read: T-606 ranks on demand and T-607 samples the race; neither probes a host unasked.

## Approach

As Q89 rules:

1. With `RelayRank auto` in the settings file or `PODSSH_RELAY_RANK=auto`, and never by default
   (Q89): when no rank holds for this egress, a session of `ssh` that has run 60 s probes the
   hosts of the pool in its own process, one at a time, one probe each 10 s at most, 8 hosts at
   most in a session, each with `?dial=lazy` and three WebSocket pings (a few KiB), and keeps what
   it measured as a rank whose source is `background`, which T-607 reads as it reads T-606's.
2. Never before the session opened, never during a race, never in `proxy` or `pipe` (the runs of a
   ProxyCommand are short and many), never with `PODSSH_OFFLINE`, and never past the session's
   end: a probe in flight then is dropped.
3. `doctor` and `podssh status` name the setting, and when the last background rank was made.
4. The manual and `docs/relay.md`; rule 2 of `AGENTS.md` names the exception, as Q89 words it.

## Decision

Q89 (the operator, 2026-11-03) rules: unasked only with `RelayRank auto`, in the bounds of the
Approach. Then: the probe with `?dial=lazy`, so that no target sees a connection
that sends it nothing, as `ping`'s rule asks (`crates/podssh-cli/src/ping/relay.rs:1-8`), and the
relay's dial is out of a background figure: a background rank orders by the client's leg alone,
and a rank of T-606 keeps the dial. Lost: the dial to `github.com:22` in each background probe,
which would make 8 short connections a day to GitHub's SSH port from each user.

The calls of the draft (2026-11-03), each with what lost:

- **Which sessions.** `podssh ssh` alone, in its session's loop (`tries`), and only a session that
  the relay's default list carried: not a list that the user named, whose order T-607 keeps, so
  a rank buys it nothing and its probes would go to hosts that the user did not name; not the
  direct road after the relay (T-363) nor a forwarder (T-370), which use no relay host. Lost:
  `proxy` and `pipe` (a ProxyCommand's runs are short and many, the Approach's item 2), `cp`,
  `each`, `job` and the other commands (short runs too, often many at once); each command.
- **Never beside a race.** `open` counts the races in progress (one guard at its start, in
  `podssh_relay::rank_auto`); a probe waits until none runs, and a race that starts while a probe
  runs drops it, its connection with it. Lost: the check before a probe alone (a race that starts
  during a probe would run beside it); a lock that a race waits on (a race never waits for a
  probe).
- **The session's end** aborts the task: a probe in flight is dropped and nothing of it is kept.
  Lost: a wait for the probe at the end (the session's end would wait up to a probe's bound).
- **Once a day.** Any rank that holds for this egress blocks a new run: `relay rank`'s, which the
  user asked for, one of named hosts (the file holds one rank, and podssh never puts an unasked
  one over an asked one), and a whole background rank. Lost: a background rank over an older
  `relay rank` that still holds (it would throw away what the user asked for).
- **A partial run keeps what it measured.** The rank is saved after each probe, and the hosts go in
  the pool's order, the default host first, so a partial rank orders the pool's first hosts, those
  that the default list tries, and the others keep the pool's order after them (T-607's order).
  The next session of the same day goes on with the hosts that the rank lacks, never one twice,
  8 in the day's rank in all; the rank's time stays its first probe's, so it holds 24 h from
  then. Lost: a partial rank that orders nothing until it is whole (a user whose sessions are
  short would wait for days, and the samples that it would leave in place mostly time the
  default host alone, as `staggered` seldom starts a second host); a new rank in each session
  (more than 8 hosts a day, against Q89); a rank only from a session that ran its whole plan
  (130 s at least, which few sessions reach).
- **Which 8 hosts.** The default host and the first 7 of its pool in `/relays.json`'s order (the
  seed while no pool is cached). Lost: each of the 37 (Q89 says 8); 8 at random (a rank of hosts
  that the default list may never take); the samples' order (they see the default list alone).
- **The probe** is `ping`'s leg with a query (`leg_with`, `?dial=lazy`), to `github.com:22`, three
  pings, with the deployment's cached token (the session's mint cached it). A relay that ignored
  `?dial=lazy` would dial GitHub's SSH port, as `ping` does, never the session's destination.
- **The source.** The rank keeps `source` (`relay rank`, or `background`; none in a file of before
  this entry, which `relay rank` made), `partial`, and `background_ms`, when the last background
  rank was made, kept across ranks as the samples are, so that `status` and `doctor` still say it
  after a `relay rank` replaced the rank. Lost: a file of its own (two ranks to choose between,
  where T-607 reads one).
- **The setting.** `RelayRank yes, no or auto`, and `PODSSH_RELAY_RANK=auto`; a variable that is
  set, and not empty, wins over the file, for the rank's order too (see the Correction). Lost: a
  key of its own (`RelayRankAuto yes`): two keys for one setting, where Q89 names `RelayRank auto`.
- **The test's pace.** `PODSSH_RELAY_RANK_PACE=DELAY_MS,GAP_MS`, read only where
  `cfg!(debug_assertions)` holds, the build of the tests, so that each release binary keeps 60 s
  and 10 s; the manual's ENVIRONMENT says that it is for tests only. Lost: a flag (a user could
  loosen Q89's bounds); a feature of the build (the integration test runs the binary that
  `cargo test` builds, with none); a paused clock (a process of the test has none).
- **The test.** A stand-in HTTP CONNECT proxy of the test's, in `HTTPS_PROXY`, carries each CONNECT
  of the default list to one stand-in relay (`scripts/fake-relay.py`, which now serves
  `?dial=lazy` in `scripts/fake_lazy.py` and writes a line for each connect with its query and
  its time, and for each end) with a certificate of the default relay host and its seed pool
  (`throughput_harness::default_relay`), trusted by `--ca-file`. The seed is the pool: the
  stand-in's `/relays.json` names only the host that asked, which is no alternate, so no pool file
  is needed. The test reads the stand-in's lines: each probe's start and end, its query, the
  session's own connect and end; then the rank's file and `status`. Lost: the live relay (a test
  stays offline, and Q89's probes on the operator's relay at each run); `--relay-host` (a named
  list makes no background rank, by the first call); podssh's own relay role in place of the
  stand-in (it serves `?dial=lazy` too, `crates/podssh-relay/src/serve/forward.rs`, but writes no
  line for each connect, which the test reads); a pool file in the test's cache (the seed gives 7
  hosts with none).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_rank -- background
```

Against stand-in relays, with the session's delay and the gap between probes shortened for the
test: with `RelayRank auto`, the probes come one at a time, each with `?dial=lazy`, none before
the session opened and none after it ended; with the setting off, none. Planted: two probes at
once; the test of the overlap fails.

## Correction

- 2026-11-03: the Blocker is cleared. The operator ruled Q89 (`docs/decisions.md`): podssh ranks
  unasked only with `RelayRank auto`, at most once a day for each egress, 8 hosts, one probe each
  10 s at most, each with `?dial=lazy`. Item 1 no longer waits on a default.
- 2026-11-03, the draft: the Premise's lines moved before it was read. Rule 2 begins at
  `AGENTS.md:279`, and the rows of Q89 and Q90 came above the others: Q67 is at
  `docs/decisions.md:39`, Q83 at `docs/decisions.md:23` and Q73 at `docs/decisions.md:33`. Rule 2
  had four exceptions, and Q67's XHTTP is not among them; the draft adds Q89's as the fifth.
- The settings file's `RelayRank` took yes or no alone (`crates/podssh-cli/src/settings.rs`, its
  `relayrank`), and the file's `no` won over the variable (`crates/podssh-relay/src/rank_list.rs`,
  `enabled`), where the manual said that the file is below the variable: `RelayRank` takes auto
  now, and a variable that is set, and not empty, wins (a unit test of each).
- The Approach's "8 hosts at most in a session" is 8 hosts in a day's rank, over each session that
  adds to it, as Q89 words it ("at most once a day for each egress, 8 hosts"); a session makes 8
  probes at most too.
- The code is in two modules of their own: `podssh_relay::rank_auto` (the setting, the count of
  races, the pace, the plan and the rank that a probe adds to, with its tests in
  `rank_auto_tests.rs`) and `crates/podssh-cli/src/relay_rank_auto.rs` (the task, `status`'s
  value and `doctor`'s words); `open.rs` gets two lines, the session's loop three, and
  `doctor/relay_checks.rs` one. `podssh status` gives the rank's `source` and `partial`, and
  `relay_rank_auto`; `relay rank --cached` names a background rank.

## Done

2026-11-03, drafted (`be90ae1`), merged and built by the main session, which repaired one finding
of clippy (a `?`) and formatted two files. With
`RelayRank auto` or `PODSSH_RELAY_RANK=auto` alone, a session of `podssh ssh` that the default
list carries ranks the default host and its pool in its background when no rank holds for this
egress: 8 hosts in a day, the first probe after 60 s, then one each 10 s at most, none beside a
race, none past the session's end, each with `?dial=lazy` and three pings; the rank is kept after
each probe, source `background`, and the next session of the day goes on with a partial one.

- `crates/podssh-relay/src/rank_auto.rs` (new) with `rank_auto_tests.rs`: `asked_from` (the
  variable above the file, never by default), `pace` and `pace_of` (the variable in a build with
  debug assertions alone), `racing`, `calm` and `unless_a_race`, `hosts`, `plan` and
  `with_probe`. `rank.rs`: `source`, `partial` and `background_ms`. `rank_list.rs`:
  `enabled_from`, the variable above the file. `open.rs`: the guard of a race.
- `crates/podssh-cli/src/relay_rank_auto.rs` (new): `spawn`, the run, `status_value` and
  `doctor_line`; `ssh/mod.rs` spawns it after the relay opened the session and aborts it at its
  end; `ping/relay.rs`: `leg_with`; `relay_rank.rs`: the source in the rank, its JSON, `--cached`
  and `status`; `settings.rs` and `relay_settings.rs`: `RelayRank auto`; `status.rs`:
  `relay_rank_auto`; `doctor/relay_checks.rs`: its line `rank` with the setting and the last
  background rank's age.
- `scripts/fake-relay.py` and `scripts/fake_lazy.py` (new): `?dial=lazy`, and the lines
  `connect MS PATH`, `ended MS PATH`, `lazy closed MS` and `lazy dial MS`; the harness keeps the
  stand-in's events in a file, and `throughput_harness::default_relay` signs a certificate of the
  default relay's names.
- The manual (`man/notes_relay.rs`, `man/notes.rs`, `man/facts/roads.rs` with
  `PODSSH_RELAY_RANK_PACE` for tests only), `docs/relay.md`, `docs/cli.md`, and rule 2 of
  `AGENTS.md` with Q89's exception.
- `cargo test -p podssh-relay --lib rank`: 23 passed (`rank`, `rank_list` and `rank_auto`).
- `cargo test -p podssh-cli --lib -- relay_settings relay_rank`: 8 passed; `--lib man`: 79 passed
  (each variable read is documented); `--lib`: 815 passed.
- `cargo test -p podssh-cli --test relay_rank -- background`: 2 passed, nothing skipped (13 s):
  against one stand-in behind the test's proxy, with the waits at 400 ms and 1200 ms, the first
  session's probes, ended after three, each `?dial=lazy` and none dialed, one at a time, none
  after its end; a partial rank of the plan's first hosts, of the proxy's egress, that `status`
  and `relay rank --cached` name; the second session probes the hosts that it lacks and stops; a
  third makes none. Off by default, and with the file's `auto` under `PODSSH_RELAY_RANK=yes`: none.
- `--test relay_rank` 6 passed, `--test status` 7, `--test doctor` 13 (2 ignored), `--test
  settings` 5, `--test relay` 12, the manual's 21; with the stand-in's new lazy dial, `--test
  relay_serve` 14, `--test faults` 1 (12 ignored), `--test direct_fallback` 4; the relay crate's
  `failover` 12, `e2e` 10, `cache` 21, `limits` 3, `identity` 11, `default_relay` 1.
- Planted (`sh scripts/plant-each.sh --here t608-two-probes-at-once t607-egress-ignored
  t606-rank-by-last-probe`, the last two moved by the draft): 3 caught.
- `cargo clippy -p podssh-relay --features serve,plain-ws,quick,pair,grant --all-targets` and `-p
  podssh-cli --all-targets`, `-D warnings`, and `cargo fmt --check`: clean.

No live run: the probes of Q89 are a user's choice, and the stand-ins prove the bounds; the live
relay's `?dial=lazy` is the contract's (`docs/relay.md`, "Connect options").

Repaired after the merge (2026-11-04): on Windows (the gate of `14b7943`) the last probe opened
and closed in the millisecond of the session's end, and the test's check that no probe came after
the end compared their milliseconds; it now compares their places in the stand-in's log, where the
probe's lines come before the end's. `cargo test -p podssh-cli --test relay_rank`: 6 passed here.


# T-618: `relay info` names neither `podssh relay rank` nor the order that this host's runs take, which T-610 left for T-606 and T-607

**Source:** The operator's export of GitHub #125 (aerrand-agent, 2026-11-03; GitHub has since
deleted the issue), read on 2026-11-04: its second remedy, "podssh stops presenting an unstable
rank, or measures instead", and its words "A client that calls once and takes rank 0 gets the best
host for a colo it never used". T-610 did the first half, and its Done left the rest for T-606 and
T-607, which were done after it the same day.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh relay info` sends a user, or a program that reads its `--json`, to the relay's order and to
two measures of the hosts that podssh tries, and stops there. It names neither the rank that
podssh now measures and keeps for each host of the pool (`podssh relay rank`, T-606) nor the order
that this host's runs take from it (T-607), which `podssh status` (`relay_order`) and `doctor`'s
line `rank` give with no connection. Its `pool_order` says `measured_here: false` and nothing
more, so a client of `relay info --json` that wants an order still finds only the relay's: the
client of #125's words. And a document that names no edge and scores each host 0, as podssh's own
relay role serves it, still reads as "the relay's estimate from the edge that answered, which
changes with the edge", which is not true of the role: it has no edge and gives no estimate.

## Premise

- Read: `crates/podssh-cli/src/relay_diag_text.rs` line 35 at `366f511` says "measured from this
  host: podssh relay status (the hosts that podssh tries), podssh ping --relay-host HOST (one)";
  `pool_order` gives `by`, `edge` and `measured_here` alone
  (`crates/podssh-cli/src/relay_diag_text.rs:58-63`); the
  pool's line says "the edge that answered" when the document names no edge, whatever its scores
  (`crates/podssh-cli/src/relay_diag_text.rs`, lines 70-76 at `366f511`).
- Read: T-610's Done, `TODO/relay.md:3124-3125` says "once they are done, the line names the rank
  too"; T-606 (`e892246`) and T-607 (`11295ef`) were done after T-610 (`2516f32`), and the line
  did not change.
- Read: the manual's note of `relay info` names `relay status` and `ping` alone
  (`crates/podssh-cli/src/man/notes_relay.rs`, lines 72-78 at `366f511`), and so does
  `docs/cli.md:3293-3299`.
- Read: `relay status` and `ping` time the hosts of the run's list, the default host and three
  others at most (`crates/podssh-relay/src/relay.rs:78` says "pub const MAX_ALTERNATES: usize =
  3;"; `crates/podssh-cli/src/relay_diag.rs:88-97`, `crates/podssh-cli/src/ping/mod.rs:167-172`),
  not the 37 hosts of the pool, which only `relay rank` measures.
- Read: the order that a run of the default list takes, in a word, is `order_now`
  (`crates/podssh-relay/src/rank_list.rs:195-212`), and the list in that order `placed_now`
  (`crates/podssh-relay/src/rank_list.rs:146-154`), both from the cache; `doctor` words them
  (`crates/podssh-cli/src/doctor/relay_checks.rs`, lines 39-52 at `366f511`).
- Read: podssh's own relay role answers `/relays.json` with `you.edge_colo` null
  (`crates/podssh-relay/src/serve/docs.rs:60`) and its one host at rank 0 and score 0
  (`crates/podssh-relay/src/serve/docs.rs:74-75`).

## Approach

1. After the pool, the line of the measures names `podssh relay rank` (each host of the pool,
   from this host) beside `relay status` and `ping --relay-host HOST`. A second line says which
   order this host's runs take, in `doctor`'s words (the rank kept for this egress, the times of
   earlier races, the relay's order, `RelayRank no`, or the order that the user named), with the
   list in that order: read from the cache by `order_now` and `placed_now`, with no connection.
   The words move out of `doctor/relay_checks.rs` into one function beside
   `relay_rank_auto::doctor_line`, which both call; `relay_diag.rs` computes the order and hands
   it to the text, so that `relay_diag_text.rs` stays a function of what it is given.
2. `--json`: `info` and `pool_order` stay as they are, and two keys come beside them:
   `relay_order`, the word of `podssh status` (`rank`, `samples`, `pool` or `off`; `named` for a
   list that the user named), and `relay_list`, the hosts in that order.
3. A document that names no edge and gives no host a score above 0 (podssh's own relay role)
   reads "the relay gives no estimate of a round trip", not an estimate that changes with the
   edge. The default relay's shape keeps T-610's line.
4. The manual's note of `relay info`, `docs/cli.md`, and the greps of the interop check
   `relay.info` (`scripts/interop-relay.sh`) read the new lines.

## Decision

- `relay info` reads the order from the cache and measures nothing: it reads one document from one
  host, as rule 2 of `AGENTS.md` asks, and `relay rank` measures on demand. Lost: an order that
  `relay info` measures itself, which would be a second `relay rank`.
- The pool stays in the relay's order, its fields unchanged under `info`, as T-610 keeps them: it is
  the relay's document. Lost: the pool sorted by podssh's rank, which would hide what the relay
  said, and which `relay rank --cached` gives already.
- `relay_order` is `podssh status`'s key with its words, so one word means one thing in both.
  Lost: a field inside `pool_order`, which says whose order the relay's pool is in, not which list
  a run takes.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib relay_diag_text
cargo test -p podssh-cli --test relay
cargo test -p podssh-cli --test man_page --test man_flag_parity
```

The text's unit test, with the order given: a rank of this egress gives the line that names
`podssh relay rank` and the line of the rank's order with its hosts; none, the relay's order; off,
`RelayRank no`; a named list, the order named. The role's document (`serve::docs::relays`) gives
"no estimate", and two documents of NRT and SIN keep T-610's line. The stand-in's test of `relay
info` with `--relay-host` reads the order named, and `--json` has `relay_order` `named` and
`relay_list`. Planted: the line of the order left out; the test fails.

## Correction

- 2026-11-04: the Premise cites the note of `relay info` in `docs/cli.md` at lines 3241-3247 at
  `366f511`, which hold `relay join` and `relay spec`; the note was at lines 3281-3287 at
  `366f511`, where its words were as the Premise says, and it begins at `docs/cli.md:3335`. Each
  other citation of the Premise holds. The Premise's citations of the lines that this change
  rewrote read at `366f511` now, as they no longer name those words.
- The approach's test of the role's document (`serve::docs::relays`) needs a `Config` of the role,
  which `crates/podssh-cli/src/relay_serve.rs` builds too: the unit test builds one with
  `Mint::Nobody` and the defaults, and reads its `/relays.json` as `relay info` reads a relay's.

## Done

2026-11-04, drafted, then merged; the results below were measured at the merge:

- `crates/podssh-cli/src/relay_rank_auto.rs:101-132`: `RunOrder` (the word of `podssh status`, or
  `named` for a list that the user named; its words; the list in that order) and `run_order`, read
  from the cache by `order_now` and `placed_now` with no connection, and `order_words`, the words
  that `doctor/relay_checks.rs` had, with the background rank's; `doctor_line` takes the list alone
  and calls them, so `doctor`'s line `rank` keeps its words
  (`crates/podssh-cli/src/doctor/relay_checks.rs:45`).
- `crates/podssh-cli/src/relay_diag_text.rs`: the line of the measures names `podssh relay rank`
  (each host of the pool) first (`crates/podssh-cli/src/relay_diag_text.rs:39-40`); the next line,
  with a pool or none, is "a run from this host takes WORDS; its list: HOSTS"
  (`crates/podssh-cli/src/relay_diag_text.rs:45-48`, `:113`), each host with its port when it is
  not 443; a document that names no edge and scores no host above 0 reads "the relay gives no
  estimate of a round trip" (`crates/podssh-cli/src/relay_diag_text.rs:52-54`), and a document
  with an edge or a score keeps T-610's line. The text stays a function of what it is given.
- `crates/podssh-cli/src/relay_diag.rs:167-172`: `relay info` reads the order before it prints,
  and `--json` adds `relay_order` and `relay_list` (each `host` and `port`) beside `info`,
  `pool_order` and `signed_list`, which stay as they were.
- The manual's note of `relay info` (`crates/podssh-cli/src/man/notes_relay.rs:87-99`) and of the
  default list's rank (`:120-121`), `docs/cli.md` and `docs/relay.md` say the same; the interop
  check `relay.info` (`scripts/interop-relay.sh`) greps the line of the measures with `relay rank`
  and the line of the order named.
- Tests: `the_text_names_relay_rank_and_the_order_that_a_run_takes` (each of `rank`, `samples`,
  `pool`, `off` and `named` gives its words and the list after the line of the measures; no pool,
  the line still), `the_roles_document_gives_no_estimate` (the role's `/relays.json` from
  `serve::docs::relays`: "no estimate"; the stand-in's shape, edge TEST and score 0: T-610's
  line), `the_pool_is_the_relays_order_from_the_edge_that_answered` (NRT and SIN keep T-610's line;
  its case of no edge has scores now, as an empty pool with no edge gives no estimate),
  `relay_rank_auto::tests::each_order_has_its_words`, and the stand-in's test of `relay info`
  (`crates/podssh-cli/tests/relay.rs`), which reads the order named with its port, and
  `relay_order` `named` with `relay_list` in `--json`.
Merged and measured by the main session the same day, onto `3988c8c`:

- `cargo test -p podssh-cli --lib relay_diag_text`: 5 passed. `cargo test -p podssh-cli --lib
  relay_rank_auto`: 2 passed. `cargo test -p podssh-cli --test relay`: 6 passed. `cargo test
  -p podssh-cli --test man_page --test man_flag_parity`: 11 and 15 passed. `cargo test -p
  podssh-cli --test relay_rank` (its module `rank_background` reads `status`'s `relay_order`; the
  doctor's words moved): 6 passed. Clippy `-p podssh-cli --all-targets -D warnings`: clean;
  rustfmt: clean.
- Planted: `sh scripts/plant-each.sh --here t618-order-left-out t618-role-estimate
  t610-pool-as-advice` (the line of the order left out; each pool read as an estimate; T-610's
  plant, made again for the new pool line, as its old patch no longer applies): 3 caught.
- The interop check `relay.info` (`scripts/interop-relay.sh`) runs in the gate's step `release`,
  at the push of this merge.


# T-619: The note to the relay's operator asks nothing of `/relays.json`'s rank, which changes with the edge that answered

**Source:** The operator's export of GitHub #125 (aerrand-agent, 2026-11-03; GitHub has since
deleted the issue), read on 2026-11-04: its first remedy, "the relay pins the estimate to one
vantage point and names that vantage in the payload, so two answers are comparable".
**Category:** docs
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

#125 names two remedies, one on each side. podssh's side is T-610, T-606, T-607 and T-618. The
relay's side, a rank and a score that two calls can compare, is in no item of the note to the
relay's operator, where a change of the default deployment goes since Q63, so its operator was
never asked for it, nor told that podssh takes the relay's order only where no rank and no
samples hold.

## Premise

- Read: Q63, `docs/decisions.md:40` says "stays the default relay; a change of that deployment
  stays an item of"; no entry waits for one.
- Read: `docs/relay-operator.md` has no item on `/relays.json`'s rank or `score_ms`: its sections
  "Defects on the relay's side" (`docs/relay-operator.md:34`) and "Questions about the contract"
  (`docs/relay-operator.md:430`) name other changes.
- Read: `docs/relay.md:607-608` says "ranks relays by the Cloudflare edge that answered, which
  changes between identical calls" (measured 2026-10-01); #125 measured it again on 2026-11-03,
  through one proxy: three calls answered by NRT, SIN and ARN, each of the 37 hosts with another
  rank and score between the first and the third.
- Read: the relay's document says that `/relays.json` "ranks the pool for your edge colo and the
  target" and documents its own `?prefer=`, `?region=`, `?relay=` and `?spread=`
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:70-71`); the record reads only
  `?relay=` (`docs/relay.md:579-580`), so whether one of the others pins the rank is not known.
- Read: the relay's `policy.note`, as #125 quotes it: "score_ms is a static estimate of client to
  relay to target round trip; probe /health on each host and keep the fastest for your path".
- Read: podssh's own relay role serves its one host, with `you.edge_colo` null and a score of 0
  (`crates/podssh-relay/src/serve/docs.rs:60`, `crates/podssh-relay/src/serve/docs.rs:74-75`), so
  each call gets the same answer there, with no vantage to pin.
- Read: podssh's default list takes the relay's order only where no rank and no samples hold for
  this egress, or with `RelayRank no` (`docs/relay.md:171-182`).

## Approach

1. Read the live relay's `/relays.json` once, for what its own document says of `?prefer=`,
   `?region=` and `?spread=`, with the caller's fields (`you`) left out of what is kept: a short
   read of the live relay, which `AGENTS.md` (section 4) allows.
2. An item of `docs/relay-operator.md`, under "Questions about the contract", with this entry and
   #125: what was measured (2026-10-01, and #125's three calls); what would make two answers
   comparable (an estimate from one vantage that the document names, or the edge's estimate with
   that edge named beside each score); whether a parameter of item 1 pins it already; and "In
   podssh": T-606, T-607 and T-608 (podssh measures its own order), T-610 and T-618 (`relay info`
   says whose order it shows), and the role's one host.
3. `docs/relay.md`, "Relay facts for a client that selects a relay": #125's measurement beside the
   one of 2026-10-01, what item 1 found, and the item's place.

## Decision

- An item of the note and a reading, not a change of podssh's client: since T-607 podssh's runs do
  not depend on the relay's order where a rank or samples hold, and a client cannot pin the
  relay's estimate. Lost: a client that asks `/relays.json` with a parameter that pins the order,
  which needs item 1 to show that one does; then it is an entry of its own.
- The entry is done when the item is written (Q63: no entry waits for the relay's operator); an
  answer of the deployment is read as the note's section "When an item is ready" says.

## Prove

```sh
python scripts/check-repo.py
cargo todo check
```

The item is in `docs/relay-operator.md`, with this entry and #125, and so is the fact in
`docs/relay.md`; the reading of item 1 is quoted with its date, and holds no token, no address of
this host and none of the document's `you`; both checks pass with the new citations.

## Correction

- 2026-11-04: the section "Questions about the contract" begins at `docs/relay-operator.md:437`,
  not at line 430 at `366f511`, which is inside item 19 (T-421); the paragraph of the default
  list's rank is `docs/relay.md:174-183`, beside the range that the Premise cites. Each claim of
  the Premise holds at its lines.
- The relay's `policy.note` is quoted from #125's export, of which this repository keeps no copy; the
  item and `docs/relay.md` say "as #125 quotes it", and step 1's read of the live document checks
  it.

## Done

2026-11-04, drafted, then merged; the results below were measured at the merge:

- Step 1, the live relay's `/relays.json`, read once by the main session on 2026-11-04 through
  this host's proxy, with its `you` left out of what was kept (version `2026-10-03-r2`, 37 hosts
  in its pool): it has no words on `?prefer=`, `?region=` or `?spread=`; its `policy` echoes them
  as `prefer` (`auto`), `region_pin`, `relay_pin` and `spread`, each null for a call that gave
  none; its `policy.note` is the one that #125 quotes ("score_ms is a static estimate of
  client→relay→target round trip; probe /health on each host and keep the fastest for your
  path"); and no field names the vantage of `score_ms`. So no parameter that the document names
  says that it pins the rank and the score to one vantage, and no client entry follows (the
  Decision). The reading is in the item and in `docs/relay.md`
  (`docs/relay-operator.md:486-495`, `docs/relay.md:590-595`).
- Step 2: item 20 of the note, "A rank and a score that two calls can compare", under "Questions
  about the contract" (`docs/relay-operator.md:465-506`), with this entry and #125: the
  measurements of 2026-10-01 and of #125's three calls; the two forms that would make two answers
  comparable; the parameters of step 1; and "In podssh": T-606, T-607 and T-608, T-610 and T-618,
  and the role's one host, which `relay info` reads as no estimate.
- Step 3: `docs/relay.md`, "Relay facts for a client that selects a relay"
  (`docs/relay.md:572-599`): #125's measurement after the one of 2026-10-01, which keeps its words
  (`docs/relay.md:576-578`), the parameters of step 1, podssh's own order, and the item's place.
- `python scripts/check-repo.py`: passed. `cargo todo check`: the record agrees.

# T-629: `podssh relay serve` keeps each capability of its start after the bind, while it serves each client

**Source:** GitHub #127 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh relay serve --listen 0.0.0.0:443` needs a privilege for one call alone, the bind of a port
below 1024: a start as root, or a file capability on the binary. The role keeps that privilege for
its whole run, through each client's TLS, its token, its proof of a key and the dial of its target,
so a fault in any of them runs with more than the role needs. Nothing after the bind needs it.

## Premise

Read at `2042200`:

- `crates/podssh-cli/src/relay_serve.rs:286` says "let listener = std::net::TcpListener::bind(listen)",
  and `:218` reads its address; the runtime and its two workers come later, in
  `crates/podssh-cli/src/relay_serve.rs:333`, which says "worker_threads(2)". Between the two the
  process has one thread, so a drop there holds for each thread made after it. The issue's line
  numbers are of an older tree; the order is as it says.
- The listener is the user's (Q1): `crates/podssh-cli/src/relay_serve.rs:204` says
  "crate::pipe::listen::allowed()?;" before the bind.
- No source of the workspace calls `prctl` or `capset` (searched for `capset`, `NO_NEW_PRIVS` and
  `CAPBSET`), so no step drops a privilege today.
- After the bind the role still reads files: the certificate on SIGHUP and when its files change
  (`crates/podssh-cli/src/relay_serve.rs` at `ce411ac`, lines 341-377, T-447), the file of pairs at each pair
  (`crates/podssh-relay/src/serve/reverse/pairs.rs:292`), and ACME's cache at each renewal. A root
  that dropped `CAP_DAC_OVERRIDE` reads a file of another owner only as its mode lets uid 0
  (Inferred from capabilities(7); not measured here).
- `crates/podssh-cli/Cargo.toml:146` says "[target.'cfg(unix)'.dependencies]" above the binary's
  `libc` row, so the calls need no new crate and no C of a library crate (rule 4 of `AGENTS.md`).
- `crates/podssh-cli/src/exitmap.rs:139` says "Fault::Capability | Fault::Config => sysexits::EX_CONFIG":
  78 is this host not set up for the mode.
- The role behind a quick tunnel binds nothing (`crates/podssh-cli/src/node_quick_relay.rs`), so
  this is for `relay serve` alone.

## Approach

1. A module beside `crates/podssh-cli/src/relay_serve/certs.rs`, Linux alone (elsewhere it does
   nothing), with its system calls behind a seam that its tests replace.
2. Probe first (rule 1 of `AGENTS.md`): `capget` reads the sets; a process that holds no capability,
   the usual start, does nothing more and says nothing.
3. After the bind, before the runtime: `PR_SET_NO_NEW_PRIVS`; each capability of the bounding set
   dropped, `EINVAL` past the kernel's last one and `EPERM` with no `CAP_SETPCAP` taken as done; then
   `capset` with the three sets empty. A failed `capset` refuses the start with 78, which names the
   call and the errno. The uid and the gid stay.
4. The first line says it: "the capabilities of the start dropped after the bind".
5. A reload that cannot read its files after the drop says so in its line and keeps the pair that it
   serves, as a reload that fails does now; the manual, `docs/relay.md` ("podssh's own relay") and
   `SECURITY.md` name the drop and that a root's files of another owner need their mode.

## Decision

2026-11-04 (the drafting agent of the triage). The drop happens by default, with no flag to keep the
capabilities: nothing that the role does after the bind needs one, as read above, and an owner who
starts it as root would rarely ask. Lost: a flag that asks for the drop (the case that needs it is the
one that does not know); a warning alone (the path stays open); a change of uid to another user, which
needs a user of the host by name and moves the cache, the pairs and ACME's account to another owner (a
later entry, if an owner asks).

2026-11-04 (the drafting agent of T-629), for what the draft met. No row of `docs/decisions.md` settles
these, and none changes one.

1. A start as root keeps uid 0, and its first line says so: "it stays uid 0, which may still write each
   file that root owns", with the way out, a user of its own with the file capability
   `cap_net_bind_service`. With no capability, uid 0 still writes each file that root owns by its mode
   (a crontab, an `authorized_keys`), so the drop alone closes less for root than for a user with a file
   capability, and the line tells the owner. Lost: a change to another uid after the bind (it needs
   `CAP_SETUID` before the drop and a user of the host by name, and the cache, the file of pairs and
   ACME's account, written as root, would refuse that user: the next pair and the next renewal fail); a
   refusal to start as root (a role that starts today would stop); a flag that names the user (a later
   entry, if an owner asks).
2. No new privileges is asked for at each start, also one that holds no capability, and nothing is said
   of it: it costs nothing, and keeps a fault that runs a setuid program from gaining by it. Lost: no
   call at all for such a start (step 2 of the Approach), which leaves that path open.
3. The first thread drops on itself, by a job that the command's thread sends it
   (`crates/podssh-cli/src/first_thread.rs`), and each thread of `/proc/self/task` is then read again
   (the Correction). Lost: a first thread that drops its capabilities right after it starts the command's
   thread, for each command (each podssh process would show no capability in `/proc/PID/status` while its
   command's thread holds them, for a need of `relay serve` alone); `relay serve` on the first thread
   (`main.rs` would read the arguments, and it decides nothing).
4. With a capability held, a step that fails and a thread that keeps one refuse the start (78), as the
   Approach says. With none held, or with sets that neither `capget` nor `/proc/thread-self/status`
   gives, each failure is a note of the first line, and the start goes on: a start that works today does
   not stop for a drop of nothing. Lost: a line alone with a capability held (the role would serve with
   what it says it gave up).
5. The bounding set goes where `CAP_SETPCAP` is effective; else the first line says that it stays, as no
   new privileges keeps an exec from gaining by it. Lost: each of the 64 drops tried, and `EPERM` taken.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib relay_serve
cargo test -p podssh-cli --lib first_thread
cargo test -p podssh-cli --test relay_serve
sh scripts/plant-each.sh --here t629-drop-after-runtime t629-capset-failure-taken t629-job-on-its-own-thread
```

With the seam: the order bind, drop, runtime; `EINVAL` and `EPERM` of the bounding set taken; each
other errno, and a failed `capset`, 78; no call at all where the sets are empty. In the build image,
a role started with `CAP_NET_BIND_SERVICE` (`setpriv --inh-caps`, or a container that grants it) binds
a port below 1024, and `/proc/PID/task/*/status` of each of its threads reads `CapEff` and `CapPrm` 0
once the first line is out. Planted: the drop moved after the runtime starts, and the worker threads'
`CapEff` test fails.

## Correction

2026-11-04 (the drafting agent of T-629). Read in this tree: `crates/podssh-cli/src/main.rs` runs each
command on a thread of 16 MiB that it starts, and its first thread waits for it in a join. So at the
bind the process has two threads, not one as the Premise says, and Linux keeps the capability sets for
each thread: a drop on the command's thread alone left the first thread with each capability of the
start, and `/proc/PID/status`, which reads the first thread, would have shown them. The first thread
now waits for work from the command's thread (`crates/podssh-cli/src/first_thread.rs`), and the drop
runs on both; then each thread of `/proc/self/task` is read again, and one that keeps a capability
stops the start (78). The Approach is otherwise as written, with the calls of the Decision (no new
privileges at each start; the bounding set where `CAP_SETPCAP` is effective). The Prove's role is
started as the test runs (as root in the build image), on `127.0.0.1:0`, not with `setpriv`: an exec as
root gives each capability of the bounding set, and the test reads each thread's `CapEff`, `CapPrm`,
`CapInh`, `NoNewPrivs` and, with `CAP_SETPCAP`, `CapBnd`.

## Done

2026-11-04, merged from its draft (`1d6791d`).

- `podssh relay serve` binds its port, then gives up each capability before its runtime starts:
  no new privileges, the bounding set emptied where `CAP_SETPCAP` is effective, and `capset` with
  each set zero, on each thread that holds one: the first thread of the process, which waits while
  a thread of 16 MiB runs the command, runs the drop on itself (`crates/podssh-cli/src/first_thread.rs`,
  `main.rs`), as Linux keeps capabilities for each thread. The role then reads each thread of
  `/proc/self/task`, and a thread that still holds one stops the start (78). A start as root keeps
  uid 0 and says so in its first line. The manual, `docs/relay.md` and `SECURITY.md` say it.
- `cargo test -p podssh-cli --lib -- relay_serve first_thread node_exit net:: man::`: 102 passed;
  `--test relay_serve` (with `serve_caps`, run here as root): 24 passed; `cargo test -p podssh-cli
  --no-fail-fast`, the whole crate with the first thread's change: 1,868 passed, 0 failed. Plants
  `t629-drop-after-runtime`, `t629-capset-failure-taken` and `t629-job-on-its-own-thread` caught.
  Clippy clean (one `let ... else` of a test written with `?` at the merge); rustfmt clean.

# T-635: `podssh relay serve` has no list of private targets between public ones alone and `--allow-private`

**Source:** GitHub #133 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A role dials public addresses alone, or, with `--allow-private`, each address there is, the loopback
and RFC 1918 among them. An owner whose role must reach one host inside its network has to open the
whole of it to each holder of a token.

## Premise

Read at `2042200`:

- `crates/podssh-relay/src/serve/policy.rs:19-20` holds the choice in one `bool`, `private`;
  `crates/podssh-relay/src/serve/policy.rs:142` says "if self.private {" and returns each address
  unchecked; else `:94` refuses the first address that is not public.
- `crates/podssh-relay/src/serve/policy.rs:107-109` hands a name to the host's proxy unresolved only with
  `private`, so a role without `--allow-private` checks each address that it dials.
- The flag: `crates/podssh-cli/src/flags/relay.rs:66` (the row `allow-private`),
  `crates/podssh-cli/src/relay_serve.rs:249` says "private: s.allow_private", and the role behind a
  quick tunnel the same in `crates/podssh-cli/src/node_quick_relay.rs:110`.
- Each road of the role goes through `Policy::plan`: `/connect/`
  (`crates/podssh-relay/src/serve/forward.rs:100`), the resumable layer
  (`crates/podssh-relay/src/serve/layer.rs:185`), the HTTP road
  (`crates/podssh-relay/src/serve/http_road/mod.rs:142`) and `/trace`
  (`crates/podssh-relay/src/serve/docs.rs:132`); one change there serves each.
- podssh has this list already for an exit: `podssh node --exit --routes` takes ranges
  (`crates/podssh-cli/src/node_exit.rs:93`), each a `Range` of `ADDR/BITS` or one address
  (`crates/podssh-cli/src/net/policy_words.rs`, lines 123 at `c3a9b89` and on), and an address that is not public is let
  through only inside one (`crates/podssh-cli/src/node_exit.rs:215-219`). `Range::parse` takes a
  prefix with host bits and reads it as its network (the same file, lines 131 to 147 at `c3a9b89`):
  `10.0.0.5/8` is `10.0.0.0/8`, with no word.

## Approach

1. `Range` moves to `podssh-relay` (beside `crates/podssh-relay/src/serve/policy.rs`), and the exit's
   `--routes` reads it from there; a prefix with host bits is refused by both, with the network that
   it would name.
2. `Policy` gains the ranges; an address that is not public is dialed when a range holds it, each
   address of a name checked, as the exit checks them; port 25 stays refused first, for every target.
3. `podssh relay serve --routes RANGES` and `podssh node NAME --quick-tunnel --relay --routes RANGES`
   for the role, comma-separated as the exit's; with `--allow-private` it is refused (64), as the two
   say opposite things. The first line names the ranges.
4. A target that no range holds keeps today's refusal; the manual, `docs/relay.md` ("Limits that users
   see") and the role's section say the ranges.

## Decision

2026-11-04 (the drafting agent of the triage). One word for one idea: the role's ranges are named
`--routes`, as an exit's, and take ranges and single addresses, not names. Lost: the issue's
`--allow-target` with names, as a name admits what the resolver says at the dial, and the check of each
address is what holds (the policy checks addresses already, `crates/podssh-relay/src/serve/policy.rs:138-143`);
a second word for the exit's idea. A prefix with host bits is refused, as `ip route` refuses one,
also for the exit, whose silent widening is the same fault.

2026-11-04 (the drafting agent of T-635), for what the draft met. No row of `docs/decisions.md` settles
these, and none changes one.

1. The flag stays `--routes RANGES`, one value of ranges separated by commas, as the exit's. Lost: a
   flag given more than once (`--allow-target` of the issue, repeatable): the parser makes a flag
   repeatable by its name for each verb that has it (`crates/podssh-cli/src/tree.rs`, `appended`), so
   `node --exit --routes` and `net add --routes` would take it too, whose readers take one value; one
   form for the three is plainer.
2. A name is admitted by its addresses alone, each inside a range or public, as the triage decided: a
   test of a name (`localhost`) passes where a range holds each of its addresses, and a name of one
   address outside is refused whole.
3. `podssh net add --routes`, which lists in the net's document the routes that an exit's own
   `--routes` dials, refuses a prefix that sets bits past it too, as the exit does. A word of a
   document signed before keeps its reading (`Range::parse`), so a rule or a route of an older document
   reaches what it reached. Lost: a strict reading of each document (a document of before would lose a
   route with no word); `net add` that takes what the exit refuses (an owner's list and an exit's flag
   that never agree).
4. The client reads a target outside each range in T-628's words, `HOST:PORT not in the ALLOW list:
   this relay dials no address of it`, unchanged; the owner's line on stdout adds "nor in a range of
   --routes" to its cause. The first line names the ranges as given: ", the private targets in RANGES
   too".
5. On a node, `--routes` with `--relay` is the role's and with `--exit` the exit's: the two never meet,
   as `--exit` refuses `--quick-tunnel` and `--relay` needs it. With neither, the refusal names both.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve --lib -- serve::policy serve::ranges
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_routes --test relay_serve_contract
cargo test -p podssh-cli --lib -- relay_serve node_exit net::
cargo test -p podssh-cli --test relay_serve
cargo test -p podssh-cli --test exit --test exit_routes --test node_quick_relay
sh scripts/plant-each.sh --here t635-any-address-of-a-name t635-any-private-with-a-range t635-routes-unread
```

A range lets one private literal in and refuses the next; a name whose addresses a range holds is
dialed, one with an address outside refused; no range is today's policy; `10.0.0.5/8` is refused at
the start of a role and of an exit; `--routes` with `--allow-private` exits 64; through the role, a
listed loopback target is reached and another refused with "not in the ALLOW list". Planted: the check
that takes any address of a name in place of each, and the test of a name with one address outside
fails.

## Correction

2026-11-04 (the drafting agent of T-635). Read in this tree, after T-628: the Premise's lines of
`crates/podssh-relay/src/serve/policy.rs` are of `2042200`; the refusal of an address that is not
public is now `Refused::NotDialed`, whose words name no address (`this relay dials no address of it`),
with the cause in the owner's line alone, and a target outside each range keeps those words. The
Prove's `cargo test -p podssh-cli --test node_routes` is the test of a node's routes of T-089, not of
an exit's `--routes`: an exit's refusal of `10.0.0.5/8` is in `--test exit`, and `net add`'s in `--test
exit_routes` (Decision 3); the Prove names those. `Range` moved to
`crates/podssh-relay/src/serve/ranges.rs`, and `crates/podssh-cli/src/net/policy_words.rs` names it
from there, so each reader of the net is unchanged.

## Done

2026-11-04, merged from its draft (`82301fd`).

- `podssh relay serve --routes RANGES` (and `podssh node NAME --quick-tunnel`'s role): a private
  target in one of the ranges is dialed; each address of a name must be public or in a range; a
  target outside them gets T-628's words, unchanged. `Range` moved to
  `podssh_relay::serve::ranges`; a prefix with host bits (`10.0.0.5/8`) is refused by the role, the
  exit and `net add`, and the ranges of a signed document read as before.
- `cargo test -p podssh-relay --features serve --lib -- serve::policy serve::ranges`: 12 passed;
  `--features serve,plain-ws --test relay_serve_routes --test relay_serve_contract`: 2 and 14
  passed; `cargo test -p podssh-cli --test exit --test exit_routes --test node_quick_relay --test
  man_page --test man_flag_parity --test flag_table`: passed (the CLI's whole crate 1,868 passed).
  Plants `t635-any-address-of-a-name`, `t635-any-private-with-a-range` and `t635-routes-unread`
  caught. Clippy clean with `serve,plain-ws`.

# T-636: The relay role counts no bytes for each key across its sessions, and keeps no count across a restart

**Source:** GitHub #134 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The relay role caps one session at 64 MiB both ways and brakes each address at 120 mints and pairs a
minute, but sums nothing for a key: a key of the list may open as many sessions as its tokens let it,
and nothing says, or limits, what one key carried in a day. A restart forgets it all.

## Premise

Read at `2042200`:

- One counter for both ways: `crates/podssh-relay/src/serve/forward.rs:250` says
  "let moved = Arc::new(AtomicU64::new(0));", and `:330` ends the session at the cap;
  `crates/podssh-relay/src/serve/mod.rs:78` says "Payload bytes, both ways together." The counter
  dies with its session.
- A token names no key: `crates/podssh-relay/src/serve/tokens.rs:61` MACs the expiry alone under the
  run's secret, which `:52` draws at each start, so a restart ends each token
  (`docs/relay.md:92` says "a token is the contract's form under a secret of the run"). A ledger keyed
  by the token, as the issue first proposes, would count a principal that the next mint or restart
  replaces; the issue's own Risks say so.
- The key is known at the mint: `crates/podssh-relay/src/serve/mod.rs:371-375` takes the key that
  proved itself, and drops it after its line.
- The role keeps one private file already, by an atomic writer (`crates/podssh-relay/src/serve/reverse/pairs.rs:451`)
  and a SHA-256 of each token (`:448`).
- The brake counts requests for each address (`crates/podssh-relay/src/serve/brake.rs:22` says
  "pub const PER_MINUTE: usize = 120;"), never bytes.

## Approach

1. At a mint for a key (`--mint keys:FILE`, `--mint net`), the role keeps the token's digest with the
   key's fingerprint, in memory until the token ends; at most 64 live tokens a key, the oldest
   forgotten first. A token minted for anyone counts against no key.
2. Each session of the forward road, `/connect/`, the layer and the HTTP road, counts each way apart
   and charges its key once, at its end; an empty keepalive frame is no byte.
3. `--quota MIB`: a key's budget for a day (UTC), both ways together; a token whose key spent it gets
   `403 forward: this key's quota of MIB for today is spent`, before the dial, and the next day
   begins it again.
4. `--usage FILE`, a private file of each key's totals for the day and the day before, written by the
   pairs' atomic writer each 2 s while a count moved; a file that does not read stops the start (78),
   as the pairs' file does; a write that fails is a line.
5. The first line, the manual and `docs/relay.md` say the quota; `relay serve` prints a key's totals at
   SIGHUP, beside the certificate's reload.

## Decision

2026-11-04 (the drafting agent of the triage). By the key, not by the token: the token names no one and
dies at a restart, and the key is what an owner lends. A budget for a day, not for a lifetime: a key
has no end, and a lifetime cap needs a reset that someone must remember. Lost: the issue's ledger by
the token's digest; a new form of token that carries the key (the contract's form is what clients
cache, and the digest's map does the same in the role's memory); budgets for each way apart (one
budget holds what an owner lends; the counts keep both ways for the line).

2026-11-05 (the drafting agent of T-636). Under a budget, a token that the role minted for a key and
holds no more (past the key's 64) is refused, `403 forward: this relay counts each token for its key,
and holds this one no more; mint another`, and podssh's client, which forgets a cached token that a
relay refuses, mints once more: forgotten silently, its sessions would count against no key, and a key
that minted 65 tokens would pass its budget. Without a budget nothing is refused, and such a token
counts against no key. Two mints of one millisecond make one token (`ephm1.<expiry>.forward.<mac>`),
so the second key's is minted a millisecond shorter, 64 times at most, then `503`; lost: a nonce in
the token, which changes the contract's form. A session is charged once, at its end, so a key may pass
its budget by the sessions that it holds open, 64 MiB each at most, and a session open at a stop or a
crash is not kept; lost: a charge at each frame (a lock and a count of the file at each frame, and the
plant), and a session cut at its key's budget, which the Approach does not ask and which would end a
client's shell in the middle. A request that never became a session (a refusal, a target out of
reach) charges nothing and counts no session: the count starts at the upgrade. Each link of the layer
is a session of its own, its frames of the layer among its payload, as for its cap of 64 MiB. The file
is read up to 16 MiB, not the cache's 64 KiB (`crates/podssh-relay/src/cache.rs:45`), which holds a few
hundred keys: a role whose own file grew past it would not start. `--quota` is whole MiB from 1 to
16777216; `--quota` and `--usage` beside `--mint anyone` or `nobody`, which count no key, are usage
errors (64). The relay behind a quick tunnel counts in memory, with no budget; lost: `--quota` for
`podssh node --relay` now, whose flags of the role are `relay serve`'s four. The Prove's test through
the role is `--test relay_serve_usage`: `crates/podssh-relay/tests/relay_serve_contract.rs` holds 485
lines.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib serve::usage
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_usage
cargo test -p podssh-cli --lib relay_serve::quota
cargo test -p podssh-cli --test relay_serve serve_refuses
sh scripts/plant-each.sh --here t636-charge-each-frame
```

A new module's tests: a key's total comes back from the file after a restart; a half-written file
leaves the old one whole; a token minted for anyone is charged to no key; the day turns the budget
over. Through the role: a key over its budget is refused before the dial, and the stand-in target sees
no connection; keepalives charge nothing; two keys count apart. Planted: the charge at each frame in
place of the session's end, and the test that counts one session once fails.

## Done

2026-11-05, merged from its draft (`034dc65`).

- The counts (`crates/podssh-relay/src/serve/usage.rs`, with `usage_keyed.rs` and `usage_file.rs`): at
  each mint for a key, `/v1/mint` keeps the token's SHA-256 with the key's fingerprint, also a token
  of one session of the cleartext road; `/connect/` (`forward.rs`), each link of `/v1/layer/`
  (`layer.rs`) and `/v1/http/open/` (`http_road/`) take a `Meter` of the token's key before the dial,
  `403` for a key whose budget is spent, count the payload each way, and charge once at the end (a
  drop of the session's task charges too); `Config` holds the counts (`usage`). `relay serve
  --quota MIB` and `--usage FILE` (`crates/podssh-cli/src/relay_serve/quota.rs`), the first line's
  words, the keeper of the file each 2 s, a write at a planned stop, and each key's totals at SIGHUP.
  The manual (the notes of `relay serve`, the rows of `--quota` and `--usage`), `docs/relay.md` ("What
  each key carried, and its budget for a day") and `docs/cli.md` say it.
- `cargo test ... --lib serve::usage`: 6 passed (one session charged once at its end, each way
  apart, two keys apart, a refusal no session; a token of anyone's charged to no key, and refused
  under a budget where the role mints for keys; 64 live tokens a key, one token one key's; the budget
  spent, said once, and turned over by the day, the day before kept; the totals back from the file
  after a restart, a private file, nothing after two days, a file cut short refused; a write that
  fails leaves the file of before whole, and the next takes each count).
- `cargo test ... --test relay_serve_usage`: 2 passed (through the role, `--mint keys:` of two
  keys and a budget of 64 bytes: 40 bytes each way charged once; then `/connect/`, `/v1/layer/` and
  `/v1/http/open/` refuse the key, also with a new token, and the target sees one connection alone;
  the other key counts apart; keepalives each 100 ms and empty frames of the client charge nothing).
- `cargo test -p podssh-cli --lib relay_serve::quota`: passed (the bounds of `--quota`, and both
  flags refused where no key mints). `cargo test -p podssh-cli --test relay_serve serve_refuses`:
  passed (`--quota` with `--mint nobody` is 64; `--usage` with another subcommand is 64).
- Planted, a charge at each frame (`sh scripts/plant-each.sh --here t636-charge-each-frame`):
  caught (the test of one session charged once failed); `t671-close-ends-the-session`, which the
  draft brought up to date, caught.
- The crates whole, at the merge onto T-667: the relay crate with each serve feature and `quic`,
  869 passed; podssh-ws 481; the CLI 1,921; 0 failed. Clippy clean after two repairs of the draft's
  tests (`expect_err`, and a conversion that only T-646's list needs); rustfmt rewrapped its lines.
  `relay_serve.rs`'s tests moved to `relay_serve/tests.rs`, as the role's flags of both entries made
  the file 513 lines.

# T-637: Sessions of one process that open at once against a failing relay host each dial it, and each waits out its own deadline

**Source:** GitHub #135 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A process that opens several relay sessions at once (a copy over several sessions, Q23; `each`; a
long-lived node or session daemon) tries each host for each session apart. Against a host that just
failed, each session dials it, waits its own deadline, and learns nothing from the others; a host that
answers slowly is asked again by each.

## Premise

Read at `2042200`:

- `crates/podssh-relay/src/open.rs:212` is the road of each session, and its gate of mints is its own:
  `crates/podssh-relay/src/open.rs:239` says "let gate = MintGate::default();", so two calls of `open`
  share no state (`crates/podssh-relay/src/failover.rs:294`).
- Each host attempt runs under `HOST_DEADLINE` (`crates/podssh-relay/src/open.rs` at `96a4eb2`, line 322), 45 s
  (`crates/podssh-relay/src/open.rs:37`).
- What one run learns, the next run reads: the record of failures keeps a host 600 s
  (`crates/podssh-relay/src/failures.rs:30`) and rests one that two short sessions cut
  (`crates/podssh-relay/src/failures.rs:32-36`, T-563); it orders the hosts and admits each.
- Whether a failure is the host's: `crates/podssh-relay/src/open.rs:71-93`, where a `502` that names
  the target is final (`:89`).
- A server's wait: `crates/podssh-relay/src/token.rs:210` keeps a mint's `Retry-After`; a refused
  upgrade carries no header to the caller.

## Approach

1. A gate for each origin (`Relay`, host and port, `crates/podssh-relay/src/relay.rs:83-86`), in the
   process: up to 8 attempts at once while the host has not failed; after a failure that
   `another_host_may_help` gives to the host, one probe at a time, after a wait of 5 s that doubles to
   300 s, and the gate opens again on any answer that shows the host alive (a policy's `403` or the
   target's `502` among them).
2. The wait sits outside `HOST_DEADLINE`, so that a wait that ends is never read as a host that timed
   out; each admission takes the gate's epoch, so one wave of failures moves the ladder once.
3. A session that the gate holds tries the next host at once where the list has one, and says one line,
   `HOST: waits Ns after a failure of this process; trying the next host`; with no other host it waits,
   bounded by its own `ConnectTimeout`.
4. A mint's `Retry-After` can lengthen a wait, never shorten it; a new command starts with open gates,
   as each process does.

## Decision

2026-11-04 (the drafting agent of the triage). The longest wait is 300 s, as the record's rest of a
host (T-563), not the issue's 4 h: a gate lives in one process, and a node or a daemon that waited
hours after its host came back would serve nothing. A held session goes to the next host first. Lost:
a gate shared between processes, a file and a lock on each attempt for a case that the record of
failures covers between runs.

2026-11-05 (the drafting agent), within that call:

- **The ladder is the backoff's own: 1 s, doubling to 30 s** (`BACKOFF_FIRST` and `BACKOFF_MAX` of
  `crates/podssh-relay/src/open.rs`), not the 5 s and 300 s of the Approach. The resumable layer's new
  link goes through `open` to its one host, a list of one that the user named
  (`crates/podssh-relay/src/forward_layer/client.rs:154` says "hosts: vec![relay], explicit: true"), and
  waits the same backoff between links
  (`crates/podssh-relay/src/session/resume.rs:377` says "let pause = crate::open::backoff(attempt);"):
  under a gate of 300 s, a session alone would wait up to 300 s after its host came back, where its own
  backoff waits 30 s at most, and a first wait of 5 s would cost a brief outage 5 s to resume where it
  cost about 1 s. So the gate shares one backoff for each host among the sessions of a process: a lone
  session waits as before, and a wave of them costs one probe a step. A mint's `Retry-After` holds the
  gate up to 300 s, the triage's bound kept for a server's own word (`failures::REST`). Lost: 5 s and
  300 s; the issue's 4 h.
- **A host of no verdict admits up to 8 at once**, as the Approach says: a cold wave of 64 at a failing
  host costs at most 8 dials, and once it failed, 64 at once cost one probe, the case that the tests
  hold. Lost: one scout for a host of no verdict, the others waiting for its answer as the mint's gate
  waits (`failover::MintGate`), which would cost each command of several sessions (`cp` with several,
  `each`) up to an open's time at its start on a healthy relay.
- **A full gate (8 running) holds the next attempt for a slot**, with a next host too: the host is
  healthy, and the race's own stagger starts the next host after 2 s. Lost: a refusal at once, which
  would spread a healthy batch over the pool.
- **The verdict reuses the record's reason** (`failures::reason`): a failure is one where the record of
  failures would keep one, so the gate and the record agree on what is the host's; any other answer of
  the relay's (a refusal, its 502, a mint that issues none) shows it alive, and an error of this side
  (offline, a token of the environment, the proxy's 407) says nothing. An answer of an older epoch
  leaves a closed gate closed, and a failure of an older epoch on a gate open again since is ignored:
  the newer answer holds.
- **The lines**: a held attempt with a next host ends at once with `OpenError::Held`, whose line goes
  with the race's notes (`HOST: waits N s after a failure of this process; trying the next host`); a
  run whose every host is held says the last host's wait before its round, as the race gives an
  attempt's notes only when it ends. `Held` records nothing, and exits 69 as an unavailable relay.
- `open.rs` was at 498 lines: its tests moved to `crates/podssh-relay/src/open_tests.rs`, as
  `failures.rs`'s did; the manual's item "A host that failed" moved to
  `crates/podssh-cli/src/man/facts/failed.rs`, beside the gate's, as `facts.rs` was at 499.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib gate
cargo test -p podssh-relay --lib open
cargo test -p podssh-relay --lib failures
cargo test -p podssh-relay --test failover
cargo test -p podssh-cli --lib man::
```

With a paused clock: 64 attempts at once against one failing origin dial it once, and the rest go to
the next host or wait; a stale epoch's verdict lengthens a wait and never shortens it; a `403` opens
the gate; a lease dropped with no verdict frees its slot; the wait never counts against
`HOST_DEADLINE`. Planted: the wait inside the deadline, and the test of a held session that is not a
timeout fails.

## Done

2026-11-05, merged from its draft (`18b641c`).

- `crates/podssh-relay/src/gate.rs`: the gates of a process (`gate::process`), one for each host and
  port; `admit` (8 at once while open; closed for the ladder's wait, then one probe; with a next host a
  held attempt is refused at once with `OpenError::Held`, else it waits), the lease freed by its
  verdict or its drop, the epochs, `verdict` of each end, `guarded` (the wait, then the attempt within
  its deadline), and `all_held`, the line of a run whose every host is held. `open`'s attempt passes
  `guarded` with `HOST_DEADLINE`, and its round says `all_held`'s line; `OpenError::Held` goes to the
  next host and records nothing (`failures::reason`).
- Tests: `gate_tests.rs` (paused clock: a cold wave of 64 dials at most 8 and moves the ladder once;
  after a failure, 64 at once dial once, 32 with a next host held at once and 32 with none waiting, one
  of them the probe, the rest until their caller's limit; an older epoch lengthens and never shortens;
  each end's verdict; a 403 and a 502 at the probe open the gate; a dropped lease frees its slot, and a
  dropped probe the probe's place; a wait of 60 s past a deadline of 2 s is no timeout; the ladder 1 to
  30 s and a Retry-After up to 300 s; the line of a run all held, one origin in any case);
  `open_tests.rs` (a held host goes on, records nothing, and its lines); `tests/failover.rs` (64
  sessions through `race`, after the first host failed, go to the next at once and dial it not, 8 at a
  time at the next).
- The manual (THE RELAY, "A process's sessions"), `docs/relay.md` (after the list of how podssh
  selects relay hosts).
- `cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code,quic --lib -- gate
  open failures`: 33 passed; `--test failover`: 13 passed. The relay crate whole, with each serve
  feature and `quic`: 881 passed, 0 failed; podssh-ws 481; the CLI 1,921 (`--lib man::` among them).
  The plants `t637-wait-in-deadline`, `t637-old-answer-opens`, `t637-drop-keeps-slot` and
  `t637-each-failure-moves`: 4 caught. Clippy clean; rustfmt rewrapped `OpenError::Held`.
- At the merge onto T-667, four tests that run the opener (`relay_serve_cleartext`,
  `relay_serve_h2` and others) overflowed a worker's stack of 2 MiB in a debug build: `guarded` held
  the attempt's whole future, the opener's largest. The attempt is boxed before the gate takes it,
  and each passed.

# T-644: `podssh relay serve` cannot share its port with a local sshd: an SSH client on its listener meets the cleartext road

**Source:** GitHub #142 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An owner whose host lets one port in, 443, can serve the relay or a shell on it, not both: an SSH
client that reaches the role's listener gets no sshd.

## Premise

Read at `2042200`:

- The listener decides by the first byte already, which the issue missed:
  `crates/podssh-relay/src/serve/listener.rs` at `5af6682`, lines 32-41 peeks it, and a byte that begins no TLS handshake
  goes to the cleartext road (T-326); `crates/podssh-relay/src/serve/cleartext.rs:38-44` peeks and
  takes nothing.
- So an SSH client, whose version line begins `SSH-`, meets the cleartext road, which reads an HTTP
  head (`crates/podssh-relay/src/serve/cleartext.rs:60`) under the role's 30 s
  (`crates/podssh-relay/src/serve/mod.rs:63`): the client waits for a banner that never comes, then is
  cut (Inferred from the code; not measured). With `--cleartext no` it meets TLS, which fails at once.
- The node's check of a standard sshd peeks for the version line in the same way
  (`crates/podssh-relay/src/reverse/sshd.rs:1-5`), each 20 ms (`:19`); the word is the node's
  (`crates/podssh-cli/src/flags/node.rs:126`).
- The role's policy refuses a loopback target (`crates/podssh-relay/src/serve/policy.rs:140-143`), so an
  sshd of this host is no target of `/connect/`.
- `TODO/serve.md:1295-1296` plans the same choice for `podssh serve --listen` (T-124, step 5).

## Approach

1. `podssh relay serve --sshd ADDR:PORT`: an sshd that the owner names; with none, nothing changes.
2. Before the cleartext road's check, a peek of up to 4 bytes, bounded as the first byte is: `SSH-`
   goes to the named sshd, its bytes untouched, copied both ways; each other start goes on as today.
3. The dial of the sshd goes by the role's way out (T-457), so the loopback, and what `NO_PROXY`
   names, go directly, never through the policy of targets; it is the owner's own service (the
   Decision of 2026-11-05).
4. The first line says that a shell is published on the port, behind the sshd's own authentication;
   a line for each SSH connection names its peer. The manual and `docs/relay.md` say it.
5. A client that waits for the server's line before it sends its own is never routed: the peek's
   bound passes, and the connection goes on as today (the cleartext road's wait).

## Decision

2026-11-04 (the drafting agent of the triage). The word `--sshd` with a value, as the issue asks: a
node's `--sshd` marks its TARGET as a standard sshd, and here the value is that sshd. Lost: a new word
for one idea. Off unless named: a port of the relay that answers SSH is a door the owner opens.

2026-11-05 (the drafting agent of T-644), each call for the operator to confirm under Q86:

- **The dial goes by the role's way out** (`crates/podssh-relay/src/serve/sshd.rs:94`, through
  the dial of the forward road), with no policy of targets: the loopback, the issue's "local
  sshd", and what `NO_PROXY` names go directly, and another address through the host's proxy
  where one is set. Lost: the Approach's dial that is always direct, as rule 2 of `AGENTS.md`
  sends each dial of the role through `HTTPS_PROXY` when it is set, and a dial past it would be a
  new exception of that rule, which is the operator's to make; an sshd on another host that the
  proxy does not reach is named in `NO_PROXY`.
- **ADDR is an address, never a name** (64). Lost: a name resolved once at the start, as the issue
  proposes: `localhost` gives `::1` first where many sshds listen on `127.0.0.1` alone, and a name
  that each dial resolved again could come to name another host. The owner writes the address
  that the sshd listens on.
- **One bound for the peek**, 30 s from the accept for the first byte and the three after it,
  peeked again each 20 ms as the node's check of an sshd peeks. Lost: a shorter bound of its own
  for the rest, as the issue's `FIRST_WAIT`: each SSH client sends its four bytes in one segment,
  a client that stalls inside them is no client to route, and the cleartext road's own bound of a
  head follows, as before.
- **No limit, token or brake of the contract** before the sshd: the sshd's own `MaxStartups` and
  `LoginGraceTime` bound the connections that have not logged in, as on its own port. Lost: the
  contract's 180 s idle, 12 h and 64 MiB, which would cut a shell or a copy that the owner's sshd
  keeps; and the brake of mints, which counts what costs the role a token, and would cut a loop of
  the owner's own copies.
- **The sshd sees the role's address**, and the role's line on stdout maps each client to the
  role's end of its connection to the sshd (`sshd from PEER, at the sshd as ADDR:PORT`, and one at
  its end). Lost: a dial that keeps the client's address (`IP_TRANSPARENT`), which needs
  `CAP_NET_ADMIN` that the role gives up after its bind (T-629); and the PROXY protocol, which
  OpenSSH's sshd does not read. The manual, `docs/relay.md` and `SECURITY.md` say what this costs
  with OpenSSH 9.8 and later (`PerSourcePenalties`), and its remedy.
- **No check of the sshd at the start.** Lost: a dial at the start that reads its version line, as
  a node's `--sshd` does: the relay is the role's first service, an sshd that starts after it or
  restarts is no fault of the role's, and each such check is a connection with no login in the
  sshd's log. A failed dial is a line on stdout, which names the sshd and why.
- **The client of an sshd that does not answer** gets one line before any version line, which
  RFC 4253 lets a server send and which names no address of the host, then the role reads what it
  sent, 5 s and 64 KiB at most, so that its close is no reset that loses the line. Lost: a silent
  close, which leaves the client a closed connection with no cause.
- **`TCP_NODELAY` on both sockets of a session**, so that the role adds no wait to a keystroke, as
  OpenSSH sets it on its own socket of an interactive session. Lost: the kernel's default.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_cleartext
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_sshd --test relay_serve_h2
cargo test -p podssh-relay --features serve,plain-ws,quic --test relay_serve_quic
cargo test -p podssh-relay --features serve --lib serve::sshd
cargo test -p podssh-cli --lib relay_serve::sshd
cargo test -p podssh-cli --test relay_serve
sh scripts/plant-each.sh --here t644-peek-takes-bytes t644-each-start-to-sshd t644-stall-routed
sh scripts/plant-each.sh --here t644-sshd-through-policy t644-sshd-unread
```

OpenSSH's `ssh -p PORT` to the role's listener, with `--sshd` naming an sshd of the test, logs in and
runs a command; a TLS client on the same listener still upgrades; with no `--sshd`, the SSH client
gets no sshd and the cleartext road answers HTTP as before. Planted: a peek that takes the bytes, and
the sshd's test fails on a version line cut short; each start that is no TLS sent to the sshd, and
the test of `/health` beside it fails; a start cut short taken for SSH, and the test of the bound
fails; the sshd checked by the policy of targets, and the test of the loopback's sshd fails; the
listener given no sshd, and OpenSSH's login through the role's port fails.

## Correction

2026-11-05 (the drafting agent of T-644). Two citations of the Premise name other lines, at
`2042200` as at this draft. The role's 30 s for a request's head is `HEAD_WAIT`:
`crates/podssh-relay/src/serve/mod.rs:66` says "const HEAD_WAIT". The policy refuses the loopback
as an address that is not public:
`crates/podssh-relay/src/serve/policy.rs:145` says "self.unlisted(&wanted)", and
`crates/podssh-relay/src/serve/policy.rs:193` says "ip.is_loopback()". What the Premise says of them
holds. Its Approach, item 3, now follows the Decision of 2026-11-05.

## Done

2026-11-05, merged from its draft (`edd405d`).

- The decision (`crates/podssh-relay/src/serve/listener.rs:47`): with `--sshd`, after the first byte
  that begins no TLS, `crates/podssh-relay/src/serve/sshd.rs:62` peeks up to four bytes within the
  same 30 s; `SSH-` goes to `crates/podssh-relay/src/serve/sshd.rs:88`, which dials the sshd by the
  role's way out, says `sshd from PEER, at the sshd as ADDR:PORT`, copies both ways with
  `TCP_NODELAY` and says its end; another start goes to the cleartext road, or to TLS with
  `--cleartext no`. An sshd that does not answer gets the client one line
  (`crates/podssh-relay/src/serve/sshd.rs:117`). The binary: `--sshd ADDR:PORT`
  (`crates/podssh-cli/src/flags/relay.rs:89`), read at `crates/podssh-cli/src/relay_serve.rs:198`
  (an address, else 64) and named in the first line; with another subcommand, 64. The manual (the
  row and a note of `relay serve`), `docs/relay.md` ("SSH on the relay role's port"),
  `docs/cli.md`, `docs/mesh.md` and `SECURITY.md` say it. The gate runs `relay_serve_sshd` in its
  step of the role's tests with `plain-ws` (`scripts/gate.sh`).
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_sshd`: 8 passed (a
  version line and 64 KiB after it reach a stand-in sshd whole, and its line comes back, under the
  default policy; a line in three parts is waited for; OpenSSH's sshd answers on the role's port;
  `/health` beside the sshd gets the cleartext road and a record of TLS goes to TLS, neither to the
  sshd; with `--cleartext no`, SSH still reaches it; a start of `SSH` that stalls, and none, are no
  SSH after the bound, their bytes left, and `SSX` is no SSH at once; with no sshd, a version line
  gets no answer within 1.5 s and the cleartext road's 400 once a head ends; an sshd that does not
  answer gets the client the line, and the owner's line names it). `--test relay_serve_cleartext
  --test relay_serve_h2 --test relay_serve_quic`: passed (their `Door` has no sshd).
- `cargo test -p podssh-relay --features serve --lib serve::sshd`: 2 passed (the four bytes
  decide; another start decides at its first differing byte; a part waits).
- `cargo test -p podssh-cli --lib relay_serve::sshd`: passed (an address and a port alone,
  never a name, a port 0 or a bare port; the first line's words, and the host's proxy named for an
  address that it carries and not for the loopback).
- `cargo test -p podssh-cli --test relay_serve`: 27 passed (`serve_sshd`: OpenSSH's client on the
  role's port logs in to OpenSSH's sshd of `--sshd` with a key and runs a command whose output its
  shell computed; the first line names the sshd and the shell; the owner's line maps the client;
  `podssh proxy` through the same port still takes TLS's upgrade, and the cleartext road answers
  `/health`; with no `--sshd`, a version line gets no answer, the cleartext road answers 400 once a
  head ends, and OpenSSH's client gets no banner within 3 s. `serve_refuses_...`: a name in
  `--sshd` and `--sshd` with `relay status` are 64.)
- The plants `t644-peek-takes-bytes`, `t644-each-start-to-sshd`, `t644-stall-routed`,
  `t644-sshd-through-policy` and `t644-sshd-unread`: 5 caught.
- The crates whole at the merge: the relay crate with each serve feature and `quic`, 905 passed;
  podssh-ws 486; the CLI 1,948; 0 failed. Clippy and rustfmt clean.

# T-646: `--mint keys:` takes a file alone, so a role in a read-only image changes whom it mints for only by a rebuild

**Source:** GitHub #144 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The relay role's list of keys that may mint and pair is a file of its host. A role run from an image
with no writable volume changes the list by a rebuild; a URL is read as a relative path, and fails at
the start with a path that was never one.

## Premise

Read at `2042200`:

- `crates/podssh-cli/src/relay_serve.rs:270-283` reads `keys:` and makes the rest a path, with no
  other form; `crates/podssh-cli/src/relay_serve.rs` at `fed191c`, lines 292-299, reads it at the start, and a file that
  does not read stops it (78). The role behind a quick tunnel reads the same words
  (`crates/podssh-cli/src/node_quick_relay.rs:73`).
- The list is read again for each request: `crates/podssh-relay/src/serve/keys.rs` at `fed191c`, line 80, and
  `crates/podssh-relay/src/serve/keys.rs:87` says "this relay cannot read its list of keys";
  `docs/relay.md` at `fed191c`, line 849, says "read again for each request".
- `crates/podssh-relay/src/serve/mod.rs:106` holds the list as a path; the net's members are a source
  that the binary gives (`crates/podssh-relay/src/serve/keys.rs:33`), which `--mint net` reads from the
  owner's signed document (T-455): a list that comes from elsewhere and is signed exists already.
- A list fetched over HTTPS exists for Shadowsocks: a cap of 1 MiB
  (`crates/podssh-cli/src/shadowsocks/subscription.rs:19`), a day kept (`:21`), 20 s (`:23`), three
  redirects (`:25`), `https://` alone (`:48`), through `podssh_ws::client::https_get`
  (`crates/podssh-ws/src/client.rs:280`), kept by `crates/podssh-relay/src/cache.rs:153`.

## Approach

1. `--mint keys:https://...` (and `net,keys:https://...`): any other rest stays a path. The list is
   fetched once before the bind, through the host's proxy, with the trust of `--ca-file`; a fetch that
   fails stops the start (78), as a file that does not read does.
2. The copy is kept in the cache with the time it came, and fetched again each `--list-ttl SECS`
   (default 300); a copy older than the TTL and `--list-stale SECS` (default 3600) lets no one mint,
   and the refusal of a list that cannot be read holds. A fetch that fails leaves the copy to age.
3. The list's source is a trait of the role with a file and a URL behind it, read with no wait in the
   request's path, so that `keys::prove` stays as it is.
4. `docs/relay.md` says that a list of a URL is read again at its TTL, not at each request, and that
   its trust is TLS alone; `--mint net`, signed by its owner, is named as the stronger way.

## Decision

2026-11-05 (the drafting agent of T-646). The first fetch comes once the listener is bound and the
start gave up its privileges (T-629), before the first connection, on a runtime of its own whose
threads end before the role's: a start as root would else talk to the network, and read its answer,
with the privileges that the bind alone needs. A fetch that fails stops the start (78) all the same,
the port held a moment longer. Lost: the Approach's fetch before the bind. The copy lives in memory
alone: a start whose fetch fails stops, so a copy on disk would serve no start, and the issue's image
may have no writable cache. Lost: the Approach's copy in the cache. The role's list is an enum of a
file and a URL's copy (`List`), the fetch behind a trait (`Fetch`) that the binary implements over
podssh-ws's HTTPS client and a test with its own answers; each is read with no wait, and `keys::prove`
stays as it is. Lost: one trait object for both, as the binary starts a copy's fetches, which it finds
by the variant. An answer `200` is the list whatever it holds, so a page that is no list lets no key
mint, where a failure or another status leaves the copy to age. Lost: the old copy kept on an answer
that is no list, which keeps a key that its owner took off while a captive page or a cache's error
page answers. An `http://` URL is refused (64), not read as a path that no one names. `--ca-file`
beside `--cert` and `--key` is the list's trust, and beside `--acme` the trust of both; lost: a flag
of its own. The URL's host takes `--relay-addr` and `PODSSH_RELAY_ADDR`, read only when a URL is
named, so a role of a file reads nothing that it did not. `--list-ttl` is 1 to 86400 s, `--list-stale`
0 to 604800 s, and either with no list of a URL is 64. The relay behind a quick tunnel takes the same
words at the defaults, with the node's `--ca-file`; lost: `--list-ttl` on the node now.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --lib serve::keys
cargo test -p podssh-cli --test relay_serve
cargo test -p podssh-cli --lib relay_serve
cargo test -p podssh-cli --test node_quick_relay
sh scripts/plant-each.sh --here t646-stale-copy-read
```

A role whose list is served by a test's HTTPS server mints for its keys alone; a key taken off the list
is refused after the TTL; a server that answers 5xx keeps the copy until TTL and stale pass, then no
key mints; an answer that is no list lets no one mint; a fetch that fails at the start exits 78; a
path that begins `keys:` and is no URL is a file as before. Planted: a stale copy that is still read,
and the test of the stale window fails.

## Done

2026-11-05, merged from its draft (`d69b76f`).

- The list's sources (`crates/podssh-relay/src/serve/keys/list.rs`): `List`, a file read again for
  each request or the copy of a URL's list, read with no wait, refused past its TTL and stale window,
  fetched again each TTL in the role's runtime, its lines (a fetch that failed, the first that worked
  after it, a count that moved, an answer that holds no key) to the binary; `Mint::Keys` and
  `Mint::Net` hold a `List`. The binary's fetch (`crates/podssh-cli/src/relay_serve/keys_url.rs`):
  `https://` alone, through the host's proxy, with the trust of `--ca-file`, 1 MiB, 20 s, three
  redirects, the URL shown by its host alone; `--list-ttl` and `--list-stale`; the first fetch after
  the bind (78 when it fails), its keys on the first line; `node --quick-tunnel --relay` takes the same
  words. The manual (the notes and the rows of `relay serve`, the row of `node --mint`),
  `docs/relay.md` ("A list of keys at a URL"), `docs/cli.md` and `docs/mesh.md` say it. The tests of
  `relay_serve.rs` moved to `crates/podssh-cli/src/relay_serve/tests.rs`, so that it stays within 500
  lines.
- `cargo test ... --lib serve::keys`: 8 passed (a copy read until its TTL and stale window pass,
  then no key in, and again after a fetch that works; an answer is the list, a page and bytes that are
  no text hold no key; the fetches again each TTL on a paused clock, a failure said once, the key taken
  off refused; and the tests of T-448 and T-455 on a `List`).
- `cargo test -p podssh-cli --lib relay_serve`: 24 passed (`https://` is a copy shown by its host, an
  `http://` URL 64, another rest a file; the bounds of `--list-ttl` and `--list-stale`, and 64 with no
  list of a URL; `--mint keys:https://...` and the words of the first line before a copy).
- `cargo test -p podssh-cli --test relay_serve`: 25 passed (`serve_list`: a role whose first fetch
  gets 503 exits 78 and names the URL's host alone; the list's key mints and another does not; a key
  taken off is refused after the TTL of 1 s; a server that answers 503 keeps the copy, then no key
  mints after the stale window of 2 s, then a fetch that works lets it in again; a page that is no
  list lets no key mint; no line holds the URL's path, which the server saw). `--test
  node_quick_relay`: 3 passed (the words of `--mint`, which the refusal keeps).
- Planted, a stale copy that is still read (`sh scripts/plant-each.sh --here t646-stale-copy-read`):
  caught (the test of the stale window failed).
- At the merge onto T-667, T-636 and T-637: the relay crate with each serve feature and `quic`, 884
  passed; podssh-ws 486; the CLI 1,939; 0 failed. Clippy clean after a test that needed `Debug` of
  `Lists` matched its `Err` instead; T-636's test of the role's counts takes its file as a `List`
  again (`.into()`). `relay_serve.rs`'s signals moved to `relay_serve/stopped.rs`, as the flags of
  T-667, T-636 and T-646 made it 503 lines; its tests were moved at T-636's merge.

# T-649: The relay role ends TLS for each name on its listener, so a node's own HTTPS service cannot be published by its name

**Source:** GitHub #147 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** M10
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

An owner with one public port and a role on it can publish SSH through a pair, not a node's own HTTPS
site with its own certificate: the role answers each ClientHello with its own certificate before it
knows the name.

## Premise

Read at `2042200`:

- `crates/podssh-relay/src/serve/listener.rs:60` runs the handshake first; the name comes after, from
  the session (`crates/podssh-relay/src/serve/listener.rs:69`), and so does ACME's TLS-ALPN-01
  (`:63`). The issue reads these in `relay_serve.rs`, where they were before the listener moved to
  `podssh-relay`.
- A pair is found by its name, its role and a token (`crates/podssh-relay/src/serve/reverse/pairs.rs:302`).
- A reader of a ClientHello's name exists in a test's stand-in alone
  (`crates/podssh-relay/tests/opentunnel_stand_in/parse.rs:110` for the record's length, `:120` for the
  name), and routing by a name's label in OpenTunnel's road (`crates/podssh-relay/src/opentunnel/wire.rs:206`).
- A node that ends a visitor's TLS with a name of its own exists for OpenTunnel (T-530):
  `crates/podssh-relay/Cargo.toml:96` says "the key and the CSR of its" name come from the binary.
- Publishing a local HTTP service at a public name is T-180 (`podssh funnel`, TLS at the quick tunnel's
  edge); this entry is the role's form, with TLS at the node.

## Approach

1. `podssh relay serve --publish NAME=PAIR`, repeatable; with none, nothing changes.
2. Before the handshake, a peek of the ClientHello within 10 s and 16 KiB: a name of the table, with no
   `acme-tls/1` for the role's own `--acme` name, goes to that pair's node with its bytes untouched; a
   cut or long record, no SNI, or another name goes to today's path. `acme-tls/1` for a published name
   goes to the node too, so that the node can take its own certificate.
3. A reader of the ClientHello in `podssh-relay` (out of the stand-in), with its tests for a record cut
   short and one too long.
4. The node's leg: the session's bytes as they came, through the reverse road's framing and the
   `open`, `ready`, then payload order that `crates/podssh-relay/src/serve/reverse/operator.rs` keeps,
   that order shared by both legs.
5. The node: `podssh node NAME --publish-tls TARGET` serves a TLS service of its host, or ends TLS
   itself with a certificate of ACME's TLS-ALPN-01 for NAME; the line says what the role sees (the name,
   never the bytes).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_reverse
cargo test -p podssh-cli --test relay_serve_node
```

A published name reaches a test's HTTPS server behind a node, and the client sees that server's
certificate, not the role's; the role's own names, a client by address and a cut ClientHello go to the
role as before; `acme-tls/1` for the role's name is the role's. Planted: a route that matches a name
in another case only, and the test of the case fails.

# T-671: The relay role's forward road drops a target's bytes after the client's Close, where the contract keeps them

**Source:** the draft of T-632, 2026-11-04.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay's contract keeps a target's bytes coming after a client's WebSocket Close, until the
target closes or is idle for 15 s, and then closes with `1000 client half-closed, target idle for
15s`. podssh's relay role shuts the target's write side at the client's Close and ends the session
at once, so a reply that the target sends after the end of its input never reaches a client of the
role's forward road.

## Premise

- `docs/relay.md:397` says "is no TCP half-close. But the target's bytes still come after the client's",
  measured on the default relay on 2026-10-09.
- `crates/podssh-relay/src/serve/forward.rs:283` says "return End::Client;": the client's Close
  ends the pump of both ways, after `to_target.shutdown()`.

## Approach

1. At the client's Close, the role shuts the target's write side and keeps the way down open until
   the target closes (Close `1000 target closed`) or is idle for 15 s (Close `1000 client
   half-closed, target idle for 15s`), as the contract says.
2. A contract test beside `crates/podssh-relay/tests/relay_serve_contract.rs`: a target that answers
   500 ms after the end of its input; its answer comes after the client's Close.

## Decision

2026-11-04 (the drafting agent of T-671). No row of `docs/decisions.md` settles these, and none
changes one; none is a call of policy.

1. **The role holds its answer to the client's Close by a builder of podssh-ws's session,
   `RelaySession::holding_close_answer`**, which only the role's `/connect/` takes: its reader then
   returns the Close and sends none, and the role's own Close, after the target's bytes, is the
   answer (RFC 6455, section 5.5.1, lets a side send data until it sent its Close). Each other user
   of the crate keeps the reader's echo. Lost: a reader that never echoes (each client, and `pipe
   ws-listen:`, would answer by hand); a second reader of the role's socket.
2. **A link of the resumable layer (`/v1/layer/`) still ends at its client's Close**
   (`AfterClose::Ends`): a link is not the session, the layer's `END` is its half-close (T-632), and
   a link that its client retires must free its pump at once. Lost: the 15 s on each link, which
   would hold a retired link's pump and pipe.
3. **The silence is counted from the target's last byte, or from the Close when it came later**, as
   the measurement of 2026-10-09 reads (GitHub's answer 0.4 s after the Close, the relay's Close
   15.4 s after it). Lost: 15 s from the Close alone.
4. **The 15 s is a field of the role's limits (`Limits::half_closed`)**, so that a test waits 1 s;
   no flag of `relay serve` sets it, as the contract fixes it. The close's words name the window's
   seconds, the contract's on the default. Lost: a constant (a test of 15 s); a flag (nobody asked).
5. **After the client's Close the role reads nothing more of the client**: nothing follows a Close,
   and a client that went away is found at the next write to it, or at the window's end. Lost: a
   reader of the client's socket to the end.
6. **A side effect, kept**: a client's Close before a lazy dial now hears the reason that the role
   always meant to send, `1000 client closed before the target was dialed`, where the reader's echo
   went first and took its place.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract
cargo test -p podssh-relay --features serve --lib serve::forward
cargo test -p podssh-relay --features serve,plain-ws --test session_relay_resume
sh scripts/plant-each.sh --here t671-close-ends-the-session t671-silence-from-the-close
```

A new test as in item 2; planted, the old end at the Close, it fails. A target that answers, then
holds its connection in silence, gets the role's Close 1 s after its answer, not 1 s after the
client's Close; planted, the silence counted from the Close, it fails. The layer's road is unchanged.

## Done

2026-11-04, merged from its draft (`b84add1`).

- After a client's Close, `/connect/` shuts the target's writing side and keeps carrying the
  target's bytes, then closes with `1000 target closed`, or with `1000 client half-closed, target
  idle for 15s` once the target was silent 15 s since its last byte, as `docs/relay.md` says; a
  link of `/v1/layer/` still ends at the client's Close. podssh-ws's session holds its answer to a
  Close where its owner asks (`holding_close_answer`), so the role answers once the target ends.
- `cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_contract --test
  session_relay_resume`: 16 and 6 passed; `--features serve --lib serve::forward`: 2; the relay
  crate with each serve feature and podssh-ws whole: 1,318 passed, 0 failed. Plants
  `t671-close-ends-the-session` and `t671-silence-from-the-close` caught. Clippy and rustfmt clean.

# T-677: A role with some 200 pairs or more does not start again: its file of pairs is read as a file of the cache

**Source:** the drafting agent of T-636, 2026-11-05 (a defect that it saw beside its work).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh relay serve --pairs FILE` keeps up to 4,096 pairs, and writes each into FILE; at its start it
reads FILE again. It read FILE as a file of the cache, whose reader refuses more than 64 KiB, and a
pair takes a few hundred bytes of it: a role with some 200 pairs or more did not start again (78),
and its pairs were lost to each node and operator.

## Premise

- `crates/podssh-relay/src/serve/reverse/pairs.rs` at `8462c35`, line 438, said "let text =
  crate::cache::read_private(path)?;", and line 31 says "pub const MAX_PAIRS: usize = 4096;".
- `crates/podssh-relay/src/cache.rs` at `8462c35`, line 45, said "pub const MAX_FILE: u64 = 64 *
  1024;", which `read_private` held each file to.

## Approach

A private read with a bound of its caller's (`cache::read_private_up_to`); the file of pairs takes 4
MiB, and T-636's file of counts, which had a copy of the reader for its 16 MiB, takes the same one.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,pair --lib -- serve::reverse::pairs
sh scripts/plant-each.sh --here t677-pairs-at-the-cache-s-cap
```

A role with 400 pairs, a file over 64 KiB, starts again with each of them; planted, the file read as
a file of the cache, the test fails.

## Done

2026-11-05. `cache::read_private_up_to(path, most)`, of which `read_private` is the cache's case; the
file of pairs is read up to 4 MiB (`FILE_MOST`), and the file of counts of T-636 through the same
reader. The test `a_file_larger_than_a_file_of_the_cache_is_read_again` makes 400 pairs, checks that
their file is over 64 KiB, and finds the first and the last after a restart: passed; planted
(`t677-pairs-at-the-cache-s-cap`), it fails: caught. `cargo test -p podssh-relay --features
serve,plain-ws,quick,pair,grant,piping,code,quic --lib -- pairs:: usage cache`: 35 passed. Clippy and
rustfmt clean.
