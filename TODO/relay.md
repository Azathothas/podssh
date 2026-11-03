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
   with the port when it is not 443. `same_deployment` (`crates/podssh-relay/src/pool.rs:143-148`)
   is the one rule that already decides where a token may go.
2. Use the key of the host in use at each place: the load and the store through `MintContext`
   (`crates/podssh-relay/src/token.rs` lines 84-112 at `2da855f`), the removal after a 403
   (`crates/podssh-relay/src/open.rs:351-359`), and the token check of `doctor`
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
would mint its own token, against the brake of 120 attempts a minute (`docs/relay.md:252`).
The decision said "one machine has one cached token"; on 2026-10-08 the operator ruled
"one for each relay deployment" (`docs/decisions.md:93`).

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
(`docs/relay.md:304-305`). The `health` function of `doctor`
(`crates/podssh-cli/src/doctor/relay_checks.rs:82-95`) already makes a verified `/health`
request; `crates/podssh-relay/src/pool.rs:177-194` fetches `/relays.json`. `https_get` sends no
token header (`crates/podssh-ws/src/client.rs:279-290`); `https_request` takes headers (lines
282-303).

## Approach

1. `relay status`: `/health` on each host of the list. Move `health` into `podssh-relay`, so
   `doctor` and `relay` share one path, and podbox can use it.
2. `relay info [HOST PORT]`: `/relays.json?host=&port=`, the pool and the limits, read with
   `crates/podssh-relay/src/pool.rs:152-173`.
3. `relay spec`: the `/health` version and `/llms-full.txt`, checked against the pinned facts by
   `verdict_from` (`crates/podssh-probe/src/relay_facts.rs:345-359`), or `--document FILE`.
   This is T-060.
4. `relay trace HOST PORT`: `/trace` with `banner=1`, the token in the header and never in the
   URL (`docs/relay.md:237-239`). Check HOST with `relay::check_host`
   (`crates/podssh-ws/src/names.rs:10-32`), so no text can add a query parameter.
5. `pair` and `revoke`: refuse by name, and name M4 (T-078, T-083).
6. Flags as for `doctor` (`--relay-host HOSTS`, `--relay-addr`, `--ca-file`), and `--json`
   (T-049). Each request has the 10 s limit of `doctor`
   (`crates/podssh-cli/src/doctor/relay_checks.rs:25`), and the run has a limit too.
7. Remove the owner row (`crates/podssh-cli/src/flags.rs` line 442 at `af0a163`); change `DISPATCHED`, `usage_tail`
   (`crates/podssh-cli/src/help.rs`, line 237 at `24f3e2a`), the notes, `docs/relay.md`, lines 296-302 at `24f3e2a`, and
   `docs/STATUS.md`. `dispatch.rs` has 448 lines: put the verb in its own module.

## Decision

Recommendation: remove the `--timeout` and `--jsonl` rows of `relay`
(`crates/podssh-cli/src/flags/relay.rs:9-44`), and bound each request in the code, as `doctor`
does. With the row, the gate of `crates/podssh-cli/src/dispatch.rs:304-322` stops
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

`scripts/fake-relay.py` (it serves `/health` and the mint: `:121-130`) gets `/relays.json`,
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
in a header (`crates/podssh-ws/src/client.rs:308-330`), for the pairing calls. On the live relay,
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
(`crates/podssh-relay/src/open.rs:224-275`), and keeps nothing between runs: a failure is a
note, and an entry of `Failure`. The limits are 20 s for each step and 45 s for each host (lines
25-29). Measured in the gate (`docs/STATUS.md`): a host that completes TLS and then says
nothing, and a host that does not start TLS, each cost the 20 s limit before the failover.

## Approach

1. After a host fails with an error that another host can repair (`another_host_may_help`,
   `crates/podssh-relay/src/open.rs:62-84`), write a record (host, time, class) into a private
   file `relay-failures-KEY.json` with `cache::store_file`
   (`crates/podssh-relay/src/cache.rs:151-185`). Remove the record when the host succeeds.
2. At the start of `open` (`crates/podssh-relay/src/open.rs:200-277`), move each host whose
   record is younger than a fixed window (10 min) to the end of the list, in its old order.
   Never remove a host: each host is still tried.
3. Record no error that each host would give (a policy refusal, a bad token in the
   environment): it says nothing about the host.
4. Print one note for each moved host: "trying HOST last: it failed N s ago (REASON)".
5. Ignore a record with a time in the future (a clock that moved).
6. `doctor` and `status` (T-051) show the records. State the window in THE RELAY section of the
   manual (`crates/podssh-cli/src/man/facts.rs:344-357`) and in `docs/relay.md:84-127`.
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

2026-10-12. The record in `crates/podssh-relay/src/failures.rs:1-315`: its
file and window at `crates/podssh-relay/src/failures.rs:26-30`, its entries
at `crates/podssh-relay/src/failures.rs:114-220`, the order of a run and its
notes at `crates/podssh-relay/src/failures.rs:235-255`, and the reason of a
failure at `crates/podssh-relay/src/failures.rs:289-308`. `open` orders
the hosts at `crates/podssh-relay/src/open.rs:207-213` and keeps the record
after each round at `crates/podssh-relay/src/open.rs:245-251`; the race
gives the silent hosts at `crates/podssh-relay/src/failover.rs:245-248`.
`podssh status` at `crates/podssh-cli/src/status.rs:116-120`, `podssh
doctor` at `crates/podssh-cli/src/doctor/mod.rs:99-109`, THE RELAY in the
manual at `crates/podssh-cli/src/man/facts.rs:375-392`, and
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
The gate runs the crate's tests with no C compiler (`scripts/gate.sh:163-177`). The build image
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
   (`crates/podssh-ws/src/session.rs:203-207`), which sends a real text frame; since T-071,
   `Leg::send_control` over `WsSocket` sends one too.
2. Three runs of 240 s: (a) no payload and no pings; (b) WebSocket pings every 20 s from both
   ends; (c) one byte of payload every 60 s. For each socket, record the time, the code and the
   reason of the close, or "open at 240 s".
3. At 240 s, send one byte each way: a hibernated socket can stay open and not deliver.
4. Stop the pair at the end (`POST /v1/stop/NAME`). Tokens go only in headers; never print one,
   and above all not the `stop_token` (`docs/reverse.md:291-300`).
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
   (`docs/reverse.md:37-45`), which would hide run (a).
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

**Source:** `docs/relay.md:328-340`; the reverse close table of the pinned contract
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

Not measured. Read: `docs/relay.md:317` gives the forward codes `1013` `client receive backlog`
and `target write backlog` (2 MiB queued), read from the relay's source; `docs/relay.md:328-340`
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
   into `docs/relay.md:328-340`. Change the window (512 KiB) only if the result asks for it.

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
`docs/relay.md:317` reads from the relay's source: `1013` when 2 MiB wait, and no frame dropped
(`crates/podssh-ssh/src/run.rs:26-29`). The two texts agree now. The question of this entry
stays: whether the relay's check operates at all (it reads `bufferedAmount`,
`docs/relay.md:328-340`).

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
2. D starts at 2 s. An open includes the relay's dial of the target (`docs/relay.md:183-185`), so
   a slow target also starts the next host. Measure the open times through a proxy in the box,
   and record D in `docs/STATUS.md`.
3. Send a Close to each attempt that is not kept, at once. The relay then frees the target
   socket within 15 s (`docs/design.md:659-661`, `docs/relay.md:313`); the target still sees one
   short connection, because the relay dials it before the upgrade.
4. One mint at a time for each relay deployment (single flight, keyed as T-057 keys the cache),
   against the brake of `docs/relay.md:252`. When the minting attempt is the silent one, the next
   attempt mints at its own host after D.
5. An error that each host would give (`crates/podssh-relay/src/open.rs:62-84`) still stops the
   run, and stops the other attempts.
6. Each attempt keeps its own notes, given to `notes` in the order of the list; the round notice
   (line 186 at `22c3b88`) stays a note of the run. `Failure` keeps each error; `Opened.relay` and the log
   name the host that was kept. tokio's `select!` and `JoinSet` need no new crate and no C.
7. Add the flag to `SSH_FLAGS`, `PROXY_FLAGS` and `DOCTOR_FLAGS`
   (`crates/podssh-cli/src/flags.rs:112-287`, 323-343) and to `ONCE`
   (`crates/podssh-cli/src/ssh/args.rs:171-207`); the variable to VARIABLES and the modes to THE
   RELAY (`crates/podssh-cli/src/man/facts.rs:46-297`, 170-183); both to `docs/relay.md:84-127`.
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
   (`crates/podssh-relay/src/cache.rs:417-434`), and one that refuses a write is skipped. When the
   directory of `PODSSH_CACHE_DIR` is skipped, say so once on stderr, with the reason.
4. Take the environment as a parameter, as `dial::proxy_from_vars` does
   (`crates/podssh-ws/src/dial.rs:109-123`), so that the tests can set it.
5. `doctor` names the directory in use and the variable that chose it; `status` (T-051) shows
   it; the settings file of T-048 can set it. The session log (T-056) and the failure records
   (T-059) use the same chain.
6. Change in the same commit: VARIABLES and FILES (`crates/podssh-cli/src/man/facts.rs:208-222`,
   `crates/podssh-cli/src/man/data.rs:161-169`), the test of lines 365-377 at `22c3b88`, the comment
   of `cache.rs`, and the `doctor`
   notes (`crates/podssh-cli/src/man/notes.rs:208-280`).

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
`crates/podssh-cli/src/man/facts/tests.rs:13-50` scans source, finds no absolute path literal. In
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
**Status:** open

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

## Correction

2026-11-02 (the drafting agent). Until that day this entry was blocked, and its `## Blocker`
read, moved here as `cargo todo check` refuses a Blocker on an open entry:

> The relay's operator: the egress of the relay is work of the relay project.
> The operator ruled on 2026-10-08 that the relay stays separate
> (`docs/decisions.md`).

Lifted on 2026-11-02 by Q63: see below.

The Premise, a measurement of the default deployment, stands. Approach item 2 says that podssh
"already says what happened" (`crates/podssh-relay/src/relay.rs:204-207`): true, but the direct
road after the relay hosts (T-363) does not run in this case. It runs only when no relay host
opened a session, and never with `-4` or `-6` (`docs/cli.md:384-388`); here the relay opened
(101), then closed with 1011.

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

# T-255: The relay's side drops reverse sockets at random, with no Close

**Source:** the runs of T-061 on 2026-10-09 (`crates/podssh-relay/tests/reverse_idle_live.rs`).
**Category:** measurement
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** open

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
(`docs/STATUS.md:269`). That is one run, before 2026-10-09.

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
`backoff(1)` (`crates/podssh-relay/src/reverse/node.rs:255`). Since T-379 each resume races the
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

2026-10-11. On Windows `closed` (`crates/podssh-relay/src/cache.rs:452-478`) reads the owner and
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
**Status:** open

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
(`docs/STATUS.md`, "The relay"). Read: the forward codes in `docs/relay.md:317` (2 MiB queued),
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
- Read: a beta needs the job `all` of the gate (`docs/decisions.md:58`). Citations of an older
  document of the relay were once off by 35 (`TODO/repo.md:2318-2321`).
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
  (`crates/podssh-ws/src/session.rs:312`); a message is at most 16 MiB (`:32`).
- Read: `crates/podssh-probe/facts/relay-facts.toml` line 14 at `deacafd` said "Read from /relays.json at startup,
  never compiled in" of that cap. `crates/podssh-ws/src/frame.rs:30` compiles it in, and
  `podssh-core` takes it from the facts file at compile time
  (`crates/podssh-core/src/irc/limits.rs:3-9`). The live check fetches `/llms-full.txt` and
  `/health` alone (`scripts/check-relay-spec.py:399-400`); `:196-197` reads the cap from the
  facts file.
- Read: podssh fetches `/relays.json` at a mint for its pool, and keeps `pool[].host` alone
  (`crates/podssh-relay/src/pool.rs:150-222`). `podssh relay info` reads its `limits`
  (`connect_timeout_ms`, `idle_timeout_ms`, `max_session_ms`, `max_session_bytes` and
  `max_frame_bytes`; `crates/podssh-cli/src/relay_diag_text.rs:64-77`), and a test asserts a
  stand-in's `max_frame_bytes` of 262144 (`crates/podssh-cli/tests/relay.rs:246`).
- Read: to a node, the resumable layer resumes after the relay's `1009` at the cap
  (`docs/relay.md:272-278`); a forward session has no layer.

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
**Status:** open

## Problem

Each road of the release binaries but `--direct` reaches one relay deployment, on Cloudflare,
under one domain, `ajam.dev`. A release binary copied into a cage is not updated, and it takes no
relay host outside `ssh.relay.ajam.dev`. A lapse of the domain, an outage of Cloudflare, or a
proxy that blocks the name stops `ssh`, `proxy`, `cp`, `node` and `chat` for each user, and the
relay's operator has no way to move the binaries in the field to another deployment.

## Premise

- Read: the default host and the six seeds of the pool are names under `ssh.relay.ajam.dev`
  (`crates/podssh-relay/src/relay.rs:13`; `crates/podssh-relay/src/pool.rs:20-29`), and a host of
  `/relays.json` outside the default's parent domain is dropped
  (`crates/podssh-relay/src/pool.rs:139-152`).
- Read: the relay is a Worker of Cloudflare
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:5-7`); its pool names placements
  in regions of AWS, GCP and Azure, each a name of the same domain (`:30-68`). Inferred: each is a
  placement of the same Worker.
- Read: the pairs of the reverse road live on the control host alone
  (`crates/podssh-relay/src/pair.rs:1-4`; `docs/relay.md:398-403`). The audit cited
  `docs/relay.md:390-395`; the fact is at `:398-403`.
- Read: a release binary is uploaded or copied into its host, which cannot build it or download
  it (Q48, `docs/decisions.md:54`); a machine keeps one token for each deployment, and podssh
  "never sends a token to a deployment that did not mint it" (`docs/decisions.md:93`).
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
   tried in the ways of Q10 (`docs/decisions.md:72`).
5. The cache keeps the signed document and its signature, so that a binary keeps the other
   deployments when the old domain is gone.
6. `podssh relay status` and doctor name each deployment, and whether its pool was signed.

The relay's side is item 14 of `docs/relay-operator.md`: the keys, the signed document, and a
second deployment on another provider and under another domain.

## Decision

The operator's ruling of 2026-10-31 (Q49, `docs/decisions.md`): a binary may use relays outside `ssh.relay.ajam.dev` when they are compatible, and a token goes only to the deployment that minted it. Relays that their users bring (Azathothas/podssh#60) and `podssh update` (T-375) make the signed list less pressing: when this entry is taken up, its Approach is read again against them, and a signature of the document stays the relay's operator's (`docs/relay-operator.md`, item 14).

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
**Status:** open

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
already tells the two apart (`scripts/fake_reverse.py:286-298`), with a grace of 2 s.

What the client does (the research of 2026-11-02 on the client's side), where the default
deployment still closes the socket: make the cut cheap. A 1003 is no exit since T-409, and the
operator's layer resumes since T-410; but the node's first connection again after a fault waits
`backoff(1)`, 0.5 s to 1.5 s (`crates/podssh-relay/src/reverse/node.rs:255`), though a 1003 is no
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
(`crates/podssh-relay/src/open.rs:208-251`), which `ssh`, `proxy`, `pipe`, `chat`, `doctor` and
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
  WebSocket road (`crates/podssh-relay/src/open.rs:209`, `crates/podssh-relay/src/open.rs:249`).
- `crates/podssh-cli/src/relay_ends.rs`: what a cut is (`cut_by`, `cut`), and `Told`, the relay
  stream that tells the record how its session ended once SSH lets it go, which
  `crates/podssh-cli/src/ssh/transport.rs:206` spawns. `podssh proxy`
  (`crates/podssh-cli/src/proxy.rs:395`) and the relay's end of `podssh pipe` (`carry_opened`)
  tell it at their end (`crates/podssh-cli/src/pipe/relay.rs:210-212`).
- `podssh status`: `relay_failures` names the road, and `relay_opened` gives the hosts that opened
  lately (`crates/podssh-cli/src/status.rs:216-223`); `podssh doctor`'s line `failed relays` says
  each host tried last, and a line `opened relays` those tried first
  (`crates/podssh-cli/src/doctor/mod.rs:399-427`). THE RELAY in the manual
  (`crates/podssh-cli/src/man/facts.rs:371-388`), `docs/relay.md` (step 5 of the selection) and
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
cache directory" (`docs/decisions.md:93`), and this one is another user's.

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
  directory, the temporary directory, the working directory" (`docs/decisions.md:93`); Q68 reads
  the effective uid's entry of `/etc/passwd` as a file, for the login name
  (`docs/decisions.md:33`, T-500).

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
`docs/relay.md` (the paragraph of T-243, `docs/relay.md:145-153`), and `docs/architecture.md` says
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
