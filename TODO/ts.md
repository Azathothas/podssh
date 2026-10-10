This file holds the work on `podssh ts`: the command in `crates/podssh-cli/src/ts.rs`, the adapter
crate crates/podssh-ts/, and the fork vendor/tailscale-rs with its patches in vendor/patches/
(`vendor/tailscale-rs/LOCAL-PATCHES.md`). It has the rows C2, C3 and C9 of the former defects page
(`git show 3ee70dc:docs/defects.md`) and the Tailscale item of M8 (`docs/ROADMAP.md:247-250`). All
of it is behind the cargo feature `ts`: the default binary refuses `podssh ts` with exit 70. The
fork builds aws-lc and uses much memory, so run one build at a time with `CARGO_BUILD_JOBS=4`
(`AGENTS.md`, section 4). The fork's own tests run in the build image through
`scripts/ts-derp-prove.sh:82-131`.

# T-100: C2: `podssh ts` waits for ever when no network map arrives

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row C2 (high). Confirmed
here on `3ee70dc` by reading the command and the fork.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`--timeout` limits the start of the node and the TCP connect, but not the status query or the peer
lookup. Both wait inside the fork until the control server sends the first network map. When no
map arrives, `podssh ts` and `podssh ts -W PEER:PORT` wait for ever, also in a script that gave
`--timeout`. `--ts-wait-allowlist` does not help: its loop runs only after the query returns.

## Premise

Measured: `podssh ts --timeout 5s </dev/null` exits 70 ("'ts' is not available in this build"), so
the rest is read. `bound` wraps only `TsNode::start` and `tcp_connect`
(`crates/podssh-cli/src/ts.rs`, lines 207-221 at `4c3b456`, `crates/podssh-cli/src/ts.rs`, lines 353-363 at `4c3b456`), not `node.status()`
or `node.peer_ip()` (`crates/podssh-cli/src/ts.rs`, line 289 at `4c3b456`, `crates/podssh-cli/src/ts.rs`, line 344 at `4c3b456`). The
module comment says that the bound caps the whole operation (`crates/podssh-cli/src/ts.rs`, lines 9-14 at `4c3b456`),
and `docs/cli.md:627-629` makes that a rule.

Read: `status()` calls `Device::self_node()` (`crates/podssh-ts/src/node.rs`, lines 76-79 at `4c3b456`), whose reply
waits in a queue until a map with the self node arrives
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:278-295`,
`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:544-558`). `peer_ip()` waits for the first
peer update (`vendor/tailscale-rs/ts_runtime/src/peer_tracker/mod.rs:74-98`), against its comment
"never a hang" (`crates/podssh-ts/src/node.rs`, lines 90-92 at `4c3b456`). The wait loop handles only `NetmapPending`,
a self node with no home region (`crates/podssh-cli/src/ts.rs`, lines 288-320 at `4c3b456`).

## Approach

1. Make one deadline from `--timeout` at the start of `ts_async` (`crates/podssh-cli/src/ts.rs`, lines 77-83 at `4c3b456`),
   and give each later wait only the time that remains.
2. Add `TsNode::status_within(limit)` and `TsNode::peer_ip_within(limit)`: the fork call inside
   `tokio::time::timeout`, and `NodeError::NetmapPending` when the limit passes. A dropped query
   leaves its reply sender queued (`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:288-292`);
   a later send must not panic.
3. With no `--timeout` (a terminal), limit the first map wait by `--ts-wait-allowlist`, else by a
   named constant of 20 s, "a design constant, not a measurement", as at
   `crates/podssh-cli/src/ts.rs`, lines 298-301 at `4c3b456`. The default stays fail-fast (`docs/decisions.md:42`).
4. Apply the same limit to the address wait in `Device::tcp_connect`
   (`vendor/tailscale-rs/src/lib.rs:308-312`). Keep one message and exit 78 for "no map in time".
5. Correct the two comments, and update `docs/STATUS.md`, line 307 at `7aa955a` in the same commit.

## Decision

2026-10-10, in the work:
- The deadline and the limited wait live in podssh-ts (`crates/podssh-ts/src/wait.rs`), where a
  test with a paused clock reaches them without a fork. With `--timeout`, each wait gets what
  remains of it and no window of its own; without, `--ts-wait-allowlist`, else `FIRST_MAP_WAIT`.
- Step 4 is done from podssh, not in the fork: the pipe asks for the node's own address with the
  limit (`TsNode::address_within`) before `tcp_connect`, whose own ask then has its answer. A
  patch of the fork lost: one more local patch to carry, for what podssh can do from outside.
- `--ts-wait-allowlist` gives the window of the pipe's waits too: it is how long a run waits for
  the relay to admit its key, whichever form runs.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ts --test netmap_wait
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
timeout 120 target/debug/podssh ts --ts-mode relay --ts-auth-key-file KEYFILE --ts-state STATE --timeout 20s </dev/null; echo "exit=$?"
```

The new file crates/podssh-ts/tests/netmap_wait.rs gives the limit a future that never ends
(`std::future::pending`) under `tokio::time::pause()`, and checks the time that remains for each
wait. Plant: await with no limit; an outer `tokio::time::timeout` must then fail the test. An
offline test cannot reach the fork's queue: with a silent control server, the start itself waits
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:136-158`). The second command is the feature
suite (226 passed, `docs/STATUS.md:325`). The third is live, with a `ts` build, while no map comes
(`docs/tailscale.md:10-11`): it must print `exit=78` after about 20 s, not `exit=124`.

## Correction

2026-10-10: the claim of step 2 holds. A reply that the fork sends after a wait gave up goes
nowhere: kameo 0.21.1's `ReplySender::send` discards the result of its send (`let _ =
self.tx.send(...)`, in `src/reply.rs` of the crate). The count of the feature suite is now
424 passed, 0 failed, 24 ignored before this entry (`docs/STATUS.md:325` said 226 at T-060). The
live command needs a tailnet auth key file, and no document names one: the key is in `.env/`,
which a session may not read. Which file a session may pass to `--ts-auth-key-file` is the
operator's question Q40 (`TODO/PROGRESS.md`).

## Done

2026-10-10. One deadline from `--timeout`, made when the run starts, and each later wait gets
what remains (`crates/podssh-cli/src/ts.rs`, `crates/podssh-ts/src/wait.rs`). The status, a
peer's name and the node's own address each wait for the first network map at most
`--ts-wait-allowlist`, else `FIRST_MAP_WAIT` (20 s, a design constant), and never past the
deadline (`TsNode::status_within`, `peer_ip_within` and `address_within` in
`crates/podssh-ts/src/node.rs`); a wait that passes its limit is `NetmapPending`: one message, and
exit 78. The comments that said the bound caps the run, and that a lookup never hangs, now say
what holds.
- Native, Windows 11: `cargo test -p podssh-ts --test netmap_wait`, 3 passed, under a paused clock:
  a wait for a map that never comes (`std::future::pending`) ends at its limit; after a start of
  5 s, a bound of 20 s leaves the map wait 15 s, and the run ends at 20 s; with no bound, the
  window stays. Planted, a wait with no limit: the outer timeout of an hour fails two tests.
  `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast`: 427
  passed, 0 failed, 24 ignored. clippy with no warning. `cargo test --workspace`:
  1140 passed, 0 failed, 38 ignored.
- The live command of the Prove waits for Q40 and T-251.


# T-101: C3: a local end of input cuts the reply in the `podssh-ts` pipe

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row C3 (high). Confirmed
here on `3ee70dc` by reading the pipe and its tests.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh ts -W HOST:PORT` copies stdin to the stream and the stream to stdout. When stdin ends
first, the pipe returns at once, and a reply that the peer sends after that is lost. A request on
stdin, such as an HTTP `GET`, thus gets no answer on stdout. A closed stdout also ends the pipe
with exit 70, not as a clean end.

## Premise

Read: `pipe_streams` races the two directions and returns when the first ends; on the local end it
reports `down: None` (`crates/podssh-ts/src/pipe.rs`, lines 62-93 at `1ee321d`). Its comment calls this the behaviour
of an OpenSSH `ProxyCommand` (`crates/podssh-ts/src/pipe.rs`, lines 51-61 at `1ee321d`). The test
`local_eof_first_cuts_the_down_leg` asserts it, and checks nothing about the remote's bytes
(`crates/podssh-ts/tests/pipe.rs`, lines 62-95 at `1ee321d`). The next test accepts the same
(`crates/podssh-ts/tests/pipe.rs`, lines 97-122 at `1ee321d`).

Read: `podssh proxy` keeps receiving after the end of stdin (`crates/podssh-cli/src/pipe/relay.rs:94-108`),
and a closed stdout is a clean end there (`crates/podssh-cli/src/pipe/relay.rs:197-201`) and in the rules
(`docs/cli.md:605`). `podssh ts -W` exits 70 on each copy error (`crates/podssh-cli/src/ts.rs`, lines 404-407 at `1ee321d`).
The relay closes a half-closed forward session after 15 s with no bytes from the target
(`docs/relay.md:186`). An earlier version of the pipe waited with no limit, and hung
(`crates/podssh-ts/src/pipe.rs`, lines 77-81 at `1ee321d`).

## Approach

1. On the end of stdin, shut down the write half of the stream, as today
   (`crates/podssh-ts/src/pipe.rs`, lines 69-73 at `1ee321d`), and keep copying the stream to stdout.
2. End the pipe when the stream ends, when stdout closes, or after 15 s with no bytes from the
   stream. Name the 15 s as a constant: the value of the relay's rule.
3. Report exact counts in both directions (`crates/podssh-ts/src/pipe.rs`, lines 34-49 at `1ee321d`). A closed stdout is
   a clean end with exit 0 (`crates/podssh-cli/src/ts.rs`, lines 391-408 at `1ee321d`).
4. Rewrite the two tests, and update `docs/STATUS.md:311` in the same commit.

## Decision

Recommendation: keep reading after the end of stdin, with an idle limit of 15 s, as `podssh proxy`
and the relay's forward road do. The alternative, no limit, lost because a peer that never closes
then holds the pipe for ever, which was measured. `ssh` stops its `ProxyCommand` at the end of a
session, so the limit matters only for scripts.

2026-10-10, in the work:
- The counts are exact in both directions: each leg counts its bytes as they go, so a leg that
  the end drops mid-copy still reports what it moved; `PipeEnds` says whether stdin ended and why
  the pipe ended (`End`).
- The end of the stream still ends the pipe at once, as before: the remote has said all it will.
- The idle limit runs only after the end of stdin: before it, an interactive session may be silent
  for as long as its user is.
- A write error on stdout that means its reader left (`BrokenPipe`, `ConnectionReset`,
  `ConnectionAborted`) is the clean end; any other stays a failure, with 70.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ts --test pipe
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
```

New tests in crates/podssh-ts/tests/pipe.rs: `a_reply_after_local_eof_reaches_stdout` (the remote
writes after the local end; the bytes arrive, and `down` is exact),
`a_silent_peer_ends_the_pipe_after_the_idle_limit` (under `tokio::time::pause()`) and
`a_closed_stdout_is_a_clean_end`. Plant: return at once on the local end again; the first test must
fail. T-106 checks the real binary: a request through `podssh ts -W` gets its reply on stdout.

## Done

2026-10-10. At the end of stdin the pipe shuts the stream's write half and reads on: it ends when
the stream ends, when stdout closes, or when the stream sends nothing for 15 s
(`IDLE_AFTER_EOF`, the relay's rule), and it reports exact counts both ways and why it ended
(`crates/podssh-ts/src/pipe.rs`). `podssh ts -W` exits 0 at each of these ends, a closed stdout
with them, and says which on stderr (`crates/podssh-cli/src/ts.rs`).
- Native, Windows 11: `cargo test -p podssh-ts --test pipe`, 8 passed: the new
  `a_reply_after_local_eof_reaches_stdout` (the peer answers only after it has read the whole
  request and its end; the reply arrives, up 5 and down 5), `a_silent_peer_ends_the_pipe_after_the_idle_limit`
  and `the_idle_limit_counts_from_the_last_byte_of_the_stream` under a paused clock (15 s, and
  20 s plus 15 for a reply in two parts 10 s apart), and `a_closed_stdout_is_a_clean_end`; the two
  old tests that asserted the cut, rewritten. Planted, a return at the end of stdin: the first
  test fails, and three others; planted, a closed stdout as an error: its test fails.
  `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast`: 430
  passed, 0 failed, 24 ignored. clippy with no warning. `cargo test --workspace`:
  1143 passed, 0 failed, 38 ignored.
- The real binary with a request and its reply through `podssh ts -W` is T-106's check, which
  waits for the relay's operator.

# T-102: C9: the automatic mode always selects tcp, and ephemeral nodes are not logged out

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row C9 (medium). Confirmed
here on `3ee70dc` by reading the adapter and the fork.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

With `--ts-mode auto`, `podssh ts` always takes `tcp`, because each probe only checks that a key
file was given. On a host that cannot reach the stock DERP servers, it never falls through to
`relay`. With `--ts-ephemeral`, the node registers as ephemeral, but podssh never logs it out, so
the tailnet keeps an offline device until the control server removes it.

## Premise

Read, at `c17e64f`: `probe` returns `Ok` for `Tcp` and `Relay` when `has_key` is true
(`crates/podssh-ts/src/chain.rs` lines 44-61), which `podssh ts` always sets
(`crates/podssh-cli/src/ts.rs` line 136). The first ready mode of `tcp`, `relay` wins
(`crates/podssh-ts/src/chain.rs` lines 63-76), and a test asserts it (`crates/podssh-ts/tests/chain.rs`
lines 26-31). The decided chain is tun, socks, tcp, relay (`docs/decisions.md:42`), and the rule is to probe
before use (`docs/target-environment.md:90-92`).

Read, at `c17e64f`: `ephemeral` goes into the register request (`crates/podssh-ts/src/node.rs` line
69). The fork has no logout: `Device::shutdown` only stops the actors (`vendor/tailscale-rs/src/lib.rs`
lines 327-357), and `podssh ts` never calls `TsNode::shutdown` (`crates/podssh-ts/src/node.rs` lines
124-127). The fork's own type says that a register request with an expiry in the past expires the
current node key (`vendor/tailscale-rs/ts_control_serde/src/register.rs:92-97`).

## Approach

1. Probe each mode before `TsNode::start`, through the proxy of T-103, in 8 s per step as
   `podssh doctor` does (`crates/podssh-cli/src/doctor/net.rs:14-15`): for `tcp`, a TLS handshake to
   a stock DERP server on port 443; for `relay`, one to the relay host. Dial with
   `crates/podssh-ws/src/dial.rs:224-227`. `Unknown` is never ready (`crates/podssh-ts/src/chain.rs:15-24`).
2. Add a logout to the fork: a register request with an expiry in the past, a `ControlRunner`
   message and `Device::logout(timeout)`, as a new patch with its row in
   `vendor/tailscale-rs/LOCAL-PATCHES.md`.
3. `TsNode::shutdown` logs out first when the node is ephemeral, in 5 s at most. `podssh ts` calls
   it at the end of each form, also after an error (`crates/podssh-cli/src/ts.rs`, lines 232-242 at
   `c17e64f`). Never
   log out a node that is not ephemeral: its allowlist entry is lost (`docs/tailscale.md:76-77`).
4. Update `docs/tailscale.md` and `docs/STATUS.md:311` in the same commit.

## Decision

Recommendation: probe before the start, because the chain falls through only before a dial
(`crates/podssh-ts/src/chain.rs:1-7`). Starting in `tcp` and again in `relay` lost: it registers
twice, and it waits for a failure that has no limit today. Take the DERP host from the default
DERP map through the proxy, as a fork test does (`vendor/tailscale-rs/ts_netcheck/src/derp_latency.rs:146`).

Decided in the work (2026-10-10):
- A forced mode is checked too, alone, and a check that fails exits 78 with its reason. Starting it
  unchecked lost: the start then waits with no limit for a route that the check found missing (a
  planted start through a proxy that refuses waited out its whole bound of 60 s).
- The checks run in chain order, and a later mode is not checked once one passed. Checking both
  at once lost: a second connection at a time (`AGENTS.md`, rule 2), and a ready `tcp` that waits
  for a slower `relay`.
- `tcp` tries the first DERP server of each of the first three regions of the map, in one step of
  8 s, with the server's DERP port, 443 when the map gives none: one server that is down does not
  fail the mode. A list of DERP hosts in the code lost: Tailscale renames its servers (the map of
  2026-10-10 names `derp1f.tailscale.com`).
- The key file, the state file and the proxy URL are checked before the network, so a usage error
  waits for no network check.
- The logout comes after the bound of `--timeout`, in 5 s at most. A logout cut to what remains of
  the bound lost: a run that used its whole bound would leave its device behind.
- No auth key goes with the logout. Go's client attaches its key to each register request, a
  logout too (`tailscale/tailscale:control/controlclient/direct.go`, `doLogin`), and headscale
  takes a logout with or without one (`juanfont/headscale:hscontrol/auth.go`, `handleLogout`).
  Sending it lost: the control server finds the node by its key, and the key would cross the
  network once more. If the live run shows that Tailscale's control server needs it, it goes in.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ts --test chain
cargo test --manifest-path vendor/tailscale-rs/Cargo.toml -p ts_control --test logout
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
```

In crates/podssh-ts/tests/chain.rs, `auto_takes_relay_when_the_tcp_probe_fails` replaces
`the_default_chain_prefers_tcp_then_relay`. Plant: ignore the probe result; that test must fail.
The fork test vendor/tailscale-rs/ts_control/tests/logout.rs checks the request body: this node
key and an expiry in the past. Run it in the build image. Live: after `podssh ts --ts-ephemeral`
exits, the node must leave the device list of the tailnet in 60 s.

## Correction

2026-10-10 (found in T-104): "none in the fork's `ts_control`, `ts_runtime` and `tailscale`" was read
through podssh's workspace, which caps the lints of a path dependency outside it. With the fork's
own manifest, clippy finds none in `ts_control` and `tailscale`, and in `ts_runtime` one from patch
0011: T-276.

2026-10-10: T-103 is not done, so there is no proxy of T-103 to use. The checks take `--ts-proxy`,
read with the port that the fork gives a URL with none (8080), else the environment's proxy for
each host, as each other podssh command does; the fork's own dial still takes `--ts-proxy` only,
which T-103 repairs, and its Approach now says so.

## Done

2026-10-10, in the commit that closes this entry. Before the node starts, `podssh ts` checks each
mode in chain order through the proxy, each step in 8 s (`crates/podssh-cli/src/ts/probe.rs`):
`tcp` reads Tailscale's default DERP map from `login.tailscale.com` and makes a TLS handshake with
the first DERP server of each of the first three regions until one answers, and `relay` makes one
with the relay host; podssh's trust store verifies each. `ChainInputs` holds the verdict of each
mode's check, and a mode with none is `Unknown`, never ready (`crates/podssh-ts/src/chain.rs`).
`auto` takes the first that passed and says which it passed over; a forced mode is checked alone;
with none ready, each reason is printed and the exit is 78. The fork has a logout, patch
`vendor/patches/0016-logout.patch` with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`:
`ts_control::logout` posts a register request with this node key and an expiry in the past, the
control runner answers a `Logout` message over its connection, and `Device::logout(timeout)` waits
for the answer. `TsNode::shutdown` logs an ephemeral node out first, in 5 s at most, and never one
that is not ephemeral; `podssh ts` calls it at the end of each form, after an error too, and says
when a logout failed (`crates/podssh-ts/src/node.rs`, `crates/podssh-cli/src/ts.rs`).
`docs/tailscale.md`, the manual, the help of `--ts-mode` and `--ts-ephemeral`, and `docs/STATUS.md`
say so.
- Native, Windows 11: `cargo test -p podssh-ts --test chain`, 6 passed, with
  `auto_takes_relay_when_the_tcp_probe_fails` in place of `the_default_chain_prefers_tcp_then_relay`;
  planted, the probe ignoring the check: that test fails, and two others. The fork's test, `cargo
  test -p ts_control --test logout` through podssh's workspace, 2 passed; planted, the expiry left
  out, and one a day ahead: the first test fails each time. `cargo test -p podssh-cli --features ts
  --test ts_probe`, 7 passed: the DERP servers of the map that `login.tailscale.com` served
  (`crates/podssh-cli/tests/fixtures/derpmap-default-2026-10-10.json`), the servers passed over,
  the proxy of the checks, a proxy that opens each tunnel late to a server that says nothing,
  which each check leaves at the 2 s that remain of its bound, and runs through a proxy that
  refuses, which exit 78 with each reason and start no node (no state file is made); planted, a
  mode selected with no check, both runs start the node and fail, and with no bound around a
  whole step, the `tcp` check took 3.8 s. Live from this machine, the ignored
  `both_checks_pass_from_this_machine`: the `tcp` check passed in 1524 ms, the `relay` check in
  361 ms. The sixteen patches, applied to
  an export of pristine `f4781c4`, give the vendored tree byte for byte on all 33 touched paths.
  `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast`: 467 passed, 0
  failed, 25 ignored. clippy with `-D warnings`: no warning, and none in the fork's `ts_control`,
  `ts_runtime` and `tailscale`. `cargo test --workspace --no-fail-fast`: 1198 passed, 0
  failed, 39 ignored.
- Waits for T-251: the fork's test with the fork's own manifest, in the build image. Waits for
  T-251 and Q40, the auth key file that a session may pass: the live run, in which an ephemeral
  node leaves the tailnet's device list within 60 s of the end of `podssh ts --ts-ephemeral`.

# T-103: The DERP dial of the Tailscale fork does not use the proxy

**Source:** `docs/ROADMAP.md:247-250` ("first repair its DERP dial, which does not use the proxy").
Confirmed here on `3ee70dc` by reading the fork and the command.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

In `relay` mode, the node dials the relay over a WebSocket. That dial goes straight out, with the
system resolver and no time limit, so on a host whose only egress is a CONNECT proxy the node never
reaches DERP. Also, `podssh ts` does not read `HTTPS_PROXY`: only `--ts-proxy` gives a proxy, unlike
each other podssh command, and a proxy password in `--ts-proxy` is on the command line.

## Premise

Read, at `0b6f4b8`: `ws::connect_with_subprotocol` opens `TcpStream::connect((hostname, port))`
(`vendor/tailscale-rs/ts_derp/src/ws.rs` lines 63-68). The other three dial sites check the proxy
first (`vendor/tailscale-rs/ts_derp/src/dial.rs` lines 191-204, `vendor/tailscale-rs/ts_http_util/src/lib.rs`
lines 126-141, `vendor/tailscale-rs/ts_control/src/control_dialer.rs` lines 82-86), and the proxy module
warns that a fourth path that goes direct keeps the route that cannot work
(`vendor/tailscale-rs/ts_http_util/src/proxy.rs` lines 9-12). `relay` mode reaches `ws::connect` through
the pin (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:333-340`), and so does the
WebSocket mode with no pin (`vendor/tailscale-rs/ts_derp/src/client.rs:141-147`).

Read, at `0b6f4b8`: `podssh ts` takes the proxy from `--ts-proxy` only (`crates/podssh-cli/src/ts.rs`
lines 176-207), against the manual (`crates/podssh-cli/src/man/facts.rs:45-51`), the rule at
`docs/target-environment.md:68-71` and `SECURITY.md:61-65`. A URL with no port means 80 in podssh
(`crates/podssh-ws/src/dial.rs:70`) but 8080 in the fork (`vendor/tailscale-rs/ts_http_util/src/proxy.rs`, lines
39-41 at `0b6f4b8`).
Not measured: whether the proxy of a sandbox allows `tcp.ts.relay.ajam.dev:443` (`docs/tailscale.md:78-79`).

## Approach

1. In the fork, write one function that opens TCP to a host name: through the proxy when one is
   set, else direct, in 20 s at most (`vendor/tailscale-rs/ts_http_util/src/proxy.rs:43-44`). Call
   it from `ws::connect_with_subprotocol` and from `dial_by_ipusage`, so one branch serves both.
2. Add it as a new patch with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`, replace the stale
   text at `vendor/README.md`, lines 62-75 at `0b6f4b8`, and check that the whole chain of patches still applies.
3. In `podssh ts`, take `--ts-proxy`, else `podssh_ws::dial::proxy_from_env`
   (`crates/podssh-ws/src/dial.rs:169-193`). Give the fork a URL with an explicit port, and never
   print its credentials. The fork has one proxy for each process
   (`vendor/tailscale-rs/ts_http_util/src/proxy.rs:169-184`), so apply `NO_PROXY` for each host in
   the new function.
4. Update `crates/podssh-cli/src/flags.rs:274-275`, `docs/tailscale.md:78-79` and
   `docs/STATUS.md:311` in the same commit.

Added by T-102 (2026-10-10): the checks of each mode before the start already take `--ts-proxy`,
else the environment's proxy (`crates/podssh-cli/src/ts/probe.rs`); give the fork the same choice.
The fork's `ProxyConfig::from_url` sends the user name and the password as `url::Url` gives them,
percent-encoded (`vendor/tailscale-rs/ts_http_util/src/proxy.rs`, lines 75-78 at `0b6f4b8`), where podssh-ws decodes
them: decode them in the new function, and test a password with `%40` in it.

## Decision

Decided in the work (2026-10-10):
- A URL with no port means port 80 in `podssh ts` too, the flag's as each variable's, as in each
  podssh command, and the fork gets the port written. The fork's 8080 for the flag lost: one URL
  would name two ports in podssh.
- The `no_proxy` list goes to the fork with a proxy that the environment named, in its
  `ProxyConfig`, and the fork applies it for each host by podssh's rules; a test compares the two
  readings case by case. The flag names one proxy for each host, as podssh-ws's explicit proxy.
  Reading `NO_PROXY` in the fork lost: the fork would read a variable that podssh did not choose.
- The fork still sends a loopback host through its proxy unless the list names it, where podssh-ws
  never does: no node dials a loopback host, and the fork's tests reach their stand-ins so.
- Credentials in `--ts-proxy` are warned of, not refused: the flag stays usable where no variable
  can be set. Refusing lost: it breaks each script that passes them today.
- Repaired here, found in the work: the fork's refusals quoted the proxy URL, with its password, and
  podssh-ts quoted it too, as did the `Debug` of the fork's `ProxyConfig` (Base64) and of podssh's
  `TsConfig`; none does now. A proxy at an IPv6 address kept its brackets in the fork, so the dial to
  it could not resolve on Linux; the address goes without them now. The fork's TLS took rustls's
  process default provider, which a build with two providers lacks: `cargo test --workspace`, whose
  iroh test relay turns on `ring`, panicked in the first TLS of the new tests, and so would a podssh
  built with the features `ts` and `iroh-test`. The fork names aws-lc-rs now, patch 0018.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh run -- 'sh /work/scripts/ts-derp-prove.sh'
cargo test -p podssh-ts --test config
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
```

A new step of the script runs the fork test vendor/tailscale-rs/ts_derp/tests/ws_proxy_dial.rs,
which follows `vendor/tailscale-rs/ts_derp/tests/proxy_dial.rs:14-67`: the call
`ws::connect("relay.invalid", 443)` must send `CONNECT relay.invalid:443` to a fake proxy, then fail
at TLS, not at the name. Plant: remove the proxy branch; the fake sees nothing, and the test fails.
A new test in crates/podssh-ts/tests/config.rs checks the choice: the flag, then the variables in
the order of `crates/podssh-ws/src/dial.rs:163`. Live: with `HTTPS_PROXY` naming
`scripts/fake-proxy.py`, `podssh ts --ts-mode relay` must make its log list the relay host.

## Correction

2026-10-10 (found in T-104): "no warning, also in the fork's crates" was read through podssh's
workspace, which caps the lints of a path dependency outside it. With the fork's own manifest,
clippy warns in `ts_derp` about the size of `ts_derp::Error`, as since patch 0003, and in
`ts_http_util`'s proxy tests about a mutex guard held across awaits, as in patch 0013, two of them
in this entry's tests: T-276.

## Done

2026-10-10, in the commit that closes this entry. The fork has one dial by host name,
`ts_http_util::proxy::dial`: through the proxy when it `applies` to the host, else direct, within
20 s either way. `ws::connect_with_subprotocol` and `dial_by_ipusage` use it, and each of the four
dial sites asks `applies(host)`; the proxy's `no_proxy` list goes direct; the fork decodes the
proxy's credentials, and none of its refusals quotes the URL. Patch
`vendor/patches/0017-proxy-dial.patch` with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`, and
`vendor/patches/0018-tls-provider.patch`, the fork's TLS on a named provider; the stale text of
`vendor/README.md` is replaced. `podssh ts` takes `--ts-proxy`, else the first of the
variables that each podssh command reads, in its order, with `no_proxy`
(`podssh_ts::config::choose_proxy`, with podssh-ws's reading and its `PROXY_VARS`), gives the fork
a URL with its port written, uses the same proxy for its checks before the start, and says when
`--ts-proxy` holds credentials. The help of `--ts-proxy`, the manual, `docs/tailscale.md` and
`docs/STATUS.md` say so; `scripts/ts-derp-prove.sh` runs the fork's new tests.
- Native, Windows 11: `cargo test -p podssh-ts --test config`, 7 passed, with the choice: the flag,
  then the variables in the order of podssh-ws's `PROXY_VARS`, an empty one skipped, `no_proxy`
  before `NO_PROXY`; the port and the credentials as podssh reads them; a bad proxy named by its
  source, its password quoted nowhere. `cargo test -p podssh-ts --test derp_proxy`, 5
  passed, through stand-ins on the loopback: `ws::connect("relay.invalid", 443)` sends `CONNECT
  relay.invalid:443` to the proxy; a host on the list goes direct to its stand-in relay; the
  credentials reach the proxy as typed; a proxy at `[::1]` is reached; and the fork's `no_proxy`
  rules equal podssh-ws's in 21 cases. Planted, one at a time: the old direct dial, a list never
  read, the credentials as `url` gives them, a matcher that keeps the port, and the brackets kept:
  each fails its test. The fork's own tests, with the fork's manifest and lock: `cargo test
  --manifest-path vendor/tailscale-rs/Cargo.toml -p ts_derp` with `ws_proxy_dial`, `proxy_dial`,
  `connect_mode` and `wire_compat`, 9 passed; `-p ts_http_util --test proxy`, 8 passed; `-p
  ts_control --test logout`, 2 passed. `cargo test -p podssh-ts -p podssh-cli --features
  podssh-cli/ts --no-fail-fast`: 476 passed, 0 failed, 25 ignored. clippy with `-D
  warnings`: no warning, also in the fork's crates. `cargo test --workspace --no-fail-fast`:
  1206 passed, 0 failed, 39 ignored; before patch
  0018, two of the new tests panicked there. The eighteen patches give the vendored tree byte for
  byte on all 36 touched paths. Live, `ts_derp`'s example `ws_handshake` with the fork's manifest:
  TLS and the WebSocket upgrade to the relay, its server key, then its close 1008 for a fresh key.
- Live, this machine: with `HTTPS_PROXY` naming `scripts/fake-proxy.py`, which let only the relay
  host through, `podssh ts --ts-mode relay` passed its check through the proxy (`200 CONNECT
  tcp.ts.relay.ajam.dev:443` in the proxy's log) and started the node, and the node's own dial to
  the control server went through the same proxy (`403 CONNECT controlplane.tailscale.com:443`),
  which refused it there: nothing reached Tailscale, and the run ended at its bound of 20 s with
  exit 78.
- Waits for T-251: `scripts/ts-derp-prove.sh` in the build image. Waits for T-251 and Q40: the
  relay host in the log of the fake proxy from the node's own DERP dial, which comes after the node
  has registered.

# T-104: `podssh ts` connects again after a drop

**Source:** `docs/ROADMAP.md:247-250` ("and its missing reconnection"). Read here on `3ee70dc` in
the fork, and in kameo 0.21.1, the fork's actor crate, in the local cargo registry.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

When the DERP connection of a region drops, the fork logs the error and never dials again, so the
node has no path to its peers and a `-W` pipe stalls with no message. A connection that dies with no
close is not even noticed: the client keeps no limit on the server's keepalives. The control
connection starts again at most five times in 5 s, and then stops for good.

## Premise

Read, at `a3c196e`: `Runner::run` ends at the first error
(`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs` lines 248-254), `start_runner` only logs
it (lines 72-76), and the task then stops normally
(`vendor/tailscale-rs/ts_runtime/src/task.rs:80-85`). In kameo, a normal stop of a linked actor does
not stop its partner (`on_link_died` in `tqwewe/kameo:src/actor.rs`). So `Uniderp` stays with no
runner until a changed region (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs`, lines
171-192 at `a3c196e`). The client ignores the timing of `KeepAlive` frames
(`vendor/tailscale-rs/ts_derp/src/client.rs`, lines 277-282 at `a3c196e`).

Read, at `a3c196e`: `ControlRunner` stops when the map stream ends
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs` lines 426-429), under the default
supervision (`vendor/tailscale-rs/ts_runtime/src/lib.rs` lines 161-170): five restarts in 5 s at
most, with no wait
(`tqwewe/kameo:src/supervision.rs`). podssh's relay client has the rules to copy: a capped backoff
with jitter (`crates/podssh-relay/src/open.rs:262-276`), and a ping every 10 s with three silent
checks allowed (`crates/podssh-ws/src/client.rs:31-32`, `docs/relay.md:84-86`).

## Approach

1. Make the DERP runner a loop: connect, run, wait, and again
   (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs`, lines 248-254 at `a3c196e`). The loop gets the connect
   and run steps as arguments, so a test drives it with no network.
2. Wait with podssh's backoff, passed in `RuntimeOptions`; count from 1 after a link of 60 s. With
   a pin, each region dials the relay with one key (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:333-340`):
   two sockets must not replace each other for ever (`crates/podssh-ts/src/classify.rs:3-6`).
3. Do not retry `1008 "not authorized"`, except under `--ts-wait-allowlist` (`docs/decisions.md:42`);
   it goes to the state of T-105. The inactivity close of a region that is not home is no error
   (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:404-409`).
4. Ping every 10 s; three silent intervals mean a dead link, after the relay answered one ping.
5. Restart `ControlRunner` with the same backoff and no count limit. podssh-cli prints one stderr
   line for each drop and each new connection. Add the patch and its row, and update
   `docs/tailscale.md`, `docs/STATUS.md:311` and `crates/podssh-cli/src/man/notes.rs:314-339`.

## Decision

Recommendation: connect again inside the fork's runner. The network stack keeps its TCP streams
over a short break, and only the runner knows the region and the key. A new `Device` from
podssh-cli after each drop lost, because it breaks each open stream and registers again.

Decided in the work (2026-10-10):
- The loop is `ts_runtime::reconnect::keep` over a `Link` trait (wait, connect, run, changed): the
  DERP runner implements it, and the tests drive fakes. Liveness is `until_silent` over a `Heard`
  trait, which the DERP client implements with a count of pongs and the time of the last frame.
- A link that answered no ping is never declared dead: a relay that does not answer DERP pings
  would otherwise be dropped each 30 s.
- With a pin, one runner serves each region: the relay closes the older of two sockets with one
  key (`crates/podssh-ts/src/classify.rs:3-6`), so a runner for each region would replace the
  others' sockets for as long as their regions were active. The runner is the lowest region of
  the map, kept up as home is.
- The control runner retries its dial itself, in its start: the runtime waits for it in its own
  start and handles no restart until then, so a control server that could not be reached at start
  was dialled once and never again. After the start, a drop stops it, and the supervisor restarts it
  with no limit, each start waiting out its backoff first.
- The changes of the links go to a broadcast channel that the caller may hand the fork in its
  `Config`, so `podssh ts` hears those of a slow start too. A first connection writes no line:
  each run has one. A reason from the network is made safe for the terminal.
- The typed close of T-105's first step is done here, as the refusal rule needs it: `WsIo` puts a
  `WsClose { code, reason }` in its `io::Error`, and `ts_derp::Error::ws_close` finds it. The text of
  the error is the one that it always had. Matching the text lost: a relay's reason could hold it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh run -- 'sh /work/scripts/ts-derp-prove.sh'
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
```

A new step of the script runs the fork test vendor/tailscale-rs/ts_runtime/tests/reconnect.rs. It
drives the loop with fakes under `tokio::time::pause()`: `a_dropped_link_is_dialled_again_with_backoff`,
`a_1008_not_authorized_is_not_retried_by_default`, `a_silent_link_is_dead_after_three_checks` and
`a_non_home_inactivity_close_waits_for_activity`. Plant: end the loop on the first error again; the
first test must fail. The live drop test is part of T-106.

## Correction

2026-10-10 (found in T-276): the Prove names a step of `scripts/ts-derp-prove.sh` for the fork's
test `reconnect`, and this entry's commit did not add it; T-276 did, with the test `ping`.

2026-10-10: the control connection was not even restarted five times at start. A failed start of
the control runner reaches its supervisor, the runtime, as a link that died, but the runtime is then
still in its own start, waiting for that runner, and handles no signal until it ends: measured
through `scripts/fake-proxy.py`, one dial to the control server in 40 s. Step 5 covers it: the
runner dials again in its start.

## Done

2026-10-10, in the commit that closes this entry. Patch `vendor/patches/0019-reconnect.patch`,
with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`: `ts_runtime::reconnect`
(`vendor/tailscale-rs/ts_runtime/src/reconnect.rs`) keeps a link for ever with podssh's backoff,
from the first wait again after a link of 60 s, and returns only on a refusal that it does not
retry; `until_silent` declares a link dead after three silent pings, once it answered one. Each
DERP region's runner is a `Link` with that liveness, and with a pin one runner serves each region,
always home. The DERP client sends pings and counts the pongs, which ended the connection before.
The control runner dials again with the backoff, in its start and after each drop, with no limit of
restarts. The links' changes go to a broadcast channel (`Device::link_events`, or the caller's in
`Config::link_events`); `podssh ts` hands its own and writes a line for each drop, each return and
a refusal (`crates/podssh-cli/src/ts/links.rs`), and `--ts-wait-allowlist` retries a refusal.
`docs/tailscale.md`, the manual and `docs/STATUS.md` say so.
- Native, Windows 11: the fork's `cargo test --manifest-path vendor/tailscale-rs/Cargo.toml -p
  ts_runtime --test reconnect`, 7 passed: the four tests of the Prove, the cap of the wait and its
  start again after a link of 61 s, the relay's close 1008 "not authorized" as a refusal, and a far
  end that never answered a ping, not declared dead. Planted, the loop ending at the first error:
  four of them fail, the first among them. The same file runs in podssh's workspace from
  `crates/podssh-ts/tests/reconnect.rs`, 7 passed. `-p ts_derp --test ping`, against a stand-in
  DERP server: the pong of a ping is counted and the link outlives it; planted, no arm for the
  pong: it fails. A unit test in `ts_derp` keeps a close's code, reason and text. The fork's
  suites of `ts_runtime`, `ts_derp`, `ts_http_util`, `ts_control` and `tailscale`: 58 passed.
  `cargo test -p podssh-cli --features ts --test ts_links`, 3 passed. `cargo test -p podssh-ts -p
  podssh-cli --features podssh-cli/ts --no-fail-fast`: 486 passed, 0 failed, 25
  ignored. `cargo test --workspace --no-fail-fast`: 1213 passed, 0 failed, 39
  ignored. clippy with `-D warnings` on podssh's crates: no warning; the fork's own clippy finds no
  new kind of warning, and its old ones are T-276. The nineteen patches give the vendored tree byte
  for byte on all 41 touched paths.
- Live, this machine, through `scripts/fake-proxy.py` as `HTTPS_PROXY`, which let only the relay
  through: the control server was dialled again after 1.3 s, 2.1 s, 5.4 s and 6.1 s, and `podssh
  ts` said each drop; before, once in 40 s, and nothing said.
- Waits for T-251: `scripts/ts-derp-prove.sh` in the build image. Waits for T-106, the relay's
  operator: the live drop test with two nodes.

# T-105: The fork shows the relay's `1008 not authorized` as a missing network map

**Source:** `docs/tailscale.md`, lines 12-14 at `d345b14` ("Repair this first"), and the comment at
`crates/podssh-cli/src/ts.rs`, lines 332-335 at `d345b14` (measured on 2026-10-07). Read here on `3ee70dc` in the fork.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

When the relay refuses a node key with `1008 "not authorized"`, nothing in `podssh ts` says so. The
refusal ends as a log line of the fork, and podssh shows no log of the fork. The user sees "no
netmap yet" or a hang, not the one fact that tells what to do: the key must go into the relay's
allowlist. The exit is 78, not the 77 that `podssh ts` gives for a refused key.

## Premise

Read, at `d345b14` for the code that T-104 and this entry changed: the transport turns a close
into an `io::Error` with the text
`websocket closed: code=1008 reason="not authorized"` (`vendor/tailscale-rs/ts_derp/src/ws.rs:224-237`),
and the handshake returns it (`vendor/tailscale-rs/ts_derp/src/client.rs:211-216`). The runner
passes it up (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs`, lines 248-254 at `a3c196e`), and `start_runner`
gives it to `tracing::error!` only (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs`, lines 72-76 at `a3c196e`).
No podssh crate installs a `tracing` subscriber, so the line goes nowhere. `classify_1008` and the
exit 77 exist (`crates/podssh-ts/src/classify.rs:17-25`, `crates/podssh-cli/src/ts.rs` lines 314-326), but
they see only the error texts of `Device` calls.

Correction (2026-10-10): the exit 77 lives in `crates/podssh-cli/src/ts/exits.rs` now, moved out of
`crates/podssh-cli/src/ts.rs` by this entry.

Read: the symptom is not always a missing map. The status line needs the home region of the self
node (`crates/podssh-ts/src/node.rs:140-147`). Control sets it from the region that the node prefers
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:363-376`), which comes from HTTPS latency
checks of the stock DERP map (`vendor/tailscale-rs/ts_runtime/src/derp_latency.rs:37-58`), not from
the relay. So a refused node can still print a status line and exit 0. This widens the defect.

## Approach

1. In `ts_derp`, `WsIo` puts a typed `WsClose { code, reason }` inside its `io::Error`
   (`vendor/tailscale-rs/ts_derp/src/ws.rs:224-237`), and `ts_derp::Error` gets a method that
   returns it. The frame codec does not change.
2. In `ts_runtime`, keep the newest DERP state of each region (connected, refused or failed), set
   in `start_runner` and later in the loop of T-104. `Device::derp_state()` returns it with no wait,
   forwarded as `SelfNode` is (`vendor/tailscale-rs/src/lib.rs:323-330`).
3. In podssh-ts, add `NodeError::DerpRefused { code, reason }`. `status()` and `-W` read the state
   first, and `relay` mode prints a status line only with a connected home region.
4. In podssh-cli, map it through `classify_1008` to exit 77 (`crates/podssh-cli/src/ts.rs`, lines 314-326 at `d345b14`),
   and remove the old comment at `crates/podssh-cli/src/ts.rs`, lines 332-335 at `d345b14`.
5. Add the patch and its row, and update `docs/tailscale.md`, lines 12-14 at `d345b14` and `docs/STATUS.md:311`.

Added by T-104 (2026-10-10): step 1 is done, in patch 0019: `WsIo` puts a typed `WsClose { code,
reason }` in its `io::Error`, and `ts_derp::Error::ws_close` finds it, with a unit test of the close
in `vendor/tailscale-rs/ts_derp/src/ws.rs`. The node's link changes (`Device::link_events`) already
carry a refusal, `LinkChange::Refused`, which `podssh ts` writes on stderr: the state of step 2 can
come from them.

## Decision

Decided in the work (2026-10-10):
- The newest state of each link is a shared map that the runtime writes as each change comes,
  and that `Device::link_states` reads with no message. A message forwarded as `SelfNode` is lost:
  `SelfNode` waits for the network map, and a refusal must not.
- In `relay` mode the relay is the node's only DERP link (T-104), so "a connected home region" is
  that link: the status line and `-W` wait for it within the window of the network map, and a
  refusal ends the wait at once. In `tcp` mode a DERP link that is down does not stop the start:
  UDP may carry the node; a refusal is 77 there too.
- Under `--ts-wait-allowlist` a refusal is dialled again (T-104), and a link whose last failure was
  a refusal at the end of the wait is 77, not 78.
- `ts_derp::ws::WsIo` takes its stream as a type parameter, TLS over TCP by default, so the test
  of the close runs through a real WebSocket over an in-memory pipe.
- The message of a missing network map no longer guesses at the allowlist: a refusal is said apart.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh run -- 'sh /work/scripts/ts-derp-prove.sh'
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
```

The fork test vendor/tailscale-rs/ts_derp/tests/ws_close.rs checks that a close 1008 keeps its code
and reason through `ts_derp::Error`. A runtime test with a fake connect that returns it expects the
state "refused", and a podssh-ts test maps that state to exit 77. Plant: keep only the text; the
first test must fail. The live step M3 (`scripts/ts-derp-prove.sh:120-123`) must still see the
refusal. Live, with a `ts` build: an ephemeral node with a new state file exits 77 and names 1008.

## Done

2026-10-10, in the commit that closes this entry. Patch `vendor/patches/0021-link-states.patch`,
with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`: the runtime keeps the newest state of each
link (`reconnect::LinkStates`: connected, failed, refused), set at each change, and
`Device::link_states` reads it with no wait; a drop says whether it was a refusal dialled again.
`WsIo` is generic over its stream. podssh-ts: `derp_verdict` and `TsNode::derp_ready_within`
(`crates/podssh-ts/src/node.rs`) give `NodeError::DerpRefused` and, in `relay` mode,
`NodeError::DerpPending`; `podssh ts` waits for the relay's link before the status line and `-W`,
and maps a refused key to 77 with what it needs (`crates/podssh-cli/src/ts/exits.rs`). The old
comment of `no_map` is gone. `docs/tailscale.md`, the manual and `docs/STATUS.md` say so, and
`scripts/ts-derp-prove.sh` runs `ws_close`.
- Native, Windows 11: the fork's `cargo test --manifest-path vendor/tailscale-rs/Cargo.toml -p
  ts_derp --test ws_close`, 1 passed: a WebSocket server over a pipe closes 1008 "not authorized",
  and `ts_derp::Error::ws_close` gives the code and the reason, with the old text; planted, the close
  as text only: it fails. `-p ts_runtime --test reconnect`, 8 passed, with
  `a_refusal_leaves_the_link_refused_and_a_retried_one_failed`. `cargo test -p podssh-ts --test
  derp_state`, 3 passed; planted, the refusal ignored: it fails. `cargo test -p podssh-cli --features
  ts --test ts_exits`, 3 passed; planted, each close read as another session: it fails. The fork's
  suites of the touched crates: 60 passed, and its clippy with `-D warnings`: no warning.
  `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast`: 493
  passed, 0 failed, 25 ignored. `cargo test --workspace --no-fail-fast`: 1217
  passed, 0 failed, 39 ignored. clippy with `-D warnings`: no warning. The twenty-one
  patches give the vendored tree byte for byte on all 42 touched paths.
- Live, this machine: the fork's example `ws_handshake` (step M3): the relay refused a fresh key
  with 1008 "not authorized", and without the subprotocol the upgrade with HTTP 426.
- Waits for T-251: `scripts/ts-derp-prove.sh` in the build image. Waits for T-251 and Q40: the live
  run, an ephemeral node with a new state file that exits 77 and names 1008.

# T-106: The live test of `podssh ts` with two nodes

**Source:** `docs/ROADMAP.md:247-250` ("then the tests with two nodes"), `docs/tailscale.md:22`.
Read here on `3ee70dc`.
**Category:** measurement
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

No test has shown two `podssh ts` nodes that exchange bytes. The only live test is ignored, and it
can never pass: each run makes a new state file, so the node key is new and not in the relay's
allowlist. Until a test with two nodes passes, nobody knows if `relay` mode works, from a normal
host or from a sandbox.

## Premise

Read: the ignored test makes a new state file in the temporary directory and removes it
(`crates/podssh-cli/tests/ts_behave.rs:228-255`); a new state file is a new node key
(`docs/tailscale.md:76-77`). Its reason still names M5. On 2026-10-07, registration worked, no map
came in 60 s, and only the operator can add a node key to the allowlist (`docs/tailscale.md:8-24`).

Read: `podssh ts` has no form that accepts a connection (`crates/podssh-cli/src/ts.rs:246-250`), but
the fork can listen in its own network stack, with no socket of the host
(`vendor/tailscale-rs/src/lib.rs:296-305`). The fork's echo example takes the auth key on the
command line (`vendor/tailscale-rs/examples/tcp_echo/main.rs:24-28`), which podssh must not do. With
the pin, each region's runner dials the relay
(`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:333-340`), so two `relay` nodes meet there.
Not measured: whether the proxy of a sandbox allows `tcp.ts.relay.ajam.dev:443` (`docs/tailscale.md:78-79`).

## Approach

1. Start after T-103, T-104 and T-105 (`docs/ROADMAP.md:247-250`).
2. Make two state files once, outside the repository, and keep them. For the allowlist, print only
   the node key prefix of each (`crates/podssh-ts/src/status.rs:7-22`).
3. Node A: a new example, crates/podssh-ts/examples/ts_echo.rs, in `relay` mode: an echo on the
   tailnet stack, with the auth key from a file. Node B: the real binary, `podssh ts -W A:PORT`,
   sends 1 MiB; the SHA-256 both ways must be equal. Run B from a normal host, and from the box of
   `scripts/test_in_box.sh`, whose only egress is a CONNECT proxy.
4. Drop test (T-104): stop `scripts/fake-proxy.py` during a pipe of 5 min, and start it again on the
   same port. The pipe must go on, and stderr must show the drop and the new connection.
5. Repair the ignored test: the key and state paths come from variables that only the test reads,
   and the state stays. Name M8 in its reason.
6. Record each result with its date in `docs/STATUS.md:64`, `docs/tailscale.md:8-24` and
   `crates/podssh-cli/src/man/notes.rs:314-339`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --features ts --test ts_two_nodes -- --ignored --nocapture
cargo test -p podssh-cli --features ts --test ts_behave -- --ignored ts_live_status_prints_the_node_line
sh scripts/ts-two-nodes.sh path/to/podssh-ts-x86_64-unknown-linux-musl
```

The new test crates/podssh-cli/tests/ts_two_nodes.rs runs node A in the process and the real binary
(`CARGO_BIN_EXE_podssh`) as node B, and compares the SHA-256 of 1 MiB both ways. The second command
is the repaired status test. The new script scripts/ts-two-nodes.sh runs node B in the box, with a
static binary built with `--features ts`. Each command must exit 0 with the two kept state files.

## Blocker

The relay's operator: the node keys of the two kept state files on the relay's allowlist, with a
Tailscale admin token and the relay's deployment credential that only the operator has
(`docs/tailscale.md:20-21`). T-103, T-104 and T-105 are done first. Sessions skip this entry until
then (the operator's ruling of 2026-10-08).

# T-240: `podssh ts --jsonl` writes no JSON

**Source:** found while T-100 to T-106 were written (finding 1). Measured here on `3ee70dc` with
the default binary.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh ts` lists `--jsonl` as "one JSON object per event on stdout", but it never writes JSON. The
flag only makes the run non-interactive, so `--timeout` becomes required. A script that asks for
JSON gets the plain status line, or the raw stream of `-W`. With `-W`, stdout is the stream, so a
JSON line there would break it.

## Premise

Measured: `podssh ts --help` exits 0 and lists `--jsonl` as "one JSON object per event on stdout".
The command `podssh ts -W peer.invalid:22 --jsonl --timeout 5s </dev/null` exits 70 in the default
build ("'ts' is not available in this build"), so the parser accepts the flag. The command
`podssh proxy --jsonl example.invalid 22 </dev/null` exits 64: "--jsonl is refused in ProxyCommand
mode."

Read: the row is at `crates/podssh-cli/src/flags.rs`, lines 293-294 at `efee2fc`. `podssh ts` reads the flag once, in
`resolve_tty` (`crates/podssh-cli/src/ts.rs`, line 48 at `efee2fc`), which only makes the run non-interactive
(`crates/podssh-cli/src/non_interactive.rs`, lines 61-76 at `efee2fc`). The status form writes plain text
(`crates/podssh-cli/src/ts.rs`, lines 314-316 at `efee2fc`, `crates/podssh-ts/src/status.rs:17-21`), and `-W` writes the
stream (`crates/podssh-cli/src/ts.rs`, lines 391-393 at `efee2fc`). `proxy --jsonl` is refused at parse, with the reason
(`crates/podssh-cli/src/tree.rs`, lines 179-187 at `efee2fc`, `crates/podssh-cli/src/non_interactive.rs`, lines 309-320 at `efee2fc`).
`serde_json` is already a dependency of the binary (`crates/podssh-cli/Cargo.toml:53`).

## Approach

1. Refuse `--jsonl` with `-W` at parse, with exit 64 and the reason, next to the `proxy` refusal
   (`crates/podssh-cli/src/tree.rs`, lines 179-187 at `efee2fc`): stdout carries the stream. Refuse `--jsonl=` too.
2. In the status form, write the status as one JSON object on one line, with `serde_json`:
   `{"event":"status","nodekey_prefix":...,"tailnet_ip":...,"home_region":...}`. Never the key.
3. Keep errors on stderr as text; the exit code stays the result. T-104 and T-105 add events (a
   drop, a new connection, a refusal) to this form when their states exist.
4. Change the help text of the row (`crates/podssh-cli/src/flags.rs`, lines 293-294 at `efee2fc`) and the notes of the
   manual (`crates/podssh-cli/src/man/notes.rs`, lines 353-355 at `efee2fc`) in the same commit. The tests of the manual
   compare the row with the help.

## Decision

Recommendation: refuse the flag with `-W`, and write JSON in the status form. The status line is
the one event of that form today, so the change is small, and scripts get what the help promises.
The alternative, refuse `--jsonl` in each form until a stream of events exists, lost because the
status form has a result to give now.

2026-10-10, in the work: `-W` is any argument that starts with `-W`, so `-W HOST:PORT` and
`-WHOST:PORT` are both refused with `--jsonl`, in either order. The JSON is made in podssh-cli with
`serde_json`, from `StatusFacts`, which has no field for a key.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ts_parse -- jsonl
cargo test -p podssh-cli --no-fail-fast
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
timeout 20 target/debug/podssh ts -W peer.invalid:22 --jsonl --timeout 5s </dev/null; echo "exit=$?"
```

New tests: `ts_w_with_jsonl_is_refused_at_parse` in `crates/podssh-cli/tests/ts_parse.rs`, and a
test of the JSON status object (one line, the three facts, no other text) in
`crates/podssh-cli/tests/ts_behave.rs`. Plant: remove the refusal; the parse test must fail. The
second command runs the tests of the manual in the default build. The last command uses the
default binary, before anything connects: it must print the refusal and `exit=64`.

## Done

2026-10-10. `podssh ts -W ... --jsonl` (and `--jsonl=`) is refused at parse with 64 and the reason,
next to the refusal under `proxy` (`crates/podssh-cli/src/tree.rs`,
`crates/podssh-cli/src/non_interactive.rs`). The status form with `--jsonl` writes one JSON object
on one line: `{"event":"status","nodekey_prefix":...,"tailnet_ip":...,"home_region":...}`
(`status_json` in `crates/podssh-cli/src/ts.rs`); errors stay text on stderr. The help row and
the manual's note say so (`crates/podssh-cli/src/flags.rs`, `crates/podssh-cli/src/man/notes.rs`).
- Native, Windows 11: `cargo test -p podssh-cli --test ts_parse`, 6 passed, with the new
  `ts_w_with_jsonl_is_refused_at_parse` (five spellings, and the status form that takes the flag);
  `the_jsonl_status_is_one_json_object_of_the_three_facts` in `ts_behave.rs` (one line, four keys).
  Planted, the refusal removed: the parse test fails. The default binary:
  `timeout 20 target/debug/podssh ts -W peer.invalid:22 --jsonl --timeout 5s </dev/null` printed
  the refusal, `exit=64`. `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts
  --no-fail-fast`: 432 passed, 0 failed, 24 ignored. clippy with no warning.
  `cargo test --workspace`: 1144 passed, 0 failed, 38 ignored, the tests of the manual
  with them.

# T-241: The tailnet auth key is not cleared from memory

**Source:** found while T-100 to T-106 were written (finding 2). Read here on `3ee70dc`.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh ts` reads the tailnet auth key from a file and keeps copies of it in plain buffers. When a
buffer is freed, the key stays in memory, where a core dump or a swap page can keep it. The relay
token and the passphrases of podssh are cleared when they are dropped; the auth key is not. The
fork also keeps its own copy for the whole session.

## Premise

Read: `AuthKey` holds a plain `Vec<u8>` and has no `Drop` (`crates/podssh-ts/src/secret.rs`, lines 9-41 at `160773e`).
`expire` writes zeros in a plain loop and then clears the vector
(`crates/podssh-ts/src/secret.rs`, lines 33-40 at `160773e`); only a test calls it (`crates/podssh-ts/tests/secret.rs:18-24`).
Known from the documentation of the `zeroize` crate, not verified here: a compiler can remove such
writes, because nothing reads the bytes after them.

Read: `podssh ts` reads the file into a plain buffer and trims it into a second copy
(`crates/podssh-cli/src/ts.rs`, lines 164-171 at `160773e`, `crates/podssh-cli/src/ts.rs`, lines 255-261 at `160773e`). `TsNode::start` makes
a third copy, a `String` that goes to the fork (`crates/podssh-ts/src/node.rs`, lines 54-55 at `160773e`,
`crates/podssh-ts/src/node.rs`, line 67 at `160773e`). The fork keeps it in its configuration and in the parameters of
its control runner, for each registration (`vendor/tailscale-rs/ts_runtime/src/lib.rs`, line 54 at `160773e`,
`vendor/tailscale-rs/ts_runtime/src/control_runner.rs`, line 54 at `160773e`, `vendor/tailscale-rs/ts_runtime/src/control_runner.rs`, line 108 at `160773e`).

Read: the relay token is a `Zeroizing<String>` (`crates/podssh-relay/src/token.rs:29`), and
`zeroize` is a workspace dependency (`Cargo.toml:163`), but podssh-ts does not use it
(`crates/podssh-ts/Cargo.toml`, lines 10-14 at `160773e`). The fork already depends on it
(`vendor/tailscale-rs/Cargo.toml:106`). The comment at `crates/podssh-ts/src/secret.rs`, lines 3-5 at `160773e` names a
model file that no longer exists.

## Approach

1. Add `zeroize` from the workspace to `crates/podssh-ts/Cargo.toml`, lines 10-14 at `160773e`. Hold the bytes in
   `Zeroizing<Vec<u8>>`, give `AuthKey` a `Drop` that clears them, and mark it `ZeroizeOnDrop`.
   `expire` calls `zeroize()`.
2. In `crates/podssh-cli/src/ts.rs`, lines 164-171 at `160773e`, read the file into `Zeroizing<Vec<u8>>`, and trim it
   in place, not into a copy (`crates/podssh-cli/src/ts.rs`, lines 255-261 at `160773e`).
3. In `TsNode::start`, make the fork's `String` from the bytes with no other copy
   (`crates/podssh-ts/src/node.rs`, lines 54-55 at `160773e`). Expire podssh's key when the start returns
   (`crates/podssh-cli/src/ts.rs`, lines 213-227 at `160773e`), because podssh no longer needs it.
4. In the fork, hold the key as `Zeroizing<String>` in `Config` and in `Params`, as a new patch
   with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`.
5. Correct the comment at `crates/podssh-ts/src/secret.rs`, lines 3-5 at `160773e`, and name the tailnet key in the
   rule at `SECURITY.md`, lines 53-56 at `160773e`, in the same commit.

Pitfall: `Device::new` takes the key by value (`crates/podssh-ts/src/node.rs`, line 67 at `160773e`), so only the fork
can clear its copy (step 4).

## Decision

2026-10-10, in the work:
- `AuthKey::new` takes `impl Into<Zeroizing<Vec<u8>>>`: a buffer that clears itself goes in with
  no copy, and a plain `Vec<u8>` still does. The trim works in place on that buffer.
- The fork keeps the public signature `Device::new(&Config, Option<String>)`, and moves the
  `String` into its `Zeroizing<String>` with no copy: its examples and its tests stay as they are.
- A key that is not UTF-8 gives back its bytes in the error; they are cleared before the error
  is returned. `std::fs::read` allocates its buffer for the file's size, and its own growth is
  not under podssh's control: one buffer, which the `Zeroizing` clears.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ts --test secret
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
```

A new test in `crates/podssh-ts/tests/secret.rs`, `the_key_is_cleared_on_drop`, requires
`AuthKey: zeroize::ZeroizeOnDrop`. Plant: remove the marker or the `Drop`; the test then fails to
build. `expire_zeros_and_locks` (`crates/podssh-ts/tests/secret.rs:18-24`) must still pass. The
second command builds the fork with the new patch. A test that reads freed memory is not sound, so
the rest of the proof is the type and a review of each copy that Premise names.

## Correction

2026-10-10: the fork's record of its patches named the user of the machine that measured it
(`vendor/tailscale-rs/LOCAL-PATCHES.md`, which `scripts/check-repo.py` does not read, as it skips
`vendor/`); `AGENTS.md` (section 4) forbids it, so the name is gone in this commit. Its old
measurement also holds only outside podssh's repository: `git apply` inside it reads each patch's
path from the repository's root and skips it, with exit 0.

## Done

2026-10-10. The tailnet auth key is held in `Zeroizing<Vec<u8>>` (`AuthKey`, which is
`ZeroizeOnDrop` and clears its bytes in `expire` and on drop: `crates/podssh-ts/src/secret.rs`).
`podssh ts` reads the file into such a buffer, trims it in place, and expires its key as soon as
the start returns (`crates/podssh-cli/src/ts.rs`); `TsNode::start` makes the one copy that the
fork takes, and clears it if it is not UTF-8 (`crates/podssh-ts/src/node.rs`). The fork holds the
key in `Zeroizing<String>` in `ts_runtime::Config` and in its control runner's `Params`, patch
`vendor/patches/0015-zeroize-auth-key.patch` with its row in
`vendor/tailscale-rs/LOCAL-PATCHES.md`. `SECURITY.md` names the tailnet key in the rule of
credentials.
- Native, Windows 11: `cargo test -p podssh-ts --test secret`, 4 passed, with the new
  `the_key_is_cleared_on_drop`; `expire_zeros_and_locks` passes. Planted, the `ZeroizeOnDrop`
  marker removed: the test does not build (`AuthKey: ZeroizeOnDrop` is not satisfied). The chain
  of the fork's fifteen patches applies to an export of pristine `f4781c4` and gives the vendored
  tree byte for byte on all 29 touched paths. `cargo test -p podssh-ts -p podssh-cli --features
  podssh-cli/ts --no-fail-fast`: 433 passed, 0 failed, 24 ignored. clippy with no
  warning. `cargo test --workspace`: 1145 passed, 0 failed, 38 ignored.
- The rest of the proof is the types and a review of each copy that the premise names: the
  file's buffer and its trim (cleared), podssh's `AuthKey` (expired at the start's return, cleared
  on drop), the one `String` for the fork (moved into `Zeroizing`), and the fork's copies in
  `Config` and `Params` (cleared on drop). A test that reads freed memory would not be sound.

