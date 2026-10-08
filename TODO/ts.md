This file holds the work on `podssh ts`: the command in `crates/podssh-cli/src/ts.rs`, the adapter
crate crates/podssh-ts/, and the fork vendor/tailscale-rs with its patches in vendor/patches/
(`vendor/tailscale-rs/LOCAL-PATCHES.md`). It has the rows C2, C3 and C9 of the former defects page
(`git show 3ee70dc:docs/defects.md`) and the Tailscale item of M8 (`docs/ROADMAP.md:240-243`). All
of it is behind the cargo feature `ts`: the default binary refuses `podssh ts` with exit 70. The
fork builds aws-lc and uses much memory, so run one build at a time with `CARGO_BUILD_JOBS=4`
(`AGENTS.md`, section 4). The fork's own tests run in the build image through
`scripts/ts-derp-prove.sh:82-100`.

# T-100: C2: `podssh ts` waits for ever when no network map arrives

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row C2 (high). Confirmed
here on `3ee70dc` by reading the command and the fork.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`--timeout` limits the start of the node and the TCP connect, but not the status query or the peer
lookup. Both wait inside the fork until the control server sends the first network map. When no
map arrives, `podssh ts` and `podssh ts -W PEER:PORT` wait for ever, also in a script that gave
`--timeout`. `--ts-wait-allowlist` does not help: its loop runs only after the query returns.

## Premise

Measured: `podssh ts --timeout 5s </dev/null` exits 70 ("'ts' is not available in this build"), so
the rest is read. `bound` wraps only `TsNode::start` and `tcp_connect`
(`crates/podssh-cli/src/ts.rs:213-227`, `crates/podssh-cli/src/ts.rs:365-376`), not `node.status()`
or `node.peer_ip()` (`crates/podssh-cli/src/ts.rs:295`, `crates/podssh-cli/src/ts.rs:356`). The
module comment says that the bound caps the whole operation (`crates/podssh-cli/src/ts.rs:9-14`),
and `docs/cli.md:165-167` makes that a rule.

Read: `status()` calls `Device::self_node()` (`crates/podssh-ts/src/node.rs:81-84`), whose reply
waits in a queue until a map with the self node arrives
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:208-225`,
`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:445-459`). `peer_ip()` waits for the first
peer update (`vendor/tailscale-rs/ts_runtime/src/peer_tracker/mod.rs:74-98`), against its comment
"never a hang" (`crates/podssh-ts/src/node.rs:98-100`). The wait loop handles only `NetmapPending`,
a self node with no home region (`crates/podssh-cli/src/ts.rs:294-327`).

## Approach

1. Make one deadline from `--timeout` at the start of `ts_async` (`crates/podssh-cli/src/ts.rs:76-82`),
   and give each later wait only the time that remains.
2. Add `TsNode::status_within(limit)` and `TsNode::peer_ip_within(limit)`: the fork call inside
   `tokio::time::timeout`, and `NodeError::NetmapPending` when the limit passes. A dropped query
   leaves its reply sender queued (`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:218-222`);
   a later send must not panic.
3. With no `--timeout` (a terminal), limit the first map wait by `--ts-wait-allowlist`, else by a
   named constant of 20 s, "a design constant, not a measurement", as at
   `crates/podssh-cli/src/ts.rs:305-308`. The default stays fail-fast (`docs/decisions.md:39`).
4. Apply the same limit to the address wait in `Device::tcp_connect`
   (`vendor/tailscale-rs/src/lib.rs:272-276`). Keep one message and exit 78 for "no map in time".
5. Correct the two comments, and update `docs/STATUS.md:186` in the same commit.

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
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:79-89`). The second command is the feature
suite (226 passed, `docs/STATUS.md:200`). The third is live, with a `ts` build, while no map comes
(`docs/tailscale.md:10-11`): it must print `exit=78` after about 20 s, not `exit=124`.

# T-101: C3: a local end of input cuts the reply in the `podssh-ts` pipe

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row C3 (high). Confirmed
here on `3ee70dc` by reading the pipe and its tests.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`podssh ts -W HOST:PORT` copies stdin to the stream and the stream to stdout. When stdin ends
first, the pipe returns at once, and a reply that the peer sends after that is lost. A request on
stdin, such as an HTTP `GET`, thus gets no answer on stdout. A closed stdout also ends the pipe
with exit 70, not as a clean end.

## Premise

Read: `pipe_streams` races the two directions and returns when the first ends; on the local end it
reports `down: None` (`crates/podssh-ts/src/pipe.rs:65-100`). Its comment calls this the behaviour
of an OpenSSH `ProxyCommand` (`crates/podssh-ts/src/pipe.rs:54-64`). The test
`local_eof_first_cuts_the_down_leg` asserts it, and checks nothing about the remote's bytes
(`crates/podssh-ts/tests/pipe.rs:62-95`). The next test accepts the same
(`crates/podssh-ts/tests/pipe.rs:97-122`).

Read: `podssh proxy` keeps receiving after the end of stdin (`crates/podssh-cli/src/proxy.rs:159-175`),
and a closed stdout is a clean end there (`crates/podssh-cli/src/proxy.rs:231-234`) and in the rules
(`docs/cli.md:143`). `podssh ts -W` exits 70 on each copy error (`crates/podssh-cli/src/ts.rs:397-400`).
The relay closes a half-closed forward session after 15 s with no bytes from the target
(`docs/relay.md:126`). An earlier version of the pipe waited with no limit, and hung
(`crates/podssh-ts/src/pipe.rs:84-88`).

## Approach

1. On the end of stdin, shut down the write half of the stream, as today
   (`crates/podssh-ts/src/pipe.rs:76-80`), and keep copying the stream to stdout.
2. End the pipe when the stream ends, when stdout closes, or after 15 s with no bytes from the
   stream. Name the 15 s as a constant: the value of the relay's rule.
3. Report exact counts in both directions (`crates/podssh-ts/src/pipe.rs:37-52`). A closed stdout is
   a clean end with exit 0 (`crates/podssh-cli/src/ts.rs:384-401`).
4. Rewrite the two tests, and update `docs/STATUS.md:190` in the same commit.

## Decision

Recommendation: keep reading after the end of stdin, with an idle limit of 15 s, as `podssh proxy`
and the relay's forward road do. The alternative, no limit, lost because a peer that never closes
then holds the pipe for ever, which was measured. `ssh` stops its `ProxyCommand` at the end of a
session, so the limit matters only for scripts.

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

# T-102: C9: the automatic mode always selects tcp, and ephemeral nodes are not logged out

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row C9 (medium). Confirmed
here on `3ee70dc` by reading the adapter and the fork.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

With `--ts-mode auto`, `podssh ts` always takes `tcp`, because each probe only checks that a key
file was given. On a host that cannot reach the stock DERP servers, it never falls through to
`relay`. With `--ts-ephemeral`, the node registers as ephemeral, but podssh never logs it out, so
the tailnet keeps an offline device until the control server removes it.

## Premise

Read: `probe` returns `Ok` for `Tcp` and `Relay` when `has_key` is true
(`crates/podssh-ts/src/chain.rs:44-61`), which `podssh ts` always sets
(`crates/podssh-cli/src/ts.rs:129-133`). The first ready mode of `tcp`, `relay` wins
(`crates/podssh-ts/src/chain.rs:63-76`), and a test asserts it (`crates/podssh-ts/tests/chain.rs:32-37`).
The decided chain is tun, socks, tcp, relay (`docs/decisions.md:39`), and the rule is to probe
before use (`docs/target-environment.md:90-92`).

Read: `ephemeral` goes into the register request (`crates/podssh-ts/src/node.rs:66`). The fork has
no logout: `Device::shutdown` only stops the actors (`vendor/tailscale-rs/src/lib.rs:325-355`), and
`podssh ts` never calls `TsNode::shutdown` (`crates/podssh-ts/src/node.rs:110-113`). The fork's own
type says that a register request with an expiry in the past expires the current node key
(`vendor/tailscale-rs/ts_control_serde/src/register.rs:92-97`).

## Approach

1. Probe each mode before `TsNode::start`, through the proxy of T-103, in 8 s per step as
   `podssh doctor` does (`crates/podssh-cli/src/doctor/net.rs:12-13`): for `tcp`, a TLS handshake to
   a stock DERP server on port 443; for `relay`, one to the relay host. Dial with
   `crates/podssh-ws/src/dial.rs:204-212`. `Unknown` is never ready (`crates/podssh-ts/src/chain.rs:13-22`).
2. Add a logout to the fork: a register request with an expiry in the past, a `ControlRunner`
   message and `Device::logout(timeout)`, as a new patch with its row in
   `vendor/tailscale-rs/LOCAL-PATCHES.md`.
3. `TsNode::shutdown` logs out first when the node is ephemeral, in 5 s at most. `podssh ts` calls
   it at the end of each form, also after an error (`crates/podssh-cli/src/ts.rs:228-235`). Never
   log out a node that is not ephemeral: its allowlist entry is lost (`docs/tailscale.md:23-24`).
4. Update `docs/tailscale.md` and `docs/STATUS.md:190` in the same commit.

## Decision

Recommendation: probe before the start, because the chain falls through only before a dial
(`crates/podssh-ts/src/chain.rs:1-7`). Starting in `tcp` and again in `relay` lost: it registers
twice, and it waits for a failure that has no limit today. Take the DERP host from the default
DERP map through the proxy, as a fork test does (`vendor/tailscale-rs/ts_netcheck/src/derp_latency.rs:146`).

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

# T-103: The DERP dial of the Tailscale fork does not use the proxy

**Source:** `docs/ROADMAP.md:240-243` ("first repair its DERP dial, which does not use the proxy").
Confirmed here on `3ee70dc` by reading the fork and the command.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

In `relay` mode, the node dials the relay over a WebSocket. That dial goes straight out, with the
system resolver and no time limit, so on a host whose only egress is a CONNECT proxy the node never
reaches DERP. Also, `podssh ts` does not read `HTTPS_PROXY`: only `--ts-proxy` gives a proxy, unlike
each other podssh command, and a proxy password in `--ts-proxy` is on the command line.

## Premise

Read: `ws::connect_with_subprotocol` opens `TcpStream::connect((hostname, port))`
(`vendor/tailscale-rs/ts_derp/src/ws.rs:63-68`). The other three dial sites check the proxy first
(`vendor/tailscale-rs/ts_derp/src/dial.rs:191-204`, `vendor/tailscale-rs/ts_http_util/src/lib.rs:126-141`,
`vendor/tailscale-rs/ts_control/src/control_dialer.rs:82-86`), and the proxy module warns that a
fourth path that goes direct keeps the route that cannot work
(`vendor/tailscale-rs/ts_http_util/src/proxy.rs:9-12`). `relay` mode reaches `ws::connect` through
the pin (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:285-292`), and so does the
WebSocket mode with no pin (`vendor/tailscale-rs/ts_derp/src/client.rs:135-141`).

Read: `podssh ts` takes the proxy from `--ts-proxy` only (`crates/podssh-cli/src/ts.rs:198-211`),
against the manual (`crates/podssh-cli/src/man/facts.rs:46-50`), the rule at
`docs/target-environment.md:68-71` and `SECURITY.md:40-43`. A URL with no port means 80 in podssh
(`crates/podssh-ws/src/dial.rs:66`) but 8080 in the fork (`vendor/tailscale-rs/ts_http_util/src/proxy.rs:39-41`).
Not measured: whether the proxy of a sandbox allows `tcp.ts.relay.ajam.dev:443` (`docs/tailscale.md:25-26`).

## Approach

1. In the fork, write one function that opens TCP to a host name: through the proxy when one is
   set, else direct, in 20 s at most (`vendor/tailscale-rs/ts_http_util/src/proxy.rs:36-37`). Call
   it from `ws::connect_with_subprotocol` and from `dial_by_ipusage`, so one branch serves both.
2. Add it as a new patch with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`, replace the stale
   text at `vendor/README.md:62-75`, and check that the whole chain of patches still applies.
3. In `podssh ts`, take `--ts-proxy`, else `podssh_ws::dial::proxy_from_env`
   (`crates/podssh-ws/src/dial.rs:131-162`). Give the fork a URL with an explicit port, and never
   print its credentials. The fork has one proxy for each process
   (`vendor/tailscale-rs/ts_http_util/src/proxy.rs:105-120`), so apply `NO_PROXY` for each host in
   the new function.
4. Update `crates/podssh-cli/src/flags.rs:281-282`, `docs/tailscale.md:25-26` and
   `docs/STATUS.md:190` in the same commit.

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
the order of `crates/podssh-ws/src/dial.rs:153`. Live: with `HTTPS_PROXY` naming
`scripts/fake-proxy.py`, `podssh ts --ts-mode relay` must make its log list the relay host.

# T-104: `podssh ts` connects again after a drop

**Source:** `docs/ROADMAP.md:240-243` ("and its missing reconnection"). Read here on `3ee70dc` in
the fork, and in kameo 0.21.1, the fork's actor crate, in the local cargo registry.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

When the DERP connection of a region drops, the fork logs the error and never dials again, so the
node has no path to its peers and a `-W` pipe stalls with no message. A connection that dies with no
close is not even noticed: the client keeps no limit on the server's keepalives. The control
connection starts again at most five times in 5 s, and then stops for good.

## Premise

Read: `Runner::run` ends at the first error
(`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:248-254`), `start_runner` only logs it
(`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:72-76`), and the task then stops normally
(`vendor/tailscale-rs/ts_runtime/src/task.rs:80-85`). In kameo, a normal stop of a linked actor does
not stop its partner (`on_link_died` in `tqwewe/kameo:src/actor.rs`). So `Uniderp` stays with no
runner until a changed region (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:171-192`).
The client ignores the timing of `KeepAlive` frames (`vendor/tailscale-rs/ts_derp/src/client.rs:277-282`).

Read: `ControlRunner` stops when the map stream ends
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:409-412`), under the default supervision
(`vendor/tailscale-rs/ts_runtime/src/lib.rs:160-169`): five restarts in 5 s at most, with no wait
(`tqwewe/kameo:src/supervision.rs`). podssh's relay client has the rules to copy: a capped backoff
with jitter (`crates/podssh-relay/src/open.rs:263-277`), and a ping every 10 s with three silent
checks allowed (`crates/podssh-ws/src/client.rs:31-32`, `docs/relay.md:68-70`).

## Approach

1. Make the DERP runner a loop: connect, run, wait, and again
   (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:248-254`). The loop gets the connect
   and run steps as arguments, so a test drives it with no network.
2. Wait with podssh's backoff, passed in `RuntimeOptions`; count from 1 after a link of 60 s. With
   a pin, each region dials the relay with one key (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:285-292`):
   two sockets must not replace each other for ever (`crates/podssh-ts/src/classify.rs:3-6`).
3. Do not retry `1008 "not authorized"`, except under `--ts-wait-allowlist` (`docs/decisions.md:39`);
   it goes to the state of T-105. The inactivity close of a region that is not home is no error
   (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:351-356`).
4. Ping every 10 s; three silent intervals mean a dead link, after the relay answered one ping.
5. Restart `ControlRunner` with the same backoff and no count limit. podssh-cli prints one stderr
   line for each drop and each new connection. Add the patch and its row, and update
   `docs/tailscale.md`, `docs/STATUS.md:190` and `crates/podssh-cli/src/man/notes.rs:84-87`.

## Decision

Recommendation: connect again inside the fork's runner. The network stack keeps its TCP streams
over a short break, and only the runner knows the region and the key. A new `Device` from
podssh-cli after each drop lost, because it breaks each open stream and registers again.

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

# T-105: The fork shows the relay's `1008 not authorized` as a missing network map

**Source:** `docs/tailscale.md:12-14` ("Repair this first"), and the comment at
`crates/podssh-cli/src/ts.rs:312-316` (measured on 2026-10-07). Read here on `3ee70dc` in the fork.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

When the relay refuses a node key with `1008 "not authorized"`, nothing in `podssh ts` says so. The
refusal ends as a log line of the fork, and podssh shows no log of the fork. The user sees "no
netmap yet" or a hang, not the one fact that tells what to do: the key must go into the relay's
allowlist. The exit is 78, not the 77 that `podssh ts` gives for a refused key.

## Premise

Read: the transport turns a close into an `io::Error` with the text
`websocket closed: code=1008 reason="not authorized"` (`vendor/tailscale-rs/ts_derp/src/ws.rs:190-201`),
and the handshake returns it (`vendor/tailscale-rs/ts_derp/src/client.rs:205-210`). The runner
passes it up (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:248-254`), and `start_runner`
gives it to `tracing::error!` only (`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:72-76`).
No podssh crate installs a `tracing` subscriber, so the line goes nowhere. `classify_1008` and the
exit 77 exist (`crates/podssh-ts/src/classify.rs:17-25`, `crates/podssh-cli/src/ts.rs:269-281`), but
they see only the error texts of `Device` calls.

Read: the symptom is not always a missing map. The status line needs the home region of the self
node (`crates/podssh-ts/src/node.rs:81-88`). Control sets it from the region that the node prefers
(`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:276-289`), which comes from HTTPS latency
checks of the stock DERP map (`vendor/tailscale-rs/ts_runtime/src/derp_latency.rs:37-58`), not from
the relay. So a refused node can still print a status line and exit 0. This widens the defect.

## Approach

1. In `ts_derp`, `WsIo` puts a typed `WsClose { code, reason }` inside its `io::Error`
   (`vendor/tailscale-rs/ts_derp/src/ws.rs:190-201`), and `ts_derp::Error` gets a method that
   returns it. The frame codec does not change.
2. In `ts_runtime`, keep the newest DERP state of each region (connected, refused or failed), set
   in `start_runner` and later in the loop of T-104. `Device::derp_state()` returns it with no wait,
   forwarded as `SelfNode` is (`vendor/tailscale-rs/src/lib.rs:287-294`).
3. In podssh-ts, add `NodeError::DerpRefused { code, reason }`. `status()` and `-W` read the state
   first, and `relay` mode prints a status line only with a connected home region.
4. In podssh-cli, map it through `classify_1008` to exit 77 (`crates/podssh-cli/src/ts.rs:269-281`),
   and remove the old comment at `crates/podssh-cli/src/ts.rs:312-316`.
5. Add the patch and its row, and update `docs/tailscale.md:12-14` and `docs/STATUS.md:190`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh run -- 'sh /work/scripts/ts-derp-prove.sh'
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast
```

The fork test vendor/tailscale-rs/ts_derp/tests/ws_close.rs checks that a close 1008 keeps its code
and reason through `ts_derp::Error`. A runtime test with a fake connect that returns it expects the
state "refused", and a podssh-ts test maps that state to exit 77. Plant: keep only the text; the
first test must fail. The live step M3 (`scripts/ts-derp-prove.sh:89-92`) must still see the
refusal. Live, with a `ts` build: an ephemeral node with a new state file exits 77 and names 1008.

# T-106: The live test of `podssh ts` with two nodes

**Source:** `docs/ROADMAP.md:240-243` ("then the tests with two nodes"), `docs/tailscale.md:17`.
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
(`crates/podssh-cli/tests/ts_behave.rs:213-242`); a new state file is a new node key
(`docs/tailscale.md:23-24`). Its reason still names M5. On 2026-10-07, registration worked, no map
came in 60 s, and only the operator can add a node key to the allowlist (`docs/tailscale.md:8-19`).

Read: `podssh ts` has no form that accepts a connection (`crates/podssh-cli/src/ts.rs:232-235`), but
the fork can listen in its own network stack, with no socket of the host
(`vendor/tailscale-rs/src/lib.rs:260-269`). The fork's echo example takes the auth key on the
command line (`vendor/tailscale-rs/examples/tcp_echo/main.rs:24-28`), which podssh must not do. With
the pin, each region's runner dials the relay
(`vendor/tailscale-rs/ts_runtime/src/multiderp/uniderp.rs:285-292`), so two `relay` nodes meet there.
Not measured: whether the proxy of a sandbox allows `tcp.ts.relay.ajam.dev:443` (`docs/tailscale.md:25-26`).

## Approach

1. Start after T-103, T-104 and T-105 (`docs/ROADMAP.md:240-243`).
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
6. Record each result with its date in `docs/STATUS.md:52`, `docs/tailscale.md:8-19` and
   `crates/podssh-cli/src/man/notes.rs:84-87`.

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
(`docs/tailscale.md:15-16`). T-103, T-104 and T-105 are done first. Sessions skip this entry until
then (the operator's ruling of 2026-10-08).

# T-240: `podssh ts --jsonl` writes no JSON

**Source:** found while T-100 to T-106 were written (finding 1). Measured here on `3ee70dc` with
the default binary.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

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

Read: the row is at `crates/podssh-cli/src/flags.rs:295-296`. `podssh ts` reads the flag once, in
`resolve_tty` (`crates/podssh-cli/src/ts.rs:43`), which only makes the run non-interactive
(`crates/podssh-cli/src/non_interactive.rs:61-76`). The status form writes plain text
(`crates/podssh-cli/src/ts.rs:296-298`, `crates/podssh-ts/src/status.rs:17-21`), and `-W` writes the
stream (`crates/podssh-cli/src/ts.rs:384-386`). `proxy --jsonl` is refused at parse, with the reason
(`crates/podssh-cli/src/tree.rs:292-300`, `crates/podssh-cli/src/non_interactive.rs:268-279`).
`serde_json` is already a dependency of the binary (`crates/podssh-cli/Cargo.toml:43`).

## Approach

1. Refuse `--jsonl` with `-W` at parse, with exit 64 and the reason, next to the `proxy` refusal
   (`crates/podssh-cli/src/tree.rs:292-300`): stdout carries the stream. Refuse `--jsonl=` too.
2. In the status form, write the status as one JSON object on one line, with `serde_json`:
   `{"event":"status","nodekey_prefix":...,"tailnet_ip":...,"home_region":...}`. Never the key.
3. Keep errors on stderr as text; the exit code stays the result. T-104 and T-105 add events (a
   drop, a new connection, a refusal) to this form when their states exist.
4. Change the help text of the row (`crates/podssh-cli/src/flags.rs:295-296`) and the notes of the
   manual (`crates/podssh-cli/src/man/notes.rs:84-87`) in the same commit. The tests of the manual
   compare the row with the help.

## Decision

Recommendation: refuse the flag with `-W`, and write JSON in the status form. The status line is
the one event of that form today, so the change is small, and scripts get what the help promises.
The alternative, refuse `--jsonl` in each form until a stream of events exists, lost because the
status form has a result to give now.

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

# T-241: The tailnet auth key is not cleared from memory

**Source:** found while T-100 to T-106 were written (finding 2). Read here on `3ee70dc`.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`podssh ts` reads the tailnet auth key from a file and keeps copies of it in plain buffers. When a
buffer is freed, the key stays in memory, where a core dump or a swap page can keep it. The relay
token and the passphrases of podssh are cleared when they are dropped; the auth key is not. The
fork also keeps its own copy for the whole session.

## Premise

Read: `AuthKey` holds a plain `Vec<u8>` and has no `Drop` (`crates/podssh-ts/src/secret.rs:9-41`).
`expire` writes zeros in a plain loop and then clears the vector
(`crates/podssh-ts/src/secret.rs:33-40`); only a test calls it (`crates/podssh-ts/tests/secret.rs:18-24`).
Known from the documentation of the `zeroize` crate, not verified here: a compiler can remove such
writes, because nothing reads the bytes after them.

Read: `podssh ts` reads the file into a plain buffer and trims it into a second copy
(`crates/podssh-cli/src/ts.rs:161-168`, `crates/podssh-cli/src/ts.rs:240-246`). `TsNode::start` makes
a third copy, a `String` that goes to the fork (`crates/podssh-ts/src/node.rs:55-56`,
`crates/podssh-ts/src/node.rs:70`). The fork keeps it in its configuration and in the parameters of
its control runner, for each registration (`vendor/tailscale-rs/ts_runtime/src/lib.rs:54`,
`vendor/tailscale-rs/ts_runtime/src/control_runner.rs:54`, `vendor/tailscale-rs/ts_runtime/src/control_runner.rs:108`).

Read: the relay token is a `Zeroizing<String>` (`crates/podssh-relay/src/token.rs:29`), and
`zeroize` is a workspace dependency (`Cargo.toml:161`), but podssh-ts does not use it
(`crates/podssh-ts/Cargo.toml:10-14`). The fork already depends on it
(`vendor/tailscale-rs/Cargo.toml:106`). The comment at `crates/podssh-ts/src/secret.rs:3-5` names a
model file that no longer exists.

## Approach

1. Add `zeroize` from the workspace to `crates/podssh-ts/Cargo.toml:10-14`. Hold the bytes in
   `Zeroizing<Vec<u8>>`, give `AuthKey` a `Drop` that clears them, and mark it `ZeroizeOnDrop`.
   `expire` calls `zeroize()`.
2. In `crates/podssh-cli/src/ts.rs:161-168`, read the file into `Zeroizing<Vec<u8>>`, and trim it
   in place, not into a copy (`crates/podssh-cli/src/ts.rs:240-246`).
3. In `TsNode::start`, make the fork's `String` from the bytes with no other copy
   (`crates/podssh-ts/src/node.rs:55-56`). Expire podssh's key when the start returns
   (`crates/podssh-cli/src/ts.rs:213-227`), because podssh no longer needs it.
4. In the fork, hold the key as `Zeroizing<String>` in `Config` and in `Params`, as a new patch
   with its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`.
5. Correct the comment at `crates/podssh-ts/src/secret.rs:3-5`, and name the tailnet key in the
   rule at `SECURITY.md:40-43`, in the same commit.

Pitfall: `Device::new` takes the key by value (`crates/podssh-ts/src/node.rs:70`), so only the fork
can clear its copy (step 4).

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
