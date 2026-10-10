# LOCAL-PATCHES.md — podssh's carried patch set

This tree is a vendored copy of `tailscale/tailscale-rs` at commit
`f4781c480e8d1376aed89f737beefe7425e8b866` (2026-09-29) with a small local
patch set. podssh is the consumer; upstream declines external PRs (issue #291),
so the patches are carried rather than proposed.

Re-apply the set to a pristine checkout:

```sh
git clone https://github.com/tailscale/tailscale-rs
cd tailscale-rs
git checkout f4781c480e8d1376aed89f737beefe7425e8b866
for p in /path/to/podssh/vendor/patches/*.patch; do
    patch -p1 < "$p" || exit 1
done
```

MEASURED 2026-10-05, on Windows in Git Bash: each of the eight patches
passes `git apply --check` against the pristine clone `.tmp/tailscale-rs`
(exit 0 for all eight, read unpiped). No patch is applied there; the check does
not write. ⛔ Re-measured 2026-10-06 for all thirteen: the full chain applies
for real to a scratch export of pristine `f4781c4` (`git apply`, exit 0) and
reproduces the vendor tree byte-for-byte on all 27 touched paths
(`diff -q` per path, exit 0) — which is how the missing 0010 lock hunk above
was found. ⛔ Re-measured 2026-10-07 for all fourteen: chain applies exit 0,
byte-identical on all 28 touched paths. Re-measured 2026-10-10 for all fifteen
(podssh T-241): the chain applies to an export of pristine `f4781c4` made
outside podssh's repository (`git apply` inside it reads each path from the
repository's root and skips it), exit 0, and is byte-identical on all 29
touched paths. Re-measured 2026-10-10 for all sixteen (podssh T-102), the same
way: exit 0, byte-identical on all 33 touched paths; for all eighteen
(podssh T-103): exit 0, byte-identical on all 36; for all nineteen
(podssh T-104): exit 0, byte-identical on all 41; for all twenty
(podssh T-276): exit 0, byte-identical on all 41; and for all twenty-one
(podssh T-105): exit 0, byte-identical on all 42.

## The patch set

| Patch | File | Hunks | Why |
| --- | --- | --- | --- |
| `0001-ts_derp-Cargo.toml.patch` | `ts_derp/Cargo.toml` | 1 | Add `tokio-tungstenite 0.24` (`default-features = false`, `features = ["handshake"]`) for WebSocket framing only; TLS stays `ts_tls_util`, no second TLS stack. |
| `0002-ts_derp-src-lib.rs.patch` | `ts_derp/src/lib.rs` | 1 | `pub mod ws;` — export the WebSocket transport module. |
| `0003-ts_derp-src-error.rs.patch` | `ts_derp/src/error.rs` | 1 | Three new variants: `Dial` (`#[from] dial::Error`), `NoServerReachable`, `WebSocket` (`#[from] tungstenite::Error`) — the typed errors that replace two `unwrap()` panics plus the transport error. |
| `0004-ts_derp-src-client.rs.patch` | `ts_derp/src/client.rs` | 2 | Remove both panics. `connect()`: `dial_region_tls(..).await.unwrap()` becomes `?`. `Client::connect`: `connect(..).await?.unwrap()` becomes a `NoServerReachable` error — upstream issue #439. |
| `0005-ts_derp-src-ws.rs.patch` | `ts_derp/src/ws.rs` (new) | 1 | The WebSocket transport: `connect` / `connect_with_subprotocol` do TCP → TLS (SNI = hostname, via `ts_tls_util`) → RFC 6455 handshake with `Sec-WebSocket-Protocol: derp`; `WsIo` implements `AsyncRead + AsyncWrite`: one binary message per `poll_write`, byte-stream reads across message boundaries, close code and reason surfaced in the `io::Error`. |
| `0006-ts_derp-tests-wire_compat.rs.patch` | `ts_derp/tests/wire_compat.rs` (new) | 1 | M1: pins the exact ClientInfo JSON bytes and the absence of a `meshKey` property, with camelCase and `meshKey`-rename shadow plants the same predicate must reject. |
| `0007-ts_derp-examples-ws_handshake.rs.patch` | `ts_derp/examples/ws_handshake.rs` (new) | 1 | M3: live handshake probe. Fresh keypair, ServerKey frame reported from the bytes read, expected WebSocket close `1008 "not authorized"`; `--no-subprotocol` is the negative control expecting HTTP 426. |
| `0008-Cargo.lock.patch` | `Cargo.lock` | 8 | Resolution for the new dependency: adds `tokio-tungstenite 0.24.0`, `tungstenite 0.24.0`, `rand_chacha 0.3.1`, `utf-8 0.7.6`, and `tokio-tungstenite` to `ts_derp`'s dependency list. |
| `0009-connect-mode.patch` | `ts_derp/src/client.rs`, `ts_derp/src/lib.rs`, `ts_runtime/src/multiderp/uniderp.rs`, `ts_derp/tests/connect_mode.rs` (new) | 4 | E39 increment 1: `ConnectMode { TcpUpgrade (default), WebSocket }`, `DefaultIo` as an `{ Http, Ws }` enum with `AsyncRead`/`AsyncWrite` delegation, `connect(region, mode)` branching (WS via `ws::connect` on the first dialable server — see `ws_target`), `Client<WsIo>::connect_ws` convenience, `Runner::connect_mode` (default `TcpUpgrade`; the DERP-only increment feeds `RuntimeOptions` here). Proven by `ts_derp/tests/connect_mode.rs` (4 tests: default pins TCP, selection skips stun-only/self-signed; inverted-selection plant fails 3). |
| `0010-proxy-dialer.patch` | `ts_http_util/src/proxy.rs` (new), `ts_http_util/src/lib.rs`, `ts_http_util/Cargo.toml`, `ts_http_util/tests/proxy.rs` (new), `ts_control/src/control_dialer.rs`, `ts_derp/src/dial.rs`, `ts_derp/tests/proxy_dial.rs` (new), `Cargo.lock` | 8 | E39 increment 2: one CONNECT dialer (`ProxyConfig` URL/env parsing, process-global `configure`, `connect(host, port)` with 16 KiB response bound, 20 s bound, 2xx required, optional `Proxy-Authorization`), routed into all three dial sites (`dial_tcp`, `ControlTcpDialer::dial` — dial plans skipped under proxy — `dial_by_ipusage` — `FixedAddr` ignored under proxy); `DialMode::Ace`'s `unimplemented!()` becomes an `Err`. Proven by `ts_http_util/tests/proxy.rs` (5 tests: echo + CONNECT count, 403 named with no fallback, 407/200 auth, head bound, URL parsing) and site tests (`dial_tcp` via fake proxy on an unresolvable name, `dial_server` by hostname; both branches plant-removed and seen to fail). ⛔ The `Cargo.lock` hunk (`base64 0.22.1` under `ts_http_util`, following the `base64.workspace` manifest line) shipped in the increment-2 commit but was missing from the patch file; increment 3's chain re-check caught the 1-line drift and folded the hunk into 0010 where it belongs. |
| `0011-derp-only-gating.patch` | `ts_runtime/src/options.rs` (new), `ts_runtime/tests/options.rs` (new), `ts_runtime/src/lib.rs`, `ts_runtime/src/env.rs`, `ts_runtime/src/direct.rs`, `ts_runtime/src/stunner.rs`, `ts_runtime/src/multiderp/uniderp.rs`, `ts_runtime/Cargo.toml`, `src/lib.rs`, `Cargo.lock` | 10 | E39 increment 3: DERP-only runtime gating. `RuntimeOptions { no_udp, derp: DerpOptions { ws, override_host, override_port }, proxy }`, all defaulting to stock behavior; `Config.options` feeds one `Env` copy at startup (`apply_proxy` before any actor dials); `Uniderp` reads `derp_mode()` and `derp_pin()` from it (a pin implies WS and bypasses the region's servers via `connect_ws`); `DirectActor`/`Stunner`/netmon spawn only under `!no_udp`; the two `DirectActor` bind/publish `unwrap()`s and the `Stunner` publish `unwrap()` become log-and-continue; top-level `Device` builds `options: Default::default()` until the `ts` verb exposes them. Proven by `ts_runtime/tests/options.rs` (5 tests: stock defaults, ws selection, pin split with 443 default, env carriage, proxy feed; mode-inversion, proxy-no-op and port-80 plants each fail exactly their test, restores green). ⛔ Gap, named: no test fails when a `!no_udp` spawn gate is removed — a boot test would dial the control plane from `ControlRunner::on_start`, so the gates' proof is the live two-node M5 boot, not this suite. |
| `0012-derp-example-mode.patch` | `ts_derp/examples/ping.rs`, `ts_derp/examples/listen.rs` | 2 | Increment-1 follow-up: the two upstream examples still called the 2-argument `Client::connect` and broke `cargo test -p ts_derp` (which builds examples); both now pass `ConnectMode::TcpUpgrade`, keeping stock behavior. Found by increment 3's widened verification (whole-package suites, not `--test`-only). |
| `0013-proxy-test-serial.patch` | `ts_http_util/tests/proxy.rs` | 1 | Increment-2 follow-up: the proxy suite flaked on Windows loopback (rotating 1–4 failures, `os error 10054` / truncated heads) because `configure` is process-global and parallel tests dialled each other's fake proxy. The four async tests now serialize on a poison-tolerant `SERIAL` mutex: 3/3 green guarded runs, 4/4 red with the guards stripped. |
| `0014-device-options.patch` | `src/config.rs`, `src/lib.rs` | 2 | E39 increment 4b: `tailscale::Config` gains `pub options: ts_runtime::options::RuntimeOptions` (defaulting to stock in the hand-written `Default` impl), and `Device::new` threads `config.options.clone()` into `ts_runtime::Config` instead of `Default::default()` — replacing the increment-3 placeholder comment at the same site. Without it podssh-ts could select WS/pin/proxy but the runtime would never receive them. |
| `0015-zeroize-auth-key.patch` | `ts_runtime/Cargo.toml`, `ts_runtime/src/lib.rs`, `ts_runtime/src/control_runner.rs`, `src/lib.rs`, `Cargo.lock` | 6 | podssh T-241: the auth key that `Device::new` takes by value is moved, with no copy, into a `zeroize::Zeroizing<String>` in `ts_runtime::Config` and in the control runner's `Params`, so each copy is cleared from memory when it is dropped; `ts_runtime` depends on the fork's workspace `zeroize`, and the lock says so. The public signature of `Device::new` is unchanged. |
| `0016-logout.patch` | `ts_control/src/client/register.rs`, `ts_control/src/client/mod.rs`, `ts_control/src/lib.rs`, `ts_control/tests/logout.rs` (new), `ts_runtime/src/control_runner.rs`, `ts_runtime/src/lib.rs`, `src/lib.rs` | 7 | podssh T-102: a logout, which the fork lacked. `ts_control::logout_body` builds a register request with this node's key and an expiry in the past (Go's `time.Unix(123, 0)`), with no auth key (Go's client attaches its key to each register request; the control server finds the node by its key); `ts_control::logout` posts it to `machine/register` and takes any success status unless the body names an `Error`, and does not read the answer as a registration (headscale answers `MachineAuthorized: false` for an ephemeral node that it deleted); `LogoutError` says why one failed. The control runner answers a new `Logout` message over its registered connection, the runtime forwards it, and `Device::logout(timeout)` waits for the answer. Proven by `ts_control/tests/logout.rs` (2 tests: this node key, an expiry in the past, no auth key; with the expiry planted away, or planted a day ahead, the first fails). |
| `0017-proxy-dial.patch` | `ts_http_util/src/proxy.rs`, `ts_http_util/src/lib.rs`, `ts_http_util/tests/proxy.rs`, `ts_derp/src/ws.rs`, `ts_derp/src/dial.rs`, `ts_derp/tests/ws_proxy_dial.rs` (new), `ts_control/src/control_dialer.rs` | 7 | podssh T-103: the DERP dial over WebSocket went straight out, with the system resolver and no bound, so in `relay` mode a host whose only egress is a CONNECT proxy never reached DERP. `proxy::dial(host, port)` opens TCP by name, through the proxy when it `applies` to the host, else direct, within 20 s either way; `ws::connect_with_subprotocol` and `dial_by_ipusage` (for a server dialled by name) use it, and each of the four dial sites asks `applies(host)`. `ProxyConfig::with_no_proxy` carries a `no_proxy` list, by podssh's rules for that variable; `from_url` percent-decodes the user name and the password (`url::Url` gives them escaped), keeps an IPv6 proxy's address without its brackets, and quotes the URL in no refusal; the `Debug` of `ProxyConfig` hides the credentials. Proven by `ts_derp/tests/ws_proxy_dial.rs` (the dial sends `CONNECT relay.invalid:443` to a fake proxy, and fails at TLS) and three new tests in `ts_http_util/tests/proxy.rs` (credentials decoded; a host on the list dialled direct; no message shows the credentials); in podssh, `crates/podssh-ts/tests/derp_proxy.rs` runs the same through podssh's workspace, each test failing on its planted defect. |
| `0018-tls-provider.patch` | `ts_tls_util/src/lib.rs`, `ts_tls_util/src/insecure.rs` | 4 | podssh T-103: each TLS config of `ts_tls_util` took rustls's process default provider, which rustls has only when its build holds one provider; built beside a crate that turns on `ring` (podssh's workspace with its iroh test relay, or a podssh build with the `iroh-test` feature), each DERP or control connection panicked. Both configs now name aws-lc-rs, the provider that `ts_tls_util` already selects, with rustls's safe protocol versions. Proven in podssh: `cargo test --workspace --test derp_proxy` failed twice with rustls's panic before, and passes; live, `ts_derp`'s `ws_handshake` example still meets the relay's TLS and its close 1008. |
| `0019-reconnect.patch` | `ts_runtime/src/reconnect.rs` (new), `ts_runtime/src/lib.rs`, `ts_runtime/src/env.rs`, `ts_runtime/src/options.rs`, `ts_runtime/src/control_runner.rs`, `ts_runtime/src/multiderp/mod.rs`, `ts_runtime/src/multiderp/uniderp.rs`, `ts_runtime/Cargo.toml`, `ts_runtime/tests/reconnect.rs` (new), `ts_derp/src/client.rs`, `ts_derp/src/ws.rs`, `ts_derp/src/error.rs`, `ts_derp/Cargo.toml`, `ts_derp/tests/ping.rs` (new), `ts_derp/tests/ws_proxy_dial.rs`, `src/lib.rs`, `src/config.rs`, `Cargo.toml` | 18 | podssh T-104: a DERP region's runner ended at its first error for good, and the control runner stopped after five restarts in 5 s, or, while the node started, after its first failed dial. `reconnect::keep` runs a `Link` for ever with podssh's backoff (1 s to 30 s, a random factor in [0.5, 1.5), from 1 again after a link of 60 s) and ends only on a refusal (a close 1008 "not authorized", typed now as `ws::WsClose` inside the `io::Error`, found by `Error::ws_close`), unless `Reconnect::retry_refused`; `until_silent` declares a link dead after three silent pings 10 s apart, once it has answered one. The DERP client sends pings and counts pongs, which ended the connection before. With a pin, one runner serves each region. The control runner dials again in its start, and is restarted with no limit, each start after its backoff. Each change of a link goes to a broadcast channel, `Device::link_events`, or the caller's in `Config::link_events`. The `let _` of 0017's test is a `drop`, for the fork's lints. Proven by `ts_runtime/tests/reconnect.rs` (7 tests under a paused clock; the loop ending at the first error fails four), `ts_derp/tests/ping.rs` (a stand-in DERP server answers a ping; with no arm for the pong it fails), and a unit test of the close in `ts_derp/src/ws.rs`. |
| `0020-clippy.patch` | `ts_derp/src/error.rs`, `ts_derp/src/client.rs`, `ts_derp/examples/ws_handshake.rs`, `ts_runtime/src/lib.rs`, `ts_runtime/src/multiderp/mod.rs`, `ts_runtime/src/multiderp/uniderp.rs`, `ts_http_util/tests/proxy.rs`, `ts_http_util/Cargo.toml` | 9 | podssh T-276: the fork's own clippy, which no podssh build shows (cargo caps the lints of a path dependency outside the workspace), warned in the crates that podssh's patches change. `ts_derp::Error::WebSocket` boxes its error, with a `From` for the unboxed one (each `Result` of `ts_derp` was large), and `DefaultIo::Ws` its stream; `ws_handshake` reads the upgrade's status through the box; the netmon gate of 0011 is one `if`; the proxy tests take turns on an async lock, held across their awaits; two lines of 0019 are formatted. Proven by `cargo clippy -p ts_derp -p ts_runtime -p ts_http_util -p ts_tls_util -p ts_control -p tailscale --all-targets -- -D warnings`, exit 0, which fails on the error unboxed again; `scripts/ts-derp-prove.sh` runs it. |
| `0021-link-states.patch` | `ts_runtime/src/reconnect.rs`, `ts_runtime/src/env.rs`, `ts_runtime/src/lib.rs`, `ts_runtime/src/control_runner.rs`, `ts_runtime/tests/reconnect.rs`, `ts_derp/src/ws.rs`, `ts_derp/tests/ws_close.rs` (new), `src/lib.rs` | 11 | podssh T-105: the relay's refusal of a node key reached no caller, and looked like a network map that had not come. `reconnect::LinkStates` keeps the newest state of each link (connected, failed, refused), written by `Env::link_changed` at each change, and `Device::link_states` reads it with no wait; `LinkChange::Dropped` says whether the drop was a refusal dialled again. `ws::WsIo` takes its stream as a type parameter, TLS over TCP by default, with `WsIo::new`. Proven by `ts_derp/tests/ws_close.rs` (a WebSocket server over an in-memory pipe closes 1008; the code and the reason reach `Error::ws_close`; with the close as text only it fails) and a test of the states in `ts_runtime/tests/reconnect.rs`. |

`LOCAL-PATCHES.md` (this file) is fork bookkeeping and is not part of the twenty-one
patches; deleting it changes nothing that builds.

## What the patches deliberately do not do

- **The runtime still defaults to TCP.** 0011 feeds the mode and the pin from
  `RuntimeOptions` (`Uniderp` reads `derp_mode()` / `derp_pin()` off the one
  `Env` copy; a pin implies WS), but `RuntimeOptions::default()` selects
  `TcpUpgrade` with no pin, and top-level `Device` still builds that default —
  so an unconfigured device runs exactly as before. Selecting WS / the lab pin
  is the `ts` verb's job (increment 4). The proxy dialer is likewise fed, not
  forced: `apply_proxy` with `None` leaves direct dialing in place.
- **The `Host` header still comes from the dialed IP.** The stage-2 design
  rebuilds the upgrade URL from `server.hostname` + `server.https_port`;
  0009 keeps the existing construction untouched because the change is
  unobservable offline and untestable without a tailnet — bundling it would
  risk the TCP path with no way to verify. It lands with the proxy increment,
  which reworks dialing anyway.
- **No changed frame codec.** `ts_derp::frame` and `Client::handshake` are
  untouched, which is what keeps the ClientInfo JSON contract pinned by
  `tests/wire_compat.rs` meaningful.
- **No self-signed certificate support.** `dial.rs` still skips
  `TlsValidationConfig::SelfSigned`; `ws::connect` dials a public-CA hostname.

## The ClientInfo JSON contract (why `0006` is load-bearing)

The relay at `tcp.ts.relay.ajam.dev` reads ClientInfo by exact camelCase
property (`meshKey`, `version`, `CanAckPings`, `IsProber`, `AppName`;
`worker/src/derp/login.ts`) and ignores unknown properties. A present
`meshKey` closes the connection with 1008 (invalid value: "bad client info";
any value: "mesh not supported"). `ClientInfoPayload` has no serde rename, so
the wire JSON is snake_case and the relay never sees a `meshKey` property —
that name mismatch is the only reason this handshake is not refused. A future
`#[serde(rename_all = "camelCase")]` on that struct (or a well-meaning
"Go-compat" edit) flips the wire to `meshKey: "none"` and the relay closes
1008. `tests/wire_compat.rs` fails in that case, and the live probe
(`ws_handshake`) observes it as a close other than `1008 "not authorized"`.

## Build notes

- The vendored workspace builds standalone (its own `[workspace]` and
  `Cargo.lock`). `ts_tls_util` pulls `tokio-rustls/aws-lc-rs`, so a standalone
  build needs `cc`, `cmake`, `make` and `perl` — measured in the podssh build
  container (`rust:1-alpine`, 2026-10-05).
- podssh's own gate (`CC=/nonexistent`) does not cover `vendor/`; this tree is
  outside the gate's scan roots and is built separately until the adapter
  lands (stage-2 report, "CC-gate policy").
