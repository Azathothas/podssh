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
way: exit 0, byte-identical on all 33 touched paths.

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

`LOCAL-PATCHES.md` (this file) is fork bookkeeping and is not part of the sixteen
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
