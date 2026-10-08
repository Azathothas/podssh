This file holds the work on `podssh-ws`, the crate that reaches the relay: TCP and proxies, TLS
with podssh's own pure-Rust provider, and the WebSocket client. W10, W13 and W14 are rows of the
former defects page (`git show 3ee70dc:docs/defects.md`); the features come from the
`podssh-ws` item of ROADMAP M4 and `docs/design.md:102-104`, and from GitHub issues. The crate
must build with no C compiler (`scripts/gate.sh:61-69`).

# T-063: W10: the frame decoder does not check a received control frame

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row W10 (medium);
RFC 6455 section 5.5. Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The decoder accepts a Close, Ping or Pong frame that is fragmented or that has more than 125
bytes. RFC 6455 section 5.5 forbids both. podssh then answers a fragmented Ping, and reads an
oversized Close as a normal end of the session.

## Premise

Read on `3ee70dc`, the defect holds. `frame::decode` (`crates/podssh-ws/src/frame.rs:113-225`)
checks the reserved bits (lines 124-128), the opcode (129-135), the mask direction (141-150) and
the length caps (152-194). It never compares `fin` or the length with `MAX_CONTROL_PAYLOAD`
(lines 33-37) for the opcodes 0x8 to 0xA. The constant only stops the answer to a large Ping,
and the session goes on (`crates/podssh-ws/src/session.rs:181-187`;
`crates/podssh-ws/src/client.rs:323-327`). A Ping with FIN clear becomes `Event::Pong` and gets
an answer (`crates/podssh-ws/src/client.rs:363-365`). A Close or a Pong of any size is accepted
(`crates/podssh-ws/src/session.rs:188-199`). A Close of 1 byte is read as a Close with no code
(lines 275-278); RFC 6455 section 5.5.1 allows 0 bytes, or 2 and more.

## Approach

1. In `frame::decode`, when the length is known and before the payload is copied
   (`crates/podssh-ws/src/frame.rs:208`): for an opcode of 0x8 or more, return `WsError::Frame`
   when `fin` is clear or the length is over 125. Name the rule in the message.
2. Refuse a Close payload of 1 byte in the same place.
3. The read then fails (`crates/podssh-ws/src/session.rs:176`). Today a failed read sends no
   Close (`crates/podssh-ssh/src/relay_stream.rs:138-140`): send 1002 (protocol error) there, as
   lines 130-137 do for an unexpected frame. `podssh proxy` exits as for a broken session.
4. `crates/podssh-ws/tests/rfc6455.rs` has 486 lines: put the new tests in a new file,
   crates/podssh-ws/tests/control_frames.rs.
5. Record the repair in `docs/STATUS.md` (Components, `podssh-ws`) in the same commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test control_frames   # new
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws
```

The frames are bytes written from the RFC, not made by podssh's encoder: a Ping with FIN clear,
a Ping and a Close of 126 bytes (the 16-bit length form), and a Close of 1 byte, each refused;
the controls of 0 and 125 bytes, each accepted. A session test: a fragmented Ping gets no Pong,
and the read ends with an error. Planted defect: remove the check; the four refusal tests fail,
and the two controls pass.

# T-064: W13: `OsRng::fill_bytes` panics when the system gives no random bytes

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row W13 (low).
Confirmed here on `3ee70dc` by reading the code; two more call sites found.
**Category:** defect
**Milestone:** M4
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

When the operating system gives no random bytes, podssh's random source panics instead of
returning an error. Its callers expect an error: the comment of the masking key says "It is a
`Result`, not a panic". A panic ends the whole process, not one session.

## Premise

Read on `3ee70dc`, the defect holds. `OsRandom::fill` calls `rand::rngs::OsRng.fill_bytes` and
always returns `Ok` (`crates/podssh-ws/src/crypto/random.rs:13-23`), and its comment (lines
15-19) says that this cannot fail. It can: `Cargo.lock` gives `podssh-ws` `rand` 0.8, whose
`rand_core` 0.6.4 implements `fill_bytes` for `OsRng` as `try_fill_bytes` and a panic on an
error (read in the cargo registry copy, `rust-random/rand:rand_core/src/os.rs`, lines 61-64 of
that release). `generate_key` and `masking_key` map an error that never comes
(`crates/podssh-ws/src/handshake.rs:23-29`, 256-271). Two more sites, not in the W13 row, panic
the same way: `rng.fill_bytes` for the X25519 secret (`crates/podssh-ws/src/crypto/kx.rs:52-56`)
and `EphemeralSecret::random` for P-256 (line 66).

## Approach

1. In `random.rs`, call `OsRng.try_fill_bytes`, and map an error to
   `rustls::crypto::GetRandomFailed`; rustls 0.23.45 turns it into
   `Error::FailedToGetRandomBytes` (read in its `src/error.rs`). Correct the comment.
2. X25519 (`crates/podssh-ws/src/crypto/kx.rs:52-56`): fill the 32 bytes through
   `OsRandom::fill`, and return `Error::FailedToGetRandomBytes` on a failure.
3. P-256 (line 66): draw 32 bytes the same way, make the secret with
   `p256::SecretKey::from_slice` (draw again, a few times at most, when it is zero or out of
   range), and compute the shared secret with the `diffie_hellman` function of `elliptic-curve`
   0.13. Check the API of `p256` 0.13.2 first. No generator that can panic goes in.
4. Make the source a parameter in the tests, so a failing source can be planted.
5. Add a test that reads the crate's source, as `crates/podssh-cli/src/man/facts.rs:216-235`
   does, and fails on `fill_bytes(` or `OsRng` outside `random.rs`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws
cargo test -p podssh-ws --test live_handshake -- --ignored   # the live relay, on request
```

New tests: with a failing source, `fill` returns `GetRandomFailed` and `masking_key` returns
`WsError::Frame`, with no panic; the source scan finds no `fill_bytes(` call. A handshake still
completes with each group: X25519 against the live relay, and P-256 against a server that offers
only P-256 (`openssl s_server -groups P-256` in the container gate). Planted defect: call
`fill_bytes` again; the failing-source test panics, and fails.

# T-065: W14: `probe::PrintChain` accepts each certificate, and is a public export

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row W14 (medium);
`SECURITY.md:78-80`; the `podssh-ws` item of ROADMAP M4 and `docs/design.md:104` ("behind a
feature"). Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`podssh_ws::probe::PrintChain` is a certificate verifier that accepts each certificate and each
signature. It is a public export of a library that podbox is to use. A caller can install it by
mistake and turn TLS verification off, with no flag and no warning.

## Premise

Read on `3ee70dc`, the defect holds: `pub mod probe;` (`crates/podssh-ws/src/lib.rs:21`).
`verify_server_cert` prints the chain and returns `ServerCertVerified::assertion()`
(`crates/podssh-ws/src/probe.rs:24-39`); both signature checks accept (lines 41-57); a library
prints to stdout (lines 32-37). Its only user is the example
`crates/podssh-ws/examples/inspect_peer_chain.rs:25-29`. The module comment says that the test
suite asserts that the shipped configuration does not use it (`probe.rs:9-12`), but no test
names `PrintChain`: a search finds it only in `probe.rs`, the example and the documents. Also,
lines 134 and 178 of `probe.rs` index the certificate with no bound check, so a short
certificate panics the probe. The shipped configuration calls `.dangerous()` to install the
WebPKI verifier (`crates/podssh-ws/src/tls.rs:162-166`), so a scan cannot look for that word
alone.

## Approach

1. Move `PrintChain` and its DER helpers into the example
   (`crates/podssh-ws/examples/inspect_peer_chain.rs`), and remove `pub mod probe;`. Keep each
   file under 500 lines.
2. Add the test that `probe.rs:9-12` promised: a scan of the source of `podssh-ws`,
   `podssh-relay`, `podssh-ssh` and `podssh-cli`, as `crates/podssh-cli/src/man/facts.rs:216-235`
   reads source. It fails on `impl ServerCertVerifier` and on `set_certificate_verifier`.
3. In the example, replace the two unchecked indexes with `get`, so a short certificate gives
   "cannot read" and no panic.
4. Change in the same commit: `SECURITY.md:78-80` (the gap is closed), `docs/design.md:104`,
   and `docs/STATUS.md` (Components, `podssh-ws`).

## Decision

Recommendation: move the verifier into the example; then no build of the library can contain
it. A cargo feature lost: cargo joins the features of all the crates of one build, so one crate
in podbox's tree that turns the feature on gives the verifier to each crate of that build.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws   # with the new source scan
cargo build -p podssh-ws --examples
! grep -rn PrintChain crates/podssh-ws/src
```

The scan passes on the tree, and the example still builds. Planted defect: add an
`impl ServerCertVerifier` to `crates/podssh-ws/src/tls.rs`; the scan fails and names the file.

# T-066: A `rustls::ClientConfig` that the caller supplies, for podbox

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:79-80` and 102-104. Read here
on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podbox is to use `podssh-relay`, and to keep its own TLS: the `ring` provider, and TLS 1.2 for
proxies that intercept TLS. `podssh-ws` always builds its own configuration with podssh's
provider, so podbox cannot.

## Premise

Read: `open_tls` builds the trust anchors and the configuration on each call
(`crates/podssh-ws/src/client.rs:179-199`, through `crates/podssh-ws/src/tls.rs:153-173`).
`WsClientConfig` carries only a `Trust` (`crates/podssh-ws/src/client.rs:47-61`). The same
`Trust` goes through `podssh-relay`: `Request` (`crates/podssh-relay/src/open.rs:127-137`),
`MintContext` (`crates/podssh-relay/src/token.rs:92-97`), the pool refresh
(`crates/podssh-relay/src/pool.rs:109-118`), and the `https_*` functions
(`crates/podssh-ws/src/client.rs:253-279`). podssh's configuration offers no ALPN
(`crates/podssh-ws/src/tls.rs:167-170`), because the upgrade is HTTP/1.1 only
(`docs/relay.md:169`). The `tls12` feature of `rustls` is on in the workspace
(`[workspace.dependencies]` of `Cargo.toml`).

## Approach

1. A type in `podssh-ws` for the TLS choice: podssh's own (`Trust`, as now), or an
   `Arc<rustls::ClientConfig>` of the caller. Use it where `Trust` is used for a connection:
   `WsClientConfig`, `open_tls`, `https_get` and `https_post_json`.
2. Carry it through `podssh-relay`: `Request`, `MintContext` and the pool refresh.
3. Refuse a caller's configuration that offers ALPN, with a message that says why. Never change
   a caller's configuration silently.
4. The caller owns its verifier: `podssh-ws` cannot check it, and the documentation says so.
   podssh's binary never uses the caller form; the source scan of T-065 also fails on it in
   `podssh-cli`.
5. `podssh-ws` must not depend on `ring`, also not in its tests: the gate builds the tests with
   no C compiler. The tests make the caller's configuration with podssh's own provider.
6. The default stays `Trust`, so the binary does not change.
7. Change `docs/design.md:102-104` and `docs/architecture.md` in the same commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws -p podssh-relay
```

A new test connects through the caller form to a local TLS test server (as
`crates/podssh-ws/tests/hostname_verification.rs:63` starts one), with a caller configuration
whose only root is the test CA, which the default store does not hold. A configuration with the
ALPN `h2` is refused. podbox's own test with two clients is the exit check of M4 (T-085).
Planted defect: ignore the caller's configuration and build podssh's; the test CA is then
unknown, and the test fails.

# T-067: TLS 1.2, for intercepting proxies

**Source:** `docs/STATUS.md` (Components, `podssh-ws`: "No TLS 1.2 (some intercepting proxies
need it)"); `docs/design.md:79-80`. podssh has not measured such a proxy.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Some proxies that intercept TLS speak only TLS 1.2. podssh offers only TLS 1.3, so the handshake
with such a proxy fails, also when its CA is in the trust store (`--ca-file`, `SSL_CERT_FILE` or
the system bundle).

## Premise

Read: the provider has two suites, both TLS 1.3 (`crates/podssh-ws/src/crypto/suites.rs:55-56`),
and its comment says that TLS 1.2 suites are absent on purpose (lines 7-11). The configuration
enables both versions (`crates/podssh-ws/src/tls.rs:162-164`); rustls accepts that, because one
suite is usable, and then offers no TLS 1.2 suite (rustls 0.23.45, `with_protocol_versions` in
its `src/builder.rs`, read in the cargo registry). The `tls12` feature of `rustls` and
`tokio-rustls` is on (`Cargo.toml`). The provider has HMAC
(`crates/podssh-ws/src/crypto/hmac.rs`), AES-GCM and ChaCha20-Poly1305
(`crates/podssh-ws/src/crypto/aead.rs`), the ECDHE groups (`crates/podssh-ws/src/crypto/kx.rs`),
and RSA and ECDSA verification (`crates/podssh-ws/src/crypto/sign.rs`). The stand-in relay
requires TLS 1.3 (`scripts/fake-relay.py:232-233`).

## Approach

1. Add TLS 1.2 suites: ECDHE-ECDSA and ECDHE-RSA, each with AES-128-GCM, AES-256-GCM and
   ChaCha20-Poly1305. Each needs a PRF (rustls has one on top of an HMAC provider) and a TLS 1.2
   AEAD: GCM with a 4-byte implicit salt and an 8-byte explicit nonce; ChaCha20-Poly1305 with
   the nonce of RFC 7905.
2. The TLS 1.3 suites stay first in `ALL_CIPHER_SUITES`, and `self_check`
   (`crates/podssh-ws/src/crypto/suites.rs:77-104`) checks the new suites too.
3. No CBC suite, no RSA key exchange, no SHA-1 suite.
4. Test each suite against software that podssh did not write: `openssl s_server -tls1_2` with
   one suite at a time in the container gate, and `scripts/fake-relay.py` with an option for TLS
   1.2 only.
5. The relay line of `doctor` names the version
   (`crates/podssh-cli/src/doctor/relay_checks.rs:79-82`); the live relay must still give TLS
   1.3.
6. Change the comment of `suites.rs`, `docs/architecture.md:46`, the Trust item of the manual
   (`crates/podssh-cli/src/man/facts.rs:166-179`) and `docs/STATUS.md` in the same commit.

## Decision

Recommendation: offer both versions in each ClientHello, and let rustls choose. A server with
TLS 1.3 answers with 1.3, and the downgrade value of RFC 8446 section 4.1.3, which rustls
checks, stops a forced fall to 1.2. A second attempt with 1.2 after a failed 1.3 handshake lost:
that attempt is the downgrade that the value cannot show, and it doubles the time to fail. A flag
that turns 1.2 on lost: the hosts that need it see a failure first.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws
sh scripts/dev.sh check                                      # openssl s_server -tls1_2, each suite
cargo test -p podssh-ws --test live_handshake -- --ignored   # the live relay still gives TLS 1.3
```

Each TLS 1.2 suite completes a handshake and moves data with OpenSSL. The stand-in relay in its
TLS 1.2 mode carries a session. The live test asserts TLS 1.3. Planted defect: remove one suite
from the list; its OpenSSL check fails.

# T-068: Plain `ws://` to loopback, for tests only

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:103`.
**Category:** feature
**Milestone:** M4
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The tests of podbox, and a stand-in relay written in Rust, need a WebSocket session over plain
TCP on the loopback. `podssh-ws` always does TLS, so each such test needs a CA and certificates.

## Premise

Read: `connect` always calls `open_tls` (`crates/podssh-ws/src/client.rs:154-176`), and the
upgrade takes the TLS stream type (`crates/podssh-ws/src/client.rs:205-249`). `RelaySession` is
generic over its stream (`crates/podssh-ws/src/session.rs:32`), so a session over `TcpStream`
is possible. `podssh-relay` gives the TLS type back (`Opened`,
`crates/podssh-relay/src/open.rs:139-144`). The tests use in-memory streams
(`crates/podssh-ws/tests/session.rs:33-35`) or local TLS servers
(`crates/podssh-ws/tests/hostname_verification.rs:63`). `dial::is_loopback` exists
(`crates/podssh-ws/src/dial.rs:164-172`).

## Approach

1. Add `connect_plain_loopback` behind a cargo feature, `plain-ws`, off by default. It gives
   `RelaySession<TcpStream>`.
2. It refuses each host that `is_loopback` refuses, and it uses no proxy: a token over plain TCP
   must not leave the host.
3. Make `upgrade` generic over the stream, so both paths share it.
4. The runners of `podssh-relay` (T-079, T-081) must take any stream type, so that podbox's
   tests can use them.
5. The binary never enables the feature; a check in the gate proves it.
6. Change `docs/design.md:103` in the same commit.

## Decision

Recommendation: the feature and the loopback check together. The feature keeps the code out of
the binary; the check holds in each build that enables the feature. The check alone lost: the
code would be in the binary, one mistake from use.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --features plain-ws --test plain_loopback   # new
! cargo tree -p podssh-cli -e features | grep -q plain-ws
```

A local listener on 127.0.0.1 answers the upgrade with the bytes that `scripts/fake-relay.py`
writes for a `101` (lines 136-138), and the session carries data both ways. The host 192.0.2.1
is refused with no connection attempt. The second command shows that the binary does not enable
the feature. Planted defect: remove the loopback check; the refusal test fails.

# T-069: Typed session errors in `podssh-ws`

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:103`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The methods of a relay session return `String` errors. A caller cannot tell a dead link from a
protocol error, a stalled write or an end with no Close, except by matching text. The reverse
runners and the retry rules (T-025) need these classes.

## Premise

Read: `send_binary` and `send_text` (`crates/podssh-ws/src/session.rs:86-94`), `send_close`
(104-109), `read_frame` (170-221) and `write` (223-228) return `Result<_, String>`;
`watch_liveness` returns a `String` (142-166). The callers keep or pass the text:
`crates/podssh-ssh/src/relay_stream.rs:95-96` and 138-140 put it in `RelayEnd::Failed`;
`crates/podssh-cli/src/proxy.rs:212-247` prints it; `podssh-transport` makes it
`TransportError::Unexpected` (`crates/podssh-transport/src/socket.rs:75-80`, 109, 115, 136).
Tests and the gate match the text: `crates/podssh-ws/tests/session.rs:108` ("continuation") and
172 ("without a WebSocket Close"), and `scripts/interop-faults.sh:148` ("pings unanswered").
`WsError` exists (`crates/podssh-ws/src/error.rs:50-70`), but the session does not use it.

## Approach

1. Add `SessionError` to `crates/podssh-ws/src/error.rs` (96 lines; `session.rs` has 282):
   `Io` (the kind and the text), `Idle` (no data for the read limit), `WriteStalled` (the write
   limit), `Protocol` (a frame or a message that RFC 6455 forbids), `Dead` (from
   `watch_liveness`), `ClosedWithoutClose`, and `TooLarge` (the limit).
2. Each session method returns it; `watch_liveness` returns `Dead`.
3. `Display` gives the same text as now, so the tests and the gate still match.
4. The callers keep their behaviour: `RelayEnd::Failed` takes the error; `podssh proxy` keeps
   its exit codes; `podssh-transport` maps each class (T-072 and T-073 use them later).
5. Record the change in `docs/STATUS.md` (Components) in the same commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws -p podssh-transport
cargo test -p podssh-ssh -p podssh-cli
sh scripts/dev.sh check   # interop-faults still finds "pings unanswered"
```

New tests make each class with a scripted peer on an in-memory stream: a peer that sends nothing
(`Idle`), a peer that never reads (`WriteStalled`), a fragment with no start (`Protocol`), an end
of stream with no Close, and a peer that stops answering pings (`Dead`). The tests that match
the text still pass. Planted defect: map each error to `Io`; the class tests fail.

# T-070: A SOCKS5 proxy for the egress

**Source:** yituorou/meatshell (an outbound SOCKS5 and HTTP proxy, GitHub #22) and
sleepinginsummer/agent-ssh-cli (a `socksProxy` for each connection, GitHub #21). Read in the
reports, not verified here. No SOCKS proxy was measured on a target host.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podssh speaks only HTTP CONNECT to a proxy. A host whose only way out is a SOCKS5 proxy, often
given as `ALL_PROXY=socks5h://...`, cannot reach the relay: podssh refuses the setting.

## Premise

Read: `HttpProxy::parse` refuses each scheme but `http`, with "proxy scheme socks5:// is not
supported; podssh speaks HTTP CONNECT to an http:// proxy"
(`crates/podssh-ws/src/dial.rs:49-59`). `proxy_from_vars` reads `https_proxy`, `HTTPS_PROXY`,
`all_proxy` and `ALL_PROXY` (line 153), and parses the first that is set (line 161). `dial`
makes the error `DialError::BadProxy` (line 217), which stops the failover at once
(`crates/podssh-relay/src/open.rs:62`) and gives exit 78 in `podssh proxy`
(`crates/podssh-cli/src/proxy.rs:162`). `doctor` reports it as `FAIL`
(`crates/podssh-cli/src/doctor/net.rs:103-109`). Two tests assert the refusal:
`crates/podssh-cli/tests/doctor.rs:129-138` and `crates/podssh-ws/tests/dial.rs:34-42`.

## Approach

1. A proxy type with two forms, HTTP and SOCKS5, in `dial.rs`; `ProxyChoice::Via` takes it
   (`crates/podssh-ws/src/dial.rs:74-83`). Parse `socks5://` and `socks5h://` with an optional
   `user:password@`, decoded as for HTTP (lines 392-410).
2. The SOCKS5 exchange (RFC 1928): offer the method 0x00, and 0x02 only with credentials; the
   user and password of RFC 1929, each of 1 to 255 bytes; CONNECT with the address type 3, the
   host name, so the client needs no DNS (`crates/podssh-ws/src/dial.rs:5-8`). Read exactly the
   length of the reply: the bytes after it belong to TLS, as `read_head_exact` keeps them
   (lines 308-331). Bound each step.
3. When the proxy answers 0x08 (address type not supported), resolve the name in podssh's own
   order (pinned, system, DNS over HTTPS), and try once with the address.
4. Map each answer to the HTTP case that `another_host_may_help`
   (`crates/podssh-relay/src/open.rs:54-76`) and the exit codes of `podssh proxy`
   (`crates/podssh-cli/src/proxy.rs:158-171`) already treat: a refused user or password as 407
   (the same for each host: stop); 0x02 (not allowed) as 403; 0x03, 0x04 and 0x05 as 502.
5. Credentials never in output: `Display` shows the host and port only (`dial.rs:39-44`).
6. `doctor` names the SOCKS5 proxy, and its proxy checks
   (`crates/podssh-cli/src/doctor/net.rs:162-185`) work for both forms. The two tests above
   plant `ftp://` and `socks4://` instead; `socks4` and `socks4a` are refused by name.
7. Change the proxy variables in VARIABLES (`crates/podssh-cli/src/man/facts.rs:46-49`),
   `docs/architecture.md` and `docs/cli.md` in the same commit.

## Decision

Recommendation: send the host name for `socks5://` too, with the 0x08 fallback above. curl
resolves the name on the client for `socks5://`, but the hosts that podssh is made for often
have no DNS (`docs/STATUS.md`, "In the operator's real sandboxes, measured"), so a local lookup
fails first there. Following curl lost for that reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws --test dial
cargo test -p podssh-cli --test doctor
sh scripts/dev.sh check   # interop: through the SOCKS5 server of OpenSSH (ssh -D)
```

A stand-in on 127.0.0.1, as in `crates/podssh-ws/tests/dial.rs:79-101`, checks the bytes: the
greeting, the user and password, and a CONNECT with the address type 3 and the relay's name. In
the gate, the SOCKS5 server of OpenSSH (`ssh -N -D 127.0.0.1:PORT` to the test server) carries a
session to the stand-in relay, and a password in the proxy URL never appears in the output.
Planted defect: send the address (type 1); the stand-in refuses it, and the test fails.

# T-242: The frame decoder accepts a length that is not in the minimal form

**Source:** found by the writer of `TODO/repo.md` (2026-10-08) in
`crates/podssh-ws/src/frame.rs`; RFC 6455 sections 5.2, 7.1.7 and 7.4.1. Confirmed here on
`3ee70dc` by reading the code.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

RFC 6455 section 5.2 says that a frame must give its payload length in the minimal number of
bytes. podssh's decoder accepts a 16-bit length below 126 and a 64-bit length below 65536. A
peer that sends one breaks the protocol, and podssh reads the frame as valid.

## Premise

Read on `3ee70dc`, the defect holds. `frame::decode` reads the 16-bit length with no lower
bound (`crates/podssh-ws/src/frame.rs:158-165`). It reads the 64-bit length and checks only the
size of the platform and the forward cap of 262144 bytes (lines 166-186); that cap also refuses
a value with its top bit set, which section 5.2 forbids too. `frame::encode` writes the minimal
form (lines 80-88). The tests check the encoder at the boundaries 125, 126, 65535 and 65536
(`crates/podssh-ws/tests/rfc6455.rs:108-137`), and no test decodes a length that is not
minimal. The only caller in the code is `next_event`, for the frames of the relay
(`crates/podssh-ws/src/client.rs:358-367`). The stand-in relay writes the minimal form
(`scripts/fake-relay.py:54-62`); the frames of the real relay were not checked for it.

## Approach

1. In `frame::decode`, refuse a 16-bit length below 126 and a 64-bit length below 65536 with a
   `WsError::Frame` that names the rule (`crates/podssh-ws/src/frame.rs:158-186`), before the
   payload is copied.
2. A client that receives such a frame fails the WebSocket connection (RFC 6455 section 7.1.7):
   it sends a Close with 1002, a protocol error (section 7.4.1), and then closes the TCP
   connection. Today a failed read sends no Close
   (`crates/podssh-ssh/src/relay_stream.rs:138-140`); T-063 adds that Close for each decoder
   error, so this entry uses the same path.
3. The rule holds in both directions (`Role::Client` and `Role::Server`), so a stand-in relay in
   Rust (T-068) checks podssh's own frames with it too.
4. `crates/podssh-ws/tests/rfc6455.rs` has 486 lines: put the tests in a new file,
   crates/podssh-ws/tests/frame_lengths.rs.
5. Record the repair in `docs/STATUS.md` (Components, `podssh-ws`) in the same commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test frame_lengths   # new
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws
```

The frames are bytes written from the RFC, not made by podssh's encoder. Refused: the marker 126
with a length of 125, and the marker 127 with a length of 65535. Accepted: the marker 126 with
126, and the marker 127 with 65536. A session test: such a frame ends the read with an error,
and the client sends a Close with 1002. Planted defect: remove the check; the two refusal tests
fail, and the two controls pass.
