This file holds the work on `podssh-ws`, the crate that reaches the relay: TCP and proxies, TLS
with podssh's own pure-Rust provider, and the WebSocket client. W10, W13 and W14 are rows of the
former defects page (`git show 3ee70dc:docs/defects.md`); the features come from the
`podssh-ws` item of ROADMAP M4 and `docs/design.md:484-488`, and from GitHub issues. The crate
must build with no C compiler (`scripts/gate.sh:154-166`).

# T-063: W10: the frame decoder does not check a received control frame

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row W10 (medium);
RFC 6455 section 5.5. Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The decoder accepts a Close, Ping or Pong frame that is fragmented or that has more than 125
bytes. RFC 6455 section 5.5 forbids both. podssh then answers a fragmented Ping, and reads an
oversized Close as a normal end of the session.

## Premise

Read on `3ee70dc`, the defect holds; the lines below are those of `3b60753`. `frame::decode`
(`crates/podssh-ws/src/frame.rs` lines 113-225 at `076e3ce`) checks the reserved bits (lines 124-128 at `22c3b88`), the
opcode (129-135), the mask direction (141-150) and the length caps (152-194). It never compares
`fin` or the length with `MAX_CONTROL_PAYLOAD` (lines 33-37 at `076e3ce`) for the opcodes 0x8 to 0xA. The
constant only stops the answer to a large Ping, and the session goes on
(`crates/podssh-ws/src/session.rs` lines 181-187 at `076e3ce`; `crates/podssh-ws/src/client.rs` lines
331-335). A Ping with FIN clear becomes `Event::Pong` and gets an answer (`client.rs` lines
371-373). A Close or a Pong of any size is accepted (`session.rs` lines 188-199 at `076e3ce`). A Close of 1
byte is read as a Close with no code (`session.rs` lines 275-278 at `076e3ce`); RFC 6455 section 5.5.1 allows
0 bytes, or 2 and more.

## Approach

1. In `frame::decode`, when the length is known and before the payload is copied
   (`crates/podssh-ws/src/frame.rs` line 208 at `3b60753`): for an opcode of 0x8 or more, return
   `WsError::Frame` when `fin` is clear or the length is over 125. Name the rule in the message.
2. Refuse a Close payload of 1 byte in the same place.
3. The read then fails (`crates/podssh-ws/src/session.rs` line 176 at `3b60753`). Today a failed
   read sends no Close (`crates/podssh-ssh/src/relay_stream.rs:267-269`): send 1002 (protocol
   error) there, as lines 130-137 do for an unexpected frame. `podssh proxy` exits as for a
   broken session.
4. `crates/podssh-ws/tests/rfc6455.rs` has 486 lines: put the new tests in a new file,
   crates/podssh-ws/tests/control_frames.rs.
5. Record the repair in `docs/STATUS.md` (Components, `podssh-ws`) in the same commit.

## Decision

2026-10-09: the Close 1002 of step 3 is sent by the session, not by `relay_stream.rs`.
`RelaySession::read_frame` fails the connection (`fail`, RFC 6455 section 7.1.7) for each error
of the decoder (1002) and of the reassembly of a message (1002, or 1009 for a message over 16
MiB); a broken socket or an end of stream sends nothing, because no peer is left to tell.
`read_frame_over`, the reader of one stream that the tests script, does the same. Lost: the Close
in the error arm of `relay_stream.rs`, which cannot tell a protocol error from a broken socket,
and which `podssh proxy`, on the same session, would not have had. The size guard before a Pong
stays as a second line.

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

## Done

2026-10-09, in the commit "A control frame that RFC 6455 forbids fails the connection".

- `frame::decode` refuses, as soon as the length is known, a Close, Ping or Pong that is
  fragmented or carries more than 125 bytes (RFC 6455 section 5.5), and a Close of 1 byte
  (section 5.5.1); each message names the rule.
- The session fails the connection with a Close 1002 after such a frame, and after a reassembly
  error (1009 for a message over 16 MiB); see Decision. `podssh ssh` and `podssh proxy` then end
  as for a broken session.
- `crates/podssh-ws/tests/control_frames.rs` (new): the four refusals, each a test on bytes written
  from the RFC; the controls of 0 and 125 bytes for each control opcode; a fragmented Ping and a
  Close of 126 bytes on a session (no Pong, the read ends, a Close 1002 goes out); a continuation
  with no message (a Close 1002). `read_frame_does_not_answer_an_oversized_ping_or_one_after_a_close`
  of `handshake_tail.rs` became two tests: the oversized Ping is refused with a Close 1002, and a
  Ping after a Close gets no answer.
- Prove: `cargo test -p podssh-ws --test control_frames`: 7 passed. `CC=/nonexistent
  CXX=/nonexistent cargo test -p podssh-ws`: 142 passed, 0 failed. `cargo test --no-fail-fast`:
  792 passed, 0 failed, 7 ignored.
- Plants, each restored: the check removed: the four refusal tests and the session test failed,
  and the two controls passed; the Close of `fail` removed: both session tests of
  `control_frames.rs` failed.

# T-064: W13: `OsRng::fill_bytes` panics when the system gives no random bytes

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row W13 (low).
Confirmed here on `3ee70dc` by reading the code; two more call sites found.
**Category:** defect
**Milestone:** M4
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

When the operating system gives no random bytes, podssh's random source panics instead of
returning an error. Its callers expect an error: the comment of the masking key says "It is a
`Result`, not a panic". A panic ends the whole process, not one session.

## Premise

Read on `3ee70dc`, the defect holds; the lines below are those of `510d86f`. `OsRandom::fill`
calls `rand::rngs::OsRng.fill_bytes` and always returns `Ok`
(`crates/podssh-ws/src/crypto/random.rs` lines 13-23 at `c56792f`), and its comment (lines 15-19 at `c56792f`) says that
this cannot fail. It can: `Cargo.lock` gives `podssh-ws` `rand` 0.8, whose `rand_core` 0.6.4
implements `fill_bytes` for `OsRng` as `try_fill_bytes` and a panic on an error (read in the
cargo registry copy, `rust-random/rand:rand_core/src/os.rs`, lines 61-64 at `22c3b88` of that release).
`generate_key` and `masking_key` map an error that never comes
(`crates/podssh-ws/src/handshake.rs` lines 23-29 and 256-271 at `c56792f`). Two more sites, not in the W13
row, panic the same way: `rng.fill_bytes` for the X25519 secret
(`crates/podssh-ws/src/crypto/kx.rs` lines 52-56 at `c56792f`) and `EphemeralSecret::random` for P-256 (line
66).

## Approach

1. In `random.rs`, call `OsRng.try_fill_bytes`, and map an error to
   `rustls::crypto::GetRandomFailed`; rustls 0.23.45 turns it into
   `Error::FailedToGetRandomBytes` (read in its `src/error.rs`). Correct the comment.
2. X25519 (`crates/podssh-ws/src/crypto/kx.rs` lines 52-56 at `510d86f`): fill the 32 bytes through
   `OsRandom::fill`, and return `Error::FailedToGetRandomBytes` on a failure.
3. P-256 (line 66): draw 32 bytes the same way, make the secret with
   `p256::SecretKey::from_slice` (draw again, a few times at most, when it is zero or out of
   range), and compute the shared secret with the `diffie_hellman` function of `elliptic-curve`
   0.13. Check the API of `p256` 0.13.2 first. No generator that can panic goes in.
4. Make the source a parameter in the tests, so a failing source can be planted.
5. Add a test that reads the crate's source, as `crates/podssh-cli/src/man/facts/tests.rs:13-37`
   does, and fails on `fill_bytes(` or `OsRng` outside `random.rs`.

## Decision

2026-10-09:

1. P-256 is proven against a TLS stack that podssh did not write by the live relay, not by an
   `openssl s_server` in the container gate: `each_group_alone_completes_a_handshake_with_the_relay`
   offers one group at a time with the configuration that ships (`tls::client_config_with`, new)
   and asserts the group that the relay chose. The live tests are in the default suite, so the
   gate and CI run it. Lost: an OpenSSL server in the gate, a second peer for the same proof, and
   its setup in the image.
2. The source is a parameter as `&dyn SecureRandom` (`kx::start_with`,
   `handshake::masking_key_from`, `handshake::generate_key_from`) and as `&mut impl RngCore`
   (`random::fill_from`, under `OsRandom`): the first plants a source that fails, the second plants
   an `RngCore` whose `fill_bytes` panics, as that of `OsRng` does.
3. P-256 draws eight times at most; a source that gives only zero or out-of-range draws is
   `FailedToGetRandomBytes`, as one that gives none.
4. The scan also refuses `::random(&mut`, a generator that takes an RNG, beside `fill_bytes(` and
   `OsRng` outside `crypto/random.rs`.

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

## Done

2026-10-09, in the commit "No draw of random bytes can panic".

- `random::fill_from` reads with `try_fill_bytes` and maps a failure to `GetRandomFailed`;
  `OsRandom::fill` calls it with `OsRng`. Its comment says why.
- `kx::start_with(group, random)`: X25519 fills its 32 bytes through the source (and wipes the
  copy on the stack); P-256 makes its secret with `p256::SecretKey::from_slice` from 32 drawn
  bytes (see Decision) and computes the shared secret with `p256::ecdh::diffie_hellman`. No
  generator that can panic is left; `KxGroup::start` calls `start_with` with `OsRandom`.
- `handshake::generate_key_from` and `masking_key_from`; `tls::client_config_with`.
- `crates/podssh-ws/tests/random_source.rs` (new): a source that gives no bytes is an error for
  `fill_from`, both WebSocket keys and both groups; P-256 draws again after out-of-range draws;
  P-256 agrees with `p256`'s own `EphemeralSecret` on the shared secret; X25519 agrees with
  itself; the source scan. `live_handshake.rs`: each group alone completes a handshake with the
  relay.
- Prove: `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws`: 151 passed, 0 failed, 2
  ignored; among them the live handshakes, X25519 alone and P-256 alone. `cargo test
  --no-fail-fast`: 804 passed, 0 failed, 7 ignored.
- Plant: `fill_from` calls `fill_bytes` again: `a_source_that_gives_no_bytes_is_an_error`
  panicked ("fill_bytes was called"), and the scan named `crypto/random.rs`.

# T-065: W14: `probe::PrintChain` accepts each certificate, and is a public export

**Source:** the former defects page (`git show 3ee70dc:docs/defects.md`), row W14 (medium);
`SECURITY.md` lines 78-80 at `4e817d7`; the `podssh-ws` item of ROADMAP M4 and `docs/design.md`
line 104 at `4e817d7` ("behind a feature"). Confirmed here on `3ee70dc` by reading the code.
**Category:** defect
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh_ws::probe::PrintChain` is a certificate verifier that accepts each certificate and each
signature. It is a public export of a library that podbox is to use. A caller can install it by
mistake and turn TLS verification off, with no flag and no warning.

## Premise

Read on `3ee70dc`, the defect holds; the lines below are those of `4e817d7`. `pub mod probe;`
(`crates/podssh-ws/src/lib.rs` line 22 at `510d86f`). `verify_server_cert` prints the chain and returns
`ServerCertVerified::assertion()` (crates/podssh-ws/src/probe.rs, gone since this entry, lines
24-39); both signature checks accept (lines 41-57 at `22c3b88`); a library prints to stdout (lines 32-37 at `510d86f`). Its
only user is the example (`crates/podssh-ws/examples/inspect_peer_chain.rs` lines 25-29 at `510d86f`). The
module comment says that the test suite asserts that the shipped configuration does not use it
(`probe.rs` lines 9-12 at `510d86f`), but no test names `PrintChain`: a search finds it only in `probe.rs`,
the example and the documents. Also, lines 134 and 178 at `510d86f` of `probe.rs` index the certificate with
no bound check, so a short certificate panics the probe. The shipped configuration calls
`.dangerous()` to install the WebPKI verifier (`crates/podssh-ws/src/tls.rs:310-314`), so a scan
cannot look for that word alone.

## Approach

1. Move `PrintChain` and its DER helpers into the example
   (`crates/podssh-ws/examples/inspect_peer_chain.rs`), and remove `pub mod probe;`. Keep each
   file under 500 lines.
2. Add the test that `probe.rs` (lines 9-12 at `510d86f`) promised: a scan of the source of `podssh-ws`,
   `podssh-relay`, `podssh-ssh` and `podssh-cli`, as `crates/podssh-cli/src/man/facts/tests.rs:13-37`
   reads source. It fails on `impl ServerCertVerifier` and on `set_certificate_verifier`.
3. In the example, replace the two unchecked indexes with `get`, so a short certificate gives
   "cannot read" and no panic.
4. Change in the same commit: `SECURITY.md` (lines 78-80 at `4e817d7`: the gap is closed),
   `docs/design.md` (line 104 at `4e817d7`), and `docs/STATUS.md` (Components, `podssh-ws`).

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

## Done

2026-10-09, in the commit "No crate carries a verifier that accepts each certificate".

- `PrintChain` and its DER helpers moved into `crates/podssh-ws/examples/inspect_peer_chain.rs`;
  crates/podssh-ws/src/probe.rs and `pub mod probe;` are gone, so no build of the library
  contains them.
- `crates/podssh-ws/tests/no_permissive_verifier.rs` (new) scans the `src` of each crate of the
  workspace (166 files; it fails when it reads 100 or fewer) for `ServerCertVerifier for` (an
  impl, however the trait is named), `set_certificate_verifier` and
  `ServerCertVerified::assertion`, and names each file. The shipped configuration installs its
  WebPKI verifier with `with_custom_certificate_verifier`, which the scan allows.
- In the example: the two unchecked indexes use `get`, and a field that a short certificate does
  not hold prints "cannot read". A defect found while moving it is repaired too: the walk to the
  `signatureAlgorithm` began at offset `0x30` (the tag) instead of 0, so it read whatever
  SEQUENCE sat at byte 48. Three tests in the example (`cargo test -p podssh-ws --example
  inspect_peer_chain`). Against the live relay it read the chain of three certificates:
  ecdsa-with-SHA256, ecdsa-with-SHA384 and sha256WithRSAEncryption.
- `SECURITY.md` (the design rule on TLS says so; the gap is gone), `docs/design.md`,
  `docs/ROADMAP.md` (M4: out of the library, not behind a feature) and `docs/STATUS.md`.
- Prove: `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws`: 143 passed, 0 failed, 2
  ignored. `cargo build -p podssh-ws --examples`: no warning. `grep -rn PrintChain
  crates/podssh-ws/src`: exit 1, no line. `cargo test --no-fail-fast`: 796 passed, 0 failed,
  7 ignored.
- Plant: `// impl rustls::client::danger::ServerCertVerifier for Planted {}` added to
  `crates/podssh-ws/src/tls.rs`: the scan failed and named that file; restored, it passed. The
  first form of the scan looked for `impl ServerCertVerifier` and would have missed that path.

# T-066: A `rustls::ClientConfig` that the caller supplies, for podbox

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:446-447` and 102-104. Read here
on `3ee70dc`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podbox is to use `podssh-relay`, and to keep its own TLS: the `ring` provider, and TLS 1.2 for
proxies that intercept TLS. `podssh-ws` always builds its own configuration with podssh's
provider, so podbox cannot.

## Premise

Read; the lines of `podssh-ws` are those of `c56792f`. `open_tls` builds the trust anchors and
the configuration on each call (`crates/podssh-ws/src/client.rs` lines 187-207 at `723d90b`, through
`crates/podssh-ws/src/tls.rs` lines 153-180 at `723d90b`). `WsClientConfig` carries only a `Trust`
(`client.rs` lines 47-61 at `723d90b`). The same `Trust` goes through `podssh-relay`: `Request`
(`crates/podssh-relay/src/open.rs:147-159`), `MintContext`
(`crates/podssh-relay/src/token.rs:94-99`), the pool refresh
(`crates/podssh-relay/src/pool.rs:177-185`), and the `https_*` functions (`client.rs` lines
261-287). podssh's configuration offers no ALPN (`tls.rs` lines 174-177 at `723d90b`), because the upgrade is
HTTP/1.1 only (`docs/relay.md:279`). The `tls12` feature of `rustls` is on in the workspace
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
7. Change `docs/design.md:484-488` and `docs/architecture.md` in the same commit.

## Decision

2026-10-09:

1. The type of step 1 is `Trust` itself, with a third variant `Trust::Caller(CallerConfig)`, made
   only by `Trust::caller`, which refuses ALPN. Each place that carries a `Trust` for a
   connection (`WsClientConfig`, `open_tls`, the `https_*` functions, and in `podssh-relay`
   `Request`, `MintContext` and the pool refresh) then carries the caller's choice with no new
   parameter, which is step 2 with no change there. Lost: a new type beside `Trust`, which
   changes about 60 places for the same result.
2. `CallerConfig` equals itself only (the same `Arc`): a `ClientConfig` has no equality, and two
   can differ in a verifier that no field shows.
3. The doctor of `podssh-ws` reports a caller's configuration as `????`: podssh cannot check its
   roots or its verifier. The doctor of `podssh-cli` matches the forms with a wildcard, so the
   binary names no caller form, as the scan of step 4 requires.
4. The tests reach the server by `open_tls`, which `connect` and the `https_*` functions call:
   those take the server name from the host, and a loopback server for a test name cannot be
   reached by that name on each host.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws -p podssh-relay
```

A new test connects through the caller form to a local TLS test server (as
`crates/podssh-ws/tests/hostname_verification.rs:55` starts one), with a caller configuration
whose only root is the test CA, which the default store does not hold. A configuration with the
ALPN `h2` is refused. podbox's own test with two clients is the exit check of M4 (T-085).
Planted defect: ignore the caller's configuration and build podssh's; the test CA is then
unknown, and the test fails.

## Done

2026-10-09, in the commit "A library can bring its own rustls configuration".

- `crates/podssh-ws/src/tls.rs`: `Trust::Caller(CallerConfig)` and `Trust::caller(config)`,
  which refuses a configuration that offers ALPN and says why; `tls::config_for(trust)`, the
  caller's configuration as it is or podssh's own. `open_tls` uses it, so `connect` and the
  `https_*` functions do too. `roots_for` refuses a caller's configuration (podssh cannot list
  its roots).
- `crates/podssh-ws/tests/caller_tls.rs` (new): through the caller form, `open_tls` reaches a
  loopback TLS server whose only root is a test CA, and reads what it sends; the control, the
  default store, fails on the unknown issuer; a configuration with `h2` and `http/1.1` is
  refused; the configuration is used as it is. `tests/no_permissive_verifier.rs`: the source of
  `podssh-cli` names no caller form.
- `docs/architecture.md` (the trust store) and `docs/design.md` say so.
- Prove: `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws -p podssh-relay`: 182
  passed, 0 failed, 4 ignored (155 of `podssh-ws`). `cargo test --no-fail-fast`: 808 passed,
  0 failed, 7 ignored.
- Plants, each restored: `config_for` building podssh's own for a caller: the server test failed
  (the test CA was unknown) and so did the test of the same configuration; a line naming
  `Trust::caller` in `crates/podssh-cli/src/proxy.rs`: the scan failed and named that file.

# T-067: TLS 1.2, for intercepting proxies

**Source:** `docs/STATUS.md` (Components, `podssh-ws`: "No TLS 1.2 (some intercepting proxies
need it)"); `docs/design.md:446-447`. podssh has not measured such a proxy.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Some proxies that intercept TLS speak only TLS 1.2. podssh offers only TLS 1.3, so the handshake
with such a proxy fails, also when its CA is in the trust store (`--ca-file`, `SSL_CERT_FILE` or
the system bundle).

## Premise

Read: the provider has two suites, both TLS 1.3 (`crates/podssh-ws/src/crypto/suites.rs`, line 55
at `0d3d13a`), and its comment says that TLS 1.2 suites are absent on purpose (lines 7-11 at `0d3d13a`). The configuration
enables both versions (`crates/podssh-ws/src/tls.rs:310-312`); rustls accepts that, because one
suite is usable, and then offers no TLS 1.2 suite (rustls 0.23.45, `with_protocol_versions` in
its `src/builder.rs`, read in the cargo registry). The `tls12` feature of `rustls` and
`tokio-rustls` is on (`Cargo.toml`). The provider has HMAC
(`crates/podssh-ws/src/crypto/hmac.rs`), AES-GCM and ChaCha20-Poly1305
(`crates/podssh-ws/src/crypto/aead.rs`), the ECDHE groups (`crates/podssh-ws/src/crypto/kx.rs`),
and RSA and ECDSA verification (`crates/podssh-ws/src/crypto/sign.rs`). The stand-in relay
requires TLS 1.3 (`scripts/fake-relay.py`, lines 426-427 at `0d3d13a`).

## Approach

1. Add TLS 1.2 suites: ECDHE-ECDSA and ECDHE-RSA, each with AES-128-GCM, AES-256-GCM and
   ChaCha20-Poly1305. Each needs a PRF (rustls has one on top of an HMAC provider) and a TLS 1.2
   AEAD: GCM with a 4-byte implicit salt and an 8-byte explicit nonce; ChaCha20-Poly1305 with
   the nonce of RFC 7905.
2. The TLS 1.3 suites stay first in `ALL_CIPHER_SUITES`, and `self_check`
   (`crates/podssh-ws/src/crypto/suites.rs:87-129`) checks the new suites too.
3. No CBC suite, no RSA key exchange, no SHA-1 suite.
4. Test each suite against software that podssh did not write: `openssl s_server -tls1_2` with
   one suite at a time in the container gate, and `scripts/fake-relay.py` with an option for TLS
   1.2 only.
5. The relay line of `doctor` names the version
   (`crates/podssh-relay/src/health.rs:103-106`, which `doctor` and `relay status` share); the live relay must still give TLS
   1.3.
6. Change the comment of `suites.rs`, `docs/architecture.md` (line 46 at `0d3d13a`), the Trust item of the manual
   (`crates/podssh-cli/src/man/facts.rs` lines 408-424 at `59b67e6`) and `docs/STATUS.md` in the same commit.

## Decision

Recommendation: offer both versions in each ClientHello, and let rustls choose. A server with
TLS 1.3 answers with 1.3, and the downgrade value of RFC 8446 section 4.1.3, which rustls
checks, stops a forced fall to 1.2. A second attempt with 1.2 after a failed 1.3 handshake lost:
that attempt is the downgrade that the value cannot show, and it doubles the time to fail. A flag
that turns 1.2 on lost: the hosts that need it see a failure first.

Taken, with these calls made in the work (2026-10-11). The PRF of each TLS 1.2 suite is rustls's
own over this provider's HMAC (`PrfUsingHmac`), and its records are `crypto/tls12.rs` on the
provider's AEAD. ECDSA with the other hash on each curve joined the verifiers: TLS 1.2 does not
bind the hash to the curve, and OpenSSL's `s_server` signed its key exchange with a P-256 key and
SHA-384, which failed as `BadSignature` until then; rustls's own providers map each scheme to both
curves with its hash. RSA PKCS #1 got its three schemes, for a TLS 1.2 key exchange; rustls takes
them for TLS 1.2 only. The checks are `s_server` with one suite at a time, natively and in the
gate, whose library step installs openssl and sets `PODSSH_TEST_OPENSSL`, so that a missing
openssl fails rather than skips. The stand-in relay's TLS 1.2 mode is a mode (`tls12`), so that
the cells of the harness and the faults of the gate start it as they start the others.

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

## Done

Done on 2026-10-11. Six TLS 1.2 suites follow the two of TLS 1.3
(`crates/podssh-ws/src/crypto/tls12.rs`): ECDHE_ECDSA and ECDHE_RSA, each with AES-256-GCM,
AES-128-GCM and ChaCha20-Poly1305, the PRF rustls's own over the provider's HMAC. The verifiers
gained ECDSA P-256/SHA-384 and P-384/SHA-256, and the handshake gained the three schemes of RSA
PKCS #1, for TLS 1.2. `self_check` checks that TLS 1.3 comes first, and that each TLS 1.2 suite is
ECDHE with a hash that its PRF can run. The stand-in relay has a mode `tls12`. The manual's Trust
item, `docs/architecture.md`, `SECURITY.md` and `docs/STATUS.md` say so, and the gate's library
step installs openssl and sets `PODSSH_TEST_OPENSSL`.

Prove, on Windows: `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws --test tls12`, 9
passed against OpenSSL 3.5.7's `s_server`, held to TLS 1.2 and to one suite at a time: each of the
six suites carried 20 lines each way, reversed by the server; a key exchange signed with PKCS #1
v1.5 (`-sigalgs RSA+SHA256`); TLS 1.3 from a server that speaks it; and no handshake with a CBC
suite alone. The whole crate with no C compiler, 173 passed, with the live handshake, which now
asserts that the live relay gives TLS 1.3. `tests/signatures.rs`: ECDSA with the other hash
verifies under its own algorithm only. `cargo test -p podssh-cli --test relay`: through the
stand-in in its mode `tls12`, `relay status` names TLS 1.2, and a trace and an SSH session work.
Planted, each caught by its check: a suite removed from the list (HandshakeFailure, the Prove's
plant), the P-256/SHA-384 verifier taken out of the mapping (`BadSignature`), and a wrong explicit
nonce of GCM (`BadRecordMac`). In the build image: the same 9 checks with Alpine's OpenSSL 3.5.9
and `PODSSH_TEST_OPENSSL` set; `scripts/interop.sh` 286 passed, 0 failed, with a stand-in relay
that speaks only TLS 1.2 carrying an OpenSSH session.

# T-068: Plain `ws://` to loopback, for tests only

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:485-486`.
**Category:** feature
**Milestone:** M4
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The tests of podbox, and a stand-in relay written in Rust, need a WebSocket session over plain
TCP on the loopback. `podssh-ws` always does TLS, so each such test needs a CA and certificates.

## Premise

Read: `connect` always calls `open_tls` (`crates/podssh-ws/src/client.rs` lines 162-184 at
`23b5d82`), and the upgrade takes the TLS stream type (the same file, lines 212-256 at
`23b5d82`). `RelaySession` is
generic over its stream (`crates/podssh-ws/src/session.rs:33`), so a session over `TcpStream`
is possible. `podssh-relay` gives the TLS type back (`Opened`,
`crates/podssh-relay/src/open.rs:161-166`). The tests use in-memory streams
(`crates/podssh-ws/tests/session.rs:34-36`) or local TLS servers
(`crates/podssh-ws/tests/hostname_verification.rs:55`). `dial::is_loopback` exists
(`crates/podssh-ws/src/dial.rs:133-141`).

## Approach

1. Add `connect_plain_loopback` behind a cargo feature, `plain-ws`, off by default. It gives
   `RelaySession<TcpStream>`.
2. It refuses each host that `is_loopback` refuses, and it uses no proxy: a token over plain TCP
   must not leave the host.
3. Make `upgrade` generic over the stream, so both paths share it.
4. The runners of `podssh-relay` (T-079, T-081) must take any stream type, so that podbox's
   tests can use them.
5. The binary never enables the feature; a check in the gate proves it.
6. Change `docs/design.md:485-486` in the same commit.

## Decision

Recommendation: the feature and the loopback check together. The feature keeps the code out of
the binary; the check holds in each build that enables the feature. The check alone lost: the
code would be in the binary, one mistake from use.

The session that built it (2026-10-09) made these calls:

- **The resolved address is checked too.** A name such as `x.localhost` goes through the resolver,
  which could answer with an address that is not the loopback; only a loopback answer is used, so
  the token stays on the host whatever the resolver says. The plant of the first check showed the
  second: 192.0.2.1 was still refused, as "resolved to no loopback address".
- **The check of the binary is a script**, `scripts/no-plain-ws.sh`, that reads the exit code of
  `cargo tree` on its own (the command of the Prove passes when `cargo tree` itself fails).
- **Step 4 is a step of T-079**, the node runner, which now says it; T-081 is the facade for
  podbox's production, which needs no plain stream.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --features plain-ws --test plain_loopback   # new
! cargo tree -p podssh-cli -e features | grep -q plain-ws
```

A local listener on 127.0.0.1 answers the upgrade with the bytes that `scripts/fake-relay.py`
writes for a `101` (lines 136-138 at `22c3b88`), and the session carries data both ways. The host 192.0.2.1
is refused with no connection attempt. The second command shows that the binary does not enable
the feature. Planted defect: remove the loopback check; the refusal test fails.

## Done

2026-10-09, in the commit "A plain ws:// session to the loopback, for tests".

- `crates/podssh-ws/src/plain.rs` (new, feature `plain-ws`, off by default):
  `plain::connect_loopback(host, port, path, token, timeout, idle)` gives a
  `RelaySession<TcpStream>`. It refuses a host that `is_loopback` refuses, before any connection;
  it uses only a loopback address of what the name resolves to; it uses no proxy; the path and the
  token meet the rules of `connect`. `upgrade` is generic over the stream, and both paths share
  it.
- `scripts/gate.sh`: the test of the feature, and `scripts/no-plain-ws.sh` (new), which fails
  when `cargo tree -p podssh-cli -e features` names `plain-ws`. `docs/development.md`,
  `docs/design.md` and T-079 (step 10) say so.
- Prove: `cargo test -p podssh-ws --features plain-ws --test plain_loopback`: 2 passed (the
  upgrade answered with the 101 of `scripts/fake-relay.py`, `hello` down and `ping` up, the token
  in its header; 192.0.2.1, `example.org`, 10.0.0.1, `[2001:db8::1]`, 0.0.0.0 and
  `localhost.example` refused at once). `sh scripts/no-plain-ws.sh`: exit 0. `cargo test
  --no-fail-fast`: 810 passed, 0 failed, 7 ignored.
- Plants, each restored: the loopback check removed: the refusal test failed; `features =
  ["plain-ws"]` on the dependency of `podssh-cli`: `scripts/no-plain-ws.sh` exited 1 and showed
  the feature.

# T-069: Typed session errors in `podssh-ws`

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:486-487`.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The methods of a relay session return `String` errors. A caller cannot tell a dead link from a
protocol error, a stalled write or an end with no Close, except by matching text. The reverse
runners and the retry rules (T-025) need these classes.

## Premise

Read; the lines of the files that this entry changed are those of `723d90b`. `send_binary` and
`send_text` (`crates/podssh-ws/src/session.rs` lines 86-94 at `23b5d82`), `send_close` (104-109),
`read_frame` (170-221) and `write` (223-228) return `Result<_, String>`; `watch_liveness`
returns a `String` (142-166). The callers keep or pass the text:
`crates/podssh-ssh/src/relay_stream.rs` lines 95-96 and 138-140 at `23b5d82` put it in `RelayEnd::Failed`;
`crates/podssh-cli/src/pipe/relay.rs:105-181` prints it; `podssh-transport` makes a write error
`TransportError::Unexpected` (crates/podssh-transport/src/socket.rs at `e8bbd4d` lines 104-113, 143, 161
and 185), and, since T-072, a read error `Aborted` with its text. Tests and the gate match the
text: `crates/podssh-ws/tests/session.rs` lines 108 ("continuation") and 172 ("without a
WebSocket Close"), and `scripts/interop-faults.sh:269` ("pings unanswered").
`WsError` exists (`crates/podssh-ws/src/error.rs:56-76`), but the session does not use it.

## Approach

1. Add `SessionError` to `crates/podssh-ws/src/error.rs` (96 lines; `session.rs` has 282):
   `Io` (the kind and the text), `Idle` (no data for the read limit), `WriteStalled` (the write
   limit), `Protocol` (a frame or a message that RFC 6455 forbids), `Dead` (from
   `watch_liveness`), `ClosedWithoutClose`, and `TooLarge` (the limit).
2. Each session method returns it; `watch_liveness` returns `Dead`.
3. `Display` gives the same text as now, so the tests and the gate still match.
4. The callers keep their behaviour: `RelayEnd::Failed` takes the error; `podssh proxy` keeps
   its exit codes; `podssh-transport` maps each class (T-073 uses them later). T-072, done
   first, keeps the text of a read error in `Aborted { detail }`; the class decides between
   `Aborted` and `Unexpected` (see Decision).
5. Record the change in `docs/STATUS.md` (Components) in the same commit.

## Decision

2026-10-09:

1. Each class keeps the text that the session gave before, and `Display` prints it: a message and
   the checks that read it do not change. `From<SessionError> for String` lets a caller that
   reports text keep its `?`, so `podssh proxy` needed no change.
2. `podssh-transport` maps each class to its retry rule (`socket::lost`): a frame or a message
   that RFC 6455 forbids, and a message over the limit, are `Unexpected` (never retried); each
   other class is a link that broke, `Aborted` (reconnect). The class is not carried in
   `TransportError`: its `retry` is what a runner needs, and the text is kept. Lost: a second
   error type inside `TransportError`.
3. A write that has no bytes for its masking key is `Io` (kind `Other`); a ping that cannot be
   sent keeps the class of that write, with its context; only unanswered pings are `Dead`.
4. `read_frame_over`, the reader of one stream that the tests script, keeps its `String`: it is
   not a method of a session.

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


## Correction

2026-10-31 (T-361): T-082 moved the codecs of `podssh-transport`, with their tests, into
`podssh-relay`, and the crate is gone: this Prove's `cargo test -p podssh-transport` runs as `cargo
test -p podssh-relay` since.

## Done

2026-10-09, in the commit "A session's failure has a class".

- `crates/podssh-ws/src/error.rs`: `SessionError` (`Io` with the kind, `Idle`, `WriteStalled`,
  `Protocol`, `TooLarge`, `Dead`, `ClosedWithoutClose`), each with its text; `context` adds a
  prefix and keeps the class. Each method of `RelaySession` returns it, and `watch_liveness`
  returns `Dead`.
- `RelayEnd::Failed` takes the error (`crates/podssh-ssh/src/relay_stream.rs`); an unexpected
  frame on the forward path is `Protocol`. `podssh-transport`: the seam `WsSession` takes the
  class (`adapt::SessionError`), and `WsSocket` maps it (see Decision).
- Tests: the tests of `crates/podssh-ws/tests/session.rs` that read the text assert the class too
  (`Protocol`, `Idle`, `ClosedWithoutClose`, `Dead`), and a new one: a write to a peer that never
  reads is `WriteStalled`. crates/podssh-transport/tests/socket.rs at `e8bbd4d`: each class has its retry.
- Prove: `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws -p podssh-transport`: 240
  passed, 0 failed. `cargo test --no-fail-fast` (`podssh-ssh` and `podssh-cli` among them):
  810 passed, 0 failed, 7 ignored. The gate of the commit (CI) runs `interop-faults.sh`,
  whose check still reads "pings unanswered".
- Plant: each class of `session.rs` made `Io`: five tests of `session.rs` and one of
  `control_frames.rs` failed.

# T-070: A SOCKS5 proxy for the egress

**Source:** yituorou/meatshell (an outbound SOCKS5 and HTTP proxy, GitHub #22) and
sleepinginsummer/agent-ssh-cli (a `socksProxy` for each connection, GitHub #21). Read in the
reports, not verified here. No SOCKS proxy was measured on a target host.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh speaks only HTTP CONNECT to a proxy. A host whose only way out is a SOCKS5 proxy, often
given as `ALL_PROXY=socks5h://...`, cannot reach the relay: podssh refuses the setting.

## Premise

Read, at `dab5669`: `HttpProxy::parse` refuses each scheme but `http`, with "proxy scheme
socks5:// is not supported; podssh speaks HTTP CONNECT to an http:// proxy"
(`crates/podssh-ws/src/dial.rs`, lines 53-63). `proxy_from_vars` reads `https_proxy`,
`HTTPS_PROXY`, `all_proxy` and `ALL_PROXY` (lines 163 and 184), and parses the first that is set
(line 192). `dial` makes the error `DialError::BadProxy` (line 232), which stops the failover at
once (`crates/podssh-relay/src/open.rs:70`) and gives exit 78 in `podssh proxy`
(`crates/podssh-cli/src/proxy.rs:278`). `doctor` reports it as `FAIL`
(`crates/podssh-cli/src/doctor/net.rs`, lines 101-107). Two tests assert the refusal:
`crates/podssh-cli/tests/doctor.rs`, lines 144-153, and `crates/podssh-ws/tests/dial.rs`, lines
50-58.

## Approach

1. A proxy type with two forms, HTTP and SOCKS5, in `dial.rs`; `ProxyChoice::Via` takes it
   (`crates/podssh-ws/src/dial.rs:31-40`). Parse `socks5://` and `socks5h://` with an optional
   `user:password@`, decoded as for HTTP (now `crates/podssh-ws/src/proxy.rs:177-195`).
2. The SOCKS5 exchange (RFC 1928): offer the method 0x00, and 0x02 only with credentials; the
   user and password of RFC 1929, each of 1 to 255 bytes; CONNECT with the address type 3, the
   host name, so the client needs no DNS (`crates/podssh-ws/src/dial.rs:6-9`). Read exactly the
   length of the reply: the bytes after it belong to TLS, as `read_head_exact` keeps them
   (`:297-320`). Bound each step.
3. When the proxy answers 0x08 (address type not supported), resolve the name in podssh's own
   order (pinned, system, DNS over HTTPS), and try once with the address.
4. Map each answer to the HTTP case that `another_host_may_help`
   (`crates/podssh-relay/src/open.rs:62-84`) and the exit codes of `podssh proxy`
   (`crates/podssh-cli/src/proxy.rs:274-287`) already treat: a refused user or password as 407
   (the same for each host: stop); 0x02 (not allowed) as 403; 0x03, 0x04 and 0x05 as 502.
5. Credentials never in output: `Display` shows the host and port only (now
   `crates/podssh-ws/src/proxy.rs:70-75`).
6. `doctor` names the SOCKS5 proxy, and its proxy checks
   (`crates/podssh-cli/src/doctor/net.rs:201-243`) work for both forms. The two tests above
   plant `ftp://` and `socks4://` instead; `socks4` and `socks4a` are refused by name.
7. Change the proxy variables in VARIABLES (`crates/podssh-cli/src/man/facts.rs:46-55`),
   `docs/architecture.md` and `docs/cli.md` in the same commit.

## Decision

Recommendation: send the host name for `socks5://` too, with the 0x08 fallback above. curl
resolves the name on the client for `socks5://`, but the hosts that podssh is made for often
have no DNS (`docs/STATUS.md`, "In the operator's real sandboxes, measured"), so a local lookup
fails first there. Following curl lost for that reason.

Decided in the work (2026-10-11):
- The answer to the user and password is taken with the version 1 of RFC 1929, or with SOCKS's
  own 5, which a few servers send; curl reads the status alone. Refusing a 5, as Go's x/net and
  PySocks do, lost: the status decides, and the hosts that podssh is for do not choose their
  proxy.
- The iroh road and `podssh ts` refuse a SOCKS5 proxy by name, as their dials (iroh's relay
  client, the fork's DERP dial) speak CONNECT only; a SOCKS5 dial in each is T-280 and T-281. A
  quiet direct connection in its place lost: such a host often has no other way out, and the
  setting would be ignored with no word.
- `podssh status` gives the proxy's kind (`http` or `socks5`), and `relay status`, `doctor` and
  `ping` say `SOCKS5 CONNECT` for a request through one, so that the protocol of the egress is
  known with no connection.

## Prove

```sh
export CARGO_BUILD_JOBS=4
CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws --test dial
cargo test -p podssh-cli --test doctor
sh scripts/dev.sh check   # interop: through the SOCKS5 server of OpenSSH (ssh -D)
```

A stand-in on 127.0.0.1, as in `crates/podssh-ws/tests/dial.rs:128-150`, checks the bytes: the
greeting, the user and password, and a CONNECT with the address type 3 and the relay's name. In
the gate, the SOCKS5 server of OpenSSH (`ssh -N -D 127.0.0.1:PORT` to the test server) carries a
session to the stand-in relay, and a password in the proxy URL never appears in the output.
Planted defect: send the address (type 1); the stand-in refuses it, and the test fails.

## Done

2026-10-11, in the commit that closes this entry.
- `Proxy` (`crates/podssh-ws/src/proxy.rs`) has two kinds: HTTP CONNECT (`http://`, or a bare
  `host:port`; port 80) and SOCKS5 (`socks5://` and `socks5h://`; port 1080); `HttpProxy` is its
  old name. The user and the password are split before they are decoded, so an escaped `:` stays
  in the user; for SOCKS5 each has 1 to 255 bytes. `socks4` and `socks4a` are refused by name.
- `crates/podssh-ws/src/socks5.rs`: the greeting offers 0x00, and 0x02 only with credentials;
  RFC 1929; CONNECT with the address type 3 and the name, so this host needs no DNS; the reply
  read to exactly its end; on reply 8, one more try with an address that podssh resolves in its
  own order; each step within the dial's limit. A refused password, or no method that podssh
  offered, is a 407; reply 2 a 403; replies 1 and 3 to 6 a 502; reply 7 and a broken answer a
  fault of the protocol. So the failover and the exit codes treat SOCKS5 as HTTP.
- The iroh road and `podssh ts` refuse a SOCKS5 proxy by name (T-280, T-281). `doctor` names
  the SOCKS5 proxy; `podssh status` gives `kind`; `relay status`, `doctor` and `ping` say
  `SOCKS5 CONNECT`. The manual's VARIABLES and its note on `status`, `docs/architecture.md`,
  `docs/cli.md` and `README.md` say it.
- Native, Windows 11: `CC=/nonexistent cargo test -p podssh-ws`, each suite passed: `--test
  socks5` 9 (the greeting, RFC 1929 and CONNECT by name, byte for byte, through a stand-in; each
  reply mapped; a bound name and an IPv6 address read to their end; one more try with an address
  on reply 8; an answer to the password with the version 5), `--test dial` 14. `cargo test -p
  podssh-cli --test doctor` 10, `--test status` 5, `--test ping` 11, `--test relay` 9, `--lib`
  204; `cargo test -p podssh-relay --lib` 20; `cargo test -p podssh-iroh --features test-relay
  --test relays` 7; `cargo test -p podssh-ts --test config` 8. `cargo clippy --all-targets` with
  `-D warnings`: the default crates, and with the feature `iroh-test`. `cargo test --workspace
  --no-fail-fast`: 1443 passed, 0 failed, 49 ignored, and no scratch left.
- Planted, then restored: the name sent as the address 127.0.0.1 (type 1) failed
  `a_tunnel_goes_by_name_and_needs_no_dns` and the test of reply 8 (7 passed, 2 failed).
- `scripts/interop-socks.sh`, which `scripts/interop-faults.sh` runs in the build image:
  OpenSSH's `ssh -D` as the SOCKS5 proxy carries `podssh ssh` to the stand-in relay and `relay
  status` to its `/health`, ssh's own `-vv` log shows each request with the relay's name, and the
  password of the proxy URL appears in no output. In CI at `385486f` (run 38111621670): the step
  `release`, interop 288 passed, 0 failed; the step `lint`, clippy with the feature `ts`, passed.

# T-242: The frame decoder accepts a length that is not in the minimal form

**Source:** found by the writer of `TODO/repo.md` (2026-10-08) in
`crates/podssh-ws/src/frame.rs`; RFC 6455 sections 5.2, 7.1.7 and 7.4.1. Confirmed here on
`3ee70dc` by reading the code.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

RFC 6455 section 5.2 says that a frame must give its payload length in the minimal number of
bytes. podssh's decoder accepts a 16-bit length below 126 and a 64-bit length below 65536. A
peer that sends one breaks the protocol, and podssh reads the frame as valid.

## Premise

Read on `3ee70dc`, the defect holds. `frame::decode` reads the 16-bit length with no lower
bound (`crates/podssh-ws/src/frame.rs:175-190`). It reads the 64-bit length and checks only the
size of the platform and the forward cap of 262144 bytes (lines 166-186 at `22c3b88`); that cap also refuses
a value with its top bit set, which section 5.2 forbids too. `frame::encode` writes the minimal
form (`:101-109`). The tests check the encoder at the boundaries 125, 126, 65535 and 65536
(`crates/podssh-ws/tests/rfc6455.rs:92-117`), and no test decodes a length that is not
minimal. The only caller in the code is `next_event`, for the frames of the relay
(`crates/podssh-ws/src/client.rs:422-436`). The stand-in relay writes the minimal form
(`scripts/fake_ws.py:21-29`); the frames of the real relay were not checked for it.

## Approach

1. In `frame::decode`, refuse a 16-bit length below 126 and a 64-bit length below 65536 with a
   `WsError::Frame` that names the rule (`crates/podssh-ws/src/frame.rs:175-215`), before the
   payload is copied.
2. A client that receives such a frame fails the WebSocket connection (RFC 6455 section 7.1.7):
   it sends a Close with 1002, a protocol error (section 7.4.1), and then closes the TCP
   connection. Since T-063 the session sends that Close for each error of the decoder
   (`crates/podssh-ws/src/session.rs:335-342`), so this entry needs no new path.
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

## Done

2026-10-13.

- `frame::decode` (`crates/podssh-ws/src/frame.rs`) refuses, as soon as the length field is read
  and before the masking key and the payload, a 16-bit length below 126 and a 64-bit length below
  65536, with a `WsError::Frame` that names RFC 6455 5.2 and the minimal form. The check is in
  `decode`, so it holds for `Role::Client` and `Role::Server` alike. A 64-bit length with its top
  bit set stays refused by the forward cap, as before.
- The session needed no change: since T-063 it fails the connection with a Close 1002 after each
  error of the decoder (`RelaySession::read_frame`, through `fail`).
- `crates/podssh-ws/tests/frame_lengths.rs` (new), on bytes written from the RFC, each in both
  directions (a server's frame unmasked, a client's masked with the key of section 5.7):
  `a_16_bit_length_below_126_is_refused` (125, 1 and 0) and
  `a_64_bit_length_below_65536_is_refused` (65535, 126, 125 and 0), each from the whole frame and
  from its header alone, so that nothing waits for a payload that it will refuse; the controls
  `the_16_bit_form_from_126_is_accepted` (126 and 65535) and
  `the_64_bit_form_from_65536_is_accepted` (65536 and the forward cap); and
  `a_length_not_in_the_minimal_form_fails_the_connection_with_1002`: through a session, a frame
  in the minimal form is read first, then the same payload with the marker 126, or 127, ends the
  read with `SessionError::Protocol` and a Close 1002 goes out.
- `docs/STATUS.md` (Components, `podssh-ws`).
- Prove, Windows 11: `cargo test -p podssh-ws --test frame_lengths`, 5 passed;
  `CC=/nonexistent CXX=/nonexistent cargo test -p podssh-ws`, 212 passed, 0 failed (the property
  tests of T-202 among them). Planted, both checks turned off: the two refusal tests and the
  session test failed, and the two controls passed; restored, 5 passed.
- Nothing waits for T-251. The frames of the real relay were not read for the minimal form; a
  live test that met a frame that is not minimal would now end with a Close 1002.

# T-265: A silent first address holds the whole of a direct dial

**Source:** `podssh doctor` in a build with the feature `iroh` (T-162),
2026-10-09: the line of n0's first relay failed after 15 s, where curl
reached the same relay at once.
**Category:** defect
**Milestone:** M6
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A direct connection resolves its host and tries each address in turn, but
the first address gets the whole time limit. An address that never answers,
as an IPv6 address with no route can, uses up the limit, and the next
address is never tried. A host with broken IPv6 then fails each direct dial
to a host whose first address is IPv6.

## Premise

Measured on this machine, 2026-10-09: `aps1-1.relay.n0.iroh.link.` resolves
to an IPv6 and an IPv4 address; curl got `/ping` over IPv4 in 0.68 s, and
the doctor's dial timed out after 15 s on the IPv6 address. Read, at
`fc01756`: connect_direct of crates/podssh-ws/src/dial.rs awaits each
address with the dial's whole deadline, in the order of the resolver.

## Approach

1. Start each address 250 ms after the one before, or at once when the one
   before failed (RFC 8305's attempt delay); the first that connects wins,
   and the others stop.
2. Let the two families take turns, the first family first (RFC 8305,
   section 4), so a family that does not work costs one delay.
3. A test with a name pinned to a silent documentation address, then the
   loopback: the dial connects in well under the limit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test dial_race --test dial
```

The dial connects to the second address within 3 s; a planted attempt delay
of 600 s (each address in turn, as before) waits for the silent address and
fails.

## Done

2026-10-09, with T-162.

- `crates/podssh-ws/src/dial.rs`: the attempts of a direct dial start
  `ATTEMPT_DELAY` (250 ms) apart, or at once after a failure, in the order
  of `interleave`; the first that connects wins, and dropping the set stops
  the others.
- Prove, native: `cargo test -p podssh-ws --test dial_race --test dial`: 16
  passed. `192.0.2.1`, then the loopback: connected in 0.27 s. Planted, an
  attempt delay of 600 s: the dial waited for the silent address until its
  limit of 10 s, and the test failed.
- `podssh doctor` in a build with the feature `iroh`: the line of n0's first
  relay now passes, `/ping` in 576 ms over IPv4.

# T-311: podssh in a Claude Code cloud container: an agent proxy, and an egress that intercepts TLS

**Source:** the operator, 2026-10-30: a cloud session's own container is
"another unique scenario: how would podssh work here".
**Category:** measurement
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The testers' sandboxes are of several kinds (`docs/target-environment.md`). A
Claude Code cloud container is one more: its documented way out is a local
agent proxy (`HTTPS_PROXY` on the loopback) that re-terminates TLS with a CA
of its own, and its documentation says that WebSocket upgrades, ports other
than 443 and raw TCP do not go through. Nobody had measured podssh there.

## Premise

Read: the container's description of its proxy (outside the repository)
names the CA bundle in `SSL_CERT_FILE` and the other CA variables, and lists
the WebSocket upgrade as not supported. Not measured: what podssh meets.

## Approach

1. `podssh doctor`, with and without `SSL_CERT_FILE`.
2. The certificate that arrives for the relay and for github.com, through the
   proxy and directly.
3. `podssh proxy github.com 22`, and `podssh ssh -T git@github.com` with a
   throwaway key, through the relay; the same with `--direct`.
4. The results in `docs/STATUS.md` and `docs/target-environment.md`; an
   entry for each defect found.

## Prove

The commands of the approach, with their results in `docs/STATUS.md`.

## Done

2026-10-30, with `target/debug/podssh` built in the container at
`9b6dda2`; the results are in `docs/STATUS.md` ("In a Claude Code cloud
container, measured") and `docs/target-environment.md`.

- `podssh doctor`: 31 ok, 0 FAIL, 0 ????, exit 0: the relay's four hosts with
  TLS 1.3 and a verified chain, a token minted, github.com:22 through the
  relay with GitHub's ED25519 key. With `SSL_CERT_FILE` unset: 32 ok.
- Through the proxy, the relay's own chain (Google Trust Services WE1), and
  for github.com a certificate of the proxy's CA; direct TLS on port 443, a
  certificate of the egress's CA.
- `podssh proxy github.com 22`: GitHub's banner. `podssh ssh -T
  git@github.com` with a throwaway key: `Permission denied (publickey)`, 255.
- `podssh ssh --direct`: 255 with `Connection reset by peer`, after the
  proxy's `200` (T-317).
- The defects found: T-313, T-314 and T-315 in the tests, T-316, T-317 and
  T-318 in podssh; the research of the same day added T-319 and T-320.

# T-315: The live handshake tests dial the relay directly, past `HTTPS_PROXY`

**Source:** the native tests of 2026-10-30 in a Claude Code cloud container
(T-311): four tests of `crates/podssh-ws/tests/live_handshake.rs` failed with
`InvalidCertificate(UnknownIssuer)`.
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The tests open TCP to the relay themselves and check its chain against the
compiled-in roots. Where an egress intercepts direct TLS, the chain is the
egress's, and podssh's verifier refuses it, as it must: the tests fail for a
fact of the place, not of podssh. podssh itself goes through `HTTPS_PROXY`,
which there carries the relay's own chain.

## Premise

Measured on 2026-10-30: direct TLS to the relay presents a certificate of
"Egress Gateway SDS Issuing CA (production)"; through the agent proxy, the
relay's own chain (Google Trust Services WE1).

## Approach

1. The tests reach the relay as podssh does: through the proxy that
   `HTTPS_PROXY` names, when one is set (`podssh_ws::dial::dial` with
   `ProxyChoice::FromEnvironment`), and directly else, as before.
2. No skip for a chain of another issuer: a broken store of roots gives the
   same error, and these tests exist to find it. With no proxy, behind an
   egress that intercepts TLS, they fail, as podssh itself would.

## Prove

```sh
cargo test -p podssh-ws --test live_handshake
```

The tests pass in the container through its proxy, with the relay's own
chain; in CI they pass with no proxy, as before.

## Done

2026-10-30. The dial of `crates/podssh-ws/tests/live_handshake.rs` is
`podssh_ws::dial::dial` with `ProxyChoice::FromEnvironment`: through the
proxy that `HTTPS_PROXY` names, else directly, as before.

- In the container, through its proxy: the 4 tests passed with the relay's
  own chain, in the run of the whole suite; before, they failed with
  `InvalidCertificate(UnknownIssuer)` against the egress's chain.
- For CI, with no proxy: the run of this commit.

# T-316: `no_proxy` with CIDR blocks: an address inside a listed block goes through the proxy

**Source:** the research of 2026-10-30 on the proxies of sandboxes, and the
`NO_PROXY` of a Claude Code cloud container (T-311), which lists
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` and
`169.254.0.0/16`.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`no_proxy_matches` (`crates/podssh-ws/src/dial.rs`) compares names only: an
entry `10.0.0.0/8` matches the host `10.0.0.0/8`, and no address. So
`podssh ssh --direct 10.1.2.3` and a tailnet address in `100.64.0.0/10` go to
the proxy, where curl, Go and Python's requests go directly.

## Premise

Read: curl matches an address against a CIDR entry since 7.86, and Go's
`httpproxy` and Python's `requests` do too; wget does not. Not read here: a
client that reads CIDR entries for names (none of them does).

## Approach

1. An entry `ADDR/BITS` (IPv4 or IPv6) matches a target that is an address
   inside the block; a name is never resolved for the match.
2. The man page's note on `no_proxy` and `docs/cli.md` say it; `doctor`'s
   line names the entry that matched.

## Prove

```sh
cargo test -p podssh-ws --test dial
cargo test -p podssh-ts --test derp_proxy
cargo test -p podssh-cli --test doctor
```

A unit test for each form: `10.1.2.3` in `10.0.0.0/8`, `100.100.1.1` in
`100.64.0.0/10`, `fd7a::1` in `fd7a::/16`, `10.1.2.3` not in `10.0.0.0/16`
of another block, a name never in a block. The Tailscale fork reads the
list for the node, and must agree case for case. Planted: the CIDR test
removed from the matcher; the tests fail.

## Done

2026-10-30. A block `ADDR/BITS`, IPv4 or IPv6, matches each address inside
it, and an IPv4 address written as IPv6 (`::ffff:10.1.2.3`) as the IPv4
address; a name never matches a block, and a block with bits out of range
or no address matches nothing (`crates/podssh-ws/src/dial.rs`,
`no_proxy_entry` and `in_block`). The Tailscale fork reads the list by the
same rules (`vendor/tailscale-rs/ts_http_util/src/proxy.rs`, patch 0023),
and the test of their agreement has nine cases of blocks more. `doctor`
names the entry that kept the relay host off the proxy: "NO_PROXY's entry
10.0.0.0/8 excludes 10.1.2.3". The manual's row of `no_proxy`,
`docs/architecture.md` and `docs/tailscale.md` say it.

- Linux, 2026-10-30: `cargo test -p podssh-ws --test dial`, 15 passed;
  `cargo test -p podssh-ts --test derp_proxy`, 6 passed; `cargo test -p
  podssh-cli --test doctor`, 11 passed (2 ignored, live);
  `--lib man::` 35 and `--test man_page` 10 passed. clippy of the three
  crates and rustfmt clean.
- Planted: the block test removed from podssh-ws's matcher, the test of
  blocks failed ("10.1.2.3 is inside a block of ..."); removed from the
  fork's, the agreement failed ("10.0.0.0/8" for "10.1.2.3"); restored, each
  passed.

# T-317: A proxy that answers `200` to CONNECT and then carries no SSH: `doctor` says that plain ssh can leave, and `--direct` ends with a bare reset

**Source:** T-311, 2026-10-30: through the container's agent proxy, `CONNECT
github.com:22` gets `200 Connection Established`, then the server's banner
never comes (the proxy waits for TLS); `podssh doctor` printed
"CONNECT github.com:22: allowed ... plain ssh can leave this way too", and
`podssh ssh --direct` ended with "Connection reset by peer", 255.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A `200` proves that the proxy took the CONNECT, not that the tunnel carries
bytes as they are. A proxy that intercepts TLS for a name waits for a
ClientHello and drops SSH. `doctor` then gives wrong advice, and `--direct`
gives no reason.

## Premise

Measured on 2026-10-30: `CONNECT github.com:22` and `CONNECT
github.com:443` get 200, and nothing comes in 15 s; `CONNECT
ssh.github.com:443` gets 200, then a reset. Through the relay, the same
host's banner comes at once.

## Approach

1. `doctor`'s check of port 22 reads the server's first bytes after the 200,
   for 5 s: `SSH-2.0-` is "plain ssh can leave this way"; nothing, or a
   reset, is "the proxy took the CONNECT and carried no SSH: it may expect
   TLS; use the relay".
2. `podssh ssh --direct`: a reset or silence before the banner, after a 200,
   names the proxy and the same cause, with the advice to leave `--direct`
   out.

## Prove

```sh
cargo test -p podssh-cli --lib doctor::net
cargo test -p podssh-cli --test direct_proxy
```

Against a stand-in proxy that answers 200 and then sends nothing, and one
that resets, the line and the message name the cause; against one that
carries the bytes, the line says that plain ssh can leave. Planted: the 200
alone trusted; the tests fail.

## Done

2026-10-30. `doctor` reads the first bytes of github.com port 22 for 5 s
after the proxy's 200, and on the direct road too: only a line that starts
with `SSH-` says that plain ssh can leave; silence, a close, a reset or other
bytes say that the proxy took the CONNECT and carries no SSH
(`crates/podssh-cli/src/doctor/net.rs`, `no_ssh_banner`). `podssh ssh
--direct` through a proxy watches for the first byte that comes back
(`crates/podssh-cli/src/ssh/transport.rs`, `Heard`); a session that fails with
none adds the line that names the proxy and the relay as the way
(`crates/podssh-cli/src/ssh/mod.rs`). The manual's note of `doctor` and the
help of `--direct` say it.

- Linux, 2026-10-30: `cargo test -p podssh-cli --lib`, 349 passed (2 new:
  a banner, a banner after other lines, a TLS alert, a close, a reset, and
  silence bounded by 5 s); `--test direct_proxy`, 3 passed (a stand-in that
  resets after its 200, one that stays silent, ended within the connect
  timeout of 3 s, and one that sends a banner, which is not blamed);
  `--test doctor` 11, `--test man_page` 10, `--test ssh_args` 26.
- Planted: the 200 alone trusted in `doctor`, both new unit tests failed;
  the proxy never named by `--direct`, the reset and silent tests failed.
- Live, in a Claude Code cloud container through its agent proxy: `doctor`
  says "github.com:22: 127.0.0.1:35713 took the CONNECT (140 ms), then
  nothing came in 5 s: it carries no SSH, and may expect TLS", 31 ok; `podssh
  ssh --direct git@github.com` ends after 2 s with the reset and then "the
  proxy 127.0.0.1:35713 took the CONNECT, and no byte of an SSH server came
  back: it may expect TLS and carry no SSH. Without --direct, the relay
  carries SSH over HTTPS", 255.

# T-318: A relay's name pinned to a loopback address goes to the proxy

**Source:** the native tests of 2026-10-30 (T-313): `--relay-host
relay-a.test:PORT --relay-addr relay-a.test=127.0.0.1` with `HTTPS_PROXY`
set sends `CONNECT relay-a.test` to the proxy.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

podssh never sends a loopback target to a proxy, as the proxy's loopback is
not this host's (`crates/podssh-ws/src/dial.rs`, `proxy_from_vars`). A name
that `--relay-addr` pins to a loopback address is such a target, but the
choice reads the name only, so the proxy gets a name that it cannot reach.

## Premise

Read: the manual says that through a proxy podssh sends names and needs no
DNS, and that `--relay-addr` is used with no proxy. A pin to a loopback
address is only for a relay on this host, which no proxy can reach.

## Approach

1. A relay host whose pinned addresses are all loopback addresses goes with
   no proxy, as a loopback name does; a pin to another address keeps today's
   rule.
2. The manual's note on `--relay-addr` says it.

## Prove

```sh
cargo test -p podssh-ws --test dial_pinned
```

A unit test: a pin to 127.0.0.1 gives no proxy; a pin to 203.0.113.5 keeps
the proxy. Planted: the pin not read; the first test fails.

## Done

2026-10-30. `proxy_from_vars` takes a name whose pins are all loopback
addresses as a loopback target, and gives it no proxy; a name with a pin to
any other address, or with none, keeps the proxy
(`crates/podssh-ws/src/dial.rs`, `pinned_to_loopback`). The help of
`--relay-addr` says it.

- Linux, 2026-10-30: `cargo test -p podssh-ws --test dial_pinned`, 1 passed
  (a pin to 127.0.0.1; to `::1` and 127.0.0.2, with the name's case and
  final dot; to 203.0.113.5; one pin on loopback and one not; no pin);
  `--test dial` 15; podssh-cli's `--lib man::` 35, `--test man_page` 10,
  `--test ssh_args` 26; clippy and rustfmt clean.
- Planted: the pin not read; the test failed ("pinned to 127.0.0.1");
  restored, it passed.
- Later, 2026-10-30: the gate failed at `472adff`, in its steps m6 and
  release. The runs of `m6_exit` and `faults` and the interop checks
  `faults.proxy_502.failover`, `roost.cut` and `upgrade.cut` go through a
  stand-in proxy whose map names relay-a.test, and pinned that name to the
  loopback too; since this entry the pin sent them around the proxy, and no
  fault came. They pin no address now (`scripts/interop-faults.sh`,
  `scripts/interop-roost.sh`, `scripts/interop-upgrade.sh`,
  `crates/podssh-cli/tests/m6_exit.rs`, `crates/podssh-cli/tests/faults.rs`),
  and the runs of `m6_exit` and `faults` clear the machine's proxy
  variables first: a cloud container's `https_proxy` is read before the
  test's `HTTPS_PROXY`, and here sent them to the container's proxy.

# T-320: A `407` names the proxy's authentication scheme

**Source:** the research of 2026-10-30 on the proxies of sandboxes: Go,
wget, requests and reqwest send Basic only, curl also NTLM and Negotiate,
and enterprise proxies ask for each of them.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

podssh sends Basic credentials from the proxy URL, and on a `407` does not
read `Proxy-Authenticate`: a user behind an NTLM or Negotiate proxy reads
that the proxy refused, with no reason that podssh could have given.

## Premise

Read: RFC 9110, section 11.7.1: a `407` carries `Proxy-Authenticate` with
the schemes that the proxy accepts. Not measured: a real NTLM proxy.

## Approach

1. On a `407`, the message names each scheme of `Proxy-Authenticate`, and
   says which podssh can use (Basic, from the URL's user and password).
2. `doctor`'s proxy line says the same.

## Prove

```sh
cargo test -p podssh-ws --test dial
```

Against a stand-in proxy that answers `407` with `Proxy-Authenticate: NTLM`
and `Negotiate`, the message names both and says that podssh sends Basic
only. Planted: the header not read; the test fails.

## Done

2026-10-30. On a `407`, the reason names each scheme of the
`Proxy-Authenticate` headers, once each and in order, two challenges in one
header and a comma inside a quoted parameter included, and says what podssh
can give: with a proxy that takes no Basic, that podssh sends Basic only;
with Basic and no user in the URL, how to give one; with Basic and the
URL's user and password sent, that the proxy refused them
(`crates/podssh-ws/src/proxy_auth.rs`, from `connect_via` in
`crates/podssh-ws/src/dial.rs`). `doctor`'s CONNECT lines print the same
error.

- Linux, 2026-10-30: `cargo test -p podssh-ws --test dial`, 16 passed (NTLM
  and Negotiate in two headers; Basic with a quoted realm and Digest in one,
  with and without the URL's credentials; a 407 with no header); `cargo test
  -p podssh-ws`, 214 passed; clippy and rustfmt clean.
- Planted: the header not read; the test failed; restored, it passed.
- Not measured: a real NTLM proxy.

# T-324: `doctor` tells the three failures of the upgrade apart, and samples each probe

**Source:** GitHub #54 (Nemo-010, 2026-10-30), with its comment on samples.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

`doctor` gives one verdict for the WebSocket upgrade and one time for each
probe. A refused upgrade, an answer of 101 with a wrong
`Sec-WebSocket-Accept`, and a connection that dies after a valid 101 are
three failures with three ways out, and one sample cannot tell a path that
refuses from one that was slow, nor a steady path from a lossy one.

## Premise

- Read: the proxy's probes give one time each
  (`crates/podssh-cli/src/doctor/net.rs`, `through_proxy`), and the relay's
  checks one verdict for the upgrade and one SSH handshake
  (`crates/podssh-cli/src/doctor/relay_checks.rs`).
- Read: since T-317 the probe of port 22 reads the server's banner after the
  200; nothing else reads what the path does to a stream.
- Read (#54's comment): the best of nine samples or more is the path's floor,
  the median its cost, the 95th percentile what a keystroke sometimes pays,
  and the share of timeouts and resets its loss. Not measured here.

## Approach

1. The upgrade's verdict, three ways: not 101 (with the status and the
   first line of the body), 101 with a wrong `Sec-WebSocket-Accept`, and a
   connection that dies within 5 s after a valid 101.
2. Each probe that connects runs at least nine times over at least a
   second, and its line gives best, median, 95th percentile, loss (timeouts
   and resets counted apart) and jitter; `--json` the same fields.
3. A bound on the whole: `doctor` stays under a minute on a path that
   answers.

## Decision

- Only the probes of TCP are tried nine times: each `CONNECT` through the
  proxy, and `direct TCP`. The relay's `/health`, its upgrade and the SSH
  handshake stay one each: each is a request to the relay's Worker, on its
  operator's quota, and a session to GitHub, and nine of each in each run
  would multiply that load for a time that the `CONNECT` to the relay's
  host already gives. Lost: the upgrade sampled too (#54's comment: the loss
  tells a refused upgrade from a dropped one), as its three verdicts tell
  those apart at one try.
- A first try that timed out ends the probe; a later try waits four times
  the first try's time, from 3 s to 8 s; and no try starts that could end
  more than 10 s after the first began
  (`crates/podssh-cli/src/doctor/samples.rs:129`). Lost: nine tries always,
  72 s for one probe on a path that does not answer; one short bound for
  each try, which counts the tries of a slow path as lost.
- A refusal (the proxy's `403`, a port that refuses) is an answer, not a
  loss, as #54's comment counts timeouts and resets. Lost: a refusal counted
  as a loss, which would call a strict proxy lossy.
- The banner of port 22 is read on the first connection that opened, held
  while the other tries run: no tenth connection.
- The meaning of a wrong accept is podssh-ws's
  (`crates/podssh-ws/src/handshake.rs:211`), so `podssh ssh` says it too; the
  death after a valid 101 is doctor's
  (`crates/podssh-cli/src/doctor/relay_checks.rs:212`), as a session of
  `podssh ssh` already names the relay's end.

## Prove

```sh
cargo test -p podssh-cli --test doctor
cargo test -p podssh-cli --test doctor_upgrade
cargo test -p podssh-cli --lib doctor::
cargo test -p podssh-ws --test rfc6455
```

Against a stand-in relay that answers 403 (`scripts/fake-relay.py`, mode
`refuse:403`), one that answers 101 with a wrong accept (`badaccept`), and
one that closes after a valid 101 (`hangup:200`), each line names its own
failure. Against a stand-in that drops one probe in three, the loss reads
33 %. Planted: one verdict for the three; the test fails.

## Correction

2026-10-30. Item 1 was met in part before this entry: `check_response`
gives an answer other than 101 its status and its text
(`crates/podssh-ws/src/handshake.rs:185` says "if status != 101 {"), and a
101 with a wrong or no `Sec-WebSocket-Accept` its own error, and the
forward line carries each (`crates/podssh-cli/src/doctor/relay_checks.rs:158`).
Measured against the stand-in relay before the change: a wrong accept read
"Sec-WebSocket-Accept was ..., expected ...", with nothing of what it means,
and a valid 101 that the stand-in ended 200 ms later read "the connection
closed unexpectedly (the relay connection failed: peer closed connection
without sending TLS close_notify ...)", which named neither the 101 nor the
cut. What was left of item 1: the meaning of a wrong accept, and the third
failure. The Prove names the new test `doctor_upgrade`, which runs the
stand-in relay, and the test of podssh-ws.

## Done

2026-10-30. Each probe of TCP in `doctor` (each `CONNECT` through the
proxy, and `direct TCP`) is tried nine times, 125 ms apart
(`crates/podssh-cli/src/doctor/samples.rs`), and its line gives the best
time, the median, the 95th percentile, the jitter and the loss, the
timeouts and the other breaks apart, with each refusal counted as an
answer; `--json` gives the same as `samples` (`tries`, `connected`,
`best_ms`, `median_ms`, `p95_ms`, `jitter_ms`, `timed_out`, `broke`,
`refused`, `ms`). A 101 with a wrong or no accept says that something
between answered in the relay's place; a valid 101 after which the
connection ends with no Close says that the upgrade passed, when the
connection ended, and that something between drops the stream after the
upgrade. The stand-in relay has two modes for them, `badaccept` and
`hangup:MS`. The manual and `docs/cli.md` say it.

- Linux, 2026-10-30: `cargo test -p podssh-cli --lib doctor::`, 27 passed
  (the summary of nine tries, a lossy path's 33 %, refusals, a first try
  that timed out, the budget of 10 s on tokio's paused clock, and the three
  ends after a valid 101); `--test doctor`, 12 passed (through a stand-in
  proxy that drops each third CONNECT, each line says "loss 3 of 9 (33 %: 3
  broke)", and `--json` 9 tries, 6 connected and 3 broke); `--test
  doctor_upgrade` passed (the stand-in relay in `refuse:403`, `badaccept`
  and `hangup:200`: three lines, each with its own failure and none of the
  words of the others); `cargo test -p podssh-ws --test rfc6455`, 25
  passed; `--test man_page` 10 and `--test flag_table` 8; clippy and rustfmt
  clean.
- Planted: one verdict for the three ("the forward session failed"):
  `doctor_upgrade` failed; one try for each probe (`TRIES` 1): the test of
  the lossy proxy failed; restored, both passed.
- Live, in a Claude Code cloud container through its agent proxy,
  2026-10-30: `podssh doctor`, 31 ok and 0 FAIL in 15 s.
  "tcp.ssh.relay.ajam.dev:443: allowed by 127.0.0.1:35713; best 202 ms,
  median 238 ms, p95 264 ms, jitter 14 ms; loss 0 of 9"; github.com:443
  best 118 ms, median 128 ms; github.com:22 took the CONNECT and carried no
  SSH, with its nine tries (best 101 ms, median 129 ms).
- Not measured: a real proxy that loses tries, and a real hop that drops
  the upgraded stream.

# T-325: `doctor` measures what the path does to a stream: buffering, a cap on bodies, an idle limit

**Source:** GitHub #54 (Nemo-010, 2026-10-30).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** blocked

## Problem

Which road can work through a proxy depends on what the proxy does to a
stream: whether it holds a response until its end, holds a request body
until its end, refuses a body above a size, or ends a quiet stream after a
time. `doctor` measures none of these, and the road of T-319 is to be
chosen by such a probe.

## Premise

- Read: no check of `doctor` sends a body or holds a stream quiet
  (`crates/podssh-cli/src/doctor/net.rs`,
  `crates/podssh-cli/src/doctor/relay_checks.rs`).
- Read (#54): a 408 at 60 s is the default idle limit of an AWS load
  balancer, a 504 at 60 s nginx's `proxy_read_timeout`, a 524 at 125 s
  Cloudflare's, and 1 MiB nginx's `client_max_body_size`. Inferred from
  their documented defaults, not measured.
- Read (`docs/relay.md`): the relay has no endpoint that streams a response
  in chunks or takes a body, so the probes have nothing of podssh's to ask.

## Approach

1. With the relay's operator: an endpoint that sends a response in timed
   chunks, and one that takes a body in chunks and says when each came.
2. Four probes against the relay's own host: response streaming (the time
   of the first byte against the last), request streaming (a stall between
   chunks), the body cap (doubling until 413 or 431), and the idle limit (a
   quiet stream, and the time and status when it ends).
3. A table of fingerprints in the source, as `relay-facts.toml` is for the
   contract, so that a line names the product, never as a fact: "looks like".
4. The results go to T-319's choice of the split or the serial form.

## Prove

```sh
cargo test -p podssh-cli --test doctor_stream
```

Against stand-ins that buffer a response, buffer a body, refuse 1 MiB and
end a quiet stream at 3 s, each line names the property and the size or
the time. Planted: the chunk times ignored; the buffering test fails.

## Blocker

The relay's operator: the relay has no endpoint that streams a response or
takes a body (`docs/relay.md`).

# T-326: A cleartext road on port 443, probed after the TLS road fails

**Source:** GitHub #56 (Nemo-010, 2026-10-30).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** blocked

## Problem

Each road starts with TLS. A proxy that tunnels CONNECT but decides by the
SNI or the certificate that it sees could pass a WebSocket upgrade in
cleartext on port 443 where it intercepts TLS. podssh has no such road and
no probe for it.

## Premise

- Read: the relay's token goes in a header, never in the URL
  (`crates/podssh-ws/src/handshake.rs`); in cleartext the header is readable
  by each hop. SSH inside stays encrypted end to end.
- Measured (2026-10-30, in a Claude Code cloud container, through its agent
  proxy): `CONNECT tcp.ssh.relay.ajam.dev:443` got 200, then a cleartext
  `GET /` was reset with no answer, as a hop that expects TLS resets it.
- Not measured: what Cloudflare's edge answers to cleartext on port 443
  from a path with no such proxy (GitHub Actions can measure it).

## Approach

1. A variant of the connection with no TLS in `podssh-ws`; the upgrade is
   the same request over any stream.
2. Tried only after the TLS road failed, and only when the operator has
   ruled on the token in cleartext (Q45); `doctor` names which road on 443
   answered, and tells a refusal by policy (403) from a reset.

## Decision

2026-10-30, the operator (Q45, `docs/decisions.md`): the road is allowed,
tried only after the TLS road failed, with a relay token minted for that
one session and never cached; `doctor` names the road that answered.

## Prove

```sh
cargo test -p podssh-ws --test cleartext_road
```

Against a stand-in proxy that intercepts TLS and passes cleartext, the
session opens on the cleartext road after the TLS road fails; against one
that resets cleartext, `doctor` says so. Planted: the road tried first; the
test fails.

## Blocker

The relay's operator: an endpoint that takes the upgrade in cleartext on
port 443 (Cloudflare's edge serves TLS there).

# T-340: On Windows and macOS podssh reads no store of the system, and `UnknownIssuer` comes with no hint

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 5.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh trusts its compiled-in roots, a `podssh-ca.pem` next to the binary and the first bundle at
a Unix path. A proxy that re-terminates TLS with a root that an administrator put in the system's
store (by GPO or MDM) makes each relay connection fail with rustls's `UnknownIssuer`, and no
command says what to do. Four of the eight release binaries are for Windows and macOS.

## Premise

- Read: the system's bundles are Unix paths (`crates/podssh-ws/src/tls.rs:99-108`), and the
  default roots were the compiled-in Mozilla roots, `podssh-ca.pem` next to the binary and the
  first bundle that reads (`crates/podssh-ws/src/tls.rs` lines 180-200 at `59b67e6`). An explicit
  file (`--ca-file`, `SSL_CERT_FILE`) is used alone and never widened
  (`crates/podssh-ws/src/tls.rs:35-36`).
- Read: a failed handshake gives rustls's text: `crates/podssh-ws/src/client.rs:133` says "TLS
  with the relay failed: {why}", and `crates/podssh-ws/src/client.rs` lines 202-203 at `1316e53`
  kept rustls's words. doctor adds a hint for the
  clock's errors only (`crates/podssh-cli/src/doctor/relay_checks.rs` lines 96-105 at `b9e007c`), and its test
  asserts none for `UnknownIssuer` (`:344`).
- Read: the release builds two binaries for macOS and two for Windows
  (`.github/workflows/release.yml:286-297`, `:329-345`).
- Read: `windows-sys` 0.61 is already a dependency of `podssh-relay` on Windows
  (`crates/podssh-relay/Cargo.toml:67-68`), a crate with no C; `rustls-native-certs` 0.8.4,
  `schannel` and `security-framework` are in the lock through other crates
  (`Cargo.lock:4826-4827`).
- Read: one proxy that re-terminates TLS was measured, with its CA in `SSL_CERT_FILE` and in the
  system's store of Linux (`docs/target-environment.md:57-63`).
- Inferred: on macOS, `/etc/ssl/cert.pem` lacks a root that an administrator added to a keychain;
  on Windows, no path of the list exists. No Windows or macOS host behind such a proxy was
  measured.

## Approach

1. One hint, in podssh-ws, for a handshake that failed with `UnknownIssuer` (rustls's
   `CertificateError::UnknownIssuer`, and its text as the fallback): the issuer is not trusted
   here; a proxy that re-signs TLS needs its CA, in `--ca-file FILE` or `SSL_CERT_FILE` (which
   replace the store) or in `podssh-ca.pem` next to the binary (which adds to it). Each command
   gets it with the error's text (`crates/podssh-ws/src/client.rs:204`,
   `crates/podssh-ws/src/tls.rs:151`), and doctor too. T-345 adds the clock's errors to the same
   function.
2. Windows: the stores `ROOT` and `CA` of the current user and of the machine, read through
   `windows-sys` (its feature `Win32_Security_Cryptography`: `CertOpenSystemStoreW`,
   `CertEnumCertificatesInStore`), as a source of the default trust after `podssh-ca.pem`; an
   explicit file stays alone. doctor names each store and its count. A store that does not open
   is passed over with a note, never an error.
3. macOS: on a macOS runner, add a root to the System keychain and compare `/etc/ssl/cert.pem`.
   If the file lacks the root, read the keychains through the Security framework's Rust bindings
   (`security-framework`) in the same way.
4. The manual's section on TLS and `docs/architecture.md` give the sources in their order, for
   each system.

## Decision

`windows-sys` won: the workspace builds it already, the call is two functions, and podssh keeps
its own order of sources. `rustls-native-certs` lost: its sources and their order are its own on
each system (Inferred), and on Linux it would read again what podssh reads.

Decision 2, the stores of Windows: `ROOT` of the user and of the machine, as roots. `CA` lost: its
certificates are intermediates, which Windows trusts only through a root, and a process of the
user adds one to the user's `CA` with no prompt, where an addition to the user's `ROOT` asks the
user (Inferred); read as roots, they would widen what Windows trusts. A certificate counts as
Windows counts it for TLS: its usage, from the extension and the store's property
(`CertGetEnhancedKeyUsage`), is all or holds server authentication, it is valid today, and no
`Disallowed` store holds it. Each certificate of `ROOT` lost: it would trust a root that Windows
limits to another usage, or that an administrator distrusted.

Decision 3, macOS: `security-framework` won, as `windows-sys` did: it compiles no C, it is in the
lock, and podssh reads with it only the trust settings of the user and of the administrator,
where an addition goes; the user's decide first, as in the framework. The System domain is
Apple's own roots, which `/etc/ssl/cert.pem` holds (Inferred), beside podssh's compiled-in roots.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib tls
cargo test -p podssh-cli --test proxy
```

A stand-in relay whose certificate no root of podssh signs: `podssh proxy` and `podssh ssh` end
with the hint, which names `--ca-file`. In CI on `windows-2025`: a root added to the user's
`ROOT` store lets a session through a stand-in that it signs, and doctor names the store.
Planted: the match of `UnknownIssuer` removed; the test of the hint fails.

## Correction

Approach item 2 named the stores `ROOT` and `CA`, `CertOpenSystemStoreW`, and a proof with a root
in the user's `ROOT`. Decision 2 reads `ROOT` alone; `CertOpenStore` with the store's place opens
the machine's too, where `CertOpenSystemStoreW` opens the user's only; and CI adds the root to the
machine's `ROOT`, which the user's view of `ROOT` holds too, as an addition to the user's asks its
user in a dialog that a runner cannot answer (Inferred). Approach item 3's experiment is a step
of the same test: on the runner it asserts that no bundle of `SYSTEM_BUNDLES`, `/etc/ssl/cert.pem`
among them, holds the root that the keychain trusts. On GitHub's macOS runners no root can be put in
either domain of trust settings: `security add-trusted-cert -d` asks for the right
`com.apple.trust-settings.admin` in a dialog that no one answers, and granting the right fails as
root too, `security authorizationdb write com.apple.trust-settings.admin allow` giving "NO
(-60005)", errAuthorizationDenied (build runs 41176904479 and 41177809365, `macos-15`). The macOS
step reads both domains with no root of the test in them; the run with a root in a domain needs a
Mac whose administrator answers the dialog, and is not made (Done).

## Done

2026-10-31: done. Done here, items 1, 2, 3 and 4. Windows in CI at `eee611a` (build run 41171716387, the
job `windows`): with the root out of the store, the server that it signs was refused with
`UnknownIssuer`; with the root in the machine's `ROOT` store (`Import-Certificate`), the same
server passed with the default trust, the root coming from the user's view of `ROOT` (340 roots,
339 before; 225 passed over as no root for TLS), no bundle file holding it; doctor said "trust
store 458 anchors: 118 compiled-in roots (webpki-roots 1.0.11 of 2026-10-23) + 340 from the
current user's ROOT store" and named both stores. macOS in CI at `7b402d0` and `1a9aefe` (the job
`macos`, `macos-15`): podssh read both domains of trust settings, "the user's trust settings: 0
root(s); the administrator's trust settings: 0 root(s)", and a server that the test's root signs
was refused; the root could not be put in a domain (the Correction), so the step that wanted it
is now `the system's trust settings, read`: the same control and doctor's line, with no root
added. Not measured: podssh's read of a domain that holds a root, on macOS; the logic that sorts
a store's certificates is the unit test's below, the same on each system:

- `podssh_ws::tls::handshake_hint` and `handshake_failure`: rustls's
  `CertificateError::UnknownIssuer`, found in the `io::Error` by its type and
  by its text as the fallback, gets `UNKNOWN_ISSUER_HINT`, which names
  `--ca-file FILE`, `SSL_CERT_FILE` and `podssh-ca.pem` next to the binary.
  `ConnectError::Tls`, `tls::connect_over` and the query of DNS over HTTPS
  give it, so each command and doctor's relay line say it.
- Tests: the hint by type and by text, none for a wrong name or a reset
  (`cargo test -p podssh-ws --lib tls`, 1 passed); a server whose root is in
  no store gives the hint through `connect_over` with the default trust, and
  through a file of its root it passes (`--test hostname_verification`, 4
  passed); through the stand-in relay with no `--ca-file`, `podssh ssh`,
  `podssh proxy` and `podssh doctor` end with it
  (`cargo test -p podssh-cli --test faults -- --ignored a_relay_whose_issuer`,
  1 passed), and the gate's `scripts/interop-faults.sh` has the same check,
  `faults.issuer`. Planted, the match of `UnknownIssuer` removed: each of the
  three failed.
- `podssh_ws::stores` (`crates/podssh-ws/src/stores/`): on Windows, `ROOT` of the current user
  and of the machine through crypt32 (`CertOpenStore` read-only, `CertEnumCertificatesInStore`,
  `CertGetEnhancedKeyUsage`, `CertVerifyTimeValidity`), less what a `Disallowed` store holds; on
  macOS, the trust settings of the user and of the administrator through `security-framework`
  3.7 (no C; both already in the lock). `tls::default_roots` adds each store's roots after
  `podssh-ca.pem`; a store that does not open is passed over with its note. doctor's line
  "system stores" names each store with its count, on Windows and macOS only. Tests: the sort
  of a store's certificates (usage, `Disallowed`, a root given by an earlier store) and the
  summary (`cargo test -p podssh-ws --lib stores`, 3 passed; planted, the `Disallowed` check and
  the dedupe each removed: each failed); `cargo clippy -p podssh-ws --all-targets` for
  `x86_64-pc-windows-gnu` and `aarch64-apple-darwin`, `-D warnings`, clean.
- `crates/podssh-ws/tests/system_store.rs`, which the jobs `windows` and `macos` of
  `.github/workflows/build.yml` run: the test's root written, a server that it signs refused
  with `UnknownIssuer` while no store holds it, then trusted with the default trust once the root
  is in the machine's `ROOT` (`Import-Certificate`) or in the System keychain with the
  administrator's trust (`security add-trusted-cert -d`), no bundle file holding it; doctor offline
  names each store; the root leaves the store in each case. Here, with no store: the control
  passes and the run that wants the root in a store fails.
- The manual's Trust item (now `crates/podssh-cli/src/man/facts/trust.rs`, out of `facts.rs` at
  its 500 lines) and `docs/architecture.md` give the sources in their order on each system and
  the hint.

# T-344: DNS over HTTPS: two operators, one encoding, and no memory of the addresses that worked

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 9.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

On a host with no working resolver and no proxy, podssh asks DNS over HTTPS of two operators, at
four known addresses, in their own JSON form. A firewall that blocks those addresses, or a change
of that form, leaves `--relay-addr` alone. podssh keeps no address that carried a session.

## Premise

- Read: the resolution goes from an IP literal to the pins, the system's resolver, then DNS over
  HTTPS (`crates/podssh-ws/src/resolve.rs`, lines 1-11 at `927eb24`); with an HTTP proxy none of it runs for the
  target, and TLS always checks the target's name (lines 12-15 at `927eb24`).
- Read: the resolvers are Cloudflare's and Google's, by IP literal, each with its JSON path
  (lines 28-32 at `927eb24`); each query dials port 443 directly (lines 144-163 at `927eb24`),
  with `Accept: application/dns-json` (line 156 at `927eb24`), for A and then AAAA (line 125 at `927eb24`).
- Read: the relay's pool is cached on disk at a mint (`crates/podssh-relay/src/pool.rs:175-194`);
  nothing caches an address.
- Inferred: RFC 8484 defines the wire form, `application/dns-message`, and no standard defines the
  JSON form; firewalls that block the known addresses of public resolvers are common.

## Approach

1. A cache of addresses: when a session through the relay reached `101`, the address that carried
   it, under its name, in the cache beside the pool, with the time. It is tried after the system's
   resolver fails and before DNS over HTTPS; TLS still checks the name, so a wrong address fails
   the handshake. An old address is still tried, last.
2. A third operator by IP literal, after the four of today (Quad9 is a candidate; Inferred: it
   serves RFC 8484 at `/dns-query`).
3. RFC 8484's wire form beside the JSON form: a GET with `?dns=` and
   `Accept: application/dns-message`, with a small encoder of the query and a decoder of A, AAAA
   and SRV answers in podssh-ws, by hand, and a fuzz target (T-198). The JSON form stays first where an
   operator serves it; the wire form is its fallback, and the only form for an operator with no
   JSON. T-339 takes the SRV answer.
4. doctor names the source of each address it used: a pin, the system, the cache, or DNS over
   HTTPS.

## Decision

A codec by hand won: three record types and a fuzz target. `hickory-proto` lost: a large crate
for so little, and a parser of untrusted bytes that podssh does not fuzz. Both are pure Rust.

Decided in the work (2026-10-31):

- **Where the cache stands in the order.** Its addresses are asked only once the system resolver
  failed, so a host whose resolver works never meets them: those younger than 7 days
  (`podssh_ws::resolve::FRESH`) before DNS over HTTPS, an older one after it, last. A week: the
  relay's names keep their addresses for months (the address that `docs/STATUS.md` measured for
  `--relay-addr` is one that each operator gave on 2026-10-31), and a host that runs podssh once
  a week finds its own still fresh. Lost: the record's TTL (300 s), which would leave nearly each
  run's address old, behind DNS over HTTPS; no window, which would keep a stale address before
  DNS over HTTPS for good.
- **A dial hands over to the next source.** `resolve` gave the addresses of one source; now the
  dialer (`crates/podssh-ws/src/race.rs`) asks the sources after the cache when none of its
  addresses connects within 4 s (`SOURCE_WAIT`), and DNS over HTTPS ends 4 s before the dial's
  limit when an old address waits. The system resolver's answer, a pin and an IP literal hand
  over to nothing, as before. Lost: the cache's addresses alone, which would put a stale address
  in the place of DNS over HTTPS for a week; a race of the sources, which would open more than
  one connection at once (`AGENTS.md`, rule 2 of section 5).
- **What is kept, and what goes.** The address of a session's `101`, when the dialer reached it
  straight (through a proxy it is the proxy's), for a name that no pin holds, and not this
  host's own; 4 addresses a host and 32 hosts, a time written again after an hour at most. An
  address goes when a host failed at it after its connection opened, as no relay would: TLS
  refused the name, the upgrade broke, or another server answered, as Cloudflare's edge does
  with a valid certificate at an address of another of its sites (`docs/STATUS.md`, the row of
  a wrong `--relay-addr`); the relay's own refusals (a token, the policy, a target that it
  cannot reach) keep it. Lost: forgetting at a TLS failure alone, which would keep such an
  address of Cloudflare's for a week; forgetting at a failure of TCP, which would empty the
  cache in the hour that a network is down, the hour when it is needed next.
- **The JSON form first, the wire form for a miss of its form.** An answer that is not of the
  form asked (a status of 4xx but 429, a body that does not read) goes to the wire form at the
  same address, which then answers the next record type too; a failure of the way (TCP, TLS, no
  answer in time, 429, 5xx) goes to the next resolver, and a status of the resolver's own
  (NXDOMAIN, SERVFAIL) is its answer. Lost: the wire form after each failure, which would double
  the cost of each address that a firewall drops.
- **Quad9 third, its two addresses, in the wire form alone.** Read on 2026-10-31 through
  fetch.web.pkgforge.dev: `https://dns.quad9.net/dns-query` answered RFC 8484's GET in the wire
  form (`crates/podssh-ws/tests/fixtures/doh/README.md`), and the JSON API's query with
  `400 DoH unable to decode BASE64-URL`; the certificate that `dns.quad9.net` presented (serial
  `0cc33029e45df0257de872a8fccf1731`, read from crt.sh) names 9.9.9.9 and 149.112.112.112 among
  its IP addresses. Its filter of malware's names takes no relay's name.
- **A resolver's connection has 3 s** (`DOH_CONNECT`) of its 5 s: a firewall that drops the four
  addresses of Cloudflare and Google costs 12 s, not 20 s, so Quad9 is asked within a step's
  20 s. Lost: 5 s as before, which would leave Quad9 unasked behind four dropped addresses.
- **The wire form checks the question** of its answer, name and type, case aside: an answer for
  another question is refused. A label holds printable ASCII and no dot, and a pointer goes back
  before its run of labels, so that each walk ends. The JSON form is read as before.
- **The dialer keeps the source of each connection** (`podssh_ws::resolve::dialed`, the last
  32), which `health` reads for doctor's relay lines and the opener for the address to forget.
  Lost: the source in the stream's type, which would change `open_tls` and each of its callers.
- **The system resolver has no bound of its own**, as before: a bound would change which answer
  wins where the resolver is slow; a fresh address of the cache needs no network, so it is
  asked within a step once glibc's resolver gives up (Inferred: 5 s, twice, by default).
- **Files under 500 lines**: the race of addresses moved from `dial.rs` to
  `crates/podssh-ws/src/race.rs`, doctor's DNS checks from `net.rs` to
  `crates/podssh-cli/src/doctor/names.rs`, and the tests of `resolve.rs` to
  `crates/podssh-ws/src/resolve/tests.rs`; `podssh_ws::dial::interleave` and `connect_direct` stay
  where their callers find them.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib resolve
cargo test -p podssh-ws --test doh_wire
```

A wire answer captured from each operator (bytes that podssh did not write) decodes to its
addresses; a cached address is tried when the system's resolver and DNS over HTTPS fail; a wrong
cached address fails TLS on the name. Planted: the cache asked before the system's resolver; the
test of the order fails.

## Correction

- Premise, the second item: since T-339, `doh_srv` asks the same resolvers for SRV records
  through the proxy when one is set (`crates/podssh-ws/src/resolve.rs`, lines 224-253 at
  `5877a00`): only the lookup of addresses dials port 443 directly. Both take the wire form now.
- Premise, the Inferred item: Read, RFC 8484 (through fetch.web.pkgforge.dev): a GET with `dns=`
  in base64url with no padding, `application/dns-message`, and the ID 0 that a cache wants
  (sections 4.1 and 6). Approach item 2's Inferred is measured (Decision).
- Prove: at the dialer, the test of a cached address after the system resolver and DNS over
  HTTPS fail takes a name that no resolver can be asked for (with a `+`), so that it needs no
  network; DNS over HTTPS's own failure is the unit test's, with a stand-in for its answer.

## Done

2026-10-31, done: drafted, then merged and measured; the fuzz run waits for T-251 (below).

- `podssh_ws::resolve` asks, in order, an IP literal, the pins, the system resolver, the fresh
  addresses that carried a session, DNS over HTTPS, then the old ones
  (`crates/podssh-ws/src/resolve/order.rs`); `resolve_from` resumes after a source, and `Found`
  names the source and whether another follows. The dialer races each source's addresses, hands
  over after 4 s when another follows, and keeps the source of each connection
  (`crates/podssh-ws/src/race.rs`, `crates/podssh-ws/src/resolve/memory.rs`). The wire form is
  `crates/podssh-ws/src/resolve/wire.rs`: the query, its base64url, and the decoder of A, AAAA
  and SRV. `DOH_RESOLVERS` gives each resolver's forms, Quad9's two after the four; `doh_ask`
  names the form that answered, and `doh_srv` takes the wire form too.
- `podssh_relay::addresses` keeps `relay-addresses.json` in the cache
  (`crates/podssh-relay/src/addresses.rs`): the opener keeps the address of each session's
  `101`, and forgets one of the cache at which a host failed as no relay would; `pins::apply`
  and the opener give the record to the dialer.
- doctor: a line `cached` with each address, its age and its turn; the line of DNS over HTTPS
  names the form that answered; each relay line names the source of its address, as
  `TCP ADDRESS (SOURCE)` (`crates/podssh-relay/src/health.rs`).
- The manual (THE RELAY's DNS, the cache of FILES, doctor's note), `docs/architecture.md` (the
  way to the relay, three limits), `docs/design.md`, `docs/development.md` (the seeds), and
  `docs/STATUS.md`.
- Bytes that podssh did not write: 15 answers of Cloudflare, Google and Quad9
  (`crates/podssh-ws/tests/fixtures/doh/`), and RFC 8484's own queries and answer in the unit
  tests. The fuzz target `dns_wire`, seeded by the 15 answers (`scripts/fuzz-seeds.py`).
- Measured at the merge (2026-10-31): `cargo test -p podssh-ws --lib resolve` passed 15 (the
  order with stand-ins, the codec against RFC 8484's examples, the forms and their misses, the
  memory); `--test doh_wire` passed 8 (the 15 answers; each cut refused, no changed byte a panic;
  the system resolver before the cache; a fresh address that does not connect hands over to the
  old one; a wrong address of the cache refused by TLS on the name). Planted, `Source::Cache`
  before `Source::System` in `ORDER`: the two tests of the order in the unit tests and the one of
  `doh_wire` failed. `cargo test -p podssh-relay --lib addresses` passed 4 and `--lib open` 7;
  `--features quick --test quick_tunnel` 7; `cargo test -p podssh-cli --lib doctor` 37 and `--test
  doctor` 13, T-366's case of names and addresses among them, now on `names.rs`. clippy `-D
  warnings` asked for tokio's lock in `doh_wire`, which held std's across an await; rustfmt.
- The fixtures are what the operators send: asked again from this host through its proxy on
  2026-10-31, Cloudflare's A answer was the same 72 bytes, and Google's the same two records in
  the other order (it turns them).
- The sweep of the default relay's name failed on the unit tests of `resolve/tests.rs`, a test
  module in a file of its own, which it read as library code; it now skips a file that its parent
  declares under `#[cfg(test)]`, and planted, the name at the top of `resolve/order.rs` still
  failed it.
- The live run (less than 5 minutes) cannot run on this host: its sandbox answers TLS to any
  address with a certificate for `default.domain`, which podssh refused for each of the six. It
  runs in GitHub Actions, `.github/workflows/doh-live.yml`, by hand. Its first run (41203490598,
  at `298761e`) found a defect that no test here could: the four of Cloudflare and Google answered
  in each form, and Quad9 answered `HTTP 505`, as it serves HTTP/2 alone (curl through this host's
  proxy: 505 to HTTP/1.1, 200 to HTTP/2). Repaired: a resolver marked `http2` is asked over HTTP/2
  with ALPN `h2` (`crates/podssh-ws/src/resolve/h2.rs`, h2's client, pure Rust), directly and
  through a proxy. `cargo test -p podssh-ws --test doh_h2` passed 3 against h2's own server behind
  TLS: Quad9's captured answer came whole and decoded, a server of HTTP/1.1 alone was refused before
  a request, an answer over the bound was refused; planted, no ALPN offered, the two that need an
  answer failed. podssh-ws, 254 passed; clippy clean. Its second run (41205878813, at `22d9de6`)
  passed: each of the six resolvers answered `github.com` by its address through verified TLS,
  each in the wire form, Quad9's two over HTTP/2, and a reserved name stopped at the first answer
  (NXDOMAIN).
- Waits for T-251: `dns_wire` for 120 s in `fuzz.yml` (UNVERIFIED).

# T-345: Only `doctor` names the clock when a certificate has expired or is not valid yet

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 11.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A host whose clock is wrong sees each certificate as expired, or as not valid yet. `doctor` says
that certificates are checked against this host's clock, and gives its reading; `ssh`, `proxy`
and each other command print rustls's words alone. An error should tell what to do
(`docs/architecture.md:182`).

## Premise

- Read: doctor's hint (`crates/podssh-cli/src/doctor/relay_checks.rs` lines 96-105 at `b9e007c`) and its tests
  (`:341-344`).
- Read: the other commands print the error's text: `crates/podssh-ws/src/client.rs:133` says "TLS
  with the relay failed: {why}"; the TLS of IRC and of the quick tunnel's edge gives the text of
  `crates/podssh-ws/src/tls.rs:151` (`crates/podssh-relay/src/quick/edge.rs:111-113`).
- Read: rustls 0.23.46 (`Cargo.lock:4776-4777`) has the errors `Expired`, `ExpiredContext`,
  `NotValidYet` and `NotValidYetContext`, and writes the two with a context as "certificate
  expired: verification time" and "certificate not valid yet: verification time" (its
  `src/error.rs`, read in cargo's registry); doctor's match of the text ("expired", "not valid
  yet") holds for both.
- Read: the expiry of a cached token is read against the local clock, and a token that the relay
  refuses is minted again once (`crates/podssh-relay/src/cache.rs:84`;
  `crates/podssh-relay/src/open.rs:349-360`): that case needs no hint.

## Approach

1. The function of T-340 in podssh-ws (this entry makes it, if it comes first): a handshake that
   failed with one of the four time errors (their text as the fallback) gets the clock's hint,
   with this host's clock in UTC, in doctor's words.
2. Each place where podssh-ws makes the text of a TLS error uses it: `ConnectError::Tls`
   (`crates/podssh-ws/src/client.rs:204`), `tls::connect_over` (`crates/podssh-ws/src/tls.rs:151`)
   and the query of DNS over HTTPS (`crates/podssh-ws/src/resolve.rs:155-158`). doctor's `clock_hint`
   calls it, so that the words are the same.
3. Tests through a stand-in relay with an expired certificate: `podssh ssh`, `podssh proxy` and
   `podssh cp` each name the clock and its reading.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib tls
cargo test -p podssh-cli --test proxy
```

A stand-in relay with a certificate that ended a day ago: the error of each command names this
host's clock. Planted: the match of `ExpiredContext` removed; the test with rustls's error with a
context fails.

## Correction

Approach item 3 and the Prove named `--test proxy` for a stand-in relay with an expired
certificate: the stand-in relay with its own CA is the fault harness's (`--test faults`, and
`scripts/interop-faults.sh` in the gate), where T-340's test of an unknown issuer is; the new
test is there, beside it. doctor's date is podssh-ws's now (`podssh_ws::clock`), which doctor's
words and each command's share, so item 2's "doctor's `clock_hint` calls it" holds by its words.

## Done

2026-10-31: each command names this host's clock when a certificate has expired or is not valid
yet. `podssh_ws::tls::handshake_hint` gives, beside T-340's hint of an unknown issuer, the clock's
words for rustls's `Expired`, `ExpiredContext`, `NotValidYet` and `NotValidYetContext`, by type
and by text; `ConnectError::Tls`, `tls::connect_over` and the query of DNS over HTTPS take it
through `handshake_failure`, as they took T-340's. `podssh_ws::clock` holds the words and the
IMF-fixdate that doctor wrote before (doctor's `clock.rs` takes them from there), and doctor adds
its own only to a text that does not hold them.

- Through the fault harness's stand-in relay, with a leaf that its CA signed and that ended a day
  before it began (`openssl x509 -days -1`): `podssh ssh` said "TLS with the relay failed:
  invalid peer certificate: Expired; certificates are checked against this host's clock, which
  reads Sat, 31 Oct 2026 07:47:07 GMT", and `podssh proxy` and `podssh cp` say the same
  (`cargo test -p podssh-cli --test faults -- --ignored a_relay_whose_certificate`, 1 passed;
  with T-340's of the issuer, 2 passed). Planted, the clock's branch taken away: that test and
  the unit test failed.
- Unit tests: the four errors by type and one by text get the words, a name mismatch none
  (`cargo test -p podssh-ws --lib tls`); the date and the words of a given clock
  (`podssh_ws::clock::tests`); podssh-ws 231 passed in 33 binaries; doctor 33, `--test doctor`
  12, `--test proxy` 9; clippy `-D warnings` and rustfmt clean.
- The gate: `scripts/interop-faults.sh` makes the expired leaf, starts a stand-in with it and
  checks `faults.clock`; `scripts/interop-baseline.txt` holds it, and the floor of `faults` is
  39 (`cargo todo interop`: 617 ids of 44 harnesses meet the baseline). Its run is CI's.
- `docs/architecture.md` and the manual's Trust item say it.
- 2026-10-31, after the close: the gate's step `release` failed at 925c94b (build run
  41185627815): the build image's OpenSSL 3.5.9 refuses `x509 -days -1` ("Error: end date before
  start date"), where this host's 3.0.13 took it, and as that leaf was a step of the chain of
  certificates, faults.certs, faults.standins and faults.clock failed. The leaf is now made by
  `openssl ca` with `-startdate 20200101000000Z -enddate 20200102000000Z`, in a step of its own,
  so that its failure is faults.clock's alone, with names relative to the certificates'
  directory, as OpenSSL reads a path in its config with escapes; the fault harness of the Rust
  tests makes it the same way, when a cell asks for it. Measured: in an Alpine 3.24.3 container,
  OpenSSL 3.5.9, the recipe made a leaf that `openssl verify` calls expired, and the old command
  gave the CI's error; here, the script's changed part made each certificate and started each
  stand-in, and with `openssl ca` planted to fail, each other certificate and stand-in still;
  `--test faults -- --ignored a_relay_whose_certificate`, 1 passed.
- 2026-10-31, the gate's step `release` at 91c62c8 (build run 41188615860): the leaf of 2020
  was made and its stand-in started, and podssh said "invalid peer certificate: certificate
  expired: verification time ..., but certificate is not valid after ...; certificates are checked
  against this host's clock, which reads Sat, 31 Oct 2026 09:31:41 GMT", which is right; but
  faults.clock looked for "Expired", rustls's word for a leaf that ends before it begins, and failed.
  It now takes either of rustls's two words after "invalid peer certificate", and a refusal that
  names the host `relay-expired.test` does not match. And `cargo todo interop` found the new file
  a harness that the baseline did not name, as it printed `faults.certs`: it prints no id now and
  sets `FAULT_CERTS`, which `interop-faults.sh` says, and the baseline names it a support file;
  `cargo todo interop`, 617 ids of 44 harnesses, and `--test interop`, 11 passed.


# T-366: `doctor` asks the proxy for an address as well as for names, and says which of the two it takes

**Source:** GitHub #74 (Nemo-010, 2026-10-31).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Each CONNECT of `doctor` names a host, as each road of the release binaries does. A proxy that
allows listed names only and a proxy that takes any public address give those probes the same
answers. A road that must ask for an address works through the second only: an address that the
user gives to `--direct`, WARP's endpoint (T-352), and Tor's first hops (T-353), which the
consensus names by their addresses (Inferred). So `doctor` cannot say which of those roads this
host has.

## Premise

- Read: through a proxy, `doctor` asks for the relay's host and for `github.com` on ports 443 and
  22, each by name (`crates/podssh-cli/src/doctor/net.rs:18-20`, `:201-251`), and
  `crates/podssh-cli/src/doctor/net.rs:146` says "podssh asks it to CONNECT by name, so no DNS is
  needed".
- Read: the dialer gives a proxy the relay's name and never an address, and a pin of the relay's
  name to an address that is not the loopback keeps the name for the proxy
  (`crates/podssh-ws/src/dial.rs:6-9`, `:125-131`); a CONNECT names the host as it was given
  (`:255-264`). So no road of the release binaries asks a proxy for an address, but `--direct`,
  `pipe tcp:` and a target of `-R`, each to an address that the user gives.
- Read: with no proxy, `doctor` reaches addresses already: DNS over HTTPS to the resolvers'
  address literals (`crates/podssh-cli/src/doctor/net.rs:294-365`;
  `crates/podssh-ws/src/resolve.rs:28-32`), each checked by TLS for its address
  (`crates/podssh-ws/src/resolve.rs:148-158`).
- Read: the proxy of the measured sandbox gave `200` for public names on ports 443, 80 and 8443,
  and `403 not a public host` for private and metadata addresses
  (`docs/target-environment.md:21`); no public address literal was asked. The box's proxy
  resolves each name and checks its addresses, so it takes a public literal as it takes a name
  (`scripts/box/proxy.py:107-115`).
- Read: the study of carriers takes it as Inferred that a proxy which allows listed names only
  refuses WARP's address literal (`docs/carriers.md:81-89`).
- Read: a test of `doctor` counts the lines whose check is `CONNECT`, and wants three
  (`crates/podssh-cli/tests/doctor.rs:345-369`).

## Approach

1. Through a proxy, one more probe: a CONNECT to the first address of `DOH_RESOLVERS` on port 443,
   sampled as the other probes are (T-324), then the TLS handshake of that resolver for its
   address, so that a `200` that carries nothing is named, as T-317 names it for port 22. The
   probe has a check name of its own, not `CONNECT`, so the three `CONNECT` lines and their test
   stay as they are.
2. Its line gives the proxy's answer as the proxy gave it: a `403` with its reason, a `407`, a
   `502`, or a loss, which T-324 counts.
3. One line names the case: names and addresses; names only (a road that asks for an address
   cannot leave here); addresses only (the relay's name is refused here, and a road by address
   can leave); neither. With no proxy, the same line comes from `direct TCP` and DNS over HTTPS.
4. `--json` gives the probe and the case (T-049).
5. `scripts/box/proxy.py` gets a mode that takes names only and one that takes addresses only.
6. The manual's note of `doctor`, and the item of WARP in `docs/carriers.md`: the probe that
   measures the case, with the date and the host of each measurement.

## Decision

- The address is the first of `DOH_RESOLVERS`: podssh depends on it already, it is public and
  long lived, and it serves TLS on port 443 with a certificate for its address. Lost: an address
  of `github.com`, which a cage cannot resolve and a proxy resolves only for itself; an address
  compiled in for this probe alone, one more fact to keep.
- P3, not P2: no road of the release binaries asks a proxy for an address (Premise). The fact
  serves `--direct` to an address, and the roads of T-352 and T-353, which wait for Q52.
- A road to the relay by its address, where a proxy refuses names and takes addresses, is not in
  this entry: #74 does not ask for it, and no host of that kind was measured.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test doctor
cargo test -p podssh-cli --lib doctor::net
```

Three stand-in proxies on the loopback: one takes names and refuses each address literal with
`403 not on the allowlist`, one takes literals and refuses names, one takes both. The line of the
case names each of the three, and the three `CONNECT` lines stay. Planted: the probe sent by name;
the case "names only" is not found, and its test fails. In the box, with its proxy in each mode:
the same. Live, behind the agent proxy of a cloud session (a host that a session may measure): the
probe's line and the case, in `docs/STATUS.md`.

## Done

2026-10-31: `doctor/address.rs`: through a proxy, the line `IP CONNECT` asks for the first resolver
of DNS over HTTPS by its address on port 443, sampled nine times as the other probes are, then does
its TLS for that address on the first connection that opened; the line `egress takes` names the
case, which with no proxy comes of `direct TCP` and of DNS over HTTPS; `--json` gives both, the
probe with its samples. `scripts/box/proxy.py` takes `--take names|addresses|both`. `cargo test -p
podssh-cli --test doctor` passed 13: through three stand-in proxies, of names only (literals
refused with `403 not on the allowlist`), of addresses only and of both, each piping what it takes
on port 443 to a TLS server of the test's own for the resolver's address, the line of the case
named each, and the three `CONNECT` lines stayed; `--json` gave both checks. Planted, the probe
sent by name with its TLS for the address: the names-only proxy took it, and the test failed. `cargo
test -p podssh-cli --lib doctor::` passed 35; clippy clean. Live, on this cloud session's host
behind its agent proxy: `IP CONNECT` 1.1.1.1:443, the CONNECT taken and its TLS reset; `egress
takes` names only. The manual's note of doctor, `docs/cli.md` and WARP's item of
`docs/carriers.md` say it. The box's run, with its proxy in each mode, waits for the checks of the
release (T-251), as each run in a container does.

# T-377: The keys of podssh's own AEAD ciphers outlive their use, since chacha20poly1305 0.11

**Source:** T-355's reading of chacha20poly1305 0.11 for the fork (#67), 2026-10-31: the fork's
`ts_noise` warns that 0.11 makes the zeroize of a key a feature.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The TLS provider of podssh-ws keeps each session's AEAD key in a cipher of RustCrypto. When the
session ends, the key stays in the freed memory, where a dump of the process, or a later bug
that reads freed memory, finds it; x25519-dalek's secrets are wiped for this reason. T-333 moved
podssh to chacha20poly1305 0.11, which wipes its key only with a feature that podssh does not
turn on, where 0.10 always did. AES-GCM and the block cipher of QUIC's header protection never
wiped theirs.

## Premise

- Read: the root `Cargo.toml` asked for `chacha20poly1305` 0.11 with `alloc` alone, `aes-gcm`
  0.11 with `aes` and `alloc`, and `aes` 0.9 with no feature, where x25519-dalek takes `zeroize`
  with the reason (`Cargo.toml` lines 141-149 at `3218fc6`).
- Read, in cargo's registry: chacha20poly1305 0.10.1 wipes its key in the `Drop` of
  `ChaChaPoly1305` and implements `ZeroizeOnDrop` with no condition; 0.11.0 does both only under
  `#[cfg(feature = "zeroize")]`, a feature that also turns on `chacha20/zeroize`. aes-gcm 0.10.3 and 0.11.1 implement `ZeroizeOnDrop` only with their
  optional `zeroize`, and aes 0.9.3 wipes its key schedule only with its optional `zeroize`.
- Read: podssh-ws makes the ciphers of TLS from a session's key
  (`crates/podssh-ws/src/crypto/aead.rs:79-85`) and those of QUIC
  (`crates/podssh-ws/src/crypto/quic.rs:67`).

## Approach

1. The root `Cargo.toml`: `zeroize` for chacha20poly1305, aes-gcm and aes, with the reason beside
   x25519-dalek's.
2. A test of podssh-ws that each cipher type it holds (ChaCha20-Poly1305, AES-128-GCM,
   AES-256-GCM, AES-128 and AES-256) implements `ZeroizeOnDrop`, as the fork's `ts_noise` checks
   its own: it fails to compile when a feature is gone.
3. `cargo deny` (zeroize is already in the tree), STATUS.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib crypto
cargo test -p podssh-ws
```

The test compiles and passes; planted, `zeroize` taken from chacha20poly1305 alone, it fails to
compile and names `ZeroizeOnDrop`.

## Done

2026-10-31: the root `Cargo.toml` turns on `zeroize` for chacha20poly1305, aes-gcm and aes, with
the reason beside x25519-dalek's; the lock adds zeroize to chacha20poly1305's dependencies, and
`fuzz/Cargo.lock` follows (with base64 0.23, which 1a9aefe left at 0.22 there).

- `crypto::tests::each_cipher_wipes_its_key_when_dropped` in podssh-ws asks `ZeroizeOnDrop` of
  ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM, AES-128 and AES-256: 1 passed. Planted,
  chacha20poly1305 without `zeroize`: the test does not compile, "the trait `ZeroizeOnDrop` is
  not implemented for `ChaChaPoly1305<...>`".
- `cargo test --locked -p podssh-ws -p podssh-relay`, 452 passed in 81 binaries; the live
  handshakes with the relay (`--test live_handshake`), 6 passed; clippy `-D warnings` and rustfmt
  clean for podssh-ws.
