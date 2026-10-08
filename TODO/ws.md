This file holds the work on `podssh-ws`, the crate that reaches the relay: TCP and proxies, TLS
with podssh's own pure-Rust provider, and the WebSocket client. W10, W13 and W14 are rows of the
former defects page (`git show 3ee70dc:docs/defects.md`); the features come from the
`podssh-ws` item of ROADMAP M4 and `docs/design.md:117-121`, and from GitHub issues. The crate
must build with no C compiler (`scripts/gate.sh:61-71`).

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
(`crates/podssh-ws/src/frame.rs` lines 113-225) checks the reserved bits (lines 124-128), the
opcode (129-135), the mask direction (141-150) and the length caps (152-194). It never compares
`fin` or the length with `MAX_CONTROL_PAYLOAD` (lines 33-37) for the opcodes 0x8 to 0xA. The
constant only stops the answer to a large Ping, and the session goes on
(`crates/podssh-ws/src/session.rs` lines 181-187; `crates/podssh-ws/src/client.rs` lines
331-335). A Ping with FIN clear becomes `Event::Pong` and gets an answer (`client.rs` lines
371-373). A Close or a Pong of any size is accepted (`session.rs` lines 188-199). A Close of 1
byte is read as a Close with no code (`session.rs` lines 275-278); RFC 6455 section 5.5.1 allows
0 bytes, or 2 and more.

## Approach

1. In `frame::decode`, when the length is known and before the payload is copied
   (`crates/podssh-ws/src/frame.rs` line 208 at `3b60753`): for an opcode of 0x8 or more, return
   `WsError::Frame` when `fin` is clear or the length is over 125. Name the rule in the message.
2. Refuse a Close payload of 1 byte in the same place.
3. The read then fails (`crates/podssh-ws/src/session.rs` line 176 at `3b60753`). Today a failed
   read sends no Close (`crates/podssh-ssh/src/relay_stream.rs:139-141`): send 1002 (protocol
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
(`crates/podssh-ws/src/crypto/random.rs` lines 13-23), and its comment (lines 15-19) says that
this cannot fail. It can: `Cargo.lock` gives `podssh-ws` `rand` 0.8, whose `rand_core` 0.6.4
implements `fill_bytes` for `OsRng` as `try_fill_bytes` and a panic on an error (read in the
cargo registry copy, `rust-random/rand:rand_core/src/os.rs`, lines 61-64 of that release).
`generate_key` and `masking_key` map an error that never comes
(`crates/podssh-ws/src/handshake.rs` lines 23-29 and 256-271). Two more sites, not in the W13
row, panic the same way: `rng.fill_bytes` for the X25519 secret
(`crates/podssh-ws/src/crypto/kx.rs` lines 52-56) and `EphemeralSecret::random` for P-256 (line
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
5. Add a test that reads the crate's source, as `crates/podssh-cli/src/man/facts.rs:219-238`
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
(`crates/podssh-ws/src/lib.rs` line 22). `verify_server_cert` prints the chain and returns
`ServerCertVerified::assertion()` (crates/podssh-ws/src/probe.rs, gone since this entry, lines
24-39); both signature checks accept (lines 41-57); a library prints to stdout (lines 32-37). Its
only user is the example (`crates/podssh-ws/examples/inspect_peer_chain.rs` lines 25-29). The
module comment says that the test suite asserts that the shipped configuration does not use it
(`probe.rs` lines 9-12), but no test names `PrintChain`: a search finds it only in `probe.rs`,
the example and the documents. Also, lines 134 and 178 of `probe.rs` index the certificate with
no bound check, so a short certificate panics the probe. The shipped configuration calls
`.dangerous()` to install the WebPKI verifier (`crates/podssh-ws/src/tls.rs:237-241`), so a scan
cannot look for that word alone.

## Approach

1. Move `PrintChain` and its DER helpers into the example
   (`crates/podssh-ws/examples/inspect_peer_chain.rs`), and remove `pub mod probe;`. Keep each
   file under 500 lines.
2. Add the test that `probe.rs` (lines 9-12) promised: a scan of the source of `podssh-ws`,
   `podssh-relay`, `podssh-ssh` and `podssh-cli`, as `crates/podssh-cli/src/man/facts.rs:219-238`
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

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:79-80` and 102-104. Read here
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
the configuration on each call (`crates/podssh-ws/src/client.rs` lines 187-207, through
`crates/podssh-ws/src/tls.rs` lines 153-180). `WsClientConfig` carries only a `Trust`
(`client.rs` lines 47-61). The same `Trust` goes through `podssh-relay`: `Request`
(`crates/podssh-relay/src/open.rs:125-135`), `MintContext`
(`crates/podssh-relay/src/token.rs:92-97`), the pool refresh
(`crates/podssh-relay/src/pool.rs:117-126`), and the `https_*` functions (`client.rs` lines
261-287). podssh's configuration offers no ALPN (`tls.rs` lines 174-177), because the upgrade is
HTTP/1.1 only (`docs/relay.md:174`). The `tls12` feature of `rustls` is on in the workspace
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
7. Change `docs/design.md:117-121` and `docs/architecture.md` in the same commit.

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
`crates/podssh-ws/tests/hostname_verification.rs:63` starts one), with a caller configuration
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
enables both versions (`crates/podssh-ws/src/tls.rs:237-239`); rustls accepts that, because one
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
   (`crates/podssh-cli/src/doctor/relay_checks.rs:93-96`); the live relay must still give TLS
   1.3.
6. Change the comment of `suites.rs`, `docs/architecture.md:46`, the Trust item of the manual
   (`crates/podssh-cli/src/man/facts.rs:169-182`) and `docs/STATUS.md` in the same commit.

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

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:118-119`.
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
`crates/podssh-relay/src/open.rs:137-142`). The tests use in-memory streams
(`crates/podssh-ws/tests/session.rs:34-36`) or local TLS servers
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
6. Change `docs/design.md:118-119` in the same commit.

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
writes for a `101` (lines 136-138), and the session carries data both ways. The host 192.0.2.1
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

**Source:** the `podssh-ws` item of ROADMAP M4; `docs/design.md:119-120`.
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
`send_text` (`crates/podssh-ws/src/session.rs` lines 86-94), `send_close` (104-109),
`read_frame` (170-221) and `write` (223-228) return `Result<_, String>`; `watch_liveness`
returns a `String` (142-166). The callers keep or pass the text:
`crates/podssh-ssh/src/relay_stream.rs` lines 95-96 and 138-140 put it in `RelayEnd::Failed`;
`crates/podssh-cli/src/proxy.rs:212-247` prints it; `podssh-transport` makes a write error
`TransportError::Unexpected` (`crates/podssh-transport/src/socket.rs` lines 104-113, 143, 161
and 185), and, since T-072, a read error `Aborted` with its text. Tests and the gate match the
text: `crates/podssh-ws/tests/session.rs` lines 108 ("continuation") and 172 ("without a
WebSocket Close"), and `scripts/interop-faults.sh:148` ("pings unanswered").
`WsError` exists (`crates/podssh-ws/src/error.rs:50-70`), but the session does not use it.

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
  reads is `WriteStalled`. `crates/podssh-transport/tests/socket.rs`: each class has its retry.
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
(`crates/podssh-cli/src/doctor/net.rs:104-110`). Two tests assert the refusal:
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
   (`crates/podssh-cli/src/doctor/net.rs:163-186`) work for both forms. The two tests above
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
(`crates/podssh-ws/src/client.rs:401-410`). The stand-in relay writes the minimal form
(`scripts/fake-relay.py:54-62`); the frames of the real relay were not checked for it.

## Approach

1. In `frame::decode`, refuse a 16-bit length below 126 and a 64-bit length below 65536 with a
   `WsError::Frame` that names the rule (`crates/podssh-ws/src/frame.rs:158-186`), before the
   payload is copied.
2. A client that receives such a frame fails the WebSocket connection (RFC 6455 section 7.1.7):
   it sends a Close with 1002, a protocol error (section 7.4.1), and then closes the TCP
   connection. Since T-063 the session sends that Close for each error of the decoder
   (`crates/podssh-ws/src/session.rs:245-252`), so this entry needs no new path.
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
