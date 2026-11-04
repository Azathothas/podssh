# vendor/ — carried third-party source

Dependabot moves none of these copies, and cargo-deny passes over their
advisories, as each is a path package. Two watches stand in (T-341;
`docs/development.md`, "Updates"): `scripts/check-vendored.py`, each week,
fails when an upstream released what the line "Upstream read" of its section
does not name; `scripts/check-vendored-advisories.py`, on each push and each
day, fails on an advisory of advisory-db that names a copy's version. Read the
release or the advisory, judge it, then move the copy, or the line "Upstream
read" (or `deny.toml`'s ignores) with the day and the reason.

## tailscale-rs

- **Upstream**: <https://github.com/tailscale/tailscale-rs>
- **Commit**: `f4781c480e8d1376aed89f737beefe7425e8b866` (2026-09-29)
- **Upstream read**: `v0.6.1` on 2026-10-31, the newest release, which the
  commit above is past. Its head moves each day; its releases are what the
  watch reads (T-341).
- **Vendored**: 2026-10-05, from the clone `.tmp/tailscale-rs`
  (MEASURED 2026-10-05: `git log -1 --format='%H %cd'` in that clone printed
  the sha above). The **import** is byte-identical to that clone except
  `.git/`, which was dropped; the **shipped tree** is that import plus the
  patch set below and `LOCAL-PATCHES.md`. The patch set applied to an export
  of the pristine commit gives the shipped tree, and `diff -r` then names
  `LOCAL-PATCHES.md` alone (measured on 2026-11-01 with the 29 patches,
  T-384).
- **License**: BSD-3-Clause, with the patent grant (`LICENSE`, `PATENTS`
  retained). CI files and the upstream `AGENTS.md` are retained for fidelity.
- **Local patch set**: `patches/*.patch`, described patch by patch in
  [`tailscale-rs/LOCAL-PATCHES.md`](tailscale-rs/LOCAL-PATCHES.md).

### Why vendored

- podssh needs DERP-over-WebSocket, which upstream does not implement
  (`ts_derp` dials TCP + `Upgrade: DERP` only), plus two reachable `unwrap()`
  panics fixed (upstream issue #439). Upstream declines external PRs (#291),
  so the changes are carried as a patch set over a pinned commit.
- A git or `[patch.crates-io]` dependency would add an external moving target
  to every build and would not carry the patches. A vendored subtree is
  reproducible and inspectable, and it keeps the third-party code out of
  podssh's workspace: the vendored tree has its own `[workspace]`, so its
  crates are not podssh workspace members. (The 500-line rule and the
  `CC=/nonexistent` gate scan `crates/` only; this tree is outside both.)
- podssh reaches the vendored crates later by path dependency from the adapter
  crate. To check the smoke property: `cargo metadata` in the podssh root must
  show only podssh's members.

### How to re-vendor

```sh
# 1. Fresh upstream checkout at the pinned commit (read-only scratch).
git clone https://github.com/tailscale/tailscale-rs .tmp/tailscale-rs-new
git -C .tmp/tailscale-rs-new checkout f4781c480e8d1376aed89f737beefe7425e8b866

# 2. Replace the tree, drop the clone's .git, keep everything else.
#    LOCAL-PATCHES.md is podssh-authored bookkeeping: keep the old copy.
cp vendor/tailscale-rs/LOCAL-PATCHES.md .tmp/LOCAL-PATCHES.md.keep
rm -rf vendor/tailscale-rs
cp -a .tmp/tailscale-rs-new vendor/tailscale-rs
rm -rf vendor/tailscale-rs/.git
cp .tmp/LOCAL-PATCHES.md.keep vendor/tailscale-rs/LOCAL-PATCHES.md

# 3. Re-apply the local patch set (each must exit 0).
for p in vendor/patches/*.patch; do
    patch -p1 -d vendor/tailscale-rs < "$p" || exit 1
done
```

When re-pinning to a newer commit, expect the patch set to need a rebase; the
patch files are the artifact to carry, and `git apply --check` against the new
pristine tree is the cheap way to detect drift. `Cargo.lock` is patched by
`0008`; regenerate it with `cargo update -p ts_derp` in the vendored tree after
a re-pin, and the diff should show only dependency-resolution changes.

### What this tree provides

`tailscale-rs/LOCAL-PATCHES.md` describes each patch, with its proof. In
short: DERP over a WebSocket to a pinned relay (`ts_derp::ws`), with the
ClientInfo JSON that the relay's parser expects; one HTTP CONNECT or SOCKS5
proxy for each connection of the node, to the control server and to DERP,
over the WebSocket too, by host name, with a `no_proxy` list and a bound on
each dial;
the runtime options that gate UDP off and pin the relay; the tailnet auth key
in memory that is cleared; a logout; and a test's CA beside the roots, from
`PODSSH_TS_TEST_CA_FILE`, for the stand-in control server of
`scripts/ts-headscale.sh` (0027, T-334).

Not done here: the home-region override, and connecting again after a drop
(T-104).

## russh

- **Upstream**: <https://github.com/warp-tech/russh> (once Eugeny/russh),
  the release 0.65.0 of crates.io, whose `.cargo_vcs_info.json` names the
  commit `183a22e8f8f490fa09b6eb7bd044ef99d8c4414f`.
- **Upstream read**: 0.65.0 on 2026-11-02, the copy's own release and the
  newest of crates.io; its default branch reads such replies as 0.65.0 does.
- **Vendored**: 2026-11-02 (T-460), from the copy that cargo unpacked of
  that release, whose archive has the SHA-256 of `Cargo.lock`'s checksum
  (`3bb77a4b...`). The import is the published crate byte for byte, but
  `.cargo-ok`, a mark of cargo's own; the shipped tree is the import plus
  the patches of `patches/russh/`, in the order of their numbers
  (`0001-reply-data.patch`, `0002-window-target.patch` of T-661,
  `0003-publickey-signed-at-once.patch` of T-664, and `0004-window-low.patch` of
  T-670), and nothing else.
- **License**: Apache-2.0, as its `Cargo.toml` says.
- **How podssh uses it**: the root `Cargo.toml` puts it in the place of the
  release with `[patch.crates-io]`, and excludes it from the workspace, so
  its tests, examples and benches are not podssh's; `fuzz/Cargo.toml` does
  the same. The version stays 0.65.0, so no requirement changes, and the
  lock files' `russh` entries have no source and no checksum, as a path
  package has none. `scripts/check-repo.py` fails when a lock leaves the
  patch unused, as it would after an update of russh that did not move it.

### The patches

| Patch | Files | Why |
| --- | --- | --- |
| `patches/russh/0003-publickey-signed-at-once.patch` | `src/auth.rs`, `src/client/encrypted.rs`, `src/client/mod.rs` | podssh T-664: russh's client sends each public key as a query first (`USERAUTH_REQUEST` with FALSE), and signs only after the server's `USERAUTH_PK_OK`: a round trip that RFC 4252, section 7, lets a client leave out for a key that the server takes. The patch adds `auth::Method::PublicKeySigned` and `Handle::authenticate_publickey_signed`, whose first request carries the signature, built by the code that answers a `USERAUTH_PK_OK` (`client_send_key_signature`), so its bytes are those of the second request of a query; a server that does not take the key answers with a failure, as to a query. OpenSSH's client sends such a request for a key file with no `.pub` beside it. podssh sends it for the key that a host took last (`crates/podssh-ssh/src/accepted.rs`). Proven by the test `client::encrypted::tests::a_key_signed_at_once_is_one_request_with_its_signature` (the request's bytes, and its signature checked as a server checks it), and in podssh by `crates/podssh-ssh/tests/cold_connect.rs` against russh's server. Since this patch, podssh calls a method that the published crate lacks, so T-460's plant `t460-published-russh` takes 0001 out of the copy in place of the published crate. |
| `patches/russh/0001-reply-data.patch` | `src/client/encrypted.rs`, `src/client/mod.rs`, `src/client/reply_data.rs` (new) | podssh T-460, GitHub #83 and #85: russh's client ended the whole connection when a reply to a global request held data after its type: `ensure_end` on each failure, before it looked at which request the reply answers, and on a success of a keepalive, a ping, `no-more-sessions@openssh.com` or a cancel; and it read a success of `tcpip-forward` with more than a port as a refusal. RFC 4254, section 4, lets a success carry "response specific data", and Go's x/crypto/ssh sends data in a failure too (`Request.Reply(false, payload)`): its servers answer a keepalive that they do not know with one, so each quiet session on them died at the first keepalive, and `-R` that they refuse as a lost connection. OpenSSH's client reads none of such data. The patch drops the data that a request needs none of, with a debug line, and reads the port of a success of `tcpip-forward` before the rest. Proven by the tests of `src/client/reply_data.rs`, in russh's own way of crafted packets, and in podssh by `scripts/interop-go-ssh.sh` against a server of x/crypto/ssh. |
| `patches/russh/0002-window-target.patch` | `src/client/encrypted.rs`, `src/client/mod.rs`, `src/client/window_target.rs` (new) | podssh T-661: russh's client adjusted each channel's window to its configured window alone; the target that its handler's `adjust_window` returned was kept in the session and never read, so no client could hold a bulk channel's window while the user types. The patch adds `Handler::window_target(channel, window) -> u32`, asked at each data message of a channel before russh decides whether to adjust its window: its answer is that channel's target, and the default, `window`, keeps russh's behaviour, as 0 does. A window already granted is never taken back (RFC 4254, section 5.2): a smaller target withholds the next adjusts. `adjust_window` still hears each adjust that went out. Proven by the tests of `src/client/window_target.rs`, in the way of crafted packets of `reply_data.rs`, and in podssh by `crates/podssh-ssh/src/pace/wire_tests.rs` against russh's server in the same process. |
| `patches/russh/0004-window-low.patch` | `src/client/encrypted.rs`, `src/client/mod.rs`, `src/client/window_target.rs`, `src/session.rs` | podssh T-670: russh adjusted a window to its target only once less than half of it was left, so a window that bounds the flow let about half of itself through each round trip: the rate that podssh measured from it gave back the same window, which never grew while the user typed on a long path. The patch adds `Handler::window_low(channel, target) -> u32`, the room left under which russh adjusts a channel's window to its target, asked after `window_target` at each data message; the default, half the target, keeps russh's behaviour, as 0 does, and a room over the target is the target, so no adjust takes a window back. `Encrypted::adjust_window_size_below` takes the room; `adjust_window_size`, which russh's server calls, keeps the half. Proven by the tests of `src/client/window_target.rs` (a room of a quarter used, one over the target, one of 0, and stderr's), and in podssh by `crates/podssh-ssh/src/pace/sim_tests.rs`. |

No podssh build runs the crate's own tests. Run its tests of the patches
with its manifest, in a target directory of their own (it fetches the
crate's dev-dependencies, and uses the crate's own `Cargo.lock`):
`cargo test --manifest-path vendor/russh/Cargo.toml --target-dir
.work/russh-target --lib client::reply_data`, `... --lib
client::window_target` and `... --lib
client::encrypted::tests::a_key_signed_at_once`.

The patches are for russh upstream too: sending them is the operator's, as
no session changes another repository. Drop a patch when a release of russh
does what it does (reads such replies; adjusts a window to the handler's
target; sends a signed request with no query first), and this tree with the
last one.

### How to carry it to another version

```sh
# 1. The published crate, from cargo's copy (after a build that fetched it),
#    or downloaded from crates.io and checked against Cargo.lock's checksum.
rm -rf vendor/russh
cp -r ~/.cargo/registry/src/index.crates.io-*/russh-NEW/. vendor/russh/
rm -f vendor/russh/.cargo-ok

# 2. The patches in their order (each must exit 0), then the version of the
#    crates' requirement of russh, and the lock files, follow.
for p in vendor/patches/russh/*.patch; do
    git apply --directory=vendor/russh "$p" || exit 1
done
```

Each patch is a unified diff of the tree before it (`a/`: the published
crate for 0001, the crate with the patches before for each later one)
against the tree after it (`b/`); `patch -p1 -d vendor/russh` takes them
too. A release whose reading of a reply, adjust of a window or authentication changed
needs the patches moved onto it, and their tests run again.

## iroh-relay

- **Upstream**: the crate `iroh-relay` 1.4.1 as crates.io publishes it
  (<https://crates.io/crates/iroh-relay>), from n0-computer/iroh at
  `d6c6963b9602d1b8dd2ba53b6519e7eb19cc7940` (its `.cargo_vcs_info.json`).
- **Upstream read**: 1.4.1 on 2026-10-31, the copy's own release.
- **Vendored**: 2026-10-12 (T-280) at 1.3.0, and carried to 1.4.1 on
  2026-10-30 with Dependabot's update of iroh, from cargo's copy of the
  published crate; the patch applied with no change. The import is that crate byte for byte, but cargo's own marker
  `.cargo-ok`; the shipped tree is the import plus the patch of
  `patches/iroh-relay/`, and nothing else.
- **License**: MIT OR Apache-2.0, with the BSD-3-Clause notice of the code
  that it took from Tailscale (`LICENSE-BSD3`, retained).
- **How podssh uses it**: `[patch.crates-io]` in the root `Cargo.toml`, so
  that iroh 1.4.1, which asks for iroh-relay 1.4.1, builds this copy; the
  tree is excluded from the workspace, so its tests and their dependencies
  are not podssh's. Only the feature `iroh` of podssh-cli compiles it.

### The patch

| Patch | Files | Why |
| --- | --- | --- |
| `patches/iroh-relay/0001-socks5-proxy.patch` | `Cargo.toml`, `src/client.rs`, `src/client/socks5.rs` (new), `src/client/tls.rs` | podssh T-280: the relay dial (`dial_url_proxy`) spoke HTTP `CONNECT` only, and took a `socks5h://` URL for a proxy that speaks TLS. A `socks5://` or `socks5h://` proxy now gets the exchange of RFC 1928 on its TCP connection, with no TLS of its own: the relay's name with the address type 3 (an address only when the relay's URL holds one), the user and password of RFC 1929 from the URL, percent-decoded, the reply read to exactly its end, and on reply 8 one more connection with an address from the client's resolver; the exchange has 10 s. A proxy URL with no port means 1080. The proxy's URL, which may hold a password, is no longer in the debug log of the dial. reqwest's feature `socks` is on, so that iroh's HTTPS probe of the relays, which picks the home relay, goes through the same proxy; in reqwest 0.13 it is hyper-util's SOCKS client, which reqwest already builds, so no crate is added. Proven by the unit tests of `src/client/socks5.rs` (the bytes of the name and of RFC 1929, a reply read to its end, reply 8 told apart) and, in podssh, by `crates/podssh-iroh/tests/proxy_env.rs`. |

No podssh build runs the crate's own tests. Run its unit tests of the patch
with its manifest, in a target directory of their own (it fetches the
crate's dev-dependencies, and uses the crate's own `Cargo.lock`):
`cargo test --manifest-path vendor/iroh-relay/Cargo.toml --target-dir
.work/iroh-relay-target --lib client::socks5`.

### How to carry it to another version

```sh
# 1. The published crate, from cargo's copy (after a build that fetched it).
rm -rf vendor/iroh-relay
cp -r ~/.cargo/registry/src/index.crates.io-*/iroh-relay-NEW/. vendor/iroh-relay/
rm -f vendor/iroh-relay/.cargo-ok

# 2. The patch (each must exit 0), then the version in the root's
#    [patch.crates-io] follows iroh's.
git apply --directory=vendor/iroh-relay vendor/patches/iroh-relay/*.patch
```

An iroh that asks for another iroh-relay leaves the patch unused: cargo says
so ("patch ... was not used in the crate graph"), and the SOCKS5 test of
`crates/podssh-iroh/tests/proxy_env.rs` fails, as the published dial takes
a `socks5h://` proxy for one that speaks TLS.

## ssh-key

- **Upstream**: <https://github.com/RustCrypto/SSH> (its directory
  `ssh-key`), the release 0.7.0-rc.11 of crates.io, whose
  `.cargo_vcs_info.json` names the commit
  `7a1c757d2e2fcde32680e373d5226481de6d434e`.
- **Upstream read**: 0.7.0-rc.11 on 2026-11-03, the copy's own release and
  the newest version of crates.io (its newest stable, 0.6.7, is older); the
  watch reads the newest version of all for a copy of a prerelease.
- **Vendored**: 2026-11-03 (T-609), from the copy that cargo unpacked of that
  release, whose archive has the SHA-256 of `Cargo.lock`'s old checksum
  (`f9a32fae...`). The import is the published crate byte for byte, but
  `.cargo-ok`, a mark of cargo's own, and two of its test keys,
  `tests/examples/id_ed25519` and `tests/examples/id_ed25519.64cols`, which
  GitHub's push protection refuses as SSH private keys (they log in nowhere,
  and only the crate's own tests, which podssh never runs, read them); the
  shipped tree is the import plus the one patch
  `patches/ssh-key/0001-ecdsa-short-scalar.patch`, and nothing else.
- **License**: Apache-2.0 OR MIT, as its `Cargo.toml` says (`LICENSE-APACHE`,
  `LICENSE-MIT` retained).
- **How podssh uses it**: russh reads every private key through it (OpenSSH's
  format, plain and encrypted, and PuTTY's). The root `Cargo.toml` and
  `fuzz/Cargo.toml` put it in the place of the release with
  `[patch.crates-io]`, and the root excludes it from the workspace, so its
  tests, examples and benches are not podssh's. The version stays
  0.7.0-rc.11, so no requirement changes, and the lock files' `ssh-key`
  entries have no source and no checksum.
- **Its test keys**: `tests/examples/` and its doc comments hold the
  crate's own throwaway keys, which log in nowhere; the secrets scan reads
  them as unverified findings, and `.github/secrets-allow.txt` names any
  that it could not verify.

### The patch

| Patch | Files | Why |
| --- | --- | --- |
| `patches/ssh-key/0001-ecdsa-short-scalar.patch` | `src/private/ecdsa.rs` | podssh T-609: an ECDSA private key's scalar is an `mpint`, which has no leading zero bytes, so OpenSSH's `ssh-keygen` writes a P-256 scalar whose first byte is zero (and whose next byte has no high bit) in 31 bytes or fewer, one key of 512. The release refused each scalar under 32 bytes ("length invalid"), so podssh could not use such a key, and the gate's interop test, whose `id_ecdsa` `ssh-keygen` makes anew each run, failed at random (run 41647533798). The patch takes any length from 1 to the field's size, as the code below it already pads. Proven in podssh by `key_file::tests::an_ecdsa_key_whose_scalar_openssh_writes_short_is_read`, a key built as OpenSSH writes it, and by a key of OpenSSH 9.6's `ssh-keygen` with a scalar of 31 bytes (`podssh keygen -y` gave its public key). |

The patch is for ssh-key upstream too: sending it is the operator's, as no
session changes another repository. Drop the patch, and this tree, when a
release of ssh-key reads such keys.

### How to carry it to another version

```sh
# 1. The published crate, from cargo's copy (after a build that fetched it).
rm -rf vendor/ssh-key
cp -a ~/.cargo/registry/src/*/ssh-key-NEW vendor/ssh-key
rm -f vendor/ssh-key/.cargo-ok
# The two test keys that GitHub's push protection refuses.
rm -f vendor/ssh-key/tests/examples/id_ed25519 vendor/ssh-key/tests/examples/id_ed25519.64cols
# 2. The patch, then the version in Cargo.lock and fuzz/Cargo.lock.
patch -d vendor/ssh-key -p1 < vendor/patches/ssh-key/0001-ecdsa-short-scalar.patch
cargo update -p ssh-key --offline
(cd fuzz && cargo update -p ssh-key --offline)
```
