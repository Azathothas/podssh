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
  patch set below and `LOCAL-PATCHES.md`. A `diff -r` against the pristine
  clone therefore reports those nine paths and nothing else — they are the
  eight patches plus the bookkeeping file, not drift.
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
in memory that is cleared; and a logout.

Not done here: the home-region override, and connecting again after a drop
(T-104).

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
