# vendor/ — carried third-party source

## tailscale-rs

- **Upstream**: <https://github.com/tailscale/tailscale-rs>
- **Commit**: `f4781c480e8d1376aed89f737beefe7425e8b866` (2026-09-29)
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
ClientInfo JSON that the relay's parser expects; one HTTP CONNECT proxy for
each connection of the node, to the control server and to DERP, over the
WebSocket too, by host name, with a `no_proxy` list and a bound on each dial;
the runtime options that gate UDP off and pin the relay; the tailnet auth key
in memory that is cleared; and a logout.

Not done here: the home-region override, and connecting again after a drop
(T-104).
