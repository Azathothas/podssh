# Development

## Requirements

- Rust 1.89 or newer for the binary (the library crates build with 1.88;
  1.92 with the `ts` feature).
- A C compiler for the binary: the SSH client's crypto is aws-lc
  (`aws-lc-sys`, through `russh`); on Windows also NASM, or aws-lc falls back
  to prebuilt objects. The library crates (`podssh-ws`, `podssh-transport`,
  `podssh-core`, `podssh-terminal`, `podssh-probe`) need none, and the gate
  checks that. The `ts` feature also needs `cmake` and `perl`.
- Python 3 for the repository checks.
- For the container gate on Windows: Git Bash, PowerShell and the operator's
  `wsl-toolkit` (rootless Podman in a dedicated WSL distribution).

## Build and test natively

```sh
export CARGO_BUILD_JOBS=4          # see "Memory" below
cargo build                        # default members; target/debug/podssh
cargo test                         # default members
cargo test -p podssh-core          # one crate
cargo build -p podssh-cli --features ts                          # with Tailscale
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts   # its tests
```

A bare `cargo build`/`cargo test` at the root uses the workspace's
`default-members`, which leave out `crates/podssh-ts`; `--workspace` brings it
back.

The whole workspace builds and tests natively on Windows (MSVC) and Linux.
The static Linux release binary needs the musl target and is built in the
container (below).

## Memory

Cargo runs one job per CPU by default. On a 20-thread machine that is 20
compiler and linker processes at once. On 2026-10-07, three such builds ran
together, two of them in containers in an uncapped WSL VM, and nearly exhausted
a 64 GB Windows machine.

- Native builds: set `CARGO_BUILD_JOBS` (4 is comfortable on 32–64 GB), or put
  `jobs = 4` under `[build]` in `~/.cargo/config.toml`.
- Container builds: `scripts/dev.sh` passes `PODSSH_JOBS` (default 4), and
  `scripts/gate.sh` caps itself at one job per 3 GiB of available memory.
- Never run two container builds at once. `scripts/dev.sh` holds a lock in
  `.work/dev.lock` and refuses a second run.
- Container memory limits are **not** a protection here: the wsl-toolkit base
  has no cgroup delegation for its Podman account, so a memory or CPU limit is
  accepted and not enforced (`wsl-toolkit base ensure` reports this,
  2026-10-08). The job cap and the lock are what bound memory.
- WSL itself (operator's machine, not changed by any script): set a ceiling in
  `%USERPROFILE%\.wslconfig`, for example `memory=24GB` and `swap=8GB` under
  `[wsl2]`, then restart WSL yourself.

## Checks

```sh
python scripts/check-repo.py      # 500-line rule, doc links, no credentials, LF shell scripts
python scripts/check-scripts.py   # shell scripts parse under dash
python scripts/check-relay-spec.py  # the live relay still matches what podssh depends on
```

Read exit codes directly, not through a pipe (`cmd | tail` reports `tail`'s
status).

## The container gate

```sh
sh scripts/dev.sh check    # host checks, then scripts/gate.sh in rust:1-alpine
sh scripts/dev.sh plant    # proves the no-C-compiler check actually fires
sh scripts/dev.sh test -p podssh-core
sh scripts/dev.sh run -- 'uname -a'
sh scripts/dev.sh help
```

`scripts/gate.sh` is the gate; CI runs the same file in the same image. It
checks that:
1. the library crates build and pass their tests with `CC=/nonexistent`;
2. the SSH client and the CLI pass their tests;
3. the `ts` feature's tests pass;
4. the static musl release binary has no dynamic dependencies and no program
   interpreter;
5. that binary works against real servers: `scripts/interop.sh` installs
   OpenSSH and Dropbear in the throwaway container, starts them on 127.0.0.1
   and runs `podssh ssh --direct` against them (exit statuses and signals,
   streams and digests, every authentication method, host keys, `-W`, `-J`,
   `-s`, ptys through pipes, and an interactive pty driven by
   `scripts/interop-pty.py`: resize, Ctrl-C, `vi`, `less`, `top`, `~.`);
   `scripts/interop-keygen.sh` checks the keys `podssh keygen` makes with
   OpenSSH's own `ssh-keygen` and `sshd`;
6. podssh survives the relay failing: `scripts/interop-faults.sh` puts a
   stand-in relay (`scripts/fake-relay.py`, TLS from a CA made for the run)
   and a stand-in CONNECT proxy (`scripts/fake-proxy.py`) between podssh and
   OpenSSH, and has them fail one way each: a host that is down, one that
   answers 503, one that never answers after TLS, one that never starts TLS,
   a proxy answering 502, a Close mid-transfer (1011) and at the byte cap
   (1009), a stall (no frames, no Pongs), and a host killed mid-session. The
   stand-ins are written here, so they test podssh's handling of each fault;
   that podssh works with the real relay is what the live tests show.

Containers are ephemeral, and `.git`, `target/`, `.env/`, `.work/`, `.tmp/` and
`.codegraph/` are not copied into them.

## Tests that count

Unit tests in this repository have repeatedly passed while the code was wrong,
because the test built its input with the same assumptions as the code (see
[audit-2026-10-08.md](audit-2026-10-08.md)). For protocol code:

- test against something podssh did not write: a real OpenSSH/Dropbear
  server, a real ircd, the live relay, or bytes captured from one;
- a new check is trusted only after it has been seen to fail on a planted
  defect and pass on correct input;
- run the real binary with stdout and stderr on separate pipes: a stray
  `println!` once passed every in-memory test suite;
- in a live test that expects a failure, send nothing after triggering it
  (dropssh once read a data frame as close code 33319);
- use `cargo test --no-fail-fast`: without it, cargo stops at the first test
  target that fails and the rest never run.

Tests never use the network. The integration tests that run the binary set
`PODSSH_OFFLINE=1`, which makes any attempt to connect fail at once with a
message; in-process tests use a destination the relay cannot take, which is
refused before anything connects.

The live check of the whole proxy path (network; mints and caches a token
like the binary does):

```sh
cargo test -p podssh-cli --test proxy_live -- --ignored
```

Older live examples take a token from the environment. Mint it, use it and
discard it in one shell, and never print it:

```sh
export PODSSH_RELAY_TOKEN="$(curl -sS -X POST https://tcp.ssh.relay.ajam.dev/v1/mint \
  -H 'content-type: application/json' -d '{}' | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
cargo run -p podssh-transport --example live_forward -- --bundle /path/to/ca-bundle.pem
unset PODSSH_RELAY_TOKEN
```

## Line endings

`.gitattributes` stores sources as LF. Shell scripts must be LF (dash rejects
CRLF). The IRC wire fixtures under `crates/podssh-core/tests/fixtures/` are
stored byte-for-byte (`-text`) because CRLF is the protocol's terminator. Do
not bulk-convert line endings in files a change does not otherwise touch.

## Release builds

The shipped binary is `podssh-cli` built for `x86_64-unknown-linux-musl` with
`RUSTFLAGS=-Ctarget-feature=+crt-static` and the `release` profile (size-optimised,
fat LTO). `scripts/gate.sh` builds it and CI uploads it.

A tag `vX.Y.Z[-pre]` runs `.github/workflows/release.yml`: static musl
binaries for x86_64 and aarch64 (each built in `rust:1-alpine` on a native
runner and checked for dynamic dependencies), a Windows binary with a static C
runtime, `SHA256SUMS`, and a GitHub release whose notes are
`docs/releases/<tag>.md` (the workflow fails without that file). A tag with a
suffix (`-beta.1`) is published as a prerelease.
