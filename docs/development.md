# Development

This page tells how to build podssh, test it, measure it in a box like the
target sandbox, and release it.

## Requirements

- Rust 1.89 or later for the binary. The library crates build with Rust
  1.85, podbox's minimum; the gate checks them on it. The `ts` feature needs
  Rust 1.92.
- A C compiler for the binary. The SSH client uses aws-lc (`aws-lc-sys`,
  through `russh`). On Windows, also NASM; without it, aws-lc uses prebuilt
  objects.
- No C compiler for the library crates (`podssh-ws`, `podssh-relay`,
  `podssh-core`, `podssh-terminal`, `podssh-probe`). The gate makes sure of
  this.
- `cmake` and `perl` for the `ts` feature only.
- Python 3 for the repository checks.
- For the container gate on Windows: Git Bash, PowerShell, and the
  operator's `wsl-toolkit`.
- For the box like the target sandbox: Podman. On Windows, the Podman
  machine.

## Build and test natively

CAUTION: Set the job limit first. See "Memory".

```sh
export CARGO_BUILD_JOBS=4
cargo build                        # target/debug/podssh
cargo test --no-fail-fast          # the default members
cargo test -p podssh-core          # one crate
cargo build -p podssh-cli --features ts                          # with Tailscale
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts   # its tests
cargo test -p podssh-ws --features plain-ws --test plain_loopback   # plain ws:// to loopback, for tests
```

- A `cargo build` or `cargo test` at the root uses `default-members`. These
  do not include `crates/podssh-ts`. Use `--workspace` to include it.
- Use `--no-fail-fast`. Without it, cargo stops at the first test target
  that fails, and the remaining targets do not run.
- The workspace builds and tests natively on Windows (MSVC) and Linux. The
  static Linux binary needs the musl target. The container gate builds it.

## Memory

Cargo runs one job for each CPU. On a machine with 20 threads, that is 20
compilers and linkers at the same time.

CAUTION: On 2026-10-07, three uncapped builds at the same time almost used
all the memory of a 64 GB machine.

1. For native builds, set `CARGO_BUILD_JOBS=4`. You can also put `jobs = 4`
   under `[build]` in `~/.cargo/config.toml`.
2. For container builds, `scripts/dev.sh` gives `PODSSH_JOBS` (default 4).
   `scripts/gate.sh` limits itself to one job for each 3 GiB of free memory.
3. Do not run two container builds at the same time. `scripts/dev.sh` holds
   a lock in `.work/dev.lock` and refuses a second run.

NOTE: A memory limit on a container does not protect the machine here. The
wsl-toolkit base gives no cgroup delegation to its Podman account, so it
accepts a memory or CPU limit and does not enforce it. The job limit and the
lock are the protection.

NOTE: To limit WSL itself, the operator can set `memory=24GB` and
`swap=8GB` under `[wsl2]` in `%USERPROFILE%\.wslconfig`, and restart WSL.
No script changes this file.

## Checks

```sh
python scripts/check-repo.py        # 500-line rule, doc links, credentials, LF in shell scripts
python scripts/check-scripts.py     # shell scripts parse under dash
python scripts/check-relay-spec.py  # the live relay still matches what podssh uses
cargo todo check                    # the work record in TODO/ agrees: counts, statuses, cited paths and lines, no citation left unmoved
cargo todo remap FILE...            # after an edit of FILE: move its citations by a diff against HEAD
```

Read each exit code directly. `cmd | tail` gives the exit code of `tail`.

## The container gate

```sh
sh scripts/dev.sh check    # the host checks, then scripts/gate.sh in the build image
sh scripts/dev.sh plant    # shows that the checks for "no C or C++ compiler" work
sh scripts/dev.sh images   # the build image runs: its uname, rustc and cargo
sh scripts/dev.sh test -p podssh-core
sh scripts/dev.sh run -- 'uname -a'
sh scripts/dev.sh help
```

Each image is named in one place, pinned to the digest of its multi-platform
index: `.github/images/build/Dockerfile` (`rust:1-alpine`, for the gate, CI
and the release), `.github/images/box/Dockerfile` (`alpine:3.20`, the box and
its SSH server) and `.github/images/box-proxy/Dockerfile`
(`python:3.12-alpine`, the box's proxy). The scripts and the workflows read
their `FROM` line, so two runs of one commit use one compiler, and
`python scripts/check-repo.py` fails on a second name. To move to a newer
image, read the digest of its index (`docker buildx imagetools inspect REF`;
the index must list linux/amd64 and linux/arm64, which the release builds),
write it into the Dockerfile, and run the gate.

`scripts/gate.sh` is the gate. CI runs the same file in the same image. The
gate makes sure that:

1. The library crates build and pass their tests with `CC=/nonexistent`
   and `CXX=/nonexistent`. The `cc` crate reads `CXX` for C++, so `CC` alone
   does not stop a C++ dependency on a host that has `c++`. The test of the
   feature `plain-ws` of `podssh-ws` runs too, and `scripts/no-plain-ws.sh`
   shows that the binary does not enable it (T-068).
2. The work record agrees with itself (`crates/podssh-todo`). Its checker
   passes its tests, where each planted disagreement must be found, and then
   checks `TODO/`: the counts against the rows, the status, title and
   milestone of each row against its entry, each id that a document names,
   each cited path and line, the work order, and `docs/ROADMAP.md`.
3. The SSH client and the command line pass their tests.
4. The tests of the `ts` feature pass.
5. The static musl binary has no dynamic dependencies and no program
   interpreter.
6. The binary works against real servers. `scripts/interop.sh` installs
   OpenSSH and Dropbear in the container, starts them on 127.0.0.1, and runs
   `podssh ssh --direct` against them: exit statuses and signals, streams
   and digests, each authentication method, host keys, `-W`, `-J`, `-s`,
   ptys through pipes, and a real pty (`scripts/interop-pty.py`: resize,
   Ctrl-C, `vi`, `less`, `top`, `~.`).
7. OpenSSH accepts the keys of `podssh keygen` (`scripts/interop-keygen.sh`):
   its `ssh-keygen` reads them and its `sshd` accepts them for login.
8. podssh handles a relay that fails (`scripts/interop-faults.sh`). A
   stand-in relay (`scripts/fake-relay.py`, with TLS from a CA made for the
   run) and a stand-in proxy (`scripts/fake-proxy.py`) fail in one way each:
   a host that is down, a 503, a host that does not answer after TLS, a host
   that does not start TLS, a proxy 502, a Close during a transfer (1011)
   and at the byte limit (1009), a stall, and a host that stops during a
   session.
9. The man page renders (`scripts/interop-man.sh`): groff and mandoc show
   each flag that `--help` shows, groff gives no warning, and `mandoc -Tlint`
   gives no error. A planted page, with one flag's term removed, must fail.

NOTE: The stand-ins are part of this repository. They test how podssh
handles each fault. The live tests show that podssh works with the real
relay.

The containers are temporary. `.git`, `target/`, `.env/`, `.work/`, `.tmp/`
and `.codegraph/` are not copied into them.

## A box like the target sandbox

`scripts/test_in_box.sh` uses Podman to build a box with the properties of
the target sandbox, and measures podssh in the box.

1. Get a static Linux binary of podssh. Use the release workflow's artifact
   or the gate's build.
2. On Windows, start the Podman machine: `podman machine start`.
3. Run the script:

   ```sh
   sh scripts/test_in_box.sh path/to/podssh-x86_64-unknown-linux-musl
   ```

The box has these properties:

- No route out. The only way out is a CONNECT proxy
  (`scripts/box/proxy.py`). It allows ports 443, 80 and 8443 to public
  hosts, and refuses other ports and private addresses with the texts of the
  sandbox's proxy.
- A resolver that does not answer, no capabilities, `no_new_privs`, and a
  seccomp filter that refuses `bind` and UDP (`scripts/box/seccomp.json`).
- No `/dev/ptmx`, and uid 0 with no name.
- A `/dev/tty` that opens and never answers, and no controlling terminal,
  as in the target sandbox. `scripts/box/deadtty.py` holds a pty with
  nobody at its master on the Podman host (the Podman machine on Windows),
  and the box has its slave at `/dev/tty`. It needs Python 3 and `setsid`
  on that host.

`BOX_RUN=tt sh scripts/test_in_box.sh BINARY` runs an interactive session
over `-tt` instead of `sandbox-check.sh` (T-004): `scripts/box/tt-session.sh`
writes keys for `vi`, `less`, `top` and Ctrl-C through a pipe to OpenSSH in a
container next to the box, which the box's proxy lets through
(`proxy.py --allow`), and checks five markers.

`scripts/box/probe.sh` compares the box with the operator's sandprobe report
of the target sandbox. If a required property is different, the script stops
and does not run podssh. Then `scripts/sandbox-check.sh` runs `doctor`,
`proxy`, `keygen`, `ssh`, a prompt with nobody to answer it, and OpenSSH
with podssh as its `ProxyCommand`.

NOTE: The box does not give EACCES for `connect()` to loopback and to some
ports, as the sandbox does.

NOTE: The sandprobe report is `.work/sandprobe-run1.txt`. It is not in the
repository, because it describes the operator's own sandbox.

To measure a real sandbox, run `sh scripts/sandbox-check.sh` in it. With no
argument, the script builds podssh first, and finds the binary where cargo
put it: `CARGO_TARGET_DIR`, the `target_directory` of `cargo metadata`, or
`target/`. It runs the binary once before the steps. Each step prints `ok`
or `FAIL` against its expected result, or `skip` with the reason when it
cannot run on that host (no `ssh`, or an OpenSSH that needs a user database
entry). The script exits 1 when a step failed.

In a sandbox where `/tmp` or `$HOME` is mounted `noexec`, `CARGO_HOME`
cannot be written, or `/tmp` is small, give cargo a directory where programs
can run. `podssh doctor` names such directories in its `exec` lines; with no
binary yet, copy `/bin/true` into a directory and run it from there.

```sh
export CARGO_HOME=/work/cargo CARGO_TARGET_DIR=/work/target TMPDIR=/work/tmp
mkdir -p "$TMPDIR"
sh scripts/sandbox-check.sh
```

## Rules for tests

These rules are necessary because tests here passed while the code was
wrong: the tests built their input with the same assumptions as the code.

1. Test protocol code against software that podssh did not write: an
   OpenSSH or Dropbear server, a real IRC server, the live relay, or bytes
   captured from one.
2. Trust a new check only after it fails on a planted defect and passes on
   correct input.
3. Run the real binary with stdout and stderr on different pipes. A stray
   `println!` passes every test that runs in memory.
4. In a live test that expects a failure, send nothing after the trigger.
   Extra bytes can arrive in place of the close code.
5. Do not use the network in a test. The tests that run the binary set
   `PODSSH_OFFLINE=1`, which makes each connection attempt fail at once
   with a message. The tests that run in the process use a destination that
   the relay cannot take, so podssh refuses it before it connects.

## Live tests

These tests use the network. Run them only on request.

```sh
cargo test -p podssh-cli --test proxy_live -- --ignored   # the proxy path, with a token
cargo test -p podssh-cli --test doctor -- --ignored       # doctor, end to end
cargo test -p podssh-ws --test live_doh -- --ignored      # DNS over HTTPS
cargo test -p podssh-relay --test live -- --ignored       # the relay answers pings
cargo test -p podssh-relay --features pair --test pair_live -- --ignored     # a pair, made and stopped
cargo test -p podssh-relay --features pair --test reverse_live -- --ignored  # a node and its operators
cargo test -p podssh-relay --features blocking --test blocking_live -- --ignored  # the same, and a forward session, through the facade
```

For interactive use on Windows, `scripts/interop-conpty.py` runs
`podssh ssh -t` in a real pseudo console against an SSH server that you
give:

```sh
python scripts/interop-conpty.py target/debug/podssh.exe root@HOST --direct
```

`scripts/capture-close.py` captures the payload of a Close that the live
relay sends, with a client of the Python standard library: bytes that podssh
did not make, for a fixture of the Close parser
(`crates/podssh-ws/tests/control_frames.rs`). It mints a token that it keeps
in memory and never prints:

```sh
python scripts/capture-close.py              # github.com:22: 1000 target closed
python scripts/capture-close.py --client-close   # what the relay does after the client's Close
python scripts/capture-reverse.py            # one session of the reverse road, frame by frame
```

`scripts/capture-reverse.py` makes a pair, opens the node's and an
operator's socket, and records each frame of one session (`hello`, `open`,
`ready`, data both ways, `close`) and whether the relay answers a Ping on the
node's socket and on the operator's; it stops the pair at the end and prints
no token.

The examples open a forward session as `podssh ssh` does
(`podssh_relay::open`): a token from the environment, the cache or a mint,
never printed.

```sh
cargo run -p podssh-relay --example live_forward          # github.com:22: its SSH banner
cargo run -p podssh-cli --example live_irc                 # an IRC registration through the relay
```

## Line endings

- `.gitattributes` stores the sources with LF.
- Shell scripts must use LF. dash refuses CRLF.
- The IRC wire fixtures in `crates/podssh-core/tests/fixtures/` are stored
  byte for byte (`-text`), because CRLF ends each IRC line.
- Do not change the line endings of a file that a change does not otherwise
  touch.

## Updates

Dependabot (`.github/dependabot.yml`) looks each week at the crates of the
workspace's `Cargo.lock`, the actions of the workflows, and the three pinned
images of `.github/images/`. Minor and patch updates of the crates come in one
pull request, and each major update alone; the actions come in one. The fork
in `vendor/tailscale-rs` has no entry: it follows its own patches. CI checks
the configuration against Dependabot's published schema, with a planted copy
that must fail.

Each pull request of Dependabot runs the whole CI: the gate, whose steps with
no C compiler judge each update of a library crate's dependencies and whose
check on Rust 1.85 refuses an update that needs a newer compiler; the plant;
and the live check of the relay's document. An update whose CI is green is
applied as the operator's own commit, then its pull request is closed:

```sh
git fetch origin pull/NUMBER/head
git cherry-pick --no-commit FETCH_HEAD   # the change, not the bot's commit
git commit                               # the operator's commit; then the checks, and push
```

A merge in GitHub's page, or a plain `git cherry-pick`, would keep the bot
as the author, and each commit of this repository is the operator's
(`docs/decisions.md`). A minimum Rust is raised only by a decision, never to
let an update in.

## Release builds

The released Linux binary is `podssh-cli` for `x86_64-unknown-linux-musl`,
built with `RUSTFLAGS=-Ctarget-feature=+crt-static` and the `release`
profile (optimized for size, fat LTO). `scripts/gate.sh` builds it, and CI
uploads it.

`.github/workflows/release.yml` makes the release binaries:

- static musl binaries for x86_64 and aarch64, each built in
  `rust:1-alpine` on a native runner, with a check for dynamic dependencies;
- a Windows binary with a static C runtime, with a check (`dumpbin
  /dependents`) that it needs no C runtime DLL.

To build and check the binaries without a release, run the workflow by hand:

```sh
gh workflow run release.yml --ref main
```

To publish a release:

1. Write the notes in `docs/releases/<tag>.md`. The workflow fails without
   this file.
2. Push the tag `vX.Y.Z` or `vX.Y.Z-pre`. A tag with a suffix (`-beta.1`)
   becomes a prerelease.
3. The workflow adds `SHA256SUMS` and publishes the release.

The plan of releases (the operator, 2026-10-08): one release, `v1.0.0`,
when each other entry is done, except the relay's (T-250). No beta, and no
release between entries: a release run takes CI from the work. The check
from end to end with no human (T-251) runs before the tag, on the gate's
artifact of the last push and a local build; then `v1.0.0` is tagged once,
and the check runs again on the published files. A defect found then goes
into `v1.0.1`. From T-210 and T-211 on, each release also has provenance
and Sigstore signatures.
