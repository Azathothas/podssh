# podssh

SSH from machines whose only way out is HTTPS.

podssh is one static binary. It is an SSH client, and it can carry any TCP
stream, through a WebSocket relay on port 443. It is for closed sandboxes:
CI runners, containers of AI agents, hosted notebooks. Such hosts have no
inbound ports and no direct outbound TCP. Often they have no working DNS, and
an HTTP proxy is their only way out. podssh needs no root, no `LD_PRELOAD`,
no installed `ssh`, and no TLS or crypto library of the system.

> [!WARNING]
> **Status: beta.** `podssh ssh`, `podssh proxy`, `podssh cp` (files),
> `podssh doctor`, `podssh keygen`, `podssh man`, `podssh status` and the
> reverse road (`podssh node`, `podssh operator`, `podssh relay`) work.
> Tests run them against OpenSSH and Dropbear servers, through the live
> relay, and in a box like the target sandbox. Chat, `podssh mv` and the
> copy of directories are not available yet. The measured state is in
> [docs/STATUS.md](docs/STATUS.md). The plan is in
> [docs/ROADMAP.md](docs/ROADMAP.md).

## How it works

```
podssh --TLS 1.3 + WebSocket, port 443--> relay --TCP--> sshd (or another TCP service)
   `-- through HTTPS_PROXY (HTTP CONNECT) when the host has one
```

- **The relay** ([`tcp.ssh.relay.ajam.dev`](https://tcp.ssh.relay.ajam.dev/),
  a Cloudflare Worker) copies bytes between a WebSocket and a TCP socket. Its
  contract is at [`/llms-full.txt`](https://tcp.ssh.relay.ajam.dev/llms-full.txt).
  [docs/relay.md](docs/relay.md) gives the parts that podssh uses.
- **Encryption.** SSH encrypts the session between podssh and the server.
  The relay can see the target, the time and volume of the traffic, and the
  start of the SSH handshake. The host-key check makes a relay in the middle
  safe. See [SECURITY.md](SECURITY.md).
- **Outbound only.** podssh opens outbound connections only (to the relay,
  or to the proxy that `HTTPS_PROXY` names). It never listens on a port.
- **Fallbacks.** If one relay host fails, podssh tries the next one. If DNS
  fails, podssh uses pinned addresses or DNS over HTTPS. If the relay goes
  silent, podssh finds it in 30 to 40 s.
- **No local pty needed.** A remote pty (`-tt`) works when stdin and stdout
  are pipes. Full-screen programs and Ctrl-C work on a host that has no
  `/dev/ptmx`.

## First steps on a new host

1. Get a static binary for the host: from the releases page when a release
   exists, or build one (see "Build"). Make it executable.
2. Run `podssh doctor`. It tells what the host allows and whether the full
   path works: one `ok`, `FAIL` or `????` line for each check (`????` is a
   check that could not run). It exits 1 if a check failed.
3. Run `podssh man`. It is the whole manual: each command, flag, `-o`
   keyword, variable, file and exit code, with examples. The binary makes it
   from its own tables and needs nothing else. `podssh man ssh` gives one
   section; `podssh man --no-pager` writes it all to stdout.
4. If the host has no working `ssh-keygen`, make a key with podssh:

   ```sh
   podssh keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519   # -N '' for no passphrase
   podssh keygen -l -f ~/.ssh/id_ed25519.pub             # its fingerprint
   ```

## Usage

podssh is the SSH client, with the options of OpenSSH:

```sh
podssh ssh user@example.org                  # an interactive shell
podssh ssh user@example.org 'uname -a'       # a command; its exit status is podssh's
podssh ssh -i key -o StrictHostKeyChecking=accept-new user@example.org true
podssh ssh -J user@bastion user@inner        # through a jump host
podssh ssh -W db.internal:5432 user@bastion  # stdin and stdout to a TCP port; nothing listens
podssh ssh -tt user@example.org < script.txt # a remote pty; local stdin is a pipe
```

Files go over SFTP, or by exec where the server has no SFTP, verified by
SHA-256 before they take the destination's name:

```sh
podssh cp report.pdf user@example.org:docs/  # up, into a directory
podssh cp user@example.org:logs/app.log .    # down
```

- On a host with no terminal (the sandbox of an agent), podssh never waits
  for input that cannot come. It refuses an unknown host key, gives its
  fingerprint, and gives `-o StrictHostKeyChecking=accept-new` as the
  remedy. Passwords and passphrases come from `SSH_ASKPASS` (with
  `SSH_ASKPASS_REQUIRE=force`), or podssh skips them with a note.
- Keepalives are on (every 60 s), because the relay closes a connection
  after 180 s with no traffic.
- `--direct` connects without the relay.
- The exit codes are those of OpenSSH: the remote status, 128 plus a signal
  number, or 255 for a failure of podssh. See `podssh man exit-status`.

If the host has an `ssh` client, podssh can be its `ProxyCommand`:

```sh
ssh -o ProxyCommand='podssh proxy %h %p' -o ServerAliveInterval=60 user@example.org
```

Or put it in `~/.ssh/config`:

```
Host example
    HostName example.org
    User me
    ProxyCommand podssh proxy %h %p
    ServerAliveInterval 60
```

`podssh proxy HOST PORT` is a byte pipe, so it also works for other TCP
protocols:

```sh
printf 'HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n' | podssh proxy example.com 80
```

`podssh man environment` lists each variable that podssh reads. The usual
one is `HTTPS_PROXY`: podssh sends the relay's name in `CONNECT`, so it
needs no DNS through a proxy.

podssh mints a relay token when it first needs one (`POST /v1/mint`, no
account), and caches it for its lifetime in the user's cache directory. Only
the owner can read the cache.

### Relay limits

| Limit | Value | What to do |
| --- | --- | --- |
| Idle cut | 180 s with no payload (the relay's keepalives do not count) | Keep `ServerAliveInterval` below 180 |
| Session length | 12 h | Connect again |
| Session volume | 64 MiB, both directions together | Use a new session for large transfers |
| Token lifetime | 72 h or less, minted with `POST /v1/mint` | podssh mints and caches tokens |
| Targets | Public hosts only; the relay refuses private, link-local and internal addresses | None |
| IPv6 targets | The relay takes an IPv6 address, but reached no IPv6 host when measured (2026-10-08) | `--direct`, where the host has IPv6 |

## Build

podssh is a Rust workspace (`crates/`). It needs Rust 1.89 or later and a C
compiler: the SSH client uses aws-lc (through `russh`). The library crates
are pure Rust. The gate makes sure that they build without a C compiler.

```sh
export CARGO_BUILD_JOBS=4
cargo build --release -p podssh-cli   # target/release/podssh
cargo test --no-fail-fast             # the default members
```

The Tailscale mode (`podssh ts`) links a fork of
[tailscale-rs](https://github.com/tailscale/tailscale-rs) that needs a C
compiler and cmake. It is a feature: `cargo build -p podssh-cli --features ts`.

CAUTION: Builds use much memory. On a small machine or a VM, set
`CARGO_BUILD_JOBS=4`. The static Linux binary is built in a `rust:1-alpine`
container. See [docs/development.md](docs/development.md).

## Documents

| Document | Contents |
| --- | --- |
| [AGENTS.md](AGENTS.md) | The start procedure and the rules for work on the repository |
| [docs/STATUS.md](docs/STATUS.md) | What works and what does not, as measured |
| [docs/ROADMAP.md](docs/ROADMAP.md) | The milestones, in order |
| [docs/design.md](docs/design.md) | What a finished podssh is, and why |
| [docs/architecture.md](docs/architecture.md) | The crates, the data flow, the design rules |
| [docs/relay.md](docs/relay.md) | The relay protocol and its limits |
| [docs/cli.md](docs/cli.md) | The rules behind the command line and the manual: parity with OpenSSH, exit codes, prompts |
| [docs/terminal.md](docs/terminal.md) | Ptys, raw mode, and the line discipline |
| [docs/target-environment.md](docs/target-environment.md) | What a constrained host allows, and the rules that follow |
| [docs/decisions.md](docs/decisions.md) | The decisions of the operator |
| [TODO/PROGRESS.md](TODO/PROGRESS.md) | The work order, and the questions for the operator |
| [TODO/INDEX.md](TODO/INDEX.md) | Each open and done item of work (defects, features, measurements), with its entry |
| [docs/development.md](docs/development.md) | Build, test, checks, the sandbox box, releases |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability; what podssh guarantees |

## License

[0BSD](LICENSE). The tailscale-rs fork in `vendor/` keeps its BSD-3-Clause
license.
