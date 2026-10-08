# podssh

SSH from machines whose only way out is HTTPS.

podssh is a single static binary that is an SSH client — and can carry any
TCP stream — through a WebSocket-to-TCP relay on port 443. It is meant for
locked-down sandboxes (CI runners, AI-agent containers, hosted notebooks) that
have no inbound ports, no direct outbound TCP, often no working DNS, and reach
the internet only through an HTTP proxy. It needs no root, no `LD_PRELOAD`, no
installed `ssh`, and no system TLS or crypto libraries.

> [!WARNING]
> **Status: beta.** `podssh ssh` (the native client) and `podssh proxy` (an
> OpenSSH `ProxyCommand`) work and are tested against OpenSSH and Dropbear
> servers and through the live relay. Reverse mode, chat and file copy are not
> implemented yet. [docs/STATUS.md](docs/STATUS.md) has the measured state;
> [docs/ROADMAP.md](docs/ROADMAP.md) the plan.

## How it works

```
podssh ──TLS 1.3 + WebSocket, port 443──▶ relay ──TCP──▶ sshd (or any TCP service)
   └── through HTTPS_PROXY (HTTP CONNECT) when the host has one
```

- **The relay** ([`tcp.ssh.relay.ajam.dev`](https://tcp.ssh.relay.ajam.dev/),
  a Cloudflare Worker) copies bytes between a WebSocket and a TCP socket. Its
  contract is published at
  [`/llms-full.txt`](https://tcp.ssh.relay.ajam.dev/llms-full.txt) and
  summarised in [docs/relay.md](docs/relay.md).
- **End-to-end encryption.** The SSH session is encrypted between your SSH
  client and the server. The relay still sees the target, the timing and
  volume, and the unencrypted start of the SSH handshake, and it could tamper
  with frames; verifying the server's host key is what makes a relay in the
  middle safe ([SECURITY.md](SECURITY.md)).
- **Outbound only.** podssh opens one outbound TCP connection (to the relay,
  or to the proxy named in `HTTPS_PROXY`) and never listens on a port.
- **No local pty needed.** A remote pty (`-tt`) works with stdin and stdout
  as plain pipes, so full-screen programs and Ctrl-C work from a host with no
  `/dev/ptmx`.

## Usage

Without an `ssh` client — podssh is the client, and takes OpenSSH's options:

```sh
podssh ssh user@example.org                  # interactive shell
podssh ssh user@example.org 'uname -a'       # a command; its exit status is podssh's
podssh ssh -i key -o StrictHostKeyChecking=accept-new user@example.org true
podssh ssh -J user@bastion user@inner        # through a jump host
podssh ssh -W db.internal:5432 user@bastion  # stdin/stdout to a TCP port; nothing listens
podssh ssh -tt user@example.org < script.txt # a remote pty, local stdin a pipe
```

On a host with no terminal (an agent's sandbox), podssh never waits for input
that cannot arrive: an unknown host key is refused with its fingerprint and
`-o StrictHostKeyChecking=accept-new` as the remedy, and passwords and key
passphrases come from `SSH_ASKPASS` (with `SSH_ASKPASS_REQUIRE=force`) or are
skipped with a note. Keepalives are on (every 60 s), because the relay closes a
connection after 180 s without traffic. `--direct` connects without the relay.
Exit codes follow OpenSSH: the remote status, 128 + a signal number, 255 for
podssh's own failures. Details: [docs/cli.md](docs/cli.md).

With an `ssh` client on the host, podssh can be its `ProxyCommand`:

```sh
ssh -o ProxyCommand='podssh proxy %h %p' -o ServerAliveInterval=60 user@example.org
```

or in `~/.ssh/config`:

```
Host example
    HostName example.org
    User me
    ProxyCommand podssh proxy %h %p
    ServerAliveInterval 60
```

`podssh proxy HOST PORT` is a plain byte pipe, so it also works for other TCP
protocols:

```sh
printf 'HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n' | podssh proxy example.com 80
```

It honours:

| variable | effect |
| --- | --- |
| `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY` | reach the relay through this HTTP proxy (`CONNECT`, by name, so no local DNS is needed) |
| `NO_PROXY`, `no_proxy` | names that bypass the proxy |
| `PODSSH_RELAY` | a different relay (`host` or `host:port`); also `--relay-host` |
| `PODSSH_RELAY_TOKEN` | use this token instead of minting one |
| `SSL_CERT_FILE` | trust only these CA certificates; also `--ca-file` |

A relay token is minted on first use (`POST /v1/mint`, no account) and cached
for its lifetime in the user's cache directory, readable by its owner only.

### Relay limits you will hit

| limit | value | what to do |
| --- | --- | --- |
| idle cut | 180 s with no payload (relay keepalives do not count) | keep `ServerAliveInterval` under 180 |
| session length | 12 h | reconnect |
| session volume | 64 MiB | use a new session for large transfers |
| token lifetime | at most 72 h, self-minted with `POST /v1/mint` | podssh will mint and cache tokens |
| targets | public hosts only; private, link-local and internal addresses are refused | — |

## Building

podssh is a Rust workspace (`crates/`). Rust 1.89 or newer, and a C compiler:
the SSH client's crypto is aws-lc (through `russh`). The library crates below
it are pure Rust and are checked to build without one.

```sh
cargo build --release -p podssh-cli   # target/release/podssh
cargo test                            # default members
```

The Tailscale mode (`podssh ts`) links a vendored fork of
[tailscale-rs](https://github.com/tailscale/tailscale-rs) that needs a C
compiler and cmake, so it is behind a feature:
`cargo build -p podssh-cli --features ts`.

Builds are memory-hungry; on small machines and VMs cap parallelism with
`CARGO_BUILD_JOBS=4`. The static Linux release binary is built in a
`rust:1-alpine` container — see [docs/development.md](docs/development.md).

## Documentation

| document | what it covers |
| --- | --- |
| [docs/STATUS.md](docs/STATUS.md) | what works and what is broken, measured |
| [docs/ROADMAP.md](docs/ROADMAP.md) | milestones to a first beta |
| [docs/design.md](docs/design.md) | what a finished podssh is: library use, constrained hosts, reliability, socat, iroh |
| [docs/architecture.md](docs/architecture.md) | crates, data flow, design rules |
| [docs/relay.md](docs/relay.md) | the relay protocol and its limits |
| [docs/cli.md](docs/cli.md) | the command line, OpenSSH parity, exit codes, prompts |
| [docs/terminal.md](docs/terminal.md) | ptys, raw mode, and the line discipline |
| [docs/target-environment.md](docs/target-environment.md) | what a constrained host allows, and the rules that follow |
| [docs/decisions.md](docs/decisions.md) | decisions in force |
| [docs/development.md](docs/development.md) | building, testing, checks, releases |
| [docs/audit-2026-10-08.md](docs/audit-2026-10-08.md) | known defects, by crate, with file and line |
| [SECURITY.md](SECURITY.md) | reporting a vulnerability; what podssh guarantees |

## License

[0BSD](LICENSE). The vendored tailscale-rs fork under `vendor/` keeps its own
BSD-3-Clause license.
