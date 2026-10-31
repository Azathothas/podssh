# podssh

SSH from machines whose only way out is HTTPS.

podssh is one static binary. It is an SSH client, and it can carry any TCP
stream, through a WebSocket relay on port 443. It is for closed sandboxes:
CI runners, containers of AI agents, hosted notebooks. Such hosts have no
inbound ports and no direct outbound TCP. Often they have no working DNS, and
an HTTP proxy is their only way out. podssh needs no root, no `LD_PRELOAD`,
no installed `ssh`, and no TLS or crypto library of the system.

> [!WARNING]
> **Status: beta.** `podssh ssh`, `podssh each`, `podssh run`, `podssh job`, `podssh session`,
> `podssh containers`,
> `podssh proxy`, `podssh pipe`, `podssh cp`, `podssh mv`, `podssh scp`,
> `podssh sftp` and `podssh edit` (files), `podssh doctor`, `podssh keygen`,
> `podssh agent`, `podssh man`, `podssh status`, `podssh ping`,
> `podssh health`, the reverse road (`podssh node`, `podssh operator`,
> `podssh relay`), `podssh chat`, `podssh play` (recordings),
> `podssh config` (settings), `podssh mcp` and `podssh update` (this
> binary, from a signed release) work.
> Tests run them against OpenSSH and Dropbear servers, through the live
> relay, and in a box like the target sandbox. The measured state is in
> [docs/STATUS.md](docs/STATUS.md).
> The plan is in [docs/ROADMAP.md](docs/ROADMAP.md).

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
- **Outbound only, unless you ask.** podssh opens outbound connections only
  (to the relay, or to the proxy that `HTTPS_PROXY` names). It listens only
  on an address that you name, of `podssh pipe` (`unix-listen:`,
  `tcp-listen:`, `http-listen:`, an HTTP CONNECT proxy, and `ws-listen:`,
  a WebSocket server) or of `podssh ssh -L` and `-D`, and on the socket of
  `podssh session start`, your own, after the bind shows that the host
  allows it. The iroh
  road, in a build with the feature `iroh`, binds UDP for direct paths only
  after a probe allows it. A node that you give a UDP target (`podssh node
  NAME udp:HOST:PORT`) sends UDP from its host, after a probe.
- **Fallbacks.** If one relay host fails, podssh tries the next one. If DNS
  fails, podssh uses pinned addresses or DNS over HTTPS. If the relay goes
  silent, podssh finds it in 30 to 40 s.
- **No local pty needed.** A remote pty (`-tt`) works when stdin and stdout
  are pipes. Full-screen programs and Ctrl-C work on a host that has no
  `/dev/ptmx`.

## First steps on a new host

1. Get a static binary for the host: a beta from the
   [releases page](https://github.com/Azathothas/podssh/releases) (each
   `v1.0.0-beta.N` is a prerelease), or build one (see "Build"). Check it
   against `SHA256SUMS`, and make it executable:

   ```sh
   T=v1.0.0-beta.2; B=podssh-x86_64-unknown-linux-musl   # or podssh-aarch64-unknown-linux-musl
   curl -fsSLO "https://github.com/Azathothas/podssh/releases/download/$T/$B"
   curl -fsSLO "https://github.com/Azathothas/podssh/releases/download/$T/SHA256SUMS"
   grep " $B\$" SHA256SUMS | sha256sum -c - && chmod +x "$B"
   ```

   From `v1.0.0-beta.2` on, a release also has
   `podssh-armv7-unknown-linux-musleabihf` (a Raspberry Pi with 32 bits) and
   `podssh-riscv64gc-unknown-linux-musl`, both static;
   `podssh-aarch64-apple-darwin` and `podssh-x86_64-apple-darwin`
   (macOS, where the check is `shasum -a 256 -c`); and
   `podssh-aarch64-pc-windows-msvc.exe` (Windows on ARM). The Mac binaries
   are not signed with a Developer ID: fetch them with `curl`, as above,
   which marks no quarantine; after a browser's download, run
   `xattr -d com.apple.quarantine FILE` first. The Windows binaries are not
   signed either, and SmartScreen may warn about them.

   From `v1.0.0-beta.2` on, the release workflow also proves where each
   binary comes from. `podssh --version` names the commit of the tag. The
   provenance of each binary names the workflow and the commit (with the
   GitHub CLI):

   ```sh
   gh attestation verify "$B" --repo Azathothas/podssh \
     --signer-workflow Azathothas/podssh/.github/workflows/release.yml --source-ref "refs/tags/$T"
   ```

   And `SHA256SUMS` is signed by the workflow at the tag (with cosign 3.x):

   ```sh
   curl -fsSLO "https://github.com/Azathothas/podssh/releases/download/$T/SHA256SUMS.sigstore.json"
   cosign verify-blob --bundle SHA256SUMS.sigstore.json \
     --certificate-identity "https://github.com/Azathothas/podssh/.github/workflows/release.yml@refs/tags/$T" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
   ```
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
   podssh keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk   # in a FIDO2 security key (Linux, Windows)
   ```

## Usage

podssh is the SSH client, with the options of OpenSSH:

```sh
podssh ssh user@example.org                  # an interactive shell
podssh ssh user@example.org 'uname -a'       # a command; its exit status is podssh's
podssh ssh -i key -o StrictHostKeyChecking=accept-new user@example.org true
podssh ssh -J user@bastion user@inner        # through a jump host
podssh ssh -A user@build 'git pull'          # the server may use your agent while the session lasts
podssh ssh -W db.internal:5432 user@bastion  # stdin and stdout to a TCP port; nothing listens
podssh ssh -N -L 5432:db.internal:5432 user@bastion  # a local port to the database, if this host may listen
podssh ssh -N -D 1080 user@bastion           # a SOCKS proxy on 127.0.0.1:1080
podssh ssh -M -N -S /tmp/cm-%C user@host &   # Unix: later runs with -S /tmp/cm-%C share this connection
podssh ssh -tt user@example.org < script.txt # a remote pty; local stdin is a pipe
podssh ssh -tt --expect 'Choice: ' --send '2\r' user@menu  # keys for a prompt after the login, then the session
podssh containers user@example.org           # the containers of docker, podman and kubectl, each with the command that enters it
```

Files go over SFTP, or by exec where the server has no SFTP, verified by
SHA-256 before they take the destination's name; `mv` then removes the
source:

```sh
podssh cp report.pdf user@example.org:docs/  # up, into a directory
podssh cp user@example.org:logs/app.log .    # down
podssh mv user@example.org:inbox/a.csv .     # down, then the far file goes
```

- On a host with no terminal (the sandbox of an agent), podssh never waits
  for input that cannot come. It refuses an unknown host key, gives its
  fingerprint, and gives `-o StrictHostKeyChecking=accept-new` as the
  remedy. Passwords and passphrases come from `SSH_ASKPASS` (with
  `SSH_ASKPASS_REQUIRE=force`), or podssh skips them with a note.
- An agent that runs one command at a time keeps a shell between its
  calls with `podssh session`: `start NAME HOST`, then `send NAME TEXT`,
  `wait NAME` (until the output stops), `capture NAME` (the screen) and
  `stop NAME`. Its socket is your own, and carries no credential.
- Keepalives are on (every 60 s), because the relay closes a connection
  after 180 s with no traffic.
- `--direct` connects without the relay.
- The exit codes are those of OpenSSH: the remote status, 128 plus a signal
  number, or 255 for a failure of podssh. See `podssh man exit-status`.
- `PODSSH_ERROR_PROGRAM` names a program that gets each failure of podssh
  as one JSON object on its stdin: the command, the exit code and podssh's
  last messages, with no credential. A remote status starts no program.
  podssh calls no AI service itself; the program decides.

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

`podssh chat` carries messages and files between two podssh ends, end to
end encrypted: one side waits as the node of a pair, the other reaches it.
Each line of stdin is a message; `/file PATH` offers a file, which the peer
writes only once it accepts it (`/accept ID`).

```sh
podssh relay pair NAME --operator-file op.json  # once, on the side that waits
podssh chat --listen NAME                       # the side that waits
podssh chat NAME --pair-file op.json            # the other side, with op.json sent over a trusted channel
```

A standard sshd gets a session that survives a lost link when a podssh next
to it owns the TCP connection to it: a roost. The roost checks that sshd
answers with SSH's version line, before it goes online and for each
session:

```sh
podssh relay pair lab --operator-file op.json   # on the server, once
podssh node lab --sshd                          # the roost, in front of 127.0.0.1:22
podssh ssh --pair-file op.json node://me@lab    # from outside; a lost link resumes the session
```

When the server has a podssh on its `PATH`, `podssh ssh --upgrade` does
these steps itself: it logs in, starts a temporary roost there in that SSH
session, and moves the session to it. With no podssh there, the session
stays as it is, with one note; podssh never copies itself to a server.

```sh
podssh ssh --upgrade me@example.org
```

`podssh man environment` lists each variable that podssh reads. The usual
one is `HTTPS_PROXY`: podssh sends the relay's name in `CONNECT`, so it
needs no DNS through a proxy. A SOCKS5 proxy works too
(`ALL_PROXY=socks5h://HOST:PORT`, with a user and a password if it needs
them).

podssh mints a relay token when it first needs one (`POST /v1/mint`, no
account), and caches it for its lifetime in the user's cache directory. Only
the owner can read the cache.

### Relay limits

| Limit | Value | What to do |
| --- | --- | --- |
| Idle cut | 180 s with no payload (the relay's keepalives do not count) | Keep `ServerAliveInterval` below 180; to a node, the resumable layer keeps the link busy |
| Session length | 12 h | Connect again |
| Session volume | 64 MiB, both directions together | Use a new session for large transfers |
| Token lifetime | 72 h or less, minted with `POST /v1/mint` | podssh mints and caches tokens |
| Targets | Public hosts only; the relay refuses private, link-local and internal addresses | None |
| IPv6 targets | The relay takes an IPv6 address, but reached no IPv6 host when measured (2026-10-08) | `--direct`, where the host has IPv6 |

### Other TCP protocols

`podssh proxy` and `podssh pipe` carry any TCP stream. A client that runs a
command as its transport needs no listener. A client that calls `connect()`
itself needs a local port or socket: `podssh pipe` listens only where you
ask for it and the host allows the bind (`podssh doctor` tries an AF_INET
and an AF_UNIX bind), and OpenSSH's `ssh -L`, with podssh as its
`ProxyCommand`, listens where a bind works and the user has an entry in the
user database. Through the relay, a session ends at 64 MiB, both directions
together ("Relay limits" above); `--direct` avoids the relay where the host
has a road of its own. These protocols are often not encrypted: reach them
with `ssh:`, so that the relay sees SSH only.

| Protocol | With no listener | With a local listener | Limits |
| --- | --- | --- | --- |
| VNC (RFB, port 5900 + display) | A viewer that runs a command as its transport: SSVNC's `ssvncviewer exec=COMMAND` (its manual; not run here) | `pipe unix-listen:` and TigerVNC's `vncviewer`, which takes a socket's path, where only an AF_UNIX bind works; else `pipe tcp-listen:` or `ssh -L` | 64 MiB through the relay, 21 full screens of 1024x768 at 32 bits with no compression; [docs/STATUS.md](docs/STATUS.md) has a viewer's rate |
| RDP (port 3389) | No client that runs a command was found; FreeRDP's `/proxy:` takes an HTTP or SOCKS5 proxy, a listener (`podssh ssh -D`) | `pipe tcp-listen:` or `ssh -L` (not measured) | 64 MiB through the relay |
| Telnet (port 23) | `podssh proxy HOST 23` carries the bytes, but the server's first bytes are options (IAC) that a client must answer | `pipe tcp-listen:`, then `telnet 127.0.0.1 PORT` | Plain text, the password too: use `ssh:` to a host near the server |
| USB/IP (port 3240) | None: `usbip` dials a host and port itself | `pipe --keep-listening tcp-listen:127.0.0.1:3240` to `ssh:`, then `usbip attach -r 127.0.0.1 -b BUSID`: `usbip` needs root and the kernel modules (`usbip-host` on the server, `vhci-hcd` here), podssh neither | 64 MiB through the relay, about 2 minutes of a disk read at the 0.5 to 0.7 MB/s measured through a sandbox's proxy: the session then ends (1009), and the device goes away; not encrypted: use `ssh:`, never `relay:` to a public `usbipd` |

```sh
# VNC where only an AF_UNIX bind works: TigerVNC's viewer at the socket
podssh pipe unix-listen:/tmp/vnc.sock ssh:me@desktop.example.org,127.0.0.1:5901 &
vncviewer /tmp/vnc.sock
# VNC where a TCP bind works: podssh listens ...
podssh pipe tcp-listen:5901 ssh:me@desktop.example.org,127.0.0.1:5901 &
# ... or OpenSSH listens, and podssh carries its session
ssh -N -L 5901:127.0.0.1:5901 -o ProxyCommand='podssh proxy %h %p' -o ServerAliveInterval=60 me@desktop.example.org
# no listener: the viewer runs podssh
ssvncviewer 'exec=podssh pipe stdio ssh:me@desktop.example.org,127.0.0.1:5901'
# Telnet to a device behind an SSH host
podssh pipe tcp-listen:2323 ssh:me@gateway.example.org,router.lan:23 & telnet 127.0.0.1 2323
# USB/IP: list the server's devices, then attach one (usbipd runs there; each usbip command connects once)
podssh pipe --keep-listening tcp-listen:127.0.0.1:3240 ssh:me@usbhost.example.org,127.0.0.1:3240 &
usbip list -r 127.0.0.1
sudo usbip attach -r 127.0.0.1 -b 1-1
```

A listener of `podssh pipe` takes one client, then closes; a viewer that
connects again, and `usbip`, which connects once to list and once to
attach, need `--keep-listening`. After `usbip attach`, the kernel speaks
USB/IP on the connection to podssh's listener, and the device stays while
that session lasts; `usbip detach` ends it.

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
