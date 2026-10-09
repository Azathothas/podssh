# Architecture

This page tells how the parts of podssh fit together. [STATUS.md](STATUS.md)
tells which parts work: the `proxy` and `ssh` flows below work, and reverse
mode does not exist yet.

## Data flow

**`podssh proxy HOST PORT`.** OpenSSH, or another tool, talks to podssh over
stdin and stdout. podssh carries the bytes.

```
stdin/stdout <-> pump <-> relay session <-> relay <-> HOST:PORT
                            |
                            `- TCP to the relay, or to HTTPS_PROXY then CONNECT
                               -> TLS 1.3 -> WebSocket upgrade with X-Relay-Token
```

**`podssh ssh user@host`.** podssh is the SSH client. `russh` does the SSH
protocol. podssh does each part around it.

```
terminal <-> session loop <-> russh <-> byte pipe <-> relay session <-> relay <-> sshd
             (raw mode,       (KEX,     (frames <->
              resize, ~.,      auth,     bytes; keeps
              exit status)     channels)  the close reason)
```

- Host keys: podssh's `known_hosts` reader.
- Authentication: agent, key files, keyboard-interactive and password,
  through `/dev/tty`, `CONIN$` or `SSH_ASKPASS`.
- `--direct` uses a TCP connection in place of the relay (through
  `HTTPS_PROXY` when it is set).
- `-J` runs each next hop in the `direct-tcpip` channel of the hop before
  it. `-W` connects stdin and stdout to such a channel.

**The way to the relay.** `podssh-relay` gives an ordered list of relay
hosts: the default host and up to three hosts of the pool, or the list that
the user gives. For each host, `podssh-ws` connects:

1. Through `HTTPS_PROXY` when it is set: `CONNECT` with the host name, so
   the proxy resolves the name.
2. Else directly. The address comes from, in order: an IP literal, a pinned
   address (`--relay-addr`), the system resolver, DNS over HTTPS by IP
   literal.
3. TLS 1.3 with a verified certificate for the relay's name, then the
   WebSocket upgrade.

The trust store is `--ca-file` or `SSL_CERT_FILE` alone, else the Mozilla
roots compiled into the binary (`webpki-roots`), a `podssh-ca.pem` next to
the binary, and the first readable system bundle. A binary keeps the roots
that it was built with: an update of the roots makes a release (Dependabot,
T-205; after `v1.0.0`, a patch release), and `podssh doctor` says when the
compiled-in roots are older than 12 months. A system bundle adds roots and
removes none, so to stop trusting a root that Mozilla removed after the
build, give `--ca-file` or `SSL_CERT_FILE` with a current bundle.

A library that embeds `podssh-ws` or `podssh-relay` can bring its own
`rustls::ClientConfig` (`Trust::caller`, T-066): podbox keeps `ring` and
TLS 1.2 for proxies that intercept TLS. It is used as it is, for each
connection and each HTTPS request, and refused when it offers ALPN, because
the upgrade is HTTP/1.1 only. Its verifier is the caller's, which podssh
cannot check; the binary never takes this form, and a test keeps it out.

If a host fails with an error that another host can repair, `podssh-relay`
tries the next host. During the session, a ping every 10 s finds a silent
relay in 30 to 40 s. See [relay.md](relay.md).

**Reverse mode** (`podssh node`, `podssh operator`; milestone M4) uses the
same relay session with the framing of the reverse legs: the node
multiplexes sessions by a 32-character id, and the operator leg carries bare
bytes. See [reverse.md](reverse.md).

## Crates

| Crate | Role | Internal dependencies |
| --- | --- | --- |
| `podssh-cli` | The `podssh` binary: arguments, `--help`, the generated man page, dispatch, the `proxy` pump, the options of `ssh`, `doctor`, `keygen` | each crate below (`podssh-ts` only with the feature `ts`, `podssh-iroh` only with the feature `iroh`) |
| `podssh-ssh` | The SSH client: russh (aws-lc-rs) over a byte stream, the relay stream, `known_hosts`, the authentication chain, prompts, the terminal (raw mode, size, escapes), exit codes, a host-key probe, key generation | `podssh-ws` |
| `podssh-relay` | Relay hosts, the pool and failover, tokens (mint, cache, mint again), the forward opener; the pairs, the codecs (the framing of the node and operator legs, the control messages, the close table) and the runners of the reverse road (feature `pair`); the resumable layer between two podssh ends (`session/`: its records, offsets and handshake, sans-IO, and its two ends over tokio streams); the blocking facade for podbox (feature `blocking`). No C. | `podssh-ws` |
| `podssh-ws` | The connection to the relay: TCP, proxies, the DNS fallbacks, TLS (rustls with podssh's own pure-Rust provider), the WebSocket client | none |
| `podssh-core` | Protocol state machines with no I/O: `irc/` | none |
| `podssh-terminal` | A line discipline in the process (not used yet) | none |
| `podssh-probe` | Facts about the structure of the relay's document (tests only) | none |
| `podssh-ts` | The Tailscale adapter over `vendor/tailscale-rs` (feature `ts`) | the fork in `vendor/` |
| `podssh-iroh` | The iroh road between two podssh ends (feature `iroh`, T-162, T-163): an iroh endpoint with podssh's relays, proxy, name resolution and trust store, UDP only after a probe, the resumable layer's sessions over QUIC streams, the keys in private files, the tickets, and the allowlist of a node | `podssh-relay`, `podssh-ws` |

## Design rules

These rules apply to each change. The reasons are in
[target-environment.md](target-environment.md) and
[decisions.md](decisions.md).

1. **Protocols are sans-IO.** `podssh-core` takes bytes and gives bytes and
   events. It has no socket and no clock. This makes the protocol code
   testable. Also test it against real peers: captured transcripts, OpenSSH
   and Dropbear servers, real IRC servers. A test that makes its input with
   the code that it checks proves nothing.
2. **The transport does not know the protocol.** `podssh-relay` and
   `podssh-ws` move bytes. They do not know whether the bytes are SSH, IRC
   or another protocol.
3. **One outbound connection, and no listener that the user did not ask
   for.** No `bind`, no `listen`, no loopback helpers. `podssh doctor` binds
   a socket to test the host and closes it without listening. A listener
   that the user asks for (`-L`, `-D`, connection sharing, `podssh agent`)
   opens only when a probe at run time allows the bind: on loopback or
   AF_UNIX, unless the user sets the address. A race between relay hosts can
   open a second connection for a short time ([decisions.md](decisions.md),
   2026-10-08). The iroh road (feature `iroh`), which the user selects,
   binds UDP for direct paths only after a probe shows that a UDP socket
   binds, and opens more than one outbound connection (its relay's probes),
   as the operator accepted for that road.
4. **No C in the library crates.** `podssh-ws`, `podssh-relay`,
   `podssh-core`, `podssh-terminal` and `podssh-probe` use rustls with
   podssh's own provider and RustCrypto crates. The gate
   makes sure of this with `CC=/nonexistent` and `CXX=/nonexistent`. The
   binary links aws-lc through `russh` for SSH, and the Tailscale fork with
   the feature `ts`.
5. **No `LD_PRELOAD`, no helper processes.** podssh does in its own process
   what the host cannot supply (a pty, a line discipline). A tty in user
   space for a child of `podssh serve` keeps this rule: podssh answers the
   child's tty system calls from its own process, and puts no code into the
   child ([decisions.md](decisions.md), 2026-10-08; T-248).
6. **Credentials never go to output.** Tokens and keys never appear in
   stdout, stderr, logs, URLs or argv. They go in headers, in files with
   tight permissions, or in the environment.
7. **stdout is data.** Diagnostics go to stderr, so podssh can be in a pipe
   or be the `ProxyCommand` of OpenSSH.
8. **Errors tell what to do.** One line says what failed and what to do,
   with a stable exit code: usage 64, configuration 78, unavailable 69, not
   implemented 70. `podssh ssh` uses the exit codes of OpenSSH: the remote
   status, 128 plus a signal number, or 255 for its own failures.
9. **Files have 500 lines or fewer.** Split a file by responsibility. Do not
   remove comments to make it fit.
