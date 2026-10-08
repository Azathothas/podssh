# Architecture

How podssh fits together. [STATUS.md](STATUS.md) says how much of it works
today: the `proxy` and `ssh` flows below work; reverse mode does not exist
yet.

## Data flow

**`podssh proxy HOST PORT`** — milestone 1, working. OpenSSH (or any tool)
talks to podssh over stdin/stdout; podssh carries the bytes.

```
stdin/stdout ⇄ pump ⇄ relay session ⇄ relay ⇄ HOST:PORT
                       │
                       └─ TCP to the relay, or to HTTPS_PROXY then CONNECT
                          → TLS 1.3 → WebSocket upgrade with X-Relay-Token
```

**`podssh ssh user@host`** — milestone 2. podssh is the SSH client: the
protocol is `russh`, and everything around it is podssh's.

```
terminal ⇄ session loop ⇄ russh ⇄ byte pipe ⇄ relay session ⇄ relay ⇄ sshd
           (raw mode,      (KEX,    (frames ⇄
            resize, ~.,     auth,    bytes; keeps
            exit status)    channels) the relay's
                                      close reason)
            host keys: podssh's known_hosts reader; auth: agent, key files,
            keyboard-interactive and password through /dev/tty or SSH_ASKPASS
```

`--direct` replaces the relay with a TCP connection (through `HTTPS_PROXY`
when one is set); `-J` runs each next hop inside the previous hop's
`direct-tcpip` channel; `-W` connects stdin/stdout to such a channel.

**Reverse mode** (`podssh node` / `podssh operator`) uses the same relay
session with the reverse legs' framing: the node multiplexes sessions by a
32-character id; the operator leg is bare bytes. See [relay.md](relay.md).

## Crates

| crate | role | internal dependencies |
| --- | --- | --- |
| `podssh-cli` | the `podssh` binary: argument parsing, `--help`, the generated man page, dispatch, relay selection and tokens, the `proxy` pump, `ssh` option resolution | all of the below (Tailscale only with feature `ts`) |
| `podssh-ssh` | the native SSH client: russh (aws-lc-rs) over any byte stream, the relay-to-stream pipe, `known_hosts`, the authentication chain, prompts, the terminal (raw mode, size, escapes), exit codes | `podssh-ws` |
| `podssh-ws` | dialing the relay: TCP, TLS (rustls with podssh's own pure-Rust crypto provider), the WebSocket client | — |
| `podssh-transport` | the relay protocol: framing for the forward, node and operator legs, control messages, close codes | `podssh-ws` |
| `podssh-core` | protocol state machines with no I/O: `irc/`, and the retired hand-written `ssh/` (to be removed) | — |
| `podssh-terminal` | terminal handling and the in-process line discipline | — |
| `podssh-probe` | the relay document's structural facts (tests only today) | — |
| `podssh-ts` | Tailscale adapter over `vendor/tailscale-rs` (feature `ts`) | the vendored fork |

## Design rules

These hold for every change. The reasons are in
[target-environment.md](target-environment.md) and
[decisions.md](decisions.md).

1. **Protocols are sans-IO.** `podssh-core` takes bytes and returns bytes and
   events; it owns no socket and no clock. That is what makes the protocol
   code testable — but only when it is also tested against real peers
   (captured transcripts, OpenSSH and Dropbear servers, real ircds). A test
   that builds its own input with the same code it checks proves nothing.
2. **The transport is protocol-agnostic.** `podssh-transport` and `podssh-ws`
   move bytes and never learn whether they carry SSH, IRC or anything else.
3. **One outbound connection, never a listener.** No `bind`, no `listen`, no
   loopback helpers.
4. **No C in the library crates.** `podssh-ws`, `podssh-transport`,
   `podssh-core`, `podssh-terminal` and `podssh-probe` use rustls with
   podssh's own provider and RustCrypto crates; enforced by `CC=/nonexistent`
   in the gate. The binary links aws-lc through `russh` for SSH (operator
   decision, 2026-10-08), and the Tailscale fork (feature `ts`).
5. **No LD_PRELOAD, no helper processes.** Anything the host cannot provide
   (a pty, a terminal discipline) podssh does in-process.
6. **Credentials never reach output.** Tokens and keys never appear in stdout,
   stderr, logs, URLs or argv; they travel in headers, files with tight
   permissions, or the environment.
7. **stdout is data.** Diagnostics go to stderr, so podssh can sit in a pipe
   or be an OpenSSH `ProxyCommand`.
8. **Errors are actionable.** One line saying what failed and what to do,
   and a stable exit code: usage 64, configuration 78, unavailable 69, not
   implemented 70; `podssh ssh` follows OpenSSH instead (the remote status,
   128 + a signal, 255 for its own failures).
9. **Files stay under 500 lines.** Split by responsibility; never trim
   comments to fit.
