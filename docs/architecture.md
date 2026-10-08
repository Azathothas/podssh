# Architecture

How podssh is meant to fit together. [STATUS.md](STATUS.md) says how much of
it works today: the `proxy` flow below works; the native SSH flow and reverse
mode do not exist yet.

## Data flow

**`podssh proxy HOST PORT`** — milestone 1, working. OpenSSH (or any tool)
talks to podssh over stdin/stdout; podssh carries the bytes.

```
stdin/stdout ⇄ pump ⇄ relay session ⇄ relay ⇄ HOST:PORT
                       │
                       └─ TCP to the relay, or to HTTPS_PROXY then CONNECT
                          → TLS 1.3 → WebSocket upgrade with X-Relay-Token
```

**`podssh ssh user@host`** — milestone 2. podssh is the SSH client.

```
terminal ⇄ terminal layer ⇄ SSH client ⇄ relay session ⇄ relay ⇄ sshd
           (raw mode, or the             (keys, host-key
            in-process line               check, channels)
            discipline when
            there is no pty)
```

**Reverse mode** (`podssh node` / `podssh operator`) uses the same relay
session with the reverse legs' framing: the node multiplexes sessions by a
32-character id; the operator leg is bare bytes. See [relay.md](relay.md).

## Crates

| crate | role | internal dependencies |
| --- | --- | --- |
| `podssh-cli` | the `podssh` binary: argument parsing, `--help`, the generated man page, dispatch; it will own each verb's event loop | all of the below (Tailscale only with feature `ts`) |
| `podssh-ws` | dialing the relay: TCP, TLS (rustls with podssh's own pure-Rust crypto provider), the WebSocket client | — |
| `podssh-transport` | the relay protocol: framing for the forward, node and operator legs, control messages, close codes | `podssh-ws` |
| `podssh-core` | protocol state machines with no I/O: `ssh/` and `irc/` | — |
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
4. **No C in the default build.** rustls with podssh's own provider and
   RustCrypto crates; enforced by `CC=/nonexistent` in the gate. Tailscale is
   the opt-in exception (feature `ts`).
5. **No LD_PRELOAD, no helper processes.** Anything the host cannot provide
   (a pty, a terminal discipline) podssh does in-process.
6. **Credentials never reach output.** Tokens and keys never appear in stdout,
   stderr, logs, URLs or argv; they travel in headers, files with tight
   permissions, or the environment.
7. **stdout is data.** Diagnostics go to stderr, so podssh can sit in a pipe
   or be an OpenSSH `ProxyCommand`.
8. **Errors are actionable.** One line saying what failed and what to do,
   and a stable exit code (usage 64, configuration 78, unavailable 69,
   not implemented 70).
9. **Files stay under 500 lines.** Split by responsibility; never trim
   comments to fit.
