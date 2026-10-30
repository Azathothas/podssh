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
   the proxy resolves the name. The proxy can be HTTP (`http://`) or SOCKS5
   (`socks5://`, `socks5h://`; T-070): podssh sends the host name to a
   SOCKS5 proxy too (address type 3), with the user and password of RFC
   1929 when the URL has them, reads its reply to exactly its length, and
   tries once more with an address that it resolves itself when the proxy
   takes no names (reply 8). A SOCKS5 refusal is read as the HTTP case of
   the same meaning, 403 for its rules, 407 for its authentication and 502
   for the rest, so the failover and the exit codes are the same. SOCKS4,
   which has no authentication, is refused. The iroh road takes a SOCKS5
   proxy too, by the relay's name, through the patch of iroh-relay that
   podssh carries in `vendor/` (T-280); so does the tailnet, through the
   fork's patch 0022 (T-281). `no_proxy` keeps a host off the proxy: a name
   with its subdomains, `*`, or a block `ADDR/BITS` for each address inside
   it, never a name (T-316), as curl, Go and Python's requests read it.
2. Else directly. The address comes from, in order: an IP literal, a pinned
   address (`--relay-addr`), the system resolver, DNS over HTTPS by IP
   literal.
3. TLS with a verified certificate for the relay's name, then the
   WebSocket upgrade. One ClientHello offers TLS 1.3 first, and TLS 1.2
   with ECDHE and AES-GCM or ChaCha20-Poly1305, for a proxy that intercepts
   TLS and speaks only 1.2 (T-067). A server that speaks 1.3 gets 1.3, and
   the downgrade value of RFC 8446 section 4.1.3, which rustls checks, stops
   a forced fall to 1.2. There is no CBC suite, no RSA key exchange and no
   SHA-1.

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
| `podssh-relay` | Relay hosts, the pool and failover, tokens (mint, cache, mint again), the forward opener; the pairs, the codecs (the framing of the node and operator legs, the control messages, the close table) and the runners of the reverse road (feature `pair`); the resumable layer between two podssh ends (`session/`: its records, offsets and handshake, sans-IO, and its two ends over tokio streams); UDP in a stream (`udp/`, T-168: each datagram after its length, and the flow at the far end, a UDP socket connected to the target); the blocking facade for podbox (feature `blocking`). No C. | `podssh-ws` |
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
   as the operator accepted for that road. A node whose TARGET is
   `udp:HOST:PORT` (T-168), which the user names, sends UDP from its host:
   one socket of port 0 for each flow, connected to the target, after a
   probe that made and closed one. The near end of a flow binds nothing.
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

## Limits

What a peer or a file can make podssh hold, and how long podssh waits for
each step (T-201). Each bound is a constant in the file named. Past a bound
podssh stops reading and says why, or the writer waits for the reader; no
buffer grows without a bound. `cargo test -p podssh-ws --test limits` and
`cargo test -p podssh-relay --test limits` push a peer in the process past
each bound of the connection, and `scripts/interop-limits.sh` measures a
session whose output nobody reads.

### Memory

| What | Bound | Where | Past it |
| --- | --- | --- | --- |
| A frame from the relay | 262144 bytes | `FORWARD_MAX_FRAME`, `crates/podssh-ws/src/frame.rs` | Known from the frame's header, before its payload: the session ends with a Close 1002, "frame length N exceeds the forward cap of 262144". `podssh ssh` then exits 255, `podssh proxy` 69 |
| A message in fragments | 16 MiB | `MAX_MESSAGE`, `crates/podssh-ws/src/session.rs` | The fragment that would pass it is not kept: a Close 1009, "a fragmented message exceeded 16777216 bytes", and the same exit codes |
| The head of the relay's answer to the upgrade | 16 KiB | `UPGRADE_HEAD`, `crates/podssh-ws/src/client.rs` | "the WebSocket upgrade failed: no end of the response headers within 16 KiB", and the next relay host; with none left, `podssh ssh` exits 255, `podssh proxy` 69 |
| The head of an HTTPS answer: a token's mint, the pool, a pair's call | 16 KiB | `MAX_HEAD`, `crates/podssh-ws/src/http.rs` | "no end of the response headers within 16 KiB"; a mint that fails so moves to the next relay host |
| The body of an HTTPS answer | The caller's: 64 KiB for a mint, 256 KiB for the pool, 4096 bytes of a refused upgrade | `crates/podssh-ws/src/http.rs`, and each caller | "the response body is larger than allowed": from the length before the body, from the chunks, or from the bytes before the close. A refused upgrade is then named by its status line alone |
| The head of a proxy's answer to CONNECT | 16 KiB | `MAX_PROXY_RESPONSE`, `crates/podssh-ws/src/dial.rs` | "the proxy PROXY did not answer as its protocol says: no end of headers within 16384 bytes", and the next relay host |
| The pool, `/relays.json` | 256 KiB | `MAX_BODY`, `crates/podssh-relay/src/pool.rs` | The refresh after a mint fails with no word: the cached pool, or the default relay's seed, stays |
| A file of the cache: a token, the pool | 64 KiB | `MAX_FILE`, `crates/podssh-relay/src/cache.rs` | Not read, as a file that the cache makes again: the token is minted again, and the pool is fetched at the next mint |
| A `known_hosts` file | 16 MiB | `MAX_FILE`, `crates/podssh-ssh/src/known_hosts.rs` | "FILE cannot be read (it is larger than 16 MiB, which no known_hosts file is)": no key of it is trusted, and a user file past it records no new key, so `accept-new` refuses an unknown one (exit 255) |
| An `ssh_config` file | 4 MiB | `MAX_FILE`, `crates/podssh-cli/src/ssh/config.rs` | "FILE is larger than 4 MiB, which no ssh_config is", exit 78 |
| The SSH window of a channel | 512 KiB | `WINDOW`, `crates/podssh-ssh/src/run.rs` | The server waits until podssh reads: a session whose output nobody read for 30 s, while the server wrote 50 MB, peaked at 7460 KiB, and one whose reader took each byte at 6884 KiB (`scripts/interop-limits.sh`) |
| russh's queue of a channel | 100 messages of 32 KiB at most | russh's `channel_buffer_size`, which `crates/podssh-ssh/src/run.rs` leaves at its default | The connection's task waits, and reads no more from the server: a second bound behind the window. Measured: with the window at 64 MiB the peak was 8948 KiB; without both, 62708 KiB |
| What the relay holds for a slow podssh, on the forward path | 2 MiB, by the relay's document; whether its check operates is not measured (T-062) | The relay's: [relay.md](relay.md) | A Close 1013, "client receive backlog"; the window of 512 KiB keeps a server from having that much in flight |
| The relay stream of `podssh ssh` | 256 KiB each way, frames of 64 KiB | `PIPE`, `CHUNK`, `crates/podssh-ssh/src/relay_stream.rs` | The writer waits |
| The relay end of `podssh proxy` | 256 KiB each way, frames of 32 KiB | `PIPE`, `CHUNK`, `crates/podssh-cli/src/pipe/relay.rs` | The writer waits |
| A read of `podssh pipe` | 32 KiB | `CHUNK`, `crates/podssh-cli/src/pipe/pump.rs` | One read at a time |
| What is typed while `--persist` connects again | 64 KiB | `QUEUE`, `crates/podssh-ssh/src/io.rs` | The rest is dropped, and podssh says how many bytes |
| The replay buffer of a resumable session | 4 MiB each way; `PODSSH_REPLAY_BUFFER` gives 4 to 16 MiB, and another value is ignored | `crates/podssh-relay/src/session/replay.rs` | The writer waits for the peer's `ACK`; no byte is dropped |
| The replay buffers of a node | 64 MiB | `NODE_BUDGET`, `crates/podssh-relay/src/reverse/layered.rs` | A new resumable session is closed: "this node keeps as many resumable sessions as its budget allows (64 MiB of replay buffers)" |
| What waits for a node's local side | 1 MiB for a side with no flow control; a handler with its own keeps its window | `QUEUE_BYTES`, `crates/podssh-relay/src/reverse/node.rs` | That session ends with its reason, and the others go on (T-256) |
| An operator's input before the node is ready | 1 MiB | `QUEUE_BEFORE_READY`, `crates/podssh-relay/src/reverse/operator.rs` | A Close 1000, and "more than 1048576 bytes of input came before the node was ready" |
| An IRC line | 8192 bytes | `DEFAULT_MAX_LINE`, `crates/podssh-core/src/irc/framing.rs` | The line is dropped to its end, and counted as lost |

### Time

| What | Bound | Where | Past it |
| --- | --- | --- | --- |
| Each step of reaching a relay host: the proxy and TCP, TLS, the upgrade, a mint | 20 s | `CONNECT_TIMEOUT`, `crates/podssh-relay/src/open.rs` | The next relay host |
| One relay host, its mint included | 45 s | `HOST_DEADLINE`, `crates/podssh-relay/src/open.rs` | "the relay host did not answer within 45 s", and the next relay host |
| The SSH handshake | `ConnectTimeout`, 60 s when none is set | `crates/podssh-ssh/src/run.rs` | "HOST: the SSH handshake did not finish within N s", exit 255 |
| Nothing from the relay | 90 s | `DEFAULT_IDLE_TIMEOUT`, `crates/podssh-ws/src/client.rs` | "no data from the relay for 90s": the session ends |
| The relay's answer to a ping | A ping each 10 s; 3 intervals with nothing | `LIVENESS_EVERY`, `LIVENESS_ALLOWED`, `crates/podssh-ws/src/client.rs` | The link is dead ("pings unanswered"): a session of the forward road ends (255), and the resumable layer moves its session to a new link |
| One write to the relay | 60 s | `WRITE_TIMEOUT`, `crates/podssh-ws/src/client.rs` | "sending to the relay stalled for 60s": the session ends |
| A server's answer to a pty or a session request | 30 s | `REPLY_WAIT`, `crates/podssh-ssh/src/session.rs` | Taken as a refusal: "the server refused to start a shell" (or the command, or the subsystem) |
| The exit status once stdout's reader has gone | 5 s | `STATUS_WAIT`, `crates/podssh-ssh/src/io.rs` | The session ends with no status, exit 255 |
| New connections of `--persist` after a loss | 10, within 300 s | `ATTEMPTS`, `WITHIN`, `crates/podssh-cli/src/ssh/persist.rs` | "...; gave up after N new connections in S s", exit 255 |
| A connection of `--persist` that starts a new count after its loss | 30 s up | `STEADY`, `crates/podssh-cli/src/ssh/persist.rs` | Its loss counts in the round of the loss before it (T-042) |
| A forward of `-R` that the server refuses after a loss of `--persist -N` | Asked again for 120 s, with the relay's wait between | `FORWARDS_AGAIN`, `crates/podssh-cli/src/ssh/persist.rs` | "Warning: remote port forwarding failed for listen port N", or with `ExitOnForwardFailure` the end of the run (255) |
