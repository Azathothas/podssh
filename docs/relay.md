# The relay

podssh talks to a WebSocket-to-TCP relay. The relay's own document is the
contract; this page summarises the parts podssh depends on and links to the
source for everything else.

- Live contract: <https://tcp.ssh.relay.ajam.dev/llms-full.txt>
- Pinned copy used by the tests:
  [`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`](../crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt)
- Version checked against: `2026-10-03-r2` (`/health`, 2026-10-08; the live
  document was byte-identical to the pinned copy, SHA-256 `88eb1b0b…a5a8`).

The relay publishes a version and it changes. When `/health` reports a
different version, the live document wins: re-read it, update the pinned copy
and this page together.

```sh
curl -sS https://tcp.ssh.relay.ajam.dev/health
curl -sS https://tcp.ssh.relay.ajam.dev/llms-full.txt | sha256sum
```

## Forward path — what `podssh proxy` and `podssh ssh` use

```
wss://tcp.ssh.relay.ajam.dev/connect/<host>/<port>
X-Relay-Token: <forward token>
```

- After `101 Switching Protocols`, **binary frames carry the raw TCP stream
  verbatim** in both directions. No session-id prefix, no control messages, no
  subprotocol. Frame boundaries mean nothing; the receiver reassembles a byte
  stream.
- The relay dials the target **before** the upgrade (10 s timeout), so an
  unreachable target is a plain HTTP `502`, not a WebSocket close.
- The relay sends a **zero-length binary frame every 25 s** as a keepalive.
  Clients must ignore empty frames — they are not EOF.
- A WebSocket Close stops client→target delivery. There is no TCP half-close.
- Maximum frame: 262144 bytes (`/relays.json` → `limits.max_frame_bytes`).

### Tokens

- Self-minted, no account: `POST https://tcp.ssh.relay.ajam.dev/v1/mint` with
  body `{}` returns `{token, expires, scope}` (`expires` in ms since the epoch).
- Shape `ephm1.<expiry-ms>.forward.<mac>`, valid for at most 72 h, checked once
  per WebSocket upgrade.
- Send it in the `X-Relay-Token` header. The `?token=` and `/t/<token>/…` forms
  exist for clients that cannot set headers; URLs end up in logs, so podssh does
  not use them.
- `403 missing or wrong token` → mint a new one. A `403` that names the target
  (`not in the ALLOW list`) is a policy refusal; a new token will not help.
  `429` → back off (`Retry-After`). `503` → issuance or authentication is not
  configured; do not retry.

### Limits (the ones users notice)

| limit | value |
| --- | --- |
| idle cut | 180 000 ms without **payload**; the relay's keepalives do not reset it |
| session length | 720 min (12 h) |
| session volume | 64 MiB |
| unauthenticated attempts | 120 per minute per address (mint, pair, tokenless upgrades) |
| targets | public TCP only; RFC 1918, CGNAT, link-local, unique-local, multicast, documentation ranges, internal suffixes and names resolving into private space are refused; Cloudflare ranges are refused on the direct road; port 25 is refused (the contract says "on the direct road", `/relays.json` says "on every road", 2026-10-08) |

Because of the idle cut, an idle SSH session must send traffic at least every
180 s: `ServerAliveInterval=60` in ProxyCommand mode, client keepalives in the
native client.

### Connect knobs (query string)

`?family=4|6`, `?path=vpc|direct`, `?dial=lazy` (dial on the first client byte),
`?precheck=<ms>` (wait for the target's first bytes before upgrading; `0` skips
it, for protocols where the client speaks first).

Measured 2026-10-01: `?precheck` is capped at about 400 ms (the wait was the
same for any value from 400 ms to an hour, on every target); it returns early
when the target speaks first; a non-numeric value is silently treated as `0`.

### Errors and close codes

- Error bodies are plain text prefixed by the path. A valid token on a
  WebSocket endpoint without an upgrade gets `426`. Every reverse
  authentication failure is `403 reverse: forbidden` (measured 2026-10-01).
- `/trace` alone is public; `/trace?target=…&banner=1` and `?egress=1` need a
  forward token (`403 trace: missing or wrong token` without one).
- **The forward path's close codes are not in the contract**; its published
  table is for the reverse path only (reading a forward close through it is how
  a first-pass report invented a `1009`). As the relay sends them in its
  Close frames (version 2026-10-03-r2, read from its source), they are:

  | code | reasons |
  | --- | --- |
  | `1000` | `target closed`; `client half-closed, target idle for 15s`; `client closed before the target was dialed` |
  | `1001` | `idle timeout` (180 s with no payload); `session time cap` (12 h) |
  | `1009` | `session byte cap` (64 MiB, **both directions counted together**); `frame larger than 262144 bytes` |
  | `1011` | `connect failed: …`; `target closed before sending anything`; `wrong target banner …`; `client send failed: …`; `write failed: …`; `client error` |
  | `1013` | `client receive backlog`; `target write backlog` (2 MiB queued) |

  Only `1000` is a normal end; `podssh proxy` exits non-zero and prints the
  reason for every other code, and `podssh ssh` prints it when the connection
  drops. Codes not in this table are reported verbatim, with control
  characters removed from the reason.
- Backpressure closes the session (`1013`, at 2 MiB queued) rather than
  dropping a frame. podssh advertises a 512 KiB SSH window, so a server cannot
  have more than that in flight towards a slow podssh. Whether the relay's
  check fires at all is unverified: it reads `bufferedAmount`, which Workers
  may not expose.
- The upgrade is HTTP/1.1 only; podssh never offers h2 through ALPN.

### Choosing a relay

Measured 2026-10-01:

- `/relays.json` ranks relays by whichever Cloudflare edge answered, which
  changes between identical calls; its `score_ms` is a fixed estimate and
  disagreed with measured latency.
- An unknown `?relay=` gets a `200` and is ignored, so a relay name has to be
  validated by the client.
- `/connect/` ignores ranking parameters: the hostname dialled decides. The
  `X-Relay-Name` header on the `101` names the relay that served the session.

### Open questions

- Does the 180 s idle cut apply to reverse sockets? (On the forward path it is
  measured: see [STATUS.md](STATUS.md).)
- The short index `/llms.txt` (r2) carried facts the full document lacks:
  `/v1/pair` can return `409` (retry with a fresh pair), and rotating the mint
  secret invalidates every token at once.

## Reverse path — reaching a host with no egress except the relay

Not implemented in podssh yet (roadmap milestone 4); the rules learned so far
are in [reverse.md](reverse.md).

- `POST /v1/pair` (body `{}`) returns `{name, node_token, connect_token,
  stop_token, expires}` (≤ 72 h).
- The **node** keeps a WebSocket open to `/v1/node/<name>` with `node_token`. It
  receives JSON **text** frames `hello`, `open {id}`, `close {id}` and answers
  `ready {id}` or `reject {id, reason}` (also text frames). Each node **binary**
  frame is the 32 lowercase hex characters of the session id followed by up to
  64 KiB of payload (65568 bytes on the wire at most). Control frames are capped
  at 4 KiB.
- The **operator** connects to `/v1/connect/<name>` with `connect_token`, waits
  for the `ready` text frame, then sends and receives raw binary frames with
  **no framing at all**. An operator text frame closes the socket `1003`; any id
  an operator sends is rewritten, never honoured.
- One node socket per name (a second is refused `409`). `POST /v1/stop/<name>`
  stops the node and its sessions; it has been observed to answer
  `{"stopped": false}` while still destroying the credentials, so treat local
  copies as revoked regardless of the answer.
- The full close-code table (1000–1013 with reasons and actions) is in the
  contract, "Reverse close codes".

## Diagnostics

- `/health` — version, edge colo, egress counters.
- `/relays.json?host=<h>&port=<p>` — ranked colo pool and limits.
- `/trace?target=<host>:<port>&banner=1` — the relay dials the target and
  reports the first banner line; useful to separate "relay problem" from
  "target problem".
