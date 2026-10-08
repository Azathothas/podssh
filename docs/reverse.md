# Reverse mode (milestone 4)

`podssh node` exposes a local service on a host whose only egress is the
relay; `podssh operator` reaches it. The wire format is in [relay.md](relay.md)
and in the relay's own contract. These are the rules learned before
2026-10-08, mostly from dropssh, a sibling project that implemented both
sides.

## Node

- The 32-character session id and its payload go out as **one** WebSocket
  frame, so there is a single writer.
- Stop writing to a session as soon as `close {id}` arrives: `data` or `ready`
  for a stale id makes the relay close the node socket with `1003`, which kills
  every session on it.
- Never close the socket to end one session.
- Send `ready {id}` only once the local service accepts the connection.
- Route by id, never by arrival order, and validate the hex before looking the
  id up.
- On `409` (a second socket for the same name), exit; do not retry.
- Do not depend on `hello`: its direction is disputed, and the `maxSessions`
  value seen on the wire (`64`) is in no published document.
- The relay sends no keepalives on reverse sockets, and a quiet socket goes
  dormant. Judge liveness by counting unanswered probes (dropssh probes every
  20 s and gives up after 3), and reconnect with backoff and jitter.
- Serve SSH in-process. A stock server behind a node in a sandbox fails:
  `dropbear -i` on a socketpair dies because musl's `getnameinfo` refuses
  `AF_UNIX`, `initgroups` fails under seccomp, and OpenSSH's sshd cannot start
  where `chroot` is denied.

## Operator

- Never add or remove the 32-byte id: the operator leg carries no framing.
- A `reject` text frame carries the full reason before the close, whose reason
  is cut to 123 bytes.
- Wait longer than the relay's 15 s for `ready`.

## Exit codes

- A session that never got `ready` never exits 0.
- After `ready`, closes `1003` and `1009` exit non-zero (dropssh exited 0).
- Branch on the close code **and** the reason: the two `1001` reasons (node
  stopped, pair expired) need opposite actions, and an empty `1001` reason must
  not trigger a new mint.

## Credentials

- Never print the `stop_token`. The relay's reference client puts tokens in
  URLs; podssh does not copy that.
- After `POST /v1/stop`, both remaining tokens were answered
  `403 reverse: forbidden` (measured 2026-10-01). Which token `/v1/status`
  accepts is UNKNOWN.
