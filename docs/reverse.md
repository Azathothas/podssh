# Reverse mode (milestone M4)

`podssh node` makes a local service available from a host whose only egress
is the relay. `podssh operator` reaches that service. The wire format is in
[relay.md](relay.md) and in the relay's own contract. Most rules on this page
come from dropssh, a sibling project that implemented both sides.

## Node

1. Send the 32-character session id and its payload as **one** WebSocket
   frame. Thus there must be one writer only.
2. Stop the writes to a session as soon as `close {id}` arrives. A `data` or
   `ready` for an old id makes the relay close the node socket with `1003`,
   which ends each session on it.
3. Do not close the socket to end one session.
4. Send `ready {id}` only after the local service accepts the connection.
5. Route by id, never by the order of arrival. Validate the hex before you
   look up the id.
6. On `409` (a second socket for the same name), exit. Do not retry.
7. Do not depend on `hello`. Its direction is disputed, and the value of
   `maxSessions` seen on the wire (`64`) is in no published document.
8. The relay sends no keepalives on reverse sockets, and a quiet socket
   becomes dormant. Count the probes that get no answer (dropssh probes every
   20 s and stops after 3). Connect again with a jittered backoff.
9. Serve SSH in the process. A standard server behind a node in a sandbox
   fails: `dropbear -i` on a socketpair stops because `getnameinfo` of musl
   refuses `AF_UNIX`; `initgroups` fails under seccomp; and the sshd of
   OpenSSH cannot start where `chroot` is refused.

## Operator

1. Never add or remove the 32-byte id. The operator leg has no framing.
2. A `reject` text frame carries the full reason before the close. The
   reason of the close is cut to 123 bytes.
3. Wait longer than the relay's 15 s for `ready`.

## Exit codes

1. A session that never got `ready` never exits 0.
2. After `ready`, the closes `1003` and `1009` give an exit code that is not
   zero. (dropssh exited 0.)
3. Use the close code **and** the reason. The two reasons of `1001` (node
   stopped, pair expired) need opposite actions. An empty reason with `1001`
   must not start a new mint.

## Credentials

WARNING: Never print the `stop_token`. The relay's reference client puts
tokens in URLs. podssh does not do that.

- After `POST /v1/stop`, the relay answered both remaining tokens with
  `403 reverse: forbidden` (measured 2026-10-01; again on 2026-10-09, for
  each token and for a second stop).
- `/v1/status` accepts `connect_token` only; `node_token` and `stop_token`
  get `403` (measured 2026-10-09, T-078).
