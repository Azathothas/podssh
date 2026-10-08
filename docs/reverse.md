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
7. Do not depend on `hello`. Its value of `maxSessions` is in no published
   document. Measured 2026-10-09: the relay sends the node
   `{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}`
   first; podssh's node takes its limit, and 16 sessions when none comes.
8. The relay sends no keepalives on reverse sockets, and a quiet socket
   becomes dormant. Count the probes that get no answer (dropssh probes every
   20 s and stops after 3). Connect again with a jittered backoff. The relay
   answers a Ping on a node socket with a Pong of the same payload (measured
   2026-10-09), so podssh's node pings every 10 s and drops the socket after 3
   silent intervals.
9. Serve SSH in the process. A standard server behind a node in a sandbox
   fails: `dropbear -i` on a socketpair stops because `getnameinfo` of musl
   refuses `AF_UNIX`; `initgroups` fails under seccomp; and the sshd of
   OpenSSH cannot start where `chroot` is refused.

podssh's node (`podssh_relay::reverse`, feature `pair`, T-079) keeps these
rules. One task writes to the socket and holds the state of each session, so
no frame goes out without its id, before its `ready` or after its `close`; a
late byte of a closed session is dropped, and the other sessions go on. A
session over the limit gets `reject` at once, and the handler has 10 s to
open the local side. It acts on each end by its code and reason: `409`,
exit; `1001 operator stopped reverse relay`, exit and delete the stored pair;
`1001 pair expired` (or a `403` after the expiry), a re-pair hook, off by
default; `1003` and `1009`, exit; anything else, connect again with the
jittered backoff. A node that cannot connect as it is set up (an unusable
proxy setting or trust store) exits too, as connecting again would repeat
it. A stop closes each session with `close {id}`, then the socket with
`1000`. Measured against the live relay on 2026-10-09: two
sessions at once, 1 MiB each way through an echo node, came back whole
(`cargo test -p podssh-relay --features pair --test reverse_live --
--ignored`).

`podssh node NAME TARGET` (T-083) runs this node for the pair stored under
the label NAME, and each session dials TARGET. `podssh relay pair NAME`
makes the pair, and writes the operator's part with `--operator-file`.
Measured against the live relay on 2026-10-09: an operator that held the
operator's part alone read GitHub's SSH banner through
`podssh node lab github.com:22` (`cargo test -p podssh-cli --test node_live
-- --ignored`).

## Operator

1. Never add or remove the 32-byte id. The operator leg has no framing.
2. A `reject` text frame carries the full reason before the close. The
   reason of the close is cut to 123 bytes. (Measured 2026-10-09: a node's
   reason of 200 bytes reached the operator whole, with a Close `1011`.)
3. Wait longer than the relay's 15 s for `ready`.

podssh's operator (`podssh_relay::reverse::operator`, feature `pair`, T-080)
keeps these rules. Before `ready` it keeps up to 1 MiB of input and sends
nothing; it waits 20 s for `ready`. Then it sends what it kept, in order, and
copies both ways in frames of at most 64 KiB, with no id and no text frame;
an empty frame is ignored. At the end of its input it sends a Close `1000`
and waits up to 10 s, so the last bytes arrive. The relay answers a Ping on
the operator's socket too (measured 2026-10-09), so it pings as the node
does. Its outcome: never ready (a failure, with a `reject`'s whole reason),
ended after `ready` (`1000` a success, each other code a failure with the code
and the reason), or the end of its input. podssh's node sends the whole
reason of a `reject` or a `close`, cut only to fit the 4 KiB control frame.
A Close of the relay that crosses the operator's own, with a code other than
`1000`, is a failure too.

Synchronous code (podbox) runs the node and the operator through
`podssh_relay::blocking` (feature `blocking`, T-081): a handler opens each
session of the node as a reader and a writer, and an operator session runs
over a reader and a writer, such as standard input and output.

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
