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
   With the resumable layer (T-153) and the end-to-end channel (T-088),
   the local service is the node's podssh: `ready` goes at once, and the
   node dials TARGET after the layer's handshake and once the channel let
   the operator's key in, and, with routes (T-089), the route that it
   named.
5. Route by id, never by the order of arrival. Validate the hex before you
   look up the id.
6. On `409` (a second socket for the same name) at the first registration,
   another node has the name, or the relay still holds the socket of the
   node that ran just before this one (a restart, or a box's script that
   starts the next node at once): connect again with the jittered backoff
   for 30 s, with a line for each `409`, then exit (T-416). After a loss, the relay
   can still hold the old socket for a time: connect again with the jittered
   backoff until the resume deadline after the loss (10 minutes, or the
   time of `--resume-deadline`: the time that the resumable layer keeps a
   session, T-306), then exit (T-261).
7. Do not depend on `hello`. Its value of `maxSessions` is in no published
   document. Measured 2026-10-09: the relay sends the node
   `{"type":"hello","version":1,"maxFrameBytes":65536,"maxSessions":64}`
   first; podssh's node takes its limit, and 16 sessions when none comes.
8. The relay sends no keepalives on reverse sockets. A quiet socket is not
   cut: with no payload for 240 s, with Pings or with none, both sockets
   carried a byte each way afterwards (T-061, 2026-10-09). But the relay's
   side ends a socket's connection at random, with no Close (T-255). Count
   the probes that get no answer (dropssh probes every 20 s and stops after
   3). Connect again with a jittered backoff. The relay answers a Ping on a
   node socket with a Pong of the same payload (measured 2026-10-09), so
   podssh's node pings every 10 s and drops the socket after 3 silent
   intervals.
9. Serve SSH in the process. A standard server behind a node in a sandbox
   fails: `dropbear -i` on a socketpair stops because `getnameinfo` of musl
   refuses `AF_UNIX`; `initgroups` fails under seccomp; and the sshd of
   OpenSSH cannot start where `chroot` is refused.

podssh's node (`podssh_relay::reverse`, feature `pair`, T-079) keeps these
rules. One task writes to the socket and holds the state of each session, so
no frame goes out without its id, before its `ready` or after its `close`; a
late byte of a closed session is dropped, and the other sessions go on. A
session whose local side reads no more ends alone, with `close {id}` and the
reason, so that the socket's reader never waits for it: 1 MiB may wait for a
local side, and with the resumable layer twice its window, which its client
sends with no acknowledgement, so that a slow local side is not taken for a
stopped one (T-271). The node says `online` once the relay has its socket. A
session over the limit gets `reject` at once, and the handler has 10 s to
open the local side. It acts on each end by its code and reason: `409`,
connect again for 30 s at the first registration (T-416), and after a loss
until the resume deadline, with a line on stderr for each `409` and the time
left, then exit; `1001 operator stopped reverse relay`, exit and delete the stored pair;
`1001 pair expired` (or a `403` after the expiry), the repair hook: the
CLI's takes the pair stored under the node's label since, if it expires
later, else the node exits (T-395); `1003` and `1009`, a fault of the node's own bytes, a line and a new
socket, as one frame must not lock out a server that only the node reaches
(T-409; the sessions of the socket resume on the next); anything else,
connect again with the jittered backoff. A node that cannot connect as it is set up (an unusable
proxy setting or trust store) exits too, as connecting again would repeat
it. A stop closes each session with `close {id}`, then the socket with
`1000`. Measured against the live relay on 2026-10-09: two
sessions at once, 1 MiB each way through an echo node, came back whole
(`cargo test -p podssh-relay --features pair --test reverse_live --
--ignored`).

`podssh node NAME TARGET` (T-083) runs this node for the pair stored under
the label NAME, and each session dials TARGET. `podssh relay pair NAME`
makes the pair, and writes the operator's part with `--operator-file`;
`podssh relay status --pair-file FILE` asks `/v1/status/<name>` with that
part's connect token, so an operator's host sees the node and the pair's
expiry too (T-591).
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

`podssh operator NAME` (T-084) runs this operator on stdin and stdout, a
byte pipe as `podssh proxy` is, and `podssh ssh node://[user@]NAME` runs the
SSH client over it, with the node's host key under `node://NAME`. Measured
against the live relay on 2026-10-09: `podssh ssh node://test@lab 'exit 3'`
gave 3 through a node in front of railway.new's SSH service, and
`podssh operator lab` carried that server's banner (`cargo test -p
podssh-cli --test node_live -- --ignored`). Since T-151, `podssh ssh
node://` sends nothing until the node's first byte, to learn whether the
node offers the resumable layer ([design.md](design.md), section 5).
`podssh proxy node://NAME` (T-587) is the same pipe as `podssh operator
NAME`, by one function, in the form of a node that `ssh` takes. With
`--ConnectTimeout SECONDS` (T-589) one bound covers the operator's socket,
the node's `ready` (the leg's hook `OperatorLimits::on_ready` names that
step), its first bytes and the handshakes of the layer and of the channel;
past it the run ends with 69 and the step's words.

Since T-153, each session of `podssh node` runs the resumable layer: the
node answers `ready` at once, greets, and dials TARGET only after the
operator's handshake; it keeps a session and its connection to TARGET for
10 minutes after a lost link, or for the time of `--resume-deadline` (1
minute to 72 h, T-306), which it names to the operator, and at most 64 MiB
of replay buffers. A session whose TARGET ended and whose `CLOSE` went out
holds only the bytes that the operator has not acknowledged, and once the
operator had each byte, its id alone; `podssh operator`, `podssh pipe` with
a `node:` side and `podssh ssh node://` take the signals that end them
(OpenSSH's SIGHUP to its ProxyCommand first) as the end of their bytes, and
close the session, which the node then forgets (T-586). A refusal for the
budget names the sessions that hold it and when the first of them is
forgotten, and the node says it on stderr too.
`podssh ssh node://` and `podssh operator` run the client: after a lost
leg, they open a new one and resume the session where it was, unless the
relay's close says not to come back (a stopped or expired pair, a fault of
podssh's own bytes). A new leg goes to the control host, which alone serves
`/v1/connect` ([relay.md](relay.md)). An operator that does not speak the
layer uses a node of `--plain` (T-263), which carries each session's bytes
as they are, with no resume. Measured 2026-10-09 through the live relay:
GitHub's banner came through a node to `podssh operator` and through the
library's leg with the layer's client (`cargo test -p podssh-cli --test
node_live -- --ignored`), and `podssh ssh node://` logged in to
railway.new through the layer, which then limited the anonymous visitor
(its exit 13) in place of running `exit 3`.

`podssh node NAME [TARGET] --sshd` (T-166) is a roost: a node in front of
a standard sshd, `127.0.0.1:22` by default, so that a normal server gets
the layer. Before it registers, it reads each TARGET's first line, and
requires SSH's version line within 10 s; each session's own connection to
sshd, made after the layer's handshake, is checked again, and a session
whose TARGET does not answer as sshd ends with the reason. The check peeks,
so the line still reaches the client ([cli.md](cli.md)). The sshd runs
already: podssh brings none. A TARGET on the loopback that refuses the dial
makes the roost say whether this host has an sshd, and the command that
installs one, which it never runs (T-590); `podssh doctor`'s line `sshd`
says the same before a roost starts.

Synchronous code (podbox) runs the node and the operator through
`podssh_relay::blocking` (feature `blocking`, T-081): a handler opens each
session of the node as a reader and a writer, and an operator session runs
over a reader and a writer, such as standard input and output.

## The end-to-end channel

Between two podssh ends, each session's bytes run the channel of T-088
(`crates/podssh-relay/src/e2e/`) above the resumable layer, so the relay
carries ciphertext. The legs keep their framing: the channel's bytes are the
session's bytes.

1. Each end sends `podssh-e2e/1` and a newline first, the node at once: a
   client of the layer sends nothing before the far end's first byte.
2. Then frames: a 2-byte length (big-endian) and one message of
   `Noise_XX_25519_ChaChaPoly_SHA256`, 65535 bytes at most. The second and
   third messages of the handshake carry their sender's Ed25519 key and its
   signature of the sender's Noise static key.
3. The node's first message after the handshake is its verdict: let in, or
   refused (a key that is not in its allowlist, a target out of reach, or
   another reason). The node dials TARGET only after it let the key in.
4. Each later message is data, or the clean end of one direction; the
   stream under the channel is shut when both directions ended. A stream
   that ends with no such end is a cut. A message that fails its check ends
   the session: the relay can drop, repeat, move or change one.
5. `--no-e2e` at both ends carries the bytes as before; an end with the
   channel refuses a peer without it, by the first bytes that it sends.
6. The operator's proof of its key may name a route of the node (T-089),
   encrypted with it: the relay never sees which. The node refuses a route
   that it does not have, or that the key may not use, before it dials. The
   same word may name a target of the operator's own, `HOST:PORT` (an IPv6
   address in brackets), which its `:` tells from each route's name: an
   exit node (T-431, `podssh node --exit`) resolves it, checks each address,
   and dials the checked addresses alone; a node that is no exit refuses it,
   and a node of before T-431 refuses the proof whole.
7. Two ends that hold the net's document (T-429) say so: the operator's
   first message carries `podssh-net/1` in clear, which an end of before
   sets aside; only then do the proofs take the net's form (version 3),
   which names the route, the owner and the serial held, and whether a
   document follows. The operator's newer document is a message of its own
   before the verdict; the node's, after a verdict that let the operator in.
   Each goes to a member of it only. The node's verdict on a member follows
   the net's policy (T-430) for the route named, or for the target with no
   route, with the document that it holds once the operator's came; for an
   exit's target, the policy's `exit:NODE` or a range, then each address
   again once the name resolved (T-431).

## The transit road

A pair's node and its operators also meet at a magic-wormhole transit relay
(T-436), Least Authority's `wss://relay.mw.leastauthority.com` by default,
which needs no account and which the operator's ruling Q65 lets podssh try
unasked ([carriers.md](carriers.md)). It carries a session where the
relay of the pair is down, or refused by a proxy, as long as the pair
lasts. `PODSSH_TRANSIT=no` turns it off; a `ws://` or `wss://` URL there
names another relay.

1. Each end derives the relay's TOKEN (64 hex digits) and the key of a
   proof from the pair's connect token and name, by HKDF-SHA256, and takes
   a random SIDE (16 hex digits) for its run.
2. Each connection sends `please relay TOKEN for side SIDE` and a newline,
   alone in one binary message; the relay answers `ok` and a newline to
   both once two sides of the TOKEN met, then copies the messages. A
   connection waits while nobody comes; two connections of one SIDE never
   meet.
3. After `ok`, each end sends its part (`N`, the node; `C`, a client) and a
   nonce, then an HMAC-SHA256 of both nonces under the proof key. A peer of
   the same part (two clients of one pair) parts and tries again; a peer
   whose proof fails (one that knows the TOKEN alone, as the relay does) is
   refused, so the node's door stays the pair's.
4. The bytes after the proofs are the link's: the resumable layer and, above
   it, the end-to-end channel, as on the pair's road. The relay has no
   half-close, so an end's Close ends both directions after the bytes that
   it sent.

A node of the layer and the channel (no `--plain`, no `--no-e2e`) with a TCP
TARGET keeps one connection waiting, opens the next at each meeting, and
shares its keeper with the pair's road, so that a session resumes on either;
a node of `--derp` with a pair does the same. `podssh ssh node://NAME` races
the road last, only when each road before it failed, and again at each
resume. Tests: `cargo test -p podssh-relay --test transit`, against
magic-wormhole's own relay on the loopback (5 passed, 2026-11-02), and with
`--ignored` through Least Authority's relay (`transit-live.yml`).

## Finding a node

A pair's name is random and lasts 72 hours at most, so podssh finds a node
by a name of the user's own, and by its key, and asks no directory
(T-090):

- **A label, on the operator's host.** `podssh relay pair NAME` keeps the
  pair under the label NAME (`pair-NAME.json`, private), and each command
  finds the pair by it; a new pair kept under the same label takes the old
  one's place, so a script stays the same. Nobody but the user sees the
  label: the relay sees the pair's random name, and when each end connects.
- **The node's key, pinned by label.** The node's key stays across its
  pairs (`node-NAME.key`), and the operator pins it by label at its first
  sight (`known-nodes`, T-087): a new pair of the same node needs no new
  trust step, and a node with another key is refused. The pins name a
  label and a key, never a pair or a token; the relay sees ciphertext.
- **A new pair reaches its operators** in the operator's part that `podssh
  relay pair --operator-file` writes, which the user hands on. Its delivery
  through the relay waits for the relay's operator (T-086).
- **A member of the net** (T-429): a name that the user's own net names
  is looked up there first, with the key that the channel then checks in
  place of the pins, and the tickets that race beside the pair kept under
  the name; `podssh ssh NAME` alone reaches a member with the role `node`
  ([cli.md](cli.md), "`podssh net`").
- **No directory, and no mDNS.** A directory in the relay would give it a
  list of each node and when it is online, and needs its operator; mDNS
  would announce a node to its network, and the sandboxes that podssh
  serves refuse UDP. Neither exists.

## Exit codes

1. A session that never got `ready` never exits 0.
2. After `ready`, the closes `1003` and `1009` give an exit code that is not
   zero. (dropssh exited 0.)
3. Use the close code **and** the reason. The two reasons of `1001` (node
   stopped, pair expired) need opposite actions. An empty reason with `1001`
   must not start a new mint.
4. An end with no Close is the link, and so is `1011 node disconnected` for
   the node's link: the relay's side drops them at random (T-255). Say so,
   and that a new session may work; the node connects again by itself.
   `podssh operator` exits 69 for both.

## Credentials

WARNING: Never print the `stop_token`. The relay's reference client puts
tokens in URLs. podssh does not do that.

- After `POST /v1/stop`, the relay answered both remaining tokens with
  `403 reverse: forbidden` (measured 2026-10-01; again on 2026-10-09, for
  each token and for a second stop).
- `/v1/status` accepts `connect_token` only; `node_token` and `stop_token`
  get `403` (measured 2026-10-09, T-078).

## The Piping Server road

A proxy that refuses the WebSocket upgrade stops the pair's road at both
ends, as each relay and each carrier but one needs the upgrade. A Piping
Server needs none: it streams the body of a `POST /PATH` into the answer to
a `GET /PATH`, over plain HTTPS ([carriers.md](carriers.md), item 5 of the
reverse road). podssh's road through one (T-437, drafted 2026-11-02;
`crates/podssh-relay/src/piping/`) keeps these rules:

1. A path is the only meeting point, so each comes from the pair's secret:
   the HMAC of the connect token over the pair's name, which both ends hold
   and no path shows. The node waits at its door, a GET of one such path,
   asked again after each hello, after each loss and each 4 minutes.
2. A client posts a hello at the door: the mode of its link, a random id,
   and a tag of the secret, so that the node opens no link for a stranger.
   A whole POST ends once the node's GET took it, so a node that is not
   there is told in 20 s; a door that another client holds for a moment is
   knocked at again.
3. Each link has two paths of its id, one for each way. Each end POSTs its
   way and GETs the other's; each way begins with a mark of the link and
   the way, which the receiver checks before the resumable layer reads a
   byte, so an end that took the wrong path ends the link there.
4. Over HTTP/2, where the server's TLS takes `h2` (`ppng.io` does), the door
   and each link are streams of one connection, with a PING each 25 s. Over
   HTTP/1.1, each streamed way has a connection of its own: a node holds its
   door's and two for each link, a client two (see T-437's Decision on Q44).
5. A streamed POST that gets no answer within 15 s is held on the way: the
   client asks for numbered pieces from then on, a whole POST to `PATH-N`
   for each piece of at most 64 KiB, one after another, and the far end
   GETs them in turn. A failed POST ends the link, and the layer sends again
   what the far end did not acknowledge.
6. The layer and the end-to-end channel run above each link, as on each
   road between two podssh ends: the server sees the paths, the sizes and
   the times, and a change that it makes ends the session.

`podssh node NAME TARGET` probes once TARGET answered: one upgrade of its socket's
path at the relay with no token, which the relay refuses with its own word
(`403 reverse: forbidden`). A refusal of 400, 403, 405 or 501 in words that
are not the relay's, or a `426` (the request came with its `Upgrade` taken
off), is a refusal on the way: the node then serves the Piping Server road
alone, unasked (Q65), until the pair expires, as the pair's road could not
pass and a proxy's `403` must not read as a stopped pair. A connection that
ends with no answer, or a gateway's `5xx`, is no such sign, as a relay that
went away looks the same. `podssh ssh
node://NAME` takes the road when the pair's leg finds the same, and races
the roads again at each resume. `PODSSH_PIPING=yes`, or a server's
`https://` URL, asks for the road: the node serves it beside the pair's
road, with one keeper of sessions for both, and the client races it 250 ms
after the pair's road; `PODSSH_PIPING=no` turns it off. Measured (2026-11-02):
`cargo test -p podssh-relay --features piping --test piping`, against
nwtgck's two servers on the loopback, 6 passed; a short live run through
`ppng.io` (`--test piping_live -- --ignored`) passed.

## A carrier

A host whose every road out is closed often grants one channel, as the
exec channel of a platform's own SSH. `--carrier ADDR` (T-595) puts the
node's socket on such a stream, with no relay, no pair and no token
(`crates/podssh-relay/src/serve/reverse/carrier.rs`):

1. The stream carries the node's socket, its WebSocket frames with no HTTP
   before them. The node is the client's side of the WebSocket, as on the
   relay's socket, and runs its own `serve`; the other end runs the relay
   role's side of the socket (T-427) in its own process, for this one node,
   and each operator's leg is a pipe in that process to it. So rules 1 to 5
   of "Node" hold as they are, and the role's checks of them too.
2. The role speaks first (`hello`). The node's first frame is a Ping, sent
   once its TARGET answered: no `open` goes before it, as the role ends a
   session that the node does not ready within 15 s (`1013 node open
   timeout`), and a node that a program starts can take longer to read.
3. The stream is the door: whoever holds it reached the node through what
   carries it. The end-to-end channel stays on, and the operator pins the
   node's key under NAME, a label alone, so a stream that another key
   answers is refused (77).
4. One stream for the node's life. At its end the sessions end, and the node
   exits 0 after the operator's Close, or 69 for a stream that failed. The
   operator starts a stream of `exec:` again, once for each wait, for the
   next leg; a stream of `stdio` or `fd:N` has one life (`410`).
5. The relay's limits do not hold: no cap of 64 MiB a session, and no
   expiry of a pair. The role's bound of 1 MiB for a slow receiver does, and
   the layer keeps its window below it.
6. Each client of a node takes the carrier: `operator`, `proxy`, `ssh`,
   `cp`, `mv`, `scp` and `sftp` to `node://NAME`, and `pipe`'s `node:` and
   `udp:node:` sides. One command serves one role, and each of its
   connections, and each client of a listening `pipe`, is a leg of its own
   on the one stream, which ends with the command: the node hears the Close,
   and the program of `exec:` ends. `--ConnectTimeout` of `operator`,
   `proxy` and `pipe` bounds the open, the node's read of the stream first.
