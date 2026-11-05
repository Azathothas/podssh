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
   Its `version` is the relay's dialect, which the node compares ("The
   dialect of the road", below).
8. The relay sends no keepalives on reverse sockets. A quiet socket is not
   cut: with no payload for 240 s, with Pings or with none, both sockets
   carried a byte each way afterwards (T-061, 2026-10-09). But the relay's
   side ends a socket's connection at random, with no Close (T-255). Count
   the probes that get no answer (dropssh probes every 20 s and stops after
   3). Connect again at once after a socket that served, as a drop, a
   restart (`1012`) or one bad frame is no overload, and then with a
   jittered backoff. The relay answers a Ping on a
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
stopped one (T-271). Its control frames go before the sessions' bytes
(T-410), and the bytes wait in a line for each session, a turn each
(T-648): four reads of a local side may wait in its line, 256 in all, the
one queue's room of before, and a line that holds nothing always takes one
read. So an interactive session's echo waits for one read of each other
session at most, not for a bulk copy's backlog on a slow egress, and a
session's `close` still follows its last bytes. The node says `online` once
the relay has its socket. A
session over the limit gets `reject` at once, and the handler has 10 s to
open the local side. It acts on each end by its code and reason: `409`,
connect again for 30 s at the first registration (T-416), and after a loss
until the resume deadline, with a line on stderr for each `409` and the time
left, then exit; `1001 operator stopped reverse relay`, exit and delete the stored pair;
`1001 pair expired` (or a `403` after the expiry), the repair hook: the
CLI's takes the pair stored under the node's label since, if it expires
later, else the node exits (T-395); `1003` and `1009`, a fault of the node's own bytes, a line and a new
socket, as one frame must not lock out a server that only the node reaches
(T-409; the sessions of the socket resume on the next); `1012`, a restart
of the relay, which podssh's relay role sends before a planned stop, and
anything else: connect again. For each socket that ends, a line on stderr
says how (the relay restarting, a link with no Close, a fault, another
close) and when the node connects again: at once the first time after a
socket that served, and at most once each 10 s, as its sessions wait on the
layer meanwhile (T-255, T-421); else after the jittered backoff, which the
line names. A node that cannot connect as it is set up (an unusable
proxy setting or trust store) exits too, as connecting again would repeat
it, and so does one whose relay speaks another dialect of the road (T-643).
A stop closes each session with `close {id}`, then the socket with
`1000`. Measured against the live relay on 2026-10-09: two
sessions at once, 1 MiB each way through an echo node, came back whole
(`cargo test -p podssh-relay --features pair --test reverse_live --
--ignored`).

`podssh node NAME TARGET` (T-083) runs this node for the pair stored under
the label NAME, and each session dials TARGET. `podssh relay pair NAME`
makes the pair, and writes the operator's part with `--operator-file`;
`podssh relay status --pair-file FILE` asks `/v1/status/<name>` with that
part's connect token, so an operator's host sees the node and the pair's
expiry too (T-591). On podssh's relay role a pair is renewed by its stop
token, with its tokens (T-592): `podssh relay pair --renew NAME` by hand,
and the node by itself at the start of its last day, then each hour until
it took; the role's status names the new end, which an operator whose file
names an end that passed asks once, so the operator's file keeps working.
On podssh's relay role the owner halts a pair for a while by the same
token (T-647): `podssh relay halt NAME [--reason TEXT]` closes each of its
sessions once and refuses each operator with `503` and the words, and
`podssh relay resume NAME` lets them in again. The node keeps its socket
across both, and its name, so it waits out no `409` (rule 6) after a
resume; it skips the role's `halted` and `resumed` frames, as any type
that it does not know. An operator whose session of the layer the halt
closed asks for a new leg, as after each `1011`; the `503` of a halt is
final for it, as a refused token is, so its session ends with the owner's
words and does not wait out the resume deadline.
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
past it the run ends with 69 and the step's words. `--timeout DURATION` and
`PODSSH_TIMEOUT` are other names of that bound (T-613), and the line names
the one that set it.

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
forgotten, and the node says it on stderr too. A client of `--no-resume`
asks, in the layer's handshake, for a session that the node forgets with
its connection to TARGET as the link ends, whatever the end, and carries
it on that link alone (T-612).
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
   again once the name resolved (T-431). An operator whose offer got a
   plain proof goes on without the document, and says so once (T-643).

## Grants used once

A token of the relay is a bearer token: whoever holds it can use it, as
often as it likes, until it expires. A grant (T-226, GitHub #35) lets one
operator's key in, once, at a node whose door would not take it otherwise,
and the relay never sees it (`crates/podssh-relay/src/grant/`):

1. A grant is an OpenSSH user certificate of the operator's Ed25519 key,
   the key of the end-to-end channel (`client.key`, or `--client-key`). Its
   issuer is the node's own key, or a key of `--allow` (or a member of the
   net) for what that key may reach itself, so a grant never reaches more
   than its issuer. Its principal is `node:SHA256:...`, the node's
   fingerprint, with `/ROUTE` for a route; it has a window of its own, and
   the critical option `once@podssh`. `ssh-keygen -s ISSUER -I ID -n
   node:SHA256:... -O clear -O critical:once@podssh -V +1h KEY.pub` makes
   one, and so does `podssh node NAME --grant-to KEY`, with the node's key.
2. The operator gives it with `--grant FILE` (`operator`, `proxy` and `ssh`
   to `node://`, `pipe`'s `node:` side). It goes in the operator's proof of
   the channel, version 4, around the proof of each other form, encrypted,
   after the operator checked the node's key: no relay, no proxy and no URL
   holds it, and a URL in place of the file is refused before a request
   exists. A node of before T-226 refuses that proof whole.
3. The node checks it before it dials, in this order: the key that the
   channel proved is the certificate's; the issuer's signature; a user
   certificate; the principal; the window, with 5 minutes of skew; each
   critical option known; the serials of `--revoked FILE`. Then it records
   the grant in `grants-NAME` of the cache, a file made create-new, synced,
   and its directory synced, and only then lets the session in: a second
   use is refused, also after a restart, and a crash between the two spends
   the grant. A grant decides alone: one that fails is refused, also for a
   key that `--allow` names.
4. Bound to its key, a grant that leaks is worth nothing without that key.
   A resume of the layer runs no new handshake, so a grant lets in one
   session, which lives as long as the layer keeps it.
5. Revocation: the issuer's line goes from `--allow`, or its serial goes in
   the file of `--revoked`, read again for each grant; a file that is
   missing lets no grant in.

podssh's relay role makes a pair whose connect token takes one upgrade
alone, too (`podssh relay pair NAME --once`, [relay.md](relay.md)), so that
a token that leaks after its use is worth nothing; its session resumes on
tokens of one leg ("Tokens of one leg", below). A node whose door is the
pair's token alone (no `--allow`, no net) says so as it starts: a TARGET
that is not SSH has no other gate. Measured on 2026-11-03 (T-226): `cargo
test -p podssh-relay --features pair,grant --test grant`, 9 passed, against
certificates that OpenSSH 9.6's `ssh-keygen -s` minted.

## Tokens of one leg, and a stop token that rotates

A pair's connect token opens each leg of each session until the pair ends,
and its stop token lasts as long as the pair: a token that a proxy logged
from a request's headers stays good until then. Through podssh's relay
role, each leg after a session's first has a connect token of its own,
which one upgrade spends, and the node rotates its stop token (T-615,
drafted 2026-11-04; `crates/podssh-relay/src/e2e/legs.rs`,
`crates/podssh-relay/src/reverse/legs.rs`,
`crates/podssh-relay/src/serve/reverse/legs.rs`):

1. The role's `hello` on the node's socket says `"legTokens": true` and
   `"stopRotation": true`, fields that a node of before keeps and reads
   nothing of; `/relays.json` says `"reverse": {"leg_tokens": true,
   "rotate": true}`. A relay of the contract says neither, and the node
   and its operators keep the pair's tokens as before.
2. A session that the end-to-end channel lets in above the layer gets a
   seed of 32 random bytes in the node's verdict, after the code that lets
   it in, where an operator of before reads nothing; the relay never sees
   it. Leg N of the session after the first takes the token
   HMAC-SHA256(seed, "podssh leg token, version 1" and N), in 64 hex
   digits: no token crosses a wire before its own leg, and none is carried
   ahead for the next.
3. The node registers the SHA-256 of the next four at the role, on its
   socket (`{"type":"token","digest":HEX,"expires":MS}`, a day ahead, or
   0 to withdraw one), before the verdict goes. The role takes such a
   token for one upgrade of `/v1/connect/<name>` while the node is joined,
   tells the node which (`{"type":"spent","digest":HEX}`) before the
   session's `open`, and refuses it after, also when the node registers it
   again; with no node joined, it answers `503` and takes nothing. The node
   then registers the four after it, withdraws those before it, withdraws
   each of a session that ended, and registers each session's again on
   each new socket, as a role that restarted holds none.
4. The operator's first leg opens with the pair's connect token; each next
   one, a resume, a move or a spare link, with the session's next token. A
   refusal of one (403) is tried again once, as a role that restarted holds
   it again only once the node's next socket registered it, then the next;
   after eight in a row the legs take the pair's token. So a session of a
   pair of `--once` resumes, and a token that a proxy logged is spent
   already.
5. At its first socket that heard the offer, and each day after, a node
   whose pair is the store's draws the next stop token, names its SHA-256
   at `POST /v1/rotate/<name>` by the token now, keeps the new one in the
   store in the place of the old, then uses it once: that use makes it the
   pair's and ends the one before. A stop between two steps leaves a token
   that the role takes. `podssh relay revoke` and `relay pair --renew` on
   the node's host read the store; a copy of the pair elsewhere can no
   longer stop it. A pair of `--pair-file` keeps its stop token, as that
   file is the user's. The next pair that a node goes on with at an expiry
   (T-395) is rotated so too, at its own first socket that heard the offer, and renewed (T-620).

Measured on 2026-11-04: `relay_serve_once` 6 passed and `relay_serve_node` 6 passed (T-615's Prove).

## A member that an answer leaves out

A relay of before, or one that is not podssh's, leaves out each member
that it does not know. podssh reads each optional member of a peer's
answer (a role's `hello`, an answer of `/v1/pair`) as one of three kinds,
by one rule (`podssh_relay::answer`, T-633), so that an absence is safe in
each:

- **A hint**, such as `hello`'s `maxSessions` and `maxFrameBytes`: absent,
  or zero, keeps podssh's own floor (16 sessions, the published cap of a
  frame), and never refuses; a value over the published cap is clamped.
- **An offer of a feature**, such as `hello`'s `legTokens` and
  `stopRotation`: only `true` offers. Absent, `false`, `"true"` and `1` are
  each no offer, and podssh goes on without the feature, as it did before
  the feature.
- **A guarantee that this end asked for**, such as `/v1/pair`'s `once` for
  `podssh relay pair --once`: only `true` confirms it. Anything else is a
  refusal, and podssh first undoes what the peer made (it stops the pair),
  then says it, and never retries, as the same relay would make the same.
- **A dialect**, such as `hello`'s `version` (T-643): absent, or null, is
  the dialect of before, which each peer that states none speaks; one that
  this end does not read is refused with a sentence that names both sides,
  and never tried again ("The dialect of the road", below).

A new member names its kind where it is described, and takes the rule's
function of its kind, never a comparison of its own: an `is_some()` would
read a `false` as yes.

## Pairing by a short code

The operator's part of a pair moves by a code that a person reads on the
node's host and types on the operator's, in place of a file (T-086,
drafted 2026-11-03; `crates/podssh-relay/src/code/`):

1. `podssh relay pair NAME --code` gives the pair stored under NAME while
   it has 10 minutes left, else it makes the next one first. The code is the
   mailbox's nameplate and three words of the PGP list, odd and even in
   turn, as magic-wormhole writes one (`7-crossover-clockwork-adroitness`):
   24 bits of secret. It shows on the run's terminal alone (stderr when it
   is one, else the process's terminal), never on stdout, in a log or in
   argv; a run with no terminal is refused before a pair is made.
2. The two ends meet at a mailbox of magic-wormhole's protocol: its public
   one, `wss://relay.magic-wormhole.io/v1`, then Least Authority's (Q65), or
   those of `--pair-mailbox` and `PODSSH_PAIR_MAILBOX`, such as podssh's
   relay role at `/v1/mailbox` ([relay.md](relay.md)). The taker looks for
   its giver at each in order: one that lists the code's nameplate has it,
   one that lists others has not, and where none is listed the giver's
   `pake`, which the mailbox keeps, comes at once or not at all; claiming a
   nameplate that lists others would spend a stranger's code.
3. Each end sends SPAKE2's symmetric message, keyed by the whole code with
   podssh's AppID as its identity; then each message is sealed in NaCl's
   SecretBox under a key of HKDF-SHA256 from the key, the sender's side and
   the phase, as magic-wormhole's own client does, so that a peer of its
   Python library pairs with podssh's. The mailbox sees the nameplate, the
   SPAKE2 messages, the sizes and the times: no code, and no message it
   could open or change.
4. The first sealed message, `version`, is the proof of the code. One that
   does not open ends the code at that end (`scary`); the giver leaves after
   one exchange, whatever its end, and the mailbox takes two sides of a
   nameplate alone, so an attacker gets one guess of the 24 bits for each
   code that the user makes, and is seen. A code lives 10 minutes.
5. Then podssh's own words: the giver offers its label, the node's key and
   the operator's part; the taker checks the part as a pair's answer is
   checked (T-076, T-078), pins the node's key under its own label in
   `known-nodes` (a key that differs from the pin is refused, 77, and
   nothing is kept), answers with its own key (`client.key`, or
   `--client-key`), and keeps the part as `operator-NAME.json`, where each
   client of the pair finds it by NAME. The giver adds the key's line to the
   allowlist of `--allow FILE`, which the node reads again for each
   session; with none, the pair's connect token stays the door.

Measured on 2026-11-04 (T-086): `cargo test -p podssh-relay --features
pair,code,serve --test pair_code`, 9 passed, against podssh's relay role
and magic-wormhole-mailbox-server on the loopback, with a peer of
magic-wormhole's Python library 0.24.0; `cargo test -p podssh-cli --test
relay_code --test relay_code_role`, 5 and 1 passed; through the public
mailboxes of magic-wormhole and Least Authority, two ends paired by a code
(`pair_code_live`).

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
  relay pair --operator-file` writes, which the user hands on, or by a short
  code that a person reads aloud (`podssh relay pair NAME --code`, then
  `podssh relay join NAME`, "Pairing by a short code" above, T-086), which
  pins the node's key under the label before the first session.
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
   `1012` is a relay that restarts, which podssh's relay role sends before
   a planned stop: say that, and that the node comes back with the relay.
   `podssh operator` exits 69 for each. A session of the layer resumes on
   a new leg after each of them, and says nothing of it but its loss and
   its resume.

## Credentials

WARNING: Never print the `stop_token`. The relay's reference client puts
tokens in URLs. podssh does not do that.

- After `POST /v1/stop`, the relay answered both remaining tokens with
  `403 reverse: forbidden` (measured 2026-10-01; again on 2026-10-09, for
  each token and for a second stop).
- `/v1/status` accepts `connect_token` only; `node_token` and `stop_token`
  get `403` (measured 2026-10-09, T-078).
- Each token is a bearer token. A grant used once ("Grants used once",
  above) holds the node's door with a key that the channel proves; a pair
  of `--once` on podssh's relay role ends its connect token at its first
  upgrade (T-226); on that role each later leg takes a token of its own,
  and the node rotates its stop token ("Tokens of one leg", above; T-615).

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

## The OpenTunnel road

OpenTunnel gives a node, with no account, a public name whose TLS ends at
the node itself ([carriers.md](carriers.md), item 6 of the reverse road):
the node's leg is a WebSocket through `HTTPS_PROXY`, and a client's is TLS
by name on port 443, with no upgrade, so a client behind a proxy that
refuses the upgrade has this road beside Piping Server's. podssh's road
(T-530 and T-531, drafted 2026-11-03; `crates/podssh-relay/src/opentunnel/`)
keeps these rules:

1. A node makes one tunnel for its life (Q76), keeps it with its token, its
   key and its CSR in a private file before the service orders its
   certificate, and binds the same CSR again at a start that stopped
   half-way, so that it never spends the service's 5 certificates of a day
   for a tunnel. A tunnel whose token the service no longer takes is made
   again, and said.
2. The node claims one route, 26 random letters, never the tunnel's own
   name, which the logs of Certificate Transparency show: a visitor of that
   name is closed by the service before the node hears of it. The node's
   name is `ROUTE.ID.opentunnel.xyz`.
3. Each visitor's connection comes over the bridge from its ClientHello on;
   the node ends TLS with the tunnel's certificate, in podssh-ws's server,
   and serves the resumable layer and the end-to-end channel above it, with
   one keeper of sessions beside the pair's road.
4. The node renews nothing itself: the service renews the certificate with
   the same CSR, and the node asks for it each 12 hours, each minute in its
   last 30 days, and presents a new one from the next handshake on.
5. A client dials the name that the node printed, `--opentunnel-name`, or
   the one kept under NAME, and checks TLS by that name; the channel checks
   the node's key. The service sees the names, the times and the sizes.

Measured on 2026-11-03 (T-530): `cargo test -p podssh-relay --features
opentunnel --test opentunnel_link`, 7 passed, against a stand-in of the
protocol; `opentunnel-interop.yml` against OpenTunnel's own server v0.6.1
(run 41675551360); and `cargo test -p podssh-cli --test opentunnel_road`
from end to end.

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
7. The exit goes on a carrier too (T-596): `podssh node NAME --exit
   --carrier ADDR` at the end with egress, and `podssh exit NAME --listen
   ADDR:PORT --carrier ADDR` at the other, whose `stdio` is its own to give,
   as its stdin and stdout carry nothing else. The proxy starts the stream
   at once, so that the node's first frame is answered, and each of its
   connections is a leg; a stream of `stdio` or `fd:N` ends the proxy when
   its node leaves. The stream is no door to the egress: a member's key and
   the net's rule to `exit:NAME`, or to a range, as on each road.
8. `ssh`, `proxy` and `pipe` take the exit on a carrier too, with `--exit
   NAME --carrier ADDR` (T-614): each session of the command is a leg of
   its one stream, whose channel's word is the target, as `exit --listen`'s
   are; their stdin and stdout are their own, so they take `exec:` and
   `fd:N` alone. A `pipe` with a `node:` side and `--exit` on one carrier
   is refused (64), as one node is at the other end of a stream.

## A node's upgrade in place

A node's sessions lived in its process, so a node that started again to
take a new binary ended each of them, and its sshd's connections with them.
A node of the pair's road now hands them to the binary that takes its place
(T-668, drafted 2026-11-05; `crates/podssh-cli/src/node_upgrade/`,
`crates/podssh-relay/src/session/handover/`,
`crates/podssh-relay/src/e2e/hold/`):

1. SIGUSR2 asks. `podssh update` sends it, once it replaced the binary, to
   each node of `--detach` of the user that takes it (such a node writes
   `detached/NAME.upgrade`, its pid, beside its run's record), while the
   run's lock is held and the record names that pid; a unit of systemd
   takes `systemctl kill -s USR2 UNIT`. A node of another road ignores the
   signal, which no longer ends it.
2. The binary at the node's path runs once first, as `podssh --version`
   with `PODSSH_HANDOVER=probe`, 10 s at most, and must add the line
   `podssh-handover 1`: a build of before, a file that does not start, or
   another version of the handover leaves the node as it is, with a line.
3. The node stops its socket as a stop does, each session's `close` saying
   `the node is upgrading`, which a client of the layer takes as a loss.
   Each link of the layer stops at a record's end, as for a resume; each
   end-to-end channel stops between two messages, its keys (split from its
   handshake), its nonces and the bytes cut short each way kept; and each
   target's TCP connection leaves the runtime as a socket.
4. The node becomes the new binary by `execve`, in the same process: the
   same pid, words, environment, scope of systemd and lock of a detached
   run, so a supervisor of `--restart` or a service manager sees no end. The
   sessions' state passes in anonymous memory (`memfd_create` on Linux, a
   POSIX shared object unlinked at once on macOS, else a private file of the
   cache unlinked at once), which `PODSSH_HANDOVER=fd:N:pid:P` names to that
   process alone; each socket and that memory stay open across the exec, as
   no other descriptor does.
5. The new binary reads the sessions before it connects, keeps each as a
   session whose link was lost, for the time that it had left, and comes
   online; each client resumes on a new leg, and the sshd's connection is
   the one of before. The layer's records are not part of the handover, so
   a build that changes them still takes the sessions of the one before.
6. A session that cannot move (a UDP flow, a target in the process, a
   channel that does not stop within 10 s) is kept as an ended one: its
   client's resume hears `CLOSE` with why. A session of `--plain`, which has
   no layer, ends at the stop. A binary that does not start after its probe
   gives the sessions back, and this one serves on.

Windows has no such signal, and a process that started the new binary
beside it would change the node's pid, which a supervisor takes for its
end: a node there takes a new binary at its next start, its sessions ending
as before. Measured on 2026-11-05 (`cargo test -p podssh-relay --test
session_handover`, 3 passed; `cargo test -p podssh-cli --test node_moves`, 3
passed), on Linux.

## The dialect of the road

The reverse road states a version in two places, and neither end compared
it: the role's `hello` says `"version": 1`, and the operator of the
end-to-end channel offers the net's document in its first message. A node
and a relay of two dialects got as far as a frame that one of them did not
read, which it dropped, and the node connected again for ever; an operator
whose offer a node answered plainly went on with no word (T-643, GitHub
#141; `crates/podssh-relay/src/reverse/control.rs`,
`crates/podssh-relay/src/serve/reverse/proto.rs`):

1. The dialect is a number, 1 today. A `hello` with no `version`, or null,
   is 1, the dialect of the contract, as is an upgrade with no
   `X-Podssh-Proto`: each relay and each podssh of before speaks it. Zero
   is no absence, and a value that is no whole number is no dialect. This
   is the fourth kind of a member that an answer leaves out, beside the
   hint, the offer and the guarantee (`podssh_relay::answer::dialect`).
2. podssh reads the dialects from `PROTO_MIN` to `PROTO`, both 1: so the
   check refuses nothing until the dialect changes, and the change that
   raises `PROTO` decides how long the one before is read.
3. The node states its dialect on each upgrade of `/v1/node/<name>` and
   `/v1/connect/<name>`, in `X-Podssh-Proto`; a forward session states none.
   It compares the `version` of the relay's `hello`: one that it does not
   read closes its socket at once, before any session, and ends the node
   with exit 78 and one sentence that names the relay's dialect, the range
   that the node reads and the side to update, never a new socket, as each
   would meet the same. A `426` to its upgrade ends it so too, with the
   relay's words.
4. podssh's relay role reads the dialect that a node's or an operator's
   upgrade states, once the pair's token passed (a wrong one gets the `403`
   of each failed authentication, which says nothing of a dialect), and
   before the name's `409`, a halt, and a token of `--once` or of one leg
   is spent. One that it does not read gets `426` with one sentence that
   names both and the side to update, and its own dialect in
   `X-Podssh-Proto`. An operator takes that `426` as final: 78 for its
   first leg, and a session of the layer ends at its next one.
5. The channel: an operator that offered the net's document and got a plain
   proof goes on, as T-429 lets a node outside the net, or of before, in by
   its own door; it says so once, `podssh ssh -v` among its verbose lines
   (the node holds none, or its podssh is older), on the pair's road; the
   roads that `podssh ssh` races, and `podssh operator`, which has no
   verbose lines, say nothing of it (T-643's Decision 7). The issue asked
   for a refusal; the call is the operator's to confirm (Q86, T-643's
   Decision).

Measured on 2026-11-05, each passed (T-643's Prove): `cargo
test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code
--test reverse_node --test reverse_dialect --test relay_serve_dialect`, and
`cargo test -p podssh-relay --test e2e_net`.
