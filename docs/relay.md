# The relay

podssh talks to a WebSocket-to-TCP relay. The relay's own document is the
contract. This page gives the parts that podssh uses, and how podssh selects
relay hosts. [carriers.md](carriers.md) studies the carriers that need no such relay.

- The live contract: <https://tcp.ssh.relay.ajam.dev/llms-full.txt>
- The pinned copy that the tests use:
  [`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`](../crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt)
- The version checked: `2026-10-03-r2` (`/health`, 2026-10-08). The live
  document was the same, byte for byte, as the pinned copy (SHA-256
  `88eb1b0b...a5a8`).

The relay publishes a version, and the version changes. When `/health`
gives a different version, the live document is correct. Read it again, then
update the pinned copy and this page in the same commit.

```sh
curl -sS https://tcp.ssh.relay.ajam.dev/health
curl -sS https://tcp.ssh.relay.ajam.dev/llms-full.txt | sha256sum
```

With the binary alone, `podssh relay spec` reads both, and checks the
document against the facts that podssh was built with
(`crates/podssh-probe/facts/relay-facts.toml`): `ok`, or a `FAIL` line for
each fact that the relay changed, and exit 1. `--document FILE` checks a
copy instead. `scripts/check-relay-spec.py` checks the same facts, and CI
asks both for one verdict (`scripts/relay-spec-agree.py`).

Each fact names its line of the document as a hint, and the heading that it
stands under (T-338). A fact is read at its line first, then on each line of
its section: a line that the relay inserts above a fact moves the fact
within its section, and it holds, with a `note` line that names the old line
and the new one, for the hint to be moved by hand; a fact that left its
section, or changed, fails. The checks exit 0 when each fact holds, 1 when
one changed, and 2 (69 for `podssh relay spec`) when the relay could not be
read; CI tries a relay that cannot be read twice more, 60 s apart, and a
changed fact fails at once.

`.github/workflows/relay-watch.yml` runs the check each day, and by hand,
with no push: a fact that changed opens one issue, titled with the pin and
the facts that failed; a document that could not be read in three runs in a
row, one. The same run reads the expiry of the relay's domain from its RDAP
record (`scripts/check-domain.py`: the registry's server by IANA's
bootstrap, then rdap.org): exit 1, and an issue, when it is less than 90
days ahead; 2, never a pass, when no record was read. A run by hand takes
`dry_run`, which opens no issue, and `plant` (`moved-section`, `unreadable`)
to prove each path.

## podssh's own relay (T-169)

Since the operator's ruling Q63 (2026-11-02, [mesh.md](mesh.md)) the relay
is also a role of podssh itself: `podssh relay serve` serves the forward road
of this contract, so that a user who runs it on a host of their own needs no
other party, and each client of podssh reaches it unchanged.

```sh
podssh relay serve --listen 0.0.0.0:443 --cert fullchain.pem --key key.pem --mint anyone
podssh relay serve --listen 0.0.0.0:443 --acme relay.example.org --mint anyone
podssh ssh --relay-host relay.example.org user@target
```

It serves `/health` (the service `tcp-ssh-relay`, the version `podssh
VERSION`), `/v1/mint`, `/connect/<host>/<port>` with `?dial=lazy`,
`?precheck` and `?family`, `/relays.json`, `/trace` and `/llms-full.txt`
(the pinned copy). Its limits are the ones below. A target is dialed only
once each address of its name is public, and port 25 is refused; a `403`
names the target and "not in the ALLOW list", as the client reads a policy
refusal. Each write waits for the reader on the other side, so no queue of a
session grows without a bound (T-336 asks the same of the default relay).
The key is a P-256 key in PEM, signed in pure Rust as podssh's other TLS is;
a token is the contract's form under a secret of the run, so a restart ends
each token. The certificate is read again on SIGHUP, and when its files
change, so that a renewal needs no restart (T-447): the next handshakes take
the new pair, each session that is open goes on, and a pair that does not
load, or whose key is not its leaf's, is said while the old one stays.
`--acme NAME` takes a certificate for NAME from Let's Encrypt (or the CA of
`--acme-directory URL`) by TLS-ALPN-01 on the role's own listener, keeps it
in the cache and renews it in the role 30 days before its end; the client
of ACME is the binary's, on aws-lc-rs, and the role's TLS stays podssh-ws's.
Its reverse road (T-427) is in "The relay role's reverse road", below, and
the role behind a quick tunnel, with no listener, at the end.

## How podssh selects relay hosts

The code is in `crates/podssh-relay/`.

1. If `--relay-host`, `PODSSH_RELAY` or the `RelayHost` of podssh's
   settings file (T-048) is given, in that order of precedence, podssh tries
   those hosts in that order: `HOST[:PORT][,HOST[:PORT]...]`, separated by
   commas only.
2. Else, podssh tries the default host `tcp.ssh.relay.ajam.dev`, then up to
   three hosts of its pool. The pool is the `pool[].host` list of
   `/relays.json`, cached on disk. Six measured hosts seed it until a cached
   pool exists. podssh reads the pool again in the background after a token
   mint, when the cache is older than 7 days.
3. For each host, podssh gets a token, then opens the WebSocket. Each step
   has a limit of 20 s, and the whole attempt has a limit of 45 s.
4. The hosts overlap, as `--relay-failover MODE`, `PODSSH_RELAY_FAILOVER` or
   the settings file's `RelayFailover` says (the flag wins, then the
   variable; T-220). `staggered`, the default: the next host
   starts when the attempt before it has not opened within 2 s, or at once
   when it failed; the first attempt that opens is kept, and of two that
   opened together, the earlier in the list. `parallel`: each host starts at
   once; an attempt that opens waits at most 2 s for each host before it
   that still runs, and then the earliest that opened is kept. `serial`:
   one host at a time, as before T-220, with a limit of 5 s for each step of
   a host that has a successor. A session that opened and is not kept gets
   a Close at once, so the relay frees its target's socket; the target saw
   one short connection, as the relay dials it before the upgrade. One token
   is minted at a time for each deployment: an attempt waits at most 2 s for
   a mint that another has in flight, and then reads the token that it
   cached, or mints at its own host when the first is the silent one.
5. An error that another host can repair (a host that is down, a time-out, a
   proxy 5xx, a relay 503) goes to the next host. Such a host, and one that
   said nothing while a host after it opened, is tried last for 10 minutes,
   in each run (T-059): the record is `relay-failures.json` in the cache,
   with when each host failed and why in a few words, and a host that opens
   leaves it. It holds for a list that the user named too, as its order is
   a preference: a note says "trying HOST last: it failed N s ago (WHY)",
   and no host is left out. A record from the future, of a clock that
   moved, is ignored; a 502, which is the target's, records nothing. An error that each host
   gives (a policy refusal, a target that does not resolve, a bad token in
   the environment, a proxy that wants credentials) stops each attempt at
   once.
6. `ConnectionAttempts` repeats the whole list, with a backoff of 1 s that
   doubles up to 30 s, scaled by a random factor from 0.5 to 1.5.
7. When no host opened a session, and the user named no relay (step 1) and
   no `-4` or `-6`, `podssh ssh` tries the direct road once (T-363): the
   dial of `--direct`, through `HTTPS_PROXY` when one is set, and the
   server's version line within 10 s. One line says so before the dial;
   when both roads fail, a line names both with their times, and the exit is
   the relay's. A list that the user named is the relay alone, and
   `PODSSH_DIRECT=no` or the settings file's `Direct no` turns the fallback
   off ([cli.md](cli.md), "Options of `podssh ssh`").

A token is cached for its relay deployment, with the host that minted it.
The hosts of the default deployment share one token: a pool host accepts the
token of the default host (measured 2026-10-08). Any other host has its own
token, under its name and its port when that is not 443. So podssh never
sends a cached token to a deployment that did not mint it (T-057). A cache
entry that does not name the host that minted it (written before
2026-10-08) is not used.

The cache is the first directory that takes a file (T-243): the one of
`PODSSH_CACHE_DIR`, the user's cache directory, the user's runtime
directory, the temporary directory (`TMPDIR`, `TMP` or `TEMP`; on Unix the
fixed `/tmp` and `/dev/shm` only when none is set), then `.podssh` in the
working directory. Each place comes from the environment, and a directory
that refuses a write is skipped. A named directory that is skipped, or a
relative `PODSSH_CACHE_DIR`, is said once on stderr, with the reason.
`PODSSH_CACHE_DIR=none` keeps no file: a token is minted on each run, and
`podssh doctor` says so. `podssh status` shows the directories in order.

## The forward path: what `podssh proxy` and `podssh ssh` use

```
wss://tcp.ssh.relay.ajam.dev/connect/<host>/<port>
X-Relay-Token: <forward token>
```

- After `101 Switching Protocols`, **binary frames carry the raw TCP
  stream** in both directions. There is no session-id prefix, no control
  message and no subprotocol. Frame boundaries mean nothing; the receiver
  joins the bytes into a stream.
- The relay connects to the target **before** the upgrade (time-out 10 s).
  Thus a target that cannot be reached gives a plain HTTP `502`, not a
  WebSocket close.
- The relay sends a **zero-length binary frame every 25 s** as a keepalive.
  A client must ignore an empty frame; it is not the end of the stream.
- A WebSocket Close stops the delivery from the client to the target. There
  is no TCP half-close. But the target's bytes still come after the client's
  Close, until the target closes, or until it is idle for 15 s; then the
  relay's Close is `1000 client half-closed, target idle for 15s`. Measured
  2026-10-09 (`python scripts/capture-close.py --client-close`): GitHub's
  answer, 800 bytes, came 0.4 s after the Close, and the relay's Close
  15.4 s after it.
- The maximum frame is 262144 bytes (`/relays.json`,
  `limits.max_frame_bytes`). podssh takes in frames up to that cap, or up to
  a larger `max_frame_bytes` that its cached `/relays.json` gives, never over
  16 MiB; its byte and time budgets go under a smaller `max_session_bytes` or
  `max_session_ms` (T-342). `scripts/check-relay-limits.py` compares the live
  limits with `crates/podssh-probe/facts/relay-limits.toml` on each push and
  each day. podssh sends at most 32 KiB in a frame
  (`FORWARD_SEND_PAYLOAD`, T-323): workerd issue 7074 reports that one write
  of more than 65,536 bytes to a socket of a Worker's `connect()` resolves,
  and that the socket then fails. A question for the relay's operator:
  whether the relay writes each frame in one `write()`, and whether its
  runtime has that limit.
- The relay answers WebSocket pings with pongs (measured 2026-10-08).
  podssh pings every 10 s and declares the link dead after three checks with
  no frame at all.

### IPv6 targets

podssh writes an IPv6 address bare in the path: `/connect/2001:db8::1/22`.
RFC 3986 allows `:` in a path segment, and does not allow a raw `[` or `]`
there.

Measured 2026-10-08 (T-007), with a TLS handshake through each session:

- The relay takes the bare address, and also `%5B` and `%5D`, raw brackets,
  and `%3A` for each colon. `/trace` reports `dialed_literal: true` and
  `address_family: 6` for such a target.
- But no byte reached an IPv6 host. On the VPC road, the upgrade succeeds,
  and the session closes at once with `1011 target closed before sending
  anything`. On the direct road (`?path=direct`), the upgrade fails with
  `502`. `?family=6` with a host name gives the same results. IPv4 to the
  same hosts worked.
- podssh then adds a note that names the likely cause: the relay has no
  IPv6 route out. The repair is the relay's (T-253).

### Tokens

- A token is minted with no account: `POST https://tcp.ssh.relay.ajam.dev/v1/mint`
  with the body `{}` gives `{token, expires, scope}`. `expires` is in
  milliseconds since the epoch.
- The form is `ephm1.<expiry-ms>.forward.<mac>`. A token is valid for 72 h or
  less. The relay checks it once for each WebSocket upgrade.
- podssh sends the token in the `X-Relay-Token` header. The `?token=` and
  `/t/<token>/...` forms are for clients that cannot set headers. podssh
  does not use them, because URLs go into logs.
- `403 missing or wrong token`: mint a new token. A `403` that names the
  target (`not in the ALLOW list`) is a policy refusal; a new token does not
  help. `429`: wait (`Retry-After`). `503`: the relay does not issue tokens
  or check them; do not retry.

### Limits that users see

| Limit | Value |
| --- | --- |
| Idle cut | 180 000 ms with no **payload**; the relay's keepalives do not reset it |
| Session length | 720 min (12 h) |
| Session volume | 64 MiB, both directions together |
| Attempts with no token | 120 per minute per address (mint, pair, upgrades with no token) |
| Targets | Public TCP only. The relay refuses RFC 1918, CGNAT, link-local, unique-local, multicast and documentation ranges, internal suffixes, and names that resolve to private addresses. It refuses Cloudflare ranges on the direct road, and port 25 (the contract says "on the direct road"; `/relays.json` says "on every road", 2026-10-08). |

Because of the idle cut, an idle SSH session must send traffic at least
every 180 s: `ServerAliveInterval=60` with `podssh proxy`, and the client's
keepalives (on by default) with `podssh ssh`. To a node, the resumable
layer sends a record each way when a side sent nothing for 10 s, which is
payload to the relay, and a link that carries nothing for 30 s is replaced
(T-154); `podssh ssh node://` then sends no SSH keepalive unless
`ServerAliveInterval` is set. The cost is about 34 bytes each way each
10 s, under 0.2 MiB of the session's 64 MiB in 12 h.

Because of the session length and volume, `podssh cp` and `podssh mv` count
the payload bytes of each relay session both ways, and its age. Before 60
MiB or 11 h 30 min they open a new session and go on at the offset of the
copy (T-137; the constants are in `crates/podssh-relay/src/relay.rs`). The
4 MiB under the cap leave room for what the relay holds queued (up to 2 MiB)
and the framing of SSH. `PODSSH_SESSION_BUDGET` lowers the byte budget for a
relay with smaller caps; it never raises it.

To a node, the resumable layer moves the session before these limits
(T-155): at 48 MiB of a link, both ways, or at 11 h, the client opens a new
link through the usual roads and relay hosts, and the node greets on it
while the old link carries the session. Then the old link stops at a record
boundary and says `RETIRE`, and the new one resumes from the offsets of its
own handshake. A move that fails is no fault: at the cap the relay closes
the link with `1009`, and the layer resumes the session. `-v` prints one
line for each move. A pair lives 72 h at most, and the relay renews none:
`podssh ssh node://` and `podssh operator` warn an hour before it expires,
and at the expiry the relay ends each session of the pair (`1001 pair
expired`), which the layer does not resume. The node says the expiry 24 h,
6 h and 1 h before it, with the command that makes the next pair;
`podssh relay pair NAME` makes it in the last 24 h of the old one, and the
node takes it at the expiry with no new start (T-395).

### Connect options (query string)

`?family=4|6`, `?path=vpc|direct`, `?dial=lazy` (connect on the first byte
of the client), `?precheck=<ms>` (wait for the first bytes of the target
before the upgrade; `0` skips the wait, for protocols where the client
speaks first).

Measured 2026-10-01: the relay limits `?precheck` to about 400 ms (the wait
was the same for each value from 400 ms to one hour, on each target). The
wait ends early when the target speaks first. The relay reads a value that
is not a number as `0`, with no message.

### Errors and close codes

- An error body is plain text that starts with the path. A valid token on a
  WebSocket endpoint with no upgrade gets `426`. Each failed reverse
  authentication gets `403 reverse: forbidden` (measured 2026-10-01).
- `/trace` alone is public. `/trace?target=...&banner=1` and `?egress=1`
  need a forward token (`403 trace: missing or wrong token` without one).
- **The contract does not give the close codes of the forward path.** Its
  published table is for the reverse path only. These are the codes that the
  relay sends in its Close frames (version 2026-10-03-r2, read from its
  source):

  | Code | Reasons |
  | --- | --- |
  | `1000` | `target closed`; `client half-closed, target idle for 15s`; `client closed before the target was dialed` |
  | `1001` | `idle timeout` (180 s with no payload); `session time cap` (12 h) |
  | `1009` | `session byte cap` (64 MiB, **both directions together**); `frame larger than 262144 bytes` |
  | `1011` | `connect failed: ...`; `target closed before sending anything`; `wrong target banner ...`; `client send failed: ...`; `write failed: ...`; `client error` |
  | `1013` | `client receive backlog`; `target write backlog` (2 MiB queued) |

  Only `1000` is a normal end. For each other code, `podssh ssh` and
  `podssh proxy` name the part that broke (the relay's link to the target,
  the link between podssh and the relay, or a limit of the relay), keep the
  code and the reason as the relay wrote them, and say what may help in a
  second line (T-024): `podssh: 127.0.0.1:2201: the relay lost its
  connection to 127.0.0.1:2201 (relay close 1011: write failed: ...)`. A
  connection that ends with no Close is the link between podssh and the
  relay. podssh reports a code that is not in this table as it is, with
  control characters removed from the reason.
- By the relay's source, backpressure closes the session (`1013`, at 2 MiB
  queued), and the relay drops no frame; the check reads `bufferedAmount`,
  which Workers may not supply. Measured on 2026-10-31 (T-062), the check
  does not operate: through the relay's own loop, a client that read
  16 KiB/s for 90 s got no Close, from a cloud container and from GitHub's
  network, while 47 MiB more than it read had left the far end; the relay or
  its edge held them (`crates/podssh-relay/tests/live_backpressure.rs`,
  `.github/workflows/relay-live.yml`). podssh advertises an SSH window of
  512 KiB, so a server cannot have more than that in flight to a slow
  podssh, and the relay holds no more for an SSH session; a raw stream
  (`podssh proxy`, `-W`) has no bound short of the session byte cap. When a
  `1013` comes, podssh names it, says what makes it, and does not try again
  (the stand-in relay's mode `backlog`, `crates/podssh-cli/tests/faults.rs`).
- The upgrade is HTTP/1.1 only. podssh never offers h2 through ALPN.

### Relay facts for a client that selects a relay

Measured 2026-10-01:

- `/relays.json` ranks relays by the Cloudflare edge that answered, which
  changes between identical calls. Its `score_ms` is a fixed estimate, and
  it did not agree with the measured latency.
- An unknown `?relay=` gets a `200` and is ignored, so the client must
  validate a relay name.
- `/connect/` ignores ranking parameters: the host name dialled decides. The
  `X-Relay-Name` header of the `101` names the relay that served the
  session.

### Open questions

- Why does the relay's side drop a socket of the reverse road with no
  WebSocket Close? Measured on 2026-10-09 (T-061, T-255): from this machine
  and from a GitHub Actions runner, in bursts (about 9 an hour of a session
  from 00:27 to 01:28 UTC, then one in 4.6 hours of sessions until 02:05);
  one socket at a time while the relay lives on (it tells the other end),
  or both sockets of one pair at once. Forward sessions had none in 1.2
  hours. The relay's operator can tell why (T-255 waits for them).
- The short index `/llms.txt` (r2) has facts that the full document does
  not: `/v1/pair` can return `409` (retry with a new pair), and a change of
  the mint secret makes each token invalid at once.

## The reverse path: a host whose only egress is the relay

podssh implements this path in `podssh-relay`, behind the feature `pair`:
the pairs (T-078), the node (T-079) and the operator (T-080); the commands
are `podssh relay`, `podssh node`, `podssh operator` and
`podssh ssh node://NAME` (T-083, T-084). The rules are in
[reverse.md](reverse.md).

- `POST /v1/pair` (body `{}`) gives `{name, node_token, connect_token,
  stop_token, expires}` (72 h or less). Measured 2026-10-09: each token is
  64 characters of `[0-9a-z]`, the name 34 characters of `[-0-9a-z]`, and
  `expires` is in milliseconds, 72 h ahead.
- `GET /v1/status/<name>` accepts `connect_token` only, and answers
  `{"online": false, "sessions": 0}`; `node_token`, `stop_token` and no
  token get `403 reverse: forbidden` (measured 2026-10-09).
- The **node** keeps a WebSocket open to `/v1/node/<name>` with
  `node_token`. It receives JSON **text** frames `hello`, `open {id}` and
  `close {id}`, and answers `ready {id}` or `reject {id, reason}`, also in
  text frames. Measured 2026-10-09 (`python scripts/capture-reverse.py`):
  `hello` comes first, with `maxSessions` 64 and `maxFrameBytes` 65536; the
  operator's `ready` carries the session's id; the relay answers a Ping on
  the node's socket and on the operator's. Each **binary** frame of the node
  is the 32 lowercase hex characters of the session id, then up to 64 KiB of
  payload (65568 bytes on the wire at most). Control frames are limited to
  4 KiB.
- The **operator** connects to `/v1/connect/<name>` with `connect_token`,
  waits for the `ready` text frame, then sends and receives raw binary frames
  with **no framing**. A text frame from the operator closes the socket with
  `1003`. The relay rewrites an id that an operator sends; it never uses it.
  Only the control host serves the reverse road: measured 2026-10-09, an
  operator's `/v1/connect/<name>` on two pool hosts
  (`tcp-eu-central-1` and `tcp-ap-south-1`) got `HTTP 503: reverse:
  unavailable`, while the control host carried the session. So a resumed
  session (T-153) comes back through the control host, by each of its
  addresses (pins, the resolver, DNS over HTTPS), never through the pool.
- One node socket for each name; a second one gets `409`.
  `POST /v1/stop/<name>` stops the node and its sessions. It was seen to
  answer `{"stopped": false}` and still destroy the credentials, so treat
  local copies as revoked, whatever the answer. Measured again 2026-10-09:
  `{"stopped": false, "sessions": 0}` with no node online, then `403` for
  each token and for a second stop.
- The full table of reverse close codes (1000 to 1013, with reasons and
  actions) is in the contract, "Reverse close codes".
- No idle cut (T-061, measured 2026-10-09): a session with no payload after
  its first byte kept both sockets open for 240 s and then carried a byte
  each way, with no frame at all, with a Ping from one end every 20 s, and
  with a Ping from each end every 10 s. The relay sent no keepalive, and
  answered each Ping. But in 6 of the 12 runs, the relay's side ended a
  socket's connection with no WebSocket Close, at 24 s to 212 s, also under
  payload. The relay saw it: it sent the operator `1011 node disconnected`,
  or the node a `close` of the session (T-255).

## Diagnostics

- `/health`: the version, the edge colo, egress counters.
- `/relays.json?host=<h>&port=<p>`: the ranked pool and the limits.
- `/trace?target=<host>:<port>&banner=1`: the relay connects to the target
  and gives the first banner line. Use it to tell a relay problem from a
  target problem. `podssh relay status`, `podssh relay info [HOST PORT]` and
  `podssh relay trace HOST PORT` ask these three (T-058). Measured
  2026-10-11: a target trace answers `target` with `ok`, `road`, `dialed`,
  `address_family`, `connect_ms`, `first_byte_ms`, `bytes_seen`, `verdict`
  and `banner`, or with `error` alone for a target that the relay will not
  dial; on the VPC road, a closed port gives `ok: true` and the verdict
  `silent-or-unreachable`.

## The relay role's reverse road (T-427)

`podssh relay serve` serves the reverse path of the contract too, so that
`podssh relay pair --relay-host`, `podssh node`, `podssh operator` and
`podssh ssh node://` work through it with no other relay, as they work
through the default one:

- `POST /v1/pair` makes a pair for whom the role mints tokens (`--mint`):
  a name of 34 characters of `[-0-9a-z]`, three tokens of 64 characters of
  `[0-9a-z]`, 72 h of life, as the default relay's (measured 2026-10-09).
  A name in use gets `409`; past 4096 pairs, `429`; a body that is not `{}`
  or nothing, `400`. `--pairs FILE` keeps the pairs in FILE, of mode 0600,
  so that they outlive a restart; it holds the SHA-256 of each token, never
  a token, and the role compares a token by its digest.
- `/v1/node/<name>`, `/v1/connect/<name>`, `GET /v1/status/<name>` and
  `POST /v1/stop/<name>`, each with its own token, from `X-Relay-Token` or
  `?token=`; a wrong one gets `403 reverse: forbidden`, a second node `409`
  before the upgrade, and a socket's path with no upgrade `426`.
- The node gets `hello` (`maxSessions` 64, `maxFrameBytes` 65536), `open
  {id}` and `close {id}`; the operator gets `ready` before the session's
  first byte, and a `reject` with its whole reason before a Close whose
  reason is cut to 123 bytes. Each fault of a node's bytes closes its socket
  with its row of the close table, and each of its operators hears that
  cause; else a node that leaves gives them `1011 node disconnected`.
- What the default deployment does not do. At most 1 MiB waits for a slow
  operator: past it, the frame is dropped, the session ends with `1011
  relay backpressure`, and the node's other sessions go on (T-336). The
  role reads an operator only while the node's queue has room, so a slow
  node slows its operators and loses nothing. A frame of the node for a
  session that ended in the last 2 s was on its way, and is dropped; one for
  an id never given, or closed long before, closes the node's socket with
  `1003 unknown session id` (T-421). A planned stop (Ctrl-C, SIGTERM)
  closes each reverse socket with `1012 relay restarting` first, which a
  client tells apart from a lost link (T-255).
- The role pings each reverse socket every 20 s, and drops one that answers
  nothing for 60 s, so that a dead node's socket does not hold its name.

## Tokens for the keys of a list (T-448)

`podssh relay serve --mint keys:FILE` mints tokens, and makes pairs, for
the keys of FILE alone, a list in the format of `podssh node --allow`,
read again for each request. The contract's request, `{}`, gets `401` with
a challenge of the role's (`c1.<end-ms>.<nonce>.<mac>`, a minute of life,
under the role's secret). podssh then sends the request once more, with
the key of this client (`client.key` in the cache, the key that a node's
allowlist lets in), the challenge, and the key's Ed25519 signature of
`podssh relay key, version 1`, the `Host` that the request sends, the path
and the challenge (`crates/podssh-relay/src/keyed.rs`). The role answers
`403` for a key that is not on the list, a signature that does not verify,
a challenge that is not its own, that ended or that was answered before,
and a request whose `Host` is not the name that its TLS asked for; the
`403` names the key's fingerprint, for the owner's list. A relay of the
contract never answers `401`, so a client asks nothing more of it.

## The relay role behind a quick tunnel (T-428)

Where nothing may listen, the node of a quick tunnel serves the role:

```sh
podssh node relay --quick-tunnel --relay --allow owners.txt
podssh ssh --relay-host https://NAME.trycloudflare.com user@target
```

The node dials Cloudflare's edge as for any quick tunnel, and gives each
request of a path of the relay (`/health`, `/v1/mint`, `/connect/HOST/PORT`,
`/relays.json`, `/trace`, `/llms-full.txt`, and each path under `/v1/`) to
the role in place of its 404, on a pipe in the process: the request as
cloudflared's proxy sends one to an origin of HTTP/1.1 (the visitor's
headers but those of one hop, and for a WebSocket the upgrade's three, as
cloudflared sets them), and the role's answer back as cloudflared's writer
sends an origin's, over HTTP/2 (a 101 as 200, the headers serialized) and
over QUIC (a 101 as it is, each header in the metadata). A WebSocket's
frames pass the edge unchanged, so after the upgrade each byte goes as it
came, both ways. With a TARGET too, a visitor's WebSocket at another path
still reaches TARGET; with none, each path is the role's.

The tunnel's name, the one line on stdout, is the relay host. The role
mints, and makes pairs, for the keys of the node's `--allow` by default,
and a key's signed request must name the tunnel as its `Host`, as behind a
listener it must name its TLS's name: the edge took the visitor's TLS for
that name. `--mint`, `--pairs` and `--allow-private` are those of `podssh
relay serve`. The name is new at each run, and a pair names its relay
host, so a pair of the role's serves its node's run; `--pairs FILE` keeps
the pairs all the same, as `relay serve`'s does. A planned stop closes each
socket of the reverse road with `1012` first. The role dials its targets
from the node's host directly, as on a listener.
