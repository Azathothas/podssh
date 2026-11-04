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
refusal. Between that and `--allow-private`, which dials each address,
`--routes RANGES` lists private ranges (`ADDR/BITS` or one address,
separated by commas, as an exit's `--routes`; T-635): a target is dialed
when each address of its name is public or inside one of them, and another
gets the refusal of a role with no range, in the same words, so a client
reads nothing new; the role's line on stdout adds "nor in a range of
--routes". Port 25 stays refused inside a range. A prefix that sets bits
past it (`10.0.0.5/8`) is refused at the start with the network that it
names, by the role and by an exit, and `--routes` beside `--allow-private`
is refused (64). The first line names the ranges. The list is one for each
token that the role mints, with no ports and no names: a name is admitted
by its addresses, as they resolve on the role's host at each dial. A name that does not resolve, that resolves to an address that is
not public, or that has no address of the family asked for gets one
sentence, `HOST:PORT not in the ALLOW list: this relay dials no address of
it`, which names no address, so that a holder of a token cannot map the
role's own network by names (GitHub #126); the role's line on stdout keeps
the cause. Each write waits for the reader on the other side, so no queue of a
session grows without a bound, and on Linux each socket of the role holds at
most 128 KiB unsent (`TCP_NOTSENT_LOWAT`), so a slow reader ties a few
hundred KiB of the host to its session, not the MiB of a send buffer that
the kernel grew (T-336; measured: a forward client that read 16 KiB/s left at
most 378 KB past its target, 4.9 MB before the bound).
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
Its reverse road (T-427) is in "The relay role's reverse road", below, the
role behind a quick tunnel, with no listener, after it, and its targets
through the host's `HTTPS_PROXY` in "The relay role's way out" (T-457).
An IPv6 target that its host cannot route out gets a `502` before the
upgrade, which says so ("IPv6 targets", below; T-253). Its listener takes
the cleartext road beside TLS, by the first byte of each connection, with
tokens of one session alone ("The cleartext road", below; T-326). For a
proxy that refuses the upgrade, its HTTP road carries the same sessions over
plain requests ("The relay role's HTTP road", below; T-319). A client whose
TLS chooses `h2` gets HTTP/2 with extended CONNECT, so that the sessions of
one process are streams of one connection ("The relay role's HTTP/2",
below; T-321).
Beside the contract, `/v1/layer/<host>/<port>` carries a forward session in
the resumable layer, so that the role keeps a standard sshd's connection
across a drop of the client's link ("The relay role's resumable layer",
below; T-173).

A port below 1024 needs a privilege for its bind alone: a start as root, or
the file capability `cap_net_bind_service` on the binary. On Linux the role
gives up each capability of its start once its listener is bound, before its
runtime makes a thread (T-629): `PR_SET_NO_NEW_PRIVS`, each capability of
the bounding set where `CAP_SETPCAP` allows it, and `capset` with the
effective, permitted and inheritable sets empty. Linux keeps them for each
thread, so the process's first thread, which waits while another runs the
command, does the same on itself; then each thread of `/proc/self/task` is
read again. A step that fails, or a thread that keeps a capability, stops the
start (78); a start that held none asks for no new privileges alone, and says
nothing. The uid and the gid stay: a start as root stays uid 0, which may
still write each file that root owns, and its first line says so; a user of
its own with the file capability binds the port with none of root's. A file
of another owner that the role reads again (its certificate, the file of
`--pairs`, the cache of ACME) must let it read by its mode, and a reload that
cannot read it says so and keeps the pair that it serves. Other systems have
no such sets.

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
   mint, when the cache is older than 7 days. Up to four hosts of other
   deployments follow, from a signed list alone ("A signed list of
   deployments", below; T-346).
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
   said nothing while a host after it opened, is tried last for 10 minutes, in each run (T-059);
   so is, for 5 minutes, a host whose last 2 sessions its side cut (the link lost, or the relay's close for
   its link to podssh) within 300 s of their open, as `ssh`, the commands that reach a first hop as it does,
   `proxy` and `pipe`'s relay end tell; and a host that opened in the last 10 minutes, with no failure since
   and its last session not cut, is tried first (T-563). The record is `relay-failures.json` in the cache, for
   each road apart: when each host failed and why in a few words, when it last opened and how often, and its
   sessions cut short in a row; a host that opens keeps its entry, with no failure. It holds for a list that the user
   named too, as its order is a preference: a note says "trying HOST last: it failed N s ago (WHY)", and no host is left out. A record from the future, of a clock that
   moved, is ignored; a 502, which is the target's, records nothing. An error that each host
   gives (a policy refusal, a target that does not resolve, a bad token in the environment, a proxy that wants credentials) stops each attempt at once.
6. `ConnectionAttempts` repeats the whole list, with a backoff of 1 s that
   doubles up to 30 s, scaled by a random factor from 0.5 to 1.5.
7. When no host opened a session, and the user named no relay (step 1),
   `podssh ssh` tries the direct road once (T-363): the dial of `--direct`,
   through `HTTPS_PROXY` when one is set, of the family of `-4` or `-6` when
   one is given (T-253), and the server's version line within 10 s. So it
   does, at once, when a host opened a session to an IPv6 target and closed
   it before any byte came ("IPv6 targets", below). One line says so before
   the dial; when both roads fail, a line names both with their times, and
   the exit is the relay's. A list that the user named is the relay alone,
   and `PODSSH_DIRECT=no` or the settings file's `Direct no` turns the
   fallback off ([cli.md](cli.md), "Options of `podssh ssh`").

`podssh relay rank` (T-606) measures each host of the default list's pool
from this host, on demand, one at a time: rounds of a session to
`github.com:22` each, timed from the dial to the upgrade, and kept in the
cache as `relay-rank.json` for 24 h for the egress that measured it. The
order is the share of failed probes, then the median time to open, then the
p95, a tie within 50 ms or 10 % kept in the order given. It is a measure of
this host's path, which `/relays.json`'s rank is not (see "Relay facts for a
client that selects a relay"), and podssh makes no rank unasked unless
`RelayRank auto` asks (Q89, T-608, below).

The default list takes the rank (T-607). While a rank holds for this egress,
step 2's three hosts of the pool are the best three of the rank, and a run
tries the default host at its place among them; the record of step 5 still
moves a host that failed lately to the end. Each run keeps the time to open
of each host that opened in its race (from its dial to the `101`, the token
left out), the last 8 of each host with when and the egress, in the rank's
file; where no rank holds, they order the pool. They cost no connection. A
list that the user named keeps its order. `PODSSH_RELAY_RANK=no`, or the
settings file's `RelayRank no`, gives the pool's order of `/relays.json`, as
before; a variable that is set, and not empty, wins over the file.
`podssh status` gives `relay_order` (`rank`, `samples`, `pool` or `off`),
and `podssh doctor` a line `rank` with the list in that order; so does
`podssh relay info`, after the relay's pool, and its `--json` gives
`relay_order` and `relay_list` beside `pool_order` (T-618).

A rank in a session's background (T-608) comes only when the user asks for
it, with the settings file's `RelayRank auto` or `PODSSH_RELAY_RANK=auto`;
never by default (Q89). Then a session of `podssh ssh` that the default list
carries, when no rank holds for this egress, probes the default host and the
hosts of its pool in the relay's order, 8 at most in a day, in its own
process, one at a time: the first after the session ran 60 s, then one each
10 s at most, none while a race of relay hosts runs (`open` counts the races
in progress, and a race that starts drops a probe in flight), none with
`PODSSH_OFFLINE`, and none past the session's end, which aborts the task and
drops a probe in flight. Each probe is a session to `github.com:22` with
`?dial=lazy` and three WebSocket pings that sends no byte, so the relay
dials no target, and its time to open is this host's leg alone, the relay's
dial left out, where a rank of `relay rank` keeps the dial. The rank is kept
after each probe with the source `background`, and the default list takes
it as it takes one of `relay rank`; a session that ended first leaves it
partial, and the next session of the day goes on with the hosts that it
lacks, never one twice. A rank that holds, of either source, makes no new
one: at most once a day for each egress. `podssh proxy`, `pipe`, `cp` and
the other commands make none, nor a list that the user named.
`podssh status` gives `relay_rank_auto` (`asked`, `by`, `last_ms`,
`last_age_s`, `partial`) and the rank's `source`; `podssh doctor`'s line
`rank` names the setting and when the last background rank was made. It is
an exception of rule 2 of `AGENTS.md`, bounded as Q89 rules.

A token is cached for its relay deployment, with the host that minted it.
The hosts of the default deployment share one token: a pool host accepts the
token of the default host (measured 2026-10-08). Any other host has its own
token, under its name and its port when that is not 443, a host of another
deployment of a signed list too (T-346). So podssh never
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

On Unix the user's cache and runtime directories count only in the user's
own tree (T-593, GitHub #118): each of their directories that exists, up to
`HOME` (else up to `/`), belongs to the effective uid or to root, as
OpenSSH's StrictModes walks a key's path. One in another user's tree, as
when root runs with the `HOME` of another account, is passed over:
`XDG_CACHE_HOME`, then `HOME/.cache`, then the `.cache` of the home of the
uid's entry in `/etc/passwd` (read as a file, as T-500 reads the login
name; on macOS `getpwuid_r` first). podssh makes no directory in another
user's tree but the cache's own, so a missing `.cache` there stays its
owner's to make. A key, the pins, a pair or a token that an earlier run kept
in a place passed over is still read there, after the user's own places, so
a node keeps its identity; a run says once where its key is and where to
move it, and podssh moves nothing. A new pin of pins found there goes into a
copy in the user's own cache. `podssh status` (`cache.passed`) and `podssh
doctor` name each place passed over, with why. On Windows,
`LOCALAPPDATA` is used as it is.

## A signed list of deployments (T-346)

A host of `/relays.json` outside the default's parent domain
(`ssh.relay.ajam.dev`) is dropped from the pool, as a token of the default
deployment would go to it. A host of another deployment comes from a signed
list alone, which `/relays.json` may carry beside the pool, as its field
`signed` (the code: `crates/podssh-relay/src/pool/signed.rs` and
`crates/podssh-relay/src/pool/kept.rs`):

```json
"signed": {"doc": "{\"deployments\":[{\"hosts\":[\"relay.example.org\"],\"name\":\"backup\"}],\"issued\":1793577600,\"not_after\":1801353600,\"podssh-relays\":1,\"serial\":1793577600}",
           "key": "64 hex digits of an Ed25519 key",
           "sig": "base64 of 64 bytes"}
```

- **The form.** `doc` is the document's exact text, so that no canonical
  form of JSON is needed: `podssh-relays` (the form, 1; another is
  refused), `serial` (it only grows for its key), `issued` and `not_after`
  (seconds since 1970), and `deployments`, 1 to 16, each a `name` (letters,
  digits, `-` and `_`) and 1 to 8 `hosts` as `--relay-host` takes them;
  8 KiB at most. `sig` is the key's Ed25519 signature of `podssh-relays/1`,
  a zero byte, and the text, so that a signature of the key serves no other
  use of it. OpenSSL's `pkeyutl -sign -rawin` makes one that podssh takes.
- **The keys that a binary trusts.** Those compiled in
  (`podssh_relay::pool::signed::BUILT_IN`, the keys of the default
  deployment's operator; none on 2026-11-04, [relay-operator.md](relay-operator.md),
  item 14), those of `PODSSH_RELAY_KEYS` and of the settings file's
  `RelayKeys` (each `SHA256:...`, as `ssh-keygen -l` shows an Ed25519 key,
  or its 64 hex digits), and the key of each member of the net that this
  host holds with the role `relay`, while the document holds.
  `PODSSH_RELAY_KEYS=none` trusts no key, those compiled in too.
- **The check.** A trusted key, its signature of the exact text, the form,
  a `not_after` still ahead, a life of 400 days at most from `issued`, and
  a serial not below the list kept of its key. A list that fails any of
  them is not used, and the pool keeps the default's domain alone, as
  before.
- **The cache.** A list that holds is kept as `relay-deployments.json`, the
  newest of each key (4 keys at most), with its signature, and checked again
  at each read: a key no longer trusted, a list past its end, or a cache
  file that changed stops counting at once. A list is learned from the
  `/relays.json` that the pool's refresh reads after a mint, with no request
  more, and from `podssh relay info`, which keeps the first host's list
  when it holds; and from the host of a relay member of the net (below).
- **The list of deployments.** With no list named, the default host and
  three hosts of its pool come first, then at most four hosts of the other
  deployments, the first host of each deployment first. Each such host
  mints a token of its own, which goes to no other host, and its TLS is
  checked by its own name. A list that the user named takes none; nor does
  a run with `PODSSH_RELAY_TOKEN`, as that token is the default
  deployment's. Once the default's hosts fail, the record of failures
  (T-059) tries them last, so in an outage of the default's domain the
  other deployments go first.
- **What the binary says.** `podssh relay info` names the first host's
  list: none, the key, why it is trusted, the serial, the end and each
  deployment, or why it is not used; `--json` adds `signed_list`. `podssh
  relay status`, `podssh status` (`deployments`) and `podssh doctor` (a
  line `deployments`) name each deployment of the list, and whether its
  list was signed.
- **podssh's relay role signs its own.** `podssh relay serve --deployment
  NAME=HOST[:PORT][,HOST[:PORT]...]`, repeatable, puts a list of those
  deployments in each `/relays.json`, signed by the key of `--list-key
  FILE` (`relay-list.key` in the cache, made when it is missing), for 90
  days and again each day with a higher serial; its first line names the
  key's fingerprint, which each client trusts by `PODSSH_RELAY_KEYS`,
  `RelayKeys` or the net. Nothing of a request goes into what it signs. A
  member of a net with the role `relay` that signs with the key that the
  net names for it is trusted by each member that holds the net.
- **The net's relay members (T-617).** A member of the net with the role
  `relay` and a host in the net's document (`podssh net add NAME KEY
  --roles relay --relay-host HOST[:PORT]`, the member's field `relay`) is
  asked for its list: a run that opens a session on the default list, and
  `podssh relay status`, ask that host's `/relays.json` first, at most once
  a day for each member whatever it answered (5 s each, 8 s in all), with
  no token, through the proxy of the environment, and take the list there
  only when the member's key signed it, by the check above; its
  deployments then follow the default list in that run. The host joins no
  list by it, as the role's own list names where sessions go. No run asks
  with `PODSSH_RELAY_TOKEN`, with a list that the user named, or with no
  cache; the asks are kept as `relay-members.json`
  (`crates/podssh-relay/src/pool/members.rs`).

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

Measured again 2026-11-03 (T-253, `cargo test -p podssh-relay --test live
-- --ignored ipv6 --nocapture`): the relay host took the literal, and the
session closed with the same `1011` when the first bytes went.

What podssh does about it (T-253):

- `podssh ssh` reads that `1011`, for an IPv6 target (an address, or `-6`)
  and before any byte of the target, as a relay that reached no IPv6 host:
  where the user named no relay, it tries the direct road at once, with its
  line, of IPv6 alone under `-6` (step 7 above), in place of the try of the
  relay once more. Else, and when the direct road fails too, a note names
  the roads that carry IPv6: a relay of the user's on a host with IPv6, a
  node with IPv6 egress (`-J node://NAME`), or `warp://[ADDR]`. `podssh
  proxy`, which has no direct road, gives the note.
- podssh's own relay role (`podssh relay serve`, below) dials an IPv6
  target where its host routes IPv6 out, and refuses one that its host
  cannot route before the upgrade, also with `?dial=lazy`: `502 relay:
  cannot reach [ADDR]:PORT: this relay's host has no IPv6 route out`. A
  name of both families keeps its IPv4 addresses. The client tries the next
  relay host at once on that `502`, as on each `502` that names no fault of
  the target's name. The role knows its host's routes from the table that
  Linux gives as a file (`/proc/net/ipv6_route`, read again each 30 s),
  which opens no socket; where there is none, from its own dials: one that
  met no route (`ENETUNREACH`, no address of the family) for a minute, and
  one that connected. The loopback is its own. Through the host's proxy
  (T-457) the proxy's way out decides, and the role refuses nothing for it.
  `/relays.json` says what the role knows: `"egress": {"ipv6": true, false
  or null, "known_by": WORDS}`.
- What `tcp.ssh.relay.ajam.dev` lacks here (an IPv6 route, or a `502`
  before the upgrade) is a note of [relay-operator.md](relay-operator.md),
  item 3.
- `podssh doctor`'s line `ipv6`, in its section `relay`, gives what the
  first relay host that answered says in `egress` of its `/relays.json`,
  or for the default relay, which says nothing of it, its egress when last
  measured; beside it the direct road's, by this host's own probes: the
  proxy's way out where a proxy takes the address, else an IPv6 socket and
  the same table of routes ([cli.md](cli.md), "`podssh doctor`").

### Tokens

- A token is minted with no account: `POST https://tcp.ssh.relay.ajam.dev/v1/mint`
  with the body `{}` gives `{token, expires, scope}`. `expires` is in
  milliseconds since the epoch.
- The form is `ephm1.<expiry-ms>.forward.<mac>`. A token is valid for 72 h or
  less. The relay checks it once for each WebSocket upgrade. podssh's relay
  role also mints a token of one session for `POST /v1/mint?once=1`, which
  one upgrade spends: the token of the cleartext road ("The cleartext road",
  below; T-326).
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
| Targets | Public TCP only. The relay refuses RFC 1918, CGNAT, link-local, unique-local, multicast and documentation ranges, internal suffixes, and names that resolve to private addresses. It refuses Cloudflare ranges on the direct road, and port 25 (the contract says "on the direct road"; `/relays.json` says "on every road", 2026-10-08). podssh's relay role dials the private ranges of its `--routes` too, or each address with `--allow-private` (T-635). |

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
line for each move. A pair lives 72 h at most, and the default relay renews
none: `podssh ssh node://` and `podssh operator` warn an hour before it
expires, and at the expiry the relay ends each session of the pair (`1001
pair expired`), which the layer does not resume. The node says the expiry
24 h, 6 h and 1 h before it, with the command that makes the next pair;
`podssh relay pair NAME` makes it in the last 24 h of the old one, and the
node takes it at the expiry with no new start (T-395). podssh's own relay
role renews a pair by its stop token, with its tokens (T-592, "The relay
role's reverse road", below), and a node the next pair that it goes on with too (T-620).

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
  `.github/workflows/relay-live.yml`). podssh's SSH window of a channel on
  this road is 1.5 MiB at most (T-662), shared by the channels that carry
  bulk, each 512 KiB at least, so a server cannot have more than that in
  flight to a slow podssh, and the relay holds no more for an SSH session's
  channel; a raw stream
  (`podssh proxy`, `-W`) has no bound short of the session byte cap. When a
  `1013` comes, podssh names it, says what makes it, and does not try again
  (the stand-in relay's mode `backlog`, `crates/podssh-cli/tests/faults.rs`).
  Measured again on 2026-11-03 from a cloud container: no Close in 90 s,
  and 48878136 bytes past the far end. podssh's own role holds no such
  queue ("podssh's own relay", above).
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

Measured again on 2026-11-03 by a tester (GitHub #125, which GitHub no
longer has), through one proxy: three calls, answered by the edges NRT, SIN
and ARN, and each of the 37 hosts of the pool had another rank and another
score in the first call and the third. The document's `policy.note`, as #125
quotes it, calls `score_ms` a static estimate of the round trip from the
client through the relay to the target. Whether `?prefer=`, `?region=` or
`?spread=` pins the rank to one vantage: the live document (read once on
2026-11-04, version `2026-10-03-r2`, T-619) says nothing of it. Its `policy`
echoes `prefer` (`auto`), `region_pin`, `relay_pin` and `spread`, null where
the call gave none, its note is the one that #125 quotes, and no field names
the vantage of `score_ms`. A run of podssh takes this rank only where it measured
none for its egress (T-606, T-607, above), and `podssh relay info` says
whose rank it shows (T-610, T-618). A rank that two calls can compare is
item 20 of [relay-operator.md](relay-operator.md), the note to the relay's
operator.

### Open questions

- Why does the relay's side drop a socket of the reverse road with no
  WebSocket Close? Measured on 2026-10-09 (T-061, T-255): from this machine
  and from a GitHub Actions runner, in bursts (about 9 an hour of a session
  from 00:27 to 01:28 UTC, then one in 4.6 hours of sessions until 02:05);
  one socket at a time while the relay lives on (it tells the other end),
  or both sockets of one pair at once. Forward sessions had none in 1.2
  hours. The relay's logs can tell why ([relay-operator.md](relay-operator.md),
  item 2). podssh's own relay role sends `1012` before each stop that it
  plans, so a drop with no Close through it is the path's; T-255 measures
  the default deployment again beside the role (`reverse_drops_live.rs`,
  `reverse-drops.yml` with `relay: role`), and what each drop costs
  podssh's node and a session of its layer.
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
  `podssh relay trace HOST PORT` ask these three (T-058); `podssh relay rank`
  times a session through each host from this host (T-606). Measured
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
  or nothing, `400`. A role that mints for keys keeps a share of the 4096
  for each key (T-630, "A key's share of the pairs" below). `--pairs FILE`
  keeps the pairs in FILE, of mode 0600, so that they outlive a restart; it
  holds the SHA-256 of each token, never a token, and the role compares a
  token by its digest.
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
  node slows its operators and loses nothing. The frames to a node wait in
  a line for each session, a turn each (T-648): one session may hold the
  1 MiB, another's empty line still takes a frame, and so an operator's
  keystroke waits for one frame of each other session, not for an upload's
  backlog; the text frames (`open`, `spent`) go before the sessions' bytes,
  and a session's `close` after its own. A frame of the node for a
  session that ended in the last 2 s was on its way, and is dropped; one for
  an id never given, or closed long before, closes the node's socket with
  `1003 unknown session id` (T-421). A planned stop (Ctrl-C, SIGTERM)
  closes each reverse socket with `1012 relay restarting` first, which a
  client tells apart from a lost link (T-255): after the frames that wait
  for it, the sessions' last bytes, for 1 s at most, then before them; the
  role then waits for each peer's answer to its Close, 3 s at most in all,
  so that its end is no reset that can lose the Close on the peer's side.
  A node or an operator that comes during the stop gets `503 reverse:
  relay restarting` with `Retry-After: 1`. podssh's node says that the
  relay is restarting and connects again at once, and each session of the
  layer resumes once the role is back with the pairs of `--pairs FILE`.
- The role pings each reverse socket every 20 s, and drops one that answers
  nothing for 60 s, so that a dead node's socket does not hold its name.
- Beside the contract, a renewal (T-592): `POST /v1/renew/<name>` with the
  pair's stop token, which its owner alone holds, answers `{"expires": MS}`,
  72 h from then and never earlier than the pair's end, and the pair keeps
  its three tokens, so that each operator's file keeps working; the file of
  `--pairs` keeps the new end, and the timers of the node's socket and of
  each operator's leg wait for it. Another token, and a pair that does not
  exist or ended, get the `403 reverse: forbidden` of each failed
  authentication; a method other than POST, `405`. `GET /v1/status/<name>`
  names `expires` beside `online` and `sessions`. A relay of the contract
  has no such path (the stand-in answers `404`), which a client reads as
  no renewal. There is no cap on renewals: the owner ends the pair with its
  stop token at any time.
- Beside the contract, a pair whose connect token takes one upgrade alone
  (T-226): `POST /v1/pair?once=1` (`podssh relay pair NAME --once`) answers
  the contract's fields and `"once": true`. The first operator's upgrade
  that the role takes spends the token: a second upgrade, and the status,
  get the `403 reverse: forbidden` of each failed authentication, also
  after a restart, as the file of `--pairs` keeps the use; so the pair
  carries one session, with no resume, and a token that leaks from a log
  after its use is worth nothing. The node's token and the stop token stay
  as they are. `/relays.json` offers it as `"reverse": {"pair_once": true}`.
  The query holds no credential, and the proof of a key (T-448) signs the
  path alone. A relay of the contract makes a pair of before, with no
  `once`, which `relay pair --once` stops and refuses (69). A grant used
  once (T-226, [reverse.md](reverse.md), "Grants used once") is checked at
  the node, on each road, and needs nothing of a relay.
- Beside the contract, tokens of one leg and a stop token that the node
  rotates (T-615, [reverse.md](reverse.md), "Tokens of one leg"). The
  node's `hello` adds `"legTokens": true` and `"stopRotation": true`, and
  `/relays.json` `"reverse": {"leg_tokens": true, "rotate": true}`; a
  carrier's role offers neither. The node's text frame
  `{"type":"token","digest":HEX,"expires":MS}` registers the SHA-256 of a
  token until MS, held to a day, or withdraws it with an end that passed;
  a frame that is not of this form closes the node's socket with `1003
  invalid token frame`. Such a token takes one upgrade of
  `/v1/connect/<name>`, never the status, while the node is joined with
  room for a session; with no node, `503 reverse: node unavailable` with
  `Retry-After: 1`, and nothing is taken. The node hears
  `{"type":"spent","digest":HEX}` before that session's `open`, and a
  spent token gets the `403` of each failed authentication after, also
  once the node registers it again. A pair keeps 256 live tokens and 256
  spent ones, those that end first making room, in memory alone: a node
  registers its own again at its next socket. `POST /v1/rotate/<name>` with
  the stop token and `{"digest": HEX}` answers `{"rotated": true}`: HEX is
  the SHA-256 of the next stop token, which the node drew, and the first
  request that the new token authenticates makes it the stop token and
  ends each one before it; the file of `--pairs` keeps both. Another
  token, and a pair that ended, get `403`; a body with no digest of 64 hex
  digits, `400`; a method other than POST, `405`. A relay of the contract
  answers the path as one it does not have, which the node reads as no
  rotation.

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

## Tokens for the members of the net (T-455)

`podssh relay serve --mint net` mints, and makes pairs, for the members of
the net that the host holds ([mesh.md](mesh.md), section 3), each by the
same signature of the role's challenge with the key that the net names for
it; `--mint net,keys:FILE` for those and the keys of FILE. The role reads
the document, and checks its owner's signature, for each request
(`crates/podssh-cli/src/net/mint.rs`), so that a member that a newer
document removed is refused from that serial on. A token that it minted
before lives until its end or the role's stop, as a token of a list's key
does: the contract's token names no key.

- With no policy in the document, each member mints, as each member
  reaches each. With a policy, a member mints where a rule lets it reach
  `relay:*`; behind a node's quick tunnel (`podssh node NAME --quick-tunnel
  --relay --mint net`), `relay:NAME` reaches it too, NAME the node's name
  in the net, as `exit:NAME` names a node's egress. `podssh relay serve`
  has no key of its own, so only `relay:*` and `*` name it.
- The signature is checked before whom the key is, so a refusal by the net
  goes only to the key's holder. A key that is no member gets `403` that
  names the key and the document's serial, never the net or its members; a
  member that the policy refuses gets the policy's words.
- A host with no net, with one that fails its check or that ended, or with
  `PODSSH_NET=no`, does not start (78); once the net goes bad, each request
  gets a `403` that names no file, and `podssh net ls` on the host says
  why.

## A key's share of the pairs (T-630)

A role that mints for keys (`--mint keys:FILE`, `--mint net`, or both)
lends each of them a part of its reverse road, and a pair lives 72 h: one
key that pairs in a loop must not take each of the 4096 places and leave
the others `429` for days. So the role keeps half of its table as a
reserve, in equal parts for the keys that it mints for at that moment (the
list's and the net's members, each read again for the request), one place
at least; the other half goes to whoever asks first.

- A key makes a pair within its reserve while the table has a place, and
  past it while the places left after this one still hold each other key's
  unused reserve. So a busy key among idle ones borrows past its own (with
  4 keys, 2560 of 4096), and each other key still finds its reserve (512
  each); a key alone takes the whole table.
- Past that, `429` with `Retry-After: 60` and the key's own count and
  reserve: `/v1/pair: this key holds N pairs, past its share of M while
  others wait`, which names no other key and no other count. A full table
  is still `/v1/pair: this relay keeps 4096 pairs already`. podssh's client
  says the role's words after its own (`the relay is limiting new pairs;
  try again in 60 s: ...`). The role says `/v1/pair: a key past its share
  of M pairs` on its own lines, after the line that names the key.
- A pair keeps the fingerprint of the key that made it, in memory and in
  the file of `--pairs` (`"maker"`), so that the share holds across a
  restart; a renewal keeps it, and a pair that is stopped or expires gives
  its place back to its key. A file of before has no maker: its pairs, and
  each pair of a role that mints for anyone, count against no key.
- It is a share, not a defence: a holder of several keys of the list has a
  reserve for each, and the reserve moves when the list or the net does. A
  count of the net's members includes those that its policy refuses, which
  makes each reserve smaller, never one key's larger than its part.

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
that name. `--mint`, `--pairs`, `--allow-private` and `--routes` are those
of `podssh relay serve`. The name is new at each run, and a pair names its relay
host, so a pair of the role's serves its node's run; `--pairs FILE` keeps
the pairs all the same, as `relay serve`'s does. A planned stop closes each
socket of the reverse road with `1012` first. The role dials its targets
from the node's host as on a listener: through the host's `HTTPS_PROXY`
when one is set ("The relay role's way out", below), the proxy that the
node's own dial of the edge takes too.

## The relay role's way out (T-457)

The role dials each target of its forward road, and of `/trace`, as
podssh's client reaches its relay (rule 2 of `AGENTS.md`): through the
proxy that the host's `https_proxy`, `HTTPS_PROXY`, `all_proxy` or
`ALL_PROXY` names, the first that is set, by HTTP CONNECT or SOCKS5, read
once as the role starts; the loopback, and what `no_proxy` or `NO_PROXY`
names, go directly (`crates/podssh-relay/src/serve/egress.rs`). A proxy
that cannot be read stops the start (78), and the first line names the
proxy by its host and port, never by its credentials.

- **What the proxy is asked for.** The role's policy checks each address of
  a name as it resolves on the role's host, before any CONNECT, and the
  proxy is then asked for each checked address in turn, never for the
  name: a proxy whose resolver answers otherwise (its own DNS, a split
  horizon, a name that rebinds) reaches nothing that the policy did not
  check, as the exit of T-431 dials its addresses. With `--allow-private`,
  which checks no address, and no `?family`, the name goes to the proxy as
  it came, for the proxy to resolve, so a host with no DNS (the target
  environment's, [target-environment.md](target-environment.md)) reaches
  each target that its proxy reaches; a name that the role cannot resolve
  is else its `502`. The ranges of `--routes` (T-635) keep each check: a
  name is resolved on the role's host, and the proxy is asked for each
  address that is public or inside a range.
- **A refusal.** The proxy's refusal is the role's `502`, `relay: cannot
  reach HOST:PORT: the proxy of the relay's host refused CONNECT ADDR:PORT:
  403 Forbidden`, which a client reads as an answer about the target (Q69).
  The client's words never say where the host's proxy is; the role's line
  (`proxy: the proxy HOST:PORT refused ...`, on stdout for `relay serve`,
  on stderr for a node) does, never its credentials. The proxy's own answer
  is the last word: a CONNECT that it allows is the role's session.
- **`/trace`** gives `"road": "proxy"` and `"proxy": "http"` (or `socks5`)
  for a target reached through the proxy, the address asked of it in
  `dialed` (or the name, with no `address_family`), and the proxy's
  refusal in `error`.

## The relay role's brake (T-454)

`podssh relay serve` counts the requests to `/v1/mint` and to `/v1/pair` of
each address over a sliding minute, with each connection to its mailbox
(T-086, below), the paths together, as the default
relay counts its attempts with no token ("Limits that users see"): the
121st within a minute gets `429` with `Retry-After`, the seconds until the
oldest of the 120 is a minute old, which podssh's client says ("retry in N
s"). Only the requests let through count, so a client that asks again too
soon is told the same end. A keyed mint (T-448) is two requests, its `401`
and the signed one.

- The address is the TCP peer that the listener accepted, never a header,
  which a client could change at each request to count apart. An IPv6
  address counts by its first 64 bits, an IPv4 address in IPv6's form as
  the IPv4 one. Behind the quick tunnel (T-428), the peer is Cloudflare's
  edge, so the node is to give the role the visitor that the edge names in
  `CF-Connecting-IP` ("the client IP address connecting to Cloudflare",
  Cloudflare's page of HTTP headers, read 2026-11-02), which `edge_visitor`
  of `crates/podssh-relay/src/serve/brake.rs` reads as one address, and
  `serve_from` takes. A request whose address the caller does not give
  shares one count with each other such request.
- The counts take 4096 addresses at most, each with the times of up to 120
  requests: an address whose minute is over is forgotten first, then the
  one heard from least lately.
- `/health`, `/relays.json`, `/trace`, `/llms-full.txt` and the sockets of
  both roads are not counted: a socket needs a token or a pair that the
  brake let through, and the role checks it with a MAC or a digest alone.
- The first refusal of an address is a line on stdout,
  `/v1/mint: braked, an address past 120 requests in a minute`, which does
  not name the address; the next ones until it is let through again say
  nothing.

## The relay role's mailbox (T-086)

`podssh relay serve` is a meeting point of the pairing by a short code
([reverse.md](reverse.md), "Pairing by a short code") at `/v1/mailbox`: a
WebSocket of magic-wormhole's mailbox protocol, version 1
(magic-wormhole/magic-wormhole-protocols:server-protocol.md), so that a
user's own relay serves the two ends of `podssh relay pair --code` and
`podssh relay join` (`--pair-mailbox wss://HOST/v1/mailbox`) with no third
party, and a client of magic-wormhole's Python library with podssh's AppID
meets them there (`crates/podssh-relay/src/serve/mailbox/`). So do the two
ends of the net's invitation, `podssh net invite NAME` and `podssh net
join` (T-616), whose exchange has the same AppID and another name in its
sealed version phase; its document goes in parts within the bound of a
body below.

- It serves podssh's AppID alone (`github.com/Azathothas/podssh/pair`):
  a `bind` of another is an `error`, so the role is no public mailbox of
  other applications.
- Each command is answered as magic-wormhole-mailbox-server's
  `server_websocket.py` answers it: an `ack`, then `welcome`, `nameplates`,
  `allocated`, `claimed`, `released`, `closed`, `pong`, each `message` of
  the open mailbox to each side, or `error` with the command in `orig`
  (`crowded`, `reclaimed`, `must bind first`, and the rest of that file's
  words). `allocate` gives the smallest free nameplate from 1 to 999, and
  claims it; a mailbox's id is 16 random bytes in hex, so that none is
  opened past its nameplate.
- Two sides of a nameplate and of a mailbox at most: a third gets
  `crowded`, which is the mailbox's part of a code's single use. A side that
  released a nameplate cannot claim it again. A nameplate goes once each
  side released it, a mailbox, with its messages, once each side closed it.
- Its bounds: 4096 nameplates and 4096 mailboxes held at once, 32 messages
  of a mailbox, a body of 16384 hex digits, a phase of 32 bytes, and 20
  minutes of life for each nameplate, mailbox and connection, as a code
  lives 10; a client that says nothing for 5 minutes is ended, and the role
  pings each one each 30 s. One table for each role, in memory: a restart
  of the role spends each code in flight.
- Each connection counts in the brake as a request of `/v1/pair` does
  ("The relay role's brake", above), as each is an attempt.
- It learns no code: the ends run SPAKE2 over it and seal each later
  message. It sees the nameplate, the sides, the sizes and the times.

## The relay role's probes (T-325)

`podssh relay serve`, and the role behind a node's quick tunnel, serve two
endpoints with which `podssh doctor --stream` measures what a path does to
a stream ([cli.md](cli.md), `podssh doctor`): go-httpbin's `/drip` and
`/anything`, with their queries, under `/v1/probe`, so that doctor asks
go-httpbin (`-prefix /v1/probe`) and the role alike
(`crates/podssh-relay/src/serve/probe.rs`). They need no token, dial
nothing and keep nothing of a body; at most 16 run together, and the next
gets `503` with `Retry-After`. The brake does not count them.

- `GET /v1/probe/drip?duration=S&numbytes=N` (`delay=S` and `code=C` too,
  each as go-httpbin reads it: seconds, or Go's `2s` and `500ms`, with its
  defaults, 2 s of delay among them, so `podssh doctor` asks `delay=0`): after
  the delay, the head with `Content-Length: N`, then N bytes of `*`, the
  first at once and each next one a pause later, the pause the duration over
  the gaps rounded up, as go-httpbin's, so the last goes at the duration;
  each byte is flushed at its own moment, from the start. 600 s and 64 KiB
  at most; a value that does not read is `400`.
- `POST /v1/probe/anything` (or PUT): a body of its `Content-Length`, 8 MiB
  at most, read as it comes and dropped, answered with
  `{"bytes": N, "parts": [{"from_ms", "to_ms", "bytes"}, ...]}`: the reads
  less than 50 ms apart are one part, 64 parts at most, each time from the
  end of the head. A larger body gets `413` before it is read, and one with
  no length or with `Transfer-Encoding`, `411`; the rest of a refused body
  is read and dropped for 5 s, so that the refusal is not lost to a reset.
  A body that waits 60 s for its next bytes gets `408`.
- `/relays.json` names their limits beside the contract's, in
  `limits.probe`: `paths`, `drip_max_ms`, `drip_max_bytes`,
  `body_max_bytes`, `body` (`streamed`), `quiet_max_ms` and `at_once`.
  Behind a quick tunnel's node, which takes a request's body whole, 32 KiB
  at most, before the role reads it, and ends an answer whose bytes stop for
  60 s (`crates/podssh-relay/src/quick/origin.rs`), the role's document
  says so: `behind` (`the node of a quick tunnel`), `body` `whole`,
  `body_max_bytes` 32768 and `quiet_max_ms` 60000, so that a client names
  them as the node's, not the path's.

A relay of the contract alone serves neither, and the default relay
answers no probe; there `doctor --full` measures the quiet limit alone, on
a socket of the reverse road, which that relay ends for no idleness
([relay-operator.md](relay-operator.md), item 6).

## The cleartext road (T-326)

For a proxy that tunnels `CONNECT` but cuts TLS that it does not know, by
its SNI or its certificate (GitHub #56), podssh has a road with no TLS on
the relay's own port, by the operator's ruling Q45: tried last, after the
TLS road failed, with a token minted for that one session and never cached,
as each hop can read the header. SSH inside stays end to end, its host key
checked as on each road; each hop sees the target, the time and the volume,
and that token.

- **The client** (`crates/podssh-relay/src/cleartext.rs`). Once each relay
  host failed, `podssh_relay::open` takes the hosts whose TLS failed in TLS
  itself (a certificate that is not the relay's, a reset or a close in the
  handshake, or its bound: `podssh_ws::cleartext::tls_failed`), the first
  of each deployment alone, one at a time, each within 45 s. For each: the
  same `CONNECT`, through `HTTPS_PROXY`, then `POST /v1/mint?once=1` with
  `{}` and no TLS, signed by the client's key when the relay answers `401`
  with a challenge (T-448); an answer that does not say `"once": true`, or
  whose `expires` is more than 10 minutes away, gets no upgrade, as podssh
  sends no other token in cleartext; then the upgrade of the forward path
  with that token in `X-Relay-Token`. No token of `PODSSH_RELAY_TOKEN` or
  of the cache goes there. Its lines are notes; when the road fails, the
  run's failure, its exit code and the forwarders' fallback stay the TLS
  road's. `PODSSH_CLEARTEXT=no` turns it off.
- **The role** (`crates/podssh-relay/src/serve/listener.rs` and
  `cleartext.rs`). `podssh relay serve` peeks at the first byte of each
  connection: `0x16`, a record of TLS's handshake, goes to TLS as before;
  another goes to the cleartext road, unless `--cleartext no`. There it
  serves `GET /health`; `POST /v1/mint?once=1`, for whom `--mint` names and
  under the brake, which answers `{token, expires, scope, "once": true}`
  with a token of the form `once1.<expiry-ms>.<nonce>.<mac>` under the
  role's secret, which ends 5 minutes later; and `GET /connect/<host>/<port>`
  with such a token, which the upgrade spends, whatever its end, so that a
  second use gets `403`. The role keeps the spent tokens until their end,
  65536 at most, and refuses one more past them. A token of 72 h, the mint
  of one, the reverse road, `/relays.json`, `/trace` and the probes get
  `403` in cleartext, and go over TLS. Over TLS, `POST /v1/mint?once=1`
  mints the same token of one session, and the role's forward road takes it
  once.
- **The probe of #56** (`podssh_ws::cleartext::probe`, `podssh doctor`'s
  line `cleartext`, [cli.md](cli.md)): a `CONNECT` to a host's port, then
  `GET /health` with no TLS, no token and no target, and what came back,
  named: a reset or a close with no answer, a record of TLS, the edge's
  refusal (`400`, in nginx's words "The plain HTTP request was sent to
  HTTPS port"), a refusal by policy (`403`), a redirect, or an answer.
- **The default relay** serves TLS alone on 443 (Cloudflare's edge), so its
  mint in cleartext is refused there. Measured on 2026-10-30 through a
  cloud container's proxy: the cleartext `GET /` was reset with no answer.
  Again on 2026-11-04 (T-326, `podssh doctor --quick`): 443 reset with no
  answer, and port 80 answered with the relay's own `/health`. What its
  edge answers to cleartext from a path with no such proxy waits for the
  live run of T-326 on a runner, and its want is item 7 of
  [relay-operator.md](relay-operator.md).
## The relay role's HTTP road (T-319)

For a proxy that ends TLS for the relay's name, refuses the WebSocket
upgrade and still carries plain requests and their answers (GitHub #55; the
proxy of a Claude Code cloud container documents such a refusal, T-311),
`podssh relay serve`, and the role behind a node's quick tunnel, carry a
session of the forward road over requests of HTTP/1.1
(`crates/podssh-relay/src/serve/http_road/`); podssh's client speaks it
once each relay host failed and the way to one refused the upgrade
([cli.md](cli.md), "The HTTP road after the relay hosts";
`crates/podssh-relay/src/http_road/`). Its split form keeps two connections
to the host, which the operator's ruling Q44 allows on this road alone; the
serial form, one, is its fallback. The default relay serves none of it
([relay-operator.md](relay-operator.md), item 5).

- `POST /v1/http/open/HOST/PORT[?family=4|6]` with the forward token in
  `X-Relay-Token`, as `/connect/` takes it: the role checks the target by
  the same policy, dials it the same way (through its host's proxy when one
  is set), and answers its refusals as `/connect/` does (`403 forward: ...
  not in the ALLOW list`, `502 relay: cannot reach ...`); else `200` with
  `{"session", "key", "batch_max", "wait_max_ms", "down_max", "forms"}`.
  The id is 32 hex digits, the key 43 characters of base64url; 256
  sessions of a process at once at most, then `503` with `Retry-After`.
- Each later request names the session by its id in the path, and proves
  it by its key in `X-Session-Key`, never in a URL. A wrong key and an
  unknown id get the same `404 http: no such session`.
- `POST /v1/http/s/ID/up?seq=N[&fin=1]`: one batch, `batch_max` bytes at
  most (256 KiB; 32 KiB behind a quick tunnel's node, which takes a body
  whole), numbered from 0. `204` once the role stored it; a number taken
  before is the same batch, answered alike and stored once; another number
  than the next is `409`. The role holds 8 batches that the target has not
  taken, and a batch past them waits 10 s for room, then gets `503` with
  `Retry-After: 1`. `X-Ack` in each answer is the batches that the target
  took. After the batch of `fin=1` the target gets TCP's half-close.
- `GET /v1/http/s/ID/down?at=OFFSET&wait=MS`: the target's bytes from
  OFFSET, which says that each byte before it came, so the role forgets
  them; it holds 2 MiB that no request acknowledged, and reads the target
  no further until one does. With bytes there, `200` with `X-Offset:
  OFFSET`, which streams them in chunks on a kept connection, or to the end
  of the connection, and ends 20 ms after nothing more came, or at
  `down_max` (1 MiB), so that a hop that holds an answer to its end holds a
  short one; with none within the wait (25 s at most), a whole `204`. A
  newer request down ends an older one. An offset before what came, or past
  what the role sent, is `409`.
- `POST /v1/http/s/ID/x?[seq=N&]at=OFFSET&wait=MS[&fin=1]`, the serial
  form: the batch, as `up` takes it, when `seq` is given, then the bytes
  down from OFFSET in a whole answer of their length; an exchange that
  carried a batch waits for no byte down.
- `POST /v1/http/s/ID/close` ends the session (`1000 client closed`).
- Once the session ended, each request gets `410` with `X-Close: CODE
  REASON`, the close codes and reasons of the forward road ("Errors and
  close codes"), for 60 s, then `404`. The target's end is `1000 target
  closed`, once a request down acknowledged each of its bytes. The limits are
  the forward road's: 180 s with no payload, 12 h, 64 MiB both ways; and a
  session with no request for 60 s ends with `1001 client gone`.
- A connection carries one request after another while its client keeps
  it, and a request of another path that comes on it goes to the role's
  routes. Behind a quick tunnel's node, which passes an answer to the end of
  its connection, each answer closes its connection.

The role's lines say `http open` and `http close CODE` for each session.
Measured on 2026-11-04 (`crates/podssh-relay/tests/http_road.rs`, 8 passed, and
`crates/podssh-relay/tests/http_road_quick.rs`, 2 passed): 20 MiB each way in each form, each
byte once through lost and cut answers.

## The relay role's HTTP/2 (T-321)

The contract's upgrade is HTTP/1.1, one TLS connection for each session.
RFC 8441 carries a WebSocket as one stream of an HTTP/2 connection
(GitHub #51), so that a process's sessions to one host (`podssh each`, a
fan-out of `job`) share one TLS connection. The default relay's edge
chooses `h2` and offers no extended CONNECT (measured 2026-10-30,
[relay-operator.md](relay-operator.md), item 8); `podssh relay serve`
offers it (`crates/podssh-relay/src/serve/http2/`):

- **ALPN.** The listener offers `h2`, then `http/1.1` (and `acme-tls/1`
  with `--acme`); `--http2 no` offers `http/1.1` alone, as before. A client
  that offers no ALPN, as each road of podssh but this one, gets HTTP/1.1.
- **SETTINGS.** `SETTINGS_ENABLE_CONNECT_PROTOCOL` 1, 16 streams at once
  (`MAX_CONCURRENT_STREAMS`), a window of 1 MiB for each stream
  (`INITIAL_WINDOW_SIZE`) and 16 MiB for the connection, so that a stream
  that a slow target holds full takes no other stream's window, and a
  connection holds 16 MiB of a client's bytes at most.
- **A session.** `CONNECT` with `:protocol websocket`, `:scheme https`,
  `:authority` and the `:path` of the upgrade (`/connect/<host>/<port>`
  with its knobs, the layer's or the reverse road's), `sec-websocket-version:
  13` and the token in `x-relay-token`, with no `Sec-WebSocket-Key` (RFC
  8441, section 5). The role makes it the upgrade of HTTP/1.1 of that path,
  with a key of its own, on a pipe in memory to its routes, so that each
  road keeps its token, its checks, its brake and its limits; the `101`
  is answered `200`, and the frames of RFC 6455 then cross the stream as
  they cross TCP, the client's masked. A refusal is the upgrade's, with its
  status and its body (`403 forward: missing or wrong token`, `502 relay:
  cannot reach ...`). A `CONNECT` with another `:protocol` gets `501`, one
  with none `405`.
- **Other requests.** `GET /health`, `/relays.json`, `/trace` and
  `/llms-full.txt`, and `POST /v1/mint`, answer as over HTTP/1.1, whole.
  Each other request (the HTTP road's, the probes', a pair's call) is reset
  with `HTTP_1_1_REQUIRED` (RFC 9113, section 7), which a client of HTTP/2
  follows by asking again over HTTP/1.1, as each keeps a connection or a
  stream as HTTP/1.1 gives it. A WebSocket of the reverse road or of the
  mailbox is the upgrade of its path, as a session is.
- **An end.** A connection with no stream for 120 s ends with a `GOAWAY`.
  The end of a session's stream is the WebSocket's; a stream reset by the
  client ends its session alone; a lost connection ends each session on it.

The role's lines say `h2` for each connection of HTTP/2, beside `upgrade`
for each session. podssh's client takes the road to a relay host that the
user named, and to the default relay with `PODSSH_H2=yes` alone
([cli.md](cli.md), "The WebSocket over HTTP/2"; `crates/podssh-ws/src/h2_road/`).
Measured on 2026-11-04: `cargo test -p podssh-relay --features serve,plain-ws --test
relay_serve_h2`, 6 passed (`crates/podssh-relay/tests/relay_serve_h2.rs`).

## The relay role's resumable layer (T-173)

A forward session to a standard sshd ends at each drop of the client's
link: the contract's `/connect/` ends the target's connection with its
WebSocket. `podssh relay serve`, and the role behind a node's quick tunnel,
serve `/v1/layer/<host>/<port>` beside the contract, where the role is the
far end of podssh's resumable layer ([design.md](design.md), section 5) for
a target that speaks none, as a node is for its TARGET
(`crates/podssh-relay/src/serve/layer.rs`):

- each WebSocket to the path is one link of a session; the role greets,
  and the layer's handshake tells a new session from a resume;
- the target is dialed once, after a new session's handshake, so a link
  that never completes one costs no dial; it waits while the client's link
  is lost, until a resume on a new link carries the session on, or the
  layer's 10 minutes pass and the target is shut;
- the token (`X-Relay-Token`), the upgrade and the policy are checked
  before the upgrade, for each link, with the refusals of `/connect/`
  (`403 forward: ... not in the ALLOW list`, `502 relay: ...`); a
  `?family` holds, and the dial of a new session waits for its handshake
  whatever `?dial` and `?precheck` say;
- the layer's secret never crosses the role: each resume proves it with
  the nonces of its own link, and the path names the target alone;
- each link keeps the limits of a session (180 s with no payload, 12 h,
  64 MiB); the layer's heartbeat is payload, and the client moves the
  session to a new link at 48 MiB or 11 h (T-155);
- the sessions hold 256 MiB of replay buffers at most, 4 MiB each
  (`--resume-budget MIB`, from 4 to 16384, or 0 for none, which offers no
  road), and one whose link is lost is kept 10 minutes
  (`--resume-deadline TIME`, from 1 minute to 72 h, which the layer's
  `GREETING` names to the client); a new session past the budget is
  refused in its handshake, with the layer's `REFUSE` (busy, code 6) and
  words that name what holds the budget, before its client sent a byte of
  it, and the role's stdout says it once a minute at most; the budget
  counts each new session from its admission, before its target is dialed,
  so that new sessions at once do not pass it together;
- a restart forgets each session: a resume then gets the layer's refusal
  of an unknown session, once its client minted a new token where the role
  mints for it, and else `403` for the old one; either ends the session;
- the role names `end.v1` in its `GREETING` (T-632): a client that names it
  too ends its bytes with the layer's `END`, and the role shuts the
  target's writing side (TCP's half-close) once it wrote each byte before
  the end, and reads on, so a target that reads to the end of its input
  still answers; the target's own end goes back as `END`, or as `CLOSE`
  where the client's `END` came first, and the session ends when that
  `CLOSE` is answered. A client that does not name it gets `CLOSE` at
  either end, as before, and the end of its bytes ends the session.
  `podssh proxy` names it, and `podssh ssh`, whose SSH ends both ways at
  once, does not.

`/relays.json` offers it in `forward`: `layer`, `true` where a new session
can have room, and `host`, the name of this process for each link of a
session, `HOST` or `HOST:PORT`, which `--resume-host` gives, else `null`. A
client asks for the layer only where `layer` is `true`
(`crates/podssh-relay/src/forward_layer/offer.rs`). The client of the
library (`crates/podssh-relay/src/forward_layer/client.rs`) sends each link
of a session, the first too, to the host that `host` names, else to the
host whose document it read, never another of a list, as only that process
holds the session; it takes a `host` that is the host it asked, with any
port, or a host of its deployment by the pool's rule (another host under
its parent domain), and for an address the same address alone; another
name is said in a line and not taken. A refusal that a new link would get
again (`401`, `403`, `404`, `410`) ends the session, and each other failure
is tried again with the layer's backoff until the deadline; a `REFUSE`
(busy) of the first link's handshake sends the session to the contract's
`/connect/`, with no resume. `podssh proxy` and `podssh ssh`, and each
command that reaches its server as `podssh ssh` does, take it where the
first host offers it: its offer kept for a day, read at each run with
`PODSSH_RELAY_LAYER=yes`; a kept offer whose host answers `404` for the
layer's path is forgotten and the session takes `/connect/`
([cli.md](cli.md)). The default relay offers none
([relay-operator.md](relay-operator.md), item 16): a Durable Object of that
deployment would be its far end.

Where several processes of the role serve one name, behind a balancer or
the addresses of one DNS name, each gives `--resume-host`, a name that
reaches it alone and that its certificate holds, so that each resume
reaches the process that holds its session; each link, the first too, gets
its token at that name, as the forward opener mints at the host that it
dials. The test of it (`crates/podssh-relay/tests/session_relay_resume.rs`)
puts two processes behind one name that a balancer sends to each in turn.
The live run of the road, on a GitHub runner to its own sshd with the
client's link cut by `scripts/fake-proxy.py`, is
`.github/workflows/relay-layer-live.yml`, started by hand alone, which runs
`scripts/relay-serve-live.sh` with `layer`.
