# The mesh: podssh's own nodes, at parity with Tailscale (milestone M10)

The operator ruled on 2026-11-02 (Q63, [decisions.md](decisions.md)) that
podssh grows into a mesh of its user's own nodes, with Tailscale's features,
and that the relay becomes a role of podssh itself. Until then 15 entries
waited for "the relay's operator": the relay `tcp-ssh-relay` is a Worker of
another repository, whose source no session can read or change, and podssh
took its contract as its boundary (Q4, Q9). The operator's words: "having
our own relay seems just passing the problem to someone else ... perhaps it
is time, we went full on tailscale-like parity? introduce, exit mode, serve,
funnel, etc; then it would make sense to have the relay in podssh itself".

So no one else holds the dependency: a relay is one more thing that a
user's own podssh does, on a node that has an open port or a quick tunnel,
beside the public services that need no account (Q65) and the standard
servers that a user runs (Q66). `tcp.ssh.relay.ajam.dev` stays the default
relay, and the items of [relay-operator.md](relay-operator.md) are notes for
that deployment; no entry waits for one.

This page is the design. Each part names its entry, and
`TODO/PROGRESS.md` gives the order.

## 1. What a user gets

| Tailscale | podssh | Entry |
| --- | --- | --- |
| A tailnet: a coordination server, node keys, Tailnet Lock | A net: a list of the user's nodes, signed by the user's own key, held by each node; no server to trust | T-429 |
| MagicDNS | A member's name: `podssh ssh NAME`, `node://NAME` | T-429 |
| ACLs and grants | The net's policy, signed by the owner, checked at each node; a grant used once, checked at the node | T-430, T-226 |
| Auth keys, a device's approval | Pairing by a short code over a public mailbox, with a PAKE; a new device's join of the net by one, its owner checked at the device | T-086, T-616 |
| DERP and peer relays | The roads race (iroh, DERP, pairs, quick tunnel, the carriers of Q65); the relay as a role of a node; a member that relays for two others | T-169, T-427, T-428, T-434 |
| Exit nodes | `podssh node --exit`: the node's egress for its owner's forward road, and a local SOCKS5 or HTTP proxy when the user asks | T-431 |
| Subnet routers | `--routes CIDR,...`: the private networks that the node reaches, for the net | T-432 |
| `tailscale serve` | `podssh share`: a node's local services, by name, for the net | T-433 |
| `tailscale funnel` | `podssh funnel`: a local HTTP service at a public `https://` name | T-180 |
| Tailscale SSH | `podssh ssh node://NAME` (M4); `podssh serve`, the server in the cage, stays held (Q32) | done; T-248 |
| Taildrop | `podssh cp` to and from `node://NAME`, and a member's `NAME:PATH` | done; T-453 |
| `tailscale status`, `ping`, `netcheck` | `podssh status`, `ping` and `doctor` for the net | T-435 |

`podssh serve` is M5's command (the server in the cage), so Tailscale's
serve is `podssh share` here.

## 2. The parts that exist

Most of the mesh is built: the expansion joins what M4, M6 and the roads
gave.

- A node and its operator: `podssh node NAME TARGET [ROUTE=TARGET]...`
  ([reverse.md](reverse.md)). Its routes name several services of one
  node, and `podssh share` adds and removes more while it runs (T-433).
- The end-to-end channel: Noise XX with each end's Ed25519 key, under the
  carrier; the node lets in the keys of its `--allow` file before it dials
  ([design.md](design.md), section 5; `crates/podssh-relay/src/e2e/`).
- The resumable layer: each byte numbered, a resume on any road, so that a
  session moves between carriers.
- The roads between two ends, raced: `crates/podssh-cli/src/ssh/roads.rs:1`
  races the iroh road, the pair's road and the DERP road, and each resume
  races them again, for `ssh` and for the copies (T-551).
- A node with no inbound port that serves visitors: the quick tunnel's node
  is the server of the visitors' WebSockets on the connection that podssh
  dialed, and gives 404 to each other request
  (`crates/podssh-relay/src/quick/serve.rs:8`), but those of the relay role
  with `--relay` (T-428).
- The server's side of the WebSocket handshake (`crates/podssh-ws/src/server.rs`).
- The relay's contract, executable: `scripts/fake-relay.py` and
  `scripts/fake_reverse.py` serve the forward road, `/v1/mint`, `/health`,
  `/relays.json`, `/trace` and the whole reverse road, as strictly as the
  live relay, and the offline suite runs against them.

## 3. The net

A net is a document that the owner's key signs: its members, each with a
name, its Ed25519 key, its roles (node, exit, relay, share) and the roads
where it can be found; its policy (T-430); a serial and an expiry. The
owner's key is an OpenSSH key that `podssh keygen` makes, and can stay on
one machine. Each member holds the newest document that it was given, and
takes a newer one only with the owner's signature and a higher serial, so
there is no server to trust and nothing to hold up (T-429).

- **Finding a member.** A node publishes where it is: its record at n0's
  pkarr server (Q57) names its iroh home, and names its DERP home and its
  quick tunnel too (T-445). A client looks a member up by name in the net,
  then by key in the record.
- **Joining.** `podssh net invite NAME` gives a short code; the new device
  says it on its side (`podssh net join`), and both ends run SPAKE2 over a
  public magic-wormhole mailbox (Q65, T-086); the owner's side then signs
  the new key into the net, and gives the device the signed document
  (T-616, below).
- **Leaving.** A member removed from a newer document is refused by each
  member that has that document; a member that a lost key held is removed
  the same way.
- **Policy.** Who may reach which node, which share and which exit, as
  Tailscale's ACLs; checked by the node that is reached, never by a relay.
- **A person at the node.** `podssh node --ask` asks a person at the node's
  terminal of each key that the policy, `--allow` or a grant lets through,
  and a yes covers the device while one of its sessions is open and 120 s
  after (T-638; [reverse.md](reverse.md), "A person at the node").

What T-429 built ([cli.md](cli.md), "`podssh net`"):

- The document is JSON, written on one line with its keys in order, and
  the owner's signature is OpenSSH's SSHSIG over its bytes in the namespace
  `podssh-net`, so `ssh-keygen -Y verify` and `-Y sign` read and make one.
  Each end keeps it in one file (`net.doc` of the cache, or `PODSSH_NET`).
- A field that an earlier podssh does not know stays when its owner signs a
  change, and `requires` names each part that an end must read to take the
  document: the policy (T-430) names its own, so that an end that cannot
  read the rules refuses the document and keeps the older one, never
  skipping the rules.
- The newer document passes in the end-to-end channel
  (`crates/podssh-relay/src/e2e/net.rs`): the operator's first message of
  the handshake offers it in clear, which an end of before sets aside; the
  proofs then name each end's owner and serial, encrypted; the operator's
  document goes before the node's verdict, the node's after it, each only to
  a member. The library compares serials, and the binary checks the
  signature, so no SSH code comes into the library.
- A node whose key is a member lets in the members of the document held,
  for each session (`crates/podssh-cli/src/net/admit.rs`), on the pair's,
  the iroh, the DERP and the quick tunnel's roads, as far as the policy lets
  (T-430, below). The DERP road's node starts with no `--allow` when its key
  is a member, and the members are then its whole door (T-452); so do the
  OpenTunnel road's (T-531) and the quick tunnel's (T-550), whose names are
  public too. With `--relay` and no `--mint`, the quick tunnel's role mints
  for that door.

What T-445 built (drafted 2026-11-02; [design.md](design.md), section 7):

- The record is one signed packet of pkarr with two names in the node's
  zone: iroh's `_iroh` (`relay=URL`, in iroh-dns's own words), which iroh's
  tools and n0's DNS read, and podssh's `_podssh` (`derp=TICKET`,
  `quick=NAME.trycloudflare.com`), which iroh reads past; a key that iroh
  does not know under `_iroh` would make iroh refuse the whole record
  (`crates/podssh-iroh/src/pkarr_record.rs`).
- A node of `--iroh --derp` names its DERP home once its DERP road is
  online, and again at each move; a node of `--quick-tunnel`, or of the
  DERP road alone, has no iroh relay, and keeps its record at n0's server
  too, unless `PODSSH_IROH_PKARR` names another or `off` (Q81, which widens
  Q57; `crates/podssh-cli/src/node_record.rs`).
- `podssh ssh node://NAME` of a member that the net names by its key asks
  the record once each road with a ticket failed, keeps it 30 s, and races
  each road that it names and no ticket gave: the iroh road, the DERP road
  and the quick tunnel (`crates/podssh-cli/src/ssh/iroh/record.rs`). A
  client takes of a record what it takes of a command line, and a DERP
  ticket of another key, or a name outside `trycloudflare.com`, is set
  aside; the end-to-end channel checks the member's key on each road.
- A member's name is a destination (`crates/podssh-cli/src/net/lookup.rs`):
  `node://NAME`, and `NAME` alone with the role `node`; the net names the key
  that the channel checks, and the tickets that race. The copies read
  `NAME:PATH` by the same resolution (T-453), and race the roads that `ssh`
  races, in the same order (T-551, `crates/podssh-cli/src/ssh/node_roads.rs`).

What T-430 built ([cli.md](cli.md), "`podssh net`"):

- The policy is the document's field `policy`, which `requires` names:
  rules from members (`*`, a name, `tag:TAG`) to what they may reach (`*`,
  `NODE` whole, `NODE/ROUTE`, `tag:TAG`, `exit:NODE`, `exit:*`, a range
  `ADDR/BITS`, and since T-455 `relay:NODE` and `relay:*`, a relay role's
  tokens and pairs), and tags; with no policy, each member reaches each, as
  Tailscale's default policy (`crates/podssh-cli/src/net/policy.rs`). A rule
  only allows, so what this podssh does not read allows nothing.
- The node that is reached decides, for each session, with the newest
  document that it holds: the channel's admission now sees the route that
  the operator named (`crates/podssh-relay/src/e2e/ends.rs`), so that a
  member let in to one route reaches neither another route nor the target
  with no route. Its refusal names the rule list's serial and what was
  asked; a relay never sees which route.
- `podssh net policy set FILE`, `clear`, `show` and `check FROM TO`, the
  last with no connection. The words of exits and ranges are read and
  checked now; the node that uses them came with T-431, which asks
  `crates/podssh-cli/src/net/policy.rs` for `exit:NODE` and an address, and
  T-432 builds the net's routes on it.

What T-616 built (drafted 2026-11-04; [cli.md](cli.md), "`podssh net`"):

- The join runs the exchange of the pairing by a code
  (`crates/podssh-relay/src/code/run.rs`), whose runs carry an offer, an
  answer and the giver's last words as bytes for each kind of exchange; the
  version phase names the kind, so that a code given to the other kind's
  command is told apart before either end says a word, with the command
  that takes it. Its words are the binary's
  (`crates/podssh-cli/src/net/invitation.rs`), as the document and its
  signature are: the library carries no SSH code.
- `podssh net invite NAME` offers the net's name, its owner's public key,
  NAME and its roles; the device answers with its key, or with why it
  refuses; the owner's host reads its document again, adds the member as
  `add` does, signs and keeps the next serial, then gives the signed
  document in parts, each below the role's bound on a mailbox's message.
  The owner's key is found, and a passphrase asked, before the code is
  made; the agent's signature runs on a thread of its own. A NAME that is
  a member already goes to its own key alone, with the document held, so
  that a code never hands a member's name to a new key
  (`crates/podssh-cli/src/net/invite.rs`).
- `podssh net join` checks the owner before it keeps anything: the owner
  of `--owner`, else of the net that it holds, else the person's `yes` at
  the terminal, with the fingerprint made from the offer's key; a run with
  its code on a pipe and neither is refused before the code is read. Then
  its key, the node's of NAME by default, and the document, checked
  against the offer and the key, taken by the rule of `podssh net take`
  (`crates/podssh-cli/src/net/join.rs`).
- The owner's side keeps the new serial before it sends it. A last word
  lost leaves the member in the owner's document and nothing on the
  device: `podssh net invite NAME` again gives the device the document
  held, by a new code, as the key is the member's already; never a serial
  that the device holds and the owner does not.

What T-435 built (2026-11-04; [cli.md](cli.md), "The status of the
net"), as Tailscale's `ping`, `status` and `netcheck`:

- `podssh ping NAME` races a member's roads as `podssh ssh` races them, but
  lets each road that starts run on to the far end's first bytes, so that
  each has its time, and names the one that answered first; each link ends
  before a byte is sent on it, so the node dials nothing at its TARGET
  (`crates/podssh-cli/src/ssh/road_probe.rs`).
- Each race to a node keeps its end in the cache, and `podssh status --net`
  lists each member with its roles, the document's serial, and the road that
  last reached it from this host, or the race that found none
  (`crates/podssh-cli/src/net/state.rs`).
- `podssh doctor` asks the public carriers of Q65 that the roads try
  unasked, and the net's member relays at the hosts that the document names
  for them (`crates/podssh-cli/src/doctor/members.rs`).

What T-617 built (drafted 2026-11-04; [relay.md](relay.md), "A signed list
of deployments"):

- The owner names where a relay member's role serves its signed list:
  `podssh net add NAME KEY --roles relay --relay-host HOST[:PORT]`, the
  member's field `relay`, one host, written only when given, so that a
  document of before reads as it did (`crates/podssh-cli/src/net/doc.rs`).
  The key that the net names for the member is the key of the role's list
  (T-346), which its first line names.
- A run that opens a session on the default list asks that host's
  `/relays.json` before its race, once a day for each member whatever it
  answered, 5 s each and 8 s in all, and takes the list there only by the
  member's key (`crates/podssh-relay/src/pool/members.rs`); the list's
  deployments then follow the default list in that run. The host itself
  joins no list, as the role's own list names where sessions go. So a
  client of the net learns its role's deployments with no `--relay-host`
  and no key of its own, also when the default's domain is gone.
- `podssh relay status` asks the members that are due too, and names each
  relay member: its host, then its list taken with its serial, or why not,
  and when it was asked (`--json`: `members`).

## 4. The relay as a role of podssh

`podssh relay serve` (T-169, T-427) serves the relay's contract, version
`2026-10-03-r2`, so that each podssh client and each test of the forward and
the reverse road works against it unchanged: its forward road, and its pairs,
nodes and operators ([relay.md](relay.md), "The relay role's reverse road"),
which `--pairs FILE` keeps across a restart:

- where it can listen: on an address that the user names (Q1), with a
  certificate from files, read again on SIGHUP, or from ACME by TLS-ALPN-01
  on the role's own listener, kept in the cache and renewed in the role
  (T-447);
- where it cannot: behind the node's own quick tunnel (`podssh node NAME
  --quick-tunnel --relay`), whose node gives the relay's routes to the role
  in place of its 404, over HTTP/2 and QUIC, with no listener, the tunnel's
  name the relay host and the keys of `--allow` its own by default (T-428);
- for the keys of a list, each by its signature of the role's challenge
  (`--mint keys:FILE`, T-448; a file, or a URL's list fetched again at its
  TTL, T-646), and for the net's members by the same
  signature, as the net's policy lets them reach `relay:*` or `relay:NODE`
  (`--mint net`, T-455); for anyone, only when the user asks;
- with a brake of 120 mints and pairs a minute for each address, as the
  default relay's, so that one client fills neither the table of pairs nor
  the role's CPU ([relay.md](relay.md), "The relay role's brake", T-454);
- with what each key that mints carried, a budget for a day for each key
  (`--quota MIB`) and a file that keeps the counts across a restart
  (`--usage FILE`), so that an owner who lends the relay to their keys
  knows and bounds what each one carries ([relay.md](relay.md), "What each
  key carried, and its budget for a day", T-636);
- with its targets through the host's `HTTPS_PROXY` when one is set, each
  by the address that its policy checked, so that a role behind a quick
  tunnel on a host whose one way out is a proxy serves its forward road too
  ([relay.md](relay.md), "The relay role's way out", T-457);
- with its HTTP road, for a proxy that refuses the upgrade: the sessions of
  the forward road over plain requests, in a split form on two connections
  (Q44) and a serial form on one, behind a listener and behind a quick
  tunnel ([relay.md](relay.md), "The relay role's HTTP road", T-319);
- with HTTP/2 and RFC 8441's extended CONNECT on its listener, so that the
  sessions of a client's process are streams of one TLS connection
  ([relay.md](relay.md), "The relay role's HTTP/2", T-321);
- with pairs that their owner renews by the stop token, 72 h from then with
  the same tokens, as often as asked: `podssh relay pair --renew NAME`, and
  each node in its pair's last day, so that a node of the role outlives
  72 h with its operators' files unchanged (T-592);
- with QUIC on its port of UDP when asked (`--quic yes`), each stream a
  connection to the same routes, which a client races before its TCP roads
  where a probe found that UDP passes ([relay.md](relay.md), "The relay
  role's QUIC", T-667);
- with an sshd of the owner's on its port when named (`--sshd ADDR:PORT`):
  an SSH client of its listener goes to that sshd by its first four bytes,
  so that a host that lets one port in serves the relay and a shell, behind
  the sshd's own authentication ([relay.md](relay.md), "SSH on the relay
  role's port", T-644);
- with names that its owner publishes to nodes (`--publish NAME=PAIR`): a
  ClientHello of such a name goes to that pair's node before any handshake,
  its bytes untouched, so that a node's own HTTPS site answers with its own
  certificate, and the role reads the name, never the bytes; the role's
  form of funnel, with TLS at the node, where T-180 is TLS at the quick
  tunnel's edge ([relay.md](relay.md), "A name published on the relay
  role's port", T-649).

The role does what the default deployment does not do, which were the items
of [relay-operator.md](relay-operator.md): bounded queues for a slow client
(T-336), a Close before a planned stop (T-255), IPv6 egress where the host
has it (T-253), a frame in flight for a session that was just closed
dropped, not the node's socket (T-421), the split HTTP road (T-319),
extended CONNECT on its own listener (T-321), cleartext on port 443 with a
token for one session (T-326), the probes of `doctor` (T-325), grants used
once (T-226), a mailbox of the pairing by a short code (T-086, at
`/v1/mailbox`), resumption for a standard sshd (T-173), and its place in a
signed list of relays (T-346). A member of a net with the relay role also
carries sessions between two other members that no other road joins
(T-434): a node makes a pair at each relay member that the document names
with a host, at most three, by its own key; a member with no road to it
asks such a role for a leg by the node's key (`POST /v1/leg/<KEY>`, with its
own key's proof), which races once each road before it failed; the
end-to-end channel and the resumable layer stay above, so that the member
that relays sees bytes it cannot read ([relay.md](relay.md), "A leg for a
member of the net").

## 5. Exit, routes, share and funnel

- **Exit** (T-431). `podssh node NAME --exit` lends the node's egress: an
  operator of the net names it (`--exit NAME`) on `ssh`, `proxy`, `cp` and
  `pipe`, and the forward road starts at the node, on any road between the
  two. A local SOCKS5 and HTTP CONNECT proxy serves other programs when the
  user asks for its listener (Q1). The targets are public addresses, as on
  the relay, unless routes allow more.

  What T-431 built ([cli.md](cli.md), "The exit of the net"): the
  operator's word in the channel names the target, `HOST:PORT`, in place of
  a route (`crates/podssh-relay/src/e2e/ask.rs`), so each road whose node
  serves routes carries it: the pair's, the transit relay's, the Piping
  Server's, the DERP and the iroh roads (`Routes::exit`). The node lets out
  a member of a net that gives it the role `exit`, as the policy lets it
  reach `exit:NODE` or a range; it resolves the name with podssh's
  resolver, checks each address by the relay role's check of a public
  address, dials a private one only inside `--routes`, and dials the
  checked addresses alone (`crates/podssh-cli/src/node_exit.rs`). `podssh
  ssh --exit NAME` races the node's roads as `node://NAME` does, with the
  host's own key; `proxy`, `pipe`'s `relay:` and `podssh exit --listen`
  take the pair's road, and answer a client once the node's verdict came.
  T-432 adds the net's list of each node's routes and `--exit auto` (see
  Routes below). Over
  a carrier (T-596), `podssh exit --listen --carrier` is the client of
  `podssh node --exit --carrier`, each connection a leg of the one stream;
  so are `ssh`, `proxy` and `pipe` with `--exit NAME --carrier ADDR`
  (T-614), each session a leg of the command's own stream. `podssh doctor
  --exit NAME` (T-458) says what the net held lets this client, the pair,
  and one session from the exit, with whose a refusal is. Behind a quick
  tunnel (T-459), `podssh node NAME --exit --quick-tunnel` serves its
  visitors through the exit's routes, its door the keys of `--allow` or the
  net's members; `podssh ssh --exit cf://HOST` and the copies reach it by
  the tunnel's name, the channel's word naming the first hop, while `podssh
  exit`, `proxy --exit` and `pipe --exit`, whose sessions ride a relay's
  legs, refuse a `cf://` name.
- **Routes** (T-432). `--routes CIDR,...` lets the net's members reach the
  private networks that the node reaches, within the policy, as a Tailscale
  subnet router does; the node's own host (its loopback and its own
  addresses) only where a range names one address alone. The owner lists
  each exit's routes in the net's document (`podssh net add NAME KEY
  --roles node,exit --routes RANGES`), and `--exit auto` takes the exit
  whose narrowest route holds a target's address ([cli.md](cli.md), "The
  exit of the net").
- **Share** (T-433). `podssh share` adds, removes and lists the services of
  a running node by name, for the members that the policy lets in: a
  service is reached as `node://NODE/NAME`.

  What T-433 built (drafted 2026-11-05; [cli.md](cli.md), "The shares of a
  node"): a share is a route that the node reads for each session from its
  share file, `node-NAME.shares` beside its key or the file of `--shares
  FILE` (`crates/podssh-cli/src/share/serve.rs`), so a node of the channel
  serves routes on each road from its start, and `podssh share add
  NAME=HOST:PORT`, `rm NAME` and `ls` change and read that file under its
  lock (`crates/podssh-cli/src/share/file.rs`); the policy, an allowlist's
  `routes=` and a grant hold a share as a route, at the node
  (`crates/podssh-relay/src/reverse/routes.rs`). The net's document lists
  each node's shares by name, as its owner writes them (`podssh net add
  NAME KEY --roles node,share --shares NAMES`), and `podssh share ls --net`
  lists them; each node serves what its own file holds, as the owner's key,
  which may be on another host, signs the list.
- **Funnel** (T-180). `podssh funnel TARGET` publishes a local HTTP service
  at a public `https://` name through the quick tunnel that podssh makes:
  a random name with no account, or a named tunnel of the user's own
  account through its token file (`--tunnel-token-file FILE`). The node's
  origin is TARGET for each path (`podssh_relay::quick::funnel`): each
  request goes to a new connection of TARGET as HTTP/1.1 with
  `Connection: close`, its body as it comes, in chunks where the visitor
  named no length (`origin_stream`); the answer's body goes to the edge as
  it comes, a chunked one decoded as a stream; a WebSocket passes through.
  TARGET is `HOST:PORT`, `unix-connect:PATH` or `exec:CMD`, as `podssh pipe`
  names them, so that a node in a cage serves a socket or a program. TLS
  ends at Cloudflare's edge, which reads the traffic, and the node says so.
  Where the quick tunnel's edge is out of reach, OpenTunnel can carry it,
  with TLS that ends at the node (T-532).

## 6. Carriers and standard servers

The public services of Q65, each tried unasked, each under the end-to-end
channel and the resumable layer, so that a carrier is trusted for
availability only ([carriers.md](carriers.md)):

- the magic-wormhole transit relay of Least Authority, a pair's carrier on
  port 443 (T-436);
- the public magic-wormhole mailboxes, for pairing by a short code (T-086);
- Piping Server, for a proxy that refuses the WebSocket upgrade (T-437);
- the Wisp demo server, a forwarder after the three of Q56 (T-438);
- each other service that fits, once its terms are read (T-442): ntfy.sh,
  a meeting point of the pairing where a proxy refuses the WebSocket
  upgrade (T-496); a second public Piping Server, `piping.onrender.com`
  (T-497); and upterm's community server, a door on 443 to a machine that
  runs upterm's own host (T-495).

The triage of the operator's sweep of public relays (2026-11-02) found one
more that fits: OpenTunnel, a blind TLS tunnel with no account, whose TLS
ends at the node and whose client's leg needs no upgrade (T-530, T-531,
drafted 2026-11-03: `podssh node --opentunnel` and `podssh ssh node://NAME
--opentunnel-name`); a node with no other road tries it unasked (Q76). The operator's rulings
of the same day (Q74, Q75, Q77, Q78, Q82; [decisions.md](decisions.md))
take each other fallback that exists: Tailscale's main DERP fleet after
tailcat's, once a short test shows that it lets podssh in (T-534); the
public Wisp servers that are made for it (T-535); the overlay networks of
other projects, a research entry each (T-536 to T-544), and the meeting
points of the pairing: Nostr's ephemeral events (T-545), the trackers
(T-546) and the pub/sub networks (T-547); as last fallbacks, the tunnel
providers (Pinggy T-548, Serveo T-549, localhost.run T-565, srv.us T-566,
tunnl.gg T-567, localtunnel T-568, bore.pub T-569, ssh-j.com T-570),
Syncthing's relays (T-571), file hosts and paste sites (T-572), public proxy
nodes (T-573, T-574), a third public Piping Server (T-575), HTTP Relay
(T-576), Bare servers (T-577), Tor's onion services (T-578) and libp2p's
relays (T-579); and roads over UDP where UDP passes: Hysteria 2 (T-580),
TUIC (T-581) and MASQUE over HTTP/3 (T-582). A domain that looks taken over
is never used (Q79). The manual says which it tries last, and why (T-533).

A carrier with no endpoint of its own (T-595, GitHub #124): a stream that
exists already, as the exec channel of a platform's own SSH into a host
whose every road out is closed, carries the node's socket of the reverse
road, and the client's end serves the relay role's side of that socket in
its own process, for that one node (`podssh node --carrier ADDR`, `podssh
operator --carrier ADDR`, `podssh proxy --carrier ADDR node://NAME`,
`podssh ssh --carrier ADDR node://NAME`, the copies to `node://NAME` and
`pipe`'s `node:` side with it, each connection of a command a leg of the one
stream; [cli.md](cli.md)). The stream is the door, the
end-to-end channel pins the node's key under its label, and no protocol is
new. The exit goes over such a stream too (T-596): `podssh node NAME --exit
--carrier ADDR` lends its egress to `podssh exit NAME --listen ADDR:PORT
--carrier ADDR` at the stream's other end, so the host whose one channel is
a platform's exec channel gets egress through that channel's other end, the
issue's case; the stream is the door to the node's TARGET, never to its
egress, which the net's rule of the exit holds as on each road. `podssh
ssh`, `proxy` and `pipe` take `--exit NAME` beside `--carrier ADDR` too
(T-614, Q90): a host that starts the channel itself carries its own session
through the egress of the node at its other end, with no proxy between.

The standard protocols of Q66, so that a server that the user runs is a
road with no relay: HTTP CONNECT to a second proxy over TLS, HTTP/1.1 and
HTTP/2 (T-439); VLESS over a WebSocket and over XHTTP (T-440; over HTTP/1.1
on two connections, T-456); wstunnel's
protocol (T-441); and those that T-442 found: chisel (`--chisel`, T-490), Trojan
(`--trojan`, T-491), Shadowsocks 2022 (in `--shadowsocks`, T-492), Outline's Shadowsocks in a WebSocket
and its `ssconf://` keys (in `--shadowsocks`, T-493), NaiveProxy's server through `--via` (T-494), frp for the reverse
road (T-498), and the IETF's connect-tcp once it is an RFC (T-499).
[carriers.md](carriers.md) gives each reason, and those that do not fit.

## 7. Small repairs that the research found

- The resumable layer's window on the pair's road is above the relay's
  bound of 1 MiB for a slow receiver (T-443).
- Each TLS connection builds its own configuration, so that no session of
  a run resumes TLS (T-444).

## 8. The order, and the release

The relay role comes first, as it turns most of the waiting entries into
work against a server that podssh controls: its forward road (T-169), its
reverse road (T-427), behind a quick tunnel (T-428), with the repairs of
section 7. Then the net (T-429, T-430, T-086, T-226), then exit, routes,
share and funnel (T-431, T-432, T-433, T-180), then the carriers and the
protocols, then the status of the net (T-435). The release of M10 is
`v1.1.0`, with betas `v1.1.0-beta.N` before it, by the rules of T-309
(T-446).

## Sources

The research of 2026-11-02 read these through the services of
<https://web.pkgforge.dev/llms.txt>.

- Tailscale's features: <https://tailscale.com/kb/1103/exit-nodes>,
  <https://tailscale.com/kb/1019/subnets>,
  <https://tailscale.com/kb/1312/serve>,
  <https://tailscale.com/kb/1223/funnel>,
  <https://tailscale.com/kb/1591/peer-relays>,
  <https://tailscale.com/kb/1226/tailnet-lock>.
- The magic-wormhole transit relay and mailbox:
  <https://github.com/LeastAuthority/destiny/blob/main/FAQ.md>,
  <https://winden.app/terms>,
  <https://github.com/magic-wormhole/magic-wormhole-protocols>.
- Piping Server: <https://github.com/nwtgck/piping-server>, <https://ppng.io/>.
- Wisp: <https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md>,
  <https://wisp.mercurywork.shop/>.
- XHTTP: <https://github.com/XTLS/Xray-core/discussions/4113>; wstunnel:
  <https://github.com/erebe/wstunnel>; Caddy's forward proxy:
  <https://github.com/caddyserver/forwardproxy>.
- SPAKE2: <https://crates.io/crates/spake2>.
