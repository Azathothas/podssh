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
| Auth keys, a device's approval | Pairing by a short code over a public mailbox, with a PAKE | T-086 |
| DERP and peer relays | The roads race (iroh, DERP, pairs, quick tunnel, the carriers of Q65); the relay as a role of a node; a member that relays for two others | T-169, T-427, T-428, T-434 |
| Exit nodes | `podssh node --exit`: the node's egress for its owner's forward road, and a local SOCKS5 or HTTP proxy when the user asks | T-431 |
| Subnet routers | `--routes CIDR,...`: the private networks that the node reaches, for the net | T-432 |
| `tailscale serve` | `podssh share`: a node's local services, by name, for the net | T-433 |
| `tailscale funnel` | `podssh funnel`: a local HTTP service at a public `https://` name | T-180 |
| Tailscale SSH | `podssh ssh node://NAME` (M4); `podssh serve`, the server in the cage, stays held (Q32) | done; T-248 |
| Taildrop | `podssh cp` to and from `node://NAME` | done |
| `tailscale status`, `ping`, `netcheck` | `podssh status`, `ping` and `doctor` for the net | T-435 |

`podssh serve` is M5's command (the server in the cage), so Tailscale's
serve is `podssh share` here.

## 2. The parts that exist

Most of the mesh is built: the expansion joins what M4, M6 and the roads
gave.

- A node and its operator: `podssh node NAME TARGET [ROUTE=TARGET]...`
  ([reverse.md](reverse.md)). Its routes already name several services of
  one node, which `podssh share` manages (T-433).
- The end-to-end channel: Noise XX with each end's Ed25519 key, under the
  carrier; the node lets in the keys of its `--allow` file before it dials
  ([design.md](design.md), section 5; `crates/podssh-relay/src/e2e/`).
- The resumable layer: each byte numbered, a resume on any road, so that a
  session moves between carriers.
- The roads between two ends, raced: `crates/podssh-cli/src/ssh/roads.rs:1`
  races the iroh road, the pair's road and the DERP road, and each resume
  races them again.
- A node with no inbound port that serves visitors: the quick tunnel's node
  is the server of the visitors' WebSockets on the connection that podssh
  dialed, and gives 404 to each other request
  (`crates/podssh-relay/src/quick/serve.rs:8`).
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
- **Joining.** `podssh net invite` gives a short code; the new device says
  it on its side, and both ends run SPAKE2 over a public magic-wormhole
  mailbox (Q65, T-086); the owner's side then signs the new key into the net.
- **Leaving.** A member removed from a newer document is refused by each
  member that has that document; a member that a lost key held is removed
  the same way.
- **Policy.** Who may reach which node, which share and which exit, as
  Tailscale's ACLs; checked by the node that is reached, never by a relay.

## 4. The relay as a role of podssh

`podssh relay serve` (T-169, T-427) serves the relay's contract, version
`2026-10-03-r2`, so that each podssh client and each test of the forward and
the reverse road works against it unchanged:

- where it can listen: on an address that the user names (Q1), with a
  certificate from files or from ACME;
- where it cannot: behind the node's own quick tunnel, whose node serves the
  relay's routes to its visitors instead of 404, with no listener (T-428);
- for a net: a member mints its tokens with its key; for anyone, only when
  the user asks.

The role does what the default deployment does not do, which were the items
of [relay-operator.md](relay-operator.md): bounded queues for a slow client
(T-336), a Close before a planned stop (T-255), IPv6 egress where the host
has it (T-253), a frame in flight for a session that was just closed
dropped, not the node's socket (T-421), the split HTTP road (T-319),
extended CONNECT on its own listener (T-321), cleartext on port 443 with a
token for one session (T-326), the probes of `doctor` (T-325), grants used
once (T-226), resumption for a standard sshd (T-173), and its place in a
signed list of relays (T-346). A member of a net with the relay role also
carries sessions between two other members that no other road joins
(T-434).

## 5. Exit, routes, share and funnel

- **Exit** (T-431). `podssh node NAME --exit` lends the node's egress: an
  operator of the net names it (`--exit NAME`) on `ssh`, `proxy`, `cp` and
  `pipe`, and the forward road starts at the node, on any road between the
  two. A local SOCKS5 and HTTP CONNECT proxy serves other programs when the
  user asks for its listener (Q1). The targets are public addresses, as on
  the relay, unless routes allow more.
- **Routes** (T-432). `--routes CIDR,...` lets the net's members reach the
  private networks that the node reaches, within the policy.
- **Share** (T-433). `podssh share` adds, removes and lists the services of
  a running node by name, for the members that the policy lets in: a
  service is reached as `node://NODE/NAME`.
- **Funnel** (T-180). `podssh funnel TARGET` publishes a local HTTP service
  at a public `https://` name through the quick tunnel that podssh makes:
  a random name with no account, or a named tunnel of the user's own
  account through its token file.

## 6. Carriers and standard servers

The public services of Q65, each tried unasked, each under the end-to-end
channel and the resumable layer, so that a carrier is trusted for
availability only ([carriers.md](carriers.md)):

- the magic-wormhole transit relay of Least Authority, a pair's carrier on
  port 443 (T-436);
- the public magic-wormhole mailboxes, for pairing by a short code (T-086);
- Piping Server, for a proxy that refuses the WebSocket upgrade (T-437);
- the Wisp demo server, a forwarder after the three of Q56 (T-438);
- each other service that fits, once its terms are read (T-442).

The standard protocols of Q66, so that a server that the user runs is a
road with no relay: HTTP CONNECT to a second proxy over TLS, HTTP/1.1 and
HTTP/2 (T-439); VLESS over a WebSocket and over XHTTP (T-440); wstunnel's
protocol (T-441); and the others that T-442 finds.

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
