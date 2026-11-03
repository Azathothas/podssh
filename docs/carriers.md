# Carriers without the operator's relay

Since Q65 (2026-11-02, [decisions.md](decisions.md)), podssh may try the
services of Q65 when its user did not ask: Least Authority's
magic-wormhole transit relay, the public magic-wormhole mailboxes, Piping
Server (`ppng.io`) and the Wisp demo server, and each other public service
that fits, once its terms and limits are read and written on this page.

On 2026-10-31 two studies read the documents, the terms and the source code
of services that could carry podssh's bytes where the operator's relay
cannot: one for the forward road (a client to a public SSH server,
[relay.md](relay.md)), and one for the reverse road (a client to a podssh
node, [reverse.md](reverse.md)). They read and did not measure: no carrier
on this page was run against podssh. Each fact is read in a source of the
last section, unless it says Inferred. The forward study puts each carrier
in one of three classes: **A**, the provider's own network goes to the
target; **B**, the provider tunnels to a host that the user controls, and
that host goes to the target; **C**, the user deploys a relay.

## The forward road

No well-known provider offers a documented service, with no account, that
carries any TCP target over a WebSocket. The audit of the same day found
that each road of the release binaries but `--direct` depends on Cloudflare
and on one domain (T-346). The relay is a Cloudflare Worker, whose egress
prefers a binding of Workers VPC through Cloudflare Gateway
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`). Since Q63
(2026-11-02) the relay is also a role of podssh itself, which a user runs
on a host of their own (T-169; [mesh.md](mesh.md)).

The candidates, ranked:

1. **Cloudflare Tunnel to the user's own jump host** (`cf://`, T-264;
   class B).
   - Who, and the account: Cloudflare and the user. A named tunnel needs a
     Cloudflare account with a domain on Cloudflare [F20]; a quick tunnel
     needs none (T-300).
   - Through a proxy: the WebSocket that `cloudflared access tcp` opens
     passes a CONNECT proxy. A proxy that re-terminates TLS passes it when
     podssh trusts the proxy's CA and the proxy passes the upgrade
     (Inferred). A proxy that refuses the upgrade stops it.
   - Use and limits: SSH through a tunnel is a documented use [F20]. A
     quick tunnel is for testing, with no uptime guarantee
     ([design.md](design.md), section 2).
   - Rust and C: built, pure Rust.
   - Effort: S. `-J cf://HOST` is refused today; T-347 makes a `cf://` host
     the first hop of a jump chain, so that the next hop runs in its
     `direct-tcpip` channel. With no account:
     `podssh node NAME --sshd --quick-tunnel` on a host whose egress is open.
   - Risks: the user needs such a host, and a quick tunnel's name changes
     at each run.
2. **GCP IAP TCP forwarding** (class B).
   - Who, and the account: Google; an account, a project, and a VM as the
     jump host.
   - Through a proxy: `wss://tunnel.cloudproxy.app/v4/connect` with a
     Bearer token and the subprotocol `relay.tunnel.cloudproxy.app`; data
     in frames of 16 KiB at most, with acknowledgements [F21] [F22]. It
     passes a CONNECT proxy, and a proxy that re-terminates TLS where that
     proxy passes a WebSocket (Inferred). A refused upgrade stops it.
   - Limits: "not intended for bulk transfer", and a cut after an hour with
     no traffic [F21].
   - Rust and C: the framing is small; its RS256 token is signed with
     aws-lc-rs in the binary, as podssh signs RSA.
   - Effort: M. Risks: a cloud credential that lives long, in a file, and
     the cost of the VM. T-351, after Q51.
3. **AWS EC2 Instance Connect Endpoint, and Session Manager** (class B).
   - Who, and the account: Amazon; an account, a VPC and an instance.
   - Through a proxy: EICE is a presigned SigV4 `wss://` URL, valid for
     60 s, then raw binary frames, and AWS's client honours `HTTPS_PROXY`
     [F24]. Session Manager has a message format of its own [F25b], and
     forwards to a remote host with no SSH hop [F25].
   - Limits: EICE gives an hour to each connection, and 20 at once [F23];
     Session Manager cuts after 20 minutes idle by default [F25]. A session
     must open a new connection before the hour, as `podssh cp` does before
     the relay's caps.
   - Effort: M (Session Manager: L). Risk: EICE's URL carries a credential,
     which design rule 6 forbids ([architecture.md](architecture.md)).
     T-351, after Q51.
4. **WARP, MASQUE over HTTP/2** (class A).
   - Who, and the account: Cloudflare. The registration needs no e-mail,
     but the open client usque sends the headers of "WARP for Android" and
     a random Android serial [F4]. A variant is the user's own Cloudflare
     One organization, free under 50 users, with a headless enrolment by a
     service token [F28] [F29].
   - Through a proxy: connect-ip over HTTP/2 to 162.159.198.2:443 [F1]
     [F2]; Cloudflare says that TCP 443 is "required for HTTP/2 fallback"
     [F5]. The names of MASQUE had no A record on 2026-10-31, so a CONNECT
     must name the IP literal, which a proxy that allows listed names only
     refuses (Inferred). `podssh doctor` measures it (T-366): its line
     `egress takes` names the case. Measured on 2026-10-31 on a cloud
     session's host behind its agent proxy: names only (the proxy took the
     CONNECT to 1.1.1.1:443 and reset its TLS), so WARP cannot leave there. The client pins the endpoint's key and presents a
     client certificate [F4], so a proxy that re-terminates TLS breaks it.
   - Limits: none published; the registration is rate-limited [F1].
   - Rust and C: no usable library. usque is Go; usque-rs takes quiche,
     whose BoringSSL is C, and a TUN device [F1b]. The mode with no IP stack
     works over QUIC only [F3]. Over HTTP/2, podssh would need HTTP/2's
     extended CONNECT (which T-321 needs too), capsules, and smoltcp, which
     is pure Rust [F31] and which Cloudflare says "does not support modern
     TCP features" [F7].
   - Effort: L. Risks: a closed API that can change at any time. T-352,
     after Q52.
   - Built (T-352, drafted 2026-10-31): `warp://HOST[:PORT]`, in a feature
     crate (`crates/podssh-warp/src/lib.rs`), pure Rust. Read in the fork of
     connect-ip-go that usque takes (`client_h2.go`): over HTTP/2 the request
     is a classic CONNECT, `:authority cloudflareaccess.com:443`, with the
     protocol in the header `cf-connect-proto` and no `:protocol`, so it
     needs no extended CONNECT; usque sends `pq-enabled: false` and no
     `User-Agent`. A device is registered once, with the user's acceptance of
     the Terms, and kept in the cache. The live run waits for GitHub Actions
     (Q52).
   - Under volume (T-398, drafted 2026-11-01): the edge sends a DATA frame of
     HTTP/2 for each packet, and h2 ends a connection whose small frames wait
     unread past its budget, which ended cfrs's WARP road (cfrs #32). podssh
     sets the budget to a stream's window of the smallest frames, and its
     stack reads the tunnel while a packet waits to go out
     ([design.md](design.md), section 2, "WARP's road").
   - A front door's new key (T-399, drafted 2026-11-01): cfrs met a new
     device whose front door showed another key than its record's until the
     record was read again (cfrs #32). On a certificate of another key,
     podssh reads the record again from the API and tries a new key that it
     gives; a key that the API never gave is never taken, so a proxy that
     re-terminates TLS still breaks the road.
   - A tunnel that carries nothing (T-560, drafted 2026-11-02; GitHub #107):
     a front door that completes the CONNECT, TLS and the CONNECT of HTTP/2
     and then relays nothing gave a road that was open, each stream in it
     quiet. Once the tunnel opens, podssh connects inside it to `1.1.1.1:443`
     (IPv6's resolver for a device of IPv6 alone), 3 s at most, twice 700 ms
     apart; a SYN-ACK or a reset that comes back is the answer, inside the one
     connection of the road. Its failure is a line of the road (69), which the
     run does not remember as it remembers a proxy; `PODSSH_WARP_PROBE=no`
     skips it.
   - The endpoints in turn (T-561, drafted 2026-11-02; GitHub #108): the road
     dialled one constant address whatever the API had said. The record now
     keeps the API's peers (each `endpoint.v4`, then `.v6`, on port 443) and
     the endpoint that last opened; the road tries that one, then
     162.159.198.2:443, then the peers, one at a time, the dial of each but
     the last within 3 s. usque keeps the API's peers as its endpoints of
     QUIC and dials 162.159.198.2 for HTTP/2 apart from them (usque's
     `cmd/register.go` and `config/endpoints.go`, read on 2026-11-02 through
     <https://web.pkgforge.dev/llms.txt>'s forge service), so whether a peer
     serves HTTP/2 on TCP 443 is Inferred until `warp-live.yml`'s step with a
     proxy that refuses 162.159.198.2:443 measures it.
5. **Tor through Arti** (class A).
   - Who, and the account: volunteers [F17]; no account.
   - Through a proxy: Arti 2.2.0 and later dials through an HTTP CONNECT
     proxy given as an IP literal [F15]. Only Tor relays on the ports that
     the cage allows (443, 80 and 8443,
     [target-environment.md](target-environment.md)) can be first hops;
     whether Arti can be held to them was not read. Tor's own TLS fails
     through a proxy that re-terminates TLS (Inferred). meek_lite fronts
     through CDN77 with POST requests [F16] [F30], so it should pass a proxy
     that refuses the upgrade (Inferred). WebTunnel is a "WebSocket-like
     HTTPS connection" [F17], but no built-in bridge uses it [F16].
     Snowflake needs WebRTC over UDP (Inferred).
   - Terms: Tor's default exit policy accepts port 22 [F19]; a target may
     refuse Tor's exits (Inferred). Counted on 2026-11-02, in the consensus
     of 00:00 UTC (Verified [N7]): 1,121 of the 2,766 exits accept port 22,
     and 1,774 of the 3,754 guards have an ORPort on 443.
   - Rust and C: arti-client is 0.47, not 1.x; its default compression
     needs C, it keeps its state in SQLite (C), and its pluggable transports
     are other programs [F14]. ptrs-gesher-webtunnel takes rustls with ring,
     which holds C [F18].
   - Effort: L. Risks: slow, C, and an API that moves. T-353, after Q52.
   - Built (T-353, 2026-11-01, partial): `tor://HOST[:PORT]`, in a feature
     crate (`crates/podssh-tor/src/lib.rs`), arti-client 0.47 with the
     features `tokio`, `rustls` and `static-sqlite`: its only C is SQLite.
     Arti's TCP provider is podssh's dial, so each first hop goes through the
     proxy by its address, and its first hops are held to the ports of
     `PODSSH_TOR_PORTS` (443 alone through a proxy). The live run waits for
     the operator (Q60).
   - Bridges (T-385, 2026-11-01; measured in a private network): `PODSSH_TOR_BRIDGES`,
     a file of bridge lines, makes the bridges Arti's only first hops.
     meek_lite and WebTunnel run in podssh's process, in podssh-ws, with no
     other program: Arti dials each as a transport that it does not manage,
     a SOCKS5 proxy at a sentinel address that podssh's TCP provider
     answers with a pipe in memory (`crates/podssh-tor/src/transport.rs`).
     Both pass where HTTPS passes, a proxy that re-terminates TLS included
     when podssh trusts its CA; WebTunnel needs the upgrade, meek's POSTs do
     not. Each line must carry the bridge's fingerprint, which Arti asks
     for, so Tor Browser's meek_lite line through CDN77, which has none,
     cannot serve; the user brings bridges. The study:
     [tor-transports.md](tor-transports.md).
6. **A Worker in the user's own Cloudflare account** (class C). It works as
   the relay does, and could serve the split road of T-319 too. The free
   plan gives 100,000 requests a day and 10 ms of CPU for each request
   [F9]; whether a long session meets error 1102 is not documented
   (Inferred). Effort: S. Since Q63 (2026-11-02) podssh's own relay role
   serves the same contract on a host of the user's (T-169).
7. **Other products' WebSocket forwarders** (class A in shape: the
   forwarder dials the target). Read in GitHub #59 and #60, a tester's
   measurement of 2026-10-31 from a host with direct egress, not measured
   here: the Worker of Mudlet's web client (`web-proxy.mudlet.org`, the
   target in its query), an older copy of it (`mudix.delwing.workers.dev`),
   and ssheasy's proxy (`ssheasy.com/p`, the target in a first frame of
   JSON) each gave GitHub's banner. Their sources: `Mudlet/mudlet-web:worker/index.js`
   (Cloudflare's runtime refuses port 25, private addresses and
   Cloudflare's own) and `hullarb/ssheasy:proxy/main.go` (1 GiB at full
   speed, then 100 KiB/s; one connection a second from each address; and,
   read on 2026-11-02, an audit log of each source address, target host,
   target port and byte count [N6]). No account, no token; they serve their
   own products' users and publish no limit. podssh's road to a forwarder
   that the user names is `--forwarder` (T-369), with no relay token; by
   the operator's ruling Q56 the binary names the three by a word, and
   tries them when each relay host failed with no word about the target (T-370; Q69, T-509).

   **Wisp, and Mercury Workshop's demo server** (read on 2026-11-02;
   T-438). Wisp is a published protocol "for proxying multiple TCP/UDP
   sockets over a single websocket connection" [N1]: a packet is a type, a
   stream id and a payload; `CONNECT` names a stream's type, port and host;
   `CONTINUE` gives the packets that the server can buffer for a stream, a
   flow control for each; `CLOSE` gives a reason (unreachable, refused,
   blocked by the server, throttled, among others). The public server
   `wss://wisp.mercurywork.shop/` "is available primarily for demo and
   testing purposes", runs wisp-server-python with a "500kB/s bandwidth
   limit per IP", and resolves names through 1.1.1.3, a resolver that
   blocks malware and adult names [N2]. wisp-server-python refuses
   loopback and private addresses and filters no port by default [N3], so
   port 22 passes unless the deployment adds a rule (Inferred); whether it
   does was not read. The host is behind Cloudflare, with no category
   (Verified [N8] [N13]); no account; a WebSocket by name on 443, so it needs
   the upgrade. The Rust crate `wisp-mux` is LGPL-3.0-only [N4]; podssh-ws
   can speak the small protocol itself (Inferred). Its operator's words
   rule out a default: by Q65 podssh may try it when the user did not ask,
   after the three forwarders of Q56, never first.

   **The other public Wisp servers** (the sweep of 2026-11-02 [W1]). The
   sweep took 76 more Wisp servers from the server lists of web proxies on
   GitHub, and 53 of them answered a bare upgrade with `101`. podssh names
   none of them, tries none unasked, and does not use one as a test target:
   - The lists come from projects that serve a network's users against that
     network's own filter: one of them holds a table of the browser
     extensions of school filters (Securly, GoGuardian, LANSchool, Linewize,
     Blocksi), to detect them [W2]. 7 of the 16 purpose-built hosts that
     were looked up are "Anonymizer" in a filter list (Verified [N8]).
   - No host names an operator, terms or limits. The sweep flagged 54 of
     the 76 as domains of other parties (schools, churches, clubs,
     publishers, hotels, small businesses), or names made to pass for such,
     and 32 of them took the upgrade; one is a look-alike of an education
     site's name. Inferred [W1]: hosts used without their owners' knowledge,
     or names that impersonate. podssh keeps no list of them either: a
     list goes stale, and a server that a user names stays the user's.
   - Mercury Workshop's second host, `anura.pro`, is the Wisp server of the
     demo of its own web proxy, Scramjet [W3], and is "Anonymizer"
     (Verified [N8]); its operator offers `wisp.mercurywork.shop` alone, for
     demo and testing [N2].
   - `relay.widgetry.org`, which the sweep took for a Wisp server, is the
     wsproxy of v86's own example: it relays Ethernet frames for the guests
     of that emulator, which needs an IP stack, and v86's document says that
     public proxies give limited bandwidth [W4].

   A Wisp server that the user runs stays `--forwarder wisp+wss://HOST/`.
   The operator ruled Q75 (2026-11-02): podssh tries the public Wisp
   servers that their operators run for that use, after the other
   forwarders, and never a domain that looks taken over (Q79). T-535's
   research picks them, each with its source, before any joins the
   fallback.

   Built by T-438 from the document alone (`crates/podssh-ws/src/wisp/`):
   the word `wisp`, the last of the fallback, and `--forwarder
   wisp+wss://HOST/PATH/` for a server that the user runs. Read on
   2026-11-02 in the servers' sources, for the tests: wisp-server-python
   0.9.0 (AGPL-3.0, run in the tests, never copied) speaks version 1 only,
   ignores the offered protocol, gives each stream 128 packets of credit
   and a `CONTINUE` after each 32 that it wrote, and closes each stream
   that it cannot open with `0x42`, whatever the cause [N3]; its reader of
   the WebSocket waits while one stream's buffer is full, so a client that
   ignored the credit would hold up each stream of its connection. Mercury
   Workshop's JavaScript server (`wisp-js` 0.5.2, LGPL-3.0) speaks version
   2, but sends a stream's `CONTINUE` for UDP streams alone, so a TCP
   stream through it that keeps the credit stops after its first 128
   packets (Inferred from MercuryWorkshop/wisp-js:src/server/connection.mjs;
   not measured). The tests: a stand-in of version 1 and 2 written from
   the document, wisp-server-python on the loopback, and the demo server
   from GitHub Actions (`.github/workflows/forwarder-live.yml`).
8. **Shadowsocks servers that the user names** (class A in shape: the
   server dials the target that its address header names). Read in GitHub
   #62 (a tester's report of 2026-10-31, not measured here): such servers
   run on port 443, with keys that their operators give out, some on public
   pages; a key that VPNBook published took the salt and the header and gave
   no byte back. The AEAD form is small, and podssh-ws has its ciphers: the
   road is `--shadowsocks FILE` (T-373), of `ss://` lines and subscriptions,
   with no plugin and no Shadowsocks 2022. A proxy that waits for TLS on
   port 443 carries no Shadowsocks (Inferred, as for SSH, T-317), and a
   public key has no operator who answers for it, so podssh names none.

9. **upterm's community server, `uptermd.upterm.dev`** (class B: the
   server tunnels to a machine of the user's that runs `upterm host`; read
   on 2026-11-02 for T-442). Fits: T-495.
   - Who, and the account: upterm's author runs it on Fly.io, "for your
     convenience (please put it into good use!)" [S6]; no account, no terms
     and no limits found. Its README now names the use: "Leave a door open on
     a machine ... and reach it ... through the relay, without opening a
     port. Only your own keys get in" [S5]. By default any SSH client may
     register a session as a host [S5].
   - The protocol: the host runs an SSH server in its own process, dials
     uptermd over SSH, asks it for a session (the global request
     `upterm-create-session@upterm.dev`, a message of protobuf) and for a
     `streamlocal-forward` named by the session's ID [S5]. A guest's SSH
     ends at uptermd, which checks the
     guest's key against the host's list, mints a short-lived user
     certificate, and makes its own SSH connection to the host's server
     through the tunnel [S5]. So uptermd sees the guest's SSH in clear;
     podssh's own SSH to the far machine's sshd, in a `direct-tcpip` channel
     to its loopback (`--allow-forwarding=loopback`), keeps the session end
     to end (Inferred). uptermd's host key is a certificate, under an
     `@cert-authority` line that the README gives [S5].
   - Through a proxy: `wss://uptermd.upterm.dev` on 443, a WebSocket by name
     that carries SSH in binary messages, with `Authorization: Basic` of the
     session's ID and its node, and an `Upterm-Client-Version` header; and
     with no WebSocket, SSH on port 22, which the measured cage refuses
     ([target-environment.md](target-environment.md)); upterm itself
     takes `HTTPS_PROXY` for `wss://` [S5]. TLS 1.2, ALPN `h2`, a Let's
     Encrypt certificate valid to 2027-01-24; no category in the index, and
     the family resolvers clear it (Verified [S4] [N8]). Both ends can be in
     a cage of an HTTPS-only proxy.
   - Rust and C: podssh-ws's WebSocket and podssh's SSH client, which reads
     host certificates. Effort: M for a guest; a podssh node as an upterm
     host needs an SSH server in the node for uptermd's hop, L, and is not
     filed: podssh's own nodes have roads on 443 (the reverse road below).
   - The tests: uptermd and `upterm host` of the release v0.41.0
     (2026-11-02, Apache-2.0, with `checksums.txt`) in containers [S5].

Since the operator's rulings Q77 and Q78 (2026-11-02, [decisions.md](decisions.md)), an item
below that needs no account of the user's and carries bytes is no longer out: it is a last
fallback, tried after podssh's own roads and after the services that allow the use, whatever its
terms, with a word to the user that the target goes to a third party that nobody vouches for; each
gets an entry, research first where its protocol was not read. An item that needs an account,
carries no stream, or answers only on a port that the host cannot reach stays out for that reason.
A domain that looks taken over is never used (Q79).

The entries of the items below, filed on 2026-11-02: the public proxy nodes of aggregator lists
(T-574), with VMess's protocol, which no road of podssh speaks (T-573); Bare servers, as a hop to
a WebSocket road (T-577); and file hosts and paste sites, as a carrier that stores and forwards
(T-572). MASQUE over HTTP/3, where UDP passes, is T-582 (Q82). The others stay out: Deno Deploy,
Fly.io, Cloudflare's TURN, GitHub Codespaces, Microsoft dev tunnels and the MASQUE servers of
others need an account of the user's; the tailscale road is built; Federation 2's forwarder lets
in its own web client alone, by its Origin, so podssh would pass for that client to use it, and it
stays out, a call for the operator to confirm (Q86), as Q74 asks a test that a service lets podssh
in; and the two Workers want a credential that their owners give.

Ruled out:

- **MASQUE servers that others run** (read on 2026-11-02 for T-442):
  WARP is the one with no account, and podssh speaks it (T-352). CONNECT-UDP
  carries UDP, which no road of the forward road needs; masque-go speaks it
  over HTTP/3 alone, which needs UDP [S14]. CONNECT-IP needs an IP stack, as
  WARP's road has one.
- **Deno Deploy**: its policy forbids a "Forward proxy" and a "VPN" [F11].
- **Fly.io**: its policy bans spam proxying only [F12], but it is a VM:
  class B as a jump host, or class C with podssh's own relay role on it
  (T-169, Q63).
- **Cloudflare's TURN**: no TCP relaying, no RFC 6062 [F13].
- **GitHub Codespaces**: its terms forbid use "unrelated to the development
  or testing" of its repository [F26].
- **Microsoft dev tunnels**: the class of `cf://`, with no domain needed,
  but an account; 5 GB for each user a month, at up to 20 MB/s [F27]. Not
  studied further.
- **Already there**: the tailscale road (the feature `ts`, which has C)
  reaches DERP over a WebSocket through the proxy
  ([tailscale.md](tailscale.md)), so a node of a tailnet is a jump host of
  class B today.
- **Public proxy nodes of aggregator lists** (VLESS, VMess and Trojan over a
  WebSocket on 443; the sweep of 2026-11-02 left them out [W1]): their
  operators are anonymous and answer for nothing, and a list changes within
  hours, as with the public Shadowsocks keys of item 8. podssh names none
  and fetches no such list; `--vless` (T-440) is for a server that the user
  runs, or that its operator gives the user.
- **Bare servers** (read on 2026-11-02 for the sweep [W5]): TompHTTP's Bare
  protocol, which openbare's nodes speak, fetches an `http:` or `https:`
  URL, or opens a WebSocket to a `ws:` URL, for web proxies that run in a
  browser; it carries no TCP stream. openbare calls itself "A
  decentralized, censorship-resistant web proxy network".
- **Other products' forwarders of the sweep** [W1]: Federation 2's, a free
  MUD's, takes `host` and `port` in its query as Mudlet's Worker does, and
  checks the Origin of its own web client; podssh never sends another
  client's Origin. Two Workers that want a bearer token and a ticket for
  each session need a credential that their owners give.
- **File hosts and paste sites** (29 in the sweep [W1]): each keeps whole
  uploads, for hours or days, where anyone with the link reads them; a
  session over them is a stream of uploads, which their rules forbid
  (0x0.st: "NOT a platform for: ... other automated mass uploads" [W6]).
  The sweep links them to GitHub #55, which is the split road between two
  podssh ends through podssh's own relay role (T-319), not a file host.

What follows: T-347 is open; T-351 waits for Q51, and T-352 and T-353 for
Q52 ([TODO/PROGRESS.md](../TODO/PROGRESS.md), "Questions for the
operator").

The pool of the default relay, read again by the sweep of 2026-11-02
[W1]: `/relays.json` held 37 hosts, and 36 answered `/health`. Each is a
host of the same Worker under `ssh.relay.ajam.dev`; a name's `aws:`,
`gcp:` or `azure:` is the Worker's placement near that cloud's region, not
another provider (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:30-66`;
Inferred from that document's word "placement"). So the pool spreads the
egress, and the dependence on Cloudflare and on one domain stands. podssh
tries the default host and three hosts of the pool when the user names no
list ([relay.md](relay.md), "How podssh selects relay hosts").

## The reverse road

podssh already protects a session on a carrier that it does not trust
([design.md](design.md), section 5):

- The end-to-end channel, Noise XX with each end's Ed25519 key, ends the
  session on a message that is changed, dropped, repeated or reordered; the
  node gives its verdict before it dials.
- The resumable layer numbers each byte, keeps 4 MiB to send again, resumes
  on any new link with a proof under a secret that the carrier never sees,
  sends a heartbeat each 10 s, moves at 48 MiB or 11 h, and opens spare
  links.

So a carrier is trusted for availability only: it gives a meeting point by
a key or a name, and bytes in order. It still sees keys, times, volumes and
the addresses of the egress. A carrier of datagrams needs an adapter under
the layer that sends again, as a gap ends a link.

The candidates, ranked:

1. **n0's public iroh relays.**
   - Who, and the account: Number 0, for "development and hobby use only"
     [R1]; no account.
   - Through a proxy: a WebSocket over HTTPS ([design.md](design.md),
     section 7); a proxy that re-terminates TLS passes it when podssh trusts
     the proxy's CA (Inferred).
   - Limits: a limit for each connection, not published, that slows the
     sender [R2]; a paid tier at $19 a month gives 5 MB/s [R4].
   - Rust and C: built (`podssh-iroh`); its aws-lc-rs is C, which is allowed
     outside the library crates.
   - Effort: S. Risks: only the newest iroh is supported [R1]: a relay
     that refuses the iroh of a binary is named, with `podssh update` and
     `--iroh-relay` as the ways out. The release binaries have the road
     since T-348 (Q50).
   - Read again on 2026-11-02: "We monitor public relays for abuse. If we
     detect malicious activity, we reserve the right to block offending IP
     addresses or users" [N5]. Cloudflare Gateway puts `iroh.link` in the
     categories "DNS Tunneling" and "CIPA Filter", with a security flag,
     and n0's relays and `dns.iroh.link` inherit both (Verified [N8]).
     Inferred: a proxy or a resolver that blocks "DNS Tunneling" refuses
     the road that podssh tries first, and the record of Q57, so a second
     and a third provider with clean names matter.
   - The sweep of 2026-11-02 named three relays under `relay.iroh.network.`
     [W1], names of n0's older documents (Inferred): n0's page names no
     host on 2026-11-02 [N5], and podssh's table is that of iroh 1.4.1's
     `defaults::prod` (`crates/podssh-iroh/src/relays.rs:17-22`).
2. **Tailscale's DERP relays for tailcat** (`tc301a.ipn.dev` to
   `tc304a.ipn.dev`).
   - Who, and the account: Tailscale, "our free rate-limited DERP relays"
     for tailcat, which has no accounts [R5] [R6]; no account.
   - Through a proxy: derper always serves a WebSocket at `/derp` [R7], and
     the fleet does too (Inferred: tailcat's demo in a browser uses DERP
     alone [R5]); the fork in `vendor/tailscale-rs` speaks it.
   - Limits: rate-limited, in four regions [R6]; a packet is 64 KiB at most
     [R8]; the server drops packets when a client's queue of 32 is full
     [R9]; public since 2026-08-31 [R6].
   - Rust and C: DERP's framing is pure Rust, but the fork's TLS takes
     aws-lc-rs, so the link moves onto podssh-ws.
   - Effort: M in the study; L with an adapter under the layer. Risks: the
     use by other clients is not stated, and Tailscale's terms were not
     read. derper can verify its clients, refuse names of applications, or
     admit clients by a URL [R7]; the main fleet, "free-to-use" in
     Headscale's words [R10], is for Tailscale's clients. T-349; Q50 makes
     it a fallback that podssh may try unasked.
   - Built (T-349, drafted 2026-10-31): the link in `podssh-relay`, feature
     `derp`, on podssh-ws, with an adapter under the layer that sends again
     what a server drops ([design.md](design.md), section 8). derper
     upgrades its WebSocket only with the subprotocol `derp`, and ends a
     connection at a message of more than 32,768 bytes [R46] [R47]; a full
     queue drops its oldest packet [R9]; a client names its program, which
     a server may refuse [R48]. tailcat refuses its own test of throughput
     through the fleet [R5], so no throughput run goes there. The command
     line and the race follow (T-379).
   - Tailscale's main fleet (read on 2026-11-02 for the sweep, which counted
     88 servers in 28 regions in Tailscale's map, 85 of which answered `/`
     [W1]). A `200` on `/` says nothing of who may relay: derper admits each
     key unless it runs with `--verify-clients` or `--verify-client-url`
     [W7], and whether Tailscale's servers do was not read. Each server says
     of itself that it relays "end-to-end encrypted traffic for Tailscale
     clients" [W8]; Tailscale's documents say "DERP servers only serve as the
     connective tissue between devices in your tailnet" [W9]; its terms
     (last updated 2026-08-25) bind each one "accessing or using the
     Services" to use them "solely in accordance with the Agreement, our
     Documentation" (section 2.5), and forbid to "circumvent any security
     measure" (section 2.3) [W10]. Tailscale made tailcat's servers for
     clients with no account, and "may revoke access to them at any time,
     for any reason" [W11]. `tailscale.com`, and so each of its DERP
     servers, is "Anonymizer" in two filter lists, where `tc301a.ipn.dev`
     has no category (Verified [N8]): where a filter blocks anonymizers, the
     main fleet adds no reach (Inferred). The operator ruled Q74
     (2026-11-02): podssh tries the main fleet after tailcat's servers,
     once a short test shows that they let podssh in. T-534 runs that test
     first, from GitHub Actions and the session's host, then adds the
     fallback. Headscale's documents read the map at
     `https://controlplane.tailscale.com/derpmap/default` (read again on
     2026-11-02 [R10]).
   - Community DERP servers: the sweep found 8 on public lists of
     Headscale's users, and 1 answered; their operators and terms could not
     be read [W1]. podssh names none; `--derp-server` takes a server that the
     user trusts (T-379).
3. **Least Authority's magic-wormhole transit relay** (read on 2026-11-02;
   T-436).
   - Who, and the account: Least Authority, the servers behind its Winden
     and Destiny [N11]; no account. Its terms (Winden's General Terms, last
     updated 2022-09-27): "Both Sender and/or Receiver can use the Service
     without prior registration" (section 1.2), and "It is technically
     possible to connect and use the backend servers used by Winden with
     applications other than Winden. By using these servers with other
     applications, you agree to be bound to these same Terms" (section
     1.6); they forbid misuse, and let Least Authority block or limit for
     good cause (sections 3 and 4) [N12]. They describe a transfer between
     a sender and a receiver; Inferred: a node that opens a waiting
     connection for each client that it expects keeps closer to that than
     one that waits all day.
   - The protocol: a client writes `please relay TOKEN for side SIDE\n`;
     the relay waits for a second connection with the same TOKEN and
     another SIDE, sends `ok\n` to both, then copies the bytes, over TCP or
     a WebSocket, "including mixing and matching", whose binary messages
     are a byte stream [N9] [N10]. A pair relay by token: the shape of a
     podssh pair.
   - Through a proxy: `wss://relay.mw.leastauthority.com` answers on 443,
     with TLS 1.2, ALPN `h2` and a Let's Encrypt certificate valid to
     2026-12-09, and has no category (Verified [N8] [N13]); a WebSocket by
     name, so it needs the upgrade. The default transit of magic-wormhole,
     `tcp:transit.magic-wormhole.io:4001`, has no WebSocket, and its port is
     one that the measured cage refuses [N11].
   - Limits: the reference server documents a wait of 30 s, 10 MB and
     60 s, each marked unused in its source [N10]; those of Least
     Authority's deployment are not published.
   - Rust and C: the `magic-wormhole` crate is EUPL-1.2 [N14]; podssh needs
     the handshake line and `ok\n` over podssh-ws's WebSocket, with a TOKEN
     for each link derived from the two ends' keys (Inferred), and the
     layer and the channel above, as on each carrier. Effort: S.
   - Measured on 2026-11-02 against magic-wormhole-transit-relay 0.5.0
     (Twisted 26.10.0, Autobahn 26.10.2) on the loopback, with a WebSocket
     client written by hand, as `python -m twisted transitrelay
     --websocket=tcp:PORT`: the upgrade with a `Host` that names the port;
     the line as one binary message, with its newline; `ok\n` to both as a
     binary message once a second side met, and none for two connections
     of one side; Pings answered while a side waits; and the bytes that a
     side sent before its Close reached the other side before a Close 1000.
     The relay's source answers `bad handshake\n` to a line that it does not
     read, `impatient\n` to bytes before `ok`, and drops the other waiting
     connections of a token once two met [N10].
   - Built (T-436, drafted 2026-11-02): `podssh-relay`'s `transit` module,
     on podssh-ws's WebSocket through `HTTPS_PROXY`, pure Rust. The TOKEN is
     not of each link: it comes, with the key of a proof, from the pair's
     connect token and name by HKDF-SHA256, which both ends hold; each end
     keeps one random SIDE for its run, so that its own connections never
     meet each other. After `ok`, each end sends its part (node or client)
     and a nonce, then an HMAC of both nonces under the proof key: a side
     that knows the TOKEN alone, as the relay does, is refused, and two
     clients of one pair that met each other part and try again. A node of
     the layer and the channel keeps one connection waiting, opens the next
     at each meeting, and shares its keeper with the pair's road;
     `podssh ssh node://` tries the road last, once each other road failed.
     `PODSSH_TRANSIT=no` turns it off, and a URL names another relay. Its
     tests run magic-wormhole's own relay on the loopback (5 passed,
     2026-11-02), and a short live run met through Least Authority's relay
     with 1 MiB each way ten times of thirteen; the three first runs met
     nobody, their cause not found (T-450).
4. **Cloudflare's quick tunnel** (T-300).
   - Who, and the account: Cloudflare, for testing and development; no
     account.
   - Through a proxy: the client, yes (`cf://`); the node needs TCP 7844,
     which the measured cage refuses ([design.md](design.md), section 2).
     Inside WARP's tunnel, on port 443, a node reaches it from a cage whose
     proxy takes a CONNECT to an address (T-374, drafted 2026-10-31).
   - A second public server (read on 2026-11-02 for T-442; fits: T-497):
     Piping Server's README lists `https://ppng.io`,
     `https://piping.onrender.com` and `https://piping.glitch.me` as public
     servers [S9]. `piping.onrender.com/version` answered `1.12.9`, from
     Render's origin behind Cloudflare; `piping.glitch.me` answered 410 with
     Glitch's page [S9]. It has no category of its own, and `onrender.com`
     is "Content Servers" (Verified [N8]). Render spins a free web service
     down after 15 minutes with no inbound traffic, takes about a minute to
     spin it up, and may suspend one that "initiates an uncommonly high
     volume of traffic" [S9]; whether this one is on the free tier was not
     read, and no terms of its own were found. So it is the second server,
     tried when the first failed, with short live runs.
   - Limits: 200 requests in flight; no SLA. Built, pure Rust. Effort: S.
   - Risks: nodes with an open egress only; the protocol is not published,
     and T-339 watches its pin.
   - Category (Verified on 2026-11-02 [N8]): `api.trycloudflare.com`,
     which a node asks for a tunnel, is "Malware" in Cloudflare Gateway,
     with a security flag; `trycloudflare.com`, which names the tunnels, is
     "Content Servers" and "Technology". Inferred: a proxy that filters by
     category can refuse the making of a tunnel and pass its use.
5. **Piping Server, `https://ppng.io`** (read on 2026-11-02; T-437).
   - Who, and the account: its author, nwtgck, runs `https://ppng.io` and
     `https://ppng.io:8443/` (the Rust server) [N15] [N17]; no account; no
     terms found.
   - The protocol: "It transfers data to `POST /thepath` into
     `GET /thepath` streamingly", of any length [N15]; a link both ways is
     two paths, one for each direction, as `go-piping-duplex` and
     `piping-ssh-web` carry SSH [N16].
   - Through a proxy: plain HTTPS by name on 443, with no upgrade: the one
     carrier with no account found that passes a proxy that refuses the
     WebSocket upgrade, at both ends. It answers with TLS 1.2, ALPN `h2`
     and a Let's Encrypt certificate issued 2026-10-24, is not behind
     Cloudflare, and has no category (Verified [N8] [N13]); its page
     showed "Piping Server 1.12.9".
   - How podssh would use it (Inferred): over HTTP/2, the GET of one
     direction and the POST of the other are two streams of one
     connection; where a proxy buffers request bodies, one POST for each
     chunk on a numbered path, as the split road of Q44 does; the node
     keeps a GET waiting on a path derived from the two ends' keys, with
     the layer and the channel above.
   - Limits: not published, and not determined. Rust and C: nothing new,
     podssh-ws's HTTP client; its servers, nwtgck's and
     `piping-server-rust`, run in Podman for the tests. Effort: M.
   - Read in the source on 2026-11-02 [N25] [N26]: a sender and its
     receivers meet on a path, `?n=` receivers for one sender (1 by
     default; the Rust server refuses more), in either order, each waiting
     with no limit of the server's (Node's server sets `requestTimeout`
     to 0); a second sender, or a receiver past `n`, gets `400`, and so
     does each request on a path whose transfer runs, until it ends
     (Node's; the Rust server frees the path once the transfer starts). A
     sender's answer comes at once (`[INFO] Waiting for 1 receiver(s)...`)
     and ends once its receiver took the body, with words of its own when
     the receiver went away halfway; a receiver's answer carries the
     sender's `Content-Length` when it had one. A receiver that goes away
     ends its sender, and the other way round. `/`, `/noscript`,
     `/version`, `/help`, `/favicon.ico` and `/robots.txt` are the
     server's own. Node's server speaks HTTP/2 on its TLS port alone, with
     HTTP/1.1 beside it; the Rust server speaks both on its plain port too,
     HTTP/2 by prior knowledge.
   - Built (T-437, drafted 2026-11-02; `crates/podssh-relay/src/piping/`):
     the node waits at a door whose path comes from the pair's secret; a
     client's hello there names a random link, whose two ways have paths of
     their own and begin with a mark that the receiver checks. Each end
     POSTs its way and GETs the other's: over HTTP/2 on one connection
     where the server's ALPN takes `h2`, else over HTTP/1.1, through
     `HTTPS_PROXY`. A streamed POST that gets no answer within 15 s makes
     the client ask for numbered pieces, a whole POST to `PATH-N` for each.
     A node serves the road unasked once a probe finds the upgrade to the
     relay refused on the way, and a client once its pair's road found the
     same (Q65); `PODSSH_PIPING` names another server, or `no`
     ([reverse.md](reverse.md), "The Piping Server road").
6. **OpenTunnel, `opentunnel.xyz`** (read on 2026-11-02 for the sweep;
   T-530, T-531).
   - Who, and the account: Anomaly (`anomalyco` on GitHub) runs it on
     Fly.io; its server and its two clients are MIT, and its release v0.6.1
     (2026-10-23) has a `SHA256SUMS` [W12]. "Creating a tunnel needs no
     account" [W13]. No terms were found (its repository's code and a
     search, 2026-11-02).
   - The protocol: `POST /api/tunnel` gives a tunnel, `<id>.opentunnel.xyz`,
     and a bearer token; the client makes a P-256 key and a CSR for the name
     and `*.<name>`, and the service gets the certificate from ZeroSSL by
     DNS-01 and renews it, so the key never leaves the client. The client
     keeps a bridge: one WebSocket with the subprotocol `opentunnel`, JSON
     control messages in its text frames, and each visitor's bytes in binary
     frames of a `u32` connection id and 32 KiB at most, 256 connections a
     bridge at most, with a heartbeat and an idle bound that the server
     names [W13]. The server reads a visitor's ClientHello on 443 for its
     SNI alone, and sends the connection, still encrypted, over the bridge:
     TLS ends at the client, so the service never sees plaintext [W12].
   - Through a proxy: the bridge and the API go through `HTTPS_PROXY`, and
     through a proxy that re-terminates TLS whose CA is trusted [W12], so a
     node's leg passes where a WebSocket passes. A client's leg is TLS by
     name to `ROUTE.<id>.opentunnel.xyz:443`, with no upgrade: it passes a
     proxy that refuses the upgrade, and one that re-terminates TLS, as the
     node's certificate is a public one (Inferred). `opentunnel.xyz` has no
     category (Verified [N8]).
   - Limits: 30 tunnels an hour and 10 at once from one address, and 5 new
     certificates a day for one tunnel [W13]; no limit of bytes or of time
     was found. A tunnel's name goes into the logs of Certificate
     Transparency, and its routes' names do not, under the wildcard [W12]:
     anyone may connect to the name, so the end-to-end channel's allowlist
     is the node's door, as on DERP.
   - Rust and C: the crate `opentunnel` takes rustls with ring, which holds
     C [W14]; podssh would speak the protocol itself on podssh-ws, with a CSR
     of the binary's ACME client (`crates/podssh-cli/src/acme/certs.rs:91`)
     and the TLS of podssh-ws's server. The tests: its server from its
     source, with MySQL 8 and its local test CA, in containers [W12].
     Effort: L for the link, M for the command line.
   - Risks: one company, and a service of 2026 (its repository dates from
     2026-03-30 [W12]); one security vendor calls the name "Suspicious",
     with one detection of a blacklist [W15]. The operator ruled Q76
     (2026-11-02): a node with no other road tries it unasked, one tunnel
     for each node, off with `PODSSH_OPENTUNNEL=no`.
7. **Microsoft Dev Tunnels**: a preview, for "adhoc testing and
   development" [R11]. The host logs in with Microsoft or GitHub; a client
   can be anonymous, or use a token of 24 h [R12]. The host opens a
   `tunnel-relay-host` WebSocket, and TLS ends at Microsoft's ingress [R13]
   [R12]. 5 GB for each user a month, 20 MB/s, 10 tunnels [R14]. Its SDK
   needs openssl and russh 0.37 [R15], and its outer SSH has a "none" key
   exchange [R13]. Effort: L; a person must log in once.
8. **ngrok**: an authtoken. The agent dials `connect.ngrok-agent.com:443`,
   trusts ngrok's own root only unless `connect_cas: host` is set, and takes
   `proxy_url` [R16]. The free plan gives 1 GB a month, and TCP endpoints
   need a card [R17]; the `ngrok` crate 0.19 uses rustls [R18]. Effort: M;
   the risk is the quota.
9. **Cloudflare's Realtime TURN**: credentials that an account mints, valid
   for 48 h at most [R19]; TURN over TLS on 443/tcp [R20], which is not
   HTTP, so a proxy that re-terminates TLS breaks it (Inferred); UDP only,
   with no RFC 6062 [R19]; drops past 50 to 100 Mbps for one allocation
   [R20]. It needs a TURN client, and QUIC or an adapter on top. Effort: L.
10. **Azure Relay Hybrid Connections, and AWS IoT Secure Tunneling**: made
    for access that goes out only; a cloud account; a WebSocket at both ends
    [R21] [R22]. Azure charges each listener, with 5 GB a month included
    [R23]; AWS gives 800 kbps and 12 h, at $1 for each tunnel [R24] [R25].
    Effort: S to M; the risks are the cost, and AWS is too slow for copies.
11. **An iroh relay or a pair relay in the user's own Cloudflare account**
    (Workers and Durable Objects): the free plan's 100,000 requests a day,
    with incoming WebSocket messages counted 20 to 1 [R26]. The Worker
    lives outside podssh; since Q63 (2026-11-02) a pair relay of the
    user's own is podssh's relay role, on a host of the user's (T-427).

Meeting points carry signals only. As carriers of bytes, they are shared
services with small messages and rate limits.

- **n0's pkarr server, `dns.iroh.link`**: records signed with Ed25519, over
  HTTPS, rate-limited. Its page says that users are "more than welcome to
  run production systems" [R27], where the page of the relays says
  "development and hobby use only" [R1]. The node's key is already Ed25519
  ([reverse.md](reverse.md)). T-350, after Q50.
- **Nostr**: relays need not store ephemeral events (kinds 20000 to 29999)
  [R28]; nos.lol, damus.io and Primal take messages of 131,072 to 1,000,000
  bytes (their NIP-11 documents). The `nostr` crate needs the C library
  `secp256k1` [R29]; the pure-Rust `k256` has BIP-340 signatures [R30].
  The sweep of 2026-11-02 listed about 50 public relays, 4 of which took a
  bare upgrade [W1]. Each relay has its own operator and its own policy,
  which its NIP-11 document gives (`terms_of_service`, `auth_required`,
  `payment_required`, `restricted_writes`) [W25], so no one set of terms
  holds for the network. The operator ruled Q77 (2026-11-02): Nostr's
  ephemeral events become a meeting point of the pairing, tried unasked
  after podssh's own. T-545 carries T-086's messages there, with BIP-340
  signatures of the pure-Rust `k256`.
- **ntfy.sh**: 4,096 bytes for each message, 250 a day, and it bans abuse
  [R31]. Read again on 2026-11-02 for T-442; fits as a meeting point of the
  pairing by a short code where a proxy refuses the WebSocket upgrade, which
  the mailboxes below need (T-496).
  - Terms (ntfy LLC, last updated 2026-01-26): "You may use the Service
    without creating an account or subscribing to a paid plan. Free usage is
    subject to rate limits"; it forbids spam, to "Circumvent rate limits",
    and an "unreasonable or disproportionately large load"; "Topic names on
    ntfy.sh are public ... your topic name functions as a password"; "best
    effort", with no uptime promised [S1].
  - Limits: 4,096 bytes a message; 60 requests at once for each visitor,
    then one each 5 s; 250 messages a day on ntfy.sh; 30 open subscriptions
    [S2]. A pairing sends a few messages of SPAKE2 and of the version phase
    (Inferred from T-086's protocol).
  - Through a proxy: a topic is read as a JSON stream by a plain GET
    (`TOPIC/json`), or polled (`poll=1`, `since=`), and written by a POST:
    no upgrade [S2]. TLS 1.2, ALPN `h2`, a Let's Encrypt certificate valid
    to 2027-01-23; no category in the index, and the family resolvers clear
    it (Verified [S4] [N8]).
  - The server: Apache-2.0 and GPLv2, release v2.36.0 (2026-10-31) with
    `checksums.txt` [S3], for the tests. Rust and C: nothing new, the HTTP
    client of podssh-ws. Effort: S, on T-086's exchange.
- **The public magic-wormhole mailboxes** (read on 2026-11-02; T-086):
  `wss://relay.magic-wormhole.io/v1`, on port 443 since the commit
  "public_relay.py: use TLS" (`f0522ac7dc`, 2026-05-13), and before it
  `ws://` on port 4000; and Least Authority's
  `wss://mailbox.mw.leastauthority.com/v1` [N11] [N18]. A mailbox stores
  and forwards the messages of two clients of one application's id.
  magic-wormhole's documents say "Application developers can use this one,
  or they can run their own", and its source says of the first: "If it
  gets too expensive to run, I'll shut it down" [N18]. The two ends run
  SPAKE2 over it, keyed by a short code, so it learns nothing of the code.
  Least Authority's mailbox, read again on 2026-11-02 for T-442: Winden's
  terms cover "the backend servers used by Winden" with other applications
  (section 1.6 [N12]), as for its transit relay; TLS 1.2, ALPN `h2`, a Let's
  Encrypt certificate valid to 2026-12-09; no category in the index, and
  the family resolvers clear it (Verified [S4] [N8]). It fits, as T-086's
  second mailbox; no entry more.

Since the operator's rulings Q77 and Q78 (2026-11-02, [decisions.md](decisions.md)), an item
below that needs no account of the user's and carries bytes is no longer out: it is a last
fallback, tried after podssh's own roads and after the services that allow the use, whatever its
terms, with a word to the user that the target goes to a third party that nobody vouches for; each
gets an entry, research first where its protocol was not read. An item that needs an account,
carries no stream, or answers only on a port that the host cannot reach stays out for that reason.
A domain that looks taken over is never used (Q79).

The entries of the items below, filed on 2026-11-02: Syncthing's relays on port 443 (T-571);
Yggdrasil's peers (T-540) and each other overlay network of the sweep, a research entry each
(NetBird T-536, Firezone T-537, ZeroTier T-538, Tox T-539, croc T-541, HyperDHT T-542, Cabal
T-543, Hyphanet T-544); HTTP Relay's demo server (T-576); libp2p's circuit relays (T-579); Tor's
onion services (T-578); public MQTT brokers, with the pub/sub networks, one research entry
(T-547); Pinggy (T-548), Serveo (T-549) and localhost.run (T-565); bore.pub (T-569); `srv.us`
(T-566), `tunnl.gg` (T-567), localtunnel (T-568) and `ssh-j.com` (T-570); a third public Piping
Server, serv00's (T-575); and the trackers, a research entry (T-546). The others stay out, as each
needs an account of the user's: chatmail's iroh relays (a mail account, to learn the relay's
URL), Matrix.org, zrok, and Metered's TURN.

Ruled out:

- **Syncthing's relays**: volunteers, any client, and a specification that
  invites other programs [R32]; but 87 of the pool's 100 relays use port
  22067 and only 8 use 443, each as an IP literal (counted on 2026-11-02,
  Verified [N19]; 88 and 5 on 2026-10-31), and the session mode is
  raw TCP while the protocol mode needs client certificates, so a proxy
  that re-terminates TLS breaks both (Inferred). Read again for T-442 on
  2026-11-02: 5 of the 100 on port 443 at about 09:40 UTC, each an IP literal
  (Verified [S7]), so the pool moves within a day. The specification says
  that a relay tells the modes apart by the first byte, 0x16 for protocol
  mode's TLS, and that session mode "is a plain-text protocol" [S7]: a
  connection of session mode cannot start as TLS does, so a proxy that waits
  for TLS on 443 refuses it, and a proxy that allows listed names refuses
  each IP literal (Inferred). It stays out.
- **Yggdrasil's public peers** (read on 2026-11-02 for T-442): an overlay of
  IPv6 whose peers are "virtual wires which are used for traffic routing";
  its list asks for "a small number of NEARBY peers" and "Do not add large
  numbers of peers" [S8]. Of its 365 entries, 20 are `tls://` on port 443
  (10 of them IP literals) and 6 `wss://` on 443, the rest on other ports or
  QUIC; 9 of those 26 were online at 09:02 UTC, 2 of them `wss://` [S8].
  Through a proxy only the `wss://` peers pass a proxy that re-terminates
  TLS (Inferred). No Rust crate implements the network
  (crates.io, 2026-11-02 [S8]): podssh would port its Go source, the links,
  the routing and the sessions, and run a stream over its datagrams, as the
  DERP road's adapter does; effort L and more. Out, as the roads of podssh's
  own nodes on 443 carry the same pairs.
- **HTTP Relay, `demo.httprelay.io`** (read on 2026-11-02 for T-442): the
  shape of Piping Server, a POST to `/link/CHANNEL` met by a GET there, but
  its own page says "Streaming ✖": each request is a whole message [S10]. Its
  public server is a demo, whose `/health` answered 503 on 2026-11-02, and
  its last release is 2.0.1 (2022-04-11) [S10]. Out: Piping Server streams,
  and T-497 gives it a second server.
- **The iroh relays of chatmail's servers** (read on 2026-11-02 for T-442):
  Delta Chat's mail servers run an iroh relay for its realtime channels;
  one deployment's design names iroh-relay v0.35, where podssh's iroh is
  1.4, and a client learns the relay's URL by IMAP METADATA after it logs in
  [S11], so it needs a mail account there. Out.
- **libp2p's circuit relay v2**: Kubo's defaults are 2 minutes and 128 KiB
  in each direction [R33], enough for hole punching only.
- **Public MQTT brokers**: none is reachable on 443 in practice. HiveMQ's
  broker "must not be used in Production", and its WSS port is 8884 [R34];
  EMQX uses 8084 [R35]; Mosquitto 8081 and 8091 [R36]; Eclipse's sandbox
  lists 443 [R45], and its page answered 522 on 2026-10-31.
- **Matrix.org**: a verified e-mail and an age of 18, and the server keeps
  the history [R37]; an event is 65,536 bytes at most [R38].
- **Tor's onion services**: the purpose fits, but Tor's TLS fails through a
  proxy that re-terminates TLS (Inferred). WebTunnel needs bridge lines and
  a transport in Go [R39], another program, which rule 3 of
  [AGENTS.md](../AGENTS.md), section 5, forbids. Arti's restricted
  discovery of onion services is stable since 1.7.0 [R40], and 2.7.0
  repaired defects of onion services [R41]. Both reasons changed on
  2026-11-01: T-385 runs meek_lite and WebTunnel in podssh's own process,
  and both pass a proxy that re-terminates TLS whose CA podssh trusts.
- **Pinggy, localhost.run and Serveo**: small operators. Corrected on
  2026-11-02: Pinggy's leg need not be raw SSH, as it takes SSH inside TLS
  on ports 443 and 7878, also through an HTTP proxy, and gives TLS tunnels
  on 443 that it routes by SNI [N20]; Serveo documents private SSH
  forwarding by alias with no account, over raw SSH on 22 or 443 [N21];
  localhost.run carries HTTP(S) only on its free tier [N22]. Raw SSH fails
  where a proxy waits for TLS ([target-environment.md](target-environment.md)).
  They stay out for their terms, their limits (Pinggy's free tunnels end at
  60 minutes [R42]; Serveo's anonymous TCP at 10 minutes [N21]) and their
  categories: `a.pinggy.io` is "Security threats" and "Malware",
  `serveo.net` "Security threats" (Verified [N8]). localhost.run, read again
  on 2026-11-02 [X2]: its client is `ssh -R 80:localhost:PORT localhost.run`,
  which names no port, so SSH on port 22 (Inferred); a free domain carries
  HTTP alone, changes after a few hours and has a speed limit; HTTPS on
  443 ends at its edge, which sends plain HTTP down the tunnel.
- **bore.pub**: one person runs it, on the control port 7835 and random
  ports [R43]. Read on 2026-11-02: it restarts on purpose and "isn't meant
  for long-lived connections" (its issue 170, 2025-06-24), it was down on
  2026-09-08 (issue 202), and a monitor of a third party reported it down
  for 3 months [N23]. Its protocol, read on 2026-11-02 [X5]: JSON
  messages ended by a zero byte on the control port 7835; the client's
  `Hello` names a port, the server's `Hello` gives the public port, a
  `Connection` with a UUID comes for each visitor, and the client takes it
  on a new connection with `Accept`; a server with a secret sends a
  `Challenge` first.
- **zrok**: accounts at both ends, 5 GB a day on the free plan [R44], and
  no SDK in Rust (Inferred).
- **OpenRelay, Metered's TURN**: now a Metered account, with 500 MB free
  (read on 2026-11-02 [N24]); and TURN relays UDP.
- **Overlay networks of other projects** (the sweep of 2026-11-02 [W1];
  read the same day). NetBird's relays, 67 over a WebSocket on TCP 443,
  admit a peer with a token of NetBird's management server alone: the relay
  refuses to start with no `--auth-secret`, and "The Management server
  provides the tokens for the peers" [W16], so each peer needs an account.
  Firezone's relays are TURN on UDP, behind an account; ZeroTier's roots
  use UDP 9993; croc's relay uses TCP 9009; the bootstrap nodes of
  HyperDHT, Cabal and Hyphanet use UDP or other ports [W1]. Tox's TCP relays
  try port 443 first [W17], and 4 of the 28 nodes of its list listen there
  [W1], but they speak Tox's own handshake, not TLS, so a proxy that waits
  for TLS refuses them, and a proxy of names alone each IP literal
  (Inferred, as for Syncthing's above). Yggdrasil's peers: T-442.
  ZeroTier, read on 2026-11-02 [X6]: ZeroTier Inc. runs a TCP relay that
  ZeroTier One falls back to where it cannot use UDP, `204.80.128.1/443`
  in its source, which its document calls slow; a user may run one
  (pylon's `reflect` mode).
- **Pub/sub networks** (the sweep [W1]; read on 2026-11-02). Bluesky's
  relays send each record to each consumer, and a record is written to a
  PDS by an account [W18]. ActivityPub's relays take a server's posts and
  send them to each server that subscribed: a server and a domain of the
  user's, and a broadcast of what it sends (Inferred). The Waku Network
  takes a message from a member alone: "Publishers must register to send
  messages", by an RLN membership on a smart contract [W19]; whether the
  fleet of Status that the sweep listed holds the same rule was not read.
  XMTP sends to
  an inbox that a wallet's signature registered [W20]. The Farcaster hubs
  of the sweep were gone [W1]. Nostr: the meeting points above.
- **Trackers** (41 on 443 in the sweep, 2 of them WebTorrent's with a
  WebSocket [W1]): a tracker gives a peer list, or passes WebRTC's offers
  between the peers of one torrent [W21], and the bytes then need a path
  between the peers, or WebRTC over UDP (Inferred). The default WebTorrent
  tracker's domain is "Questionable Content" in an anti-piracy list
  (Verified [N8]).
- **SSH tunnel providers of the sweep**: `ssh-j.com`, a public SSH jump
  and forwarding server with no account [W22], and `tunnl.gg` take raw SSH
  on port 22 in their own commands [W22] [W26], which the measured cage
  refuses ([target-environment.md](target-environment.md)), and the sweep
  read `srv.us` as the same kind [W1]; `tunnl.gg` gives HTTPS URLs alone;
  localtunnel's client dials a raw TCP port that its server names [W23]. A
  user whose egress reaches one may name it as a hop of `-J`, with no change
  of podssh. Read on 2026-11-02: `ssh srv.us -R 1:localhost:PORT` gives
  HTTPS URLs "derived from your SSH key", with no account, and needs a key
  [X3]; localtunnel's client asks `https://localtunnel.me/?new` for an id,
  a port and a URL, then opens raw TCP to that port, and a visitor's
  request meets a reminder page unless it carries the header
  `Bypass-Tunnel-Reminder` [X4].
- **Other public Piping Servers**: of the servers that Piping Server's wiki
  names, the sweep found `ppng.io` alone alive, and by a search
  `piping.onrender.com` (T-442's research) and `p.kokoro.serv00.net` [W1].
  The last runs on serv00, whose terms forbid to "use account for" "Proxy
  software", "VPN" and "Tunneling software" (item 7) [W24].

The chain that the study recommends, for `podssh node` and
`podssh ssh node://` with no pair, raced as T-164 races the roads:

1. iroh through n0's relays (T-348);
2. DERP over a WebSocket through tailcat's relays (T-349), a second
   provider under the same layer and channel;
3. the quick tunnel, where the node reaches TCP 7844 (T-300);
4. a carrier that the user supplies: an iroh relay in their own Cloudflare
   account, n0's paid relays, Dev Tunnels, or Azure Relay.

The meeting point stays the ticket, or the key and the relay, pinned by a
label, with a pkarr record for a node whose home relay changed (T-350); on
DERP, a client tries the other servers of the fleet after the ticket's. The
operator's ruling Q50 (2026-10-31) puts the iroh road in the release
binaries (T-348), and lets n0's relays and tailcat's be tried when the user did not
ask (T-349, T-350; [decisions.md](decisions.md)).

Since Q65 (2026-11-02), Least Authority's transit relay follows DERP in
that chain (T-436), and Piping Server carries the road where a proxy
refuses the WebSocket upgrade, which none of the others passes (T-437).
The study of 2026-11-02 ranks the carriers with no account in this order:
n0's relays, tailcat's DERP, the transit relay, the quick tunnel, Piping
Server; the categories above make a second and a third provider worth
more than a faster first one. The triage of the sweep of 2026-11-02 puts
OpenTunnel (item 6) after them: its client's leg needs no upgrade and its
TLS ends at the node, so a client behind a proxy that refuses the upgrade
has a second carrier beside Piping Server (T-530, T-531), and `podssh
funnel` a name whose TLS the edge does not end (T-532). A node with no
other road tries it unasked (Q76, 2026-11-02).

## Servers that a user runs

Since Q66 (2026-11-02, [decisions.md](decisions.md)), podssh speaks, as a
client, the standard protocols of servers that a user runs, so that such a
server is a road with no relay: HTTP CONNECT to a second proxy over TLS
(`--via`, T-439), VLESS over a WebSocket and over XHTTP (`--vless`, T-440)
and wstunnel's protocol (`--wstunnel`, T-441), after Shadowsocks' AEAD form
(`--shadowsocks`, T-373). The research of T-442 read the protocols below on
2026-11-02, in their specifications and their servers' sources; it ran
none of them. "Passes" means: through an HTTP CONNECT proxy to port 443,
with TCP and TLS alone.

1. **chisel** (fits: T-490).
   - What it is: one binary, MIT, run as `chisel server`, often behind TLS
     on 443; release v1.13.0 (2026-10-11) with `chisel_1.13.0_checksums.txt`
     [S12].
   - The protocol: a WebSocket with the subprotocol `chisel-v3`, which the
     server requires; SSH in its binary messages (Go's `crypto/ssh`, the
     server's version `SSH-chisel-v3-server`), with password authentication
     by `--auth user:pass` or an authfile of the targets that each user may
     reach; the server's key checked by "hashing the ECDSA public key using
     SHA256 and encoding the result in base64", 44 characters; a global
     request `config`, JSON of the client's version and its remotes; then a
     channel `chisel` for each tunnel, its extra data `HOST:PORT`, which the
     server dials before it accepts; `ping` requests both ways [S12].
   - Passes: yes, with the upgrade; a proxy that refuses the upgrade stops
     it. The SSH inside is checked against the server's key, so a proxy that
     re-terminates TLS passes it when podssh trusts the proxy's CA
     (Inferred).
   - Rust and C: podssh-ws's WebSocket with russh's client inside it. russh
     links aws-lc, so this client lives in the binary's crates, not in
     podssh-ws (rule 4 of [AGENTS.md](../AGENTS.md), section 5). Effort: M.
2. **Trojan** (fits: T-491).
   - The protocol: after a real TLS handshake, `hex(SHA224(password))`,
     CRLF, a request of SOCKS5's shape (CONNECT, an address's type, the
     address, the port), CRLF, then the payload, in one write; a server that
     reads a wrong password or request hands the connection to a preset
     endpoint, an HTTP server by default, so that it looks like a web site
     [S13]. Xray-core writes the same request, and serves it over TLS and
     over a WebSocket; trojan-go has a WebSocket mode too, for a CDN [S13].
   - The servers: trojan-gfw's own, GPL-3.0, its last release 1.16.0
     (2020-06-10) with a PGP signature for each file; trojan-go 0.10.6
     (2021-09-14); Xray-core, whose v26.10.21 T-440's tests pin [S13].
   - Passes: over TLS by name on 443, yes. A proxy that re-terminates TLS
     and reads HTTP inside refuses the request, which is not HTTP; the
     WebSocket form passes there where the upgrade passes (Inferred).
   - Rust and C: SHA-224 of the `sha2` crate, which podssh-ws holds, and
     podssh-ws's TLS and WebSocket. Effort: M, less than VLESS's.
3. **Shadowsocks 2022, SIP022** (fits: T-492).
   - The protocol: a pre-shared key of 16 or 32 bytes in base64, never a
     password; each stream's key by BLAKE3's `derive_key` over the key and a
     salt; a request of a salt, a fixed header (a type, a timestamp, a
     length) and a header of the address with padding or payload; the
     response's header holds the request's salt; a timestamp more than 30 s
     off is a replay; `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`
     are mandatory, `2022-blake3-chacha20-poly1305` is optional [S16].
     `--shadowsocks` refuses each 2022 method by its name today (T-373).
   - Passes: as T-373's AEAD form, raw TCP to the server's port, so a proxy
     that waits for TLS on 443 carries none (Inferred, as for SSH, T-317).
   - The server: shadowsocks-rust, MIT, v1.25.0 (2026-08-26) with a
     `.sha256` for each file [S16]; the gate's image installs its `ssserver`
     for T-373's tests.
   - Rust and C: `blake3` 1.8.7 with its feature `pure` builds no C and no
     assembly [S16]; AES-GCM and ChaCha20-Poly1305 are in podssh-ws.
     Effort: M.
4. **Shadowsocks in a WebSocket, Outline's** (fits: T-493).
   - What it is: Outline's server, outline-ss-server (Apache-2.0), serves
     Shadowsocks in a WebSocket by a path since 1.9.0 (2025-02-11):
     `websocket-stream` for TCP and `websocket-packet` for UDP, on a web
     server of its own that a TLS front such as Caddy covers; v1.9.2 has a
     `checksums.txt` [S17]. The Outline SDK's endpoint carries the stream as
     it is in binary messages, and refuses a message of another kind [S17].
   - Its keys: a dynamic access key is the location of a configuration,
     `ssconf://` read as `https://`, in JSON (`server`, `server_port`,
     `password`, `method`) or in a YAML whose TCP part names
     `$type: websocket` and a `wss://` URL; "A dynamic access key URL is a
     credential" [S17].
   - Passes: yes, a WebSocket over TLS by name, where T-373's raw TCP does
     not pass a proxy that waits for TLS.
   - Rust and C: T-373's codec and podssh-ws's WebSocket; a reader of the
     key's YAML. Effort: M.
5. **NaiveProxy's server** (fits, through `--via`: T-494).
   - What it is: Caddy with klzgrad's fork of forwardproxy, Apache-2.0,
     release v2.11.7-naive2 (2026-10-22): an HTTP/2 CONNECT proxy over TLS
     with a layer of padding [S18].
   - The padding is opted into by a `padding` header in the CONNECT and in
     its answer, and its servers "should interoperate with any regular HTTP/2
     clients"; the fork pads only a request that has the header [S18]. So
     `--via` (T-439) should reach it as it is (Inferred). With
     `probe_resistance`, a request whose credentials fail goes to the next
     handler, a web server, in place of a `407` [S18], and `--via` gives its
     words to a `407` alone.
   - Passes: as `--via`. Effort: S, a measurement and the words of that
     refusal.
6. **frp** (fits: T-498).
   - What it is: frps and frpc, Apache-2.0, about 110,000 stars, release
     v0.71.1 (2026-10-14) with `frp_sha256_checksums.txt` [S19]. Many users
     run a frps on a public host already.
   - The protocol: the transports `tcp`, `kcp`, `quic`, `websocket` and
     `wss`; the WebSocket at the path `/~!frp`, in binary frames; messages of
     a type byte and JSON, `Login` with a `privilege_key`; "STCP (Secret
     TCP)", a service with a `secretKey` and no public port, which another
     frpc visits with the same key (`NewVisitorConn`, with a `sign_key` and a
     timestamp); TLS on by default since 0.50 [S19]. Its other parts, the
     control connection's cipher and its multiplexing, are for the entry to
     read in the source.
   - Passes: over `wss://` on 443, with the upgrade. A reverse road through
     a server that the user runs: a podssh node logs in as a frpc with an
     STCP service, and `podssh ssh node://` visits it.
   - Rust and C: podssh-ws's WebSocket and JSON, and a multiplexer.
     Effort: L.
7. **connect-tcp, the IETF's template-driven CONNECT** (waits for its RFC:
   T-499).
   - The draft: version 17 (2026-10-29), an Internet-Draft; a URI template
     with `target_host` and `target_port`; on HTTP/1.1 a GET with
     `Upgrade: connect-tcp`, on HTTP/2 and HTTP/3 an extended CONNECT with
     `:protocol = connect-tcp`; the payload in capsules DATA (0x08) and
     FINAL_DATA (0x09); for the interop of this version, the token
     `connect-tcp-12` [S14].
   - The servers: none of the working group's own. The author's fork of
     masque-go speaks HTTP/3 alone and cites draft 09; erlang_masque speaks
     HTTP/2 and HTTP/3 but carries raw bytes with no capsules, an earlier
     form [S14]. The wire moved between drafts, and no server over HTTP/2
     that speaks draft 17 was found, so there is nothing to test against.
   - Passes: over HTTP/2 and HTTP/1.1 by name, as `--via` does (Inferred).
     Effort: M, once it is an RFC.
8. **Hysteria 2** (where UDP passes, Q82). The protocol "MUST be
   implemented on top of the standard QUIC transport protocol" with
   unreliable datagrams, and its server looks like an HTTP/3 server [S15]:
   UDP alone, which the hosts of podssh's design do not have, and where UDP
   passes the iroh road speaks QUIC already. The operator ruled Q82
   (2026-11-02): roads over UDP, Hysteria 2, TUIC and MASQUE over HTTP/3,
   tried only where a probe found that UDP passes, after the roads over
   TCP. Read again on 2026-11-02 [S15]: a client's first request is an
   HTTP/3 `POST /auth` with `Hysteria-Auth`, a server that accepts it
   answers status 233, and each TCP stream is a bidirectional QUIC stream
   that opens with a request of ID 0x401 and the address as `host:port`.
   Entries: T-580 (Hysteria 2), T-581 (TUIC), T-582 (MASQUE over HTTP/3).
9. **TUIC** (where UDP passes, Q82; read on 2026-11-02 [X1]). Version 5:
   each command is a version, a type and its data, on QUIC's streams and
   datagrams. `Authenticate` is a UUID and a token of 32 bytes that the TLS
   keying material exporter derives, with the UUID as its label and the
   password as its context; `Connect` names an address on a bidirectional
   stream, and the bytes follow it at once, as the server never answers a
   command; UDP goes in `Packet`s; a `Heartbeat` keeps the connection. The
   repository is GPL-3.0 and has no implementation of its own; its servers
   are mihomo, shoes, sing-box and Itsusinn's tuic. Entry: T-581.

## Sources

Read on 2026-10-31 through the services of web.pkgforge.dev.

The forward road:

- [F1] https://github.com/Diniboy1123/usque
- [F1b] https://github.com/Diniboy1123/usque-rs (its `Cargo.toml`)
- [F2] https://github.com/Diniboy1123/usque/wiki/HTTP-2-support
- [F3] https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode
- [F4] usque: `api/masque.go`, `internal/consts.go` and `api/cloudflare.go`
- [F5] https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/
- [F7] https://blog.cloudflare.com/faster-sase-proxy-mode-quic/
- [F9] https://developers.cloudflare.com/workers/platform/limits/
- [F11] https://docs.deno.com/deploy/acceptable_use_policy/
- [F12] https://fly.io/legal/acceptable-use-policy/
- [F13] https://developers.cloudflare.com/realtime/turn/faq/
- [F14] https://docs.rs/arti-client/latest/arti_client/
- [F15] https://github.com/zydou/arti, a mirror of Tor's repository, as
  Tor's GitLab refused automated reads: `CHANGELOG.md` (2.2.0) and
  `crates/arti/src/arti-example-config.toml`
- [F16] https://bridges.torproject.org/moat/circumvention/builtin
- [F17] https://manpages.debian.org/testing/webtunnel/webtunnel-client.1.en.html;
  https://community.torproject.org/relay/setup/webtunnel/
- [F18] https://crates.io/crates/ptrs-gesher-webtunnel
- [F19] https://manpages.debian.org/testing/tor/torrc.5.en.html
- [F20] https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-cloudflared-authentication/
- [F21] https://cloud.google.com/iap/docs/using-tcp-forwarding;
  https://cloud.google.com/iap/docs/faq
- [F22] https://emile.hofsink.net/posts/iap-deep-dive/
- [F23] https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-with-ec2-instance-connect-endpoint.html
- [F24] https://github.com/aws/aws-cli/blob/v2/awscli/customizations/ec2instanceconnect/eicesigner.py,
  and `websocket.py` beside it
- [F25] https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html,
  and `session-preferences-timeout.html` beside it
- [F25b] https://github.com/aws/session-manager-plugin/blob/mainline/src/message/clientmessage.go
- [F26] https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features
- [F27] https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits;
  https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/faq
- [F28] https://developers.cloudflare.com/cloudflare-one/tutorials/deploy-client-headless-linux/
- [F29] https://www.cloudflare.com/zero-trust/products/access
- [F30] https://www.bamsoftware.com/papers/fronting/
- [F31] https://crates.io/crates/smoltcp

The reverse road:

- [R1] https://docs.iroh.computer/iroh-services/relays/public
- [R2] https://docs.iroh.computer/relays/rate-limiting
- [R3] https://www.iroh.computer/blog/v1
- [R4] https://docs.iroh.computer/iroh-services/relays/shared
- [R5] https://github.com/tailscale/tailcat; https://tailcat.dev/derpmap.json
- [R6] https://tailscale.com/blog/tailcat
- [R7] https://github.com/tailscale/tailscale/blob/main/cmd/derper/derper.go
- [R8] https://github.com/tailscale/tailscale/blob/main/derp/derp.go
- [R9] https://github.com/tailscale/tailscale/blob/main/derp/derpserver/derpserver.go
- [R10] https://headscale.net/stable/ref/derp/
- [R11] https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
- [R12] https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/security
- [R13] https://github.com/microsoft/dev-tunnels/blob/main/rs/src/connections/relay_tunnel_host.rs
- [R14] https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits
- [R15] https://github.com/microsoft/dev-tunnels/blob/main/rs/Cargo.toml
- [R16] https://ngrok.com/docs/agent/config/v3/;
  https://ngrok.com/docs/gateway/agent/connect-url
- [R17] https://ngrok.com/docs/pricing-limits/free-plan-limits;
  https://ngrok.com/docs/pricing-limits
- [R18] https://crates.io/crates/ngrok
- [R19] https://developers.cloudflare.com/realtime/turn/faq/
- [R20] https://developers.cloudflare.com/realtime/turn/
- [R21] https://learn.microsoft.com/en-us/azure/azure-relay/relay-hybrid-connections-protocol
- [R22] https://docs.aws.amazon.com/iot/latest/developerguide/secure-tunneling.html
- [R23] https://azure.microsoft.com/en-us/pricing/details/service-bus
- [R24] https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html
- [R25] https://aws.amazon.com/iot-device-management/pricing/
- [R26] https://developers.cloudflare.com/durable-objects/platform/pricing/
- [R27] https://docs.iroh.computer/connecting/dns-address-lookup
- [R28] https://github.com/nostr-protocol/nips/blob/master/01.md
- [R29] https://crates.io/crates/nostr
- [R30] https://crates.io/crates/k256
- [R31] https://docs.ntfy.sh/publish/#limitations
- [R32] https://docs.syncthing.net/specs/relay-v1.html;
  https://docs.syncthing.net/users/strelaysrv.html;
  https://relays.syncthing.net/endpoint
- [R33] https://github.com/ipfs/kubo/blob/master/docs/config.md
- [R34] https://www.mqtt-dashboard.com/
- [R35] https://www.emqx.com/en/mqtt/public-mqtt5-broker
- [R36] https://test.mosquitto.org/
- [R37] https://matrix.org/legal/terms-and-conditions/
- [R38] https://spec.matrix.org/latest/client-server-api/
- [R39] https://community.torproject.org/relay/setup/webtunnel/
- [R40] https://blog.torproject.org/arti_1_7_0_released/
- [R41] https://blog.torproject.org/arti_2_7_0_released/
- [R42] https://pinggy.io/
- [R43] https://github.com/ekzhang/bore;
  https://github.com/ekzhang/bore/issues/196
- [R44] https://zrok.io/pricing/; https://docs.zrok.io/docs/concepts/sharing-private
- [R45] https://testmqtt.com/brokers/eclipse
- [R46] https://github.com/tailscale/tailscale/blob/v1.104.4/derp/derpserver/websocket.go,
  and `handler.go` beside it
- [R47] https://github.com/coder/websocket/blob/v1.8.15/read.go (`defaultReadLimit`)
- [R48] https://github.com/tailscale/tailscale/blob/v1.104.4/derp/derp_client.go,
  and `types/key/node.go`

Read or measured on 2026-11-02 through the services of web.pkgforge.dev,
for Q65 and the corrections of that day. "Verified" marks a measurement
through those services (a TLS handshake, a category lookup, or a count in a
public data file), not a run of podssh.

- [N1] https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md
  (version 2.1)
- [N2] https://wisp.mercurywork.shop/
- [N3] https://github.com/MercuryWorkshop/wisp-server-python (v0.8.3; its
  source at v0.9.0, read on 2026-11-02 for T-438)
- [N4] https://crates.io/crates/wisp-mux;
  https://github.com/MercuryWorkshop/epoxy-tls
- [N5] https://docs.iroh.computer/iroh-services/relays/public
- [N6] https://raw.githubusercontent.com/hullarb/ssheasy/HEAD/proxy/main.go
  (its last change `94592d8497`, 2024-03-06)
- [N7] https://onionoo.torproject.org/details?running=true&fields=or_addresses,flags,exit_policy_summary
  (the consensus of 2026-11-02 00:00 UTC, counted)
- [N8] https://domain.web.pkgforge.dev/category (Cloudflare Gateway's
  categories, and the flags of public filtering resolvers)
- [N9] https://github.com/magic-wormhole/magic-wormhole-protocols/blob/main/transit.md
- [N10] https://github.com/magic-wormhole/magic-wormhole-transit-relay
  (`src/wormhole_transit_relay/transit_server.py`, `server_state.py` and
  `docs/running.md`); https://meejah.ca/blog/wormhole-for-the-web
- [N11] https://github.com/magic-wormhole/magic-wormhole/issues/574;
  https://github.com/LeastAuthority/destiny/blob/main/FAQ.md
- [N12] https://winden.app/terms (last updated 2022-09-27; the read service
  answered from a stored copy)
- [N13] https://domain.web.pkgforge.dev/tls/HOST (TLS handshakes of
  `relay.mw.leastauthority.com`, `ppng.io` and `wisp.mercurywork.shop`)
- [N14] https://crates.io/crates/magic-wormhole;
  https://github.com/magic-wormhole/magic-wormhole.rs
- [N15] https://github.com/nwtgck/piping-server; https://ppng.io/
- [N16] https://github.com/nwtgck/go-piping-tunnel;
  https://github.com/nwtgck/go-piping-duplex;
  https://github.com/nwtgck/piping-ssh-web
- [N17] https://github.com/nwtgck/piping-server/wiki/Ecosystem-around-Piping-Server
- [N18] https://magic-wormhole.readthedocs.io/en/latest/server-protocol.html;
  https://magic-wormhole.readthedocs.io/en/latest/api.html;
  `src/wormhole/cli/public_relay.py` of
  https://github.com/magic-wormhole/magic-wormhole, and its history
  (`f0522ac7dc`, 2026-05-13)
- [N19] https://relays.syncthing.net/endpoint (counted)
- [N20] https://pinggy.io/docs/client_behind_proxy/;
  https://pinggy.io/docs/tls_tunnels/; https://pinggy.io/docs/tlstcp_tunnels/
- [N21] https://serveo.net/docs/
- [N22] https://localhost.run/
- [N23] https://github.com/ekzhang/bore/issues/170; the issues of
  https://github.com/ekzhang/bore (202); https://www.saashub.com/bore-pub-status
  (a third party)
- [N24] https://www.metered.ca/tools/openrelay/; https://www.metered.ca/pricing
- [N25] https://github.com/nwtgck/piping-server: `src/piping.ts`,
  `src/index.ts` and `src/reserved-paths.ts` of its main branch, and its
  `package.json` (1.12.9, the version that `ppng.io` showed)
- [N26] https://github.com/nwtgck/piping-server-rust: `src/piping_server.rs`
  and `src/main.rs` of its main branch, and `src/main.rs` and `Cargo.toml`
  at v0.18.0 (hyper 1.2, hyper-util's server of both protocols)

Read or measured on 2026-11-02 through the services of web.pkgforge.dev,
for T-442. "Verified" marks a reading of those services, as above.

- [S1] https://docs.ntfy.sh/terms/ (last updated 2026-01-26)
- [S2] https://docs.ntfy.sh/publish/ (its "Limitations");
  https://docs.ntfy.sh/subscribe/api/
- [S3] https://github.com/binwiederhier/ntfy (its release v2.36.0)
- [S4] https://domain.web.pkgforge.dev/tls/HOST (TLS handshakes of
  `ntfy.sh`, `mailbox.mw.leastauthority.com` and `uptermd.upterm.dev`)
- [S5] https://github.com/owenthereal/upterm: its README,
  `host/internal/reversetunnel.go`, `ws/client.go` and `upterm/const.go` of
  its default branch, and its release v0.41.0 (2026-11-02)
- [S6] https://owenou.com/upterm/ (its author's page)
- [S7] https://relays.syncthing.net/endpoint (counted);
  https://docs.syncthing.net/specs/relay-v1.html
- [S8] https://publicpeers.neilalexander.dev/ (the list for v0.5 and its
  status of 2026-11-02 09:02 UTC, counted); a search of crates.io for
  `yggdrasil` and `ironwood`
- [S9] https://github.com/nwtgck/piping-server (its README, "Public
  servers"); https://piping.onrender.com/version;
  https://piping.glitch.me/version; https://render.com/docs/free
- [S10] https://httprelay.io/; https://httprelay.io/features/link;
  https://gitlab.com/jonas.jasas/httprelay (its releases);
  https://demo.httprelay.io/health
- [S11] https://madmail.chat/docs/TDD/11-proxy-services (a chatmail
  deployment's design)
- [S12] https://github.com/jpillora/chisel at v1.13.0: `share/version.go`,
  `client/client.go`, `client/client_connect.go`, `server/server.go`,
  `server/server_handler.go`, `share/tunnel/tunnel_out_ssh.go` and
  `share/tunnel/tunnel_in_proxy.go`; its release v1.13.0
- [S13] https://trojan-gfw.github.io/trojan/protocol;
  https://github.com/trojan-gfw/trojan (its release 1.16.0);
  https://github.com/p4gefau1t/trojan-go (its README and release v0.10.6);
  `XTLS/Xray-core:proxy/trojan/protocol.go` at v26.10.21
- [S14] https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp/
  (draft 17); `bemasc/masque-go:proxy.go` (its branch `capsules`);
  https://github.com/benoitc/erlang_masque (its README,
  `benoitc/erlang_masque:docs/2-use/connect-tcp.md` and
  `benoitc/erlang_masque:docs/reference/conformance.md`)
- [S15] https://v2.hysteria.network/docs/developers/Protocol/
- [S16] https://shadowsocks.org/doc/sip022.html;
  https://github.com/shadowsocks/shadowsocks-rust (its release v1.25.0);
  `BLAKE3-team/BLAKE3:build.rs` and `BLAKE3-team/BLAKE3:Cargo.toml` at
  1.8.7
- [S17] https://developers.google.com/outline/docs/guides/service-providers/caddy;
  https://developers.google.com/outline/docs/guides/service-providers/dynamic-access-keys;
  `OutlineFoundation/outline-ss-server:cmd/outline-ss-server/config_example.yml`,
  and `main.go` beside it at v1.9.2, and its releases 1.9.0 and 1.9.2;
  `Jigsaw-Code/outline-sdk:x/websocket/endpoint.go`
- [S18] https://github.com/klzgrad/naiveproxy (its README, "Padding
  protocol, an informal specification");
  `klzgrad/forwardproxy:forwardproxy.go` (its branch `naive`), and its
  release v2.11.7-naive2
- [S19] https://github.com/fatedier/frp (its README);
  `fatedier/frp:pkg/util/net/websocket.go` and `fatedier/frp:pkg/msg/msg.go`
  at v0.71.1; its release v0.71.1

Read on 2026-11-02 through the services of web.pkgforge.dev, for the triage
of the operator's sweep of public relays. "Verified" marks a reading of
those services, as above. No host that the sweep lists was contacted for
this page: a host's own page is cited from a search index or an archive.

- [W1] The sweep: a report of the operator's research agent of 2026-11-02,
  measured from a host whose only egress is an HTTP CONNECT proxy and whose
  DNS does not resolve, by a `GET /` and a bare WebSocket upgrade with no
  frame for each host, with the pool files of Tailscale and Syncthing; about
  700 endpoints in twelve classes, about 315 of which answered; with its
  probe's results and the handshakes that it captured. Not in the
  repository.
- [W2] `0800WebDev/zinc:script.js`, read in the sweep's copy (its list of
  Wisp servers, and its table of the extensions of school filters)
- [W3] https://github.com/MercuryWorkshop/scramjet/commit/8a5444b5d6c3267c3934daac84ab992ad1fc6d80
  ("[scramjet/demo] set wisp url to anura.pro", 2026-02-19), read in a
  search result; the repository's description: "Scramjet is a versatile web
  proxy designed to bypass internet censorship"
- [W4] `copy/v86:docs/networking.md`
- [W5] `tomphttp/specifications:BareServerV3.md` and
  `tomphttp/specifications:README.md`; `nirholas/openbare:README.md`
- [W6] https://0x0.st/, its capture of 2025-12-02 in the Wayback Machine,
  through archive.web.pkgforge.dev ("Terms of Service")
- [W7] `tailscale/tailscale:cmd/derper/derper.go` (its flags
  `verify-clients` and `verify-client-url`, read in a search result);
  https://tailscale.com/docs/reference/derp-servers/custom-derp-servers
  ("Anyone that knows the IP address of your DERP server could add it to
  their DERP map")
- [W8] https://derp3g.tailscale.com/, as a search index holds it: "This is
  a Tailscale DERP server. It provides STUN, interactive connectivity
  establishment, and relaying of end-to-end encrypted traffic for
  Tailscale clients."
- [W9] https://tailscale.com/kb/1232/derp-servers (validated 2026-01-21)
- [W10] https://tailscale.com/terms (last updated 2026-08-25), sections 1,
  2.3 and 2.5
- [W11] `tailscale/tailcat:README.md`, its section "Stability"
- [W12] https://github.com/anomalyco/opentunnel: its README (the
  architecture, "Corporate proxies / custom CAs", the deployment on Fly.io,
  and the server's local run with MySQL 8 and its test CA), its creation
  (2026-03-30) and its release v0.6.1; the text of `opentunnel.xyz`, read
  in a search result
- [W13] `anomalyco/opentunnel:docs/protocol.md` (the HTTP API, the
  provisioning, the bridge) and `anomalyco/opentunnel:docs/server.md`
  ("Limits")
- [W14] `anomalyco/opentunnel:crates/opentunnel/Cargo.toml`
- [W15] https://gridinsoft.com/online-virus-scanner/url/opentunnel-xyz, read
  in a search result
- [W16] `netbirdio/netbird:relay/cmd/root.go` ("auth secret is required")
  and `netbirdio/netbird:shared/relay/auth/hmac/doc.go`, at `5b55b834bf`
  (2026-11-02)
- [W17] `irungentoo/toxcore:docs/TCP_Network.txt` ("The first port the
  server will try binding to is 443 followed by port 3389")
- [W18] https://docs.bsky.app/docs/advanced-guides/api-directory and
  https://docs.bsky.app/docs/advanced-guides/firehose, read in search
  results
- [W19] https://blog.waku.org/explanation-series-rln-relay/;
  `waku-org/specs:standards/core/rln-contract.md`; read in search results
- [W20] https://docs.xmtp.org/chat-apps/core-messaging/create-a-client,
  read in a search result
- [W21] `webtorrent/bittorrent-tracker:README.md`
- [W22] https://news.ycombinator.com/item?id=26500128 (its author's post);
  https://lottunnels.github.io/lottunnels/Binaries/sshj/; the text of
  `ssh-j.com`, read in a search result
- [W23] `localtunnel/localtunnel:lib/TunnelCluster.js`
- [W24] https://www.serv00.com/terms-of-service/
- [W25] `nostr-protocol/nips:11.md`
- [W26] https://github.com/klipitkas/tunnl.gg (its README, MIT), read in a
  search result

Read on 2026-11-02 through the services of web.pkgforge.dev (read, forge
and search), for the entries of the rulings Q74, Q75, Q77, Q78 and Q82
(T-534 to T-549 and T-565 to T-582). No host of the sweep's lists was
contacted beyond a public page that those services read: each fact is
from a project's own repository or document.

- [X1] https://github.com/tuic-protocol/tuic: `tuic-protocol/tuic:SPEC.md`
  (version `0x05`) and its README (its servers and clients); GPL-3.0, its
  last push 2025-05-15
- [X2] https://localhost.run/docs/ (its pages "The Basics", "HTTP
  Tunnels", "TLS Passthru Tunnels", "CLI Reference", "Forever Free" and
  "FAQ")
- [X3] https://github.com/xmit-dev/srv.us (its README; 0BSD)
- [X4] `localtunnel/localtunnel:lib/Tunnel.js` and its README (MIT);
  its issues 663 and 407 (the header `Bypass-Tunnel-Reminder`) and 719
  (the tunnel password), read in search results
- [X5] `ekzhang/bore:src/shared.rs` (`CONTROL_PORT`, `ClientMessage`,
  `ServerMessage`)
- [X6] https://docs.zerotier.com/relay/;
  `zerotier/ZeroTierOne:service/OneService.cpp` (`ZT_TCP_FALLBACK_RELAY`),
  read in a search result
- [X7] The licenses of the servers that the tests of T-568, T-569, T-580,
  T-581 and T-582 would run, read in GitHub's records:
  `HyNetworks/hysteria` (MIT; its old name `apernet/hysteria`),
  `Itsusinn/tuic` (GPL-3.0), `quic-go/connect-ip-go` (MIT),
  `localtunnel/server` (MIT) and `ekzhang/bore` (MIT)
