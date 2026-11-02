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
   tries them when each relay host failed (T-370).

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

Ruled out:

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

What follows: T-347 is open; T-351 waits for Q51, and T-352 and T-353 for
Q52 ([TODO/PROGRESS.md](../TODO/PROGRESS.md), "Questions for the
operator").

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
6. **Microsoft Dev Tunnels**: a preview, for "adhoc testing and
   development" [R11]. The host logs in with Microsoft or GitHub; a client
   can be anonymous, or use a token of 24 h [R12]. The host opens a
   `tunnel-relay-host` WebSocket, and TLS ends at Microsoft's ingress [R13]
   [R12]. 5 GB for each user a month, 20 MB/s, 10 tunnels [R14]. Its SDK
   needs openssl and russh 0.37 [R15], and its outer SSH has a "none" key
   exchange [R13]. Effort: L; a person must log in once.
7. **ngrok**: an authtoken. The agent dials `connect.ngrok-agent.com:443`,
   trusts ngrok's own root only unless `connect_cas: host` is set, and takes
   `proxy_url` [R16]. The free plan gives 1 GB a month, and TCP endpoints
   need a card [R17]; the `ngrok` crate 0.19 uses rustls [R18]. Effort: M;
   the risk is the quota.
8. **Cloudflare's Realtime TURN**: credentials that an account mints, valid
   for 48 h at most [R19]; TURN over TLS on 443/tcp [R20], which is not
   HTTP, so a proxy that re-terminates TLS breaks it (Inferred); UDP only,
   with no RFC 6062 [R19]; drops past 50 to 100 Mbps for one allocation
   [R20]. It needs a TURN client, and QUIC or an adapter on top. Effort: L.
9. **Azure Relay Hybrid Connections, and AWS IoT Secure Tunneling**: made
   for access that goes out only; a cloud account; a WebSocket at both ends
   [R21] [R22]. Azure charges each listener, with 5 GB a month included
   [R23]; AWS gives 800 kbps and 12 h, at $1 for each tunnel [R24] [R25].
   Effort: S to M; the risks are the cost, and AWS is too slow for copies.
10. **An iroh relay or a pair relay in the user's own Cloudflare account**
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
- **ntfy.sh**: 4,096 bytes for each message, 250 a day, and it bans abuse
  [R31].
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

Ruled out:

- **Syncthing's relays**: volunteers, any client, and a specification that
  invites other programs [R32]; but 87 of the pool's 100 relays use port
  22067 and only 8 use 443, each as an IP literal (counted on 2026-11-02,
  Verified [N19]; 88 and 5 on 2026-10-31), and the session mode is
  raw TCP while the protocol mode needs client certificates, so a proxy
  that re-terminates TLS breaks both (Inferred).
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
  repaired defects of onion services [R41].
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
  `serveo.net` "Security threats" (Verified [N8]).
- **bore.pub**: one person runs it, on the control port 7835 and random
  ports [R43]. Read on 2026-11-02: it restarts on purpose and "isn't meant
  for long-lived connections" (its issue 170, 2025-06-24), it was down on
  2026-09-08 (issue 202), and a monitor of a third party reported it down
  for 3 months [N23].
- **zrok**: accounts at both ends, 5 GB a day on the free plan [R44], and
  no SDK in Rust (Inferred).
- **OpenRelay, Metered's TURN**: now a Metered account, with 500 MB free
  (read on 2026-11-02 [N24]); and TURN relays UDP.

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
more than a faster first one.

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
- [N3] https://github.com/MercuryWorkshop/wisp-server-python (v0.8.3)
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
