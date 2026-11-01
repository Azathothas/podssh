# Carriers without the operator's relay

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
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`).
Cloudflare's Self-Serve Subscription Agreement forbids using its services
"to provide a virtual private network or other similar proxy services"
(section 2.2.1(j), [F8]). Whether that holds for the relay is a question
for the relay's operator ([relay-operator.md](relay-operator.md), item 15).

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
   - Terms and limits: SSH through a tunnel is a documented use [F20]. A
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
   - Terms: the Application Terms license "the Application" only, forbid to
     reverse engineer it, and let Cloudflare "block certain kinds of usage"
     [F6].
   - Limits: none published; the registration is rate-limited [F1].
   - Rust and C: no usable library. usque is Go; usque-rs takes quiche,
     whose BoringSSL is C, and a TUN device [F1b]. The mode with no IP stack
     works over QUIC only [F3]. Over HTTP/2, podssh would need HTTP/2's
     extended CONNECT (which T-321 needs too), capsules, and smoltcp, which
     is pure Rust [F31] and which Cloudflare says "does not support modern
     TCP features" [F7].
   - Effort: L. Risks: a closed API that can change at any time, and the
     terms. T-352, after Q52.
   - Built (T-352, drafted 2026-10-31): `warp://HOST[:PORT]`, in a feature
     crate (`crates/podssh-warp/src/lib.rs`), pure Rust. Read in the fork of
     connect-ip-go that usque takes (`client_h2.go`): over HTTP/2 the request
     is a classic CONNECT, `:authority cloudflareaccess.com:443`, with the
     protocol in the header `cf-connect-proto` and no `:protocol`, so it
     needs no extended CONNECT; usque sends `pq-enabled: false` and no
     `User-Agent`. A device is registered once, with the user's acceptance of
     the Terms, and kept in the cache. The live run waits for GitHub Actions
     (Q52).
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
     refuse Tor's exits (Inferred).
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
     the operator (Q60); meek and WebTunnel wait.
6. **A Worker in the user's own Cloudflare account** (class C). It works as
   the relay does, and could serve the split road of T-319 too. The free
   plan gives 100,000 requests a day and 10 ms of CPU for each request
   [F9]; whether a long session meets error 1102 is not documented
   (Inferred). The terms: section 2.2.1(j) [F8]. Effort: S, but podssh ships
   no relay: the relay stays a separate project
   ([decisions.md](decisions.md), Q4 and Q9; T-169).
7. **Other products' WebSocket forwarders** (class A in shape: the
   forwarder dials the target). Read in GitHub #59 and #60, a tester's
   measurement of 2026-10-31 from a host with direct egress, not measured
   here: the Worker of Mudlet's web client (`web-proxy.mudlet.org`, the
   target in its query), an older copy of it (`mudix.delwing.workers.dev`),
   and ssheasy's proxy (`ssheasy.com/p`, the target in a first frame of
   JSON) each gave GitHub's banner. Their sources: `Mudlet/mudlet-web:worker/index.js`
   (Cloudflare's runtime refuses port 25, private addresses and
   Cloudflare's own) and `hullarb/ssheasy:proxy/main.go` (1 GiB at full
   speed, then 100 KiB/s; one connection a second from each address). No
   account, no token; they serve their own products' users and publish no
   limit. podssh's road to a forwarder that the user names is
   `--forwarder` (T-369), with no relay token; by the operator's ruling
   Q56 the binary names the three by a word, and tries them when each relay
   host failed (T-370).
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
  class B, with a relay that podssh does not ship (T-169).
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
3. **Cloudflare's quick tunnel** (T-300).
   - Who, and the account: Cloudflare, for testing and development; no
     account.
   - Through a proxy: the client, yes (`cf://`); the node needs TCP 7844,
     which the measured cage refuses ([design.md](design.md), section 2).
     Inside WARP's tunnel, on port 443, a node reaches it from a cage whose
     proxy takes a CONNECT to an address (T-374, drafted 2026-10-31).
   - Limits: 200 requests in flight; no SLA. Built, pure Rust. Effort: S.
   - Risks: nodes with an open egress only; the protocol is not published,
     and T-339 watches its pin.
4. **Microsoft Dev Tunnels**: a preview, for "adhoc testing and
   development" [R11]. The host logs in with Microsoft or GitHub; a client
   can be anonymous, or use a token of 24 h [R12]. The host opens a
   `tunnel-relay-host` WebSocket, and TLS ends at Microsoft's ingress [R13]
   [R12]. 5 GB for each user a month, 20 MB/s, 10 tunnels [R14]. Its SDK
   needs openssl and russh 0.37 [R15], and its outer SSH has a "none" key
   exchange [R13]. Effort: L; a person must log in once.
5. **ngrok**: an authtoken. The agent dials `connect.ngrok-agent.com:443`,
   trusts ngrok's own root only unless `connect_cas: host` is set, and takes
   `proxy_url` [R16]. The free plan gives 1 GB a month, and TCP endpoints
   need a card [R17]; the `ngrok` crate 0.19 uses rustls [R18]. Effort: M;
   the risk is the quota.
6. **Cloudflare's Realtime TURN**: credentials that an account mints, valid
   for 48 h at most [R19]; TURN over TLS on 443/tcp [R20], which is not
   HTTP, so a proxy that re-terminates TLS breaks it (Inferred); UDP only,
   with no RFC 6062 [R19]; drops past 50 to 100 Mbps for one allocation
   [R20]. It needs a TURN client, and QUIC or an adapter on top. Effort: L.
7. **Azure Relay Hybrid Connections, and AWS IoT Secure Tunneling**: made
   for access that goes out only; a cloud account; a WebSocket at both ends
   [R21] [R22]. Azure charges each listener, with 5 GB a month included
   [R23]; AWS gives 800 kbps and 12 h, at $1 for each tunnel [R24] [R25].
   Effort: S to M; the risks are the cost, and AWS is too slow for copies.
8. **An iroh relay or a pair relay in the user's own Cloudflare account**
   (Workers and Durable Objects): the free plan's 100,000 requests a day,
   with incoming WebSocket messages counted 20 to 1 [R26]. The Worker lives
   outside podssh, as the relay stays a separate project (T-169).

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

Ruled out:

- **Syncthing's relays**: volunteers, any client, and a specification that
  invites other programs [R32]; but 88 of the pool's 100 relays use port
  22067 and only 5 use 443, each as an IP literal, and the session mode is
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
- **Pinggy, localhost.run and serveo**: small operators; the node's leg is
  raw SSH (`ssh -p 443 ... free.pinggy.io`), and Pinggy's free tunnels end
  at 60 minutes [R42]. Raw SSH fails where a proxy waits for TLS
  ([target-environment.md](target-environment.md)).
- **bore.pub**: one person runs it, on the control port 7835 and random
  ports, and it was down in May 2026 [R43].
- **zrok**: accounts at both ends, 5 GB a day on the free plan [R44], and
  no SDK in Rust (Inferred).

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

## Sources

Read on 2026-10-31 through the services of web.pkgforge.dev.

The forward road:

- [F1] https://github.com/Diniboy1123/usque
- [F1b] https://github.com/Diniboy1123/usque-rs (its `Cargo.toml`)
- [F2] https://github.com/Diniboy1123/usque/wiki/HTTP-2-support
- [F3] https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode
- [F4] usque: `api/masque.go`, `internal/consts.go` and `api/cloudflare.go`
- [F5] https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/
- [F6] https://www.cloudflare.com/application/terms/ (last updated
  2024-10-18)
- [F7] https://blog.cloudflare.com/faster-sase-proxy-mode-quic/
- [F8] https://www.cloudflare.com/terms/ (last updated 2025-09-12)
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
