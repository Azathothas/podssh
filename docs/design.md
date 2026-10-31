# Design: the finished podssh

This page gives the design of the finished podssh, and why. It answers five
questions of the operator: can the core be a library for podbox; can podssh
replace podbox, sandssh and dropssh on the most constrained hosts; how
reliable must it be; can it replace socat or tailcat; and is iroh useful.
[ROADMAP.md](ROADMAP.md) gives the order of the work.
[decisions.md](decisions.md) gives what the operator decided.

Each fact has a label:

- **MEASURED**: a test was run.
- **READ**: read in code or in a document.
- **INFERRED**: a conclusion that no test or document confirms.

## 1. The summary

- podssh gets out of a cage better than each sibling project.
- podssh gets into a cage on the reverse road (M4), to a service that runs there; its own SSH server for the cage is M5, which the operator holds (Q32).
- One architecture serves all three needs: a shared C-free relay library
  with several transport roads, a resumable session layer when both ends run
  podssh, and an SSH server in the process for the cage side.

## 2. The architecture

```
                        podssh (one static binary)
  ssh  proxy  pipe  cp  serve  node  operator  doctor  keygen  chat  ts  iroh
   |                       |
   |        podssh-ssh: russh client and server, terminal, SFTP     [C: aws-lc]
   |                       |
   `---- podssh-relay: roads, failover, liveness, resumable sessions,
                       tokens, pairing, node/operator, blocking facade   [no C]
                                    |
   .--------------.-----------------+--------------.-------------.-----------.
 forward road   reverse road      iroh road      direct road   tailscale road
 any public     podssh at both    podssh at both TCP, through  feature ts
 TCP service    ends; resumable   ends; QUIC     HTTPS_PROXY
 (one-sided)    layer on top      [feature, C]
   `--------------`-- podssh-ws: CONNECT proxy, TLS, WebSocket, DNS fallbacks [no C]
```

### Select a road

podssh tries the roads in this order. When two roads are possible, podssh
races them. [carriers.md](carriers.md) studies the carriers that need no relay of the operator's.

| Far end | First | Then | Last |
| --- | --- | --- | --- |
| A podssh node or peer (a name or a ticket) | The iroh road (direct when UDP works, else through a relay) | The reverse road with the resumable layer | None |
| A standard sshd, public | The forward road, with failover across relay hosts | The direct road (`--direct`, or when a probe shows it works; the probe is T-363) | None |
| A standard sshd behind a podssh `roost` (`podssh node NAME --sshd`) | The iroh or reverse road to the roost | The forward road | None |
| A tailnet node | The tailscale road (feature `ts`) | None | None |
| A service that `cloudflared` publishes (`cf://HOST`) | The WebSocket of the tunnel, as `cloudflared access tcp` opens it, through `HTTPS_PROXY` | None | None |
| A VM of the user's on GCP (`iap://PROJECT/ZONE/INSTANCE`) | IAP's WebSocket for TCP, as `gcloud compute start-iap-tunnel` opens it, through `HTTPS_PROXY` | None | None |
| An EC2 instance of the user's (`eice://ENDPOINT/ADDRESS`) | The WebSocket of an EC2 Instance Connect Endpoint, its URL presigned as aws-cli presigns it, through `HTTPS_PROXY` | None | None |

Each road has the same rules:

- one attempt for each host, with a time limit, and a jittered backoff
  across hosts;
- liveness checks at each layer;
- the relay's close reason goes to the user;
- credentials never go on argv, in URLs, or in output;
- each capability is probed before podssh uses it.

**The road of a Cloudflare tunnel (T-264, built 2026-10-11).** `podssh ssh
cf://HOST` and `podssh proxy cf://HOST` open the WebSocket to `wss://HOST/`
that `cloudflared access tcp` opens, with the same upgrade, read in its
source: no relay, and no program of Cloudflare's. The credentials of
Cloudflare Access go in its headers. Each message up is at most 16 KiB, as
the origin cuts a longer one, and podssh sends no Ping, as the origin answers
one outside the lock of its writes; the end of the stream, with no Close, is
the end of the session. MEASURED against a stand-in on the loopback
(`cargo test -p podssh-ws --features plain-ws --test cloudflare_access`); a
live check waits for a service that the operator publishes.

**The roads of a cloud's own tunnel (T-351, built against stand-ins on
2026-10-31).** `podssh ssh iap://PROJECT/ZONE/INSTANCE` and `podssh ssh
eice://ENDPOINT/ADDRESS` reach a VM of the user's through GCP's
Identity-Aware Proxy for TCP and AWS's EC2 Instance Connect Endpoint, each
a WebSocket on port 443 through `HTTPS_PROXY`, with no relay: the VM is then
a jump host (`-J`), a carrier of the forward road that is not the
operator's relay, for a user with a cloud account and no domain
([carriers.md](carriers.md), class B). Each needs the user's account, in a
file that the user names (Q51). IAP's token goes in a header, and IAP's own
messages carry the stream, with acknowledgements and a reconnect that takes
a lost link up, as gcloud does; a service account's key signs its JWT in
aws-lc-rs, in the binary. EICE's URL is presigned with SigV4 and carries the
credential: the one exception to the rule above, made for each connection
and never shown. The protocol code is in `podssh-ws` (`iap`, `eice`), with
no C; the files of the accounts, the JWT and the token's exchange are in
the binary (`crates/podssh-cli/src/ssh/cloud.rs`). Checked against
stand-ins, in memory and on the loopback, that speak each protocol as
gcloud's, IAP Desktop's and aws-cli's sources say, with bytes that gcloud's
own client wrote and URLs that aws-cli's own signer made; the live run
waits for the operator's throwaway accounts (T-376).

**The race (T-164, built 2026-10-10).** `podssh ssh node://NAME
--iroh-ticket TICKET` races the iroh road to the node's ticket and the
reverse road of its pair. The iroh road starts first; the pair's road after
250 ms (`session::race::HEAD_START`, as RFC 8305 gives IPv6 one), or at
once when the iroh road fails before. The first far end that speaks wins,
and the layer's handshake goes on that link alone: the far end dials its
target only when a handshake completes, so the losing link, which never
sends `OPEN`, costs no connection to sshd. Each resume runs the same race.
`podssh node NAME TARGET --iroh` serves both roads when it has the pair,
with one keeper of sessions for both, so a session resumes on either.
MEASURED: the rules on a paused clock with stand-in roads
(`cargo test -p podssh-relay --test session_race`); live, with a pair on the
live relay and iroh's relay server on the loopback, the iroh road won when
both answered, and TARGET saw one connection; with the iroh road pointed at
a silent relay, the pair's road won (`cargo test -p podssh-cli --features
iroh-test --test road_race -- --ignored`).

**The roost (T-166, built 2026-10-12).** A roost is `podssh node NAME
[TARGET] --sshd`: a node in front of a standard sshd, by default
`127.0.0.1:22`, which owns the TCP connection to it, so that a normal
server gets the resumable layer and, with `--iroh`, the iroh road. It is a
flag of `node`, not a command of its own (pigeons' `roost`): a roost is a
node, with the same pair, keys, roads and exit codes. Before it registers,
the roost dials each TARGET and peeks at its first line, which must be
SSH's version line within 10 s, as iroh-ssh checks its sshd; each
session's own connection, made after the layer's handshake, is checked
again. The client keeps sshd's host key under `node://NAME`. MEASURED:
`cargo test -p podssh-cli --test roost` (8 passed, 2026-10-12); the gate's
`scripts/interop-roost.sh` waits for a run (T-251).

### A quick tunnel that podssh makes itself (T-170, research of 2026-10-12)

The question: can podssh publish a service at `https://NAME.trycloudflare.com`
with no account and no `cloudflared`, and can a cage do it? The research read
Cloudflare's documents and the source of cloudflared at `bf4f502` (GitHub
`cloudflare/cloudflared`: main on 2026-10-08, one commit after the tag
2026.10.0, released in 2026.10.1), online. T-299 read each cited file again
at the release 2026.10.6 (commit `35b379a`): each claim holds there, and the
four citations that moved are given here at 2026.10.6. Each fact below is
READ, unless it says otherwise or says measured (T-299, "The edge,
measured"); a path with a line is a file of cloudflared at 2026.10.6.

**The answer.** A quick tunnel needs no account, but its connector must reach
Cloudflare's tunnel edge on port 7844: by QUIC on UDP, or by HTTP/2 over TLS
on TCP. The measured cage allows `CONNECT` to ports 443, 80 and 8443 only,
and no UDP (`docs/target-environment.md`), and the edge's 443 and 8443 serve
no tunnel (measured, below), so a cage's proxy gives no road to the edge. The
relay's VPC road does: TLS to the edge's 7844 through `podssh proxy`
completed (measured, below). A host whose egress reaches TCP port 7844 can
publish a quick tunnel directly, and the edge took one over HTTP/2 (measured
with cloudflared, below). There, podssh would be the connector and the origin
in one process, so nothing listens; and a client in a cage reaches the name
on port 443 through `HTTPS_PROXY`, with the WebSocket of `cf://` (T-264).
T-300 builds the connector over HTTP/2, and T-301 over QUIC: podssh's own
is `crates/podssh-relay/src/quick/` (the Cap'n Proto of the registration by
hand, tested against bytes of `capnp encode`; HTTP/2 with `h2`; QUIC with `noq` and the keys of podssh-ws's own provider), and
`podssh node NAME TARGET --quick-tunnel` (`crates/podssh-cli/src/node_quick.rs`).
Its client is `cf://NAME`, the road of T-264: a far end whose first frame is
the layer's `GREETING` is a podssh node, and the session runs in the layer
with the end-to-end channel above it, a new WebSocket after each lost one
(`crates/podssh-cli/src/ssh/cloudflare/layer.rs`); cloudflared's services
speak SSH first, and their bytes pass on as they are.

**The request for a tunnel.** `cloudflared tunnel --url URL` posts to
`https://api.trycloudflare.com/tunnel`, the default of a hidden flag
(`cmd/cloudflared/tunnel/cmd.go:866-871`), with `Content-Type:
application/json`, cloudflared's `User-Agent` and an empty body
(`cmd/cloudflared/tunnel/quick_tunnel.go:144-150`). It waits 15 s, and reads
1 MiB of the reply at most (`quick_tunnel.go:24`, `quick_tunnel.go:32`). The
JSON reply has `success`, `errors` (each a code and a message) and `result`:
`id` (a UUID), `name`, `hostname`, `account_tag` and `secret`, bytes that Go
writes in base64 (`quick_tunnel.go:262-287`). The id, the account tag and the
secret are the tunnel's credentials (`quick_tunnel.go:182-186`): podssh would
keep the secret as it keeps a token, never shown. cloudflared's HTTP client
for this request has no proxy setting, so it goes direct, never through
`HTTPS_PROXY` (`quick_tunnel.go:137-143`; measured: a proxy in
`HTTPS_PROXY` saw nothing, T-299). The API took the same request through a
CONNECT proxy with another `User-Agent` (measured, below). The body `{"auth_mode":"otp"}`
asks for a protected tunnel, whose visitors get a one-time PIN by mail
(`--allowed-mail`; `quick_tunnel.go:28-44`); that needs a browser, so podssh
has no use for it.

**What Cloudflare promises.** A quick tunnel has a new name each time, needs
no account, takes 200 requests in flight at most (more get `429`), carries no
Server-Sent Events, has no uptime guarantee, and is for testing and
development (Cloudflare, "Quick Tunnels",
https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/, updated
2026-09-30). cloudflared's own notice adds that such tunnels fall under
Cloudflare's Online Services Terms of Use (`quick_tunnel.go:26`). Those terms
(https://www.cloudflare.com/website-terms/, effective 2025-08-01) do not name
Tunnel. Their section 7 forbids going around a limit of the services, and
obtaining "materials or information" by "any means not intentionally made
available through the Websites or Online Services": the clause is about what
one obtains, not about the client (READ again on 2026-10-30, T-299). The
Self-Serve Subscription Agreement has no such clause, and binds the users of
an account; an account-less quick tunnel falls under the Online Services
Terms, which cloudflared's notice names (INFERRED). No clause that the
research read names another client. Whether a connector of podssh's own is a
forbidden means is the operator's call (Q43). A limit on how often a tunnel can be made: not documented, not
verified. cloudflared makes one connection for a quick tunnel, where a named
tunnel makes four (`quick_tunnel.go:221-223`, `cmd.go:781-785`). The
protocol below is not a published contract: cloudflared is its only
documented client, so podssh would pin it, as it pins the relay's.

**Where the edge is.** cloudflared looks up the SRV record
`_v2-origintunneld._tcp.argotunnel.com` (`us-v2-origintunneld` with
`--region us`) with the system's resolver, then with DNS over TLS to
1.1.1.1:853 (`edgediscovery/allregions/discovery.go:16-26`,
`discovery.go:112-132`, `edgediscovery/allregions/regions.go:138-144`). The
record must give two regions, and gives their port
(`edgediscovery/allregions/regions.go:21-34`, `discovery.go:172-193`).
Cloudflare's documents name them `region1.v2.argotunnel.com` and
`region2.v2.argotunnel.com`, each with ten IPv4 and ten IPv6 addresses, on
port 7844 for TCP and UDP; port 443 serves optional things only (updates,
`api.cloudflare.com`, a TXT record of features), and a tunnel runs without
them ("Configuration", https://developers.cloudflare.com/tunnel/configuration/,
updated 2026-09-29). A hidden flag, `--edge`, replaces the lookup with given
addresses, and its help says that it works only in Cloudflare's own test
environment (`cmd.go:668-673`, `supervisor/supervisor.go:56-64`). podssh's
DNS over HTTPS asked for A and AAAA records only before T-339; the
connector needs SRV, or the two documented names. Since T-339, the node of
`podssh node --quick-tunnel` asks for the SRV record over DNS over HTTPS,
through the proxy when one is set (`podssh_ws::resolve::doh_srv`, in RFC
8484's wire form too since T-344), and takes its two targets and port when
the record names two regions under `argotunnel.com` on one port; else
the two documented names and port 7844, and the node says why once a run.

**No proxy.** cloudflared dials the edge with a plain dialer, never through a
proxy (`edgediscovery/dial.go:13-42`; measured: a proxy in `HTTPS_PROXY` saw
no line from it over HTTP/2 or QUIC, T-299). The request for proxy support
(GitHub cloudflare/cloudflared#350) was closed on 2023-09-05 by a maintainer:
the project does not want it, and QUIC, not HTTP/2, is the transport that it
means users to have; cloudflare/cloudflared#1025 says the same ("the
official transport to use should be QUIC, which wouldn't work for the SOCKS
proxy"). QUIC is UDP, so it cannot use an HTTP CONNECT proxy (INFERRED);
HTTP/2 can, through a proxy that allows `CONNECT` to 7844 (measured, below).
Third-party patches exist: a pull request for SOCKS5, closed unmerged in 2023;
`AlliotTech/cloudflared_proxy`, SOCKS5 with HTTP/2 forced, which notes proxies
that choke on a client hello with ML-KEM; a patch of the snap for an HTTP
proxy. None is a result for quick tunnels. Port 443 of the edge is no
fallback: the documents call it optional, the code has none, and it serves
no tunnel's TLS (measured, below).

**The two transports.** Both use TLS, with Cloudflare's own roots added to
the system's (`tlsconfig/origin_ca.go:76-104`, `tlsconfig/cloudflare_ca.go`).

| | HTTP/2 | QUIC |
| --- | --- | --- |
| Carrier | TLS over TCP, port 7844 | QUIC over UDP, port 7844 |
| TLS name, ALPN | `h2.cftunnel.com`, no ALPN | `quic.cftunnel.com`, `argotunnel` (`connection/protocol.go:9-21`, `protocol.go:58-72`) |
| Roles | cloudflared runs an HTTP/2 server on the connection that it dialed; the edge is the HTTP/2 client (`connection/http2.go:53-97`; measured: the edge sends the client preface, T-299) | The edge opens a stream for each request (`connection/quic_connection.go:170-201`) |
| The control stream | The edge's request with `Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream` (`http2.go:26-32`, `http2.go:405-407`) | The first stream, which cloudflared opens (`quic_connection.go:89-96`) |
| A request | An HTTP/2 stream; the same header says `websocket`, and `Cf-Cloudflared-Proxy-Src` marks raw TCP (`http2.go:377-420`) | Six bytes that name the kind of stream, the version `01`, then a Cap'n Proto `ConnectRequest`: a destination, a type (http, websocket or tcp) and headers as metadata (`tunnelrpc/quic/protocol.go:8-29`, `tunnelrpc/proto/quic_metadata_protocol.capnp:8-28`) |
| The answer | The status, a 101 sent as 200, and the origin's headers in the one header `Cf-Cloudflared-Response-Headers`, each name and value in base64 with no padding (`http2.go:238-286`, `connection/header.go:50-112`) | The same six bytes and version, then a `ConnectResponse`: an error and metadata (`tunnelrpc/quic/request_server_stream.go:35-58`) |
| Datagrams | None | On, for the UDP and ICMP of private networks (`connection/quic_config.go:20-38`, called at `supervisor/tunnel.go:589-590`) |

A quick tunnel sets the protocol to `quic` when none is named
(`quick_tunnel.go:217-219`), and a protocol that is set has no fallback:
only `auto`, the default of a named tunnel, falls back
(`protocol.go:117-137`). So a quick tunnel uses QUIC alone, and
`--protocol http2` makes one over TCP.
The edge takes a quick tunnel over HTTP/2, which no document says: measured
with cloudflared (T-299, below).

**The registration.** On the control stream, cloudflared is a client of
Cap'n Proto RPC with the standard framing of a stream
(`tunnelrpc/utils.go:55-61`, `tunnelrpc/registration_client.go:36-45`). It
calls the edge's `registerConnection` with the account tag and the secret,
the tunnel's id, the index of the connection, and its options: a client id,
a list of features, its version and its platform
(`tunnelrpc/proto/tunnelrpc.capnp:113-169`). The answer is an error, with
whether and when to try again, or the details: an id of the connection, the
data center, and whether the tunnel is managed remotely
(`tunnelrpc.capnp:137-158`). A tunnel that is not managed remotely then
sends its ingress rules as JSON (`updateLocalConfiguration`;
`connection/control.go:108-119`), and `unregisterConnection` ends the
connection (`control.go:124-147`). At 2026.10.6 the default features
include `serialized_headers` (`features/features.go:5-25`), the form of the
answers of HTTP/2 above. Since commit `77a79bf` (TUN-10904, 2026-10-29),
in the release 2026.10.7 of 2026-10-30 (read 2026-10-31), the edge
"universally supports the legacy default features": `serialized_headers`,
`quick_reconnects`, `allow_remote_config`, `support_quic_eof` and
`management_logs` are deprecated and filtered, and registration names
`support_datagram_v3_2` only when datagram v3 is chosen. There the default
list is empty, and the answers of HTTP/2 carry the serialized header always.
podssh names the five on, as 2026.10.6 does, which the edge takes from each
release that it supports. A weekly workflow, `upstream.yml`, compares
cloudflared's newest release with the pin's table
(`crates/podssh-relay/src/quick/cloudflared-pin.txt`: the tag, the commit,
the day, and the SHA-256 of the four files of the protocol at the pin, and
of a later release where a person read its change and judged it the same):
it fails when one of the files moved, or the pin is 9 months old, and names
each file (T-339). The edge's refusals, and its answers that podssh does
not read, name the release that podssh speaks.

**A WebSocket through the tunnel.** For an HTTP origin, cloudflared sends the
upgrade on to the origin, and after its 101 copies the stream's bytes both
ways, unchanged (`proxy/proxy.go:234-321`). So the frames of the visitor's
WebSocket reach the origin (INFERRED from cloudflared's side; that the edge
passes them unchanged is not verified). podssh, as the origin in the same
process, would answer the upgrade itself and run the resumable layer over the
WebSocket; its client is the road of T-264, with no credential of Access,
since a quick tunnel has none.

**What podssh needs, with no C:**

- HTTP/2: `h2` 0.4.19 is in `Cargo.lock` already, through hyper (READ); it
  serves a connection that its caller dialed, as cloudflared does.
- Cap'n Proto: the crates `capnp` and `capnp-rpc` (0.27, MIT,
  https://github.com/capnproto/capnproto-rust). Their code generator needs
  the `capnp` tool, which is C++ (docs.rs, capnpc 0.27.0), so the generated
  code would be committed, or the few messages written by hand. That this RPC
  and cloudflared's (`zombiezen.com/go/capnproto2`) agree on the wire: not
  verified.
- TLS: podssh's own provider (`crates/podssh-ws/src/tls.rs`), with a trust
  store that holds the root of the edge's certificate: "CloudFlare Origin SSL
  ECC Certificate Authority", one of cloudflared's three, signs it, and no
  root of the system does (measured, below). cloudflared offers
  X25519MLKEM768, P256Kyber768Draft00 and P-256, and no X25519
  (`cloudflare/cloudflared:crypto/curves.go`, and its log); podssh's TLS
  offers X25519 and secp256r1 with no ML-KEM
  (`crates/podssh-ws/src/crypto/kx.rs`), and the edge took a classical
  handshake with each (measured, below).
- The prechecks of cloudflared at startup
  (`cloudflare/cloudflared:prechecks/probes.go`: for each region DNS, QUIC,
  TCP and TLS, 5 s each, and TCP to `api.cloudflare.com:443`; off with
  `--no-prechecks`) use the name `probe.cftunnel.com`, which the edge took,
  and log the table "CONNECTIVITY PRE-CHECKS" (measured, below). The edge's
  requests include the kind `update-configuration`, and a hidden flag,
  `--cacert`, replaces the roots of the edge's connection (READ).
- QUIC: only after a UDP probe, as on the iroh road (section 7). A QUIC
  connection binds a UDP socket (`connection/quic.go:24-95`).
- The egress to port 7844: direct TCP where a probe allows it; through a
  proxy only where it allows `CONNECT` to 7844; through the relay's forward
  road, whose VPC road reached the edge's 7844 and carried its TLS (T-299,
  below). Its direct road refuses Cloudflare's ranges
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:224-227`).

Two connectors in Rust exist; neither was run here. libcfd (GitHub
`apersomany/libcfd`, 0.3.0 on 2026-10-30) says that it makes quick tunnels
over QUIC (quinn or quiche) and HTTP/2, with an RPC written by hand ("it does
not use `capnp-rpc`"); its repository has no license that GitHub detects.
`lordmacu/cloudflare-quick-tunnel-rs` makes them over QUIC only (quinn 0.11
and rustls), with generated Cap'n Proto code committed, cloudflared's schemas
and the three roots; GitHub says Apache-2.0, and its README says MIT or
Apache-2.0. podssh copies from neither without reading its license again
(READ in their repositories on 2026-10-30, T-299).

#### The edge, measured (T-299, 2026-10-30)

Measured from a GitHub-hosted runner with the operator's leave (Q43), by the
workflow quick tunnel edge (`.github/workflows/quick-tunnel-edge.yml`, with
`scripts/quick-tunnel-edge.py`): run 41071742798 at 14:29 UTC
(https://github.com/Azathothas/podssh/actions/runs/41071742798), on the
image ubuntu24 20261026.354.1 with OpenSSL 3.0.13 and cloudflared 2026.10.6,
whose sha256 (`1d356dac…462d`) matched its release page. A runner has open
egress: it shows what the edge takes. The box's proxy
(`scripts/box/proxy.py`) stands for the policy of the measured cage; no cage
was measured. Three tunnels were made, each alive for less than 15 s, and no
request met a 429.

**Where the edge is.** Over DNS over HTTPS, the SRV record
`_v2-origintunneld._tcp.argotunnel.com` gave `region1.v2.argotunnel.com`
(priority 1) and `region2.v2.argotunnel.com` (priority 2), both on port 7844.
Each name had ten IPv4 addresses (198.41.192.7 to .227 and 198.41.200.13 to
.233), and region1 had ten IPv6 ones (2606:4700:a0::1 to ::10, as curl
resolved them).

**The ports and TLS, direct.** `openssl s_client` with the three roots of
cloudflared (`tlsconfig/cloudflare_ca.go` at the tag) and
`-verify_return_error`, to 198.41.192.7, 198.41.200.13 and 198.41.192.47
(the first of the SRV answer), each with the same result:

| Port | TCP | TLS with the name `h2.cftunnel.com` |
| --- | --- | --- |
| 7844 | connected | TLS 1.3, verified, in 21 to 58 ms; the same with the names `probe.cftunnel.com` and `region1.v2.argotunnel.com`, and with no name |
| 443 | connected | failed. Through the proxy to the name, Python's ssl said "unable to get local issuer certificate": the certificate there does not chain to cloudflared's roots (Inferred for the direct cells, whose cause openssl's summary did not give) |
| 8443 | connected | failed, as on 443 |
| 80 | connected | not TLS ("wrong version number") |

On 7844 the edge took the default groups (it chose X25519), X25519 alone and
P-256 alone: a classical handshake, with no ML-KEM, passes. It chose no ALPN
when offered `h2`, and none when offered nothing. The leaf is "CloudFlare
Origin Certificate" (O = CloudFlare, Inc., OU = CloudFlare Origin CA),
issued by "CloudFlare Origin SSL ECC Certificate Authority", one of the three
roots, and valid from 2023-12-13 to 2038-12-09. The system's roots do not
verify it (curl: "unable to get local issuer certificate"). Python's check of
the name passed for `h2.cftunnel.com`; curl's failed for
`region1.v2.argotunnel.com`. After the handshake and this side's HTTP/2
preface, the first bytes that the edge sent were `PRI * HTT`, the start of
HTTP/2's client preface: the edge is the client on the connection that the
connector dialed, as `connection/http2.go` reads.

**Through the box's proxy.** `CONNECT region1.v2.argotunnel.com:7844` got
`403 not on the egress allowlist`. 443 and 8443 got 200, and TLS then failed
as above. With 7844 let through (`--allow
region1.v2.argotunnel.com:7844=198.41.192.7:7844`), TLS 1.3 to the edge
verified through the proxy. So a proxy that allows CONNECT to 7844 carries
the edge's TLS. The measured cage's policy does not allow it, and the ports
that it allows serve no tunnel.

**The request for a tunnel.** `POST https://api.trycloudflare.com/tunnel`
through the box's proxy (a CONNECT to 443, which its policy allows), with the
User-Agent `podssh-measurement/T-299`, not cloudflared's: HTTP 200 in 3057
ms. The reply holds `success` (a boolean), `errors` (an empty list) and
`result`, with `id` (36 characters), `name` (35), `hostname` (48),
`account_tag` (32) and `secret` (44, the base64 of 32 bytes: Inferred from
the length), and no `messages`. The hostname is four words joined by hyphens,
under `trycloudflare.com`. No value was printed.

**cloudflared, as a reference.** Two runs in front of a page on 127.0.0.1,
each with `HTTPS_PROXY` set to the box's proxy and `--edge-ip-version 4`:

| | Run A: `--protocol http2` | Run B: no `--protocol` |
| --- | --- | --- |
| The request for the tunnel | 5 s | 3 s |
| Registered | 5 s after the start, at `msp01` through 198.41.192.47, `protocol=http2` | 4 s after the start, at `ord07` through 198.41.200.73, `protocol=quic` |
| The page through the name (curl, DNS over HTTPS) | at the 4th try, 12 s after the start | at the 2nd try, 7 s after the start |
| After SIGTERM | "Unregistered tunnel connection", then the end | "Retrying connection in up to 2s", then the end |
| Lines in the proxy's log | none | none |

So a quick tunnel registers over HTTP/2, and serves. cloudflared sent
nothing through `HTTPS_PROXY`: not the request, not the prechecks, not the
edge. Each run logged `ha-connections:1` and "Tunnel connection curve
preferences: [X25519MLKEM768 CurveID(65074) CurveP256]" (65074 is 0xFE32,
P256Kyber768Draft00 in IANA's registry: Inferred from the number). In the
table "CONNECTIVITY PRE-CHECKS" of both runs, each line passed: DNS of both
regions, "QUIC connection successful" (UDP) and "HTTP/2 connection
successful" (TCP) to both, and `api.cloudflare.com:443`. Its summary named
the protocol that the run then used.

**The relay's roads.** Run 41072705691 at 14:35 UTC
(https://github.com/Azathothas/podssh/actions/runs/41072705691), with podssh
built from `fb712a2` in the job and the live relay (`tcp.ssh.relay.ajam.dev`,
version 2026-10-03-r2), which mints its own token. `podssh relay trace` to
198.41.192.7, 198.41.200.13 and `region1.v2.argotunnel.com` on 7844, and to
198.41.192.7 on 443, gave for each `ok: true` on the road `vpc`, the address
dialed as a literal (the name gave 198.41.192.77), and the verdict
`silent-or-unreachable`. A TLS server sends nothing first, and on this road
a trace does not tell an open port from a closed one
([relay.md](relay.md)). Then TLS with `h2.cftunnel.com` and cloudflared's
roots, over `podssh proxy` to the same three targets on 7844 (the relay's
forward road): TLS 1.3, verified, no ALPN, in 525 to 617 ms, after which the
edge sent HTTP/2's client preface. So the relay's VPC road carries a
connector's TCP to the edge, and a client that reaches the relay on 443
reaches the edge's 7844, where the cage's proxy refuses it. The direct road
was not tried: it refuses Cloudflare's ranges ([relay.md](relay.md)), and
podssh does not choose the road.

**Not tried, and why.** QUIC from a client of podssh's own (the plan's
`aioquic` client): the prechecks show that a runner reaches UDP 7844, and a
cage has no UDP. A WebSocket through the name: T-300's tests carry one. The
bytes of a registration: they hold the tunnel's secret, so their capture
waits for the operator's machine (item 5 of T-299's Approach).

## 3. The core as a library for podbox

podbox is the container runtime that podssh grew out of (HEAD `452d792`). It
needs the reverse legs of the relay: a node in the sandbox registers at
`/v1/node/NAME`, and an operator outside connects to it.

Facts about podbox (READ):

- Its own implementation of the reverse legs works live: two sessions at
  the same time over the live relay (2026-09-28).
- It has no support for an HTTPS proxy. It connects to the relay directly,
  so its node cannot reach the relay from a sandbox whose only egress is an
  HTTP proxy (`podbox-ssh/src/mux.rs`).
- It is synchronous (no async runtime). It allows a C compiler (it builds
  `ring`). Its MSRV is 1.85. It measures the size cost of each dependency.
- It is made for TLS-intercepting proxies, which often present RSA
  certificates or TLS 1.2.

**What exists (2026-10-09).** The C-free crate `podssh-relay` gives relay
selection, the pool, failover, tokens (mint, cache, mint again) and the
forward opener. `podssh-ws` gives CONNECT dialing with `NO_PROXY`, verified
TLS with RSA, the DNS fallbacks, the WebSocket upgrade with typed errors that
keep the relay's status and reason, and `RelaySession`, which keeps text and
binary frames apart as the reverse protocol needs.

The facade for podbox (`podssh_relay::blocking`, feature `blocking`, T-081)
is a `Client` that owns a tokio runtime on the current thread and blocks on
it; no tokio type is in its API. It makes, asks about and stops pairs; runs
a node whose handler opens each session as a `std::io` reader and writer;
runs an operator session over a reader and a writer, such as standard input
and output; and opens a forward session as a `Read + Write` stream. Two
threads carry each session, so a blocking read stalls no other session. A
call from a thread that runs a tokio runtime is refused, and nothing panics.
Its offline tests run against a stand-in relay over plain `ws://` (feature
`plain-ws`), as podbox's can. The library crates declare Rust 1.89, the
minimum of their dependencies: by the operator's ruling of Q48
(2026-10-31), no older minimum of an embedder holds a dependency back, so
podbox builds them with Rust 1.89 or later. The gate checks them on it.

**What podbox needs (milestone M4), and what of it exists:**

```
podssh-relay
  pair       pair / stop / status                    [feature pair: T-078]
  reverse    node::run(handler) and operator::run(io): one writer, ready
             before data, late bytes dropped, a limited queue before ready,
             liveness pings, actions for close codes (409 exit, 1001 stopped,
             expiry -> a re-pair hook), jittered backoff  [T-079, T-080]
  session    the resumable stream layer (section 5)
  blocking   a synchronous facade that owns a current-thread runtime
                                                   [feature blocking: T-081]
```

- `podssh-ws`: a `rustls::ClientConfig` that the caller supplies (so podbox
  can keep `ring` and TLS 1.2; `Trust::caller`, T-066), plain `ws://` on
  loopback for tests (feature `plain-ws`, T-068), typed session errors
  (`SessionError`, T-069), and no verifier that accepts each certificate
  (T-065 moved `PrintChain` to an example).
- `podssh-transport` moved into `podssh-relay`, and its unused backpressure
  module went (T-082, 2026-10-09).
- podbox then pins `podssh-relay` by git revision and removes its own
  `ws.rs`, `tls.rs`, its direct dial and its pairing through curl.

## 4. Constrained hosts, and the sibling projects

To get out of a cage, podssh is ready now. To get into one, it has M4 and needs
M5. Getting into the cage was the main job of sandssh and dropssh.

The sibling projects (READ in their code):

| | sandssh (Python) | dropssh (C) | sandhome (POSIX sh) |
| --- | --- | --- | --- |
| Job | SSH into the cage, one session for each dial, its own relay | Multiplexed SSH into the cage over the reverse path of the ajam relay | A development environment in the cage |
| Needs in the cage | python3, a patched dynamic dropbear, cc for `fakepwd.so` | A static binary, a patched dropbear, `/bin/sh` | sh, curl or wget, cc for its shims |
| Shims | `fakepwd`, `fakepty` (LD_PRELOAD), dropbear patches | dropbear patches (`-Y` passwd file, setgroups, pipe and AF_UNIX peers, `/etc/shells`) | Seven LD_PRELOAD shims (pty, passwd, ptrace, GPU, input, X11, Wayland), the `errandsh` line discipline, memfd exec |
| Known defects | Exits 1 on each clean close (MEASURED). An idle node dials again every 15 s, and the relay pairs operators with dead registrations (MEASURED). | Exits 0 after 1003 or 1009. Retries 409 forever. Tokens on argv. | Ctrl-C cannot stop a running command under `errandsh`. |

podssh now replaces `sandssh connect` and `dropssh connect`: one static
binary, no OpenSSH, no Python, no shims, correct exit codes, tokens never on
argv, and tests against real servers. podssh also has, since 2026-10-08:
`podssh doctor`, `podssh keygen`, pinned addresses and DNS over HTTPS, and a
box like the target sandbox for tests.

What podssh needs to get into a cage, in order of importance. Item 1 is built (M4), item 5
is done (T-001), `podssh cp` of item 4 is built, and `podssh serve` is held (Q32):
1. **A reverse node and operator** with the measured rules of dropssh
   (section 3).
2. **An SSH server in the process for the node** (`podssh serve`): the
   server side of russh. It runs as the user that the sandbox gives, with no
   passwd entry, setgroups, chroot, `/etc/shells` or `/var`. The host key is
   in a state file. Authorized keys come from a flag or a file. This
   replaces dropbear and each patch of the siblings.
3. **A terminal on the server side for cages with no `/dev/ptmx`**: a real
   pty when one exists; else a tty that podssh makes when a probe allows it
   (T-248); else a line discipline in the process that also *signals the
   process group of the child* on Ctrl-C. Only the server side
   can do this, and `errandsh` cannot.
4. **File copy with no scp, sftp-server or rsync**: an SFTP server in
   `podssh serve`, and `podssh cp` with an exec transfer (cat and base64) as
   the fallback for minimal servers. In chunks, verified by digest,
   resumable from an offset, and aware of the relay's limits (64 MiB and
   12 h for each session).
5. **A run in a real sealed sandbox.** Each sibling records one. podssh
   passes in a box like the sandbox, and in two real sandboxes (T-001).

The job of sandhome (to make third-party programs work in the cage with
LD_PRELOAD shims and toolchains) is not in the scope of podssh, because of
the decision "no LD_PRELOAD". podssh goes the other way: use the cage as a
thin client and work on a real host over `podssh ssh -tt`, or give the cage a
usable shell through `podssh serve`.

## 5. Reliability: jitter, latency, drops, reconnections, changed addresses

### What podssh does now (2026-10-08)

| Failure | What podssh does |
| --- | --- |
| A relay host is down, refuses, or is behind a proxy 5xx | Fails over to the next host: the default host and up to three hosts of the pool, or the user's list. Each attempt has a limit of 45 s. |
| No proxy and no DNS | Uses an IP literal, a pinned address, the system resolver, then DNS over HTTPS by IP literal |
| Latency | 60 s for the SSH handshake; 30 s for a pty or exec reply; 30 s for each SFTP reply with no file data, and 60 s for an SFTP read or write (T-133) |
| A silent link | A ping every 10 s; dead after three checks with no frame (30 to 40 s). To a node, the resumable layer's heartbeat too: a link with nothing from the far end for 30 s is dead, and a new one replaces it (T-154) |
| A stuck write | Fails after 60 s with no progress, on the relay road (the relay leg's limit) and with `--direct` (a writer around the TCP stream, T-227); the session ends with 255 |
| The relay's idle cut | Keepalives every 60 s keep the session (MEASURED: 602 s with keepalives; cut at 184 s without). To a node, the layer's records each 10 s keep it, and SSH sends no keepalive unless asked (T-154) |
| The relay's limits (12 h, 64 MiB) | The session ends, with the reason. To a node, the session moves to a new link before them, at 48 MiB or 11 h (T-155) |
| A dropped connection | On the forward road, the session ends; `ssh` prints the relay's reason and exits 255; with `--persist`, it connects again and attaches the same tmux session on the server (T-178), and with `--persist -N` it connects again and asks for the forwards again (T-042). `cp` and `mv` go on over a new connection, at the offset of the copy, 5 times in a row at most with no new byte (T-136). To a node (`ssh node://`, `operator`), the resumable layer carries the session onto a new link, for 10 minutes (T-153) |
| A changed client address | The session is lost. With `--direct`, `PODSSH_MPTCP=yes` asks Linux for Multipath TCP (T-172): where the server speaks it and the host's path manager has an endpoint on each network, the connection can go on over the other network when one goes; elsewhere, and through a proxy, the connection is plain TCP, and `-v` says which. Not measured yet, and waiting for T-251 and two networks of the operator's: a session to such a server with one of two networks taken down, and whether Cloudflare's edge, so the relay's road, takes MPTCP (`cargo test -p podssh-ws --test mptcp -- --ignored`). Recommendation: on request and on `--direct` only, until both are measured; where both ends run podssh, the resumable layer carries a session to a new address on any road (T-153) |

The relay has no resumption on either path (READ, in the relay's source and
contract). When the WebSocket closes, the relay closes the TCP connection to
the target within 15 s. When a reverse node connects again, each operator
session on it ends.

### The design: three layers

1. **Each connection attempt is redundant** (done in M3): an ordered list of
   relay hosts, a jittered backoff, a limit for each attempt, failover on
   dial errors, proxy 5xx and refused upgrades, `ConnectionAttempts`, and
   pings that find a dead link in seconds. To add: a race between roads when
   two are possible.
2. **When both ends run podssh, a session survives a drop** (M6). A
   resumable stream layer under SSH, as in Eternal Terminal:
   - each direction carries byte offsets, and the receiver acknowledges;
   - the sender keeps the bytes that are not acknowledged in a limited
     replay buffer (4 to 16 MiB, with backpressure when it is full);
   - the first connection sets a session id and a 256-bit resume secret;
   - after a loss, the client connects again through any road and any relay
     host, proves the secret, and each side sends again from the other's
     offset;
   - a heartbeat every 10 to 15 s counts as payload, so it also prevents the
     relay's idle cut;
   - before the limit of 64 MiB or 12 h, the session moves to a new relay
     connection.

   The far end is `podssh serve` or `podssh node` in a cage, or a podssh next
   to a standard sshd. That podssh owns the TCP connection to sshd, so a
   standard server also gets a session that survives a change of the
   client's network. The cost is about 1000 to 2000 lines.
3. **When only one end runs podssh** (a standard sshd behind the forward
   road), nothing can keep the TCP connection to sshd without help from the
   relay. The options, the least costly first:
   - automatic reconnection with a new authentication, and `tmux new -A` to
     attach again for interactive sessions (only on request; tmux is probed,
     never assumed): `podssh ssh --persist` since T-178, and for a
     tunnel of `-N`, a new connection that asks for its forwards again,
     since T-042;
   - a podssh that the user installed on the server: `podssh ssh --upgrade`
     (T-167) logs in, starts a temporary node there in that SSH session (a
     roost, whose pair's token comes back in the SSH channel), and logs in
     again through it, so the session gets layer 2; with no podssh there,
     the session stays, with one note, and nothing is copied to the server;
   - a relay feature: a Durable Object that owns the target socket across
     client reconnections, a resume token in the `101` response, and offset
     framing as a protocol version that the client selects. This is a
     project of the relay's operator, and it costs Durable Object time for
     the whole session.

An interactive echo for high latency (as mosh does) is a later option on top
of layer 2. It needs podssh at both ends, and it cannot use UDP here.

The fault-injection harness in the gate (`scripts/interop-faults.sh`) tests
layer 1. Layers 2 and 3 need it extended: latency, jitter, limited
bandwidth, a changed address.

### The functions of Mosh, and where podssh gives each (T-171, research of 2026-10-12)

Mosh is a remote shell over UDP. Its sources here: the paper (K. Winstein
and H. Balakrishnan, "Mosh: An Interactive Remote Shell for Mobile Clients",
USENIX ATC 2012, https://mosh.org/mosh-paper.pdf), https://mosh.org, and its
source at `decd9b7` (GitHub `mobile-shell/mosh`; the last release is 1.4.0,
of 2022-10-27), read online. podssh runs no `mosh-server`
(`docs/decisions.md`, 2026-10-08), and copies no code of Mosh, whose license
is the GPL. Each fact below is READ; nothing was measured in this research.
A path with a line is a file of Mosh.

**The difference of layers.** Mosh moves the screen; podssh moves bytes.
Mosh's server runs a terminal emulator, and sends the client the state of
the screen (paper §2, §3). podssh's layer runs under SSH, so it carries
SSH's bytes, and only the end that runs the SSH server sees the bytes of the
pty in clear. So a function of the screen needs `podssh serve` at the far
end (T-107, T-110, which the operator holds), or a model of the screen on
the client (T-160). A node in front of a standard sshd can give the
functions of bytes only.

| Function of Mosh | In Mosh | In podssh |
| --- | --- | --- |
| Roaming | The server sends to the address of the newest authentic datagram (paper §2.2; `src/network/network.cc:482-487`, `src/network/network.cc:522-529`); the client takes a new source port after 10 s with no round trip (`src/network/network.h:146`, `src/network/network.cc:396-397`) | A resume over a new link, through any road (T-153), measured with a new address (T-156). A silent old link is found dead after 30 s (`crates/podssh-relay/src/session/pump.rs:60`); a spare link beside it opens once a question waited 3 s with no answer, or after 20 s of quiet, and takes the session when its far end greets first (T-305) |
| Outages and sleep | The server keeps the session until its client comes back; `MOSH_SERVER_NETWORK_TMOUT` sets a limit, none by default (`src/frontend/mosh-server.cc:394-406`) | 10 minutes (`crates/podssh-relay/src/session/resume.rs:44`, T-153), or the node's `--resume-deadline`, 72 h at most, which it names to its client (T-306); a shell that `podssh serve` keeps longer (T-159) |
| A heartbeat | An empty acknowledgement each 3 s, which also keeps a NAT's mapping (paper §2.3; `src/network/transportsender.h:51`) | Each 10 s on the layer (T-154; `crates/podssh-relay/src/session/pump.rs:57`); SSH's keepalives on the forward road |
| Local echo | Each key is predicted; the predictions of an epoch show once one of them is confirmed; by default they show when the round trip passes 30 ms, or a prediction waited 250 ms, and are underlined past 80 ms (paper §3.2; `src/frontend/terminaloverlay.h:215-225`) | T-160, on request, above 120 ms |
| The echo's acknowledgement | The server marks the last key that the program has had for 50 ms, so the client knows when its echo is due (paper §3.2) | T-160, item 3: the far end reports the offset of the input that reached the pty |
| The latest screen, not each byte | Frames of the difference of screens, at most one each half round trip (20 to 250 ms), after 8 ms of collection, so Ctrl-C stops a flood within a round trip (paper §2.3; `src/network/transportsender.h:49-50`, `src/network/transportsender-impl.h:55-71`) | T-303, on request, to `podssh serve` |
| No head-of-line blocking | Each datagram is an idempotent difference from a numbered state, so a lost one costs only itself (paper §2.2) | The iroh road carries a stream (T-162); datagrams: T-304 |
| Congestion | A smoothed round trip and a timeout of 50 ms to 1 s, as TCP computes them; ECN slows the sender (`src/network/network.h:139-140`, `src/network/network.cc:461-500`) | TCP or QUIC under the layer; a rate limit for copies (T-145) |
| A notice of silence | A line at the top after 6.5 s with no word from the server, or 10 s with no acknowledged state, drawn over its own model of the screen (`src/frontend/terminaloverlay.h:159-161`, `src/frontend/terminaloverlay.cc:204-218`) | A line on stderr at a loss and at a resume (`crates/podssh-cli/src/layered.rs:407`, `crates/podssh-cli/src/layered.rs:418`); with the layer, a notice once a question waited 5 s with no answer, counting up: in the window's title, saved on the terminal's stack of titles and taken back, so the screen is not touched, where the terminal is known to keep that stack; a line with no pty (T-302, `docs/terminal.md`) |
| A new client | Only the client process that holds the key comes back (paper §2.1; GitHub mobile-shell/mosh#394); mosh.org suggests screen or tmux | T-158 and T-159 attach from a new process; T-161 gives the screen |
| Encryption | AES-128 in OCB mode, with a key that SSH carries (paper §2.2) | SSH, and the Noise channel above the layer (T-088) |
| The start | SSH runs `mosh-server`, which prints a port and a key, then forks (`src/frontend/mosh-server.cc:450-462`); it listens on a UDP port of 60001 to 60999 (`src/network/network.h:142-143`) | No listener (`AGENTS.md`, section 5, rule 2): a node or a roost reaches out (T-083, T-166); a start from a standard sshd: T-167 |
| An escape | Ctrl-^ then `.` (paper, Figure 1) | `~.` (`crates/podssh-ssh/src/escape.rs:1-9`) |

What podssh does not need, and why:

- **Scrollback.** Mosh keeps the screen only, so the output of a `cat` of a
  large file is lost to the terminal's scrollback (paper §2; GitHub
  mobile-shell/mosh#122, open). podssh passes each byte, so the local
  scrollback stays whole. The frames of T-303 would lose it, so they come
  on request only.
- **Forwarding.** Mosh has no port forwarding and no agent forwarding
  (GitHub mobile-shell/mosh#337 and #696, open); podssh has SSH's.
- **UTF-8 only.** mosh-server does not run without a UTF-8 locale
  (`src/frontend/mosh-server.cc:338-360`); podssh passes bytes in any
  encoding.
- **A UDP port on the server.** podssh listens on nothing, by its rules.

Mosh's own figures (paper §4), not podssh's: over a 3G link, the median
response to a key was 5 ms with Mosh and 503 ms with SSH, as Mosh showed
70 % of keys at once; with 29 % loss each way, the mean was 0.329 s for Mosh
with no prediction and 16.8 s for SSH. Each new entry above measures podssh
first, with the fault harness (T-203), and with Mosh as a reference, never a
road, where a test host of the operator's has it. That harness shapes the
TCP stream of the stand-in relay, where a loss is only a delay; a loss of
datagrams needs a stand-in of its own (T-304).

### The end-to-end channel above layer 2 (T-088)

When both ends run podssh, each session runs a Noise XX channel above layer 2
(`crates/podssh-relay/src/e2e/`), on both roads: one handshake for a session,
which a resume carries on, as the layer gives each byte once and in order.
The relay sees the layer's records (offsets, acknowledgements, heartbeats) and
ciphertext. A channel for each link, under the layer, lost: a handshake at each
resume, with the resume's proof inside it, for nothing that the relay learns
less. Each end proves its Ed25519 key of T-087 in the handshake: the Noise
static key is derived from the key's seed and signed by it. The layer's own
exchange (the resume secret, from X25519) stays unauthenticated: an active
relay could take part in a resume, but it reads and writes ciphertext only,
and each change that it makes ends the session.

### The records and the handshake of layer 2 (T-151)

The layer is the `session` module of `podssh-relay`: sans-IO, but for its
two ends over tokio streams. A record is a type byte, a 32-bit length and a
body of at most 64 KiB. Numbers are big-endian, and offsets and values have
64 bits.

| Type | Record | Sent by | Body |
| --- | --- | --- | --- |
| 0x01 | `GREETING` | far end | magic, version, role, nonce, features |
| 0x02 | `OPEN` | client | magic, version, role, nonce; then 0x00 and a public key (new), or 0x01 and a session id (resume); then features |
| 0x03 | `ACCEPT` | far end | 0x00, a session id and a public key (new); or 0x01, an offset and a proof (resume) |
| 0x04 | `PROOF` | client | an offset and a proof |
| 0x05 | `REFUSE` | either | a code byte and a reason |
| 0x06 | `DATA` | either | the offset of its first byte, then the bytes |
| 0x07 | `ACK` | either | an offset |
| 0x08 | `PING` | either | a value |
| 0x09 | `PONG` | either | the value of the `PING`, then an offset |
| 0x0a | `CLOSE` | either | a reason: the session ends, not only the link; the peer answers with its own `CLOSE` (T-262) |
| 0x0b | `RETIRE` | client | nothing: this link ends, and the session goes on over another (T-155) |

The magic is the 14 bytes `podssh-session`, and the version is 1; each side
names the highest version that it speaks, and the session speaks the lower.
The roles are 1 (a client), 2 (`podssh node`) and 3 (`podssh serve`). A
nonce, a public key and a proof have 32 bytes, and a session id 16. Features
are a count byte (16 at most), then each name as a length byte and 1 to 32
bytes of `a-z`, `0-9`, `.`, `-` and `_`; a side ignores a name that it does
not know (`replay.v1`, `heartbeat.v1` and `move.v1` come with T-152 to
T-155; a far end's `deadline.SECONDS` with T-306). A reason is UTF-8, 1024
bytes at most. The codes of `REFUSE`: 1 an
unknown session, 2 a wrong proof, 3 an offset no longer kept, 4 the
version, 5 the role, 6 busy, 7 a record out of its place, 0 another reason.

- **Offsets.** Each side numbers the bytes that it sends from 0, across
  each link of the session. A `DATA` record below the next offset expected
  loses its overlap. One above it is a gap: the link ends, and nothing after
  a gap is ever delivered.
- **A new session.** The far end sends `GREETING` and the client `OPEN`
  with its X25519 public key; neither record waits for the other. `ACCEPT`
  gives the session's id and the far end's public key. The secret is
  HKDF-SHA256 with both nonces as the salt (the far end's first), the X25519
  value as the input, and as the info `podssh-session v1 secret`, a 0 byte,
  the id and both public keys (the client's first): 32 bytes.
- **A resume.** `OPEN` names the session. Once the client has the far end's
  nonce, its `PROOF` carries its received offset and the HMAC-SHA256 under
  the secret of `podssh-session v1 client proof`, a 0 byte, the id, both
  nonces of this link and that offset. The far end checks it, and answers
  `ACCEPT` with its own received offset and the same HMAC of
  `podssh-session v1 far proof`, which the client checks. Each side then
  sends from the other's offset.
- **The replay buffer** (T-152), when both sides name `replay.v1`. Each
  side keeps the bytes that it sent from the peer's acknowledged offset on:
  4 MiB in each direction, up to 16 MiB with `PODSSH_REPLAY_BUFFER`. When it
  is full, the writer waits for an `ACK`, so SSH waits and its window stops
  the far side; no byte that is not acknowledged is ever dropped. A receiver
  acknowledges each 64 KiB at once, fewer bytes after 200 ms, and in each
  `PONG`. A resume sends again from the peer's received offset; one that the
  buffer no longer keeps (below the acknowledged offset, or past the bytes
  sent) gets `REFUSE` (3) with both offsets in its reason, and the session
  ends: never a silent gap. A peer that does not name `replay.v1` gets no
  buffer and no `ACK`, since it would never acknowledge.
- **What the layer defends against.** The relay terminates TLS, so it can
  read and log each byte. The secret never crosses it, and a proof names the
  nonces of its own link: a reader of the relay's logs cannot take a
  session, and a replayed `PROOF` fails. An active relay can still put itself
  in the middle of a new session's exchange and break the session, as it can
  break any session today; SSH, above the layer, keeps the bytes secret and
  whole either way. A public key of low order is refused at both ends.
- **A far end with no layer.** No type byte is printable, and an SSH server
  sends a line of text first (RFC 4253, section 4.2). On the reverse road the
  client sends nothing until the far end's first byte, 30 s at most (longer
  than the operator leg's wait for `ready`): a `GREETING` starts the layer,
  and any other byte, or none, means no layer. The bytes then pass as they
  are, and `-v` says so.

- **The heartbeat** (T-154), when both sides name `heartbeat.v1`. A side
  that sent nothing for 10 s sends `PING`, and the far side answers `PONG`
  with its received offset, an acknowledgement. Any bytes from the far end
  count as life; a link with none for 30 s is dead, and the session goes
  on over a new one. Each record is payload to the relay, so the idle cut
  never comes; the cost is about 34 bytes each way each 10 s. To a node,
  SSH sends no keepalive of its own unless `ServerAliveInterval` is set,
  since a keepalive with no answer would end a session that the layer
  carries over.
- **Across links** (T-153). The client resumes after each loss but a
  `CLOSE`, a `REFUSE`, and a relay close that a new link would only get
  again (a stopped or expired pair, a fault of podssh's own bytes:
  `podssh_relay::reverse::closes::resumes`). It tries a new link with the
  backoff of the forward opener, until the far end's deadline after the
  loss; the far end keeps the session and its target as long, then forgets
  it, and a late resume gets `REFUSE` (1, an unknown session). A resume can come while the
  far end still runs the old link: the old link stops, and the new one goes
  on from the client's offset. Bytes received and not written to the
  application stay with the session, so a link that ends in a write loses
  none.
- **The deadline** (T-306). A far end keeps a lost session 10 minutes, or
  the time of `podssh node --resume-deadline` (1 minute to 72 h, the
  longest life of a pair), and names it in its `GREETING` as one more
  feature name, `deadline.SECONDS`. A side that does not know the name
  ignores it, and with no name both sides keep 10 minutes. The client waits
  as long, or less with its own `--resume-deadline`; never longer. The node's
  bound on replay buffers holds: a session kept longer holds its buffers
  longer. The client counts the wait on a monotonic clock, which need not
  count a sleep of its host; a client that wakes after the far end forgot
  the session gets `REFUSE` (1), and says that the far end forgot it, with
  how long it was away by the wall clock.
- **One writer for each link** (T-262). The side that reads a link never
  waits to write to it: an `ACK`, a `PONG` or a `PING` waits for the link's
  one writer, which sends it before its next `DATA`. When each end's reader
  waited for its own writer, stalled on a full link, and both ends sent at
  once, neither link moved again. The bytes of a resume go out the same
  way, while the new link is read. A link whose writes fail is still read
  for 5 s at most: a relay delivers the far end's last bytes and its `CLOSE`
  before it closes the link.
- **The end of a session** (T-262). The side whose application ended its
  bytes sends `CLOSE` after the last of them, and the peer answers with its
  own `CLOSE`; then both forget the session. A link that ends before the
  answer leaves the session to a resume, which sends the `CLOSE` again. A
  far end that no longer knows the session, after this side's application
  ended, had the `CLOSE`, and the session ended there; then no loss is said,
  and a loss after a `CLOSE` is said only when the resume goes on, or takes
  longer than 3 s (T-354). A resume that the far end accepted while the
  session ended on the old link gets a `CLOSE`. A far end's last record on a
  link (that `CLOSE`, a `REFUSE`, the `CLOSE` of a session that it cannot
  start) stays until the client ends the link, 10 s at most: a relay that
  ends both ways when one fails drops a record still on its way at the
  client's next write, as a stand-in relay showed (T-354). A client whose
  write in the handshake fails reads what came before, so a `REFUSE` that
  says why is not taken for a failed link.
- **A move** (T-155), when both sides name `move.v1` and
  `replay.v1`. At 48 MiB of a link both ways, or at 11 h, the client opens a
  new link and waits for its `GREETING` while the old link carries the
  session; then the old link stops at a record boundary and says `RETIRE`,
  and only then does the new link's handshake take the offsets. An offset
  taken while the old link still carried acknowledgements could fall below
  them, and ask for bytes that the other side no longer keeps. A session
  whose application ended does not move. The far end lets the newest resume
  take a session: the client runs one handshake at a time, so an older one
  that still waits is a link that the client left. The client warns an hour
  before its pair expires (72 h at most); at the expiry the relay ends each
  session of the pair with `1001`, which no resume carries on.
- **A spare link** (T-305), in podssh's commands, unless
  `PODSSH_SPARE_LINKS=no`. When a question of the client (`DATA` that the
  far end acknowledges, a `PING`) has waited 3 s with nothing from the far
  end, or, with the heartbeat, nothing came for 20 s, the client opens a
  new link beside the silent one, as for a move, one each 10 s at most,
  and reads its `GREETING` alone. When the old link's bytes come first
  (each read wakes the watch at once, while the new link connects too),
  the new link closes before its handshake, and its far end dials nothing;
  when both came, the old link goes on. When the new link greets first,
  the old one stops, with no `RETIRE`, as it carries nothing, and the new
  link's resume takes the session (when that handshake fails, the next
  link is tried at once, as after a loss, which is said once): a new
  address of the client costs seconds, not the 30 s after which a silent
  link is dead. Measured through the stand-in proxy's `--move` on the
  pair's road, 5 runs each: a resume 3.0 to 3.2 s after the move with a
  spare link, 35.0 to 35.1 s with none. The iroh road opens no spare link:
  its QUIC carried the session across the move with no resume of the layer
  in 5 runs of 5, and a spare there, a stream of the same connection, only
  added a resume, in 3 runs of 5.
- **Kept shells** (T-158), when both sides name `keep.v1`: `podssh ssh`
  names it, and a far end that keeps a shell after its client leaves, as
  `podssh serve` will (T-159); a node never names it, as its SSH server is
  another program. The layer carries nothing more for it: the road reads
  the offer from the handshake, then SSH asks the far end to keep a shell
  (`~d`) or to join one (`--attach`), with requests of its own
  (`docs/terminal.md`, "Detach and attach again").

Measured 2026-10-09: `podssh node` runs the far end for each session, and
`podssh ssh node://` and `podssh operator` run the client. A node keeps 64
MiB of replay buffers at most, a whole buffer for each session that it
keeps, and dials its target only after a session's handshake. Through the
live relay, a node in front of `github.com:22` carried GitHub's banner
through the layer to `podssh operator`, and `podssh ssh node://` logged in
through it.

## 6. socat and tailcat

**tailcat** ([tailscale/tailcat](https://github.com/tailscale/tailcat), Go,
BSD-3) is netcat over the data plane of Tailscale, with no control plane: no
account, user space, DERP then hole punching, a `tc...` address that is a
bearer credential, with `serve`, `forward`, `socks`, `serve exec`, an SSH
server and file transfer. Its released builds have no support for a system
proxy (`ts_omit_useproxy`, READ). On a host whose only egress is an HTTP
proxy, it cannot reach DERP. podssh cannot repair that by forwarding
sockets: tailcat connects to DERP itself, and the only hooks are a listener
or LD_PRELOAD, which podssh does not use.

**socat** has address types that need no listener: stdio and file
descriptors, EXEC and SYSTEM, outbound TCP (only through CONNECT on the
measured host), UNIX-CONNECT, socketpairs and pipes. Each `*-LISTEN` address
needs `bind`, which the measured sandbox refuses for TCP.

**The design: `podssh pipe A B`**, with no listener by default (M7):

| Address | Meaning |
| --- | --- |
| `-`, `stdio`, `fd:N` | Local descriptors |
| `exec:CMD` | A child with a socketpair (pipes as the fallback, and on Windows); its exit status passes through |
| `unix-connect:PATH` | An existing local socket |
| `relay:HOST:PORT` | TCP through the relay (what `podssh proxy` is now) |
| `ssh:[USER@]BASTION,HOST:PORT` | TCP that an SSH server opens (`-W`) |
| `node:NAME[,PORT]` | A podssh node through the reverse road |
| `udp:node:NAME` | UDP that a node sends, for its TARGET `udp:HOST:PORT` (T-168) |
| `iroh:TICKET` | A podssh peer over iroh (section 7) |

Since T-174 and T-175, `podssh pipe` has the local addresses (`-`,
`stdio`, `fd:N`, `exec:CMD`), the roads (`relay:`, `ssh:`, `node:`,
`iroh:`) and `tcp:HOST:PORT`, the direct road through `HTTPS_PROXY`;
since T-176, `unix-connect:PATH`, with a named pipe or AF_UNIX on Windows;
since T-177, the listeners `unix-listen:PATH` and `tcp-listen:[ADDR:]PORT`,
after a probe, for one client or, with `--keep-listening`, each in turn;
since T-168, `udp:node:NAME`; and since T-181, `serial:PATH[,BAUD]`, a serial
line of this host, on Unix.

**UDP over the relay** (T-168). The relay carries TCP only, and the
measured sandbox refuses UDP, so a datagram leaves from a node on a host
that allows it: `podssh node NAME udp:HOST:PORT`, which probes UDP before
it registers. Each session is one flow, a UDP socket of the node connected
to the target; in the session, each datagram is its length in two bytes,
then its bytes (65,507 at most). The near end binds nothing: a program gets
an AF_UNIX `SOCK_DGRAM` socketpair, or stdin and stdout carry the framing.
The limits, which UDP itself does not have:

- Over TCP, datagrams wait for each other. A lost segment delays each later
  datagram until it is sent again, where UDP would lose the one datagram
  and go on; a protocol that times its own packets (QUIC, a game) sees the
  delay as congestion.
- Nothing is dropped on the way: what UDP would drop arrives late, and the
  relay's limits of a session hold for each flow.
- The session has no half-close: the near end keeps it 5 s after its last
  datagram for the answers, and the node ends a flow after 60 s with no
  datagram. Each flow is a session of the relay, with the setup of one: the
  layer's handshake and the end-to-end channel's.

A listener exists only where it is allowed: on the far side (a node, or SSH
`-R`, where the server listens), or locally after a probe shows that an
AF_UNIX or loopback bind works. Tools that start an ssh-like program
already work through podssh (`GIT_SSH_COMMAND`, `rsync -e`, the
`core.gitProxy` of git with `podssh proxy`). Tools that call `connect()`
themselves (curl, browsers) need a listener or the sandbox's own proxy;
podssh cannot help them without one ([the clients that work](../README.md#other-tcp-protocols)).

## 7. iroh

**Use iroh as the road between two podssh ends, for reliability and
multiplexing more than for speed. Do not use it in place of the WebSocket
relay when the far end is a standard sshd.** (Research of 2026-10-08 in the
crates, the iroh source at v1.3.0 and the documents of n0; no build.)

Facts (READ):

- iroh is QUIC between endpoints identified by Ed25519 keys, with NAT
  traversal when UDP works, and a relay (HTTPS on port 443, upgraded to a
  WebSocket) when it does not.
- Version 1.0 came on 2026-06-15, with a promise of stable wire and API. The
  current release is 1.3.0 (2026-09-28).
- Three advisories of 2026-10-05 affect each release up to 1.0.3. The worst
  is a relay frame that blocks the inbound traffic of a client for good.
  podssh must require version 1.1 or later.
- MIT or Apache-2.0. MSRV 1.91. It can use the aws-lc-rs backend, as russh
  does. It adds about 190 to 245 crates, and several megabytes.

**In the target sandbox** (no UDP, egress only through CONNECT, no DNS),
iroh can run only with this configuration (READ; MEASURED on 2026-10-31 on a
host with no UDP out and its egress through CONNECT, though with DNS, T-348; the target
sandbox itself is not measured):

| Need | How |
| --- | --- |
| No UDP | `clear_ip_transports()` (relay only), or a UDP bind marked as not required and tried only after podssh's own probe. The default endpoint requires a UDP bind and does not start without one. A bind is not a datagram that leaves: the sockets stay only after a QUIC address discovery to the home relay came back (T-359). |
| Egress only through CONNECT | `proxy_url(...)`: the relay dial sends `CONNECT relay:443` with the name. podssh gives its own proxy resolution (the `proxy_from_env` of iroh ignores `ALL_PROXY` and `NO_PROXY`). |
| No DNS | The `Minimal` preset (no pkarr or DNS lookups), podssh's own relay URL, peers dialled by ticket (a key and a relay URL), a resolver that fails fast |
| A home relay | The HTTPS `/ping` probe must pass through the proxy. Without it, the endpoint can connect out but nothing can connect to it. |

**Built (T-162, 2026-10-09):** the crate `podssh-iroh`, in the binary with
the feature `iroh` only, which each release binary has since T-348 (Q50).
When a home relay refuses the iroh of a binary, as n0's relays will refuse
an old one, the relay is asked once, after its connection failed, with
iroh's own upgrade, and its answer is named, with `podssh update` and
`--iroh-relay` as the ways out (`podssh-iroh`'s `version.rs`). iroh 1.4.1 with no default features and
`tls-aws-lc-rs`: no ring, no port mapping, no metrics. The endpoint has the
`Minimal` preset and no address lookup; the relays given, n0's four public
relays by default; podssh's proxy for the relay (iroh's `proxy_url`), at an
address that podssh resolved; podssh's name resolution in place of iroh's
resolver; podssh's trust store for the relay's certificate; and no IP
transport unless a UDP probe binds, then UDP sockets that are not required.
Since T-359 (2026-10-31) those sockets stay only after a datagram came back:
the endpoint's first report of the network (iroh's `unstable-net-report`)
holds a round trip of QUIC address discovery to the home relay, on its port
7842, within 6 s of the start; else the endpoint is made again with no UDP and
the same key, before it dials or serves. The wait on a host that drops UDP
is iroh's own limit for that probe, 3 s. `PODSSH_IROH_UDP=on` takes UDP after
the bind alone, for a relay that runs no QUIC address discovery, and `off`
takes none. The HTTPS probe of the relays, through the proxy, picks the home relay; the
captive portal check is off. A session is a bidirectional QUIC stream with
the ALPN `podssh/1`; the client's first byte announces it, as a QUIC peer
learns of a stream only from its first byte, and the stream then carries the
resumable layer's records. Found on the way (READ in iroh 1.3.0, and
MEASURED in the crate's tests):

- iroh's own proxy selection reads `HTTP_PROXY` first, then `HTTPS_PROXY`,
  and knows no `ALL_PROXY` or `NO_PROXY`; the HTTP client of its relay probe
  reads `ALL_PROXY` itself. With `ALL_PROXY` alone, an endpoint with iroh's
  own selection probed its relay through the proxy, dialled it without, and
  got no home relay.
- iroh puts a proxy's user name and password in `Proxy-Authorization` as the
  URL writes them, escapes and all, and in base64url, where RFC 7617 asks for
  base64. podssh refuses such credentials with the reason, where the proxy
  would refuse them with none.
- The relay's name goes to the proxy in `CONNECT`; the proxy's own name is
  resolved by the resolver that podssh gives iroh.
- iroh-relay's relay dial speaks HTTP `CONNECT` only, and has no hook for a
  dial of the caller's. podssh carries a patch of iroh-relay 1.4.1
  (`vendor/iroh-relay`, T-280): a SOCKS5 proxy gets the relay's name with
  the address type 3, the user and password of RFC 1929, and one more try
  with an address on reply 8; reqwest's SOCKS5 carries the HTTPS probe.

MEASURED offline: 20 MiB each way through a stand-in CONNECT proxy and a
relay on the loopback, under a name that only the proxy resolves, with equal
digests; podssh's trust store refuses the test relay's self-signed
certificate. `podssh doctor`, with the feature, reached n0's first relay
with `/ping` in 576 ms. Not measured yet: a real sandbox, and the
throughput by the method of T-157, which T-251 runs (T-348).

**Built (T-163, 2026-10-10):** keys, tickets and the allowlist.
`podssh node NAME TARGET --iroh` serves TARGET over the iroh road with no
pair, and prints its key and its ticket; `podssh ssh iroh:TICKET` dials it.

- Each end's key is an Ed25519 secret in a private file, in hex as iroh
  parses it: the node's under its NAME, the client's one for each user, in
  the cache's directories or the file of `--iroh-key`. A file is made whole
  or not at all (a temporary file and a hard link), so two first runs get
  one key; a file that is not private, or a symbolic link, is refused and
  kept, as a new key would change the ticket. A key is shown by its public
  half, which the allowlist takes as it is.
- The ticket is `iroh:` and iroh's own ticket of an endpoint (iroh-tickets
  1.0), with the node's key and its home relay, and no address of its host:
  with UDP, the relay tells each side the other's addresses. It is an
  address, not a credential (the entry's decision), so it may go on a
  command line.
- Access is by the allowlist of `--iroh-allow`, read again for each
  connection: the handshake proves the client's key, and a refused one is
  closed with the code 403 before any stream, so it never reaches TARGET.
  The client then prints its own key, the line to add.
- The client carries the session over a stream of one QUIC connection, and
  after a lost link over a new stream, or a new connection. The layer's
  features over iroh are `replay.v1` and `heartbeat.v1`: a move keeps a
  session within the limits of the WebSocket relay's sessions, which a QUIC
  connection does not have.

MEASURED offline (`cargo test -p podssh-iroh --test keys --test tickets`):
iroh's own ticket (the vector of iroh-tickets, written by another encoder)
parses to its key, relay and address, and podssh writes it back the same; a
node refuses a client whose key is not in its allowlist, opens no target
for it, and lets the client in once its key is added; a planted node that
admits each key fails that check. The command line end to end came with
T-165.

**Built (T-165, 2026-10-10):** the relays as a setting, the first that
answers first. The table is n0's four public relays, read in iroh 1.3.0 and 1.4.1;
`--iroh-relay` (on `node` and `ssh`) and `PODSSH_IROH_RELAY` replace it, the
flag first. A relay is `https://HOST[:PORT]` and nothing more. iroh itself
picks the relay with the least latency, in no order, and can change it
during a run (READ: `net_report.rs`); so podssh asks `/ping` of each relay in
the list's order, through the proxy and with its own trust store, 5 s at
most each, and gives iroh the first that answers alone: the home relay, and
the one that a node's ticket names for the run. With none that answers,
iroh gets them all, and its own probes are the fallback. A client asks the
ticket's relays first; iroh dials a peer's relay when it is in no list
(READ: the relay actor reads its map only for a token). `podssh doctor`
says the `/ping` of each relay, and the home relay.

MEASURED offline (`cargo test -p podssh-iroh --test relays`, and
`cargo test -p podssh-cli --features iroh-test --test iroh_road`): with a
silent relay first and iroh's relay server on the loopback second, the
second is the home relay, its certificate checked by podssh's trust store;
`podssh node --iroh` and `podssh ssh iroh:TICKET` from end to end: the
client is refused and prints its key, and once that key is in the
allowlist, with no new start of the node, the command runs, and the host
key is kept under `iroh:` and the node's key.

MEASURED on the loopback (T-157, the debug build, 2026-10-10): SSH through
iroh's relay server, p50 34.6 MiB/s up and 25.6 MiB/s down, where `--direct`
to the same server gives 165.9 and 106.3: the iroh road's own limit on this
machine, before any network. Through n0's relays: not measured yet (T-251).

What iroh then gives, when both ends run podssh:

- **Sessions that survive relay drops and address changes**: QUIC
  keepalives every 5 s, a relay client that connects again after network
  changes and relay restarts, and retransmission of lost packets.
- **Multiplexing**: SSH sessions, forwards, file transfers and chat as
  streams of one connection.
- **No accounts**: the key is the identity. Access by an allowlist of keys or
  a relay token. A node is reachable through its relay with no `listen()`.
- **Full speed outside the sandbox**: on normal networks, the connection
  moves from the relay to direct UDP during the session.

**The speed in the sandbox is not measured.** There, each byte goes through
the relay, as QUIC in a WebSocket in TLS in a CONNECT tunnel (two congestion
controllers, TCP head-of-line blocking), so the relay sets the limit. The
known figures (2026-10-08):

- The operator measured **30 to 50 MiB/s with `sendme`** (iroh's file
  transfer) on normal networks. This was most likely a direct path, which a
  sandbox with no UDP cannot use.
- A third party measured a **browser** client (wasm), relay only, at 1.0 to
  1.3 MiB/s through the relays of n0 with round trips of 290 to 378 ms, and
  12.5 MiB/s through a local relay. This is a worst case, not the native
  relay throughput.
- n0 publishes no relay throughput figures. Its free relays are for
  development and hobby use, with a rate limit that is not published. Its
  paid tier states 5 MB/s.

The number that matters (native, relay only, through a CONNECT proxy, on
each candidate relay) is measured in M6, before a default depends on it. The
operator's own Cloudflare relay could host the iroh relay protocol: at least
three independent projects implement it on Workers and Durable Objects
(READ, not verified), billed for each incoming message.

dumbpipe ("netcat over iroh"), pigeons (`pigeons roost` next to sshd,
`pigeons fly --stdio` as a ProxyCommand), iroh-ssh and sendme all use the
default preset of n0 with no proxy support. None works in the target sandbox
as released. They are design references, not dependencies.

Costs against the rules of podssh, which the operator accepted for this road
([decisions.md](decisions.md)): iroh binds netlink sockets on Linux (not
fatal if refused, but it tries), and it opens more than one outbound
connection (latency probes, the home relay of a peer).

**The consequence: the road between two podssh ends has two
implementations.** The iroh road where it can run (measured on each host,
by `doctor` and at connect time), and podssh's own resumable layer over the
WebSocket reverse road where it cannot. The fallback is necessary: the first
real sandbox can block what iroh needs (the `/ping` probe, netlink, or the
relay name in the proxy's allowlist). Both roads carry the same SSH, `cp`,
`pipe` and chat, so a session does not depend on its road.

## 8. DERP

**Use DERP as the second carrier between two podssh ends that needs no
relay of the operator's, after n0's iroh relays, under the same resumable
layer and end-to-end channel.** The operator's ruling Q50 (2026-10-31) makes
Tailscale's servers for tailcat a fallback that podssh may try when the user
did not ask ([decisions.md](decisions.md)); [carriers.md](carriers.md) ranks
the carriers. (Read on 2026-10-31 in Tailscale's source at v1.104.4, in
coder/websocket at v1.8.15, and in tailcat's map and README, through the
services of web.pkgforge.dev; nothing of theirs was run.)

Facts (READ):

- A DERP server forwards packets between Curve25519 keys. It upgrades a
  WebSocket at `/derp` only when the request names the subprotocol `derp`
  (`derp/derpserver/websocket.go`), and answers `/derp/probe` with nothing,
  for a measure of latency. A WebSocket message of more than 32,768 bytes
  from a client ends the connection: that is coder/websocket's default read
  limit, and derper does not raise it.
- The handshake: the server sends its key after the magic `DERP🔑`; the
  client sends its key and its info, JSON sealed to the server's key with
  NaCl's box under a random nonce; the server answers with its info, sealed
  back. The info may name a rate (a token bucket), which derper does not. A
  client may name its program (`AppName`), and a server may refuse a name
  (`--disallow-app-names`).
- A server queues 32 packets for each receiver, and drops the oldest when a
  packet comes to a full queue (`sendPkt`). It keeps the order of one
  sender's packets. It drops a client whose connection takes no bytes for
  2 s (`DefaultTCPWiteTimeout`). It may limit what it reads from each client
  (`--rate-config`), by reading slower, which slows the sender.
- A packet to a key that is not on the server is dropped; the server answers
  `PeerGone` (not here) only to Tailscale's disco packets. When a peer that
  sent to a client leaves, the client gets `PeerGone` (disconnected).
- tailcat's map (https://tailcat.dev/derpmap.json) has four regions of one
  server each, `tc301a.ipn.dev` (New York) to `tc304a.ipn.dev` (Tokyo).
  tailcat calls them "our free rate-limited DERP relays", and refuses its own
  test of throughput through them.

**Built (T-349, drafted 2026-10-31):** the module `derp` of `podssh-relay`,
feature `derp`, pure Rust (NaCl's box from RustCrypto's `crypto_box`, which
the lock had already through the vendored fork).

- The way: TLS through `HTTPS_PROXY` with podssh's provider and trust store,
  then the WebSocket with the subprotocol `derp`, as Tailscale's own client in
  a browser asks for it. No token goes to a DERP server.
- The keys: a node's DERP key is derived from the seed of its identity with a
  label of its own, so that its address stays across runs and no key does two
  jobs; a client's is new for each run, so that two clients of one user are
  never taken for one client connected twice. `AppName` is `podssh`.
- The adapter under the layer: each link is a stream of numbered segments of
  30 KiB at most, so that a packet stays under one message's 32,768 bytes.
  The receiver acknowledges each segment past a gap at once, with up to 8
  ranges that it holds, and the window that it has room for. As the server
  keeps their order, a segment is lost once a segment sent after it arrived;
  else at its retransmission timeout, as RFC 6298 computes it, which doubles.
  The window halves at a loss, once for each window, and grows as TCP's, up
  to 24 segments, under the queue of 32 that the acknowledgements share. A
  link with segments on their way and no acknowledgement for 30 s is dead,
  as the layer takes a silent link.
- A link: the client sends `OPEN` until the node answers, 6 s at most; then
  the layer runs on it with the features of the iroh road (`replay.v1`,
  `heartbeat.v1`). A lost link is replaced by a new one, on the same
  connection while it lives, else on a new one.
- The node: one connection to its home, made again after each loss with the
  forward opener's jittered backoff, and one keeper of sessions across links
  and connections. Its home is the first server of the list whose probe
  answers: the fleet, or the servers of `PODSSH_DERP_SERVER`.
- The ticket: `derp:` and one word of base32 that holds the node's Ed25519
  key, its DERP key and its home server. A client tries that server first,
  then the other servers of the fleet, where a node whose home went away
  calls the next one home; so this road needs no record of pkarr.

MEASURED: UNVERIFIED, until the merge of T-349 runs
`cargo test -p podssh-relay --features derp --test derp_link` (a stand-in
server in memory, with 5 % of the packets dropped) and
`sh scripts/interop-derp.sh` (Tailscale's derper in Podman).

The command line (`podssh node --derp`, `podssh ssh derp:TICKET`), the race
of T-164 with the other roads, and the fallback that Q50 allows come with
T-379.

## 9. Questions for the operator

The operator decided the questions about the beta, the order of M4 to M6,
iroh, the resumable layers, `podssh pipe exec:` and chat
([decisions.md](decisions.md)). One question stays open, for the relay's
operator.

1. **Resumption in the relay for a standard sshd** (a Durable Object that
   keeps the target socket across client reconnections; a protocol change;
   billing for its time). Recommendation: not now; look at it again after
   M6 (T-173).
2. **`podssh pipe exec:`** runs the user's own program. Decided on
   2026-10-08: accepted; the rule "no helper processes" is about podssh's
   own shims (T-174).
3. **Chat**: decided on 2026-10-08: on the roads between two podssh ends,
   end-to-end encrypted, after M6 (T-099), and IRC through public servers
   as a second transport (T-252).
