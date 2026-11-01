# meek and WebTunnel in the Tor road: a study for T-385

2026-11-01. Read only: nothing was built (no cargo, no go), no container
ran, and nothing connected to Tor's network. Each claim is marked **Read**
(at the file and line given) or **Inferred**.

Sources: `REG` = `~/.cargo/registry/src/index.crates.io-*/` (Arti 0.47.0
as podssh-tor fetches it). `PTM` = tor-ptmgr 0.47.0 from
https://static.crates.io/crates/tor-ptmgr/tor-ptmgr-0.47.0.crate (not in
`REG`: podssh-tor does not enable `pt-client`). `LYR` = lyrebird at commit
362a60bb4e3f (2026-10-08), `MEEK` = meek v0.38.0 (2022-10-28), `WT` =
webtunnel v0.0.7 (2026-09-15), each a module zip from proxy.golang.org
(gitlab.torproject.org refused the fetcher: HTTP 403 and 525). `CHU` =
chutney at the commit that `scripts/tor-net.sh` pins (c6b2c5fa).
`MOAT` = https://bridges.torproject.org/moat/circumvention/builtin, fetched
2026-11-01.

## 1. An in-process pluggable transport for arti-client 0.47

### How Arti routes a bridge to a transport

- **Read.** `tor-chanmgr` dispatches a channel by its method. A
  `ChannelMethod::Pluggable` target goes to
  `AbstractPtMgr::factory_for_transport(name)`, and that function returns
  an `Arc<dyn ChannelFactory>` (`REG/tor-chanmgr-0.47.0/src/factory.rs:131-137`,
  `:176-207`). These traits are public. So are `TransportImplHelper`, which
  turns a stream into a channel (`src/transport.rs:36-51`), and
  `ChanBuilder::new_client(runtime, helper)` (`src/builder.rs:75`).
- **Read.** The only setter is `ChanMgr::set_pt_mgr`, under `pt-client`
  (`REG/tor-chanmgr-0.47.0/src/lib.rs:413-416`). arti-client calls it with
  its own `tor_ptmgr::PtMgr` when it builds its running state
  (`REG/arti-client-0.47.0/src/client.rs:1209-1225`).
- **Read.** An embedder reaches the `ChanMgr` only through
  `TorClient::chanmgr()`. That method requires `experimental-api`
  (`client.rs:1859-1866`; the feature is `__is_experimental`, at
  `Cargo.toml:100`). It also needs a running state. Without one it returns
  `BootstrapRequired` (`client.rs:2500-2506`). The running state is built
  only inside `bootstrap` (`client.rs:2358-2399`) or when an onion service
  launches (`:2010`).
- **Inferred.** With this setter, the embedder's `set_pt_mgr` always runs
  after Arti's own PtMgr is in place and after bootstrap has started. The
  first bridge channels race it.
- **Answer to "is there a public API to register a factory per transport
  name":** not on `TorClient`. There is one on `ChanMgr`, which arti-client
  hides behind an unstable feature and makes available too late (**Read**,
  as above).

### The route without that API: an "unmanaged" transport that podssh's runtime answers

- **Read.** An unmanaged transport is a `[[bridges.transports]]` entry
  with `protocols` and `proxy_addr`: a `SocketAddr` with no `path`
  (`PTM/src/config.rs:27-59`). Its validation refuses `path` together with
  `proxy_addr` (`:78-110`). arti-client tests this form
  (`REG/arti-client-0.47.0/src/config.rs:1070-1080`). The builder is public
  as `arti_client::config::pt::TransportConfigBuilder` (`config.rs:57-58`).
- **Read.** For such a transport, `PtMgr::factory_for_transport` builds
  `ExternalProxyPlugin::new(self.runtime.clone(), endpoint, SocksVersion::V5)`
  and wraps it in `ChanBuilder::new_client(self.runtime.clone(), ..)`
  (`PTM/src/lib.rs:368-383`; SOCKS5 is fixed at `config.rs:195-205`). The
  runtime is the client's own (`client.rs:1187`, `:1214-1220`), which for
  podssh is the `CompoundRuntime` with `ProxiedTcp` in its TCP slot
  (`crates/podssh-tor/src/client.rs:21-29`).
- **Read.** `ExternalProxyPlugin::connect` calls
  `runtime.connect(proxy_addr)`, which is podssh's provider. It then runs
  a SOCKS client handshake on the stream it gets back
  (`REG/tor-chanmgr-0.47.0/src/transport/proxied.rs:80-105`, `:108-168`,
  `:456-488`). The bridge's `k=v` settings are joined as `k=v;k=v` with
  backslash escapes (`:492-550`). They are carried in the SOCKS5 user
  name, up to 255 bytes, and the rest in the password, up to 510 bytes in
  all. With no settings, the handshake uses NoAuth (`:556-581`).
- **Read.** tor-ptmgr only warns when `proxy_addr` is not a loopback
  address (`PTM/src/lib.rs:130-141`).
- **Inferred.** podssh can therefore give Arti meek and WebTunnel with no
  experimental API:
  1. Configure each transport as unmanaged at a sentinel address, for
     example `127.0.0.1:1` and `127.0.0.1:2`.
  2. `ProxiedTcp::connect` recognises the sentinel before it calls
     podssh-ws's `dial`, and returns one end of an in-memory
     `tokio::io::duplex`.
  3. A task holds the other end. It answers the SOCKS5 handshake, reads
     the settings, and opens the transport through podssh-ws.

  Nothing binds, listens or starts. A loopback address is used as a key
  only, and is never dialled.
- **Read.** The stream's type is already right: the PT channel is
  `ChanBuilder<R, ExternalProxyPlugin<R>>`, whose stream is `R::Stream`
  (`proxied.rs:457`). That is podssh's `ProxiedStream`, which Arti's rustls
  already wraps for direct channels.

### Features, C and other programs

- **Read.** arti-client's `pt-client` enables `bridge-client`,
  `tor-chanmgr/pt-client`, `tor-guardmgr/pt-client` and `tor-ptmgr`
  (`REG/arti-client-0.47.0/Cargo.toml:184`, `:59`).
  `bridge-client` adds `tor-dirmgr`'s `routerdesc`, `tor-circmgr`'s
  `specific-relay` and `tor-protover` (their `Cargo.toml` features), and
  tor-ptmgr's dependencies are all Rust (`PTM/Cargo.toml:85-161`).
  **Inferred:** no new C; SQLite stays the only C.
- **Read.** arti-client takes tor-ptmgr with its default features
  (`arti-client Cargo.toml:424-426`). Those include `managed-pts`
  (`PTM/Cargo.toml:47`), which compiles a launcher of PT programs,
  `Command::new(binary_path)` (`PTM/src/ipc.rs:19`, `:571`). It also spawns
  an idle reactor task (`PTM/src/lib.rs:173-188`).
  - **Inferred:** the launcher runs only for a transport that has a
    `path`. podssh must never write one. It must also refuse any
    `bridges.transports` in a network TOML (`PODSSH_TOR_NETWORK`), so that
    rule 3 holds by a check and a test, not by construction.
- **Read.** Arti requires an RSA identity in each bridge line: "need an
  RSA identity" (`REG/tor-guardmgr-0.47.0/src/bridge/config.rs:68-70`,
  `:352-356`). A PT bridge may give `-` instead of an address
  (`:60-66`, `:476-492`).
- **Read.** `path_rules.reachable_addrs` filters a PT bridge by the
  address in its line. The guard filter checks
  `chan_method().socket_addrs()` (`tor-guardmgr/src/filter.rs:128-143`),
  and a PT target with an IP and port returns it
  (`REG/tor-linkspec-0.47.0/src/transport.rs:596-605`).
  - **Inferred:** applied to the bridge set (`tor-guardmgr/src/lib.rs:994-998`),
    podssh's `PODSSH_TOR_PORTS=443` would drop meek's dummy
    `192.0.2.20:80`. With bridges, podssh must clear `reachable_addrs` or
    write the address as `-`.
- **Read.** A PT channel gets a fixed 10 s for connect, TLS and the link
  handshake (5 s when direct; `REG/tor-chanmgr-0.47.0/src/builder.rs:198-210`).

## 2. meek_lite: the wire protocol

### The bridge line

- **Read.** The form is `meek_lite ADDR [FP] url=URL front=FRONT
  [utls=ID]`, or `targets=URL|F1+F2,URL2|F3` in place of `url`/`front`
  (`LYR/transports/meeklite/meek.go:53-57`, `:90-143`). The URL scheme is
  http or https (`frontlist.go`, `toGoURL`).
- **Inferred.** `ADDR` is a dummy, never dialled.

### The requests

- **Read.** One worker sends one request at a time (`meek.go:308-374`).
- **Read.** Each request is `POST` to the URL's path, with:
  - the URL's host replaced by `front` for the dial and for TLS (`:263-274`);
  - `Host:` set to the real URL host (`:279-281`);
  - `X-Session-Id: ID` (`:282`);
  - `User-Agent` set empty (`:283`). **Inferred:** Go then omits the
    header.
- **Read.** The body holds the pending upstream bytes, at most `0x10000`
  (64 KiB); writes are joined up to that size, and the excess goes into the
  next request (`:328-347`). A poll has no body.
- **Read.** On status 200, the response body, read up to 64 KiB, is the
  downstream data (`:292-296`). Any other status, or an error, moves to the
  next front. It retries up to 10 times, 100 ms apart (`:62-67`,
  `:256-305`). After that the connection ends (`:340-343`).
- **Read.** The poll interval is 0 after any data in either direction,
  100 ms after the first empty exchange, then ×1.5 up to 5 s (`:63-65`,
  `:352-371`). meek-client has the same constants, but retries after 30 s
  (`MEEK/meek-client/meek-client.go:63-81`).
- **Read.** The session ID is 32 hex digits: the first 16 bytes of the
  SHA-256 of 64 random bytes (`meek.go:414-421`). meek-client uses 8
  random bytes (`meek-client.go:63`, `:275`). The server requires 8
  characters at least (`MEEK/meek-server/meek-server.go:58`, `:224-228`).
- **Read.** TLS: without `utls`, Go's `http.Transport` over the PT's dial;
  with it, a uTLS round tripper (`meek.go:391-397`).
  - **Inferred:** `http.Transport` with only `Dial` set speaks HTTP/1.1
    with keep-alive.

### The server

- **Read.** meek-server keeps one ORPort connection for each session ID
  (`meek-server.go:152-170`). It copies the body into that connection,
  reads back for 10 ms (`:61-64`, `:193-215`), and answers 200 with
  `application/octet-stream`. It drops a session after 120 s idle (`:70`).
- **Read.** `GET /` gives a diagnostic page (`:129-138`). The server does
  not check `Host`.

### Domain fronting

- **Read.** TCP and SNI go to `front`; `Host:` names the real URL host
  (above).
- **Inferred:** the CDN routes by `Host`. A proxy that forwards with
  CONNECT sees `FRONT:443` only. A proxy that re-terminates TLS sees both
  names and could refuse a mismatch.
- **Inferred:** Tor's own TLS travels inside the HTTP bodies. So meek, and
  WebTunnel too, also work through a proxy that re-terminates TLS, where a
  direct Tor channel fails (`docs/carriers.md`, item 5), when podssh
  trusts the proxy's CA for the outer TLS.

### The built-in bridge today

- **Read** (`MOAT`): the keys `meek` and `meek-azure` both give
  `meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org
  front=www.phpmyadmin.net utls=HelloRandomizedALPN`. The CDN is CDN77, and
  the line has **no fingerprint**. The other keys are 7 obfs4 bridges and
  2 snowflake bridges. There is no WebTunnel key.
- **Inferred:** Arti 0.47 refuses this line, because it lacks an RSA
  identity (section 1). The fingerprint of the bridge behind CDN77 was not
  determined.

## 3. WebTunnel: the wire protocol

### The bridge line and its arguments

- **Read.** The server announces `webtunnel [2001:db8:…]:443 FP url=URL
  ver=0.0.7`. The address is a synthetic IPv6 address in 2001:db8::/32,
  hashed from the URL, with port 443 (`WT/main/server/main.go:53-74`).
- **Read.** The client's arguments (`LYR/transports/webtunnel/client.go`):

  | Argument | Meaning | Lines |
  | --- | --- | --- |
  | `url=` | `https` means TLS and port 443; `http` means no TLS and port 80 | `:53-83` |
  | `addr=` | the TCP endpoint | `:78-80` |
  | `servername=` | the SNI | `:90-92` |
  | `sni-imitation=` | another SNI, with the URL host verified | `:85-88` |
  | `utls=` | the TLS fingerprint; default `hellorandomizednoalpn`, `none` for Go's | `:94-105` |
  | `cert=` | a pinned chain hash in base64, which sets `AllowInsecure` | `:107-109`, `:150-158` |
  | `cert-domain=` | the name verified | `:111-113` |

  The client never reads `ver`.

### The handshake

- **Read.** The client dials, runs TLS when the scheme is https, and
  writes `GET /PATH HTTP/1.1` with `Host: URL-HOST`,
  `Connection: upgrade` and `Upgrade: websocket`, and no
  `Sec-WebSocket-Key` (`WT/transport/httpupgrade/httpupgrade.go:32-46`).
  It accepts only the status `101 Switching Protocols` with those two
  headers (`:53-57`), then carries raw bytes both ways, with no WebSocket
  framing (`:56`). The source itself says its buffered read of the
  response is unreliable (`:47`).
  - **Inferred:** `req.Write` adds `User-Agent: Go-http-client/1.1`.
- **Read.** The server is a plain TCP listener, with no TLS. It reads one
  request and checks only `Connection` and `Upgrade`, not the path
  (`:61-85`; `WT/main/server/main.go:111-175`).
  - **Inferred** (README; `release/container/`): TLS and the secret path
    are the job of a reverse proxy in front of it.
- **Read.** The pin is a SHA-256 chained over each DER certificate
  (`WT/common/certiChainHashCalc/pin.go`).

### Rust crates

- **Read** (crates.io API; `ptrs-gesher-webtunnel-0.7.0/Cargo.toml:74-132`):
  ptrs-gesher-webtunnel 0.7.0 (2026-10-13, MIT OR Apache-2.0, Rust 1.92)
  takes:
  - rustls 0.23 with `ring` and `tls12`;
  - tokio-rustls;
  - webpki-roots 0.26;
  - hickory-resolver 0.26 with `https-ring`.

  So it brings ring, which is C and assembly, plus its own DNS. It sends
  `Sec-WebSocket-Key` and `Version: 13` (`src/tests.rs:216-218`), unlike
  Tor's client.
- **Inferred.** It is unusable in podssh-ws, by rule 4, and the handshake
  is about 100 lines.
- **Read.** No Rust crate of Tor's meek turned up in searches of crates.io
  for meek, webtunnel, ptrs, lyrebird and "pluggable transport".
  sillad-meeklike is Geph's own "meek-like" protocol (**Inferred** not
  compatible); jmwample's `ptrs` and `obfs4` crates are obfs4 only.

## 4. Local tests with software that podssh did not write

### chutney

- **Read.** chutney's PT support is hard-wired to obfs4. The node fields
  are `pt_bridge`, `pt_transport` and `pt_executable` (default
  `obfs4proxy`; `CHU/lib/chutney/TorNet.py:624-629`). The torrc gets
  `ServerTransportPlugin {pt} exec {exe}` and `ExtOrPort`, but
  `ServerTransportListenAddr obfs4 …` has the name written in
  (`lib/chutney/tor/torrc.py:356-368`). The bridge line's extra arguments
  exist for obfs4 alone; any other name raises "Unhandled pt_transport"
  (`lib/chutney/tor/builder.py:608-630`). `bridges-obfs4` sets
  `sandbox=0`, "incompatible with pt_transport" (`CHU/networks/bridges-obfs4`).
  arti.toml lists `net.bridges` under `bridges.bridges`
  (`lib/chutney/arti/config.py:102-123`). `bridges-min-arti` exists, but
  its client node needs an `arti` binary (`CHU/networks/bridges-min-arti`).
- **Inferred, the way through.** A network script of podssh's own,
  through `chutney init --net-from-script-path FILE` (**Read**,
  `TorNet.py:2272`). It holds the authorities and exits of `basic`, and
  one node with `bridge=1, relay=1, sandbox=0` whose `extra_raw_torrc`
  (**Read**, `TorNet.py:797`, `torrc.py:402`) holds:

  ```
  ExtORPort auto
  ServerTransportPlugin meek exec /abs/meek-server --disable-tls --log meek.log
  ServerTransportListenAddr meek ADDR:7002
  ServerTransportPlugin webtunnel exec /abs/webtunnel-server
  ServerTransportListenAddr webtunnel ADDR:15000
  ServerTransportOptions webtunnel url=http://ADDR:15000/SECRET
  ```

  The pattern of these lines is **Read** in `MEEK/meek-server/torrc` and
  `WT/release/container/start-tor.sh`. The fingerprint comes from
  chutney's arti.toml; the test writes `meek_lite 192.0.2.1:1 FP
  url=http://ADDR:7002/` and `webtunnel [2001:db8::1]:443 FP
  url=http://ADDR:15000/SECRET`, which replace chutney's plain
  `bridges.bridges` in podssh's network loader.

### meek-server

- **Read.** meek v0.38.0 is under CC0 (`MEEK/COPYING`). `go.mod` declares
  Go 1.13, the module path `git.torproject.org/pluggable-transports/meek.git`,
  and goptlib v1.1.0, utls v1.1.5, x/crypto and x/net, each on
  proxy.golang.org (each `.info` read, and the meek module's under that path).
- **Read.** It has three modes: `--disable-tls`, `--cert/--key`, and ACME
  (`meek-server.go:1-25`, `:360-430`). It needs a port from
  `ServerTransportListenAddr` (`:277-284`).
- **Inferred:** it builds with `go install
  git.torproject.org/pluggable-transports/meek.git/meek-server@v0.38.0`,
  `CGO_ENABLED=0`.

### WebTunnel server

- **Read.** v0.0.7 is under MIT (`WT/LICENSE`). Its `go.mod` declares Go
  1.18 and one dependency, goptlib v1.6.0. Its Dockerfile builds it with
  `golang:1.26-trixie` and `CGO_ENABLED=0`.
- **Inferred:** `go install
  gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/main/server@v0.0.7`.

### Toolchain and images

- **Read** (`go version`): this host has Go 1.24.7, which suffices for
  both servers. lyrebird, the client, needs Go 1.26.0 (`LYR/go.mod:73`);
  it is needed only for a comparison run.
- **Read** (apt-cache): Ubuntu 24.04 has obfs4proxy 0.0.14 (2.1 MB),
  which **Inferred** includes a meek_lite client. It has no package for
  meek-server or WebTunnel.
- **Read** (Docker Hub, compressed amd64): `golang:1.26-trixie` 313 MB,
  `golang:1.24-alpine` 83 MB, `thetorproject/webtunnel-bridge:latest`
  158 MB (2026-07-02), `thetorproject/obfs4-bridge:latest` 63 MB. The
  webtunnel-bridge image writes a torrc for Tor's public network
  (`start-tor.sh`), so **Inferred** it is unfit for chutney.
- **Inferred:** builds with the local Go, two static binaries of about
  10 MB each, are smaller and simpler than any image.

### Runs

All local, on an address of this host that is not loopback, with the
proxy a stand-in. podssh sends no loopback address through a proxy (**Read**,
T-353's Done).

- **(a) meek over HTTP:** `--disable-tls`.
- **(b) meek over HTTPS with fronting:** meek-server with `--cert/--key`
  for a certificate that names FRONT, from a test CA in podssh's bundle;
  the line has `url=https://REAL.test/ front=FRONT`; the stand-in proxy
  maps every name to ADDR and records a CONNECT to FRONT. A unit test
  against a stand-in proves `Host: REAL.test`.
- **(c) WebTunnel over `http://`:** the client supports it (**Read**,
  `client.go:63-65`).
- **(d) WebTunnel over `https://`:** behind a TLS front, stunnel or nginx.
  **Inferred:** stunnel is a package of Ubuntu and of Alpine, as the
  gate's step `ssh` installs it for `ssh+tls://` (T-372).
- **Planted defects:**
  - the sentinel dialled for real: no bootstrap;
  - no `X-Session-Id`: meek-server answers 400;
  - no `Upgrade` header: the WebTunnel server refuses.

## 5. Recommendation

### The smallest design

1. **podssh-tor:** arti-client with `pt-client` added; `bridges.enabled =
   true` and `bridges.bridges` from the user's lines, which must carry a
   fingerprint; `bridges.transports = [{protocols = ["meek_lite"],
   proxy_addr = "127.0.0.1:1"}, {protocols = ["webtunnel"], proxy_addr =
   "127.0.0.1:2"}]`; `reachable_addrs` cleared while bridges are in use;
   any transport with a `path`, and any `bridges.transports` in a network
   TOML, refused.
2. **`runtime.rs`:** `ProxiedStream` becomes an enum of a TCP stream and a
   duplex. `connect` matches a sentinel exactly and spawns the far end;
   any other address is dialled as today. The far end is a SOCKS5 server
   with user and password: tor-socksproto's `SocksProxyHandshake`
   (feature `proxy-handshake`, pure Rust; **Read**
   `REG/tor-socksproto-0.47.0/src/lib.rs:57-70`), or about 100 lines of
   its own. It undoes the escapes of `proxied.rs:492-550`, ignores the
   CONNECT target, and replies 0 once the transport is open, or 1 with a
   logged reason.
3. **podssh-ws `meek.rs`** (about 350 lines):
   - one TLS connection to `FRONT:443` (or the URL's host) through `dial`
     and `tls_over` with SNI = FRONT, verified as on every podssh road
     (`crates/podssh-ws/src/tls.rs:3-14`), and kept alive;
   - POSTs one at a time through `http::exchange` (`src/http.rs`), with
     `Host`, `X-Session-Id` (32 hex digits), `Content-Length` and no
     `User-Agent`, each body at most 64 KiB, and each response capped at
     64 KiB;
   - lyrebird's poll schedule and its 10 retries 100 ms apart, with a
     reconnection on a broken connection;
   - `utls=` accepted and ignored, and `targets=` optional.
4. **podssh-ws `webtunnel.rs`** (about 150 lines):
   - a dial to `addr=`, or to the URL's host and port;
   - TLS with SNI = `servername=`, or else the URL's host, verified;
   - `cert=` only as a second check after verification, never
     `AllowInsecure`, because `tls.rs` forbids a bypass. Write this as a
     Decision: a bridge with a self-signed certificate is then refused.
   - the GET exactly as Tor's client sends it, the 101 checked as it
     checks it, and the response head read to its last byte so that no
     byte of Tor's TLS is lost.
5. **The CLI:** `PODSSH_TOR_BRIDGES`, a file of bridge lines (with or
   without `Bridge `), or an `-o` keyword; doctor's line `tor` names the
   transport and the bootstrap time; the manual.

### Effort

**Inferred:** M for the code, about 1,300 lines with unit tests. Add S to
M for the harness: the network script, the Go builds of the two servers
in `scripts/tor-net.sh`, and the CI job. L with both together, as T-353
says.

### Risks

- **The sentinel depends on undocumented behaviour:** `ExternalProxyPlugin`
  dials the PT's address through the client's runtime. An Arti release
  could change that. A test must fail when no SOCKS greeting reaches the
  sentinel.
- **`pt-client` compiles a process launcher**, which is dormant unless a
  `path` is set.
- **A meek channel must open within Arti's fixed 10 s** (**Read**,
  `builder.rs:198-210`).
- **The built-in CDN77 line cannot be used:** Arti requires a fingerprint
  that the line lacks. So no built-in default; the user brings bridges.
- **Fronting is fragile:** CDN77 may end it; a TLS-inspecting proxy may
  compare SNI with `Host` (**Inferred**); the built-in line asks for uTLS
  (`HelloRandomizedALPN`, possibly h2), while podssh would speak HTTP/1.1
  with rustls's fingerprint, which CDN77 may or may not accept.
- **Traffic analysis:** without uTLS, rustls's ClientHello marks meek and
  WebTunnel to a censor (**Inferred**).
- **meek is slow:** at most 64 KiB in one request, one request at a time,
  and polls of up to 5 s when idle.
- **WebTunnel needs the upgrade:** a proxy that refuses it stops
  WebTunnel, as it stops the relay. meek's POSTs pass.

### Alternatives that lost

| Alternative | Why it lost |
| --- | --- |
| `experimental-api` and `chanmgr().set_pt_mgr` | unstable API; reachable only after bootstrap starts, so it races the first channels (section 1) |
| ptrs-gesher-webtunnel | ring (C) and DNS of its own, in podssh-ws (rule 4) |
| lyrebird or obfs4proxy as a managed PT | starts a program (rule 3) |

### What can be tested here

All of section 4, (a) to (d), against chutney, meek-server and the
WebTunnel server, through a stand-in proxy: the SOCKS bridge inside the
process, both transports, Arti's bootstrap through a bridge, and a login
over `tor://`. Not here: the CDN77 front, real WebTunnel bridges, uTLS,
and Tor's own network, which waits for Q60.

## Not determined

- The fingerprint of the bridge behind the CDN77 meek line, and whether
  CDN77 accepts HTTP/1.1 POSTs from a client without uTLS.
- Whether `go install` reaches proxy.golang.org through this host's agent
  proxy. Nothing was run.
- Whether Arti fetches a bridge's descriptor through a PT channel in
  chutney at this commit. `bridges-min-arti` exists, but its results were
  not read.
- Whether a plain relay of `basic` could act as the "bridge", so that no
  new chutney network is needed.
- Whether Arti's preferences of address family drop WebTunnel's synthetic
  IPv6 target.
- The exact sizes of the Go binaries.
