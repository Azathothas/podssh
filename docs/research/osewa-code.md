# osewa (github.com/rjyo/osewa) against podssh: a study of the repository and its code

Date: 2026-11-04. Read, not run: osewa was cloned (`git clone --depth 50`, HEAD `3190718`, 2026-11-04) into a
scratch directory and read; nothing of it was built or executed. GitHub metadata (stars, issues, releases,
contributors, commit count) came through `forge.web.pkgforge.dev` (the operator's rule of 2026-10-31). The
paper's text was read from its source in the repository (`site/src/pages/paper.astro`), only to know which
claims to check. osewa paths below are relative to its repository; podssh paths to `/workspace/podssh`.
"Verified" means read in code at the cited lines; "doc" means read only in osewa's own documents.

## 1. What osewa is

| | |
| --- | --- |
| Purpose | A replacement for ssh/mosh for **interactive terminals to hosts you can reach directly**: sessions live on the host (one `holder` process per session, with libghostty-vt keeping the real screen), and a client attaches, detaches and resumes over QUIC (UDP) or TLS 1.3 WebSocket (TCP), raced. Also `-L`-style forwards and exec (no pty) on the same connection. README.md:1-15, docs/PROTOCOL.md:11-20 |
| Architecture | One binary `osewa` (crates/osewa): `osewa server` (one per Unix user, TCP+UDP 7322, single-threaded tokio `current_thread` + LocalSet, crates/server/src/cli.rs:35-43, 10-11), `osewa holder` (one per session, Unix socket, spawned with `setsid`, crates/server/src/lib.rs:654), clients (CLI, and a C API `crates/ffi/include/osewa.h` for iOS/Android apps). Wire: `type u8, stream u32, payload` frames (docs/PROTOCOL.md:115-176) on WebSocket messages or length-prefixed QUIC streams (docs/QUIC.md:86-100) |
| Language | Rust (31.8k lines non-test, 22.3k test lines), plus libghostty-vt (Zig, pinned commit, built by `scripts/libghostty.sh`) and a 647-line C bridge (crates/ghostty/csrc/bridge.c). quinn 0.11, rustls 0.23 on ring, tokio |
| Age and activity | First commit 2026-10-30 ("wire: frames and messages, byte-compatible with the Go peers": a Rust port of an earlier Go v0; comments still word errors "as v0 servers word it", crates/server/src/cli.rs:104). GitHub repo created 2026-10-31. 177 commits in 6 days, **one author** (rjyo, 176 contributions). Heavily agent-built (CLAUDE.md with rules). 32 stars, 0 forks, 0 PRs |
| Releases | One: v0.1.0 (2026-11-02): linux/darwin x amd64/arm64 gz, `SHA256SUMS`, `build.json`. No signature or provenance file. darwin binaries Developer-ID signed and notarized (scripts/sign-darwin.sh) |
| Tests | 739 `#[test]`/`#[tokio::test]` (1 ignored). Every crate has tests (CLAUDE.md rule). Tests are self-referential (osewa client against osewa server, fake transports, crates/client/src/tests/fake.rs); no interop target exists or is needed. **No CI in the repository** (no `.github/`); the gate is `make check` run by hand (Makefile:25-27). The benchmark rig ("an e2e suite in Docker" with netem, README.md:326-327) is **not in the repository** |
| Issues | 2, both open: #1 Ctrl-T takeover vs Kitty CSI u keys; **#2 "Support for ProxyJump"** (a bastion user cannot reach port 7322 behind it; the only workaround is an ssh tunnel, which "makes the service pointless") |
| Platforms | Linux and macOS (amd64, arm64); iOS xcframework and Android `libosewa.so` of the C API (scripts/build-ios-framework.sh, scripts/build-android-lib.sh). **No Windows**: zero `cfg(windows)` in the tree; Unix sockets, PTYs and libc throughout |
| License | Apache-2.0 (LICENSE, NOTICE credits libghostty-vt, MIT) |

Maturity, against podssh: osewa is a 6-day-old, single-author v0.1.0 with a narrow, deep scope (terminal
transport). podssh is a ~342k-line workspace (12 crates, ~4,300 tests), `v1.0.0` on 2026-11-02, tested
against OpenSSH, Dropbear and live relays, with CI on Linux, Windows and macOS (40 workflow files).

## 2. osewa's network and connectivity capabilities, verified

State: **real** (in code, wired, tested), **partial** (in code with a stated or found limit), **claimed**
(in docs/README/paper only), **absent**.

| Capability | Evidence | State | Notes |
| --- | --- | --- | --- |
| Carrier 1: TLS 1.3 WebSocket over TCP, own RFC 6455 code, path `/osewa`, subprotocol `osewa.v0` | crates/carrier/src/ws/handshake.rs:423 (client GET), crates/client/src/dial.rs:239-251, crates/server/src/lib.rs:318-356 | real | ALPN forced to `http/1.1` (dial.rs:244-245). Direct TCP only |
| Carrier 2: QUIC (quinn 0.11) on the UDP port of the same number | crates/carrier/src/quic/mod.rs:103-142, 225-266; crates/server/src/cli.rs:110-125 | real | Advertised in WELCOME `carriers`, cached per host in hosts.json (`quic_port`), so the **first connection after login is always WebSocket** (docs/QUIC.md:33-54) |
| Carrier race: QUIC first, WebSocket 300 ms later (at once if QUIC fails); first WELCOME wins | crates/client/src/dial.rs:29-33, 193-237 | real | `OSEWA_CARRIER=quic|ws` forces one (crates/client/src/conn.rs:241-243). No per-network memory of a UDP failure: every connect on a UDP-dead network pays 300 ms (docs/QUIC.md:267-271, open question) |
| TCP dial race: a second attempt to the same address list after 250 ms if the first connect is pending | crates/client/src/dial.rs:23-27, 282-348 | real | This is **not** Happy Eyeballs across families (its comment says "happy-eyeballs style"): `TcpStream::connect(String)` tries the resolved addresses in order (dial.rs:257-262) |
| QUIC dial: a new attempt every 500 ms, at most 4 in flight; gives up at once on a refusal | crates/carrier/src/quic/mod.rs:211-266 | real | Address choice: **first IPv4 address unless the host is an IPv6 literal** (mod.rs:268-275), so a v6-only client with a dual-stack name loses QUIC |
| Happy Eyeballs (RFC 6555, 300 ms) for `forward.open` on the server | crates/server/src/dial.rs:1-60 | real | Server-side only, for the forward's target |
| Dual-stack listener | crates/server/src/cli.rs:152-162 (`[::]:port`, else `0.0.0.0`) | real | |
| HTTP CONNECT / SOCKS proxy, `HTTPS_PROXY` | none: no `proxy`/`socks`/`CONNECT` anywhere in crates/ (grep), dial is `TcpStream::connect` (crates/client/src/dial.rs:257-262) | **absent** | README.md:285-286 says the WebSocket "gets through proxies"; the code has no proxy client, the port is 7322, and the self-signed pinned certificate fails under a TLS-inspecting proxy |
| DNS fallbacks (pinned addresses, DoH) | `tokio::net::lookup_host` only (crates/carrier/src/quic/mod.rs:227) | absent | |
| NAT traversal, hole punching, STUN/ICE, relays, rendezvous | none in code | **absent** | The host must accept inbound TCP (and UDP) 7322: `osewa login` fails with "open TCP port {port} to this device (the host's firewall, a cloud security group)" (crates/client/src/login.rs:140-147). NAT'd hosts are reached by running osewa over Tailscale (README.md:78-119) |
| Bastion / ProxyJump | none; issue #2 open | absent | |
| Reverse connection (host dials out) | none | absent | |
| Enrollment and install over ssh | crates/client/src/login.rs:104-150, crates/client/src/install.rs:88-100 | real | Spawns the system `ssh` once; refuses targets that start with `-` (login.rs:200-207). Copies the osewa binary to `~/.local/bin` on the host and starts a daemon or a systemd/launchd user service |
| Auth: Ed25519 device keys, TLS 1.3 only, mutual, raw-key pin on both ends | crates/auth/src/tls.rs:24-77, 123-131 | real | Server re-reads `devices` on every handshake (crates/auth/src/devices.rs:87-98), no TLS session tickets or resumption on either side (tls.rs:44-62, 66-77), so a revocation applies on the next connect. No 0-RTT (docs/QUIC.md:80-81) |
| Compression server-to-client: permessage-deflate with context takeover (WS); raw deflate stream on the QUIC main stream via ALPN `osewa.v0+deflate` | crates/carrier/src/ws/deflate.rs; crates/carrier/src/quic/frames.rs:180-241; crates/carrier/src/quic/mod.rs:38-44, 147-164 | real | Client-to-server never compressed (keystrokes beside attacker-influenced data) (docs/PROTOCOL.md:624-630). The WS also deflates incompressible channel data (63-67 MB/s vs 206-211 MB/s on QUIC lanes on loopback, docs/QUIC.md:248-257, a TODO) |
| Multiplexing: up to 64 streams per connection (sessions, forwards, exec) | docs/PROTOCOL.md:221, 519-531 | real | |
| No head-of-line blocking between channels (QUIC only): each forward/exec direction on its own unidirectional QUIC "lane"; terminals and control on one main stream with higher quinn priority | crates/carrier/src/quic/mod.rs:328-350, 452-493 | real (QUIC); absent (WS) | All terminal sessions share the main stream, so they still block each other |
| Priority scheduling: control > sessions > exec > forwards, round-robin in a class, anti-starvation after 64 KiB | crates/server/src/queue.rs:11-24, 58-64, 192-230 | real | Server's send queue only |
| End-to-end credit flow control (CREDIT/GRANT), adaptive window 16 KiB..4 MiB from credited rate x min RTT | docs/PROTOCOL.md:338-370, 560-570 | real (doc + server code) | |
| In-flight bound while typing: bulk held to rate x (p10 RTT, <= min+20 ms) + 40 ms; 200 ms when nobody typed for 2 s; per stream and per connection | crates/server/src/flight.rs:7-21, 63-73; crates/server/src/channel.rs:382, 420-447 | real | The client does the same for uploads (crates/client/src/channel.rs:662-692; doc PROTOCOL.md:591-593) |
| Kernel view of the TCP path (Linux `TCP_INFO`, macOS `TCP_CONNECTION_INFO`): bytes in flight + unsent, min RTT; bulk held to min RTT + 10 ms of queue while typing, with a BBR-like 1.25/0.75 probe cycle | crates/server/src/path.rs:30-115, 117-162 | real | Linux offsets read from a raw buffer (path.rs:52-73) |
| `TCP_NOTSENT_LOWAT` 16 KiB on both ends, `TCP_NODELAY` | crates/server/src/lowat.rs:5-34, crates/server/src/lib.rs:337-340, crates/client/src/dial.rs:35-41, 253-275 | real | |
| Request BBR for TCP on Linux (`TCP_CONGESTION`), silently keeps the default if refused | crates/server/src/lowat.rs:36-47 | real | |
| QUIC tuning: initial/min MTU 1200 (fits Tailscale's 1280), PMTUD on, idle 30 s / keepalive 15 s, stream window 8 MiB, connection 64 MiB, initial RTT 100 ms, initial cwnd 32 x 1200, datagrams off | crates/carrier/src/quic/mod.rs:88-142 | real | |
| QUIC unsent bound: quinn's send window set to cwnd + 16 KiB before every write (an analogue of NOTSENT_LOWAT) | crates/carrier/src/quic/frames.rs:152-167, 211-223 | real | |
| QUIC congestion control choice: Cubic (no HyStart in quinn) default, `OSEWA_QUIC_CC=bbr|newreno` | crates/carrier/src/quic/mod.rs:46-86, 124-141; rationale docs/QUIC.md:193-219 | real | |
| UDP socket buffers raised to 7 MiB (halving on refusal; `SO_*BUFFORCE` tried on Linux) | crates/carrier/src/quic/mod.rs:93-209 | real | The FORCE call needs CAP_NET_ADMIN; it fails harmlessly otherwise |
| Keepalive and dead-path detection: app ping every 5 s; "suspect" when a ping or unacked typed input waits max(3 x sRTT, 1 s); dead after 2 missed pongs; suspect triggers a redial while the old connection may recover | crates/client/src/conn.rs:36-43, 747-837 | real, but partial vs the claim | "About a second" holds only while there is unacked input, or when the app calls `check()` (an OS network-change hook, `osewa_network_changed`, crates/ffi/include/osewa.h:81, 141); idle detection is up to ~5 s + 1 s |
| Reconnect loop: first try at once, backoff 250 ms..1 s, each attempt bounded to 3 s; all sessions resumed in parallel, HELLO + attach pipelined in one flight | crates/client/src/link.rs:19-25, 299-422, 457-481; crates/client/src/conn.rs:230-250 | real | |
| Session resume from a log position (8 MiB ring), else a libghostty snapshot of the screen; input exactly-once by per-client seq + INPUT_ACK | docs/PROTOCOL.md:261-309, 372-399; crates/holder/src/session.rs:1034-1057 | real, with a limit | Over 1 MiB of parked input the holder acks and **drops** events unapplied (PROTOCOL.md:394-399): "exactly-once" except on overflow |
| "Latest screen, not backlog": a lagging stream drops unsent output and gets screen snapshots (abandonable), then a full snapshot with history | docs/PROTOCOL.md:311-336 | real (doc; holder code: crates/holder/src/queue.rs, catch-up tests crates/holder/src/tests/catchup.rs) | Effects (bell, clipboard, notify) in skipped output never fire |
| Session outlives the network server (holder is a separate process); server restart keeps sessions | crates/server/src/lib.rs:654 (setsid); test crates/ffi/src/tests/api.rs:105 `reconnects_across_server_restart` | real | Host reboot ends them. Idle sessions are killed after **24 h** by default (PROTOCOL.md:430-434); a holder of another build is refused as `incompatible` (PROTOCOL.md:200-209) |
| QUIC connection migration | quinn server default (passive, NAT rebinding) | partial | Active migration not used; a real network change = new connection + resume (docs/QUIC.md:238-246) |
| Predictive local echo (mosh epochs, plus the holder's ECHO/ICANON `input_mode` event) | crates/mirror/src/predict.rs (752 lines, 784 test lines); docs/PROTOCOL.md:436-458 | real | Client-side; shown only at RTT >= 30 ms |
| Port forwarding | `-L`-style only: `[bind:]port[:host:port]` (crates/osewa/src/channels.rs:180-238) | partial | No `-R`, no `-D`/SOCKS, no UDP, no agent forwarding, no file copy protocol (only exec pipes) |
| UDP carriage, IPv6 tunnelling, exit/subnet routing, mesh | none | absent | |
| Mobile: C API, background `pause`/`wake`, network-changed hook | crates/ffi/include/osewa.h:81, 133-143; crates/client/src/link.rs:190-213 | real | |
| Self-update | crates/osewa/src/autoupdate.rs:1-14 (**auto by default**, server checks hourly); crates/client/src/release.rs:34-56, 104-133 | real; weak integrity | Downloads by spawning `curl`/`wget`; checks the binary against `SHA256SUMS` fetched from the same release: no signature. `OSEWA_RELEASES` redirects to any mirror |
| DPI/censorship resistance (443, SNI fronting, ECH, uTLS) | none | absent | Port 7322, custom path/subprotocol, rustls default ClientHello |

## 3. Comparison

| Capability | osewa (evidence) | podssh (evidence or entry) | Verdict |
| --- | --- | --- | --- |
| Works where the only egress is an HTTP CONNECT / SOCKS5 proxy, no DNS | Absent (section 2) | `HTTPS_PROXY` CONNECT with the relay name, SOCKS5 (`crates/podssh-ws/src/proxy.rs`, `socks5.rs`), pinned addresses and DoH by IP (`crates/podssh-ws/src/resolve.rs:67-69`), HTTP road for proxies that refuse the upgrade (T-319) | **podssh far ahead** |
| Reaching a host with no inbound port / behind NAT / behind a bastion | Absent; needs open TCP+UDP 7322 or a VPN (login.rs:140-147); issue #2 | Reverse road (`podssh node`, crates/podssh-relay/src/reverse/), iroh hole punching, DERP road, quick tunnel, relay role on a user's node, `-J` | **podssh far ahead** |
| Censorship / blocking resistance | Absent | Cloudflare-fronted 443, WARP MASQUE (crates/podssh-warp), Tor (crates/podssh-tor), meek, VLESS, Shadowsocks, Wisp, wstunnel, webtunnel (crates/podssh-ws/src/), Q65/Q77 public carriers | **podssh far ahead** |
| Works with a standard sshd (OpenSSH, Dropbear), nothing installed on the server | No: needs osewa server on the host, installs itself over ssh | Yes (the main road); never copies itself (README.md:230-233) | **podssh ahead** |
| Family Happy Eyeballs on the client | No (sequential addresses; QUIC picks first IPv4) | RFC 8305 race across families and resolver sources (`crates/podssh-ws/src/race.rs:1-6`, T-265, T-344) | **podssh ahead** |
| Direct QUIC raced against TCP | Yes, 300 ms head start, tuned quinn (section 2) | iroh road (QUIC, UDP after a probe) raced with the pair's and DERP roads for `node://` (`crates/podssh-cli/src/ssh/roads.rs:1`); iroh with default transport (`crates/podssh-iroh/src/endpoint.rs:306-330`, no `transport_config`); UDP roads T-580/T-581/T-582 open | Parity on the race; **osewa ahead on QUIC tuning** |
| Keystrokes ahead of bulk on one connection (priority, credit, BDP+40 ms in-flight bound, NOTSENT_LOWAT, TCP_INFO, BBR) | Real (section 2) | SSH multiplexes all channels in one stream; fixed 512 KiB window per channel (`crates/podssh-ssh/src/run.rs:26-30`); `TCP_NOTSENT_LOWAT` 128 KiB only on the relay role's sockets (`crates/podssh-relay/src/serve/sockets.rs:5-50`, T-336); client sockets only `TCP_NODELAY`. No entry; **never measured** (no echo-under-load figure in docs/STATUS.md) | **osewa ahead** |
| HOL between forwards and the terminal | None on QUIC (lanes) | Inside one SSH connection, always (SSH framing); separate commands (`cp`) use separate connections | **osewa ahead** (podssh can only approach it) |
| Dead-path detection and roaming time | ~1 s while typing, <= ~6 s idle (conn.rs:36-43, 747-837); app network-change hook; claimed 0.4 s resume (lab, rig absent) | Layer: spare link after 3 s of an unanswered question or 20 s quiet (`crates/podssh-relay/src/session/beside.rs:38-43`), measured resume 3.0-3.2 s after a new address (TODO/resume.md, T-305); dead after 30 s (`session/pump.rs:55-60`); forward road without the layer: 30-40 s (docs/design.md:652) | **osewa ahead** (on speed); podssh ahead on where it can resume (any road and relay host) |
| Session survives a lost link | Yes, any client process, host-held (24 h idle default) | Layer when both ends run podssh: 10 min, node `--resume-deadline` up to 72 h (T-153, T-306); standard sshd: `--persist` re-login + tmux (T-178); role's `/v1/layer` keeps sshd's TCP (T-173) | Parity in kind; osewa simpler for its case; podssh covers standard sshd |
| Session outlives the far-end server process / the client for days | Yes (holder process; server restart test) | T-159 open (needs `podssh serve`, T-107/T-110, released by Q92 on 2026-11-03) | **osewa ahead** |
| Screen snapshot on attach; latest screen on a slow link | Yes (libghostty-vt on the host) | T-161 (open, research), T-303 (open); layer replays bytes | **osewa ahead** |
| Predictive local echo | Yes (crates/mirror/src/predict.rs) | T-160 open, start condition T-107 + T-110 | **osewa ahead** |
| Input exactly-once across reconnects | seq + ack (holder/session.rs:1034-1057), drops past 1 MiB parked | Byte offsets + acks both directions, replay buffer (docs/design.md:674-686) | Parity (podssh's is byte-exact both ways) |
| Fast connect + first command | Claimed 311-388 ms at ~100-120 ms RTT (1-RTT QUIC, pinned key, pipelined HELLO+requests, conn.rs:230-250) | Not measured as a figure; relay road = proxy CONNECT + TLS + WS + SSH KEX + auth + channel; ControlMaster `-M/-S` reuses a connection | osewa ahead (by design; podssh unmeasured) |
| Compression | Server-to-client deflate on by default, both carriers | SSH `-C` / `Compression` (zlib), opt-in (`crates/podssh-ssh/src/run_config.rs:64-66`) | osewa ahead on default; parity in mechanism |
| End-to-end encryption and auth | Pinned mutual TLS 1.3, Ed25519 devices, per-handshake revocation | SSH host keys + Noise XX between podssh ends with Ed25519 (`crates/podssh-relay/src/e2e/`), signed net document and policy (T-429, T-430), signed one-use grants (T-226) | Parity on crypto; **podssh ahead** on identity/policy |
| Forwarding breadth | `-L` and exec only | `-L`, `-D` SOCKS, `-W`, `-J`, `-A`, ControlMaster, `pipe`, UDP in a stream at a node (`crates/podssh-relay/src/udp/`), exit and routes (T-431, T-432) | **podssh far ahead** |
| File copy | None (exec pipes) | `cp`/`mv`/`scp`/`sftp`, digests, resume at offset, parallel | **podssh ahead** |
| Mesh, exit nodes, subnet routes, pairing by code | Absent | T-429..T-435 done; T-433, T-434, T-180 open | **podssh far ahead** |
| Multipath | No | `PODSSH_MPTCP=yes` on `--direct` (`crates/podssh-ws/src/mptcp.rs`), unmeasured | podssh ahead (opt-in, unmeasured) |
| UDP datagrams for interactive data | Deliberately off (docs/QUIC.md:123-125, 261-263) | T-304 open | Both lack |
| Per-network memory of UDP failure | Open question (docs/QUIC.md:267-271) | UDP probe before QUIC (T-400), rank per egress (Q89) | podssh ahead |
| Release integrity and update | Unsigned SHA256SUMS beside the binary, auto-update default on, hourly on servers, curl/wget | cosign-signed SHA256SUMS + provenance; `podssh update` checks both (`crates/podssh-cli/src/man/notes_update.rs:9-13`) | **podssh ahead** |
| Platforms | Linux, macOS; iOS/Android library | Linux (static musl x86_64/aarch64/armv7/riscv64), macOS, Windows (x86_64, aarch64) | podssh ahead on OS coverage; osewa ahead on mobile embedding |
| ECH, ClientHello mimicry | No | No (grep: no ECH in crates/) | Both lack |
| Interop testing against third-party software, CI | None needed / no CI | OpenSSH, Dropbear, live relays, CI on three OSes | podssh ahead |

## 4. Reality check

### osewa claims that the code does not back (or backs less than stated)

1. **"TLS 1.3 WebSocket over TCP: it gets through proxies and UDP-hostile networks"** (README.md:285-286). No
   proxy client exists (no CONNECT, no SOCKS, no env lookup); the dial is `TcpStream::connect` to port 7322
   (crates/client/src/dial.rs:257-262). It gets through networks that allow TCP 7322 outbound, nothing more.
   The pinned self-signed certificate also fails behind any TLS-inspecting proxy (crates/auth/src/tls.rs:64-77).
2. **"Nothing to configure"** (README.md:288) and **"Does it replace ssh? For interactive work, yes"**
   (README.md:332-333): the host needs inbound TCP and UDP 7322 opened (login.rs:140-147); a NAT'd host or one
   behind a bastion cannot be reached (issue #2). No `-R`, `-D`, agent forwarding or file copy.
3. **"Pings detect a dead path in about a second"** (README.md:296-297; paper.astro:429, 450): true only when
   typed input is unacked or an app calls `check()`; the idle ping is every 5 s (conn.rs:39), so idle
   detection is up to ~6 s.
4. **"The terminal protocol that never drops"** (README.md:3) and "sessions survive ... server restarts":
   real for server restarts, but sessions with no attached stream and no output are killed after 24 h by
   default (PROTOCOL.md:430-434), an update to an incompatible build strands them (PROTOCOL.md:200-209), the
   ring is 8 MiB, and input over 1 MiB parked is acked and dropped (PROTOCOL.md:394-399).
5. **"No passwords, no trust on first use"** (README.md:269-270): the server key arrives over ssh at
   enrollment (login.rs:118-127), so its trust is ssh's first-use host-key trust, moved earlier, not removed.
6. **"Happy-eyeballs style" TCP dial** (crates/client/src/dial.rs:282-284): a duplicate attempt to the same
   address list after 250 ms, not RFC 6555/8305 family racing; QUIC uses the first IPv4 address only
   (crates/carrier/src/quic/mod.rs:268-275).
7. **Benchmarks are not reproducible from the repository.** The netem Docker rig behind every "lab" figure
   (8-100x echo, 0.4 s resume, "none within 15 s") is not in the repo (README.md:326-327 names it; no file
   has `netem`/compose), and the paper's "Reproduce: make bench-vs · make bench-mosh"
   (site/src/pages/paper.astro:174) names Makefile targets that do not exist (Makefile:1). Only the
   real-path harness `osewa-bench vs` (crates/bench/src/vs.rs:1-20) and its raw outputs are present. The
   README itself says the lab's QUIC passed Docker's UDP forwarding, capping it near 1.4 MB/s (README.md:74-76).
   In its own real-path VPS run, mosh's echo under a download (113/119 ms p50/p95) was within 11 ms of osewa
   QUIC (102/105) and better than osewa WebSocket's p95 (143) (bench/real-world-vps-2026-10-31.txt): the
   headline multiples are against ssh on shaped deep buffers, not against mosh, and real paths show 1.4x.
8. **"Exactly-once input"** (README.md:259-260): exactly-once while the holder lives and under 1 MiB parked
   (above).
9. **"No head-of-line blocking: each port forward and exec gets its own QUIC stream"** (README.md:264-265):
   true on QUIC only; over the WebSocket fallback everything shares one TCP stream, and on QUIC all
   terminal sessions share the main stream.

What the code does back, and well: the carrier race, the QUIC tuning, the keystroke-first send path (priority
classes, credit, in-flight bounds, TCP_INFO, NOTSENT_LOWAT on both ends), the pinned mutual TLS with
per-handshake revocation, the reconnect loop, the host-held sessions surviving server restarts, prediction.

### podssh claims found weaker than stated (or gaps the docs do not flag)

1. **No latency-under-load figure exists for any road.** docs/STATUS.md has throughput (STATUS.md:428-503)
   and fault survival, but no keystroke echo during a bulk transfer; design.md:759 delegates congestion to
   "TCP or QUIC under the layer". osewa's central metric is one podssh has never taken.
2. **The fixed 512 KiB SSH window** (crates/podssh-ssh/src/run.rs:26-30) was chosen for the relay's 2 MiB
   bound, but also applies on `--direct`, where it bounds one channel to 512 KiB per round trip (about
   5 MiB/s at 100 ms; INFERRED, not measured: the direct road's WAN throughput was not measured on 2026-11-04,
   STATUS.md:499-501) and lets up to 512 KiB queue ahead of an echo (about 4 s at 1 Mbit/s; INFERRED).
3. **Roaming is slower than mosh-class tools.** Measured resume 3.0-3.2 s after a new address (T-305) and
   30-40 s on the forward road without the layer (design.md:652); these are honest in the docs, but the
   thresholds are fixed (3 s, 20 s, 30 s) rather than scaled to the measured RTT.
4. **The iroh road's QUIC is untuned** (crates/podssh-iroh/src/endpoint.rs:306-330 sets no transport) and
   through n0's relays runs at ~1 MiB/s (STATUS.md:463, 491); "full speed outside the sandbox"
   (design.md:1268-1269) rests on a direct path measured on one host (STATUS.md:449-452).
5. **mesh.md's "at parity with Tailscale"** is the goal of M10, and its table lists open entries (T-433,
   T-434, T-180; T-106's live test of `podssh ts`); the page names them, so it is a plan, not an overclaim.

## 5. Where osewa is ahead, and what podssh should build

Each proposal keeps podssh's rules: no new outbound connection beyond the documented exceptions, no listener,
nothing privileged assumed (each socket option tried and its failure tolerated, as a probe), no C in the
library crates, and runtime probes. On 2026-11-04 none was an entry unless named; `docs/research/osewa.md` lists the entries filed from them.

### A. Interactive-first flow control from the SSH client (new entry; **M**; highest value)

Parity: what osewa's server does for its own protocol (priority, BDP + 40 ms in-flight bound while typing,
200 ms idle, NOTSENT_LOWAT), done **from podssh's side of plain SSH**, so it works against stock OpenSSH and
Dropbear and through any relay:
1. Receive side: podssh grants each SSH channel's window. Track "the user typed in the last 2 s" (session
   channel input); while true, cap the window a bulk channel (forwards, `-D`, SFTP, non-pty exec) may have
   outstanding to rate x (minRTT + 40 ms), floor 16-32 KiB; idle, rate x (minRTT + 200 ms). Rate from window
   consumption, RTT from `keepalive@openssh.com` round trips and window-adjust timing (end to end; through a
   CONNECT proxy `TCP_INFO` sees only the first hop, so it is a secondary input on `--direct` only).
2. On the relay roads keep 512 KiB as the ceiling (the relay's bound); on `--direct`, let the ceiling grow
   (4-16 MiB) so long fat paths are not window-bound (fixes 4.2 above too).
3. Send side: a priority queue in front of russh's writer: session-channel data and window adjusts before
   bulk channel data; `TCP_NOTSENT_LOWAT` 16 KiB on the client's own socket (the proxy's or the target's),
   set and ignored on failure.
4. The hook exists: russh's client `Handler::adjust_window(channel, window) -> u32` returns "the next target
   window" each time the client adjusts a channel's window (vendor/russh/src/client/mod.rs:3165-3170), and
   podssh does not implement it (no `fn adjust_window` in crates/). A granted window cannot be taken back in
   SSH, so the bound works by withholding adjusts; a russh patch (`vendor/patches/russh/`) is needed only if
   the hook's cadence is too coarse. This may make A closer to **S-M**.

Exceed: osewa's bound needs osewa on both ends; podssh's would hold against any sshd, and podssh can add the
same at its own node and relay role (both send towards clients) so both directions are covered when podssh is
at both ends. Prove: first build the measurement (C below), then show echo p50/p95 during a download on the
same connection fall to near idle on a deep-buffer shaped link, with bulk within ~10% of today's.

### B. RTT-scaled dead-path detection and a network-change hint (extend T-305; **S**)

Parity: osewa suspects a link after max(3 x sRTT, 1 s) of unacked input (conn.rs:747-837) and lets an app say
"the network changed". podssh: make `SPARE_AFTER` (beside.rs:38) max(3 x sRTT, 1 s) with sRTT from the layer's
acks, keep 3 s as the ceiling; on the forward road with `--persist`, use the SSH keepalive the same way. Add an
optional hint: a change of the host's interface addresses seen by `getifaddrs` polled each second (no socket,
no privilege) opens the spare at once. Exceed: podssh's spare link already races roads and relay hosts at the
resume (osewa redials one host:port), so the resume would be both fast and on another road. Rule fit: the spare
link is an existing exception (one at a time, one each 10 s).

### C. Measure what osewa measures (new measurement entry; **S-M**; do first)

Two figures per road with the T-203 harness (`scripts/fake_shape.py`): (1) echo p50/p95 of a key while a
download runs on the same connection, on four shapes like osewa's (120 ms/50 Mbit/s; 60 ms/10 Mbit/s with a
deep buffer; 20 ms/20 Mbit/s 1% loss; 100 ms/1 Mbit/s 1% loss; "deep buffer" = the shaper accepts into a
queue of seconds and drips at the rate); (2) connect + run `true`, cold, at 120 ms. With OpenSSH's client as
the reference, and mosh only as a reference where a test host has it (design.md:780-787). Record commands in
STATUS. Unlike osewa, keep the rig in the repository.

### D. Predictive local echo (T-160; **L**)

T-160's start condition (T-107 + T-110) is reachable since Q92 released the holds (docs/decisions.md:106).
Two further points from osewa's code: (1) osewa uses mosh's epoch rule *and* the holder's ECHO/ICANON event
(PROTOCOL.md:436-458); the epoch rule alone already keeps an unechoed secret off the screen ("a secret that is
never echoed is therefore never drawn"), which is how mosh works with no termios report. So a client-only
mode against a standard sshd is defensible, with the far end's ECHO flag as a second guard where a podssh far
end exists; that changes T-160's invariant, so it needs a `## Decision` in T-160 (or a question to the
operator), not a silent change. (2) Use a pure-Rust screen model (podssh-terminal's grammar, or an Apache/MIT
crate with no C), never libghostty (rule 4). Exceed: on by measured RTT (T-053/`podssh ping`) and per road.

### E. Host-held sessions, snapshot on attach, latest screen on a slow link (T-107/T-110 -> T-159, T-161, T-303; **L**)

osewa's model to borrow: one holder process per session that outlives the network server (setsid, a socket
per session), an output ring addressed by position with a snapshot when the position fell out, and a lagging
stream that drops unsent output for screen snapshots, then restores history. In podssh this belongs in
`podssh serve` (now in the work order), with a pure-Rust model. Exceed: keep podssh's byte-exact replay as the
default (scrollback whole), and use snapshots only on attach from a new process, past the ring, or when a
measured lag passes a threshold (T-303 "on request" already says so).

### F. QUIC tuning for the iroh road and the UDP roads (T-162 follow-up, T-580..T-582; **S-M**)

Where iroh 1.4's builder exposes quinn's transport settings (verify): initial MTU 1200 (Tailscale's 1280 tun),
initial window 32 packets, initial RTT 100 ms, receive windows above the layer's window, and a send-window
bound of cwnd + 16 KiB so little waits unsent. Put a session's interactive stream above a copy's stream in
priority where they share a connection (a copy on its own QUIC stream of the same iroh connection, not a new
connection, saves a handshake and keeps HOL away). For T-304 (datagrams), osewa's evidence is to measure first
(docs/QUIC.md:123-125, 261-263).

### G. Output compression on the relay roads (new entry; **S**, measure before a default)

The relay ends a session at 64 MiB (README.md:255); terminal output deflates 6-8x (osewa's figure,
PROTOCOL.md:624-626). Proposal: `Compression yes` by default for pty sessions on the relay roads, off for
copies (already compressed or incompressible data costs CPU; osewa's own TODO, QUIC.md:248-257). SSH keeps
per-direction contexts, so keystrokes never share a context with output. Measure the bytes a `top`/TUI session
sends per hour with and without.

### H. Fewer round trips to the first command (new entry; **M**)

Measure first (C). Then: pipeline what SSH allows (send the session channel open and its `exec`/`pty-req`
without waiting where russh permits; offer the first key's signature directly in `publickey` when only one key
is configured, RFC 4252 allows it), and for `node://` send the layer's handshake and first records in one
flight as osewa pipelines HELLO + attach (conn.rs:230-250). Exceed: ControlMaster already removes the cost for
repeat runs on Unix.

## 6. What podssh should not copy

1. **An inbound port as the way in** (TCP+UDP 7322, login.rs:140-147): it contradicts rule 2 and podssh's whole
   target (hosts with no inbound ports and HTTPS-only egress).
2. **A pinned self-signed TLS endpoint on a non-standard port with a fixed path and subprotocol** (`/osewa`,
   `osewa.v0`): blocked by egress filters, fingerprintable, and broken by TLS-inspecting proxies that podssh
   supports by trusting the proxy's CA.
3. **Auto-update on by default, hourly on servers, verified only by a SHA256SUMS from the same place, fetched
   by spawning curl/wget** (autoupdate.rs:1-14, release.rs:34-56, 104-133): one compromised release account or a
   set `OSEWA_RELEASES` runs code on every host. podssh's signed update and its rule against starting programs
   the user did not name are better.
4. **Copying the binary onto the server over ssh at login** (install.rs:88-100): podssh's `--upgrade` uses only
   a podssh already on the server's PATH (README.md:230-233).
5. **A C/Zig terminal engine in the core, and a wire format tied to its snapshot bytes**: rule 4 forbids C in the
   library crates, and osewa's coupling already forced "incompatible" sessions after updates
   (PROTOCOL.md:200-209, 300-306).
6. **A single-threaded server for all clients** (cli.rs:35-43): fine for one user, a limit for podssh's relay role.
7. **Dropping input over a bound while still calling input "exactly once"** (PROTOCOL.md:394-399): if podssh adds
   such a bound, it says so to the user.
8. **Benchmark headlines from a rig that is not in the repository**: podssh's rule (a command in STATUS for each
   figure) is the right one; keep any echo-under-load rig (C) in the repository.
9. **Filtering the terminal stream by default** (other OSCs, DCS, tmux passthrough dropped, README.md:250-252):
   right for a host-held screen, wrong for podssh's byte-transparent default (it would break programs that rely
   on passthrough).

## Summary of gaps for podssh, ranked

1. Keystroke latency under bulk on one connection: no control and no measurement (A, C). New entries.
2. Roaming speed: fixed 3 s/20 s/30 s thresholds vs osewa's RTT-scaled ~1 s (B). Extend T-305.
3. Host-held sessions, snapshots, latest screen (E): T-159, T-161, T-303 behind `podssh serve` (T-107/T-110, now released).
4. Predictive echo (D): T-160, reachable now; consider a client-only epoch mode.
5. QUIC tuning on the iroh and future UDP roads (F); compression on relay roads (G); connect round trips (H).

Everything about reachability (proxies, NAT, bastions, no inbound port, DNS loss, censorship, standard sshd,
forwarding breadth, mesh, release integrity, Windows) is podssh's, by a wide margin; osewa has none of it.
