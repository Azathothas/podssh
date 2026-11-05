# osewa's paper, read against podssh: a reality check (Q99)

Study of 2026-11-04, for the operator's ruling Q99 (`docs/decisions.md`). Its subject is the
paper at <https://osewa.dev/paper> and the site around it (`/`, `/docs`, `/docs/install`,
`/docs/sessions`, `/docs/forward-exec`, `/docs/server`, `/docs/devices`, `/docs/files`,
`/docs/troubleshooting`, `/docs/cli`). A second agent studies the code. This study read the code
only where a claim of the paper needed checking.

**Method.** The pages were read through the services of <https://web.pkgforge.dev/llms.txt>.
The paper came from `read.web.pkgforge.dev`, a provider's rewrite of 2,975 words. The raw HTML came
from `fetch.web.pkgforge.dev`, and a text extraction of my own matched it. Each docs page came
the same way. The repository `rjyo/osewa` was read at `main` = `319071838632` (2026-11-04
01:04 UTC) through `forge.web.pkgforge.dev` and `fetch.web.pkgforge.dev`: README.md,
docs/PROTOCOL.md, docs/QUIC.md, bench/RESULTS.md, the three raw result files in `bench/`, the
Makefile and Dockerfile, and these sources: `crates/client/src/{dial,conn,link}.rs`,
`crates/carrier/src/{quic/mod.rs,ws/handshake.rs}`, `crates/server/src/{lowat,path,dial}.rs`,
`crates/auth/src/tls.rs` and `crates/bench/src/{vs,resume,lib,main}.rs`. Nothing was built or
run. podssh was read at the working tree of 2026-11-04.

**Labels.** For osewa:

- **MEASURED**: osewa's own measurement. The paper or RESULTS.md gives a number and a setup.
- **ASSERTED**: the paper states it and gives no measurement.
- **IMPL**: I read it in osewa's code or protocol document.
- **FUTURE**: the paper's roadmap.

For both projects:

- **READ**: read in podssh's documents or code.
- **INFERRED**: my own reasoning. Nobody measured it.

## 0. The findings in brief

1. **osewa and podssh serve opposite environments.** osewa needs these things:
   - a host that the client reaches directly on TCP port 7322, and on UDP 7322 for speed;
   - ssh access once, to enroll;
   - a resident server on that host.

   osewa has no proxy support. Its client calls `TcpStream::connect` directly, with no
   CONNECT, no SOCKS and no `HTTPS_PROXY`. It has no relay, no NAT traversal, no port 443 and no
   DNS fallback. In podssh's target sandbox, osewa cannot connect at all. That sandbox allows
   CONNECT to ports 443, 80 and 8443 only, and its UDP returns `EPERM` (`docs/target-environment.md:20-24`).
   On reachability, podssh is far ahead.
2. **osewa is genuinely ahead on transport quality between two reachable ends:**
   - **Interactive latency under load.** A key echoes quickly while a download runs on the same
     connection. osewa gets this from typing-aware flight control: a priority writer,
     end-to-end credit, an in-flight bound of about BDP + 40 ms while the user types,
     `TCP_NOTSENT_LOWAT` of 16 KiB, and the kernel's `TCP_INFO`.
   - **Cold connect latency.** osewa needs about 3 RTT over QUIC.
   - **Throughput on a long, fat path.** osewa measured 27 to 40 MB/s at about 100 ms.
   - **Fast liveness.** A connection is suspect after max(3 RTT, 1 s) with input unacknowledged.

   podssh has measured none of these four. Its SSH receive window is a fixed 512 KiB
   (`crates/podssh-ssh/src/run.rs:26-30`). At 100 ms RTT that caps one channel near 5 MiB/s. On a
   slow link it lets up to 512 KiB queue ahead of an echo: 0.4 s at 10 Mbit/s and 4 s at 1 Mbit/s
   (INFERRED).
3. **Much of the paper's evidence is weak.**
   - The lab headline numbers have no published harness, no published raw data and no stated
     sample size. The "Reproduce: make bench-vs · make bench-mosh" targets do not exist in the
     public Makefile.
   - "100×" is a censored timeout: ssh's echo is counted as 15 s.
   - In the lab, QUIC was capped at about 1.4 MB/s by Docker's UDP forwarding. The README says
     so; the paper page does not.
   - The real-path data is stronger: 5 runs, with raw per-run files published. It shows modest
     echo gains on real paths: 102 vs 145 ms, and 129 vs 178 ms. On the Tailscale path the
     download was not faster than ssh's. ssh had the higher rate while the user typed: 10.87 vs
     9.82 MB/s.
4. **osewa's lab data does not show that QUIC's per-stream independence is the cause of its echo
   gains.** Over TLS WebSocket, which runs on TCP and has head-of-line blocking, echo during a
   download was *faster* than over QUIC: 73 vs 138 ms on cellular, and 125 vs 154 ms at
   1 Mbit/s. The gain comes from flight control, which runs on both carriers. podssh can copy
   flight control without QUIC and without a server of its own, through stock sshd and SSH
   channel windows (section 6, G2). That is how podssh can exceed osewa.
5. **podssh's own record claims more than it has measured in one area.** The record measures
   capability and failover. It has no measurement of what a user feels on a real path: echo idle
   and under load, cold connect plus a command, throughput on a WAN direct road, and roaming on a
   real client. Its "parity with Tailscale" (`docs/mesh.md`) is parity of features, not of
   performance.

## 1. What the paper proposes

**The document.** It is a single web page of about 3,000 words. It has these sections:

- `#why`: "ssh and mosh were built for networks we no longer have".
- `#bench`: the lab, the Tokyo runs and the resources.
- `#start`: the quick start.
- `#roadmap`.
- `#how`: 01 hybrid carrier, 02 the host keeps the real screen, 03 keystrokes first.
- `#agents`.
- `FAQ`, which includes `#security`.

The page has no authors, no references and no related work besides ssh and mosh. It does not
mention Eternal Terminal, SSH3 or the QUIC-based SSH projects, and it does not cite the mosh paper
whose predictive echo it reuses. It has no threat-model section. The project was created on
2026-10-31, and `v0.1.0` came out on 2026-11-02. It has 32 stars and 2 open issues. One of the
issues (#2) asks for ProxyJump, which osewa lacks.

**The problem** (`#why`). Bandwidth is cheap now, and "even [Starlink] carries tens of Mbit/s". What
hurts is "latency, deep buffers, switching networks and blocked UDP", together with long-running
coding-agent TUIs that are checked from laptops and phones. ssh's session dies with its TCP
connection, and "under load each key waits behind the download". mosh is UDP-only, has no forwards
and no scrollback, and its emulator garbles.

**The environment model.** It is implicit and was reconstructed from the site:

- The user has ssh access to the host once (`osewa login` runs over ssh).
- The host can run a per-user resident server that listens on TCP and UDP 7322. The host has
  systemd or launchd user services, and `loginctl enable-linger` on Linux.
- The client reaches that port directly, or through a tailnet that the user already runs.
- UDP may be blocked. Then TCP 7322 must pass.
- Port 443 is optional. It "needs root ... redirect 443 to it with the host's firewall"
  (`/docs/server`).
- Linux and macOS only, with no Windows.

**The threat model.** It is implicit, from the FAQ and `/docs/devices`. There is a network
attacker in the middle. osewa answers it with TLS 1.3, mutual Ed25519 keys and a server key that
enrollment pins. The trust in that pin comes from ssh's own host-key trust. It also covers a
revoked device (refused at its next connect) and a hostile remote program (escape sequences
filtered).

These are not addressed:

- censorship and DPI;
- traffic analysis;
- intercepting proxies;
- a host behind NAT;
- a stolen device key, which is a plain 0600 file with no passphrase or agent;
- audit. The FAQ admits there is none.

**The architecture** (`#how`, `/docs`):

- One binary plays three parts:
  - the client;
  - `osewa server`, one per Unix user, which terminates TLS, checks device keys and relays
    frames;
  - `osewa holder`, one process per session, which holds the PTY and a libghostty-vt screen.
- Holders do not depend on the server, so sessions survive a server restart or update (IMPL:
  PROTOCOL.md "Processes"). An update that changes the protocol or snapshot version leaves
  sessions running but not attachable (IMPL).
- Two carriers carry the same frames:
  - QUIC on UDP 7322, using quinn 0.11 with ALPN `osewa.v0` or `osewa.v0+deflate`;
  - TLS 1.3 WebSocket on TCP 7322, at path `/osewa` with subprotocol `osewa.v0`.

  The client races them, and QUIC gets a 300 ms head start (IMPL: `crates/client/src/dial.rs`,
  `QUIC_RACE_AFTER`). The QUIC port is learned from WELCOME and cached in `hosts.json`, so the
  first connection after login is WebSocket only (IMPL: QUIC.md "Discovery").

**The protocols** (PROTOCOL.md v0, "draft. Breaking changes are allowed until v1"):

- **Frames.** Each frame is `type u8 | stream u32 | payload`. JSON carries control. A feature
  list in HELLO and WELCOME gates optional parts.
- **Sessions** have an epoch, a log position, and an output ring of 8 MiB. Resume replays from
  the position, or sends a snapshot.
- **Input.** Each input event has a sequence number, and the holder acknowledges it with
  INPUT_ACK. The client keeps up to 512 KiB unacknowledged and resends it after a reconnect
  (exactly once).
- **Flow control.** Credit runs end to end, per stream, between the holder and the client, with
  a window of 16 KiB to 4 MiB. Channel streams also get an in-flight bound and priority classes.
- **Channels.** `forward.open` works like `ssh -L`, and `exec.start` runs a command with no PTY.
  Channel streams do **not** resume: "They don't resume: a client opens new ones after it
  reconnects" (IMPL: PROTOCOL.md "Channel streams", Lifetime).
- **Auth.** Each side has a self-signed Ed25519 certificate. The server checks the client's key
  against its `devices` file. The client checks the server's key against the pin from
  enrollment.
- **Compression.** Only the server compresses, with permessage-deflate on WebSocket, or a raw
  deflate stream on QUIC's main stream.

## 2. Each network mechanism, and its evidence

| Mechanism | What the paper says (section) | Status | Checked in code or docs |
| --- | --- | --- | --- |
| Hybrid carrier | "QUIC and TLS WebSocket, raced on every connect ... QUIC gets a 300 ms head start ... Nothing to configure" (`#how` 01) | IMPL. The cost with UDP blocked, "300 ms per connect", is ASSERTED. | `dial.rs` `dial_race`. A host whose QUIC port is not cached dials WebSocket only (QUIC.md). "Nothing to configure" leaves out the firewall step: open TCP and UDP 7322 (`/docs/install`). |
| Port | "Both are TLS 1.3 on port 7322" (`#how` 01); "TCP and UDP 7322" (FAQ) | IMPL | 443 needs root or a firewall redirect (`/docs/server`). |
| HTTP or SOCKS proxy | Not in the paper. The README says the WS carrier "gets through proxies and UDP-hostile networks". | ASSERTED, and **contradicted** by the code | `tcp_connect` is a plain `TcpStream::connect(addr)`. There is no proxy code in the client crate. With mutual TLS on self-signed certificates, a TLS-intercepting proxy cannot pass. |
| NAT traversal, relays | None. FAQ: "Does it work behind a VPN or tailnet? Yes" | Not a feature. osewa rides the user's tailnet. | No STUN, relay or hole punching. The host must be reachable. |
| Discovery | `osewa login` saves the host (`/docs/install`) | IMPL | The address comes from `ssh -G`, port 7322, or `--addr`. The QUIC port comes from WELCOME. A WELCOME never names a host (QUIC.md), which is a good defence. |
| Encryption and auth | "TLS 1.3 only, and both ends prove who they are with Ed25519 keys on every connection" (FAQ `#security`) | IMPL. "Is it as safe as ssh? The cryptography is" is ASSERTED, and the FAQ admits there is no audit. | No TLS session resumption, so a revoked device is out on its next connect (IMPL, with a test). There is no 0-RTT, because of replay of INPUT (IMPL, QUIC.md). The certificate CN is `osewa`. The QUIC SNI is the host, or the literal `osewa`. |
| Trust bootstrap | "The server's key comes to you during enrollment over ssh, so there's no 'trust this host?' prompt" (FAQ) | IMPL | The trust comes from ssh's own host key, which is itself trust on first use. |
| Session survival | "Lives on the host: survives roaming, sleep and server restarts" (`#why` table) | MEASURED for an IP change (lab). Sleep and server restart are ASSERTED in the paper. | Holders outlive the server (IMPL). A host reboot kills sessions. An incompatible update strands them. |
| Resume | "0.4 s to resume after sleep or an IP change (mosh 1.1 s, ssh dies)" (header, `#bench`) | MEASURED (lab). Method: "Client moved to a new IP after 5 s offline. Time from the network coming back to a working session." | No RTT is given for the rig, and no sample size. `osewa-bench resume` runs "from inside a container, next to the server on one network". The harness behind the 0.4 s is not published. |
| Dead-path detection | "Pings spot a dead path in about a second, and unacked keys are resent" (`#how` 02) | IMPL only in part. "About a second" holds only while the user types, or on an explicit wake check. | `conn.rs`: `PING_INTERVAL` is 5 s. A connection is suspect after max(3 × RTT, 1 s) with no pong or INPUT_ACK. Two missed pings kill it. Idle detection is therefore about 5 to 6 s. QUIC keepalive is 15 s with a 30 s idle timeout. |
| Redial | "500 ms between redial races" (`#how` 02 figure) | IMPL | `link.rs`: backoff 250 ms to 1 s, each attempt 3 s. A QUIC dial starts a new attempt every 500 ms, up to 4 in flight (`quic/mod.rs`). A TCP dial starts a second attempt after 250 ms (`dial.rs` `RACE_AFTER`). |
| Exactly-once input | "exactly-once input" (`#roadmap` M1); "0 keys lost" (`#how` 02) | IMPL | INPUT seq and INPUT_ACK. This covers keys only. Channel bytes are not resumed. |
| Priority and flight control | "Frames go out by priority: control, terminals, exec, then forwards. While you type, bulk is held to the path's bandwidth-delay product plus 40 ms of queue" (`#how` 03) | IMPL and MEASURED (echo under load, below) | PROTOCOL.md "In flight". The bound is RTT × rate + 40 ms while the user typed in the last 2 s, and 200 ms when idle. `TCP_NOTSENT_LOWAT` is 16 KiB. Over TCP the server reads `TCP_INFO` (`server/src/path.rs`) and asks for BBR (`lowat.rs`). |
| No head-of-line blocking | "Each forward gets its own QUIC stream, so a lost packet in a download never blocks a key" (`#how` 03) | IMPL. The benefit is ASSERTED, and the lab data argues against it (section 3). | QUIC.md admits a residue: the server's `write_loop` "awaits each frame in turn, so a write blocked on a lane ... holds up everything queued behind it, the main stream's frames included". |
| Latest screen on a slow link | "the latest screen on a slow link" (`#roadmap` M1) | IMPL, not measured separately | Catch-up snapshots (PROTOCOL.md "Lagging clients"). |
| Predictive echo | "Local echo prediction: Yes" (lab table) | IMPL. Its benefit is not measured, because echo was timed with prediction off. | `--predict auto` above 30 ms RTT (`/docs/sessions`). |
| MTU | "QUIC starts with 1200-byte packets to fit a WireGuard MTU" (FAQ) | IMPL | PMTUD runs up to 1452 (QUIC.md). |
| Congestion | Not in the paper | IMPL (QUIC.md) | Cubic without HyStart, initial window of 32 packets, initial RTT of 100 ms, UDP buffers of 7 MiB (forced where allowed), and `OSEWA_QUIC_CC` set to `bbr` or `newreno`. The case against HyStart is MEASURED on 6 fresh connections. |
| Connection migration | Not in the paper | IMPL (passive only) | QUIC follows NAT rebinding. "Active migration ... is not used" (QUIC.md, read 2026-11-04). |
| UDP payloads | None | Not a feature | Datagrams are off (QUIC.md). There is no UDP forwarding. |
| IPv6 | Not in the paper | IMPL, in part | The server listens dual-stack. A QUIC dial "is the first IPv4 one unless the host is an IPv6 literal" (QUIC.md). The TCP dial uses the resolver's order, with no RFC 8305 between families. |
| Compression | Not in the paper. The docs say snapshots and text "shrink about 6-8x". | IMPL, default on | Server to client only, with a context kept across messages. The docs admit "the same trade-off as SSH or mosh compression". |
| DPI and censorship | Not addressed | — | The port is not 443, the certificate is self-signed with CN `osewa`, and the ALPN `osewa.v0` can be read in the QUIC Initial (INFERRED: any observer can decrypt Initial packets). |
| Mux, Moshi, "every screen" | M4 next, M5 and M6 later (`#roadmap`) | FUTURE | — |

## 3. Its evaluation, and how strong the evidence is

### 3.1 The lab ("Every lab result", `#bench`)

The setup is "Same container and ports for every side, netem-shaped links". It has four
profiles (RESULTS.md, "How we measured"):

| Profile | RTT | Rate | Other |
| --- | --- | --- | --- |
| Far fiber | 120 ms | 50 Mbit/s | — |
| Cellular | 60 ms | 10 Mbit/s | deep buffer |
| Wi-Fi | 20 ms | 20 Mbit/s | 1 % loss |
| Slow | 100 ms | 1 Mbit/s | 1 % loss |

The numbers come from one "full run of 2026-10-31", over QUIC:

| Measure | osewa | ssh | Ratio |
| --- | --- | --- | --- |
| Echo p50 during a download, cellular | 138 ms | 1,714 ms | 12.4× |
| Echo p50 during a download, Wi-Fi | 44 ms | 374 ms | 8.5× |
| Echo during a download, 1 Mbit/s | 154 ms | "none within 15 s" | about 97× |
| Connect plus a command, 120 ms RTT | 388 ms | 1,630 ms | 4.2× |
| Resume after an IP change | 0.4 s | dies | mosh: 1.1 s |

The 1 Mbit/s ratio is censored: it is `MISSED` = 15 s in `vs.rs`. Over WebSocket, echo during a
download was 73 ms on cellular and 125 ms at 1 Mbit/s.

Weaknesses:

- **Nothing can be reproduced from the public repository.** The paper says "Reproduce: make
  bench-vs · make bench-mosh". The public Makefile has only `libghostty build check test cover
  clean ios-framework release release-publish`. The netem and Docker harness is not in the
  repository. `crates/bench/src/lib.rs` calls it "the e2e harness [that] drives this helper and
  checks patterns with its own code". No raw lab output is published.
- **The sample size is unstated** for each lab cell. The real-path harness types 40 keys each run
  at 150 ms gaps, and the lab is presumably similar (INFERRED). There are no error bars and no
  repeat runs.
- **There is a rig artefact.** "QUIC reaches the container through Docker's UDP port forwarding,
  which caps a 50 Mbit/s download near 1.4 MB/s" (README; not on the paper page). The paper's lab
  row "Bulk throughput: Equal to ssh; ahead on lossy Wi-Fi (0.99 vs 0.92 MB/s)" therefore
  compares a capped QUIC.
- **mosh was not measured** for echo or bulk in the lab. Its column shows "—".
- **The QUIC versus TCP evidence goes against the paper's own explanation.** The WebSocket
  carrier, which has head-of-line blocking, echoed faster than QUIC in both loaded profiles. The
  echo gain is flight control, not QUIC streams.
- **The ssh baseline is a choice.** In the real-path harness, ssh's download runs on the same
  ControlMaster as its terminal, `cat /dev/urandom` beside `cat` (`vs.rs`). That is the worst case
  for ssh: one TCP, and its 2 MiB channel windows queue ahead of the key. A user's
  `scp` on a second TCP connection would still meet the shared bottleneck queue, but not ssh's
  own channel queue. The lab's ssh setup is not stated. osewa's flight control bounds only
  osewa's own traffic. A browser or `rsync` beside it still fills a deep buffer (INFERRED). The
  paper never says this.
- **Resume.** Who triggers the reconnect and the rig's RTT are unstated, and so is mosh's
  heartbeat state. "ssh dies" holds for an IP change. A short sleep with no address change does
  not kill a TCP connection.

### 3.2 The real paths (`#bench`, "Thailand to Tokyo"; RESULTS.md)

**Thailand to a Tokyo Linode, about 100 ms RTT** (1 vCPU, 1 GB). The paper shows this one.
Median of 5 runs, server build `377ebff`, 2026-10-31:

| Measure | osewa QUIC | osewa WS | ssh | mosh |
| --- | --- | --- | --- | --- |
| Connect plus `true` | 311 ms | 511 ms | 1,337 ms | 1,993 ms |
| Echo idle, p50 | 99 ms | 101 ms | 110 ms | 114 ms |
| Echo under load, p50 / p95 | 102 / 105 ms | 104 / 143 ms | 145 / 150 ms | 113 / 119 ms |
| Download alone | 39.67 MB/s | 27.26 MB/s | 11.96 MB/s | — |
| Download while typing | 30.55 MB/s | 27.28 MB/s | 11.55 MB/s | 15.45 MB/s |

The per-run raw data is in `bench/real-world-vps-2026-10-31.txt`:

- osewa QUIC's download while typing varied from 15.80 to 39.88 MB/s.
- One of ssh's echo runs gave 242 ms.
- One of mosh's downloads gave 0.33 MB/s.
- ssh and mosh used sshd on port 2222, because "some fresh TCP connections to port 22 got no
  answer".

**Thailand to a Tokyo Mac mini over Tailscale, about 125 ms.** This is in the README, not on the
paper page. The 2026-11-01 run:

| Measure | osewa QUIC | ssh | mosh |
| --- | --- | --- | --- |
| Connect | 387 ms | 1,627 ms | 2,366 ms |
| Echo under load, p50 | 129 ms | 178 ms | 198 ms |
| Download alone | 9.86 MB/s | 9.82 MB/s | — |
| Download while typing | 9.82 MB/s | **10.87 MB/s** | — |

The 2026-10-31 run on the same path:

| Measure | osewa QUIC | osewa WS | ssh | mosh |
| --- | --- | --- | --- | --- |
| Echo under load, p50 | 132 ms | — | 258 ms | 152 ms |
| Download while typing | 7.27 MB/s | 9.01 MB/s | 6.94 MB/s | — |

**Strengths.** These runs are on real paths. Each tool ran in the same session, with 5 runs and 5
cold connects each, a 3 s warm-up and a 15 s measure. The raw per-run files are published, and the
harness code `vs.rs` is public. The authors state a noise floor ("differences under ~20 ms are
path noise") and the day-to-day variation.

**Weaknesses:**

- One client location and two servers.
- Only one set of runs on each path a day, and the VPS runs on a single day.
- The paper shows only the path where osewa's download wins by 3×.
- Under the paper's own 20 ms noise floor, osewa and mosh do not differ on the VPS echo under load
  (102 vs 113 ms).
- The connect comparison is unequal:
  - osewa: an in-process library `dial` and `exec` of `true` run directly, with no shell and no
    process start (`vs.rs` `Osewa::connect`);
  - ssh: a fresh `ssh -o ControlPath=none target true` process, so client start-up, config,
    host-key check, sshd's fork and PAM, and the login shell running `true` all count.

  The fair baseline that latency-minded ssh users run, ControlMaster with ControlPersist, is
  excluded. osewa's RTT advantage is still real: about 3 RTT against about 8 to 10 (INFERRED).
- ssh's 3× lower download on the VPS is most likely its fixed per-channel window on a long path.
  2 MiB / 0.1 s is about 21 MB/s, and the measured figure was 12. It is not a congestion
  difference (INFERRED; the paper does not analyse it). The mosh column fits this reading: its
  download over a separate ssh connection beat ssh's own.

### 3.3 Resources (`#bench`, "Light when idle. Honest about the cost.")

| Measure | osewa | mosh | ssh |
| --- | --- | --- | --- |
| Host memory, idle session | 14.3 MB | 20.6 MB | 27.4 MB |
| Client memory, idle session | 6.9 MB | — | — |
| Host CPU per MB, log tail | 302 ms | 434 ms | 66 ms |
| Host CPU per MB, flood | 6 ms | 45 ms | 12 ms |

All are MEASURED, in the same lab container over WS. **The method is not given:** RSS or PSS,
and whether the shared server process counts or only the holder. The flood figures hide a
trade-off. osewa let the program write 173 MB/s by dropping output ("clients never slow the
program"), where ssh held it to 1.2 MB/s. The host memory under a flood is 35.6 MB for osewa
against 27.6 for ssh (RESULTS.md, not on the paper page).

### 3.4 Overall strength

| Claim | Strength |
| --- | --- |
| Real-path connect latency | Moderate to strong: a public harness, raw data, 5 runs |
| Real-path echo under load | Moderate: small effect, near noise against mosh |
| Lab echo gains | Plausible by mechanism, but unreproducible and of unknown sample size |
| Resume time | Weak: method underspecified, harness unpublished |
| Resources | Weak: method unstated |
| HoL benefit of QUIC | Not supported by osewa's own lab data |

## 4. Comparison

| Mechanism | osewa (paper section; code) | podssh (evidence, or the entry that plans it) | Verdict |
| --- | --- | --- | --- |
| Way out of a restricted host | Direct TCP or UDP 7322 only (`#how` 01; `dial.rs`) | WS on 443 through `HTTPS_PROXY` (CONNECT and SOCKS5), the cleartext road, the HTTP road for an upgrade refused (T-319), HTTP/2 extended CONNECT (T-321), `--via`, VLESS, wstunnel, Wisp, Piping, WARP, Tor (`docs/architecture.md:9-222`; `docs/design.md:48-58`) | **podssh far ahead** |
| TLS-intercepting proxy | Breaks (mutual TLS, self-signed) | CA handling with `--ca-file` and the system stores, and TLS 1.2 fallback (`docs/architecture.md:143-173`), measured (`docs/STATUS.md:724-726`) | **podssh ahead** |
| Inbound port on the far host | Required: TCP and UDP 7322, resident server | None: node and roost dial out on the reverse road (M4); quick tunnel, OpenTunnel and DERP | **podssh far ahead** |
| NAT traversal | None; a user's tailnet | iroh hole punching after a UDP probe, iroh, DERP and pair relays, the relay role (`docs/design.md` §7; `docs/mesh.md` §4) | **podssh far ahead** |
| DNS independence | System resolver only | IP literal, pin, system resolver, address cache, then DoH by IP (`docs/architecture.md:128-142`) | **podssh ahead** |
| Far end needs custom software | Yes: an osewa server and holders on each host | No: any sshd on the forward road. A roost or node gives resumption (T-166, T-173). | **podssh ahead** |
| Carrier race | QUIC, then WS after 300 ms | iroh, then the pair after 250 ms, then DERP (T-164, T-379); relay hosts staggered 2 s (T-220) | **Parity** (podssh races more roads) |
| QUIC to the far end | Direct 1-RTT QUIC to the host | Only podssh to podssh, over iroh. No QUIC to the relay role, no HTTP/3 (T-582 is WARP only). | **osewa ahead** for a reachable host (G6) |
| Auth and encryption | Mutual TLS 1.3 with Ed25519 and a pinned key | SSH end to end (host keys, agent, FIDO keys); Noise XX with Ed25519 above the layer between podssh ends (T-088); a signed net and policy (T-429, T-430) | **Parity or podssh ahead** (agent and FIDO; the relay sees only ciphertext) |
| Trust bootstrap | Pin over ssh at enrollment | `accept-new` TOFU for SSH; `--upgrade` returns a roost's pair token in the SSH channel (T-167); SPAKE2 codes (T-086, T-616) | **Parity** |
| Revocation | `devices` re-read on each connect; open connections stay | Allowlist re-read on each connection (T-163); net serials (T-429) | **Parity** |
| Survives a client network change | Terminals yes: holder plus seq and ack. Forwards and exec no. | With podssh at both ends, or the relay role's layer (T-173): **every SSH channel**, because the layer is under SSH (T-153), for 10 min to 72 h (T-306). The default relay's forward road: no (`--persist` plus tmux, T-178). | **podssh ahead** on scope, with a podssh far end; **osewa ahead** for a standard host with its own server |
| Time to resume after a move | 0.4 s, lab (MEASURED by osewa) | 3.0 to 3.2 s on a stand-in, `--move`, with spare links (T-305, `TODO/resume.md:2214-2223`); 17 to 40 s before T-305 (`docs/STATUS.md:774`); never measured on a real roaming client | **osewa ahead** (G5) |
| Dead-path detection | max(3 RTT, 1 s) with input unacknowledged; 5 s ping | Spare link at a 3 s question or 20 s of quiet (T-305); forward road ping each 10 s, dead at 30 to 40 s (`docs/design.md:652`) | **osewa ahead** (G5) |
| Far-end restart | Sessions survive a server restart or compatible update | A node's restart ends its sessions and their sshd connections (INFERRED from `crates/podssh-relay/src/session/keep.rs` being in memory; T-159 is held, Q32) | **osewa ahead** (G8) |
| Echo under load, priority, flight control | Priority classes, credit, BDP + 40 ms while typing, `NOTSENT_LOWAT` 16 KiB, `TCP_INFO`, BBR; MEASURED | Fixed SSH window 512 KiB (`crates/podssh-ssh/src/run.rs:26-30`); russh grants the window on receipt (`vendor/russh/src/client/encrypted.rs:604-624`); the relay role's `NOTSENT_LOWAT` 128 KiB (`docs/relay.md:74-79`); the default relay buffers without bound (`docs/architecture.md:334`, 47 MiB measured); **no measurement** | **osewa far ahead** (G1, G2) |
| Cold connect plus a command | About 3 RTT; 311 ms at 100 ms (MEASURED) | About 8 to 10 RTT through proxy, relay and SSH (INFERRED); never measured; T-444 resumes TLS within a process | **osewa ahead** (G4) |
| Bulk throughput on a long path | 27 to 40 MB/s at about 100 ms | ≤ about 5 MiB/s for each channel at 100 ms with a 512 KiB window (INFERRED); 1.8 MiB/s SFTP through a 100 ms stand-in (`docs/STATUS.md:550-551`); relay roads 1 to 2.4 MiB/s; n0 relay about 1 MiB/s; the direct WAN road not measured (`docs/STATUS.md:526-530`) | **osewa far ahead** on direct roads (G3) |
| HoL between channels | QUIC lane per channel, with a residue in the writer | One SSH byte stream; on iroh one QUIC stream for each session; on HTTP/2 up to 16 sessions on one TCP (`docs/architecture.md:217`) | **osewa ahead** (G7) |
| Forwarding kinds | `-L` style and exec only | `-L`, `-R`, `-D` (SOCKS), `-W`, `-J`, agent forwarding, SFTP, UDP in a stream (T-168), exit and routes (T-431, T-432) | **podssh far ahead** |
| Congestion and QUIC tuning | Tuned and documented; a knob | iroh's defaults; untuned and unmeasured on a WAN | **osewa ahead** (G9) |
| MTU | 1200 initial, then PMTUD | iroh's defaults (not checked) | **Parity, probably** |
| IPv6 | Dual-stack listen; QUIC IPv4-first by name | `-4` and `-6`, `?family`; the default relay reached no IPv6 host; IPv6 egress in the relay role (T-253) | **Both partial** |
| Compression | Server to client on by default | SSH `-C` opt-in | **podssh's default is safer** (section 7) |
| DPI posture | Port 7322, self-signed certificate, ALPN readable in QUIC Initial | Standard TLS to 443 to a CDN name; Tor, WARP and meek fallbacks; iroh's QUIC is as readable as osewa's | **podssh ahead** on its TCP roads |
| Predictive echo | Yes, auto above 30 ms | T-160 (open, held behind `podssh serve`, Q32) | **osewa ahead** (not network) |
| Latest screen and catch-up | Yes | T-161, T-303 (open, held) | **osewa ahead** (not network) |
| UDP per-network verdict cache | Open question 3 in QUIC.md | Decided against (`TODO/roads.md:5581-5583`) | **Both lack** (by choice) |
| QUIC datagrams | Off by choice | T-304 (open) | **Both lack** |
| Measuring what users feel | Echo, connect and bulk on 2 real paths; a lab that cannot be reproduced | Failover, faults and throughput on the loopback or through a container's proxy; **no echo, no connect latency, no WAN direct** | **osewa ahead** in kind; **podssh ahead** in rigour where it does measure (plants, raw commands, baselines) |

## 5. Reality check

### 5.1 What the paper over-claims

1. **"Works with UDP blocked: Yes, falls back to TCP"** (lab table). This holds only where TCP 7322
   to the host passes. There is no proxy support, and port 443 needs root. The README goes
   further: it says the WS "gets through proxies". No code supports that.
2. **"8–100× faster"** (`#bench` h2, home page). 100× is ssh's 15 s timeout. 8× and 12× are
   single lab runs that nobody can reproduce. On real paths the gain is 1.4×: 102 vs 145 ms, and
   129 vs 178 ms. When idle the difference is 1.1×, which is noise.
3. **"downloads at three times ssh's speed"** (Tokyo section). This is true on one path. On the
   Tailscale path in the README, ssh matched osewa alone and beat it while the user typed. The
   paper attributes the gap to flight control. The likely cause is ssh's fixed channel window
   (INFERRED).
4. **"Bulk throughput: Equal to ssh"** in the lab, while QUIC was capped near 1.4 MB/s by
   Docker. The paper page leaves this caveat out.
5. **"connects four times faster"**: an in-process library dial against a cold ssh process with
   ControlPath disabled and the command run through a shell.
6. **"Pings spot a dead path in about a second"**: only with input pending, or on a wake check.
   When idle it is up to about 6 s.
7. **"QUIC ... so a lost packet in a download never blocks a key"**: osewa's own lab shows TCP
   echoing faster under load. QUIC.md admits that a blocked lane write stalls the main stream in
   the server's write loop.
8. **"Survives sleep / IP change: ssh No"**: ssh survives a short sleep with no address change.
9. **"0.4 s to resume"**: lab only, with the RTT, sample size and harness unpublished.
10. **"Is it as safe as ssh? The cryptography is"**. Compression from the server is on by default
    with a context shared across messages, which is a CRIME-like side channel. The docs
    acknowledge it, and OpenSSH's compression is off by default. Device keys sit in plain files.
    There is no audit, and the protocol is a v0 draft "breaking changes are allowed".
11. **"Nothing to configure"**: the user must open TCP and UDP 7322 on the host's firewall or
    security group, and run `loginctl enable-linger`.
12. **"Reproduce: make bench-vs · make bench-mosh"**: these targets are not in the public
    Makefile.
13. **Memory "half of ssh's"**: the method is not stated.

### 5.2 Where podssh's own documents claim more than they have measured

1. **"Parity with Tailscale"** (`docs/mesh.md` title and §1) maps features, not performance. The
   measured roads carry 0.97 to 2.4 MiB/s (`docs/STATUS.md:489-518`). The default relay cuts a
   session at 64 MiB and 12 h. The DERP road's rate and a direct iroh path on a WAN are not
   measured. T-433 (share), T-434 (member relay), T-180 (funnel), T-534 and T-535 are open.
   Many rows of M10 are "drafted and merged ... unreleased", with their live runs waiting (Q88).
2. **Nothing records what a user feels.** No echo latency, idle or under load. No cold
   "connect plus a command". No throughput on the direct road or the forward road to a public
   server (`docs/STATUS.md:526-530`, read on 2026-11-04, says it is not measured). No roaming on a real client: T-305's
   3.0 to 3.2 s is a loopback stand-in's `--move`.
3. **The fixed SSH window limits throughput.** The 512 KiB window (`run.rs:26-30`) bounds every
   long road. `docs/STATUS.md:550-551` admits the bound for SFTP. README, `docs/design.md` and
   `docs/mesh.md` never say that a `--direct` or iroh direct session on a 100 ms path cannot
   exceed about 5 MiB/s in one channel (INFERRED).
4. **"podssh gets out of a cage better than each sibling project"** (`docs/design.md:18`) is
   ASSERTED. No side-by-side measurement backs it.
5. **The iroh road in the target sandbox** "is not measured" (`docs/design.md:1157-1160`). The
   Windows row of 34.6 MiB/s was a direct path on one host (T-335).
6. **MPTCP** (T-172) is opt-in and not measured (`docs/design.md:657`).
7. **The Mosh table** (`docs/design.md:750-764`) puts podssh's entries beside Mosh's functions.
   Three of them (T-160, T-303, T-304) are open and held behind `podssh serve` (Q32). The table
   says so, but a quick reader takes it as capability.

## 6. Where osewa is genuinely ahead: proposals to reach parity and exceed it

Each proposal fits `AGENTS.md` §5: one outbound connection unless an exception applies, no
privilege, no C in library crates, and a probe at runtime. The `G` numbers are for new entries.
The sizes follow `TODO/INDEX.md`: S is under a day, M a few days, L a week.

### G1. Measure what osewa measures, first (S to M, P2)

- **Gap.** podssh has no echo, connect or bulk-with-typing numbers, so no claim against osewa can
  be made either way.
- **Parity.**
  - Extend `podssh ping DEST` (T-053 already logs in, echoes through `cat`, and sends `--size`
    down and up) with:
    - `--connect-runs N`: a cold connect plus `true`, timed from process start, as osewa's `vs`
      does;
    - `--under-load`: echo p50 and p95 while `head -c` streams down on the same SSH connection,
      40 keys 150 ms apart, after a 3 s warm-up;
    - `--json` with the raw samples of each run.
  - Run it on every road: `--direct`, the default relay, the relay role, `node://` over the
    pair, iroh and DERP.
  - Copy osewa's four profiles into T-203's fault harness. Its stand-in relay already shapes
    delay and rate in user space, so it needs no netem and no root. A "deep buffer" is a rate
    limit with an unbounded queue.
- **Exceed.**
  - Publish each run's raw file, as osewa does for its real paths but not its lab.
  - Plant a defect for each check: the samples dropped, the warm-up counted.
  - Put a regression bound in the gate. The echo p50 under load in the cellular profile must stay
    below, for example, 3 × RTT + 40 ms.
  - Where the operator allows it, run osewa and OpenSSH on the same test host as references,
    never as roads.
- **Rules.** The probe's own connection. Nothing listens.
- **Existing.** T-053, T-203 and T-157 are done. A new entry; no entry plans it.

### G2. Typing-aware flight control in podssh's SSH client (M, P2): the main way to exceed osewa

- **Gap.** osewa holds bulk at about BDP + 40 ms while the user types. podssh lets 512 KiB of each
  channel sit ahead of a key. The default relay buffers without bound (47 MiB measured,
  `docs/architecture.md:334`), so podssh's window is the only bound. russh grants window space on
  receipt, against one fixed target (`vendor/russh/src/session.rs:305-350`).
- **Parity:**
  1. **A per-channel receive window** (a patch under `vendor/patches/russh/`, as T-460's
     patch is):
     - The target is set per channel by podssh, and the window is granted as the application
       consumes the data, not as russh receives it.
     - Size the target from the session's own measures, the window-adjust round trip and the
       delivered rate. Through a CONNECT proxy the kernel sees only the leg to the proxy, so
       `TCP_INFO`, osewa's trick, says nothing about the path.
     - Bulk channels (SFTP, `direct-tcpip`, exec with no pty, agent): rate × (min RTT + 40 ms),
       clamped 16 KiB to the road's cap, while a key was typed in the last 2 s.
     - The pty channel gets a lower cap while the user types, so Ctrl-C shows sooner.
  2. **Pace podssh's own senders.** `cp` and `sftp` uploads, `-L`, `-R` and `-D` forwards, and
     `pipe` hold their writes while a key waits. Keys and WINDOW_ADJUST go first. podssh owns
     these writers, so no russh change is needed.
  3. **`TCP_NOTSENT_LOWAT` at 16 KiB** on podssh's own TCP sockets (direct, relay and proxy legs)
     where `setsockopt` succeeds: a probe, not an assumption. In the relay role, measure 16 to
     32 KiB against today's 128 KiB, and ask for BBR only where the kernel allows it unprivileged.
- **Exceed.**
  - osewa's flight control needs osewa's server on the host. This needs nothing on the far end:
    it works against stock OpenSSH and Dropbear, on every road, through the default relay.
  - Between podssh ends, the layer's ACK and PONG timings give an end-to-end RTT on any carrier.
  - The relay role can add fairness for each session.
- **Prove (sketch).** With G1's cellular profile, echo p50 under load ≤ 2 × the idle echo. With
  the patch planted out, the test fails.
- **Existing.** None.

### G3. Autotuned windows for throughput on long paths (S, P2; with G2)

- **Gap.** A 512 KiB window means at most about 5 MiB/s per channel at 100 ms. osewa's channel
  credit starts at 4 MiB ("34 MB/s at 120 ms").
- **Parity and exceed.**
  - When nobody types, grow the bulk window to 2 × the measured BDP, up to a cap for each road:
    - `--direct`, iroh direct and the relay role: 16 to 64 MiB, as memory allows;
    - the default relay: keep about 512 KiB to 2 MiB, under its documented 1013 at 2 MiB
      (T-062);
    - the pair road: 768 KiB (T-443).
  - SFTP's `IN_FLIGHT` (`crates/podssh-ssh/src/sftp/pipeline.rs:37`) follows the window.
  - This beats OpenSSH's fixed 2 MiB, the cause of ssh's 12 MB/s in osewa's run, and osewa's own
    4 MiB cap.
- **Rules.** No new connection. Memory is bounded by the cap.
- **Existing.** None. T-140 and T-141 measured the pipeline, not the window.

### G4. A faster cold connect (M, P3)

- **Gap.** About 3 RTT for osewa against about 8 to 10 RTT for podssh (INFERRED; G1 measures
  it).
- **Parity:**
  1. Keep TLS session tickets across runs, in the private cache as `relay-addresses.json` is.
     T-444 resumes TLS only within a process. That saves 1 RTT; never use 0-RTT.
  2. Remember which key a host last accepted, and send the signed publickey request at once
     instead of the query first. RFC 4252 §7 allows it. That saves 1 RTT.
  3. Measure the token mint's share on the first run.
- **Exceed.**
  - A kept master on the user's request (`ControlPersist`; `-M` and `-S` exist on Unix, behind
    the AF_UNIX bind probe). It gives connect plus a command in 2 RTT (channel open, then exec),
    below osewa's 3, against any sshd.
  - On podssh's own relay role, an early-data flag in the upgrade lets the first SSH bytes ride
    with it (a podssh-only extension of the role).
- **Rules.** A listener only on request (rule 2's exception). The cache files are mode 0600.
- **Existing.** T-444 (done). A new entry.

### G5. Liveness and roaming measured in RTTs, with a wake check (S, P2)

- **Gap.** osewa: max(3 × RTT, 1 s), and a check on wake. podssh: a fixed 3 s question or 20 s of
  quiet (T-305), and the forward road's 30 to 40 s.
- **Parity.**
  - Spare link at max(3 × sRTT, 1 s). The layer's PING and PONG, and its ACK timing, give sRTT.
  - A wake or move check with no privilege: a periodic timer that fires more than 2 s late, or
    a jump between the monotonic and boot-time clocks, probes at once.
  - On the forward road, the same check makes the notice of T-302 and T-307 sooner.
- **Exceed.**
  - podssh's spare link runs beside the old one and can resume on **another road** (iroh, DERP,
    a relay host). osewa can only redial the same host.
  - Measure resume on a real move. Two networks are not available to CI, so use a live relay run
    with the stand-in proxy's `--move`, plus the operator's host where two uplinks exist.
  - Target ≤ 1 s from the network's return.
- **Rules.** T-305's spare link is already accepted. One spare each 10 s still bounds the
  connections.
- **Existing.** T-305, T-302 and T-307 are done. A new entry refines them.

### G6. QUIC on 443 to podssh's own relay role, raced with TCP (L, P3)

- **Gap.** osewa gets a 1-RTT handshake, connection IDs that survive NAT rebinding, and no
  head-of-line blocking across sessions where UDP passes. podssh's relay role speaks TCP only, and
  podssh speaks no HTTP/3 (T-582).
- **Parity.**
  - The relay role also listens on UDP 443:
    - QUIC with an ALPN of podssh's own, each session a stream; or
    - HTTP/3 with RFC 9220's extended CONNECT, for clients that front it with a CDN later.
  - The client races QUIC first, after a UDP probe (T-359's QAD probe is the model), with a head
    start of about 300 ms, then WebSocket and TCP, as osewa does.
  - The resumable layer stays on top, so a QUIC loss is still resumed on any road.
- **Exceed.**
  - It runs on **443**, behind the user's own relay or a quick tunnel, not on an inbound 7322.
  - It falls back across every TCP road podssh has, not one WebSocket.
  - It keeps the layer's exactly-once delivery for **all** channels.
- **Rules.**
  - Q82 frames roads over UDP "where a probe found that UDP passes".
  - The race of two carriers to one host needs a ruling, like Q44 (decide and list it, Q86).
  - Rule 4: QUIC in `podssh-relay` needs a pure-Rust stack and a rustls provider with QUIC
    support. Whether podssh-ws's own provider covers QUIC's header protection is not verified.
    Otherwise put it in a crate outside the no-C list, as `podssh-iroh` is.
- **Existing.** T-580 to T-582 (other servers' UDP roads). A new entry.

### G7. Bulk off the interactive stream (M, P3)

- **Gap.** osewa gives each forward and exec its own QUIC lane. podssh multiplexes channels inside
  one SSH stream, and T-321 puts up to 16 sessions on one TCP.
- **Parity.**
  - On the iroh road, open each further SSH connection of a process (`cp`, `sftp`, a bulk `-L`)
    as a **new QUIC stream of the same iroh connection**. That adds no connection. Give the
    interactive stream a higher priority.
  - On the relay, keep a bulk session off the HTTP/2 connection of an interactive one, or prefer
    HTTP/1.1 for bulk.
- **Exceed.** QUIC stream priority across sessions of one process, with one congestion
  controller for all.
- **Rules.** It needs a second SSH login, so the user's command must ask for it, as `cp` does.
- **Existing.** T-321 (partial). A new entry.

### G8. A node that survives its own upgrade (L, P3)

- **Gap.** osewa's holders outlive a server restart. A podssh node's sessions die with the
  process.
- **Parity.**
  - `podssh update`, or a signal, on a running node re-executes the binary.
  - The new process inherits the sockets: the links and the sshd connections.
  - The layer's state (ids, secrets, offsets, replay buffers) passes over a pipe, and each
    session resumes in place.
- **Exceed.**
  - The layer is byte-level, so no snapshot format can strand sessions, as osewa's incompatible
    updates do.
  - The sshd TCP connection itself survives.
- **Rules.** Rule 3: this binary started again at the user's request (Q61). Windows needs
  `WSADuplicateSocket`. Probe it.
- **Existing.** T-159 (held, Q32) is about shells, not this. A new entry.

### G9. QUIC tuning on the iroh road, measured (S, P3)

- **Gap.** osewa tunes and documents its QUIC: no HyStart, an initial window of 32, an initial RTT
  of 100 ms, 7 MiB socket buffers, and a congestion knob. podssh uses iroh's defaults, and nobody
  has measured them on a WAN.
- **Parity.**
  - Measure an iroh direct path with the method of T-157, between GitHub Actions and the
    operator's host of `PODSSH_THROUGHPUT_SSH`, in short runs (Q91).
  - Ask for larger UDP buffers with the unprivileged `SO_RCVBUF` and `SO_SNDBUF` only. Never use
    `*FORCE`, which needs `CAP_NET_ADMIN`.
  - Expose iroh's congestion and transport settings where iroh allows it.
- **Exceed.** Commit the A/B raw data.
- **Existing.** T-162 and T-335. A new entry.

### Lower value, or held

- **A second TCP attempt after 250 ms for a lost SYN** (osewa's `RACE_AFTER`). It only helps with
  `--direct` and no proxy: through a proxy, the SYN goes to the proxy. Rule 2 would need a ruling.
  Recommend it only after G1 shows lost SYNs.
- **Predictive echo, screen catch-up and snapshots** (T-160, T-161, T-303). osewa's
  credit-driven catch-up is a good reference design. These are held behind `podssh serve` (Q32),
  and they are not network features.

## 7. Ideas in the paper that podssh should not adopt

1. **An inbound, non-443 port on every host, with a resident listening server and firewall
   changes.** This breaks rule 2 and podssh's environment. podssh's outbound-only reverse road
   and its 443 roads are the stronger design for restricted hosts.
2. **Self-signed mutual TLS as the outer layer on a public port.** A TLS-intercepting proxy cannot
   pass it. It is also a distinct fingerprint: CN `osewa`, and an ALPN `osewa.v0` that the QUIC
   Initial exposes. Keep WebPKI TLS to 443 outside, and SSH or Noise inside.
3. **Server compression on by default, with a context across messages.** It is a CRIME-like side
   channel, which osewa admits, and it costs CPU on data that does not compress (osewa's own
   TODO in QUIC.md: 63 against 206 MB/s). Keep SSH `-C` opt-in.
4. **Dial storms**: a QUIC attempt every 500 ms up to 4 in flight, plus a parallel TCP attempt.
   They conflict with rule 2 and with proxies that count connections. Take the RTT-scaled
   detection (G5), not the parallel dials.
5. **A server that installs itself over ssh and updates itself each hour from release assets
   verified only by the same release's `SHA256SUMS`.** podssh never copies itself to a server
   (README), and it verifies with cosign and attestations. Keep both.
6. **A custom far-end protocol in place of SSH.** podssh's value is that it interoperates with any
   sshd. Take osewa's mechanisms at the SSH-client and carrier level (G2, G3, G4) instead.
7. **Device keys only in plain files, with no agent or FIDO support.** podssh already has both.
8. **Terminal state through a C or Zig library (libghostty-vt) in the session path.** Rule 4,
   and podssh's byte transparency, which keeps the local scrollback whole. If T-161 ever needs a
   model, make it pure Rust.

## 8. For the main session

- **osewa runs no public servers.** Its only endpoints are `osewa.dev` (static, with
  `install.sh`) and GitHub releases. A live comparison under Q99 therefore needs an osewa server
  on a test host. It would listen on TCP and UDP 7322 and, as a service, update itself each hour.
  That is an operator's call. If allowed:
  - run `osewa server` in the foreground for the run alone, with `OSEWA_AUTO_UPDATE=off`, on the
    operator's `PODSSH_THROUGHPUT_SSH` host;
  - measure with G1's harness beside `osewa-bench vs`;
  - remove it after the run.
- **The suggested order of entries**:
  1. G1 (measure).
  2. G2 and G3 (flight control and windows). This is the main gain, against any sshd.
  3. G5 (liveness).
  4. G4 (connect).
  5. G9.
  6. G7.
  7. G6.
  8. G8.
- **Facts to keep beside each entry.** Each figure of osewa above is osewa's own, at commit
  `319071838632` and at the paper as fetched on 2026-11-04. The lab figures have no public
  harness. The real-path raw files are `bench/real-world-vps-2026-10-31.txt`,
  `bench/real-world-2026-10-31.txt` and `bench/real-world-2026-11-01.txt`.
