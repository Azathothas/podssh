# Roadmap

Ordered milestones from today's pre-alpha to a public beta and beyond. Each
milestone ends with something a user can run, and its exit criteria are
commands, not opinions. [STATUS.md](STATUS.md) says where the code is now.

Work one milestone at a time, in order. Do not start the next one until the
current one's exit criteria pass on a real host.

## M0 — Repository rescue (2026-10-08)

- [x] Measure the real state (build, tests, binary behaviour, CI).
- [x] Fix the CI failure: the IRC grammar fixture lost its CRLFs on checkout.
- [x] Cap build parallelism in every script (a full gate nearly exhausted the
      developer machine's memory through WSL).
- [x] Make the Tailscale adapter an opt-in cargo feature (`ts`), so the
      default build is pure Rust.
- [x] Replace contradictory docs with README, STATUS, ROADMAP, a short
      AGENTS.md, and topic pages; archive the old record.

## M1 — `podssh proxy`: a byte pipe through the relay (first useful release)

Lets any host that has an `ssh` binary reach SSH servers through the relay:
`ssh -o ProxyCommand='podssh proxy %h %p' user@host`. Also works for any TCP
protocol a tool can speak over stdin/stdout.

- [x] Relay client (`podssh-ws`): full duplex (separately locked read and
      write halves); bounded TCP, proxy exchange, TLS handshake and upgrade;
      an idle read limit above the relay's 25 s keepalive; WebSocket Close
      sent, echoed and parsed; fragmented messages reassembled; typed errors
      that keep the relay's HTTP status and explanation.
- [x] `HTTPS_PROXY` support: `CONNECT relay:443` by hostname (no client DNS);
      `https_proxy`, `ALL_PROXY`, `NO_PROXY`, Basic proxy credentials.
- [x] Trust roots with fallbacks: `--ca-file`/`SSL_CERT_FILE` alone, else a
      `podssh-ca.pem` beside the binary, the first system bundle, and the
      compiled-in Mozilla roots.
- [x] Tokens: minted with `POST /v1/mint` through the same path, cached per
      relay (config dir → `$TMPDIR` → `/dev/shm` → cwd; 0600, no symlinks),
      re-minted once when the relay rejects a cached token,
      `PODSSH_RELAY_TOKEN` override. Never printed.
- [x] The verb: `podssh proxy HOST PORT` (or `HOST:PORT`), keepalives
      skipped, stdin EOF keeps the reply coming, exit 0 on a clean close,
      sysexits codes and one-line reasons otherwise.
- [x] A default relay, `tcp.ssh.relay.ajam.dev`, overridable by
      `--relay-host` and `PODSSH_RELAY`.

The trust fallback and the default relay reverse two rules an earlier agent
wrote ("no compiled-in CA roots", "no default relay"); the operator approved
both on 2026-10-08 because they conflict with "never assume the client has any
setup".

**Exit criteria**
- [x] `ssh -o ProxyCommand='podssh proxy %h %p' git@github.com` reaches GitHub's
      authentication step from a normal machine (Windows and the static Linux
      binary), and through a CONNECT proxy that only allows port 443
      (2026-10-08; [STATUS.md](STATUS.md) has the details).
- [ ] The same works from a constrained sandbox. Needs the operator's sandbox.
- [x] An idle session with `ServerAliveInterval=60` survives 10 minutes
      (2026-10-08, a real login on `railway.new`: 602 s, exit 0; the same
      session with keepalives off was cut by the relay after 184 s).

## M2 — `podssh ssh`: native client for hosts without `ssh`

**The engine.** The operator asked (2026-10-08) for `russh` to be evaluated
before finishing the hand-written implementation in `podssh-core/src/ssh`.
Measured the same day, in throwaway crates:

| option | builds with no C compiler | Terrapin (CVE-2023-48795) | maintenance |
| --- | --- | --- | --- |
| `russh` 0.64.1 | **no**: `compile_error!` unless the `ring` or `aws-lc-rs` backend is on, and both need `cc` | strict-kex implemented | active (release 2026-10-05) |
| `makiko` 0.2.5 | **yes**: RustCrypto only, mostly the versions podssh already uses | no strict-kex: offer only AES-GCM (no ChaCha20-Poly1305, no EtM MACs) to stay out of reach | last release 2025-03 |
| fix the hand-written code | yes | strict-kex must be written | about 3–4 weeks; 18 audited defects |

**Decided 2026-10-08 (operator): `russh` with the `aws-lc-rs` backend, in the
default build.** The no-C rule now covers the library crates (`podssh-ws`,
`podssh-transport`, `podssh-core`, `podssh-terminal`, `podssh-probe`); the
`podssh` binary links aws-lc. podssh keeps its own code for the transport
(relay, proxy, TLS), host keys, the terminal and the command line. The
hand-written client in `podssh-core/src/ssh` is removed once `podssh ssh`
passes its exit criteria.

Done 2026-10-08 ([STATUS.md](STATUS.md) has the measurements):

1. [x] An interop harness, run by the gate on every change
   (`scripts/interop.sh`, `scripts/interop-pty.py`; 62 checks, all passing):
   OpenSSH (with and without `PermitTTY`, and with PAM) and Dropbear on
   127.0.0.1; exit statuses 3, 0, 1, 127 and 143; payloads of 262144, 262145
   and 5,000,000 bytes by digest; every authentication method; host-key
   refusals; `-W`, `-J`, `-s`, `-N`; ptys through pipes and through a real
   local pty. Not covered yet: a server
   that never answers `pty-req`, a shell-only server that refuses `exec`, a
   channel that closes with no exit status.
2. [x] Host keys: `known_hosts` lookup (hashed entries, wildcards, negation,
   `@revoked`), the trust-on-first-use prompt, accept-new, refusal with both
   fingerprints on a changed key, under every policy.
3. [x] Auth: agent, key files (Ed25519, ECDSA, RSA with SHA-2), encrypted keys,
   keyboard-interactive and password, from the terminal or `SSH_ASKPASS`;
   refusals that say what was skipped and why.
4. [x] Sessions: exec with stdout/stderr apart and the remote exit status;
   shell with a pty and raw local terminal; window size and resize; `~.`;
   keepalives on by default every 60 s.
5. [ ] The in-process line discipline (`podssh-terminal`) for the one case
   nothing else covers: a person typing through a frontend that is not a
   terminal, to a server with no pty and no line discipline of its own. The
   no-`/dev/ptmx` client is covered without it: `-tt` gives a remote pty over
   plain pipes (measured: Ctrl-C and `vi` through pipes). Still open: fix its
   inverted mode selection and wire it behind an explicit flag.
6. [x] The hand-written client in `podssh-core/src/ssh` and the unreachable
   `podssh-cli/src/security` module are removed.

The command line follows OpenSSH; [cli.md](cli.md) has the measured details.

**Exit criteria**
- [x] `podssh ssh user@host 'exit 3'` exits 3 against OpenSSH and Dropbear
      (interop, 2026-10-08), and through the relay (`railway.new`).
- [x] An interactive session (`vi`, `less`, `top`, Ctrl-C) works from a normal
      terminal (a local pty, `interop-pty.py`) and from a host with no
      `/dev/ptmx` (`-tt` over pipes: Ctrl-C and `vi`).
- [ ] The same from the operator's real sandbox, and on Windows.

## M3 — Beta: nothing single-point, nothing assumed

Decided 2026-10-08 ([design.md](design.md) sections 3, 7 and 8): the first
beta waits for these, so no single relay host, missing DNS or silent stall can
take podssh down.

- [x] **Relay hosts with failover** (2026-10-08, crate `podssh-relay`).
      `--relay-host` and `PODSSH_RELAY` take an ordered comma-separated list;
      by default the default host is followed by up to three pool hosts (the
      pool read from `/relays.json` at each mint and cached; six measured
      hosts seed it); one attempt per host bounded at 45 s; errors another
      host could fix move on, errors every host would repeat stop at once;
      `ConnectionAttempts` rounds with jittered backoff. Measured: a dead
      first host failed over to `tcp-eu-west-3`, which accepted the token
      cached for the default host.
- [x] **Liveness** (2026-10-08). The session pings the relay every 10 s and
      declares the link dead after 30 s with nothing at all from it (any
      frame counts, so a slow upload cannot fake a death), enforced only once
      the relay has answered a ping. Measured: the relay answers pings (3 of
      3); a 50 s idle session with SSH keepalives off stayed up.
- [ ] **No proxy and no DNS.** DNS over HTTPS to an IP literal (repair and wire
      the unused DoH code, or replace it), and `--relay-addr HOST=IP` to pin an
      address.
- [ ] **`podssh doctor`**: proxy and its allowlist (which ports and names it
      lets through), AF_INET and AF_UNIX bind, `/dev/ptmx`, a passwd entry,
      which directories can execute, `/proc`, the CA bundle, each relay
      host, the token. Each check is `ok`, `FAIL` or `????`; unknowns are
      counted separately and never fail the run; a check that did not run is
      never `ok`; it prints what was actually opened; servers are identified
      by equality (the expected host key), never by the shape of a banner (a
      banner-shape check once graded the wrong server as good).
- [ ] **`podssh keygen`** for hosts with no `ssh-keygen` (Ed25519 by default;
      OpenSSH format; never prints the private key).
- [ ] **A fault-injection harness** in the gate: a killed relay host, a proxy
      answering 5xx, a stalled link past each timeout, a WebSocket closed
      mid-transfer; run against real OpenSSH like the interop harness.
- [ ] **Measured where it is meant to run**: the operator's real sandbox, and
      interactive use on Windows.
- [ ] **Publication**: tag `v0.1.0-beta.1`; the release workflow
      (`.github/workflows/release.yml`) builds static musl binaries for
      x86_64 and aarch64 and a Windows binary with checksums, and the notes
      (`docs/releases/v0.1.0-beta.1.md`) are written. Checks per artefact: a
      musl static-PIE binary reports `Type: DYN`, so the proof that it is
      static is no `NEEDED` entries and no `PT_INTERP` segment; `readelf` reads
      only ELF, so Windows uses `dumpbin /dependents` (an MSVC build needs
      `+crt-static`). README usage verified on a clean machine.
- [x] Git history cleaned before the repository went public (2026-10-08: one
      fresh commit; the old history kept only in a local bundle).
- [x] Repository made public; CI runs on every push (2026-10-08, green).
- Open: how the compiled-in `webpki-roots` certificates get updated in
  released binaries.

**Exit criteria**
- The interop and fault-injection harnesses pass in the gate.
- `podssh ssh` and `podssh proxy` work from the operator's real sandbox,
  including with one relay host made unreachable.

## M4 — `podssh-relay`, the reverse road, and podbox

- [ ] A C-free library crate `podssh-relay` ([design.md](design.md) section
      1): relay selection and the pool, tokens, pairing (`pair`, `stop`,
      `status`), the forward opener, the reverse node and operator runners
      ported from podbox's live-proven loops with podssh-transport's codecs
      folded in (one writer, `ready` before data, late bytes dropped, a capped
      pre-`ready` queue, close-code actions, liveness, jittered backoff), and a
      blocking facade for podbox. Rules so far: [reverse.md](reverse.md).
- [ ] `podssh-ws`: a caller-supplied `rustls::ClientConfig` (podbox keeps
      `ring` and TLS 1.2 for intercepting proxies), plain `ws://` on loopback
      for fake-relay tests, typed session errors, `probe::PrintChain` behind a
      feature.
- [ ] `podssh node NAME TARGET` (expose a local TCP service through the
      reverse road) and `podssh ssh NODE` / `podssh operator NAME`.

**Exit criteria**
- Two concurrent sessions through the live relay, from a sandbox whose only
  egress is a CONNECT proxy, to a node in another such sandbox.
- podbox builds against `podssh-relay` through its blocking facade and passes
  its own two-client test.

## M5 — `podssh serve`: into the cage

- [ ] russh's server inside the node: runs as whatever user the sandbox gives,
      with no passwd entry, setgroups, chroot, `/etc/shells` or `/var`; host
      key in a state file; authorized keys from a flag or file; exec;
      direct-tcpip into the cage.
- [ ] The terminal: a real pty when `/dev/ptmx` exists; otherwise an in-process
      line discipline (`podssh-terminal`, its inverted mode selection fixed)
      that signals the child's process group on Ctrl-C
      ([terminal.md](terminal.md)).
- [ ] SFTP in-process (`russh-sftp`, client and server).
- [ ] `podssh cp`/`mv`: SFTP, falling back to an exec transfer against minimal
      servers; write to a temporary name and rename only after verifying the
      digest; resumable by offset; rolling over to a new relay session before
      the relay's 64 MiB and 12 h caps. Across hosts `mv` is copy, verify,
      delete, and podssh says up front that it is not atomic; assume no POSIX
      tools or interactive-shell environment remotely.

**Exit criteria**
- From a sealed sandbox (no ptmx, no passwd, no bind), an operator gets a
  shell where `vi`, `less` and Ctrl-C work, and copies 200 MiB in and out with
  matching digests.

## M6 — Sessions that survive

- [ ] podssh's own resumable stream layer over the reverse road: per-direction
      byte offsets and acknowledgements, a bounded replay buffer with
      backpressure, a session id and resume secret, heartbeats that also keep
      the relay's idle cut away, rollover before the relay's caps, reconnect
      through any relay host.
- [ ] The iroh road, cargo feature `iroh` (`>= 1.1`, aws-lc-rs, the `Minimal`
      preset, podssh's proxy resolution, no UDP unless probed, dialled by
      ticket), raced with the reverse road. iroh relays are configurable; the
      default is n0's public relays until the operator runs his own iroh relay
      on his Cloudflare account, then his first and n0's as the fallback.
- [ ] Throughput measured on each road and relay, inside and outside a
      sandbox, before any default depends on it.

**Exit criteria**
- A session survives the relay host being killed, the client's address
  changing and a 3-minute stall, on both the resumable layer and the iroh
  road.

## M7 — `podssh pipe`, and `--persist`

- [ ] `podssh pipe A B`, listener-free: `stdio`, `fd:N`, `exec:CMD`
      (socketpair, pipes as the fallback), `unix-connect:PATH`,
      `relay:HOST:PORT`, `ssh:BASTION,HOST:PORT`, `node:NAME`, `iroh:TICKET`;
      local listening only after a probe shows it is allowed
      ([design.md](design.md) section 4).
- [ ] `--persist` for interactive sessions against stock sshd: reconnect and
      reattach `tmux` when the server has it (probed, never assumed).

## M8 — The rest

- Chat: redesigned on the two-podssh roads (end-to-end encrypted), or IRC as
  before ([irc.md](irc.md)); the operator decides when it starts.
- Tailscale (`podssh ts`, feature `ts`): first fix its DERP dial that ignores
  the proxy and its missing reconnect, then the two-node acceptance tests
  ([tailscale.md](tailscale.md)).
- `ssh_config` compatibility ([cli.md](cli.md)), `-R`, `status`.
- Relay-side resumption for stock sshd (a Durable Object owning the target
  socket across reconnects): not now; revisit after M6.
