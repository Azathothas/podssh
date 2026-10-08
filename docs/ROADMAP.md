# Roadmap

This page gives the milestones of podssh, in order. Each milestone ends with
something that a user can run. Its exit criteria are commands and results.
[STATUS.md](STATUS.md) gives the measured state.

- Do one milestone at a time, in order.
- Do not start the next milestone until the exit criteria of the current
  one pass on a real host.
- In a milestone, do the first item that is not done (`- [ ]`).
- When an item is done, mark it `- [x]`, and record the measurement in
  [STATUS.md](STATUS.md) in the same commit.

## M0: Repository rescue (done 2026-10-08)

- [x] The real state is measured: build, tests, binary behaviour, CI.
- [x] CI passes: the IRC grammar fixture keeps its CRLFs.
- [x] Each script limits the build jobs.
- [x] The Tailscale adapter is the cargo feature `ts`; the default build has
      no Tailscale code.
- [x] The documents are README, STATUS, ROADMAP, decisions, defects, a short
      AGENTS.md, and topic pages.

## M1: `podssh proxy`, a byte pipe through the relay (done 2026-10-08)

A host that has `ssh` reaches SSH servers through the relay:
`ssh -o ProxyCommand='podssh proxy %h %p' user@host`. The pipe also works for
each TCP protocol that a tool can speak over stdin and stdout.

- [x] The relay client (`podssh-ws`): full duplex; limits on TCP, the proxy
      exchange, TLS and the upgrade; an idle read limit above the relay's
      keepalive (25 s); WebSocket Close sent, echoed and parsed; fragmented
      messages joined; typed errors that keep the relay's status and reason.
- [x] `HTTPS_PROXY`: `CONNECT relay:443` with the host name (no DNS on the
      client); `https_proxy`, `ALL_PROXY`, `NO_PROXY`; Basic proxy
      credentials.
- [x] Trust roots with fallbacks: `--ca-file` or `SSL_CERT_FILE` alone;
      else a `podssh-ca.pem` next to the binary, the first system bundle, and
      the compiled-in Mozilla roots.
- [x] Tokens: minted with `POST /v1/mint`, cached for each relay, minted
      again once when the relay refuses a cached token; `PODSSH_RELAY_TOKEN`.
      Never printed.
- [x] The command `podssh proxy HOST PORT`.
- [x] A default relay, `tcp.ssh.relay.ajam.dev`, that `--relay-host` and
      `PODSSH_RELAY` override.

**Exit criteria**

- [x] `ssh -o ProxyCommand='podssh proxy %h %p' git@github.com` reaches the
      authentication step of GitHub: on Windows, with the static Linux
      binary, and through a CONNECT proxy that allows only port 443.
- [ ] The same from a constrained sandbox. See M3, "Measured in the
      operator's real sandbox".
- [x] An idle session with `ServerAliveInterval=60` stays up for 10
      minutes.

## M2: `podssh ssh`, a client for hosts with no `ssh` (done 2026-10-08)

The client is `russh` with the `aws-lc-rs` backend
([decisions.md](decisions.md)). podssh keeps its own code for the transport
(relay, proxy, TLS), host keys, the terminal and the command line.

- [x] An interop harness that the gate runs on each change
      (`scripts/interop.sh`, `scripts/interop-pty.py`; 62 checks).
- [x] Host keys: `known_hosts` lookup (hashed entries, wildcards, negation,
      `@revoked`), the prompt on first use, accept-new, and refusal of a
      changed key with both fingerprints.
- [x] Authentication: agent, key files (Ed25519, ECDSA, RSA with SHA-2),
      encrypted keys, keyboard-interactive and password, from the terminal or
      `SSH_ASKPASS`.
- [x] Sessions: exec with stdout and stderr apart and the remote exit status;
      a shell with a pty and a raw local terminal; window size and resize;
      `~.`; keepalives every 60 s.
- [x] The hand-written client and the unused `security` module are removed.
- The line discipline in the process (`podssh-terminal`) moved to M5.

**Exit criteria**

- [x] `podssh ssh user@host 'exit 3'` exits 3 against OpenSSH and Dropbear,
      and through the relay.
- [x] An interactive session (`vi`, `less`, `top`, Ctrl-C) works from a
      terminal, from a host with no `/dev/ptmx` (`-tt` over pipes), and on
      Windows.
- [ ] The same from the operator's real sandbox. See M3.

## M3: Beta, with nothing single-point and nothing assumed

The first beta waits for M3 ([decisions.md](decisions.md)). After M3, no
single relay host, missing DNS or silent stop can stop podssh.

- [x] **Relay hosts with failover** (`podssh-relay`). `--relay-host` and
      `PODSSH_RELAY` take an ordered list. By default, the main host comes
      first, then up to three hosts of the pool. One attempt for each host,
      limited to 45 s. An error that another host can repair goes to the next
      host; an error that each host gives stops at once. `ConnectionAttempts`
      repeats the rounds, with a jittered backoff.
- [x] **Liveness.** The session pings the relay every 10 s. After three
      checks in a row with no frame at all, the link is dead: 30 to 40 s.
      The rule applies only after the relay answers a ping.
- [x] **No proxy and no DNS.** The dialer uses, in order: an IP literal; a
      pinned address (`--relay-addr HOST=IP`, `PODSSH_RELAY_ADDR`); the
      system resolver; DNS over HTTPS to Cloudflare and Google by IP literal.
      TLS always checks the relay's name.
- [x] **`podssh doctor`.** One `ok`, `FAIL` or `????` line for each check
      of the host, the egress and the relay. Unknowns never fail the run.
      Servers are identified by equality (the expected host key), never by
      the form of a banner.
- [x] **`podssh keygen`** for hosts with no working `ssh-keygen`. OpenSSH
      reads its keys and accepts them.
- [x] **A fault-injection harness** in the gate (`scripts/interop-faults.sh`,
      11 faults).
- [x] **Interactive use on Windows** (`scripts/interop-conpty.py`, 14
      checks in a real pseudo console).
- [x] **`podssh man`, the whole manual from the binary.** Text that the
      binary generates from its own tables, paged on a terminal, with
      `--no-pager`, `--roff` and one section at a time. Tests check it
      against the code; the gate renders it with groff and mandoc.
- [x] **A box like the target sandbox** (`scripts/test_in_box.sh`): a Podman
      box that matches the sandprobe report of the target sandbox. podssh
      passes all its checks in the box.
- [ ] **Measured in the operator's real sandbox.** Run
      `sh scripts/sandbox-check.sh` there. With no argument it builds
      podssh, then runs `doctor`, `proxy`, `keygen`, `ssh`, and OpenSSH with
      podssh as its `ProxyCommand`. Record the output in STATUS.
- [ ] **Publication.** Tag `v0.1.0-beta.1`. The release workflow builds the
      static musl binaries for x86_64 and aarch64 and the Windows binary,
      checks them, and publishes them with `SHA256SUMS` and the notes in
      `docs/releases/v0.1.0-beta.1.md`. Before the tag: update the notes
      with the sandbox result, and run the commands of the README on a clean
      host with the release workflow's binary.
- [x] The git history was replaced by one commit before the repository went
      public. The old history is in a local bundle.
- [x] The repository is public. CI runs the gate on each push.

Open question: how do the compiled-in `webpki-roots` certificates get updates
in released binaries?

**Exit criteria**

- The interop and fault-injection harnesses pass in the gate.
- `podssh ssh` and `podssh proxy` work from the operator's real sandbox,
  also when one relay host cannot be reached.

## M4: `podssh-relay`, the reverse road, and podbox

- [ ] Add to the C-free crate `podssh-relay` ([design.md](design.md),
      section 1): pairing (`pair`, `stop`, `status`), the reverse node and
      operator runners, and a blocking facade for podbox. Port the runners
      from podbox, which works live, and move the codecs of
      `podssh-transport` into them: one writer, `ready` before data, late
      bytes dropped, a limited queue before `ready`, actions for each close
      code, liveness, jittered backoff. First repair the defects of
      `podssh-transport` that these runners use ([defects.md](defects.md):
      T1, T2, T5, T8, T9). The rules so far: [reverse.md](reverse.md).
- [ ] `podssh-ws`: a `rustls::ClientConfig` that the caller supplies (podbox
      keeps `ring` and TLS 1.2 for intercepting proxies), plain `ws://` on
      loopback for tests, typed session errors, and `probe::PrintChain`
      behind a feature (defect W14).
- [ ] `podssh node NAME TARGET` (a local TCP service through the reverse
      road), and `podssh ssh NODE` and `podssh operator NAME`.

**Exit criteria**

- Two sessions at the same time through the live relay, from a sandbox whose
  only egress is a CONNECT proxy, to a node in another such sandbox.
- podbox builds against `podssh-relay` through its blocking facade and passes
  its own test with two clients.

## M5: `podssh serve`, into the cage

- [ ] The server of russh in the node. It runs as the user that the sandbox
      gives, with no passwd entry, setgroups, chroot, `/etc/shells` or
      `/var`. The host key is in a state file. Authorized keys come from a
      flag or a file. It supplies exec, and direct-tcpip into the cage.
- [ ] The terminal: a real pty when `/dev/ptmx` exists. Else the line
      discipline in the process (`podssh-terminal`, with defects L1 to L5
      repaired), which signals the process group of the child on Ctrl-C
      ([terminal.md](terminal.md)).
- [ ] SFTP in the process (`russh-sftp`, client and server).
- [ ] `podssh cp` and `podssh mv`: SFTP, with an exec transfer as the
      fallback for minimal servers. Write to a temporary name, and rename only
      after the digest is correct. Continue from an offset after a drop. Open
      a new relay session before the limits of the relay (64 MiB, 12 h).
      Across hosts, `mv` is copy, verify, delete; podssh says first that it is
      not atomic. Do not assume POSIX tools or an interactive shell on the
      remote host.

**Exit criteria**

- From a sealed sandbox (no ptmx, no passwd, no bind), an operator gets a
  shell where `vi`, `less` and Ctrl-C work, and copies 200 MiB in and out
  with matching digests.

## M6: Sessions that survive

- [ ] podssh's own resumable stream layer over the reverse road: byte
      offsets and acknowledgements for each direction, a limited replay
      buffer with backpressure, a session id and a resume secret, heartbeats
      that also prevent the relay's idle cut, a new session before the
      relay's limits, and reconnection through each relay host.
- [ ] The iroh road, cargo feature `iroh` (version 1.1 or later, aws-lc-rs,
      the `Minimal` preset, podssh's proxy resolution, no UDP unless probed,
      dialled by ticket), raced with the reverse road. The iroh relays are
      configurable. The default is n0's public relays until the operator runs
      an iroh relay on the operator's Cloudflare account; then that relay is
      first and n0's relays are the fallback.
- [ ] Throughput measured on each road and relay, in and out of a sandbox,
      before a default depends on it.

**Exit criteria**

- A session survives a stopped relay host, a change of the client's address
  and a stall of 3 minutes, on the resumable layer and on the iroh road.

## M7: `podssh pipe`, and `--persist`

- [ ] `podssh pipe A B`, with no listener: `stdio`, `fd:N`, `exec:CMD` (a
      socketpair, with pipes as the fallback), `unix-connect:PATH`,
      `relay:HOST:PORT`, `ssh:BASTION,HOST:PORT`, `node:NAME`, `iroh:TICKET`.
      A local listener only after a probe shows that it is allowed
      ([design.md](design.md), section 4).
- [ ] `--persist` for interactive sessions against a standard sshd: connect
      again and attach `tmux` again when the server has it (probed, never
      assumed).

## M8: The rest

- Chat: a new design on the roads between two podssh binaries (end-to-end
  encrypted), or IRC as before ([irc.md](irc.md)). The operator decides when
  it starts.
- Tailscale (`podssh ts`, feature `ts`): first repair its DERP dial, which
  does not use the proxy, and its missing reconnection; then the tests with
  two nodes ([tailscale.md](tailscale.md)).
- Compatibility with `ssh_config` ([cli.md](cli.md)), `-R`, and `status`.
- Resumption in the relay for a standard sshd (a Durable Object that keeps
  the target socket across reconnections): not now; look at it again after
  M6.
