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

Then:
1. An interop harness: OpenSSH and Dropbear servers in a container, run
   against every change. No SSH change lands on self-consistency tests alone.
   Exit cases 7, 0, 1, 143 (a signal), 127, and a channel with no exit status;
   payloads of 262144 and 262145 bytes checked by digest; a clean close (a
   sibling's transport exited 1 on every clean close); the no-pty paths forced
   (`sshd -o PermitTTY=no`, a server that never answers `pty-req`, no local
   terminal) and a shell-only server that refuses `exec`.
2. Host keys: `known_hosts` lookup, trust-on-first-use prompt,
   `-o StrictHostKeyChecking=accept-new`, refusal with both fingerprints on a
   mismatch ([SECURITY.md](../SECURITY.md) lists the parsing traps).
3. Auth: publickey (ed25519, ecdsa, rsa-sha2), encrypted key files, agent if
   available; password and keyboard-interactive when a terminal or askpass
   exists.
4. Sessions: exec (`podssh ssh host cmd`) with stdout/stderr split and the
   remote exit status; interactive shell with a pty and raw local terminal;
   window size and resize ([terminal.md](terminal.md)). Keepalives are on by
   default (OpenSSH's default is off), every 60 s, below the relay's 180 s idle
   cut, and unanswered ones are counted.
5. Hosts with no local pty: the in-process line discipline
   (`podssh-terminal`), after fixing its inverted mode selection.

The command line follows OpenSSH; [cli.md](cli.md) has the measured details.

**Exit criteria**
- `podssh ssh user@host 'exit 3'` exits 3, against OpenSSH and Dropbear.
- An interactive session (`vi`, `less`, `top`, Ctrl-C) works from a normal
  terminal and from a host with no `/dev/ptmx`.

## M3 — Public beta

- [ ] Static release binaries (x86_64 and aarch64 Linux musl; Windows) with
      checksums, built by CI from a tag. Checks for each artefact: a musl
      static-PIE binary reports `Type: DYN`, so the proof that it is static is
      no `NEEDED` entries and no `PT_INTERP` segment; `readelf` reads only ELF,
      so Windows uses `dumpbin /dependents` (and an MSVC build needs
      `+crt-static` to avoid the VC runtime DLL); check `ldd`'s printed text,
      not its exit code, which varies.
- [ ] Git history cleaned before the repository goes public: it still contains
      notes about operator credentials, private test machines and a
      third-party sandbox capture that were removed from the tree on
      2026-10-08.
- [ ] Repository made public; CI runs on every push.
- [ ] README usage verified on a clean machine; known limitations listed.
- Open: how the compiled-in `webpki-roots` certificates get updated in
  released binaries.

## After the beta (order to be confirmed by the operator)

- **M4 — reverse mode** (`podssh node` / `podssh operator`): reach a host whose
  only egress is the relay. Rules so far: [reverse.md](reverse.md).
- **M5 — chat** (`podssh chat`): IRC between two constrained users. The current
  client hangs at registration on IRCv3 servers and sends plaintext through the
  relay; both must be fixed first. Which servers work: [irc.md](irc.md).
- **M6 — Tailscale** (`podssh ts`, feature `ts`): finish the DERP-over-relay
  node and the two-node acceptance tests ([tailscale.md](tailscale.md)).
- **M7 — the rest**:
  - `cp`/`mv`: write to a temporary name and rename only after verifying;
    across hosts `mv` is copy, verify, delete the source, and podssh says up
    front that it is not atomic; prefer `exec` (sandbox servers may have no
    sftp) and assume no POSIX tools or interactive-shell environment remotely.
  - `doctor`: each check is `ok`, `FAIL` or `????`; unknowns are counted
    separately and never fail the run; a check that did not run is never `ok`;
    print what was actually opened; identify servers by equality (the expected
    host key), never by the shape of a banner (a banner-shape check once graded
    the wrong server as good).
  - `status`, and `ssh_config` compatibility ([cli.md](cli.md)).
