# Status

Measured on 2026-10-08 (Windows 11 host, native `cargo 1.98.0`,
`CARGO_BUILD_JOBS=4`, and the `rust:1-alpine` container gate). Update this page
whenever the state changes, with the date and the command that measured it.

## Summary

**`podssh ssh`, `podssh proxy`, `podssh doctor` and `podssh keygen` work;
nothing else does yet.**

- `podssh ssh` is a native SSH client (on `russh`) with OpenSSH's command
  line. On 2026-10-08 it passed all 62 checks against real OpenSSH and
  Dropbear servers in the container gate, ran through the live relay to
  `railway.new`, and ran `--direct` against a Tailscale SSH server.
- `podssh proxy HOST PORT` carries a TCP stream through the relay, directly or
  through an HTTP CONNECT proxy, and works as an OpenSSH `ProxyCommand`
  (verified live 2026-10-08, including a 10-minute idle session).
- `podssh doctor` reports what a host allows and whether the relay path
  works, one `ok`/`FAIL`/`????` line per check (2026-10-08: Windows, the Linux
  container, and through a CONNECT proxy that allows only port 443).

Reverse mode, chat, file copy and the other subcommands are not implemented.
The IRC code has wire-level bugs found by review
([audit-2026-10-08.md](audit-2026-10-08.md)); the plan is in
[ROADMAP.md](ROADMAP.md).

## Subcommands

| subcommand | state |
| --- | --- |
| `podssh proxy HOST PORT` | **works** (2026-10-08): byte pipe through the relay; `HTTPS_PROXY`/`NO_PROXY`; token minted and cached; trust-root fallbacks; one-line errors with sysexits codes |
| `podssh ssh` | **works** (2026-10-08): through the relay or `--direct`; OpenSSH options; host keys, agent/keys/password/keyboard-interactive; exec, shell, subsystem, `-W`, `-J`, `-N`; ptys with raw mode, resize and `~.`; OpenSSH exit codes |
| `podssh node`, `podssh operator` | not implemented (exits 70) |
| `podssh chat` | not implemented (exits 70) |
| `podssh cp`, `podssh mv` | not implemented (exits 70) |
| `podssh doctor` | **works** (2026-10-08): host, egress and relay checks; exit 0, or 1 when a check failed |
| `podssh keygen` | **works** (2026-10-08): Ed25519, ECDSA and RSA key pairs in OpenSSH's format; `-y`, `-l`; passphrases asked for, never taken from argv |
| `podssh relay`, `status` | not implemented (exits 70) |
| `podssh man` | works: the manual page, generated from the flag tables |
| `podssh ts` | only with the `ts` cargo feature: status line and a `-W` byte pipe over a tailnet; the live two-node test has never run |

### `podssh ssh`, measured

| check | result |
| --- | --- |
| `scripts/interop.sh` in `rust:1-alpine`: the static binary against OpenSSH (Alpine `openssh-server`, with and without `PermitTTY`, and with PAM) and Dropbear on 127.0.0.1 | **62 of 62 passed** (second run; the first passed 60 of 61, see below): exit statuses 3, 0, 1, 127 and 143 (a signal) on both servers; stdout/stderr apart; 262144, 262145 and 5,000,000 bytes up and round trip with equal digests, both servers; Ed25519, RSA, ECDSA, an encrypted key via `SSH_ASKPASS`, password via `SSH_ASKPASS` (both servers), wrong password, `BatchMode` refusals with notes, PAM keyboard-interactive; accept-new, strict, a changed key refused even with `StrictHostKeyChecking=no`; `-W` to Dropbear through OpenSSH; `-J` OpenSSH to Dropbear (exit 5); `SetEnv`; `-N`; `-tt` over pipes (remote pty, the `PermitTTY=no` fallback, Ctrl-C as a byte); `vi` through pipes; `-s sftp` answering `SSH_FXP_VERSION`; a local pty (`interop-pty.py`): size, resize, Ctrl-C, `vi`, `less`, `top`, exit status, `~.`, terminal restored |
| the first run's failure | `-s sftp` returned nothing: the test closed stdin at once, and OpenSSH's `sftp-server` exits on end of input without replying (reproduced on a Debian host without podssh). With stdin held open, `podssh ssh -s HOST sftp` returns `SSH_FXP_VERSION`; the test now holds it open |
| through the relay to `railway.new` (anonymous SSH service, throwaway key), Windows build | `exit 3` gives 3; host key recorded with accept-new; stdout/stderr apart; 300 KB up and 5 MB down with equal digests; changed, revoked, strict-unknown and batch-unknown host keys all refused (255) with the fingerprints; `-W` refused by that server, reported, 255 |
| `--direct` to a Tailscale SSH server over the tailnet, Windows build | a command and exit status 4 passed through; `-s sftp` |
| a remote command killed by a signal, on `railway.new` | 255, as OpenSSH: that server reports exit status -1 instead of an exit signal |
| interactive sessions on Windows | **not yet run** |
| from a real constrained sandbox | **not yet run** |

### `podssh proxy`, measured live

| check | result |
| --- | --- |
| Windows OpenSSH 10.3 → `podssh proxy` → relay → `github.com:22` | auth step reached (`Permission denied (publickey)` with a throwaway key); host key `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` = GitHub's published Ed25519 key; 2.9 s including minting |
| same, through a local CONNECT proxy allowing only port 443 | the proxy saw exactly two `CONNECT tcp.ssh.relay.ajam.dev:443` (mint, session); no client-side DNS |
| a proxy that refuses the relay's port | `the proxy … refused CONNECT …: 403 not on the egress allowlist`, exit 77 |
| Alpine OpenSSH + the static musl binary, in the container | same auth step and host key |
| HTTP to `example.com:80` with stdin closed before the reply | full reply, exit 0 |
| unknown host / private address | relay's reason passed through (`does not resolve`, `blocked address range`), exit 69 / 77 |
| `cargo test -p podssh-cli --test proxy_live -- --ignored` | GitHub's SSH banner through the relay |
| a real login: Windows OpenSSH → `podssh proxy` → relay → `railway.new` (anonymous SSH service, throwaway key) | shell and `exit 3` work; `ssh` exits 3 |
| idle session, `ServerAliveInterval=60`, remote `sleep 600` | survived: 602 s, exit 0 |
| the same with `ServerAliveInterval=0` (control) | cut by the relay after 184 s (its 180 s idle cut), `ssh` exit 255 |
| relay failover: `--relay-host "tcp.ssh.relay.ajam.dev:9,tcp-eu-west-3.ssh.relay.ajam.dev"` to `github.com:22` | the first host timed out after 20 s and was named; the second, a pool host, accepted the token cached for the default host and delivered GitHub's banner (2026-10-08) |
| liveness: the relay answers WebSocket pings | 3 pongs for 3 pings (`cargo test -p podssh-relay --test live -- --ignored`) |
| a 50 s idle session through `podssh proxy` with `ServerAliveInterval=0` | stayed up under the 10 s ping watcher, exit 0 |
| DNS over HTTPS: `github.com` through each of 1.1.1.1, 8.8.8.8, 1.0.0.1, 8.8.4.4 alone | all answer through verified TLS (`cargo test -p podssh-ws --test live_doh -- --ignored`); Google's needed RSA verification, added that day |
| `--relay-addr tcp.ssh.relay.ajam.dev=104.21.39.2` (the relay's real address) | GitHub's banner through the relay |
| `--relay-addr tcp.ssh.relay.ajam.dev=1.1.1.1` (a wrong address) | Cloudflare's edge there holds a valid certificate for the name and refuses the request (its error 1034); podssh failed over to a pool host and the session opened |
| from a real constrained sandbox | **not yet run** |

### `podssh doctor`, measured

| where | result |
| --- | --- |
| Windows 11, native debug build, no proxy | 16 ok, 0 FAIL, 0 ????; exit 0 in about 4 s. Four relay hosts answered `/health` (`tcp-ssh-relay 2026-10-03-r2`) over TLS 1.3 with verified certificates, each line naming the address opened; the forward session to `github.com:22` met GitHub's published Ed25519 key `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`; clock within 2 s |
| the same, through a local CONNECT proxy that allows only port 443 | 17 ok; `CONNECT` lines: the relay and `github.com:443` allowed, `github.com:22` refused with the proxy's `403 not on the egress allowlist`; every relay line says `opened CONNECT … through` the proxy. The proxy's log listed exactly the connections the report named |
| `--relay-host dead-host.invalid,tcp.ssh.relay.ajam.dev` | exit 1, 2 FAIL: DNS over HTTPS (`1.1.1.1 answered that dead-host.invalid does not exist`) and that relay host; the token and the forward session went through the second host (`after dead-host.invalid failed`) |
| a studio host on the tailnet (Ubuntu 22.04), the release workflow's static x86_64 binary | 25 ok, exit 0, 3.9 s: open egress (`github.com:22` reachable directly), the system trust store added to the compiled-in roots, every relay host answering |
| `rust:1-alpine` container, as root | 26 ok, exit 0: a passwd entry, `/proc`, a pty (`/dev/pts/0`), AF_INET and AF_UNIX bind (file and abstract) allowed; a copy of podssh ran from `/tmp`, `/var/tmp`, `/root` and `/work`, and was refused in `/dev/shm`, which the report named as a noexec mount; trust store from `SSL_CERT_FILE` |
| `cargo test -p podssh-cli --test doctor` | offline: network checks reported as one `????`, never `ok`; planted failures (no `HOME`, an unusable proxy setting) give `FAIL` and exit 1; proxy credentials and a token in the environment never appear in the output |
| `cargo test -p podssh-cli --test doctor -- --ignored` | the live path end to end, exit 0 (3.6 s) |

### `podssh keygen`, measured

| check | result |
| --- | --- |
| `scripts/interop-keygen.sh` in the container gate, against Alpine's OpenSSH | **25 of 25**: for Ed25519, ECDSA P-384 and RSA 3072, OpenSSH's `ssh-keygen -y` reads the private key and derives the `.pub` key, `ssh-keygen -l` prints the same line as `podssh keygen -l`, `podssh keygen -y` agrees, and `sshd` accepts the key for login; modes 600 and 644; a key encrypted with a passphrase from `SSH_ASKPASS` decrypts with OpenSSH, a wrong passphrase is refused, and it logs in; overwriting a key is refused (exit 1, the key unchanged); `-N 'secret words'` is refused (exit 64, nothing written) |
| Windows, against OpenSSH 10.3p1's `ssh-keygen` | the same `-y` and `-l` agreement for all three types |
| `cargo test -p podssh-cli --test keygen` | the private key never appears in any output; no way to ask for a passphrase (no terminal: the test detaches from it) refuses and names `-N ''` |

## Components

| crate | size (src / tests, lines) | what holds | what is broken or missing |
| --- | --- | --- | --- |
| `podssh-ws` | 4.2k / 4.0k | TLS 1.3 through rustls with podssh's own pure-Rust crypto provider (ECDSA P-256/P-384, Ed25519, RSA PKCS #1 and PSS); certificate and hostname checks with no bypass; full-duplex session with ping liveness; HTTP CONNECT proxies (never for loopback); trust fallbacks; bounded connect, TLS and upgrade; pinned addresses and DNS over HTTPS when the system resolver fails (a name that does not exist ends the lookup at the first answer) | no TLS 1.2 (some intercepting proxies need it); control frames not size-checked on receive; `probe::PrintChain` (accepts any certificate) still a public export |
| `podssh-relay` | 1.2k / 0.2k | relay host lists, the cached pool and failover; tokens minted, cached and re-minted; the forward opener (moved out of `podssh-cli` 2026-10-08; no C) | no reverse node/operator legs or pairing yet (M4) |
| `podssh-transport` | 5.6k / 3.9k | forward-path framing; reverse-path session-id codec and close-code table | about 600 lines are used outside tests; the reverse node leg sends control frames as binary and cannot work live; the 2.3k-line DNS/DoH stack is unused and cannot resolve anything; the backpressure module is unused |
| `podssh-ssh` | 3.1k / 0.1k | the native client: russh 0.64.1 (aws-lc-rs; strict key exchange and the ML-KEM hybrid key exchange in its defaults); a relay-to-stream pipe that keeps the relay's close reason; a `known_hosts` reader (hashed entries, wildcards, negation, markers); the auth chain; prompts via `/dev/tty`, `CONIN$` or `SSH_ASKPASS`; raw mode, resize, escapes; OpenSSH exit codes; a host-key probe that never authenticates (for `doctor`) | no `ssh_config`; no `-L`/`-R`/`-D`/`-A`/X11; host certificates checked as plain keys; Windows interactive use not tested; no reconnect when the connection drops |
| `podssh-core` (`irc/`; the hand-written `ssh/` was removed 2026-10-08) | 3.8k / 1.9k | sans-IO client, message grammar, IRCv3 tags | registration hangs on IRCv3 servers (CAP END order); CRLF injection through message text; plaintext through the relay; file transfer never run live and broken for short final chunks |
| `podssh-terminal` | 2.5k / 1.2k | line-editing state machine | used by nothing; **mode selection inverted** (with no remote pty it refuses all input); no raw mode; cursor counts bytes, not characters |
| `podssh-cli` | 7.0k / 2.9k | parsing, help, generated man page, refusals; `proxy`; `ssh` option resolution (`-o`, destinations, defaults, transport); `doctor` | 7 of 12 subcommands unimplemented (`node`, `operator`, `chat`, `cp`, `mv`, `relay`, `status`) |
| `podssh-ts` + `vendor/tailscale-rs` | 0.5k / 0.4k + 68k vendored | DERP over WebSocket (fork patches) | behind the `ts` feature; auto mode always picks `tcp`; live acceptance not run |
| `podssh-probe` | 0.4k / 0.3k | checks the relay document's structure against a pinned copy | used by nothing; duplicates `scripts/check-relay-spec.py` |

## Build, tests, CI

| what | result | how |
| --- | --- | --- |
| library crates (`podssh-ws`, `-transport`, `-core`, `-terminal`, `-probe`) | build and pass their tests with `CC=/nonexistent` | `scripts/gate.sh` |
| default tests | **647 passed, 0 failed, 5 ignored** (the live tests: proxy, doctor, relay pings, DNS over HTTPS twice), Windows, 2026-10-08 | `cargo test --no-fail-fast` |
| Tailscale feature tests | **226 passed, 0 failed, 2 ignored** (the live tests) | `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts` |
| repository checks | pass | `python scripts/check-repo.py` |
| static release binary | **4,008,448 bytes** with the SSH client (aws-lc and russh), `doctor` and `keygen`, static PIE, no `NEEDED` entries, no interpreter. It was 3,848,704 before `keygen`, 3,586,496 before `doctor`, 1,622,944 with `proxy` only, and 7,403,072 while the Tailscale fork was linked | `scripts/gate.sh` |
| container gate | **green** (2026-10-08, with `doctor` and `keygen`): every build and test step, and interop 87 of 87 (62 SSH checks, 25 keygen checks) | `sh scripts/dev.sh check` |
| no-C plant | fires twice for the right reason (a planted `ring` fails because no C compiler exists), control passes | `sh scripts/dev.sh plant` |
| CI | the repository is public since 2026-10-08; the first run on it (commit `9a03102`) passed | `gh run list` |

## The relay

`tcp.ssh.relay.ajam.dev` reports version `2026-10-03-r2`; its published
document is byte-identical to the pinned copy
(SHA-256 `88eb1b0b8571b829daab17614ea2e27966ba5611951ea28db84660fc41cfa5a8`),
and `python scripts/check-relay-spec.py` passes against it. Limits from
`/relays.json`: 262144-byte frames, 180 s idle cut, 12 h and 64 MiB per session.
See [relay.md](relay.md).

## Re-measuring

```sh
cargo test                                   # default members
cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts
cargo test -p podssh-cli --test proxy_live -- --ignored   # network: live relay
cargo test -p podssh-cli --test doctor -- --ignored       # network: live relay
target/debug/podssh doctor                   # this host, its egress, the relay
python scripts/check-repo.py
python scripts/check-relay-spec.py           # live relay
ssh -o ProxyCommand='target/debug/podssh proxy %h %p' -T git@github.com
sh scripts/dev.sh check                      # Linux gate and static binary
```

Set `CARGO_BUILD_JOBS=4` (or lower) first on machines with less than 32 GB of
memory; see [development.md](development.md).
