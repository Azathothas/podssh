# Status

Measured on 2026-10-08 (Windows 11 host, native `cargo 1.98.0`,
`CARGO_BUILD_JOBS=4`, and the `rust:1-alpine` container gate). Update this page
whenever the state changes, with the date and the command that measured it.

## Summary

**`podssh ssh` and `podssh proxy` work; nothing else does yet.**

- `podssh ssh` is a native SSH client (on `russh`) with OpenSSH's command
  line. On 2026-10-08 it passed 60 of 61 checks against real OpenSSH and
  Dropbear servers in the container gate (the one failure was the test, fixed
  the same day), ran through the live relay to `railway.new`, and ran
  `--direct` against a Tailscale SSH server.
- `podssh proxy HOST PORT` carries a TCP stream through the relay, directly or
  through an HTTP CONNECT proxy, and works as an OpenSSH `ProxyCommand`
  (verified live 2026-10-08, including a 10-minute idle session).

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
| `podssh relay`, `status`, `doctor` | not implemented (exits 70) |
| `podssh man` | works: the manual page, generated from the flag tables |
| `podssh ts` | only with the `ts` cargo feature: status line and a `-W` byte pipe over a tailnet; the live two-node test has never run |

### `podssh ssh`, measured

| check | result |
| --- | --- |
| `scripts/interop.sh` in `rust:1-alpine`: the static binary against OpenSSH (Alpine `openssh-server`, with and without `PermitTTY`, and with PAM) and Dropbear on 127.0.0.1 | **60 of 61 passed**: exit statuses 3, 0, 1, 127 and 143 (a signal) on both servers; stdout/stderr apart; 262144, 262145 and 5,000,000 bytes up and round trip with equal digests, both servers; Ed25519, RSA, ECDSA, an encrypted key via `SSH_ASKPASS`, password via `SSH_ASKPASS` (both servers), wrong password, `BatchMode` refusals with notes, PAM keyboard-interactive; accept-new, strict, a changed key refused even with `StrictHostKeyChecking=no`; `-W` to Dropbear through OpenSSH; `-J` OpenSSH to Dropbear (exit 5); `SetEnv`; `-N`; `-tt` over pipes (remote pty, the `PermitTTY=no` fallback, Ctrl-C as a byte); a local pty (`interop-pty.py`): size, resize, Ctrl-C, `vi`, `less`, `top`, exit status, `~.`, terminal restored |
| the failure | `-s sftp` returned nothing: the test closed stdin at once, and OpenSSH's `sftp-server` exits on end of input without replying (reproduced on a Debian host without podssh). With stdin held open, `podssh ssh -s HOST sftp` returns `SSH_FXP_VERSION` (measured against a Tailscale SSH server). Test fixed; gate re-run pending |
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
| from a real constrained sandbox | **not yet run** |

## Components

| crate | size (src / tests, lines) | what holds | what is broken or missing |
| --- | --- | --- | --- |
| `podssh-ws` | 3.6k / 3.7k | TLS 1.3 through rustls with podssh's own pure-Rust crypto provider; certificate and hostname checks with no bypass; full-duplex session; HTTP CONNECT proxies; trust fallbacks; bounded connect, TLS and upgrade | no RSA signature verification (a relay chain with an RSA certificate would fail); control frames not size-checked on receive; `probe::PrintChain` (accepts any certificate) still a public export |
| `podssh-transport` | 5.6k / 3.9k | forward-path framing; reverse-path session-id codec and close-code table | about 600 lines are used outside tests; the reverse node leg sends control frames as binary and cannot work live; the 2.3k-line DNS/DoH stack is unused and cannot resolve anything; the backpressure module is unused |
| `podssh-ssh` | 3.0k / 0.2k | the native client: russh 0.64.1 (aws-lc-rs; strict key exchange and the ML-KEM hybrid key exchange in its defaults); a relay-to-stream pipe that keeps the relay's close reason; a `known_hosts` reader (hashed entries, wildcards, negation, markers); the auth chain; prompts via `/dev/tty`, `CONIN$` or `SSH_ASKPASS`; raw mode, resize, escapes; OpenSSH exit codes | no `ssh_config`; no `-L`/`-R`/`-D`/`-A`/X11; host certificates checked as plain keys; Windows interactive use not tested; no reconnect when the connection drops |
| `podssh-core` (`irc/`; the hand-written `ssh/` was removed 2026-10-08) | 3.8k / 1.9k | sans-IO client, message grammar, IRCv3 tags | registration hangs on IRCv3 servers (CAP END order); CRLF injection through message text; plaintext through the relay; file transfer never run live and broken for short final chunks |
| `podssh-terminal` | 2.5k / 1.2k | line-editing state machine | used by nothing; **mode selection inverted** (with no remote pty it refuses all input); no raw mode; cursor counts bytes, not characters |
| `podssh-cli` | 6.0k / 2.5k | parsing, help, generated man page, refusals; relay selection, token minting and caching, a shared relay opener; `proxy`; `ssh` option resolution (`-o`, destinations, defaults, transport) | 9 of 12 subcommands unimplemented; relay and token code lives in the binary crate, not a library (the unreachable `security/` module was removed 2026-10-08) |
| `podssh-ts` + `vendor/tailscale-rs` | 0.5k / 0.4k + 68k vendored | DERP over WebSocket (fork patches) | behind the `ts` feature; auto mode always picks `tcp`; live acceptance not run |
| `podssh-probe` | 0.4k / 0.3k | checks the relay document's structure against a pinned copy | used by nothing; duplicates `scripts/check-relay-spec.py` |

## Build, tests, CI

| what | result | how |
| --- | --- | --- |
| library crates (`podssh-ws`, `-transport`, `-core`, `-terminal`, `-probe`) | build and pass their tests with `CC=/nonexistent` | `scripts/gate.sh` |
| default tests | **601 passed, 0 failed, 1 ignored** (the live proxy test); fewer than before because the removed `security/` and hand-written SSH modules took their tests with them | `cargo test --no-fail-fast` |
| Tailscale feature tests | **226 passed, 0 failed, 2 ignored** (the live tests) | `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts` |
| repository checks | pass | `python scripts/check-repo.py` |
| static release binary | **3,586,496 bytes** with the SSH client (aws-lc and russh), static PIE, no `NEEDED` entries, no interpreter. It was 1,622,944 with `proxy` only, and 7,403,072 while the Tailscale fork was linked | `scripts/gate.sh` |
| container gate | every build and test step green; interop 60 of 61 (see above) | `sh scripts/dev.sh check` |
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
python scripts/check-repo.py
python scripts/check-relay-spec.py           # live relay
ssh -o ProxyCommand='target/debug/podssh proxy %h %p' -T git@github.com
sh scripts/dev.sh check                      # Linux gate and static binary
```

Set `CARGO_BUILD_JOBS=4` (or lower) first on machines with less than 32 GB of
memory; see [development.md](development.md).
