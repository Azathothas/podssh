# Status

Measured on 2026-10-08 (Windows 11 host, native `cargo 1.98.0`,
`CARGO_BUILD_JOBS=4`, and the `rust:1-alpine` container gate). Update this page
whenever the state changes, with the date and the command that measured it.

## Summary

**`podssh proxy` works; nothing else does yet.** `podssh proxy HOST PORT`
carries a TCP stream through the relay, directly or through an HTTP CONNECT
proxy, and works as an OpenSSH `ProxyCommand`. That was verified live on
2026-10-08: OpenSSH reached GitHub's authentication step and pinned GitHub's
published host key, from Windows, from the static Linux binary, and through a
proxy that only allows port 443.

The native SSH client, reverse mode, chat and the other subcommands are not
implemented. A review found wire-level bugs in the SSH and IRC code that the
unit tests did not catch: many tests check the code against itself, and some
encode the bugs as expected behaviour. Details, with file and line, are in
[audit-2026-10-08.md](audit-2026-10-08.md); the plan is in
[ROADMAP.md](ROADMAP.md).

## Subcommands

| subcommand | state |
| --- | --- |
| `podssh proxy HOST PORT` | **works** (2026-10-08): byte pipe through the relay; `HTTPS_PROXY`/`NO_PROXY`; token minted and cached; trust-root fallbacks; one-line errors with sysexits codes |
| `podssh ssh` | not implemented (exits 70) — milestone 2 |
| `podssh node`, `podssh operator` | not implemented (exits 70) |
| `podssh chat` | not implemented (exits 70) |
| `podssh cp`, `podssh mv` | not implemented (exits 70) |
| `podssh relay`, `status`, `doctor` | not implemented (exits 70) |
| `podssh man` | works: the manual page, generated from the flag tables |
| `podssh ts` | only with the `ts` cargo feature: status line and a `-W` byte pipe over a tailnet; the live two-node test has never run |

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
| `podssh-core` (`ssh/`) | 2.2k / 0.9k | RFC 4251 codec, exchange hash, AEAD primitive wiring, ed25519 host-key verification | no session driver; against OpenSSH it fails at the first encrypted packet, at publickey auth, at channel open and at pty-req; a peer-triggerable panic; no strict-kex (Terrapin) countermeasure |
| `podssh-core` (`irc/`) | 3.8k / 1.9k | sans-IO client, message grammar, IRCv3 tags | registration hangs on IRCv3 servers (CAP END order); CRLF injection through message text; plaintext through the relay; file transfer never run live and broken for short final chunks |
| `podssh-terminal` | 2.5k / 1.2k | line-editing state machine | used by nothing; **mode selection inverted** (with no remote pty it refuses all input); no raw mode; cursor counts bytes, not characters |
| `podssh-cli` | 7.2k / 3.8k | parsing, help, generated man page, refusals; `proxy` with relay selection, token minting and caching | 10 of 12 subcommands unimplemented; the old `security/` module (known_hosts, a token cache) is unreachable and has latent bugs; `proxy` uses the new `token_cache.rs` instead |
| `podssh-ts` + `vendor/tailscale-rs` | 0.5k / 0.4k + 68k vendored | DERP over WebSocket (fork patches) | behind the `ts` feature; auto mode always picks `tcp`; live acceptance not run |
| `podssh-probe` | 0.4k / 0.3k | checks the relay document's structure against a pinned copy | used by nothing; duplicates `scripts/check-relay-spec.py` |

## Build, tests, CI

| what | result | how |
| --- | --- | --- |
| default build (6 crates, no Tailscale) | builds; its dependency graph has no `cc`, `ring` or `aws-lc` | `cargo build`; `cargo tree -e normal,dev,build` |
| default tests | **651 passed, 0 failed, 1 ignored** (the live proxy test) | `cargo test --no-fail-fast` |
| Tailscale feature tests | **226 passed, 0 failed, 2 ignored** (the live tests) | `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts` |
| repository checks | pass | `python scripts/check-repo.py` |
| static release binary | **1,622,944 bytes**, static PIE, no `NEEDED` entries, no interpreter, built with no C compiler. It was 598,776 bytes before `proxy` linked the TLS and WebSocket client, and 7,403,072 while the Tailscale fork was linked | `scripts/gate.sh` |
| container gate | **green** (every step exit 0, about 4 min at 4 jobs; WSL VM peaked near 7 GB) | `sh scripts/dev.sh check` |
| no-C plant | fires twice for the right reason (a planted `ring` fails because no C compiler exists), control passes | `sh scripts/dev.sh plant` |
| CI | failed on 25 of the 27 pushes since 2026-10-05, always the same cause (a test fixture lost its CRLFs on checkout; fixed 2026-10-08). CI runs once the repository is public | `gh run list` |

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
