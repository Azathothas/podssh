# AGENTS.md

Guide for agents (and people) working on podssh. Short on purpose; the
details live in `docs/`.

## What this is

podssh is a static Rust binary that carries SSH — or any TCP stream — through a
WebSocket-to-TCP relay on port 443, for sandboxes whose only egress is HTTPS,
often only through an HTTP proxy. It is **early: `podssh proxy` (an OpenSSH
`ProxyCommand` through the relay) works; the native client and the other
subcommands do not yet.**

## Read first, in this order

1. [README.md](README.md)
2. [docs/STATUS.md](docs/STATUS.md) — the measured state.
3. [docs/ROADMAP.md](docs/ROADMAP.md) — what to do next: the first unchecked
   item of the current milestone.
4. [docs/decisions.md](docs/decisions.md) — the operator's decisions. Do not
   re-argue them; ask the operator if one seems wrong.

Then the page you need: [architecture](docs/architecture.md),
[relay](docs/relay.md), [target environment](docs/target-environment.md),
[command line](docs/cli.md), [terminal](docs/terminal.md),
[development](docs/development.md), the milestone pages
([reverse mode](docs/reverse.md), [IRC](docs/irc.md),
[Tailscale](docs/tailscale.md)), and the
[2026-10-08 audit](docs/audit-2026-10-08.md) for known defects with file and
line.

## Build safely

This machine nearly ran out of memory once (2026-10-07) when three uncapped
cargo builds overlapped.

- Always cap cargo: `export CARGO_BUILD_JOBS=4`.
- Run one build at a time. Never start a container build while another build
  is running.
- Day to day, build natively: `cargo build`, `cargo test` (default members,
  pure Rust). Use `--features ts` only when working on Tailscale.
- Linux-only checks and the static release binary: `sh scripts/dev.sh check`,
  which is capped and serialized by a lock.
- Never call `wsl.exe`, and never `wsl --shutdown`, `--terminate` or
  `--unregister`. Linux work goes through `scripts/dev.sh`.

## Rules

From [docs/decisions.md](docs/decisions.md):

- Never assume the client host has any privilege, tool or setup. Probe at
  runtime; a capability that was not probed is not used.
- One outbound connection, through `HTTPS_PROXY` when it is set. Never bind,
  listen or use loopback helpers.
- No `LD_PRELOAD` and no helper processes. No C in the library crates
  (`podssh-ws`, `podssh-transport`, `podssh-core`, `podssh-terminal`,
  `podssh-probe`); the binary links aws-lc for SSH (`russh`).
- Credentials never appear in output, logs, URLs, argv, commits or issues.
  Mint, use and discard a relay token in one shell. Never read or print
  `.env/`.
- No source file over 500 lines: split it, never trim comments to fit.
- Fix what you find broken in the same session. Prefer redundancy and
  fallbacks over minimal code.
- Leave the line endings of files you do not otherwise change.
- Work on `main`. Attribute commits to the operator alone, with no co-author
  lines. Push only verified work (tests and `python scripts/check-repo.py`
  green); never rewrite published history.
- `.tmp/` holds read-only clones of sibling projects. Never modify them, and
  check a clone exists before concluding anything from it.

## How to work

- Take the next unchecked [ROADMAP](docs/ROADMAP.md) item and finish it to its
  exit criteria before starting another.
- Test protocol code against something podssh did not write: OpenSSH or
  Dropbear servers, a real ircd, the live relay, or bytes captured from one.
  Tests that only check the code against itself have hidden many bugs here.
- Trust a new check only after it has failed on a planted defect and passed on
  correct input.
- Read exit codes directly, not through a pipe. Put a bound on every network
  and process wait.
- When the state changes, update [STATUS.md](docs/STATUS.md) (with the date and
  the command that measured it) and tick [ROADMAP](docs/ROADMAP.md) items in
  the same change. That is the whole record; there is no other bookkeeping.
- Comments explain why, briefly. No `⛔` emphasis, no session history, no
  doc line numbers in code.
- CI runs the gate on every push. Before each commit, run
  `python scripts/check-repo.py` and the tests.

## Map

| path | what it holds |
| --- | --- |
| `crates/podssh-cli` | the `podssh` binary: parsing, help, man page, dispatch |
| `crates/podssh-ws` | TLS (own pure-Rust rustls provider) and the WebSocket client |
| `crates/podssh-transport` | relay protocol framing for the forward, node and operator legs |
| `crates/podssh-core` | sans-IO protocol code: `ssh/`, `irc/` |
| `crates/podssh-terminal` | line discipline and terminal handling |
| `crates/podssh-probe` | relay document facts (tests only) |
| `crates/podssh-ts` | Tailscale adapter (feature `ts`) |
| `vendor/tailscale-rs` | vendored fork with local patches (`vendor/patches/`); outside the workspace and the 500-line rule |
| `scripts/` | `dev.sh` (container runs), `gate.sh` (the build gate), `plant.sh`, `check-*.py` |
| `docs/` | the documentation: STATUS, ROADMAP, decisions and topic pages |
