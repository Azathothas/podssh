# Decisions

Decisions the operator (the project owner) has made, newest first within each
section. They are not re-argued without the operator. When one changes, edit
it here and say what replaced it; do not leave two versions standing.

## Product

| date | decision |
| --- | --- |
| 2026-10-08 | **Native SSH is `russh` with the `aws-lc-rs` backend, in the default build.** The no-C rule now covers the library crates only (`podssh-ws`, `podssh-transport`, `podssh-core`, `podssh-terminal`, `podssh-probe`); the `podssh` binary links aws-lc. The hand-written SSH code is retired once `podssh ssh` works. |
| 2026-10-08 | **Going public:** the git history is replaced by one fresh commit (the old history kept in a local bundle), old CI runs deleted, the repository made public. After that, verified milestones are pushed without asking, and `v0.1.0-beta.1` is tagged and released with static Linux binaries and checksums once `podssh ssh` passes its exit criteria. |
| 2026-10-08 | **Milestone 1 ships a usable default:** the relay `tcp.ssh.relay.ajam.dev` is compiled in (overridable), and Mozilla's root store (`webpki-roots`) is embedded as the last-resort trust fallback after an explicit CA file and the system bundle. This reverses two earlier agent-made rules ("no default relay", "no compiled-in roots"). |
| 2026-10-08 | **Tailscale is opt-in.** `podssh ts` is the `ts` cargo feature, because the vendored fork dominates build time, memory and binary size. |
| 2026-10-05 | **Never assume the client has any privilege, tool or setup.** In the operator's words: *"NEVER ASSUME OUR CLIENT HAS ANY PRIVS, TOOLS, SETUP."* Everything the host offers is probed at runtime; presence differs between sessions and images. |
| 2026-10-05 | **Tailscale support** (`podssh ts`, alias `tailscale`): "vanilla" means a TUN device; the auto chain is tun → socks → tcp → relay; `podssh ssh` does not route through the tailnet automatically in the first release; waiting for the relay allowlist is opt-in (fail fast by default); a client-side DERP home pin lives in the fork. |
| 2026-10-05 | **Exit codes:** usage errors 64, configuration errors 78 (sysexits). Applied. |
| 2026-10-04 | **IRC safety:** podssh never executes anything received over chat and never fetches a peer's files on its own. |
| 2026-10-01 | **No `LD_PRELOAD`, no out-of-process shims.** A preload shim fails silently against a static binary and looks like an authentication failure. podssh does what the host lacks in-process. |
| 2026-10-01 | **The terminal must be usable once connected.** Where nothing provides echo, editing and history (no pty on either side and no line discipline on the server), podssh supplies the line discipline itself. A server without a pty may still run its own (podbox does), so the mode is chosen from three inputs; see [terminal.md](terminal.md). |
| 2026-10-01 | **IRC is required:** two users in constrained environments must be able to chat and share files. podssh implements the protocol and the relay carries the bytes, like SSH. Open: the code today talks to public IRC servers in plaintext, and the "no third-party server" topology has no design yet. |
| 2026-10-01 | **Tokens:** one machine, one cached token; the cache lives in the first writable of the config directory, `$TMPDIR`, `/dev/shm`, the working directory; mode 0600, and a failed `chmod` does not stop podssh. |
| 2026-10-01 | **CLI:** `podssh` with no subcommand never connects anywhere; `chat` is the IRC subcommand; the man page is generated from the code. |

## Working on the repository

| date | decision |
| --- | --- |
| 2026-10-08 | **Lightweight tracking:** [STATUS.md](STATUS.md) (measured state), [ROADMAP.md](ROADMAP.md) (ordered milestones), a short `AGENTS.md`, and topic pages. The previous record (spec, 39 TODO entries, research, reviews, plans) was read for anything still useful, which was moved into the topic pages, and then deleted; it survives only in the pre-publication history bundle. |
| 2026-10-08 | **CI only runs once the repository is public.** Until then the gate is local: native tests plus `sh scripts/dev.sh check`. |
| 2026-10-07 | **Fix what is found broken on the spot,** in the same session; never defer it or call it someone else's. |
| 2026-10-07 | **Redundancy and fallbacks from day one** beat "minimal code": design for the first contact with a hostile host. |
| 2026-10-07 | **Leave existing line endings alone.** Never bulk-convert files a change does not otherwise touch. |
| 2026-10-01 | **No source file over 500 lines.** Split it; never delete comments to fit. Documentation is exempt. `scripts/check-repo.py` enforces it for Rust under `crates/`; `scripts/dev.sh` (about 600 lines, mostly comments) is the known exception to split. |
| standing | **Commits are attributed to the operator alone.** No co-author lines. |
| standing | **Agents never call `wsl.exe`**, and never `wsl --shutdown`, `--terminate` or `--unregister`: they affect every distribution on the machine. Linux work goes through `sh scripts/dev.sh`. |
| standing | **`.tmp/` holds read-only clones of sibling projects.** Never modify, commit or rebase inside them, and check the directory exists before concluding anything from it. |

## Superseded

| date | decision | replaced by |
| --- | --- | --- |
| 2026-10-01 | "There is no `ssh` on the sandbox." | The 2026-10-04 probe found `/usr/bin/ssh`; the 2026-10-05 rule: probe, never assume. |
| 2026-10-01 | "Use wsl-toolkit directly for testing." | All Linux work goes through `scripts/dev.sh`. |
| 2026-10-04, 2026-10-05 | Work orders (relay → IRC chat → … → SSH; E33 → relay C1/C3/C4 → E39 → live IRC → E01). | [ROADMAP.md](ROADMAP.md), 2026-10-08. |
| 2026-10-05 | "Drop the no-C gate when the Tailscale adapter joins the workspace." | Tailscale became the opt-in `ts` feature (2026-10-08); the same day the no-C rule was narrowed to the library crates for `russh`. |
| 2026-10-08 | "Native SSH: evaluate `russh` first; the engine choice is open." | `russh` with `aws-lc-rs` in the default build (2026-10-08). |
| 2026-10-05 | Session authorizations for the previous agent (minting tokens unattended, using operator credentials and test machines, commit and push per change). | Not standing permissions; ask in the session that needs them. |
