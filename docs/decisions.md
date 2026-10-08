# Decisions

This page lists the decisions of the operator (the owner of the project).
The newest decision is first in each section.

- Do not change a decision without the operator.
- When a decision changes, edit its row and move the old text to
  "Superseded". Do not keep two versions as current.

## Product

| Date | Decision |
| --- | --- |
| 2026-10-08 | **The way to a finished podssh** ([design.md](design.md)). The first beta waits for milestone M3: relay failover, liveness, a fallback for no proxy and no DNS, `doctor`, `keygen`, and a run in a real sandbox. Then M4 (`podssh-relay`, the reverse road, podbox), M5 (`podssh serve`), and M6 (sessions that survive a drop). M6 builds two resumable layers, each the fallback of the other: podssh's own layer over the WebSocket relay, and iroh. |
| 2026-10-08 | **iroh is a road that the user must select**, for connections between two podssh binaries. Its relays are configurable. The default is n0's public relays until the operator runs an iroh relay on the operator's own Cloudflare account. Then the operator's relay is first and n0's relays are the fallback. |
| 2026-10-08 | **The SSH client is `russh` with the `aws-lc-rs` backend, in the default build.** The rule "no C" applies to the library crates only: `podssh-ws`, `podssh-relay`, `podssh-transport`, `podssh-core`, `podssh-terminal`, `podssh-probe`. The `podssh` binary links aws-lc. |
| 2026-10-08 | **The repository is public.** The git history was replaced by one commit (the old history is in a local bundle), and the old CI runs were deleted. Verified milestones are pushed without a question. `v0.1.0-beta.1` is tagged and released, with static Linux binaries and checksums, when M3 is complete. |
| 2026-10-08 | **Milestone 1 gives a usable default.** The relay `tcp.ssh.relay.ajam.dev` is compiled in, and the user can override it. Mozilla's root store (`webpki-roots`) is the last trust fallback, after an explicit CA file and the system bundle. |
| 2026-10-08 | **Tailscale is a feature that the user must select.** `podssh ts` is the `ts` cargo feature, because the fork uses most of the build time, the memory and the binary size. |
| 2026-10-05 | **Do not assume that the client has a privilege, a tool or a setup.** The operator's words: *"NEVER ASSUME OUR CLIENT HAS ANY PRIVS, TOOLS, SETUP."* podssh probes what the host gives at runtime. What a host gives changes between sessions and images. |
| 2026-10-05 | **Tailscale support** (`podssh ts`, alias `tailscale`). "Vanilla" means a TUN device. The automatic chain is tun, then socks, then tcp, then relay. `podssh ssh` does not use the tailnet automatically in the first release. A wait for the relay's allowlist is used only on request; the default is to fail fast. A client-side DERP home pin is in the fork. |
| 2026-10-05 | **Exit codes:** 64 for a usage error, 78 for a configuration error (sysexits). |
| 2026-10-04 | **IRC safety:** podssh never executes something that it receives over chat, and never gets a peer's files on its own. |
| 2026-10-01 | **No `LD_PRELOAD`, and no shims in other processes.** A preload shim fails silently against a static binary and looks like an authentication failure. podssh supplies in its own process what the host does not have. |
| 2026-10-01 | **The terminal must be usable after the connection.** When no part gives echo, editing and history (no pty on either side, and no line discipline on the server), podssh supplies the line discipline. A server with no pty can have its own line discipline (podbox has one), so three inputs select the mode. See [terminal.md](terminal.md). |
| 2026-10-01 | **IRC is necessary.** Two users in constrained hosts must be able to chat and share files. podssh supplies the protocol and the relay carries the bytes, as for SSH. Open items: the client sends plain text to public IRC servers, and the topology with no third-party server has no design yet. |
| 2026-10-01 | **Tokens:** one machine has one cached token. The cache is in the first writable directory of: the configuration directory, `$TMPDIR`, `/dev/shm`, the working directory. The mode is 0600. If `chmod` fails, podssh continues. |
| 2026-10-01 | **Command line:** `podssh` with no subcommand never connects. `chat` is the IRC subcommand. The code generates the man page. |

## Work on the repository

| Date | Decision |
| --- | --- |
| 2026-10-08 | **The documents use ASD-STE100 (Simplified Technical English).** They give the current state and procedures, not history; git keeps the history. The documents for agents send the reader to the exact document for each task ([AGENTS.md](../AGENTS.md)). |
| 2026-10-08 | **The box like the target sandbox uses Podman directly** (`scripts/test_in_box.sh`). The build gate continues to use `scripts/dev.sh`. |
| 2026-10-08 | **Light records:** [STATUS.md](STATUS.md) for the measured state, [ROADMAP.md](ROADMAP.md) for the milestones in order, [defects.md](defects.md) for the open defects, a short [AGENTS.md](../AGENTS.md), and topic pages. |
| 2026-10-07 | **Repair a defect in the session that finds it.** Do not defer it, and do not call it the work of another person. |
| 2026-10-07 | **Redundancy and fallbacks from the first day** are better than minimal code. Design for the first contact with a hostile host. |
| 2026-10-07 | **Do not change the line endings** of a file that a change does not otherwise touch. |
| 2026-10-01 | **No source file has more than 500 lines.** Split a longer file. Do not delete comments to make it fit. Documents are exempt. `scripts/check-repo.py` checks the Rust files under `crates/`. `scripts/dev.sh` (about 600 lines) is a known exception that must be split ([defects.md](defects.md), B8). |
| standing | **Commits are attributed to the operator only.** No co-author lines. |
| standing | **Agents never call `wsl.exe`**, and never `wsl --shutdown`, `--terminate` or `--unregister`. These commands act on each distribution of the machine. Linux builds use `sh scripts/dev.sh`. |
| standing | **`.tmp/` holds read-only copies of other projects.** Do not change, commit or rebase in them. Make sure that the directory exists before you use it. |

## Superseded

| Date | Decision | Replaced by |
| --- | --- | --- |
| 2026-10-08 | "CI runs only when the repository is public; until then the gate is local." | The repository became public on 2026-10-08. CI runs the gate on each push. |
| 2026-10-08 | "Native SSH: evaluate `russh` first; the engine is open." | `russh` with `aws-lc-rs` in the default build (2026-10-08). |
| 2026-10-05 | "Drop the no-C gate when the Tailscale adapter joins the workspace." | Tailscale became the `ts` feature (2026-10-08). The same day, the no-C rule was limited to the library crates. |
| 2026-10-05 | Permissions for an earlier agent (unattended token mints, the operator's credentials and test machines, a commit and push for each change). | Not standing permissions. Ask in the session that needs them. |
| 2026-10-04, 2026-10-05 | Work orders (relay, IRC chat, then SSH; E33, relay C1/C3/C4, E39, live IRC, E01). | [ROADMAP.md](ROADMAP.md), 2026-10-08. |
| 2026-10-01 | "There is no `ssh` on the sandbox." | The probe of 2026-10-04 found `/usr/bin/ssh`. The rule of 2026-10-05: probe, never assume. |
| 2026-10-01 | "Use wsl-toolkit directly for testing." | Linux builds use `scripts/dev.sh`; the sandbox box uses Podman directly (2026-10-08). |
