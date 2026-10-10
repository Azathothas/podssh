# Index

Every entry of the work record, one line each, sorted by id. The entry lives
in the file that its row links. It closes there, with its Prove run and the
result written down.

What to do next is not on this page: `TODO/PROGRESS.md` holds the only work
order. `TODO/RULES.md` tells how the record is kept. `TODO/issues.md` maps
each GitHub issue to its entries.

`cargo todo set` and `cargo todo counts` derive the counts from the rows.
`cargo todo check` asserts that the counts, the rows and the entries agree.
The gate runs it on each push.

## Values

**Priority.**

- **P0**: breaks correctness, loses data, or stops the process.
- **P1**: a documented capability does not work, or a flag does nothing.
- **P2**: worth doing; nothing is wrong without it.
- **P3**: worth recording, so that nobody has to find it again.

A defect in code that no command of the default build uses is P2 at most.

**Effort.** S is under a day. M is a few days. L is a week. There is no XL:
an entry of that size is two entries.

**Status.** `open`, `partial`, `blocked` or `done`. A blocked entry names
who must act, and what unblocks it. Parked work stays `open`; its start
condition is in the entry and in `TODO/PROGRESS.md`.

**Milestone.** `M3` to `M9`, as in `docs/ROADMAP.md`; M9 is `v1.0.0`.
`backlog`: in no milestone; the operator scheduled each one after M8
(2026-10-08). `none`: not milestone work (the
repository and CI).

**Category.** `defect`, `feature`, `measurement`, `release`, `chore`,
`research` or `docs`.

## The order, and the argument for it

1. The milestones go in the decided order: M3, then M4, M5 and
   M6 (`docs/decisions.md`). M7 and M8 come after them, then the `backlog`
   entries, then M9 (`v1.0.0`).
2. In a milestone: P0, then P1, then P2, then P3. At one priority, an S entry
   goes first when it does not depend on a larger one.
3. An entry that another entry depends on goes first: the transport defects
   T-071 to T-076 before the node runner T-079, and the line discipline
   defects T-125 to T-129 before T-111.
4. The operator scheduled each `backlog` entry after M8, and the surface
   for agents (T-049, T-050, T-012, T-052 and T-051) after M3 and
   before M4 (`docs/decisions.md`, 2026-10-08): those entries are small, and
   the testers asked for them.
5. `none` entries (the repository and CI) go between milestone entries, the
   highest priority first. They do not wait for a milestone.
6. An entry that waits for a measurement in a real sandbox is done in one
   session with the other entries of that kind.
7. The entries that wait for the relay's operator are skipped: T-086,
   T-106, T-169, T-173, T-180, T-226, T-253 and T-255.

## Counts

**274 entries: 104 open, 0 partial, 22 blocked, 148 done.**

| Priority | open | partial | blocked | done | total |
| --- | --- | --- | --- | --- | --- |
| P0 | 0 | 0 | 0 | 1 | 1 |
| P1 | 2 | 0 | 0 | 16 | 18 |
| P2 | 23 | 0 | 18 | 112 | 153 |
| P3 | 79 | 0 | 4 | 19 | 102 |
| **All** | 104 | 0 | 22 | 148 | 274 |

## Entries

| ID | Priority | Effort | Milestone | Category | Status | Item |
| --- | --- | --- | --- | --- | --- | --- |
| [T-001](beta.md) | P1 | M | M3 | measurement | done | Measure podssh in the operator's real sandbox |
| [T-003](beta.md) | P2 | S | M3 | research | done | Decide how the compiled-in root certificates get updates in released binaries |
| [T-004](beta.md) | P2 | S | M3 | measurement | done | Interactive use over `-tt` from a box like the sandbox: vi, less, top and Ctrl-C |
| [T-005](beta.md) | P1 | S | M3 | defect | done | A prompt never waits for ever on a `/dev/tty` with nobody behind it (GitHub #15) |
| [T-006](beta.md) | P1 | S | M3 | defect | done | `scripts/sandbox-check.sh` exits 0 when its steps fail, and ignores `CARGO_TARGET_DIR` (GitHub #28) |
| [T-007](cli.md) | P1 | S | M3 | defect | done | Bracketed IPv6 literal destinations are refused (GitHub #2) |
| [T-008](cli.md) | P2 | S | M3 | defect | done | The `--timeout` refusal with no terminal names `chat` for each command, and contradicts itself (GitHub #6) |
| [T-009](cli.md) | P2 | S | M3 | defect | done | A missing flag value is reported as an unknown flag (GitHub #8) |
| [T-010](cli.md) | P2 | S | M3 | defect | done | `podssh --help` with other words prints the help and drops the words silently (GitHub #10) |
| [T-011](cli.md) | P2 | S | M3 | defect | done | A host or target that starts with `-` can be read as a flag |
| [T-012](cli.md) | P2 | S | backlog | feature | done | `PODSSH_TIMEOUT` gives the default of `--timeout` (GitHub #12) |
| [T-013](cli.md) | P3 | S | backlog | feature | open | The help groups the commands by purpose |
| [T-014](cli.md) | P2 | M | M3 | feature | done | `podssh man` writes the whole manual from the binary (GitHub #1) |
| [T-015](cli.md) | P1 | S | M3 | defect | done | The manual showed blank flag names under groff and mandoc (GitHub #4, audit C7) |
| [T-016](cli.md) | P1 | S | M3 | defect | done | Each flag of OpenSSH 10.3p1 answers by name (GitHub #5, audit C10) |
| [T-017](cli.md) | P0 | S | M3 | defect | done | A repeated flag follows OpenSSH; `-J` and `-W` only once (GitHub #16) |
| [T-018](cli.md) | P3 | M | backlog | feature | open | `podssh keygen -p` and `-c`: change the passphrase and the comment of a key |
| [T-019](cli.md) | P3 | M | backlog | feature | open | `podssh keygen -F`, `-R` and `-H`: find, remove and hash `known_hosts` entries |
| [T-020](cli.md) | P3 | M | backlog | feature | open | `podssh keygen -Y`: SSH signatures |
| [T-021](cli.md) | P3 | M | backlog | feature | open | `podssh keygen -s`: user and host certificates |
| [T-022](cli.md) | P3 | M | backlog | feature | open | `podssh keygen -e`, `-i` and `-m`: convert key formats |
| [T-023](ssh.md) | P2 | S | M3 | defect | done | With `PubkeyAuthentication=no`, the denial still says "no key was offered; use -i FILE" (GitHub #7) |
| [T-024](ssh.md) | P2 | S | M3 | defect | done | The first line about a dropped session is generic; name the hop that broke (GitHub #17) |
| [T-025](ssh.md) | P2 | M | backlog | feature | open | Try a dropped forward session again when it is safe, by the relay's close reason (GitHub #17) |
| [T-026](ssh.md) | P2 | S | backlog | defect | done | A session that ends with no exit status never reads as a success |
| [T-027](ssh.md) | P2 | M | backlog | feature | open | Host certificates and `@cert-authority` in `known_hosts` (GitHub #29) |
| [T-028](ssh.md) | P2 | S | backlog | defect | done | `accept-new` when `known_hosts` cannot be written: verify, and say that the key was not recorded |
| [T-029](ssh.md) | P2 | S | backlog | defect | done | Two processes that record the same new host key at the same time |
| [T-030](ssh.md) | P3 | S | backlog | chore | open | Each hop of a `-J` chain checks its own host key |
| [T-031](ssh.md) | P2 | S | backlog | feature | done | Accept only the host key that a fingerprint names, for scripts with no `known_hosts` |
| [T-032](ssh.md) | P3 | S | backlog | feature | open | Run a remote command under `sudo` or `su`, with the password from `SSH_ASKPASS` |
| [T-033](ssh.md) | P3 | M | backlog | feature | open | Record a session as asciicast v2, and play it again |
| [T-034](ssh.md) | P2 | L | backlog | feature | open | `podssh agent`: an SSH agent inside podssh, with no separate binary |
| [T-035](forwarding.md) | P2 | M | M8 | feature | done | `-R`: remote forwarding, each connection made out through the proxy |
| [T-036](forwarding.md) | P2 | M | backlog | feature | open | `-A`: agent forwarding, off by default as in OpenSSH |
| [T-037](forwarding.md) | P3 | M | backlog | feature | open | `-X` and `-Y`: X11 forwarding to the display that `DISPLAY` names |
| [T-038](forwarding.md) | P2 | M | backlog | feature | open | `-L` and `-D` when a probe shows that a local bind is allowed |
| [T-039](forwarding.md) | P2 | M | backlog | feature | open | Connection sharing: `ControlMaster`, `ControlPath`, `-O` and `-S` over an AF_UNIX socket |
| [T-040](forwarding.md) | P3 | S | backlog | feature | open | `-W` to a Unix socket on the server (streamlocal) |
| [T-041](forwarding.md) | P3 | S | backlog | feature | open | The forwards of a session: a list and byte counts |
| [T-042](forwarding.md) | P3 | S | backlog | feature | open | `-R` forwards come back after a drop |
| [T-043](config.md) | P2 | M | M8 | feature | done | Read `ssh_config`: `~/.ssh/config`, `-F FILE`, `Host` patterns, and `Match` refused by name (GitHub #14, #22) |
| [T-044](config.md) | P2 | M | M8 | feature | done | `Include` in `ssh_config`, expanded as OpenSSH expands it |
| [T-045](config.md) | P3 | M | backlog | feature | open | `Match` in `ssh_config` |
| [T-046](config.md) | P2 | S | M8 | feature | done | `podssh ssh -G`: print the settings in effect (GitHub #14, #22) |
| [T-047](config.md) | P3 | M | backlog | feature | open | Import host lists from other clients into `ssh_config` |
| [T-048](config.md) | P3 | M | backlog | feature | open | A podssh settings file for its own defaults, below flags and variables |
| [T-049](machine.md) | P2 | S | backlog | feature | done | `podssh doctor --json` (GitHub #9) |
| [T-050](machine.md) | P2 | S | backlog | feature | done | `podssh man --json`: the commands, flags, keywords, variables and exit codes as data (GitHub #10) |
| [T-051](machine.md) | P2 | M | backlog | feature | done | `podssh status`: one line of JSON about the state of this host (GitHub #11) |
| [T-052](machine.md) | P2 | M | backlog | feature | done | `podssh doctor --full`: the end-to-end checks of `sandbox-check.sh`, in the binary (GitHub #13) |
| [T-053](machine.md) | P2 | M | backlog | feature | open | `podssh ping`: a short check of the path, with latency and throughput |
| [T-054](machine.md) | P3 | M | backlog | feature | open | A machine-readable result for `podssh ssh`: exit status, signal and byte counts |
| [T-055](machine.md) | P3 | M | backlog | feature | open | `podssh mcp`: the commands as tools for an agent, over stdin and stdout |
| [T-056](machine.md) | P3 | S | backlog | feature | open | A log of the sessions of this host, when the user asks for it |
| [T-057](relay.md) | P1 | S | M3 | defect | done | The relay token is cached under the first configured host, not the host that minted it (GitHub #3) |
| [T-058](relay.md) | P2 | M | backlog | feature | open | `podssh relay status`, `info`, `spec` and `trace` |
| [T-059](relay.md) | P3 | S | backlog | feature | open | A relay host that failed recently is tried last, also in the next run |
| [T-060](relay.md) | P3 | S | none | chore | done | P1: no command uses `podssh-probe` |
| [T-061](relay.md) | P3 | S | M4 | measurement | done | Measure whether the relay's idle cut applies to reverse sockets |
| [T-062](relay.md) | P3 | S | backlog | measurement | open | Measure whether the relay's backpressure close (1013) operates |
| [T-063](ws.md) | P2 | S | M4 | defect | done | W10: the frame decoder does not check a received control frame |
| [T-064](ws.md) | P3 | S | M4 | defect | done | W13: `OsRng::fill_bytes` panics when the system gives no random bytes |
| [T-065](ws.md) | P2 | S | M4 | defect | done | W14: `probe::PrintChain` accepts each certificate, and is a public export |
| [T-066](ws.md) | P2 | M | M4 | feature | done | A `rustls::ClientConfig` that the caller supplies, for podbox |
| [T-067](ws.md) | P2 | M | backlog | feature | open | TLS 1.2, for intercepting proxies |
| [T-068](ws.md) | P3 | S | M4 | feature | done | Plain `ws://` to loopback, for tests only |
| [T-069](ws.md) | P2 | S | M4 | feature | done | Typed session errors in `podssh-ws` |
| [T-070](ws.md) | P2 | M | backlog | feature | open | A SOCKS5 proxy for the egress |
| [T-071](transport.md) | P2 | S | M4 | defect | done | T1: `send_text` sends a binary frame, so the node leg cannot work |
| [T-072](transport.md) | P2 | S | M4 | defect | done | T2: a received Close frame loses its code and reason |
| [T-073](transport.md) | P2 | S | M4 | defect | done | T5: the `ready` gate is not enforced |
| [T-074](transport.md) | P3 | S | M4 | chore | done | T7: the backpressure module is not used |
| [T-075](transport.md) | P2 | S | M4 | defect | done | T8: a 403 is not retried with a new token, and a 503 is retried |
| [T-076](transport.md) | P2 | S | M4 | defect | done | T9: host and node names are not validated or escaped |
| [T-077](transport.md) | P3 | S | M4 | chore | done | T10: the `Transport` trait has no implementation, and `Backoff` is used only by tests |
| [T-078](reverse.md) | P2 | M | M4 | feature | done | Pairing in `podssh-relay`: pair, stop and status |
| [T-079](reverse.md) | P2 | L | M4 | feature | done | The node runner |
| [T-080](reverse.md) | P2 | M | M4 | feature | done | The operator runner |
| [T-081](reverse.md) | P2 | M | M4 | feature | done | A blocking facade of `podssh-relay`, for podbox |
| [T-082](reverse.md) | P2 | M | M4 | chore | done | Move the codecs of `podssh-transport` into `podssh-relay` |
| [T-083](reverse.md) | P2 | M | M4 | feature | done | `podssh node NAME TARGET` |
| [T-084](reverse.md) | P2 | M | M4 | feature | done | `podssh operator NAME` and `podssh ssh NODE` |
| [T-085](reverse.md) | P2 | M | M4 | measurement | blocked | M4 exit: two sessions at once into a node in another sandbox, and the facade for podbox |
| [T-086](reverse.md) | P3 | M | backlog | feature | blocked | Pairing by a short one-time code, given out of band |
| [T-087](reverse.md) | P2 | M | backlog | feature | done | Node identity and access: a node key, an allowlist, an expected fingerprint, revocation |
| [T-088](reverse.md) | P2 | L | backlog | feature | done | End-to-end encryption between two podssh ends |
| [T-089](reverse.md) | P3 | M | backlog | feature | open | A node offers several named targets, each with its own grant |
| [T-090](reverse.md) | P3 | M | backlog | feature | open | Find a node by name with no payload leak |
| [T-091](irc.md) | P2 | S | M8 | defect | done | I1: `CAP END` is sent only after 001 |
| [T-092](irc.md) | P2 | M | M8 | defect | done | I2: the client asks for each offered capability |
| [T-093](irc.md) | P2 | S | M8 | defect | done | I3: text is not checked for CR, LF and NUL |
| [T-094](irc.md) | P2 | S | M8 | defect | done | I4: trailing forms of JOIN, NICK and PRIVMSG are dropped |
| [T-095](irc.md) | P2 | M | M8 | defect | done | I5: PART, KICK, 005, a new connection and 433 are handled incorrectly |
| [T-096](irc.md) | P2 | S | M8 | defect | done | I6: the line framing loses lines, and its buffer has no limit |
| [T-097](irc.md) | P2 | M | M8 | defect | done | I7: file chunks are too long with the server's prefix, and the last acknowledgement is wrong |
| [T-098](irc.md) | P3 | S | M8 | defect | done | I8: the keepalive sends a visible channel message |
| [T-099](irc.md) | P2 | L | M8 | feature | done | `podssh chat` on the roads between two podssh ends, end-to-end encrypted |
| [T-100](ts.md) | P2 | S | M8 | defect | done | C2: `podssh ts` waits for ever when no network map arrives |
| [T-101](ts.md) | P2 | S | M8 | defect | done | C3: a local end of input cuts the reply in the `podssh-ts` pipe |
| [T-102](ts.md) | P2 | M | M8 | defect | done | C9: the automatic mode always selects tcp, and ephemeral nodes are not logged out |
| [T-103](ts.md) | P2 | M | M8 | defect | done | The DERP dial of the Tailscale fork does not use the proxy |
| [T-104](ts.md) | P2 | M | M8 | feature | done | `podssh ts` connects again after a drop |
| [T-105](ts.md) | P2 | M | M8 | defect | done | The fork shows the relay's `1008 not authorized` as a missing network map |
| [T-106](ts.md) | P2 | M | M8 | measurement | blocked | The live test of `podssh ts` with two nodes |
| [T-107](serve.md) | P2 | M | M5 | feature | blocked | `podssh serve`: the russh server, its host key in a state file, and authorized keys |
| [T-108](serve.md) | P2 | M | M5 | feature | blocked | `podssh serve`: exec, a shell and the environment, as the sandbox's user |
| [T-109](serve.md) | P2 | S | M5 | feature | blocked | `podssh serve`: direct-tcpip into the cage |
| [T-110](serve.md) | P2 | M | M5 | feature | blocked | `podssh serve`: a real pty when `/dev/ptmx` exists |
| [T-111](serve.md) | P2 | L | M5 | feature | blocked | `podssh serve` with no `/dev/ptmx`: the line discipline, and Ctrl-C to the child's process group |
| [T-112](serve.md) | P2 | M | M5 | feature | blocked | An SFTP server in `podssh serve` |
| [T-113](serve.md) | P2 | M | M5 | measurement | blocked | M5 exit: a usable shell and 200 MiB each way from a sealed sandbox |
| [T-114](serve.md) | P2 | M | backlog | feature | open | `podssh serve`: access rules for each key and command |
| [T-115](serve.md) | P3 | M | backlog | feature | open | `podssh serve`: a TOTP second factor |
| [T-116](serve.md) | P3 | S | backlog | feature | open | `podssh serve`: an audit log |
| [T-117](serve.md) | P2 | S | M5 | feature | blocked | `podssh serve`: a clean stop, and SIGHUP reads the settings again |
| [T-118](serve.md) | P2 | S | M5 | feature | blocked | `podssh serve`: a slow client cannot stall a pty or fill the memory |
| [T-119](serve.md) | P3 | S | backlog | feature | open | `podssh serve`: the MOTD and `~/.hushlogin` |
| [T-120](serve.md) | P3 | M | backlog | feature | open | `podssh serve`: shell integration marks, when asked |
| [T-121](serve.md) | P3 | M | backlog | feature | open | Install `podssh serve` or `podssh node` as a service with no privileges |
| [T-122](serve.md) | P3 | S | backlog | feature | open | `podssh serve`: each pty child in its own transient scope when systemd is there |
| [T-123](serve.md) | P3 | M | backlog | feature | open | `podssh serve` accepts `tcpip-forward` from a standard `ssh -R` |
| [T-124](serve.md) | P3 | M | backlog | feature | open | `podssh serve --listen`: SSH on a TCP port on a host that allows it |
| [T-125](terminal.md) | P2 | S | M5 | defect | done | L1: the mode selection of the line discipline is the wrong way round |
| [T-126](terminal.md) | P2 | M | M5 | defect | done | L2: the line discipline has no raw mode and no window size |
| [T-127](terminal.md) | P2 | S | M5 | defect | done | L3: the cursor counts bytes, not characters |
| [T-128](terminal.md) | P2 | S | M5 | defect | done | L4: `ESC O x` keys ring the bell, and a single Escape removes the next key |
| [T-129](terminal.md) | P2 | M | M5 | defect | done | L5: Delete, Home and End, Ctrl-Z, Ctrl-S, Ctrl-Q, and remote output over the edited line |
| [T-130](terminal.md) | P3 | S | backlog | docs | open | State which terminal sequences podssh reads and which it passes unchanged |
| [T-131](terminal.md) | P3 | S | backlog | measurement | open | Which servers honour the `signal` request for Ctrl-C with no remote pty |
| [T-132](terminal.md) | P3 | S | backlog | research | open | Compare the Windows console handling with csshw's |
| [T-133](copy.md) | P2 | M | M5 | feature | done | An SFTP client in the process, the base of `cp` |
| [T-134](copy.md) | P2 | M | M5 | feature | done | `podssh cp` over SFTP: a temporary name, the digest, then a rename |
| [T-135](copy.md) | P2 | M | M5 | feature | done | `podssh cp` by exec when the server has no SFTP |
| [T-136](copy.md) | P2 | M | M5 | feature | done | `podssh cp` continues from an offset after a drop |
| [T-137](copy.md) | P2 | M | M5 | feature | done | `podssh cp` opens a new relay session before the relay's limits |
| [T-138](copy.md) | P2 | S | M5 | feature | done | `podssh mv`: copy, verify, delete, and say first that it is not atomic |
| [T-139](copy.md) | P2 | L | M5 | feature | done | `podssh scp` and `podssh sftp` with the command lines of OpenSSH |
| [T-140](copy.md) | P3 | M | backlog | feature | open | Pipelined SFTP |
| [T-141](copy.md) | P3 | M | backlog | feature | open | Parallel transfer in chunks |
| [T-142](copy.md) | P3 | L | backlog | feature | open | Delta copy: only the blocks that changed |
| [T-143](copy.md) | P3 | M | backlog | feature | open | Copy directories: `-r`, `--exclude`, an ignore file, `--dry-run` |
| [T-144](copy.md) | P3 | S | backlog | feature | open | `podssh cp --delete`: make the target a mirror |
| [T-145](copy.md) | P3 | S | backlog | feature | open | Progress, cancellation and a bandwidth limit for copies |
| [T-146](copy.md) | P3 | M | backlog | feature | open | Keep the metadata of a copy |
| [T-147](copy.md) | P3 | S | backlog | feature | open | `podssh cp --inplace` |
| [T-148](copy.md) | P3 | M | backlog | feature | open | ZMODEM in a terminal session |
| [T-149](copy.md) | P3 | M | backlog | feature | open | `podssh edit HOST:PATH` |
| [T-150](copy.md) | P3 | M | backlog | feature | open | A copy protocol between two podssh ends |
| [T-151](resume.md) | P2 | L | M6 | feature | done | The resumable layer: its handshake and the byte offsets |
| [T-152](resume.md) | P2 | M | M6 | feature | done | The replay buffer, limited, with backpressure |
| [T-153](resume.md) | P2 | L | M6 | feature | done | Resume through any road and relay host, with a session secret and a capped backoff |
| [T-154](resume.md) | P2 | S | M6 | feature | done | Heartbeats that also prevent the relay's idle cut |
| [T-155](resume.md) | P2 | S | M6 | feature | done | Move a session to a new relay connection before the relay's limits |
| [T-156](resume.md) | P2 | M | M6 | measurement | done | M6 exit: a session survives a stopped relay host, a new address and a stall of 3 minutes |
| [T-157](resume.md) | P2 | M | M6 | measurement | done | Throughput on each road and relay, by a committed method |
| [T-158](resume.md) | P3 | M | backlog | feature | open | Detach and attach again |
| [T-159](resume.md) | P3 | M | backlog | feature | open | Sessions on the far end that outlive the client |
| [T-160](resume.md) | P3 | L | backlog | feature | open | Local echo and prediction for high latency |
| [T-161](resume.md) | P3 | L | backlog | research | open | Screen state and scrollback when a client attaches |
| [T-162](roads.md) | P2 | L | M6 | feature | done | The iroh road behind the cargo feature `iroh` |
| [T-163](roads.md) | P2 | S | M6 | feature | done | iroh tickets and node keys |
| [T-164](roads.md) | P2 | M | M6 | feature | done | Race the iroh road and the reverse road |
| [T-165](roads.md) | P2 | S | M6 | feature | done | Configurable iroh relays, the operator's relay first |
| [T-166](roads.md) | P3 | M | backlog | feature | open | A roost: a podssh next to a standard sshd |
| [T-167](roads.md) | P3 | M | backlog | feature | open | Start from a standard sshd, then move the session to a better road |
| [T-168](roads.md) | P3 | M | backlog | feature | open | UDP over the relay |
| [T-169](roads.md) | P3 | L | backlog | feature | blocked | A self-hosted relay that speaks the relay's contract |
| [T-170](roads.md) | P3 | M | backlog | research | open | A Cloudflare quick tunnel made by podssh itself, with no `cloudflared`: the protocol and its ports |
| [T-171](roads.md) | P3 | M | backlog | research | open | The functions of Mosh that M6 and T-160 do not give, made in podssh itself |
| [T-172](roads.md) | P3 | S | backlog | research | open | Multipath TCP on the direct road |
| [T-173](roads.md) | P3 | L | M8 | feature | blocked | Resumption in the relay for a standard sshd |
| [T-174](pipe.md) | P2 | M | M7 | feature | done | `podssh pipe A B` with local addresses |
| [T-175](pipe.md) | P2 | M | M7 | feature | done | `podssh pipe` with remote addresses |
| [T-176](pipe.md) | P2 | S | M7 | feature | done | `podssh pipe` with `unix-connect:PATH` |
| [T-177](pipe.md) | P3 | M | M7 | feature | done | `podssh pipe` with a local listener after a probe |
| [T-178](pipe.md) | P2 | M | M7 | feature | done | `--persist`: connect again and attach `tmux` again |
| [T-179](pipe.md) | P3 | S | backlog | docs | open | Desktop streams and Telnet through `proxy` and `pipe` |
| [T-180](pipe.md) | P3 | L | backlog | feature | blocked | Publish a local HTTP service at `https://NAME` through the relay |
| [T-181](pipe.md) | P3 | S | backlog | feature | open | A `serial:` address for a local serial device |
| [T-182](pipe.md) | P3 | S | backlog | docs | open | USB/IP devices through `podssh pipe`: a tested recipe, with no driver in podssh |
| [T-183](multi.md) | P3 | M | backlog | feature | open | Run one command on many hosts |
| [T-184](multi.md) | P3 | S | backlog | feature | open | Host groups and brace expansion of host names |
| [T-185](multi.md) | P3 | L | backlog | feature | open | Interactive broadcast to several sessions, with an emergency stop |
| [T-186](multi.md) | P3 | L | backlog | feature | open | A control surface for agents on live sessions |
| [T-187](multi.md) | P3 | M | backlog | feature | open | Snippets and argument templates, shown before they run |
| [T-188](multi.md) | P3 | S | backlog | feature | open | A host picker when `podssh ssh` gets no destination |
| [T-189](multi.md) | P3 | M | backlog | feature | open | The health of the far host over the session |
| [T-190](multi.md) | P3 | M | backlog | feature | open | Containers and pods as destinations |
| [T-191](multi.md) | P3 | M | backlog | feature | open | Expect rules, and tasks before and after a connection |
| [T-192](multi.md) | P3 | S | backlog | feature | open | Copy, then run: `podssh run` |
| [T-193](multi.md) | P3 | M | backlog | feature | open | Jobs on the far host: start, list, stop |
| [T-195](multi.md) | P3 | S | backlog | feature | open | Hand an error report to a program that the user names, for triage by an AI or a script |
| [T-197](multi.md) | P3 | M | backlog | feature | open | A queue of detached remote jobs: submit, list, wait and fetch the output, with no GPU logic |
| [T-198](robustness.md) | P2 | M | backlog | chore | open | Fuzz each parser |
| [T-199](robustness.md) | P2 | M | backlog | chore | open | A scored interop harness |
| [T-200](robustness.md) | P3 | M | backlog | chore | open | A terminal oracle |
| [T-201](robustness.md) | P2 | M | backlog | chore | open | Resource limits, stated and tested |
| [T-202](robustness.md) | P3 | S | backlog | chore | open | Property tests for the state machines |
| [T-203](robustness.md) | P2 | M | M6 | chore | done | The fault-injection harness: latency, jitter, bandwidth, a new address |
| [T-204](repo.md) | P2 | M | none | chore | done | Adopt the todo model, with a Rust checker in the gate |
| [T-205](repo.md) | P2 | S | none | chore | done | Dependabot for cargo, GitHub Actions and the build image (GitHub #27) |
| [T-206](repo.md) | P2 | S | none | chore | done | B7: the build image is not pinned to a digest |
| [T-207](repo.md) | P3 | S | none | chore | done | B8: `scripts/dev.sh` has about 600 lines |
| [T-208](repo.md) | P2 | S | none | chore | done | A changelog from the commits, and release notes from it (GitHub #27) |
| [T-209](repo.md) | P2 | S | none | chore | done | Secret scanning with TruffleHog in CI (GitHub #27) |
| [T-210](repo.md) | P2 | S | M9 | release | open | Build provenance for each release binary |
| [T-211](repo.md) | P2 | S | M9 | release | open | Signed checksums for each release |
| [T-212](repo.md) | P2 | M | none | chore | done | Parallel CI, with the gate as the one source |
| [T-213](repo.md) | P2 | M | none | chore | blocked | CI runs the box like the target sandbox |
| [T-214](repo.md) | P2 | M | none | chore | done | CI on Windows |
| [T-215](repo.md) | P2 | M | none | chore | done | rustfmt and clippy in the gate |
| [T-216](repo.md) | P2 | S | none | chore | done | Advisories and licenses of the dependencies, checked in CI |
| [T-217](repo.md) | P3 | S | none | chore | done | The declared minimum Rust versions, checked in CI |
| [T-218](repo.md) | P2 | M | M9 | release | open | More release targets: macOS, Linux armv7 and riscv64, and Windows aarch64 |
| [T-219](repo.md) | P2 | S | none | chore | done | The no-C gate also stops C++ |
| [T-220](relay.md) | P2 | M | backlog | feature | open | A silent first relay host costs a full dial before the next host is tried (GitHub #30) |
| [T-221](resume.md) | P3 | M | backlog | feature | open | Replayed output after dropped bytes starts at a boundary of the terminal grammar (GitHub #31) |
| [T-222](serve.md) | P2 | S | M5 | feature | blocked | `podssh serve` finds a shell with no passwd entry and no `/etc/shells`, and names each candidate that failed (GitHub #32) |
| [T-223](repo.md) | P3 | S | none | defect | done | `scripts/check-repo.py` passes when it finds nothing to check (GitHub #33) |
| [T-224](repo.md) | P2 | S | none | chore | done | The gate finds a listener in the source: a scan with an allow-list (GitHub #33) |
| [T-225](robustness.md) | P3 | M | backlog | chore | open | The interop gate takes each expected exit code from stock OpenSSH, beside the literal (GitHub #34) |
| [T-226](reverse.md) | P2 | M | backlog | feature | blocked | Pairing grants that are signed and used once, not bearer tokens that can be replayed (GitHub #35) |
| [T-227](ssh.md) | P2 | S | backlog | defect | done | `--direct` has no limit on a stuck write, but the relay leg fails after 60 s (GitHub #36) |
| [T-228](ssh.md) | P2 | M | backlog | feature | open | A credential helper inside podssh, for passphrases and passwords |
| [T-229](ssh.md) | P3 | L | backlog | feature | open | Hardware keys (FIDO2 `sk-` keys) in `podssh keygen`, the client and `podssh agent` |
| [T-230](cli.md) | P2 | S | M3 | defect | done | The help and the manual say that `-R` is refused because podssh never binds |
| [T-231](cli.md) | P2 | S | M3 | defect | done | A bad `PODSSH_RELAY` or `PODSSH_RELAY_ADDR` exits 64, not 78 |
| [T-232](cli.md) | P3 | S | backlog | chore | open | `gate_prompt` and `PromptSite` are used only by tests, and name flags that do not exist |
| [T-233](cli.md) | P2 | S | M3 | defect | done | The help of a command that is not implemented does not say so |
| [T-234](cli.md) | P2 | S | M3 | defect | done | `podssh man relay` shows the command and not the topic THE RELAY, and the list of sections names `relay` twice |
| [T-235](cli.md) | P3 | S | backlog | defect | open | The help puts `--help` at a different indent from the other options |
| [T-236](ssh.md) | P2 | S | M3 | defect | done | Authentication has no time limit, but the comment of `connect_timeout` says that it has |
| [T-237](ssh.md) | P2 | S | M3 | defect | done | The client accepts each channel that the server opens; OpenSSH refuses a channel that it did not ask for |
| [T-238](ssh.md) | P2 | S | M3 | defect | done | `%` tokens differ from OpenSSH: some stay literal, `%u` gives the remote user, and an unknown token is kept |
| [T-239](forwarding.md) | P2 | S | M3 | defect | done | `-W` with a path, or with no port, is read as a TCP host on port 22 |
| [T-240](ts.md) | P2 | S | M8 | defect | done | `podssh ts --jsonl` writes no JSON |
| [T-241](ts.md) | P2 | S | M8 | defect | done | The tailnet auth key is not cleared from memory |
| [T-242](ws.md) | P3 | S | backlog | defect | open | The frame decoder accepts a length that is not in the minimal form |
| [T-243](relay.md) | P2 | S | backlog | feature | open | The user can choose the cache directory, and no directory is fixed in the code |
| [T-244](repo.md) | P3 | M | none | chore | done | Code comments break `AGENTS.md` rule 6, and some name files and facts that are wrong |
| [T-245](repo.md) | P2 | S | none | chore | blocked | The box refuses each bind, but sandbox A allows an AF_UNIX bind |
| [T-246](repo.md) | P3 | S | none | chore | done | `scripts/dev.sh` excludes each file named `agents.md` from the container copy, with no reason given |
| [T-247](repo.md) | P3 | S | none | chore | done | `podssh-cli` declares dependencies that it does not use |
| [T-248](serve.md) | P2 | M | M5 | research | blocked | A tty for `podssh serve` where `/dev/ptmx` is missing: a new devpts instance, or a tty in user space |
| [T-249](repo.md) | P2 | M | none | chore | done | A cited line that moved still exists, so the checker does not see a stale citation |
| [T-250](release.md) | P1 | M | M9 | release | open | Publish v1.0.0, the first stable release |
| [T-251](release.md) | P1 | M | M9 | measurement | open | The check of a release from end to end, with no human |
| [T-252](irc.md) | P2 | M | M8 | feature | done | `podssh chat --irc`: IRC as a second transport for chat |
| [T-253](relay.md) | P2 | M | backlog | defect | blocked | The relay's egress reaches no IPv6 host |
| [T-254](repo.md) | P2 | S | none | defect | done | `cargo todo check` passes when a cited file was edited and `remap` was not run |
| [T-255](relay.md) | P2 | M | M4 | measurement | blocked | The relay's side drops reverse sockets at random, with no Close |
| [T-256](reverse.md) | P2 | S | M4 | defect | done | A local side that does not read stops every session of the node |
| [T-257](ssh.md) | P2 | M | backlog | defect | open | An RSA user key signs through the `rsa` crate, which is open to a timing attack |
| [T-258](repo.md) | P3 | S | none | defect | done | Line numbers written as plain text in the record are not moved |
| [T-259](repo.md) | P2 | S | none | defect | done | One dropped connection fails a live TLS test, and with it the gate |
| [T-260](repo.md) | P3 | S | none | chore | done | The open pull requests of Dependabot, #37 to #42 |
| [T-261](resume.md) | P2 | S | M6 | feature | done | A node that lost its socket connects again on `409`, until the resume deadline |
| [T-262](resume.md) | P1 | M | M6 | defect | done | A session cut at random points can end before its bytes come through |
| [T-263](resume.md) | P3 | S | M6 | feature | done | A node in plain mode, for a client with no resumable layer |
| [T-264](roads.md) | P2 | M | backlog | feature | open | Reach a service that `cloudflared` publishes, through `HTTPS_PROXY` |
| [T-265](ws.md) | P1 | S | M6 | defect | done | A silent first address holds the whole of a direct dial |
| [T-266](repo.md) | P1 | S | none | defect | done | The vi check of the Windows console job fails at random |
| [T-267](copy.md) | P1 | S | none | defect | done | A copy follows a source that grows, and does not end |
| [T-268](repo.md) | P1 | S | none | defect | done | A pull that Docker Hub refuses fails a job of CI before its check |
| [T-269](ssh.md) | P1 | S | none | defect | done | A session can wait for ever when its link ends while it sends |
| [T-270](resume.md) | P1 | S | none | defect | done | A resume whose far-end task starts late takes the session from a newer one |
| [T-271](reverse.md) | P1 | S | none | defect | done | A client can reach a node before it is online, and a node takes a slow local side of the layer for a stopped one |
| [T-272](repo.md) | P1 | S | none | defect | done | The tests leave their scratch directories in the temporary directory |
| [T-273](config.md) | P2 | S | M8 | defect | done | The `%` tokens of `User` and `RemoteCommand`, as OpenSSH expands them |
| [T-274](relay.md) | P2 | M | backlog | defect | open | On Windows, the owner and the writers of a private file are not checked |
| [T-275](irc.md) | P2 | S | M8 | defect | done | The transfer sends as fast as its acknowledgements come, and a server's rate limit closes it |
| [T-276](repo.md) | P3 | S | none | chore | done | The fork's own clippy warns, and no podssh build shows it |
| [T-277](repo.md) | P3 | S | none | chore | done | The record's check sees no citation that a commit left unmoved |
