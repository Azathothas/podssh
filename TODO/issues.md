# GitHub issues and reports

Where each GitHub issue of `Azathothas/podssh`, and each sandbox report, went
in the record. An issue can close when its entries are done; its closing
comment names them. A request that podssh already meets says so here, with
the evidence.

Triage of 2026-10-08: issues #1 to #36.

## Defects and small requests

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #1 | `podssh man` writes the whole manual | closed | T-014 |
| #2 | Bracketed IPv6 literals refused | closed | T-007 (the commit "IPv6 addresses as targets: podssh sends the bare literal to the relay"); T-253 waits for the relay's operator |
| #3 | The token cache key is the first host | closed | T-057 (the commit "Relay tokens: one cache entry for each deployment, with the host that minted it") |
| #4 | Blank flag names under groff | closed | T-015 |
| #5 | `-c`, `-m`, `-X`, `-Y`, `-O`: "unknown flag" | closed | T-016 |
| #6 | `cp`, `mv`, `relay` print the `chat` example | closed | T-008 (the commit "A command that is not implemented says so before the --timeout gate") |
| #7 | `PubkeyAuthentication=no` still advises `-i` | closed | T-023 (the commit "A refusal names keys only when keys were tried") |
| #8 | A missing value reads as an unknown flag | closed | T-009 (the commit "A flag with no value names the flag and its value") |
| #9 | `podssh doctor --json` | closed | T-049 (the commit "podssh doctor --json") |
| #10 | A machine-readable flag table | open | T-050, and T-010 (`--help --json` drops `--json`; done in the commit "podssh --help and --version drop no word"). The issue closes with T-050 |
| #11 | `podssh status` | open | T-051 |
| #12 | `PODSSH_TIMEOUT` | open | T-012 |
| #13 | `podssh doctor --full` | open | T-052 |
| #14 | `ssh_config`, `-F` and `-G` | open | T-043, T-044, T-045, T-046 |
| #15 | `keygen` waits for ever on a dead `/dev/tty` | closed | T-005 (repaired in `eacd94e`; measured in the box in the commit "The box has the sandbox's dead /dev/tty; T-005 measured there") |
| #16 | A repeated flag keeps the last value | closed | T-017 |
| #17 | Relay drops (1011): a generic message, no retry | open | T-024 (done in the commit "A dropped session names the hop that broke"), T-025; T-062 (the backpressure close). The issue closes with T-025 and T-062 |
| #27 | Repository health | open | T-205, T-206, T-207, T-208, T-209, T-210, T-211, T-212, T-213, T-214, T-215, T-216, T-217, T-218 |
| #28 | `sandbox-check.sh` exits 0 on failure | closed | T-006 (the commit "sandbox-check.sh: each step has a verdict, and a failed step fails the run") |

## Feature requests with reports (#18 to #26)

Each request lists asks, and its comments hold reports on other projects.
Each ask is below with its entries. The operator ruled on the questions of
scope on 2026-10-08 (`docs/decisions.md`).

**#18, transports and reachability.** The iroh road: T-162, T-163, T-164,
T-165. QUIC with a fallback over TLS and TCP: T-162 and T-164 (the reverse
road is the fallback), T-124 (a server that listens, after a probe). A
self-hosted relay: T-169 (it waits for the relay's operator). SSH on port 443: podssh already carries SSH over port 443
through the relay; for a server that listens, T-124. UDP over TCP:
T-168. A Cloudflare quick tunnel, made by podssh itself: T-170. QUIC between peers with a relay
fallback and an allowlist: T-162, T-087. The sandbox limits (no UDP, port 22
refused, only CONNECT): already a decision (probe, never assume;
`docs/decisions.md`, 2026-10-05).

**#19, the reverse road and sessions that survive.** A receiving mode: T-079,
T-083. Resume by byte offset with a limited replay ring: T-151, T-152,
T-153. Byte replay or screen state: T-152 and T-161. The reconnection policy:
T-153, T-154. A start over a standard sshd: T-167. A lasting terminal through
`tmux`: T-178. A clean server life cycle: T-117.

**#20, `podssh serve` and the pty in the cage.** The server: T-107, T-108,
T-109, T-110, T-111, T-112, T-113. A session that outlives the window: T-159.
Line discipline and copy mode: T-111, T-125 to T-129, T-161. Backpressure:
T-118. A handshake with version and role: T-151. An install with no
privileges: T-121; an agent, a credential helper and hardware keys, inside
podssh: T-034, T-228, T-229. The host key of each hop: T-030.
A limit on each wait: T-110, T-111, T-112, T-133. Transient scopes: T-122.

**#21, file copy.** Resume with a side file: T-136. Delta, parallel and the
copy options: T-141, T-142, T-143, T-144. A fast road with a fallback: T-164.
Integrity, atomic replacement, `--inplace`, metadata: T-134, T-147, T-146. A
dry run: T-143. Progress, cancellation, remote changes: T-145, T-149. ZMODEM:
T-148. Pipelined SFTP: T-140.

**#22, `ssh_config` and the flags of OpenSSH.** The parser: T-043, T-044. The
settings in effect (`-G`): T-046. `Match`: T-045. `-F` and the port forms of
copy tools: T-043, T-139. Repeated flags: T-017 (done). Values that start with
`-`: T-011.

**#23, output for machines.** JSON on each surface: T-049, T-050, T-051,
T-054. Latency and throughput, and a short preflight: T-053. The health of
the far host: T-189. An exec result with the real exit status: T-054. No
success without an exit status: T-026. The flag table: T-050. The state of
this host: T-051.

**#24, many sessions.** Broadcast, an emergency stop and reviewed macros:
T-185, T-187. A control surface for agents: T-186; over stdio: T-055.
Host groups and per-host settings: T-184, T-043. Session recording: T-033.
Fan-out with an exit rule: T-183. Import and export: T-047.

**#25, robustness and releases.** A circuit breaker: T-059; the retry policy:
T-025. Rate limits and quotas: T-169 (in a relay; it waits for the relay's operator), T-114 (in `serve`),
T-145 (a bandwidth limit). Resource limits: T-201. Connection sharing: T-039.
A scored interop harness: T-199. Fuzzing and a terminal oracle: T-198,
T-200. An audit log: T-116. Live tests kept out of the default run: already
so (the live tests are `#[ignore]`; `docs/STATUS.md`, "Measure again").
Provenance of releases: T-210, T-211.

**#26, streams that are not SSH.** A binary protocol through `-W` or exec:
already works (`docs/STATUS.md`: 262144, 262145 and 5,000,000 bytes with
equal digests over exec, and `-W`). AF_UNIX streams: T-176, T-040. Desktop
streams: T-179. UDP over TCP: T-168. Publish a local HTTP service: T-180 (it waits for the relay's
operator).
Port discovery: T-180. A local-only mode: T-177. USB/IP: T-182 (a tested recipe over `podssh pipe`).

## Requests of a second review (#29 to #36)

Each request cites the lines that it read in podssh and in another project.
Each became one entry, or two. The entry says which claims it verified, and
corrects a claim that the code does not support.

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #29 | Host certificates are dropped, not verified | open | T-027 |
| #30 | The relay hosts are tried one at a time | open | T-220 |
| #31 | Where the replayed output may begin | open | T-221; the invariant of T-152 (no byte that is not acknowledged is dropped) |
| #32 | `podssh serve` finds a shell with no passwd entry | open | T-222 |
| #33 | `check-repo.py` passes with nothing to check; no scan for a listener | open | T-223, T-224; the floors of `cargo todo check` are in T-204 (done) |
| #34 | The expected exit codes, from stock OpenSSH | open | T-225 |
| #35 | Signed pairing grants that are used once | open | T-226 (it waits for the relay's operator) |
| #36 | `--direct` has no limit on a stuck write | open | T-227 |

## The reports on other projects (in #18 to #25, and in #29 to #36)

| Report | Entries |
| --- | --- |
| lablup/bssh | T-043, T-046, T-053, T-107, T-018 to T-022, T-140, T-199, T-027, T-028, T-029, T-030, T-039, T-183 |
| VLOD-ZDOV/quic-ssh | T-162, T-164, T-151, T-152, T-153, T-159, T-043, T-160, T-143, T-035, T-038, T-040, T-086, T-087, T-115, T-052, T-198 |
| nikhiljha/rose | T-160, T-161, T-162, T-158, T-167, T-087, T-130, T-201 |
| adonm/zuko | T-162, T-086, T-163, T-177, T-135, T-150, T-052, T-158, T-121, T-087 |
| rustonbsd/iroh-ssh | T-166, T-165, T-163, T-121, T-043, T-090, T-218, T-114, T-225 |
| willykeenan/warren | T-169, T-088, T-089, T-087, T-086, T-180, T-201, T-151, T-157, T-224, T-227 |
| arjun988/GPU-Share | T-086, T-087, T-162, T-052, T-134, T-114, T-169, T-197, T-179, T-090 |
| EpicEric/sandhole | T-123, T-124, T-168, T-169, T-180, T-114, T-157 |
| mirkobozzetto/bunflared | T-170, T-180, T-177, T-055; WebSocket passthrough already holds (`podssh proxy` is a byte pipe) |
| greaber/syq | T-079, T-083, T-136, T-134, T-147, T-054, T-089, T-145, T-146, T-143, T-226 |
| menhera-org/ssh-obi | T-167, T-151, T-152, T-153, T-154, T-158, T-119, T-122 |
| ado11231/slingshot | T-086, T-114, T-079, T-143, T-178, T-189, T-193, T-192, T-220; a menu-bar app: no, podssh is a CLI (`docs/decisions.md`) |
| gold-silver-copper/fux | T-159, T-161, T-118, T-151, T-158, T-186, T-200, T-198, T-117 |
| l0ng-ai/tty7 | T-159, T-153, T-107, T-186, T-120, T-030, T-133, T-036, T-121, T-221, T-224 |
| AlpinDale/parsync | T-136, T-142, T-141, T-164, T-139, T-048, T-144, T-143, T-150, T-134 |
| sleepinginsummer/agent-ssh-cli | T-136, T-134, T-054, T-039, T-114, T-031, T-032, T-043, T-034, T-026 |
| OthmaneBlial/MobaRust | T-149, T-145, T-041, T-038, T-053, T-187, T-185, T-201, T-047, T-179, T-181, T-202, T-227 |
| yituorou/meatshell | T-070, T-047, T-034, T-148, T-134, T-041, T-189, T-179, T-181, T-185 |
| TeddyHuang-00/sshping | T-053, T-157, T-045, T-049 |
| Petyok/SSHub | T-043, T-049, T-054, T-042, T-171, T-034, T-033, T-047, T-011 |
| cubic-vm/cubic | T-011, T-139, T-181, T-049, T-050, T-051, T-035, T-013 |
| rssh-org/rssh | T-033, T-041, T-034, T-195, T-190, T-185, T-187, T-222; colored command blocks: no, podssh is a CLI (`docs/decisions.md`) |
| totoshko88/RustConn | T-175, T-043, T-038, T-172, T-153, T-056, T-034, T-189, T-191, T-032, T-047 |
| whme/csshw | T-185, T-184, T-043, T-048, T-187, T-151, T-132, T-210, T-188 |
| ImKKingshuk/USBoverSSH | T-059, T-025, T-039, T-051, T-121, T-145, T-116, T-007, T-009, T-040, T-176, T-182 |

## The sandbox reports of 2026-10-08

| Report | Entries |
| --- | --- |
| Sandbox A (`report-podssh-sandbox-KTM-2026-10-08.txt`) | T-001 (done), T-004, T-005, T-006, T-024, T-025, T-157 |
| Sandbox B (`report-podssh-3a88e1d-20261008.txt`) | T-001 (done), T-004, T-157 |
