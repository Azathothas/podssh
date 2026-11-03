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
| #2 | Bracketed IPv6 literals refused | closed | T-007 (the commit "IPv6 addresses as targets: podssh sends the bare literal to the relay"); T-253 is M10's, in podssh's own relay role (Q63) |
| #3 | The token cache key is the first host | closed | T-057 (the commit "Relay tokens: one cache entry for each deployment, with the host that minted it") |
| #4 | Blank flag names under groff | closed | T-015 |
| #5 | `-c`, `-m`, `-X`, `-Y`, `-O`: "unknown flag" | closed | T-016 |
| #6 | `cp`, `mv`, `relay` print the `chat` example | closed | T-008 (the commit "A command that is not implemented says so before the --timeout gate") |
| #7 | `PubkeyAuthentication=no` still advises `-i` | closed | T-023 (the commit "A refusal names keys only when keys were tried") |
| #8 | A missing value reads as an unknown flag | closed | T-009 (the commit "A flag with no value names the flag and its value") |
| #9 | `podssh doctor --json` | closed | T-049 (the commit "podssh doctor --json") |
| #10 | A machine-readable flag table | closed | T-050 (the commit "podssh man --json"), and T-010 (`--help --json` drops `--json`; done in the commit "podssh --help and --version drop no word") |
| #11 | `podssh status` | closed | T-051 (the commit "podssh status: one line of JSON about this host") |
| #12 | `PODSSH_TIMEOUT` | closed | T-012 (the commit "PODSSH_TIMEOUT gives the default of --timeout") |
| #13 | `podssh doctor --full` | closed | T-052 (the commit "podssh doctor --full logs in to GitHub with a key made for the check") |
| #14 | `ssh_config`, `-F` and `-G` | closed (2026-10-30, with a comment that names the entries and commits; in `v1.0.0-beta.1`) | T-043, T-044, T-045, T-046 |
| #15 | `keygen` waits for ever on a dead `/dev/tty` | deleted on GitHub by 2026-11-02 (it was closed) | T-005 (repaired in `eacd94e`; measured in the box in the commit "The box has the sandbox's dead /dev/tty; T-005 measured there") |
| #16 | A repeated flag keeps the last value | deleted on GitHub by 2026-11-02 (it was closed) | T-017 |
| #17 | Relay drops (1011): a generic message, no retry | deleted on GitHub by 2026-11-02 (it was closed) | T-024 (the commit "A dropped session names the hop that broke"), T-025 (33c9a31), T-062 (the backpressure close: f93e4a2, b1f75c9); T-336 is M10's, in podssh's own relay role (Q63) |
| #27 | Repository health | open | T-205, T-206, T-207, T-208, T-209, T-210, T-211, T-212, T-213, T-214, T-215, T-216, T-217, T-218 |
| #28 | `sandbox-check.sh` exits 0 on failure | deleted on GitHub by 2026-11-02 (it was closed) | T-006 (the commit "sandbox-check.sh: each step has a verdict, and a failed step fails the run") |

## Feature requests with reports (#18 to #26)

Each request lists asks, and its comments hold reports on other projects.
Each ask is below with its entries. The operator ruled on the questions of
scope on 2026-10-08 (`docs/decisions.md`).

**#18, transports and reachability.** The iroh road: T-162, T-163, T-164,
T-165. QUIC with a fallback over TLS and TCP: T-162 and T-164 (the reverse
road is the fallback), T-124 (a server that listens, after a probe). A
self-hosted relay: T-169 (M10, in podssh's own relay role since Q63). SSH on port 443: podssh already carries SSH over port 443
through the relay; for a server that listens, T-124. UDP over TCP:
T-168. A Cloudflare quick tunnel, made by podssh itself: T-170 (the research, done), then T-299
(the measurement), T-300 and T-301. QUIC between peers with a relay
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
T-148. Pipelined SFTP: T-140. Closed on 2026-10-30 with a comment that names
the entries and commits; each is in `v1.0.0-beta.1` but T-164, which needs a
build with the feature `iroh`.

**#22, `ssh_config` and the flags of OpenSSH.** The parser: T-043, T-044. The
settings in effect (`-G`): T-046. `Match`: T-045. `-F` and the port forms of
copy tools: T-043, T-139. Repeated flags: T-017 (done). Values that start with
`-`: T-011. A Mosh transport for each host (SSHub's report): no road runs
`mosh-server` (`docs/decisions.md`); the functions of Mosh: T-171 (the map, done), then T-302,
T-303, T-304, T-305 and T-306.

**#23, output for machines.** JSON on each surface: T-049, T-050, T-051,
T-054. Latency and throughput, and a short preflight: T-053. The health of
the far host: T-189. An exec result with the real exit status: T-054. No
success without an exit status: T-026. The flag table: T-050. The state of
this host: T-051. Closed on 2026-10-30 with a comment that names the entries
and commits, all in `v1.0.0-beta.1`.

**#24, many sessions.** Broadcast, an emergency stop and reviewed macros:
T-185, T-187. A control surface for agents: T-186; over stdio: T-055.
Host groups and per-host settings: T-184, T-043. Session recording: T-033.
Fan-out with an exit rule: T-183. Import and export: T-047, T-292 (PuTTY,
MobaXterm, Remmina), T-327 (mRemoteNG) and T-328 (FinalShell, Termius; it
waits for the operator's exports).

**#25, robustness and releases.** A circuit breaker: T-059; the retry policy:
T-025. Rate limits and quotas: T-169 (in podssh's own relay role, M10, Q63), T-114 (in `serve`),
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
Closed on 2026-10-30 with a comment that names the entries and commits, and
T-180, `podssh funnel` in M10 (Q63).

## Requests of a second review (#29 to #36)

Each request cites the lines that it read in podssh and in another project.
Each became one entry, or two. The entry says which claims it verified, and
corrects a claim that the code does not support.

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #29 | Host certificates are dropped, not verified | deleted on GitHub by 2026-11-02 (it was closed (`a1d32e0`, 2026-10-11)) | T-027 |
| #30 | The relay hosts are tried one at a time | deleted on GitHub by 2026-11-02 (it was closed (`4cfbd5f`, 2026-10-11)) | T-220 |
| #31 | Where the replayed output may begin | deleted on GitHub by 2026-11-02 (it was closed) | T-221 (`61e55d1`); the invariant of T-152 (no byte that is not acknowledged is dropped, `d70f88f`) |
| #32 | `podssh serve` finds a shell with no passwd entry | deleted on GitHub by 2026-11-02 (it was open) | T-222 |
| #33 | `check-repo.py` passes with nothing to check; no scan for a listener | deleted on GitHub by 2026-11-02 (it was closed) | T-223 (the commit "Each repository check has a floor, and fails on an empty tree"), T-224 (the commit "The repository check finds a listener outside its allowance"); the floors of `cargo todo check` are in T-204 (done). Closed on 2026-10-09 with a comment that names them |
| #34 | The expected exit codes, from stock OpenSSH | deleted on GitHub by 2026-11-02 (it was closed) | T-225 (`e8bec97`) |
| #35 | Signed pairing grants that are used once | deleted on GitHub by 2026-11-02 (it was open) | T-226 (M10, in podssh's own relay role since Q63) |
| #36 | `--direct` has no limit on a stuck write | deleted on GitHub by 2026-11-02 (it was closed (`f502fba`, 2026-10-11)) | T-227 |

## Requests after the triage (#51 on)

#37 to #50, #52, #53, #57, #58, #64 to #68, #77, #78 to #82, #119, #120, #122 and #123 are pull requests;
Dependabot's #44 to #47, updates of a major version, are T-330, but #47 (aes-gcm 0.11), which is
T-333 (done on 2026-10-31, after the ruling of Q48); Dependabot's #57 and #64
to #68 are T-355, and so is #77 (pageant 0.2.5 in `fuzz/Cargo.lock`, as in the
root lock), made on `main` and closed with a comment; Dependabot's #78 to #82 of 2026-11-01
(the tailscale image, the minor and patch group, rand 0.10, sha2 0.11 and hmac 0.13) are T-386;
Dependabot's #119, #120, #122 and #123 of 2026-11-02 (Python 3.15 for the box's proxy, the build
image's digest, sha2 0.11.1 and simple-dns 0.13) are T-597.

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #51 | An HTTP/2 road over extended CONNECT (RFC 8441) | open | T-321 (M10, on podssh's own relay role's listener since Q63; the default relay's edge chose `h2` and did not offer extended CONNECT, measured on 2026-10-30) |
| #54 | `doctor` measures what the proxy does to a stream | closed | T-324 (the three failures of the upgrade, and samples with their loss; the commit "doctor samples each probe of TCP, and names three failures of the upgrade"); T-325 (buffering, a cap on bodies, an idle limit) is M10's, served by podssh's own relay role (Q63) |
| #55 | The split road's wire protocol | open | T-319 (its Approach holds the protocol; the operator allowed its second connection, Q44, and it is M10's since Q63, served by podssh's own relay role) |
| #56 | A cleartext road on port 443, probed | open | T-326 (the operator allowed it with a token for one session, Q45, and it is M10's since Q63, served by podssh's own relay role) |
| #59 | The forward road without the operator's relay: ways with no account to reach a `host:port` (research) | open | Each road of its ranking, in the paragraph below |
| #60 | A relay template: a WebSocket forwarder that takes the destination from the URL | closed 2026-11-01, each entry done | T-369 (a forwarder that the user names); T-370 (the public forwarders in the binary, and a fallback to them, by the operator's ruling Q56) |
| #61 | SSH on port 443 as a hop | closed 2026-11-01, each entry done | T-371 (the hop measured, and a `doctor` line for a hop, b666713), T-372 (a hop or a destination whose SSH is wrapped in TLS, `ssh+tls://`, 60c2414) |
| #62 | A Shadowsocks road with a refreshable subscription | closed 2026-11-01, each entry done | T-373 (`--shadowsocks FILE`, tested against shadowsocks-rust's `ssserver` and `sslocal`) |
| #63 | Anonymous exits with no TUN device: WARP over HTTP/2, and Arti | closed 2026-11-01, each entry done | T-352 (Option 1, WARP; its first comment's measurements are in the Premise), T-353 (Option 2, Arti, live on Tor's public network by Q60), T-374 (its second comment: the quick tunnel's edge through WARP) |
| #69 | `doctor` reports a bind as if it had measured a listener | closed | T-357 and T-358 (the commit "T-357 and T-358: done. podssh doctor listens once on each socket that it binds", 12fc719: the lines `listen AF_INET` and `listen AF_UNIX`, by the operator's ruling on Q53). `-L` exits 255 on a refused listener, not 77 as the issue says |
| #70 | The UDP probe measures a local bind, not egress | closed | T-359 (done, 2026-10-31); the quick tunnel's QUIC has its own probe, its handshake (T-301), not this one, so one bind does not decide two roads |
| #71 | The record checks its citations, not its sentences | closed 2026-10-31, each entry done | T-360 (the map of issues against GitHub), T-361 (the targets of a Prove), T-362 (claims of "yet", and a status beside an id). Its five statements: four corrected in place in the commit of the triage (`docs/architecture.md`, `docs/design.md`, `docs/irc.md`), and the fifth, the facts file's comment, is T-342's (its Approach item 5). The reporter withdrew its item on `UNVERIFIED`. #59 to #63, which it found with no row, wait for their triage (T-360, item 5) |
| #72 | The direct road has no automatic selection | closed 2026-11-01, its entry done | T-363 (after the relay hosts fail, in the order of the road table, not before them as the issue asks) |
| #73 | `-R` refuses the socket forms that `-L` and `-D` carry | closed | T-365 (done, 2026-10-31), which takes the remote SOCKS form (`-R [bind_address:]port`) too: #73 reads its refusal as parity, but OpenSSH carries it (measured with OpenSSH 9.6p1's `ssh -G`) |
| #74 | `doctor` never tells a name allowlist from an address allowlist | closed 2026-10-31, its entry done | T-366 |
| #75 | An HTTP CONNECT listener | closed 2026-10-31, its entry done | T-367 |
| #76 | `ws:` and `ws-listen:` as addresses of `pipe` | closed 2026-10-31, each entry done | T-368, with the reader of requests of T-367 |
| #83 | A quiet minute ends the session when a Go server's reply to the keepalive carries data | closed 2026-11-03, each entry done (`b026d58`) | T-460 (russh ends the connection on a failure with data, which Go's x/crypto/ssh sends; OpenSSH reads none) |
| #84 | Exit 0 with stdout cut at the relay's 64 MiB | closed 2026-11-02, its entry done (`5b2468a`) | T-461 (the status came before the output's end; no rotation for a plain sshd, whose far end keeps nothing to go on with) |
| #85 | `-R` refused by a Go server reads as a lost connection | closed 2026-11-03, each entry done (`772275c`) | T-460 (the connection was lost: the failure's data ended it, inferred from the 0.7 s), T-464 (that line names no cause) |
| #86 | A `-J` hop that opens its channel and carries nothing ends in a bare 60 s timeout | closed 2026-11-02, its entry done (`f460dcf`) | T-462 (the hop took the channel, as the handshake's line came; a refused one is named at once, as `crates/podssh-cli/tests/jump_hop.rs:180` tests) |
| #87 | `cp --delta` falls back to a full copy with no word | closed 2026-11-03, its entry done (`9679787`) | T-470 (also: the copy by exec does not read `--delta`, and a server with a command and no `copy-data` gets its delta through that command) |
| #88 | `health` gives the host's 48 CPUs and 188 GiB, not the container's 4 CPUs and 4 GiB | closed 2026-11-03, its entry done (`0ce6745`) | T-480 (the cgroup's limits, v2 and v1, beside the host's facts, and `effective` in the JSON) |
| #89 | `sftp`'s `ls -l` is not OpenSSH's long form | closed 2026-11-03, its entry done (`57fd523`) | T-471 (also: `-f`, `-h`, `-r`, `-S` and `-t` of `ls` do nothing; the words "as OpenSSH's sftp" are the about of `--help`, `crates/podssh-cli/src/flags.rs:397`, not the README's) |
| #90 | A summary line, and progress in a pipe, for `cp` and `run` | open | T-472 |
| #91 | `job` and `--persist` with no tmux: the command that installs it, and the dependency in the README | open | T-481 (the hint from the far host's package manager, the README's first steps, and `job --no-tmux`, whose runner alone signals its own child, so the PID reuse that T-193 set `nohup` aside for cannot kill another process) |
| #92 | A preflight of the far host: what its server allows, before a long command needs it | open | T-482 (`health --preflight`; `doctor --via` is T-439's flag, and `doctor` takes no option of `ssh`); its rows of #83 to #87 are those issues' own entries |
| #93 | `pipe http-listen:` takes `ssh:USER@HOST`, and a worked example of CONNECT | closed 2026-11-03, its entry done (`7417676`) | T-483 |
| #94 | `each --json` and `--result-file`: each host's status and streams in one object | open | T-484 (a record of each session, in place of the process's, which T-183's Done names) |
| #95 | `cp --no-clobber`, `--update` and `--backup` | open | T-473 |
| #96 | `job log --follow` on one connection | open | T-485 |
| #97 | `--result-file` for `cp`, `mv`, `run` and `sftp`, in one schema | open | T-486 (the copy's bytes are `transferred`, as `bytes` keeps the meaning of `ssh`'s), with T-484's record of a session for `run` |
| #98 | A warning before the relay's 180 s idle cut | closed 2026-11-02, its entry done (`b39a29d`) | T-463 |
| #99 | `doctor` says once that each TLS handshake was reset | open | T-487 (the kind of each failure kept, not read from the system's words; a reference handshake with `github.com`; a diagnosis after the counts) |
| #100 | `cp` chooses `--parallel` itself for many small files | open | T-474 (Q23 sets the default of relay sessions; the files at once are channels of one connection: T-474's Decision) |
| #101 | `podssh mcp` offers `cp`, `job` and `health` as tools | closed 2026-11-03, its entry done (`f8eaeb4`) | T-488 (with `session`, which the issue names too; the copy's local side behind a new `--allow-dir`, the sessions behind `--allow-session`) |
| #102 | `chat --listen --linger`, and a word on the end of stdin | closed 2026-11-03, its entry done (`ea2a70b`) | T-489 (the listener connects out to the relay, so `--linger` adds no listener) |
| #103 | `run` reads a `.podsshignore` by default, and `--dry-run` | open | T-475 (its first ask is met already, `crates/podssh-cli/src/run_cmd/mod.rs:141-145`, as its comment found) |
| #104 | A target that ends the connection right after the login reads as a refused session | closed 2026-11-02, its entry done (`772275c`) | T-464 (the words "Disconnected" and "Channel send error" are russh's, not the server's) |
| #105 | `cp -r` says a skip twice, and exits 66 for a skip | closed 2026-11-03, its entry done (`a383ce9`) | T-476 (the line said twice is the first failure of the tree, not the last skip) |
| #106 | The fallback to other products' forwarders should be asked for: 20.8 s against 0.14 s on a dead target, and the target goes to three services | closed 2026-11-03, its entry done (`b32ecef`) | T-509 (the fallback follows the relay's answer about the target too, a 502 or a refusal by policy, which no forwarder mends; the default of off is the operator's to rule, as Q56 set it on) |
| #107 | WARP's road opens on TLS to the edge, and proves no packet through the tunnel | open | T-560 |
| #108 | WARP's road dials one constant address, not the API's peers | closed 2026-11-03, its entry done (`c5299c2`) | T-561 |
| #109 | WARP's registration has one API name and no second route | closed 2026-11-03, its entry done (`cde307f`) | T-562 (the second name goes in once a live run shows it is the same API) |
| #110 | The relay's record forgets a host that opens, and keys each road's verdict by the host | closed 2026-11-03, its entry done (`7abebd2`) | T-563 |
| #111 | podssh never raises its soft limit of open files | closed 2026-11-03, its entry done (`5b643b1`) | T-564 |
| #112 | A node refuses each new session once its replay budget is full, and names the budget, not its cause | closed | T-586 (inferred, which its Prove measures: OpenSSH ends its ProxyCommand `operator` with SIGHUP, and the node keeps each such session 10 minutes, charged a whole buffer) |
| #113 | `proxy` cannot address `node://NAME` | open | T-587 (`proxy node://NAME` as the pipe of `operator NAME`, a call of Q86; the issue's prefix `podssh ssh:` is not this code's) |
| #114 | `ssh node://` waits the whole ConnectTimeout, where `operator` to the same node reads sshd's line in 3 s | closed | T-588 (not reproduced; no test runs `ssh node://` from Windows) |
| #115 | `operator` and `proxy` take no `--ConnectTimeout` | open | T-589 |
| #116 | `node --sshd` with no sshd says `Connection refused`; a line of `doctor` for it | closed 2026-11-03, its entry done (`279a283`) | T-590 |
| #117 | A pair's expiry of 3 days, no renewal, and `relay status` with no expiry | open | T-591 (`relay status NAME` names the expiry of a stored pair already; an operator's file cannot be asked), T-592 (a renewal, in podssh's relay role, M10) |
| #118 | The node's key under `HOME/.cache` when `HOME` is another user's | closed | T-593 |
| #121 | `docs/STATUS.md` describes `main`, and the release has no exit node | open | T-594 (the exit is in `v1.0.1`'s notes, T-584) |
| #124 | A carrier over stdio or exec for a node and its client | open | T-595, T-596 (the exit over it) |

**The survey of #59, of 2026-10-31.** It extends #18 and the study of
carriers of the same day (`docs/carriers.md`, whose forward road is T-347,
T-351, T-352 and T-353). Its ranking, road by road: 1, a forwarder that
takes its target from the URL: T-369, and T-370 for the forwarders in the
binary (Q56), both done on 2026-11-01; 2, the same Worker in the user's own Cloudflare account: a
template of T-369 can name it, podssh ships no forwarder (a relay of the user's own
is T-169, podssh's own relay role since Q63, 2026-11-02), and a recipe for it is
part of Q56; 3, SSH on port 443 as a hop: T-371 and T-372 (#61, both done); 4,
Shadowsocks: T-373 (#62, done); 5 and 6, WARP and Arti: T-352 and T-353 (#63,
Q52, settled); 7, n0's iroh relays: a road already (T-162, done), and T-348 for the
release binaries (Q50, settled on 2026-10-31). The comment's corrections of the
study: the three forwarders are T-369 and T-370; the 60 s of EICE's
presigned URL, which the comment found in no document of AWS, the study
cites to AWS's own client, its source F24
(`aws/aws-cli:awscli/customizations/ec2instanceconnect/eicesigner.py`),
which the comment does not name, and T-351 keeps it; Microsoft Dev
Tunnels, which the study left out of the forward road as a tunnel of the
class of `cf://` that needs an account, is fourth on its reverse road, and
`cf://` with a quick tunnel gives that class with no account (T-347); the
rules of `connect()` in a Worker (port 25, and Cloudflare's and private
addresses, refused as targets) hold for the forwarders of T-369. The
classes that gave no road (TURN with TCP allocations, public frp, VPN exits
that need a TUN device, domain fronting) need what a cage does not give
(UDP, a TUN device, a port other than 443, 80 and 8443), or do not exist (a
public front to any target), as #59 says.

**The two options of #63.** Its prerequisite for both, a TCP/IP stack in the
process, holds for T-352 and T-374; Arti gives a stream for each target, so
T-353 needs none (Inferred).
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
| mirkobozzetto/bunflared | T-170, T-299, T-300, T-301, T-180, T-177, T-055; WebSocket passthrough already holds (`podssh proxy` is a byte pipe) |
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
| Petyok/SSHub | T-043, T-049, T-054, T-042, T-171, T-302, T-303, T-304, T-305, T-306, T-034, T-033, T-047, T-011 |
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

## The report of the operator's testing agents on `v1.0.0`, 2026-11-02

A black-box test of `podssh-x86_64-unknown-linux-musl` `v1.0.0` (`35a0d19`) on a Debian 13 guest
with a curated environment (no `USER`, no `ssh` config, no key, no `tmux`, egress through one HTTP
CONNECT proxy on ports 80 and 443): eight issues, not on GitHub, a ledger of 40 observations
(L-01 to L-40), its findings and a checker of its claims, which the triage read and did not run.
Each entry says which claims it verified in the code, and corrects the ones that the code does not
support.

| Report | Entries |
| --- | --- |
| Issue 01, "no user name" with `USER`, `LOGNAME` and `USERNAME` unset (`01-no-user-name.md`; L-01) | T-500 (the README of this repository names no `ssh railway.new`; that one-liner is Railway's page) |
| Issue 02, `--su` waits for ever when `SSH_ASKPASS` exits not 0 (`02-su-hang.md`; L-03, L-05, L-11) | T-501 (L-11, `--sudo` under `NOPASSWD`, is by design) |
| Issue 03, `-o ProxyCommand=none` does not beat a file's `ProxyCommand` (`03-proxycommand-in-config.md`; L-07) | T-502 (L-07 is T-043's Decision: `podssh proxy %h %p` names `podssh ssh` itself, and runs nothing) |
| Issue 04, host names by road, and `each`'s blanks (`04-each-whitespace.md`; L-18, L-19) | T-503 (the check of the relay road is podssh's own, not the relay's), T-504 |
| Issue 05, 22 keywords of a restriction accepted with no word (`05-ignored-config-keywords.md`; L-08, L-09, L-39) | T-505 (L-39's two notes come from Debian's `/etc/ssh/ssh_config`, not OpenSSH's defaults) |
| Issue 06, an empty list reads as a broken one (`06-empty-list-output.md`; L-23) | T-506 (`job list` prints no header either) |
| Issue 07, the way back after a downgrade (`07-update-rollback-advice.md`; L-37) | T-507 |
| Issue 08, `--timeout` on two copy verbs of four (`08-timeout-inconsistent.md`; L-12, L-13, L-30) | T-508 (the split is T-139's Decision; the silent server's wait is ConnectTimeout's 60 s, past the report's 30 s; L-30 is met) |
| The ledger's other observations | L-04, L-28 and L-40: T-509, with GitHub #106; L-06: T-481 (GitHub #91); L-15 and L-16: T-510; L-20: T-475; L-26: T-483; L-32: T-511; L-10, L-14, L-17, L-22, L-25, L-27, L-29 and L-36: T-512. Met: L-21 (the row of `--timeout` of `job` names `wait`, and the refusal names `job wait`, `crates/podssh-cli/src/flags/job.rs:14-15`), L-33 (the table of flags for a program is `podssh man --json`, T-050, which holds no such word; `--help` is prose for a person). Not podssh's, as the ledger says: L-02 (Railway refused each login), L-24 (the quick tunnel's road, as its manual says), L-31 and L-35 (the proxy dropped a CONNECT), L-34 (a note on the test), L-38 (both forms of help work) |

The report names GitHub #22 (T-502 and T-505 are on its ground, `ssh_config` and the flags of
OpenSSH) and #60 (T-509 narrows T-370's fallback).
