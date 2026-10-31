The roads beyond the forward and reverse roads: the iroh road of milestone M6
and its race with the reverse road; a roost next to a standard sshd and a
start from one; UDP over the relay; a self-hosted relay, which is work of the
relay project; a quick tunnel and the functions of Mosh, made by podssh
itself; Multipath TCP; resumption in the relay (M8); and the roads of plain
HTTP and of HTTP/2 to the relay.

# T-162: The iroh road behind the cargo feature `iroh`

**Source:** ROADMAP M6 (the iroh road); `docs/design.md:956-1150`;
`docs/decisions.md` (2026-10-08: iroh is a road that the user must select);
GitHub #18 (Nemo-010, 2026-10-08: the iroh-ssh, zuko, GPU-Share and quic-ssh
reports).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

Between two podssh ends, the only road is the WebSocket relay. iroh gives
QUIC between keys, a direct path when UDP works and a relay when it does not,
and it keeps a connection across address changes. podssh has no iroh code.

## Premise

Read, not measured (`docs/design.md:963-986`): iroh 1.1 or later (advisories
up to 1.0.3), MIT or Apache-2.0, MSRV 1.91, the aws-lc-rs backend, about 190
to 245 crates. In the target sandbox it runs only with no UDP transport (or a
UDP bind after a probe), podssh's proxy in `proxy_url(...)`, the `Minimal`
preset with no pkarr or DNS, peers dialled by ticket, and a home relay whose
`/ping` passes the proxy. The operator accepted netlink sockets and extra
connections for this road (`docs/design.md:1139-1142`). The sandbox refuses UDP
(`docs/target-environment.md:23`). Measured on `3ee70dc`: `--iroh` is an
unknown flag (exit 64), and `Cargo.lock` has no iroh crate.

## Approach

1. A new crate, crates/podssh-iroh: a workspace member, not a default member,
   with `rust-version = "1.91"` and iroh `>=1.1, <2` on aws-lc-rs. A feature
   `iroh` in `crates/podssh-cli/Cargo.toml`, as for `ts`
   (`crates/podssh-cli/Cargo.toml:21-27`), and a step in `scripts/gate.sh` as
   for `ts`. The default build and the releases stay without the feature.
2. The endpoint: the `Minimal` preset, no pkarr or DNS discovery, and the
   relays of T-165. `proxy_url(...)` gets what `proxy_from_env` selects
   (`crates/podssh-ws/src/dial.rs:98-123`), so `ALL_PROXY` and `NO_PROXY` act
   as on the other roads; iroh's own selection ignores both
   (`docs/design.md:984`).
3. UDP: `clear_ip_transports()` by default. Add the UDP transport only after a
   probe that binds a UDP socket to port 0 and closes it, as `bind_inet`
   probes TCP (`crates/podssh-cli/src/doctor/unix.rs` lines 137-166 at `48a8744`).
4. A session is one QUIC stream with the ALPN `podssh/1`. It carries the
   records of the resumable layer (T-151), so it can resume on the other road
   (T-153).
5. `doctor`, with the feature: a UDP line, and the `/ping` of the home relay
   through the proxy (`crates/podssh-cli/src/doctor/host.rs:10-25`).
6. `availability()` knows `ts` as the only build feature
   (`crates/podssh-cli/src/flags.rs:457-465`): extend it. With no feature, an
   iroh destination refuses before it connects and names `--features iroh`,
   as `crates/podssh-cli/tests/ts_not_built.rs:1-4` shows for `ts`.
7. Docs: the "Outbound only" item of `README.md`, "Nothing listens" in
   `SECURITY.md:129-156`, `docs/architecture.md` (rule 3, the crates),
   `docs/design.md` section 7, and `AGENTS.md` (sections 3 and 7).

## Decision

Recommendation: a crate of its own, outside the list of crates with no C,
because iroh with aws-lc-rs needs a C compiler (`AGENTS.md`, section 5, rule
4). The alternative, a feature in `podssh-relay`, lost: with `--all-features`
that crate would need C, and the no-C step of the gate would pass only
because the feature is off.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test iroh_not_built
cargo test -p podssh-iroh -p podssh-cli --features podssh-cli/iroh
sh scripts/dev.sh check
```

The first shows that the default build refuses an iroh destination and names
the feature. The second runs two endpoints with no UDP, through a stand-in
CONNECT proxy, and carries 20 MiB with an equal SHA-256; a planted endpoint
that uses iroh's own proxy selection fails with `ALL_PROXY` set.

## Done

2026-10-09, with T-265, a defect of the dial that the doctor's new line found.

- crates/podssh-iroh (a workspace member, not a default one; Rust 1.91):
  iroh 1.3.0 (`>=1.1, <2`) with no default features and `tls-aws-lc-rs`.
  `endpoint::bind`: the `Minimal` preset, no address lookup, the relays given
  (n0's by default, `default_relays`), podssh's proxy for the relay at an
  address that podssh resolved (`HttpProxy::url_at` of podssh-ws), podssh's
  name resolution (`resolve::Podssh` in iroh's `DnsResolver::custom`),
  podssh's trust store (rustls's WebPKI verifier over podssh's roots), the
  captive portal check off, and no IP transport unless `probe::udp` binds,
  then UDP sockets that are not required. Proxy credentials that iroh would
  send wrong (escaped, and in base64url) are refused with the reason.
- `stream`: a session is a bidirectional QUIC stream with the ALPN
  `podssh/1`, announced by one byte from the client, as a QUIC peer learns of
  a stream only from its first byte; `far::serve` runs the layer's far end on
  each, with one keeper. The far end's policy of one link moved from the
  reverse road's `Layered` to `podssh_relay::session::far::serve`, which both
  roads now run.
- podssh-cli: the feature `iroh`; `podssh ssh iroh:...` exits 70 before
  anything resolves, and in the default build names `--features iroh` (an
  iroh destination is no verb, so `availability()` stays per verb); with the
  feature, it says that dialling a ticket is not implemented yet (T-163).
  `doctor`, with the feature: `bind UDP`, and `/ping` of the first relay
  through the proxy.
- The gate: `podssh-iroh` in the packages of `lint`, a clippy line with the
  feature, and the steps `msrv_iroh` (1.91) and `iroh` (the tests). The
  listener check allows the probe's and the endpoint's UDP bind. `deny.toml`
  checks the targets that podssh ships: three crates under the Unlicense are
  only for the browser's WebAssembly target of iroh's relay client, which no
  release compiles. The documents: `README.md`, `SECURITY.md`,
  `docs/architecture.md`, `docs/design.md` (section 7), `docs/development.md`
  and `AGENTS.md` (sections 3 and 7).
- Prove, native, Windows: `cargo test -p podssh-cli --test iroh_not_built`:
  2 passed. `cargo test -p podssh-iroh -p podssh-cli --features
  podssh-cli/iroh`: 336 passed, 0 failed, 8 ignored. In it: 20 MiB each way
  through a stand-in CONNECT proxy and a relay on the loopback, under a name
  that only the proxy resolves, with equal SHA-256 digests; podssh's trust
  store refuses the relay's self-signed certificate; with `ALL_PROXY` alone,
  podssh's selection reaches the relay, and the planted endpoint with iroh's
  own selection gets no home relay. `cargo deny --locked check advisories
  licenses bans sources`, and with `--all-features` for licenses and
  sources: ok. clippy with the feature: no warning.
- Live, once: `podssh doctor` of a build with the feature, this machine:
  `bind UDP` ok, and n0's first relay answered `/ping` in 576 ms; 20 ok, 0
  FAIL.
- Waits for T-251, by the decision of 2026-10-09: `sh scripts/dev.sh check`
  (the steps `msrv_iroh` and `iroh` in the build image).
- CI, the run of `8d88bdf`: the gate's steps `msrv_iroh` and `iroh` passed.
  The secret scan stopped at the made-up proxy credentials of the new tests,
  at the loopback and at a documentation address, which TruffleHog could not
  verify; they are listed in `.github/secrets-allow.txt` as test values.

# T-163: iroh tickets and node keys

**Source:** ROADMAP M6 (dialled by ticket); `docs/design.md:985` and
`docs/design.md:1107-1108`; GitHub #18 (Nemo-010, 2026-10-08: zuko's ticket
handoff; iroh-ssh's persistent and ephemeral keys).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A client reaches an iroh node by its key and a relay URL: a ticket. podssh has
no form for a ticket, no place for the keys, and no rule for who may connect.

## Premise

Read: with the `Minimal` preset nothing is discovered, so a ticket gives the
key and the relay URL (`docs/design.md:985`). The key is the identity, and
access is by an allowlist of keys or a relay token (`docs/design.md:1107-1108`).
Read in the reports, not verified here: iroh-ssh warns when a server's key is
ephemeral (`rustonbsd/iroh-ssh:src/ssh.rs`); zuko hands over a ticket out of
band (`adonm/zuko:docs/protocol.md`). Read: `podssh ts` keeps its node key in
the file that `--ts-state` names (`crates/podssh-cli/src/flags.rs:343-344`,
`crates/podssh-cli/src/ts.rs:166`). Credentials never go on argv
(`AGENTS.md`, section 4).

## Approach

1. Keys: one Ed25519 secret key for each role (node, client), in a private
   file. `--iroh-key FILE` names the file, as `--ts-state` does; with no flag,
   it goes to the first usable directory of the cache chain
   (`crates/podssh-relay/src/cache.rs`, lines 61-76 at `4dd52f8`). Reuse the private-file code of
   the token cache (`crates/podssh-relay/src/cache.rs:297-322`: mode 0600, no
   symbolic link, the owner checked); do not write a second copy.
2. Print the fingerprint of the public key, never the secret key. A node key
   persists, and a node warns when it makes a new one, because its ticket
   changes. `--ephemeral` makes a key for one run only.
3. The ticket: `iroh:` and the node's public key and home relay URL, in iroh's
   own encoding. It is an address, not a credential.
4. Access: the node accepts a client only when the client's public key is in
   its allowlist file (one key on each line), and logs a refused key by its
   fingerprint. T-087 extends this.
5. The node prints its ticket and its fingerprint on stderr when it starts.
   `podssh ssh iroh:TICKET` dials it (the address of `docs/design.md:914`).
6. Add the key files to FILES in the manual
   (`crates/podssh-cli/src/man/data.rs:146-293`), and each new variable to
   `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:45-260`).

## Decision

Recommendation: a ticket is an address, and the node's allowlist of client
keys gives access. A ticket can then go on a command line or into
`ssh_config` with no risk. The alternative, a bearer ticket (tailcat's address
is one: `docs/design.md:890-891`), lost: each process on the host can read a
command line, and the rules forbid credentials there.

2026-10-10, the shape of the command line and the files:

- `podssh node NAME TARGET --iroh` serves TARGET over the iroh road alone;
  NAME labels the node's key and its lines, and no pair is needed. Lost: both
  roads whenever a pair exists. The two roads end for different reasons (a
  pair expires, a key does not), and one keeper for both is the work of the
  race (T-164), which now says so.
- A key file holds the 32 secret bytes in hex and a newline, as iroh's
  `SecretKey` parses them (and as dumbpipe's `IROH_SECRET` gives them). With
  no `--iroh-key`, the node's key is `iroh-node-NAME.key` and the client's
  `iroh-client.key`, in the cache's directories. A key file that exists and
  is not private, or is a symbolic link, is refused with the reason and never
  replaced: a new key would change the node's ticket. The file is made whole
  or not at all (a temporary file and a hard link), so two first runs at the
  same time get one key.
- `--iroh-ephemeral`, not `--ephemeral`: the flags of a road carry its name,
  as `--ts-ephemeral` does.
- The fingerprint is the public key itself, in iroh's hex: it is not secret,
  and the allowlist takes it as it is. Lost: a hash, as ssh shows, which the
  allowlist could not take.
- The allowlist is `--iroh-allow FILE`: one key on each line (hex or base32,
  as iroh writes a key), then an optional comment; `#` starts a comment line.
  The node reads it again for each connection, so a key added counts at once.
  A line that is not a key lets nobody in and is named. With no file, nobody
  gets in, and the node says so when it starts. A file that another user owns
  or that others can write is refused, as sshd refuses an `authorized_keys`;
  others may read it, as it holds public keys.
- A refused client gets the QUIC close code 403 with the reason, and prints
  its own key with the remedy.
- The ticket holds the node's key and its home relay, and no IP address of
  its host: with UDP, the relay tells each side the other's addresses.
- The known host's name is `iroh:` and the node's key: a ticket changes with
  the home relay, the key does not.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --test keys --test tickets
```

The key test writes and reads a key file with mode 0600, refuses a symbolic
link and a file that others can read, and shows that no output holds the
secret. The ticket test parses tickets that iroh made (fixed strings, not
made by podssh's encoder), and refuses a client key that is not in the
allowlist. A planted node that accepts each key fails it.

## Done

2026-10-10.

- `podssh_relay::cache` (`cache/own.rs`): `read_own` reads a file that the
  user names, or that podssh keeps for good, with each refusal's reason (a
  symbolic link, not a regular file, another user's, open to others beyond
  what the file allows), where the cache ignores a file that it can make
  again; the cache's own reads are `read_own`'s now. `create_private` makes
  a private file whole or not at all and never over another (a temporary
  file and a hard link; in place where a file system has no hard links), and
  `create_file_in_first` does so in the first of the cache's directories
  that takes it.
- `podssh-iroh`: `keys` (a key in the file that the user names, in the
  cache under the node's NAME or the client's one name, or for one run; made
  from the OS's random source, with an error and no panic without one;
  refused and kept when it is not private; shown by its public half);
  `ticket` (iroh-tickets 1.0's ticket after `iroh:`; a node's holds its key
  and its home relay only; `follow` gives the new ticket when the home relay
  changes); `allow` (the allowlist: keys in hex or base32, comments, each
  bad line named; a file that others can change is refused); `client`
  (`Dialer`: a stream on the connection while it lives, else a new
  connection; the node's refusal known by its close code, 403; `carry` runs
  the layer and resumes it on a new link); `far::serve` closes a client that
  the allowlist refuses before any stream. Over iroh, the layer's features
  leave out `move.v1`.
- podssh-cli: `podssh node NAME TARGET --iroh` (`node_iroh.rs`): TARGET is
  dialled first, then the key, the endpoint and a home relay within 30 s;
  the key, the ticket and who may connect go to stderr, and each connection's
  key is checked against the file of `--iroh-allow`, read again each time,
  each refusal said with the key. `--iroh-key`, `--iroh-allow` and
  `--iroh-ephemeral` are usage errors with no `--iroh`, and so are
  `--iroh-ephemeral` with `--iroh-key`, and `--pair-file`, with it.
  `podssh ssh [user@]iroh:TICKET`: the ticket is checked before anything
  connects, the host key is kept under `iroh:` and the node's key, and this
  user's key (`iroh-client.key`, or `--iroh-key`) is printed when it is new
  and when a node refuses it; `-p`, `-J`, `-W`, `--direct`, `-4`, `-6`,
  `HostName` and `--pair-file` are refused with it, and SSH sends no
  keepalive by default, as to a node of the reverse road. In a build without
  the feature, `--iroh` exits 70 and names it, as an iroh destination does.
  The flag table of `node` is in `flags/node.rs`. The manual: the notes of
  `ssh` and `node`, and two rows of FILES with the feature.
- The documents: `SECURITY.md`, `docs/cli.md`, `docs/design.md` (section
  7), `docs/architecture.md`, `AGENTS.md` (the map) and `docs/STATUS.md`.
  T-164's approach now says that a node serves both roads, with one keeper,
  as part of the race.
- Prove, native, Windows: `cargo test -p podssh-iroh --test keys --test
  tickets`: 15 passed (7 and 8). A key file, of mode 0600 on Unix, is made
  once and read again; a key in the second of the cache's directories is
  found, and none is made in the first; eight first runs at once get one
  key and leave no temporary file; no output holds the secret; a file that
  is not a key is refused with its path and kept; no random source is an
  error. iroh's own ticket (the vector of iroh-tickets 1.0.0, written by
  Python's base32) parses to its key, relay and address, and podssh writes
  the same text back; tickets that reach nothing, or are no tickets, are
  refused; an allowlist takes hex, base32 and comments, and names a bad
  line. A node, over a relay on the loopback and the stand-in proxy, refuses
  a client that is not in its allowlist and opens no target for it; the
  client gets in once its key is added to the file, with no new start of
  the node. The planted node that admits each key fails that check, and a
  planted `far::serve` that skips the allowlist failed
  `a_node_refuses_a_client_that_is_not_in_its_allowlist` (run once, then
  restored). `cargo test -p podssh-cli --test iroh_cli`: 3 passed in the
  default build, 4 with the feature. `cargo test --no-fail-fast`: 1002 passed, 0 failed, 22 ignored;
  `cargo test -p podssh-iroh -p podssh-cli --features podssh-cli/iroh`:
  355 passed, 0 failed, 8 ignored. clippy in both builds: no warning. `cargo deny`: ok (iroh-tickets
  brings `heapless` 0.7 through postcard's default features, under MIT or
  Apache-2.0).
- Waits: the checks that only Unix has (modes, symbolic links) run in CI's
  gate, step `iroh`, on Linux; `sh scripts/dev.sh check` waits for T-251, by
  the decision of 2026-10-09. The command line from end to end, a node and a
  client through a relay on the loopback, needs the relays as a setting, and
  comes with T-165.
- CI, the run of `d01b9cd`: the gate's step `iroh`, on Linux, failed one
  test, `a_key_in_the_cache_is_read_from_the_first_directory_that_has_it`.
  Under a cache directory that is a file, Linux reports "Not a directory"
  where Windows reports the path as not found, and `read_own` refused with
  it. A path whose part is not a directory holds no file: `read_own` now
  answers none for it, as for a path not found, and the search goes on to
  the next directory.
# T-164: Race the iroh road and the reverse road

**Source:** `docs/design.md:45-53` (when two roads are possible, podssh races
them) and `docs/design.md:588-592` (to add: a race between roads); ROADMAP M6
(raced with the reverse road); GitHub #18 (Nemo-010, 2026-10-08: quic-ssh's
QUIC with a fallback over TCP); GitHub #21 (parsync: an optional fast path
with a fallback, `AlpinDale/parsync:src/rdma.rs`).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh cannot know before it tries whether iroh can run on a host: UDP may be
refused, the proxy may refuse the iroh relay, `/ping` may fail. A client that
waits for iroh to fail before it tries the reverse road adds the whole time
limit of iroh to each connection.

## Premise

Read: for a podssh node, the iroh road is first and the reverse road with the
resumable layer is second, raced (`docs/design.md:48-53`). The first real
sandbox can block what iroh needs, so the fallback is necessary
(`docs/design.md:1144-1150`). The user must select iroh (`docs/decisions.md`,
2026-10-08). Each road has one attempt for each host, with a time limit
(`docs/design.md:58-65`). The relay opener tries one host at a time
(`crates/podssh-relay/src/open.rs:200-277`), and no code races two roads.

## Approach

1. Race only when the user selected the iroh road and the node also has a
   reverse pair. Else use the one road, as now. A node serves both roads at
   once, with one keeper of sessions for both, so that a session resumes on
   either road: `podssh node NAME TARGET --iroh` serves the iroh road alone
   since T-163.
2. Start the iroh road first. Start the reverse road after a head start of
   250 ms, or at once when the iroh road fails before that.
3. The winner is the first link whose layer handshake (T-151) completes.
   Close the other link at once: a WebSocket Close 1000, or a QUIC close.
4. Invariant: the far end connects to its target only after a layer
   handshake, never at `open {id}`. A link that loses the race then costs no
   connection to sshd.
5. Each road keeps its own time limit and failover. When both roads fail,
   print the reason of each, with the relay's close reason.
6. With `-v`, print the road that won and its time.
7. Each resume of T-153 runs the same race.
8. Docs: the rule of the race in `docs/design.md` section 2, and the notes of
   `ssh` in the manual (`crates/podssh-cli/src/man/notes_ssh.rs:4-318`).

## Decision

Recommendation: a head start of 250 ms for the iroh road, as Happy Eyeballs
(RFC 8305) gives one to IPv6. It keeps the order of the design, and it adds
250 ms at most when iroh cannot run. The alternative, both roads at the same
moment, lost: each connection would also open a relay session at the node,
which the node must then close. Look at the head start again when T-157 has
figures.

2026-10-10, before the work:

- The form: `podssh ssh node://[user@]NAME --iroh-ticket TICKET` races the
  iroh road to TICKET and the reverse road of the pair NAME; the host key is
  kept under `node://NAME`, as with the pair alone. Lost: `iroh:TICKET` with
  an option for the pair, whose name for the known hosts would change with
  the road.
- The winner is the first link whose far end greets (its first byte); the
  layer's handshake then goes on that link alone. Lost: the first whole
  handshake, item 3 as written: the far end dials TARGET when a handshake
  completes, so two handshakes in flight could open two sessions and two
  connections to sshd. Stopping at the greeting keeps item 4 by its
  construction: the losing link never sends `OPEN`.
- The race itself is in `podssh-relay` (`session::race`), with no road in
  it, and is tested with stand-in roads; the command line gives it the two
  roads.
- `podssh node NAME TARGET --iroh` serves both roads when the pair NAME is
  stored and good, or `--pair-file` gives one, and else the iroh road alone;
  one keeper for both, so a session resumes on either road. When the pair's
  road ends (an expired or a stopped pair), the node says so and serves the
  iroh road on; Ctrl-C stops both.
- On the loopback, T-157 measured the iroh road through a relay at 25 to
  35 MiB/s; the head start stays 250 ms.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --features iroh --test road_race
```

With UDP and the iroh relay blocked, the reverse road wins within 250 ms plus
its own time. With both roads open, the iroh road wins, and the log of the
node shows no target connection for the losing link. With an iroh road that
fails at once, the reverse road starts with no head start. A planted race that
waits for the time limit of iroh fails the first check.

## Done

2026-10-10.

- `podssh_relay::session::race`: two roads, the first with a head start of
  250 ms (`HEAD_START`), the second at once when the first fails before it;
  the winner is the first link whose far end speaks, and the loser is
  dropped where it stands. `session::client`: the far end's first bytes
  (`greeted`, `Greeted`) apart from the handshake (`Greeted::start`), and
  `Rewound`, a link that gives them back, for a resume that reads them
  itself.
- `Layered::with_keeper` and `podssh_iroh::far::serve_kept`: one keeper for
  both roads. `podssh node NAME TARGET --iroh` serves the pair's road too
  when the pair is stored and good, or `--pair-file` gives one; when that
  road ends, the node says why and serves the iroh road on.
- `podssh ssh node://NAME --iroh-ticket TICKET` (`ssh/iroh/race.rs`): the
  race at the start and at each resume; the iroh road's endpoint is made in
  its own attempt, so the pair's road waits for none of it; `-v` says which
  road answered first and in how long; when both fail, each reason, and a
  refused key, are said. `--iroh-ticket` with another destination is a usage
  error; in a build without the feature, it exits 70 and names it. The large
  futures of `ssh` and `node --iroh` are on the heap: the first build of the
  race overflowed the main thread's stack of 1 MiB on Windows.
- Prove: the Approach's `--test road_race` is split in two. The rules,
  `cargo test -p podssh-relay --test session_race`, 7 passed, on a paused
  clock with stand-in roads: with the first road unable to run, the second
  wins in 300 ms, the head start and its own 50 ms; the planted race that
  waits for the first road's limit of 10 s fails that check; with both
  roads open, the first wins and the second never starts; a link that
  loses after its far end connected sends it not one byte (no `OPEN`); a
  first road that fails at 10 ms lets the second win at 40 ms; a silent far
  end loses; both failing give each reason. Live, `cargo test -p podssh-cli
  --features iroh-test --test road_race -- --ignored`, once, 10.8 s: a pair
  on the live relay, iroh's relay server on the loopback (its certificate
  beside the binary for the run), and the node on both roads: the iroh road
  won and the test's SSH server saw one connection, none for the pair's
  link that lost; with the iroh road at a relay where nothing listens, the
  pair's road won. The command line: `tests/iroh_cli.rs`. `cargo test
  --no-fail-fast`: 1014 passed, 0 failed, 24 ignored; with `iroh-test`: 368 passed, 0 failed, 12 ignored. clippy in both
  builds, and podssh-relay with all its features: no warning.
- Waits: the same race in a sandbox, where the iroh road may be blocked,
  with T-251. `podssh operator` takes the pair's road alone.

# T-165: Configurable iroh relays, the operator's relay first

**Source:** ROADMAP M6 (the iroh relays are configurable); `docs/decisions.md`
(2026-10-08: n0's public relays until the operator runs an iroh relay, then
that relay first); GitHub #18 (Nemo-010, 2026-10-08: iroh-ssh's own relays,
`rustonbsd/iroh-ssh:CUSTOM_RELAY.md`).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The iroh road needs relays that the user can change, and a default. The
decided default changes when the operator runs an iroh relay on the
operator's Cloudflare account.

## Premise

Read: the decision of the operator (`docs/decisions.md`, 2026-10-08). The
forward road has one default relay name in library code
(`crates/podssh-relay/src/relay.rs:12-13`) and a seed pool
(`crates/podssh-relay/src/pool.rs:20-29`); the same shape fits the iroh
relays. n0's free relays are for development, with a rate limit that is not
published (`docs/design.md:1124-1126`). At least three projects run the iroh
relay protocol on Workers and Durable Objects (read, not verified:
`docs/design.md:1130-1132`). The URLs of n0's relays for iroh 1.x must be read
in iroh's source at the pinned version.

## Approach

1. One table in the new crate: the default relay URLs, in order. Today, n0's.
   When the operator's relay exists, it goes first and n0's follow: a change
   of one line, with its measurement (T-157).
2. `--iroh-relay URL[,URL...]` and `PODSSH_IROH_RELAY` replace the table, as
   `--relay-host` and `PODSSH_RELAY` replace the relay list
   (`crates/podssh-relay/src/relay.rs:104-125`). The flag wins.
3. Accept `https://` URLs only, with a host that passes `check_host`
   (`crates/podssh-ws/src/names.rs:8-24`), and with no user information
   and no query.
4. The order is a failover: the first relay that answers `/ping` through the
   proxy, within a time limit, is the home relay.
5. The relay URL of a ticket (T-163) is tried for that peer, also when it is
   not in the list.
6. `doctor`, with the feature, reports the `/ping` of each relay and the home
   relay.
7. Add the variable to `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:45-260`),
   the flag to the flag table, and the default to the relay section of the
   manual (`crates/podssh-cli/src/man/facts.rs:301-456`). The tests compare
   `VARIABLES` with the source in both directions
   (`crates/podssh-cli/src/man/facts.rs:43-44`), so a variable that only the
   feature reads is in the manual only with the feature.
8. A test of the command line from end to end, which T-163 left for this
   entry: `podssh node NAME TARGET --iroh` and `podssh ssh iroh:TICKET`,
   with the relay of the new flag on the loopback, an allowlist, and a
   client that is refused, then let in.

## Decision

2026-10-10, read in iroh 1.3.0 before the work:

- iroh picks its home relay by latency among the relays of its map, with a
  hysteresis (`net_report.rs`, `add_report_history_and_set_preferred_relay`),
  and no order. So podssh asks `/ping` of each relay in the list's order,
  through the proxy and with podssh's trust store, 5 s at most each, and
  gives iroh the first that answers as its only relay: that relay is the home
  relay, and a node's ticket stays the same for the run. Lost: the whole list
  to iroh, which could take n0's relay over the operator's, against the
  decision of 2026-10-08, and could change a node's ticket whenever the
  latencies did. When no relay answers, iroh gets the whole list, and its
  own probes are the fallback.
- iroh's relay actor dials any relay URL that a peer needs, and reads its
  map only for an auth token (`socket/transports/relay/actor.rs`,
  `start_active_relay`). So the relay of a ticket is reached when it is in
  no list. The client's list starts with the ticket's relays: its home relay
  is the node's when that one answers.
- The variable `PODSSH_IROH_RELAY` is read in `podssh-iroh`, so the manual's
  check of variables against the source reads that crate, and lists the
  variable, only in a build with the feature. The flag `--iroh-relay` is in
  the tables of `node` and `ssh` in each build, as the other flags of the
  road are.
- A relay URL is `https://`, a host that `check_host` takes, an optional
  port, and no user information, path, query or fragment: iroh puts its own
  path after the origin.
- The Prove's test of the manual finds the variable, and the relays'
  paragraph of THE RELAY, in a build with the feature only; the flag is in
  each build's table, by the decision above, and its help names the
  feature.
- The test of the command line from end to end needs a relay server, which
  iroh has only behind its `test-utils`: `podssh-iroh` gets the feature
  `test-relay` (iroh's relay server on the loopback, with its certificate in
  a PEM file) and `podssh-cli` the feature `iroh-test`, which no release
  builds. Lost: iroh's relay server as a dev-dependency of `podssh-cli`,
  which each default test build would then compile.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --test relays
cargo test -p podssh-cli --features iroh --test man_page
```

The relays test takes the flag before the variable before the table, refuses
`http://` and user information, and fails over when the first relay does not
answer `/ping`; a planted list that ignores the flag fails it. The test of the
manual finds the variable and the flag in a build with the feature, and in no
other build.

## Done

2026-10-10.

- `podssh-iroh::relays`: the table (n0's four relays, read in iroh 1.3.0),
  the parse of a relay and of a list, `select` (the flag, the variable, the
  table) and `from_environment`, `ping` (moved from `podssh doctor`), and
  `home`: the first relay that answers `/ping`, 5 s at most each, alone, or
  them all when none does. `endpoint`: an empty list is the table.
  `test_relay` (feature `test-relay`): iroh's relay server on the loopback
  with its certificate in a PEM file.
- podssh-cli: `--iroh-relay` on `node` and `ssh` (a usage error without
  `--iroh` or an iroh destination; a bad value is 64, a bad variable 78).
  `podssh node --iroh` takes its home relay so, and says each relay that did
  not answer; `podssh ssh iroh:TICKET` asks the ticket's relays first, then
  the list. `podssh doctor`, with the feature: `/ping` of each relay of the
  list, by host and port, then the home relay; each relay that does not
  answer is a FAIL. The manual: `PODSSH_IROH_RELAY` in ENVIRONMENT and the
  relays in THE RELAY, with the feature only (`variables()`, and the
  variable test reads `podssh-iroh` with the feature); the notes of `ssh`
  and `node`. The gate's step `iroh`, and its clippy line, run with
  `podssh-cli/iroh-test`.
- Prove, native, Windows: `cargo test -p podssh-iroh --test relays`: 6
  passed: the flag before the variable before the table, and a planted
  selection that ignores the flag fails that check; `http://`, user
  information, a path, a query, a fragment and a bad host are refused; the
  table is iroh's own list; a silent relay first and iroh's relay server
  second: the second is the home relay, with its certificate checked by
  podssh's trust store, and an endpoint given it has it as its home relay;
  with no relay that answers, iroh gets them all, each with its reason.
  `cargo test -p podssh-cli --features iroh --test man_page`, and without
  the feature: 9 passed each. `cargo test -p podssh-cli --features iroh-test
  --test iroh_road` (item 8): `podssh node --iroh` and `podssh ssh
  iroh:TICKET` through iroh's relay server on the loopback, with
  `--iroh-relay` and `--ca-file`: the client is refused and prints its key,
  the node names the refused key; with the key added to the allowlist, the
  same command runs on the node's SSH server (a russh server in the test)
  and prints its line, exit 0, and the host key is kept under `iroh:` and
  the node's key; 6.7 s. A planted node that admits each key failed it (run
  once, then restored). The ignored live test of `doctor` (its other checks
  reach the relay of the forward road): run once, passed. `cargo test
  --no-fail-fast`: 1003 passed, 0 failed, 22 ignored; `cargo test -p podssh-iroh -p podssh-cli
  --features podssh-cli/iroh-test`: 363 passed, 0 failed, 9 ignored. clippy in both builds and
  with `iroh-test`: no warning. `cargo deny`, also with `--all-features`: ok.
- Waits: `sh scripts/dev.sh check` for T-251. n0's relays were not reached
  in this entry; a real sandbox, and the relay's throughput, are T-157's.

# T-166: A roost: a podssh next to a standard sshd

**Source:** `docs/design.md:52` (a standard sshd behind a podssh `roost`) and
`docs/design.md:607-610`; the `roost` of pigeons (`docs/design.md:1134-1137`);
GitHub #18 (Nemo-010, 2026-10-08: iroh-ssh reaches sshd by node id, and
refuses early when no sshd answers).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A standard sshd gets the resumable layer and the iroh road only when a podssh
next to it owns the TCP connection to it. A user with a normal server has no
way to run that podssh.

## Premise

Read: the far end of the layer can be a podssh next to a standard sshd, which
then owns the TCP connection to sshd (`docs/design.md:607-610`). `podssh node`
does not exist yet (T-083). Measured on `3ee70dc`: `podssh node x` exits 70
(not implemented), and `podssh node x y` exits 64, because the parser takes
a NAME only (`crates/podssh-cli/src/positionals.rs` line 42 at `af0a163`). Read in the report,
not verified here: iroh-ssh checks that a local sshd answers before it accepts
(`rustonbsd/iroh-ssh:src/ssh.rs`).

## Approach

1. A roost is `podssh node NAME 127.0.0.1:22` (T-083) with the resumable layer
   (T-151) and, with the feature, the iroh road (T-162). T-083 decides whether
   `roost` is a word of its own.
2. A preflight: before it registers, connect to the target and read the first
   line. Require `SSH-2.0-` within 10 s; else exit, and name the target and
   what came back. Check again before each new session.
3. Each client session gets its own TCP connection to sshd, made after the
   layer handshake (the invariant of T-164).
4. A roost runs on a normal server, so it may use UDP for the iroh road after
   the probe. It still listens on nothing.
5. Docs: the row of the roost in `docs/design.md` section 2, the section of
   `node` in the manual, and an example in `README.md`.

## Decision

Recommendation: the client records the host key of sshd under the name that
the user gives to `podssh ssh` (the roost's name), as OpenSSH does for a host
with a `ProxyCommand`. `podssh ssh` names a host this way today
(`crates/podssh-ssh/src/run.rs:342-352`). The alternative, the address of sshd
behind the roost (`127.0.0.1`), lost: each roost would share one name, and one
key would replace another.

2026-10-12, before the work (T-083 did not decide the word, so this entry
does):

- A roost is the flag `--sshd` of `podssh node`, not a command of its own: a
  roost is a node, with the same pair, keys, roads, routes and exit codes,
  and one table of flags. Lost: `podssh roost NAME`, pigeons' word, which
  would copy each flag of `node` and its notes.
- With `--sshd` and no TARGET, TARGET is `127.0.0.1:22`. Each TARGET is
  checked, the routes' too (`ROUTE=TARGET`).
- The check peeks at the stream (`TcpStream::peek`) and takes no byte, so
  each session's SSH client reads sshd's line itself. Lost: a read of the
  line, given back to the session by a stream with a prefix, which would
  change the type of each handler's stream.
- The first line must start `SSH-2.0-`, or `SSH-1.99-`, which RFC 4253
  (section 5.1) lets an SSH 2 client use. Lines before the version line,
  which RFC 4253 (section 4.2) lets a server send, are refused: OpenSSH and
  Dropbear send none, and a first line of another protocol then names the
  wrong port at once. A start that no version line has decides at once,
  with no wait for the line end.
- Exit codes: another service at TARGET is a TARGET set up wrong, 78; no
  connection, no line within 10 s, or a close before the line is one out of
  reach, 69, as a TARGET that cannot be dialled is now.
- The check of each session runs where the session dials TARGET: in
  `TcpHandler` and the routes of podssh-relay, and in the iroh road's dial
  (`reverse::tcp::dial_target`). A session whose TARGET fails it ends with
  the reason, as one whose TARGET cannot be dialled.
- `--sshd` goes with `--plain` and `--iroh`: a plain roost carries sshd's
  bytes with no layer, and the check is the same.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test roost
sh scripts/dev.sh check
```

The roost test (crates/podssh-cli/tests/roost.rs) points a roost at a port
with nothing on it, and at a server that answers `HTTP/1.1`: the roost exits
before it registers, and names the target. A planted roost with no preflight
registers, and the test fails. The interop harness of the gate runs a roost in
front of OpenSSH and Dropbear, and the session survives a cut link.

## Correction

2026-10-09 (T-083): `podssh node NAME TARGET` exists now. It serves a TCP TARGET for the pair stored
under the label NAME, and dials TARGET once before it registers, as iroh-ssh checks its sshd.

2026-10-12: items 1, 3 and 4 of the Approach were done before this entry.
A node runs the resumable layer since T-153, and dials TARGET only after
the layer's handshake (`crates/podssh-relay/src/reverse/layered.rs`), on
both roads since T-164; `podssh node --iroh` binds UDP only after the probe
(T-162). T-083 did not decide whether `roost` is a word of its own; the
Decision of 2026-10-12 does. What this entry adds is the check of sshd
(item 2), the default TARGET and the documents (item 5).

## Done

2026-10-12, a draft for the main session to build and test.

- podssh-relay, `crates/podssh-relay/src/reverse/sshd.rs` (new, feature
  `pair`): `check` peeks at a connection's first line within a limit
  (`BANNER_LIMIT`, 10 s) and gives the version line, or `NotSshd`: another
  first line (`Other`, with the line, made safe and cut to 80 characters),
  no whole line in time (`Silent`, with what came), a close, or a failure;
  `judge` is the verdict on the bytes so far. `reverse::tcp::dial_target`
  dials and, for a roost, checks; `TcpHandler` and `Routes` have the field
  `sshd`, and dial with it.
- podssh-cli: `podssh node NAME [TARGET] --sshd` (`node.rs`, `node_iroh.rs`,
  `flags/node.rs`, `tree.rs`): TARGET is `127.0.0.1:22` when none is given;
  before the node registers, each TARGET is dialled and checked, and a
  failure exits with TARGET and what came back (78, or 69); the first line
  says `serving the sshd TARGET (VERSION LINE)`; each session's dial, on the
  pair's road, the routes and the iroh road, runs the check.
- The manual: the flag's row, the help of TARGET, a note of `node` on the
  roost, the rows of 69 and 78, and the example of a node is now
  `podssh node lab --sshd`. `README.md` (an example), `docs/cli.md`,
  `docs/design.md` (the row of section 2, and a paragraph), `docs/reverse.md`
  and `docs/STATUS.md`.
- Tests, written and not run here (this draft ran no build):
  `crates/podssh-relay/src/reverse/sshd.rs` (unit tests of `judge`: version
  lines of SSH 2 pass, another first line is named, part of a version line
  waits); `crates/podssh-relay/tests/sshd_check.rs`
  (`the_check_takes_no_byte_of_the_stream`,
  `a_service_that_is_not_sshd_is_refused_with_its_line`,
  `a_silent_target_is_refused_after_the_limit_with_what_came`,
  `a_target_that_closes_at_once_is_refused`,
  `a_roost_s_dial_refuses_what_a_node_s_dial_takes`);
  `crates/podssh-cli/tests/roost.rs`
  (`a_roost_with_nothing_at_target_exits_before_it_registers`,
  `a_roost_in_front_of_another_service_exits_with_its_first_line`,
  `a_roost_whose_target_says_nothing_exits_after_10_s`, the control
  `a_roost_in_front_of_an_ssh_server_goes_on_to_the_relay`,
  `a_roost_with_no_target_is_in_front_of_port_22`, and through the stand-in
  relay `a_roost_carries_ssh_to_its_sshd_and_keeps_the_key_under_its_name`
  and `a_target_that_stops_answering_as_sshd_refuses_the_next_session`).
  The relay of the offline tests is a port that counts its connections,
  so a roost that registers is seen. Results: 8 passed here (Windows 11,
  with Python and openssl for the stand-in relay) and 8 passed in the
  build image; `sshd_check` 5 and the unit tests of `sshd` 3.
- The gate: `scripts/interop-roost.sh` (new), sourced by
  `scripts/interop-faults.sh`, with six ids in
  `scripts/interop-baseline.txt`: `roost.version.openssh` and `.dropbear`
  (the first line names each server's version line), `roost.cut.openssh`
  and `.dropbear` (`podssh ssh node://` through a roost, its link cut by a
  stand-in proxy during the remote command, resumes and ends 0), and
  `roost.preflight.closed` and `.other`. They wait for CI's gate and T-251.
- Waits for T-251: `sh scripts/dev.sh check` with the new harness, and the
  planted defect of the Prove (a roost with no preflight: the offline tests
  of `roost.rs` must then fail, as its registration reaches the counting
  port). No live run: a roost of the live relay in front of a real sshd is
  the same code as the stand-in's run.

# T-167: Start from a standard sshd, then move the session to a better road

**Source:** GitHub #19 (Nemo-010, 2026-10-08: rose's SSH bootstrap mode,
`nikhiljha/rose:doc/spec.md`, GPL, specification only; ssh-obi's transport
over plain ssh).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A user reaches a server over the forward road. A better road (the layer, or
iroh) needs a podssh on the server and a ticket or a pair. To set these up by
hand takes several steps on two hosts.

## Premise

Read: to a standard sshd, the forward road is the only road, and it has no
resumption (`docs/design.md:51`, `docs/design.md:611-628`). A podssh on the
server can be a roost (T-166). podssh starts another program only when the
user names it or a probe finds it (`AGENTS.md`, section 5, rule 3); this
entry keeps that rule for the server too. Inferred: an SSH connection cannot
change its road, so a second login carries the session.

## Approach

1. `podssh ssh --upgrade DEST` (this entry decides the spelling): log in over
   the forward road, as now.
2. Probe the server: run `podssh --version` by exec, with a limit of 10 s.
   When no podssh answers, stay on the forward road, and say so once.
3. Run a temporary node on the server by exec. It makes a pair or an iroh
   endpoint, and writes one line with its ticket or connect token to its
   stdout, in the encrypted channel. The token never crosses the relay in
   clear, and never goes on argv.
4. The client opens the layer to that node (the race of T-164), logs in again
   over it, and closes the first connection. The host key is the same, so
   `known_hosts` needs no change.
5. The temporary node ends with its last session, or 10 minutes after its
   start with no session.
6. A podssh on the server that does not offer the layer (its `GREETING` does
   not name it) leaves the session on the forward road, with one note.

## Decision

Recommendation: never copy a podssh binary to the server; when none is there,
say how to install one. To copy and start a program on the user's server is
an action that the user must ask for. The alternative, an automatic upload
(syq installs a helper on SSH servers: read in GitHub #19), lost for that
reason.

2026-10-12, before the work:

- The spelling: `podssh ssh --upgrade DEST`, a flag of `ssh`, as
  `--persist` is; the far end is `podssh node --temporary KEY`, a flag of
  `node`, as the roost of T-166 is. KEY is the fingerprint of this client's
  key (`client.key`, or `--client-key`): a public key, so it may go on
  argv; the node lets in that key alone. Lost: a verb of its own on either
  side.
- The node makes a pair, not an iroh endpoint: the pair's road is in each
  build, and the iroh road only in builds with the feature `iroh`, which no
  release has. So the move takes the pair's road alone, and the race of
  T-164 (item 4) is not run: a node and a client that both have the
  feature could race the two roads, which this draft leaves open.
- The line is `podssh-upgrade/1 ` and JSON: the relay, the pair's name, the
  connect token, the expiry, the node's key and whether the node left its
  SSH session. The client takes the first line with that mark, as a
  login's own lines may come first; it checks each field as an operator's
  file is checked, and the end-to-end channel must then find the node's key
  of the line.
- The node goes online before it writes the line, so the client's leg never
  meets a node that is not there yet. On Unix it then leaves its SSH
  session: SIGHUP ignored, its standard streams `/dev/null`, and `setsid`
  where it may. On Windows it cannot, and says so in the line: the client
  then keeps the first connection open while the session runs.
- The node's TARGET is the sshd of `SSH_CONNECTION`, on the loopback first
  (no proxy is in the way there), then at the server's address; each is
  checked as T-166 checks a roost's.
- The first connection stays open until the second login is done (the
  phase `Ready` of the login, which podssh-ssh keeps). Until then each
  failure (no podssh, no line within 60 s, no layer in the greeting, a
  failed leg, handshake or login) is one note, and the session runs on the
  first connection, which logged in already: no second prompt. Lost: the
  close of the first connection at once (item 4 as written), after which a
  failed second login would have no session to fall back on.
- With `node://`, `iroh:`, `cf://`, `--persist`, `-R` (two connections
  would each ask for the forward) and `-O`, `--upgrade` is a usage error
  (64); `ControlPath` has no effect with it, with a note under `-v`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test upgrade
sh scripts/dev.sh check
```

The upgrade test shows that the token travels only in the SSH channel and is
on no argv. The interop harness logs in to OpenSSH with a podssh on the
server's PATH, upgrades, and survives a fault of T-156. With no podssh there,
the session stays on the forward road with one note; a planted client that
starts a node with no probe fails this check.

## Done

2026-10-12, a draft for the main session to build and test.

- podssh-ssh: `upgrade` (new): `login`, the hops logged in with their
  connections kept, and `request`, the run's request on them, each failing
  in a run's own words; `begin`, `logged_in` and `reached`, the phase of a
  second login. `run::run_handles` is the request half of a run, split out
  of `run_inner`. `exec::first_line` runs a command and gives the rest of
  its first stdout line with a mark, and the command's channel, left open.
- podssh-cli: `ssh --upgrade` (`ssh/upgrade.rs`, new; the flag, `args.rs`,
  `resolve.rs`, `mod.rs`): the checks and the run of the Decision.
  `node --temporary KEY` (`node_temp.rs`, new; `node.rs`, `tree.rs`,
  `flags/node.rs`). The line (`upgrade_line.rs`, new). `layered::Begin`: the
  layer's client may start before `carry`, so that `--upgrade` reads the
  node's greeting first. `SSH_CONNECTION` is in ENVIRONMENT.
- The manual: the flags' rows, the notes of `ssh` and `node`, an example.
  `README.md`, `SECURITY.md`, `docs/cli.md`, `docs/design.md` (layer 3 of
  section 5) and `docs/STATUS.md`.
- Tests, written and not run here (this draft ran no build): unit tests in
  `crates/podssh-cli/src/upgrade_line.rs` (the line reads back; a line that
  is no offer is refused by name) and `crates/podssh-cli/src/node_temp.rs`
  (the sshd of the session, on the loopback first; with no session,
  127.0.0.1:22; a TARGET wins; a route is refused).
  `crates/podssh-cli/tests/upgrade.rs`:
  `upgrade_refuses_what_two_connections_cannot_carry`,
  `a_client_key_goes_with_upgrade_alone`,
  `with_no_podssh_on_the_server_the_session_stays_with_one_note` (the
  tests' server answers `podssh --version` with no podssh: one note, the
  command runs, one login), and, through the stand-in relay,
  `the_session_moves_to_the_temporary_node_and_no_argv_holds_a_token`
  (`crates/podssh-cli/tests/ssh_harness/podssh.rs`, new: a server whose
  `podssh ...` commands run the binary under test, with `SSH_CONNECTION`,
  each argv kept; the move, three connections to sshd, and no argv and no
  output with a word of a token's shape). Results: 5 passed here (Windows
  11, with Python and openssl), and 5 passed in the build image; the unit
  tests of `upgrade_line` and `node_temp`: 4 passed. The test of the move
  first overflowed the 1 MiB stack of Windows's main thread in the debug
  build: podssh now runs each command on a thread of 16 MiB
  (`crates/podssh-cli/src/main.rs`).
- The gate: `scripts/interop-upgrade.sh` (new), sourced by
  `scripts/interop-faults.sh`, with three ids in
  `scripts/interop-baseline.txt`: `upgrade.none` (OpenSSH with no podssh on
  its PATH: one note, the command ran), `upgrade.cut.openssh` and
  `upgrade.cut.dropbear` (a wrapper in `/usr/bin` runs the binary under
  test on the server; the session moves to the node, and a stand-in proxy
  cuts the client's link during the remote command, which resumes and ends
  0). They wait for CI's gate and T-251.
- Waits for T-251: `sh scripts/dev.sh check` with the new harness, and the
  planted client that starts a node with no probe (`upgrade.none` and
  `with_no_podssh_on_the_server_the_session_stays_with_one_note` must then
  fail on their note). No live run: the live relay's pairs are the same
  calls as the stand-in's. A Windows server, where the node cannot leave its
  session, is not measured.

# T-168: UDP over the relay

**Source:** GitHub #18 and GitHub #26 (Nemo-010, 2026-10-08: sandhole's UDP
over TCP, `EpicEric/sandhole:book/src/udp_over_tcp.md`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Traffic in the shape of DNS or QUIC needs UDP. The relay carries TCP only,
and the measured sandbox refuses UDP. podssh cannot carry a datagram today.

## Premise

Read: "TCP only; no UDP"
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:222`). The
forward road dials TCP only. A datagram to a target therefore needs a podssh
at the far end that may send UDP: a node (T-083) on a host that allows it.
The measured sandbox gives EPERM for UDP (`docs/target-environment.md:23`), so
a node in such a cage cannot send it. The near end must not bind (`AGENTS.md`,
section 5, rule 2).

## Approach

1. The framing in the stream: a 16-bit length, then the datagram (65,507 bytes
   at most), with one stream for each flow. Count and drop a datagram that is
   too long. Put the codec in `podssh-relay`, with no C.
2. The far end: a node opens a UDP socket to `HOST:PORT` for each flow, after
   a probe that UDP works there. It closes a flow after 60 s with no datagram.
3. The near end, with no listener: a child started by `exec:` gets an AF_UNIX
   `SOCK_DGRAM` socketpair, which needs no bind; or stdin and stdout carry the
   same framing. A local UDP listener comes only with T-177, after a probe.
4. The address: `udp:HOST:PORT` at the far end of `podssh pipe` (T-175).
5. State the limits in `docs/design.md` section 6: over TCP, datagrams wait
   for each other, and a lost segment delays each later datagram.

## Decision

2026-10-12, in the work:

1. The address. The relay carries TCP only, and the near end sends no UDP,
   so the target of UDP is named where the datagrams leave:
   `podssh node NAME udp:HOST:PORT`, in the grammar of the addresses of
   T-175. The pipe names the road and the framing: `udp:node:NAME`, the
   session to that node. A plain `node:NAME` carries the same bytes, the
   framing in them, on stdin and stdout; `udp:` adds the datagram
   socketpair of a program beside it, the check of the framing (65) and the
   wait for answers (item 5). `udp:HOST:PORT` in the pipe is a usage error
   (64) that names the node's form. Lost: `udp:HOST:PORT` as the pipe's own
   address, with the node named by a flag: an operator would then choose
   where a node sends UDP, and a node chooses its targets, as for TCP
   (T-089).
2. One flow is one session. Its socket is made when the session opens: under
   the layer after the layer's handshake, under the channel once the
   operator's key is let in, as a TCP target is dialled. `node.rs` runs
   either handler under the layer and the channel by one function. A UDP
   TARGET is the node's only one: no second TARGET, no route (the routes'
   dial is TCP, `crates/podssh-relay/src/reverse/routes.rs`), and not on the
   iroh road, whose far end dials TCP; each is refused by name (64). Lost:
   a UDP route, which needs a kind in the table of routes; no request asks
   for it.
3. The probe resolves TARGET as each dial does (pins, the system, DNS over
   HTTPS), makes a socket of port 0, connects it and closes it, with no
   datagram sent. A host that refuses UDP (EPERM or EACCES) exits 78, the
   code of a probe that the mode needs (`Fault::Capability`); a name with
   no address 69. Lost: a datagram to the target as the probe, which a
   service would take as a query.
4. The framing. A length over 65,507 is refused where it is read: the
   stream is not the framing. At the node it ends the flow with a line; at
   the near end it ends the pipe with 65 (`EX_DATAERR`) and the reason. A
   longer datagram from a socket (UDP over IPv6, or the program's AF_UNIX
   socket) is counted and dropped, and the count is said when the flow
   ends. A refusal of the target's host (ICMP port unreachable) is counted,
   and the flow goes on, as UDP does.
5. The end. The layer has no half-close: a session ends at the end of its
   input. So after this side's input ended, the near end keeps the session
   until no bytes came from the node for 5 s, the time a DNS client waits
   for an answer, then ends it. A datagram socket gets no end when its peer
   closes (Linux shuts the peer down for stream and seqpacket sockets only:
   read in `af_unix.c`, `unix_release_sock`, not measured). So the
   program's end is its exit: the task that holds its socket waits for it,
   and its exit code is the pipe's, as `exec:`'s is. When the other side
   ends first, the program gets 10 s, then SIGTERM, then 10 s and SIGKILL.
   The node's session opens before the program starts, so that a program
   does not start, and wait, when the session cannot open. Lost:
   `SOCK_SEQPACKET`, which has an end of input both ways, against step 3
   and macOS, which has no AF_UNIX seqpacket socket.
6. Where the datagram socketpair is refused, and on Windows, whose AF_UNIX
   has no datagram socket, the program gets the stream of `exec:`, the
   framing on its stdin and stdout; a line says so where it was refused.
7. No local UDP listener is made (step 3 makes the near end with none).
   With T-177 done, `udp-listen:` could come after a probe, each client's
   address a flow; that is a request for the operator, not made here.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test udp_framing
cargo test -p podssh-cli --test pipe_udp
```

The framing test decodes fixed byte vectors, refuses a length over 65,507,
and keeps each datagram whole across split reads; a planted decoder that
joins two datagrams fails it. The pipe test sends DNS queries from a child,
over the socketpair and a node, to a local UDP echo server, and checks each
reply.

## Done

2026-10-12. Written as a draft beside T-166, then merged over it: a UDP
TARGET and `--sshd` do not go together (64), and `--iroh` with a UDP
TARGET is refused before the road's build is looked at (64).

- podssh-relay: `crates/podssh-relay/src/udp/codec.rs` (the framing:
  `framed`, `encode`, `Decoder`, and `Frames`, a reader of datagrams that is
  safe to cancel in a `select!`), `crates/podssh-relay/src/udp/flow.rs`
  (`connect`, `probe` and `carry`: a socket of port 0 connected to the
  target, the idle limit of 60 s, the counts of a flow) and
  `crates/podssh-relay/src/reverse/udp.rs` (`UdpHandler`, a node's handler
  of a UDP target, under the layer and the channel as `TcpHandler` is).
- podssh-cli: `podssh node NAME udp:HOST:PORT`
  (`crates/podssh-cli/src/node_udp.rs`, and `crates/podssh-cli/src/node.rs`);
  `podssh pipe` with `udp:node:NAME`
  (`crates/podssh-cli/src/pipe/datagram.rs`: the bridge to the node's
  session, and the program on a datagram socketpair;
  `crates/podssh-cli/src/pipe/mod.rs` opens the node's session first).
- `scripts/check-repo.py`: the flow's socket joins the table of listeners,
  as a socket that the user names and a probe allows. `python
  scripts/check-repo.py`: ok, 2026-10-12.
- The manual (the notes of `pipe` and `node`, the rows of 65 and 78, two
  examples, the help of TARGET), `docs/cli.md`, `docs/design.md` (section
  6: the address, and the limits of UDP over TCP), `docs/architecture.md`
  (rule 3, and the row of `podssh-relay`), the map of `AGENTS.md`,
  `SECURITY.md`, `README.md` and `docs/STATUS.md`. `tests/pipe.rs` of
  podssh-cli takes `sctp:` for an unknown kind, and checks that
  `udp:HOST:PORT` names the node's form.
- `cargo test -p podssh-relay --test udp_framing`: 12 passed here. Its tests:
  fixed bytes and a DNS query decode to their datagrams; a datagram is
  framed as its length then its bytes; one over 65,507 is not framed; a
  length over 65,507 is refused as soon as its two bytes came; each
  datagram stays whole across reads cut in pieces of 1, 2, 3, 7 and 1000
  bytes, and through a reader that trickles; two datagrams in one read stay
  two; a stream that ends inside a datagram, or that is not the framing, is
  an error; a flow to a UDP server on the loopback carries five queries and
  their answers, and ends at the end of its stream; a flow ends after its
  idle limit; a flow whose stream is not the framing ends, says so, and
  sends nothing; the probe sends nothing.
- `cargo test -p podssh-cli --test pipe_udp`: 3 passed here (Windows 11,
  with Python and openssl), 4 passed (the program on the socketpair among them) in the build image. Its tests:
  `udp:HOST:PORT` in the pipe, a second TARGET, a UDP route, a TARGET with
  no port and `--iroh` are refused with 64; through the stand-in relay,
  three DNS queries on stdin, each after its length, come back answered on
  stdout, the pipe ends with 0 after its input, and a length of 65,535
  exits 65; on Unix, a Python program on the datagram socketpair sends
  three queries, checks each answer, and its status is the pipe's.
- `cargo test -p podssh-cli --lib -- node_udp address datagram`:
  12 passed here and 13 in the build image (the UDP TARGET's parse; the pipe's `udp:` addresses; on Unix,
  a program's datagrams through the socketpair, whole, and its status 3).
- Waits for T-251: the plant of a decoder that joins two datagrams, which
  must fail `two_datagrams_in_one_read_stay_two` and the tests of split
  reads; clippy and the tests of Unix in the build image; the gate; a node
  in the box (`scripts/test_in_box.sh`), whose seccomp refuses UDP, where
  the probe must exit 78; and a live run of a node in front of a DNS server
  through the live relay.

# T-169: A self-hosted relay that speaks the relay's contract

**Source:** GitHub #18 (Nemo-010, 2026-10-08: warren's self-hosted relay on
port 443, `willykeenan/warren:docs/relay.md`; GPU-Share's relay crate,
`arjun988/GPU-Share:crates/gpumesh-relay/src/main.rs`); GitHub #25 (rate
limits, quotas and connection caps, from sandhole and USBoverSSH).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** blocked

## Problem

podssh depends on one relay deployment, which the operator runs on Cloudflare
from another repository. A user cannot run a relay with the same contract on
their own server, and the gate tests faults against a stand-in in Python.

## Premise

Read: the relay is a Cloudflare Worker, and its own document is the contract
(`docs/relay.md:1-21`, `README.md:34-37`). The stand-in serves the forward
path, `/v1/mint` and `/health` only (`scripts/fake-relay.py:117-135`). The
pinned contract gives the forward path and the tokens
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:73-104`), the
reverse path and its close table
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:123-193`), and
the limits (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:220-241`).
The relay's integration suite drives its own typed client
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:107-112`). The
operator ruled on 2026-10-08 that the relay stays a separate project, and that
its contract is the boundary (`docs/decisions.md`).

## Approach

The work is in the relay project, not in this repository. What it needs, and
the part of podssh:

1. The relay project offers its relay as one program that a user runs on a
   server of their own, on port 443.
2. The forward path: `/connect/<host>/<port>`, the token header, `/v1/mint`,
   an empty frame each 25 s, the limits (180 s idle, 12 h, 64 MiB, frames of
   262144 bytes), the close codes of `docs/relay.md:244-265`, and `/health`
   with the service name that `doctor` checks
   (`crates/podssh-relay/src/health.rs:13-15`).
3. The reverse path: `/v1/pair`, `/v1/node/<name>`, `/v1/connect/<name>`,
   `/v1/stop/<name>`, the text control frames, the 32-character ids, `409` for
   a second node, and the reverse close table.
4. The targets: public addresses only, the ranges of `docs/relay.md:194`,
   checked after the name resolves. TLS with a certificate that the relay's
   owner gives. Rate limits and quotas for each address and each token.
5. The part of podssh: no change in the client, because the contract is the
   same; `--relay-host` names the relay. Test podssh against it: the live
   tests and `doctor`, pointed at it. `scripts/check-relay-spec.py` compares
   its document with the pinned copy.

## Prove

```sh
PODSSH_RELAY=relay.example.org cargo test -p podssh-cli --test proxy_live -- --ignored
PODSSH_RELAY=relay.example.org target/debug/podssh doctor
```

With a self-hosted relay at `relay.example.org`, the live test of podssh gets
GitHub's banner (the test reads `PODSSH_RELAY`:
`crates/podssh-cli/tests/proxy_live.rs:8-9`), and each relay line of `doctor`
is `ok`. The tests of the relay project cover its limits and both close
tables.

## Blocker

The relay's operator: a self-hosted relay is work of the relay project. The operator ruled on 2026-10-08 that the relay stays separate (`docs/decisions.md`).

# T-170: A Cloudflare quick tunnel made by podssh itself, with no `cloudflared`: the protocol and its ports

**Source:** GitHub #18 (Nemo-010, 2026-10-08: bunflared makes a quick tunnel
with no account through `cloudflared`,
`mirkobozzetto/bunflared:src/cloudflared.rs`); the operator's ruling of
2026-10-08: no road depends on a program of another project, and
"trycloudflare.com is scriptable" (`docs/decisions.md`).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

When no relay host can be reached, a host has no other road. A Cloudflare
quick tunnel gives a public HTTPS name with no account. podssh does not run
`cloudflared`, so it must speak the protocol of a quick tunnel itself. Nobody
knows yet what that protocol needs, or whether a cage can use it.

## Premise

Read in the report, not verified here: bunflared runs `cloudflared` for a
quick tunnel, and downloads it when it is missing. Not verified here (to read
in the source of `cloudflared`, GitHub `cloudflare/cloudflared`): a quick
tunnel starts with an HTTPS request to `api.trycloudflare.com`, which gives a
name under `trycloudflare.com` and the tunnel's credentials; the connector
then reaches Cloudflare's edge on port 7844, by QUIC on UDP or HTTP/2 over TLS
on TCP, and registers with Cap'n Proto RPC. Read: the measured proxy allows
`CONNECT` only to ports 443, 80 and 8443 (`docs/target-environment.md:21`),
and the sandbox refuses UDP (`docs/target-environment.md:23`). If the edge
needs port 7844, a cage cannot publish a tunnel. A client in a cage can still
reach the tunnel's name on port 443 with `podssh-ws`
(`crates/podssh-ws/src/client.rs:159-182`).

## Approach

1. Read the quick-tunnel code of `cloudflared`: the request to the
   trycloudflare API, its body and reply, its limits, and the terms of use.
2. Read the edge connection: the address (an SRV lookup or fixed names), the
   ports, the transports, the TLS name, the registration RPC, and the framing
   of each proxied request and WebSocket.
3. Measure on the operator's machine, with `cloudflared` as a reference only
   (never as a road): whether the edge accepts the tunnel on port 443, and
   whether the proxy of the box (`scripts/box/proxy.py`) lets it through.
4. Check what podssh can make with no C: HTTP/2 and Cap'n Proto in pure Rust
   on podssh's own TLS provider (`crates/podssh-ws/src/tls.rs`); QUIC only
   after a UDP probe; the DNS of the edge through DNS over HTTPS
   (`crates/podssh-ws/src/resolve.rs`).
5. The design: podssh is the connector and the origin in one process, so the
   edge's requests come in over the tunnel, and nothing listens (`AGENTS.md`,
   section 5, rule 2). A client reaches `https://NAME.trycloudflare.com` with
   `podssh-ws`, and runs the resumable layer (T-151) over the WebSocket. The
   protocol is not a published contract, so pin it as the relay's is pinned.
6. Write the answers in `docs/design.md` section 2, each marked measured or
   read. Then write the implementation entries, with ids from
   `cargo todo next`; or write, with the measurement, why a cage cannot
   publish a tunnel.

## Decision

2026-10-12, the calls made in the work:

- Items 1, 2 and 4 were read online: Cloudflare's documents, and cloudflared's source at `bf4f502`
  (release 2026.10.0), file by file. Nothing was downloaded, and no test reached Cloudflare.
- Item 3, the measurement, is an entry of its own, T-299, blocked on Q43: neither
  `api.trycloudflare.com` nor the tunnel edge is a test target of `AGENTS.md` (section 4), a run
  of cloudflared needs a download of it, and Cloudflare's terms bear on a connector of podssh's
  own (`docs/design.md`, section 2). The alternative, to measure now with the targets that a
  session may use, lost: none of them reaches the edge.
- Item 6: a cage cannot publish a quick tunnel by the documented road (port 7844 only), but a host
  whose egress reaches TCP port 7844 can, and a client in a cage reaches it on port 443. So the
  implementation entries are written: T-300 (the connector over HTTP/2) and T-301 (QUIC), parked
  behind T-299. HTTP/2 comes first: it needs TCP only, and `h2` is in the tree. The alternative,
  QUIC first, as cloudflared prefers, lost: it needs UDP, which no measured cage has. Another
  alternative, to build the connector now from the source alone, as T-264 was built, lost: the
  operator kept the tunnel as research (Q33, 2026-10-09), and the measurement decides whether the
  connector has a use.

## Prove

```sh
grep -n 'quick tunnel' docs/design.md
cargo todo check
```

The section of the design gives each answer with its evidence, and a claim
with no measurement says so. The checker accepts the implementation entries
that the section names.

## Correction

2026-10-12: two parts of the Premise are more precise in cloudflared's source at `bf4f502`. A
quick tunnel uses QUIC alone unless the user names `--protocol http2`: cloudflared sets `quic`
for it, and a protocol that the user names has no fallback (`docs/design.md:255-259`). And the
client in a cage is the road of T-264, `crates/podssh-ws/src/cloudflare.rs`, whose upgrade is
cloudflared's; the cited `crates/podssh-ws/src/client.rs:159-182` is the relay's upgrade, with
its token header.

## Done

2026-10-12. The answers are in `docs/design.md:129-452`, section 2, "A quick tunnel that podssh
makes itself", each READ with its source (a document of Cloudflare with its date, or a file and
lines of cloudflared at `bf4f502`), and each claim with no evidence marked not verified.
- The answer: a quick tunnel needs no account; its connector reaches the edge on port 7844 only,
  by QUIC or by HTTP/2 over TLS, and never through a proxy; the request for a tunnel goes direct
  to `https://api.trycloudflare.com/tunnel`. A cage, with `CONNECT` to 443, 80 and 8443 and no
  UDP, cannot publish one (INFERRED; port 7844 was not measured there). A host that reaches TCP
  port 7844 can, and a client in a cage reaches the name with the road of T-264.
- Read on the way, at bunflared's `e4d53e2`: it runs `cloudflared tunnel --no-autoupdate --url`
  (`mirkobozzetto/bunflared:src/tunnel.rs`) and downloads cloudflared from its GitHub releases
  with curl when it is missing (`mirkobozzetto/bunflared:src/cloudflared.rs`), as the report said.
- Not verified, each written so in the section: the edge on port 443; the edge's acceptance of a
  quick tunnel over HTTP/2; the root that signs the edge's certificate; the agreement on the wire
  of two implementations of Cap'n Proto RPC; the relay's reach to Cloudflare's addresses; a limit
  on how often a tunnel can be made.
- New entries: T-299 (the measurement, blocked on Q43), T-300 and T-301 (parked behind it); Q43
  is in `TODO/PROGRESS.md`.
- Prove: `grep -n 'quick tunnel' docs/design.md` names the section's heading and 8 more of its
  lines. `cargo todo check`: not run in this draft, which ran no cargo; it runs before the commit.

# T-264: Reach a service that `cloudflared` publishes, through `HTTPS_PROXY`

**Source:** the operator's ruling of 2026-10-09 (Q33, `docs/decisions.md`).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A user can publish an SSH or TCP service with Cloudflare's `cloudflared` on
a host of their own, behind a name of their own and, if they want, behind
Cloudflare Access. From a cage, podssh cannot reach it: the client is
`cloudflared access tcp`, and podssh runs no program of another project.

## Premise

Read: podssh's WebSocket client sends its credential in one fixed header,
`X-Relay-Token` (`crates/podssh-ws/src/client.rs:159-182`,
`crates/podssh-ws/src/handshake.rs:3`), through `HTTPS_PROXY`, with podssh's
own TLS provider; the measured proxy allows `CONNECT` to port 443
(`docs/target-environment.md:21`). Not verified here (to read in the source
of `cloudflared`, GitHub `cloudflare/cloudflared`, its `access` command):
`cloudflared access tcp --hostname HOST` carries a TCP stream over a
WebSocket to `wss://HOST`, the public name of a tunnel's ingress rule for an
`ssh://` or `tcp://` service; with Cloudflare Access, the upgrade carries a
token, the user's (`cf-access-token`) or a service token
(`CF-Access-Client-Id` and `CF-Access-Client-Secret`).

## Approach

1. Read the client side of `cloudflared access`: the URL and the path of
   the upgrade, its headers, the framing of the bytes, the close codes, and
   how a token of Access is got and sent.
2. In `podssh-ws`, the upgrade takes a list of headers in place of the one
   token header; the relay keeps `X-Relay-Token`. Each header that carries a
   token is a credential: never printed or logged, and never in a URL or on
   argv.
3. A road for `podssh ssh` and `podssh proxy` (this entry decides the
   spelling, for example a destination `cf://[user@]HOST`): the WebSocket to
   `wss://HOST`, then SSH over it, as on the relay's forward road. The token
   comes from a variable or a file. The browser login of Access cannot run
   in a cage: a service token, or a token made on another host, is the
   supported way.
4. Docs: the roads in `docs/design.md` (section 2), the manual, `docs/cli.md`.

Added by the operator's ruling of 2026-10-10 (Q38): once this road works, the throughput method of
T-157 gets a cell for it, measured with the other roads in the live run of T-251.

## Decision

Taken, with these calls made in the work (2026-10-11). The upgrade is the one of cloudflared,
read in its source at `bf4f502` (GitHub `cloudflare/cloudflared`: `carrier/`,
`cmd/cloudflared/access/`, with gorilla/websocket 1.5.3): `GET /`, a `Host` with no port, a
`User-Agent`, then the other headers in the order of their names, the three of Cloudflare Access
among them (`Cf-Access-Client-Id`, `Cf-Access-Client-Secret`, `Cf-Access-Token`). cloudflared
sends its token only on a second try, after a redirect to the login page of Access; podssh, which
runs no login, sends each credential that it was given at once. The origin reads a message into a
buffer of 16 KiB and drops the rest, so the session sends no message over 16 KiB, a longer payload
as several messages, never as fragments of one. The origin answers a Ping outside the lock of its
other writes, so the session sends none, and the idle bound of each read (90 s, against the
origin's Ping every 54 s) finds a dead link. Neither end sends a Close: the end of the stream is
the end of the session, which the pipe of `podssh proxy` takes as a clean end. The spelling is `cf://[user@]HOST`, for
`podssh ssh` and `podssh proxy`; the host key is recorded under HOST. The credentials come from
`PODSSH_CF_ACCESS_CLIENT_ID` and `PODSSH_CF_ACCESS_CLIENT_SECRET` (a service token), or
`PODSSH_CF_ACCESS_TOKEN` or the file of `PODSSH_CF_ACCESS_TOKEN_FILE` (a token that
`cloudflared access token` made), never from the command line, so no flag names a file. A bad one
exits 78, naming its variable, never its value. A refusal of Access (a redirect to its login page,
401 or 403) names those variables and exits 77; the query of a redirect, which the login page
fills, is never shown, nor a credential that an answer quotes. The upgrade's code takes a request
of its caller's (`upgrade_with` in `podssh-ws`), so the relay's request is unchanged.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test cloudflare_access
```

A stand-in server over plain `ws://` on the loopback (feature `plain-ws`)
checks the path, the headers and the bytes of an upgrade against bytes
captured once from `cloudflared access tcp`; a planted client that puts the
token in the URL fails. A live check against a service that the operator
publishes waits for the operator.

## Correction

The command of the Prove runs no test: the test file is behind the feature `plain-ws`, as
`crates/podssh-ws/tests/plain_loopback.rs` is; measured on 2026-10-11, it ran 0 tests. The command
is `cargo test -p podssh-ws --features plain-ws --test cloudflare_access`. No bytes were captured
from `cloudflared access tcp`: the stand-in checks the upgrade against cloudflared's source, read
at `bf4f502`. A capture of the program, and the live check, wait for a service that the operator
publishes.

## Done

2026-10-11. `podssh ssh cf://[user@]HOST` and `podssh proxy cf://HOST` reach a service that
`cloudflared` publishes, over the WebSocket of `cloudflared access tcp`, through `HTTPS_PROXY`,
with the credentials of Cloudflare Access from the environment
(`crates/podssh-ws/src/cloudflare.rs`, `crates/podssh-cli/src/ssh/cloudflare.rs`). The manual's
VARIABLES and the notes of `ssh`, `docs/cli.md` and `docs/design.md` (section 2) give the road.
- `cargo test -p podssh-ws --features plain-ws --test cloudflare_access`: 6 passed, on Windows,
  against a stand-in on the loopback for the edge and the origin. The upgrade, with no credential,
  a service token, a token, and both, was line by line the one of cloudflared, but for the
  User-Agent and the key of each run. 256 KiB went up as 16 messages of 16 KiB, each whole, and a
  session of the relay's kind sent one message, which the check saw. The origin's Ping got its
  Pong, and no Ping went up. A redirect to the login page of Access was told apart, with the query
  of its Location left out; a refusal that quoted a service token's secret and a token showed
  neither. The check of the head refuses a token in the URL, and another order of the headers.
- Planted: the session with no bound on its messages failed the test of 16 KiB; the session with
  its Pings failed the test of no Ping.
- `cargo test -p podssh-cli --lib -- cloudflare`: 3 passed (the destination, the credentials, a
  token's file); `cargo test -p podssh-cli --test cloudflare_cli`: 2 passed. Each flag that cannot
  go with `cf://` was refused with 64 before anything connected; `PODSSH_OFFLINE` stopped `ssh`
  (255) and `proxy` (69); a service token with no secret, and a token with a space, were refused
  (78 for `proxy`, 255 for `ssh`), naming the variables, never the value.
- `cargo test -p podssh-ws --features plain-ws`: 199 passed, 0 failed, 2 ignored;
  `cargo test -p podssh-cli`: 536 passed, 0 failed, 31 ignored; clippy with all features. The
  gate's step `libs` runs the test of the road with no C compiler. A live check, and the cell of
  T-157 for this road (Q38), wait for a service that the operator publishes.

# T-299: The quick tunnel's edge, measured: its ports through a proxy and the relay, and a captured registration

**Source:** T-170 (`docs/design.md:129-452`): the ports and the transports of a quick tunnel are
read, not measured.
**Category:** measurement
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The design of a quick tunnel that podssh makes itself (T-170) rests on Cloudflare's documents and
on cloudflared's source. No test has shown which ports of the edge take a tunnel, whether a
CONNECT proxy or the relay can carry its connection, or the bytes of a real registration, which
the tests of T-300 need.

## Premise

- Read (T-170): the edge is `region1.v2.argotunnel.com` and `region2.v2.argotunnel.com` on port
  7844, for TCP and UDP; port 443 serves optional things only (`docs/design.md:203-220`).
  cloudflared asks for a tunnel, and dials the edge, with no proxy (`docs/design.md:162-179`,
  `docs/design.md:226-240`).
- Read: the box's proxy, as the measured one, allows `CONNECT` to ports 443, 80 and 8443 only
  (`scripts/box/proxy.py:32`, `docs/target-environment.md:21`), and lets one more target through
  by its name with `--allow` (`scripts/box/proxy.py:14-16`).
- Read: the relay's direct road refuses Cloudflare's address ranges; on its VPC road the platform
  does not (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:224-227`).
- Read: neither `api.trycloudflare.com` nor the edge is a test target of `AGENTS.md` (section
  4), and cloudflared is a program of another project, which podssh uses as a reference only
  (`docs/decisions.md`, 2026-10-08).

## Approach

1. With the operator's leave (Q43): one quick tunnel at a time, a few minutes each, in front of a
   throwaway origin (a fixed page). The tunnel's secret is a credential: it stays in `.work/`,
   and is never printed.
2. The request: `POST https://api.trycloudflare.com/tunnel` as cloudflared sends it, directly and
   through the box's proxy. Record the status, the fields of the reply (never the secret) and the
   time.
3. The edge: TCP, then TLS with the name `h2.cftunnel.com`, to an address of each region, on port
   7844 and on port 443, directly and through the box's proxy with 7844 let through by `--allow`.
   Record each result, and the root of the edge's certificate chain.
4. The relay: `podssh relay trace` to an edge address on port 7844, on each of its roads, then TLS
   through `podssh proxy`. Record whether TLS completes.
5. cloudflared as a reference, never a road: `cloudflared tunnel --protocol http2 --url URL` on
   the operator's machine, and its name reached from the box with `podssh proxy cf://NAME`
   (T-264). Record whether a quick tunnel registers over HTTP/2. Where cloudflared can give the
   keys of its TLS session (not verified), capture the bytes of its control stream as fixtures for
   T-300, with a `-text` line in `.gitattributes`.
6. Write each result in the section of T-170 in `docs/design.md`, under "The edge, measured", and
   in `docs/STATUS.md`, with the date and the command.

## Decision

The operator ruled on Q43 on 2026-10-30 (`docs/decisions.md`): the measurement runs in a job of
GitHub Actions, with short runs and a throwaway origin; `cloudflared` is a reference only, never a
road. The operator decides T-300 after this entry's result.

## Prove

```sh
grep -n 'The edge, measured' docs/design.md
```

The section gives, for each port and each road, whether the edge took the connection and the
tunnel, with the date and the command; a road that was not tried says why. T-300 starts from it.

## Correction

2026-10-30, a second reading of the source and of the documents (the research of that day; nothing
was run against Cloudflare). Read: cloudflared at commit `77a79bf` (master on 2026-10-30; the
latest release is 2026.10.6), where the section of `docs/design.md` read `bf4f502` (release
2026.10.0). Each fact is Read in a source unless it says Inferred. `docs/design.md` is not edited
here; the measurement of this entry rewrites its section "The edge, measured", and these eight
points go in with it.

1. `docs/design.md` said "release 2026.10.0" (at `4457f9c`, lines 110-111): the pin is two releases old. Re-pin at the
   commit of the day of the measurement, and read the files again.
2. `docs/design.md` said "The default features include" (at `4457f9c`, lines 217-218): true at 2026.10.0. Since commit
   `77a79bf` (TUN-10904, 2026-10-29) the edge "universally supports the legacy default features",
   and registration advertises `support_datagram_v3_2` only when datagram v3 is chosen;
   `serialized_headers`, `quick_reconnects`, `allow_remote_config`, `support_quic_eof` and
   `management_logs` are deprecated and filtered (`cloudflare/cloudflared:features/features.go`).
   So the default list of today's cloudflared is empty, and the serialized form of the answers
   is not a feature any more. The Premise and item 4 of the Approach of T-300 name the features at
   `bf4f502`: see its Correction.
3. `docs/design.md` said "Which root signs" (at `4457f9c`, lines 241-243): a third party reports that the certificate
   `*.cftunnel.com` chains to one of three roots that cloudflared adds to the system's pool,
   "CloudFlare Origin SSL ECC Certificate Authority", "CloudFlare Origin SSL Certificate
   Authority" and "origin-pull.cloudflare.net" (`cloudflare/cloudflared:tlsconfig/cloudflare_ca.go`;
   the spike of `lordmacu/cloudflare-quick-tunnel-rs:docs/spike-verdict.md`, 2026-05-14, says that
   without them the handshake fails with `UnknownIssuer`). A report, not a measurement of ours:
   step 3 of the plan below records the issuers.
4. `docs/design.md` said "is not verified; cloudflared allows it" (at `4457f9c`, lines 202-203): it is still not
   verified. Cloudflare's troubleshooting page says cloudflared falls back to HTTP/2 over TCP and
   asks for 7844 on TCP; a Node script (`devsnek`, a gist) and the ignored live tests of libcfd
   aim at quick tunnels over HTTP/2. No result of any was seen.
5. `docs/design.md` said "libcfd (crates.io, 0.2.0 of 2026-09-23)" (at `4457f9c`, lines 252-253): libcfd (GitHub
   `apersomany/libcfd`) is 0.3.0 now, with QUIC (quinn or quiche) and HTTP/2, hand-written RPC
   ("it does not use `capnp-rpc`"), and still no license that GitHub detects. A second connector,
   `lordmacu/cloudflare-quick-tunnel-rs` (QUIC only, quinn 0.11 and rustls, generated capnp code
   committed, Apache-2.0 on GitHub and MIT or Apache-2.0 in its README), vendors cloudflared's
   schemas and the three roots. podssh copies from neither without reading its license again.
6. `docs/design.md` said "by means that Cloudflare did not make available on purpose" (at `4457f9c`, lines 152-153):
   the clause of the Website and Online Services Terms (effective 2025-08-01) is "any means not
   intentionally made available through the Websites or Online Services", and the sentence
   before it is about "materials or information"; it is about what one obtains, not about the
   client. The Self-Serve Subscription Agreement has no such clause (it has 2.2.1 (c), (e), (g)
   and (j)), and binds users of an account (Inferred: an account-less quick tunnel falls under
   the Online Services Terms, which cloudflared's own notice names). Whether a connector of
   podssh's own is a forbidden means stays the operator's call; the research found no clause that
   names another client.
7. Add to the section: cloudflared offers X25519MLKEM768, P256Kyber768Draft00 and P-256 only (no
   X25519; `cloudflare/cloudflared:crypto/curves.go`), and podssh's TLS offers X25519 and
   secp256r1 with no ML-KEM (`crates/podssh-ws/src/crypto/kx.rs`); a classical handshake is
   therefore a question for step 3 of the plan below. The startup prechecks
   (`cloudflare/cloudflared:prechecks/probes.go`: per region DNS, QUIC, TCP and TLS, 5 s each, and
   TCP to api.cloudflare.com:443, logged as "CONNECTIVITY PRE-CHECKS"; off with
   `--no-prechecks`) use the name `probe.cftunnel.com`. The edge's request kinds include
   `update-configuration`. A hidden flag `--cacert` replaces the roots of the edge connection.
8. The paragraph "No proxy" (at `4457f9c`, lines 180-184) holds. Add: the maintainers say the same
   in cloudflare/cloudflared#350 and #1025 ("the official transport to use should be QUIC, which
   wouldn't work for the SOCKS proxy"); QUIC is UDP, so it cannot use an HTTP CONNECT proxy
   (Inferred); HTTP/2 could, if the proxy allows CONNECT to 7844. Third-party patches exist (a
   SOCKS5 pull request, closed unmerged in 2023; `AlliotTech/cloudflared_proxy`, SOCKS5 with
   HTTP/2 forced, which notes proxies that choke on ML-KEM client hellos; a snap patch for an HTTP
   proxy); none is a result for quick tunnels. Port 443 of the edge is not a documented fallback
   ("optional", for updates and token checks; the code has no fallback to it), so a cage that
   allows 443 only has no documented road.

Facts of the request that the Approach can use. Read: cloudflared's HTTP client for
`POST /tunnel` is a `http.Transport` with no `Proxy` field, so it ignores `HTTPS_PROXY`
(Inferred from Go's zero value; step 7 of the plan shows it with a logging proxy). A quick tunnel
sets `--protocol` to `quic` when none is given, and a named protocol has no fallback, so on a
network with no UDP on 7844 `cloudflared tunnel --url` alone never connects (Inferred from those
two facts; the precheck table of step 8 shows it). Third parties report that the API can answer 429 or
"error code 1015" under load; no document gives a creation limit.

The plan of the measurement, in GitHub Actions (Q43; the leave of the operator is in the
Decision). It replaces item 1, and items 2 to 5 where it says so; the byte capture of item 5
stays a job for the operator's machine, because the capture holds the tunnel's secret in the
registration message. A hosted runner has open egress: it answers what the edge accepts, not what
a cage allows, and the box's proxy (`scripts/box/proxy.py`) stands for the cage's policy. A
runner's shared address may meet 429. Step 4 of the Approach, the relay's roads, needs a podssh
build and the relay: leave it to a local session or to a later step with the gate's artifact. The
job is the workflow quick-tunnel-edge.yml (a file that does not exist yet), with
`workflow_dispatch` only, an input `confirm` that must equal `Q43`, `permissions: contents: read`,
`concurrency`, `runs-on: ubuntu-24.04`, `timeout-minutes: 15`, no secret, and a `timeout` on each
command. The logs of a public repository are public: print no secret.

1. Check out the repository (for the box's proxy). Print `uname -r`, `openssl version` and the
   date.
2. Fetch cloudflared at a pinned release (2026.10.6 on the day of the research), and check its
   sha256 against the digest on the release page (Read there on that day; read it again when the
   workflow is written). Print its version.
3. Roots: take the three certificates from `tlsconfig/cloudflare_ca.go` at that tag. Discovery:
   the SRV record `_v2-origintunneld._tcp.argotunnel.com` over DNS over HTTPS
   (`cloudflare-dns.com/dns-query`, `accept: application/dns-json`), and the A records of
   `region1.v2.argotunnel.com` and `region2.v2.argotunnel.com`.
4. The raw matrix: for one address of each region (documented: 198.41.192.7 and 198.41.200.13,
   then the first of the SRV answer), `timeout 10 openssl s_client` with the roots and
   `-verify_return_error`, on ports 7844, 443, 8443 and 80; the names `h2.cftunnel.com` and, on
   7844, `probe.cftunnel.com`, `region1.v2.argotunnel.com` and none; the groups default, X25519
   and P-256; the ALPN none and `h2`. Record for each cell: connected, the handshake result, the
   verify code, the issuers of the chain, `notAfter`, and the first frame after an HTTP/2 client
   preface. Also Cloudflare's own test, `curl -v https://region1.v2.argotunnel.com:7844`.
5. QUIC: the precheck table of step 8 is the main answer. A second view is optional: a short
   `aioquic` client with the ALPN `argotunnel` and the name `quic.cftunnel.com`, 10 s, that prints
   whether the handshake completed and the issuer (it reads a private attribute: Inferred).
6. The proxy: start the box's proxy, and (a) post the request through it with a distinctive
   `User-Agent`, print the reply's field names and types with the secret removed, never write the
   secret to disk, make one tunnel that is never connected, and stop at a 429 or 1015; (b) open
   TLS to the edge's 7844 through the proxy with no `--allow`, which must get 403; (c) restart it
   with `--allow region1.v2.argotunnel.com:7844=198.41.192.7:7844` and repeat; (d) CONNECT to 443
   and 8443 of the same name. Keep the proxy's log.
7. One tunnel at a time, in front of a fixed page served on the loopback. Run A: cloudflared with
   `HTTPS_PROXY` set to the box's proxy, `--protocol http2`, `--edge-ip-version 4`, a log file, 100
   s at most; wait up to 60 s for the registration; read the name from the log; fetch it with a
   DNS-over-HTTPS resolver, up to six times 10 s apart; compare the body; record the time to the
   first success; optionally a WebSocket echo through the name; stop with an interrupt and look
   for the unregister message; count the log lines of the proxy that cloudflared caused (the
   expectation is none, which shows that the proxy is ignored). Run B: the same with no
   `--protocol`, and keep the table "CONNECTIVITY PRE-CHECKS", the `protocol=` and `location=`
   fields of the registration line and any "Switching to fallback".
8. Grep the logs for the words `secret` and `Credentials` before the upload; upload only the
   cloudflared logs and the proxy's log, with a retention of 3 days. A cleanup step with
   `if: always()` stops the processes. A quick tunnel ends with its process.

At most three tunnels, each under two minutes. What to write in `docs/design.md` and
`docs/STATUS.md`: the date, the run's URL, the runner image, the cloudflared version and digest;
for each address and port the result of the cell; the issuers and `notAfter`; which groups and
names the edge took; the API's status, field names and types, latency and hostname shape; the time
until the name answers; the negotiated protocol and location; the precheck table; whether the
WebSocket passed; the rows of the proxy; the rate of 429. Not in this job: the relay's roads and
the capnp fixtures.

Open points, which the measurement answers (none is a fact yet):

- Does the edge listen on 443, 8443 or 80 for `h2.cftunnel.com`? This decides the cage's case.
- Does the edge accept a classical TLS handshake, with X25519 and no ML-KEM?
- Does a quick tunnel register over HTTP/2 with a minimal registration, and is
  `updateLocalConfiguration` needed before the route is live? (The Node gist sends neither
  features nor ingress; it states no result.)
- Does `api.trycloudflare.com` accept a User-Agent that is not cloudflared's, and a request
  through CONNECT? What are its limits for the shared addresses of CI?
- Which options of `ConnectionOptions` does the edge check (client id, version, platform)?
- The idle and keepalive rules of the connection (cloudflared's HTTP/2 server settings were not
  read in full).
- The terms: whether carrying SSH, with a connector of podssh's own, is acceptable use of an
  account-less tunnel. The operator's call; the research found no ruling.

## Done

2026-10-30. The workflow quick tunnel edge (`.github/workflows/quick-tunnel-edge.yml`, with
`scripts/quick-tunnel-edge.py`), dispatched by hand with `confirm` set to `Q43`, measured the
edge from GitHub-hosted runners. Run 41071742798 (the job `edge`): the raw matrix, the box's
proxy, the request for a tunnel and cloudflared's two runs; three tunnels, each alive for less
than 15 s, and no 429. Run 41072705691 (the job `relay`, item 4 of the Approach, with `part` set
to `relay`): no tunnel. `docs/design.md` ("The edge, measured", in the section of T-170) gives
each port and road with the date and the command, and the eight points of the Correction above
are in that section; `docs/STATUS.md` has the table.

- Of the ports tried, the edge takes TLS on 7844 only: TLS 1.3 with `h2.cftunnel.com`, no ALPN,
  X25519 or P-256 with no ML-KEM, signed by the ECC root of cloudflared's three Origin roots. 443
  and 8443 connect and serve no tunnel's TLS; 80 is not TLS. After TLS the edge sends HTTP/2's
  client preface.
- The box's proxy refuses 7844 (403); with 7844 let through, it carries the edge's TLS. The
  relay's VPC road dials the edge's 7844, and TLS over `podssh proxy` verified: a road from a
  cage, through the relay.
- `POST /tunnel` through a CONNECT proxy, with a User-Agent that is not cloudflared's: 200, with
  the fields that `docs/design.md` names.
- cloudflared 2026.10.6 registered a quick tunnel over HTTP/2 and over QUIC, served the page
  through its name, and sent nothing through `HTTPS_PROXY`.
- Before the dispatch, in this container and with no contact with Cloudflare: cloudflared's help,
  read in a network namespace that had no network; the script's redaction, against a made-up log
  and a stand-in for the API (no secret, id or name printed; two planted leaks, each found); TLS
  over a stand-in for `podssh proxy`. actionlint with shellcheck, and check-repo.py, clean.
- Point 1 of the Correction, done: each cited file of cloudflared, read again at the release
  2026.10.6 (commit `35b379a`; 21 of the 23 files are byte for byte those of `bf4f502`). Each
  claim of the section holds there; four citations moved, and the section gives them at
  2026.10.6. The reading corrects two points above: `bf4f502` is main of 2026-10-08, one commit
  after the tag 2026.10.0, not that tag; and at 2026.10.6 the default features are still those of
  `bf4f502`, with `serialized_headers`: the empty list of point 2 is main's, since `77a79bf`, in
  no release yet.
- Prove: `grep -n 'The edge, measured' docs/design.md` names the heading.
- Not run, each with its reason in the section: QUIC from a client of podssh's own, a WebSocket
  through the name, and the bytes of a registration, which hold the tunnel's secret.

The capture of those bytes, for item 5 of the Approach, moves to T-300, whose tests use it (its
Correction, point 7). The alternatives lost: to keep this entry open for it, as this entry's
Prove is the section of results, and the capture serves T-300 alone, which waits for the
operator's call on this result; and to capture in Actions, as a log or an artifact of this
public repository is public, and the bytes hold the tunnel's secret.

# T-300: `podssh node` publishes a quick tunnel over HTTP/2, with no `cloudflared`

**Source:** T-170 (`docs/design.md:129-452`); the operator's ruling of 2026-10-08: podssh makes a
quick tunnel itself (`docs/decisions.md`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** done

## Problem

A podssh node on a host that reaches TCP port 7844 could be reached from a cage by a public name,
with no relay and no account. When no relay host answers, that is a road. podssh cannot make such
a name: it runs no `cloudflared`.

## Premise

- Read (T-170, `docs/design.md:129-452`): the request for a tunnel and its reply; the SRV lookup of
  the edge; TLS to `h2.cftunnel.com` with no ALPN; cloudflared as the HTTP/2 server on the
  connection that it dialed; the control stream and its Cap'n Proto registration; the one header
  of each answer (`serialized_headers`); and a WebSocket that passes to the origin unchanged.
- Read: `h2` 0.4.19 is in `Cargo.lock`, through hyper; the crates `capnp` and `capnp-rpc` are
  Rust, and their code generator needs the C++ tool `capnp` (`docs/design.md:303-335`).
- Read: podssh's DNS over HTTPS asks for A and AAAA records only
  (`crates/podssh-ws/src/resolve.rs`, line 125 at `927eb24`).
- Read: the client exists: `cf://HOST` opens cloudflared's WebSocket through `HTTPS_PROXY`
  (T-264, `crates/podssh-ws/src/cloudflare.rs`).
- Read: a node runs the far end of the resumable layer for each session (T-083, T-153).

## Approach

1. The spelling, which this entry decides: for example `podssh node NAME TARGET --quick-tunnel`.
   The node prints its name, `https://NAME.trycloudflare.com`, on stdout, as it prints an iroh
   ticket.
2. The request: `POST https://api.trycloudflare.com/tunnel` through `HTTPS_PROXY`, with podssh's
   TLS, 15 s and 1 MiB at most, as cloudflared. The secret stays in memory that is wiped, and is
   never shown.
3. The edge: SRV over DNS over HTTPS (a new record type for `resolve.rs`), or the two names of
   the documents; an address of each region in turn. TCP to port 7844 directly, or through a
   CONNECT proxy that allows it (a `403` names the port); TLS with the name `h2.cftunnel.com`, no
   ALPN, and Cloudflare's roots beside podssh's.
4. HTTP/2: podssh serves the connection with `h2`. On the control stream, Cap'n Proto RPC:
   `registerConnection` with the default features of cloudflared at `bf4f502`, then
   `updateLocalConfiguration` with one ingress rule, and `unregisterConnection` at the end. The
   generated code is committed, so the build needs no C++ tool.
5. Each request: a WebSocket upgrade becomes a session of the node's layer, answered with 200 and
   the serialized headers of a 101; any other request gets 404 with no body. 200 requests in
   flight at most, the limit of a quick tunnel.
6. The client: `podssh ssh` to the node's name runs the layer over the WebSocket of `cf://`; this
   entry decides the spelling (a far end that sends `GREETING` first can be told apart, as on the
   reverse road).
7. Pin the protocol: the files of cloudflared that it follows, at their commit, in
   `docs/design.md`, as the relay's contract is pinned.
8. Docs: the road in `docs/design.md` section 2, the manual, and `docs/cli.md`.

## Decision

Recommendation: a module of `podssh-relay` (no C), with the TLS of `podssh-ws`, and HTTP/2 only;
QUIC is T-301. The alternative, a crate of its own for Cloudflare, lost while the module is small.

2026-10-30, the operator (Q47, `docs/decisions.md`): build it, as recommended: HTTP/2 only, a
module of `podssh-relay`, the three roots that `cloudflared` adds beside podssh's own, the
relay's road to the edge where TCP 7844 is not reached, and its live tests in GitHub Actions only,
as T-299's. The operator reads Cloudflare's terms as allowing a client other than `cloudflared`.

2026-10-30, the spelling of item 6: the client is `cf://NAME.trycloudflare.com`, the road of
T-264, and a far end whose first frame is the layer's `GREETING` is a podssh node, as the reverse
road tells a node that greets from one that does not (`crates/podssh-relay/src/session/client.rs`,
`greeted`). cloudflared's SSH service speaks SSH first, so its sessions pass on as before, and the
wait for a far end's first byte costs them nothing. The node's key is the one of `--node-key`, else
pinned under `cf://NAME` at its first sight; a quick tunnel's name lives one run of its node, so
the pin guards that run's later sessions, and the key that the node prints guards the first. The
alternatives that lost: a scheme of its own (`qt://NAME`), which a user would have to choose though
the far end tells; a flag that asks for the layer, which a podssh node never needs; and a refusal
of `cf://` with no `--node-key` when the far end greets, which would end the pin's first sight
that `node://` keeps, while the node's allowlist still refuses each key it does not hold.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test quick_tunnel
```

A stand-in edge on the loopback, written from cloudflared's source at `bf4f502` (an HTTP/2 client,
and a Cap'n Proto server of `registerConnection`), checks the fields of the registration, then
opens a WebSocket stream whose layer reaches a TCP target, with equal digests both ways, and finds
the answer's headers in `Cf-Cloudflared-Response-Headers`. A planted node that sends its headers
unserialized fails it. With the leave of Q43, a live run: a node outside the box, and a client in
the box through its proxy.

## Start condition

T-299 is done: the edge's ports are measured, with the operator's leave (Q43).

## Correction

2026-10-30, the research of that day (Read in sources, nothing run against Cloudflare; the points
that are Inferred say so). The Premise names `serialized_headers` as a feature, and item 4 of the
Approach registers "with the default features of cloudflared at `bf4f502`". At cloudflared's
commit `77a79bf` (TUN-10904, 2026-10-29) the edge supports the legacy default features for every
connector, and registration advertises a feature only for datagram v3
(`cloudflare/cloudflared:features/features.go`; the second point of the Correction of T-299). So:

1. Item 4: register with an empty list of features, as today's cloudflared does by default (Read);
   a Node script (`devsnek`, a gist) registers with no features and no version, sending only the
   account tag, the secret, the tunnel id, the index 0 and `client.clientId`. Whether the edge
   accepts that for a quick tunnel is a question that the measurement of T-299 and the first
   live run of this entry answer; it is not a fact. The answers of HTTP/2 carry the serialized
   header always.
2. Item 4, the code: the generated Cap'n Proto code can be committed, and the crate `capnp-rpc`
   may be unneeded. Read in third parties, not verified by us: libcfd writes the RPC by hand
   ("it does not use `capnp-rpc`"), and `lordmacu/cloudflare-quick-tunnel-rs` ships pre-generated
   code with no `capnp` tool at build time; both claim live tests against the edge. The Premise's
   "Read" about the C++ tool for the code generator still holds.
3. Item 3, TLS: cloudflared offers X25519MLKEM768, P256Kyber768Draft00 and P-256, and not X25519
   (`cloudflare/cloudflared:crypto/curves.go`); podssh's TLS offers X25519 and secp256r1, with no
   ML-KEM (`crates/podssh-ws/src/crypto/kx.rs`). Test a classical handshake first: T-299 asks
   the edge. Add the three Origin roots that cloudflared adds (a third party reports that the
   edge's certificate chains to one of them), if T-299 confirms the issuers. Through an HTTP
   CONNECT proxy, a client hello with ML-KEM can be refused by a proxy (a third party reports it);
   podssh sends none.
4. Whether the edge needs `updateLocalConfiguration` before it routes a request: unknown, the
   Node script omits it and states no result.
5. The terms are a gate that the operator holds: no clause that the research read names another
   client; section 7 of the Website and Online Services Terms is open to two readings. The
   Decision of T-299 says that the operator decides this entry after T-299's result.
6. 2026-10-30, T-299's measurement (`docs/design.md`, "The edge, measured"): item 3 holds with
   podssh's TLS as it is. The edge took TLS 1.3 with X25519 or P-256 and no ML-KEM, chose no ALPN,
   and its certificate chains to "CloudFlare Origin SSL ECC Certificate Authority", one of the
   three roots, which podssh adds. The edge is the HTTP/2 client: it sends the client preface
   first. A quick tunnel registers over HTTP/2 (cloudflared). The API answered 200 through a
   CONNECT proxy, with a User-Agent that was not cloudflared's (item 2). Item 3 gains a road: the
   relay's VPC road carried TLS to the edge's 7844 over `podssh proxy`, so a node in a cage can
   reach the edge through the relay; the edge's 443 and 8443 serve no tunnel.
7. The bytes of a real registration (item 5 of T-299's Approach) are this entry's to capture: they
   hold the tunnel's secret, so they are captured on the operator's machine, or the secret is
   replaced before the bytes are kept as a fixture with a `-text` line in `.gitattributes`. The
   stand-in edge of the Prove is checked against them.

## Done

Partial, 2026-10-30. Done so far, each checked, nothing live yet:

- `crates/podssh-relay/src/quick/`: the Cap'n Proto of the registration
  by hand (`capnp.rs`: a builder of one segment, a reader of any segments
  with far pointers and a limit of words, the framing of a stream), the
  RPC's bootstrap, call on its promised answer, finish, and the reading of
  return and abort (`rpc.rs`), `registerConnection` and its answer
  (`register.rs`, with the features of cloudflared 2026.10.6), the control
  stream sans-IO (`control.rs`: register, finish, unregister, and an
  exception for a question of the edge), and the headers of HTTP/2
  (`headers.rs`: the kinds of request, the serialized answer, the answer
  to a WebSocket).
- Their tests read bytes of the reference encoder, `capnp encode` of Cap'n
  Proto 1.0.1, with cloudflared's schema at 2026.10.6 and capnproto2's
  `rpc.capnp` at v2.18.0 (`scripts/quick-fixtures.sh`, the fixtures in
  `crates/podssh-relay/tests/fixtures/quick/`): the builder writes the
  reference's bytes for the parameters, the bootstrap, both calls, the
  finish and the exception; the reader reads each field of the
  reference's. `cargo test -p podssh-relay --lib quick`: 19 passed.
  Planted, the target of the call as an imported capability: the test of
  the bytes failed; the union of the answer read two bytes on: both tests
  of the answer failed; each passed again without its plant.
- `crates/podssh-relay/src/quick/serve.rs` (feature `quick` of the crate,
  with `h2` 0.4.19, `http` and `bytes`, all in the lock already through
  hyper): the HTTP/2 server on the dialed connection; the control stream
  runs the registration and, at the end, the unregistration, then a GOAWAY
  and a grace of 2 s for the streams still open; a visitor's WebSocket
  gets 200 with the 101's headers serialized and the meta `{"src":"origin"}`,
  and becomes a stream of its messages' bytes, the node's frames unmasked
  (pings get pongs); any other request gets 404 with no body.
  `crates/podssh-relay/tests/quick_tunnel.rs`, the stand-in edge of the
  Prove (the `h2` crate's client, and the reference's bytes for the edge's
  side of the RPC): 3 passed, three runs of three: the registration and
  its finish, a visitor's message echoed both ways, the unregistration on
  the same capability, a refusal with its cause, and 404 for any other
  request. Planted, the 101's headers sent as they are, not serialized:
  the first test failed at its check of the serialized headers, and passed
  again without it. clippy `-D warnings` with and without the feature, and
  rustfmt: clean.
- `crates/podssh-relay/src/quick/api.rs`: the request for a tunnel through
  podssh's HTTPS path (`HTTPS_PROXY` when set, 15 s), and its reply read,
  the secret kept in memory that is wiped and never shown (3 tests: a reply
  of T-299's shape, the refusals, a body that succeeded never quoted).
  `crates/podssh-relay/src/quick/edge.rs`: the two names of the documents on
  7844, TLS with `h2.cftunnel.com`, no ALPN, and cloudflared's three roots
  beside podssh's (`cloudflare-roots.pem`, each with its SHA-256).
- `podssh node NAME TARGET --quick-tunnel` (`crates/podssh-cli/src/node_quick.rs`):
  the tunnel asked for, its URL the one line on stdout, the edge reached,
  each visitor's WebSocket a link of the layer with the channel above it
  (the pair's road's `Layered` over `E2e`), `--allow` needed as the name is
  public, a lost connection made again with the same name, the
  unregistration at Ctrl-C; the flag's row, the manual's note of `node`,
  `docs/cli.md`, `docs/design.md`, `docs/STATUS.md`. `cargo test -p
  podssh-cli --test node quick`: the refusals offline, 1 passed; the CLI's
  lib 406 passed and the manual's tests 54.
- The client, `podssh ssh cf://NAME` (`crates/podssh-cli/src/ssh/cloudflare.rs`,
  `crates/podssh-cli/src/ssh/cloudflare/layer.rs`): the far end's first
  bytes read; with no `GREETING`, the bytes pass on as before, and
  `--node-key` is refused; with it, the layer's handshake (`keep.v1`
  named), the channel above it (`--node-key`, else the pin under
  `cf://NAME`), and a task that carries the session on a new WebSocket to
  the name after each lost one; `--client-key` and `--node-key` taken for
  a `cf://` destination, and `--no-e2e` refused there, as a quick
  tunnel's node always runs the channel; SSH's keepalives off there
  unless `ServerAliveInterval` is given; and `podssh ssh`, `each`,
  `--persist`, `ping` and the copies wait up to 5 s after SSH for the
  layer's `CLOSE` and the line of a failure (`transport::settle`).
  `cargo test -p podssh-cli --lib ssh::cloudflare`: 5 passed, of them two
  against the node's own handler as `--quick-tunnel` serves each visitor
  (the layer, the channel, then TARGET, an echo in memory that counts its
  opens): 1 MiB both ways, each link cut, 1 MiB again on the resumed
  session, with one open of TARGET and equal digests; and a key out of the
  allowlist, refused with its fingerprint and the file of `--allow`, said
  before the task ends, with TARGET never opened. Planted, a dial that
  never gives a new link: the first failed; the refusal not said: the
  second failed; each passed again without its plant. `cargo test -p
  podssh-cli --test cloudflare_cli --test iroh_cli`: 7 passed, the
  channel's flags with `cf://` among them, `--no-e2e` refused. The CLI's
  lib 408 passed, the manual's tests 28 (`flag_table`, `man_flag_parity`,
  `man_json`, `man_page`); before the refusal of `--no-e2e` and the
  manual's note, the whole of `cargo test -p podssh-cli -p podssh-relay
  --features podssh-relay/quick`: 1292 passed, 0 failed, 53 ignored, in
  161 binaries. clippy `-D warnings` on both crates: clean.
- The live run, `.github/workflows/quick-tunnel-live.yml` (by hand, with
  confirm=Q43; Actions only): the node built from the commit, in front of
  an OpenSSH server on the loopback with an empty allowlist; the visitor of
  `scripts/quick-tunnel-probe.py`, directly and through the box's proxy,
  whose first frame must be the layer's `GREETING`; then `podssh ssh
  cf://NAME`: refused with the client's new key, which then goes into the
  list; 8 MiB both ways with `--node-key`, directly and through the box's
  proxy, the far end's digest equal; and a `--node-key` that is not the
  node's, refused. Run 41152476358 at `200ff2d` (2026-10-31, 00:52 to 00:54
  UTC, a hosted runner): the node registered at Cloudflare's `sjc01`, one
  name under `trycloudflare.com`; the visitor of Python's standard library
  got a 101 with its key's accept, directly and through the box's proxy,
  and the layer's `GREETING` first (98 bytes, its type `0x01`); the first
  `podssh ssh cf://NAME` was refused (255), its key then went into the
  list; 8 MiB both ways with `--node-key`, with equal digests, directly and
  through the proxy; a `--node-key` not the node's, refused (255); the node
  unregistered at its end.
- Filed: T-331, the layer's `CLOSE` in the five commands that hand their
  connection on (`job`, `pipe`, `health`, `containers`, `--upgrade`).
- A review of the code (2026-10-30, read only, by an agent of this session)
  named seven defects; each was read again at its lines, and holds. The
  allowlist held: TARGET opens only after the key is let in. Repaired, each
  with a test that its plant fails (2026-10-31):
  - A visitor's stream that the edge reset before the answer ended the
    whole connection (`respond_200(...)?`); now that visitor alone. And the
    wait between connections never fell back after a registered one
    (`crates/podssh-cli/src/node_quick.rs`): it does now (read, not tested).
  - Each ping's payload went into an unbounded queue while the writer
    waited for the edge's window; now only the latest waits, as RFC 6455,
    section 5.5.3, allows.
  - A visitor with no key could hold the node's budget: the layer took a
    slot before the channel checked the key, and a lost link kept it 600 s.
    Now the layered handler gives the channel an admission
    (`Handler::open_admitted`, `Keeper::admit`): a session counts against
    the budget once its key is let in, the keeper refusing it there when
    the budget is full, and one that was not let in waits 30 s at most for
    a resume (`UNADMITTED_WAIT`, the channel's handshake limit), not the
    deadline.
  - The edge's connection could die with no new one: HTTP/2's handshake now
    has 30 s (`HANDSHAKE_WAIT`) and ends at a stop; a PING each 30 s,
    unanswered for 30 s, ends the connection (`Ended::Silent`); the end of
    the control stream is `Failure::Ended`; and the edge's GOAWAY, which h2
    keeps to itself, is seen in the frames' headers as they pass
    (`crates/podssh-relay/src/quick/goaway.rs`) and ends the connection
    (`Ended::GoingAway`), so that the node connects again and the sessions
    resume.
  - One stream whose user read slowly held the connection's window of
    65,535 bytes; the connection's window is now that of its 256 streams,
    16 MiB.
  - A double far pointer to a segment that is not there panicked the
    reader of Cap'n Proto, and the release aborts on a panic; now it is
    malformed.
  - T-331's: `pipe` with a listener ran outside `settled` (its Done).
- `cargo test -p podssh-relay --features quick --test quick_resilience`: 7
  passed, against the stand-in edge, the helpers of `quick_tunnel` moved to
  `tests/quick_harness/`: a visitor reset before its answer, then the next
  one echoed on the same connection; a raw GOAWAY of the edge's, ended at
  once; a control stream that the edge ended; an edge that answers no PING
  (paused time: gone within 60 s); a stalled visitor beside an echoed one;
  300 pings while the writer waited: fewer than 10 pongs, the last the last
  ping's; an edge that never shakes hands (gone at 30 s), and a stop in
  the handshake. Planted, each repair undone alone (the answer fatal again,
  no GOAWAY, no end of the control stream, no PONG limit, the window of
  65,535, the unbounded queue, no handshake limit): its test failed each
  time; each passed again without its plant. `--lib quick::`: 26 passed,
  the missing segment among them (planted, the old reader panicked at its
  index), the watcher of GOAWAY's 2 among them. `cargo test -p podssh-relay --features pair --test e2e_layered`:
  4 passed, of them three visitors with no key that finish the layer's
  handshake and leave, then two clients with a key let in on a budget of
  two, and a third refused by the budget; planted, the old count of the
  budget, and a channel that admits at once: each failed at the first
  client ("this node keeps as many resumable sessions as its budget
  allows"). And two clients that reach the channel at once on a budget of
  one, both past the layer's count as neither was let in: the second is
  refused there, in the budget's words ("this node keeps as many sessions
  as its budget allows", not the target's), and the node says so. `cargo test -p podssh-relay --features blocking,quick,pair`:
  313 passed, 0 failed, in 45 binaries.

# T-301: The quick tunnel over QUIC, where a probe finds UDP

**Source:** T-170 (`docs/design.md:129-452`): cloudflared makes a quick tunnel over QUIC unless the
user names HTTP/2.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

On a host where UDP works, the connector of T-300 still runs over HTTP/2 on TCP. cloudflared's
maintainers name QUIC as the transport that they mean users to have, and HTTP/2 as one with fewer
functions.

## Premise

- Read (T-170): QUIC to port 7844 with the name `quic.cftunnel.com` and the ALPN `argotunnel`; the
  first stream, which the connector opens, is the control stream; each stream of the edge starts
  with six bytes and a version, then a Cap'n Proto `ConnectRequest`, and is answered with a
  `ConnectResponse` (`docs/design.md:242-261`).
- Read: the iroh road binds UDP only after its own probe (`docs/design.md`, section 7), and its
  QUIC stack is in the build with the feature `iroh` only.
- Read: the measured cage refuses UDP (`docs/target-environment.md:23`).

## Approach

1. After a UDP probe (the iroh road's), QUIC to the edge, with cloudflared's first packet size
   (1232 bytes for IPv4, 1252 for IPv6) and its datagrams setting, though podssh routes no
   private network.
2. The control stream: the registration of T-300, on the first stream.
3. Each stream from the edge: the signature of a data stream, the version, a `ConnectRequest`; a
   WebSocket becomes a session of the layer; the answer is a `ConnectResponse` with the headers as
   metadata.
4. A fallback to HTTP/2 when QUIC fails, as cloudflared's `auto` does; `-v` names the transport.
5. The QUIC crate: the iroh road's, or another with no C; this entry decides, with the size of
   each.

## Decision

2026-10-31, before the code:

1. The QUIC crate is noq 1.4 (n0's QUIC, which the iroh road already
   builds), with no default features: `runtime-tokio` and `rustls` only.
   Read in its manifest: `ring` and `aws-lc-rs` are optional there, and its
   `rustls` feature adds only `aes-gcm` 0.10 (pure Rust, for the integrity
   tag of a Retry). Its endpoint takes the reset key as an `HmacKey` of the
   caller's (`EndpointConfig::new`), so nothing of C is needed. Lost: quinn
   0.11, the same code before n0's fork, which would put a second QUIC
   stack beside the iroh road's in a build with both.
2. The keys of QUIC come from `podssh-ws`'s own provider: the packet key
   (AES-GCM, the nonce the IV XOR the packet number) and the header
   protection (AES on the sample, RFC 9001, section 5.4), for its two
   TLS 1.3 suites, with the limits of RFC 9001, section 6.6. Lost: rustls's
   ring or aws-lc provider for QUIC alone, which puts C in a library crate.
3. The stand-in edge's certificate is made in the test by `rcgen` with no
   crypto feature, signed by a P-256 key of `p256` through rcgen's
   `SigningKey`, so the test builds with no C compiler as the gate's
   `libs` step builds it.
4. Q47's "HTTP/2 only" is T-300's scope: the question recommended building
   T-300 over HTTP/2, which T-299 had measured, and this entry stayed open
   beside it with T-300 as its start condition. QUIC is taken only where no
   proxy is set, as a proxy carries no UDP and rule 2 of `AGENTS.md` sends
   the connection through `HTTPS_PROXY` when it is set; HTTP/2 stays the
   road through a proxy and the fallback. Its UDP socket is the
   connection's own, on a port that the system picks, as the iroh road's
   endpoint is (`scripts/check-repo.py`, the listener's allowance).
5. QUIC that fails once gives way to HTTP/2 for the rest of the run, as
   cloudflared's `auto` falls back: a network that drops UDP drops it
   again, and each try costs the handshake's 5 s. Lost: QUIC again after
   each lost connection, which a network that let UDP through later would
   reward.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test quick_tunnel_quic
```

The stand-in edge of T-300, over QUIC on the loopback: the control stream is the first stream, and
a WebSocket session reaches its target with equal digests. With UDP refused (a probe planted to
fail), the connector uses HTTP/2, and says so.

## Start condition

T-300 is done.

## Correction

2026-10-30, the research of that day: this adds to the Approach; it disproves no Premise. Read in
sources, not run by us. Item 1 asks for cloudflared's first packet size (1232 and 1252 bytes). A
third party's live spike (`lordmacu/cloudflare-quick-tunnel-rs:docs/spike-verdict.md`, 2026-05-14)
reports that stock quinn 0.11 with rustls completes the handshake with the ALPN `argotunnel`, the
name `quic.cftunnel.com` and cloudflared's three Origin roots, and that the two sizes are not
required. Treat that as a hypothesis until a run of this entry shows it. cloudflared pins the
protocol of a quick tunnel to `quic` (a named protocol has no fallback), so a network with no UDP
on 7844 never connects with `cloudflared tunnel --url` alone (Inferred); the precheck table of
cloudflared's startup, which T-299 records from a hosted runner, is the first row of this entry's
evidence for UDP. This entry waits for it.

## Done

2026-10-31. The quick tunnel runs over QUIC where no proxy is set and UDP
reaches the edge, as cloudflared's does, and over HTTP/2 elsewhere and
after a failure of QUIC. The Decision; cloudflared 2026.10.6 read in a copy
under `.tmp/` (`tunnelrpc/quic/protocol.go`: the signature of a data
stream `0A 36 CD 12 A1 3E`, of an RPC stream `52 BB 82 5C DB 65`, the
version `01`; `tunnelrpc/proto/quic_metadata_protocol.capnp`;
`connection/quic_connection.go:89-262`: the control stream is the first
that cloudflared opens, the edge opens one stream for each request, and
the metadata `HttpMethod`, `HttpHost`, `HttpHeader:NAME` and
`HttpStatus`).

The keys of QUIC, done: `crates/podssh-ws/src/crypto/quic.rs` gives both
TLS 1.3 suites of the provider their `quic` keys: AES-GCM packets with the
nonce of RFC 9001, section 5.3, and AES header protection, section 5.4,
with the limits of section 6.6. `cargo test -p podssh-ws --test quic_keys`,
6 passed: RFC 9001's server Initial (A.3) protected and opened byte for
byte, and the client's header masked from its sample (A.2); the same packet
under QUIC v2 (RFC 9369, as rustls's tests hold it); FIPS-197's AES-256 for
a mask; the GCM specification's test case 14 for an AES-256-GCM packet, a
changed byte and another packet number refused; and a mask whose first
byte has the bit 0x10 (computed with OpenSSL 3.0.13), which tells a long
header from a short one. Each failed on its plant: the bits of a long and a
short header swapped (the RFC's samples alone missed it, hence the last
test), a nonce with no packet number, and the mask one byte off.
`cargo test -p podssh-ws`: 220 passed.

The connector, done: `crates/podssh-relay/src/quick/connect.rs` (sans-IO:
the signatures, the version, `ConnectRequest` read and `ConnectResponse`
written; `cargo test -p podssh-relay --lib quick::connect`, 4 passed: the
edge's request as `capnp encode` wrote it, and the node's 101 and 404
answers byte for byte as it writes them, from
`tests/fixtures/quick/quic-connect-*.txt`); `quic.rs` (TLS 1.3 with the
ALPN, cloudflared's settings of the transport, one endpoint of port 0 for
each connection, a reset key of HMAC-SHA-256); `quic_serve.rs` (the
control stream first, then each stream of the edge in its own task: a
WebSocket answered 101 and bridged by `visitor.rs` with the bytes that came
after its request, any other request 404, an RPC stream reset).
`cargo test -p podssh-relay --features quick --test quick_tunnel_quic`, 3
passed in 5 s, against a stand-in edge of noq on the loopback whose
certificate rcgen made under a CA of the test: the registration as over
HTTP/2, 1 MB of a visitor's WebSocket echoed with equal digests, its first
bytes in the same write as its request; the 404 and the RPC stream; the
unregistration and `Ok`; a refused registration; an edge that closes
(`Closed`); and a path cut by a forwarder, with no close (`Silent` after
the 5 s). Each failed on its plant: the bytes after a request dropped, a
stream opened before the control stream, and no idle timeout. With
`CC=/nonexistent`, `podssh-relay` builds and passes them with `quick`, and
`cargo +1.89 check` of the library crates with it passes: the gate's steps
`libs` and `msrv` now build `quick` too. `cargo test -p podssh-relay
--features quick,blocking`: 321 passed.

`podssh node --quick-tunnel` (`crates/podssh-cli/src/node_quick.rs`): QUIC
first where no proxy is set, HTTP/2 after a failure of QUIC, which it says;
its line of the registration names the transport. The manual, `docs/cli.md`
and `docs/design.md` say so.

Live, in GitHub Actions (`.github/workflows/quick-tunnel-live.yml`, run
41162536619 at `98e05c2`): the node registered at Cloudflare's `dfw16` over
QUIC, and the visitors, `podssh ssh cf://NAME` with 8 MiB both ways
directly and through the box's proxy, and `podssh health` went over that
connection. With UDP to 7844 dropped, a second node said that no region
answered over QUIC and registered at `dfw13` over HTTP/2, and its visitor
got in; the first node, whose QUIC connection the same rule cut, found the
silence ("the edge stopped answering") and went on over HTTP/2, as the
fallback says.

2026-10-31, after the close (found by T-359's tests): the test
`an_edge_that_closes_and_one_that_falls_silent_end_the_connection` failed
one run in six alone, once at the edge's close and once at the silence, each
time with `Err(Control(Ended))`. When the connection ends, `accept_bi` and
the control stream both see it, and the first of the two to reach the loop
of `crates/podssh-relay/src/quick/quic_serve.rs` won: a close or a silence
read as a control stream that ended. A control stream that fails on a
connection with a reason now ends with that reason (`Closed` or `Silent`);
the test passed 16 runs of 16 alone and the file 10 of 10. Also, QUIC's own
limit of a silence and the handshake's wait, both 5 s, ended a handshake
with two sets of words, "QUIC: timed out" and "no answer over QUIC within
5 s": a handshake's timeout now has the second alone. The loop over HTTP/2
(`serve.rs`) has the same two arms; its tests passed 6 runs of 6, but none of
them ends the connection while the control stream reads, so the race is not
measured there.

# T-171: The functions of Mosh that M6 and T-160 do not give, made in podssh itself

**Source:** GitHub #22 (Nemo-010, 2026-10-08: SSHub selects a Mosh transport
for each host); `docs/design.md:630-631`; the operator's ruling of
2026-10-08: no road depends on a program of another project, and podssh
makes the useful functions itself (`docs/decisions.md`).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Mosh keeps an interactive session usable on a bad network. podssh does not
start `mosh-server` or `mosh-client`, so each function that users want from
Mosh must come from podssh's own roads and layers. Nobody has listed the
functions that are still missing.

## Premise

Read: an interactive echo for high latency, as Mosh has, is a later option on
top of layer 2 (`docs/design.md:630-631`). The measured sandbox refuses UDP
(`docs/target-environment.md:23`), and the relay carries no UDP
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:222`). Not
verified here (from the published description of Mosh): it roams to a new
client address; it survives sleep and long outages; it echoes keys locally;
it keeps the screen state on the server and skips frames under heavy output,
so that Ctrl-C shows at once; it shows a notice when the link is silent; and
it sends datagrams over UDP, with no head-of-line blocking.

## Approach

1. Check each function above in the documentation and the source of Mosh
   (GitHub `mobile-shell/mosh`), and mark each one read or measured.
2. Map each function to an entry: a new address and outages, T-151 to T-156;
   local echo, T-160; screen state, T-161; a shell that outlives the client,
   T-159; a direct UDP path where a probe allows it, the iroh road (T-162).
3. Write an entry for each function that has none, with an id from
   `cargo todo next`. The candidates:
   - the latest screen after heavy output, so that Ctrl-C shows at once; it
     needs the screen model of the far end (T-161);
   - a notice in the terminal while the link is silent, drawn with the screen
     model of T-160, so that it does not damage the screen;
   - datagrams for keys and screen updates where UDP works (QUIC datagrams on
     the iroh road), with no head-of-line blocking.
4. Measure each gain before its entry: with the fault harness (T-203), 300 ms
   of latency and 2 % loss, compare `-tt` over the layer with Mosh on the
   operator's test hosts. Mosh is a reference there, never a road.
5. Write the map in `docs/design.md` section 5, next to the paragraph about an
   interactive echo.

## Decision

2026-10-12, the calls made in the work:

- Item 1 was read online, in Mosh's paper (USENIX ATC 2012), on mosh.org and in its source at
  `decd9b7`; Mosh is GPL-3.0, so podssh reads it for its behaviour and copies no code. Each
  function is marked READ: nothing was measured.
- Item 4, the measurement, moved into each new entry as its first step: this research ran no
  network test, and the fault harness (T-203) shapes the TCP stream of the stand-in relay, where
  a loss of 2 % is only a delay. T-304 adds a stand-in that drops datagrams.
- Item 3: the three candidates are T-303 (the latest screen), T-302 (a notice of silence) and
  T-304 (datagrams). The research found two more functions with no entry: a roam that does not
  wait for the dead-link limit of 30 s (T-305), and a session that outlives a night of sleep
  (T-306; Mosh's server keeps a session with no limit by default). T-303 is parked behind T-110,
  since only the SSH server's end sees the pty in clear, and T-304 behind T-303.

## Prove

```sh
grep -n 'The functions of Mosh' docs/design.md
cargo todo check
```

The map names an entry for each function of Mosh, or gives the reason why
podssh does not need it. The checker accepts the new entries that the map
names.

## Correction

2026-10-12: "a later option on top of layer 2" holds only when the far end runs the SSH server.
The layer runs under SSH, so a node in front of a standard sshd carries SSH's ciphertext, and
cannot see the pty's bytes; the functions of the screen (an echo's acknowledgement, frames of the
screen) need `podssh serve` (T-110), and a notice drawn on the screen needs the client's model of
T-160 (`docs/design.md:648-655`). And the iroh road (Approach, item 2) gives a direct UDP path,
but carries a session as one QUIC stream, so a lost packet still holds the bytes after it; only
datagrams (T-304) remove that.

## Done

2026-10-12. The map is in `docs/design.md:637-694`, section 5, "The functions of Mosh, and where
podssh gives each": a table of 13 functions, each with Mosh's way (the paper's section, or a file
and lines of Mosh at `decd9b7`) and podssh's entry; and four functions that podssh does not need,
each with the reason (scrollback, forwarding, UTF-8 only, a UDP port on the server).
- The Premise's six functions are READ in the paper and the source: roaming, a session that
  waits for its client with no limit by default, local echo, frames of the screen that let Ctrl-C
  show within a round trip, a notice of silence after 6.5 s, and idempotent datagrams.
- Mapped to entries that exist: T-153 and T-156 (a new address), T-154 (the heartbeat), T-160
  (local echo, and its acknowledgement), T-158, T-159 and T-161 (a new client), T-088
  (encryption), T-083, T-166 and T-167 (the start), and `~.`.
- New entries: T-302 (a notice of silence that does not touch the screen), T-303 (frames of the
  screen, on request, parked behind T-110), T-304 (datagrams on the iroh road, parked behind
  T-303), T-305 (a new link beside a silent one) and T-306 (a resume deadline that the user sets).
- Not measured: Mosh's figures in the section are the paper's own; each new entry measures
  podssh first.
- Prove: `grep -n 'The functions of Mosh' docs/design.md` names the section's heading.
  `cargo todo check`: not run in this draft, which ran no cargo; it runs before the commit.

# T-172: Multipath TCP on the direct road

**Source:** GitHub #24 (Nemo-010, 2026-10-08: RustConn's Multipath TCP and its
reconnection on a network change; the report notes that the sandbox has no
MPTCP).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

On a host with two networks, a TCP connection dies with its network.
Multipath TCP (MPTCP) can move a connection to another path. It is not known
whether MPTCP helps podssh on any road.

## Premise

Read: `--direct` connects with a plain `TcpStream::connect`
(`crates/podssh-ws/src/dial.rs`, lines 247-318 at `927eb24`, the call at
line 291 at `927eb24`). Through a proxy, MPTCP can reach only the
proxy. `podssh-ws` has no `libc` dependency (`crates/podssh-ws/Cargo.toml`).
Read in the report, not verified here: RustConn uses MPTCP. Not known:
whether the relay's edge or a target server accepts MPTCP. Linux offers it
from version 5.6, when `/proc/sys/net/mptcp/enabled` is 1.

## Approach

1. The probe: read `/proc/sys/net/mptcp/enabled`, then ask for a socket with
   `IPPROTO_MPTCP`, through `libc` (a workspace dependency that compiles no
   C). On `EPROTONOSUPPORT`, `ENOPROTOOPT`, `EINVAL` or `EPERM`, use plain
   TCP. The result is the same stream, so the fallback changes no behaviour;
   `-v` names it.
2. Only on `--direct`, only on Linux, and at first only on request.
3. Measure: a direct session to a server that accepts MPTCP, then take one of
   two networks down. Record whether the session lives.
4. Measure whether the edge of Cloudflare accepts MPTCP: one connection to the
   relay, and the options of its SYN-ACK.
5. Write the results and a recommendation in `docs/design.md` section 5 (the
   table of failures).

## Decision

2026-10-12: the request is the variable `PODSSH_MPTCP` (yes or no), read
where the first hop is reached with `--direct`
(`crates/podssh-cli/src/ssh/transport.rs`), so `ssh`, `cp`, `mv`, `scp`,
`sftp`, `edit`, `ping` and the hops of `pipe ssh:` take it; another value
is refused before the connection (78, and 255 for `ssh`). A flag lost: it
would be a row in each of eight flag tables, with their parity tests, for a
switch that is on request only until it is measured. An `-o` keyword lost:
OpenSSH has none, and a file that OpenSSH also reads would break. The
address `tcp:` of `pipe` and `chat --direct` dial by themselves and do not
ask yet: step 2 names `--direct`.

2026-10-12: each error of the socket call gives plain TCP, not only the
four of step 1: a plain socket gives the error again when its cause is not
MPTCP (no descriptor left). An error for the others lost: it would fail a
dial that plain TCP can make. A connect that fails on a socket of MPTCP is
the attempt's failure, as on plain TCP, with no second try. Through a
proxy, the connection is plain TCP and says so: MPTCP could reach the proxy
only.

2026-10-12: whether the server took MPTCP is the option `TCP_IS_MPTCP`
(Linux 5.16 and later), which is 0 on a connection that fell back: `-v`
says it, and step 4 needs no capture of the SYN-ACK, as the kernel reads
its MP_CAPABLE. A capture lost: it needs a privilege that podssh never
assumes. An older kernel does not say, and `-v` says that.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test mptcp
grep -n 'Multipath TCP' docs/design.md
```

The test asks for an MPTCP socket where the kernel refuses it, and gets plain
TCP with the same result; a planted dial that fails instead fails the test.
The `grep` shows the recorded result.

## Done

2026-10-12 (a draft; the main session builds and runs it). With
`PODSSH_MPTCP=yes`, `--direct` with no proxy asks Linux for Multipath TCP.
- `crates/podssh-ws/src/mptcp.rs`: the probe (the switch of
  `/proc/sys/net/mptcp/enabled` at 1, on Linux only), the socket of
  `IPPROTO_MPTCP` through `libc` (now a dependency of podssh-ws on Linux
  alone, which compiles no C), the fallback to plain TCP with its reason,
  and the answer of `TCP_IS_MPTCP`. `crates/podssh-ws/src/dial.rs`:
  `dial_multipath`, and each attempt of the race of RFC 8305 asks for MPTCP
  when the dial does; `dial` is unchanged for its callers.
  `crates/podssh-cli/src/ssh/transport.rs`: `PODSSH_MPTCP`, and a line of
  `-v` that names the kind of connection.
- The manual: `PODSSH_MPTCP` in ENVIRONMENT and an example; `docs/cli.md`
  (Options of `podssh ssh`); `docs/design.md` section 5, the row of a
  changed client address, with the recommendation: on request and on
  `--direct` only, until it is measured; `docs/STATUS.md`.
- Tests: `cargo test -p podssh-ws --test mptcp` (a refused socket of MPTCP,
  planted, gives plain TCP with the same bytes; a host whose switch is off
  gives plain TCP and the probe's reason; the direct dial that asks for
  MPTCP carries the same bytes on each host; where the host offers MPTCP,
  both ends of MPTCP on the loopback carry them, and the server took it,
  else the test says that it did not run); the unit tests of
  `podssh_ws::mptcp` (the switch, the words of `-v`) and of the variable
  (`cargo test -p podssh-cli --lib -- transport`). Results on Windows 11:
  `mptcp` 4 passed and the live test ignored, the unit tests 3 and 1; in
  the build image: 4 passed, on a kernel with no Multipath TCP (the test of both ends said so), and the unit tests 2. The plant of the Prove, a fallback that
  returns the error instead, which must fail the first test, waits for
  T-251.
- Waiting for T-251 and the operator's hosts: step 3, a session to a server
  that speaks MPTCP with one of two networks taken down; step 4, whether
  Cloudflare's edge takes MPTCP, by the ignored live test
  `live_the_relay_s_edge_answers_a_socket_of_mptcp` from a Linux host that
  offers it. `docs/design.md` gets both results then.

# T-173: Resumption in the relay for a standard sshd

**Source:** ROADMAP M8 (not now; look at it again after M6);
`docs/design.md:611-628` (layer 3) and `docs/design.md:1240-1243` (question 1 of
section 8).
**Category:** feature
**Milestone:** M8
**Priority:** P3
**Effort:** L
**Status:** blocked

## Problem

A session to a standard sshd over the forward road ends at each drop of the
client's link. Only the relay can keep the TCP connection to sshd while the
client connects again.

## Premise

Read: when the WebSocket closes, the relay closes the TCP connection to the
target within 15 s, and it has no resumption (`docs/design.md:581-584`). The
option is a Durable Object that owns the target socket across reconnections,
a resume token in the `101` response, and offset framing as a protocol
version that the client selects. It is a project of the relay's operator, and
it costs Durable Object time for the whole session (`docs/design.md:624-628`).
The recommendation is "not now; look at it again after M6"
(`docs/design.md:1240-1243`). The relay is in another repository.

## Approach

The part of podssh, when the start condition holds:

1. Write a proposal for the relay's operator that reuses the records of the
   resumable layer (T-151). The relay becomes the far end of the layer, so
   the client keeps one implementation.
2. The client uses it only when the relay says that it offers it (a field of
   `/relays.json` or `/health`, read at run time). Never assume it.
3. Keep the resume token in memory only. Send it back in a header, never in a
   URL or in output (`docs/relay.md:178-180`).
4. A resume must reach the same Durable Object, so only hosts of one
   deployment can resume a session (the rule of the pool:
   `crates/podssh-relay/src/pool.rs:139-148`).
5. Test against the relay's implementation, live, and against the stand-in
   relay with the same state machine.
6. When the relay's version changes, update the pinned contract and
   `docs/relay.md` in the same commit (`docs/relay.md:14-16`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_relay_resume
cargo test -p podssh-relay --test live -- --ignored relay_resume
```

The first command runs the client against the stand-in with resumption in the
relay: the link drops at random points, the digests are equal, and no URL
holds the token. The live test does the same against the relay, when the
relay offers the feature.

## Blocker

The relay's operator: resumption in the relay is work of the relay project. After M6 (T-156), the
operator and the relay's operator decide question 1 of `docs/design.md` section 9. Sessions skip
this entry (the operator's ruling of 2026-10-08).

# T-280: The iroh road through a SOCKS5 proxy

**Source:** found in T-070 (2026-10-11): each other road takes a SOCKS5 proxy for the egress
since then; the iroh road refuses one by name.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A host whose only way out is a SOCKS5 proxy (`ALL_PROXY=socks5h://...`) reaches the relay and the
pair's road since T-070, but not the iroh road: iroh's relay client tunnels through an HTTP CONNECT
proxy only, so podssh refuses the setting for the iroh road before anything binds.

## Premise

- Read: podssh refuses a SOCKS5 proxy for the iroh road by name
  (`crates/podssh-iroh/src/endpoint.rs`, lines 134-140 at `3224a88`); the test
  `a_socks5_proxy_is_refused_by_name` asserts it (`crates/podssh-iroh/tests/relays.rs`, line 144
  at `3224a88`).
- Read: iroh-relay 1.3.0's client opens its relay connection through a proxy in
  `dial_url_proxy`: TCP to the proxy, TLS to it for each scheme but `http`, then an HTTP `CONNECT`
  (`n0-computer/iroh:iroh-relay/src/client/tls.rs`). A `socks5h://` URL would be taken as a proxy
  that speaks TLS.

## Approach

1. Find a hook of iroh 1.x that lets the caller open the relay's TCP stream (a dialer, or a relay
   transport of its own); if one exists, open the stream with `podssh_ws::dial::dial`, which
   speaks SOCKS5 since T-070.
2. Else carry a patch of `iroh-relay` that adds SOCKS5 to `dial_url_proxy`, as
   `vendor/tailscale-rs` is carried with its patches in `vendor/patches/`, or ask upstream
   (n0-computer/iroh) for it. Write the choice in `## Decision`.
3. Remove the refusal; the manual's VARIABLES (`crates/podssh-cli/src/man/facts.rs:46-55`) and
   `docs/architecture.md` say that the iroh road takes SOCKS5 too.

## Decision

2026-10-12: step 2, a patch of iroh-relay that podssh carries, as no hook exists (see
Correction). The crate as crates.io publishes it is in `vendor/iroh-relay`, byte for byte, with
`vendor/patches/iroh-relay/0001-socks5-proxy.patch` applied, and the root's `[patch.crates-io]`
makes iroh 1.3.0 build it; the tree is excluded from the workspace, as `vendor/tailscale-rs` is.
What lost:
- Asking upstream alone: the entry would wait on another project, and a host whose only way out
  is SOCKS5 would have no iroh road meanwhile. The patch can still be offered to n0-computer/iroh.
- A bridge on the loopback from iroh's `CONNECT` to the SOCKS5 proxy: `AGENTS.md` (section 5,
  rule 2) forbids loopback helpers.
- iroh's unstable custom transports: they carry QUIC datagrams on a transport of the caller's,
  not the relay's TCP stream; a relay client of podssh's own over one would be a second relay
  protocol, outside iroh's semantic versioning.
- A patch of iroh too, for its HTTPS probe of the relays: reqwest's feature `socks` gives the probe
  SOCKS5 with no code, from the same patched manifest.
- The dial of `podssh_ws::socks5` inside iroh-relay: a published crate with a path to podssh's
  crates would tie both. The patch's module sends the bytes that `crates/podssh-ws/src/socks5.rs`
  sends: the name with the address type 3 for `socks5://` too (T-070's decision), RFC 1929, the
  reply read to its end, and on reply 8 one more connection with an address from the dial's
  resolver, which is podssh's own (`crates/podssh-iroh/src/resolve.rs`).

2026-10-12: podssh gives iroh `socks5h://` at the proxy's address, which podssh resolved, as it
gives an HTTP proxy at its address, so iroh resolves no name. The check of a proxy's credentials
against iroh's base64url (`sendable`) is for an HTTP proxy only: the SOCKS5 dial and reqwest each
decode the URL's user and password and send them as RFC 1929 says. podssh-iroh keeps its range
of iroh: an update that asks for another iroh-relay leaves the patch unused, cargo says so, and
the SOCKS5 test fails; a pin of iroh lost, as the advisories of its earlier releases come by
updates.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --features test-relay --test proxy_env
```

A stand-in SOCKS5 proxy on the loopback, as in `crates/podssh-ws/tests/socks5.rs`, is the only
way to iroh's relay server on the loopback, which it reaches by name: the endpoint goes online
through it, and the stand-in saw the relay's name with the address type 3. Planted defect: the
refusal restored, and the test fails.

## Correction

2026-10-12, read in iroh 1.3.0 and iroh-relay 1.3.0 (cargo's copies of the published crates):
step 1 has no hook to use. The endpoint's builder takes a proxy URL only; iroh's relay actor
gives it to iroh-relay's `ClientBuilder` (`n0-computer/iroh:iroh/src/socket/transports/relay/actor.rs`),
which has no dialer of the caller's; and the custom transports (`unstable-custom-transports`)
carry datagrams, not the relay's stream. And the Premise misses a second connection through the
proxy: iroh's HTTPS probe of the relays, which picks the home relay when there is no UDP path,
goes through reqwest with `reqwest::Proxy::all` of the same URL
(`n0-computer/iroh:iroh/src/net_report/reportgen.rs`). reqwest 0.13.5 takes a `socks5h://` proxy
only with its feature `socks`, which no crate of podssh's graph turned on; without it the probe
fails, and the endpoint gets no home relay. The patch turns the feature on: in reqwest 0.13 it is
hyper-util's SOCKS client, which reqwest already builds, so no crate is added.

## Done

2026-10-13. The iroh road goes through a SOCKS5 proxy, by the relay's name.
- `vendor/iroh-relay`: iroh-relay 1.3.0 as published (43 files, all but cargo's `.cargo-ok`), and
  its patch `vendor/patches/iroh-relay/0001-socks5-proxy.patch`: `src/client/socks5.rs` (new; the
  exchange of RFC 1928 and RFC 1929, within 10 s), `src/client/tls.rs` (`dial_url_proxy` gives a
  SOCKS5 proxy the exchange in place of `CONNECT` and TLS; `dial_socks5` tries once more with an
  address on reply 8; a proxy URL with no port means 1080; the debug line of the dial names the
  proxy's host and port, not its URL, which may hold a password), `src/client.rs` (the module) and
  `Cargo.toml` (reqwest's `socks`). The root `Cargo.toml`: `exclude` and `[patch.crates-io]`.
  `vendor/README.md`: the section iroh-relay, how to run the patch's unit tests and how to carry
  it to another version. Measured with no build: the patch applies with `git apply` to a copy of
  the published crate (exit 0), and the result equals `vendor/iroh-relay` (`diff -r`, exit 0).
- `crates/podssh-iroh/src/endpoint.rs`: the refusal is gone; a SOCKS5 proxy is `socks5h://` at its
  resolved address; `sendable` for an HTTP proxy only. `crates/podssh-iroh/src/relays.rs`: the way
  of `/ping`, which `podssh doctor` prints, says `SOCKS5 CONNECT` through a SOCKS5 proxy.
- Tests: `crates/podssh-iroh/tests/proxy_env.rs`, `a_socks5_proxy_in_all_proxy_reaches_the_relay_by_name`
  (`ALL_PROXY=socks5h://USER:PASSWORD@...` alone; the stand-in of
  `crates/podssh-iroh/tests/common/socks5.rs` is the only way to the relay, takes only its user
  and password, and opens a tunnel only to the relay's name with the address type 3; the endpoint
  goes online, and each CONNECT that it got was by name); the two tests of that binary take turns
  on the environment. `crates/podssh-iroh/tests/relays.rs`,
  `a_socks5_proxy_is_taken_with_a_password_that_connect_would_send_wrong`, in place of
  `a_socks5_proxy_is_refused_by_name`. The patch's unit tests in `src/client/socks5.rs` (4: the
  name's bytes and a reply read to its end, RFC 1929's bytes, reply 8 told apart and a refusal
  named, credentials out of RFC 1929's lengths), with the crate's own manifest.
- The manual's VARIABLES, `docs/architecture.md`, `docs/design.md` (section 7) and
  `docs/STATUS.md` say it.
- Windows 11, 2026-10-13: `cargo test -p podssh-iroh --features test-relay --test proxy_env
  --test relays`, 2 and 7 passed; `cargo test --manifest-path vendor/iroh-relay/Cargo.toml
  --target-dir .work/iroh-relay-target --lib client::socks5`, 4 passed; `cargo test -p
  podssh-iroh -p podssh-cli --features podssh-cli/iroh-test`, 791 passed and 1 failed at random,
  a test of `--persist` that a race of podssh's forward table made fail, repaired in its own
  commit; clippy with `iroh-test` and rustfmt clean. `patch -p1` on the crate of the registry
  gave `vendor/iroh-relay` file for file. The first build rewrote the entry of iroh-relay in
  `Cargo.lock` to the path. Planted, the refusal of SOCKS5 put back in `proxy_url`: both
  `a_socks5_proxy_in_all_proxy_reaches_the_relay_by_name` and
  `a_socks5_proxy_is_taken_with_a_password_that_connect_would_send_wrong` failed; restored, they
  passed.
- In the build image (`sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh lint iroh msrv_iroh'`,
  2026-10-13): green; clippy 1.99 with the feature `iroh` clean, the iroh road's tests passed on
  Linux, and podssh-iroh with the patched iroh-relay checks on Rust 1.91.
- Waiting for T-251: a real SOCKS5 server on the iroh road, as OpenSSH's `ssh -D` carries the
  relay road in `scripts/interop-socks.sh`.

# T-319: An HTTP road for a proxy that refuses the WebSocket upgrade

**Source:** the research of 2026-10-30 on tunnels through proxies that end
TLS and refuse `Upgrade`; the proxy of a Claude Code cloud container
documents that refusal for the names that it intercepts (T-311). GitHub #55
(Nemo-010, 2026-10-30): the wire protocol of the split form.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** L
**Status:** blocked

## Problem

Each road of podssh starts with a WebSocket upgrade. A proxy that
re-terminates TLS for the relay's name, and refuses `Upgrade`, leaves podssh
with no road, where plain HTTPS requests still go through.

## Premise

Read (the research of 2026-10-30): such proxies carry HTTP/1.1 requests and
responses only, and often buffer a request's body. The tools that work
there split the stream: one streamed GET carries the bytes down, and a POST
for each chunk carries them up, with a sequence number (Xray's `packet-up`,
gost's `pht`); the slowest form is one POST after another (meek). A relay on
Cloudflare streams responses with no time limit, and a Durable Object can
join both directions of a session. Not measured: the body buffering of this
container's proxy.

## Approach

1. With the relay's operator: session endpoints (a GET that streams the bytes
   down, a POST for each chunk up, a session id, sequence numbers and
   acknowledgements), in the relay's contract.
2. A link of this road under the resumable layer (`podssh-relay`, `session/`),
   chosen by a probe when the upgrade is refused (T-325): the split form
   first, the serial form as its fallback. The protocol of #55: batches up
   with a sequence number each, retried with the same number and body; a
   chunk deleted only after the consuming end acknowledged it (`X-Ack`), in
   a window with a bound; a 204 as a whole answer, so that a hop that
   buffers holds nothing open; the poll interval and the batch size from
   the probe, not compiled in.
3. `doctor` names the road that works.

## Decision

2026-10-30, the operator (Q44, `docs/decisions.md`): the split form may open
its second connection, on this road only, after a probe found the upgrade
refused; the serial form is its fallback. `AGENTS.md` (section 5, rule 2)
names it as the third exception.

## Prove

```sh
cargo test -p podssh-relay --test http_road
```

Against a stand-in proxy that refuses `Upgrade` and buffers request bodies,
a session carries 20 MiB each way with equal digests on the split form and
on the serial form. Planted: the sequence number ignored; the digests differ.

## Blocker

The relay's operator: the relay has no HTTP endpoints for a session
(`docs/relay.md`).

# T-321: An HTTP/2 road: the WebSocket over extended CONNECT (RFC 8441)

**Source:** GitHub #51 (Nemo-010, 2026-10-30).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** blocked

## Problem

Each session of podssh opens its own TCP and TLS connection, and starts
with an HTTP/1.1 upgrade that must end in 101. A fan-out (`podssh each`)
or many forwards pay a TLS handshake for each session. HTTP/2 with
extended CONNECT (RFC 8441) carries a WebSocket as one stream of a
connection, answered with 200, and many sessions on one TLS connection.

## Premise

Read and verified at the cited lines (2026-10-30):

- podssh offers no ALPN: `crates/podssh-ws/src/tls.rs:315` says "no ALPN",
  and a caller's configuration that offers ALPN is refused
  (`crates/podssh-ws/src/tls.rs:86` says "alpn_protocols.is_empty()").
- The upgrade is HTTP/1.1: `crates/podssh-ws/src/handshake.rs:37` builds
  it, and `crates/podssh-ws/src/handshake.rs:185` says "status != 101".
- A relay session is generic over its stream
  (`crates/podssh-ws/src/session.rs:36` says "RelaySession<S = RelayStream>",
  and `:95`). RFC 8441 section 5 runs the frames of RFC 6455 on the HTTP/2
  stream "as if it were the TCP connection", and drops `Sec-WebSocket-Key`
  and `Sec-WebSocket-Accept`.
- `docs/design.md:305` says "0.4.19 is in": `h2` comes through hyper. Its
  client reads the server's setting (`is_extended_connect_protocol_enabled`,
  `hyperium/h2:src/client.rs`), its server's builder offers it
  (`enable_connect_protocol`, `hyperium/h2:src/server.rs`), and
  `h2::ext::Protocol` carries `:protocol`.
- RFC 8441 section 3: a client may use extended CONNECT once it received
  `SETTINGS_ENABLE_CONNECT_PROTOCOL` with the value 1; a server that does
  not support it reads such a request as malformed.

Measured (2026-10-30, in a Claude Code cloud container, through its
proxy's CONNECT; a script offered `h2` and `http/1.1` and read the first
SETTINGS frame): the relay's edge (Cloudflare) chose `h2`, and sent
MAX_CONCURRENT_STREAMS 256, INITIAL_WINDOW_SIZE 65536 and MAX_FRAME_SIZE
16777215, and no ENABLE_CONNECT_PROTOCOL. The relay of today cannot take
this road.

## Approach

1. A road `h2` in `podssh-ws`: a TLS configuration of its own that offers
   ALPN `h2` (the HTTP/1.1 road keeps none), the HTTP/2 handshake with
   larger windows, then for each session a CONNECT with `:protocol
   websocket`, the `:scheme`, `:path` and `:authority` of the upgrade, and
   the token. A 200 opens the session; a refusal reads as a refusal of the
   upgrade.
2. Taken only when the server's SETTINGS offer extended CONNECT; else the
   HTTP/1.1 upgrade on a new connection, as today, with a line in `-v`.
3. The frames run on the stream with the code of today (`frame.rs`,
   `session.rs`). The sessions of one process share one connection, up to
   the server's MAX_CONCURRENT_STREAMS; a lost connection is one lost hop
   for each of its sessions.
4. `podssh doctor` names the ALPN that the relay chose, and whether it
   offers extended CONNECT.
5. The self-hosted relay (T-169) offers it (`enable_connect_protocol`).

## Prove

```sh
cargo test -p podssh-ws --test h2_road
```

Against a stand-in server made with the `h2` crate, which offers the
setting, answers 200 and echoes: 8 sessions on one TLS connection carry
4 MiB each way with equal digests. A server that does not offer it gets
the HTTP/1.1 upgrade on a new connection, and no `:protocol`. A 403 on the
CONNECT ends the session with the relay's refusal. Planted: `:protocol`
sent with the setting absent; the fallback test fails. Live, when a relay
offers it: `podssh doctor` says so, and `podssh ssh` runs on the road.

## Blocker

The relay's operator: the relay's edge does not offer extended CONNECT
(measured above), and a relay that does is the self-hosted relay of
T-169, which waits for the relay's operator.

Read (#51's comment of 2026-10-30, checked in the RFCs): RFC 9113,
section 8.5, says that a proxy's CONNECT "MUST" omit `:scheme` and `:path`,
which RFC 8441, section 4, requires beside `:protocol`, so an HTTP/2 proxy
that does not implement RFC 8441 reads the request as malformed. RFC 8441,
section 7, keeps the traditional CONNECT to a proxy, and lets the version of
HTTP inside the tunnel decide. podssh tunnels by a traditional CONNECT, so
through a proxy that does not end TLS the relay alone must offer the
setting; a proxy that ends TLS must implement RFC 8441 itself.

# T-329: Carry the patch of iroh-relay to iroh 1.4.1 (Azathothas/podssh#53)

**Source:** Azathothas/podssh#53 (Dependabot, 2026-10-30): the group of 11
updates fails the gate's step iroh (run 41075421658); the operator's ruling
of 2026-10-30 (`docs/decisions.md`): a session repairs what an update
breaks, and commits the update with the repair.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The group moves iroh from 1.3.0 to 1.4.1, which asks for iroh-relay 1.4.1.
podssh's patched copy (`vendor/iroh-relay`, T-280) was 1.3.0, so cargo built
the published iroh-relay and left the patch unused: the relay dial took a
`socks5h://` proxy for one that speaks TLS, and the iroh road through a
SOCKS5 proxy never came online.

## Premise

- Read: the lock file of the pull request has the published iroh-relay
  1.4.1 and `[[patch.unused]]` iroh-relay 1.3.0.
- Read: `vendor/README.md` ("How to carry it to another version") names
  this failure and its repair.
- Measured: the gate's step iroh of the pull request failed at
  `a_socks5_proxy_in_all_proxy_reaches_the_relay_by_name` (run 41075421658),
  where `main` passed it.

## Approach

1. The 11 updates on `main`, each with `cargo update -p NAME --precise
   VERSION`, as the pull request names them.
2. The patch carried to iroh-relay 1.4.1, as `vendor/README.md` says: the
   published crate from cargo's copy, then `git apply` of the patch.
3. The notes of the present state follow: the root `Cargo.toml`,
   `vendor/README.md`, `docs/design.md`, and the comments of `podssh-iroh`
   and of `release.yml` (aws-lc-sys 0.46).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --test proxy_env
cargo test --manifest-path vendor/iroh-relay/Cargo.toml --target-dir .work/iroh-relay-target --lib client::socks5
cargo test --no-fail-fast
```

Each passes, and the lock file holds no unused patch. Planted: the
published iroh-relay 1.4.1 with no patch; the SOCKS5 test fails.

## Done

2026-10-30. The 11 updates of the pull request are on `main`: serde_json 1.0.154, libc 0.2.191,
zeroize 1.9.1, iroh 1.4.1, aws-lc-rs 1.18.2 (with aws-lc-sys 0.46.0), pageant 0.2.5, hyper 1.12.0,
smallvec 1.16.4, tokio-util 0.7.20, yoke 0.8.4 and zerocopy 0.8.63, each by `cargo update -p
NAME --precise VERSION`. `vendor/iroh-relay` is iroh-relay 1.4.1 as published (from n0-computer/iroh
at `d6c6963`, its `.cargo_vcs_info.json`), and the patch of `vendor/patches/iroh-relay/` applied to
it with no change; the lock file builds that copy and holds no unused patch. Each updated crate's
minimum Rust is within the gate's: zeroize and tokio-util declare 1.85, as the library crates do,
pageant 1.89 and iroh 1.91, as before. aws-lc-sys 0.46 asks for NASM on Windows x86-64 as 0.45 did
(`builder/main.rs`, `use_prebuilt_nasm`).

- `cargo test -p podssh-iroh --test proxy_env`: both passed, the SOCKS5 one by name in 8.7 s.
  Planted, the published iroh-relay 1.4.1 with no patch: the SOCKS5 test failed at its wait for
  the relay (line 90 of the test), as the pull request's run did.
- The patch's own unit tests in the vendored crate (`--lib client::socks5`): 4 passed.
- `cargo test --no-fail-fast`, the default members: 2118 passed, 0 failed, 55 ignored, in 235
  test binaries.
- The tests of the feature `iroh` (`-p podssh-iroh -p podssh-cli --features podssh-cli/iroh-test`):
  968 passed, 0 failed, 41 ignored, in 116 test binaries.

The present-state notes follow the versions: the root `Cargo.toml`, `vendor/README.md`, three
lines of `docs/design.md`, the comments of `podssh-iroh` (its relay table is the same in 1.4.1) and
the NASM comment of `release.yml`. Dependabot closes its pull request once `main` holds the
updates.

# T-331: The layer's `CLOSE` before the exit of `job`, `pipe`, `health`, `containers` and `--upgrade` on `cf://`

**Source:** found in T-300 (2026-10-30): the client of a quick tunnel's node
runs the resumable layer in a task of `cloudflare::reach`, and a command
that exits before the task ends leaves its session at the node.
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A podssh node behind a `cf://` name (`podssh node --quick-tunnel`, T-300)
gets its session from a task that carries it in the resumable layer. When
SSH closes, the task sends the layer's `CLOSE`; a process that exits first
never sends it, and the node keeps the session for a resume until its
deadline (600 s by default), with its connection to TARGET; the line of a
failure, such as a key that the node's allowlist refuses, may not be said
either. `podssh ssh`, `each`, `--persist`, `ping` and the copies wait for
the task (`transport::settle`); five commands do not.

## Premise

- Read: `crates/podssh-cli/src/ssh/transport.rs` gives each road's stream
  in `Reached`, with the layer's task in `Reached::layer`, and `settle`
  waits for it up to `CARRIAGE_WAIT`.
- Read: `crates/podssh-cli/src/job/far.rs:60-78`,
  `crates/podssh-cli/src/pipe/ssh.rs:68-91`,
  `crates/podssh-cli/src/health/mod.rs:127-134`,
  `crates/podssh-cli/src/containers/mod.rs:186-197` and
  `crates/podssh-cli/src/ssh/upgrade.rs:91-104` take `reached.stream` and
  drop `reached.layer`.

## Approach

1. Keep the layer's task beside the connection that each command keeps
   (`job`'s handles, `pipe`'s `Hops`, `health`'s and `containers`' handles,
   `--upgrade`'s first login), and call `transport::settle` where it is
   closed.
2. A test of each that can run offline: the task's end is awaited before
   the command returns (a stand-in of `Reached` with a task that ends late).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli
```

Planted, a command that drops the task: its test fails. Live, in
`.github/workflows/quick-tunnel-live.yml`: `podssh job` and `podssh pipe`
to the name, and the node's log says that each session closed, not that it
was lost.

## Correction

2026-10-30. The Approach's item 1 threads the task through each command's
own state, and item 2 tests each command with a stand-in of `Reached`. Each
of the five runs on a runtime of one thread, and a task spawned there runs
only while the command's future runs, so a wait anywhere but inside that
future cannot send the `CLOSE`; and four of them hand their connection to
callers that close it in many places (`job`'s three, `podssh run`'s, and
the queue's). The work is: `transport::keep` takes the layer's task where
each command takes its road, into one list of the process, and
`transport::settled` runs each command's whole run, then waits for each
kept task, within the 5 s of `CARRIAGE_WAIT` in all, on each path out,
failures among them: a key that the node refuses fails the login, and its
line comes from the task. The test is the one of `settled`, which every
command shares; the live run shows each command's end. The node says
nothing of a session's end, so the live check reads what the node holds:
no TCP connection of the node to TARGET is left once a command exits.

## Done

2026-10-30, partial: the code and its test; the live check waits.

- `crates/podssh-cli/src/ssh/transport.rs`: `keep` and `settled`; `keep`
  in `job/far.rs` (`podssh job` and `podssh run`), `pipe/ssh.rs`,
  `health/mod.rs`, `containers/mod.rs` and `ssh/upgrade.rs`; `settled`
  around the runs of `job`, `run`, `pipe`, `health`, `containers` and
  `ssh`, inside each runtime. `cargo test -p podssh-cli --lib
  ssh::transport`: 2 passed; the test of `settled`, on paused time: the
  wait lasts until the kept task's end (2 s), at most 5 s for a task that
  never ends, and nothing with nothing kept. Planted, `settled` with no
  wait: it failed ("until the task's end", 0 ns); it passed again without
  the plant.
- The live check, in `.github/workflows/quick-tunnel-live.yml`: after
  each `podssh ssh` and after `podssh health` (refused with its new key,
  which is said before the exit, then let in), no TCP connection of the
  node to TARGET is left within 8 s. Run 41152476358 at `200ff2d`
  (2026-10-31, with T-300's): none was left after each `podssh ssh`,
  directly and through the proxy, and after `podssh health`, whose new key
  was refused and said before the exit, then let in, the facts read.
- `cargo test -p podssh-cli`: 996 passed, 0 failed, 39 ignored, in 117
  binaries.
- The review of T-300's code (2026-10-30) found `podssh pipe` with a
  listener outside `settled`, though its `ssh:` end keeps the layer's task:
  the last client's `CLOSE` never went out, and with `--keep-listening`
  the list grew by one for each client. Repaired (2026-10-31): the
  listener's run is settled, and `keep` drops the tasks that ended
  (`transport::running`). `cargo test -p podssh-cli --lib ssh::transport`:
  3 passed; planted, a list that keeps each task: the new test failed (3
  kept, not 1).

# T-339: Nothing watches the quick tunnel's pin of cloudflared, and its edge names are fixed

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 2.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`podssh node --quick-tunnel` speaks cloudflared's protocol, which has no published contract, as
cloudflared 2026.10.6 speaks it. Cloudflare supports a cloudflared for a year after the newest
release, and cloudflared's main branch already drops the features that podssh's registration
names. No job tells when cloudflared moves. The edge's two names and its port are fixed, its
roots must be exactly three, and a refusal of the edge does not say which release podssh speaks.

## Premise

- Read: the module pins cloudflared 2026.10.6 at commit 35b379a
  (`crates/podssh-relay/src/quick/mod.rs:4-7`); the registration names that release's features
  (`crates/podssh-relay/src/quick/register.rs:22-26`); cloudflared's main deprecates and filters
  them since its commit 77a79bf, in no release when it was read (`docs/design.md:271-279`; the
  audit cited `:273-279`).
- Read: two fixed regions, port 7844 and the TLS name `h2.cftunnel.com`
  (`crates/podssh-relay/src/quick/edge.rs:22-29`); the roots must give 3 anchors and no invalid
  one (`:40-44`); the API's host is fixed (`crates/podssh-relay/src/quick/api.rs:18`). The node
  registers as `podssh` and the package's version (`crates/podssh-cli/src/node_quick.rs:158-159`),
  `1.0.0-beta.2` today (`Cargo.toml:46`).
- Read: the three roots end on 2029-08-15, 2029-08-15 and 2029-11-01
  (`crates/podssh-relay/src/quick/cloudflare-roots.pem:6`, `:25`, `:52`).
- Read: cloudflared's README says "Cloudflare currently supports versions of cloudflared that are
  within one year of the most recent release", and that breaking changes "may be introduced" for
  older ones (`cloudflare/cloudflared:README.md`, read in a clone).
- Read, through fetch.web.pkgforge.dev on 2026-10-31
  (https://api.github.com/repos/cloudflare/cloudflared/releases): 2026.10.7 came on 2026-10-30, a
  day after 2026.10.6; 2026.10.3 to 2026.10.7 came in ten days.
- Read: cloudflared finds the edge by the SRV record `_v2-origintunneld._tcp.argotunnel.com`
  (`docs/design.md:203-209`), and podssh's DNS over HTTPS asks for A and AAAA only
  (`crates/podssh-ws/src/resolve.rs`, line 125 at `927eb24`).
- Read: the edge's trust is podssh's default roots, `podssh-ca.pem` next to the binary among them,
  and cloudflared's three (`crates/podssh-relay/src/quick/edge.rs:35-46`;
  `crates/podssh-ws/src/tls.rs:204-233`).
- Inferred: Cloudflare cannot map `podssh 1.0.0-beta.2` to a release of cloudflared; some filters
  block `trycloudflare.com`.

## Approach

1. A weekly workflow `upstream.yml` (and by hand), with `contents: read`, that makes no tunnel: it
   reads cloudflared's newest release and, at its tag, the SHA-256 of
   `tunnelrpc/proto/tunnelrpc.capnp`, `features/features.go`, `tlsconfig/cloudflare_ca.go` and
   `connection/protocol.go`, against a table beside the pin (the tag, the commit and the four
   sums, in `crates/podssh-relay/src/quick/`). It fails when a sum differs, or when the pin is 9
   months old, and names each file that moved. T-341 adds its jobs to the same workflow.
2. The regions: an SRV query of `_v2-origintunneld._tcp.argotunnel.com` over DNS over HTTPS (the
   JSON API takes `type=SRV`; T-344 adds the wire form), through the proxy when one is set, within
   the dial limit. Its targets and port when it gives two names under `argotunnel.com`; else the
   two names and 7844, as today, with a note in `-v`.
3. A refusal of the edge (a registration refused, or an error that podssh does not know) names the
   release that podssh speaks: the quick tunnel of cloudflared 2026.10.6.
4. The roots: three or more anchors, none invalid; doctor names the day that the first of them
   ends, as it names the age of the compiled-in roots (T-003).
5. `docs/design.md` (the quick tunnel's section) names the watch and the lookup.

## Decision

1. **The table holds a later release's sum once it is read**: a file's line
   may repeat, one accepted sum each, with the reason in a comment. The watch
   passes while each file of the newest release holds an accepted sum, and
   the pin's age alone forces its move, at 9 months. Lost: a pin that moves
   with each release, which would make each release of cloudflared a change
   of podssh; a watch that fails until the pin moves, red each week for a
   change that is the same for podssh.
2. **2026.10.7's `features/features.go` is the same for podssh**: TUN-10904
   calls the five features of the registration legacy, which the edge
   supports for each connector and no longer needs to be told, and
   cloudflared sends none of them; podssh names them on, as 2026.10.6 does,
   which the edge takes from each release that it supports. Its sum joins the
   table with that reason.
3. **The SRV record goes through the proxy**, by the JSON API of the
   resolvers of `DOH_RESOLVERS` (`podssh_ws::client::https_get_accepting`),
   as podssh reaches anything else; the fixed names stand in for any answer
   that is not two regions under `argotunnel.com` on one port.
4. **Doctor says the day of the first root, and fails nothing**, as it says
   the age of the compiled-in roots: podssh works until that day, and a FAIL
   would fail each run of an old binary whose user runs no quick tunnel.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features quick --lib quick
gh workflow run upstream.yml
```

Tests of the SRV answer: two targets under `argotunnel.com` give two regions; one, none, or a
name elsewhere gives the fixed names. Planted: one sum of the table changed; the watch fails and
names its file.

## Correction

`podssh node` has no `-v`: its lines go to stderr. The note of Approach item
2 is said there, once a run, when the fixed names stand in. The newest
release of cloudflared, 2026.10.7, holds TUN-10904 (`docs/design.md` saw it
on main only): the watch's first comparison found `features/features.go`
moved, which Decision 2 judges.

## Done

2026-10-31. Live in GitHub Actions at `4ee1053`: `upstream.yml`, run
41169460255, read 2026.10.7, the newest release, "ok each of the 4 files at
2026.10.7 holds bytes that the table knows", and its plant exited 1 and named
`features/features.go`; `quick-tunnel-live.yml` (Q43), run 41169470799, said
no fixed names, so the SRV record named the regions (`region1.v2` and
`region2.v2` under `argotunnel.com`, port 7844), registered at Cloudflare's
`iad15` over QUIC, carried 8 MiB both ways directly and through the box's
proxy, and with UDP to 7844 dropped a second node registered at `iad17` over
HTTP/2. Here:

- `crates/podssh-relay/src/quick/cloudflared-pin.txt`: the pin 2026.10.6,
  commit `35b379ac174d60a4301615defedc821de5625cef`, released 2026-10-29,
  and the SHA-256 of `tunnelrpc/proto/tunnelrpc.capnp`,
  `features/features.go`, `tlsconfig/cloudflare_ca.go` and
  `connection/protocol.go`, read in `.tmp/cloudflared` at the tag and two of
  them again from raw.githubusercontent.com through fetch.web.pkgforge.dev,
  equal; and 2026.10.7's `features/features.go` (Decision 2).
  `scripts/check-upstream.py`, on the four files of 2026.10.7 read through
  fetch.web.pkgforge.dev: exit 0; `--plant-sum features/features.go` exit 1
  and names the file; the pin 274 days old exit 1, 273 days exit 0; a file
  unread exit 2. `.github/workflows/upstream.yml`, each Monday and by hand,
  runs it and its plant.
- `podssh_ws::resolve::doh_srv` and `parse_srv` (the JSON API's `type=SRV`,
  through the proxy); `edge::find`, `edge::choose` and `edge::Edge`: both
  transports dial the regions and the port that the record names; the node
  says the fixed names' reason once a run. Tests: the parse of a record and
  of the forms that are none; two targets under `argotunnel.com` give the
  two regions in their order, while one, none, a name elsewhere, two ports,
  one target twice and three targets give the fixed names; a proxy where
  nothing listens gives the fixed names with the reason
  (`cargo test -p podssh-relay --features quick --lib quick`, 33 passed;
  `--test quick_tunnel`, 4 passed; `cargo test -p podssh-ws`, 221 passed).
  `quick-tunnel-live.yml` fails a node that said the fixed names.
- A refusal of the edge, and an answer that podssh does not read or that is
  an error, name `quick::SPEAKS`, "the quick tunnel of cloudflared
  2026.10.6", which a test ties to the table's tag.
- The roots: three or more anchors, none invalid; `edge::ROOTS_FIRST_END`,
  2029-08-15, which a test reads off the three certificates' DER (2029-08-15,
  2029-08-15, 2029-11-01); doctor's line "quick tunnel roots" says the day
  and how near it is (`cargo test -p podssh-cli --lib doctor`, 28 passed).
- Planted, each failed its test: a target outside `argotunnel.com` accepted,
  a wrong first end, a release name that is not the table's.
- `docs/design.md` (the quick tunnel) names the lookup, the watch and
  2026.10.7. Clippy with no warning; the library crates on Rust 1.89.


# T-347: `-J cf://HOST`: a Cloudflare tunnel as the first hop of a jump chain

**Source:** the study of carriers of 2026-10-31, the forward road, item 1.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A user with one host whose egress is open can publish its sshd as a Cloudflare tunnel, with no
account (`podssh node NAME --sshd --quick-tunnel`), and reach it from a cage with
`podssh ssh cf://NAME`. That host cannot yet be a jump host: `-J cf://HOST` is refused, so the
targets that it can reach still need the relay. With it, the forward road has a carrier that is not the operator's
relay, for each user with such a host. Cloudflare documents SSH through a tunnel, and the operator
allows podssh as a client of Cloudflare (`docs/decisions.md:27`).

## Premise

- Read: a `-J` hop is read by `parse_hop`; `cf://HOST` holds one colon, so it is read as the host
  `cf` with the port `//HOST`, which is refused as a port
  (`crates/podssh-cli/src/ssh/hop.rs:49-51`); `jump_hop` refuses a node only (`:59-65`).
- Read: a `cf://` destination refuses `-J`:
  `crates/podssh-cli/src/ssh/cloudflare.rs:73` says "a Cloudflare tunnel cannot be reached
  through a -J hop yet", and `docs/cli.md:129-130` says so too.
- Read: the road of a run is chosen for the first hop's host
  (`crates/podssh-cli/src/ssh/resolve.rs:318`), and each later hop runs in a `direct-tcpip`
  channel of the session before it (`crates/podssh-ssh/src/run.rs:160-167`;
  `crates/podssh-ssh/src/forward.rs:14-22`).
- Read: the `cf://` road opens the WebSocket of `cloudflared access tcp` through `HTTPS_PROXY`,
  and a node behind it greets with the resumable layer first
  (`crates/podssh-cli/src/ssh/cloudflare.rs:1-12`); a roost is a node in front of a standard
  sshd (`docs/design.md:116-119`).
- Read in the study
  (https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-cloudflared-authentication/):
  SSH through a tunnel is a documented use. A quick tunnel is for testing, with no uptime
  guarantee (`docs/design.md:181-185`).
- Inferred: a proxy that re-terminates TLS passes it when podssh trusts the proxy's CA and the
  proxy passes the upgrade; a proxy that refuses the upgrade stops it, as it stops the relay.

## Approach

1. `jump_hop` takes `cf://[user@]HOST` as the first hop of a chain: its user, and HOST, the name
   of the tunnel's rule. A `cf://` hop after the first is refused with the reason: a hop inside an
   SSH channel has no road to Cloudflare's edge.
2. The road of the run is the `cf://` road when the first hop is one: `cloudflare::transport` for
   that hop, with its refusals of `--direct`, a port, `HostName`, `-4` and `-6` as today
   (`crates/podssh-cli/src/ssh/cloudflare.rs:69-87`), and no refusal of the hops after it.
3. The first hop's host key is kept under HOST, as for a `cf://` destination; the next hops run in
   its `direct-tcpip` channels, as each hop does today. A node behind the tunnel (a roost with
   `--quick-tunnel`) carries the first hop in the layer, as for a destination.
4. The probe is the upgrade itself: a refusal names the step and the hop, as a `cf://`
   destination's does.
5. `docs/cli.md` and the manual: `-J cf://HOST` as a first hop, the refusal of a later one, and
   the recipe of a quick tunnel in front of a jump host's sshd.

## Decision

The first hop only: a later hop would need a WebSocket to Cloudflare from inside an SSH channel
(TLS and the upgrade over `direct-tcpip`), which no user has asked for. It lost to a refusal that
says why.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args
cargo test -p podssh-cli --test cloudflare_cli
```

A stand-in of the tunnel's WebSocket on the loopback in front of a test sshd, and a second sshd
behind it: `podssh ssh -J cf://HOST second` reaches the second, with the first key under HOST; a
`cf://` second hop is refused (64). Planted: the first hop's road left as the relay's; the
stand-in sees no upgrade, and the test fails. Live in `quick-tunnel-live.yml`: a roost with
`--quick-tunnel` as the jump host of a second sshd on the runner.

## Correction

The Prove's stand-in of the tunnel on the loopback is the live run instead: the jump host is the
node's own sshd behind a real quick tunnel, and the second hop the same sshd again through that
hop's `direct-tcpip` channel (`quick-tunnel-live.yml`, Actions only, Q43). The choice of the road
and the refusals are tested offline, where the road of a `cf://` first hop says nothing of the
relay and a plain first hop does.

## Done

2026-10-31: done. The live run passed at `cb30f1e` (`quick-tunnel-live.yml`, run 41180727325).

- `jump::hops` reads `cf://[user@]HOST` as the first hop of the command's own chain (not of a
  hop's `ProxyJump`), its user and HOST, and keeps HOST as the chain's tunnel; a `cf://` hop after
  it is refused with the reason. `resolve` takes `cloudflare::transport` as the road of the run for
  that hop, with its refusals of `--direct`, `-4` and `-6`, and none of the destination's port or
  `HostName`, which are the next hop's.
- Tests: a tunnel after the first hop, `--direct` and `-4` refused (64); `-p 2222 -J
  cf://me@HOST dest` ends at its road offline (255) and says nothing of the relay, where a plain
  first hop does (`cargo test -p podssh-cli --test cloudflare_cli`, 4 passed; `--test ssh_args`,
  26 passed). Planted, no hop counted as first: the test failed.
- `docs/cli.md` and the manual's note on `cf://` give the first hop, the refusal of a later one,
  and the jump host whose sshd a tunnel publishes.
- The live run (`quick-tunnel-live.yml`, run 41176392964 at `86e4b91`): `podssh ssh cf://NAME`
  direct and through the proxy each carried 8 MiB with equal digests; the jump through the same
  node's tunnel exited 64, "--client-key is for a node://NAME, iroh:TICKET or cf://HOST
  destination": the check of the channel's flags ran before the chain was read, so a `cf://`
  first hop was no podssh end. It now runs after it, and counts that hop. Tests: `--client-key`
  with `-J cf://me@HOST` reaches its road offline (255), with a plain first hop it is refused
  (64), naming the first hop of `-J`; planted, the hop not counted, the test failed;
  `cloudflare_cli` 4 passed, `iroh_cli` 4, `ssh_args` 26; clippy clean. Run 41180727325 at
  `cb30f1e`: "ok podssh ssh -J cf://NAME: the tunnel's sshd the first hop, the second through its
  channel", the first hop authenticated through the node's real quick tunnel and the second, the
  same sshd at `127.0.0.1:4022`, through its direct-tcpip channel; each other step of the run
  passed, the direct and the proxied `cf://NAME` and the node over HTTP/2 with UDP to 7844 dropped.


# T-348: The iroh road in the release binaries, and a notice when n0 refuses an old iroh

**Source:** the study of carriers of 2026-10-31, the reverse road, build order 1.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The iroh road reaches a podssh node through n0's public relays, with no relay of the operator's,
and races the pair's road (T-164). The study ranks it first of the carriers of the reverse road
that need no relay of the operator's. The release binaries do not have it, so a user who
downloads podssh has the operator's relay alone to reach a node. n0 supports the newest iroh only,
and a release binary is not updated in the field, so n0 may one day refuse its iroh, with no word
that says why.

## Premise

- Read: the release builds `podssh-cli` with no feature on each target
  (`.github/workflows/release.yml:119`, `:189`, `:256`, `:300`, `:371`); the feature `iroh` is
  off by default, and `crates/podssh-cli/Cargo.toml:28-30` says "about 200 crates, needs Rust
  1.91 and a C compiler" of it.
- Read: `docs/decisions.md` line 41 at `27b8d8f` said "iroh is a road that the user must select", and made n0's
  public relays its default until the operator runs one. The row says nothing of the release
  binaries: "off in the release" is the default of `Cargo.toml` and the build of the workflow,
  which the study reads as the operator's policy. In a build without the feature, the iroh road
  refuses with exit code 70 (`AGENTS.md:20-21`).
- Read in the study (https://docs.iroh.computer/iroh-services/relays/public): the public relays
  are "suitable for development and hobby use only", they rate-limit, and "Only the latest stable
  release of iroh is officially supported".
- Read: the armv7 job builds with Alpine's rust (`.github/workflows/release.yml:191`); whether it
  is 1.91 or later was not read (T-343 checks it in the job). The notices of the licenses are
  made for the default features (`.github/workflows/release.yml:439`); `cargo deny` checks the
  licenses and the sources with each feature (`.github/workflows/deny.yml:44-46`).
- Read: `docs/design.md:973-974` says "about 190 to 245 crates, and several megabytes" of iroh.

## Approach

1. After Q50 (a): the release builds `-p podssh-cli --features iroh` on each target, and the
   gate's step `release` builds what ships. A target that cannot build it stops the release with
   the reason; no binary ships without the road unless the release notes say so.
2. The armv7 job checks Alpine's rust against 1.91 first (T-343).
3. The notices: `cargo about` with the feature; the release notes name the road, and the size of
   each binary before and after.
4. The notice: when n0's relay refuses the client's handshake as an old version (Inferred: the
   relay's error names the protocol), podssh says that n0 serves the newest iroh only, names the
   iroh of this binary, and names `--iroh-relay URL` (T-165).
5. `scripts/release-short.sh` checks that the binary has the road: `podssh man --json` lists it,
   and an iroh destination does not exit 70.
6. A measurement from a cage through n0's relays, by the method of T-157 (Q38 allows n0's
   relays).

## Decision

The operator's ruling of 2026-10-31 (Q50, `docs/decisions.md`): the release binaries carry the iroh road, and a node and a client try n0's public relays when the user did not ask, as a fallback; the operator does not ask n0 first.

## Prove

```sh
gh workflow run release.yml --ref main   # a dry run by hand
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --features iroh-test --test iroh_road
```

Each of the eight binaries of the dry run has the road. With a relay on the loopback that refuses
the version, the notice names this binary's iroh and `--iroh-relay`. Planted: the feature left out
of one target; the check of `scripts/release-short.sh` fails on it.

## Correction

2026-10-31: `podssh man --json` names no feature of the build, so item 5's check reads the exit of
`podssh ssh iroh:x`: 64 with the road (a ticket that is no ticket, read as one), 70 without it.
Item 4's relay is asked after its connection failed, not before each dial: iroh's relay client
keeps only the status of a refusal, and a question on each dial would be one more connection to
n0 for each session that works. Item 6 moves 200 MiB in its five runs of 20 MiB each way, over
the 100 MiB of a live test that runs with its entry (`AGENTS.md`, section 6): it waits for the
checks of the release (T-251), and a short run through n0's relays from this session's host runs
now.

## Done

2026-10-31, partial: each target of the release builds `--features "$RELEASE_FEATURES"` (`iroh`),
one variable of `.github/workflows/release.yml`, as the gate's step `release` does; the notices
are made with the same features and the eight targets of the release (`about.toml`, so that a
crate of WebAssembly alone, as iroh-relay's three under the Unlicense, ships in no notice); the
armv7 job's Alpine 3.24 has rust 1.96.1, read from its index on 2026-10-31, past iroh's 1.91
(T-343 makes the job check it); `scripts/release-short.sh` checks the road, and planted on a
build without the feature it failed, naming exit 70. The notice (`podssh-iroh`'s `version.rs`):
`cargo test -p podssh-iroh` passed, iroh's own relay server taking this build's versions and
refusing `iroh-relay-v0` in its own words; `cargo test -p podssh-cli --features iroh-test --test
iroh_road` passed, a node whose relay refuses its iroh stopping in 4 s, not its 30, with the
notice; planted, the early stop removed (the node waited 34 s) and the refusal not read (no
notice), each failed the test. Live, a build with the release's features on this host, through its
proxy: a node came online on n0's relay `use1-1`, and a client reached its Dropbear through it, the
relay carrying each byte.

2026-10-31, done: the dry run of the release workflow by hand at `7e7650b` (run 41199469920)
built the eight binaries with `RELEASE_FEATURES=iroh`, and each passed the short form of the
release check on its own platform (QEMU for riscv64), its line `ok   the iroh road: iroh:x is
read as a ticket, and refused as one` included; the preview of the release matched its
`SHA256SUMS`, and its x86_64 binary passed `scripts/release-short.sh` here too. The sizes,
beta.2's and then this build's (which also carries `podssh update`, T-375): x86_64 Linux 9.6 to
14.3 MiB (+49 %), aarch64 Linux 7.5 to 11.0 (+47 %), armv7 5.6 to 8.2 (+47 %), riscv64 7.2 to
10.9 (+51 %), macOS on Apple silicon 6.2 to 8.6 (+39 %), macOS on Intel 8.1 to 11.3 (+40 %),
Windows x86-64 7.9 to 11.1 (+40 %), Windows ARM64 6.9 to 9.7 (+41 %). The release notes of the
next beta carry the table (T-309).


# T-349: A DERP link through Tailscale's tailcat relays, a second carrier of the reverse road

**Source:** the study of carriers of 2026-10-31, the reverse road, build order 2.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

The reverse road has the relay's pairs, on one provider, and the iroh road's carrier is n0.
Tailscale runs DERP relays for tailcat, which needs no account, and DERP runs over a WebSocket on
port 443. A DERP link in `podssh-relay` would be the second carrier that needs no relay of the
operator's, after n0's, with the same layer and channel above it. The study put it at M; the
adapter under the layer and the tests against derper make it L.

## Premise

- Read: a carrier of the reverse road gives a meeting point and bytes in order, and no more: the
  end-to-end channel (Noise XX, each end's Ed25519 key, a verdict before the node dials) ends the
  session on a message that is changed, dropped, repeated or reordered
  (`crates/podssh-relay/src/e2e/mod.rs:1-16`; `crates/podssh-relay/src/e2e/channel.rs:1-4`), and
  the layer resumes on any link that reads and writes
  (`crates/podssh-relay/src/session/resume.rs:143-156`).
- Read: a gap of the layer's offsets ends a link (`docs/design.md:743-746`): a carrier of packets
  that may drop needs a layer under it that sends again.
- Read: the vendored fork's client speaks DERP over a WebSocket
  (`vendor/tailscale-rs/ts_derp/src/client.rs:31-39`), seals with `crypto_box`
  (`vendor/tailscale-rs/ts_derp/Cargo.toml:24`), and takes its TLS from a crate that builds
  aws-lc-rs (`vendor/tailscale-rs/ts_tls_util/Cargo.toml:17`); `podssh-relay` has no C
  (`AGENTS.md`, section 5, rule 4).
- Read in the study: tailcat's README offers "our free rate-limited DERP relays", whose map is
  https://tailcat.dev/derpmap.json, with four hosts, `tc301a.ipn.dev` to `tc304a.ipn.dev`
  (https://github.com/tailscale/tailcat). Tailscale's post of 2026-08-31 says that tailcat has
  "no accounts", and asks for contact about other uses (https://tailscale.com/blog/tailcat).
  derper serves a WebSocket at `/derp`, a packet is 64 KiB at most, and the server drops a
  client's packets when its queue of 32 is full (tailscale/tailscale:cmd/derper/derper.go,
  tailscale/tailscale:derp/derp.go, tailscale/tailscale:derp/derpserver/derpserver.go). Who else
  may use the fleet is not stated, and Tailscale's terms were not read.
- Read: `noq` 1.4.0, the QUIC of iroh, is in the lock (`Cargo.lock:3241-3242`).

## Approach

1. After Q50 (b): a module `derp` in `podssh-relay`, behind a feature: DERP's frames and its
   handshake (the server's key, the client's info sealed with `crypto_box`), with the fork as the
   reference, over podssh-ws's WebSocket and TLS to `wss://HOST/derp`, through `HTTPS_PROXY`.
2. The key of DERP: an X25519 key derived from the node's Ed25519 key, or a second key kept beside
   it (the entry's session decides). The client finds the node by the key that it pins (T-087), at
   a home region that the node names in its ticket.
3. Under the layer, an adapter that numbers, acknowledges and sends again, with a window under the
   server's queue; or noq's streams over DERP's packets. A measurement under drops decides.
4. The road joins the race of T-164, after the iroh road and the pair's.
5. Tests against Tailscale's derper in Podman (software that podssh did not write), and short live
   runs against tailcat's fleet when Q50 allows them.

## Decision

The operator's ruling of 2026-10-31 (Q50, `docs/decisions.md`): Tailscale's tailcat fleet is an automatic fallback of the reverse road, tried when the user did not ask; the operator does not ask Tailscale first.

2026-10-31, the draft (each call with the alternatives that lost):

- The scope: items 1, 2, 3 and 5 here, in `podssh-relay`; item 4, the command line around it
  (`podssh node --derp`, `podssh ssh derp:TICKET`), the race of T-164 and the fallback that Q50
  allows a node and a client with no pair, moves to T-379. Lost: each in one entry, which is more
  than L and so two entries (`TODO/RULES.md`, "Size"): the resolver of `podssh ssh` is at 488 of
  its 500 lines, the race of the command line is behind the feature `iroh`, and T-348 moves the
  iroh road into the release binaries meanwhile. Lost too: the node's side alone here, whose
  ticket no command would dial.
- A node's DERP key: derived from the seed of its identity by HKDF-SHA256 with the label
  `podssh derp key, version 1`, so that its address stays across runs and no key does two jobs,
  as the identity's channel key is derived (`crates/podssh-relay/src/identity/mod.rs:8-11`).
  Lost: the Montgomery form of the Ed25519 key, which a client could compute from the pinned key
  alone, but which makes the signing key agree keys too, as ed25519-dalek 2.2.0's own
  documentation of `to_scalar_bytes` advises against; and a second key file beside the node's,
  one more file to make whole, when the ticket carries the DERP key either way. A client's key is
  new for each run: one derived from the client's identity would make two processes of one user
  one client connected twice, which derper's policy for duplicates disables or switches.
- The adapter: selective repeat of podssh's own (`crates/podssh-relay/src/derp/send.rs`,
  `crates/podssh-relay/src/derp/recv.rs`). Lost: noq's streams over DERP's packets, which need a
  socket of QUIC over DERP, TLS 1.3 inside it with podssh-ws's provider, and a second layer of
  sessions beside the resumable layer's; a measurement of both was not made, and the Prove
  measures the one built. A loss is found by the order of the sends, as a server keeps one
  sender's order: lost, TCP's three repeated acknowledgements, which wait for three more segments
  where the first shows the loss.
- A segment is 30 KiB at most: a packet then stays under the 32,768 bytes of one message, past
  which derper's WebSocket ends the connection. Lost: DERP's 64 KiB, which ends it; 16 KiB, half
  the bytes for the same queue of 32 packets. The window is 24 segments at most, under that queue,
  which the acknowledgements share.
- The program's name in the client's info is `podssh`, so that a server's operator can count it,
  or refuse it. Lost: no name, which hides podssh from the operator of the server; and a name of
  another program.
- A node's home is the first server of the list whose `/derp/probe` answers, in the map's order,
  as the iroh road picks its home relay (T-165). Lost: the least latency, which probes each server
  at once, four connections at the start, for a gain that the layer does not need. A client tries
  the ticket's server first, then the rest of the fleet: lost, a record of pkarr (T-350's way)
  for a fleet of four servers.
- A rate that a server names in its info is kept by waiting. Lost: Go's client's drop of what
  exceeds it, which here only makes the adapter send again.
- The tests: a stand-in DERP server in memory (`crates/podssh-relay/tests/derp_stand_in/mod.rs`),
  over pipes and with frames of its own, so that no test listens and a defect of the library's
  frames is not the stand-in's too. Lost: the library's frames in the stand-in; TLS on the
  loopback, a listener and certificates for nothing that the interop with derper does not prove.
- The interop builds derper from its tag v1.104.4, in the Go image of `images/derper/Dockerfile`,
  and runs it with its own certificate for 127.0.0.1. Lost: an image of derper of a third party,
  which Tailscale does not publish; derper's `--dev`, plain HTTP, which podssh speaks in no road.
- The live runs against tailcat's fleet are short and by hand (`--test derp_live`, 64 KiB each
  way), as Q50 lets the road use the fleet unasked and item 5 waited for Q50; no throughput run
  goes there, as tailcat refuses its own through Tailscale's relays.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features derp --test derp_link
sh scripts/interop-derp.sh   # Tailscale's derper in Podman
```

8 MiB both ways through derper with equal digests, also with 5 % of the packets dropped by a
stand-in under the adapter. Planted: the adapter's resend turned off; the test with drops fails.

## Correction

2026-10-31, read in Tailscale's source at v1.104.4 and in coder/websocket at v1.8.15, through the
services of web.pkgforge.dev (`docs/design.md`, section 8; `docs/carriers.md`, [R46] to [R48]):

- A full queue drops its oldest packet to take the new one (`sendPkt`), not the new one.
- derper upgrades the WebSocket at `/derp` only for a request that names the subprotocol `derp`,
  and coder/websocket ends the connection at a message of more than 32,768 bytes, its default
  read limit, which derper does not raise: a DERP packet of 64 KiB is not sent whole there.
- A server drops a client whose connection takes no bytes for 2 s (`DefaultTCPWiteTimeout`), so
  the reader of a connection never waits for a link.
- A packet to a key that is not on the server is dropped with no word: `PeerGone` (not here)
  answers only Tailscale's disco packets. So a client that finds no node waits for no answer,
  within a limit.
- The server's info has `TokenBucketBytesPerSecond` and `TokenBucketBytesBurst` by those names;
  the vendored fork reads them as `tokenBucketBytesPerSecond`, which serde matches in no other
  case, and never acts on them (`vendor/tailscale-rs/ts_derp/src/frame/body/server_info.rs:26-32`).

The Approach stands; item 4 moves to T-379 (the Decision).

## Done

2026-10-31: drafted (branch `draft-derp`, `35e0b44`), then merged and measured.

- `crates/podssh-relay/src/derp/`, feature `derp`: DERP's frames (`frame.rs`), its keys and
  NaCl's box (`key.rs`), a link's packets (`packet.rs`), the adapter (`send.rs`, `recv.rs`,
  `rtt.rs`), a link and its task (`link.rs`), a connection, its handshake, its reader, writer,
  pings and pacing (`conn.rs`), TLS through the proxy and the upgrade (`dial.rs`), the fleet,
  `PODSSH_DERP_SERVER`, the probe and the home (`servers.rs`), the ticket (`ticket.rs`), the
  client (`client.rs`) and the node (`far.rs`). `crypto_box` 0.9.1 with `alloc` and `salsa20`
  only, which the lock had already.
- Measured at the merge (2026-10-31). `cargo test -p podssh-relay --features derp --lib derp`
  passed 29: the frames, the boxes (the vector of PHP Sodium Compat that crypto_box 0.9.1
  carries, sealed to the same bytes), the packets, the timeout, the ticket and its base32 (RFC
  4648's vectors), and the two halves through a simulated server (8 MiB each way with no loss and
  with 5 % dropped; a tenth dropped; a slow receiver whose queue fills; a reader that stops for
  90 s). `--test derp_link` passed 4 through the stand-in: 8 MiB both ways with equal digests,
  with no loss and with 5 % dropped, each end's link with a measured round trip; a client gives up
  on a key that is not there within 6 s; a session of the layer goes on after the client's
  connection is cut.
- `sh scripts/interop-derp.sh`, Tailscale's derper v1.104.4 built from its tag in Podman on this
  cloud session's host: `derp.transfer` (8 MiB each way over one link, equal digests),
  `derp.absent` and `derp.layer` (2 MiB of a session of the layer echoed whole) passed. The script
  now gives the build of derper the bundle of `SSL_CERT_FILE` and the host's network when the proxy
  is on the loopback, as a cloud session's re-signs TLS on 127.0.0.1.
- Live, `cargo test -p podssh-relay --features derp --test derp_live -- --ignored`, from this host
  through its proxy: the node's home was tailcat's `tc301a.ipn.dev`, 64 KiB went each way with
  equal digests, and the client's link measured a round trip of 197 ms. The test now waits up to
  5 s for that measurement, as the node's acknowledgements of the last segments may still be on
  their way when the reads end; it first printed `None` for that reason.
- Planted: the loop of `Sender::poll` that sends each lost segment again, turned off: the tests
  with drops failed, `derp::arq_tests` (5 % dropped; a reader that stops) and `derp_link`'s 5 %.
- At the merge: the writer's task held the watch's guard across an await (not `Send`), and a
  link's `opened` returned a borrow of a temporary; clippy named the decoder's `next` and the
  counter of the resend loop, now `decode` and a `take` of the window's room. podssh-relay with
  `derp,blocking,quick`: 378 passed; clippy `-D warnings` clean; the library crates build with no
  C compiler with the feature, which `scripts/gate.sh` now builds, tests and checks on the minimum
  Rust.
- After the merge (`0920c54`), podssh-cli's sweep of variables failed: `PODSSH_DERP_SERVER` was
  read and not in the manual's ENVIRONMENT, and the merge had run podssh-relay's tests alone. The
  manual names it now (`crates/podssh-cli/src/man/facts/roads.rs`), with the note that no command
  takes the road before T-379; the whole workspace's tests ran again.

# T-350: A pkarr record that finds a node whose home relay changed

**Source:** the study of carriers of 2026-10-31, the reverse road, build order 3.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A client dials an iroh node by its key and the relay of its ticket. A node's home relay is the
first relay that answers, so it can change; a client with the old ticket then dials a relay where
the node is not. A signed record under the node's key, at a server of pkarr, would tell the client
where the node is now. The study put it at S; a client of pkarr through podssh's proxy may be
podssh's own, which makes it M.

## Premise

- Read: the endpoint has no address lookup: a peer is dialled by its key and its relay
  (`crates/podssh-iroh/src/endpoint.rs:4-7`, `:305-306`), as the design chose for a host with no
  DNS (`docs/design.md:985`, `:995`).
- Read: the node's key is Ed25519 and stays across its pairs, and the operator pins it by label
  (`docs/reverse.md:180-184`).
- Read in the study (https://docs.iroh.computer/connecting/dns-address-lookup): an endpoint
  publishes a signed packet to a DNS/Pkarr server over HTTP; n0's servers are free, rate-limited,
  with no guaranteed uptime, and "You're more than welcome to run production systems" on them,
  where the page of its relays says "development and hobby use only".
- Inferred: iroh's own publisher and resolver of pkarr use an HTTP client of iroh's, which may not
  take podssh's proxy (T-280 patched the relay's dial alone).

## Approach

1. After Q50 (b): the node publishes a record under its key, signed with it: its home relay's
   URL, with a short life, and again when the home relay changes; through podssh's proxy, to n0's
   server or to one that the user names.
2. A client whose ticket's relay does not answer, or does not hold the node, resolves the key
   within a time limit and tries the relay of the record. The end-to-end channel still checks the
   node's key (T-087, T-088), so a wrong record fails the session, and no more.
3. iroh's own address lookup, if a test shows that it goes through podssh's proxy; else a small
   client of pkarr in `podssh-iroh`, over podssh-ws.
4. The record is published only when the user asks for it, until the ruling of Q50 says
   otherwise.

## Decision

The operator's ruling of 2026-10-31 (Q50, `docs/decisions.md`): n0's server of pkarr may be a default, as n0's relays are a fallback.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --features test-relay --test pkarr_lookup
```

Two relays and a server of pkarr on the loopback: the node moves to the second relay, and a
client with the first ticket finds it and connects; a record signed by another key is refused.
Planted: the check of the signature skipped; the test of the other key fails.


# T-351: Roads through a cloud's own tunnel: GCP IAP TCP forwarding, then EC2 Instance Connect Endpoint

**Source:** the study of carriers of 2026-10-31, the forward road, items 4 and 5.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** done

## Problem

A user with a cloud account can reach a VM of theirs, with no public address, through the cloud's
own tunnel over a WebSocket on port 443; the VM then reaches the target, as a jump host. These
roads give the forward road a carrier that is not the operator's relay, for users with a cloud
account and no domain. Each needs the user's account and a token, and EC2 Instance Connect
Endpoint puts a credential in its URL.

## Premise

- Read in the study (https://cloud.google.com/iap/docs/using-tcp-forwarding;
  https://emile.hofsink.net/posts/iap-deep-dive/): IAP's TCP forwarding is a WebSocket to
  `wss://tunnel.cloudproxy.app/v4/connect` with a Bearer token in its header and the subprotocol
  `relay.tunnel.cloudproxy.app`; its data goes in frames of 16 KiB at most, with
  acknowledgements; it "isn't intended for bulk transfer of data", and it ends a session after an
  hour of inactivity.
- Read in the study
  (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-with-ec2-instance-connect-endpoint.html;
  aws/aws-cli:awscli/customizations/ec2instanceconnect/eicesigner.py): EC2 Instance Connect
  Endpoint takes a presigned SigV4 `wss://` URL, valid for 60 s, then raw binary frames; AWS's
  client honours `HTTPS_PROXY`; a connection lasts an hour at most, and 20 run at once.
- Read: credentials never go in URLs (`docs/architecture.md:177-182`; `docs/design.md:64`), and
  `docs/decisions.md:43` says "in a header or a 0600 file and never in a URL" of the relay's
  tokens. The presigned URL carries an access key id and a signature in its query.
- Read: the `cf://` road uses podssh-ws's WebSocket client through the proxy
  (`crates/podssh-cli/src/ssh/cloudflare.rs:237`); an RSA key signs through aws-lc-rs in the
  binary (`deny.toml`, the reason of RUSTSEC-2023-0071); `podssh cp` opens a new session before
  the relay's caps (`docs/relay.md:205-211`), as an hour of EICE would need.
- Inferred: a proxy that re-terminates TLS passes either road where it passes a WebSocket.

## Approach

1. After Q51: a road `iap://PROJECT/ZONE/INSTANCE[:PORT]` on podssh-ws's WebSocket, through
   `HTTPS_PROXY`. Its token comes from a file that the user names (private, as the relay's token
   file) and goes in its header only: a token of a service account, signed RS256 with aws-lc-rs in
   the binary crate, or a token that gcloud made, from the file.
2. IAP's frames (the connect's SID, DATA and ACK) in a module with no I/O, tested against bytes
   captured from Google's own client.
3. The probe: the connect's `CONNECT_SUCCESS_SID` within 20 s; else the step that failed is named
   (the upgrade, the token, the instance).
4. EICE second, and only if Q51 allows its URL: the presigned URL in memory only, never printed,
   new for each connection; a session that nears the hour opens a new connection, as `cp` does.
5. The manual names each road, the account that it needs and its limits.

## Decision

The operator's ruling of 2026-10-31 (Q51, `docs/decisions.md`): both roads, IAP and EICE; EICE's presigned URL may carry its credential, an exception for that URL alone, which podssh never prints or logs. They are built and tested against stand-ins of the two endpoints; the live run waits for the operator's throwaway accounts (T-376).

The draft's calls (2026-10-31), each with what lost:

- **Read in documents, not measured live.** gcloud 570.0.0 as installed on the session's host
  (googlecloudsdk/api_lib/compute/iap_tunnel_websocket.py, iap_tunnel_websocket_utils.py,
  iap_tunnel_websocket_helper.py, iap_tunnel_lightweight_websocket.py; surface/compute/start_iap_tunnel.py);
  `GoogleCloudPlatform/iap-desktop:sources/Google.Solutions.Iap/Protocol/SshRelayFormat.cs`, its
  SshRelayConstants.cs, SshRelaySession.cs and SshRelayStream.cs at master; Google's pages
  using-tcp-forwarding and oauth2/service-account; `aws/aws-cli:awscli/customizations/ec2instanceconnect/eicesigner.py`
  with its websocket.py, opentunnel.py and eicefetcher.py at v2; `boto/botocore:botocore/auth.py` at develop;
  AWS's pages connect-with-ec2-instance-connect-endpoint, eice-quotas,
  permissions-for-ec2-instance-connect-endpoint and describe-instance-connect-endpoints; and
  `awslabs/aws-c-auth:tests/aws-signing-test-suite/v4/get-vanilla/query-signature.txt` with two more cases
  of its suite. Each page and file came through fetch.web.pkgforge.dev or read.web.pkgforge.dev, after
  their `llms.txt`.
- **Captured on the session's host, with no network.** gcloud's own `IapTunnelWebSocket` ran against a TLS
  stand-in on the loopback (`--iap-tunnel-url-override`'s path in its code): its connect, its reconnect
  after a Close 4004, its data, its acknowledgements and its resend are the tests' bytes. aws-cli's own
  `InstanceConnectEndpointRequestSigner` ran on the botocore 1.34.22 that gcloud bundles, at a fixed time
  with AWS's example key: its four presigned URLs are the tests' vectors.
- **The destinations** are `iap://[user@]PROJECT/ZONE/INSTANCE[:PORT]` and
  `eice://[user@]ENDPOINT/ADDRESS[:PORT]`, the endpoint by its DNS name and the instance by its private
  address. Lost: flags of their own (`--zone`, `--project`), which every other road would refuse; the
  instance's name or id alone, found through Compute's or EC2's API, as gcloud and aws-cli find it: a second
  host, another scope of token or two more signed calls, XML and paging, for what the user can give once.
  The host key is kept under the road's name, as `node://NAME`'s is; the blocks of `ssh_config` are the
  instance's, as a node's are its label's.
- **IAP's token** comes from a file that the user names (`PODSSH_IAP_TOKEN_FILE`, else Google's own
  `GOOGLE_APPLICATION_CREDENTIALS`), read by `podssh_relay::cache::read_private`, which refuses a file that
  another user can read, as a pair file is refused. It holds a token, read again for each link; a service
  account's key, whose JWT podssh signs RS256 through aws-lc-rs and trades at `oauth2.googleapis.com` alone;
  or `authorized_user` credentials, whose refresh token gets a token. Lost: a token in a variable (Q51 names
  a token file); a self-signed JWT as the bearer, which Google takes for some APIs and documents for no
  tunnel; the metadata server, which only a VM of GCP has; workload identity federation, another flow that
  no one asked for; the well-known file of gcloud's own credentials, which `GOOGLE_APPLICATION_CREDENTIALS`
  can name. The signature is in the binary, as rule 4 of `AGENTS.md` keeps C out of the library crates:
  podssh-cli takes aws-lc-rs at the version that podssh-ssh builds, so no crate is added.
- **The session** follows gcloud and IAP Desktop: data of 16 KiB at most; an acknowledgement once more than
  twice 16 KiB came (gcloud), before data when bytes came since the last (IAP Desktop), and after 1 s with
  nothing to send (gcloud waits 2 s); an acknowledgement below the last, or above what went, ends the
  session (gcloud). A lost link, or a Close of a code that no table names, is taken up by
  `/v4/reconnect`, three times at most, with a new token (IAP Desktop tries twice; gcloud for 15 minutes).
  Lost: gcloud's end at any Close but 4004, as a proxy's or a balancer's Close would end a session that a
  new link takes up; a resend buffer with no bound, as both clients keep, for one of 8 MiB, past which a
  lost link ends the session: a stalled server cannot make podssh hold more, and a server that waits for
  more bytes before it acknowledges cannot hang it, as a send that waited for room would.
- **The end of SSH's input** ends the session as gcloud ends it, with a Close once its bytes went, and the
  server's bytes before its own Close still reach SSH for 5 s. Lost: going on receiving, as the relay's road
  does: IAP has no half-close, so a far end that waits for the end of its input would wait for ever.
- **No Ping and no read bound on IAP**, as gcloud sends none; SSH's keepalives stay on, as on `--direct`.
  The 101's subprotocol is not read: the first message must be the connect success, which proves more
  than a header, and reading the 101's headers would copy `upgrade_with` out of a client.rs at its 500
  lines.
- **EICE's URL** is signed once TLS is up, as late as can be within its 60 s, and anew for each
  connection; `maxTunnelDuration` goes only when `PODSSH_EICE_MAX_TUNNEL_DURATION` asks, as aws-cli sends
  it only when asked. The credential comes from a file alone (Q51): the JSON of `aws configure
  export-credentials`, or a shared credentials file and `AWS_PROFILE`, in `PODSSH_EICE_CREDENTIALS_FILE`,
  `AWS_SHARED_CREDENTIALS_FILE` or `~/.aws/credentials`. Lost: the variables `AWS_ACCESS_KEY_ID` and the
  rest, as Q51 names a file; `credential_process`, which would start another program; SSO and the
  instance's metadata, more flows and hosts. SigV4 is in podssh-ws, with the hmac and sha2 that it builds,
  so that it is tested with no C. The stream is the relay stream's, binary as it is, its frames taken up to
  1 MiB, as the endpoint documents none; its Pings stay, as RFC 6455 asks a Pong of the endpoint.
- **A copy before the end of a tunnel**: `podssh cp`'s meter takes a road's age limit, EICE's duration
  less a twelfth, 30 s at least, and goes on in a new tunnel, as before the relay's limits. An SSH session
  cannot move, as an sshd runs no resumable layer: it ends at the tunnel's end, with the endpoint's reason.
- **The tests reach the stand-ins through a proxy that re-terminates TLS** with the test's own CA, by
  `https_proxy` and `--ca-file`, so the binary needs no hook to reach a stand-in. Lost: a variable that
  points the road at another host, through which a token could leave for a host that is not Google's.
  The carrier's own tests, in podssh-ws's src, run over links in memory, so that no listener stands
  outside a crate's tests directory; and the feature `plain-ws` gets no connector of either road, which
  no test would use.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --lib iap
cargo test -p podssh-ws --lib eice
cargo test -p podssh-cli --lib ssh::cloud
cargo test -p podssh-cli --lib cp::link
cargo test -p podssh-cli --lib man
cargo test -p podssh-cli --test iap_cli
cargo test -p podssh-cli --test eice_cli
```

Frames captured from gcloud decode; a stand-in of the tunnel on the loopback carries a session;
a test reads the process's arguments and its output, and finds no token. Live in GitHub Actions
with a throwaway project of the operator's.

## Correction

Read at `5877a00` on 2026-10-31.

- The Source names items 4 and 5 of the forward road; in `docs/carriers.md` GCP IAP and AWS EICE are items
  2 and 3, and items 4 and 5 are WARP and Tor (T-352, T-353).
- The first bullet holds, and gcloud's own client says more: the URL's query names the target (`project`,
  `port`, `newWebsocket=True`, `zone`, `instance`, and `interface` `nic0`) and holds no credential; the
  upgrade sends `Origin: bot:iap-tunneler`; a reconnect is `/v4/reconnect` with the session's id, the bytes
  received and the zone; gcloud takes a session up after a Close 4004 and after a link lost with no Close.
- The second bullet holds; aws-cli reads `HTTP_PROXY` before `HTTPS_PROXY`, in upper case alone, and
  `NO_PROXY` by a substring; podssh reads its own proxy variables, as on each road.
- The fourth bullet: aws-lc-rs was podssh-ssh's dependency, not the binary crate's; podssh-cli takes it now,
  the same version. `podssh cp` opened a new session before the relay's caps alone: its meter applied the
  budgets to a relay session and never spent one of another road (`Meter::left` of
  crates/podssh-cli/src/cp/link.rs, lines 56-63 at `5877a00`), so the meter now takes a road's age limit too.

## Done

2026-10-31: drafted in the worktree `cloud` (branch `draft-cloud`, `058d364`), then merged and
measured; the live run waits for the operator's throwaway accounts (T-376), as Q51 rules.

- IAP: the messages (`crates/podssh-ws/src/iap/frame.rs`), the flow (`crates/podssh-ws/src/iap/flow.rs`), the
  close codes (`crates/podssh-ws/src/iap/close.rs`), the upgrade (`crates/podssh-ws/src/iap/mod.rs`) and the
  carriage with its reconnect (`crates/podssh-ws/src/iap/carry.rs`). `cargo test -p podssh-ws --lib iap`:
  22 passed.
- EICE: SigV4 (`crates/podssh-ws/src/eice/sigv4.rs`) and the road (`crates/podssh-ws/src/eice/mod.rs`).
  `cargo test -p podssh-ws --lib eice`: 11 passed (aws-c-auth's three vectors and aws-cli's four
  URLs).
- The command line: `crates/podssh-cli/src/ssh/cloud.rs` and its directory (the destinations, the token
  of Google, the credential of AWS, the stream that says the road's end, `podssh proxy`), `-J` with a
  cloud's tunnel first, and the copy's meter. `cargo test -p podssh-cli --lib ssh::cloud`, 19 passed,
  and `--lib cp::link`, 2. The manual's variables and notes: `--lib man`, 55 passed.
- Through the stand-in proxy that re-terminates TLS: `cargo test -p podssh-cli --test iap_cli`, 6
  passed; `--test eice_cli`, 5.
- At the merge, the test of a session taken up on a new link failed 8 runs in 20: `up` sent an
  acknowledgement before the bytes that SSH had just given, and a link that broke on it returned
  before those bytes were kept, so the new link never sent them. They are kept first now
  (`crates/podssh-ws/src/iap/carry.rs`), the order on the wire unchanged: 40 runs of 40 passed. clippy
  named a `from_file` with `self`, now `read_file`, and an array of bytes in a test.
- Planted: the token printed on stderr where its file is read: three tests of `iap_cli` failed,
  each naming the token shown. The workspace: 2539 passed; clippy `-D warnings` clean.
- After the merge (`68314c6`), the gate's steps ssh, ts and iroh failed (run 41209696320): the
  tests of `iap_cli` and `eice_cli` left their scratch directories in the temporary directory.
  `scratch` gives a guard now that removes its directory as the test ends, passed or failed; in a
  temporary directory of its own, podssh-cli's tests left nothing, and all passed.
- Waits: the format and the Unix-only tests in the build image (T-251); the live run with the
  operator's throwaway accounts (T-376).


# T-352: WARP's MASQUE road over HTTP/2

**Source:** the study of carriers of 2026-10-31, the forward road, item 2; GitHub #63 (Nemo-010,
2026-10-31), its Option 1, and its first comment, with a tester's measurements.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

WARP is the one carrier that the study found that reaches any target with no setup and no
account: Cloudflare's own network goes to the target. Over HTTP/2 on port 443 it could serve a
host whose proxy allows a CONNECT to an IP literal, where the operator's relay is down or blocked.
Its API is closed, its open clients pose as Cloudflare's app, and a proxy that re-terminates TLS
breaks it. WARP and Tor, the study's items 2 and 3, are two entries, as each is L; Tor is
T-353.

## Premise

- Read in the study (https://github.com/Diniboy1123/usque; its `internal/consts.go` and
  `api/cloudflare.go`): the registration is anonymous, `POST /v0a4471/reg` with no e-mail, but the
  open client sends the headers of "WARP for Android" and a random Android serial. It speaks
  connect-ip over HTTP/2 to 162.159.198.2:443, a port that Cloudflare calls "required for HTTP/2
  fallback"
  (https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/).
- Read in the study (usque's `api/masque.go`): the client pins the endpoint's key and presents a
  client certificate, so a proxy that re-terminates TLS breaks it; the names of MASQUE had no A
  record on 2026-10-31, so a CONNECT names the IP literal.
- Read: Cloudflare's Application Terms license "the Application", forbid to "modify, decompile,
  reverse engineer" it, and let Cloudflare "block certain kinds of usage"
  (https://www.cloudflare.com/application/terms/, last updated 2024-10-18).
- Read: podssh-ws refuses a caller's ALPN and offers no client certificate
  (`crates/podssh-ws/src/tls.rs:85-96`, `:315-318`); the WebSocket over HTTP/2 is T-321, which
  waits for the relay.
- Read in the study: with no IP stack, usque's L4 mode runs over QUIC only
  (https://github.com/Diniboy1123/usque/wiki/L4-proxy-mode); over HTTP/2 a client needs one.
  smoltcp is pure Rust (https://crates.io/crates/smoltcp), and Cloudflare says that it "does not
  support modern TCP features" (https://blog.cloudflare.com/faster-sase-proxy-mode-quic/).
  usque-rs takes quiche, whose BoringSSL is C (https://github.com/Diniboy1123/usque-rs).
- Read in the study: a variant is the user's own Cloudflare One organization, free under 50 users,
  with a headless enrolment by a service token
  (https://developers.cloudflare.com/cloudflare-one/tutorials/deploy-client-headless-linux/;
  https://www.cloudflare.com/zero-trust/products/access).
- Read in GitHub #63's first comment (a tester's run of `cfrs`, a client in Rust, on 2026-10-31;
  not measured here): the registration is a `POST` to `api.cloudflareclient.com/v0a5641/reg` with
  the headers of "WARP for Android", then a `PATCH` of the device with a P-256 key and the tunnel
  type `masque`, whose answer gives the endpoint's key and its address; the edge takes TLS 1.3
  with ALPN `h2` and the name `consumer-masque.cloudflareclient.com`, then a CONNECT with
  `cf-connect-proto: cf-connect-ip`; a capsule of type 0 holds a bare IP packet, with no context
  ID, where RFC 9484 has one; the endpoint's key is the key of its certificate, whose chain no
  public root signs, and the client's certificate is self-signed over the key of the `PATCH`.

## Approach

1. After Q52, a trial in a feature crate (`podssh-warp`): the registration; TLS with ALPN `h2`,
   the client certificate and the pinned key, in its own rustls configuration outside
   podssh-ws's rules; connect-ip with its capsules over HTTP/2's extended CONNECT; and smoltcp
   for TCP inside.
2. The probe: a CONNECT to the IP literal through the proxy, then the handshake against the pinned
   key; a proxy that re-terminates TLS is named, and the road is not tried again in the run.
3. The user's own organization first, with a service token from a file, if Q52 allows only that.
4. A measurement of throughput and of a session's life beside the forward road, by the method of
   T-157.
5. The device's record and its key are kept in a private file of the cache directory (T-243) and
   used again: a registration at each start spends a device (#63's first comment).

## Decision

The operator's ruling of 2026-10-31 (Q52, `docs/decisions.md`): the WARP road is allowed; its live test may run in GitHub Actions and on a session's own host.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-warp
```

Tests against capsules and frames captured from usque; live runs in GitHub Actions only, short
ones.


# T-353: Tor through Arti, in a feature crate

**Source:** the study of carriers of 2026-10-31, the forward road, item 3; GitHub #63 (Nemo-010,
2026-10-31), its Option 2.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

Tor is run by volunteers, needs no account, and its exits accept port 22. Through Arti it could be
an anonymous fallback of the forward road, slow, where the operator's relay is down or blocked.
Arti brings C, as the features `ts` and `iroh` do.

## Premise

- Read in the study (https://docs.rs/arti-client/latest/arti_client/): arti-client is 0.47, not
  1.x; its default compression needs C, it keeps its state in SQLite (C), and its pluggable
  transports are other programs. Inferred: `TorClientBuilder` has no hook for a transport.
- Read in the study (zydou/arti:CHANGELOG.md, a mirror of Tor's repository;
  zydou/arti:crates/arti/src/arti-example-config.toml): from 2.2.0, Arti dials out through an HTTP
  CONNECT proxy, whose address must be an IP literal.
- Read: the measured cage allows CONNECT to ports 443, 80 and 8443 only
  (`docs/target-environment.md:21`), so only Tor relays on those ports could be first hops;
  whether Arti can be held to them was not read.
- Read in the study (https://bridges.torproject.org/moat/circumvention/builtin;
  https://www.bamsoftware.com/papers/fronting/): meek_lite fronts through CDN77 with POST
  requests, which a proxy that refuses the upgrade would pass (Inferred); WebTunnel is a
  "WebSocket-like HTTPS connection", but no built-in bridge uses it; Snowflake's built-in line
  names STUN servers, so it needs UDP (Inferred: no road from a cage).
- Read in the study (https://manpages.debian.org/testing/tor/torrc.5.en.html): the default exit
  policy accepts port 22. Inferred: some targets refuse Tor's exits.
- Read: podssh starts no program that the user did not name (`AGENTS.md`, section 5, rule 3), so
  a transport must run in podssh's process; podssh-ws does CONNECT, TLS and the upgrade already.
  C in a feature crate has a precedent in `ts` and `iroh` (`crates/podssh-cli/Cargo.toml:23-31`).
- Read in GitHub #63 (a tester's reading and count of 2026-10-31; not verified here): Arti's
  `reachable_addrs` holds its first hops to the ports that it lists, such as 443, 80 and 8443; 919
  of the 2,893 exits running then accepted port 22 (Onionoo's details). Inferred: Arti gives a
  stream for each target, so this road needs no TCP/IP stack in the process, which #63 counts as a
  need of both its options.

## Approach

1. After Q52, a feature crate `podssh-tor`, as `podssh-iroh` is one: arti-client with its HTTP
   CONNECT proxy (podssh resolves the proxy's name to an IP literal first), its first hops held
   to the ports that a probe of the proxy allows, and its state in podssh's cache directory
   (T-243).
2. meek, then WebTunnel, written in podssh-ws, under a runtime of `tor-rtcompat` that podssh
   gives, so that a bridge needs no other program.
3. A road with the time limits of each road; doctor says whether Tor bootstraps through the proxy,
   and in how long.
4. A measurement of the time to the first byte and of throughput, by the method of T-157.

## Decision

The operator's ruling of 2026-10-31 (Q52, `docs/decisions.md`): Tor through Arti, as a feature crate `podssh-tor` with the C of `arti-client`, as `podssh-iroh` is one.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-tor
cargo test -p podssh-cli --features tor --test tor_road -- --ignored   # live, through the box's proxy
```

Through the box's proxy, which allows the cage's ports alone: Tor bootstraps, and a session
through it gets GitHub's SSH banner. Planted: the first hops not held to the proxy's ports; the
bootstrap through the box fails.

# T-376: The live run of the roads through a cloud's own tunnel (T-351)

**Source:** the operator's answer of 2026-10-31 to the live part of T-351: stand-ins first.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** blocked

## Problem

T-351 builds its roads, GCP IAP's TCP forwarding and AWS's EC2 Instance Connect Endpoint,
against stand-ins of their endpoints. Nothing shows that they reach a real VM through a real
tunnel until a run against the clouds.

## Premise

- Read: the operator allowed both roads and asked for stand-ins first, the live run to wait for
  accounts (`docs/decisions.md:16`).

## Approach

1. With the operator's throwaway GCP project (one small VM behind IAP) and AWS account (one
   instance and an EICE endpoint), their credential files in `.env/`, used by their paths only:
   `podssh ssh` through each road to the VM, a session and a copy of 1 MiB.
2. Delete what the run made; record the run in `docs/STATUS.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cloud_tunnels_live -- --ignored --test-threads 1
```

Each road carries a session to its VM and a copy with equal digests; the credentials appear in no
output, and EICE's presigned URL in no log.

## Blocker

The operator: a throwaway GCP project with a VM behind IAP, and an AWS account with an instance
and an EICE endpoint, their credential files in `.env/`.

# T-359: The iroh road takes UDP on a bind alone, and `doctor` says that it may go direct with nothing sent

**Source:** GitHub #70 (Nemo-010, 2026-10-31).
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The iroh road gives its endpoint UDP sockets when a UDP socket binds on this host; it sends
nothing to learn whether a datagram leaves. A host that allows the bind and drops UDP further on
gets the sockets, and probes from them that never arrive, and `doctor` says that the road "may go
direct". `PODSSH_IROH_UDP=off` is for such a host, but only a user who knows to set it has it. A
capability is probed before it is used, and a bind is not what a direct path uses. P2, not P1:
the code is in a build with the feature `iroh` alone, and `TODO/INDEX.md:24` says "A defect in
code that no command of the default build uses is P2 at most".

## Premise

- Read: the probe binds a UDP socket to port 0 and drops it, and
  `crates/podssh-iroh/src/probe.rs` lines 9-10 at `925c94b` say "Nothing is sent"; the endpoint
  adds `0.0.0.0:0` and `[::]:0`, not required, when the probe binds
  (`crates/podssh-iroh/src/endpoint.rs` lines 222-227 at `925c94b`).
  T-162 chose this probe (`TODO/roads.md:50-52`).
- Read: `crates/podssh-iroh/src/endpoint.rs` lines 71-74 at `925c94b` say "as on a host whose
  UDP is refused further on than the probe sees" of `PODSSH_IROH_UDP=off`, and the manual says
  that "UDP is used when a socket binds" (`crates/podssh-cli/src/man/facts.rs` lines 273-274 at
  `925c94b`).
- Read: doctor's two answers are `ok`: "the iroh road may go direct" after a bind, and "the iroh
  road then uses its relay alone" after a refusal (`crates/podssh-cli/src/doctor/iroh.rs` lines
  12-18 at `925c94b`), in a build with the feature only
  (`crates/podssh-cli/src/doctor/mod.rs:113-114`). The refusal's
  `ok` is doctor's rule, as the relay alone is a road that works; the bind's "may go direct" is
  not measured.
- Read, in iroh 1.4.1 (the local cargo registry, `src/net_report/report.rs`): iroh's report of
  the network holds `udp_v4` and `udp_v6`, "A QAD IPv4 round trip completed", QAD being QUIC
  address discovery against a relay, on the relay's port 7842
  (`vendor/iroh-relay/src/defaults.rs:3-7`). The report is public behind iroh's feature
  `unstable-net-report` (`Endpoint::net_report`), and iroh's test relay runs QAD when it is asked
  to (`run_relay_server_with`, in iroh's `src/test_utils.rs`). So a datagram that came back from
  the road's own relay is in reach.
- Read: the quick tunnel's QUIC does not take this probe, so the issue's "one bind decides two
  roads" is wrong. T-301's Approach item 1 said "After a UDP probe (the iroh road's)"
  (`TODO/roads.md:2020`); its Decision took QUIC only where no proxy is set, on the connection's
  own socket (`TODO/roads.md:2052-2059`), and the QUIC handshake, bounded at 5 s, is its probe:
  QUIC that fails gives way to HTTP/2 for the run (`crates/podssh-cli/src/node_quick.rs:161-163`,
  `:276-295`; `crates/podssh-relay/src/quick/quic.rs:32`). Its cost on a host that drops UDP is
  one handshake a run, as its Decision item 5 chose (`TODO/roads.md:2060-2064`). doctor says
  nothing of it in the default build, where the quick tunnel is.
- Read: the measured cage refuses UDP (`docs/target-environment.md:23`), and the box does too
  (`scripts/box/seccomp.json:11-30`): there the probe is right. Inferred: it is wrong on a host
  that allows a UDP socket and drops its datagrams, as a network whose way out is a proxy can.
- Inferred, not measured: iroh dials a peer that it knows by its key and relay alone
  (`crates/podssh-iroh/src/endpoint.rs:4-5`) over the relay first, and tries direct paths beside
  it; so on a host that drops UDP the cost is probes that never arrive and a report that waits
  for them, not a wait before the relay. `-v` says at a session's end which path carried it
  (T-335).

## Approach

1. The probe has three answers: `Answered`, a QAD round trip to the road's home relay came back
   within 3 s; `Refused`, the UDP socket did not bind; `Unknown`, it bound and nothing came back
   in time.
2. No UDP for a session before an answer: the endpoint binds with its UDP sockets not required,
   as today, and dials nothing until its first report of the network, 3 s at most. A report with
   a round trip keeps it; one without closes it, and an endpoint with no UDP takes its place. A
   node's endpoint does the same before it serves. The work reads iroh 1.4.1 for how the first
   report is awaited (`Endpoint::net_report`).
3. `PODSSH_IROH_UDP=off` skips the probe, as today; `PODSSH_IROH_UDP=on` takes UDP on a bind
   alone, as before this entry, for a relay that runs no QAD.
4. doctor: `bind UDP` says only what a bind shows. A new line, `UDP out`, gives the answer and
   its time: with the feature, the QAD round trip to the home relay; in each build where no proxy
   is set, a QUIC handshake to the quick tunnel's edge as `podssh node --quick-tunnel` makes it
   (`crates/podssh-relay/src/quick/quic.rs:125-145`), and with a proxy set, that the quick tunnel
   takes HTTP/2. Each answer is `ok`, as a road with no UDP works; a home relay that does not
   answer is already `FAIL` (`crates/podssh-cli/src/doctor/iroh.rs:83-89`).
5. `-v` says which answer the road took. The manual's `PODSSH_IROH_UDP`, `docs/design.md`
   (section 7), `docs/architecture.md` (rule 3) and `SECURITY.md` say that the iroh road takes UDP
   after a datagram came back, not after a socket binds.

## Decision

1. The datagram that decides is QAD's, to the road's own relay: it is what a direct path needs,
   UDP out and back, to a server that the road already reaches. Lost: a STUN Binding to a server
   that the tree does not name, which is a new host whose answer says nothing of the relay's; a
   datagram to the peer, which is not known before the dial.
2. The wait is 3 s at each start on a host that drops UDP. Lost: a cache of the answer for each
   network, as a network can change under the same address; the race of T-164 already hides the
   wait where the reverse road is there, and `PODSSH_IROH_UDP=off` takes it away.
3. UDP beside a proxy does not change: the operator accepted the iroh road's UDP after a probe
   (`docs/architecture.md:155-159`), and the quick tunnel's narrower rule, no QUIC where a proxy
   is set (T-301), stays its own.
4. Two lines in doctor, not one: `iroh UDP out` (the round trip to the home relay, in the section
   `iroh`) and `UDP out` (the quick tunnel's edge, in each build), as they measure two servers on
   two ports, 7842 and 7844, and a host can let one through and drop the other. Lost: one line
   with two answers, which reads as one fact.
5. The endpoint that gave up on UDP is made again, with the same key, where the first one is
   closed: iroh 1.4.1 has no call that takes the UDP transports away from an endpoint that is
   bound (its builder's `clear_ip_transports` acts before the bind alone). The key is the one
   that a node's ticket and a node's allowlist name. Lost: the first endpoint kept with UDP that
   iroh would go on probing, which is the defect.
6. iroh's range is `>=1.4.1, <1.5` in `podssh-iroh` and `podssh-cli`: the report of the network is
   behind iroh's feature `unstable-net-report`, outside its semver, so a minor version may change
   it. Lost: the range `>=1.1, <2`, under which `cargo update` could take such a version and the
   build would break, not the update be read.
7. doctor's handshake with the quick tunnel's edge tries the first address of each family of each
   region at once (`podssh_relay::quick::quic::handshake`), where the node tries them in turn
   (`connect_edge`): the answer is the same fact, whether QUIC reaches the edge, within the 5 s of
   one handshake. Lost: the node's own order, under which a host that drops UDP waits 5 s for
   each address, up to 20 s for doctor's line.
8. The handshake closes at once, with no stream: nothing is registered at the edge, and no tunnel
   is made. Lost: a registration, which would make a tunnel for doctor alone.
9. The handshake with the edge is made with `--full` alone, where Approach item 4 has it in each
   run with no proxy set: the edge is Cloudflare's, a server that doctor reached in no run before,
   where the manual says that doctor reaches the relay hosts and, through the relay, github.com;
   and each test of doctor that runs its network checks would reach it, from any host, this
   session's among them, where Q43 keeps Cloudflare's edge to Actions. `--full` already adds the
   check that goes further (the login). With a proxy set, each run says that the node takes HTTP/2,
   which needs nothing sent; with none, a run without `--full` says that the line was not probed and
   how to probe it. Lost: the handshake in each run, as the Approach had it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --lib probe
cargo test -p podssh-iroh -p podssh-cli --features podssh-cli/iroh-test
cargo test -p podssh-cli --lib doctor
```

With iroh's relay server on the loopback and its QAD on: `Answered`, and the endpoint keeps its
UDP sockets (`Endpoint::bound_sockets`). The same relay with its QAD port behind a forwarder of
the test that reads and never answers: `Unknown` within the bound, and the endpoint has no UDP
socket. A refused bind, planted: `Refused`. Planted: the bind-only probe back; the test of the
silent port fails, as the endpoint keeps its UDP sockets. In the box, where UDP is refused,
doctor's `UDP out` says so; a box that allows UDP and drops it waits for T-251.

## Correction

2026-10-31: the bound of the wait is 6 s (`crates/podssh-iroh/src/probe.rs`, `REPORT_LIMIT`), not
the 3 s of Approach item 2. iroh 1.4.1 publishes its first report once its QUIC address discovery
probes have ended, each within 3 s (its `PROBES_TIMEOUT`), and its HTTPS probes, which go through
the proxy, within 5 s (its `TIMEOUT`); a host with an IPv6 address and no IPv6 route waits the
3 s of its IPv6 probe even where IPv4 answers. A bound of 3 s would take such a host, and a slow
proxy, for one that drops UDP. The wait on a host that drops UDP stays the 3 s of Decision item
2, as iroh's own limit gives it: 3003 ms against n0's relay on this session's host.

## Done

2026-10-31: the iroh road keeps UDP only after a datagram came back from its home relay, and
doctor's `bind UDP`, `iroh UDP out` and `UDP out` say what each measures; live from Actions
against Cloudflare's edge.

- `podssh_iroh::endpoint::open` gives the endpoint and the probe's answer: `Answered` (a round trip
  of QUIC address discovery to the home relay in the first report, within 6 s), `Refused` (no UDP
  socket binds), `Unknown` (bound, and nothing came back), `BindOnly` (`PODSSH_IROH_UDP=on`) and
  `Off`. With no round trip, the endpoint is closed and made again with no UDP and its key, before
  it dials or serves. `podssh ssh` says the answer with `-v`, and a node at its start.
- Tests (`crates/podssh-iroh/src/endpoint_udp_tests.rs`, against iroh's relay server on the
  loopback with its QUIC address discovery on): `Answered`, with the UDP sockets kept
  (`Endpoint::bound_sockets`); the discovery's port behind a socket of the test that reads and
  never answers: `Unknown` in about 3 s, datagrams read, no UDP socket, the same key, and online
  through the relay alone; a refused bind, planted: `Refused`, no UDP socket; `on` with no wait,
  and `off`. Planted: the bind-only probe back, the test of the silent port failed ("a port that
  never answers gave BindOnly"); the answer kept with the UDP endpoint, it failed ("the endpoint
  kept UDP that never came back"). `crates/podssh-cli/tests/iroh_road.rs`: the node says that its
  relay carries each byte, and `-v` says the road's answer; planted, each line taken away, the test
  failed. Its live test of doctor: `bind UDP` claims nothing direct, and `iroh UDP out` is `ok`.
- `cargo test -p podssh-iroh -p podssh-cli --features podssh-cli/iroh-test`: 1048 passed;
  `cargo test -p podssh-cli --lib doctor`: 33 passed; clippy `-D warnings` with the features, and
  rustfmt: clean.
- Live, this session's host (a UDP socket binds; the way out is the session's HTTPS proxy):
  `podssh doctor` with the feature said "bind UDP: bound 0.0.0.0:39130 and closed it, sending
  nothing", the four relays of n0 answered `/ping`, and "iroh UDP out: a UDP socket binds, and no
  QUIC address discovery to the home relay came back within 3003 ms, so the relay carries each
  byte". Before this entry, the same host read "the iroh road may go direct".
- doctor's `UDP out` (part 2), in each build: with a proxy set, that the node takes HTTP/2 and
  sends no UDP; else, with `--full` (Decision item 9), a QUIC handshake with the quick tunnel's
  edge, as the node's first try makes it, closed at once with no stream, and without it, that the
  line was not probed and that `--full` probes it. Against the stand-in edge of
  `crates/podssh-relay/tests/quick_tunnel_quic.rs`: the handshake answers and the edge sees the
  connection closed with no stream; a port that answers nothing: "no region of the edge answered
  over QUIC", in 5 s; a silent region beside one that answers: the answer, within the 5 s (Linux,
  where 127/8 is the loopback). Planted, each answer awaited before the first is taken: the last
  test failed on its time. The words of each answer (`doctor::quick`), 34 passed with doctor's
  others. Here, with the session's proxy set: "UDP out: a proxy is set, and no proxy carries UDP,
  so podssh node --quick-tunnel takes HTTP/2 and sends no UDP". The flag's help, the MCP tool's
  `full`, the manual's notes and `docs/cli.md` say it; `--test flag_table --test man_page --test
  doctor --test mcp` passed. Live, `quick-tunnel-live.yml` (run 41190476795 at b5b3398, Q43):
  `doctor --full` said "UDP out: QUIC to the quick tunnel's edge at 198.41.192.167:7844 answered in
  17 ms, so podssh node --quick-tunnel takes QUIC"; with UDP to 7844 dropped, "no region of the
  edge answered over QUIC: region1.v2.argotunnel.com 198.41.192.57:7844: no answer over QUIC
  within 5 s; ..." for its four addresses, IPv4 and IPv6 of both regions, "so podssh node
  --quick-tunnel takes HTTP/2"; each other step of the run passed.
- Found on the way, in T-301's loop over QUIC: a close or a silence of the connection could read
  as a control stream that ended (the test of the edge's close and silence, one run in six); and a
  handshake's timeout had two sets of words. Both repaired (T-301's Done).
- The box (UDP refused) and a box that drops UDP wait for T-251.

# T-363: The direct road is never tried after the relay hosts fail, though the road table says that a probe chooses it

**Source:** GitHub #72 (Nemo-010, 2026-10-31); `docs/design.md:51`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The road table gives the direct road as the second road to a public sshd, when a probe shows
that it works; no code tries it. When each relay host fails, `podssh ssh` ends, also where a
direct connection, or a CONNECT through the host's proxy, would reach the server. The relay's
hosts share one provider and one domain, so the direct road is the one road to a public sshd that
does not depend on them.

## Premise

- Read: `Transport::Direct` comes from `--direct` alone
  (`crates/podssh-cli/src/ssh/resolve.rs`, lines 340-346 at `4e2010e`), and else the relay (lines 348-371 at `4e2010e`); its other
  uses are a label (`crates/podssh-cli/src/ssh/mod.rs:197`), the dial
  (`crates/podssh-cli/src/ssh/transport.rs:221-265`) and a check of `--upgrade`
  (`crates/podssh-cli/src/ssh/upgrade.rs:59`). The issue's citation of
  the arm began two lines early; it is at `crates/podssh-cli/src/ssh/resolve.rs:348-354`.
- Read: `docs/design.md:45` says "podssh tries the roads in this order"; for a public sshd, the
  forward road comes first, then the direct road (`docs/design.md:51`), which at `8554930` said
  "`--direct`, or when a probe shows it works"; the triage of GitHub #69 to #72 named this entry
  there.
- Read: rule 2 of `AGENTS.md` allows a second connection at once for a race between relay hosts,
  and for the split HTTP road (`AGENTS.md:249-257`); a race of the forward and the direct road is
  neither.
- Read: the direct dial goes through `HTTPS_PROXY` when it is set, with the relay's step limit of
  20 s (`crates/podssh-cli/src/ssh/transport.rs:286-300`, `crates/podssh-relay/src/open.rs:30`),
  and names a proxy that takes the CONNECT and sends nothing back (T-317). doctor reads the
  server's version line on port 22, straight out or through the proxy, to say whether plain ssh
  can leave (`crates/podssh-cli/src/doctor/net.rs:184-199`, `:201-282`).
- Read: `cp`, `each`, `job`, `health`, `containers`, `ping` and the `ssh:` address of `pipe` reach
  their server through the same function as `podssh ssh`
  (`crates/podssh-cli/src/ssh/transport.rs:154-158`; `crates/podssh-cli/src/cp/link.rs`,
  `crates/podssh-cli/src/each/host.rs`).
- Read: on the hosts that podssh is built for, the proxy refuses port 22 and a direct dial is
  dropped with no answer (`docs/target-environment.md:21-22`); a cloud container's proxy takes
  `CONNECT github.com:22` and carries no SSH (`docs/target-environment.md:57-66`; the issue cited
  `:66-73`).
- Read: each road of the release binaries but `--direct` depends on Cloudflare and on one domain
  (`docs/carriers.md:17-19`; T-346).
- Read: the opener tries the relay hosts in turn, and stops at once on a failure that each host
  would repeat (`crates/podssh-relay/src/open.rs:1-14`).

## Approach

1. When no road is named (no `--direct`, no `--relay-host` and no `PODSSH_RELAY`, no `node://`,
   `iroh:` or `cf://` destination) and no relay host opened a session, podssh tries the direct
   road once: the dial of `--direct`, then the server's version line within 10 s, by the check of
   doctor's `no_ssh_banner`, shared; the bytes that it read go to russh first. Before the dial,
   one line says that the relay hosts failed and that podssh tries HOST:PORT directly, through the
   proxy when one is set.
2. `--direct` stays the direct road alone, and a relay that the user names stays the relay alone:
   neither falls back. `PODSSH_DIRECT=no`, and its key in the settings file (T-048), turns the
   fallback off.
3. When both fail, the lines name both roads, each with its error and its time, and the exit is
   the relay's, as today.
4. The first hop of `-J`, and each command that reaches its server through the same function, as
   in the Premise; `podssh proxy`, which has no direct road, does not change.
5. `-v` names the road that carried the session. The manual (`--direct` and the variables),
   `docs/cli.md`, `docs/relay.md` and the row of `docs/design.md:51` say so.

## Decision

1. The order is the table's: the forward road, then the direct road. The issue's order, the
   direct road first with a bound of 8 s, lost: where podssh is built for, a direct dial is dropped
   with no answer (`docs/target-environment.md:22`), so each run there would wait out the bound
   before the relay that works.
2. A race of the two roads lost: no exception of rule 2 of `AGENTS.md` covers it, so a race would
   be the operator's to allow; a road that follows a failure needs no ruling.
3. The probe is the dial that carries the session, and the server's version line on it, never
   another port or protocol (the issue's ask 3); a CONNECT that the proxy takes and that carries no
   SSH is no road (T-317).
4. The fallback is on by default, as the table gives it. Through a proxy, its CONNECT names the
   target, which the forward road's does not: the line before the dial says so, and
   `PODSSH_DIRECT=no` prevents it. Lost: off by default, which keeps the road of the table from
   each user who does not know of it.

2026-10-31, the draft (each call with the alternatives that lost):

5. The fallback is in the one function that reaches a first hop (`reach_skipping` of
   `crates/podssh-cli/src/ssh/transport.rs`), after the relay's opener failed, so that each command
   of the Premise has it with no change of its own. Lost: a fallback in `podssh ssh`'s own run,
   which `cp`, `each` and the others would not have.
6. With `-4` or `-6` the relay alone: the direct road cannot keep the family that the user asked
   for. Offline (`PODSSH_OFFLINE`), the relay alone too. `--relay-addr` names no relay: it gives
   an address of the built-in one, which falls back as before. Lost: a fallback that drops the
   family with a note, which runs a road that the user's flag ruled out.
7. The version line is read on the dial within 10 s, by doctor's check, now shared
   (`crates/podssh-cli/src/ssh/banner.rs`): one read of up to 4 KiB, whose bytes go to russh first
   (`Prefixed`). Lost: a peek that leaves the bytes in the socket, which a proxy's stream through
   podssh-ws does not offer, and russh's own banner wait, which gives no word of a proxy that
   intercepts TLS before its own limit.
8. The words: one line before the dial (the relay's time, the target, the proxy whose CONNECT names
   it, and the switch); with `-v`, the relay's own lines too, and the road that carried the session.
   When both fail, the relay's lines as before, then one line of both roads with their times; the
   exit is the relay's. Lost: the relay's lines as errors before a dial that then works, which reads
   as a failed run.
9. The switch has a key of the settings file, `Direct yes|no`, below the variable, checked when the
   file is read (78), as `RelayFailover` is. The fallback's one dial is plain TCP when
   `PODSSH_MPTCP` holds a bad word, as the relay's road never reads it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test direct_fallback
cargo test -p podssh-cli --lib ssh::transport
```

Through a stand-in relay that refuses each host, and a stand-in SSH server on the loopback:
`podssh ssh` with no `--direct` logs in over the direct road, and says that it fell back; with
`--direct` and the server's port closed, it fails and does not fall back; with `--relay-host`, or
with `PODSSH_DIRECT=no`, a failing relay ends the run; when both fail, the lines name both roads
and their times. A proxy of the test that takes the CONNECT and sends nothing: the fallback ends
with the proxy named. Planted: the fallback removed; the first test fails.

## Correction

2026-10-31, read at `a3f948d`: a stand-in relay of the Prove cannot be named, as a relay that the
user names is the relay alone (item 2). The test pins the built-in relay host, and each host of
the seed pool that a fresh cache tries after it (`crates/podssh-relay/src/pool.rs`, `SEED`), to
127.0.0.1 with `PODSSH_RELAY_ADDR`, where port 443 takes no connection: each relay host fails at
once, as one that refuses. A host where something takes 127.0.0.1:443 says that the test did not
run. The Approach stands.

## Done

2026-10-31: drafted (branch `draft-roads-cli`, after T-379), not built and not run; each result is
UNVERIFIED until the merge.

- `Transport::Relay` carries `then_direct`: no relay named (`RelayList::explicit`), no `-4` or `-6`,
  and `PODSSH_DIRECT`, else the settings file's `Direct`, not `no` (`relay_settings::direct_from`).
  After the opener failed, `after_relay` dials the first hop as `--direct` does, reads the version
  line within `VERSION_WAIT` (10 s), and gives the session its bytes first; the lines of
  `announce` and `both_failed`. doctor's `no_ssh_banner` calls the shared check.
- The manual: the help of `--direct`, a note of `podssh ssh`, `PODSSH_DIRECT` in ENVIRONMENT, and
  the settings file's `Direct`; `docs/cli.md`, `docs/relay.md` (step 7), the row of a public sshd in
  `docs/design.md`, `docs/STATUS.md`.
- UNVERIFIED: `cargo test -p podssh-cli --test direct_fallback` (4 tests: the fallback logs in and
  says so; `--direct`, `--relay-host` and `PODSSH_DIRECT=no` do not fall back, and a bad
  `PODSSH_DIRECT` is 78; both fail, with both roads and their times; a proxy that takes the
  CONNECT and sends nothing is named, within 40 s).
- UNVERIFIED: `cargo test -p podssh-cli --lib ssh::transport` (the lines, and the version line on a
  paused clock), `cargo test -p podssh-cli --lib relay_settings`, `cargo test -p podssh-cli --test
  doctor` and `--test direct_proxy` (the shared check), the manual's sweep of variables
  (`cargo test -p podssh-cli --lib man::facts`), clippy `-D warnings` and `cargo fmt --check`.
- UNVERIFIED, planted: the fallback removed (`then_direct` read as false in `reach_skipping`); the
  first test of `direct_fallback` should fail.

# T-369: `--forwarder TEMPLATE`: a road through a WebSocket forwarder that takes the target from its URL

**Source:** GitHub #60 (Nemo-010, 2026-10-31), and the survey of GitHub #59, its roads 1 and 2.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

To reach a target that the user does not run, podssh has the relay, whose one deployment the
operator runs (T-346), and `--direct`, which needs an egress that reaches the target; `cf://` and
`node://` need a host of the user's. Some public services take a target from the client and carry
its bytes over a WebSocket, with no account: the plumbing of other products, such as a MUD client
or an SSH client in a browser. A user who names one could reach a target with neither the
operator's relay nor a host of their own. podssh-ws can speak to them, but for its rules on the
relay's path and token.

## Premise

- Read in GitHub #59 and #60 (a tester's measurement of 2026-10-31, from a host with direct
  egress; not measured here): `wss://web-proxy.mudlet.org/?host=H&port=P`, the Worker of Mudlet's
  web client; an older copy of it at `mudix.delwing.workers.dev`; and `wss://ssheasy.com/p`, which
  takes the target in a first frame of JSON. Each gave GitHub's banner from `github.com:22`, and the
  first and the third from `ssh.github.com:443` too. The Worker refuses port 25, and private and
  Cloudflare addresses, and sends JSON messages in text frames (`Mudlet/mudlet-web:worker/index.js`,
  as #59 read it); ssheasy's code caps a connection at 1 GiB, then 100 KiB/s
  (`hullarb/ssheasy:proxy/main.go`, as #60 read it).
- Read: the study of carriers found no documented service, with no account, that carries any TCP
  target over a WebSocket (`docs/carriers.md:16-17`); the three above publish no limit, and say
  nothing of other clients.
- Read: a relay is a host and a port (`crates/podssh-relay/src/relay.rs:56-62`), and its forward
  path is `/connect/<host>/<port>` (`:139-152`); a run has one road, of five kinds
  (`crates/podssh-cli/src/ssh/resolve.rs:23-51`).
- Read: `validate` refuses a query other than the relay's knobs, and `connect` always sends a token
  (`crates/podssh-ws/src/client.rs:66-105`, `:159-182`); a token goes only to the deployment that
  minted it (`docs/decisions.md:55`).
- Read: a SOCKS5 proxy that the user names in `ALL_PROXY` carries each road already (T-070;
  `crates/podssh-ws/src/socks5.rs:1-7`): podssh takes a third party's proxy that the user chooses.

## Approach

1. `--forwarder TEMPLATE`, `PODSSH_FORWARDER` and `Forwarder` in the settings file (T-048), for the
   commands that take `--relay-host`; a list is tried in order, as the relay hosts are (T-220).
   `pipe` reaches a forwarder with the `wss:` of T-368.
2. A template is a `wss://` or `ws://` URL with `{host}` and `{port}` once each: podssh checks the
   target as each target is (`check_target`), then puts it in, percent-encoded. A template with
   neither sends them in a first text frame of JSON, `{"Host":HOST,"Port":PORT}`, which podssh
   writes itself. Another template is refused (64).
3. The dial is T-368's, with no token: TLS checked for the forwarder's name, the upgrade through
   `HTTPS_PROXY`, and no `/v1/mint`, no `/relays.json` and no pool.
4. The stream is the binary frames. A text frame of the forwarder is shown with `-v`, and never
   written into the stream; a close names the forwarder, its code and its reason.
5. `doctor --forwarder TEMPLATE`: the upgrade, then GitHub's banner from `github.com:22` through it.
6. The manual: a forwarder is an endpoint of another product, which publishes no limit and can
   stop at any time, so a user names more than one; podssh names none.

## Decision

- `--forwarder`, not `--relay-template` (#60's word): a forwarder does not speak the relay's
  contract, and `relay` names that contract in each flag of podssh. Lost: a kind of host in
  `--relay-host`, whose failover could then give a forwarder the relay's token.
- The user names each forwarder, as the user names a proxy in `ALL_PROXY` (Premise). Built-in
  templates of the forwarders that #59 measured, a fallback to them, and a live test against them
  wait for the operator's ruling on Q56 (T-370).
- One road for each run, as each road of `podssh ssh` is: with `--forwarder`, the relay is not
  tried after the forwarders. A race with the relay, as T-164 races the iroh road, can be a later
  step.
- A forwarder of the user's own, #59's road 2 (the same Worker in the user's own Cloudflare
  account), is a template as any other; podssh ships no forwarder, as the relay stays a separate
  project (`docs/decisions.md:38`; T-169).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test forwarder
cargo test -p podssh-cli --test forwarder_cli
```

Two stand-in forwarders on the loopback, one that takes the target from its query and one from a
first frame of JSON: a session to a test sshd through each, 1 MiB each way with equal digests; a
close names the forwarder; a template with `{host}` and no `{port}`, or with `{port}` twice, is
refused (64); a target whose name holds `&` is refused before it is put in. The stand-ins see no
`X-Relay-Token`. Against websockify in Podman, software that podssh did not write, with its target
fixed on its command line: the session's bytes pass (Inferred: it carries binary frames as they
are). Planted: the host put in with no check; the test of `&` fails.

# T-370: Built-in templates of other products' public forwarders, and a fallback to them

**Source:** GitHub #59 (Nemo-010, 2026-10-31), road 1 of its ranking, "with Mudlet and ssheasy as
built-in presets"; GitHub #60, a template "one the build knows".
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

With T-369, a user who knows a forwarder can name it. #59 asks for the three that it measured in
the binary, so that each binary has a second road to any target with no setup. Those forwarders
serve other products: their operators offer them to those products' users, and publish no limit
and no notice.

## Premise

- Read in GitHub #59 and #60, as in T-369: the three forwarders, measured from a host with direct
  egress; Mudlet's Worker (`Mudlet/mudlet-web:worker/index.js`) and ssheasy's caps
  (`hullarb/ssheasy:proxy/main.go`), as the tester read them.
- Read in GitHub #59 (the tester's reading): Mudlet's Worker runs on Cloudflare's free plan, and
  each user of Mudlet's web client shares its 100,000 requests a day.
- Read: the operator's ruling on Q50 (`docs/decisions.md`, 2026-10-31) lets the release binaries
  try n0's public relays and Tailscale's tailcat fleet when the user did not ask for them, their
  operators not asked first. Those two offer their relays to the public, for development and for
  tailcat; the forwarders of #59 serve their own products' users, and say nothing of others.
- Read: whether Cloudflare's terms, which forbid using its services "to provide a virtual private
  network or other similar proxy services", hold for the relay is a question for the relay's
  operator (`docs/relay-operator.md:83-87`).
- Read: the test targets of a session are the operator's list (`AGENTS.md:226-241`), which names
  none of the three.

## Approach

As the operator's ruling on Q56 allows (2026-10-31, `docs/decisions.md`):

1. Templates in the binary, each with its form (the query, or the frame of JSON), selected by a
   word (`--forwarder mudlet`), each with its note in the manual.
2. A fallback to them when each relay host failed, said on stderr with the forwarder's name.
3. A watch of their life, as T-339 watches the quick tunnel's pin: a check in CI that each one
   still upgrades and gives GitHub's banner.
4. The manual says that a template may also name a forwarder that the user runs (the Decision).

## Decision

- The operator's ruling on Q56: the three forwarders of #59 are built in, each selected by a word,
  and tried when each relay host fails, after the relay hosts and before the run ends; live tests
  against them run in GitHub Actions only, short. No relay token goes to a forwarder (T-369).
- No recipe of a forwarder in podssh's manual, which the ruling left open: a relay or a forwarder
  that its users host is the relay project's (T-169, `docs/relay-operator.md`, item 12), and the
  relay stays a separate project (`docs/decisions.md`, Q4 and Q9). Lost: a recipe of #59's road 2,
  the same Worker in the user's own account, which podssh would then have to keep up with
  Cloudflare's platform.
- The fallback comes after the relay hosts, not before: the relay's contract, limits and close
  codes are known (`docs/relay.md`), and a forwarder publishes none.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test forwarder_cli -- builtin
```

Each built-in template passes the stand-ins of T-369 in its form; a fallback runs only after each
relay host failed. Live, as Q56 allows: GitHub's banner through each, in GitHub Actions.

# T-371: A `-J` hop on port 443 through the proxy, measured, and a `doctor` line for a hop

**Source:** GitHub #61 (Nemo-010, 2026-10-31), and the survey of GitHub #59, its road 3.
**Category:** measurement
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

An SSH server that listens on port 443 can be the first hop of `-J`, reached with `--direct`
through a proxy that allows port 443 only, with no relay. `-J user@HOST:443` parses, but no test
runs it: not the login of a hop with a password and no terminal, and not `-W` or `-L` through such
a hop. `doctor` has no line for a hop, so a user cannot see whether one is reachable from here.

## Premise

- Read: a hop is `[user@]host[:port]` or `ssh://[user@]host[:port]`
  (`crates/podssh-cli/src/ssh/hop.rs:30-57`), and `-J` refuses a node only (`:59-65`). The road is
  chosen for the first hop's host (`crates/podssh-cli/src/ssh/resolve.rs:318`); with `--direct` it
  is TCP through `HTTPS_PROXY` (`crates/podssh-cli/src/ssh/resolve.rs:348-354`; `crates/podssh-cli/src/ssh/transport.rs:1-2`).
- Read: a prompt goes to the terminal, or to the program of `SSH_ASKPASS`, chosen as OpenSSH
  chooses it (`crates/podssh-ssh/src/prompt.rs:1-12`).
- Read: through the agent proxy of a cloud container, a CONNECT to `ssh.github.com:443` got `200`,
  and then a reset: `TODO/ws.md:1160` says "gets 200, then a reset". A proxy that waits for TLS
  carries no SSH on port 443; T-372 wraps SSH in TLS for it. Through the relay, GitHub's SSH on
  port 443 answers (`docs/STATUS.md:108`).
- Read: `doctor` asks the proxy for the relay and for `github.com` only
  (`crates/podssh-cli/src/doctor/net.rs:201-251`).
- Read in GitHub #61 (a tester's measurement of 2026-10-31, from a host with direct egress; not
  measured here): SSH banners on port 443 at `bg2.vpnjantit.com` (Dropbear 2017.75, an account with
  a password that a form makes), `ssh.tilde.club` and `ssh.blinkenshell.org` (OpenSSH); whether
  they allow `direct-tcpip` was not measured.
- Read: GitHub's SSH endpoint is a test target, and those three are not (`AGENTS.md:226-241`). The
  box's proxy allows ports 443, 80 and 8443, and lets one test target through by its name
  (`scripts/box/proxy.py:6-16`).

## Approach

1. In the box: a test sshd, with a user who logs in with a password, that the box's proxy lets
   through on port 443 by a name (`--allow`); `podssh ssh --direct -J user@NAME:443 TARGET` with
   the password from `SSH_ASKPASS` and the box's dead `/dev/tty` (T-005); `-W HOST:PORT` and `-L`
   through the hop; a second hop with `AllowTcpForwarding no`, whose refusal is named in the hop's
   words.
2. Live: `podssh ssh --direct -J git@ssh.github.com:443 HOST`, through the session's own proxy and
   through a proxy that passes bytes as they are (GitHub Actions): the banner, then GitHub's
   refusal of a key made for the check.
3. `doctor --hop [USER@]HOST[:PORT]`: the CONNECT (or the TCP with no proxy), the server's banner,
   as T-317 reads it, and the methods that the server offers for the request `none`. Through a
   proxy that waits for TLS, the line names the road of T-372.
4. `docs/cli.md` and the manual: a hop on port 443 with `--direct`, and the password of a hop from
   `SSH_ASKPASS` or from the credential store (T-228), never from the command line.
   `docs/STATUS.md`: each result.

## Decision

- The measurement first, as #61 asks: if a hop on port 443 works as it is, the entry is the tests,
  the line of `doctor` and the documents. A hop whose SSH is wrapped in TLS is T-372.
- The live hop is GitHub's (`ssh.github.com:443`), a test target. GitHub takes no login of a key
  made for the check, so it measures the dial, the banner and the refusal, and the box's sshd
  measures the rest. The free SSH services of #61 are not test targets of the operator's, and this
  entry does not need them.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- jump
cargo test -p podssh-cli --test doctor -- hop
sh scripts/test_in_box.sh   # the hop on port 443 behind the box's proxy
```

A stand-in SSH server on the loopback behind a stand-in proxy that allows port 443 only: `-J` with
the password from a stand-in of `SSH_ASKPASS` reaches the target through it, and `doctor --hop`
gives its banner and its methods; a hop that refuses `direct-tcpip` is named in its words.
Planted: the hop dialed on port 22 whatever its port; the stand-in proxy refuses it, and the test
fails. In the box: the runs of step 1. Live: the lines of step 2, in `docs/STATUS.md`.

# T-372: A hop or a destination whose SSH is wrapped in TLS: `ssh+tls://`

**Source:** GitHub #61 (Nemo-010, 2026-10-31), its part "What changes if it does not": a hop with
SSH inside TLS, which `hop.rs` cannot write.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Some SSH servers on port 443 sit behind TLS, as stunnel puts them, and a proxy that waits for TLS
on port 443 carries no plain SSH (T-317). podssh can write neither case: a hop is plain SSH over
TCP, and podssh runs no `ProxyCommand` that could add TLS.

## Premise

- Read: a hop is `[user@]host[:port]` or `ssh://[user@]host[:port]`
  (`crates/podssh-cli/src/ssh/hop.rs:30-57`); a destination can also name a road by its scheme,
  `cf://`, `node://` or `iroh:` (`crates/podssh-cli/src/ssh/resolve.rs:23-51`).
- Read: podssh runs no `ProxyCommand` (`crates/podssh-cli/src/ssh/options.rs:219-224`).
- Read: podssh-ws opens TCP through the proxy, then a TLS handshake checked for a name
  (`crates/podssh-ws/src/client.rs:184-205`), with no ALPN and no client certificate
  (`crates/podssh-ws/src/tls.rs:315-318`).
- Read: the agent proxy of a cloud container re-terminates TLS for some names, with its CA in
  `SSL_CERT_FILE` (`docs/target-environment.md:57-66`), and reset SSH on port 443
  (`TODO/ws.md:1158-1161`). Inferred: SSH inside TLS passes such a proxy where podssh trusts the
  proxy's CA.
- Read in GitHub #61 (a tester's report, which the tester's own run did not reproduce):
  `mx1.vpnjantit.com:443` and `ee2.vpnjantit.com:443` answer TLS, then SSH.

## Approach

1. A scheme `ssh+tls://[user@]host[:port]`, for a destination and for a hop of `-J`, port 443 by
   default: TCP (through the relay, `--direct`, or the hop before it), then TLS checked for `host`
   with podssh's trust (`--ca-file`), then SSH inside it. The host key is checked as for each hop.
2. A hop of TLS after the first runs its TLS inside the `direct-tcpip` channel of the hop before
   it.
3. A refusal names its step: the CONNECT, TLS (an unknown issuer with the words of T-340), or SSH.
4. `doctor --hop ssh+tls://...` (T-371): TLS, then the banner.
5. The manual and `docs/cli.md`.

## Decision

- A scheme, as `cf://` and `node://` are, not #61's `?tls=1`: a hop is not a URL with options, and
  a query would be the only one in a hop, with rules of its own.
- Any hop of a chain, not the first only, as TLS over a channel's stream is the same code. Lost: the
  first hop only, as T-347 chose for `cf://`, whose WebSocket inside a channel would need more.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_tls_hop
```

stunnel, software that podssh did not write, in the build image or in the box, in front of a test
sshd: `podssh ssh -J ssh+tls://user@hop:443 target` reaches the target, and so does the scheme as
the destination; a certificate for another name is refused at the TLS step; through a stand-in
proxy that waits for TLS and resets plain SSH, the hop of TLS passes and a plain one fails.
Planted: the certificate's name not checked; the test of another name fails.

# T-373: A Shadowsocks road, from a file of `ss://` lines that a subscription can refresh

**Source:** GitHub #62 (Nemo-010, 2026-10-31), and the survey of GitHub #59, its road 4.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A Shadowsocks server takes a target in an address header and dials it, as the relay's forward path
does, with a key in place of a token. Such servers run on port 443, with keys that their operators
give out, some of them on public pages. podssh has no client for it, so a user with such a server
cannot make it a road.

## Premise

- Read in GitHub #62 (the tester's reading of https://shadowsocks.org/doc/aead.html; not read
  here): a stream starts with a salt; each chunk is a length of 2 bytes sealed by an AEAD, then the
  sealed payload; the first payload starts with the address header (its type, the address, the
  port); the ciphers are `chacha20-ietf-poly1305` and `aes-256-gcm`; the key comes from the
  password by EVP_BytesToKey (MD5), and each subkey by HKDF-SHA1 with the info `ss-subkey`. An
  `ss://` URI (SIP002) holds the method, the password, the host and the port, and can name a
  plugin.
- Read in GitHub #62 (a tester's probe of 2026-10-31): a key that VPNBook publishes for its servers
  on port 443 took the salt and the header and gave no byte back, so it is not confirmed that such
  a server dials an arbitrary target.
- Read: podssh-ws has AES-GCM, ChaCha20-Poly1305 and HKDF of RustCrypto
  (`crates/podssh-ws/Cargo.toml:16-21`), and a SOCKS5 tunnel that names its target to a proxy
  (`crates/podssh-ws/src/socks5.rs:1-7`); a library crate has no C (`AGENTS.md`, section 5, rule
  4).
- Read: tokens and keys never appear in argv, logs or URLs, and go in files with tight permissions
  (`docs/architecture.md:177-182`); an `ss://` URI holds the password.
- Read: podssh starts no program that the user did not name (`AGENTS.md`, section 5, rule 3), and
  a plugin of Shadowsocks is another program.
- Inferred: a proxy that waits for TLS on port 443 carries no Shadowsocks, as it carries no SSH
  (T-317).

## Approach

1. A stream in podssh-ws: the AEAD form of Shadowsocks, with those two ciphers and `aes-128-gcm`,
   over TCP through `HTTPS_PROXY`, with the target in the first chunk. No plugin: a URI that names
   one is refused, with the reason.
2. `--shadowsocks FILE`: a private file, checked as the relay's token file is, of `ss://` lines,
   tried in order as the relay hosts are (T-220). A line `subscription URL` names a list to fetch
   through the proxy, over TLS and bounded in size; the list is kept in the cache directory
   (T-243) with mode 0600, and fetched again when each node of the kept list failed, or after a
   day.
3. The road joins the kinds of a run, for the commands that take `--relay-host`; the host key of
   SSH protects the session, as on each road.
4. The probe: the server's salt within a limit; silence or a reset names the proxy as the likely
   cause, as T-317 does. `doctor --shadowsocks FILE` gives a line for the first node: the TCP, the
   salt, then GitHub's banner through it.
5. The manual: a published key is shared with strangers, has no operator, and changes; podssh names
   no server and no list.

## Decision

- The protocol is written in podssh-ws with the ciphers that it has, not taken from the crate
  `shadowsocks`: the form is small, a library crate takes no C, and no runtime of another project
  comes with it. Lost: the crate in the binary, which brings more than the AEAD form needs
  (Inferred).
- The URI comes from a file, never from the command line, as it holds a password. Lost: #62's
  `--via ss://...`, which puts the password in argv.
- The user names each server and each list, as a proxy of `ALL_PROXY` (T-070); podssh names none.
  Its tests use servers that podssh did not write, never a public one: no public server is a test
  target of the operator's (`AGENTS.md:226-241`).
- Shadowsocks 2022 (SIP022) is refused by name in this entry; a later entry can take it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test shadowsocks
cargo test -p podssh-cli --test shadowsocks_cli
```

`ssserver` of shadowsocks-rust, software that podssh did not write, in Podman, for each cipher: a
session through it to a test sshd, 1 MiB each way with equal digests; a wrong password ends at the
first chunk, with the server named; a kept list whose nodes changed is fetched again from a
stand-in subscription. Bytes that `sslocal` of shadowsocks-rust sent decode. Planted: the nonce not
incremented after the chunk of the length; the session through `ssserver` fails.

# T-374: The quick tunnel's edge through WARP's tunnel, for a node whose cage reaches port 443 only

**Source:** GitHub #63 (Nemo-010), its second comment, of 2026-10-31.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A node publishes a quick tunnel at the edge's TCP port 7844 (T-300). A cage whose proxy allows
ports 443, 80 and 8443 reaches 7844 only through the relay's VPC road, so the node's road to the
edge still needs the operator's relay. WARP's tunnel (T-352) carries any port over HTTP/2 on port
443; through it, the node would reach the edge with no relay and no account.

## Premise

- Read: `crates/podssh-relay/src/quick/edge.rs:23` says "pub const PORT: u16 = 7844". The relay's
  VPC road carried TLS to that port, and `TODO/roads.md:1823` says "the edge's 443 and 8443 serve
  no tunnel".
- Read: the measured proxy allows ports 443, 80 and 8443 alone (`docs/target-environment.md:21`).
- Read: T-352 plans WARP's road over HTTP/2, with smoltcp for TCP inside, which the operator
  allowed on 2026-10-31 (Q52).
- Read in GitHub #63's second comment (a tester's report of 2026-10-31; not measured here): a
  sibling implementation registered a quick tunnel with the edge reached through WARP, and the
  tunnel's name answered `200`, after a closed port and an address with no route had failed first.
  It carried QUIC through its stack; the edge's HTTP/2 on TCP 7844, over smoltcp's TCP, would reuse
  the client of T-300.
- Read: the quick tunnel's live tests run in GitHub Actions only (`docs/decisions.md:15`).

## Approach

After T-352:

1. The node's dial of the edge gets one more road: a TCP stream to the edge's address on port 7844
   inside WARP's tunnel, after the direct dial and the relay's VPC road failed, or first when the
   user asks for it.
2. The client of T-300 runs on it as it is; the request for a tunnel to `api.trycloudflare.com`
   goes as now, through the proxy.
3. `doctor` names the road that reached the edge.
4. A measurement in GitHub Actions: a runner whose egress refuses port 7844 publishes a quick
   tunnel through WARP, and a client reaches it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test quick_edge_warp
```

A stand-in of WARP's edge, T-352's, carries a stand-in of the quick tunnel's edge: the node
registers, and a client's session passes. Planted: the stream sent past the tunnel; the stand-in
of the edge sees no connection, and the test fails. Live in `quick-tunnel-live.yml`, with port 7844
refused on the runner.

## Start condition

T-352 is done: WARP's road, on which this road runs. The operator allowed it on 2026-10-31 (Q52,
`docs/decisions.md`).

# T-378: The quick tunnel's loop over HTTP/2 may read the connection's end as its control stream's

**Source:** T-359's tests, 2026-10-31: the same race in the loop over QUIC, found and repaired
(T-301's Done).
**Category:** defect
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

When the edge closes a connection over HTTP/2, or the connection falls silent, the connection's
accept and the control stream's read can both see it. The loop takes the first of the two that
comes, and a control stream that ended returns its own end, not the connection's close or
silence. Over QUIC this happened one run in six; over HTTP/2 no test ends the connection while
the control stream reads, so it is not measured. A wrong end gives the node's operator a wrong
line. P3: the node connects again either way, and only its words differ.

## Premise

- Read: the loop over HTTP/2 returns `Ended::Http2` or `Ended::Closed` from the connection's
  accept (`crates/podssh-relay/src/quick/serve.rs:181-182`), and `Ended::Control` from the control
  stream's failure (`crates/podssh-relay/src/quick/serve.rs:197`), in one `tokio::select!`
  (`crates/podssh-relay/src/quick/serve.rs:184`).
- Read: the loop over QUIC had the same two arms, and a close or a silence read as the control
  stream's end one run in six, until the control stream's failure took the connection's reason
  (T-301's Done, 2026-10-31).
- Inferred, not measured: h2 wakes the connection's task and each stream's when the connection
  ends, so either arm can come first.

## Approach

1. A test of the loop over HTTP/2 (`crates/podssh-relay/tests/quick_tunnel.rs`) that ends the
   connection, by a close and by a silence, while the control stream reads; run it 20 times.
2. If it fails: a control stream that fails while the connection has ended takes the connection's
   end. h2 gives a stream no reason of its connection, so the loop polls the connection once
   more, within a bound, before it says the control stream's end.

## Prove

```sh
export CARGO_BUILD_JOBS=4
for i in $(seq 1 20); do cargo test -p podssh-relay --features quick --test quick_tunnel || break; done
```

Each of the 20 runs passes, with the test of step 1 among them. If step 2 was needed: with it
planted away, the test fails within the 20 runs.

## Correction

2026-10-31: the Premise's inference did not hold: over HTTP/2 the connection's end comes first.
h2's connection is driven in the loop's own task, by its accept, so the poll that reads the end
of the connection also fails its streams; the control stream's failure reaches the loop only
through its task of its own and a channel, a later poll. Measured: 2,000 closes, on one thread and
on two, each the connection's end. Step 2 is not needed.

## Done

2026-10-31: `crates/podssh-relay/tests/quick_tunnel.rs` closes the connection while the control
stream reads, 50 connections on one thread and 50 on two, each registered and then closed; and
silences it, the node's end frozen (a `Gate`), on a paused clock that takes the ping's 30 s and the
pong's 30 s at once. Twenty runs of the file passed (`cargo test -p podssh-relay --features quick
--test quick_tunnel`, 7 tests each): each close ended as `Closed` or `Http2`, and the silence as
`Silent`. Planted, a close read as the control stream's end: the test failed at its first round,
naming it. Step 2 is not needed (the Correction); clippy clean.

# T-379: The DERP road in the command line, in the race of T-164, and as the fallback that Q50 allows

**Source:** T-349, item 4 of its Approach, which its Decision of 2026-10-31 moves here; the
operator's ruling Q50.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

T-349 builds the DERP link in `podssh-relay` (feature `derp`): a node's connection to its home,
the links that clients open, the adapter under the layer, and the ticket. No command uses it:
`podssh node` serves no DERP road, `podssh ssh` dials no `derp:` ticket, and the race of T-164
has two roads. Q50 lets a node and a client with no pair try tailcat's fleet when the user did not
ask, and nothing does so.

## Premise

- Read: the node of the iroh road serves the pair's road beside it, with one keeper for both
  (`crates/podssh-cli/src/node_iroh.rs:305-306`), and `podssh node` sends `--iroh` there
  (`crates/podssh-cli/src/node.rs:72-74`).
- Read: `podssh ssh` resolves its destination into an enum of transports
  (`crates/podssh-cli/src/ssh/resolve.rs:24-51`), in a file of 488 of its 500 lines.
- Read: the race of T-164 orders two roads (`crates/podssh-relay/src/session/race.rs:56-58`), and
  the race of the command line is in a build with the feature `iroh` only
  (`crates/podssh-cli/src/ssh/iroh.rs:8-11`).
- Read: T-349's node and dialer (`crates/podssh-relay/src/derp/far.rs`,
  `crates/podssh-relay/src/derp/client.rs`); a client's DERP key is new for each run, so the
  node's allowlist checks the key that the end-to-end channel proves.

## Approach

1. `podssh node NAME TARGET --derp`: the DERP road, alone, or beside the pair's road when the
   pair NAME is stored or `--pair-file` gives one, with one keeper; its home by `/derp/probe`
   (tailcat's fleet, else `--derp-server HOST[:PORT][,...]` or `PODSSH_DERP_SERVER`); its ticket
   on stderr, and again when its home changes. It needs the end-to-end channel and `--allow`.
2. `podssh ssh [USER@]derp:TICKET[/ROUTE]`: T-349's dialer, the layer's client, and the channel to
   the ticket's Ed25519 key; the host key under `derp:` and the node's key. The resolver is split
   first, so that each file stays under 500 lines.
3. `podssh ssh node://NAME --derp-ticket TICKET`: the race of T-164 with the DERP road third,
   after the iroh road and the pair's road, at the start and at each resume.
4. Q50's fallback: a node with no pair serves the DERP road unasked, and says so; a client whose
   label holds the node's ticket dials it when the pair's road cannot run.
5. The manual: the flags, the destination, the fallback, the fleet and its limits; `podssh
   doctor` says the probe of each server of the fleet.

## Decision

The operator's ruling of 2026-10-31 (Q50, `docs/decisions.md`): Tailscale's tailcat fleet is an
automatic fallback of the reverse road, tried when the user did not ask.

2026-10-31, the draft (each call with the alternatives that lost):

- The road is in each build: podssh-cli turns podssh-relay's feature `derp` on, as it does `quick`.
  Lost: a feature of the command line, as the iroh road has one: the road is pure Rust and small
  (`crypto_box`, in the lock already), and Q50 makes it a fallback that a build without the feature
  would lose with no word.
- A node moves home after 3 failed connections in a row to its home (`far::MOVE_AFTER`): to the first
  other server of its list, from the top, that takes a connection, and it stays there
  (`crates/podssh-relay/src/derp/far.rs`). Lost: a move at the first failure, which a derper that
  restarts would turn into a move of each node and a longer try of each client; a new probe of the
  whole list, where a connection that completes DERP's handshake proves more than an empty GET; a
  move back when the first server returns, which moves each client again with a home that flaps.
- A client tries the ticket's server, then the rest of its own list (`--derp-server`, else
  `PODSSH_DERP_SERVER`, else the fleet) when that list holds the ticket's server
  (`servers::for_client_in`); T-349's `for_client` is the case of the fleet. Lost: the fleet after
  each ticket, where a node of the user's own derper never moves to tailcat's; each server of the
  list after any ticket, where a ticket of a server outside the list belongs to another list.
- More than two roads race by `session::race::in_turn`: each road 250 ms after the one before it, or
  at once when each road that started before it failed, as Happy Eyeballs staggers (RFC 8305), so
  the DERP road starts 500 ms in behind the iroh road and the pair's. Lost: the two-road race nested,
  whose inner race greets its winner before the outer one could start the third road.
- The race leaves `crates/podssh-cli/src/ssh/iroh/race.rs` for `crates/podssh-cli/src/ssh/roads.rs`,
  in each build, as a build with no iroh still races the pair's road and the DERP road; the iroh
  road's part (`IrohRoad`) stays behind the feature, with an empty type in its place without it.
  Lost: the race behind the feature `iroh`, which would refuse `--derp-ticket` in a build that has
  the DERP road.
- The fallback of a client (item 4): a ticket given with `--derp-ticket` is kept under NAME, in the
  cache as the pins are (`derp-NAME.ticket`), and a later run that gives none dials it only when each
  road before it failed (`Start::WhenAllFailed`), or alone when no pair is stored under NAME. Lost:
  the kept ticket only when no pair is stored, which misses an outage of the relay, the case the
  fallback is for (T-346); the kept ticket with the head start of a ticket given, which would load
  tailcat's fleet on each run while the pair's road works.
- The fallback of a node: a node with no pair (none stored, or one expired), an allowlist, and none of
  `--iroh`, `--plain`, `--no-e2e`, `--pair-file` or a `udp:` TARGET serves the DERP road unasked, and
  its first line says why. Lost: the road with no allowlist, which no client could pass, so the node
  refuses as before; the DERP road unasked beside `--iroh`, a node that has a road with no relay of
  the operator's already, which `--derp` adds when asked.
- `PODSSH_DERP=no` turns both fallbacks off; `--derp`, `--derp-ticket` and `derp:` still take the
  road. Lost: no switch, which leaves a user whose policy forbids a third party's relay with no way
  out, where T-363 gives `PODSSH_DIRECT=no` for its fallback; a key of the settings file first, as a
  node's service gets its variables from its file of `--env-file` and each end reads the variable
  alike.
- The road needs the end-to-end channel and `--allow`: a DERP server forwards packets from any key, so
  the channel's allowlist is the node's only door, and a client's key on the servers is new for each
  run (T-349's Decision). Lost: the allowlist's absence as "each client", as on the pair's road, where
  the relay's connect token decided who reaches the node.
- The node's name in the known hosts and the messages is `derp:` and its Ed25519 key in hex, as
  `iroh:` names the iroh road's node; `derp:PORT`, all digits, stays the host `derp` and a port, as a
  ticket starts with a letter (its version byte). Lost: the ticket, which changes with the home.
- `podssh doctor` has a section `derp` in each build: `/derp/probe` of each server in order, `FAIL`
  for each that does not answer, then the home, as `crates/podssh-cli/src/doctor/iroh.rs` does for
  n0's relays. Lost: `????` for a server that does not answer, where doctor keeps `FAIL` for a
  fallback that does not work here.
- The resolver's split (item 2): its environment (`Env`, `ca_file`) moves to
  `crates/podssh-cli/src/ssh/resolve_env.rs`, re-exported, so no caller changes, with each comment.
  Lost: the transport's choice moved out, which changes more callers' paths.
- The test: podssh-relay's own stand-in (`crates/podssh-relay/tests/derp_stand_in/mod.rs`, frames of
  its own, now with `/derp/probe`) behind TLS of the test's own CA on the loopback
  (`crates/podssh-cli/tests/derp_support/mod.rs`), as the command line is a process of its own. Lost:
  Tailscale's derper, which `scripts/interop-derp.sh` runs for the library in Podman: the road's
  interop is T-349's, and this test needs no container.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test derp_road
```

A node and a client of the command line through a stand-in DERP server: refused, then let in once
the client's key is in the node's allowlist; with the pair's road blocked, the race gives the
session to the DERP road; a client whose node's home moved finds it at the next server of the
fleet. Planted: a client that tries the ticket's server alone fails that last check.

## Start condition

T-349 is done: the DERP link of `podssh-relay` is merged and measured.

## Correction

2026-10-31, read at `a3f948d`: the keeper of both roads of the iroh road's node is not at the cited
lines, which make the sessions' pipe, but a block below them, at line 313 at `a3f948d` ("One keeper
for both roads"). The resolver had 496 lines at `a3f948d`, not 488. The Approach stands: the split
moves the resolver's environment to `crates/podssh-cli/src/ssh/resolve_env.rs`.

## Done

2026-10-31: drafted (branch `draft-roads-cli`), not built and not run; each result is UNVERIFIED
until the merge.

- podssh-relay: `session::race::in_turn` and `Start`, a race of more than two roads of one link
  (`crates/podssh-relay/src/session/race.rs`); a node that moves home, `far::serve_roaming`, `Roam`,
  `MOVE_AFTER` and `connect_to` (`crates/podssh-relay/src/derp/far.rs`); a client of the user's own
  list, `servers::for_client_in` and `Dialer::with_servers`; the stand-in answers `/derp/probe`.
- podssh-cli: `podssh node --derp` and `--derp-server`, the DERP road alone, beside the pair's road,
  or beside the iroh road and the pair's road, with one keeper (`crates/podssh-cli/src/node_derp.rs`,
  `crates/podssh-cli/src/node_iroh.rs`), and a node with no pair that serves it unasked;
  `--derp` refused with `--quick-tunnel` and `--temporary`; `--install` carries `--derp` and
  `--derp-server` into the service, and asks for no pair with `--derp`, as with `--iroh`;
  `podssh ssh derp:TICKET[/ROUTE]`
  (`crates/podssh-cli/src/ssh/derp.rs`); `node://NAME --derp-ticket TICKET` and the kept ticket, in
  the race of a node's roads (`crates/podssh-cli/src/ssh/roads.rs`); `PODSSH_DERP`; doctor's section
  `derp` (`crates/podssh-cli/src/doctor/derp.rs`); the flags (`crates/podssh-cli/src/flags/derp.rs`),
  the manual's notes of `ssh` and `node` and its ENVIRONMENT; `docs/cli.md`, `docs/design.md` (the
  road table and section 8), `docs/STATUS.md`. `derp:`, like `iroh:`, is refused by `cp`, `each`,
  `job`, `run`, `containers` and `--persist`.
- The resolver's split: `crates/podssh-cli/src/ssh/resolve.rs` keeps 467 lines.
- UNVERIFIED: `cargo test -p podssh-cli --test derp_road` (4 tests: refused, then let in, with the
  host key under `derp:`; the race with the pair's road blocked, then the kept ticket, then
  `PODSSH_DERP=no`; a node with no pair, unasked, and `PODSSH_DERP=no`; the node that moved home and
  the client of its old ticket, with the ticket's server alone as the control).
- UNVERIFIED: `cargo test -p podssh-relay --features derp --test derp_link` (the move, through two
  stand-ins in memory), `cargo test -p podssh-relay --test session_race` (four tests of `in_turn` on
  a paused clock), `cargo test -p podssh-relay --features derp --lib derp::servers`, and
  `cargo test -p podssh-cli --lib -- node_derp ssh::derp`.
- UNVERIFIED: the rest of the workspace with the change: `cargo test --workspace` (podssh-cli's
  `iroh_cli` names `derp:TICKET` in the refusal of a channel's flag now; the manual's sweep of
  variables reads `PODSSH_DERP`), `cargo build -p podssh-cli --features iroh` and
  `cargo test -p podssh-cli --features iroh-test --test iroh_road` (the race moved out of the iroh
  module), clippy `-D warnings`, `cargo fmt --check`, and the planted defect: `for_client_in`
  returning the ticket's server alone, which the last test of `derp_road` and the move's test of
  `derp_link` should fail.
- UNVERIFIED, live and short, as Q50 allows: `podssh node lab 127.0.0.1:22 --derp --allow FILE` and
  `podssh ssh derp:TICKET` through tailcat's fleet from a session's own host, and `podssh doctor`'s
  section `derp` there.
