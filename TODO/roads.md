The roads beyond the forward and reverse roads: the iroh road of milestone M6
and its race with the reverse road; a roost next to a standard sshd and a
start from one; UDP over the relay; a self-hosted relay, which is work of the
relay project; a quick tunnel and the functions of Mosh, made by podssh
itself; Multipath TCP; and resumption in the relay (M8).

# T-162: The iroh road behind the cargo feature `iroh`

**Source:** ROADMAP M6 (the iroh road); `docs/design.md:424-600`;
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

Read, not measured (`docs/design.md:431-452`): iroh 1.1 or later (advisories
up to 1.0.3), MIT or Apache-2.0, MSRV 1.91, the aws-lc-rs backend, about 190
to 245 crates. In the target sandbox it runs only with no UDP transport (or a
UDP bind after a probe), podssh's proxy in `proxy_url(...)`, the `Minimal`
preset with no pkarr or DNS, peers dialled by ticket, and a home relay whose
`/ping` passes the proxy. The operator accepted netlink sockets and extra
connections for this road (`docs/design.md:589-592`). The sandbox refuses UDP
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
   (`crates/podssh-ws/src/dial.rs:149-173`), so `ALL_PROXY` and `NO_PROXY` act
   as on the other roads; iroh's own selection ignores both
   (`docs/design.md:450`).
3. UDP: `clear_ip_transports()` by default. Add the UDP transport only after a
   probe that binds a UDP socket to port 0 and closes it, as `bind_inet`
   probes TCP (`crates/podssh-cli/src/doctor/unix.rs:137-166`).
4. A session is one QUIC stream with the ALPN `podssh/1`. It carries the
   records of the resumable layer (T-151), so it can resume on the other road
   (T-153).
5. `doctor`, with the feature: a UDP line, and the `/ping` of the home relay
   through the proxy (`crates/podssh-cli/src/doctor/host.rs:10-25`).
6. `availability()` knows `ts` as the only build feature
   (`crates/podssh-cli/src/flags.rs:461-469`): extend it. With no feature, an
   iroh destination refuses before it connects and names `--features iroh`,
   as `crates/podssh-cli/tests/ts_not_built.rs:1-4` shows for `ts`.
7. Docs: the "Outbound only" item of `README.md`, "Nothing listens" in
   `SECURITY.md:69-75`, `docs/architecture.md` (rule 3, the crates),
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

**Source:** ROADMAP M6 (dialled by ticket); `docs/design.md:451` and
`docs/design.md:557-558`; GitHub #18 (Nemo-010, 2026-10-08: zuko's ticket
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
key and the relay URL (`docs/design.md:451`). The key is the identity, and
access is by an allowlist of keys or a relay token (`docs/design.md:557-558`).
Read in the reports, not verified here: iroh-ssh warns when a server's key is
ephemeral (`rustonbsd/iroh-ssh:src/ssh.rs`); zuko hands over a ticket out of
band (`adonm/zuko:docs/protocol.md`). Read: `podssh ts` keeps its node key in
the file that `--ts-state` names (`crates/podssh-cli/src/flags.rs:277-278`,
`crates/podssh-cli/src/ts.rs:178`). Credentials never go on argv
(`AGENTS.md`, section 4).

## Approach

1. Keys: one Ed25519 secret key for each role (node, client), in a private
   file. `--iroh-key FILE` names the file, as `--ts-state` does; with no flag,
   it goes to the first usable directory of the cache chain
   (`crates/podssh-relay/src/cache.rs:61-76`). Reuse the private-file code of
   the token cache (`crates/podssh-relay/src/cache.rs:259-284`: mode 0600, no
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
   `podssh ssh iroh:TICKET` dials it (the address of `docs/design.md:414`).
6. Add the key files to FILES in the manual
   (`crates/podssh-cli/src/man/data.rs:91-169`), and each new variable to
   `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:45-122`).

## Decision

Recommendation: a ticket is an address, and the node's allowlist of client
keys gives access. A ticket can then go on a command line or into
`ssh_config` with no risk. The alternative, a bearer ticket (tailcat's address
is one: `docs/design.md:391-392`), lost: each process on the host can read a
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
them) and `docs/design.md:215-219` (to add: a race between roads); ROADMAP M6
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
(`docs/design.md:594-600`). The user must select iroh (`docs/decisions.md`,
2026-10-08). Each road has one attempt for each host, with a time limit
(`docs/design.md:55-62`). The relay opener tries one host at a time
(`crates/podssh-relay/src/open.rs:177-212`), and no code races two roads.

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
   `ssh` in the manual (`crates/podssh-cli/src/man/notes.rs:27-82`).

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
(`crates/podssh-relay/src/pool.rs:18-27`); the same shape fits the iroh
relays. n0's free relays are for development, with a rate limit that is not
published (`docs/design.md:574-576`). At least three projects run the iroh
relay protocol on Workers and Durable Objects (read, not verified:
`docs/design.md:580-582`). The URLs of n0's relays for iroh 1.x must be read
in iroh's source at the pinned version.

## Approach

1. One table in the new crate: the default relay URLs, in order. Today, n0's.
   When the operator's relay exists, it goes first and n0's follow: a change
   of one line, with its measurement (T-157).
2. `--iroh-relay URL[,URL...]` and `PODSSH_IROH_RELAY` replace the table, as
   `--relay-host` and `PODSSH_RELAY` replace the relay list
   (`crates/podssh-relay/src/relay.rs:80-101`). The flag wins.
3. Accept `https://` URLs only, with a host that passes `check_host`
   (`crates/podssh-ws/src/names.rs:8-24`), and with no user information
   and no query.
4. The order is a failover: the first relay that answers `/ping` through the
   proxy, within a time limit, is the home relay.
5. The relay URL of a ticket (T-163) is tried for that peer, also when it is
   not in the list.
6. `doctor`, with the feature, reports the `/ping` of each relay and the home
   relay.
7. Add the variable to `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:45-122`),
   the flag to the flag table, and the default to the relay section of the
   manual (`crates/podssh-cli/src/man/facts.rs:159-279`). The tests compare
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
`docs/design.md:234-237`; the `roost` of pigeons (`docs/design.md:584-587`);
GitHub #18 (Nemo-010, 2026-10-08: iroh-ssh reaches sshd by node id, and
refuses early when no sshd answers).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A standard sshd gets the resumable layer and the iroh road only when a podssh
next to it owns the TCP connection to it. A user with a normal server has no
way to run that podssh.

## Premise

Read: the far end of the layer can be a podssh next to a standard sshd, which
then owns the TCP connection to sshd (`docs/design.md:234-237`). `podssh node`
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
(`crates/podssh-ssh/src/run.rs:163-175`). The alternative, the address of sshd
behind the roost (`127.0.0.1`), lost: each roost would share one name, and one
key would replace another.

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

# T-167: Start from a standard sshd, then move the session to a better road

**Source:** GitHub #19 (Nemo-010, 2026-10-08: rose's SSH bootstrap mode,
`nikhiljha/rose:doc/spec.md`, GPL, specification only; ssh-obi's transport
over plain ssh).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A user reaches a server over the forward road. A better road (the layer, or
iroh) needs a podssh on the server and a ticket or a pair. To set these up by
hand takes several steps on two hosts.

## Premise

Read: to a standard sshd, the forward road is the only road, and it has no
resumption (`docs/design.md:51`, `docs/design.md:238-248`). A podssh on the
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

# T-168: UDP over the relay

**Source:** GitHub #18 and GitHub #26 (Nemo-010, 2026-10-08: sandhole's UDP
over TCP, `EpicEric/sandhole:book/src/udp_over_tcp.md`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

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
(`docs/relay.md:1-21`, `README.md:29-32`). The stand-in serves the forward
path, `/v1/mint` and `/health` only (`scripts/fake-relay.py:76-88`). The
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
   262144 bytes), the close codes of `docs/relay.md:179-200`, and `/health`
   with the service name that `doctor` checks
   (`crates/podssh-cli/src/doctor/relay_checks.rs:22-24`).
3. The reverse path: `/v1/pair`, `/v1/node/<name>`, `/v1/connect/<name>`,
   `/v1/stop/<name>`, the text control frames, the 32-character ids, `409` for
   a second node, and the reverse close table.
4. The targets: public addresses only, the ranges of `docs/relay.md:129`,
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
**Status:** open

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
(`crates/podssh-ws/src/client.rs:156-179`).

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

## Prove

```sh
grep -n 'quick tunnel' docs/design.md
cargo todo check
```

The section of the design gives each answer with its evidence, and a claim
with no measurement says so. The checker accepts the implementation entries
that the section names.

# T-264: Reach a service that `cloudflared` publishes, through `HTTPS_PROXY`

**Source:** the operator's ruling of 2026-10-09 (Q33, `docs/decisions.md`).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A user can publish an SSH or TCP service with Cloudflare's `cloudflared` on
a host of their own, behind a name of their own and, if they want, behind
Cloudflare Access. From a cage, podssh cannot reach it: the client is
`cloudflared access tcp`, and podssh runs no program of another project.

## Premise

Read: podssh's WebSocket client sends its credential in one fixed header,
`X-Relay-Token` (`crates/podssh-ws/src/client.rs:156-179`,
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

# T-171: The functions of Mosh that M6 and T-160 do not give, made in podssh itself

**Source:** GitHub #22 (Nemo-010, 2026-10-08: SSHub selects a Mosh transport
for each host); `docs/design.md:250-251`; the operator's ruling of
2026-10-08: no road depends on a program of another project, and podssh
makes the useful functions itself (`docs/decisions.md`).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Mosh keeps an interactive session usable on a bad network. podssh does not
start `mosh-server` or `mosh-client`, so each function that users want from
Mosh must come from podssh's own roads and layers. Nobody has listed the
functions that are still missing.

## Premise

Read: an interactive echo for high latency, as Mosh has, is a later option on
top of layer 2 (`docs/design.md:250-251`). The measured sandbox refuses UDP
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

## Prove

```sh
grep -n 'The functions of Mosh' docs/design.md
cargo todo check
```

The map names an entry for each function of Mosh, or gives the reason why
podssh does not need it. The checker accepts the new entries that the map
names.

# T-172: Multipath TCP on the direct road

**Source:** GitHub #24 (Nemo-010, 2026-10-08: RustConn's Multipath TCP and its
reconnection on a network change; the report notes that the sandbox has no
MPTCP).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

On a host with two networks, a TCP connection dies with its network.
Multipath TCP (MPTCP) can move a connection to another path. It is not known
whether MPTCP helps podssh on any road.

## Premise

Read: `--direct` connects with a plain `TcpStream::connect`
(`crates/podssh-ws/src/dial.rs:227-272`, the call at
`crates/podssh-ws/src/dial.rs:245`). Through a proxy, MPTCP can reach only the
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

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test mptcp
grep -n 'Multipath TCP' docs/design.md
```

The test asks for an MPTCP socket where the kernel refuses it, and gets plain
TCP with the same result; a planted dial that fails instead fails the test.
The `grep` shows the recorded result.

# T-173: Resumption in the relay for a standard sshd

**Source:** ROADMAP M8 (not now; look at it again after M6);
`docs/design.md:238-248` (layer 3) and `docs/design.md:609-612` (question 1 of
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
target within 15 s, and it has no resumption (`docs/design.md:208-211`). The
option is a Durable Object that owns the target socket across reconnections,
a resume token in the `101` response, and offset framing as a protocol
version that the client selects. It is a project of the relay's operator, and
it costs Durable Object time for the whole session (`docs/design.md:244-248`).
The recommendation is "not now; look at it again after M6"
(`docs/design.md:609-612`). The relay is in another repository.

## Approach

The part of podssh, when the start condition holds:

1. Write a proposal for the relay's operator that reuses the records of the
   resumable layer (T-151). The relay becomes the far end of the layer, so
   the client keeps one implementation.
2. The client uses it only when the relay says that it offers it (a field of
   `/relays.json` or `/health`, read at run time). Never assume it.
3. Keep the resume token in memory only. Send it back in a header, never in a
   URL or in output (`docs/relay.md:113-115`).
4. A resume must reach the same Durable Object, so only hosts of one
   deployment can resume a session (the rule of the pool:
   `crates/podssh-relay/src/pool.rs:79-88`).
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
operator and the relay's operator decide question 1 of `docs/design.md` section 8. Sessions skip
this entry (the operator's ruling of 2026-10-08).
