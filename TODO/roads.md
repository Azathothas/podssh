The roads beyond the forward and reverse roads: the iroh road of milestone M6
and its race with the reverse road; a roost next to a standard sshd and a
start from one; UDP over the relay; a self-hosted relay, which is work of the
relay project; a quick tunnel and the functions of Mosh, made by podssh
itself; Multipath TCP; and resumption in the relay (M8).

# T-162: The iroh road behind the cargo feature `iroh`

**Source:** ROADMAP M6 (the iroh road); `docs/design.md:717-898`;
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

Read, not measured (`docs/design.md:724-745`): iroh 1.1 or later (advisories
up to 1.0.3), MIT or Apache-2.0, MSRV 1.91, the aws-lc-rs backend, about 190
to 245 crates. In the target sandbox it runs only with no UDP transport (or a
UDP bind after a probe), podssh's proxy in `proxy_url(...)`, the `Minimal`
preset with no pkarr or DNS, peers dialled by ticket, and a home relay whose
`/ping` passes the proxy. The operator accepted netlink sockets and extra
connections for this road (`docs/design.md:887-890`). The sandbox refuses UDP
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
   (`crates/podssh-ws/src/dial.rs:96-120`), so `ALL_PROXY` and `NO_PROXY` act
   as on the other roads; iroh's own selection ignores both
   (`docs/design.md:743`).
3. UDP: `clear_ip_transports()` by default. Add the UDP transport only after a
   probe that binds a UDP socket to port 0 and closes it, as `bind_inet`
   probes TCP (`crates/podssh-cli/src/doctor/unix.rs:137-166`).
4. A session is one QUIC stream with the ALPN `podssh/1`. It carries the
   records of the resumable layer (T-151), so it can resume on the other road
   (T-153).
5. `doctor`, with the feature: a UDP line, and the `/ping` of the home relay
   through the proxy (`crates/podssh-cli/src/doctor/host.rs:10-25`).
6. `availability()` knows `ts` as the only build feature
   (`crates/podssh-cli/src/flags.rs:453-461`): extend it. With no feature, an
   iroh destination refuses before it connects and names `--features iroh`,
   as `crates/podssh-cli/tests/ts_not_built.rs:1-4` shows for `ts`.
7. Docs: the "Outbound only" item of `README.md`, "Nothing listens" in
   `SECURITY.md:94-114`, `docs/architecture.md` (rule 3, the crates),
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

**Source:** ROADMAP M6 (dialled by ticket); `docs/design.md:744` and
`docs/design.md:855-856`; GitHub #18 (Nemo-010, 2026-10-08: zuko's ticket
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
key and the relay URL (`docs/design.md:744`). The key is the identity, and
access is by an allowlist of keys or a relay token (`docs/design.md:855-856`).
Read in the reports, not verified here: iroh-ssh warns when a server's key is
ephemeral (`rustonbsd/iroh-ssh:src/ssh.rs`); zuko hands over a ticket out of
band (`adonm/zuko:docs/protocol.md`). Read: `podssh ts` keeps its node key in
the file that `--ts-state` names (`crates/podssh-cli/src/flags.rs:320-321`,
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
   `podssh ssh iroh:TICKET` dials it (the address of `docs/design.md:678`).
6. Add the key files to FILES in the manual
   (`crates/podssh-cli/src/man/data.rs:128-255`), and each new variable to
   `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:45-214`).

## Decision

Recommendation: a ticket is an address, and the node's allowlist of client
keys gives access. A ticket can then go on a command line or into
`ssh_config` with no risk. The alternative, a bearer ticket (tailcat's address
is one: `docs/design.md:654-655`), lost: each process on the host can read a
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
them) and `docs/design.md:391-395` (to add: a race between roads); ROADMAP M6
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
(`docs/design.md:892-898`). The user must select iroh (`docs/decisions.md`,
2026-10-08). Each road has one attempt for each host, with a time limit
(`docs/design.md:56-63`). The relay opener tries one host at a time
(`crates/podssh-relay/src/open.rs:188-247`), and no code races two roads.

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
   `ssh` in the manual (`crates/podssh-cli/src/man/notes_ssh.rs:4-220`).

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
published (`docs/design.md:872-874`). At least three projects run the iroh
relay protocol on Workers and Durable Objects (read, not verified:
`docs/design.md:878-880`). The URLs of n0's relays for iroh 1.x must be read
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
7. Add the variable to `VARIABLES` (`crates/podssh-cli/src/man/facts.rs:45-214`),
   the flag to the flag table, and the default to the relay section of the
   manual (`crates/podssh-cli/src/man/facts.rs:251-413`). The tests compare
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
`docs/design.md:410-413`; the `roost` of pigeons (`docs/design.md:882-885`);
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
then owns the TCP connection to sshd (`docs/design.md:410-413`). `podssh node`
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
(`crates/podssh-ssh/src/run.rs:341-351`). The alternative, the address of sshd
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
resumption (`docs/design.md:51`, `docs/design.md:414-431`). A podssh on the
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
(`docs/relay.md:1-21`, `README.md:30-33`). The stand-in serves the forward
path, `/v1/mint` and `/health` only (`scripts/fake-relay.py:102-120`). The
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
   262144 bytes), the close codes of `docs/relay.md:214-235`, and `/health`
   with the service name that `doctor` checks
   (`crates/podssh-relay/src/health.rs:13-15`).
3. The reverse path: `/v1/pair`, `/v1/node/<name>`, `/v1/connect/<name>`,
   `/v1/stop/<name>`, the text control frames, the 32-character ids, `409` for
   a second node, and the reverse close table.
4. The targets: public addresses only, the ranges of `docs/relay.md:164`,
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
for it, and a protocol that the user names has no fallback (`docs/design.md:199-203`). And the
client in a cage is the road of T-264, `crates/podssh-ws/src/cloudflare.rs`, whose upgrade is
cloudflared's; the cited `crates/podssh-ws/src/client.rs:159-182` is the relay's upgrade, with
its token header.

## Done

2026-10-12. The answers are in `docs/design.md:106-255`, section 2, "A quick tunnel that podssh
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

**Source:** T-170 (`docs/design.md:106-255`): the ports and the transports of a quick tunnel are
read, not measured.
**Category:** measurement
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** blocked

## Problem

The design of a quick tunnel that podssh makes itself (T-170) rests on Cloudflare's documents and
on cloudflared's source. No test has shown which ports of the edge take a tunnel, whether a
CONNECT proxy or the relay can carry its connection, or the bytes of a real registration, which
the tests of T-300 need.

## Premise

- Read (T-170): the edge is `region1.v2.argotunnel.com` and `region2.v2.argotunnel.com` on port
  7844, for TCP and UDP; port 443 serves optional things only (`docs/design.md:161-178`).
  cloudflared asks for a tunnel, and dials the edge, with no proxy (`docs/design.md:127-142`,
  `docs/design.md:180-184`).
- Read: the box's proxy, as the measured one, allows `CONNECT` to ports 443, 80 and 8443 only
  (`scripts/box/proxy.py:27`, `docs/target-environment.md:21`), and lets one more target through
  by its name with `--allow` (`scripts/box/proxy.py:14-18`).
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

## Prove

```sh
grep -n 'The edge, measured' docs/design.md
```

The section gives, for each port and each road, whether the edge took the connection and the
tunnel, with the date and the command; a road that was not tried says why. T-300 starts from it.

## Blocker

The operator: Q43 (`TODO/PROGRESS.md`). The targets, `api.trycloudflare.com` and the tunnel edge,
are not on the list of `AGENTS.md`, and a run of cloudflared needs a download of it.

# T-300: `podssh node` publishes a quick tunnel over HTTP/2, with no `cloudflared`

**Source:** T-170 (`docs/design.md:106-255`); the operator's ruling of 2026-10-08: podssh makes a
quick tunnel itself (`docs/decisions.md`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

A podssh node on a host that reaches TCP port 7844 could be reached from a cage by a public name,
with no relay and no account. When no relay host answers, that is a road. podssh cannot make such
a name: it runs no `cloudflared`.

## Premise

- Read (T-170, `docs/design.md:106-255`): the request for a tunnel and its reply; the SRV lookup of
  the edge; TLS to `h2.cftunnel.com` with no ALPN; cloudflared as the HTTP/2 server on the
  connection that it dialed; the control stream and its Cap'n Proto registration; the one header
  of each answer (`serialized_headers`); and a WebSocket that passes to the origin unchanged.
- Read: `h2` 0.4.19 is in `Cargo.lock`, through hyper; the crates `capnp` and `capnp-rpc` are
  Rust, and their code generator needs the C++ tool `capnp` (`docs/design.md:230-250`).
- Read: podssh's DNS over HTTPS asks for A and AAAA records only
  (`crates/podssh-ws/src/resolve.rs:124`).
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

# T-301: The quick tunnel over QUIC, where a probe finds UDP

**Source:** T-170 (`docs/design.md:106-255`): cloudflared makes a quick tunnel over QUIC unless the
user names HTTP/2.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

On a host where UDP works, the connector of T-300 still runs over HTTP/2 on TCP. cloudflared's
maintainers name QUIC as the transport that they mean users to have, and HTTP/2 as one with fewer
functions.

## Premise

- Read (T-170): QUIC to port 7844 with the name `quic.cftunnel.com` and the ALPN `argotunnel`; the
  first stream, which the connector opens, is the control stream; each stream of the edge starts
  with six bytes and a version, then a Cap'n Proto `ConnectRequest`, and is answered with a
  `ConnectResponse` (`docs/design.md:186-203`).
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

# T-171: The functions of Mosh that M6 and T-160 do not give, made in podssh itself

**Source:** GitHub #22 (Nemo-010, 2026-10-08: SSHub selects a Mosh transport
for each host); `docs/design.md:433-434`; the operator's ruling of
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
top of layer 2 (`docs/design.md:433-434`). The measured sandbox refuses UDP
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
T-160 (`docs/design.md:451-458`). And the iroh road (Approach, item 2) gives a direct UDP path,
but carries a session as one QUIC stream, so a lost packet still holds the bytes after it; only
datagrams (T-304) remove that.

## Done

2026-10-12. The map is in `docs/design.md:440-497`, section 5, "The functions of Mosh, and where
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
(`crates/podssh-ws/src/dial.rs:202-273`, the call at
`crates/podssh-ws/src/dial.rs:246`). Through a proxy, MPTCP can reach only the
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
`docs/design.md:414-431` (layer 3) and `docs/design.md:907-910` (question 1 of
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
target within 15 s, and it has no resumption (`docs/design.md:384-387`). The
option is a Durable Object that owns the target socket across reconnections,
a resume token in the `101` response, and offset framing as a protocol
version that the client selects. It is a project of the relay's operator, and
it costs Durable Object time for the whole session (`docs/design.md:427-431`).
The recommendation is "not now; look at it again after M6"
(`docs/design.md:907-910`). The relay is in another repository.

## Approach

The part of podssh, when the start condition holds:

1. Write a proposal for the relay's operator that reuses the records of the
   resumable layer (T-151). The relay becomes the far end of the layer, so
   the client keeps one implementation.
2. The client uses it only when the relay says that it offers it (a field of
   `/relays.json` or `/health`, read at run time). Never assume it.
3. Keep the resume token in memory only. Send it back in a header, never in a
   URL or in output (`docs/relay.md:148-150`).
4. A resume must reach the same Durable Object, so only hosts of one
   deployment can resume a session (the rule of the pool:
   `crates/podssh-relay/src/pool.rs:82-91`).
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
