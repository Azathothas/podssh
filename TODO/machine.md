This file holds the work that makes podssh usable by programs and agents: JSON forms of `doctor`,
`man` and the result of `ssh`, `podssh status`, the end-to-end check in the binary, `podssh
ping`, an MCP server, and a log of sessions. stdout carries the answer and nothing else
(`docs/architecture.md:127-128`). `serde` and `serde_json` are already dependencies of the binary
(`crates/podssh-cli/Cargo.toml:53`), so no entry here needs a new crate for JSON.

# T-049: `podssh doctor --json` (GitHub #9)

**Source:** GitHub #9 (Nemo-010, 2026-10-08); the `--format json` of TeddyHuang-00/sshping and
Petyok/SSHub (GitHub #22, #23; read in the reports, not verified here). Measured on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh doctor` is the first command that an agent runs on a new host, and its report is text
with `ok`, `FAIL` and `????` labels. To branch on one check, an agent must parse English text.
`--json` is refused.

## Premise

Measured with `target/debug/podssh.exe`: `podssh doctor --json` exits 64 with "unknown flag
'--json'" before any check runs.

Read, at `bc13eee`: each check goes through `Report::line` with a name and a `Verdict`
(`crates/podssh-cli/src/doctor/mod.rs` lines 115-135), which prints it at once and cleans the detail
with `podssh_ws::text::one_line` (line 138). `finish` prints the counts and exits 1 when a check
failed (lines 156-168). The sections are "this host", "egress" and "relay" (lines 76-100).
`doctor` already parses JSON with `serde_json`
(`crates/podssh-cli/src/doctor/relay_checks.rs:119`).

## Approach

1. Make `Report` keep each line (section, name, `Verdict`, the cleaned detail)
   (`crates/podssh-cli/src/doctor/mod.rs` lines 97-162 at `bc13eee`). The text renderer still prints each line
   when its check ends.
2. With `--json`, print nothing until the end; then write one JSON object to stdout: `schema`
   (1), `podssh` (the version), `os`, `arch`, `checks` (each with `section`, `check`, `status`
   and `detail`) and `counts` (`ok`, `fail`, `unknown`). `status` is "ok", "FAIL" or "unknown",
   the shape of GitHub #9. The exit code does not change.
3. One model and two renderers, as `podssh man` has (`crates/podssh-cli/src/man/model.rs`).
4. Add the row to `DOCTOR_FLAGS` (`crates/podssh-cli/src/flags.rs:336-347`), read it into
   `Parsed::Doctor` (`crates/podssh-cli/src/tree.rs` lines 172-181 and 384-392 at `c6f09a8`), and pass it on in
   `crates/podssh-cli/src/dispatch.rs:120-135`. `tree.rs` has 454 lines and `dispatch.rs` 448:
   keep the additions small, or split first.
5. The JSON carries the same detail strings as the text, which hide proxy credentials and
   tokens today (`crates/podssh-cli/tests/doctor.rs:130-154`).
6. Change the `doctor` notes (`crates/podssh-cli/src/man/notes.rs:261-280`) and
   `docs/cli.md:315-333` in the same commit.

## Decision

Recommendation: `--json` writes one JSON document when a one-shot report is complete (`doctor`,
`man`, `status`, `relay`, `ping`); `--jsonl` stays for the events of a long run (`chat`, `cp`,
`ts`: `crates/podssh-cli/src/flags.rs`, lines 272-273 at `7aa955a`, `crates/podssh-cli/src/flags/copy.rs:27-28`,
`crates/podssh-cli/src/flags.rs:288-289`). `--jsonl` also makes the run
non-interactive and starts the `--timeout` rule
(`crates/podssh-cli/src/non_interactive.rs:62-70`, 187-203), which a bounded report does not
need. `--jsonl` everywhere lost for that reason. `--format json` lost because podssh's other
output choices (`--roff`, `--no-pager`) are plain switches.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test doctor -- json      # new tests in crates/podssh-cli/tests/doctor.rs
PODSSH_OFFLINE=1 target/debug/podssh doctor --json </dev/null >doctor.json
echo "exit=$?"
cargo test -p podssh-cli --test doctor -- --ignored  # the live relay, on request
```

The new tests run the binary offline, as `crates/podssh-cli/tests/doctor.rs:98-119` does: stdout
is one JSON object; each text line has an item with the same check, status and detail; the
counts agree; a planted proxy password and a planted token do not appear. Planted defect: leave
the last check out of the JSON; the parity test fails.

## Done

2026-10-09, in the commit "podssh doctor --json".

- `Report` (`crates/podssh-cli/src/doctor/mod.rs`) keeps each line: section, check, status and
  the cleaned detail. Without `--json` it prints each line when its check ends, as before;
  with `--json` it prints nothing until `finish`, then one object: `schema` 1, `podssh`, `os`,
  `arch`, `checks` and `counts`. The flag is a row of `DOCTOR_FLAGS`, read into
  `Parsed::Doctor` and passed in `DoctorArgs`. The manual's note and `docs/cli.md` say the
  same.
- Prove: `cargo test -p podssh-cli --test doctor -- json`: 2 passed.
  `json_has_each_check_of_the_text` runs the text and `--json` offline with one HOME: each
  text line is rebuilt from its item (status, check and detail) and equals it, in order, with
  its section, and the counts agree. `json_shows_no_proxy_password_and_no_token` plants both.
  `PODSSH_OFFLINE=1 target/debug/podssh doctor --json` printed one object, exit 0 (7 ok, 1
  unknown on Windows).
- Plant: the last check left out of the JSON; the parity test failed (7 items for 8 lines).
- In the container gate, the parity test first failed: two runs bound different ports, and the
  doctor runs of parallel tests each copied the debug binary into `/dev/shm` and filled it, so
  one run reported it full. The test now masks digits, and the doctor runs of the test file
  take turns; it then passed 3 times of 3 in the container. That gate run had interop 103 of
  103 and 65 flag spellings in groff and mandoc.

# T-050: `podssh man --json`: the commands, flags, keywords, variables and exit codes as data (GitHub #10)

**Source:** GitHub #10 (Nemo-010, 2026-10-08); GitHub #23 (a table of flags and commands that an
agent can read). Measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

An agent that has only the binary cannot list which flags work, which are accepted with no
effect, and which are refused, without parsing the help or the man page. The tables that hold
these facts have no renderer for programs.

## Premise

Measured: `podssh man --json` exits 64 ("unknown flag '--json'"). `podssh --help --json` exits 0
and prints the text help, so it drops `--json` silently (T-010).

Read: the data is in tables already. Commands and flags: `VERBS`
(`crates/podssh-cli/src/flags.rs:396-429`), each row with its kind and `instead` (lines 19-47 at `22c3b88`),
and the availability (lines 443-451 at `22c3b88`). Arguments: the parser
(`crates/podssh-cli/src/man/model.rs:199-203`). Keywords:
`crates/podssh-cli/src/ssh/keywords.rs:25-96`, with the stated defaults (lines 99-104 at `22c3b88`).
Variables: `crates/podssh-cli/src/man/facts.rs:45-134`. The files and the exit codes were text
blocks only (`crates/podssh-cli/src/man/facts.rs` lines 100-145 and 231-271 at `332ee58`), and the blocks of the
manual do not keep the kind and the `instead` of a flag.

## Approach

1. A third renderer (new: crates/podssh-cli/src/man/json.rs) walks the tables, not the blocks.
2. Move the exit codes into a table that both `exit_status`
   (`crates/podssh-cli/src/man/facts.rs` lines 239-280 at `332ee58`) and the JSON read; the test at lines 379-393
   keeps checking the constants. Do the same for FILES.
3. The shape: `schema`, `podssh`, `commands` (name, aliases, about, availability "works",
   "not-implemented" or "not-in-build", arguments, and flags with short, long, value, kind
   "supported", "accepted" or "refused", help and instead), `ssh_keywords` (honoured, with
   value, help and default; ignored; refused, with the reason), `variables`, `files` and
   `exit_codes`.
4. `podssh man --json` writes all; `podssh man --json SECTION` writes one command; `--json` with
   `--roff` is a usage error (64). No pager for JSON
   (`crates/podssh-cli/src/man/mod.rs` lines 73-78 at `332ee58`).
5. The JSON is the same on each host: no path from `HOME` (`docs/cli.md:41-42`).
6. Add the row to `MAN_FLAGS` (`crates/podssh-cli/src/flags.rs:295-302`), the field to
   `man::Request` (`crates/podssh-cli/src/man/mod.rs:29-36`), and the parse
   (`crates/podssh-cli/src/tree.rs:251-259`). JSON for `--help` stays with T-010.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test man_json   # new: crates/podssh-cli/tests/man_json.rs
cargo test -p podssh-cli --test man_flag_parity
target/debug/podssh man --json </dev/null >man.json
echo "exit=$?"
```

The new test reads the JSON and requires each flag that `--help` shows, with the same kind and
value name, through the readers of `crates/podssh-cli/tests/man_extract/mod.rs`; each keyword of
the three lists; each variable; and each exit-code constant. The bytes are the same with an
empty environment and with a planted token. Planted defect: drop the `instead` of the refused
rows; the test fails.

## Done

2026-10-09, in the commit "podssh man --json".

- `crates/podssh-cli/src/man/json.rs` (new) walks the tables: `schema` 1, `podssh`, `options`,
  `commands` (name, aliases, about, `availability` works, not-implemented or not-in-build, usage,
  `arguments` from the parser, and `flags` with short, long, value, `kind` supported, accepted,
  refused or not-in-this-release, help and `instead`), `ssh_keywords` (honoured with value, help
  and default; ignored; refused with the reason), `variables`, `files` and `exit_codes`. A
  command that does not work has no option but `--help`, as in `--help` and the manual (T-233).
- `crates/podssh-cli/src/man/data.rs` (new) holds FILES and EXIT STATUS as data; the text and the
  man page render them from there, byte for byte as before (compared with `cmp`).
- `--json SECTION` takes a command (or an alias) or the tables `environment`, `files` and
  `exit-status`; a prose topic is refused with exit 64 and the text to read; so is `--json
  --roff`. JSON is never paged. The flag is a row of `MAN_FLAGS`; the manual's note and
  `docs/cli.md` describe it. The readers of the tests give each `--help` row with its
  description now (`option_rows`, `help_descriptions`).
- Prove: `cargo test -p podssh-cli --test man_json`: 4 passed (each flag of each working
  command's `--help`, with its value name, kind and what to use instead; each keyword of the
  three lists, each variable and each exit-code constant; the same bytes with an empty
  environment and with a token and another HOME; one section, and the refusals).
  `cargo test -p podssh-cli --test man_flag_parity`: 5 passed. `target/debug/podssh man --json`:
  one object, exit 0.
- Plant: `instead` dropped; the test failed at `ssh: --background` (none for `& in the shell`).
- `sh scripts/dev.sh check`: green; interop 103 of 103, 65 flag spellings in groff and mandoc.

# T-051: `podssh status`: one line of JSON about the state of this host (GitHub #11)

**Source:** GitHub #11 (Nemo-010, 2026-10-08); GitHub #23 ("machine-readable config and
state"). The operator's ruling on Q8 (2026-10-08): after M3 and before M4, with T-049,
T-050, T-012 and T-052. Measured here on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The help shows `podssh status` as "one-shot state, one line, machine-readable", but it exits
70. An agent wants a cheap call before anything else: the relay hosts in effect, whether a
token is cached and for which host, whether a host key is known, and whether podssh has a
terminal.

## Premise

Measured: `podssh status` exits 70 with "'status' is not implemented yet; nothing was done.";
`podssh status --json` exits 64 (unknown flag).

Read, at `c6f09a8`: the verb has no flags (`crates/podssh-cli/src/flags.rs` lines 409-410), an
owner row (line 429) and no arguments (`crates/podssh-cli/src/positionals.rs` line 50). Each fact
has a local source that
opens no connection: the relay list (`crates/podssh-relay/src/relay.rs:83-101`,
`crates/podssh-relay/src/pool.rs:48-61`); the token cache
(`crates/podssh-relay/src/cache.rs:78-97`, which returns the token itself in `Cached`, lines
29-33); a host key (`crates/podssh-ssh/src/known_hosts.rs:79-85`, 90-98); the attachment
(`crates/podssh-cli/src/non_interactive.rs:74-76`); the proxy, shown with no credentials
(`crates/podssh-ws/src/dial.rs:43-48`, 131-134).

## Approach

1. The syntax: `podssh status [OPTIONS] [[user@]host[:port]]`, with the relay flags of `doctor`
   (`crates/podssh-cli/src/flags.rs:336-347`). Remove the owner row, and add "status" to
   `DISPATCHED` (`crates/podssh-cli/tests/flag_table.rs:107-110`).
2. Write one line of JSON to stdout and exit 0 (64 for a usage error). No text form: `doctor`
   is the report for people.
3. The fields: `schema`; `podssh`; `relays` (host, port) and `relays_from` ("--relay-host",
   "PODSSH_RELAY" or "default and pool"); `pool` (cached, fetched, hosts); `token` (`source`
   "PODSSH_RELAY_TOKEN", "cache" or "none", the host it is cached for, the expiry), never the
   token; `proxy` (the variable and host:port) or null; `offline`; `attachment` and the
   terminal state of stdin and stdout; and `host` (the name filed in `known_hosts`, known or
   not, the key types) when a destination is given.
4. Add `cache::peek`, which gives the expiry and the path and never the token, so `status`
   cannot hold a token at all.
5. No network, no DNS and no write: unlike `doctor`, `status` makes no probe file.
6. Until T-057 is done, the cache key is the first host of the list; show it as it is.
7. Change in the same commit: the manual's notes and examples, `docs/cli.md`, and the command
   table of `docs/STATUS.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test status   # new: crates/podssh-cli/tests/status.rs
PODSSH_OFFLINE=1 target/debug/podssh status github.com </dev/null
echo "exit=$?"
```

The tests run the binary with a scratch `HOME` and `XDG_CACHE_HOME`: one line that parses as
JSON; the relay list for the flag, the variable and the default; a planted cached token and a
`PODSSH_RELAY_TOKEN` that never appear; `host.known` true for a fixture `known_hosts` entry and
false without it; the cache directory unchanged after the run. Planted defect: print the
`Cached` value with its token; the secret test fails.

## Done

2026-10-09, in the commit "podssh status: one line of JSON about this host".

- `crates/podssh-cli/src/status.rs` (new): `podssh status [--relay-host HOSTS] [--relay-addr
  HOST=IP] [[user@]host]` writes one line: `schema`, `podssh`, `relays` and `relays_from`,
  `pool` (`pool::cached`: whether, when, how many), `token` (source `PODSSH_RELAY_TOKEN`, `cache`
  or `none`; `for` the deployment key of T-057; `minted_at`, `expires_ms`, `usable`), `proxy`
  (the variable and `host:port`, or the error), `offline`, `attachment`, `stdin_tty`,
  `stdout_tty`, and `host` (the name in `known_hosts`, `known`, `key_types`). The destination
  meets `check_target`, as for `ssh`. A bad flag or destination is 64, a bad variable 78.
- `cache::peek` reads an entry without its token field: the token is never in memory.
- `Parsed` moved to `crates/podssh-cli/src/parsed.rs`, re-exported by `tree.rs` (483 lines,
  now 358), to make room for `Parsed::Status`. The owner row of `status` is gone, and the test
  of the owner rows lists `status` as dispatched; the dispatch test of an unimplemented verb
  uses `relay` now.
- The manual has notes for `status` and an example; `docs/cli.md`, the command table of
  `docs/STATUS.md`, `README.md` and `AGENTS.md` (section 1) list `status` as working.
- Prove: `cargo test -p podssh-cli --test status`: 3 passed (one line of JSON; the relays for
  the flag, the variable and the default; a refused destination; a planted cached token and
  `PODSSH_RELAY_TOKEN` absent, the cache listing equal before and after; `known` true for a
  fixture `known_hosts` entry and false for another host, `[unknown.example]:2222`).
  `PODSSH_OFFLINE=1 target/debug/podssh status github.com` printed one line, exit 0.
- Plant: the token of the cache in the line; the secret test failed.
- `cargo test --no-fail-fast`: 770 passed, 0 failed, 7 ignored. `sh scripts/dev.sh check`:
  green; interop 103 of 103; the man page shows each of 66 flag spellings, `status` included.

# T-052: `podssh doctor --full`: the end-to-end checks of `sandbox-check.sh`, in the binary (GitHub #13)

**Source:** GitHub #13 (Nemo-010, 2026-10-08); the `ping` of lablup/bssh and the `doctor` of
VLOD-ZDOV/quic-ssh (GitHub #22; read in the reports, not verified here). Measured on `3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The end-to-end check of a host is `scripts/sandbox-check.sh`, which needs a checkout and a
shell. A host that has only the binary cannot show that the SSH handshake and the host-key
check work through the relay.

## Premise

Measured: `podssh doctor --full` exits 64 (unknown flag); `podssh selftest` exits 64 (unknown
subcommand).

Read, at `bd626c7`: the script runs `doctor` (`scripts/sandbox-check.sh` lines 93-97), a banner exchange through
`podssh proxy` (lines 99-109), `keygen` with `podssh ssh -T` and `-tt` to GitHub (lines 111-132),
two prompts with nobody to answer them (lines 134-170), and OpenSSH with podssh as its
`ProxyCommand` (lines 172-185); each step has a verdict since T-006. `doctor` already opens a forward
session to `github.com:22` and checks the host key against GitHub's published keys
(`crates/podssh-cli/src/doctor/relay_checks.rs` lines 170-207 at `bd626c7`, keys at lines 30-34): that covers the
banner step. The script's `ssh` steps trust the key on first use (`accept-new`, line 65), not by
equality, and its `-tt` step never reaches a pty request: GitHub refuses the key before a
channel opens. `keygen::generate` makes a key in memory (`crates/podssh-ssh/src/keygen.rs:62-72`),
and `crates/podssh-ssh/src/keys.rs:85-88` offers a key to the server.

## Approach

1. `--full` adds the check `login` after `forward`: a new forward session (as
   `crates/podssh-cli/src/doctor/relay_checks.rs:185-205`), an SSH handshake that accepts only a
   key of `GITHUB_KEYS` (equality; the probe `crates/podssh-ssh/src/probe.rs:16-26` records a
   key the same way), then public-key authentication as `git` with a throwaway Ed25519 key from
   `keygen::generate`. The key stays in memory and is never written.
2. Verdicts: a refused key is `ok` ("the handshake, the host key and the authentication path
   work through the relay"); another host key is `FAIL`; a transport failure is `FAIL`, with
   the relay's reason (`crates/podssh-ssh/src/relay_stream.rs:45-61`); no relay host is `????`.
3. Bound each step with the doctor's limit (`crates/podssh-cli/src/doctor/relay_checks.rs:27`),
   and the whole check too.
4. No `-tt` line: with GitHub, authentication fails before a channel, so a pty request cannot
   be tested; the notes say so. No OpenSSH step (Decision).
5. The line joins the JSON of T-049. The script can call `doctor --full` and keep its OpenSSH
   step.
6. Change `DOCTOR_FLAGS` (`crates/podssh-cli/src/flags.rs:336-347`), the `doctor` notes
   (`crates/podssh-cli/src/man/notes.rs:261-280`) and `docs/cli.md:315-333` in the same commit.

## Decision

Recommendation: no OpenSSH step in the binary. `AGENTS.md` (section 5, rule 3) allows a program
that a probe found, but the step measures OpenSSH more than podssh. In both measured sandboxes,
OpenSSH stopped at once with "No user exists" (`docs/STATUS.md`, "In the operator's real
sandboxes, measured"), which the `user` check of `doctor` already reports. The alternative, run
`ssh` when `PATH` has it, lost for these reasons; the script keeps the step.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test doctor -- full
cargo test -p podssh-cli --test doctor -- --ignored full   # the live relay and GitHub, on request
sh scripts/test_in_box.sh path/to/static/podssh            # the Podman box: login ok
```

Offline, `--full` adds one `????` line and no `FAIL`. A unit test of the verdict, as
`crates/podssh-cli/src/doctor/relay_checks.rs:363-379` tests the keys: a refused key gives `ok`,
another host key gives `FAIL`. Planted defect: a handshake that accepts any host key; the
wrong-key test fails.

## Done

2026-10-09, in the commits "podssh doctor --full logs in to GitHub with a key made for the
check" (the code) and "T-052 measured in the box: login ok" (this record):

- `podssh_ssh::probe::login` (`crates/podssh-ssh/src/probe.rs`): the key exchange, a host key
  that must have one of the named fingerprints, then public-key authentication with an Ed25519
  key from `keygen::generate`, kept in memory; the whole login is bounded. Its outcome is
  `Refused`, `Accepted` or `WrongHostKey`.
- `--full` (a row of `DOCTOR_FLAGS`, read into `Parsed::Doctor` and `DoctorArgs`) adds `login`
  after `forward`, through the same relay path (`open_github`, shared with `forward`), with the
  host key that `forward` identified. A refused key is `ok`; another host key or a broken link
  is `FAIL` (with the relay's reason); no relay host, no token, or offline is `????`. The doctor
  notes, `docs/cli.md` and `scripts/sandbox-check.sh` (now `doctor --full`) say the same.
- Prove so far: `cargo test -p podssh-cli --test doctor -- full` passed (offline, one more
  `????` line and no `FAIL`); `cargo test -p podssh-cli --test doctor -- --ignored full`
  passed (live: "ok login github.com:22 through tcp.ssh.relay.ajam.dev: ... GitHub refused a key
  made for this check, as it must"; 18 ok, 0 FAIL). The probe's tests run a russh server in the
  process: with its host key named, the key is refused (`publickey` still listed); with another
  named, no key is offered. The verdicts have a unit test (`full_login_verdicts`).
- Plant: the probe's handshake accepts any host key; `login_stops_at_a_host_key_that_was_not_named`
  failed (it got `Refused`).
- The box: `sh scripts/test_in_box.sh` with the gate's binary of `d98d77e` (its CI run): the box
  matched the sandbox on each required property; `sandbox-check.sh` ran `doctor --full`: "ok
  login github.com:22 through tcp.ssh.relay.ajam.dev: ... GitHub refused a key made for this
  check, as it must", 29 ok, 0 FAIL; the script: 7 ok, 0 FAIL, 1 skip (OpenSSH needs a user
  database entry).

# T-053: `podssh ping`: a short check of the path, with latency and throughput

**Source:** GitHub #23 (the echo latency and the throughput of TeddyHuang-00/sshping, and the
`ping` of lablup/bssh; read in the reports, not verified here); the throughput runs of the two
sandboxes (`docs/STATUS.md`, "In the operator's real sandboxes, measured").
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

No short command tells how good the path is: the time of each step, the round trip, and the
throughput through the relay. The testers measured throughput by hand, with `podssh proxy` and
public HTTP servers, and one such target did not work from the relay's edge.

## Premise

Measured: `podssh ping example.org` exits 64 ("unknown subcommand 'ping'. No close subcommand,
so none is guessed.").

Read: the session pings the relay every 10 s and counts the pongs, but it measures no round
trip (`crates/podssh-ws/src/session.rs:149-173`; the payload is a counter, `:170`). `doctor`
prints the milliseconds of each `/health` request
(`crates/podssh-cli/src/doctor/relay_checks.rs:130-132`). The relay counts both directions
against 64 MiB for each session (`docs/relay.md:127`). The stand-in relay answers pings
(`scripts/fake-relay.py:246-247`).

## Approach

1. `podssh ping [OPTIONS] [user@]host`, with the relay flags and the `ssh` options that a login
   needs (reuse `resolve`). With no destination, only the relay leg (Decision).
2. The relay leg, for each host of the list: the milliseconds of TCP or CONNECT, of TLS and of
   the upgrade; then 10 WebSocket pings, each with a timestamp in its payload, each matched to
   its pong. Report the minimum, p50, p95 and maximum.
3. With a destination: the time of the SSH handshake; the echo time of single bytes through a
   remote `cat`; the throughput down with `head -c SIZE /dev/zero` and up with
   `cat > /dev/null`. Print the remote commands that ran. A missing command ends with its exit
   status (127), never with a hang.
4. `--size SIZE`: 8 MiB in each direction by default. Refuse more than 30 MiB (exit 64), so both
   directions stay under the relay's 64 MiB.
5. A time limit on each step and on the whole run. `--json` as T-049 decides.
6. Add the verb to the tables (`crates/podssh-cli/src/flags.rs:396-429`), to the help and the
   manual, and to `DISPATCHED` (`crates/podssh-cli/tests/flag_table.rs:107-110`).

## Decision

Recommendation: one verb with two forms. No destination gives the relay leg, which needs no
login and no remote program; a destination adds the SSH measures. A `--relay` flag lost: the
destination already tells the two forms apart. A remote `cat` or `head` is an assumption about
the far host, so they run only when the user gives a destination, and the output names them.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ping   # new: crates/podssh-cli/tests/ping.rs
sh scripts/dev.sh check                # interop: ping through the stand-in relay to OpenSSH
```

`--size 40M` exits 64 before any connection. In the gate, `podssh ping` through
`scripts/fake-relay.py` gets a pong for each of 10 pings, and with the OpenSSH server of
`scripts/interop.sh` it moves 8 MiB each way and exits 0. Planted defect: remove the size limit;
the 40 MiB test fails.

# T-054: A machine-readable result for `podssh ssh`: exit status, signal and byte counts

**Source:** GitHub #23 (the `--json` of sleepinginsummer/agent-ssh-cli with `exitCode`, `stdout`
and `stderr`, and `exec` of Petyok/SSHub; read in the reports, not verified here). Measured on
`3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A script that runs `podssh ssh host command` gets only an exit code. It cannot tell a remote
exit of 255 from a failure of podssh, it must parse stderr for the signal name, and it gets no
byte counts and no name of the relay host.

## Premise

Measured: `podssh ssh --json example.org true` exits 64 (unknown flag).

Read: a session ends as `io::End` (`crates/podssh-ssh/src/io.rs:20-33`). The exit status and the
signal are read in `handle_msg` (`:252-268`). The output goes straight to the process's
stdout and stderr in `write_out` (`:277-287`), so nothing counts bytes. `session::run` maps
the end to the exit code (`crates/podssh-ssh/src/session.rs:32-36`). The relay host is known
at `crates/podssh-cli/src/ssh/transport.rs:56`, and the relay's close reason is in `RelayStatus`
(`crates/podssh-ssh/src/relay_stream.rs:63-105`).

## Approach

1. A long flag `--result-file FILE` for `ssh`, a podssh flag as `--relay-host` is. At the end of
   the run, write one JSON object to FILE: `schema`; `exit` (the code that podssh exits with);
   `status` (the remote exit status, or null); `signal` (name and core dump, or null); `end`
   ("status", "no-status", "lost", "escaped", "terminated" or "failed"); the class of a failure
   ("connect", "host-key", "auth", "relay"); `bytes` (stdin, stdout, stderr); `duration_ms`;
   `relay` (host, close code and reason), or null with `--direct`.
2. Count the bytes in one place: make the output sink of `io::pump` a parameter
   (`crates/podssh-ssh/src/io.rs:131-139`, and `write_out` at `crates/podssh-ssh/src/io.rs:277-287`). T-055 needs the same change.
3. stdout and stderr stay byte for byte as now; the command's output never goes into the JSON.
4. Write the file on each path, also after a failure before the session: at the end of
   `run_ssh` (`crates/podssh-cli/src/ssh/mod.rs:90-94`). Mode 0600. Refuse `-`: stdout is data.
5. Add the row to `SSH_FLAGS` (`crates/podssh-cli/src/flags.rs:112-251`; the set of short flags
   does not change), and change the `ssh` notes and `docs/cli.md` in the same commit.

## Decision

Recommendation: a file that the user names. A JSON line on stderr lost: the remote command
writes to the same stderr, and can print a line that looks like the result. A descriptor number
(`--result-fd 3`) lost: Windows passes descriptors to a child in another way, and podssh runs
there too.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_result   # new: the JSON shape, offline
sh scripts/dev.sh check                      # interop: against OpenSSH and Dropbear
```

In `scripts/interop.sh`: `exit 3` gives status 3 and exit 3; `kill -TERM $$` gives the signal
TERM and exit 143; 5,000,000 bytes give `bytes.stdout` 5000000 and the same digest of stdout as
now; a refused key gives exit 255, the end "failed" and the class "auth". Planted defect: count
stderr into stdout; the byte test fails.

# T-055: `podssh mcp`: the commands as tools for an agent, over stdin and stdout

**Source:** GitHub #18 (the MCP interface of mirkobozzetto/bunflared,
`mirkobozzetto/bunflared:src/mcp/mod.rs`); GitHub #20 and #24 (the command line for agents of
l0ng-ai/tty7, `l0ng-ai/tty7:crates/tty7-cli/src/commands.rs`). Read in the reports, not verified
here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

An agent that speaks MCP must run podssh through a shell and parse its text. An MCP server over
stdin and stdout gives typed tools, with no shell quoting.

## Premise

Measured: `podssh mcp` exits 64 (unknown subcommand).

Read: a prompt goes to the controlling terminal or to `SSH_ASKPASS` (`docs/cli.md:622-638`),
and the terminal of an agent can be the user's own. The session output goes straight to the
process's stdout (`crates/podssh-ssh/src/io.rs:277-287`), which an MCP server over stdio uses for
its protocol. podssh never listens (`docs/architecture.md:102-112`), and stdio needs no listener.

## Approach

1. `podssh mcp`: JSON-RPC 2.0 over stdin and stdout, as the MCP specification defines its stdio
   transport (`initialize`, `tools/list`, `tools/call`).
2. The tools: `ssh_exec` (destination, command, time limit, optional stdin; the result has the
   exit, the status, the signal, stdout, stderr and `truncated`); `doctor` (T-049); `man`
   (T-050); `status` (T-051). No `proxy` tool: a byte pipe has no request and answer.
3. Each session forces `BatchMode=yes`: no prompt, ever. An unknown host key is refused unless
   the call names its fingerprint (T-031).
4. Session output goes to buffers through the sink of T-054, capped at 1 MiB for each stream;
   bytes that are not UTF-8 go as base64. Only JSON-RPC lines go to stdout.
5. podssh's own messages go to stderr. Each call has a time limit; a call past it ends its
   session.
6. Destinations only from `--allow-host PATTERN` (Decision).
7. The manual states the risk: the agent can run commands on each allowed host with the user's
   keys.

## Decision

Recommendation: no destination by default; the user names the allowed hosts when podssh starts
(`--allow-host PATTERN`, repeatable). The arguments of a tool call come from a model, and text
that the model read can ask it to reach another host with the user's keys. The alternative,
each host that `podssh ssh` reaches, lost for that reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test mcp   # new: JSON-RPC lines on stdin, PODSSH_OFFLINE=1
sh scripts/dev.sh check               # interop: tools/call ssh_exec to the OpenSSH server
```

Offline: `initialize` and `tools/list` answer; a call to a host outside `--allow-host` gives an
error result and no connection; each line on stdout parses as JSON-RPC. In the gate: `ssh_exec`
of `echo hi; exit 3` gives status 3 and the stdout "hi". Planted defect: a `println!` in the
session path; the test that parses each stdout line fails.

# T-056: A log of the sessions of this host, when the user asks for it

**Source:** totoshko88/RustConn (connection history and statistics, GitHub #24; read in the
report, not verified here).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A user cannot see which sessions ran from this host, how long they took, through which relay
host, and how they ended. Each of these facts is lost when the process ends.

## Premise

Read: podssh keeps no record of a session. `-E LOGFILE` appends podssh's own messages, which is
another purpose (`crates/podssh-cli/src/flags.rs:141-142`). The cache directories and the rules
for private files are in `crates/podssh-relay/src/cache.rs:61-76` and 164-262. `write_private`
replaces a whole file (lines 178-197 at `22c3b88`), and no function appends to one.

## Approach

1. Off by default. `PODSSH_SESSION_LOG=1` turns it on in the default place; a path turns it on
   there. The settings file of T-048 can also turn it on.
2. One JSON line for each session, at its end: the start time, the duration, the verb (`ssh` or
   `proxy`), the destination host and port, the relay host or "direct", the end, the exit code,
   the bytes and the relay's close code. The fields are the result of T-054, so one record
   serves both.
3. Never a command line, an environment value, a token or a password.
4. The file `sessions.jsonl` in the first usable cache directory, mode 0600, opened to append
   and with no symbolic link followed (the checks of `cache.rs`). One `write` for each line, so
   two processes do not mix their lines.
5. A size limit: at 1 MiB, rename the file to `sessions.1.jsonl`, and start a new one.
6. `podssh status` (T-051) shows the last line in short form.
7. Add the variable to VARIABLES (`crates/podssh-cli/src/man/facts.rs:45-134`; the tests require
   it) and the file to FILES, in the same commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test session_log   # new: crates/podssh-cli/tests/session_log.rs
sh scripts/dev.sh check                       # interop: a logged session to OpenSSH
```

Without the variable, no file appears. With it, each run adds one line, the mode is 0600 on
Unix, and two runs at the same time give two whole lines. In the gate,
`podssh ssh host 'echo SECRET-WORD'` adds a line, and the file does not contain `SECRET-WORD`.
Planted defect: log the command; that test fails.
