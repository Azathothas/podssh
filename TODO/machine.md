This file holds the work that makes podssh usable by programs and agents: JSON forms of `doctor`,
`man` and the result of `ssh`, `podssh status`, the end-to-end check in the binary, `podssh
ping`, an MCP server, and a log of sessions. stdout carries the answer and nothing else
(`docs/architecture.md:148-149`). `serde` and `serde_json` are already dependencies of the binary
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
(`crates/podssh-cli/src/doctor/relay_checks.rs`, line 119 at `24f3e2a`).

## Approach

1. Make `Report` keep each line (section, name, `Verdict`, the cleaned detail)
   (`crates/podssh-cli/src/doctor/mod.rs` lines 97-162 at `bc13eee`). The text renderer still prints each line
   when its check ends.
2. With `--json`, print nothing until the end; then write one JSON object to stdout: `schema`
   (1), `podssh` (the version), `os`, `arch`, `checks` (each with `section`, `check`, `status`
   and `detail`) and `counts` (`ok`, `fail`, `unknown`). `status` is "ok", "FAIL" or "unknown",
   the shape of GitHub #9. The exit code does not change.
3. One model and two renderers, as `podssh man` has (`crates/podssh-cli/src/man/model.rs`).
4. Add the row to `DOCTOR_FLAGS` (`crates/podssh-cli/src/flags/relay.rs:45-58`), read it into
   `Parsed::Doctor` (`crates/podssh-cli/src/tree.rs` lines 172-181 and 384-392 at `c6f09a8`), and pass it on in
   `crates/podssh-cli/src/dispatch.rs:155-171`. `tree.rs` has 454 lines and `dispatch.rs` 448:
   keep the additions small, or split first.
5. The JSON carries the same detail strings as the text, which hide proxy credentials and
   tokens today (`crates/podssh-cli/tests/doctor.rs:142-167`).
6. Change the `doctor` notes (`crates/podssh-cli/src/man/notes.rs:233-265`) and
   `docs/cli.md:1295-1313` in the same commit.

## Decision

Recommendation: `--json` writes one JSON document when a one-shot report is complete (`doctor`,
`man`, `status`, `relay`, `ping`); `--jsonl` stays for the events of a long run (`chat`, `cp`,
`ts`: `crates/podssh-cli/src/flags.rs`, lines 272-273 at `7aa955a`, `crates/podssh-cli/src/flags/copy.rs:45-46`,
`crates/podssh-cli/src/flags.rs:349-350`). `--jsonl` also makes the run
non-interactive and starts the `--timeout` rule
(`crates/podssh-cli/src/non_interactive.rs:56-64`, 187-203), which a bounded report does not
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

The new tests run the binary offline, as `crates/podssh-cli/tests/doctor.rs:110-131` does: stdout
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
(`crates/podssh-cli/src/flags.rs:349-406`), each row with its kind and `instead` (lines 19-47 at `22c3b88`),
and the availability (lines 443-451 at `22c3b88`). Arguments: the parser
(`crates/podssh-cli/src/man/model.rs:204-208`). Keywords:
`crates/podssh-cli/src/ssh/keywords.rs:25-113`, with the stated defaults (lines 99-104 at `22c3b88`).
Variables: `crates/podssh-cli/src/man/facts.rs:45-242`. The files and the exit codes were text
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
6. Add the row to `MAN_FLAGS` (`crates/podssh-cli/src/flags.rs:360-367`), the field to
   `man::Request` (`crates/podssh-cli/src/man/mod.rs:43-50`), and the parse
   (`crates/podssh-cli/src/tree.rs:262-270`). JSON for `--help` stays with T-010.

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
`crates/podssh-relay/src/pool.rs:51-64`); the token cache
(`crates/podssh-relay/src/cache.rs:72-91`, which returns the token itself in `Cached`, lines
29-33); a host key (`crates/podssh-ssh/src/known_hosts.rs:90-96`, 90-98); the attachment
(`crates/podssh-cli/src/non_interactive.rs:68-70`); the proxy, shown with no credentials
(its `Display`, `crates/podssh-ws/src/proxy.rs:70-75` since T-070).

## Approach

1. The syntax: `podssh status [OPTIONS] [[user@]host[:port]]`, with the relay flags of `doctor`
   (`crates/podssh-cli/src/flags/relay.rs:45-58`). Remove the owner row, and add "status" to
   `DISPATCHED` (`crates/podssh-cli/tests/flag_table.rs:110-139`).
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
channel opens. `keygen::generate` makes a key in memory (`crates/podssh-ssh/src/keygen.rs:76-88`),
and `crates/podssh-ssh/src/keys.rs:99-131` offers a key to the server.

## Approach

1. `--full` adds the check `login` after `forward`: a new forward session (as
   `crates/podssh-cli/src/doctor/relay_checks.rs:147-168`), an SSH handshake that accepts only a
   key of `GITHUB_KEYS` (equality; the probe `crates/podssh-ssh/src/probe.rs:16-26` records a
   key the same way), then public-key authentication as `git` with a throwaway Ed25519 key from
   `keygen::generate`. The key stays in memory and is never written.
2. Verdicts: a refused key is `ok` ("the handshake, the host key and the authentication path
   work through the relay"); another host key is `FAIL`; a transport failure is `FAIL`, with
   the relay's reason (`crates/podssh-ssh/src/relay_stream.rs:45-61`); no relay host is `????`.
3. Bound each step with the doctor's limit (`crates/podssh-cli/src/doctor/relay_checks.rs:25`),
   and the whole check too.
4. No `-tt` line: with GitHub, authentication fails before a channel, so a pty request cannot
   be tested; the notes say so. No OpenSSH step (Decision).
5. The line joins the JSON of T-049. The script can call `doctor --full` and keep its OpenSSH
   step.
6. Change `DOCTOR_FLAGS` (`crates/podssh-cli/src/flags/relay.rs:45-58`), the `doctor` notes
   (`crates/podssh-cli/src/man/notes.rs:233-265`) and `docs/cli.md:1295-1313` in the same commit.

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
`crates/podssh-cli/src/doctor/relay_checks.rs:347-363` tests the keys: a refused key gives `ok`,
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
**Status:** done

## Problem

No short command tells how good the path is: the time of each step, the round trip, and the
throughput through the relay. The testers measured throughput by hand, with `podssh proxy` and
public HTTP servers, and one such target did not work from the relay's edge.

## Premise

Measured: `podssh ping example.org` exits 64 ("unknown subcommand 'ping'. No close subcommand,
so none is guessed.").

Read: the session pings the relay every 10 s and counts the pongs, but it measures no round
trip (`crates/podssh-ws/src/session.rs:203-230`; the payload is a counter, `:227`). `doctor`
prints the milliseconds of each `/health` request
(`crates/podssh-cli/src/doctor/relay_checks.rs`, lines 130-132 at `24f3e2a`). The relay counts both directions
against 64 MiB for each session (`docs/relay.md:167`). The stand-in relay answers pings
(`scripts/fake-relay.py:388-389`).

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
6. Add the verb to the tables (`crates/podssh-cli/src/flags.rs:349-406`), to the help and the
   manual, and to `DISPATCHED` (`crates/podssh-cli/tests/flag_table.rs:110-139`).

## Decision

Recommendation: one verb with two forms. No destination gives the relay leg, which needs no
login and no remote program; a destination adds the SSH measures. A `--relay` flag lost: the
destination already tells the two forms apart. A remote `cat` or `head` is an assumption about
the far host, so they run only when the user gives a destination, and the output names them.

Taken, with these calls made in the work (2026-10-11). The relay leg goes to `--target
HOST:PORT`, else to GitHub's SSH port, the reference of `podssh doctor`; never to the
destination. A leg sends no SSH bytes, and OpenSSH 9.8 and later count such a connection as
`noauth` in `PerSourcePenalties`, against the relay's address, which each user of the relay
shares. The destination's first hop as the target lost for that reason. The steps of the SSH
connection itself lost too: the pool's opener does not report them, and the login time already
holds the relay's steps to the destination. With no destination, the run exits 0 when one relay
host gives its measures, and 69 only when none does: the pool fails over, so one host that is
down does not stop `podssh ssh`, and its line says why. `RelaySession` keeps the last 64 pongs
with the time each came (`take_pongs`, `pong_arrived`), so the leg needs no second reader, and
`podssh_ws::client::upgrade` is public, so the leg times the upgrade apart from TCP and TLS. The
JSON has the shape of `doctor --json` (T-049): `schema` and `podssh` first, and each time in a
key that ends in `_ms`.

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

## Correction

Measured on `2828281`, before this change: `podssh ping example.org` exits 64, as the Premise
says, but the message is now "unknown subcommand 'ping'. Try: podssh pipe": since the verb `pipe`
exists, `ping` is a close name. The other facts of the Premise hold at `2828281`.

## Done

Done on 2026-10-11. `podssh ping` (`crates/podssh-cli/src/ping/`, its flags in
`crates/podssh-cli/src/flags/ping.rs`) measures, with no destination, the relay leg of each relay
host: the token, DNS and TCP or CONNECT, TLS and the upgrade, each timed, then `--count` pings,
each matched to its pong by its payload. With a destination, the run is resolved as `podssh ssh`
resolves it, and adds the login, the echo through `cat` (after one round trip that is not
counted: the first can wait for the shell to start `cat`) and `--size` bytes down
(`head -c SIZE /dev/zero`) and up (`cat > /dev/null`), each command named. `--size` above 30
MiB, a bad `--count` or a bad `--target` exits 64 before any connection, and `PODSSH_OFFLINE` 69.
A program that the host lacks ends the run with 127, also when its status comes before the
server's reply. `RelaySession` keeps the last 64 pongs with the time each came. The manual
(`crates/podssh-cli/src/man/notes_ping.rs`, two examples, the rows of EXIT STATUS),
`docs/cli.md`, `README.md` and `AGENTS.md` name the command.

Prove, on Windows: `cargo test -p podssh-cli --test ping`, 11 passed, the checks through
`scripts/fake-relay.py` included (Python and openssl are here): the refusals, with no connection
to a relay host that counts them or to the SSH server; `PODSSH_OFFLINE`; the lines and the JSON
of `--direct` with 1 MiB each way; 127 for a host with no `cat`, and for one whose status comes
before the reply; a first echo 1 s late, not counted; a pong for each of 10 pings through the
stand-in, and a cached token on the second run; the JSON of the leg; 69 when no relay host
answers; and a destination through the stand-in after its leg. The test server of
`crates/podssh-cli/tests/ssh_harness/mod.rs` runs `cat`, `head -c N /dev/zero` and
`cat > /dev/null` as a POSIX server does. Planted, each caught by its assertion: the size limit
removed (the `--size 40M` case connects), the status before the reply ignored (255, not 127),
the offline check removed, a pong matched to another payload, the first echo counted. The suites
of `podssh-cli` and `podssh-ws`: 676 passed, 0 failed. In the build image, before the warm-up of
the echo: `scripts/interop.sh` 281 passed, 0 failed, with the new `scripts/interop-ping.sh`: a
pong for each of 10 pings through the stand-in relay, then the OpenSSH server through it: the
login, the echo, 8 MiB each way and exit 0, and `--json`. Live, before the tests: the relay legs
of the live relay's hosts to `github.com:22`, each with its steps and 5 pings.

# T-054: A machine-readable result for `podssh ssh`: exit status, signal and byte counts

**Source:** GitHub #23 (the `--json` of sleepinginsummer/agent-ssh-cli with `exitCode`, `stdout`
and `stderr`, and `exec` of Petyok/SSHub; read in the reports, not verified here). Measured on
`3ee70dc`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A script that runs `podssh ssh host command` gets only an exit code. It cannot tell a remote
exit of 255 from a failure of podssh, it must parse stderr for the signal name, and it gets no
byte counts and no name of the relay host.

## Premise

Measured: `podssh ssh --json example.org true` exits 64 (unknown flag).

Read: a session ends as `io::End` (`crates/podssh-ssh/src/io.rs:34-51`). The exit status and the
signal are read in `handle_msg` (`:372-390`). The output goes straight to the process's
stdout and stderr in `write_out` (`:414-431`), so nothing counts bytes. `session::run` maps
the end to the exit code (`crates/podssh-ssh/src/session.rs:39-47`). The relay host is known
at `crates/podssh-cli/src/ssh/transport.rs:137`, and the relay's close reason is in `RelayStatus`
(`crates/podssh-ssh/src/relay_stream.rs:63-105`).

## Approach

1. A long flag `--result-file FILE` for `ssh`, a podssh flag as `--relay-host` is. At the end of
   the run, write one JSON object to FILE: `schema`; `exit` (the code that podssh exits with);
   `status` (the remote exit status, or null); `signal` (name and core dump, or null); `end`
   ("status", "no-status", "lost", "escaped", "terminated" or "failed"); the class of a failure
   ("connect", "host-key", "auth", "relay"); `bytes` (stdin, stdout, stderr); `duration_ms`;
   `relay` (host, close code and reason), or null with `--direct`.
2. Count the bytes in one place: make the output sink of `io::pump` a parameter
   (`crates/podssh-ssh/src/io.rs:138-148`, and `write_out` at `crates/podssh-ssh/src/io.rs:414-431`). T-055 needs the same change.
3. stdout and stderr stay byte for byte as now; the command's output never goes into the JSON.
4. Write the file on each path, also after a failure before the session: at the end of
   `run_ssh` (`crates/podssh-cli/src/ssh/mod.rs:180-184`). Mode 0600. Refuse `-`: stdout is data.
5. Add the row to `SSH_FLAGS` (`crates/podssh-cli/src/flags.rs:112-280`; the set of short flags
   does not change), and change the `ssh` notes and `docs/cli.md` in the same commit.

## Decision

Recommendation: a file that the user names. A JSON line on stderr lost: the remote command
writes to the same stderr, and can print a line that looks like the result. A descriptor number
(`--result-fd 3`) lost: Windows passes descriptors to a child in another way, and podssh runs
there too.

2026-10-12, the calls made in the work:

- The record is the process's, in `podssh_ssh::outcome`, as the counts of
  the forwards are (T-041): atomics where the bytes pass, a lock for the
  rest; `run_ssh` writes it at its end, on each path. The sink of
  `io::pump` did not become a parameter (step 2): the bytes are counted
  where they are written, in `write_out` and in the copy of `-W`, which
  changes no signature. T-055 makes the sink a parameter if it needs one.
- `end` takes `signal` too: a command that a signal killed exits with
  128 + its number, as in OpenSSH, and `status` is then null. A run
  through a control master (T-039) ends `shared`: the master tells the
  exit code alone and carries the bytes, which are then null. With no
  session (`-W`) the end is null; `-N` ends `lost` when the server or the
  network ends the connection.
- `failure` takes `forward` and `session` too, and `usage`, `config` and
  `not-built` for the exits 64, 78 and 70 with no session; another failure
  with no session is `connect`. The relay's abnormal close is `relay` in
  place of another cause, as its lines come first (T-024). Each new
  connection of the run, a try again (T-025) or one of `--persist`, starts
  with no cause. On the node and iroh roads, the verdict of the channel
  (T-088) gives `auth`, `relay` or `session`.
- No file is written after a flag that podssh does not know: the command
  line is refused as a whole, and its `--result-file` is not read. None is
  written when a signal kills podssh: to catch SIGTERM and SIGINT with no
  terminal would change how podssh ends, which is how OpenSSH's `ssh`
  ends. A session on a terminal ends at SIGTERM or SIGHUP as `terminated`,
  and writes it.
- A new file gets the mode 0600 on Unix; a file that cannot be written is
  a line on stderr, and the exit stays the run's.
- The notes of `ssh` in the manual moved to
  `crates/podssh-cli/src/man/notes_ssh.rs`: with the note of the flag,
  `notes.rs` would have passed 500 lines.

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

## Done

2026-10-12. The record of a run in `crates/podssh-ssh/src/outcome.rs:1-157`:
the bytes at `crates/podssh-ssh/src/outcome.rs:68-76`, the end at
`crates/podssh-ssh/src/outcome.rs:86-102`, a run through a control master
at `crates/podssh-ssh/src/outcome.rs:104-115`, and the cause of a failure
at `crates/podssh-ssh/src/outcome.rs:117-136`. The bytes are counted where
they pass: stdin at `crates/podssh-ssh/src/io.rs:195`, stdout and stderr at
`crates/podssh-ssh/src/io.rs:429`, `-W` at
`crates/podssh-ssh/src/forward.rs:66` and
`crates/podssh-ssh/src/forward.rs:83`. The status and the signal at
`crates/podssh-ssh/src/io.rs:373` and `crates/podssh-ssh/src/io.rs:378`,
the end at `crates/podssh-ssh/src/session.rs:38`; the class of a hop's
failure at `crates/podssh-ssh/src/run.rs:136-146` and
`crates/podssh-ssh/src/run.rs:186`, a new connection at
`crates/podssh-ssh/src/run.rs:156`, the relay's close first at
`crates/podssh-ssh/src/run.rs:68-75`; a control master at
`crates/podssh-ssh/src/mux/client.rs:168`,
`crates/podssh-ssh/src/mux/client.rs:202` and
`crates/podssh-ssh/src/mux/client.rs:264-271`. The object in
`crates/podssh-cli/src/ssh/result.rs:15-46`, the channel's verdict at
`crates/podssh-cli/src/ssh/result.rs:48-58`, the file at
`crates/podssh-cli/src/ssh/result.rs:60-74`, written at the end of
`run_ssh` (`crates/podssh-cli/src/ssh/mod.rs:56-86`); the relay host at
`crates/podssh-cli/src/ssh/transport.rs:138` and its close at
`crates/podssh-cli/src/ssh/mod.rs:262`. The flag in `SSH_FLAGS`
(`crates/podssh-cli/src/flags.rs:199`), its note at
`crates/podssh-cli/src/man/notes_ssh.rs:243-255`, and `docs/cli.md`.

The test `crates/podssh-cli/tests/ssh_result.rs`, against the test server,
whose `exit N` and `kill NAME` are in
`crates/podssh-cli/tests/ssh_harness/ends.rs`: `exit 3` gives exit 3,
status 3, the end `status` and the bytes 0, 4 and 5, with stdout and stderr
as they were; `kill TERM` gives 143, status null and the signal TERM, and
`kill SEGV` 139 with `core_dumped`; 100,000 bytes through `cat` are counted
each way; a refused login gives `auth`, and a port where nothing listens
`connect`, each with the end `failed`; `-W /echo` carries 10,000 bytes each
way with no end, and a socket that the server refuses gives `forward`; `-`
is refused with 64, and a usage error is written with `usage`. Planted
defect: stderr counted as stdout; the first test failed. In the build
image, the new `scripts/interop-result.sh`, 9 passed, 0 failed: against
OpenSSH and against Dropbear, `exit 3`, `kill -TERM $$` (143 and the signal
TERM), 5,000,000 random bytes up and back through `cat` with the same
SHA-256 and the count 5,000,000 each way, and a login that no key opens
(255, `failed` and `auth`); and a run through a podssh control master,
which gives exit 3, the end `shared` and the bytes null. There, the tests
of the control master and `cargo clippy -p podssh-ssh -p podssh-cli
--all-targets -- -D warnings`: no failure, no warning. Here, clippy with
and without the feature `iroh`: no warning; the suites of `podssh-ssh` and
`podssh-cli`: 774 passed, 0 failed, 31 ignored (the live tests).

# T-055: `podssh mcp`: the commands as tools for an agent, over stdin and stdout

**Source:** GitHub #18 (the MCP interface of mirkobozzetto/bunflared,
`mirkobozzetto/bunflared:src/mcp/mod.rs`); GitHub #20 and #24 (the command line for agents of
l0ng-ai/tty7, `l0ng-ai/tty7:crates/tty7-cli/src/commands.rs`). Read in the reports, not verified
here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An agent that speaks MCP must run podssh through a shell and parse its text. An MCP server over
stdin and stdout gives typed tools, with no shell quoting.

## Premise

Measured: `podssh mcp` exits 64 (unknown subcommand).

Read: a prompt goes to the controlling terminal or to `SSH_ASKPASS` (`docs/cli.md:2426-2451`),
and the terminal of an agent can be the user's own. The session output goes straight to the
process's stdout (`crates/podssh-ssh/src/io.rs:414-431`), which an MCP server over stdio uses for
its protocol. podssh never listens (`docs/architecture.md:120-133`), and stdio needs no listener.

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

2026-10-12, the calls made in the work:

- Each call runs this binary again, as a child with pipes (`podssh ssh`,
  `status`, `doctor --json`, `man --json`), in place of the sink of step
  4: the records of `podssh-ssh` are the process's (the result of T-054,
  the counts of T-041, the phase of a try, the handler's last error), one
  chain of connections for each process, so one process could not run two
  calls at once. A child per call runs four at once, ends with its call at
  the limit or at a cancellation, and a stray write of the session path
  reaches the call's stdout, never the protocol's. The sink of `io::pump`
  stays as it is.
- The protocol has moved since the entry was written: its revision
  2026-07-28 has no handshake, each request names its version and the
  client's capabilities in `_meta`, `server/discover` is required, and
  each result carries `resultType`. podssh serves both eras, as that
  revision lets a server do: a request with its version is answered by
  itself; `initialize` chooses a revision of the handshake (2025-11-25,
  2025-06-18, 2025-03-26 or 2024-11-05) for the rest of the process; a
  request with neither is refused (-32602), and an unknown version gets
  -32022 with the versions that podssh has.
- The options of each session come before `-F FILE`, as the first value
  of a keyword holds: `BatchMode=yes`, `StrictHostKeyChecking=yes`,
  `ClearAllForwardings=yes`, `ForwardAgent=no`, `ForwardX11=no`,
  `ControlMaster=no`, `ControlPath=none`, `-T` and `-e none`. With no
  forward and no agent, an allowed host cannot carry a call to another;
  with no shared connection, each result has its bytes and its status.
  The server takes `-F FILE` and `--direct` for its sessions, and nothing
  else of `ssh`: the rest is in the user's `ssh_config`.
- A pattern of `--allow-host` is `[USER@]HOST` with `*` and `?`, as a
  `Host` line has them, and `!` excludes; the host is matched as the call
  names it, with no regard to case, before `HostName`. A destination is
  `[user@]host` with no port and no path: the port is the configuration's
  too. A pattern with `USER@` lets in only a destination that names that
  user, and an exclusion with one also excludes a destination that names
  none, whose user the configuration gives.
- `status` takes a destination only within `--allow-host`: it says whether
  `known_hosts` holds a host's key, which `HashKnownHosts` hides.
- An argument that a tool does not have is refused, as a misspelt one
  would be ignored; a wrong argument is the call's error (`isError`),
  which the agent can correct, as the revision 2026-07-28 has it, and an
  unknown tool is a protocol error. `isError` is true when podssh failed
  or the limit passed, not for a command whose status is not 0.
- At the end of stdin, the calls in flight have 2 s, and then end with
  their children: a client that closes stdin waits a short while before
  it ends the server, and no child may outlive it. SIGTERM, SIGINT and
  SIGHUP (Ctrl-C, Ctrl-Break and the close of the console on Windows)
  end them at once.

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

## Done

2026-10-12. `podssh mcp` in `crates/podssh-cli/src/mcp/mod.rs:59-100`, its
lines and its calls in flight at `crates/podssh-cli/src/mcp/mod.rs:107-183`,
the signals that end it at `crates/podssh-cli/src/mcp/mod.rs:187-213`, a
call at `crates/podssh-cli/src/mcp/mod.rs:216-245`. The messages in
`crates/podssh-cli/src/mcp/protocol.rs:68-101`, the two eras at
`crates/podssh-cli/src/mcp/protocol.rs:111-166` and
`crates/podssh-cli/src/mcp/protocol.rs:186-218`, the answers at
`crates/podssh-cli/src/mcp/protocol.rs:230-243`. The tools at
`crates/podssh-cli/src/mcp/tools.rs:37-115`, the command line of a call at
`crates/podssh-cli/src/mcp/tools.rs:130-206`, with the options of each
session at `crates/podssh-cli/src/mcp/tools.rs:186-204`, and its result at
`crates/podssh-cli/src/mcp/tools.rs:227-261`. The child of a call at
`crates/podssh-cli/src/mcp/child.rs:63-122`, its streams at
`crates/podssh-cli/src/mcp/child.rs:125-157`. The patterns of
`--allow-host` at `crates/podssh-cli/src/mcp/allow.rs:36-124`. The flags in
`crates/podssh-cli/src/flags/mcp.rs`, the risk and the rest in the manual
(`crates/podssh-cli/src/man/notes_mcp.rs:4-27`), and `docs/cli.md`.

The test `crates/podssh-cli/tests/mcp.rs`, 4 tests, over the stdin and the
stdout of `podssh mcp`, reads each line of stdout as one JSON-RPC answer:
the handshake of 2025-06-18, the list (`ssh_exec`, `status`, `doctor`,
`man`), `ping`, -32700, -32600, -32601 and -32602, and `server/discover`
and `tools/call` of `man` in the revision 2026-07-28; a host outside
`--allow-host` is refused with an error result, and a listener behind it
gets no connection, nor does one with no `--allow-host`, where `ssh_exec`
is not offered; a bad pattern exits 64, and a missing `-F` file 78.
Against the test's SSH server: an unknown host key fails with `host-key`;
with its fingerprint, `exit 3` gives the exit 3, the status 3, the stdout
`out` and the stderr `err!`, and the same JSON as text; `cat` gives its
stdin back; 1,500,000 bytes are cut at 1 MiB with `truncated`; a call past
its limit of 1 s ends with `timed_out`; a cancelled call gets no answer
while `ping` gets one; and the end of stdin with a call in flight ends the
server with 0. The unit tests: 17, of the patterns, the messages, the
command line of each tool and the results. Planted defects: a `println!`
in the call path failed 3 tests, each at the line that is not JSON-RPC;
a `println!` in the session path reached the call's stdout, not the
protocol's, and failed the test of `ssh_exec`. In the build image, the new
`scripts/interop-mcp.sh`, 4 passed, 0 failed: `ssh_exec` to OpenSSH and to
Dropbear gives the status 3 and the stdout `hi`, a host outside
`--allow-host` gets an error result, and each line of stdout is one
JSON-RPC answer; there, clippy with `-D warnings` and the tests of `mcp`:
no warning, no failure. Here, clippy: no warning; the suites of
`podssh-cli` and `podssh-ssh`: 795 passed, 0 failed, 31 ignored (the live tests).

# T-056: A log of the sessions of this host, when the user asks for it

**Source:** totoshko88/RustConn (connection history and statistics, GitHub #24; read in the
report, not verified here).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A user cannot see which sessions ran from this host, how long they took, through which relay
host, and how they ended. Each of these facts is lost when the process ends.

## Premise

Read: podssh keeps no record of a session. `-E LOGFILE` appends podssh's own messages, which is
another purpose (`crates/podssh-cli/src/flags.rs:141-142`). The cache directories and the rules
for private files are in `crates/podssh-relay/src/cache/dirs.rs:50-87` and
`crates/podssh-relay/src/cache.rs:176-300`. `write_private`
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
7. Add the variable to VARIABLES (`crates/podssh-cli/src/man/facts.rs:45-242`; the tests require
   it) and the file to FILES, in the same commit.

## Decision

2026-10-12, the calls made in the work:

- `PODSSH_SESSION_LOG` takes `1` or `yes` (the cache), an absolute path
  (that file; `~` is the home), and `0` or `no` (none), and beats
  `SessionLog` of the settings file, which takes the same values; an
  empty variable is unset. Another value is refused (78) before anything
  connects, as each variable's is, and `podssh status` refuses it alike.
- A line is one of a run that named its destination: an `-O` request,
  `-G` and a usage error add none. `via` is the relay host that answered,
  else the road: `relay` (no relay host answered), `direct`, `node`,
  `iroh` or `cloudflare`.
- `podssh proxy` has no SSH session: its line ends `closed` or `failed`,
  its `failure` is `relay` when no session opened, when the relay closed
  with another code than 1000, or when it exits with another code than 0,
  and its bytes are those of the pump, which counts each way now
  (`stdin` sent, `stdout` received).
- A file that a path names keeps its directory as it is: podssh makes the
  file private when it makes it, and refuses one that is a symbolic link,
  another user's, or that others can read, as the cache's files. A line
  that cannot be written is a line on stderr, and the exit code stays the
  run's.
- The file is moved aside by the run that finds it full, before its line:
  two runs that find it full at the same moment can each move a file
  aside, and the second then replaces `sessions.1.jsonl` with a file of
  few lines. The log is a record for its user, not an audit trail; T-116
  is the audit log of `serve`.

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

## Done

2026-10-12. The log in `crates/podssh-cli/src/session_log.rs:1-260`: its
values at `crates/podssh-cli/src/session_log.rs:44-75`, the facts of a run
at `crates/podssh-cli/src/session_log.rs:97-118`, the lines of `ssh` and
`proxy` at `crates/podssh-cli/src/session_log.rs:130-168`, the file, its
checks and its move aside at `crates/podssh-cli/src/session_log.rs:171-240`,
and its last line at `crates/podssh-cli/src/session_log.rs:243-260`. The
line of `podssh ssh` at the end of `run_ssh`, from its result
(`crates/podssh-cli/src/ssh/mod.rs:59-86`), and its destination at
`crates/podssh-cli/src/ssh/mod.rs:152`; that of `podssh proxy` at
`crates/podssh-cli/src/proxy.rs:47-61`, its destination at
`crates/podssh-cli/src/proxy.rs:96` and `crates/podssh-cli/src/proxy.rs:155`,
its session at `crates/podssh-cli/src/proxy.rs:258-261`; the bytes of the
pump at `crates/podssh-cli/src/pipe/pump.rs:94` and
`crates/podssh-cli/src/pipe/pump.rs:104-132`, and the relay's close at
`crates/podssh-cli/src/pipe/relay.rs:198`. `SessionLog` at
`crates/podssh-cli/src/settings.rs:246-249`, and `podssh status` at
`crates/podssh-cli/src/status.rs:103-114`. The variable in VARIABLES, the
two files in FILES, and `docs/cli.md`.

The test `crates/podssh-cli/tests/session_log.rs`, 4 tests, against the
test's SSH server: with no variable and with `0`, no file appears; with
`1` and `yes`, each run adds one line with its verb, host, port, `via
direct`, end, exit and bytes, and the run of `exit 0 SECRET-WORD` leaves no
`SECRET-WORD` and no `exit 0` in the file; the mode is 0600 on Unix;
`podssh status` gives the file and the last line, and null with the log
off; two runs at once give two whole lines in the file that a path names;
`SessionLog yes` in the settings file turns it on and `PODSSH_SESSION_LOG=no`
off; a bad value of either exits 78 and names it; a proxy that could not
open, offline, adds a line that ends `failed` with `relay`, and a usage
error adds none. The unit tests, 5: the values, the order of the variable
and the file, three lines appended at 0600 and a full log moved aside, a
symbolic link and a file that others read refused (Unix), and the lines of
both verbs. Planted defect: the command line in each line; the test failed
at the check of `SECRET-WORD`. In the build image, `scripts/interop-result.sh`
with the new `result.session_log`, 10 passed, 0 failed: a run of
`echo SECRET-WORD` against OpenSSH adds one line, of `ssh` to port 2201,
`direct`, exit 0, with no `SECRET-WORD`; there, clippy with `-D warnings`
and the tests of the log: no warning, no failure. Here, clippy: no warning;
the suites of `podssh-cli` and `podssh-ssh`: 803 passed, 0 failed, 31 ignored (the live tests).
