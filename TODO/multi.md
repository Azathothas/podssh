The backlog of work on many hosts and sessions at once: one command on many
hosts, host lists, broadcast, a control surface for agents, snippets, a host
picker, the facts and the jobs of the far host, a queue of jobs, and a hook
that hands an error report to a program that the user names. podssh stays a
CLI, with no GUI and no TUI (the operator's ruling of 2026-10-08,
`docs/decisions.md`). Most sources are the reports in GitHub #18 to #24
(`TODO/issues.md`).

# T-183: Run one command on many hosts

**Source:** GitHub #24 (fan-out with fail-fast and require-all-success, from
the bssh report); GitHub #18 (the bssh report, item 10: output modes and
`lablup/bssh:src/hostlist/`). Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An operator runs one command on ten hosts with a shell loop. The outputs mix,
a slow host blocks the others, and no exit status says whether each host
succeeded. `podssh ssh` takes one destination, as OpenSSH does.

## Premise

- Measured: `podssh each a,b -- true` exits 64 (`unknown subcommand 'each'`),
  and `podssh ssh 'web1,web2' true` exits 64 (`',' is not allowed`).
- Read: remote output goes straight to the stdout and stderr of the process
  (`crates/podssh-ssh/src/io.rs:414-431`), and podssh's own messages go to
  stderr with one `podssh: ` prefix (`crates/podssh-ssh/src/log.rs:83-103`).
  Two hosts cannot be told apart.
- Read: a host-key prompt waits for the user
  (`crates/podssh-ssh/src/hostkey.rs:208-246`); N prompts at once cannot
  work. `known_hosts` is appended under a lock since T-029
  (`crates/podssh-ssh/src/known_hosts.rs:335-410`).
- Read: with no cached token, each session mints one
  (`crates/podssh-relay/src/token.rs:134-179`); the relay allows 120 attempts
  with no token for each minute and address (`docs/relay.md:168`).

## Approach

1. A verb `each`: `podssh each [OPTIONS] HOSTS -- COMMAND`, HOSTS a comma
   list (T-184 adds braces and groups). The options: those of `ssh` that make
   sense for many hosts (`-p`, `-l`, `-i`, `-o`, `--direct`, the relay
   flags), and `--parallel N` (default 8, 64 at most), `--fail-fast`,
   `--output-dir DIR`.
2. One runtime, one task for each host, each on the existing path: the relay
   open and `podssh_ssh::run` (`crates/podssh-cli/src/ssh/mod.rs:198-274`,
   `crates/podssh-ssh/src/run.rs:35-80`). Invariant: no second SSH client.
3. Sinks: give `crates/podssh-ssh/src/io.rs:138-431` a sink for stdout and
   stderr in place of the streams of the process, and give `Log` a prefix
   (`crates/podssh-ssh/src/log.rs:12-18`). Each line gets `HOST: `. With
   `--output-dir`, the bytes go unchanged to `HOST.out` and `HOST.err`, and
   the status to `HOST.status`.
4. No prompts: BatchMode is on (`crates/podssh-cli/src/ssh/login.rs:86`).
   An unknown host key refuses that host and gives its fingerprint and
   `-o StrictHostKeyChecking=accept-new`. stdin is not read
   (`crates/podssh-cli/src/ssh/resolve.rs:411`).
5. Get the token once, before the fan-out. Serialize `known_hosts::append`
   in the process with a mutex; T-029 covers two processes.
6. The exit status: the largest status of the hosts, and 255 for a host that
   could not connect or log in; 0 only when each host gave 0. `--fail-fast`
   starts no new host after a failure, and the running ones finish. A
   summary on stderr gives each host and its status.
7. In the same commit: `crates/podssh-cli/src/flags.rs:376-427`,
   `crates/podssh-cli/src/positionals.rs:7-178`, a `Parsed` variant,
   `crates/podssh-cli/tests/flag_table.rs:110-136`, the notes, an example,
   `docs/cli.md`, `docs/STATUS.md`. T-013 can then group the commands.

## Decision

Recommendation: a new verb, because `podssh ssh` keeps the command line and
the exit codes of OpenSSH for one host (`docs/cli.md:2078-2081`), and a list
of hosts changes both. The alternative, `podssh ssh --hosts LIST`, lost: one
flag would change what the exit status means.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test each   # the exit rule, --fail-fast, the refusals (64)
sh scripts/dev.sh check                # interop.sh: the hosts below
```

The test gives the statuses 0, 3 and 255 in each order. In
`scripts/interop.sh`, `each` with `podtest@127.0.0.1:2201,podtest@127.0.0.1:2203`
and `exit 3` exits 3, with one prefixed line for each host; a closed port
adds 255 and is named. Plant: return the status of the first host; the order
0, 3 must fail.

## Done

2026-10-12. Written as a draft, then merged over T-148 and T-181.
`crates/podssh-cli/src/each/` (`mod.rs`: the command line, the plan of each
host before anything connects, the summary and the exit; `fan.rs`: the
fan-out, the rule of the exit status and the summary's lines, plain
functions of the hosts' ends; `host.rs`: one host on the road and the SSH
client of `podssh ssh`, `transport::reach` and `podssh_ssh::run::run_outcome`,
and the token before the hosts; `out.rs`: the lines with their label, the one
writer, and the files of `--output-dir`), the rows of
`crates/podssh-cli/src/flags/each.rs`, and the notes of
`crates/podssh-cli/src/man/notes_each.rs`. In `podssh-ssh`: `io::Sink`, a
channel that takes a session's output in place of the process's streams,
carried by `Options::output` (the bytes unchanged, with no console's
conversion, which the writer does for a line); `Log::with_prefix`, which
puts the prefix on each line of a message; and a mutex of the process around
`known_hosts::append`. The calls made: the command line is `podssh each
[OPTIONS] HOSTS [--] COMMAND...`, the command's words joined as `ssh` joins
them; the flags are those of the Approach, and `-F`, `-J`, `-v`, `-q` and
`--relay-failover` too, with `-p` and `-l` as on `ssh`; a far line is
`HOST: LINE`, and podssh's own lines of a host are `podssh: HOST: ...`, each
line of a message, so that the rule that podssh's lines start with
`podssh: ` holds; the label is the host as the list writes it; a host named
twice runs once; a note or a warning that each host has is said once; one
writer task puts each whole line, through tokio's stdout and stderr, so that
a slow reader holds no host's session; a line of more than 64 KiB comes in
pieces, and a last line with no newline gets one; with `--output-dir` the
files are made before anything connects (73), their names have `%XX` for
each byte but a letter, a digit, `.`, `_`, `-` and `@`, two hosts whose
files differ only in case are refused (64), a status file of an earlier
run is removed, and a host that never ran has none; the token before the
hosts is `token::obtain` at the first relay host, skipped offline, with
`--direct` and with `PODSSH_CACHE_DIR=none` (then each host mints, as each
run does); a `SessionType` that asks for no command and a `node://` or
`iroh:` destination are refused (64), and the forwards, X11 and the control
socket of `ssh_config` are not used (said with `-v`); a host is not tried
again after a drop of the relay (T-025), as the phase of a try
(`podssh_ssh::retry`) is the process's; a host that never started adds
nothing to the exit, which a failure already made non-zero; `-q` leaves the
summary out. `cargo test -p podssh-cli --test each` (the statuses 0, 3 and
255 in each order and the plant's order 0, 3; `--fail-fast` on a paused
clock; the refusals, 64, offline; each host named with 255 offline; against
the test's server on the loopback, 0, 127 and 255 in each order, one line of
known_hosts after two sessions that met the key at once, the lines and the
files of `exit 3`, `--fail-fast` with one at once, and an unknown host key):
8 passed here (Windows 11). The unit tests of `each::` (the comma list,
`--parallel`, the names of the files, the lines): 5 passed; the lib suite,
283. The plant of the Prove, the first host's status as the exit: the
orders failed (`the_exit_is_the_largest_status_in_each_order` and
`each_order_of_0_127_and_255_exits_255_and_each_host_is_named`), and it was
taken out. In the merge: `io::Sink` also takes ZMODEM's screen (T-148); the
run's input moved from `crates/podssh-ssh/src/io.rs` to its own module,
`crates/podssh-ssh/src/io/input.rs`, so that the file keeps under 500
lines; and the note of `--output-dir` names the dot, the underscore and the
hyphen in words, as the check of the notes reads `_` as a variable. The
code has no Unix-only branch. The gate's checks
(`scripts/interop-each.sh`, sourced by `scripts/interop.sh`: OpenSSH and
Dropbear at once with `exit 3`, the orders 0, 3 and 3, 0, a closed port, the
bytes of `--output-dir`, an unknown host key, `--fail-fast`) passed in CI
(cad2885, the step `release`: `each.lines`, `each.order.0_3`,
`each.order.3_0`, `each.closed`, `each.output_dir`, `each.host_key` and
`each.fail_fast`); the planted defect in the gate, the first host's status,
waits for T-251. Each host's session
takes the process's records (`podssh_ssh::outcome`, `retry`, and the
handler's last error): a lost session's words may name another host's
error, and `podssh each` writes no `--result-file` and no line of the
session log.

# T-184: Host groups and brace expansion of host names

**Source:** GitHub #24 (csshw: cluster tags and `host{1..3}`; RustConn:
groups, and settings for each host); GitHub #18 (bssh:
`lablup/bssh:src/hostlist/`). Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

To reach `web1` to `web12`, a user types twelve names or relies on the
shell. dash, cmd and PowerShell do not expand `{1..12}`, and a settings file
is not a shell. A set of hosts has no name.

## Premise

- Measured: `podssh ssh 'web{1..3}' true` exits 64 (`'{' is not allowed`),
  and `podssh ssh '@web' true` exits 64 (`"@web": empty user name`). Thus
  `{` and a leading `@` are free.
- Read: each host is checked before a connection
  (`crates/podssh-cli/src/ssh/hop.rs:30-78`,
  `crates/podssh-ws/src/names.rs:10-24`).
- Read: the `Host` lines of ssh_config are patterns, not lists
  (`docs/cli.md:2196-2289`); they cannot define a group.

## Approach

1. A new module crates/podssh-cli/src/hosts.rs expands `PREFIX{A..B}SUFFIX`
   (a zero padding of A is kept: `{01..12}`), `{a,b,c}`, and nesting, as
   bash does. More than 1000 hosts, an empty list or a reversed range exits
   64.
2. `@NAME` reads the `[groups]` table of the settings file (T-048). A group
   can name groups; a cycle exits 78.
3. Expand first, then check each name with `parse_hop` and `check_host`, so
   that a bad name fails before anything connects.
4. The users: `each` (T-183) and the broadcast (T-185). `podssh ssh` refuses
   a pattern that gives more than one host, with 64 and the hint
   `podssh each`.
5. The settings for each host stay in the `Host` blocks of ssh_config
   (T-043).
6. In the same commit: `docs/cli.md` (the grammar), the notes of `each`,
   `docs/STATUS.md`.

## Decision

Recommendation: the braces of bash, because users know them and csshw uses
them. The alternative, ranges in brackets as in pdsh and bssh (`web[1-3]`),
lost: brackets already mean an IPv6 literal (`docs/cli.md:86-89`, T-007).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli hosts::
```

The cases: `web{1..3}`, `{01..10}` with its padding, `a{b,c}d`, nesting,
1001 hosts refused, `@group` from a fixture file, and a cycle refused.
Plant: drop the zero padding; the case `{01..10}` must fail.

## Done

2026-10-12. Written as a draft over T-183.
`crates/podssh-cli/src/hosts.rs` expands a word: the items at each comma
outside braces, the braces of each item in bash's order, the first pair
first and each result again, and `@NAME` from the table of groups; its
tests are in `crates/podssh-cli/src/hosts_tests.rs`, with the fixture
`crates/podssh-cli/tests/fixtures/groups.settings`. `settings.rs` reads the
table: after a line `[groups]`, each line is `NAME HOSTS`, into
`Defaults::groups`, and the whole table is expanded once as the file is
read, so that a fault of a group is the file's (78, with its line), refused
by each command that checks the settings (`pins::apply`), as each bad line
of the file is. `podssh each` expands its word with it before any host is
resolved, and `resolve_or_refuse` takes `hosts::one` of the destination.
The calls made: a range of letters (`{a..c}`) and a step (`{A..B..N}`, N
at least 1) are taken, as bash takes them; the padding is bash's, the width
of the wider of A and B when either starts with a 0 (`{1..010}` gives
`001`); an empty item of a list gives the rest alone, as in bash
(`w{,1}`), and an empty host is refused; blanks outside braces part hosts
as commas do, for the lines of the table, and a blank inside braces is
refused; braces that hold nothing, or neither a list nor a range, are
refused where bash would keep them as text, as no host name holds a brace;
a host given twice runs once; the limit of 1000 counts the hosts after
that, and a range is refused before it is made; a group that the command
line names and the table lacks is 64 and names the groups that there are,
while one that a group names is the file's (78); a group's name has
letters, digits, `.`, `_` and `-`, not first a `.` or a `-`, and a name
that is a setting's keyword, a group given twice and a table other than
`[groups]` are refused, so that a setting put after the table is not taken
for a group; a pattern that gives one host is that host for `podssh ssh`
and each command that resolves a destination as it does, so that a group
of one names a bastion, and one that gives more is refused (64), naming
`podssh each`. `cargo test -p podssh-cli hosts::` (`web{1..3}`, `{01..10}`
with its padding, letters and a step, `a{b,c}d`, nesting, `h{1..1001}`
and three other ways past 1000 refused, the other refusals, `@group` from
the fixture, `podssh ssh`'s pattern of one host and of three, and a cycle
of two groups and of one refused with its line, 78 also at run time):
5 passed here (Windows 11). `cargo test -p podssh-cli --test each --
braces_and_groups` (through the binary, offline: a group and a range give
five hosts, each named; the refusals of `each` and of `ssh`, 64; a group
of one for `ssh`; a cycle in the file, 78): passed, with the 8 tests of
T-183, 9 in all; the lib suite, 287; `--test flag_table` and `--test
man_flag_parity`, 8 and 5; clippy clean. The plant of the Prove, the
padding dropped: `a_range_gives_each_number_and_keeps_a_zero_padding` and
`a_group_of_the_settings_file_names_hosts_and_groups` failed, and it was
taken out. The broadcast of T-185 is not built: it will
take the same word.

# T-185: Interactive broadcast to several sessions, with an emergency stop

**Source:** GitHub #24 (csshw: a daemon and N clients,
`whme/csshw:src/daemon/grid.rs`; MobaRust: a broadcast with an emergency
disable; rssh: a workbench of sessions); GitHub #21 (meatshell: quick
commands to each session). Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** done

## Problem

To type the same commands on several hosts, a user needs csshw, the
`synchronize-panes` of tmux, or a GUI. A broadcast mistake costs N times, so
a broadcast needs a stop that works at once.

## Premise

- Read: a session reads stdin on its own task and sends each chunk to one
  channel (`crates/podssh-ssh/src/io/input.rs:102-122`,
  `crates/podssh-ssh/src/io.rs:183-238`).
- Read: escapes work only at the start of a line, and only with a pty
  (`crates/podssh-ssh/src/escape.rs:1-8`).
- Read: each session can live in one process, so a broadcast needs no
  listener (`docs/target-environment.md:84-88`).

## Approach

1. Line mode: `podssh each --interactive HOSTS` opens a shell with no pty on
   each host (T-183, T-184). Each output line has its `HOST: ` prefix. The
   local terminal keeps its normal mode, so that its own line discipline
   edits the line.
2. Each line goes to the selected hosts. A line that starts with `:` is for
   podssh: `:only HOST...`, `:all`, `:none`, `:list`.
3. The emergency stop is a key that the terminal turns into a signal:
   Ctrl-\ (SIGQUIT) on Unix, Ctrl-Break on Windows. It clears the selection
   and the queued input at once, also while a line is half typed, and says
   "broadcast stopped; :all starts it again".
4. With `--confirm`, a line for more than one host waits for a second Enter.
   Ctrl-C goes to no host; `:intr` sends the `signal` request to the
   selected hosts (T-131 measures which servers honour it).
5. Each host has a queue of 64 KiB. A host whose queue is full leaves the
   selection with a message; typed input is never dropped silently.
6. No panes and no full-screen view: podssh has no TUI (the operator's
   ruling of 2026-10-08). Line mode is the whole feature.
7. In the same commit: the notes of `each`, `docs/cli.md`, `docs/STATUS.md`.

## Decision

- **The queue is the session's input, which the caller can take back.**
  `podssh_ssh::io::Feed` (`crates/podssh-ssh/src/io/feed.rs`) is a
  session's input in place of stdin (`Options::feed`, `Input::fed`): the
  hub puts each line in, and the session takes one line only when it can
  send it, so each line that waits for a slow host is in the feed, where
  the stop takes it back. Lost: a channel of tokio for each host and a task
  that passes the lines on, as `io::Input` reads stdin; the task and the
  channel would hold up to three lines that the stop can no longer reach.
- **`:intr` goes through the same feed.** The loop of the session
  (`Termination`, `crates/podssh-ssh/src/terminal/termination.rs`) sends
  `signal INT` when the feed asks, and goes on. Lost: a second channel
  in `Options`, and a new arm in the loop of `io.rs`, which several drafts
  change.
- **A full queue refuses the line for that host alone.** The line goes to
  the other hosts; the full host leaves the selection, podssh names it, and
  the summary counts the lines that did not reach it. Lost: dropping the
  queue (typed input dropped), waiting for the slow host (one host would
  stop the broadcast for each host), and a part of a line.
- **The stop drops what waits, and ends no session.** It selects no host,
  and drops each queue, a line that waits for `--confirm`, the start of a
  line, and what podssh read and did not act on yet. A line that a session
  has taken is in the SSH channel, or is the one line that it sends now:
  that goes. Lost: closing each session at the stop, which would cost once
  for each host, as the mistake that the stop is for; `exit` and the end of
  the input remain.
- **The stop is armed before anything connects, and always.** Where
  tokio cannot set the handler, podssh exits 78 (`Fault::Capability`: a
  probe that the mode needs failed). A SIGQUIT that was ignored at the
  start (`&` in a script leaves it so) is armed too, unlike the SIGINT of
  T-293: a stop that is off in some runs is no stop. Lost: a broadcast with
  no stop, and keeping an ignored SIGQUIT ignored.
- **Ctrl-C goes to no host, and cuts only after the end of the input.**
  While the input goes on, it says what to type; after the end of the
  input, it ends the wait for the shells that still run, each with 130 (as
  T-293's `End::Interrupted`). Lost: Ctrl-C that ends podssh at once
  (OpenSSH's way for `-T`): one key cuts each shell; `signal INT` to each
  selected host at Ctrl-C (T-293's way for one host): a key typed by habit
  would signal many hosts, so `:intr` asks for it by name. Ctrl-C is armed
  even when SIGINT was ignored at the start: it ends nothing while the
  input goes on.
- **`:only` names a host by its label, or by its label without `USER@`**,
  and a word takes the braces and the groups of HOSTS
  (`crates/podssh-cli/src/hosts.rs`); a word that names no host changes
  nothing. Lost: a part of a name, which can select a host that the user
  did not mean. A line that starts with `::` goes to the hosts with one `:`
  less: `:` is a command of the shell (`: > file`).
- **`--confirm`: an empty line is the second Enter.** Another line drops
  the line that waits, with a word, and is read as a new line; an empty
  line is never held. Lost: an answer `y`, which is also a command that a
  host could run.
- **64 hosts at most with `--interactive`**, the most of `--parallel`:
  each host is open at once. `--parallel`, `--fail-fast` and `--output-dir`
  are refused (64), as they are for a command. A `RemoteCommand` of
  `ssh_config` is not used, with a note of `-v`; a `SessionType` that asks
  for no shell is refused (64).
- **The exit status is the shells'**, the largest, as for a command; a
  host whose queue was full keeps its status, and the words at the time and
  in the summary say what it missed. Lost: a status of its own for a missed
  line: no code of sysexits fits, and 1 is a remote status.
- **The banner and the note at the end of the input are left out with
  `-q`**; the answers to the commands and the stop's words are not.
- **The tests' server is the test's own**
  (`crates/podssh-cli/tests/each_interactive/shell.rs`), with a shell that
  reads lines, as a shell on a pipe does; the server of
  `crates/podssh-cli/tests/ssh_harness/mod.rs` runs commands and gives no
  shell, and the file is at 494 lines, which four drafts change. The stop
  is tested by SIGQUIT through a pipe on Unix; by `Ctrl-\` typed into a
  pty that is podssh's controlling terminal on Linux (the pty of
  `pty_harness` is no controlling terminal, so the test gives one with
  `setsid` and `TIOCSCTTY`); and on Windows by Ctrl-Break typed into a
  pseudo console,
  as a key of the win32 input mode (VK_CANCEL with Ctrl), since no byte is
  Ctrl-Break: the keys that `crates/podssh-cli/tests/console.rs` types for
  T-295.
- **The gate's check is `scripts/interop-broadcast.sh`**, sourced at the
  end of `scripts/interop-each.sh`, as `scripts/interop.sh` has 500 lines;
  its file is `/tmp/podssh-after-stop`, the name of the Prove with
  podssh's prefix. After the stop it also types `:all`, which must start
  the broadcast again: a planted stop that ends podssh (no handler, so
  SIGQUIT's default action) then fails too.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test each -- interactive   # the selection, the queue limit, SIGQUIT
sh scripts/dev.sh check                               # interop.sh: the lines below
```

In `scripts/interop.sh`, lines from a pipe go to the ports 2201 and 2203.
After `:only 127.0.0.1:2203`, `echo only` reaches one host. After
`kill -QUIT`, the line `touch /tmp/after-stop` makes no file. Plant: ignore
SIGQUIT; the check of `/tmp/after-stop` must fail.

## Done

2026-10-13, written as a draft; merged in `d1c5bd1` with no run. Each
result below was measured on 2026-10-30: natively on Linux (a Claude Code
cloud container, Rust 1.99.0), and in CI at `d1c5bd1` (run 41040124516:
each job green, the Windows tests and the gate's steps in the build image).

- **The SSH client** (`crates/podssh-ssh`): `io::Feed`
  (`crates/podssh-ssh/src/io/feed.rs`), lines in, taken back, the end, and
  `signal INT` requests; `Options::feed`; `Input::fed`, which reads the
  feed and never stdin; `session::run` takes the feed when the options give
  one; `Termination::fed` sends the feed's `signal INT` on the channel, and
  the session goes on.
- **The command** (`crates/podssh-cli/src/each/broadcast/`): `--interactive`
  and `--confirm` (the rows of `crates/podssh-cli/src/flags/each.rs`,
  routed in `dispatch.rs`); `host::shell_plan`, the plan of `each` with a
  shell, no `RemoteCommand` and no `signal INT` at Ctrl-C; `hub.rs`, the
  lines and the commands `:all`, `:none`, `:only`, `:list`, `:intr`,
  `:help` and `::`, `--confirm`, the queue of 64 KiB, the stop, the end and
  the end of a host; `keys.rs`, the stop key and Ctrl-C, armed before
  anything connects; `mod.rs`, the refusals (64), the shells on `each`'s
  road and writer, stdin, and the summary.
- **The manual**: the two rows, two notes of `each`
  (`crates/podssh-cli/src/man/notes_each.rs`), an example, the exit codes
  78 and the remote status, and the help of COMMAND. `docs/cli.md` ("The
  broadcast: `--interactive`") and `docs/terminal.md` ("What podssh reads
  from the terminal") say it.
- **The tests**: `cargo test -p podssh-ssh io::feed` (5 tests: the order
  and the end, a reader that waits, a take with the signals, each signal
  once, an input that is fed): 5 passed;
  `cargo test -p podssh-cli broadcast::` (9 tests of the hub): 9 passed;
  `cargo test -p podssh-cli --test each -- interactive` (on each system:
  the refusals, the lines and the selection, `--confirm`, `:intr`, a full
  queue; on Unix: SIGQUIT, and Ctrl-C after the end of the input; on Linux:
  `Ctrl-\` in a pty; on Windows: Ctrl-Break in a pseudo console): on
  Linux 8 passed, the 3 of Unix among them; on Windows, CI's job `windows`
  passed with the default tests, Ctrl-Break in a pseudo console among them.
  The Windows test types Ctrl-Break as the test of T-295 types it, where the
  pseudo console gave a CTRL_BREAK_EVENT.
- **The planted defects**, natively, each alone: the stop ignored
  (`Key::Stop => {}` in `crates/podssh-cli/src/each/broadcast/mod.rs`) failed
  `interactive_sigquit_stops_the_broadcast_and_drops_what_waits` and the
  test of `Ctrl-\` in a pty; the stop that does not take the queues back (no
  `feed.take()` in `Hub::stop`) failed
  `the_stop_clears_the_selection_what_waits_and_a_half_line_at_once` and
  the SIGQUIT test; no limit of the queue (no check of `QUEUE` in
  `Hub::send`) failed `a_host_whose_queue_is_full_leaves_the_selection_with_a_word`
  and `interactive_a_full_queue_takes_its_host_out_of_the_selection`.
- **In the build image** (CI at `d1c5bd1`): lint (clippy 1.99 and fmt)
  green; `scripts/interop-broadcast.sh` against OpenSSH and Dropbear:
  `score broadcast 3 0 0 0 0 3` (`broadcast.both`, `broadcast.only`,
  `broadcast.stop`), and 587 ids of 41 harnesses met
  `scripts/interop-baseline.txt`.
- **What waits for T-251**: the plant of `scripts/interop-broadcast.sh`
  (SIGQUIT ignored) in the image, and the planted pseudo console on Windows.
- **Later** (the research of 2026-10-30): dtach and abduco take `Ctrl-\` as
  their key to detach, so a user of either beside podssh may want another
  stop key; a setting for it is a small follow-up, not a defect of this
  entry.

# T-186: A control surface for agents on live sessions

**Source:** GitHub #24 and GitHub #20 (tty7: `run`, `split`, `send`,
`wait --until free` and `capture`,
`l0ng-ai/tty7:crates/tty7-cli/src/commands.rs`); GitHub #19 (fux: a command
prompt for each command of the multiplexer). Read in the reports, not
verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

An agent wants to open a shell once, send keys, wait until the output stops,
and read the screen, over several of its own calls. Each run of
`podssh ssh` is one connection that ends with the process.

## Premise

- Read: a session that outlives the call of the agent lives in another
  process, and that process needs a local endpoint for requests: a
  listener. The operator ruled on 2026-10-08 (`docs/decisions.md`): a local
  listener is allowed when the user asks for it and a probe at run time
  allows the bind; loopback and AF_UNIX by default; the user can configure
  the address and can turn listening off.
- Read: `-M`, `-O` and `-S` are refused by name
  (`crates/podssh-cli/src/flags.rs`, lines 240-245 at `5fb9c1e`); `ControlMaster` is ignored
  (`crates/podssh-cli/src/ssh/keywords.rs`, line 78 at `5fb9c1e`).
- Read: with no listener, T-055 (`podssh mcp` over stdin and stdout) gives
  an agent tools for the life of one process.

## Approach

1. The probe first, with the listener code of T-177: socket, bind and listen
   on an AF_UNIX path in a state directory of mode 0700 (the chain of
   `crates/podssh-relay/src/cache.rs`). `--socket PATH` sets another path. A
   refusal exits 77 with the errno; with listening turned off
   (`PODSSH_LISTEN=no`, T-177), `session start` exits 78 before the probe.
2. `podssh session start NAME [ssh options] HOST` starts a background
   podssh that holds one SSH session with a remote pty. Then
   `session send NAME TEXT`; `session wait NAME --idle 2s` or `--match TEXT`
   (with a time limit); `session capture NAME` (the last 64 KiB, or the
   screen after T-161); `session stop NAME`; `session list`.
3. The socket has mode 0600, and the uid of each peer is checked. No TCP: a
   TCP peer cannot be checked, and a request runs commands. Windows: a named
   pipe, in a later step.
4. One JSON line for each request and each answer, with a version first.
5. The background podssh ends with its session, after `stop`, or after 1 h
   with no request, and removes its socket. Credentials never cross it.
6. In the same commit: `docs/cli.md`, the notes, `SECURITY.md:98-118` (a
   local socket that runs commands), `docs/STATUS.md`. T-039 can use the
   same background process.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

In the gate: start, send `echo hi`, wait for 2 s of silence, the capture
holds `hi`, stop; the socket has mode 0600; a client of another uid is
closed; with `PODSSH_LISTEN=no`, `session start` exits 78. In the box, which
refuses `bind`, `session start` exits 77 and names the probe. Plant: skip
the check of the uid; the check of the other uid must fail.

## Correction

2026-10-11, T-039: `-M`, `-S`, `-O`, `ControlMaster`, `ControlPath` and
`ControlPersist` work now, on Unix, with OpenSSH's control protocol
(`crates/podssh-cli/src/ssh/control.rs`, `crates/podssh-ssh/src/mux/`):
a control surface can speak to a master's socket as `-O` does.

# T-187: Snippets and argument templates, shown before they run

**Source:** GitHub #24 (MobaRust: macros reviewed before they run; rssh:
snippets; csshw: argument templates such as `{{USERNAME_AT_HOST}}`). Read in
the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An operator repeats long commands, and edits host names into them by hand. A
typo, or a value with a quote in it, runs the wrong command. A stored
command must be shown, with its values in it, before it runs.

## Premise

- Read: the remote command is the words of the command line joined with
  spaces, as OpenSSH joins them
  (`crates/podssh-cli/src/ssh/hop.rs:97-98`); podssh quotes nothing.
- Read: podssh can ask on the controlling terminal or through `SSH_ASKPASS`,
  and refuses when nobody can answer (`crates/podssh-ssh/src/prompt.rs:48-90`).
- Read: no settings file exists yet; T-048 adds it.

## Approach

1. Snippets in the `[snippets]` table of the file of T-048:
   `NAME = "COMMAND"`. The placeholders: `{{host}}`, `{{user}}`, `{{port}}`,
   and `{{1}}` to `{{9}}`. An unknown placeholder exits 78.
2. `podssh ssh --snippet NAME HOST [ARGS]`, and the same flag on `each`
   (T-183). A snippet and a command together exit 64.
3. Quote each value for a POSIX shell (`'` becomes `'\''`): a value is one
   word and runs nothing. The manual says that a template for another shell
   must not put a placeholder inside its own quotes.
4. Show the whole command on stderr, then ask `Run it? [y/N]`
   (`crates/podssh-ssh/src/prompt.rs:48-70`). With no terminal, exit 64
   unless `--yes` is given. For `each`, ask once and list the hosts.
5. In the same commit: `docs/cli.md`, the notes, an example,
   `docs/STATUS.md`.

## Decision

- **The words after the host are the values.** `podssh ssh --snippet NAME
  HOST [WORD...]`: the words must be as many as the highest `{{N}}` of the
  command, and a word that no placeholder takes is refused (64), as it
  would be a command of its own: this is the refusal of "a snippet and a
  command together". Lost: `--arg N=VALUE` flags, which double the typing
  for each value; and `--` between the values and a command, for which
  OpenSSH's command line has no place.
- **`{{host}}` is the host that podssh connects to**, after `HostName`, as
  OpenSSH's `%h`; the label that the question shows is the host as the
  command line names it. Lost: the alias as typed (`%n`), a name of this
  host's `ssh_config` that the far host does not know.
- **POSIX quotes, and a plain value as it is.** A value of letters, digits
  and `@%+:,./_-` goes in bare, so that the command that the question
  shows reads as one would type it; any other value goes in single quotes.
  `=` and `~` are quoted (zsh and each shell read them first). Lost:
  quotes on each value (a noisier question); quotes for the far shell
  found by a probe, which would need a connection before the question.
- **A placeholder inside the command's own quotes is the file's fault**,
  in single and in double quotes (78), and so is a quote that does not
  close, which also finds a `#` that the file read as a comment. Lost:
  quotes of another kind inside double quotes (`\$`, `` \` ``, `\"`), a
  second rule to get right; and a warning alone, which runs the command.
- **The values go in after the resolve.** The command line goes through
  the resolve with the command as written, so that `Match command`, the
  request and the checks of `--persist`, `--attach` and `--sudo` see a
  command; `Chosen::apply` then puts the values in, once the user, the host
  and the port of `ssh_config` are known. Lost: the values before the
  resolve (the user and the port of `ssh_config` are not known then); and
  a second resolve with the values in, which reads `ssh_config` twice.
- **The question goes where the answer comes from.** It holds the whole
  command, on the terminal or to `SSH_ASKPASS`, as stderr can go
  elsewhere; with `--yes` the command goes to stderr, and `-q` (or a
  `LogLevel` below `INFO`) leaves it out. With nobody to ask, the command
  is shown on stderr before the refusal, so that a script's log shows what
  did not run. `-G` asks nothing and runs nothing.
- **`BatchMode` forbids the question**, as it forbids each prompt (the
  Approach does not say): a script with `BatchMode=yes` and a terminal
  that nobody watches would wait 60 s. For `podssh each`, which turns
  `BatchMode` on for its hosts, the value of `-o` and `ssh_config` before
  that is kept in `Plan::batch_mode`, and one host with it is enough.
- **Each end that does not run is 64**: no, Ctrl-D, a failed askpass
  program, nobody to ask. Lost: 255, which tells a script that a
  connection failed; 1, a status of the remote command; 130, a signal.
- **`podssh each` asks once**, after each host is resolved and before a
  file of `--output-dir` is made, and shows the command once when each
  host has the same.
- **The gate's check takes two values.** The Prove's value
  `a'b; touch /tmp/inj`, put in with no quotes, leaves a quote open: `sh`
  refuses the line, and the `touch` does not run, so the plant would fail
  the check by its output alone. `scripts/interop-snippets.sh` gives `a'b`,
  which must come back unchanged, and `x; touch MARK`, which must come
  back unchanged with no MARK: the plant fails each. It is sourced at the
  end of `scripts/interop-each.sh`, as `scripts/interop.sh` has 500 lines,
  and uses its `e()`.
- **The askpass test runs on Unix.** On Windows a batch file cannot take
  the question as an argument: the standard library refuses a line break
  in the arguments of a `.cmd` (`batch file arguments are invalid`). The
  host-key question has the same lines; Windows gets `confirm` with a
  test's answers, and the runs with `--yes` and with nobody to ask.
- The rows of `--snippet` and `--yes` are in
  `crates/podssh-cli/src/flags/snippet.rs`, the same on `ssh` and `each`,
  so that `flags.rs` stays under 500 lines.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test snippets   # the expansion, the quoting, the refusal with no terminal (64)
sh scripts/dev.sh check                    # interop.sh: the injection check below
```

In `scripts/interop.sh`, the snippet `printf %s {{1}}` with the value
`a'b; touch /tmp/inj` prints the value unchanged, and `/tmp/inj` does not
exist on the server. Plant: insert the values with no quotes; `/tmp/inj`
then exists, and the check must fail.

## Correction

2026-10-13: the premise "no settings file exists yet; T-048 adds it" is
gone: T-048 is done, and `crates/podssh-cli/src/settings.rs` reads the
file, with the table `[groups]` of T-184 after its settings. `[snippets]`
is a second table of it.

## Done

2026-10-13. Finished from the start that an earlier agent left
(`snippets.rs` alone). `crates/podssh-cli/src/snippets.rs`: the pieces of
a command (text and placeholders, the refusals of a template), the
quoting, the expansion, the line of the table, `choose` (the command
line), `shown`, `confirm` with an `Asker` (the terminal or `SSH_ASKPASS`
through `podssh_ssh::prompt`, or a test's answers) and `settle`, which
fills the snippet in for each resolved connection and asks once.
`settings.rs` reads `[snippets]` beside `[groups]`, in either order, into
`Defaults::snippets`, and refuses a third table; `hosts::is_group_name`
names a snippet too. `SshArgs` has `snippet` and `yes`, and a second
`--snippet` is refused as a second `-J` is. `ssh::run` and `each::run_each`
choose the snippet before the resolve and settle it after, before
anything connects; `each::host::Plan` keeps `batch_mode`. The manual: the
rows of `crates/podssh-cli/src/flags/snippet.rs` on `ssh` and `each`, a
note of each, FILES, and an example; `docs/cli.md` has the section
"Snippets", and the settings file and `podssh each` name it. The gate:
`scripts/interop-snippets.sh` (OpenSSH and Dropbear: `a'b` and
`x; touch MARK` each come back unchanged and MARK is never made; the
question answered y and n by an askpass program; `each --snippet` with the
user, host and port of each host) and its 7 lines in
`scripts/interop-baseline.txt`. `crates/podssh-cli/tests/snippets.rs`,
with the fixture `crates/podssh-cli/tests/fixtures/snippets.settings`: the
values quoted (the exact command of the Prove's value), and on Unix each
hostile value through `sh -c`, back unchanged and its command never run;
the refusals of a template and of the table (78, with the line); the
command line (64); `confirm` with a test's answers (only y or yes runs it,
a cancel and nobody to ask refuse, `BatchMode` refuses, `--yes` and `-q`);
through the binary with no terminal, the refusals before anything connects
(64, the command shown, no file of `--output-dir`) and a bad table (78);
against the test's SSH server on the loopback, `ssh` and `each` with
`--yes` (exit 3 of `exit {{1}}`, the command shown once), and with no
`--yes` no connection; on Unix, the answers y and n of an askpass program.
`cargo test -p podssh-cli --test snippets`: 7 passed on Windows 11 and 9
in the build image (with the tests of Unix). `cargo test -p podssh-cli
--lib`, 292 passed (the settings, the hosts, the notes and the examples of
the manual), and `--test flag_table`, `--test man_flag_parity`, `--test
each` and `--test settings`: passed; `cargo test -p podssh-cli`, 795
passed. Clippy and rustfmt: clean. The plant of the Prove, the values in
with no quotes (`expand` with no `quote`): `each_value_is_one_quoted_word`
failed; restored, it passed. In the build image (the steps `lint` and
`release`, green; interop 533 passed, 0 failed),
`scripts/interop-snippets.sh` against OpenSSH 10.3p1 and Dropbear: 7 of
7, the value `a'b` back as one word and a command in a value back
unchanged and not run on each server, the question through `SSH_ASKPASS`
answered y and n, and `each --snippet` on each host. Planted in the image, the values with no
quotes: the four checks `snippets.quote.*` and `snippets.injection.*`
failed (the quote broke the line, exit 2; the injected command ran), and no
other.

# T-188: A host picker when `podssh ssh` gets no destination

**Source:** GitHub #24 (the csshw report, item 10: a host picker when it
starts with no hosts). Read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

On a terminal, `podssh ssh` with no destination only says that one is
missing. A user with a long ssh_config must remember each `Host` name. A
short numbered list helps a person; a script must still get the usage error.

## Premise

- Measured: `podssh ssh </dev/null` exits 64 with "missing destination"
  (`crates/podssh-cli/src/ssh/resolve.rs:156`).
- Read: `run_ssh` gets no terminal state
  (`crates/podssh-cli/src/dispatch.rs:265-267`), and the entry point of the
  tests has none on purpose (`crates/podssh-cli/src/dispatch.rs:31-39`,
  `crates/podssh-cli/src/pager.rs:21-45`).
- Read: the names can come only from the `Host` lines of ssh_config (T-043,
  M8); hashed `known_hosts` names cannot be listed.

## Approach

1. Pass `Tty` from `crates/podssh-cli/src/dispatch.rs:42` into `run_ssh`.
   With stdin and stdout both terminals and no destination, show the
   picker. In each other case, keep exit 64.
2. The list: the literal `Host` names of the files that T-043 reads (no
   patterns, no negations), in the order of the files. With no names, keep
   exit 64.
3. Read a number, or a text that filters the list, with `read_line`
   (`crates/podssh-ssh/src/terminal/mod.rs:26`). Empty input or Ctrl-D exits
   64. The prompt has the limit of a terminal that nobody watches
   (`crates/podssh-ssh/src/terminal/mod.rs:76-87`).
4. The chosen name takes the normal path, as if the user typed it.
5. In the same commit: the notes of ssh, `docs/cli.md`, `docs/STATUS.md`.
   This entry depends on T-043.

## Decision

- **A number picks; text only narrows.** Text keeps the names that hold
  it, case set aside, and the list comes again; a list of one name still
  takes its number. Lost: a pick when one name is left, which logs in to a
  host that the person did not see in the list. A number outside the list
  and a text that no name holds are said in the next question; 20 answers
  at most, then 64.
- **The list is the one that the reader gives with no host.** The
  `Host` lines of the files that a run reads, in their order, each name
  once, and each `Include` whose block holds for any host (outside each
  block, or after `Host *`), read by the reader of T-043 with a list of
  names (`config::host_names`). Lost: each `Include` whatever its block,
  as the reader never reads an `Include` of a block that does not apply: a
  bad file under one host must not stop each run.
- **A file that cannot be read shows no picker**: the run refuses with
  64, `missing destination`, and the reason. Lost: 78, as the resolve
  gives for the same file: the fault of the run is still its missing
  destination, and the picker only helps.
- **`BatchMode` does not apply.** The picker comes before a connection,
  and it needs stdin and stdout on a terminal: a script has neither. Lost:
  `BatchMode` first, which needs the `ssh_config` of a host not known yet.
- **The list goes to the terminal**, in the question of
  `podssh_ssh::terminal::read_line`, not to stdout, which stays the data of
  the command; the answer is echoed. With stdin and stdout on a terminal,
  no time limit applies, as a person is there.
- **The tests are a module of `crates/podssh-cli/tests/ssh_args.rs`**
  (`tests/ssh_picker/mod.rs`), as that file is near 500 lines; the Prove's
  filter `picker` matches the module's path. They answer through `Keys`,
  and a test that must read nothing has no answer: with the plant, `pick`
  asks, and the test fails at once, also where the test runs on a
  terminal.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- picker   # no terminal, or stdout alone: exit 64, nothing read
sh scripts/dev.sh check                              # interop-pty.py: the choice below
```

`scripts/interop-pty.py` gives a fixture ssh_config with three `Host` lines;
typing 2 logs in to the second host, with exit 0. Plant: show the picker
when only stdout is a terminal; that case must fail.

## Done

2026-10-13.
`crates/podssh-cli/src/ssh/picker.rs`: `wanted` (no destination, stdin and
stdout terminals), `names` (the literal `Host` names, through
`config::host_names` in `crates/podssh-cli/src/ssh/config.rs`, whose
reader keeps the names of each `Host` line it reads when asked), `choose`
(a number, or a text that narrows) and `pick`, with `Keys` for the
terminal (`Terminal`, through `read_line`) or a test's answers.
`dispatch::run_with` passes its `Tty` to `run_ssh`, which picks before
anything else is resolved; `dispatch::run`, which the tests call, has no
terminal and shows none. The note of `ssh` in the manual, the section "The
host picker" of `docs/cli.md`, and `docs/STATUS.md`. The gate:
`scripts/interop-pty.py` writes a file of `-F` with the hosts one, two and
three, sees the list on a pty, types 2, and two's `RemoteCommand` prints
`PICKED-42` with exit 0 (`pty.picker.choose`); with stdin from /dev/null
and stdout on the pty, no list, no question, and 64
(`pty.picker.stdout_alone`); its floor in `scripts/interop-baseline.txt`
is 15. `cargo test -p podssh-cli --test ssh_args -- picker` (no terminal,
stdout alone and stdin alone: nothing read, and 64 from the resolve; a
destination given and no name: nothing read; the names of a home with an
`Include`, a pattern, a negated name, a name twice and an `Include` of a
block for one host; `-F` and `-F none`; a number, a text that narrows, a
number outside the list, a text that no name holds; an empty line, blanks
and a failed terminal, 64; the name picked with the command kept, and its
`Host` block applied): 4 passed on Windows 11. The plant of the Prove,
`wanted` true with stdout alone a terminal:
`no_terminal_or_stdout_alone_reads_nothing_and_exits_64` failed; restored,
it passed. The tests of `ssh_config` and `ssh_config_file` (the reader's
change) passed; `cargo test -p podssh-cli`, 799 passed; clippy clean,
rustfmt after one line it reflowed. In the build image (the steps `lint`
and `release`, green; interop 535 passed, 0 failed),
`scripts/interop-pty.py` 17 of 17 with `pty.picker.choose` (a pty with no
destination lists the three `Host` names, and 2 logs in to the second,
whose `RemoteCommand` ran) and `pty.picker.stdout_alone` (no list, no
question, exit 64). The plant in the gate waits for T-251.

# T-189: The health of the far host over the session

**Source:** GitHub #21 (meatshell: CPU, memory, swap, network, disk and
processes); GitHub #24 (RustConn: a bar of metrics with no agent); GitHub #19
(slingshot `health`); GitHub #23 (SSHub: the state reported by the remote
end). Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Before work on a host, an operator checks its load, memory and disk. With
podssh, that is a typed command that differs for each host, and needs tools
that can be missing. `podssh doctor` checks only this host.

## Premise

- Read: an exec request runs one command through the shell of the server
  (`crates/podssh-ssh/src/session.rs:123-136`), and its output goes to stdout
  (`crates/podssh-ssh/src/io.rs:402-419`); podssh cannot read it.
- Read: on Linux, `/proc/loadavg`, `/proc/meminfo`, `/proc/uptime` and
  `/proc/net/dev` hold the facts, and a POSIX shell reads them with `read`,
  with no other tool.

## Approach

1. A verb `health`: `podssh health [ssh options] [user@]host [--json]`. It
   only reads: it never stops or changes a process.
2. One exec runs a fixed script that the binary holds, as `sh -c '...'`, so
   that a login shell of fish or csh does not matter. The script uses the
   built-ins of the shell, and `df -P` only when `command -v df` finds it.
   No text of the user goes into the script.
3. Read the output with the sink of T-183
   (`crates/podssh-ssh/src/io.rs:135-419`), parse it, and print one line for
   each fact: load, memory and swap, uptime, network bytes (two samples,
   1 s apart), disk, processes. `--json` gives one object, in the shape of
   T-049.
4. No `/proc`: print the output of `uname -s` and "no facts for this
   system". No `sh`: exit 255 with "the server has no sh".
5. The exit codes of `podssh ssh`: 0, or 255 for a failure.
6. In the same commit: the rows, the notes, an example, `docs/cli.md`,
   `docs/STATUS.md`. T-013 can then group the command.

## Decision

2026-10-13, the draft. The answer is read with `exec::capture`
(`crates/podssh-ssh/src/exec.rs:58-78`), as `podssh ping` reads its
measures and the copy by exec its steps: one command with no pty and no
input, its own limit (30 s) and cap (1 MiB), its status and its stderr.
The sink of T-183 lost: it carries a session of `podssh_ssh::run` with the
request of the command line, and needs a task to drain it, for nothing that
the capture lacks.

The facts are more than the Approach names: the CPUs and their busy share,
from a second read of `/proc/stat` (GitHub #21 asks for the CPU), and the
seconds between the two samples from a second read of `/proc/uptime`, in
place of a second that is assumed. `sleep` and `uname` run only where
`command -v` finds them, as `df` does. `read -t 1` as the wait lost: dash
has no `-t`. `df -P -k` reads the root and the home, one line for each
mount; each mount of the host lost, as most of them (`tmpfs`, `proc`, the
overlays of a container) are noise for this check.

The script is one line with no single quote, no `!` and no line break, so
that fish, csh and each POSIX shell read `sh -c '...'` the same way. Its
first line, `podssh-health 1`, is the number of its form; what a login
prints before it is not read. A section is a line `@ NAME`, which no line
of `/proc` starts with.

Facts go to stdout, a failure to stderr (`podssh: health HOST: ...`); with
`--json` stdout holds one object also after a failure, as for
`podssh ping`, so that a script reads `error` and `exit`. Each failure
after the command line is 255, as `podssh ssh` gives it, a relay out of
reach too (where `podssh proxy` gives 69); a target that the relay cannot
carry is 64. The whole run has 120 s. The verb is in the group "Check this
host and the path" (T-013), with `doctor`, `status` and `ping`.

The Prove's fixtures could not be captured here (no container may run in a
draft): `tests/fixtures/health/` holds two answers written by hand in the
form of the kernel's `/proc` and of `df -P`, as Debian 12 and Alpine 3.20
give them, each one saying so on its first lines. T-251 captures both in
the build image. The test's SSH server answers the script with the Debian
one, so that the whole road is tested natively. The gate's check is in
`scripts/interop-health.sh`, sourced by `scripts/interop-each.sh`, as
`scripts/interop.sh` has 500 lines; `scripts/interop-ping.sh` is sourced
the same way.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli health::   # the parser, on /proc text captured from Alpine and Debian
sh scripts/dev.sh check             # interop.sh: the comparison below
```

In `scripts/interop.sh`, `health --json` runs against OpenSSH and Dropbear,
and its available memory is within 5 % of `MemAvailable` read over exec.
Plant: read `MemFree` in place of `MemAvailable`; the comparison must fail.

## Correction

The first premise is wrong in its last words: podssh reads the output of a
command with `exec::capture` (`crates/podssh-ssh/src/exec.rs:58-78`), as
`podssh ping` does for its measures (`crates/podssh-cli/src/ping/far.rs`),
and since T-183 a session's output can go to a sink (`io::Sink` in
`crates/podssh-ssh/src/io.rs`). The Approach takes the capture
(Decision).

## Done

2026-10-13. `crates/podssh-cli/src/health/`:
`mod.rs` (the command line, the road and the login of `podssh ssh`, one
capture, the exit codes), `script.rs` (the script and its command),
`parse.rs` with `parse_tests.rs` (the sections, and the load, CPUs, busy
share, memory and swap, uptime, interfaces with their rates, disks and
processes; a host with no `/proc`, one with no `sleep`, a kernel with no
`MemAvailable`, no `sh`, hostile names), and `show.rs` (one line for each
fact, the JSON object). The rows of `crates/podssh-cli/src/flags/health.rs`,
the verb and its group in `crates/podssh-cli/src/flags.rs`, its argument,
its `Parsed` variant, its dispatch, its usage, the notes of
`crates/podssh-cli/src/man/notes_health.rs`, an example, and the exit codes
0 and 255 in EXIT STATUS. `docs/cli.md` ("`podssh health`"),
`docs/STATUS.md`, `README.md` and `AGENTS.md` name the command. The test's
SSH server answers the script (`crates/podssh-cli/tests/ssh_harness/health.rs`),
and `crates/podssh-cli/tests/health.rs` runs the binary against it: one
line for each fact, the JSON with the available memory of `MemAvailable`,
255 at a closed port with the error in the JSON, and 64 with no host.
`cargo test -p podssh-cli health::` (the reader, the script's form, the
lines and the JSON), 13 passed, and `cargo test -p podssh-cli --test
health`, 3 passed, on Windows 11. `cargo test -p podssh-cli --test
flag_table --test man_flag_parity` and `cargo test -p podssh-cli man::`:
passed; `cargo test -p podssh-cli`, 830 passed. Planted, `MemFree` in
place of `MemAvailable`: three tests of the reader and two of the binary
failed; restored, they passed. `scripts/interop-health.sh` gives
`health.openssh.memory`, `health.dropbear.memory` and
`health.openssh.lines`, `health.dropbear.lines`, in
`scripts/interop-baseline.txt` with the floor 4. In the build image (the
steps `lint` and `release`, green; interop 542 passed, 0 failed), against
OpenSSH 10.3p1 and Dropbear on the box's real `/proc`: 4 of 4. The gate's
plant first passed: in the build image `MemFree` is within 5 % of
`MemAvailable` (31,194,108 and 31,579,848 kB), so the check that the merge
received could not fail on it. The check now also wants the value nearer
`MemAvailable` than `MemFree` (unless the two are within 16 MiB): the code
passed it, and the plant failed both servers. The answers of Debian and
Alpine in the unit tests stay written by hand in the kernel's form; the
gate reads a real `/proc`. The code has no branch for one system.

# T-190: Containers and pods as destinations

**Source:** GitHub #24 (the rssh report, item 6: Docker containers and
Kubernetes pods found through the local tools, then exec terminals). Read in
the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

To enter a container on a remote host, a user logs in, lists the containers,
and types `docker exec -it NAME sh`. Each step is done by hand, and each
name is copied by hand.

## Premise

- Read: `podssh ssh -t HOST -- docker exec -it NAME sh` works today, as a
  remote command with a pty (`crates/podssh-cli/src/ssh/resolve.rs:269-277`,
  `crates/podssh-cli/src/ssh/hop.rs:97-108`). Only the list is missing.
- Read: podssh starts a program only when the user names it or a probe
  finds it (`AGENTS.md:246-250`). Here the programs run on the server, for a
  request of the user.

## Approach

1. A verb `containers`: `podssh containers [ssh options] HOST`. One exec
   runs a fixed script: `command -v docker podman kubectl`, then the list of
   each tool that it finds: `docker ps --format '{{.Names}}'`,
   `podman ps --format '{{.Names}}'`, `kubectl get pods -o name` (the
   current context only).
2. Print one line for each container: the tool, the name, and the command
   that enters it: `podssh ssh -t HOST -- docker exec -it NAME sh`.
   `--exec NAME` runs that command (the shell `sh`; `--shell PROG` changes
   it).
3. Check each name (letters, digits, `_`, `.` and `-`, and `pod/` for
   kubectl), and quote it for a POSIX shell, as T-187 does.
4. A tool that fails (no access to the socket of Docker) gives its stderr
   line; the other tools go on.
5. The Docker contexts of the client are not used: they connect with
   OpenSSH, not with podssh.
6. In the same commit: the rows, the notes, an example, `docs/cli.md`,
   `docs/STATUS.md`. `pipe exec:` (T-174) already carries the streams of
   `docker exec -i`.

## Decision

Recommendation: a verb that lists, and prints the `podssh ssh` command. The
alternative, a destination such as `docker:NAME@HOST`, lost: `podssh ssh`
takes the destinations of OpenSSH, and a new form in
`crates/podssh-cli/src/ssh/hop.rs:30-78` breaks that parity.

The draft (2026-10-13) keeps the verb. `podssh ssh` now takes `node://`,
`iroh:` and `cf://` too (T-084, T-163, T-264), so parity alone does not
decide; but each of those names a road to an SSH server, and a container is
a command on a server, which `podssh ssh -t HOST -- docker exec -it NAME sh`
already says in OpenSSH's words. The calls of the draft:

- **`--exec` on the connection of the list**, not a second `podssh ssh`:
  the login (`podssh_ssh::upgrade::login`) runs the list with
  `exec::capture`, then the session on the same handles
  (`podssh_ssh::upgrade::request`), as `--upgrade` does (T-167). A
  password is asked once. The alternative, the printed command run as a new
  process, lost: two logins, two questions, and the list can change between
  them.
- **The script** is one line with no `'`, under `sh -c '...'`, as the copy
  by exec runs its steps (T-135): a login shell that is not POSIX (csh,
  fish) only starts `sh`. Marks before and after each tool's list, on stdout
  and on stderr, and one at the end, tell a login's banner from a list and
  a cut list from a whole one. kubectl gets `--request-timeout=20s`, and
  the whole list 60 s, as rule 4 of section 6 of AGENTS.md wants a limit on
  each wait.
- **Names, and no quoting of them**: a name of letters, digits, `_`, `.`
  and `-`, a letter or a digit first, 253 bytes at most (`pod/` first for
  kubectl), is one word to each shell, csh and fish included, so it goes
  bare; a listed name of another form is left out and named (65). Each
  other word of a shown command (a flag's value, the host) goes through
  `list::word`, bare when plain, else `exec::shell_word`. The alternative,
  quoting each name as T-187 would, lost: T-187 is not done, and a quoted
  `a;b` would still reach the far tool as a name that no tool gave.
- **`--tool TOOL`**, a flag the Approach does not name: docker and podman
  can list the same name (a host with both, or podman-docker, whose
  `docker` runs podman). `--exec` takes the first tool in the order
  docker, podman, kubectl, says so, and `--tool` takes another.
- **The pty**: with a terminal here, or with `-tt` (the row `-t` of
  `containers`), the session has a pty and the tool gets `-it`; with none,
  `-i` alone, as docker refuses `-t` when its input is not a terminal. A
  line always shows `podssh ssh -t ... -it`, for a person at a terminal.
- **Exit codes**: 0, 65 (a name left out), 69 (no tool, a tool that
  failed, a cut list, or no container NAME), 255 (no connection, no login,
  a list that did not end in time), 64 before anything connects; with
  `--exec`, the session's status. A `node://` or `iroh:` destination is
  refused (64), as `podssh each` refuses it: its road has its own runner,
  and `transport::reach` does not reach it.
- **The fixtures** (`crates/podssh-cli/tests/fixtures/containers/`) are
  written in the formats that `docker ps --format`, `podman ps --format`
  and `kubectl get pods -o name` give: no runtime is on this machine, and
  none was captured.
- **The gate's harness** is `scripts/interop-containers.sh`, sourced at the
  end of `scripts/interop-each.sh`, as `scripts/interop.sh` is at its 500
  lines. Its stand-ins go into the first directory of the `PATH` that each
  server gives a command. A run against a real runtime is there too:
  podman, rootless as the test user, with an image made from the build
  image's own busybox (no registry); the gate's container has no
  privileges, so the id `containers.podman` may say env, and the baseline
  allows it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli containers::   # the parser, on committed output of docker, podman and kubectl
sh scripts/dev.sh check                 # interop.sh: the stand-ins below
```

In `scripts/interop.sh`, stand-ins for `docker` and `kubectl` on the `PATH`
of the server print the captured output; the list and `--exec` reach them.
Plant: skip the check of the names; the fixture with `a;b` must fail.

## Done

2026-10-13. `crates/podssh-cli/src/containers/` (`mod.rs`: the command line, the plan
before anything connects, the run on one connection, the lines and the
exit; `list.rs`: the script, its parse, the check of the names, the command
that enters a container, the shown flags), the rows of
`crates/podssh-cli/src/flags/containers.rs`, the verb in the table, the
group "Connect", the parser and the dispatch, the notes of
`crates/podssh-cli/src/man/notes_containers.rs`, two examples, the exit
codes 65, 69, 255 and the remote status in the manual, `docs/cli.md`
(section "`podssh containers`"), README.md and AGENTS.md (section 1). The
test's SSH server answers the list and the exec for a user
`containers-...` (`crates/podssh-cli/tests/ssh_harness/containers.rs`) and
grants such a user a pty.

- Windows 11: `cargo test -p podssh-cli containers::` (the script, the
  parse of the fixtures, a failed tool, the names and the plant's `a;b`, a
  cut list, `--exec` and `--shell`, the holders and the command, the
  quoting, the shown flags): 9 passed; `cargo test -p podssh-cli --test
  containers` (the refusals, 64, offline; offline 255; against the test's
  server: five lines whose commands parse as `podssh ssh` with the exec of
  their container, `--tool kubectl`, a refused docker beside kubectl (69),
  `a;b` left out (65), no tool (69), and `--exec` on one connection with
  `-i`, with `-tt` and `-it`, and a name that no list has): 7 passed; the
  manual's tests passed; `cargo test -p podssh-cli`, 846 passed.
- The merge found two defects of the draft: a word with `=` inside
  (`StrictHostKeyChecking=accept-new`) was quoted in the shown command,
  against its own tests, and is plain now, as `=` means nothing inside a
  word of a POSIX shell (a word that starts with `=` stays quoted); and the
  manual's note wrote `_` alone, which the manual's check reads as a
  variable, so it says "underscores".
- Planted, `list::valid_name` true: `a_name_that_a_shell_would_read_is_left_out`
  and `a_name_that_a_shell_would_read_is_left_out_with_65` failed; restored,
  they passed. In the build image, the same
  plant failed `containers.bad_name` (exit 0, where 65 is due), and no
  other check.
- In the build image (the steps `lint` and `release`, green; interop 550
  passed, 0 failed): `scripts/interop-containers.sh` 8 of 8 against
  OpenSSH 10.3p1 and Dropbear, with stand-ins of docker and kubectl.
- The draft's check of a real runtime, a rootless podman inside the gate's
  container, stopped the WSL distribution that runs the build image during
  its first run: the job ended mid-interop, and the next run could not
  start a container until `wsl-toolkit base ensure --repair` cleared the
  engine's run state. The harness runs no real runtime now, and
  `containers.podman` is gone from the baseline; the run without it kept
  the distribution up. A real runtime (docker, podman or kubectl on a far
  host) waits for a host that has one, at T-251.

# T-191: Expect rules, and tasks before and after a connection

**Source:** GitHub #24 (the RustConn report, item 8: expect rules, key
sequences, and tasks before and after a connection). Read in the report, not
verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Some hosts need keys after the login: a menu, a banner to confirm, a second
shell. Some users need a local command after the connection opens, as the
`LocalCommand` of OpenSSH. podssh ignores `LocalCommand`, and it has no
expect rule.

## Premise

- Measured, at `61e55d1`: `podssh ssh -o LocalCommand=true -o PermitLocalCommand=yes -v user@host.invalid true`
  prints `-o LocalCommand has no effect in podssh`, and the same for
  `PermitLocalCommand` (`crates/podssh-cli/src/ssh/keywords.rs` lines 93-94 at `61e55d1`).
- Read: remote output arrives at `crates/podssh-ssh/src/io.rs:352-367`, and
  input leaves at `crates/podssh-ssh/src/io.rs:183-229`. An expect rule goes
  between them.
- Read from memory, to verify against OpenSSH 10.3p1: OpenSSH runs
  `LocalCommand` after the connection, with the user's shell, only with
  `PermitLocalCommand yes`, and expands tokens such as `%h` and `%p`.

## Approach

1. `LocalCommand`: move it and `PermitLocalCommand` from IGNORED to
   HONOURED (`crates/podssh-cli/src/ssh/keywords.rs:25-82`), with fields in
   `crates/podssh-cli/src/ssh/options.rs:13-83`. Run it when OpenSSH runs it
   (check the order in the container). Expand the tokens with `Tokens::expand`
   (`crates/podssh-cli/src/ssh/tokens.rs:69-159`), which has `%p` and `%n`
   since T-238.
   The shell: `SHELL`, else `/bin/sh` when it exists, else exit 78.
2. Expect: `--expect TEXT --send TEXT` pairs, in order, only in a session
   with a pty. Match a literal text in the last 64 KiB of output. `--send`
   reads `\r`, `\n`, `\t` and `\xNN`. Each rule waits `--expect-timeout`
   (default 30 s); a miss ends the session with 255 and names the rule.
3. No secrets: `--send` is on the command line, which each process can read
   (`docs/architecture.md:143-145`). The manual says so; passwords come
   through `SSH_ASKPASS`.
4. Tasks before and after the connection: the shell does them
   (`cmd && podssh ssh host; cmd`). Only `LocalCommand` needs podssh,
   because it runs between the login and the session.
5. In the same commit: the keyword tables (the manual reads them), the
   notes, `docs/cli.md`, `docs/STATUS.md`. T-032 can use the expect rules.

## Decision

Recommendation: the `LocalCommand` of OpenSSH, and no flags of podssh for
other tasks, because the shell already orders commands. The alternative,
`--before CMD` and `--after CMD`, lost: they copy the shell, and add a
second way to start a program.

The draft (2026-10-13) follows it. The calls of the draft:

- **Where LocalCommand runs**: in `podssh_ssh::run`'s request step, after
  each hop's login and before the session channel opens. OpenSSH, as read
  in its `ssh.c` from memory, runs it after it sends the open of the
  session channel and before its client loop, so that no output of the
  session comes before the command's; the two orders show the same. The
  gate's `expect.local_order` compares the order with OpenSSH's own `ssh`.
  `--persist` runs it after its first login alone. A try after a drop of
  the relay (T-025) would run it twice, so the run's phase becomes
  "requested" before it starts, and no try follows.
- **Only `podssh ssh` runs it**, and chooses its shell, before anything
  connects: `SHELL`, else `/bin/sh`, else 78. The alternative, the shell
  chosen as `resolve` reads `ssh_config`, lost: `cp`, `pipe ssh:` and the
  others read the same file, run no LocalCommand (OpenSSH's `scp` and
  `sftp` pass `PermitLocalCommand=no`), and would refuse with 78 on a
  Windows host whose `ssh_config` names one. `podssh each` and `podssh
  containers` drop it, with a note: its output would have no host's label.
- **Its tokens** are those of `RemoteCommand` (`Tokens::text`), not of a
  file name (`Tokens::expand`, which the Approach names, adds `~` and
  `${NAME}`, which OpenSSH does not read in LocalCommand), and `%T` is
  `NONE`. They are expanded only with `PermitLocalCommand yes`. `-G` prints
  `permitlocalcommand` and `localcommand` as given, in the order of
  OpenSSH's `dump_client_config` as read from memory; the gate's
  `ssh.config.g.*` checks each line that podssh prints against `ssh -G`.
- **Its input is none**, where OpenSSH gives it the terminal: the
  session's reader takes stdin next, and a command that read it would take
  the session's first keys. With `-W`, its stdout goes to stderr, as stdout
  carries the stream (OpenSSH would write it into the stream). podssh waits
  for its end with no limit, as OpenSSH does: the user names the program,
  and Ctrl-C stops it.
- **An option can now start a program**, as in OpenSSH: `-o
  PermitLocalCommand=yes -o LocalCommand=...` in words that a script did
  not write would run here. T-011's rule stays the defence: a script puts
  `--` before a host that it did not write (`docs/cli.md`, "Options of
  `podssh ssh`"). T-011's reading that no option starts a program now says
  that it read the tree at `61e55d1`.
- **The expect rules** hold the session's own input until the last rule
  sent its keys: a key typed here would come between the rules' keys. Each
  rule reads only what came after the match before it, so that the echo of
  an old line does not match; several rules can match in one piece of
  output, in their order. `--send` reads `\\` too, for a backslash; an
  empty `--send` waits and sends nothing; `--expect` is a literal text of 1
  byte to 64 KiB. A rule's time starts with the session or at the match
  before it. A miss ends the session as one with no exit status (255,
  `no-status` in `--result-file`), and its line names the rule. A session
  with no pty ends with 255 before its request goes out.
- **What cannot go with the rules** (64): `-T`, `-N`, `-W`, `-s`, `--sudo`
  and `--su` (each makes its own use of the input), and `--persist` (its
  sessions follow one another). Such a run drops `ControlPath`, as
  `--record` does: a master's session would not read the rules.
- **The gate's harness** is `scripts/interop-expect.sh`, sourced at the end
  of `scripts/interop-each.sh`, as `scripts/interop.sh` is at its 500 lines.
  The test server gets `prompt` (`crates/podssh-cli/tests/ssh_harness/prompt.rs`);
  its `append` moved to `crates/podssh-cli/tests/ssh_harness/ends.rs`, so
  that `crates/podssh-cli/tests/ssh_harness/mod.rs` keeps under 500 lines,
  and the tests of `crates/podssh-cli/src/ssh/options.rs` moved to
  `crates/podssh-cli/src/ssh/options_tests.rs` for the same reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli ssh::keywords   # each HONOURED keyword is applied, LocalCommand included
sh scripts/dev.sh check                  # interop.sh: the cases below
```

In `scripts/interop.sh`: `-o PermitLocalCommand=yes -o LocalCommand='touch /tmp/lc-%h'`
makes `/tmp/lc-127.0.0.1`, and with `PermitLocalCommand=no` it does not.
`-tt` with `--expect '$ ' --send 'echo EXP\r' --expect EXP --send 'exit 4\r'`
exits 4. `--expect NEVER --expect-timeout 2s` exits 255 within 5 s. Plant:
run `LocalCommand` with no `PermitLocalCommand`; the case `=no` must fail.

## Done

2026-10-13.
`LocalCommand` and `PermitLocalCommand` are HONOURED keywords
(`crates/podssh-cli/src/ssh/keywords.rs`), read into `Settings`, planned in
`crates/podssh-cli/src/ssh/local_command.rs` (the permit, the tokens with
`%T`, `-W`, and the shell), and run by `crates/podssh-ssh/src/local_command.rs`
from the request step of `podssh_ssh::run` and from the first login of
`--persist`. The expect rules are the rows of
`crates/podssh-cli/src/flags/expect.rs`, read in their order into
`SshArgs`, checked in `crates/podssh-cli/src/ssh/expect.rs`, and run by
`crates/podssh-ssh/src/expect.rs` in the session's pump, which holds its
input until the last rule. The manual: the notes of `ssh`, the variable
`SHELL`, an example; `docs/cli.md`, README.md. Tests: `cargo test -p
podssh-ssh --lib -- expect local_command` (a text cut between two pieces,
the order of the rules, the window, the time of a rule; the shell runs the
line, on Unix): 5 passed; `cargo test -p podssh-cli --lib -- ssh::expect
ssh::local_command ssh::keywords ssh::options` (the escapes of `--send`,
the pairs, the refusals through `resolve`; the permit and the plant, the
tokens and `%T`, the shell or 78; the keyword tables, `PermitLocalCommand`
no by default): 18 passed; `cargo test -p podssh-cli --test ssh_expect`
(against the test's server: `echo EXP` then `exit 4` gives 4, a miss is
255 within 10 s and named, no pty is 255; on Unix `LocalCommand` with
`=no`, with none and with `=yes`, and its output before the session's; on
Windows 78 with no shell): 3 passed on Windows 11, 3 in the build image
with the tests of Unix; `cargo test -p podssh-cli --test
ssh_config --test ssh_config_file` (the lines of `-G`, written, not
captured): 14 and 4 passed; the manual's tests passed; podssh-cli and
podssh-ssh together, 1121 passed. The plant of the Prove
(`local_command::plan` takes no permit): `the_command_runs_only_with_permit_local_command_yes`
failed; restored, it passed. In the build image the same plant failed
`expect.local_command_no` (the command ran with `PermitLocalCommand=no`),
and no other check. In the build image (the steps
`lint` and `release`, green; interop 556 passed, 0 failed): the Unix test
of `LocalCommand` passed; `scripts/interop-expect.sh` 6 of 6 against
OpenSSH 10.3p1 and Dropbear, the order of OpenSSH's own `ssh` among them;
and the gate's `ssh.config.g.*` found each line of `-G` that podssh prints
equal to `ssh -G`'s, the new `permitlocalcommand` and `localcommand`
among them.

The merge found a defect of the draft: the first run of the gate failed
`expect.rules.dropbear`, 129 where `exit 4` gives 4. With stdin at its end,
podssh sent the channel's EOF just after the last rule's keys, and Dropbear
closed the pty and hung up the shell before it had read them; OpenSSH's
sshd kept the order. The end of input of a session with expect rules is
now the terminal's end of file, Ctrl-D, in the pty's own stream after the
keys (`crates/podssh-ssh/src/io.rs`), as a person at a terminal ends it:
the next run gave 4 on both servers.

# T-192: Copy, then run: `podssh run`

**Source:** GitHub #19 (the slingshot report, item 10: `slingshot run`
copies the changes, then runs them,
`ado11231/slingshot:crates/slingshot-cli/src/commands/run.rs`). Read in the
report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

To test code on a stronger host, a user copies the project, logs in, and
runs it: two commands, two connections, and the build output copied each
time. One command should copy what changed, run, and exit with the status
of the command.

## Premise

- Measured: `podssh run host -- true` exits 64 (`unknown subcommand 'run'`).
- Read: the copy is work of M5: `cp` over SFTP (T-134), directories and an
  ignore file (T-143), and a new relay session before the limits (T-137).
  `cp` exits 70 today (`crates/podssh-cli/src/flags.rs` lines 434-437 at
  `6483366`).

## Approach

1. A verb `run`: `podssh run [OPTIONS] [user@]host[:DIR] -- COMMAND`. DIR is
   `~/.podssh/run/NAME` by default, NAME the last part of the local
   directory.
2. Copy the working directory (or `--from DIR`) with the engine of T-134 and
   T-143: its ignore file, and the default excludes `target/`,
   `node_modules/` and `.git/`. Copy only the files whose size or time
   changed.
3. Then one exec on the same SSH connection: `cd DIR && COMMAND`, with DIR
   quoted for a POSIX shell (T-187). When the copy used most of the 64 MiB
   (`docs/relay.md:167`), run the exec on a new session (T-137).
4. The exit status: the command's, with the rules of `podssh ssh`
   (`docs/cli.md:2078-2081`). A failed copy exits 255 and runs nothing.
5. In the same commit: the rows, the notes, an example, `docs/cli.md`,
   `docs/STATUS.md`. This entry depends on T-134 and T-143.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh check   # interop.sh: the project below
```

In `scripts/interop.sh`, a fixture project holds `run.sh` (`exit 6`) and
`target/big.bin`. `run` to the port 2201 exits 6; `target/` is not on the
server; a second run copies no file. Plant: drop the default excludes; the
check of `target/` must fail.

## Correction

2026-10-09 (T-134): `podssh cp` copies files now; it is no longer
in `VERB_OWNER`, and this entry can call its engine.

# T-193: Jobs on the far host: start, list, stop

**Source:** GitHub #19 (the slingshot report, item 7: `ps` and `stop`,
`ado11231/slingshot:crates/slingshot-agent/src/jobs.rs`). Read in the
report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A long build on a remote host stops with the connection, unless the user
starts it under `nohup` or tmux by hand. podssh cannot start a command that
outlives the session, show it later, or stop it.

## Premise

- Read: a session ends with its connection (`docs/design.md:381`), and `-f`
  is refused (`crates/podssh-cli/src/flags.rs:255-256`).
- Read: tmux is never assumed; T-178 probes it with `command -v tmux`.
- Read: `podssh serve` (T-107, M5) runs on the far end only where the user
  starts it.

## Approach

1. A verb `job`: `podssh job start HOST -- COMMAND`, `job list HOST`,
   `job log HOST ID`, `job stop HOST ID`. ID: 8 random hex characters.
2. tmux first, with the probe of T-178. `start` runs
   `tmux new-session -d -s podssh-job-ID` with COMMAND quoted for a POSIX
   shell. `list` reads `tmux list-sessions -F '#{session_name}'` and keeps
   the `podssh-job-` names. `log` runs `tmux capture-pane -p -S - -t NAME`.
   `stop` runs `tmux kill-session -t NAME` for that exact name.
3. No tmux, and a `podssh serve` at the far end: the same verbs as requests
   to serve, in a step with T-107.
4. Neither: exit 255 with "the server has no tmux; job needs tmux or podssh
   serve".
5. The exit codes of `podssh ssh`. In the same commit: the rows, the notes,
   `docs/cli.md`, `docs/STATUS.md`. T-197 adds a queue on top of this.

## Decision

Recommendation: tmux or `podssh serve` only. The alternative, `nohup` or a
background `sh` with a PID file, lost: a `stop` by PID can kill another
process after the system gives the PID again, and the output has no safe
place on a host that podssh does not know.

## Prove

```sh
export CARGO_BUILD_JOBS=4
sh scripts/dev.sh check   # interop.sh, with tmux in the image: the jobs below
```

The image of `scripts/interop.sh` gets tmux (`scripts/interop.sh:24-25`).
Two jobs `sleep 300` start; `list` shows two IDs; a `stop` of one leaves the
other in `list`; `log` shows the output of a job that prints. With tmux off
`PATH`, `start` exits 255 and names tmux. Plant: stop by the prefix
`podssh-job-`; the check that the second job remains must fail.

# T-195: Hand an error report to a program that the user names, for triage by an AI or a script

**Source:** GitHub #24 (the rssh report, item 5: AI triage of the terminal,
`rssh-org/rssh:src-tauri/src/ai/`; read in the report, not verified here);
the operator's ruling of 2026-10-08 (`docs/decisions.md`): a CLI hook, and
podssh never calls an AI service itself.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

When podssh fails, a user or an agent copies its messages into another tool
to find the cause. A failure in a script is seen late, or never. podssh
cannot hand a failure to a program that the user chose: a script that files
a ticket, or a tool that asks an AI.

## Premise

- Read: podssh starts another program only when the user names it
  (`AGENTS.md:246-250`), as it runs `SSH_ASKPASS`: the program, no shell, and
  its first line read back (`crates/podssh-ssh/src/prompt.rs:102-119`).
- Read: credentials never go to output, logs, URLs or argv
  (`docs/architecture.md:143-145`). The token type never shows itself
  (`crates/podssh-relay/src/token.rs:27-56`), and doctor never shows proxy
  credentials or tokens (`docs/cli.md:1197-1199`).
- Read: podssh's messages leave through two writers: `Streams.err` in the
  command line (`crates/podssh-cli/src/dispatch.rs:26-29`), and `Log`, which
  writes to the stderr of the process itself
  (`crates/podssh-ssh/src/log.rs:83-103`). The exit code leaves through
  `crates/podssh-cli/src/dispatch.rs:311-339`.
- Read: for `podssh ssh`, an exit that is not 0 can be the remote command's
  status (`docs/cli.md:2078-2081`), which is not a failure of podssh.

## Approach

1. A variable `PODSSH_ERROR_PROGRAM`: one program, with no shell and no
   arguments, as `SSH_ASKPASS`. Add it to `VARIABLES`
   (`crates/podssh-cli/src/man/facts.rs:45-237`).
2. When: only when podssh itself fails: a usage error (64), a configuration
   error (78), 69, 70, 77, or 255 for a failure of podssh. Never after a
   success, and never for the status of a remote command or of an `exec:`
   child. The code path decides, not the number.
3. The report: one JSON object on the program's stdin, with `version`, the
   podssh version, the operating system, the verb, the exit code, the last
   64 lines (16 KiB at most) of podssh's own messages, and the relay host
   with its close code and reason when there is one. `Streams.err` and
   `Log` both feed one bounded buffer.
4. Never in the report: a token, a proxy URL, a key, a password, the
   environment, the command line as typed, or the bytes of a session. The
   messages pass through the same masking as doctor's.
5. Start the program with no shell: stdin is the report; its stdout and
   stderr go to podssh's stderr (stdout is data); a limit of 30 s, then it
   is stopped. Its status is ignored, and podssh's exit code does not
   change. A program that does not start gives one line on stderr.
6. podssh calls no AI service and no network address for this: the program
   decides what to do with the report.
7. In the same commit: `docs/cli.md` (the hook), the notes of the manual,
   `SECURITY.md:63-71` (what the report holds), `docs/STATUS.md`.

## Decision

Recommendation: a variable, as `SSH_ASKPASS`, because it reaches each verb,
also `podssh proxy` under the `ProxyCommand` of OpenSSH, with no new row in
each flag table. The alternative, a flag `--on-error PROG` on each verb,
lost: a row for each verb, and each `ProxyCommand` line must change.

When (2026-10-13, the draft): each exit code that is not 0 is a failure of
podssh, but a status that a code path passes on and 130 and 143. A path
that gives another program's status says so
(`crates/podssh-cli/src/error_program/mod.rs`, `not_a_failure`): `ssh` when
the result of T-054 has no `failure` (the remote status, 255 too, and an
end with no status, by the same rule as `--result-file`), `each` when each
host had a session, `ping` for a remote program's status, `pipe` for a
child's, `edit` for the editor's. The list of the Approach (64, 78, 69, 70,
77, 255) lost: it leaves out 1 (`doctor`'s FAIL, `keygen`), 65, 66, 73 and
75 (`cp`, `chat`, `agent`), which are failures of podssh too, and a list of
numbers is what "the code path decides" warns against. A mark at each
failure path in place of each status path lost: there are many more of
them, and a new path that forgot its mark would give no report, where a new
status path that forgets gives one too many. 130 and 143 are read by their
number: podssh gives them only after the user's SIGINT and SIGTERM, which
are no failure, and a mark in each of the five places lost to the number.

The report names its form `schema` (1), and podssh's version `podssh`, as
each JSON object of podssh does (T-049, T-054); the Approach's `version`
is read as the form's number. `-q` hides an error from the screen, not
from the report: the program is there for a failure's cause, and a script
that runs with `-q` needs it most. The last messages are kept in
`podssh-ssh` (`crates/podssh-ssh/src/said.rs`), where `Log` is, and the
stderr of the command line feeds them through a tee in `main_with_args`,
only when the variable is set: a run with none keeps nothing. A server's
banner is not kept: it is not podssh's message.

The mask is a second guard, as podssh's messages hold no credential: the
value of each credential variable (`PODSSH_RELAY_TOKEN` and the three of
Cloudflare Access) and of each proxy variable, whole and as its
`user:password`, its user and its password (3 bytes at least, the longest
first), and the user and password of each URL, become `<hidden>`; then
`podssh_ws::text::one_line`, as for the lines of `podssh doctor`. Doctor has
no mask to reuse: it never builds a string with a credential. The program's
environment has no `PODSSH_ERROR_PROGRAM` (a podssh that it runs would
start it again) and no credential variable; the proxy variables stay. A
clean environment lost: the program needs `PATH`, the home and the proxy to
reach its own service. The relay comes from the record of the SSH client
(`podssh_ssh::outcome`), else from the session log's record of `proxy`
(`relay_seen`). A panic (101) gives no report: it ends the run inside
`main_with_args`; a `catch_unwind` there lost, as the state after a panic
is not known.

The test's program is the test binary run with no argument, as the
variable takes none: each test of `crates/podssh-cli/tests/error_program.rs`
first acts as the program when `PODSSH_TEST_REPORT_TO` is set. The Prove's
"a helper test, run with `--exact`" needs arguments; the limit's test runs
the ignored test `sleeper` with them, through `error_program::give`. The
gate's check is in `scripts/interop-result.sh`, the harness of the same
code path (the failure class of T-054), as `scripts/interop.sh` has 500
lines.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test error_program   # the cases below
cargo test -p podssh-cli man::facts             # the variable is documented
sh scripts/dev.sh check                         # interop.sh: a remote 'exit 3' starts no program
```

The test names the test binary itself as the program: a helper test, run
with `--exact`, copies its stdin to a file. `podssh ssh -o NoSuchKeyword=1 host`
gives a report with exit 64 and the refusal; `PODSSH_OFFLINE=1 podssh proxy example.org 80`
gives exit 69 and a report; `podssh --version` gives none. With a token of
the right form in `PODSSH_RELAY_TOKEN`, and a proxy URL with a user and a
password in `https_proxy`, the report holds neither. Plant: start the
program for each exit that is not 0; the remote `exit 3` check must fail.

## Correction

The premise of two writers is not whole. `Log` writes to the file of `-E`
in place of stderr when it is given (`crates/podssh-ssh/src/log.rs:83-103`),
and `podssh node`, `operator`, `chat`, `pipe` and `agent` write their lines
while they serve with `eprintln!`, which is neither writer
(`crates/podssh-cli/src/node.rs:351`). The report keeps what goes through
the two writers, the file of `-E` too; the lines of `eprintln!` are not
kept, and `docs/cli.md` says so.

## Done

2026-10-13. In `podssh-ssh`:
`crates/podssh-ssh/src/said.rs`, the last 64 lines of podssh's own
messages, 16 KiB at most, each cut at 2048 bytes, kept only after
`said::start`; `Log` keeps each message that it writes with `podssh: `,
and each error that `-q` hides. In `podssh-cli`:
`crates/podssh-cli/src/error_program/` (`mod.rs`: the hook of
`main_with_args`, the rule of a failure, `not_a_failure`, the tee of the
command line's stderr, and `give`, which runs the program with the report on
its stdin from a thread, its stdout and stderr on stderr, and stops it
after 30 s; `report.rs`: the object, the secrets and the mask; `tests.rs`),
`main_with_args` in `crates/podssh-cli/src/dispatch.rs`, the marks of
`ssh`, `each`, `ping`, `pipe` and `edit`, `session_log::relay_seen`, the
row of `PODSSH_ERROR_PROGRAM` in ENVIRONMENT and an example in EXAMPLES.
`docs/cli.md` ("The report of a failure"), `SECURITY.md`, `README.md` and
`docs/STATUS.md` say what the report holds. `scripts/interop-result.sh`
gives `result.error_program.openssh`, `result.error_program.dropbear` (a
remote `exit 3` starts no program) and `result.error_program.failure` (a
login that no key opens gives one report), in
`scripts/interop-baseline.txt` with the floor of `result` at 13.
`cargo test -p podssh-cli --test error_program` (a usage error and an
offline `proxy` give a report; `--version` and the manual give none; no
credential in the report or in the program's environment; a program that
does not start is one line; the limit stops a program; on the test's
server a remote `exit 3`, `kill TERM` and `exit 255` start no program and a
closed port does): 7 passed on Windows 11 (and one ignored, the program of
the limit's test). The unit tests,
`cargo test -p podssh-cli --lib error_program::` (the rule, the mask, the
secrets, the object, the tee, the manual's row) and
`cargo test -p podssh-ssh --lib said::`: 8 and 3 passed.
`cargo test -p podssh-cli man::`: 35 passed; podssh-cli and podssh-ssh
together, 1073 passed. Planted, a program for each exit that is not 0:
`a_remote_status_starts_no_program` failed; restored, it passed. In the
build image (the steps `lint` and `release`, green; interop 538 passed,
0 failed), `scripts/interop-result.sh` 13 of 13 with
`result.error_program.openssh` and `.dropbear` (a remote `exit 3` starts no
program) and `result.error_program.failure` (a login that no key opens:
255, and one report with its messages). Planted in the image, a program for each
exit that is not 0: the three checks `result.error_program.*` failed (a
report of the remote's `exit 3`), and no other. The code has no branch for one system.

# T-197: A queue of detached remote jobs: submit, list, wait and fetch the output, with no GPU logic

**Source:** GitHub #18 (the GPU-Share report, item 8: groups and a scheduler
of Docker GPU jobs, `arjun988/GPU-Share:crates/gpumesh-core/src/scheduler.rs`;
read in the report, not verified here); the operator's ruling of 2026-10-08
that devices and workloads are streams (`docs/decisions.md`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A user has more jobs than hosts: builds, tests, long runs. Each job must
wait for a free slot, run detached from the client, and give its status and
its output later. T-193 starts, lists and stops single jobs: it has no
queue, no wait for a result, and no way to get the output back.

## Premise

- Read: T-193 runs a detached job under tmux, probed with the function of
  T-178, or under `podssh serve` (T-107).
- Read: the client can stop at any time: a sandbox ends, a laptop sleeps. A
  queue on the client dies with it, and a client that waits must not need a
  listener (`docs/target-environment.md:84-88`).
- Read: the output comes back with `cp` (T-134), within 64 MiB for each
  relay session (`docs/relay.md:167`); T-137 opens a new session.
- Read in the report: GPU-Share places jobs by idle time and free VRAM. No
  such logic here: a count of slots is the only limit.

## Approach

1. The queue lives on the far host, in `~/.podssh/queue/` (mode 0700): one
   directory for each job, named by the time of the submit and 8 random hex
   characters, so that a sorted list gives the order. Each holds `cmd`,
   `state` (`queued`, `running` or `done`), `status` and `out`.
2. `podssh job submit HOST [--slots N] -- COMMAND` writes the job as
   `queued`. Then it makes sure that one runner runs: a fixed POSIX-sh
   script that the binary holds, under `tmux new-session -d -s podssh-runner`.
   A second runner cannot start: the name of the tmux session is the lock.
   The runner starts the oldest queued job when fewer than N run (default
   1), and writes `state` and `status` when a job ends.
3. `job list HOST` prints each job with its state and status; `--json`
   gives one object.
4. `job wait HOST ID [--timeout D]` reads `state` every 5 s until it is
   `done`, and exits with the job's status. When the limit passes first, it
   exits 75; add the code to `crates/podssh-cli/src/man/data.rs:19-122`.
5. `job fetch HOST ID [DIR]` copies `out`, and the files that `--files GLOB`
   names, with the engine of T-134; DIR is `./podssh-job-ID` by default.
6. With a list of hosts (T-184), `submit` picks the host with the fewest
   queued and running jobs, read with one `job list` for each host.
7. No GPU logic and no list of devices. No tmux: exit 255 with the reason,
   as T-193. In the same commit: the rows, the notes, `docs/cli.md`,
   `docs/STATUS.md`. This entry depends on T-193 and T-134.

## Decision

Recommendation: the queue lives on the far host, because the client can
stop at any time, and must not listen to wait. The alternative, a queue in
a process on the client, lost: it dies with the client, and each later
command needs a local endpoint to reach it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli job::   # the choice of the host from the counts of each host
sh scripts/dev.sh check          # interop.sh, with tmux in the image: the queue below
```

In `scripts/interop.sh`: three jobs with one slot, `sleep 2; echo J` twice,
then `exit 5`. Right after the submits, `list` shows one job running and
two queued; `wait` on the last exits 5 within 30 s; `fetch` gets an `out`
that holds `J`. Plant: the runner ignores the count of slots; the check of
one running and two queued must fail.

## Correction

2026-10-09 (T-134): 75 (`EX_TEMPFAIL`) is in the table of exit codes
already (`crates/podssh-cli/src/man/data.rs:19-122`), for a `--timeout` of
`cp` that passed; this entry adds its sentence for `job wait`.

# T-322: The emergency stop of the broadcast has a key that the user chooses

**Source:** the follow-up that T-185's Done names ("Later", the research of 2026-10-30):
dtach and abduco take Ctrl-\ as their key to detach, so a user of either beside podssh may want
another stop key.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The stop of `podssh each --interactive` is Ctrl-\ on Unix and Ctrl-Break on Windows, and nothing
else. A user who runs podssh in dtach or abduco (which eat Ctrl-\ for their detach) cannot reach the
stop. Many laptops have no Break key, and some non-US keyboard layouts need AltGr for the backslash
(both Inferred, not checked). A broadcast mistake costs N times, so the stop must be a key that the
user can type at once.

## Premise

- Read: the stop is a key that the terminal turns into a signal, SIGQUIT on Unix and a break event on
  Windows (`crates/podssh-cli/src/each/broadcast/keys.rs:1-4`), and the name that the banner and the
  notes print is a constant (`crates/podssh-cli/src/each/broadcast/hub.rs:20` says "pub const
  STOP_KEY").
- Read (POSIX, https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap11.html): the QUIT
  character, with `ISIG` set, raises SIGQUIT and is discarded; the queues are flushed unless
  `NOFLSH`. Which character is the QUIT character is a setting of the terminal (`stty quit`), so it
  can be changed for one run. Inferred: that podssh can set it by `tcsetattr` on the terminal that
  it already puts in and out of raw mode on Unix (`crates/podssh-ssh/src/terminal/unix.rs`).
- Read in their documents: dtach and abduco use Ctrl-\ as the key to detach. clusterssh makes its
  own quit key a setting (`key_quit`, default Control-q); csshX reaches its functions by an action
  key, Ctrl-A, and a submenu.
- Read: a Windows console has Ctrl-C and Ctrl-Break as control events, and "CTRL+BREAK is always
  treated as a signal"
  (https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler). Inferred: it has no
  quit character to change.

## Approach

1. A setting that names the stop key as a control character: a flag of `each --interactive`, whose
   spelling this entry decides (for example `--stop-key ^X`); whether a keyword and a variable also
   exist follows the other settings of `each`.
2. On Unix, when stdin is a terminal: set its `VQUIT` to that character for the run, and restore the
   old one on each way out (the guard of the raw mode does it for the other settings). The kernel then
   still raises SIGQUIT, `keys.rs` is unchanged, and the terminal still drops the half-typed line.
   When stdin is not a terminal there is no key, and the stop stays `kill -QUIT`, as now.
3. Refuse by name (64) a character that the terminal already uses for INTR, EOF, SUSP, ERASE, KILL
   or the end of a line, and anything that is not a single control character.
4. On Windows the setting is refused (64), naming Ctrl-Break: an ignored key would be no stop.
5. The banner, the note of `each` in the manual and `docs/terminal.md` name the key that is in effect.
6. In the same commit: the rows of the manual, `docs/cli.md`, `docs/STATUS.md`.

## Decision

Recommendation: change the terminal's QUIT character, not read the key from stdin. The terminal
keeps its normal mode in this feature, so that its own line discipline edits the line (T-185); a key
that podssh read itself would need the raw mode, which T-185 left out, and would no longer drop a
half-typed line at the key. Lost: reading the key in raw mode; and a second, softer key for
`:none`: the stop is the one key that must always work.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test each -- interactive
```

In a pty that is podssh's controlling terminal (as the test of `Ctrl-\` in T-185 gives one), with
`--stop-key ^X`: typing Ctrl-X stops the broadcast and drops the line that is half typed, and
Ctrl-\ no longer does; after podssh exits, the pty's QUIT character is Ctrl-\ again. A character that
the terminal uses (Ctrl-C), and the setting on Windows, are refused with 64. Planted defect: leave
the QUIT character changed at the exit; the check of the restored character fails.

## Done

2026-10-30. `podssh each --interactive --stop-key KEY` takes one control
key, as `^X`, `Ctrl-X` or `C-x`, and on Unix makes it the terminal's QUIT
character for the run when stdin is a terminal, with a guard that puts the
old character back on each way out
(`crates/podssh-cli/src/each/broadcast/stop_key.rs`); the terminal still
raises SIGQUIT and drops the half line, and `keys.rs` is unchanged. A key
that a terminal keeps by default (INTR, EOF, SUSP, ERASE, KILL, the ends of
a line), one that this terminal uses for another of its characters, and
anything but one control key are refused (64); so is the flag on Windows,
which names Ctrl-Break; so is `--stop-key` without `--interactive`. The
banner, `:help` and the word at Ctrl-C name the key in effect. The manual's
note of `each`, `docs/cli.md` and `docs/terminal.md` say it.

- Linux, 2026-10-30: `cargo test -p podssh-cli --test each -- interactive`,
  10 passed: in a pty that is podssh's controlling terminal, with
  `--stop-key ^X`, the banner names Ctrl-X, Ctrl-X stops the broadcast and
  drops the half line, and the pty's QUIT character is Ctrl-\ after podssh;
  `--stop-key ^C` is refused with 64 and names INTR. `--lib`, 350 passed
  (the parse and each refusal); clippy and rustfmt clean.
- Planted: the old character not put back at the exit; the last check
  failed ("the terminal's QUIT character after podssh"); restored, it
  passed.
- Waiting for CI's job `windows`: the refusal of the flag on Windows.
