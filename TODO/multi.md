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
  (`crates/podssh-ssh/src/io.rs:378-395`), and podssh's own messages go to
  stderr with one `podssh: ` prefix (`crates/podssh-ssh/src/log.rs:79-94`).
  Two hosts cannot be told apart.
- Read: a host-key prompt waits for the user
  (`crates/podssh-ssh/src/hostkey.rs:208-246`); N prompts at once cannot
  work. `known_hosts` is appended under a lock since T-029
  (`crates/podssh-ssh/src/known_hosts.rs:335-410`).
- Read: with no cached token, each session mints one
  (`crates/podssh-relay/src/token.rs:134-179`); the relay allows 120 attempts
  with no token for each minute and address (`docs/relay.md:163`).

## Approach

1. A verb `each`: `podssh each [OPTIONS] HOSTS -- COMMAND`, HOSTS a comma
   list (T-184 adds braces and groups). The options: those of `ssh` that make
   sense for many hosts (`-p`, `-l`, `-i`, `-o`, `--direct`, the relay
   flags), and `--parallel N` (default 8, 64 at most), `--fail-fast`,
   `--output-dir DIR`.
2. One runtime, one task for each host, each on the existing path: the relay
   open and `podssh_ssh::run` (`crates/podssh-cli/src/ssh/mod.rs:156-230`,
   `crates/podssh-ssh/src/run.rs:35-80`). Invariant: no second SSH client.
3. Sinks: give `crates/podssh-ssh/src/io.rs:124-395` a sink for stdout and
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
7. In the same commit: `crates/podssh-cli/src/flags.rs:363-412`,
   `crates/podssh-cli/src/positionals.rs:7-183`, a `Parsed` variant,
   `crates/podssh-cli/tests/flag_table.rs:110-113`, the notes, an example,
   `docs/cli.md`, `docs/STATUS.md`. T-013 can then group the commands.

## Decision

Recommendation: a new verb, because `podssh ssh` keeps the command line and
the exit codes of OpenSSH for one host (`docs/cli.md:1629-1632`), and a list
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
  (`docs/cli.md:1745-1838`); they cannot define a group.

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
**Status:** open

## Problem

To type the same commands on several hosts, a user needs csshw, the
`synchronize-panes` of tmux, or a GUI. A broadcast mistake costs N times, so
a broadcast needs a stop that works at once.

## Premise

- Read: a session reads stdin on its own task and sends each chunk to one
  channel (`crates/podssh-ssh/src/io/input.rs:77-97`,
  `crates/podssh-ssh/src/io.rs:164-209`).
- Read: escapes work only at the start of a line, and only with a pty
  (`crates/podssh-ssh/src/escape.rs:1-8`).
- Read: each session can live in one process, so a broadcast needs no
  listener (`docs/target-environment.md:74-78`).

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
6. In the same commit: `docs/cli.md`, the notes, `SECURITY.md:94-114` (a
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
**Status:** open

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

# T-188: A host picker when `podssh ssh` gets no destination

**Source:** GitHub #24 (the csshw report, item 10: a host picker when it
starts with no hosts). Read in the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

On a terminal, `podssh ssh` with no destination only says that one is
missing. A user with a long ssh_config must remember each `Host` name. A
short numbered list helps a person; a script must still get the usage error.

## Premise

- Measured: `podssh ssh </dev/null` exits 64 with "missing destination"
  (`crates/podssh-cli/src/ssh/resolve.rs:156`).
- Read: `run_ssh` gets no terminal state
  (`crates/podssh-cli/src/dispatch.rs:259-261`), and the entry point of the
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

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_args -- picker   # no terminal, or stdout alone: exit 64, nothing read
sh scripts/dev.sh check                              # interop-pty.py: the choice below
```

`scripts/interop-pty.py` gives a fixture ssh_config with three `Host` lines;
typing 2 logs in to the second host, with exit 0. Plant: show the picker
when only stdout is a terminal; that case must fail.

# T-189: The health of the far host over the session

**Source:** GitHub #21 (meatshell: CPU, memory, swap, network, disk and
processes); GitHub #24 (RustConn: a bar of metrics with no agent); GitHub #19
(slingshot `health`); GitHub #23 (SSHub: the state reported by the remote
end). Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Before work on a host, an operator checks its load, memory and disk. With
podssh, that is a typed command that differs for each host, and needs tools
that can be missing. `podssh doctor` checks only this host.

## Premise

- Read: an exec request runs one command through the shell of the server
  (`crates/podssh-ssh/src/session.rs:114-127`), and its output goes to stdout
  (`crates/podssh-ssh/src/io.rs:378-395`); podssh cannot read it.
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
   (`crates/podssh-ssh/src/io.rs:124-395`), parse it, and print one line for
   each fact: load, memory and swap, uptime, network bytes (two samples,
   1 s apart), disk, processes. `--json` gives one object, in the shape of
   T-049.
4. No `/proc`: print the output of `uname -s` and "no facts for this
   system". No `sh`: exit 255 with "the server has no sh".
5. The exit codes of `podssh ssh`: 0, or 255 for a failure.
6. In the same commit: the rows, the notes, an example, `docs/cli.md`,
   `docs/STATUS.md`. T-013 can then group the command.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli health::   # the parser, on /proc text captured from Alpine and Debian
sh scripts/dev.sh check             # interop.sh: the comparison below
```

In `scripts/interop.sh`, `health --json` runs against OpenSSH and Dropbear,
and its available memory is within 5 % of `MemAvailable` read over exec.
Plant: read `MemFree` in place of `MemAvailable`; the comparison must fail.

# T-190: Containers and pods as destinations

**Source:** GitHub #24 (the rssh report, item 6: Docker containers and
Kubernetes pods found through the local tools, then exec terminals). Read in
the report, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

To enter a container on a remote host, a user logs in, lists the containers,
and types `docker exec -it NAME sh`. Each step is done by hand, and each
name is copied by hand.

## Premise

- Read: `podssh ssh -t HOST -- docker exec -it NAME sh` works today, as a
  remote command with a pty (`crates/podssh-cli/src/ssh/resolve.rs:269-277`,
  `crates/podssh-cli/src/ssh/hop.rs:97-108`). Only the list is missing.
- Read: podssh starts a program only when the user names it or a probe
  finds it (`AGENTS.md:232-236`). Here the programs run on the server, for a
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

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli containers::   # the parser, on committed output of docker, podman and kubectl
sh scripts/dev.sh check                 # interop.sh: the stand-ins below
```

In `scripts/interop.sh`, stand-ins for `docker` and `kubectl` on the `PATH`
of the server print the captured output; the list and `--exec` reach them.
Plant: skip the check of the names; the fixture with `a;b` must fail.

# T-191: Expect rules, and tasks before and after a connection

**Source:** GitHub #24 (the RustConn report, item 8: expect rules, key
sequences, and tasks before and after a connection). Read in the report, not
verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Some hosts need keys after the login: a menu, a banner to confirm, a second
shell. Some users need a local command after the connection opens, as the
`LocalCommand` of OpenSSH. podssh ignores `LocalCommand`, and it has no
expect rule.

## Premise

- Measured: `podssh ssh -o LocalCommand=true -o PermitLocalCommand=yes -v user@host.invalid true`
  prints `-o LocalCommand has no effect in podssh`, and the same for
  `PermitLocalCommand` (`crates/podssh-cli/src/ssh/keywords.rs:93-94`).
- Read: remote output arrives at `crates/podssh-ssh/src/io.rs:316-331`, and
  input leaves at `crates/podssh-ssh/src/io.rs:164-204`. An expect rule goes
  between them.
- Read from memory, to verify against OpenSSH 10.3p1: OpenSSH runs
  `LocalCommand` after the connection, with the user's shell, only with
  `PermitLocalCommand yes`, and expands tokens such as `%h` and `%p`.

## Approach

1. `LocalCommand`: move it and `PermitLocalCommand` from IGNORED to
   HONOURED (`crates/podssh-cli/src/ssh/keywords.rs:25-79`), with fields in
   `crates/podssh-cli/src/ssh/options.rs:13-80`. Run it when OpenSSH runs it
   (check the order in the container). Expand the tokens with `Tokens::expand`
   (`crates/podssh-cli/src/ssh/tokens.rs:69-141`), which has `%p` and `%n`
   since T-238.
   The shell: `SHELL`, else `/bin/sh` when it exists, else exit 78.
2. Expect: `--expect TEXT --send TEXT` pairs, in order, only in a session
   with a pty. Match a literal text in the last 64 KiB of output. `--send`
   reads `\r`, `\n`, `\t` and `\xNN`. Each rule waits `--expect-timeout`
   (default 30 s); a miss ends the session with 255 and names the rule.
3. No secrets: `--send` is on the command line, which each process can read
   (`docs/architecture.md:141-143`). The manual says so; passwords come
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
   (`docs/relay.md:162`), run the exec on a new session (T-137).
4. The exit status: the command's, with the rules of `podssh ssh`
   (`docs/cli.md:1629-1632`). A failed copy exits 255 and runs nothing.
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
**Status:** done

## Problem

A long build on a remote host stops with the connection, unless the user
starts it under `nohup` or tmux by hand. podssh cannot start a command that
outlives the session, show it later, or stop it.

## Premise

- Read: a session ends with its connection (`docs/design.md:381`), and `-f`
  is refused (`crates/podssh-cli/src/flags.rs:247-248`).
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

2026-10-13 (the draft): the calls of the work.

- **The output and the status go to files, not to tmux's pane.** Each job
  is a directory `~/.podssh/jobs/MILLIS-ID` of mode 0700, with `cmd`,
  `state`, `out` and `status`. tmux runs the command and holds it, and
  `stop` ends the session of that exact name, as the recommendation says.
  The `capture-pane` of the Approach lost: it keeps only the pane's history
  (2000 lines by default), cuts each long line at the pane's width, and
  loses the output and the status when the session ends. `remain-on-exit`
  lost too: it is set after the session starts, and a short command can
  end first. A file in a directory of the user's alone is the safe place
  that the queue of T-197 uses too.
- **`list` reads the directories, and tmux for the state.** A job is
  `running` while its session is there, `done` with its status, and `lost`
  with neither (a restart of the host or of tmux's server). A list of
  tmux's sessions alone, as in the Approach, lost: it shows no job that
  ended.
- **`stop` removes the job with its output.** It ends the session when it
  runs, with `tmux kill-session -t =podssh-job-ID` (`=` asks for the exact
  name; a bare name also matches a longer one), then removes the
  directory. A `stop` that keeps a record lost: a fifth verb would then
  remove it.
- **The far side is one script, sent with each call.** `far.sh` goes on
  the stdin of `sh -c 'INSTALL' sh MARKER ACTION ARG...` and is kept as
  `~/.podssh/jobs/jobs.sh`, which tmux runs for each job; the answer comes
  after a marker, as the copy by exec of `cp` reads it. A script that an
  earlier call left lost: a host would then run another version than the
  binary, and nothing would show it.
- **The command runs in sh, in the home directory, with no input**, as a
  command of `podssh ssh` runs in the login shell there. The login shell
  lost: it is tmux's shell too, and may not be POSIX, and the job's status
  is read in sh.
- **`--` before the command is required** (64 without it). Without it, a
  word such as the `-l` of `ls -l` would be read as podssh's `-l`, with no
  error.
- **Step 3, a `podssh serve` at the far end, waits for T-107**, which the
  operator holds (Q32). No host runs one, so the refusal with no tmux
  names tmux alone: "HOST has no tmux on PATH; podssh job runs each job in
  the host's tmux, and starts none without it".

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

## Done

2026-10-13, a draft (DRAFT T-193), not built: each result below that needs
a build or a run is UNVERIFIED, and the merger fills it in.

- `podssh job start|list|log|stop` (`crates/podssh-cli/src/job/`): the
  rows (`crates/podssh-cli/src/flags/job.rs`), the arguments, the synopsis
  and the group "Work on a host" of `--help` and the manual, the notes
  (`crates/podssh-cli/src/man/notes_job.rs`), an example, and `podssh job`
  in the row 255 of EXIT STATUS. The far script is
  `crates/podssh-cli/src/job/far.sh`; `docs/cli.md` (section
  "`podssh job`"), README.md and AGENTS.md name the command.
- `cargo test -p podssh-cli --lib job::` (the command line, the answers of
  the far script, the list): UNVERIFIED.
  `cargo test -p podssh-cli --test job` (the refusals, 64, and a host out
  of reach, 255, offline; the help and the manual): UNVERIFIED.
  `cargo test -p podssh-cli --test job_far`
  (Unix: the far script in sh through the test's server, which
  `ssh_harness::start_shell` gives; two jobs, a stop of one, the log and
  the status of a job that ended, with tmux from `PODSSH_TEST_TMUX` or
  PATH; with no tmux on PATH, 255 and no job made): UNVERIFIED, in the
  build image with tmux. The tests of the flag table and of the manual
  with the new verb (`--test flag_table`, `--test man_flag_parity`,
  `--test man_page`, `--test man_json`, `--lib man::`): UNVERIFIED.
- `scripts/interop-job.sh`, sourced by `scripts/interop-each.sh` so that
  `scripts/interop.sh` stays at 500 lines: 7 checks against OpenSSH and
  Dropbear, in `scripts/interop-baseline.txt`. UNVERIFIED: waits for T-251.
- The planted defect: `stop` ends each tmux session whose name starts
  with `podssh-job-`. The checks `job.openssh.stop` and
  `job.dropbear.stop`, and the test
  `two_jobs_run_and_a_stop_of_one_leaves_the_other`, must fail.
  UNVERIFIED: waits for T-251.

# T-195: Hand an error report to a program that the user names, for triage by an AI or a script

**Source:** GitHub #24 (the rssh report, item 5: AI triage of the terminal,
`rssh-org/rssh:src-tauri/src/ai/`; read in the report, not verified here);
the operator's ruling of 2026-10-08 (`docs/decisions.md`): a CLI hook, and
podssh never calls an AI service itself.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

When podssh fails, a user or an agent copies its messages into another tool
to find the cause. A failure in a script is seen late, or never. podssh
cannot hand a failure to a program that the user chose: a script that files
a ticket, or a tool that asks an AI.

## Premise

- Read: podssh starts another program only when the user names it
  (`AGENTS.md:232-236`), as it runs `SSH_ASKPASS`: the program, no shell, and
  its first line read back (`crates/podssh-ssh/src/prompt.rs:102-119`).
- Read: credentials never go to output, logs, URLs or argv
  (`docs/architecture.md:141-143`). The token type never shows itself
  (`crates/podssh-relay/src/token.rs:27-56`), and doctor never shows proxy
  credentials or tokens (`docs/cli.md:915-917`).
- Read: podssh's messages leave through two writers: `Streams.err` in the
  command line (`crates/podssh-cli/src/dispatch.rs:26-29`), and `Log`, which
  writes to the stderr of the process itself
  (`crates/podssh-ssh/src/log.rs:79-94`). The exit code leaves through
  `crates/podssh-cli/src/dispatch.rs:305-320`.
- Read: for `podssh ssh`, an exit that is not 0 can be the remote command's
  status (`docs/cli.md:1629-1632`), which is not a failure of podssh.

## Approach

1. A variable `PODSSH_ERROR_PROGRAM`: one program, with no shell and no
   arguments, as `SSH_ASKPASS`. Add it to `VARIABLES`
   (`crates/podssh-cli/src/man/facts.rs:45-213`).
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
   `SECURITY.md:63-67` (what the report holds), `docs/STATUS.md`.

## Decision

Recommendation: a variable, as `SSH_ASKPASS`, because it reaches each verb,
also `podssh proxy` under the `ProxyCommand` of OpenSSH, with no new row in
each flag table. The alternative, a flag `--on-error PROG` on each verb,
lost: a row for each verb, and each `ProxyCommand` line must change.

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
  listener (`docs/target-environment.md:74-78`).
- Read: the output comes back with `cp` (T-134), within 64 MiB for each
  relay session (`docs/relay.md:162`); T-137 opens a new session.
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
   exits 75; add the code to `crates/podssh-cli/src/man/data.rs:19-120`.
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
already (`crates/podssh-cli/src/man/data.rs:19-120`), for a `--timeout` of
`cp` that passed; this entry adds its sentence for `job wait`.
