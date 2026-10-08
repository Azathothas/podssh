# Command line

`podssh man` is the reference for each command, argument, flag, `-o`
keyword, variable, file and exit code. The binary makes it from its own
tables, so it describes that binary and no other version. This page gives
the rules behind those tables, for people and agents who change them.

`podssh ssh` takes the command line of OpenSSH, so it can replace `ssh` in
scripts. The facts about OpenSSH on this page were measured with OpenSSH
10.3p1 and `ssh -G`, unless a line gives another source.

## The manual

- **The tables.** The flags of each command are in
  `crates/podssh-cli/src/flags.rs`, their arguments in `src/positionals.rs`,
  the `-o` keywords in `src/ssh/keywords.rs`, and the variables, files, relay
  facts, exit codes, notes and examples in `src/man/`. `--help` and
  `podssh man` read the same tables.
- **Change the table with the code, in the same commit.** The tests fail
  when the manual and the code disagree: a variable that the code reads and
  the manual does not name (or the reverse), a default that `resolve` does
  not use, an `-o` keyword that the parser handles differently, an example
  that the parser refuses, or a note that names a flag that is gone.
- **Text first.** `podssh man` writes plain text, so it needs no `man`,
  groff or pager. On a terminal it pages: `PAGER`, else `less` when `PATH`
  has it and `TERM` names a terminal (not on Windows), else its own pager.
  `--no-pager` writes to stdout; with no terminal there is no pager.
- **Roff second.** `podssh man --roff` writes a man(7) page with standard
  macros only. A macro defined in the page is read differently by different
  renderers: an `Fl` macro that used `\$*` printed blank flag names under
  groff and mandoc. The gate renders the page with both
  (`scripts/interop-man.sh`).
- **No setting of the host.** The manual is the same bytes in each
  environment. It never shows a token or a credential.
- **A command that does not work says so.** `--help` and the manual mark a
  command that is not implemented, or not in this build, and the manual
  shows no options for it.

## Options of `podssh ssh`

- **`-P` has a different meaning for each command.** For `ssh`, `-P` is a
  tag: `ssh -G -P mytag x` prints `tag mytag`, and `-P2222` keeps port 22
  and sets the tag 2222. For `scp` and `sftp`, `-P` is the port. Thus
  `podssh ssh -P TAG` accepts the tag, ignores it, and says on stderr that
  `-p` is the port. For `cp`, `mv`, `scp` and `sftp`, `-P` is the port.
- **No option is dropped silently.** An unknown flag is an error that names
  the nearest real flag (exit 64). A dropped option can disable a security
  check without a message. OpenSSH exits 255 with `Bad configuration
  option` for an unknown `-o` keyword, before it connects.
- **Destinations.** `-J a,b` makes a chain of hops; `-J a -J b` is an error.
  `ssh host:2222` connects to a host named `host:2222` on port 22. The port
  form of OpenSSH is `ssh://user@host:2222`. podssh also accepts `host:PORT`,
  because its own "did you mean" message gives that form. A host name cannot
  contain `:`, and an IPv6 literal needs brackets.
- `-N` alone is valid. `-W HOST:PORT` is a stdio forward: no session, and
  exit when the forward fails. `-V` prints the version and does not connect.
- **A repeated value follows OpenSSH** (measured with `ssh -G`): the first
  `-p` and `-l`, the last `-e`, `-E` and `-F`, and the first value of each
  `-o` keyword. A second `-J` or `-W` is an error, as in OpenSSH. podssh's
  own `--relay-host`, `--relay-addr` and `--ca-file` may be given once: a
  comma list gives several hosts or addresses, and no relay or trust store
  is chosen by its place on the command line.
- Each flag in the usage of OpenSSH 10.3p1 has a row: supported, accepted
  with no effect (`-P`, `-g`), or refused by name with what to use instead.
  `tests/flag_table.rs` holds the reviewed set. A refusal with nothing to use
  instead says "Leave it out."

## Forwarding

- `-L` and `-D` need a local listener, so podssh refuses them. The refusal
  of `-L` gives `-W HOST:PORT`. For `-D`, `-W` is only a partial answer: a
  SOCKS proxy serves many connections, and `-W` serves one.
- `-R` does not need a local listener: the server listens, and podssh
  connects out for each connection. It is not implemented yet. Its refusal
  must not say that podssh never binds. On the measured sandbox, a
  connection back to loopback is refused, so `-R` must go through the proxy
  or fail with a clear message.
- When a server refuses `tcpip-forward`, podssh gives the server's reason.
- Agent forwarding (`-A`) is not in the scope of podssh.

## A word with no subcommand

`podssh example.org` never connects. podssh selects a suggestion in two
steps:

1. The form of the word: `@`, `.` or `:` gives `Try: podssh ssh <word>`.
2. The edit distance, with an absolute limit and a shared two-letter prefix.

The edit distance alone suggests `doctor` for `example.org` and `cp` for
`xz`. The first step prevents this.

## `podssh doctor`

`podssh man doctor` gives the checks. The rules behind them:

- `doctor` takes the relay settings of `ssh` and `proxy` (`--relay-host`,
  `--relay-addr`, `--ca-file` and their variables), so it checks the path
  that they use.
- `ok`: the check ran and podssh can work with the result. A condition that
  podssh is made for (no listener, no pty, no user database entry, no DNS)
  is a fact and gives `ok`.
- `FAIL`: something that podssh or one of its fallbacks needs is broken: a
  proxy setting that cannot be used, no place to record host keys, a relay
  host that does not answer, no token, a forward session that fails or
  meets the wrong host key, or a clock more than one hour wrong.
- `????`: the check could not run. It never counts as `ok`, and it never
  makes the run fail.
- Servers are identified by equality (GitHub's published host key), never
  by the form of a banner. A socket bind is closed at once and never
  listens. Proxy credentials and tokens are never shown.

## `podssh keygen`

`podssh man keygen` gives the flags. The rules behind them:

- The `ssh-keygen` of OpenSSH does not run without a user database entry,
  so podssh makes keys itself, in the formats of OpenSSH.
- A private key is never written over an existing file.
- A passphrase given with `-N` is refused (exit 64), because each process
  on the host can read a command line. `-N ''` is accepted. With no
  terminal and no `SSH_ASKPASS`, podssh refuses at once and names `-N ''`;
  it does not wait.
- DSA is refused, because OpenSSH 10 removed it.
- The comment comes from the environment, never from the user database.

## Exit codes

`podssh man exit-status` gives each code. The rules behind them:

- A usage error is 64 (`EX_USAGE`) for each command, before podssh does
  anything. A configuration error is 78 (`EX_CONFIG`). The shell statuses 1
  and 2 are not used for these, because a script cannot tell them from other
  programs' failures.
- `podssh ssh` uses the codes of OpenSSH, so it can replace `ssh` in
  scripts: the remote status unchanged (0 and 127 included), and 255 for a
  failure of podssh. A remote command stopped by a signal gives 128 plus the
  signal number (OpenSSH gives 255), and podssh names the signal on stderr.
- `podssh proxy` is not an SSH client: its failures use sysexits (64 to 78).
- A command that is not implemented exits 70. It never exits 0.
- A closed stdout (EPIPE) ends the session cleanly.

## Prompts and time limits

- Prompts (host key, passphrase, password, keyboard-interactive) go to the
  controlling terminal, as with OpenSSH. Thus
  `echo x | podssh ssh host cat` can still ask for a password.
  `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE` works as in OpenSSH.
- With no terminal and no askpass program, a prompt becomes a refusal that
  names the remedy. For an unknown host key: its fingerprint and
  `-o StrictHostKeyChecking=accept-new`. For a password: a key file.
- podssh asks on `/dev/tty` only when the kernel names it as the controlling
  terminal: the descriptor is a terminal of this process's session, and
  `/proc/self/stat` (when it can be read) names a terminal. In a measured
  sandbox, `/dev/tty` opened with no controlling terminal, and a read
  blocked for ever.
- When stdin, stdout and stderr are all redirected, a prompt on the terminal
  waits 60 s at most (`terminal::UNWATCHED_PROMPT`), then refuses with the
  remedy. A person at the terminal can still answer; a terminal that nobody
  watches does not stop podssh for ever.
- `-o BatchMode=yes` makes each prompt a refusal.
- A changed host key is refused, also on a terminal.
- A duration is parsed as a whole string. A malformed duration is an error,
  never zero. A time limit applies to the whole operation, not only to the
  dial.

## `ssh_config` (milestone M8)

podssh does not read `ssh_config` yet. These are the rules of OpenSSH,
measured with `ssh -G`:

- The first value obtained wins, from top to bottom. The most specific block
  does not win.
- A negated pattern excludes the host from that block only.
- `IdentityFile` and `-i` add up; they do not replace each other.
- `Include` is expanded where it appears, with globs in sorted order. A
  relative `Include` starts from `~/.ssh` (user file) or `/etc/ssh` (system
  file), not from the directory of the file that includes it.
- `*` matches across dots.
- `Match` never overrides a value that is already set. podssh must refuse
  `Match` by name, not skip it, because `Match` can change the host that
  podssh connects to.
- A missing `-F` file is an error (255), and `-F` stops the reading of each
  other configuration file. A missing `~/.ssh/config` is not an error.

NOTE: In its recommended parsing mode, `ssh2-config` 0.8.1 drops
`ProxyCommand` and `StrictHostKeyChecking` silently (read 2026-10-01). Do not
use it.
