This file holds the work on configuration files: OpenSSH's `ssh_config` (`-F`, `Host`,
`Include`, `Match` and `-G`), host lists from other clients, and a settings file for podssh's
own options. The rules of OpenSSH that podssh follows were measured with `ssh -G` and are in
`docs/cli.md:661-725`. Since T-043, `podssh ssh` reads `~/.ssh/config` and the file of `-F`.

# T-043: Read `ssh_config`: `~/.ssh/config`, `-F FILE`, `Host` patterns, and `Match` refused by name (GitHub #14, #22)

**Source:** GitHub #14 (Nemo-010, 2026-10-08); the reports on lablup/bssh, VLOD-ZDOV/quic-ssh,
TeddyHuang-00/sshping (GitHub #22), whme/csshw and RustConn (GitHub #24); ROADMAP M8.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`podssh ssh` reads no `ssh_config` file. An agent repeats each `-o` (`StrictHostKeyChecking`,
`IdentityFile`) in each call and cannot use a `Host` alias; one forgotten `-o` gives a refusal.

## Premise

Measured on `3ee70dc` (`target/debug/podssh.exe`, `PODSSH_OFFLINE=1`): with
`-F ~/.ssh/config`, `podssh ssh` exits 64 ("reading ssh_config files is not implemented yet");
`-o Match=all` exits 64 ("an ssh_config block keyword, not an option"). Read: each `-F` but
`none`, `/dev/null` and `NUL` is refused (`crates/podssh-cli/src/ssh/resolve.rs`, lines 108-115 at `c0cdd2b`).
`Settings::apply` keeps the first value of a keyword
(`crates/podssh-cli/src/ssh/options.rs`, lines 188-192 at `c0cdd2b`), the rule of `docs/cli.md`, lines 588-589 at `c0cdd2b`. A
`-o User` or `-o Port` beats `user@host` and `host:PORT`
(`crates/podssh-cli/src/ssh/resolve.rs`, lines 144-154 at `c0cdd2b`), so a file value in that `Settings` would beat
them too, which is wrong. An unknown `%` token stays as text (`crates/podssh-cli/src/ssh/resolve.rs`, lines 303-306 at `3ee70dc`).

## Approach

1. A reader in a new module, crates/podssh-cli/src/ssh/config.rs: records of file, line,
   keyword and value under their `Host` line, applied through `Settings::apply` (one path for a
   file line and `-o`). Each error names FILE:LINE; a bad file exits 78 (`docs/cli.md`, lines 528-531 at `c0cdd2b`).
2. File values go into a second `Settings`, merged after the command line: `-l`, `-o User`,
   `user@host`, then the file; `-p`, `-o Port`, `host:PORT`, then the file. `IdentityFile` adds
   to `-i` (`docs/cli.md`, line 591 at `c0cdd2b`).
3. `-F FILE` alone; `-F none` nothing; else `~/.ssh/config`, with the home from `HOME` or
   `USERPROFILE` (`crates/podssh-cli/src/ssh/resolve.rs`, lines 71-83 at `c0cdd2b`). Only a missing `-F` file is an
   error (`docs/cli.md`, lines 599-600 at `c0cdd2b`).
4. `Host` patterns through `known_hosts::wildcard`
   (`crates/podssh-ssh/src/known_hosts.rs:257-279`); not `matches`, which accepts `|1|` hashes.
5. Refuse `Match`, and `Include` until T-044, by name with FILE:LINE (`docs/cli.md`, lines 596-598 at `c0cdd2b`).
   In a block that applies, refuse each option that `-o` refuses
   (`crates/podssh-cli/src/ssh/keywords.rs`, lines 84-89 at `c0cdd2b`), but accept a `ProxyCommand` that runs
   podssh itself (`proxy %h %p`: the path of `podssh ssh` anyway). Honour `IgnoreUnknown`.
6. Refuse a file that another user owns or can write, as OpenSSH does, on the opened file
   (`crates/podssh-relay/src/cache/own.rs:22-62`, `Others::Read`, since T-163). An unknown `%`
   token is an error.
7. In the same commit: the `-F` row (`crates/podssh-cli/src/flags.rs`, lines 143-144 at `c0cdd2b`), VARIABLES and
   FILES (`crates/podssh-cli/src/man/facts.rs`, lines 45-127 and 98-142 at `c0cdd2b`), the `ssh` notes,
   `docs/cli.md`, lines 583-604 at `c0cdd2b` and `docs/STATUS.md`.

## Decision

Recommendation: read the system file (`/etc/ssh/ssh_config`, `%ProgramData%\ssh\ssh_config` on
Windows) in T-044, not here. Common distributions are believed to start it with `Include`, and
Fedora to use `Match final all` (verify this), so this entry alone would refuse it. Never reading
it lost: that drops an administrator's `StrictHostKeyChecking` without a message.

Recommendation: add `PODSSH_SSH_CONFIG`, with the meaning of `-F FILE`; `-F` wins. A process
manager sets it once, also where the home cannot be written. `-F` alone lost: each call must
repeat it, which is the complaint of GitHub #14.

Decision (2026-10-10): read only the blocks that apply. OpenSSH checks each line, also in a
block for another host; podssh refuses some keywords that OpenSSH runs (`LocalForward`, a
`ProxyCommand`), and its table can lag a newer OpenSSH, so a check of each block would stop each
connection for a line that never applies to it. Lost: OpenSSH's check, which finds a typo in a
block before the block is used; the typo is still refused, with its line, when its block applies.

Decision (2026-10-10): accept `ProxyCommand podssh proxy %h %p`, in a file and with `-o`, with no
effect: a user of OpenSSH writes it for podssh, and `podssh ssh` takes that road anyway. With
other words after `proxy` it is refused, with the reason: those are podssh's own flags, which
`podssh ssh` would not see. Lost: a refusal of each `ProxyCommand`, which stops podssh on a file
made for OpenSSH and podssh; and running the command, a second program that the user did not
name to podssh (`AGENTS.md`, rule 3).

Decision (2026-10-10): check the owner and the mode of `~/.ssh/config` alone, as OpenSSH does. A
file that `-F` or `PODSSH_SSH_CONFIG` names is the user's choice. Lost: a check of each file,
which refuses a shared file that an administrator keeps, for nothing that OpenSSH gives.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_config   # new: crates/podssh-cli/tests/ssh_config.rs
cargo test -p podssh-cli                     # the keyword, variable and manual drift tests
sh scripts/dev.sh check                      # interop: -F FIXTURE to OpenSSH and Dropbear
```

The tests: the first value wins; `!` excludes; `user@host`, `host:PORT` and `-o` beat the file;
a missing `-F` file exits 78; `Match` is refused with FILE:LINE. In `scripts/interop.sh`,
`-F FIXTURE alias` reaches the OpenSSH server. Planted defects: the file applied before `-o`,
and a skipped `Match`; a test fails for each.

## Correction

Measured on 2026-10-10 with OpenSSH 10.3p1's `ssh -G` (the client of MSYS2 on Windows; the
checks of files with the client of Alpine in the build image), where the Premise and the
Approach read otherwise:

- "An unknown `%` token stays as text" held at `3ee70dc`. Since `5521cbf` (T-238) an unknown
  token of a file name is refused: `crates/podssh-cli/src/ssh/tokens.rs:116` says "is not a
  token". `HostName` took no token at all; OpenSSH gives it `%h`, the host as typed, and `%%`,
  refuses each other token, and lowercases the result. This entry adds them. `User` (from `-o`
  and from a file, not from `-l`) and `RemoteCommand` take tokens in OpenSSH too, and podssh
  expands neither: T-273.
- Step 6 named `read_own` with `Others::Read`, which does not fit. OpenSSH follows a symbolic
  link (a store of dotfiles links `~/.ssh/config`), takes a file of root's, reads a file of 125
  kB, and checks the owner and the mode of `~/.ssh/config` alone: a file that `-F` names is read
  when another user owns it or others can write it. `read_own` refuses a link, a file of root's
  and a file over 64 KiB. The reader is podssh's own (`crates/podssh-cli/src/ssh/config.rs`): it
  follows a link, reads a pipe and at most 4 MiB, and on Unix checks `~/.ssh/config` alone: the
  user's or root's, with no write for the group or others. On Windows no file is checked, as for
  the files of the cache: T-274.
- A `Host` pattern matches the host as typed, with its case: `Host MyHost` applies to `MyHost`,
  and not to `myhost` or `MYHOST`. Only the first `IgnoreUnknown` counts, and `-o
  IgnoreUnknown` beats the file's; `-o` did not know the keyword. A `#` that starts a word
  starts a comment, also after a value.
- OpenSSH checks each line of the file, also in a block that does not apply: a keyword that it
  does not know, in a block for another host, ends each run with 255. The Decision keeps
  podssh to the blocks that apply.
- `crates/podssh-cli/tests/ssh_config.rs` holds the tests of `-G` (T-046), so the tests of this
  entry are in `crates/podssh-cli/tests/ssh_config_file.rs`.
- `cp`, `mv`, `scp`, `sftp` and the `ssh:` address of `pipe` reach a host through the same
  resolver, so they read the file too; the help of their `-F` said "read for its shared keys".
  Each test that starts podssh read the `~/.ssh/config` of the machine that ran it; each now
  sets `PODSSH_SSH_CONFIG=none`.

## Done

2026-10-10, in the commit that closes this entry. `podssh ssh` reads `~/.ssh/config`, the file of
`-F FILE` or of `PODSSH_SSH_CONFIG`, and `none` reads nothing; so do `cp`, `mv`, `scp`, `sftp` and
the `ssh:` address of `pipe`. A `Host` block applies as OpenSSH 10.3p1 applies it; its lines go
through the parser of `-o`, and an error names FILE:LINE, with 78. The command line beats the
file, and the file's `User` and `Port` come after `user@host` and `host:PORT`; `IdentityFile`
adds to `-i`. `Match`, and `Include` in a block that applies, are refused by name with
FILE:LINE. `IgnoreUnknown` is honoured with `-o` and in a file; `HostName` takes `%h` and `%%`;
a comment may follow a value; `ProxyCommand podssh proxy %h %p` is accepted. The `-F` rows of
`ssh`, `cp`, `scp` and `sftp`, VARIABLES (`PODSSH_SSH_CONFIG`), FILES (`~/.ssh/config`), the
table of keywords and `docs/cli.md` say so.

Native, Windows 11: `cargo test -p podssh-cli --test ssh_config_file`, 10 passed (11 on Unix,
where the check of the mode and of a link runs), among them the fixture against the lines that
OpenSSH 10.3p1's `ssh -G -F FIXTURE` printed for six command lines. Planted, the file applied
before `-o` fails `the_command_line_beats_the_file`, and a skipped `Match` fails
`match_and_include_are_refused_with_file_and_line`. `cargo test -p podssh-cli`: 406 passed, 0
failed, 23 ignored. `cargo test --workspace --no-fail-fast`: 1164 passed, 0 failed, 38
ignored. In CI at `28eab6b` (run 38033483197): `scripts/interop.sh`, 222 passed, 0 failed, with
the new checks, where a `Host` alias of a `-F` file reaches OpenSSH and Dropbear and podssh's
`-G` for it holds OpenSSH's lines; the Linux job ran the test of the mode and of a link.

# T-044: `Include` in `ssh_config`, expanded as OpenSSH expands it

**Source:** `docs/cli.md`, lines 620-622 at `6192513` (measured with `ssh -G`); the `include/` module of lablup/bssh
named in GitHub #22 (`lablup/bssh:src/ssh/ssh_config/`, read in the report, not verified here);
ROADMAP M8. Measured again here with OpenSSH_10.3p1.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Many user files keep their hosts in other files (`Include config.d/*`), and the system files of
common distributions are believed to start with an `Include` line. T-043 refuses `Include` by
name, so such a file cannot be used, and the system file cannot be read at all.

## Premise

Read: `docs/cli.md`, lines 620-622 at `6192513`: `Include` is expanded where it appears, with globs in sorted
order, and a relative path starts from `~/.ssh` (user file) or `/etc/ssh` (system file).

Measured here with `ssh -G -F FILE x` (OpenSSH_10.3p1 of Git for Windows, no network,
2026-10-08):

- A file that includes itself: "Too many recursive configuration includes", exit 255.
- An `Include` glob that matches no file: no error; the lines after it apply.
- `Include DIR/*.conf` with `a.conf` (`Port 2401`) and `b.conf` (`Port 2400`): `port 2401`.
  The sorted order and the first value hold.
- An `Include` inside `Host x`, for the destination `x`: the included value applies.
- `Match all`, then `Host x`, each with a port: the `Match all` port wins (`port 2300`).
  `Match final all` gives a port that no other line set (`port 2299`), and keeps the `User`
  of `Host x`.

No glob code exists in podssh. `known_hosts::wildcard`
(`crates/podssh-ssh/src/known_hosts.rs:257-279`) matches `*` and `?`.

## Approach

1. In the reader of T-043, expand `Include` at its line: each argument, with `~` and the `%`
   tokens of OpenSSH, and a relative path from `~/.ssh` (user file) or `/etc/ssh` (system file;
   `%ProgramData%\ssh` on Windows).
2. Expand a glob in the last part of the path only: list the directory, match each name with
   `wildcard`, and sort the names by bytes. Refuse a wildcard in a directory part by name, with
   FILE:LINE; never skip it. A glob that matches nothing is no error, as measured.
3. An `Include` inside a `Host` block applies only when the block applies. Compare each case of
   nesting with `ssh -G` before the code is final, and keep each case as a fixture.
4. Stop a chain of includes at a fixed depth, and name the chain in the error.
5. Read the system file after the user file, as OpenSSH does (the Decision of T-043). Accept
   `Match all` and `Match final all`, which have no condition: `Match all` applies where it
   stands, and `Match final all` applies after the last line and fills only unset values, as
   measured. Each other `Match` stays refused by name until T-045.
6. Check each included file as T-043 checks the user file: its owner and its mode.
7. Change `docs/cli.md:661-734`, FILES (`crates/podssh-cli/src/man/data.rs:108-203`) and the
   `ssh` notes in the same commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_config -- include
sh scripts/dev.sh check   # interop: podssh ssh -G and OpenSSH's ssh -G on the include fixtures
```

The fixtures are the cases measured above, a relative `Include` from a user file and from a
system file, and a wildcard in a directory part (refused). The interop step compares the lines
of `podssh ssh -G` (T-046) with the same keyword lines of OpenSSH's `ssh -G` for each fixture.
Planted defect: sort the names of a glob in reverse; the sorted-order fixture gives
`port 2400`, and the test fails.

## Correction

Measured on 2026-10-10 with OpenSSH 10.3p1's `ssh -G` in the build image (Alpine), as a user
whose home is a scratch directory, where the Approach reads otherwise:

- A wildcard in a directory part works: `Include /tmp/inc/d*/a.conf` reads `d1/a.conf`, then
  `d2/a.conf`. podssh expands it too, rather than refuse it.
- `Include` takes `~` and each `%` token but `%T`, with the values of the moment: `%p` is the port
  of `-p` or of an earlier `Port` line, else 22; `%r` the user of `-l` or of an earlier `User`
  line, else the local user; `%h` an earlier `HostName` as written, else the host as typed; `%k`
  an earlier `HostKeyAlias` as written; `%j` the host of `-J`; none is lowercased.
- A relative path starts from `~/.ssh` for a file of `-F` too, and from `/etc/ssh` for the
  system file. Arguments are read in order, and the names of a glob are sorted.
- An included file is checked as `~/.ssh/config` is, also when a file of `-F` includes it: one
  that others can write, or that another user than the user or root owns, is refused with "Bad
  owner or permissions". A name that a glob matches and that is a directory is skipped. A
  missing file is no error; `Include` with no argument is one.
- A `Host` line in an included file holds to the end of that file; the line after the `Include`
  is in the block of the file that includes it again.
- The system files: Debian 13 starts `/etc/ssh/ssh_config` with `Include
  /etc/ssh/ssh_config.d/*.conf`, then `Host *` with `SendEnv`, `HashKnownHosts` and
  `GSSAPIAuthentication`; Fedora 42 has only the `Include`, and its `50-redhat.conf` holds `Match
  final all`, which includes `/etc/crypto-policies/back-ends/openssh.config`. That file sets
  `GSSAPIKexAlgorithms`, a keyword of the GSSAPI patch of the distributions that podssh did not
  know. Debian 13's OpenSSH 10.0p2 knows `GSSAPIClientIdentity`, `GSSAPIServerIdentity`,
  `GSSAPIKeyExchange`, `GSSAPIKexAlgorithms`, `GSSAPIRenewalForcesRekey` and `GSSAPITrustDns`, and
  Fedora's `ssh -G` prints the four that have a default; podssh accepts the six with no effect,
  as it has no GSSAPI.
- `crates/podssh-cli/tests/ssh_config.rs` holds the tests of `-G` (T-046); the tests of this
  entry go to a file of their own, `crates/podssh-cli/tests/ssh_config_include.rs`.

## Done

2026-10-10, in the commit that closes this entry. `Include` is read where it stands: its
arguments in order, each with `~` and the `%` tokens of the moment, a relative path from
`~/.ssh` or from the system's directory, and the names of a glob, also of one in a directory
part, sorted (`crates/podssh-cli/src/ssh/config/glob.rs`). Each file that it reads is checked as
`~/.ssh/config` is; a missing one is no error; a directory is skipped; a `Host` line in it holds
to its end; more than 16 nested includes are an error that names the chain. The system's file
is read after `~/.ssh/config`, and not with `-F`. `Match all` applies where it stands, and
`Match final all` in a second pass that fills only what is unset; each other `Match` is still
refused by name. The six keywords of the GSSAPI patch are accepted with no effect. FILES has the
system's file, and `docs/cli.md` says each rule. `crates/podssh-cli/src/ssh/resolve.rs`, over 500
lines with this entry, gives the reading of the hosts of a command line to
`crates/podssh-cli/src/ssh/hop.rs`.

Native, Windows 11: `cargo test -p podssh-cli --test ssh_config_include`, 9 passed (10 on Unix,
where the check of an included file that others can change runs), each case with the result of
OpenSSH 10.3p1, the system files of Fedora 42 and Debian 13 included. Planted, the names of a
glob sorted in reverse: the test of the order fails. clippy with `-D warnings`: no warning.
`cargo test --workspace --no-fail-fast`: {PASSED} passed, 0 failed, {IGNORED} ignored. In
`scripts/interop.sh`, podssh's `-G` for a file with an `Include` glob and `Match final all` is
compared with OpenSSH's; its first run is CI's, at the push of this commit.

# T-045: `Match` in `ssh_config`

**Source:** `docs/cli.md:714-717`; GitHub #22 (the `match_directive/` module of lablup/bssh,
and TeddyHuang-00/sshping issue #211 with PR #212, where a skipped `Match` changed the target;
read in the reports, not verified here).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

After T-043 and T-044, podssh refuses each `Match` block that has a condition. A user whose file
uses `Match host`, `Match user` or `Match tagged` cannot use the file with podssh. To skip the
block is worse: a skipped `Match` can change the host that podssh connects to.

## Premise

Read: `docs/cli.md:714-717`: `Match` never overrides a value that is set, and podssh must refuse
it by name, not skip it. `-P TAG` is accepted and ignored today
(`crates/podssh-cli/src/flags.rs:207-208`), so `Match tagged` would give the tag its meaning.
The login name comes from the environment, never from the user database
(`crates/podssh-cli/src/ssh/resolve.rs:89-110`); `Match localuser` needs it. podssh does no
canonical pass: `CanonicalizeHostname` is accepted and ignored
(`crates/podssh-cli/src/ssh/keywords.rs:67-82`). Measured with OpenSSH_10.3p1 (T-044):
`Match all` applies where it stands, and `Match final all` fills only unset values.

## Approach

1. Evaluate the criteria `all`, `host`, `originalhost`, `user`, `localuser`, `tagged`,
   `canonical` and `final`, each with `!` negation and with comma lists of patterns, through
   `known_hosts::wildcard` (`crates/podssh-ssh/src/known_hosts.rs:257-279`).
2. `originalhost` matches the name as typed. `host` matches the name after a `HostName` of an
   earlier block. Measure each order with `ssh -G`, and keep the case of sshping PR #212 (a
   `Match` that sets `HostName`) as a test.
3. `canonical` never matches, because podssh does no canonical pass. A `final` block applies
   after the last line and fills only unset values.
4. Keep `exec` and `localnetwork` refused by name (Decision). Refuse by name each other criterion
   of the installed ssh_config(5) that this entry does not evaluate.
5. A value from a `Match` block follows the first-value rule
   (`crates/podssh-cli/src/ssh/options.rs:293-297`).
6. `-G` (T-046) evaluates the same blocks and prints the result.
7. Change `docs/cli.md:714-717` and the `ssh` notes in the same commit.

## Decision

Recommendation: keep `Match exec` and `Match localnetwork` refused by name in this entry. `exec`
starts a program through a shell at each connection and at each `-G`. A host that podssh is made
for may have no `/bin/sh`, and a file written for a workstation would then run its program in a
sandbox. `localnetwork` needs the addresses of the local interfaces, a probe that a sandbox can
refuse. The alternative, `exec` through `$SHELL` after a probe, lost for now: the user names the
program, so `AGENTS.md` (section 5, rule 3) allows it, but nobody has asked for it. It can be a
later entry.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_config -- match
sh scripts/dev.sh check   # interop: each Match fixture against OpenSSH's ssh -G
```

One fixture for each criterion, with and without `!`, and the sshping case. The interop step
compares `podssh ssh -G` with `ssh -G` on each fixture. `Match exec` gives exit 78 with
FILE:LINE and runs nothing. Planted defect: match `host` against the name as typed; the sshping
case fails.

# T-046: `podssh ssh -G`: print the settings in effect (GitHub #14, #22)

**Source:** GitHub #14 (Nemo-010, 2026-10-08) and GitHub #22 (the dump module of lablup/bssh,
`lablup/bssh:src/ssh/ssh_config/dump.rs`, read in the report, not verified here); ROADMAP M8.
**Category:** feature
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A user cannot see which settings `podssh ssh` will use. A mistake in an `-o` value, and later in
a file (T-043), shows only as a failed connection. A script cannot compare the settings of
podssh with those of OpenSSH.

## Premise

Measured on `3ee70dc` (`PODSSH_OFFLINE=1`): `podssh ssh -G example.org` exits 64 with "-G is
refused. ... podssh reads no ssh_config, so it has no configuration to print."
(`crates/podssh-cli/src/flags.rs:229-230`). Measured with OpenSSH_10.3p1 on this machine:
`ssh -G -F none -p 2222 -l alice -o ServerAliveInterval=30 example.org` exits 0 and prints 84
lines of `keyword value`, the keyword in lower case: `port 2222`, `user alice`,
`pubkeyauthentication true`, `batchmode no`, `connecttimeout none`, `serveraliveinterval 30`,
`identityfile ~/.ssh/id_rsa` (with `~`), and others. Read: `resolve::resolve`
(`crates/podssh-cli/src/ssh/resolve.rs:118-432`) decides each setting before any connection; its
result, `Resolved` (lines 27-41 at `22c3b88`), holds the settings in effect, the defaults included.

## Approach

1. Make the `-G` row Supported, with no `instead`; `crates/podssh-cli/tests/flag_table.rs:60-80`
   requires that pair. The reviewed set of short flags does not change.
2. In `run_ssh` (`crates/podssh-cli/src/ssh/mod.rs:35-95`), after `resolve` (lines 36-42 at `e8bbd4d`): with
   `-G`, print the settings and exit 0. Open nothing: no relay, no token, no pool refresh.
3. Print from `Resolved` and its `Options`, not from `Settings`, so the defaults are shown.
4. Print only keywords of OpenSSH that podssh applies
   (`crates/podssh-cli/src/ssh/keywords.rs:25-62`), and `host`, `hostname`, `user`, `port`,
   `identityfile` and `proxyjump`. Spell each value as `ssh -G` does (`true` or `yes`).
5. Keep a list in the test of the values that differ on purpose, each with its reason:
   `serveraliveinterval 60` (the relay's idle cut, `docs/relay.md:125`) and `connecttimeout 60`.
6. It does not wait for T-043: with no file, `-G` shows the effect of `-o`. After T-043 and
   T-044, `-v` names the files that were read, on stderr.
7. Change the `ssh` notes (`crates/podssh-cli/src/man/notes.rs:32-114`) and `docs/cli.md:48-132`
   in the same commit.

## Decision

Recommendation: print no podssh setting (relay hosts, `--ca-file`) with `-G`. Then a diff with
`ssh -G` works line by line, and no printed line can go into a file that OpenSSH refuses.
`podssh status` (T-051) shows the relay settings. The alternative, podssh lines such as
`relayhost`, lost because OpenSSH knows no such keyword.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_config -- print_config
PODSSH_OFFLINE=1 target/debug/podssh ssh -G -F none -p 2222 -l alice example.org </dev/null
echo "exit=$?"
sh scripts/dev.sh check   # interop: podssh ssh -G against OpenSSH's ssh -G
```

The binary prints `port 2222` and `user alice`, nothing on stderr, and exits 0; nothing
connects. The interop step runs both programs with one fixture and the same arguments, and
requires equal lines for the keywords that podssh prints, except the listed ones. Planted
defect: print `ServerAliveInterval` from `Settings` (no default); a test fails.

## Correction

2026-10-10: a third value differs on purpose. OpenSSH 10.3p1 tries five default identity files,
two of them of security keys (`~/.ssh/id_ecdsa_sk`, `~/.ssh/id_ed25519_sk`), and podssh tries
three, as it has no security keys; the test's list has them with their reason. OpenSSH prints
yes and no of `StrictHostKeyChecking` and `RequestTTY` as `true` and `false`, and some settings
as they were given (`RemoteCommand`, `ProxyJump`, `PreferredAuthentications`) where `Options`
keeps what podssh made of them, so `Resolved` keeps those too.

## Done

2026-10-10. `podssh ssh -G` prints the settings in effect and exits 0 with nothing opened
(`crates/podssh-cli/src/ssh/dump.rs`; the `-G` row is Supported, with no `instead`). Each
keyword of OpenSSH that podssh applies, with the defaults, from `Resolved` and its `Options`,
and from what `-G` prints as it was given (`Shown`: the host as typed, the settings of
authentication, `PreferredAuthentications`, `RemoteCommand`, `-J`), in OpenSSH's order and
spelling: `true` and `false` where OpenSSH writes them, `DEBUG` for DEBUG1, `\^A` for a control
escape character, `~` for an identity file under HOME, the known_hosts files expanded. No podssh
setting is printed (the Decision).
- Native, Windows 11: `cargo test -p podssh-cli --test ssh_config`, 3 passed: with each
  setting given on the command line, the 32 lines that OpenSSH 10.3p1's `ssh -G -F none`
  printed for the same arguments, equal and in order; with the defaults, the same but for the
  listed ones (`serveraliveinterval 60`, `connecttimeout 60`, the two `_sk` identity files);
  the binary prints `port 2222` and `user alice`, nothing on stderr, exit 0, offline. Planted,
  the keepalive printed with no default: the second test fails. `cargo test --workspace`:
  1118 passed, 0 failed, 37 ignored.
- Linux, in the build image: clippy with no warning, the same tests, and against Alpine's
  `ssh -G` (`openssh-client-default`) each line of podssh's is OpenSSH's, for both arguments of
  the gate's check.
- The gate (`scripts/interop.sh`): the same comparison with the image's `ssh -G`; both of its
  checks passed in CI at `97c1336` (run 38017394329).

# T-047: Import host lists from other clients into `ssh_config`

**Source:** totoshko88/RustConn (GitHub #24: import from SSH config, Ansible inventory, PuTTY,
MobaXterm, mRemoteNG and Remmina), Petyok/SSHub (GitHub #22: Termius, PuTTY and mRemoteNG),
yituorou/meatshell (GitHub #22: FinalShell sessions), and rssh-org/rssh (GitHub #24: an import
of `~/.ssh/config` into its own store). Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A user who keeps hosts in another client must type each host again as an `ssh_config` block
before podssh can use it (after T-043). An agent that gets an Ansible inventory has the same
work.

## Premise

Read: podssh has no import and no `config` command (`crates/podssh-cli/src/flags.rs:396-429`).
`serde_json` is a dependency of the binary (`crates/podssh-cli/Cargo.toml:53`), so a JSON
export needs no new crate. XML and YAML need a parser that the binary does not have. The export
formats of the other clients were not read here. Each step below starts from a real export of
that client: bytes captured from the real program (`AGENTS.md`, section 6, rule 2).

## Approach

1. Add `podssh config import FORMAT FILE` (Decision). It writes `Host` blocks to stdout and a
   summary to stderr (`docs/architecture.md:127-128`). It never writes `~/.ssh/config`; the user
   adds the output.
2. First the formats that need no new crate: the Ansible INI inventory (`ansible_host`,
   `ansible_user`, `ansible_port`), Remmina `.remmina` files and MobaXterm sessions (INI), PuTTY
   sessions from a `.reg` export (text), and FinalShell JSON. Refuse mRemoteNG XML, Ansible YAML
   and Termius by name until a parser is decided.
3. Drop each password and passphrase field. Count them on stderr ("2 passwords were not
   imported"); never print one.
4. A source name with a space, `*`, `?` or `!` is not a valid `Host` pattern. Write a safe alias
   with the source name in a comment, or refuse the entry by name.
5. Write what has no `ssh_config` keyword (a proxy of the client, a protocol other than SSH) as
   a comment line. Never drop it silently.
6. The output must read with the reader of T-043 and with OpenSSH.
7. Add the verb to the tables: `VERBS`, and `VERB_OWNER` or a dispatch arm
   (`crates/podssh-cli/src/flags.rs:396-441`), the arguments, `usage_tail`
   (`crates/podssh-cli/src/help.rs:230-243`), the manual's notes and examples, and
   `DISPATCHED` (`crates/podssh-cli/tests/flag_table.rs:107-110`).

## Decision

Recommendation: a new verb, `podssh config`, with the subcommand `import`. The flags of
`podssh ssh` copy those of OpenSSH, so an `--import` flag there would be a flag that OpenSSH
does not have. A `config` verb can also hold later subcommands for T-048. The alternative, a
separate program, lost because podssh is one binary.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test config_import   # new: crates/podssh-cli/tests/config_import.rs
sh scripts/dev.sh check                         # interop: OpenSSH reads each output
```

The fixtures are real exports, one for each format, each with a password field. The tests check
the `Host` blocks, check that no password appears on stdout or stderr, and check that a bad name
is refused or made safe. In the gate, OpenSSH's `ssh -G -F OUTPUT ALIAS` exits 0 for each
output. Planted defect: copy the password field into a comment; the secret test fails.

# T-048: A podssh settings file for its own defaults, below flags and variables

**Source:** whme/csshw (a configuration file next to the binary, GitHub #24) and
AlpinDale/parsync (variables and a configuration file with a stated precedence, GitHub #21).
Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

podssh's own settings (the relay hosts, the `--relay-addr` pins, `--ca-file`, later the time
limits) come only from flags and variables. A user on a workstation repeats the flags in each
command, or edits a shell profile. No file states them once.

## Premise

Read: each command resolves the same settings in its own copy. Relay hosts (`--relay-host`,
then `PODSSH_RELAY`, then the default and the pool: `crates/podssh-relay/src/relay.rs:83-101`)
go through one function since T-231 (`crates/podssh-cli/src/relay_settings.rs:62-74`), called in
`crates/podssh-cli/src/ssh/resolve.rs:324`, `crates/podssh-cli/src/doctor/mod.rs:56-59` and
`crates/podssh-cli/src/proxy.rs:64-67`. Trust (`--ca-file`, then `SSL_CERT_FILE`) in
`crates/podssh-cli/src/ssh/resolve.rs:337-340`, `crates/podssh-cli/src/doctor/mod.rs:60-65` and
`crates/podssh-cli/src/proxy.rs:75-79`. The pins of the flag and of the variable add up
(`crates/podssh-cli/src/pins.rs:13-23`). The token cache uses the user's
cache directory first (`crates/podssh-relay/src/cache.rs:372-381`). The decision named the
configuration directory first; the operator corrected it on 2026-10-08 (`docs/decisions.md:48`, T-243).

## Approach

1. One module (new: crates/podssh-cli/src/settings.rs) resolves each setting once: flag, then
   variable, then file, then the built-in default. A list (the pins) adds up in that order. The
   three copies above call it.
2. The file has `Keyword value` lines, read by the reader of T-043 (Decision). Each keyword has
   a row in a table that the manual reads, as `crates/podssh-cli/src/ssh/keywords.rs` does for
   `-o`.
3. The places, in this order; the first that exists is used: `PODSSH_SETTINGS` (a new
   variable, apart from the `PODSSH_SSH_CONFIG` of T-043), `$XDG_CONFIG_HOME/podssh/settings`
   (else `~/.config/podssh/settings`, and `%APPDATA%\podssh\settings` on Windows), then
   `podssh.settings` next to the binary, found as `podssh-ca.pem` is
   (`crates/podssh-ws/src/bundle.rs:32-38`). Never the working directory or `/tmp`: a file that
   names relay hosts decides where tokens go.
4. Refuse a file that is a symbolic link, or that another user owns or can write, with an error
   that names it. Check the opened file, as `read_own` does with `Others::Read`
   (`crates/podssh-relay/src/cache/own.rs:22-62`, since T-163).
5. No keyword for a token: a token in a file is a stored credential (question Q5, T-034).
6. podssh never writes the file: csshw creates one, but podssh changes nothing unasked.
7. `doctor` and `status` (T-051) name the file in use. Change in the same commit: VARIABLES and
   FILES (`crates/podssh-cli/src/man/facts.rs:45-134`, 98-142), `docs/relay.md:30-56` and
   `docs/cli.md`. The cache directory is the work of T-243.

## Decision

Recommendation: `Keyword value` lines, read by the reader of T-043. One reader serves both
files, and the binary gets no new parser. TOML lost: the `toml` crate is a dependency of
`podssh-probe` only (`crates/podssh-probe/Cargo.toml:14-16`), which no command uses (T-060),
and TOML would give the user a second syntax.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test settings   # new: crates/podssh-cli/tests/settings.rs
PODSSH_SETTINGS=fixture.settings PODSSH_OFFLINE=1 target/debug/podssh status </dev/null
echo "exit=$?"
```

The tests: each setting from the file alone, the variable over the file, the flag over both,
pins that add up, a group-writable file refused on Unix, and no file read from the working
directory. With T-051 done, `status` shows the relay hosts of the fixture. Planted defect: read
the file before the variable; the precedence test fails.

# T-273: The `%` tokens of `User` and `RemoteCommand`, as OpenSSH expands them

**Source:** T-043 (2026-10-10), measured with `ssh -G` of OpenSSH 10.3p1.
**Category:** defect
**Milestone:** M8
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A `User` or a `RemoteCommand` with a `%` token means one thing to OpenSSH and another to podssh:
podssh sends the token as text, so a file made for OpenSSH logs in as another user, or runs
another command.

## Premise

Measured on 2026-10-10 with OpenSSH 10.3p1's `ssh -G`: `User x-%h-%p` in a file gives
`user x-a-22` for the host `a`; `-o User=y-%h` gives `user y-a`; `-l y-%h` stays `y-%h`; `%r`
in `User` is an unknown token; an unknown token ends the run with 255. `RemoteCommand echo %h
%r` gives `remotecommand echo a u`, and an unknown token in it ends the run with 255, also under
`-G`. Read: the user comes as it is given (`crates/podssh-cli/src/ssh/resolve.rs`, lines 151-156 at `84df12a`), the
request takes `RemoteCommand` as it is (`crates/podssh-cli/src/ssh/resolve.rs`, line 425 at `84df12a`), and `-G`
prints it as given (`crates/podssh-cli/src/ssh/dump.rs`, line 74 at `84df12a`).

## Approach

1. Expand the tokens of `Tokens` (`crates/podssh-cli/src/ssh/tokens.rs`) in `User` from `-o` and
   from a file, never from `-l` or `user@host`, with the set that OpenSSH gives `User` (not `%r`,
   the user itself; measure which others it refuses), and in `RemoteCommand` with the whole set.
2. `-G` prints the expanded `User` and `RemoteCommand`, as OpenSSH does.
3. An unknown token is refused with the keyword: 64 from `-o`, 78 from a file.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ssh_config_file
```

The tests hold OpenSSH 10.3p1's lines for a `User` and a `RemoteCommand` with tokens, from `-o`
and from a file. Planted: a `RemoteCommand` left as it is; a test fails.

## Correction

Measured on 2026-10-10 with OpenSSH 10.3p1's `ssh -G`, for each token: `User` takes `%h %p %n
%d %i %L %l %j %k %u` and `%%`, and refuses `%C`, `%r` and `%T`; `RemoteCommand` takes each of
them but `%T`. `%h` is the host after `HostName`, `%p` the port in effect, and `%r` in
`RemoteCommand` the user in effect, also one of `-l`, taken as it is. And `HostKeyAlias` is
lowercased: `-o HostKeyAlias=Alias.K` gives `hostkeyalias alias.k`, and `%k` is that. podssh
kept the alias as given, so it looked a host key up, and recorded it, under another name than
OpenSSH's; this entry lowercases it too.

## Done

2026-10-10, in the commit that closes this entry. A `User` of `-o` or of a file takes the tokens
but `%C` and `%r`; `-l` and `user@host` are taken as they are; `RemoteCommand` takes each token,
`%r` included, and `-G` prints it expanded, as OpenSSH does. A token that OpenSSH refuses is
refused by name. `HostKeyAlias` is lowercased. The table of keywords and `docs/cli.md` say so.

Native, Windows 11: `cargo test -p podssh-cli --test ssh_config_file`, 11 passed, the new test
against the lines that OpenSSH 10.3p1's `ssh -G -F FILE` printed for six command lines. Planted,
a `RemoteCommand` left as it is: the test fails. clippy with `-D warnings`: no warning. `cargo
test --workspace --no-fail-fast`: 1165 passed, 0 failed, 38 ignored.
