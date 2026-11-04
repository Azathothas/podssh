This file holds the work on configuration files: OpenSSH's `ssh_config` (`-F`, `Host`,
`Include`, `Match` and `-G`), host lists from other clients, and a settings file for podssh's
own options. The rules of OpenSSH that podssh follows were measured with `ssh -G` and are in
`docs/cli.md:5273-5385`. Since T-043, `podssh ssh` reads `~/.ssh/config` and the file of `-F`.

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
   (`crates/podssh-ssh/src/known_hosts.rs:311-333`); not `matches`, which accepts `|1|` hashes.
5. Refuse `Match`, and `Include` until T-044, by name with FILE:LINE (`docs/cli.md`, lines 596-598 at `c0cdd2b`).
   In a block that applies, refuse each option that `-o` refuses
   (`crates/podssh-cli/src/ssh/keywords.rs`, lines 84-89 at `c0cdd2b`), but accept a `ProxyCommand` that runs
   podssh itself (`proxy %h %p`: the path of `podssh ssh` anyway). Honour `IgnoreUnknown`.
6. Refuse a file that another user owns or can write, as OpenSSH does, on the opened file
   (`crates/podssh-relay/src/cache/own.rs:22-59`, `Others::Read`, since T-163). An unknown `%`
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
  token of a file name is refused: `crates/podssh-cli/src/ssh/tokens.rs:153` says "is not a
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
  user's or root's, with no write for the group or others. On Windows no file was checked, as for
  the files of the cache, until T-274, which reads the owner and the access list.
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
(`crates/podssh-ssh/src/known_hosts.rs:311-333`) matches `*` and `?`.

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
7. Change `docs/cli.md:5273-5394`, FILES (`crates/podssh-cli/src/man/data.rs:161-476`) and the
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

**Source:** `docs/cli.md`, lines 1197-1200 at `ec7f018`; GitHub #22 (the `match_directive/` module of lablup/bssh,
and TeddyHuang-00/sshping issue #211 with PR #212, where a skipped `Match` changed the target;
read in the reports, not verified here).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

After T-043 and T-044, podssh refuses each `Match` block that has a condition. A user whose file
uses `Match host`, `Match user` or `Match tagged` cannot use the file with podssh. To skip the
block is worse: a skipped `Match` can change the host that podssh connects to.

## Premise

Read: `docs/cli.md`, lines 1197-1200 at `ec7f018`: `Match` never overrides a value that is set, and podssh must refuse
it by name, not skip it. `-P TAG` is accepted and ignored today
(`crates/podssh-cli/src/flags.rs`, lines 220-221 at `ec7f018`), so `Match tagged` would give the tag its meaning.
The login name comes from the environment, never from the user database
(`crates/podssh-cli/src/ssh/resolve.rs:142-174`); `Match localuser` needs it. podssh does no
canonical pass: `CanonicalizeHostname` is accepted and ignored
(`crates/podssh-cli/src/ssh/keywords.rs:122-132`). Measured with OpenSSH_10.3p1 (T-044):
`Match all` applies where it stands, and `Match final all` fills only unset values.

## Approach

1. Evaluate the criteria `all`, `host`, `originalhost`, `user`, `localuser`, `tagged`,
   `canonical` and `final`, each with `!` negation and with comma lists of patterns, through
   `known_hosts::wildcard` (`crates/podssh-ssh/src/known_hosts.rs:311-333`).
2. `originalhost` matches the name as typed. `host` matches the name after a `HostName` of an
   earlier block. Measure each order with `ssh -G`, and keep the case of sshping PR #212 (a
   `Match` that sets `HostName`) as a test.
3. `canonical` never matches, because podssh does no canonical pass. A `final` block applies
   after the last line and fills only unset values.
4. Keep `exec` and `localnetwork` refused by name (Decision). Refuse by name each other criterion
   of the installed ssh_config(5) that this entry does not evaluate.
5. A value from a `Match` block follows the first-value rule
   (`crates/podssh-cli/src/ssh/options.rs:445-449`).
6. `-G` (T-046) evaluates the same blocks and prints the result.
7. Change `docs/cli.md`, lines 1197-1200 at `ec7f018`, and the `ssh` notes in the same commit.

## Decision

Recommendation: keep `Match exec` and `Match localnetwork` refused by name in this entry. `exec`
starts a program through a shell at each connection and at each `-G`. A host that podssh is made
for may have no `/bin/sh`, and a file written for a workstation would then run its program in a
sandbox. `localnetwork` needs the addresses of the local interfaces, a probe that a sandbox can
refuse. The alternative, `exec` through `$SHELL` after a probe, lost for now: the user names the
program, so `AGENTS.md` (section 5, rule 3) allows it, but nobody has asked for it. It can be a
later entry.

2026-10-11, the calls made in the work, each measured with OpenSSH 10.3p1's
`ssh -G`, offline, before podssh followed it:

- The final pass is OpenSSH's: a `Match` with `final` and no `!`, also on a
  line whose other criterion fails, asks for it; each file is then read
  again, `Host` lines and `Match host` see the host after `HostName`,
  lowercased, `final` and `canonical` hold, and the blocks fill what is
  still unset; a `HostName` in that pass is not taken. T-044 read only the
  blocks of `Match final all` again, which differed from OpenSSH for a
  `Host` block of the name that `HostName` gave and for `Match canonical`.
  podssh canonicalizes no name, so `canonical` holds in the final pass
  alone, as in OpenSSH with `CanonicalizeHostname no`.
- What a final pass reads again is kept as OpenSSH keeps it: an
  `IdentityFile` and a forward given twice once (a second listener on one
  port would fail), `SendEnv` added again, and the first `SetEnv` line whole.
  podssh merged `SetEnv` by name before, and so sent the variables of a
  later line that OpenSSH does not send; it no longer does.
- `Match version` matches `OpenSSH_10.3p1`, the release whose reading
  podssh follows. Refused, it would stop each file that has one; matching
  nothing, `!version` would hold.
- `exec` and `localnetwork` are refused where they would decide: on a line
  whose other criterion fails, the block is off whatever they would say, and
  the file is read. Nothing runs.
- `localuser` reads the user of the environment, as podssh never reads the
  user database; with none, the criterion is refused, not guessed.
- `-P TAG` and `Tag` set the tag of `Match tagged`, and `-G` prints `tag`.
  The note on stderr, which said that `-P` was ignored, now speaks only for
  a tag that is a number, as one is most likely a port.
- A hop of `-J` reads its blocks as OpenSSH's jump process does: its own
  `user@`, the local user, no tag, no command, and the session type none
  (`-W`).
- An `Include` in a block that does not apply is still not read (T-044);
  measured, OpenSSH does not take a `Match final` in such a file either.

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

## Done

2026-10-11. `Match` is read as OpenSSH 10.3p1 reads it: the criteria in
`crates/podssh-cli/src/ssh/config/matching.rs:1-168`; the passes at
`crates/podssh-cli/src/ssh/config.rs:94-106`, the lines at
`crates/podssh-cli/src/ssh/config.rs:211-232` and what a `Match` line sees
at `crates/podssh-cli/src/ssh/config.rs:237-273`; the command line's part
at `crates/podssh-cli/src/ssh/resolve.rs:193-204` and, for a hop of `-J`,
`crates/podssh-cli/src/ssh/jump.rs:183-189`. `Tag` at
`crates/podssh-cli/src/ssh/options.rs:237` and the `tag` line of `-G` at
`crates/podssh-cli/src/ssh/dump.rs:113-115`; a key file once at
`crates/podssh-cli/src/ssh/options.rs:135` and
`crates/podssh-cli/src/ssh/options.rs:394-399`, the first `SetEnv` whole at
`crates/podssh-cli/src/ssh/options.rs:202-214`, a forward once at
`crates/podssh-cli/src/ssh/local_spec.rs:73-81` and
`crates/podssh-cli/src/ssh/forward.rs:37-42`; the note of `-P` at
`crates/podssh-cli/src/refuse.rs:83-99`.
- `cargo test -p podssh-cli --test ssh_config_match`: 4 passed. 32 cases,
  each a file and the words of `ssh -G`, give the lines that OpenSSH 10.3p1
  printed for them: each criterion with and without `!`, lists, case,
  `criterion=patterns`, a comment, `HostName` before and after a `Match
  host`, the user of `-l`, `user@host`, a file and the local user, `-P`
  and `Tag`, the four session types and `RemoteCommand`, `version`, `all`
  after one criterion, and the final pass (its `Host` lines, its
  lowercased host, its `HostName` not taken, a `final` on a failing line,
  `canonical`, a key file, a forward, `SendEnv` and `SetEnv` read again).
  The lines that OpenSSH refused are refused with FILE:LINE (78); `Match
  exec` and `Match localnetwork` too, with no program run; and the sshping
  case: a `Match` that sets `HostName` changes what a later `Match host`
  sees.
- `cargo test -p podssh-cli -- ssh::config`: the criteria, one by one.
- Planted, the Prove's plant: `Match host` matched against the name as
  typed. The sshping case and the cases of OpenSSH failed; restored.
- The gate's harness `scripts/interop-match.sh` (`scripts/interop-match.sh:1-139`)
  runs 16 of these cases through the image's `ssh -G` and podssh's, and
  `Match exec` through podssh: 17 passed here against OpenSSH 10.3p1 of
  Git for Windows; in the gate at this push.
- `docs/cli.md`, the manual's notes of `-P` and FILES, and the notes of
  `podssh ssh --help`, which also said that `-L` and `-D` are refused,
  stale since T-038.
- `cargo test -p podssh-cli`: 590 passed, 0 failed, 31
  ignored; clippy; rustfmt.

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
(`crates/podssh-cli/src/flags.rs:268-269`). Measured with OpenSSH_10.3p1 on this machine:
`ssh -G -F none -p 2222 -l alice -o ServerAliveInterval=30 example.org` exits 0 and prints 84
lines of `keyword value`, the keyword in lower case: `port 2222`, `user alice`,
`pubkeyauthentication true`, `batchmode no`, `connecttimeout none`, `serveraliveinterval 30`,
`identityfile ~/.ssh/id_rsa` (with `~`), and others. Read: `resolve::resolve`
(`crates/podssh-cli/src/ssh/resolve.rs:130-500`) decides each setting before any connection; its
result, `Resolved` (lines 27-41 at `22c3b88`), holds the settings in effect, the defaults included.

## Approach

1. Make the `-G` row Supported, with no `instead`; `crates/podssh-cli/tests/flag_table.rs:60-80`
   requires that pair. The reviewed set of short flags does not change.
2. In `run_ssh` (`crates/podssh-cli/src/ssh/mod.rs:91-284`), after `resolve` (lines 36-42 at `e8bbd4d`): with
   `-G`, print the settings and exit 0. Open nothing: no relay, no token, no pool refresh.
3. Print from `Resolved` and its `Options`, not from `Settings`, so the defaults are shown.
4. Print only keywords of OpenSSH that podssh applies
   (`crates/podssh-cli/src/ssh/keywords.rs:25-97`), and `host`, `hostname`, `user`, `port`,
   `identityfile` and `proxyjump`. Spell each value as `ssh -G` does (`true` or `yes`).
5. Keep a list in the test of the values that differ on purpose, each with its reason:
   `serveraliveinterval 60` (the relay's idle cut, `docs/relay.md:426`) and `connecttimeout 60`.
6. It does not wait for T-043: with no file, `-G` shows the effect of `-o`. After T-043 and
   T-044, `-v` names the files that were read, on stderr.
7. Change the `ssh` notes (`crates/podssh-cli/src/man/notes_ssh.rs:4-491` and `crates/podssh-cli/src/man/notes_ssh_more.rs:4-138`) and `docs/cli.md:48-895`
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
**Status:** done

## Problem

A user who keeps hosts in another client must type each host again as an `ssh_config` block
before podssh can use it (after T-043). An agent that gets an Ansible inventory has the same
work.

## Premise

Read: podssh has no import and no `config` command (`crates/podssh-cli/src/flags.rs:372-436`).
`serde_json` is a dependency of the binary (`crates/podssh-cli/Cargo.toml:93`), so a JSON
export needs no new crate. XML and YAML need a parser that the binary does not have. The export
formats of the other clients were not read here. Each step below starts from a real export of
that client: bytes captured from the real program (`AGENTS.md`, section 6, rule 2).

## Approach

1. Add `podssh config import FORMAT FILE` (Decision). It writes `Host` blocks to stdout and a
   summary to stderr (`docs/architecture.md:295-296`). It never writes `~/.ssh/config`; the user
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
   (`crates/podssh-cli/src/flags.rs:374-450`), the arguments, `usage_tail`
   (`crates/podssh-cli/src/help.rs:248-273`), the manual's notes and examples, and
   `DISPATCHED` (`crates/podssh-cli/tests/flag_table.rs:110-143`).

## Decision

Recommendation: a new verb, `podssh config`, with the subcommand `import`. The flags of
`podssh ssh` copy those of OpenSSH, so an `--import` flag there would be a flag that OpenSSH
does not have. A `config` verb can also hold later subcommands for T-048. The alternative, a
separate program, lost because podssh is one binary.

2026-10-12, the calls made in the work:

- The Ansible INI inventory alone is read here: it is the one format whose
  bytes could be made and read by its own program on the machines of this
  work (ansible-core 2.21.0 in the build image). PuTTY, MobaXterm, Remmina,
  FinalShell, mRemoteNG and Termius need a real export of each, which only
  the operator can give: they, and Ansible's YAML, are refused by name, and
  are T-292, blocked on Q41.
- What a host gets is what Ansible's own ssh used: the fixture inventory
  went through `ansible-inventory --list` and `ansible all -m ping -vvv`,
  and the test compares each block with the command line of ssh that
  Ansible ran for that host. Measured there: a child group beats its
  parent, a `[G:vars]` value loses its quotes, and of a variable and its
  `ansible_ssh_` name the latter wins (`ansible_ssh_port` and
  `ansible_ssh_user` over `ansible_port` and `ansible_user`).
- `ansible_ssh_common_args` goes to ssh's command line, measured: its `-o`
  options, and `-J`, become lines of the block, after Ansible's own
  settings, as on that command line, where the first value wins. A keyword
  that runs a command (`ProxyCommand` and the like), and each other flag,
  are named in a comment with no value, as a command can hold a secret.
- A secret is any variable whose name holds `pass`; it is counted for each
  host, as Ansible's listing gives it to each host (21 in the fixture).
- A host name that a `Host` line cannot hold is refused by name, with no
  alias made up: an alias would be a name that the user did not choose.
- `ansible_group_priority` is not read; groups of one depth go by name, as
  Ansible orders them with no priority set.

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

## Done

2026-10-12. `podssh config import ansible FILE`: the verb at
`crates/podssh-cli/src/config_import/mod.rs:46-169`, the inventory at
`crates/podssh-cli/src/config_import/ansible.rs:1-270`, the blocks at
`crates/podssh-cli/src/config_import/mod.rs:281-325`, with the secrets at
`crates/podssh-cli/src/config_import/mod.rs:171-175` and the options of
`ansible_ssh_common_args` at
`crates/podssh-cli/src/config_import/mod.rs:177-230`; the verb in the
tables at `crates/podssh-cli/src/flags.rs:428-429`,
`crates/podssh-cli/src/positionals.rs:228-233`,
`crates/podssh-cli/src/tree.rs:323-329` and
`crates/podssh-cli/src/dispatch.rs:167-168`.
- `cargo test -p podssh-cli --test config_import`: 5 passed. The fixture
  `crates/podssh-cli/tests/fixtures/ansible/inventory.ini`, read by
  ansible-core 2.21.0 in the build image (`inventory.list.json` and
  `ssh-exec.txt` beside it, as captured): each of the 15 hosts that
  Ansible's ssh reached gets the `Port`, `User`, `IdentityFile` and
  `ProxyJump` of its command line, and its address; no password is printed,
  and the summary counts the 21 that Ansible's listing holds; the groups
  are in each comment, and the host of `ansible_connection=winrm` gets a
  comment and no block; podssh's own `-G` reads what it printed; stdin, a
  bad line (65), a missing file (66), a name that a `Host` line cannot
  hold, and the formats refused by name (64).
- `cargo test -p podssh-cli -- config_import`: 5 passed: ranges, ports,
  the words of a line, the order of the groups, a bad line.
- Planted, the Prove's plant: each password copied into a comment; the
  test of the secrets failed; restored.
- In the gate, `match.config_import` (`scripts/interop-match.sh:140-152`):
  OpenSSH's `ssh -G` reads each block that podssh made of the fixture; it
  passed here against OpenSSH 10.3p1 of Git for Windows.
- `docs/cli.md`, the manual's notes and an example; the verb is in the
  group Settings, as T-048 will be.
- `cargo test -p podssh-cli`: 600 passed, 0 failed, 31
  ignored; clippy; rustfmt.

# T-048: A podssh settings file for its own defaults, below flags and variables

**Source:** whme/csshw (a configuration file next to the binary, GitHub #24) and
AlpinDale/parsync (variables and a configuration file with a stated precedence, GitHub #21).
Read in the reports, not verified here.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

podssh's own settings (the relay hosts, the `--relay-addr` pins, `--ca-file`, later the time
limits) come only from flags and variables. A user on a workstation repeats the flags in each
command, or edits a shell profile. No file states them once.

## Premise

Read: each command resolves the same settings in its own copy. Relay hosts (`--relay-host`,
then `PODSSH_RELAY`, then the default and the pool: `crates/podssh-relay/src/relay.rs:107-125`)
go through one function since T-231 (`crates/podssh-cli/src/relay_settings.rs:65-90`), called in
`crates/podssh-cli/src/ssh/resolve.rs`, line 314 at `99743e6`, `crates/podssh-cli/src/doctor/mod.rs:134-137` and
`crates/podssh-cli/src/proxy.rs:219-222`. Trust (`--ca-file`, then `SSL_CERT_FILE`) in
`crates/podssh-cli/src/ssh/resolve.rs`, lines 328-331 at `99743e6`, `crates/podssh-cli/src/doctor/mod.rs:165-180` and
`crates/podssh-cli/src/proxy.rs`, lines 100-104 at `99743e6`. The pins of the flag and of the variable add up
(`crates/podssh-cli/src/pins.rs:15-34`). The token cache uses the user's
cache directory first, after the directory of `PODSSH_CACHE_DIR` (T-243;
`crates/podssh-relay/src/cache/dirs.rs:145-241`). The decision named the
configuration directory first; the operator corrected it on 2026-10-08 (`docs/decisions.md:95`, T-243).

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
   (`crates/podssh-relay/src/cache/own.rs:22-59`, since T-163).
5. No keyword for a token: a token in a file is a stored credential (question Q5, T-034).
6. podssh never writes the file: csshw creates one, but podssh changes nothing unasked.
7. `doctor` and `status` (T-051) name the file in use. Change in the same commit: VARIABLES and
   FILES (`crates/podssh-cli/src/man/facts.rs:46-300`, 98-142), `docs/relay.md:102-213` and
   `docs/cli.md`. The cache directory is the work of T-243.

## Decision

Recommendation: `Keyword value` lines, read by the reader of T-043. One reader serves both
files, and the binary gets no new parser. TOML lost: the `toml` crate is a dependency of
`podssh-probe` only (`crates/podssh-probe/Cargo.toml:14-16`), which no command uses (T-060),
and TOML would give the user a second syntax.

2026-10-12, the calls made in the work:

- The keywords: `RelayHost`, `RelayAddr` (whose lines add up),
  `RelayFailover` and `CaFile` (`~` is the home). `RelayFailover` came with
  T-220, after this entry was written, and is a relay setting with a flag
  and a variable as the others. The time limits stay for later: none of
  them is a relay setting of this kind.
- Each value is checked as the file is read, as its flag is, and the file
  is refused as a whole (78, with FILE:LINE) by `pins::apply`, which starts
  each command that reaches the relay: a bad file is refused alike by each.
  An unknown keyword is refused, not ignored: the file is podssh's own, and
  a word that does nothing would be a setting that the user thinks holds.
- The owner: the user or root, and no one else may change it, as for
  `~/.ssh/config`; the cache's rule (the user alone) would refuse the file
  beside a binary that root installed. A symbolic link is refused, as step 4
  says: `PODSSH_SETTINGS` names the file itself.
- `PODSSH_SETTINGS` must be an absolute path that exists, and `none` reads
  none: a relative path would be read from the working directory.
- `podssh status` gives the path as `settings` (null with none) and
  `relays_from: "the settings file"`; its schema stays 1, as a field was
  added and none changed. `podssh doctor` names the file under "this
  host", and the source of its trust when `CaFile` gives it.
- The resolution of `podssh ssh` takes the settings through its `Env`, so
  that its tests read no file of the machine that runs them.

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

## Done

2026-10-12. The settings file in `crates/podssh-cli/src/settings.rs:1-330`:
its places at `crates/podssh-cli/src/settings.rs:129-152`, its checks at
`crates/podssh-cli/src/settings.rs:175-199`, its lines at
`crates/podssh-cli/src/settings.rs:201-314`; the relay hosts and the
failover below the flag and the variable at
`crates/podssh-cli/src/relay_settings.rs:71-86` and
`crates/podssh-cli/src/relay_settings.rs:127-137`, the pins and the refusal
of a bad file at `crates/podssh-cli/src/pins.rs:13-34`, the CA file at
`crates/podssh-cli/src/settings.rs:316-326` and, for `podssh ssh`,
`crates/podssh-cli/src/ssh/resolve.rs:158-162`; `status` at
`crates/podssh-cli/src/status.rs:65` and
`crates/podssh-cli/src/status.rs:80`, `doctor` at
`crates/podssh-cli/src/doctor/mod.rs:178` and
`crates/podssh-cli/src/doctor/mod.rs:198`.
- `cargo test -p podssh-cli --test settings`: 4 passed here, and 5 in the
  build image (`sh scripts/dev.sh run`), with the test of Unix: `status`
  takes the file's relay hosts, `PODSSH_RELAY` beats it and
  `--relay-host` both, `none` reads none, and the usual place
  (`$XDG_CONFIG_HOME`, `%APPDATA%`) is found; an unknown keyword, a bad pin,
  a bad host, a bad mode and a relative `PODSSH_SETTINGS` are refused with
  78 and the line; `doctor` names the file; the resolution of `podssh ssh`
  takes the file's relay hosts and CA file below its variables and flags;
  on Unix, a file that others can change and a symbolic link are refused.
- `cargo test -p podssh-cli -- settings`: 6 passed: the lines, the first
  value, the pins that add up, an unknown keyword, the order of flag,
  variable and file, the places, and no working directory.
- Planted, the Prove's plant: the file read before the variable; the tests
  of the order failed, here and through `status`; restored.
- The manual's ENVIRONMENT (`PODSSH_SETTINGS`), FILES and THE RELAY,
  `docs/cli.md` ("podssh's settings file", and the line of `status`) and
  `docs/relay.md`.
- `cargo test -p podssh-cli`: 609 passed, 0 failed, 31
  ignored; clippy; rustfmt.

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

# T-290: A `-J` hop takes the `ssh_config` block of its own name, as OpenSSH's jump host does

**Source:** the work of T-030 (2026-10-11): OpenSSH's jump process, measured with `ssh -v`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A hop of `-J` or `ProxyJump` is a host as typed: podssh reads no block of `ssh_config` for it.
With a block `Host bastion` that sets `HostName`, `Port`, `User` and `IdentityFile`, `podssh ssh -J
bastion host` connects to a host named `bastion` on port 22, where OpenSSH connects to the
bastion's `HostName` and port, as its user, with its key. The common `ProxyJump bastion` of a file
that OpenSSH reads fails in podssh. The destination's blocks hold for each hop instead: its
`IdentityFile` is offered to the bastion. And a hop that names no user logs in as the destination's
user, where OpenSSH's jump host logs in as its own `User`, else as the local user.

## Premise

Measured with OpenSSH 10.3p1 (2026-10-11, `ssh -v -F FILE -o ... -J
ju@jump.invalid:2222,second.invalid dest.invalid`): the jump host runs as `ssh -l ju -p 2222 -F
FILE -v -W '[%h]:%p' jump.invalid`, and the hop after it as `ssh -J ju@jump.invalid:2222 -F FILE -v
-W '[%h]:%p' second.invalid`. Each is a process of its own, which reads the file for its own
host; no `-o` of the command line reaches it, and no `-l` of the destination. ssh(1) says the
same of `-J`: the command line is for the destination, and `ssh_config` gives a jump host its
settings (read in the manual).

Read: the hops come from `-J` or `ProxyJump` as text
(`crates/podssh-cli/src/ssh/resolve.rs`, lines 201-205 at `b0177cf`), parsed by `jump_hop` alone
(`crates/podssh-cli/src/ssh/hop.rs:69-74`). Each hop logs in as its own user or the destination's
(`crates/podssh-ssh/src/run.rs:370`), with the identities of the destination
(`crates/podssh-ssh/src/run.rs:427`).

## Approach

1. Read the file's blocks for each hop's own name, as for the destination (`config::read` with
   the hop's host in the `Context`, `crates/podssh-cli/src/ssh/config.rs:59-79`): `HostName`,
   `Port` and `User` of the block, under the `user@` and `:PORT` of the hop's text, as for the
   destination (T-043). A hop with no user and no `User` of its own logs in as the local user, as
   OpenSSH's jump host does: `-l`, `-p` and the destination's `User` are the destination's alone.
2. The settings of host keys, authentication, keys and time of the command line (`-o`, `-i`)
   still hold for each hop, as today (T-030, podssh's difference from OpenSSH): a script's
   `-o StrictHostKeyChecking=accept-new -i KEY` keeps working through a jump. The hop's own
   blocks fill what the command line leaves unset, in place of the destination's: its
   `IdentityFile` after those of `-i`, its `UserKnownHostsFile`, its `StrictHostKeyChecking`.
   Each hop then carries its own options to `run::connect`.
3. A `ProxyJump` in a hop's block puts its chain before the hop, as OpenSSH's jump process does;
   a loop is refused with 64, as OpenSSH refuses a jump host loop.
4. `-G` prints the destination's settings alone, as OpenSSH's `ssh -G` does. `docs/cli.md` and
   the manual's notes say what a hop takes.

## Decision

Taken, with these calls made in the work (2026-10-11). The `ProxyJump` of a hop's block is read
for the first hop of a list alone: in the measure of the Premise, OpenSSH gave the later hop the
hops before it as its `-J`, which beats its file, and the first hop no `-J`. `-i` holds for each
hop, as `-o` does: a script's `-i KEY -J HOST` keeps working. `-C` and `Compression` of the
command line are the destination's; a hop takes its own block's. A chain of more than 16 hops is
refused, besides a loop.

## Prove

```sh
cargo test -p podssh-cli --test ssh_config_file -- jump
sh scripts/dev.sh check
```

A file with `Host bastion` (`HostName`, `Port`, `User`, `IdentityFile`) and `-J bastion`: the plan
of the run holds the bastion's address, port, user and key; a hop with no user, the local user. In
`scripts/interop.sh`, `-F FILE -J openssh-alias dropbear-alias` (the aliases of T-043) runs the
command, beside OpenSSH's `ssh` with the same line. Plant: read no block for a hop; the test and
the check fail.

## Done

2026-10-11. Each hop reads its own blocks in `crates/podssh-cli/src/ssh/jump.rs:1-273`, and its
login, made as the destination's, in `crates/podssh-cli/src/ssh/login.rs:1-96`. The options of
each hop are `Options::jump_options` (`crates/podssh-ssh/src/options.rs:220-224`), which
`connect_hops` gives each hop with the run's memory of its logins
(`crates/podssh-ssh/src/run.rs:148-176`, `crates/podssh-ssh/src/run.rs:310-321`); `BatchMode` of a
try after the first reaches each hop (`crates/podssh-ssh/src/options.rs:350-358`).
- `cargo test -p podssh-cli --test ssh_config_file -- jump`: 2 passed. `-J bastion` takes the
  bastion's `HostName`, `Port`, `User`, `IdentityFile` and `HostKeyAlias` and the command line's
  `StrictHostKeyChecking`, and neither the destination's key nor its alias; a hop with no user
  logs in as the local user, never as `-l`; `user@` and `:PORT` beat its blocks. The first hop's
  `ProxyJump` makes a chain, a later hop's is not read, and a loop is refused with 64. Planted, a
  hop that reads no block (the Prove's plant): both tests failed; restored.
- `cargo test -p podssh-ssh --lib -- run::`: 3 passed, among them a hop's own options with the
  run's memory, else the connection's, its own `HostKeyAlias`, and `set_batch_mode` for each hop.
- `scripts/interop.sh:327-337`: `ssh.config.jump_alias`, `-F FILE -J openssh-alias dropbear-alias`
  with podssh and with OpenSSH's `ssh`, each to exit 6 (the floor of ssh is 72). The gate runs it
  at this push.
- `docs/cli.md:140-146` and `docs/cli.md:5318-5330`, and the manual's file `~/.ssh/config`, say what
  a hop takes.
- `cargo test -p podssh-ssh`: 142 passed; `cargo test -p podssh-cli`: 565 passed, 0 failed,
  31 ignored; clippy; rustfmt.

# T-292: `podssh config import` from PuTTY, MobaXterm, Remmina, FinalShell, mRemoteNG and Termius

**Source:** the work of T-047 (2026-10-12): its step 2 asks for each format
from a real export of its program; GitHub #22 and #24, the reports that
T-047 names (read in the reports, not verified here).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

`podssh config import` reads an Ansible INI inventory alone (T-047). A user
who keeps hosts in PuTTY, MobaXterm, Remmina, FinalShell, mRemoteNG or
Termius types each host again.

## Premise

Read: `podssh config import putty FILE` and the others, and Ansible's YAML,
are refused by name with exit 64 (`crates/podssh-cli/src/config_import/mod.rs`).
`AGENTS.md`, section 6, rule 2, and T-047's premise: each format is read
from a real export of its program. None of these programs is on the
machines of this work, and a session downloads no program to make one.

## Approach

1. Each format as T-047 reads the inventory: the same writer, the same
   counting of secrets, and a comment for what has no keyword.
2. mRemoteNG's XML and Ansible's YAML need a parser: decide the crate, or
   keep them refused (Decision).
3. Each export a fixture under `crates/podssh-cli/tests/fixtures/`, kept
   byte for byte.

## Decision

The operator ruled on Q41 on 2026-10-30 (`docs/decisions.md`): each format is
tested on export files that the program itself wrote and that are published,
each cited with its URL and license, and kept byte for byte as a fixture. A
format with no such file stays out, named as waiting, until one exists. The
Blocker that asked for the operator's own exports is gone: it lost to files
that anyone can check.

2026-10-30, a call of the research (the operator may change it): the XML
parser is `roxmltree` 0.21 with `default-features = false`, in
`podssh-cli` (a crates.io reading of that day: pure Rust, no C, a
read-only DOM, MSRV 1.60, 95 M downloads, last release 2026-10-24, one
dependency, `memchr`, which `Cargo.lock` holds already). The mRemoteNG
file nests containers and inherits the user down the tree, which a DOM
reads in a few lines. `quick-xml` lost: its 0.42 needs Rust 1.86 (0.41
needs 1.79), `Cargo.lock` holds it only for the features `ts` and `iroh`,
and a pull parser needs more code for a tree. A hand-written XML reader
lost: its edge cases (entities, CDATA, namespaces such as `mrng:`) are
the parser's work. INI (Remmina, MobaXterm) and the `.reg` files of PuTTY
are read by hand with the standard library, as the Ansible INI reader is.
No format of this entry needs YAML: the entry keeps Ansible's YAML refused
by name. (If it is wanted later: `saphyr` or `yaml-rust2`, both pure Rust;
`serde_yaml` is archived and `serde_yml` has RUSTSEC-2025-0068, and both
bring unsafe transpiled C.)

2026-10-30, a second call: a fixture is a real file whose license allows it
in this repository (`LICENSE` is 0BSD). Files under the GPL, and files with
no license, are not committed until the operator rules that GPL test data
may sit here with a notice of its license (an open point of the
Correction). The cases that only such files show (a `REGEDIT4` header, a
jump through `ProxyMethod=5`, a gateway of MobaXterm, nested folders) are
inputs that the test builds by hand from the documented format, named as
built, never as exports.

2026-10-30, the calls of the work (the operator may change them):

- A session's label becomes the name of its block, each run of characters
  that a `Host` line cannot hold made one `-` (`John Doe` is `John-Doe`), a
  second of the same name `-2`, and the label itself goes in a comment
  above it. Lost: refusing such a label, as the Ansible reader refuses a
  host name, which would drop most of PuTTY's sessions.
- `user@host` in PuTTY's `HostName` gives `User` and `HostName`, as PuTTY
  itself reads the box; it wins over `UserName`, as in PuTTY.
- A `.ppk` key is a comment that says how `puttygen` converts it, never an
  `IdentityFile`, which ssh would fail to read at each login. A key path of
  MobaXterm, in its own macros, is a comment too.
- PuTTY's `Environment` is a comment with the count of its variables: a
  variable can hold a secret (a real fixture holds `AWS_SECRET_KEY` there).
- MobaXterm's text is UTF-8 when it is valid UTF-8, else Windows-1252.
- mRemoteNG, FinalShell and Termius move to T-327, which waits: no file of
  theirs is under a license that this repository can hold (Correction).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test config_import
```

For each format, the blocks of its fixture, and no password on stdout or
stderr. Planted defect: copy a password field into a comment; the test of
the secret fails.

## Correction

2026-10-30, the research of that day. Read means: seen in the source at the
URL or the commit named; Inferred means: concluded from what was read. The
Premise holds. What follows is what the Approach needs and the Premise did
not have. The samples lay in `.work/` of one machine; this entry keeps their
addresses and digests, so that a session can fetch them again.

**The formats.**

- PuTTY. Sessions are in the registry (`HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions`);
  the program has no file export, and its manual points to `regedit`
  (Read: https://the.earth.li/~sgtatham/putty/latest/htmldoc/Chapter4.html,
  sections 4.1.2 and 4.33). On Unix, one file for each session, in `sessions/` of
  `PUTTYDIR`, else `$XDG_CONFIG_HOME/putty` or `~/.config/putty` when it exists, else
  `~/.putty`; a line is `key=value` with no quotes, the file name is `%XX` decoded, and
  the first line is `Present=1` (Read in `unix/storage.c` of a fork at tag putty-0.83,
  codefloe.com/dwn/putty-nt35; upstream answered 403, so "the same as upstream" is Inferred).
  Keys: `HostName` (three real files hold `user@host` there), `PortNumber` (`dword:` hex in a
  `.reg`, decimal in a Unix file), `UserName` (may be empty), `Protocol` (`ssh`, `telnet`, `raw`,
  `rlogin`, `serial`: only `ssh` makes a block, the rest a comment), `PublicKeyFile` (a `.ppk`,
  which OpenSSH cannot read), `ProxyMethod`, `ProxyHost`, `ProxyPort`, `ProxyUsername`,
  `ProxyPassword`, `ProxyTelnetCommand`. The order of `ProxyMethod` is none, SOCKS4, SOCKS5, HTTP,
  Telnet, Local, SSH port-forward, SSH exec, SSH subsystem (Read in `putty.h`; that the stored
  number has the same order is Inferred, a real file with 5 and a `plink -load X -nc %host:%port`
  command agrees: 5 is Local). A jump is method 6 ("SSH to proxy and use port forwarding", Read in
  the manual, section 4.16.1); no real file with 6 was found; the pattern in the wild is method 5
  with `plink -load OTHER -nc %host:%port`. There is no folder: the session name is the label.
- MobaXterm. The vendor documents the menu only ("Export sessions from this folder"); the
  format is not documented. The best description is a community study of version 26.3
  (Read: https://gist.github.com/Ruzgfpegk/ab597838e4abbe8de30d7224afd062ea); the samples agree
  with it field by field. INI: `[Bookmarks]`, then `[Bookmarks_N]` with `SubRep=Folder\Sub`
  (the folder path); a session is `Name=` followed by ` #ICON#TYPE%f1%f2...#font...#flags#comment#tabcolor`.
  Separators are `#` (outer) and `%` (inner). SSH is type 0 (icon 109): field 1 host, 2 port,
  3 user (`<default>` or empty: none), 7 login command, 8 to 10 gateway hosts, ports and users
  (several joined by `__PIPE__`), 14 private key path, 15 gateway keys, 19 proxy type (0 none, 6
  SSH forward, 7 SSH command), 20 to 22 proxy host, port and login, 26 proxy command. Other types
  (RDP 4, VNC 5, SFTP 7, serial 8) have other field orders: dispatch on the type first. Escapes:
  `__PIPE__`, `__PTVIRG__` (`;`), `__DBLQUO__`, `__DIEZE__` (`#`), `__PERCENT__`; path macros
  `_CurrentDrive_`, `_ProfileDir_`, `_MyDocuments_`. A gateway line is confirmed by a real file
  of `gplv2/mobaxterm2ssh` (`data/moba.ini`, MIT), which carries a company's internal addresses
  and was not kept. The gist says Windows-1252 and CRLF; the four files that were read are ASCII,
  so the code page is Inferred: decode bytes 0x80 to 0x9F through a 32-entry table and the rest as
  Latin-1.
- Remmina. INI with one `[remmina]` section (Read: the wiki
  https://gitlab.com/Remmina/Remmina/-/wikis/Remmina-Config-File-Options and `FreeRDP/Remmina` at
  `bb33690d`: `src/remmina_ssh_plugin.c`, `src/remmina_file.c`, `src/remmina_ssh.c`). Files:
  `~/.local/share/remmina/*.remmina` (older `~/.remmina`), named `group_ssh_<name>_<host>.remmina`.
  Keys: `protocol=SSH` (RDP, VNC, SFTP and the rest: a comment), `server=host[:port]` (`[v6]:port`
  is accepted, the default port is 22), `username`, `name` (the label), `group` (the folder; a
  nested separator is not verified), `ssh_auth` (0 password, 1 identity file, 2 agent, 3 public key
  automatic, 4 GSSAPI, 5 keyboard-interactive), `ssh_privatekey`, `ssh_certfile`,
  `ssh_proxycommand` (a command: a comment), `ssh_stricthostkeycheck`, `ssh_compression`,
  `ssh_forward_x11`, `ssh_ciphers`, `ssh_kex_algorithms`, `ssh_hostkeytypes`. `ssh_tunnel_*` is
  the tunnel of a non-SSH profile and the nearest thing to a jump host (Inferred); it is empty in
  every sample with `protocol=SSH`. A profile that once was RDP keeps its RDP keys. A template can
  hold `%Host%`.
- mRemoteNG. GPL-2.0 source, `mRemoteNG/mRemoteNG` at `25ef453a` (2026-10-28): the schemas
  `mRemoteNG/Schemas/mremoteng_confcons_v2_5.xsd` to `v2_8.xsd`, the reader
  `XmlConnectionsDeserializer.cs` (`MaxSupportedConfVersion = 2.9`), the writers
  `XmlConnectionNodeSerializer26.cs` to `28.cs`, `XmlConnectionsDecryptor.cs`,
  `AeadCryptographyProvider.cs`, `RootNodeInfo.cs` (all Read). The root is
  `<Connections Name Export EncryptionEngine BlockCipherMode KdfIterations FullFileEncryption Protected ConfVersion>`;
  version 1.77 writes it as `mrng:Connections xmlns:mrng="http://mremoteng.org"` with lowercase
  booleans, older test files write `Connections` and `True` and `False`. `Node Type="Container"` is
  a folder and holds `Node Type="Connection"`. Attributes of a connection: `Name`, `Id`, `Hostname`,
  `Port`, `Username`, `Domain`, `Password`, `Protocol` (by name: `SSH1`, `SSH2`, `Telnet`, `RAW`,
  `Rlogin`, `RDP`, `VNC`, `HTTP(S)`, `PowerShell`, `WSL`, `IntApp`), `PuttySession` (the name of a
  PuTTY session), `SSHTunnelConnectionName` (another connection by name: the jump host),
  `SSHOptions` (extra ssh arguments, schema 2.7 and later), `Descr`, `UserField`. Inheritance:
  `InheritUsername="True"` and its kind mean that the value is the container's, so the effective
  user is resolved up the tree.
- FinalShell. No vendor documentation. One JSON file for each host, `conn/<id>_connect_config.json`
  (macOS `~/Library/FinalShell/conn`; Windows `%LOCALAPPDATA%\finalshell\conn` or the install
  directory). Read in the decoders `XLevon/FinalshellDecoderX` (`src/core.py`) and
  `jesse0830/jiayang` (a skill file; FinalShell 4.6.5), and in the importers of meatshell,
  Miaominal and DengShell, which agree: `host`, `port`, `user_name`, `name`, `id`, `parent_id`
  (`root` or a folder id), `conection_type` (the typo is real; 100 SSH, 101 RDP),
  `authentication_type` (1 password), `password`, `secret_key_id`, `proxy_id` (`"0"` none),
  `port_forwarding_list`, `delete_time` (non-zero: in the trash). The folder file format is not
  verified.
- Termius. There is no export. The vendor documents import only
  (https://docs.termius.com/getting-started/import-existing-hosts; the index
  https://docs.termius.com/llms.txt has no export page). `termius export-ssh-config` of the old
  CLI is reported empty and incompatible with the current app (`termius/termius-cli` issues 173,
  183, 188 and 198). The tools on GitHub that call themselves exporters decrypt the local database
  and write passwords and keys in clear: not an export of the program.

**Passwords: count them, never import them.** PuTTY never stores a login password; the one secret
is `ProxyPassword`, in plain text (Read: manual, section 4.16.4), and the command of a Local proxy
may hold `%pass` (4.16.5): a comment with no value, as T-047 does for `ProxyCommand`. MobaXterm keeps
passwords outside the session string, in `[Passwords]` (`ssh22:user@host=blob`) and `[Sesspass]`
of `MobaXterm.ini`, under the master password; an `.mxtsessions` export holds `[Bookmarks*]`
only, so the count there is 0 unless a hand-made file adds the sections; the SFTP proxy password is
plain text (the gist). Remmina: `password`, `ssh_passphrase`, `ssh_tunnel_password` and
`ssh_tunnel_passphrase` hold `.` (the keyring) or a base64 blob that `remmina_crypt` encrypts under a
secret of `remmina.pref` (Read: `src/remmina_file.c`); count the two kinds apart. mRemoteNG:
`Password`, `VNCProxyPassword` and `RDGatewayPassword` are encrypted (version 2.6 and later: AES-GCM
with a PBKDF2 key of `KdfIterations`; the key is the master password, or the built-in `mR3m` when
none is set; earlier versions use a legacy Rijndael provider), so with the default key anybody can
decrypt them, and podssh must not: count and skip. `FullFileEncryption="True"` encrypts the whole
body: refuse by name. FinalShell: `password` is a reversible obfuscation that third-party tools
undo: count it, never decode it.

**Encodings.** A `.reg` file of `regedit /e` and `reg export` (header `Windows Registry Editor
Version 5.00`) is UTF-16LE with a BOM; `regedit /ea` writes `REGEDIT4` in ANSI (Read in a comment of
the source of `sshub`, https://docs.rs/crate/sshub/latest/source/src/import/putty.rs; the UTF-16
claim itself is Inferred: no real UTF-16 file was found, because code search does not index them).
Of 82 distinct real files with a host, none began with `FF FE`: 75 were ASCII with `5.00` (LF or
CRLF), 4 were `REGEDIT4`, 3 had a UTF-8 BOM. The reader takes all four, and the test transcodes an
ASCII fixture to UTF-16LE at test time (a real one is missing; say so in the test). Key names differ
in case in practice (`SOFTWARE\SimonTatham` and `Software\SimonTatham`). The session
`Default%20Settings` is the template, never a host. Names are escaped by byte, in uppercase hex
(space, `\`, `*`, `?`, `%`, controls, bytes above `~`, a leading `.`; Read in
`windows/utils/escape_registry_key.c` of the fork) and are UTF-8 after the decoding. Values:
`"x"="a\\b"` escapes `\` and `"`; `dword:` and `hex:`; the file also holds `SshHostKeys`, `Jumplist`
and the root key, which the reader skips.

**What the writer must do** (the writer and the secret counter of T-047). PuTTY: skip
`Default%20Settings` and each session that is not `ssh`; split `user@host` of `HostName` into `User`
and `HostName`, or keep it whole with a comment (an open point); write a `.ppk` as a comment, or as
`IdentityFile` with a comment (an open point: podssh does not read PuTTY's format); comment
`ProxyTelnetCommand`; count a non-empty `ProxyPassword`. MobaXterm: dispatch on the type; gateway
fields 8 to 10 become `ProxyJump`; decode `__PIPE__` and its kind; count the entries of
`[Passwords]` and `[Sesspass]`; the login and macro fields can hold secrets: a comment with no value.
Remmina: `server=host:port` is split; `.` and blobs are counted apart. mRemoteNG: resolve the
inheritance of the user; `SSHTunnelConnectionName` becomes `ProxyJump` when its name is a node, else
a comment; refuse `FullFileEncryption`; never decrypt.

**The fixtures: real files, with their license** (Read in the GitHub API of 2026-10-30; each file is
fetched at its commit, from `raw.githubusercontent.com/OWNER/REPO/COMMIT/PATH`). These permissive
ones can be committed, each with its notice in a `THIRD-PARTY` file next to the fixtures:

| File | Repository and path | Commit | License | SHA-256 |
| --- | --- | --- | --- | --- |
| PuTTY `.reg`, one SSH session, a `.ppk` key, CRLF | `ctxis/DynamicLabs:Ansible/tasks/attacks/T1552_2/puttyregkey/putty_session.reg` | `e03ba4b9bccc129819520a76be5552da7b9b3a17` | MIT | `0a5e6690e2b18205b2ac29bfa66d07cbe7bf721809004cfd369e498ba2a2b162` |
| PuTTY `.reg`, Default Settings with `user@host`, a `Jumplist`, LF | `chauncey-garrett/dotfiles:putty/putty.reg` | `74b4c13665e18ec3b058ffc420932fdb39031880` | MIT | `e3e81a62775888f85b06036e74f93808937bb44a66dff59dd6e30f58054dfe82` |
| PuTTY `.reg`, a UTF-8 BOM, Default Settings only | `sstallion/dotfiles:extra/Windows/PuTTY.reg` | `ead220ca6e198c066f626e740d95ccf7609b2cbb` | BSD-2-Clause | `8264dbf630178ec4f440af8f72f1613bb5a001b447300db8d4cf00f614b7ab34` |
| PuTTY Unix file, Default Settings (the name is `%XX` encoded) | `KunoiSayami/dotfiles:.putty/sessions/Default%20Settings` | `f8d4b6fdc1c6ca075231d2ea4b9cbd846b73b07c` | Unlicense | `e55ad9f98c122fb599287c8483b864d8e97f511ba751d32c5d9c95b7d8872644` |
| MobaXterm `.mxtsessions`, nested `SubRep`, `__PTVIRG__`, localhost | `OElabed/ice-microservices:dev-tools/ice-sessions.mxtsessions` | `2273860d63e496b49e9642aef314b68e08d21a79` | MIT | `ed90b9e9beda688ef75df5fef2760bdc65f00dd5e46eea899308e9cc63c4c6e5` |
| Remmina, the full key set of `protocol=SSH`, with `%Host%` placeholders | `OneIdentity/SCALUS:scripts/examples/ssh.remmina` | `24e7efa58e5f413b2b4ea80a023525963d8f0aaf` | Apache-2.0 | `e142e9d40b231d3bb7d9f2972b99902f8ec886fe8884b7b6a6250ba94e8d43b9` |
| mRemoteNG, `mrng:` namespace, ConfVersion 2.6, one SSH2 node with an encrypted password | `DHemken97/NKeeper:export-mremote-example.xml` | `5652109f3fd6b4bcfbc2fba9f93c9b78688d61b0` | MIT | `25f4c05d6469b7f052fbf80c051afeed6b180f84d54e28e352b06d7eebd78408` |

Whether each satisfies Q41 is not settled by its license. The Remmina file is a template (it may not
come from Remmina's writer, Inferred from the `%Host%`); the NKeeper file has the shape of mRemoteNG
1.77's output, but that mRemoteNG wrote it is Inferred; the three PuTTY `.reg` files and the Unix file
hold few or no hosts (Default Settings; one session). The multi-host cases rest on files that cannot
be committed today:

- No license, real: PuTTY `.reg` of `ardentperf/racattack` (`putty-saved-sessions.reg`, 4 sessions,
  LF; commit `a41f4b7302fd0afc8bd4c13e6faca9bb4d71b2c6`), `xorrkaz/enterprise-network-programmability`
  (`putty/putty.reg`, 12 sessions, SSH and Telnet, CRLF; `bf54cfc7086c0da5348ed6e24e9295ad9bdba590`),
  `theeternalsw0rd/dotfiles` (`terminals/putty/cygwin.reg`, `REGEDIT4`, a Local proxy;
  `c6e1cda79b8ba32e9b72967158c3dc8ed4f8a7dc`), `JW0914/Wikis`
  (`Scripts+Configs/PuTTY/Multi-Hop/PuTTY_Profile_TrueNAS_Remote_Multi-hop.reg`, `ProxyMethod=5` with
  `plink -load OTHER -nc %host:%port`, `HostName=root@host`; `1680c8d3ec4319d4a4f1281e925d5c0e2def1282`),
  `SteveCTOS/SteveCTOS` (`putty/sessions/ctools` and `development`, Unix files;
  `f16a045b58eede2de661ea17ba2a052c6e86790e`); MobaXterm `Nomard/network-infra-obsidian-template`
  (`VaultSample/App Files/MobaXterm/MobaXterm Sessions.mxtsessions`, CRLF, a serial session;
  `7306420ddc3edb37fc2c7301c9641885bc14554b`); Remmina `srackham/dotfiles`
  (`dot_local/share/remmina/group_ssh_rpi1_rpi1.remmina`; `39e5147de93ad77ec28358e2ea0fd0b5650bfd7a`),
  `zany130/dotfiles-garuda` (an SSH profile with RDP keys; `bf44153a7b70c02af69fd2fd3b40a05f5b48242c`)
  and `aomogol/install-arch-2024` (`448ebc82a05dd30e05f057a078faf1726a944d8a`), all with `password=.`.
- GPL: mRemoteNG's own test resources `mRemoteNGTests/Resources/confCons_v2_5.xml`,
  `confCons_v2_6.xml`, `confCons_v2_6_5k-iterations.xml`, `confCons_v2_6_passwordis_Password.xml` (the
  master password is `Password`) and `confCons_v2_6_fullencryption.xml`, with the schemas
  `mremoteng_confcons_v2_6.xsd` and `v2_8.xsd`, all at `25ef453aaf18f292478dd41e5bb26798ff504312`
  (written by the program, real encrypted test passwords, an empty `Hostname` in each, one SSH2 node);
  `cremenescu/mRemoteNXT:examples/demo-config.xml` (`f52e810f5bbc8bfe620e179d235678886fb0b9bc`; 10 SSH2
  nodes in 4 folders on TEST-NET addresses; it may not come from mRemoteNG); and, hand-written by
  other importers and so no export at all, `Ruzgfpegk/sessionator` (GPL-3.0), `2shiraz/tyrminal`
  (Apache-2.0, `tests/fixtures/import/mobaxterm-sessions.mxtsessions`) and
  `totoshko88/RustConn` (GPL-3.0, `ssh_server.remmina`).
- No file that the program wrote was found for FinalShell: the importers' fixtures are synthetic
  (`AnalyseDeCircuit/oxideterm`, GPL-3.0; `BitsFlowCloud/DengShell`, MIT, built in code); one skill
  file quotes a real file with its values blanked and has no license. None for Termius (no export).
  By Q41, these two formats stay out, named as waiting, until one exists.
- No sample holds a non-empty `ProxyPassword`, a `[Passwords]` entry or a Remmina blob. The test of the
  secret uses copies of a licensed fixture with a made-up value (mRemoteNG's blobs and the
  `ssh_passphrase` placeholders already are test values).

**Open points for the operator or a later session** (none is a fact):

1. May GPL files (mRemoteNG's tests, the demo file) live in this repository as test data, with a
   notice? Else the mRemoteNG cases rest on the NKeeper file and on built inputs; the authors of the
   unlicensed files could be asked for a license.
2. A real UTF-16LE PuTTY export, beyond the test-time transcoding, was not found.
3. The `.ppk` as `IdentityFile`, and `user@host` in `HostName`: the two choices above.
4. Not checked against a real file: Remmina's nested `group` separator, FinalShell's folder files,
   mRemoteNG's key derivation before version 2.6, and the `ProxyMethod` numbers 6 to 8.
5. Whether the NKeeper and demo files were written by mRemoteNG: a user of 1.77.x could say.
6. FinalShell and Termius: the operator may supply a file from a real install, which settles both.

2026-10-30, later: two rows of the table above were wrong when their files
were fetched at their commits for the fixtures (each digest matched).
`OneIdentity/SCALUS` is under the MIT license at `24e7efa5`, not Apache-2.0
(its `LICENSE` there says "MIT License, Copyright (c) 2020 Cody Batt").
`DHemken97/NKeeper` has no license file at `5652109f` (none of `LICENSE`,
`LICENSE.md`, `LICENSE.txt`, `COPYING` and the like, and its README names
none), so its file cannot be committed, and mRemoteNG has no fixture: it
waits with FinalShell and Termius (T-327). The other five files are in
`crates/podssh-cli/tests/fixtures/sessions/`, byte for byte, with the
license of each repository in `THIRD-PARTY.md` there.

## Done

2026-10-30. `podssh config import putty`, `mobaxterm` and `remmina` read
the saved sessions of those programs into `Host` blocks
(`crates/podssh-cli/src/config_import/putty.rs`, `mobaxterm.rs`,
`remmina.rs`, and `sessions.rs` for the model and the writer), with the
writer, the comments and the counting of secrets of T-047. A `.reg` file is
read in UTF-16LE, UTF-8 with or without its mark, or the ANSI of
`REGEDIT4`; a directory gives each of its files, as PuTTY on Unix and
Remmina keep one file for each session. mRemoteNG, FinalShell and Termius,
and Ansible's YAML, stay refused by name (64), and wait in T-327.

- Linux, 2026-10-30: `cargo test -p podssh-cli --test config_import`, 9
  passed: the real PuTTY session (`John Doe`: `HostName 127.0.0.1`,
  `User blue`, its `.ppk` and its `Environment` as comments), the three
  templates that are no host, and the same file transcoded to UTF-16LE with
  its mark, as no real one was found; each of the 12 sessions of the real
  MobaXterm export, with its folder; the real Remmina template, whose
  `%Host%` is no host. Copies of the fixtures with made-up values: a proxy
  password of PuTTY and an SSH proxy as `ProxyJump`, a session file of Unix
  named `web%20server`, a `[Passwords]` entry of MobaXterm, and a Remmina
  profile with a secret in the keyring and one encrypted: each counted, none
  printed. `--lib config_import`, 11 (the encodings, the `%XX` names, a
  `.reg` value, the fields of MobaXterm, the forms of Remmina's server); the
  lib 368, `man_page` 10, `flag_table` 8; clippy and rustfmt clean.
- Planted: the proxy password copied into a comment; the test of the secret
  failed ("a secret was printed"); restored, it passed.
- Not measured: a real UTF-16LE export, a real file with a password, a
  PuTTY session with `ProxyMethod` 6, and a real Remmina profile that its
  own writer made (the fixture is a template).
- 2026-10-30, later: the gate's steps ssh, ts and iroh failed on `1891f43`
  (run 41069857511), "the tests left in the temporary directory": the four
  scratch directories of `config_import` were never removed. Each is now a
  guard that removes its directory when the test ends, also when it fails.
  Linux: `config_import` 9 passed, and `/tmp` held no `podssh-config-import-*`
  after the run (before the repair, each run left four); clippy clean.

# T-327: `podssh config import` from mRemoteNG

**Source:** T-292, 2026-10-30: these three formats have no real export
under a license that this repository can hold. FinalShell and Termius
moved to T-328 on 2026-10-30, as they wait for an export.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A user who keeps hosts in mRemoteNG, FinalShell or Termius types each host
again: `podssh config import` refuses the three by name (64).

## Premise

- Read (T-292's Correction): mRemoteNG's own test files, written by the
  program, are under the GPL (`mRemoteNG/mRemoteNG`), and the one other file
  of its shape has no license; FinalShell and Termius have no export, only
  importers' synthetic fixtures and tools that decrypt their databases.
- Read: by Q41 (`docs/decisions.md`), a format is tested on a file that its
  program wrote and that is published under a license that the repository
  can hold; else it waits, named.

## Approach

1. mRemoteNG: the XML of `confCons.xml` (`roxmltree`, as T-292's Decision
   chose), the folders and the inheritance of the user, a jump by
   `SSHTunnelConnectionName`, each password counted and never decrypted,
   `FullFileEncryption` refused by name; on mRemoteNG's own test files, once
   the operator rules on GPL test data (Q46), or on a file that the operator
   supplies.
2. FinalShell and Termius: T-328.

## Decision

2026-10-30, the operator (Q46, `docs/decisions.md`): mRemoteNG's own test
files, under the GPL-2.0, may live under `crates/podssh-cli/tests/fixtures/`,
each with its license and source in a notice beside it; none is linked into
a binary.

## Prove

```sh
cargo test -p podssh-cli --test config_import
```

The blocks of mRemoteNG's fixtures, and no password on stdout or stderr.
Planted: a password copied into a comment; the test fails.

## Done

2026-10-30.

- `crates/podssh-cli/src/config_import/mremoteng.rs`: the XML of
  `confCons.xml` with `roxmltree` 0.21 (`default-features = false`, as
  T-292's Decision chose; MIT or Apache-2.0): each `Node` of
  `Type="Connection"` a session in the folders of the `Container` nodes
  above it; `Protocol="SSH2"` a block, `SSH1`, each other protocol and each
  other type a comment; each field that a node inherits (`Inherit…`, `True`
  or `true`) from the nearest folder above it with its own;
  `SSHTunnelConnectionName` the `ProxyJump` through the connection of that
  name, its own tunnel first, a tunnel to no SSH connection and a loop as
  comments; a PuTTY session other than `Default Settings` and `SSHOptions`
  as comments with no value; each `Password`, `VNCProxyPassword` and
  `RDGatewayPassword` counted, never decrypted; `FullFileEncryption`
  refused by name (65). `podssh config import mremoteng FILE`; the manual's
  note, `docs/cli.md`, `docs/STATUS.md`.
- The fixtures: mRemoteNG's `confCons_v2_5.xml`, `confCons_v2_6.xml` and
  `confCons_v2_6_fullencryption.xml` at `25ef453`, with its `COPYING.txt`
  and a notice of their source and SHA-256
  (`crates/podssh-cli/tests/fixtures/mremoteng/`), by the ruling of Q46.
  The real files have no host on any connection; a copy with made-up hosts,
  a tunnel and a made-up password tests the mapping.
- `cargo test -p podssh-cli --test config_import`: 12 passed, of them the
  three of mRemoteNG: each connection of both real files in its folder,
  their 10 and 15 passwords counted, and no password value of the files
  printed; the copy's blocks (`Connection1.3`: `HostName web.example`,
  `Port 2222`, `User userFolder1`, `ProxyJump root@bastion.example`; a user
  inherited through two folders); the file encrypted whole refused. `cargo
  test -p podssh-cli --lib`: 413 passed (4 of the reader: inheritance, a
  chain of tunnels and a loop, SSH1 and another type, the refusals); the
  manual's tests 28; clippy `-D warnings`: clean. Planted, a password
  copied into a comment: the copy's test failed ("a secret was printed");
  it passed again without the plant. A first plant, with the made-up
  password on an RDP connection, passed: a session of another protocol
  writes no note, so the test now puts it on the SSH connection.
- `fuzz/Cargo.lock` gains `roxmltree`, and `h2`, `http` and the crates
  that T-300's feature `quick` of `podssh-relay` brought to `podssh-cli`,
  at the versions of `Cargo.lock`.

# T-328: `podssh config import` from FinalShell and Termius

**Source:** T-327, 2026-10-30: FinalShell and Termius have no export that
their programs wrote and that is published.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** blocked

## Problem

A user who keeps hosts in FinalShell or Termius types each host again:
`podssh config import` refuses the two by name (64).

## Premise

- Read (T-292's Correction): FinalShell and Termius have no export, only
  importers' synthetic fixtures and tools that decrypt their databases.
- Read: by Q41 (`docs/decisions.md`), a format is tested on a file that its
  program wrote and that is published under a license that the repository
  can hold; else it waits, named.

## Approach

1. With a file of a real install of each program: read its hosts, users,
   ports, keys and jumps as T-292's formats do; each password counted and
   never decrypted.
2. Until then, the refusal by name stays, and says what podssh needs.

## Prove

```sh
cargo test -p podssh-cli --test config_import
```

For each format, the blocks of its fixture, and no password on stdout or
stderr. Planted: a password copied into a comment; the test fails.

## Blocker

The operator: a real export of FinalShell and of Termius, written by each
program, under a license that this repository can hold (Q41).
The operator ruled on 2026-10-31 that this is a known gap: `v1.0.0` does
not wait for it, and its notes name it (`docs/decisions.md`).
The hold ended on 2026-11-03 (Q92, `docs/decisions.md`): the entry waits for this input
alone, and takes its place in the work order once the operator gives it.

# T-502: `-o ProxyCommand=none` does not beat a file's `ProxyCommand`, and the first `ProxyCommand` of a file does not hold

**Source:** the report of the operator's testing agents on `v1.0.0` (`35a0d19`), 2026-11-02 (T-500's
Source): its issue 03 (`03-proxycommand-in-config.md`) and its ledger's L-07. With the line
`ProxyCommand ssh -W %h:%p b` in a file of `-F`,
`podssh ssh --direct -F FILE -o ProxyCommand=none HOST true` exits 78 with "FILE:1: ProxyCommand: podssh ssh reaches the host through the relay itself and runs
no ProxyCommand ..."; so do `cp`, `scp`, `sftp` and `mv`, where `-o User` and `-o Port` beat the
same file. A `ProxyCommand` of a block that does not apply is not read; one of `Host *` stops each
destination. Related: GitHub #22. Read at `01e371e`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The command line's value of a keyword beats a file's, as in OpenSSH; for `ProxyCommand` it does
not. A `Host *` block (or `Match all`, or `Match final`) with a jump host for OpenSSH, from a base
image or a user's dotfiles, stops podssh for each host, and the one way out, `-F none`, drops each
other block of the file too.

## Premise

- Read: the `-o` of the command line are applied first (`crates/podssh-cli/src/ssh/resolve.rs:139-141`),
  the file is read into settings of its own (`crates/podssh-cli/src/ssh/resolve.rs:206`), and the
  two are merged, the first value obtained winning (`crates/podssh-cli/src/ssh/resolve.rs:210`,
  `crates/podssh-cli/src/ssh/options.rs:349-355`, `crates/podssh-cli/src/ssh/options.rs:445-449`).
- Read: `ProxyCommand none` sets nothing (`crates/podssh-cli/src/ssh/options.rs:221`), and
  `podssh proxy %h %p` adds a note alone (`:224`); each other value is an error (`:225-236`), which
  a line of a file gets with its place and the file's exit, 78
  (`crates/podssh-cli/src/ssh/config.rs:226`, `crates/podssh-cli/src/ssh/resolve.rs:206`). So no
  value of the command line stands before the file's; and in one file, a `ProxyCommand none` of an
  earlier block does not stand before a later `Host *`'s, where OpenSSH takes the first.
- Read: a block that does not apply is not read (T-043's Decision), and `Match` is read (T-045), as
  the report found.
- Read (L-07): T-043 decided to accept `ProxyCommand podssh proxy %h %p` with no effect, and to
  run no `ProxyCommand` (rule 3 of `AGENTS.md`), as `podssh ssh` is the program that it names; so
  `/nonexistent/podssh proxy %h %p`, accepted and never run, is that decision. Its note says "-o
  ProxyCommand has no effect in podssh", at `-v` alone (`crates/podssh-cli/src/ssh/resolve.rs:391`).
- Read: 78 is the exit of a configuration error (`docs/decisions.md`, 2026-10-05); the report asks
  for 255, or 64.

## Approach

1. A `ProxyCommand` that podssh takes as its own road (`none`, or `podssh proxy %h %p`) is a value
   that holds: the first one given, on the command line or in a file, is kept, and each later
   `ProxyCommand` is not read, as OpenSSH reads the first alone. So `-o ProxyCommand=none` beats
   each file, and the `ProxyCommand none` of a `Host bastion` block beats a later `Host *`'s.
2. A `ProxyCommand` that runs another command, with no value before it, stays refused, with 78 and
   its place, and the line names the way out: "...; -o ProxyCommand=none makes podssh ssh take its
   own road for this run, with the file's other settings".
3. `-v` names the place of the value that it does not run: "ProxyCommand podssh proxy %h %p
   (FILE:N) is not run: podssh ssh carries the session itself", in place of a note that says "-o".
4. Each verb that reads the file gets it through the resolve: `cp`, `mv`, `scp`, `sftp`, `run`,
   `each`, `health` and the others.
5. Tests in `crates/podssh-cli/tests/ssh_config_file.rs`: the report's file with
   `-o ProxyCommand=none`, and with `-o ProxyCommand='podssh proxy %h %p'`, logs in to the harness
   with `--direct`; a `Host x` block with `ProxyCommand none` before a `Host *` with a command: `x` logs
   in, another host is refused (78) with the new words; `cp` with the same file and `-o`.

## Decision

Recommendation, for the operator to rule: a `ProxyCommand` that applies to each host and that no
earlier value beats stays a refusal (78), as T-043 decided: the file asks for a road (a jump host, a
proxy of a company) that podssh does not take, and to carry the session over the relay with a note
would send it where the file's author did not. The way out is one flag, which the line names. Lost:
ignore it with a note, as the inert keywords are (the report's ask); and 255 at the connect, as a
fault of the configuration is 78 (2026-10-05).

**Ruled, Q70 (2026-11-02):** as recommended: refused with 78, and the refusal names `-o ProxyCommand=none`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib ssh::options
cargo test -p podssh-cli --test ssh_config_file -- proxy_command
```

Planted: `none` sets nothing again: the test of `-o ProxyCommand=none` fails with 78.

## Correction

2026-11-02, read in OpenSSH 10.3p1's `readconf.c` and `ssh.c` (tag `V_10_3_P1` of
openssh-portable, through `fetch.web.pkgforge.dev`): the Premise holds at its lines, but it misses
how OpenSSH ties `ProxyJump` to `ProxyCommand`. `parse_jump` reads a `ProxyJump` only while
`proxy_command == NULL && jump_host == NULL` (`readconf.c:3484`), and `oProxyCommand` sets a value
only while none is set (`readconf.c:1529-1541`); `ssh.c:1316-1318` then refuses a `ProxyCommand`
other than `none` beside a jump ("inconsistent options: ProxyCommand+ProxyJump"). In 10.3p1 `-J`
sets no `ProxyCommand none`, and refuses a `ProxyCommand` given before it (`ssh.c:878-889`). So, once a `ProxyCommand` holds (`-o
ProxyCommand=none`, or the `ProxyCommand none` of an earlier block), OpenSSH reads no later
`ProxyJump`; podssh read it, and would have jumped where OpenSSH goes straight. Approach, added:
1b. A `ProxyJump` after the `ProxyCommand` that holds is not read; one given before it keeps its
hops. `-J` keeps its own place (podssh does not refuse it beside `-o ProxyCommand=none`, where
OpenSSH refuses the pair in one order of the two), and the `ProxyCommand` of the command line
holds for each hop of `-J` too, as the settings of host keys do (T-290): a hop's own `ProxyJump`
is then not read either.

## Done

Drafted 2026-11-02 by a drafting agent, which built nothing; merged and measured by the main
session on 2026-11-03.
- `crates/podssh-cli/src/ssh/options.rs`: the first `ProxyCommand` that podssh takes as its own
  road (`none`, `podssh proxy %h %p`) is kept with its place (`proxy_command`), and each later
  `ProxyCommand` and each later `ProxyJump` are not read; a command with no value before it is
  refused (`proxy_refused`), and the refusal of a file's line names `-o ProxyCommand=none` (Q70).
  The values of the keywords went to `crates/podssh-cli/src/ssh/options_values.rs`, for the length
  of the file.
- `crates/podssh-cli/src/ssh/given.rs`: the place of a value (`-o`, or `FILE:LINE` and whether it
  is the system's file), which `crates/podssh-cli/src/ssh/config.rs` gives each line it applies.
- The reading of a file starts from what the command line gives it (`Settings::for_files`: its
  `IgnoreUnknown` and its `ProxyCommand`), for the destination
  (`crates/podssh-cli/src/ssh/resolve.rs`) and for each hop of `-J`
  (`crates/podssh-cli/src/ssh/jump.rs`), so a file's command after the command line's `none` is
  never read; `cp`, `mv`, `scp`, `sftp`, `run`, `each`, `health` and the others take it through
  `resolve_or_refuse`.
- `-v` names the place of a `ProxyCommand podssh proxy %h %p` that podssh does not run
  (`crates/podssh-cli/src/ssh/noted.rs`).
- The manual's `~/.ssh/config` (`crates/podssh-cli/src/man/data.rs`), the refusal's row of
  `ProxyCommand` (`crates/podssh-cli/src/ssh/keywords.rs`) and `docs/cli.md`, section
  "`ssh_config`", say the same.
- Tests: `cargo test -p podssh-cli --lib ssh::options`, 9 passed (the first value holds; a later
  `ProxyJump` is not read; the refusal names its way out) and `--lib ssh::given`, 1, `--lib
  ssh::noted`, 1; `cargo test -p podssh-cli --test ssh_config_file -- proxy_command`, 6 passed: the
  report's file with `-o ProxyCommand=none`, `NONE` and `podssh proxy %h %p`, and with `-J`; a
  `Host x` block's `none` before `Host *`; a later `ProxyJump`; `cp`, `mv`, `scp` and `sftp`
  offline, 69 with `none` and 78 without; a login to the test's server with `--direct` at the
  file's `Port`).
- Planted: `scripts/plants/t502-none-sets-nothing.plant` (`none` sets nothing again): caught,
  the test of the report's file failed.
- The merge: the test of a later `ProxyJump` failed, as its file gave `Host *`'s `ProxyJump
  bastion` to the bastion too, a jump host loop that T-290 refuses with 64: the bastion's block now
  names `ProxyJump none`, and the test holds what it says. `resolve.rs`'s notes join T-502's
  (`noted::of`) and T-500's of where the login name came from. `cargo todo remap` from the tree
  before the draft; rustfmt and clippy of `podssh-cli` with `-D warnings`, all targets: clean.

# T-505: Keywords that restrict a connection (`Ciphers`, `HostKeyAlgorithms`, `RequiredRSASize` and others) are accepted with no effect and no word, and the manual says that they change nothing

**Source:** the report of 2026-11-02 (T-500's Source): its issue 05
(`05-ignored-config-keywords.md`) and its ledger's L-08, L-09 and L-39. A `Host *` with `Ciphers`,
`MACs`, `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, `RequiredRSASize 3072`
and `VerifyHostKeyDNS yes`: exit 0, stderr empty, and with `-v` a line "-o Ciphers has no effect in
podssh" for each. The report splits the 50 keywords of the manual into 28 inert ones and 22 of a
restriction. `-G` prints 40 lines where OpenSSH prints 91 (L-09); `-v` names `HashKnownHosts` and
`GSSAPIAuthentication` in each run (L-39). Related: GitHub #22. Read at `01e371e`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A hardened `~/.ssh/config`, or `-o Ciphers=...`, connects with podssh's own algorithms and no word,
and the manual says that those keywords "change nothing that podssh does". A restriction that the
user asked for is gone with no sign, and an audit finds it.

## Premise

- Read: the 50 keywords are accepted with no effect, as they "ask for nothing podssh does
  differently, or limit algorithm lists that podssh keeps modern itself"
  (`crates/podssh-cli/src/ssh/keywords.rs:119-132`), and the manual says "Accepted and ignored,
  because they change nothing that podssh does" (`crates/podssh-cli/src/man/model.rs:268-272`).
- Read: each one is a note (`crates/podssh-cli/src/ssh/options.rs:272`), "-o NAME has no effect in
  podssh" (`crates/podssh-cli/src/ssh/resolve.rs:391`), said at `-v` alone
  (`crates/podssh-cli/src/ssh/mod.rs:260-262`): "-o" also for the line of a file, with no file and
  no line.
- Read, against L-39: the two notes of each run come from Debian 13's `/etc/ssh/ssh_config`, whose
  `Host *` sets `HashKnownHosts` and `GSSAPIAuthentication` (T-044's Correction), and which podssh
  reads after `~/.ssh/config`; they are not OpenSSH's defaults.
- Read: russh's lists of algorithms are podssh's to set (`crates/podssh-ssh/src/run_config.rs:18`),
  and podssh orders the host key algorithms by `known_hosts` already
  (`crates/podssh-ssh/src/run_config.rs:21-47`); no keyword reaches the lists.
- Read: Fedora's system file includes the crypto policy's file (T-044's Correction). Inferred, not
  read here: that file sets `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms`,
  `PubkeyAcceptedAlgorithms`, `CASignatureAlgorithms` and `RequiredRSASize` for each host, so a
  note at the default level for those would come in each run on Fedora.
- Read, against the report's table: `CertificateFile` names the user's certificate, not a host's,
  so a login that needs it fails where podssh does not apply it, and the user sees that;
  `HostbasedAcceptedAlgorithms` restricts a hostbased login, which podssh does not make, so it is
  inert here.
- Read (L-09): `-G` prints the keywords that podssh applies (`crates/podssh-cli/src/ssh/dump.rs:1-7`),
  as its manual says (`crates/podssh-cli/src/man/notes_ssh_more.rs:40-44`), so it has no line for
  an algorithm list.

## Approach

1. Applied, as filters of what podssh offers, in OpenSSH's forms (a list, `+` to add, `-` to
   remove, `^` to put first; a name that podssh lacks is dropped): `Ciphers`, `MACs`,
   `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms` (and its old name
   `PubkeyAcceptedKeyTypes`) and `CASignatureAlgorithms`; and `RequiredRSASize`: a host's or a
   user's RSA key smaller than it is refused, as OpenSSH refuses it (default 1024, as OpenSSH's).
   A list that leaves nothing that podssh speaks is refused before anything connects (64 on the
   command line, 78 in a file), and names what podssh speaks.
2. A note at the default level, once for each keyword and run, for a restriction that podssh does
   not apply (`BindAddress`, `BindInterface`, `IPQoS`, `TCPKeepAlive`, `ChannelTimeout`,
   `RekeyLimit`, `UpdateHostKeys`, `VerifyHostKeyDNS`, `CertificateFile`, `SecurityKeyProvider`,
   `Tunnel`, `TunnelDevice`, `WarnWeakCrypto`), when the user gave it (on the command line, in `-F`'s or
   `PODSSH_SSH_CONFIG`'s file, or in `~/.ssh/config`): "VerifyHostKeyDNS yes (~/.ssh/config:4) is
   not applied: podssh checks host keys against known_hosts alone". None for a line of the system's
   file, and none with `-q`.
3. The inert keywords keep their note at `-v`, and each note names its place
   ("/etc/ssh/ssh_config:22: HashKnownHosts has no effect in podssh"), not "-o".
4. `-G` prints the lists of step 1 as podssh will offer them (`ciphers`, `macs`, `kexalgorithms`,
   `hostkeyalgorithms`, `pubkeyacceptedalgorithms`, `casignaturealgorithms`, `requiredrsasize`).
5. The manual splits its list in three: applied, accepted with a note (not applied), and inert;
   `docs/cli.md` says the same.
6. Tests: the reading of the lists and their forms; `-G` gives each list as filtered;
   `-o Ciphers=3des-cbc`, which podssh lacks, is refused (64); `RequiredRSASize 4096` against the
   harness's RSA host key of 2048 bits is refused with 255 and its words; the note of
   `VerifyHostKeyDNS` of `-F` at the default level, none for the same line in a system file of the
   test, none with `-q`. In `scripts/interop.sh`, `-o KexAlgorithms=curve25519-sha256` against
   OpenSSH, whose log names that exchange.

## Decision

Recommendation, for the operator to rule: apply the lists, which filter what podssh offers
already, and say the rest. Lost: a note alone for each of the 22 (the report's second way): on
Fedora each run would print seven lines for its crypto policy, which sets them for each program.
Lost: the manual's split alone (its first way), which still connects with no word. `BindAddress`
and `BindInterface` stay notes: a bind of the client's socket is outside rule 2 of `AGENTS.md`, and
the relay road has no local address to choose.

**Ruled, Q71 (2026-11-02):** as recommended: the lists apply.

Calls of the draft (2026-11-02, Q86), with what lost:
- **For the operator to confirm:** the host key algorithms that `known_hosts` records for the host
  go first within each list, also one that replaces podssh's own or one with `^`. OpenSSH 10.3p1
  keeps such a list's own order (`sshconnect2.c:239-251`: the order of `known_hosts` for no list,
  or one with `+` or `-`, alone). Lost, OpenSSH's rule: Fedora's crypto policy gives an explicit
  `HostKeyAlgorithms` in each run, ECDSA first, and podssh, which records one key of a host (no
  `UpdateHostKeys`), would ask a host that it knows by its Ed25519 key for an ECDSA key that it
  does not know: a question, or a refusal under `StrictHostKeyChecking yes`, where nothing changed.
- **For the operator to confirm:** podssh's own lists, which a list with `+`, `-` or `^` starts
  from and `-G` prints, are what it offered before (russh's), not OpenSSH's defaults; `ssh-rsa`
  (SHA-1) stays in its own `PubkeyAcceptedAlgorithms` (for an agent's key, when the server lists
  nothing better, T-257) and `CASignatureAlgorithms`, where OpenSSH 8.2 and 8.8 dropped it. Lost,
  OpenSSH's defaults: they would change what podssh offers and takes when no keyword is given,
  which Q71 did not ask; to drop SHA-1 RSA from podssh's own lists is a call of its own.
- A name that podssh does not speak is left out, with a note at `-v`, where OpenSSH refuses a
  name that OpenSSH does not know (`ciphers_valid`, `mac_valid`, `kex_names_valid` and
  `sshkey_names_valid2`, `readconf.c:1589-1660`) and leaves out one that it knows and lacks
  (`kex_assemble_names`, `kex-names.c:243-336`). Lost, a refusal: podssh cannot know each name of
  each release of OpenSSH, and a name of a newer one, as a distribution's policy writes it, would
  stop each run. A pattern is taken in each form, where OpenSSH takes one in a list of `-` alone
  for `Ciphers`, `MACs` and `KexAlgorithms`; a `!` outside a list of `-` is refused, as OpenSSH
  refuses it.
- The lists of the command line hold for each hop of `-J`, as its settings of host keys do
  (T-290), where OpenSSH's jump process gets no `-o`. Lost: the hop's own file alone, which would
  let a hop take what the command line forbids.
- `-c` and `-m` stay refused, and name `-o Ciphers=LIST` and `-o MACs=LIST`; `-Q` names `-G`. Lost:
  `-c` and `-m` as flags of `ssh`, `scp` and `sftp`, new flags that the entry does not ask for.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib ssh::keywords
cargo test -p podssh-cli --test ssh_config_file -- algorithms
```

Planted: a list read and not applied: the test of `-G` fails.

## Correction

2026-11-02, read in OpenSSH 10.3p1 (tag `V_10_3_P1` of openssh-portable, through
`fetch.web.pkgforge.dev`), `ssh_config(5)`, and this tree. The Premise holds at its lines; three
facts change the Approach:
- Its inference about Fedora is read now: T-044's fixture of Fedora 42's crypto policy
  (`crates/podssh-cli/tests/ssh_config_include.rs:189-196`, as its packages write it) sets
  `Ciphers`, `MACs`, `KexAlgorithms`, `PubkeyAcceptedAlgorithms`, `CASignatureAlgorithms` and
  `RequiredRSASize`, in the final pass of a `Match final all` block of the system's file. Each of
  its names is one that podssh speaks, so the policy applies, with no note.
- OpenSSH holds a certificate to `RequiredRSASize` by the RSA key of its CA too ("A certificate is
  no stronger than the CA key that signed it", `sshkey_check_rsa_length`, `sshkey.c:1455-1475`),
  and takes no RSA key under 1024 whatever the keyword says (`SSH_RSA_MINIMUM_MODULUS_SIZE`); its
  `-G` prints the value as given (`readconf.c:3800`). Approach, step 1, added: so does podssh.
- `CASignatureAlgorithms` holds for a host certificate whose CA a `@cert-authority` line names
  (`sshkey_cert_check_host`, `sshconnect.c:1078-1086`); another's certificate is checked as its
  plain key, as T-027 falls back. An RSA key of the user signs with the first of RSA's algorithms
  of `PubkeyAcceptedAlgorithms` that the server lists (`key_sig_algorithm`,
  `sshconnect2.c:1159-1206`); russh tells the server's best alone, so podssh takes it when the list
  does, else the list's first of RSA. `-G` prints `requiredrsasize` after `serveraliveinterval`,
  and the lists among the strings, in OpenSSH's places (`dump_client_config`, `readconf.c:3728`).

## Done

Drafted 2026-11-02 by a drafting agent, which built nothing; merged and measured by the main
session on 2026-11-03.
- `crates/podssh-ssh/src/algorithms/`: the six lists, assembled as `kex_assemble_names` assembles
  them over podssh's own (russh's) and what podssh speaks (russh's, but `none` and `clear`, and no
  extension of the key exchange), with the names left out and the refusal of a list that leaves
  nothing (`mod.rs`, `names.rs`); what they do (`apply.rs`): the handshake's ciphers, MACs, key
  exchanges (russh's extensions kept) and host key algorithms (`run_config.rs`, then the order of
  `known_hosts`), the certificates asked of a host of a `@cert-authority` line, a key of the user
  that `PubkeyAcceptedAlgorithms` or `RequiredRSASize` leaves out, which `-v` names, and the hash of
  RSA (`keys.rs`), and a host key, or the RSA key of a certificate's CA, under `RequiredRSASize`, or
  a certificate of a named CA signed with an algorithm that `CASignatureAlgorithms` does not name,
  refused with 255 before any question (`handler.rs`). `Options::algorithms` carries them.
- `crates/podssh-cli/src/ssh/algorithms.rs`: each keyword read where it is given, the first value
  holding (the command line's seed the reading of each file, T-502's `for_files`), a list that
  leaves nothing refused with its place (64, or 78 with `-o KEYWORD=LIST` named as the way past
  it); `crates/podssh-cli/src/ssh/login.rs` gives the lists to the destination's options and each
  hop's, and `crates/podssh-cli/src/ssh/jump.rs` gives a hop the command line's.
- `crates/podssh-cli/src/ssh/keywords.rs`: the eight keywords applied (`HONOURED`), the thirteen of
  a restriction accepted with a note (`NOTED`, each with its reason), and the 29 inert ones
  (`IGNORED`); `crates/podssh-cli/src/ssh/noted.rs`: the note of a restriction that the user gave,
  at the default level, once (`Resolved::warnings`, which `-q` hides), and at `-v` the place of
  each inert keyword ("FILE:LINE: NAME has no effect in podssh"), the names left out, and a
  restriction of the system's file.
- `-G` prints the six lists and `requiredrsasize` (`crates/podssh-cli/src/ssh/dump.rs`).
- The manual splits its list in three (`crates/podssh-cli/src/man/model.rs`), with a note of the
  lists (`crates/podssh-cli/src/man/notes_ssh_more.rs`) and `noted` in `podssh man --json`
  (`crates/podssh-cli/src/man/json.rs`); `-c`, `-m` and `-Q` name what to use
  (`crates/podssh-cli/src/flags.rs`, `crates/podssh-cli/src/flags/scp.rs`, and the context of
  `scripts/plants/t139-scp-row.patch`); `docs/cli.md` says the same, in "Options of `podssh ssh`"
  and "`ssh_config`".
- Tests: `cargo test -p podssh-ssh --lib algorithms`, 6 passed (5 of the draft: the forms, a name left out
  and a list of none refused, the certificates and extensions, the keys left out and RSA's hash,
  the RSA floor of a key and of a host key); `cargo test -p podssh-cli --lib ssh::keywords`, 7,
  `ssh::options`, `ssh::noted`, `ssh::algorithms`, 2, and the whole `--lib ssh::`, 99 passed; `cargo test -p podssh-cli --test
  ssh_config_file -- algorithms`, 5 passed ( `-G` for each list and form, from `-o` and a file, and for a
  hop; the refusals with 64 and 78, offline; `RequiredRSASize 4096` against the test's server with
  an RSA host key of 2048 bits, 255 with its words, and a list of host key algorithms with none in
  common; `PubkeyAcceptedAlgorithms` that leaves the Ed25519 key unoffered, 255, and `-v`'s line;
  the note of `VerifyHostKeyDNS` once at the default level, at `-v` for the system's file, none
  with `-q`); `--test ssh_config`, 3 passed, and the fixture of `--test ssh_config_file` with OpenSSH's
  `requiredrsasize 1024` and the lists apart; `--test ssh_config_include`, 10 passed (Fedora's
  policy applies, with no note); `--test man_json`, 4 passed; the whole `ssh_config_file`, 24, and
  `podssh-ssh --lib`, 269.
- Interop, waiting for the build image, which this host's Docker did not run (the gate's step
  `release` at the push): `INTEROP_ONLY=algorithms sh scripts/interop.sh BIN`
  (`scripts/interop-algorithms.sh`, ten checks, `algorithms.*` in
  `scripts/interop-baseline.txt`): against an sshd limited to `Ciphers aes128-ctr` at `LogLevel
  DEBUG2`, podssh's own list logs in, `-o Ciphers=aes128-ctr` too and its log names the cipher,
  `-o Ciphers=aes256-ctr` finds none in common (255), `-o KexAlgorithms=curve25519-sha256` and
  `-o HostKeyAlgorithms=rsa-sha2-512` are named in its log, `RequiredRSASize=4096` refuses its RSA
  key of 3072 bits, `PubkeyAcceptedAlgorithms` leaves the Ed25519 key out and signs the RSA key
  with `rsa-sha2-256` (the log's line of `userauth_pubkey` at DEBUG2 is to be read on the first
  run), `-o Ciphers=3des-cbc` is 64 with nothing in its log, and `-G`'s `requiredrsasize` is
  OpenSSH's. The checks of `ssh -G` in `scripts/interop.sh` leave the lists out, as podssh's own.
- Planted: `scripts/plants/t505-list-not-applied.plant` (the lists never reach the
  options: the test of `-G` must fail), `t505-rsa-floor-unchecked.plant` (no RSA floor for a host
  key), `t505-system-file-said.plant` (the system's file said at the default level), and
  `t505-lists-not-offered.plant` (the lists never reach the handshake: the interop check of no
  cipher in common must fail). The first three, `sh scripts/plant-each.sh --here`: each caught;
  the fourth (group `ssh-keys`) through `plants.yml` on a runner.
- The merge: `resolve.rs`'s warnings take T-505's `noted::said` beside T-500's and T-502's notes;
  `cargo todo remap` from the tree before the draft; rustfmt of `podssh-ssh` (the order of
  `lib.rs`'s modules) and clippy of `podssh-ssh` and `podssh-cli` with `-D warnings`, all targets:
  clean. The draft's two calls are in "For the operator to confirm (Q86)" of `TODO/PROGRESS.md`.
