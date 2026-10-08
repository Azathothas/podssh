# Command line

`podssh ssh` takes OpenSSH's command line, so it can replace `ssh` in scripts
and in an agent's habits. The OpenSSH facts below were measured against
OpenSSH 10.3p1 with `ssh -G` (2026-10-02) unless a line says otherwise.

## Options

- **`-P` means a different thing per command.** On `ssh` it is a tag:
  `ssh -G -P mytag x` prints `tag mytag`, and `-P2222` leaves port 22 and sets
  tag 2222. `scp` and `sftp` both list `[-P port]`. So `podssh ssh -P TAG` is
  accepted, ignored, and says on stderr that `-p` is the port; on `cp`, `mv`,
  `scp` and `sftp`, `-P` is the port.
- **No option is dropped silently.** An unknown flag is an error that names the
  nearest real flag (exit 64). OpenSSH exits 255 with `Bad configuration
  option` for an unknown `-o` keyword, before connecting. With that check
  removed, `--StrictHostKeyChekcing=no` was once silently ignored and podssh
  exited 0.
- **Destinations.** `-J a,b` chains hops; `-J a -J b` is an error.
  `ssh host:2222` dials a host literally named `host:2222` on port 22;
  OpenSSH's port form is `ssh://user@host:2222`. podssh also accepts
  `host:PORT` (a host name cannot contain `:`; IPv6 literals need brackets),
  because its own "did you mean" message suggests that form.
- `-N` on its own is valid. `-W HOST:PORT` is a stdio forward (no session,
  exit on forward failure). `-V` prints the version without connecting.
- Every OpenSSH flag gets either support or a refusal by name: `-l`, `-A`,
  `-C`, `-B`/`-b`, `-e`, `-c`, `-m`, `-X`/`-Y`, `-O` and `-E` included.

## Forwarding

- `-L` and `-D` need a local listener, so they are refused. The `-L` refusal
  points to `-W HOST:PORT`; for `-D` that is only a partial answer, because a
  SOCKS proxy serves many connections and `-W` serves one.
- `-R` is compatible with "never listen": the server listens and podssh dials
  out for each connection. It is not implemented yet, and its refusal must not
  claim that podssh never binds. On the measured sandbox a dial back to
  loopback is refused, so `-R` will have to go through the proxy or fail with
  a clear message.
- When a server refuses `tcpip-forward`, podssh passes its reason on.
- Agent forwarding (`-A`) is out of scope.

## A bare word with no subcommand

`podssh example.org` never connects. The suggestion is chosen in two steps:
first the shape (`@`, `.` or `:` means `Try: podssh ssh <word>`), then edit
distance with an absolute threshold and a shared two-letter prefix. Distance
alone suggests `doctor` for `example.org` and `cp` for `xz`.

## Exit status

`podssh ssh`:

- the remote command's exit status, unchanged (0 and 127 included);
- 128 + the signal number when the remote command was killed by a signal
  (`kill -TERM $$` gives 143). OpenSSH gives 255 there; podssh says which
  signal, on stderr;
- 255 for podssh's own failures, as OpenSSH: connection, host key,
  authentication, and a session that ends with no exit status;
- 64 for a usage error, before anything is attempted.

A closed stdout (EPIPE) ends the session cleanly. `podssh proxy` is not an SSH
client and uses sysexits codes (64–78) for its own failures.

## Prompts and timeouts

- Prompts (host key, passphrase, password, keyboard-interactive) go to the
  controlling terminal, as OpenSSH does, so `echo x | podssh ssh host cat`
  can still ask for a password. `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE` works
  as in OpenSSH.
- With no terminal and no askpass, a prompt is a refusal that names the
  remedy: for an unknown host key, its fingerprint and
  `-o StrictHostKeyChecking=accept-new`; for a password, a key file.
  `-o BatchMode=yes` turns every prompt into that refusal.
- A changed host key is refused even on a terminal.
- Durations are parsed as a whole string: dropssh read `30x` with `atoi`, got
  0, and silently disabled its timeout. A timeout bounds the whole operation,
  not just the dial.

## `ssh_config` (milestone 7)

OpenSSH's rules, measured with `ssh -G`:

- the first value obtained wins, reading top to bottom (not the most specific
  block);
- a negated pattern only excludes the host from that one block;
- `IdentityFile` and `-i` add up rather than replace;
- `Include` is expanded where it appears, globs sorted; a relative `Include`
  resolves against `~/.ssh` (user file) or `/etc/ssh` (system file), not the
  including file's directory;
- `*` matches across dots;
- `Match` never overrides a value already set; podssh refuses `Match` by name
  rather than skipping it, because it can change which host is dialled;
- a missing `-F` file is fatal (255), and `-F` stops every other config file
  from being read; a missing `~/.ssh/config` is fine.

`ssh2-config` 0.8.1 silently drops `ProxyCommand` and `StrictHostKeyChecking`
under its recommended parsing mode (read 2026-10-01), so it is not a shortcut.
