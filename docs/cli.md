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

## `podssh doctor`

`podssh doctor` reports what this host allows and whether the relay path
works, measured rather than assumed. It takes the relay settings `ssh` and
`proxy` take (`--relay-host`, `--relay-addr`, `--ca-file` and their
environment variables), so it checks the path they would use. Each line is
`ok`, `FAIL` or `????`, the thing checked, and what was found or opened:

- **this host**: the user database entry, where host keys are recorded, the
  token cache, `/proc`, a pty, binding AF_INET and AF_UNIX sockets (closed at
  once, never listening), which directories programs can run from (a copy of
  podssh is run from each), and the terminal;
- **egress**: the proxy setting (credentials never shown), the TLS provider
  and trust store, what the proxy lets through (`CONNECT` to the relay and to
  `github.com` on 443 and 22) or, with no proxy, whether port 22 is open
  directly, the system resolver, and DNS over HTTPS;
- **relay**: each relay host's `/health` over verified TLS, with the address
  actually opened; a token (never shown); a forward session to
  `github.com:22`, identified by GitHub's published host key; and this
  host's clock against the relay's.

A condition podssh is built for (no listener, no pty, no user database
entry, no DNS) is a fact and reads `ok`. `FAIL` means something podssh or one
of its fallbacks needs is broken: an unusable proxy setting, nowhere to
record host keys, a relay host that does not answer, no token, a forward
session that fails or meets the wrong host key, a clock more than an hour
off. `????` is a check that could not run: never counted as passing, and
never a reason for the run to fail.

The report goes to stdout. Exit status: 0 when no check failed, 1 when one
did, 64 for a usage error. With `PODSSH_OFFLINE` set nothing connects, and
the network checks are one `????` line.

## `podssh keygen`

`podssh keygen` (also spelled `podssh ssh-keygen`) makes a key pair on a host
with no `ssh-keygen`, or none that runs: OpenSSH's refuses to run without a
user database entry. It takes the flags scripts use, `-t ed25519|ecdsa|rsa`,
`-b`, `-f`, `-C`, `-N ''` and `-q`, writes OpenSSH's own formats (the private
key mode 0600 and never over an existing file, the public key to `FILE.pub`),
and prints the SHA-256 fingerprint. `-y -f FILE` prints a private key's public
key and `-l -f FILE` the line `ssh-keygen -l` prints.

- The default is Ed25519 in `~/.ssh/id_ed25519`; ECDSA is P-256 unless `-b`
  says 384 or 521; RSA is 3072 bits unless `-b` says 2048 to 16384. DSA is
  refused (OpenSSH 10 removed it).
- A passphrase is asked for, twice, on the terminal or through
  `SSH_ASKPASS`. `-N ''` makes a key without one. A passphrase given with
  `-N` is refused (exit 64), because every process on the host can read a
  command line; with no terminal and no `SSH_ASKPASS`, podssh refuses and
  names `-N ''` rather than wait.
- The comment defaults to `USER@HOST` from the environment, never from the
  user database.

Exit status: 0, 1 when a key could not be made or read (as `ssh-keygen`), 64
for a usage error. Measured against OpenSSH in the interop harness: its
`ssh-keygen -y` reads every key podssh makes (Ed25519, ECDSA P-384, RSA 3072,
and one encrypted with a passphrase), its `ssh-keygen -l` prints the same
line, and `sshd` accepts each for login.

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
