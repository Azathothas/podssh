# Command line

This page tells how the commands of podssh read their arguments, what they
print, and their exit codes. `podssh ssh` takes the command line of OpenSSH,
so it can replace `ssh` in scripts. The facts about OpenSSH on this page were
measured with OpenSSH 10.3p1 and `ssh -G`, unless a line gives another
source.

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
- Each flag of OpenSSH is supported or refused by name, including `-l`,
  `-A`, `-C`, `-B` and `-b`, `-e`, `-c`, `-m`, `-X` and `-Y`, `-O` and `-E`.

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

`podssh doctor` tells what this host allows and whether the relay path
works. It takes the relay settings of `ssh` and `proxy` (`--relay-host`,
`--relay-addr`, `--ca-file` and their environment variables), so it checks
the path that they use. Each line has `ok`, `FAIL` or `????`, the thing
checked, and what was found or opened.

- **This host:** the user database entry, where host keys are recorded, the
  token cache, `/proc`, a pty, a bind of AF_INET and AF_UNIX sockets (closed
  at once, never listening), which directories can run programs (a copy of
  podssh runs from each), and the terminal.
- **Egress:** the proxy setting (credentials never shown), the TLS provider
  and the trust store, what the proxy allows (`CONNECT` to the relay and to
  `github.com` on ports 443 and 22) or, with no proxy, whether port 22 is
  open directly, the system resolver, and DNS over HTTPS.
- **Relay:** the `/health` of each relay host over verified TLS, with the
  address opened; a token (never shown); a forward session to
  `github.com:22`, identified by GitHub's published host key; and the clock
  of this host against the relay's.

The results:

- `ok`: the check ran and podssh can work with the result. A condition that
  podssh is made for (no listener, no pty, no user database entry, no DNS)
  is a fact and gives `ok`.
- `FAIL`: something that podssh or one of its fallbacks needs is broken: a
  proxy setting that cannot be used, no place to record host keys, a relay
  host that does not answer, no token, a forward session that fails or
  meets the wrong host key, or a clock more than one hour wrong.
- `????`: the check could not run. It never counts as `ok`, and it never
  makes the run fail.

The report goes to stdout. The exit code is 0 when no check failed, 1 when a
check failed, and 64 for a usage error. When `PODSSH_OFFLINE` is set, nothing
connects, and the network checks are one `????` line.

## `podssh keygen`

`podssh keygen` (also `podssh ssh-keygen`) makes a key pair on a host that
has no `ssh-keygen`, or a `ssh-keygen` that does not run. The `ssh-keygen` of
OpenSSH does not run without a user database entry.

- Flags: `-t ed25519|ecdsa|rsa`, `-b`, `-f`, `-C`, `-N ''` and `-q`.
  `-y -f FILE` prints the public key of a private key. `-l -f FILE` prints
  the line that `ssh-keygen -l` prints.
- The output is in the formats of OpenSSH. The private key has mode 0600 and
  is never written over an existing file. The public key goes to `FILE.pub`.
  The command prints the SHA-256 fingerprint.
- The default is Ed25519 in `~/.ssh/id_ed25519`. ECDSA is P-256 unless `-b`
  gives 384 or 521. RSA is 3072 bits unless `-b` gives 2048 to 16384. DSA is
  refused, because OpenSSH 10 removed it.
- podssh asks for a passphrase two times, on the terminal or through
  `SSH_ASKPASS`. `-N ''` makes a key with no passphrase.
- A passphrase given with `-N` is refused (exit 64), because each process on
  the host can read a command line.
- With no terminal and no `SSH_ASKPASS`, podssh refuses at once and names
  `-N ''`. It does not wait.
- The comment is `USER@HOST` from the environment, never from the user
  database.

The exit code is 0, 1 when a key cannot be made or read (as `ssh-keygen`),
and 64 for a usage error.

## Exit codes

| Command | Exit code | Meaning |
| --- | --- | --- |
| `podssh ssh` | the remote status | The remote command's exit status, unchanged (0 and 127 included) |
| `podssh ssh` | 128 + the signal number | A signal stopped the remote command (`kill -TERM $$` gives 143). OpenSSH gives 255; podssh names the signal on stderr. |
| `podssh ssh` | 255 | A failure of podssh, as with OpenSSH: the connection, the host key, the authentication, or a session that ends with no exit status |
| each command | 64 | A usage error, before podssh does anything |
| `podssh proxy` | sysexits (64 to 78) | A failure of podssh. `proxy` is not an SSH client. |
| `podssh doctor` | 0 or 1 | 1 when a check failed |
| `podssh keygen` | 0 or 1 | 1 when a key cannot be made or read |
| a command that is not implemented | 70 | The command refuses |

A closed stdout (EPIPE) ends the session cleanly.

## Prompts and time limits

- Prompts (host key, passphrase, password, keyboard-interactive) go to the
  controlling terminal, as with OpenSSH. Thus
  `echo x | podssh ssh host cat` can still ask for a password.
  `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE` works as in OpenSSH.
- With no terminal and no askpass program, a prompt becomes a refusal that
  names the remedy. For an unknown host key: its fingerprint and
  `-o StrictHostKeyChecking=accept-new`. For a password: a key file.
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
