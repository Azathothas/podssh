# Security

podssh is beta software. No third party has audited it.

## Report a vulnerability

Use the private vulnerability report of GitHub: **Security**, then **Report
a vulnerability**, on this repository. Do not open a public issue for a
security problem.

## Advisories of the dependencies

CI reads the dependencies against the RustSec advisories on each push and
each day (`deny.toml`, `.github/workflows/deny.yml`). On an advisory:
update the crate when a fixed version exists, and say in the release notes
which release carries the fix. When no fixed version exists, read whether
podssh reaches the affected code; ignore the advisory only with its reason
and the date, in `deny.toml`. A vulnerability that podssh reaches keeps an
entry in `TODO/` until it is fixed.

## What the relay can see and do

The relay is between podssh and the server in every connection. The relay
can see:

- the target host and port;
- the time and the volume of the traffic;
- the start of the SSH connection before the key exchange: the version
  strings and the key-exchange offers.

After the key exchange, the relay sees only ciphertext.

The relay can drop, delay or add frames. The integrity check of SSH starts
only after the key exchange. Thus the strict key exchange (the fix for
Terrapin, CVE-2023-48795) is important when a relay is in the path. russh
uses it.

The host-key check makes a relay in the middle safe:

- podssh refuses an unknown host key unless you accept it;
- podssh always refuses a changed host key;
- podssh has no option that skips the check.

## Design rules

Each rule is implemented.

- **TLS to the relay is verified** against trusted roots and against the
  relay's host name. There is no option that skips the verification, and no
  crate carries a verifier that accepts each certificate: a test scans the
  source of each one (T-065). The verifier that prints a chain for a
  diagnosis lives in an example of `podssh-ws`, outside each library.
- **Credentials are not shown.** A relay token or a key never goes into
  output, logs, URLs or command lines. The types that hold a token do not
  print it, and a redaction removes the whole token. `podssh keygen` refuses
  a passphrase on the command line, and never prints a private key.
- **On Windows, a file mode of 0600 has no effect.** The access control list
  of the profile directory protects the token cache and the keys.
- **Text from a peer is made safe before it goes to a terminal.** Close
  reasons, HTTP error bodies, SSH banners and disconnect messages,
  keyboard-interactive prompts and IRC text can contain ESC, BEL or a bare
  CR. One shared function removes them.
- **`known_hosts` is read as OpenSSH reads it.** Hashed host names use
  HMAC-SHA1 with the decoded salt. `@revoked` and `@cert-authority` are
  markers, not key types. A revoked key is refused. A bad line is skipped.
  The message gives the line that matched. A key is recorded under the
  target host, never under the relay's name. A changed key is never replaced
  automatically: podssh gives the file, the line and both fingerprints.
- **Nothing listens unless the user asks.** podssh opens outbound
  connections only, except `podssh pipe` with `unix-listen:` or
  `tcp-listen:`, which the user names: a Unix socket is made mode 0600 and
  takes only programs of the same user, a TCP port takes each local user
  (and other hosts when its address is not loopback), podssh says so, and
  `PODSSH_LISTEN=no` turns listening off. It never executes something that
  it receives over chat. `podssh doctor` binds a socket to test whether the
  host allows a bind, and closes it without listening. The iroh road, in a
  build with the feature `iroh`, binds UDP for its direct paths only after
  a probe allows it; with no UDP, its relay carries each byte, and a peer
  is accepted only with the ALPN of podssh's sessions.
- **A node of the iroh road lets in only the keys of its allowlist.** Its
  ticket is an address, not a credential, so it may go on a command line.
  Each end's key is its identity, in a private file that podssh makes once
  and never replaces; a key file that is a symbolic link, another user's,
  or readable by others is refused with the reason. podssh shows a key by
  its public half only. The node reads its allowlist for each connection,
  refuses an allowlist that others can change, and closes a refused
  connection before any stream, so a refused client never reaches TARGET.
- **A channel that podssh did not ask for is refused.** A server can open
  channels toward the client (`forwarded-tcpip`, agent, X11, `session`,
  `direct-tcpip` and the two streamlocal kinds). podssh asks for none, so
  it refuses each with "administratively prohibited", as OpenSSH does, and
  warns about an agent or X11 channel. A feature that asks for one kind
  (`-R`, `-A`, `-X`) accepts only that kind, for its own requests, and reads
  an accepted channel at once or closes it: a channel kept unread would stop
  the whole session.

## Known gaps

The open defects are entries in [TODO/INDEX.md](TODO/INDEX.md). These affect
security:

- podssh offers no host certificate algorithm, so a server shows its plain
  key. podssh does not use `@cert-authority` lines: a host that only such a
  line trusts is an unknown host (T-027, [TODO/ssh.md](TODO/ssh.md)).
- A signature with an RSA user key, and an RSA key that `podssh keygen`
  makes, use the `rsa` crate, whose private-key operations are not
  constant-time (RUSTSEC-2023-0071, the Marvin attack; no fixed version). The
  default key, Ed25519, and ECDSA keys do not use it, and an agent keeps the
  key in its own process (T-257, [TODO/ssh.md](TODO/ssh.md)). The check of a
  server's RSA certificate uses only the public key.
- The IRC client sends plain text through the relay. No command uses it yet.
