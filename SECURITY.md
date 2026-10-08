# Security

podssh is beta software. No third party has audited it.

## Report a vulnerability

Use the private vulnerability report of GitHub: **Security**, then **Report
a vulnerability**, on this repository. Do not open a public issue for a
security problem.

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
  relay's host name. There is no option that skips the verification.
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
- **Nothing listens.** podssh opens outbound connections only. It never
  executes something that it receives over chat. `podssh doctor` is the only
  part that binds a socket: it tests whether the host allows a bind, and
  closes the socket without listening.

## Known gaps

The open defects are entries in [TODO/INDEX.md](TODO/INDEX.md). These affect
security:

- podssh offers no host certificate algorithm, so a server shows its plain
  key. podssh does not use `@cert-authority` lines: a host that only such a
  line trusts is an unknown host (T-027, [TODO/ssh.md](TODO/ssh.md)).
- The IRC client sends plain text through the relay. No command uses it yet.
- `PrintChain` in `podssh-ws`, a certificate verifier that accepts every
  certificate, is a public export of the library (T-065, [TODO/ws.md](TODO/ws.md)).
  No command uses it.
