# Security

podssh is pre-alpha software. Do not rely on it to protect anything yet.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on this repository. Please do not open a public issue for a
security problem.

## What the relay can see and do

The relay is in the middle of every connection, so it matters what it learns:

- the target host and port, the timing and volume of traffic, and the
  plaintext start of the SSH connection (the version strings and the key
  exchange offer);
- after the key exchange, only ciphertext;
- it can drop, delay or inject frames. SSH's integrity check covers the
  connection only after the key exchange, which is why the strict key exchange
  (the fix for Terrapin, CVE-2023-48795) matters with a relay in the path.

What makes a relay in the middle safe is **host-key verification**: podssh
refuses an unknown key unless you accept it, always refuses a changed key, and
has no option to skip the check. The relay's own document stopped calling the
path "end-to-end encrypted" in its r2 revision.

## Design rules

These are rules the code follows or must follow; each says which.

- **TLS to the relay is verified** against trusted roots and the relay's
  hostname, with no bypass. (Implemented.)
- **Credentials stay out of sight.** Relay tokens and keys never appear in
  output, logs, URLs or command lines. A derived `Debug` on a struct that holds
  a header map prints the token, so such types are opaque; redaction removes
  the whole token, never down to a prefix such as `ephm1.`. On Windows, a
  file mode of 0600 does nothing; the protection there is the profile
  directory's ACL. (Implemented for the relay token.)
- **Peer text is made safe before it reaches a terminal.** Close reasons, HTTP
  error bodies, SSH banners and disconnect messages, keyboard-interactive
  prompts and IRC text can carry ESC, BEL or a bare CR, which repaint the line,
  ring or overwrite. One shared function strips them; a sibling project ended
  up with two that diverged.
- **`known_hosts` is read the way OpenSSH reads it.** Hashed hosts use
  HMAC-SHA1 keyed with the decoded salt. `@revoked` and `@cert-authority` are
  markers, not key types, and a revoked key is refused, never treated as
  unknown. A bad line is skipped and keeps its line number; the line reported
  is the one that matched. Keys are recorded under the target host, never the
  relay's name. A changed key is never replaced automatically: podssh prints
  the file, the line and both fingerprints.
- **Nothing listens.** podssh opens outbound connections only, and never
  executes anything it receives over chat. `podssh doctor` is the one place
  that binds a socket, to learn whether the host allows it; it closes the
  socket without listening.

## Known gaps

Tracked in [docs/audit-2026-10-08.md](docs/audit-2026-10-08.md) and
[docs/ROADMAP.md](docs/ROADMAP.md):

- The native SSH client (`podssh ssh`) is not finished. The earlier
  hand-written implementation in `crates/podssh-core/src/ssh` has no strict
  key exchange and known wire-level bugs; it is being replaced by `russh` and
  is not connected to any command.
- The IRC client talks to public servers in plaintext through the relay.
- The WebSocket layer's diagnostic certificate printer (`PrintChain`, which
  accepts any certificate) is still a public library export.
