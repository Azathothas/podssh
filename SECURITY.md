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

Between two podssh ends (a node and its operator, on either road), each
session runs the end-to-end channel (T-088): Noise XX above the resumable
layer. The relay then sees the layer's records (offsets, acknowledgements,
heartbeats), ciphertext, and the time and the volume. It can still drop,
delay, repeat or change a frame, but each such fault ends the session: it
cannot read a byte, or change one unseen. `--no-e2e`, given at both ends,
turns the channel off.

The host-key check makes a relay in the middle safe:

- podssh refuses an unknown host key unless you accept it;
- podssh always refuses a changed host key;
- podssh has no option that skips the check.

## Design rules

Each rule is implemented.

- **TLS to the relay is verified** against trusted roots and against the
  relay's host name, with TLS 1.3, or TLS 1.2 with ECDHE and an AEAD for a
  proxy that intercepts TLS (T-067); a server that speaks 1.3 cannot be
  forced down to 1.2. There is no option that skips the verification, and no
  crate carries a verifier that accepts each certificate: a test scans the
  source of each one (T-065). The verifier that prints a chain for a
  diagnosis lives in an example of `podssh-ws`, outside each library.
- **An update is checked before it is written** (T-375). `podssh update`
  runs only when asked, and no other command looks for a release. Before it
  writes a byte, it checks the release's `SHA256SUMS` against the signature
  that the release workflow made with Sigstore: the leaf certificate that
  Fulcio gave `release.yml` of this repository at that tag, by Sigstore's
  roots compiled into podssh, and Rekor's signed record of the signature,
  with no other network; then the binary's SHA-256 against its line. TLS to
  GitHub carries no part of this trust: a proxy that reads the traffic can
  hold a release back, and cannot change one. It never goes to an older
  release than the running one unless `--version` names it, and a failure
  leaves the old binary as it was.
- **Credentials are not shown.** A relay token, a tailnet auth key or a key
  never goes into output, logs, URLs or command lines. The types that hold a
  token or the tailnet key do not print it, and clear it from memory when
  they drop it; a redaction removes the whole token. `podssh keygen` refuses
  a passphrase on the command line, and never prints a private key. The
  report of a failure that the program of `PODSSH_ERROR_PROGRAM` gets
  (T-195) holds podssh's own messages only, each through a mask that hides
  the value of each credential and proxy variable and the user and password
  of each URL; the program gets no credential variable in its environment.
- **A cloud's road takes the user's account from a file, and EICE's URL
  is the one URL that carries a credential** (T-351). `iap://` reads a
  token, or the key of a service account, from the file of
  `PODSSH_IAP_TOKEN_FILE` or `GOOGLE_APPLICATION_CREDENTIALS`, and `eice://`
  a credential of AWS from the file of `PODSSH_EICE_CREDENTIALS_FILE`,
  `AWS_SHARED_CREDENTIALS_FILE` or `~/.aws/credentials`: each file is refused
  when another user may read it, as a pair file is, and only its path goes
  in a variable. A service account's key signs its JWT through aws-lc-rs,
  never through `rsa`, and its token comes from `oauth2.googleapis.com`
  alone (a key that names another token endpoint is refused), through the
  same proxy and the same trust as the tunnel. IAP's token goes in the
  upgrade's `Authorization` header alone. EICE's URL is presigned with SigV4,
  as AWS's own client presigns it, and so carries the key's id, the
  signature and a temporary key's token: the one exception to the rule
  above, by the operator's ruling Q51. podssh signs a new one for each
  connection once TLS is up, good for 60 s, keeps it in memory that is
  wiped, never prints or logs it, and takes each part of it, and of the
  credential, out of an answer that quotes it. Google and AWS end the TLS,
  so they see what the relay sees: the target, the time and the volume,
  and the start of SSH before its key exchange.
- **On Windows, the owner and the access list of a private file are
  checked** (T-274), as OpenSSH for Windows checks them: the owner is the
  user, SYSTEM, the Administrators or TrustedInstaller, and a file that
  another principal may change is refused, `~/.ssh/config` and each file
  that it includes among them. A file of the cache, a key and a pair file
  are refused when another principal may read them too. Unlike OpenSSH
  10.0p2, the right to change the access list counts as a write. podssh
  makes its own files and directories, and the keys of `podssh keygen`
  (T-288), with an access list of their own, which lets in the user, SYSTEM
  and the Administrators alone, whatever the directory above them lets in;
  a key's `.pub` also lets Everyone read it.
- **Text from a peer is made safe before it goes to a terminal.** Close
  reasons, HTTP error bodies, SSH banners and disconnect messages,
  keyboard-interactive prompts, chat messages and IRC text can contain ESC,
  BEL or a bare CR. One shared function removes them.
- **`known_hosts` is read as OpenSSH reads it.** Hashed host names use
  HMAC-SHA1 with the decoded salt. `@revoked` and `@cert-authority` are
  markers, not key types. A revoked key is refused. A host that a
  `@cert-authority` line names is asked for a certificate, which is checked
  as OpenSSH checks it (T-027): the CA, the signature, the validity window,
  the type, the principal and the critical options; it is accepted with no
  record, and a certificate from a CA that no line names is checked as its
  plain key. A CA line never makes a plain key known. A bad line is skipped.
  The message gives the line that matched. A key is recorded under the
  target host, never under the relay's name. A changed key is never replaced
  automatically: podssh gives the file, the line and both fingerprints.
- **Nothing listens unless the user asks.** podssh opens outbound
  connections only, except `podssh pipe` with `unix-listen:`,
  `tcp-listen:`, `ws-listen:` (T-368: a WebSocket server, which refuses a
  browser's request, one with an `Origin`) or `http-listen:` (T-367: an HTTP CONNECT proxy, which on
  an address that is not loopback takes only the clients that give a
  credential of its private file, compared in constant time, and dials
  nothing for another), `podssh ssh` with `-L` or `-D` (T-038) and the control
  socket of `-M` (T-039), which the user names, and `podssh agent` and
  `podssh session start`, which the user starts (T-034, T-186): each listener
  is made before anything connects, and refuses the run when it cannot be;
  a port of `-L` or `-D` with no address is loopback only; a Unix socket
  is made mode 0600 (the agent's in a new directory of mode 0700, a
  session's in a directory of mode 0700 of the cache) and takes only
  programs of the same user, a named
  pipe on Windows only processes of the same user, a TCP port takes each
  local user (and other hosts when its address is not loopback), podssh
  says so, and `PODSSH_LISTEN=no` turns listening off. The agent's keys
  live in its memory only. It never executes something that
  it receives over chat. `podssh doctor` binds a socket to test whether the
  host allows a bind and a listen, listens once with a backlog of 1 on
  127.0.0.1 and on a socket file of mode 0600, accepts nothing, and closes it
  at once; with `PODSSH_LISTEN=no` it does not listen. The iroh road, in a
  build with the feature `iroh`, keeps UDP for its direct paths only after
  a datagram came back from its home relay (T-359); with no UDP, its relay carries each byte, and a peer
  is accepted only with the ALPN of podssh's sessions. A node whose TARGET
  is `udp:HOST:PORT` (T-168) sends UDP from its host, one socket of port 0
  for each flow, connected to the target, after a probe; the client of
  such a node, `podssh pipe udp:node:NAME`, sends no UDP and binds nothing.
- **A session's socket types into its shell** (T-186). `podssh session`
  keeps an SSH session with a pty in a podssh of its own, for an agent's
  later calls: each program that runs as this user can type into that
  session and read its screen, as it can use the user's keys. So its
  socket is this user's alone, as above, and never TCP, whose peer's user
  cannot be read. No key, password or token crosses it: the session's
  podssh logs in as `podssh ssh` would, and a request carries text to type.
  `send` with no text reads a password from stdin, so that no command line
  holds it.
- **Each end of a road between two podssh ends proves its key** (T-087).
  A node has one Ed25519 key for each label and a client one for each user,
  in the private files of the cache, the same on each road; a key is shown
  by its SHA256 fingerprint, as OpenSSH shows one. The channel's Noise key
  is derived from the key and signed by it, so the handshake proves the key
  itself. An operator pins a node's key at its first sight (`known-nodes`)
  and refuses a key that differs, with both fingerprints, the file and the
  line; it never replaces a pin. `--node-key` and an iroh ticket name the
  key instead. The operator checks the node's key before it proves its
  own. A node with `--allow` lets in only the keys of its allowlist, read
  for each session, and dials its target only after it let the key in. No
  end falls back to plain text: one with the channel refuses a peer
  without it.
- **`podssh ssh --upgrade` copies nothing to the server, and its token
  crosses the relay only inside SSH** (T-167). It runs a podssh that is on
  the server already, after `podssh --version` found one. The temporary
  node's line, with its pair's connect token, comes back on that command's
  stdout, in the SSH channel; the token is on no argv, in no file and in no
  log. The node lets in the client key that the command names alone, and
  the client checks the node's key of the line in the end-to-end channel,
  then the server's host key under the destination's own name.
- **Chat writes a file only once the user accepts it, and runs nothing**
  (T-099). `podssh chat` always runs the end-to-end channel, so the relay
  reads no message and no file. A file goes under a temporary name into the
  directory that the user chose, is checked against the SHA-256 of its
  offer, and takes its name only then, never over a file that is there; its
  name is the last part of the offered one, so it never goes out of that
  directory. The lines that wait for a peer stay in memory, never on disk.
- **A node of the iroh road lets in only the keys of its allowlist.** Its
  ticket is an address, not a credential, so it may go on a command line.
  Each end's key is its identity, in a private file that podssh makes once
  and never replaces; a key file that is a symbolic link, another user's,
  or readable by others is refused with the reason. podssh shows a key by
  its public half only. The node reads its allowlist for each connection,
  refuses an allowlist that others can change, and closes a refused
  connection before any stream, so a refused client never reaches TARGET.
- **podssh signs nothing and makes no key with the `rsa` crate.** Its
  private-key operations are not constant-time (RUSTSEC-2023-0071, the
  Marvin attack; no fixed version). An RSA user key signs each login through
  aws-lc-rs, whose RSA is constant-time, never with SHA-1, at 2048 to 8192
  bits; `podssh keygen -t rsa` makes its key there; and `podssh agent` keeps
  no RSA key, as russh's agent server would sign with it through `rsa`. A
  test reads the source for each way back (T-257). The `rsa` crate stays for
  the check of a server's RSA certificate, with the public key only, and in
  russh's reader of an RSA key in a PEM or PKCS#8 file, which computes with
  the key once, as it reads it.
- **Old schemes are read, never written.** A key file encrypted as OpenSSL
  encrypts a PEM key (its key from MD5 of the passphrase, AES or Triple DES
  in CBC mode), or as OpenSSH's `ssh-keygen -m PKCS8` encrypts it (PBKDF2
  with HMAC-SHA1), is opened so that it can be used or rewritten (T-287):
  `podssh keygen -p` writes it in the format of OpenSSH, with bcrypt-pbkdf
  and AES-256-CTR. podssh writes no key in an old scheme.
- **A channel that podssh did not ask for is refused.** A server can open
  channels toward the client (`forwarded-tcpip`, agent, X11, `session`,
  `direct-tcpip` and the two streamlocal kinds). podssh refuses each that
  it did not ask for with "administratively prohibited", as OpenSSH does,
  and warns about an agent or X11 channel. A feature that asks for one kind
  (`-R`, `-A`, `-X`) accepts only that kind, for its own requests, and reads
  an accepted channel at once or closes it: a channel kept unread would stop
  the whole session. `-X` and `-Y` give the server a spoofed cookie; the
  real one never leaves this host, and replaces the spoofed one in the first
  packet of each X11 channel (T-037).

- A run that `--detach` or `-f` sends to the background (T-380) is this
  program started again, with no other program: it closes each descriptor
  that it inherited, keeps the caller's terminal only until it is ready,
  and writes its log in the cache (mode 0600, in a directory of mode
  0700). It touches no variable by which a CI finds a job's processes
  (`RUNNER_TRACKING_ID`, `BUILD_ID`, `JENKINS_NODE_COOKIE`): a tunnel that
  outlived a shared runner's job would be a way back into another's
  network, and the user asked to outlive the caller, not the job.

## Known gaps

The open defects are entries in [TODO/INDEX.md](TODO/INDEX.md). These affect
security:

- Over IRC (`podssh chat --irc`, T-252), the server and each user of the
  channel read the messages: IRC has no end-to-end channel. TLS inside the
  relay stream is the default, so the relay sees only TLS; `--irc-plaintext`
  sends plain text, which the relay and each server read, and podssh says
  so. Between two podssh ends, chat runs the end-to-end channel (T-099).
- The first session to a node trusts the key that answers (trust on first
  use): a relay in the middle of that first session could have its own key
  pinned. Compare the fingerprint that the node says as it starts, or give
  it with `--node-key`; an iroh ticket names the key (T-087).
- The end-to-end channel is podssh's own framing over the `snow` crate. No
  third party has audited it (T-088).
- With `-A` (T-036), the server, and root on it, can use each key of the
  agent while the session lasts, as with OpenSSH. podssh binds the
  forwarded agent to the server's host key (`session-bind@openssh.com`,
  T-279), as OpenSSH does, so an OpenSSH agent keeps from the server each
  key that `ssh-add -h` limits to other hosts. An agent that knows no such
  limit (Pageant, `podssh agent`) refuses the bind and serves each key.
  Agent forwarding is off unless asked for.
