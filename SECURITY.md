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

A net of the user's own nodes (`podssh net`, T-429) is a document that the
owner's OpenSSH key signs (SSHSIG, namespace `podssh-net`). An end trusts
the owner of the first document that its user takes, and then takes only
documents of that owner with a higher serial and an end still to come; no
server and no relay vouches for one. Two ends of the net pass the newer
document inside the channel, to a member only, so the relay sees no more
than a word in clear that both ends read documents. A node of the net lets
in each member that the document held names: whoever holds the owner's
private key decides who reaches the user's nodes, so that key is kept as a
login key is; a removed member is refused by each node that holds the newer
document, and a document that ended lets nobody in by the net.

An exit node (`podssh node --exit`, T-431) lends its host's egress: it dials,
from its own host, a target that a member of its net names inside the
channel, so the relay sees neither the target nor a byte. It lets out only
the members of a net that gives the node the role `exit`, as the net's
policy lets each (`exit:NODE`, or an address of a range), never a key of
`--allow` nor an operator of the pair's connect token alone. It resolves
each name itself and dials the addresses that it checked, never the name
again, so a name that resolves anew elsewhere (DNS rebinding) reaches
nothing unchecked; a private, loopback, link-local or other non-public
address, the ranges that the relay refuses, is dialled only inside a range
of the node's `--routes`. A loopback address, or one of the exit's own host,
is dialled only where a range names that one address (T-432), so a wide range
does not hand the node's own services to the net: the host's addresses are
read before each dial, and a connection that went to the host anyway is
closed unread. `--exit auto` picks an exit by the routes that the net's signed
document lists, and the exit still checks each address against its own
`--routes` and the policy. A member that the policy lets out reaches each
public address and port from the exit's host, as through a VPN, and the
exit's owner answers for that traffic. `podssh exit --listen` serves the
exit to the programs of the client's host on a loopback address alone, as
its SOCKS takes no credentials.

A node of the OpenTunnel road (`podssh node --opentunnel`, T-530 and T-531)
keeps a tunnel of `opentunnel.xyz`, whose service gets the CSR of the
tunnel's name and never its key, which the node keeps in a private file
beside the tunnel's bearer token. TLS ends at the node: the service reads
the SNI of each visitor's ClientHello and sends the rest on, still
encrypted, so it sees the names, the times and the sizes, never the
plaintext. A tunnel's name is in the logs of Certificate Transparency, and
anyone may connect to it, so the node claims a route of 26 random letters
alone, and its door is the end-to-end channel's allowlist, `--allow` or the
net's members; it refuses to start with neither. A client checks the
node's certificate by its name, then the node's key in the channel.

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
  diagnosis lives in an example of `podssh-ws`, outside each library. The
  node of `podssh ts` adds the CA file of `PODSSH_TS_TEST_CA_FILE` to its
  roots, for a test's stand-in control server (T-334): a root more, never a
  check less, and `podssh ts` says when it is set.
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
- **A relay token crosses with no TLS on one road alone, and it is a token
  of one session** (T-326, the operator's ruling Q45). The cleartext road
  on the relay's port comes last, once each relay host failed and the TLS
  of one failed on the way, for a proxy that cuts TLS. It sends no token of
  `PODSSH_RELAY_TOKEN` or of the cache: it asks the relay for a token of one
  session, which lives minutes, is never cached, and is spent at its one
  upgrade, so a hop that read it has no second use; an answer that does not
  say so gets no upgrade. Each hop sees the target, the time and the volume,
  as the relay does, and could take that one upgrade in the client's place;
  SSH inside stays end to end, its host key checked. podssh's relay role
  serves only `/health`, that mint and that upgrade in cleartext, and
  `--cleartext no` turns it off there; `PODSSH_CLEARTEXT=no` turns it off in
  the client.
- **The cache stays in its user's own tree** (T-593, GitHub #118). On Unix
  `XDG_CACHE_HOME`, `HOME/.cache` and `XDG_RUNTIME_DIR` count only when each
  of their directories that exists, up to the home, belongs to the
  effective uid or to root; else the home of the uid's entry in
  `/etc/passwd` gives the cache. So root with the `HOME` of another account
  keeps no key or pin where that account could move or replace it, and
  makes no `.cache` there that would be closed to its owner. A key, the
  pins, a pair or a token that an earlier run kept there is still read, so
  a node keeps its identity, and the run says where it is; podssh moves
  nothing and writes nothing more there.
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
- **An agent's tools reach only what the user allowed** (T-055, T-488).
  `podssh mcp` takes the words of each call from a model, which text that
  the model read can steer. Each tool that reaches a host (`ssh_exec`,
  `health`, the `job_` tools, the copies, `session_start`) reaches only a
  host of `--allow-host`, with no prompt, a host key that `known_hosts`
  holds, no forwarding and no shared connection, which the user's `-F` file
  cannot undo. The copies have a gate of their own for this host's files:
  they are offered only with `--allow-dir DIR`, each local path is
  resolved, its links followed, and refused outside each DIR before any
  child runs, and a DIR that holds `~/.ssh` or podssh's cache is refused as
  the server starts. The session tools come only with `--allow-session`;
  the server drives only the sessions that it started and stops each as it
  ends, so that no shell stays on a host with no owner.
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
- **A grant lets one key in once, and no relay sees it** (T-226, GitHub
  #35). A grant is an OpenSSH user certificate of the operator's key, for
  one node or route, with a window and the critical option `once@podssh`,
  signed by the node's own key or by a key that the node already lets reach
  as much. It travels inside the end-to-end channel, after the operator
  checked the node's key, never in a URL, a header or a file of the relay.
  The node checks that the channel proved the certificate's key, the
  issuer, the principal, the window and each critical option, then records
  the grant as used in a private file made create-new and synced, before it
  dials: a second use, also after a restart, is refused, and a grant that
  leaks is worth nothing without its key. A node whose door is the pair's
  connect token alone says so as it starts, as whoever holds the token
  reaches a TARGET that has no login of its own; podssh's relay role makes
  a connect token of one upgrade where the pair asks for it (`relay pair
  --once`).
- **A code of the pairing is a credential for 10 minutes, and gets one
  guess** (T-086). `podssh relay pair NAME --code` shows a nameplate and
  three words of the PGP list, 24 bits of secret, on its terminal alone,
  never on stdout, in a log or in argv; `podssh relay join` reads it at a
  prompt or from a pipe. The ends run SPAKE2 keyed by the whole code over a
  mailbox, then seal each message in NaCl's SecretBox under a key of it, so
  the mailbox, a proxy or a copy of the traffic learns nothing that a
  guess offline could test. An online attacker who claims the nameplate
  gets one try: a version that does not open ends the code at both ends,
  the giver leaves after one exchange whatever its end, and a mailbox takes
  two sides of a nameplate alone; the user sees the failure, and a new code
  is a new draw. The connect token crosses inside the sealed messages only.
  The taker pins the node's key that came with the part, and the giver adds
  the taker's key to `--allow` only where the user named the file; each
  shows the other's fingerprint, for a person to compare.
- **A code of the net's invitation adds one device, and the device checks
  the owner first** (T-616). `podssh net invite NAME` and `podssh net join`
  run the pairing's exchange with its bounds: one guess for each code, 10
  minutes, the code on the owner's terminal alone. The sealed version phase
  names the kind of exchange, so a code given to the other command is told
  apart before either end says a word. The device keeps nothing, and makes
  no key, before it checked the owner: the key that `--owner` names, the
  owner of the net that it holds, or the person's `yes` at the terminal,
  with the fingerprint that the device made from the owner's key; a run
  that can ask nobody and names no owner is refused before the code is
  read, as a stranger's code would make the device a member of the
  stranger's net, and a node of the device would let the stranger's members
  in. The owner's host signs only the key that came by the code, never gives
  a member's name to another key, and keeps the new serial before it sends
  it, so a guess that wins adds one new member, which the owner's lines name
  and `podssh net rm` removes, and no device holds a serial that its owner
  lacks. The document crosses inside the sealed messages, and the device
  checks its signature, its owner, its net and its own key in it, then
  takes it by the rule of `podssh net take`.
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
  `podssh detached stop` (T-392) sends a signal only to the pid that the
  holder of a run's lock wrote, while the lock is held: a record of a run
  that ended names a pid that the system may have given to another process.
- `podssh relay serve --acme NAME` (T-447) keeps its ACME account's key and
  the certificate's key in the cache, each of mode 0600 in a directory of
  mode 0700, and refuses one that is a symbolic link, another user's, or
  readable by others: the account's key orders and revokes certificates of
  the account at that CA, and the certificate's key serves as the role. The
  certificate's key is made anew at each renewal, and kept in one file with
  its chain, replaced whole, so that no read pairs a key with another
  certificate. TLS-ALPN-01's certificate is self-signed for the one name, is
  presented only to a hello whose one protocol is `acme-tls/1`, and goes
  when its order ends; such a connection carries nothing after its
  handshake. A pair read again on SIGHUP is served only when its key is the
  key of its leaf.

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
  it with `--node-key`; an iroh ticket names the key (T-087), and so does a
  pairing by code, which pins the key before the first session (T-086).
- A pairing by code is as strong as its 24 bits against one guess for each
  code: an attacker who wins that draw (1 in 16,777,216) gets the pair's
  connect token, and its key goes into `--allow` where the giver named the
  file. The public mailboxes (Q65) can stop a pairing, never read it; a
  user who wants no third party names their own relay's mailbox.
- The end-to-end channel is podssh's own framing over the `snow` crate. No
  third party has audited it (T-088).
- The tokens of a pair on the default relay are bearer tokens for up to 72
  h: whoever holds the connect token reaches the node's door, and its
  `stop_token` ends the pair. The node's `--allow`, its net and its grants
  (T-226) hold the door behind it; a connect token of one upgrade comes from
  podssh's relay role alone, as the default relay's contract has none.
- With `-A` (T-036), the server, and root on it, can use each key of the
  agent while the session lasts, as with OpenSSH. podssh binds the
  forwarded agent to the server's host key (`session-bind@openssh.com`,
  T-279), as OpenSSH does, so an OpenSSH agent keeps from the server each
  key that `ssh-add -h` limits to other hosts. An agent that knows no such
  limit (Pageant, `podssh agent`) refuses the bind and serves each key.
  Agent forwarding is off unless asked for.
