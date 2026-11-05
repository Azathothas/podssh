# Command line

`podssh man` is the reference for each command, argument, flag, `-o`
keyword, variable, file and exit code. The binary makes it from its own
tables, so it describes that binary and no other version. This page gives
the rules behind those tables, for people and agents who change them.

`podssh ssh` takes the command line of OpenSSH, so it can replace `ssh` in
scripts. The facts about OpenSSH on this page were measured with OpenSSH
10.3p1 and `ssh -G`, unless a line gives another source.

## The manual

- **The tables.** The flags of each command are in
  `crates/podssh-cli/src/flags.rs`, their arguments in `src/positionals.rs`,
  the `-o` keywords in `src/ssh/keywords.rs`, and the variables, files, relay
  facts, exit codes, notes and examples in `src/man/`. `--help` and
  `podssh man` read the same tables.
- **Change the table with the code, in the same commit.** The tests fail
  when the manual and the code disagree: a variable that the code reads and
  the manual does not name (or the reverse), a default that `resolve` does
  not use, an `-o` keyword that the parser handles differently, an example
  that the parser refuses, or a note that names a flag that is gone.
- **Text first.** `podssh man` writes plain text, so it needs no `man`,
  groff or pager. On a terminal it pages: `PAGER`, else `less` when `PATH`
  has it and `TERM` names a terminal (not on Windows), else its own pager.
  `--no-pager` writes to stdout; with no terminal there is no pager.
- **Roff second.** `podssh man --roff` writes a man(7) page with standard
  macros only. A macro defined in the page is read differently by different
  renderers: an `Fl` macro that used `\$*` printed blank flag names under
  groff and mandoc. The gate renders the page with both
  (`scripts/interop-man.sh`).
- **Data third.** `podssh man --json` writes the tables as one JSON object
  for a program (GitHub #10): the commands with their availability,
  arguments and flags, each flag with its kind and what to type instead;
  the `-o` keywords; the variables; the files; the exit codes. It reads the
  tables, not the text, so it keeps what the text drops. `--json SECTION`
  gives one command, or the table of `environment`, `files` or
  `exit-status`; a prose topic has no JSON form (exit 64), and neither has
  `--json --roff`.
- **No setting of the host.** The manual is the same bytes in each
  environment. It never shows a token or a credential.
- **A command that does not work says so.** `--help` and the manual mark a
  command that is not implemented, or not in this build. Its own `--help`
  and its section of the manual give the same sentence, and no option but
  `--help`: the options of a command that does nothing cannot be used.

## Options of `podssh ssh`

- **`-P` has a different meaning for each command.** For `ssh`, `-P` is a
  tag: `ssh -G -P mytag x` prints `tag mytag`, and `-P2222` keeps port 22
  and sets the tag 2222. For `scp` and `sftp`, `-P` is the port. Thus
  `podssh ssh -P TAG` sets the tag that `Match tagged` reads (T-045), and a
  tag that is a number gets a note on stderr that `-p` is the port. For
  `cp`, `mv`, `scp` and `sftp`, `-P` is the port.
- **No option is dropped silently.** An unknown flag is an error that names
  the nearest real flag (exit 64). A known flag with no value names the flag,
  in both spellings, and the value that it needs (exit 64). A dropped option
  can disable a security check without a message. OpenSSH exits 255 with
  `Bad configuration option` for an unknown `-o` keyword, before it connects.
  `podssh --help COMMAND` prints the help of COMMAND; each other word after
  `--help` or `--version` is refused (exit 64).
- **The keywords of a restriction apply** (T-505, Q71). `Ciphers`, `MACs`,
  `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms` (and its
  old name `PubkeyAcceptedKeyTypes`) and `CASignatureAlgorithms` filter what
  podssh offers, read as OpenSSH 10.3p1's `kex_assemble_names`
  (`kex-names.c`) reads them: a list replaces podssh's own, one that starts
  with `+` adds to it, with `-` takes from it (a pattern of `*` and `?`
  too, and `!` there), and with `^` puts its names first. A name that
  podssh does not speak (`3des-cbc`, `umac-64@openssh.com`,
  `sntrup761x25519-sha512@openssh.com`) is left out, and `-v` says so, as
  OpenSSH filters a list by what it speaks; a list that leaves nothing is
  refused before anything connects, with what podssh speaks: 64 for `-o`,
  78 for a line of a file, whose refusal names `-o KEYWORD=LIST`, which goes
  past it. The first value of each keyword holds, on the command line or in
  a file, and a later one is not read. The lists of the command line hold
  for each hop of `-J` too. The host key algorithms that `known_hosts`
  records for the host go first within the list, also for a list that
  replaces podssh's own or one with `^`, where OpenSSH keeps the list's
  order: a key that podssh knows is never passed over for one that it does
  not (Decision of T-505). A certificate's name is asked for only of a host
  that a `@cert-authority` line names (T-027). `RequiredRSASize` is the
  least RSA key: a smaller key of the user (a file's, or an agent's) is not
  offered, and `-v` says why, and a smaller host key, or RSA key of the CA
  of a host certificate, ends the connection with 255 before any question;
  under 1024 it changes nothing, as in OpenSSH. `CASignatureAlgorithms`
  holds for a certificate of a CA that a `@cert-authority` line names for
  the host: another is checked as its plain key, as OpenSSH falls back.
  `-G` prints each list as podssh will offer it (`ciphers`, `macs`,
  `kexalgorithms`, `hostkeyalgorithms`, `pubkeyacceptedalgorithms`,
  `casignaturealgorithms`) and `requiredrsasize`, in OpenSSH's places;
  podssh's own lists are russh's, and differ from OpenSSH's on purpose.
  `-c` and `-m` are refused, and name `-o Ciphers=LIST` and `-o MACs=LIST`.
- **The other keywords of a restriction are said** (T-505). `BindAddress`,
  `BindInterface`, `CertificateFile`, `ChannelTimeout`, `IPQoS`,
  `RekeyLimit`, `SecurityKeyProvider`, `TCPKeepAlive`, `Tunnel`,
  `TunnelDevice`, `UpdateHostKeys`, `VerifyHostKeyDNS` and `WarnWeakCrypto`
  are accepted and not applied; a value that the user gave, with `-o` or in
  a file of the user's (`-F`, `PODSSH_SSH_CONFIG`, `~/.ssh/config` and what
  they include), gets one line at the default level, once for each keyword
  and run: `VerifyHostKeyDNS yes (/home/u/.ssh/config:4) is not applied:
  podssh checks host keys against known_hosts alone`. A line of the
  system's file gets it at `-v` alone, as a distribution writes that file
  for each program, and `-q` shows none. The keywords that change nothing
  that podssh does (`HashKnownHosts`, the GSSAPI ones and the others of the
  manual) get a note at `-v` that names their place:
  `/etc/ssh/ssh_config:22: HashKnownHosts has no effect in podssh`, or `-o
  HashKnownHosts has no effect in podssh`. The manual's section of `ssh`
  lists the three kinds apart.
- **Destinations.** `node://[user@]NAME` is the node of the pair under the
  label NAME (T-084), reached through the relay, with its host key recorded
  under `node://NAME`, which no DNS name can be; `node:22` is still the host
  `node` on port 22. A node has no port, and `-J`, `-W` and `--direct` do
  not go with it (exit 64). To a node, podssh sends nothing until the
  node's first bytes, 30 s at most: a node that offers the resumable layer
  greets with its first record, and `-v` says whether it did (T-151,
  `docs/design.md` section 5). With the layer, a lost link to the relay is
  replaced by a new one for as long as the node keeps the session (10
  minutes, or the node's `--resume-deadline`), and the SSH session goes on
  where it was, with one line on stderr for each loss and each resume
  (T-153). `--resume-deadline TIME` waits at most TIME, never longer than
  the node keeps the session; when the node forgot the session, as after a
  sleep of this host longer than its deadline, the line says so, with how
  long this side was away by the wall clock (T-306). `--no-resume` asks the
  node, in the layer's handshake (`once.v1`), to end the session with its
  link (T-612): a lost link ends the session, with a line, no spare link
  or move goes beside it, and the node forgets the session and its
  connection to TARGET as the link ends; `-v` says that the node took the
  ask, and a line that a node of an earlier podssh does not know it and
  keeps the session as before. A link that goes silent gets a spare link
  beside it once the node has not answered for three round trips of the
  link, 1 s to 3 s (T-663; a host that wakes from a sleep asks at once),
  and the spare resumes the session when it greets first: a new address
  costs seconds, not the 30 s after which a silent link is dead (T-305);
  `-v` says each spare link, `PODSSH_SPARE_LINKS=no` turns them off, and
  the iroh road opens none, as its QUIC moves the session by itself.
  `-J a,b` makes a chain of hops; `-J a -J b` is an error. Each hop checks
  its own host key, filed under its own name: `host`, or `[host]:port` off
  port 22 (T-030). `HostKeyAlias` names the destination's key alone, as it
  is and with no port, as OpenSSH files it. Each hop reads the blocks of
  `ssh_config` for its own name, as OpenSSH's jump host does, and logs in as
  its own `user@`, its `User`, else the local user (T-290; see
  `ssh_config`). The settings of host keys, authentication, keys and time
  of `-o` and `-i` hold for each hop too; OpenSSH applies its command line
  to the destination only (its jump process gets `-l`, `-p`, `-J`, `-F` and
  `-v`).
  Each later hop is reached on a `direct-tcpip` channel of the hop before
  it, whose open has that hop's `ConnectTimeout` (T-462, GitHub #86): a hop
  that never answers it gives "the hop HOP did not answer the open of a
  channel to DEST:PORT within N s". A channel that opened, and on which no
  byte of an SSH server came, names the hop, never a handshake of the
  destination: "the hop HOP opened its channel to DEST:PORT, and no byte
  came on it within N s: no SSH server answered behind the hop", or "and it
  closed before any byte came". `-v` says the open, and each 10 s while
  nothing came; a refusal keeps the hop's words.
  `ssh host:2222` connects to a host named `host:2222` on port 22. The port
  form of OpenSSH is `ssh://user@host:2222`. podssh also accepts `host:PORT`,
  because its own "did you mean" message gives that form. A host name cannot
  contain `:`. An IPv6 address needs brackets only before a port:
  `user@2001:db8::1` is port 22, and podssh reads the port of
  `user@[2001:db8::1]:2222` as it reads `host:PORT` (OpenSSH reads a port
  there only in the `ssh://` form). `-4` or `-6` with an address of the
  other family is refused. `podssh proxy` takes the bare address that
  OpenSSH gives for `%h`. A host that starts with `-` is refused (exit 64),
  also as `-o HostName=`, as OpenSSH refuses it. podssh reads options before
  and after the destination, as OpenSSH does, so a script that passes a host
  that it did not write puts `--` before it: `podssh ssh -- "$HOST" COMMAND`,
  `podssh proxy -- "$HOST" PORT`.
  Each host that is dialed (the destination after `HostName`, each hop of
  `-J`) is checked before anything connects, on each road, by the relay's
  rule (T-503): letters, digits, `.`, `-` and `_`, not first a `-` or a
  `.`, at most 253 characters, or an IPv4 or IPv6 address; else exit 64,
  with `--direct` too, so that no `$`, `!`, blank or `/` reaches a proxy or
  a resolver. A name beyond ASCII goes in its ASCII form (`xn--...`): a
  proxy takes a `CONNECT` in ASCII, and podssh has no IDNA of its own. An
  IPv6 address with a zone (`fe80::1%eth0`) is taken where this host dials
  it (`--direct`) or a jump host does, and refused through the relay.
  OpenSSH's own list is shorter (it takes `!`, `/` and each byte above
  127).
- `-N` alone is valid. `-W HOST:PORT` is a stdio forward: no session, and
  exit when the forward fails. `-W` takes `HOST:PORT`, `[ADDR]:PORT`, or
  `/PATH`, a Unix socket on the server (T-040), which the server opens as
  `direct-streamlocal@openssh.com`, as OpenSSH's `-W /PATH` does; through a
  control master too. A value with no port is refused, as OpenSSH refuses
  it, and so is a relative path (exit 64); a server that refuses the socket
  (`AllowStreamLocalForwarding no`) gives its reason, and 255. In Git Bash,
  `MSYS_NO_PATHCONV=1` keeps a path as it is typed. A `-J` hop keeps its own
  reading, where a host alone is port 22. `-V` prints the version and does
  not connect.
- **`cf://[user@]HOST` is a service that `cloudflared` publishes (T-264).**
  HOST is the DNS name of a tunnel's `ssh://` or `tcp://` rule. podssh opens
  the WebSocket to `wss://HOST/` that `cloudflared access tcp` opens, with
  its upgrade, through `HTTPS_PROXY` when one is set: no relay, and no
  program of Cloudflare's. A name behind Cloudflare Access needs a service
  token, `PODSSH_CF_ACCESS_CLIENT_ID` and `PODSSH_CF_ACCESS_CLIENT_SECRET`
  (both or neither), or a token that `cloudflared access token
  -app=https://HOST` made where its login runs, in `PODSSH_CF_ACCESS_TOKEN`
  or the file of `PODSSH_CF_ACCESS_TOKEN_FILE`; each goes in its header,
  never in a URL, and a bad one exits 78 (255 for `ssh`) naming the
  variable, never the value. A refusal of Access (a redirect to its login
  page, 401 or 403) names those variables and exits 77, another refusal 69.
  The host key is recorded under HOST. A tunnel has no port here; `-J`,
  `-4`, `-6`, `HostName` and `--direct` are refused (64). `-J cf://HOST`
  makes a tunnel the first hop of a chain (T-347): the run's road reaches the
  tunnel, and the hops after it, and the destination with its own port, run
  in its `direct-tcpip` channels, so a jump host whose sshd a tunnel publishes
  (`cloudflared` or `podssh node --quick-tunnel`) reaches the rest. A
  tunnel after the first hop is refused (64): a hop inside an SSH channel has
  no road to Cloudflare's edge. `podssh proxy
  cf://HOST` is the same pipe, with no PORT and no relay flag. Each message
  up is at most 16 KiB, as the origin cuts a longer one; podssh sends no
  Ping, as the origin answers one outside the lock of its writes; and the
  end of the stream, with no Close, is the end of the session.
  A podssh node behind HOST (`podssh node --quick-tunnel`, T-300) sends the
  resumable layer's `GREETING` first, where cloudflared's SSH service
  speaks SSH first: the session then runs in the layer, with the
  end-to-end channel above it, and a new WebSocket to HOST carries it after
  each lost one, as on `node://`. The node's key is the one of
  `--node-key` (the key that the node prints as it starts), else it is
  pinned under `cf://HOST` at its first sight: a quick tunnel's name lives
  one run of its node, so the pin guards that run's later sessions, and
  `--node-key` the first. `--client-key` applies as on `node://`, and no
  key of this client is made before the far end greets as a node;
  `--node-key` with a far end that greets with no layer is refused (255;
  77 for a copy), and `--no-e2e` with `cf://` (64), as a quick tunnel's
  node always runs the channel. SSH's keepalives are off there unless
  `ServerAliveInterval` is given, as the layer's heartbeat finds a dead
  link, and the run waits up to 5 s after SSH for the layer's `CLOSE`.
  `podssh proxy cf://HOST` carries the bytes as they are, so OpenSSH's
  `ProxyCommand` reaches cloudflared's services only.
- **`iap://[user@]PROJECT/ZONE/INSTANCE[:PORT]` is a port of a VM of GCP,
  through its Identity-Aware Proxy for TCP (T-351).** podssh opens the
  WebSocket that `gcloud compute start-iap-tunnel` opens, to
  `wss://tunnel.cloudproxy.app/v4/connect` through `HTTPS_PROXY` when one is
  set, with the upgrade that gcloud 570.0.0's own client sent to a stand-in
  on the loopback: the target in the query, `Origin: bot:iap-tunneler`, the
  subprotocol `relay.tunnel.cloudproxy.app`, and the token in
  `Authorization`, never in the URL. The token comes from the file of
  `PODSSH_IAP_TOKEN_FILE`, else of `GOOGLE_APPLICATION_CREDENTIALS`, refused
  when another user may read it, as a pair file is: a token of `gcloud auth
  print-access-token`, read again for each link; the JSON key of a service
  account, whose token podssh asks `oauth2.googleapis.com` for, through the
  same proxy, with a JWT that it signs RS256 through aws-lc-rs; or the
  credentials of `gcloud auth application-default login`. IAP's messages
  carry the stream: data of 16 KiB at most, acknowledged as gcloud and IAP
  Desktop acknowledge it. A lost link is taken up on a new one at the bytes
  that each side had (`/v4/reconnect` with the session's id), with a new
  token, three times at most, and what IAP had not taken goes again; a line
  tells of each. podssh waits 20 s for IAP's connect success, and a failure
  names its step: the token (78), the upgrade (401 or 403: 77, naming the
  role `roles/iap.tunnelResourceAccessor`), the account (close 4033: 77),
  the VM's port (close 4003: 69, naming the firewall's range
  35.235.240.0/20), or the VM (close 4047: 69). The host key is recorded
  under `iap://PROJECT/ZONE/INSTANCE`; the blocks of `ssh_config` are those
  of INSTANCE. `-p` and `Port` give the port; `--direct`, `-4`, `-6`,
  `HostName` and a `-J` hop before it are refused (64). `-J iap://...` makes
  the VM the first hop of a chain, as `-J cf://HOST` does. `podssh proxy
  iap://PROJECT/ZONE/INSTANCE:PORT` is the same pipe, with no PORT word, no
  user and no relay flag; the end of its input ends the session once its
  bytes went, as gcloud ends it, as IAP has no half-close. IAP "isn't
  intended for bulk transfer of data", and ends a session after an hour
  with no traffic (Google's documents).
- **`eice://[user@]ENDPOINT/ADDRESS[:PORT]` is a port of an EC2 instance,
  through an EC2 Instance Connect Endpoint (T-351).** ENDPOINT is the
  endpoint's DNS name, as `aws ec2 describe-instance-connect-endpoints`
  gives it, and ADDRESS the instance's private address, an IPv6 one in
  brackets: podssh makes no call to EC2's API. It opens the WebSocket that
  `aws ec2-instance-connect open-tunnel` opens, to `wss://ENDPOINT/openTunnel`
  through `HTTPS_PROXY` when one is set, its URL presigned with SigV4 for
  60 s as aws-cli's own signer presigns it, once TLS is up, for that one
  connection. The URL carries the credential (the key's id, the signature,
  and a temporary key's token): the one exception to "credentials never in
  URLs", by the operator's ruling Q51. podssh keeps it in memory that is
  wiped, never prints or logs it, and takes each part of it, and of the
  credential, out of an answer that quotes it. The credential comes from
  the file of `PODSSH_EICE_CREDENTIALS_FILE`, else of
  `AWS_SHARED_CREDENTIALS_FILE`, else `~/.aws/credentials`, each refused when
  another user may read it: the JSON that `aws configure export-credentials`
  writes in its process format, or a shared credentials file, its profile
  that of `AWS_PROFILE`, else `default`. The stream goes in binary messages
  as they are. A tunnel lasts an hour at most, or
  `PODSSH_EICE_MAX_TUNNEL_DURATION` (1 to 3600 s, sent as
  `maxTunnelDuration`, which an IAM policy may require), and an endpoint
  takes 20 at once; `podssh cp` goes on in a new tunnel a twelfth of the
  duration before its end, 30 s at least, as it does before the relay's
  limits. A refusal (401 or 403) exits 77, naming
  `ec2-instance-connect:OpenTunnel` and this host's clock, as a presigned URL
  is checked against AWS's. The host key is recorded under
  `eice://ID/ADDRESS`, ID the endpoint's; the flags, `-J` and `podssh proxy`
  go as with `iap://`.
- **`warp://[user@]HOST[:PORT]` is a port of any host inside WARP's tunnel
  (T-352), in a build with the feature `warp`.** Cloudflare's own network
  reaches HOST, with no relay and no account: the road that usque speaks
  over HTTP/2 (`crates/podssh-warp/src/lib.rs`). podssh dials Cloudflare's endpoint
  162.159.198.2:443, else the API's peers (below), or `PODSSH_WARP_ENDPOINT`,
  through `HTTPS_PROXY` when
  one is set, by its address, as the names of MASQUE have no A record; TLS
  1.3 with ALPN `h2`, the name `consumer-masque.cloudflareclient.com`, the
  device's self-signed certificate, and the endpoint's key pinned, as no
  public root signs it; one CONNECT of HTTP/2 with `cf-connect-proto:
  cf-connect-ip`, whose bodies carry IP packets in capsules of type 0; and
  TCP inside on smoltcp, in this process, with no TUN device. HOST's name is
  asked of 1.1.1.1 inside the tunnel, over TCP, else of podssh's own
  resolver. The first run registers a device with WARP's API
  (`api.cloudflareclient.com`, else `api.devices.cloudflare.com`, through the
  proxy, with the headers of "WARP for Android" that the open clients send;
  T-562) once `PODSSH_WARP_ACCEPT_TERMS=yes`
  accepts Cloudflare's Terms, and keeps its record, its token and its key in
  the cache (`warp-device.json`, mode 0600); with no record and no
  acceptance, the run refuses (78), naming the Terms. A team's token of a
  Cloudflare One organization, in the private file of
  `PODSSH_WARP_TEAM_TOKEN_FILE`, enrols the device there. Each request to
  the API goes by its routes in turn: `PODSSH_WARP_API=https://HOST[:PORT]`
  first when it is set, then the route that answered for the device before
  (its record keeps it), then the API's two names; a route that is not
  reached gives way to the next, an answer, a refusal too, is the API's, and
  the enrolment goes by the route that registered the device. The failure
  names each route and why. A proxy that
  refuses the CONNECT to the address, or cuts the TLS after it, is named,
  with `podssh doctor`'s line `egress takes` for the case (69). A certificate
  of another key than the pinned one sends podssh to WARP's API for the
  device's record again (`GET /reg/ID` with its token, through the proxy,
  T-399): a new key that the API gives is kept in the record and tried, and
  once more a second later, as WARP's front door showed a new device another
  key than its record's (cfrs #32); a key that the API never gave is never
  taken. Else the certificate is a proxy's that re-terminates TLS: it is
  named by its issuer (69), and the road is not tried again with it in the
  run. Once the tunnel opens, the probe proves that it carries a packet
  (T-560): one TCP connection inside it to `1.1.1.1:443` (IPv6's resolver
  for a device of IPv6 alone), within 3 s, tried twice 700 ms apart; a
  SYN-ACK or a reset that comes back through the tunnel is its answer. A
  front door that took TLS and HTTP/2 and relays nothing is said in one line
  of the road, "the tunnel opened and carried nothing" (69), not left to each
  stream's timeout, and it is not remembered for the run as a proxy is.
  `PODSSH_WARP_PROBE=no` skips the probe, for a host where that target is
  filtered inside WARP, and `-v` says that the tunnel is taken unproven.
  Each endpoint of the device goes in turn (T-561), one at a time and never
  in a race: the one that last opened, the record's endpoint of HTTP/2
  (162.159.198.2:443), then the peers that WARP's API gave at the
  registration (each `endpoint.v4`, then `.v6`, on port 443), each once; the
  dial of each but the last within 3 s. An endpoint that the way out does
  not reach, whose TLS or HTTP/2 fails, or whose tunnel carries nothing
  gives way to the next; a device that the edge refuses, a proxy that
  re-terminates TLS and this host's part end the road, as each endpoint
  would give the same. The record keeps the endpoint that opened, tried
  first the next time, and forgets it when none opens; the failure of each
  names each endpoint and why. `PODSSH_WARP_ENDPOINT` is the run's one
  endpoint, tried alone, and changes no record. A
  key that the edge does not know exits 77. The host key is recorded
  under `warp://HOST`; `-p` and `Port` give the port; `--direct`, `-4`, `-6`,
  `HostName` and a `-J` hop before it are refused (64), and `-J warp://HOST`
  makes HOST the first hop of a chain. `podssh proxy warp://HOST:PORT` is
  the same pipe. In a build without the feature, a `warp://` destination
  exits 70 before anything connects.
- **`tor://[user@]HOST[:PORT]` is a port of any host through the Tor
  network (T-353), in a build with the feature `tor`.** Arti runs in this
  process (`crates/podssh-tor/src/client.rs`), with no relay, no account and
  no program besides. Each of its connections to a Tor relay is podssh's own
  dial (`crates/podssh-tor/src/runtime.rs`): through `HTTPS_PROXY` when one
  is set, to the relay's address and port, and Arti listens on nothing.
  Through a proxy, Arti takes as first hops only the relays on port 443, or
  on the ports of `PODSSH_TOR_PORTS` (a list, or `any`; any port with no
  proxy), as a cage allows only a few. An exit resolves HOST and connects to
  it; an exit's policy, or the host, may refuse Tor. The first run fetches
  Tor's directory, which can take a minute; Arti keeps it and its guards in
  the cache's `tor/` (mode 0700), and later runs start sooner. Arti's TLS is
  podssh-ws's own rustls provider, installed as the process's, and its only
  C is SQLite, of its state. The host key is recorded under `tor://HOST`;
  `-p` and `Port` give the port; `--direct`, `-4`, `-6` and `HostName` are
  refused (64), and `-J tor://HOST` makes HOST the first hop of a chain.
  `podssh proxy tor://HOST:PORT` is the same pipe. In a build without the
  feature, a `tor://` destination exits 70 before anything connects. Tor's
  own TLS fails through a proxy that re-terminates TLS, or that allows few
  ports; bridges pass both (T-385). `PODSSH_TOR_BRIDGES` names a file of
  bridge lines, as Tor gives them out (with or without `Bridge `); Arti's
  first hops are then those bridges alone, and `PODSSH_TOR_PORTS` does not
  hold. A line is a plain bridge, or one of meek_lite or WebTunnel, which
  podssh speaks itself, in this process (`crates/podssh-ws/src/meek.rs`,
  `crates/podssh-ws/src/webtunnel.rs`): Arti dials each transport as a
  SOCKS5 proxy at a sentinel address, which podssh's TCP provider answers
  with a pipe in memory (`crates/podssh-tor/src/transport.rs`), so nothing
  listens and no program starts. meek_lite sends Tor's bytes in POSTs to
  its `url=`, its TLS to `front=` with the front's name and `Host` the
  URL's host; WebTunnel upgrades at its secret path, then carries raw
  bytes. Each connects through the proxy, its TLS checked with podssh's
  trust; WebTunnel's `cert=` is a second check after that one, never in its
  place. Arti asks each line for the bridge's fingerprint, so a line with
  none is refused, Tor Browser's meek_lite line among them, and so is
  another transport (obfs4, snowflake), which would be another program.
- **The direct road after the relay hosts** (T-363), as the road table of
  [design.md](design.md) gives it. When no relay host opened a session, and
  the user named no relay (`--relay-host`, `PODSSH_RELAY` or the settings
  file's `RelayHost`), podssh tries the direct road once: the dial of
  `--direct`, through `HTTPS_PROXY` when one is set, then the server's
  version line within 10 s, whose bytes go to the SSH client first, of the
  family of `-4` or `-6` when one is given (below). One line says that the
  relay hosts failed, after how long, and that
  podssh tries HOST:PORT directly, and through which proxy, whose CONNECT
  then names the target, which the relay's does not. A proxy that takes the
  CONNECT and sends nothing is no road (T-317): the line names it. When both
  fail, the relay's lines come first, then one that names both roads with
  their times, and the exit is the relay's. With `-v`, the relay's lines
  come before the dial, and a line says that the direct road carried the
  session. `--direct` is the direct road alone, and a named relay is the
  relay alone: neither falls back. `PODSSH_DIRECT=no`, or `Direct no` in the
  settings file, turns the fallback off; another word is refused (78). The
  first hop of `-J`, and each command that reaches its server as `ssh` does
  (`cp`, `each`, `job`, `health`, `containers`, `ping`, `pipe ssh:`), do the
  same; `podssh proxy`, which has no direct road, does not. The direct road
  comes after the relay, never before it or beside it: where podssh is
  built for, a direct dial is dropped with no answer
  ([target-environment.md](target-environment.md)).
- **The direct road after a relay that reached no IPv6 host** (T-253). With
  `-4` or `-6` the direct road keeps the family: a name is resolved on this
  host, and its addresses of that family alone are dialed in turn, each
  through the proxy that the name takes, as an address; an address is of its
  own family. `podssh ssh` takes the direct road at once, in place of the try
  of the relay once more (T-025), when a relay host opened a session to an
  IPv6 target (an address, or `-6`) and closed it before any byte came: with
  `1011 target closed before sending anything`, as the default relay did for
  each IPv6 target ([relay.md](relay.md), "IPv6 targets"), or with the words
  of podssh's own relay role, `this relay's host has no IPv6 route out`. Its
  line says that the relay reached no IPv6 host, and when the direct road
  fails too, a note names the roads that carry IPv6: a relay of the user's
  on a host with IPv6 (`podssh relay serve`, then `--relay-host`), a node
  with IPv6 egress (`-J node://NAME`), or `warp://[ADDR]`, which podssh
  never tries unasked. With a relay named, or `PODSSH_DIRECT=no`, the run
  ends with that note, as before.
- **The cleartext road, the relay's last** (T-326, the operator's ruling
  Q45, GitHub #56). When each relay host failed, and the TLS of one failed
  on the way (a certificate that is not the relay's, as a proxy that
  intercepts TLS by its SNI or its certificate presents its own; a reset or
  a close in the handshake; or its bound), podssh tries that host once more
  with no TLS, on its own port, through `HTTPS_PROXY` as each road dials:
  the first host of each deployment alone, one at a time, 45 s each, before
  the direct road and the forwarders. It asks for a token of one session,
  `POST /v1/mint?once=1`, signed by the client's key where the relay asks
  (T-448), then upgrades with it, in cleartext. Each hop reads the target
  and that token, which lives minutes and which one upgrade spends; SSH
  inside stays end to end. No other token goes there (not
  `PODSSH_RELAY_TOKEN`, not the cache's), the token is never cached, and a
  relay whose answer does not say `"once": true`, with an end within 10
  minutes, gets no upgrade. One line says what goes, and one which host
  carries the session; `-v` says that the session runs in cleartext, and
  `doctor`'s line `forward` names it. Its failures are lines alone: the
  run's failure, its code and the forwarders' fallback stay the TLS road's.
  `podssh relay serve` serves the road ([relay.md](relay.md), "The
  cleartext road"); the default relay's edge serves TLS alone on 443 and
  refuses it. `ssh`, `proxy`, `pipe` and each command that reaches its
  server as `ssh` does take it, a named relay too. `PODSSH_CLEARTEXT=no`
  turns it off; another word is said in a line, and the road is not tried.
- **The HTTP road after the relay hosts** (T-319, the operator's ruling
  Q44; [relay.md](relay.md), "The relay role's HTTP road"). When no relay
  host opened a session and the way to one of them refused the WebSocket
  upgrade (a page of the proxy's, or a `426` of a relay that got the request
  with its `Upgrade` taken off, as the probe of the Piping Server road tells
  the way's refusal from the relay's own word), `ssh`, each command that
  reaches its server as `ssh` does, and `proxy` carry the session to that
  host over plain HTTPS requests of HTTP/1.1, which `podssh relay serve`
  serves: the same token (minted once more when the role no longer takes a
  cached one), the target's checks and the limits of the WebSocket road. The
  split form comes first: the bytes up in numbered batches, one POST after
  another, and the bytes down from their offset on a second connection; when
  that connection gives no answer within 20 s, the serial form on the first
  connection, one POST after another, each answered with the bytes down.
  Each request goes again until an answer comes, so a proxy that loses an
  answer, or cuts one, loses no byte and doubles none. One line names the
  host and the road before it; `-v` names the form. It comes before the
  direct road and the forwarders, which a proxy that refuses the upgrade
  refuses too, or which send the target to another; when it fails, its line
  says why, and they follow. A relay with no such road (the default relay's
  deployment) is named as one. `PODSSH_HTTP_ROAD=no` turns it off, `split` or
  `serial` names one form, and another word is refused (78).
- **The WebSocket over HTTP/2, to a relay of the user's** (T-321, GitHub
  #51; RFC 8441; [relay.md](relay.md), "The relay role's HTTP/2"). To a
  relay host that the user named (`--relay-host`, `PODSSH_RELAY`,
  `RelayHost`), the sessions of one process are streams of one HTTP/2
  connection where the host offers extended CONNECT, as `podssh relay
  serve` does, so the hosts of `podssh each`, and each other session of the
  run to that host, pay no TCP and TLS past the first. podssh offers `h2`,
  then `http/1.1`, by ALPN, on a TLS configuration of this road alone (each
  other road offers none), sends a PING after HTTP/2's handshake and reads
  the server's SETTINGS before it, and only where they offer
  `SETTINGS_ENABLE_CONNECT_PROTOCOL` sends a `CONNECT` with `:protocol
  websocket`, the path, the name and the token of the upgrade, the token in a
  field that HPACK never indexes; a `200` opens the session, another status
  is the relay's refusal, as for the upgrade. A connection carries 16
  sessions at most, each with a window of 1 MiB in one of 16 MiB for the
  connection; another session opens another connection, and one with no
  session closes after 30 s. A lost connection is a lost link for each of
  its sessions at once. Where TLS chose `http/1.1`, the upgrade goes on that
  connection; where HTTP/2's SETTINGS offer no extended CONNECT, or HTTP/2
  did not carry the `CONNECT`, that connection closes first, the upgrade
  goes on a new one, and the run takes HTTP/1.1 to that host for 10
  minutes. `-v` names the road of each session ("the relay host H opened
  the session, over HTTP/2 (RFC 8441), on a connection that it shares").
  The default relay's edge chooses `h2` with no extended CONNECT (measured
  2026-10-30), so no session to it takes the road unless
  `PODSSH_H2=yes`; `PODSSH_H2=no` keeps each session on its own connection,
  and another word offers the road to none, which `doctor`'s line `http2`
  fails with. A caller's own TLS configuration (`Trust::caller`) is used as
  it is, with no ALPN, so it takes the upgrade alone.
- **`--forwarder TEMPLATES` reaches the first hop through other products'
  WebSocket forwarders, in place of the relay** (T-369, GitHub #60). A
  forwarder dials the host and the port that a client names and carries the
  bytes in binary frames: the plumbing of Mudlet's web client or of ssheasy's
  SSH client in a browser. A template is a `ws://` or `wss://` URL with
  `{host}` and `{port}` once each, in its path or its query, which podssh
  fills with the target, checked as a target of the relay is and then
  percent-encoded; or a URL with neither, and then the target goes in a first
  text frame, `{"Host":HOST,"Port":PORT}`, which podssh writes itself, and
  the forwarder's answer `{"status":"ok"}` (ssheasy's, in a binary frame)
  comes before the target's bytes and is not passed on. A template with one
  placeholder, either twice, another brace, a placeholder in the authority,
  a fragment, or a user and a password, is refused (64). A list, separated
  by commas (a comma inside a template is `%2C`), is tried in order: a
  forwarder that refuses the upgrade, that closes within 3 s of it (a
  Worker answers the upgrade before it dials, and closes with 1011 when it
  cannot reach the target), or that answers with a failure, gives way to the
  next. The dial is that of `podssh pipe wss://` (T-368): TLS checked for
  the forwarder's name, through `HTTPS_PROXY`, and no relay token, no
  `/v1/mint`, no `/relays.json` and no pool. Binary frames carry the bytes,
  out in frames of 32 KiB at most; a text frame is the forwarder's own word,
  shown with `-v` and never written into the session; a close other than
  1000 names the forwarder, its code and its reason. `PODSSH_FORWARDER`,
  and `Forwarder` in the settings file, give the list below the flag. A run
  has one road: `--relay-host`, `--relay-failover`, `--direct`, `-4`, `-6`,
  and a destination with a road of its own are refused beside the flag
  (64), and `PODSSH_FORWARDER` beside `PODSSH_RELAY` (78); a relay flag on
  the command line beats the variable and the file. The commands that reach
  their server as `ssh` does take it (`cp`, `mv`, `scp`, `sftp`, `edit`,
  `each`, `run`, `job`, `session`, `containers`, `health`), and so does
  `podssh proxy`, whose end of stdin sends no Close, as on the relay's road;
  `podssh pipe` reaches a forwarder by its URL with `wss://`. `podssh doctor
  --forwarder` checks each one: the upgrade, then GitHub's published host key
  on `github.com:22` through it. A forwarder is another product's endpoint,
  which publishes no limit and can stop at any time, so a user names more
  than one. A template may name a forwarder that the user runs.
- **`--forwarder wisp+wss://HOST/PATH/` names a server of the Wisp
  protocol** (T-438, [carriers.md](carriers.md)): Mercury Workshop's
  protocol, which carries TCP streams over one WebSocket, the target in a
  `CONNECT` packet of its own, so the URL has no `{host}` or `{port}` (64)
  and its path ends with `/` (64; without it a Wisp server reads the older
  wsproxy's form). podssh-ws speaks it itself, from its document
  (`crates/podssh-ws/src/wisp/`): the upgrade offers the protocol
  `wisp-v2`; a server that sends its `INFO` speaks version 2, and podssh
  answers with the version that both take and the extensions that both
  list (the message of the day, shown with `-v`, and stream open
  confirmation); a server that sends its `CONTINUE` first speaks version
  1. Each session is one stream on a WebSocket of its own; no `DATA` goes
  past the credit of the server's last `CONTINUE`; a `CLOSE` before the
  target's first bytes (within 3 s, or before the confirmation) gives way
  to the next forwarder with the server's reason (`0x42` unreachable,
  `0x48` blocked, `0x49` throttled, and the others of the protocol); the
  end of the caller's bytes sends a `CLOSE` with `ssh`, and none with
  `proxy`, as Wisp has no half-close. A server that requires a password
  or a key is refused, as podssh sends neither and no credential goes in
  a URL. The same dial as each forwarder's: one connection, through
  `HTTPS_PROXY`, TLS checked for the server's name, no relay token.
- **Four words name public forwarders, which the binary carries, and they
  follow the relay when each relay host failed** (T-370, the operator's
  ruling Q56; T-438, Q65): `mudlet` (`wss://web-proxy.mudlet.org/`, the
  Worker of Mudlet's web client), `ssheasy` (`wss://ssheasy.com/p`, the
  frame form) and `mudix` (`wss://mudix.delwing.workers.dev/`, an older copy
  of Mudlet's Worker), the three that GitHub #59 measured; then `wisp`
  (`wisp+wss://wisp.mercurywork.shop/`, Mercury Workshop's demo server of
  the Wisp protocol, "primarily for demo and testing", 500 kB/s for each
  address), last and never first, as Q65 rules; `--forwarder
  mudlet,ssheasy` takes them as templates are taken, and an unknown word is
  refused (64) with the list, its text not shown. When each relay host
  failed with a failure that a forwarder may not share (69 or 77 as `proxy` exits: not a bad setting, not
  a target that cannot go) and with no word about the target (a dial, TLS, a time-out, an upgrade, the
  relay's own 5xx, a refused token; T-509, Q69), and the relay was podssh's own choice (no `--relay-host`,
  `PODSSH_RELAY` or `RelayHost`, and no `-4` or `-6`), `ssh`, each command of its road and `proxy` try them
  in that order, 10 s at most each, before the run ends, after the direct road where that one is tried
  (T-363, `PODSSH_DIRECT`), as the direct road sends the target to no one else; `proxy`, which has no
  direct road, tries them at once. The relay's 502 of a target that it could not reach, and its refusal of a
  target by policy (a blocked range, a port), end the run with the relay's words and send the target to no
  forwarder. One line says that `HOST:PORT` goes to them and the bound of the wait; the carrier is named
  after each failure before it; when none carries, one line gives each one's reason, and the run ends with
  the relay's code. The order puts a second provider before a second copy of the first.
  When none carries, their `ws://` form follows, last (T-326, GitHub #56): the host of each is probed with
  no TLS on port 80, one at a time, 5 s each (the probe of `doctor`'s line `cleartext`), and the `ws://`
  form of each that passed (an answer of HTTP that is neither a refusal of cleartext, nor a redirect, nor
  a `403`) is tried in the same order, the line before them naming them and saying that each hop reads the
  target; no relay token goes to a forwarder. `PODSSH_CLEARTEXT=no` turns that form off.
  `PODSSH_FORWARDER_FALLBACK=no` or `ForwarderFallback no` turns it off, and another word is refused (78);
  `doctor`'s line `fallback` says whether it is on, as `????` (it measured nothing), and asks none unless
  `--forwarder` names them. They serve their own products' users and publish no limit: ssheasy's code slows a connection to
  100 KiB/s after 1 GiB and takes one connection a second from each address;
  Mudlet's Worker shares its plan's requests with each user of Mudlet's web
  client. `.github/workflows/forwarder-live.yml` checks each one from GitHub
  Actions each day, as Q56 and Q65 allow: GitHub's version line through it;
  it runs the Wisp client against wisp-server-python on the runner's
  loopback first.
- **`PODSSH_MPTCP=yes` asks for Multipath TCP on the direct road** (T-172),
  on Linux, and only on request. With `--direct` and no proxy, each attempt
  asks the kernel for a socket of `IPPROTO_MPTCP`: where the server speaks
  MPTCP too, the connection can go on over another network of this host
  when one goes, where the host's path manager has an endpoint on each.
  Where `/proc/sys/net/mptcp/enabled` is not 1, where the kernel or a
  sandbox refuses the socket, through a proxy (MPTCP would reach the proxy
  only), and on another system, the connection is plain TCP, the same
  stream; `-v` says which, and on Linux 5.16 and later whether the server
  took MPTCP. The relay's road never asks for it. It is a variable, not a
  flag or an `-o` keyword, so that each command that reaches its first hop
  as `ssh --direct` does (`cp`, `mv`, `scp`, `sftp`, `edit`, `ping`, the
  hops of `pipe ssh:`) reads it, and OpenSSH has no keyword for it. Another
  value than yes or no is refused before the connection (78; 255 for
  `ssh`).
- **`--host-key-fingerprint SHA256:B64[,...]` accepts only the keys that it
  names** (T-031), for a script that got the server's fingerprint from its
  operator and has no `known_hosts`: under each `StrictHostKeyChecking`,
  `accept-new` included, another key is refused with exit 255 and both
  fingerprints, and the named key is accepted and recorded nowhere. A
  revoked or a changed key in `known_hosts` is refused first. The
  fingerprint is the one that `ssh-keygen -l` prints; a value that is not
  one, or a second flag, is a usage error (64). It holds for the
  destination only: `-J` hops keep `known_hosts`. OpenSSH has no keyword
  for it, so it is a flag, not an `-o` keyword that would break a file
  that OpenSSH also reads.
- **`--persist` keeps the work through a lost link** (T-178), against a
  standard sshd, where the resumable layer cannot help. After the login,
  podssh looks for tmux (`command -v tmux`, in `sh`) and refuses without it (exit
  255): a new shell after a loss would look like the old one and have lost
  its state. The refusal ends with the command that installs tmux, from the
  probe of `podssh job` (T-481, below); podssh runs none. A login that runs
  no `sh` is asked `command -v tmux` itself, and its refusal has no
  command. The session is `tmux new-session -A -s NAME`, with a pty as
  `-tt` asks; NAME is `podssh`, or the one of `--persist-name` (letters,
  digits, `_` and `-`, 32 at most). A lost link is a session that ended
  with no exit status: with `--direct`, or through the relay when its link
  broke (the ping watcher) or it closed with 1001, 1006, 1009 or 1011. Then
  podssh connects again, 10 times at most within 5 minutes of the loss,
  after the jittered wait of the relay's failover (a connection that lasted
  less than 30 s starts no new count: a link that falls again and again
  gives up, T-042), checks that the session
  is still there (`tmux has-session`), and attaches it. A session that is
  gone ends the run (255), as do an exit status, a detach of tmux (0), `~.`,
  a refused host key or login, and Ctrl-C during the wait. The logins after
  the first ask nothing (as `BatchMode=yes`): the input belongs to the
  session, and a key that a passphrase opened and a password that the
  server took are kept for the run. Keys typed during the wait go to the
  session after the attach, 64 KiB at most. With a command, `-W`, `-s`,
  `-T`, `RemoteCommand`, `node://` or `iroh:`, `--persist` is a usage error
  (64). The first connection's failure is final, as without `--persist`.
- **`--persist -N` keeps the forwards through a lost link** (T-042), as a
  tunnel that must last: no tmux runs. After a loss podssh connects again,
  as above, and asks the server for each `-R` again; `-L` and `-D` keep
  their listeners, which serve on the new connection. The server's own close
  is a loss too, as a forward keeps nothing on the server that its restart
  would lose; a close of the relay that would come again (1008, 1013) ends
  the run. After a loss, a forward that the server refuses is asked again,
  with the same wait, for 2 minutes at most, as the server may hold its
  port until it sees the old connection dead; then it is refused as on the
  first connection: a warning, or with `ExitOnForwardFailure` the end of the
  run (255). A port that the server chose (`-R 0:...`) can change, and
  podssh prints the new one. Each loss is a line on stderr that names the
  hop that broke, and each return a line. The logins after the first ask
  nothing (as `BatchMode=yes`), unless `SSH_ASKPASS_REQUIRE=force` names a
  program of `SSH_ASKPASS` to ask. With `-N` and no forward, or with
  `--persist-name`, it is a usage error (64).
- **`--persist-forever` never gives up** (T-391), for a tunnel that a
  server must keep, as a reverse tunnel that is the only way into it: with
  `--persist`, podssh connects again after each loss for as long as it
  takes, after the relay's jittered wait, about 30 s at most, as a node retries
  its relay; a first connection that failed (the relay or the network not
  up, as at a boot) is a loss too, after its lines. It says each of
  the first 10 attempts and then one in 10. A refused host key or login
  still ends the run (255), as does Ctrl-C during the wait. Without
  `--persist`, it is a usage error (64).
- **`--attach NAME DEST` joins a shell that the far end keeps** (T-158),
  from a new podssh process or from another host; `--attach DEST` with no
  other word lists the kept shells, one on each line, and exits 0. Only a
  far end of `node://NAME` that names `keep.v1` in the resumable layer
  keeps shells: another destination is a usage error (64), and a far end
  that keeps none ends the run with 255 before a session opens. In a
  session with a pty there, `~d` asks the far end to keep the shell,
  prints the name that it keeps it as, and exits 0; elsewhere `~d` goes to
  the server as typed ([terminal.md](terminal.md), "Detach and attach
  again"). The far end gives a shell to one client at a time: `--take`
  takes it from the client that has it, whose session ends. It refuses an
  attach from inside the shell itself, which `PODSSH_SHELL_ID` names. Its
  refusal is its words on stderr and its exit status. With a command,
  `-N`, `-W`, `-s`, `-T`, `RemoteCommand` or `--persist`, `--attach` is a
  usage error (64), and a control master does not carry it.
- **`--upgrade` moves the session to a better road** (T-167), when the
  server has a podssh. The login is as each run's, on the forward road or
  with `--direct`; then podssh runs `podssh --version` there (10 s) and,
  when a line `podssh VERSION` comes back, `podssh node --temporary KEY` in
  the same SSH session, KEY being the fingerprint of this client's key
  (`client.key` in the cache, or `--client-key`). That node stands in front
  of the sshd of its session (a roost, T-166), makes a pair that no file
  keeps, and writes one line on its stdout: the pair's relay, name, connect
  token and expiry, and its own key. The SSH channel carries that line,
  encrypted, so the token crosses the relay only inside SSH, and it is on
  no argv. podssh opens the operator's leg to the pair, reads the node's
  greeting (no layer, no move), and logs in again through the node with the
  resumable layer and the end-to-end channel, which must find the node's
  key of the line. The host key is the same, under DEST's own name, so
  `known_hosts` needs no change, and no `-J` hop is used again. The first
  connection closes once the second login is done; until then, a failure
  of the move (no podssh, no line within 60 s, no layer, a failed second
  login) is one note on stderr, and the session runs on the first
  connection. The logins after the first ask nothing. podssh never copies
  itself to the server: a podssh must be on the `PATH` of a command that
  sshd runs. The node ends with its last session, or 10 minutes after its
  start with none, and stops its pair. On Unix it leaves its SSH session
  (SIGHUP ignored, its standard streams to `/dev/null`), so that the end of
  the first connection does not end it; on Windows it cannot, says so in its
  line, and the first connection stays open while the session runs.
  `--upgrade` with `node://`, `iroh:`, `cf://`, `--persist`, `-R` or `-O`
  is a usage error (64); `ControlPath` has no effect with it. The move takes
  the pair's road alone: the iroh road to the node, raced with it as T-164
  races them, is not built: T-167's Decision left it out.
- **Ctrl-C with no remote pty sends `signal INT` to the command** (T-293),
  in a session that runs a command or a shell: podssh waits 2 s for the
  command's end, whose signal or status is the exit code, and a second
  Ctrl-C, or the end of the wait, ends podssh with 130. **`--no-signal`**
  keeps OpenSSH's behaviour: no request, and Ctrl-C ends podssh at once
  ([terminal.md](terminal.md), "Ctrl-C with no remote pty").
- **`--result-file FILE` writes the result of the run as JSON** (T-054), at
  its end, also when it failed before it connected, so that a script tells
  the remote command's status from a failure of podssh with no parsing of
  stderr: `schema`, `exit` (the code that podssh exits with), `status` (the
  remote exit status, or null), `signal` (`name` and `core_dumped`, or
  null), `end` (`status`, `signal`, `no-status`, `lost`, `escaped`,
  `terminated`, `detached`, `interrupted`, `failed`, or `shared`; null with no session, as with `-W`),
  `failure` (`connect`, `host-key`, `auth`, `forward`, `relay`, `session`,
  `usage`, `config` or `not-built`, or null: `connect` also when podssh got
  no session for another cause), `bytes` (`stdin`, `stdout`
  and `stderr`, as they passed), `duration_ms`, and `relay` (`host`,
  `close_code` and `reason`, or null with no relay). A signal ends with
  128 + its number, as in OpenSSH, and `status` is then null. `-N` ends
  `lost` when the server or the network ends the connection. A link lost
  after the remote exit status and before the end of the output ends
  `lost` with `exit` 255, and `status` keeps the remote status (T-461). A run through
  a control master (T-039) ends `shared`: the master tells the exit code
  alone, a status or 128 + a signal, and carries the bytes, which are then
  null. stdout and stderr stay byte for byte as they are: the command's
  output never goes into the file. A new file is made for its owner alone
  (mode 0600 on Unix); `-` is refused (64), as stdout is the command's. A
  file that cannot be written is a line on stderr, and the exit code stays
  the run's. No file is written after a flag that podssh does not know,
  which ends it before it reads the others (64), nor when a signal kills
  podssh, as it kills OpenSSH's `ssh`: only a session on a terminal ends at
  SIGTERM or SIGHUP, as `terminated`, and writes it.
- **A warning before the relay's idle cut** (T-463, GitHub #98): the relay
  ends a session after 180 s with no payload either way, which keepalives
  prevent and `-o ServerAliveInterval=0` allows. Through the relay, once
  nothing crossed for the cut less the lead, podssh warns once: "the relay
  ends this session in 30 s, as nothing crossed it for 150 s: a key, or -o
  ServerAliveInterval below 180, keeps it", in the window's title where the
  session shows the notice of a silent far end there (T-302, taken back at
  the next payload), else as one line on stderr, also into a pipe; and again
  only after a payload crossed. **`--idle-warn SECONDS`** sets the lead (30
  s, or a sixth of a shorter cut of a relay's limits); 0 turns it off, and
  so does `-q`. The warning sends nothing: a session whose keepalives are
  off stays so. `podssh proxy --idle-warn SECONDS` warns on stderr, which
  its SSH client shows. Not on `node://` and the other roads of the
  resumable layer, whose heartbeat keeps the link busy, nor with
  `--direct`; with `--persist`, which attaches again after the cut, and
  `--upgrade`, not before T-583.
- **`--sudo` and `--su` run the remote command as root** (T-032), with the
  password asked here, on the terminal or through `SSH_ASKPASS`, never on
  the command line. `--sudo` sends `sudo -S -k -p PROMPT -- sh -c '...'`
  with no pty, PROMPT a marker of this run, and the command prints a second
  marker as it starts: podssh answers that prompt once, holds its own input
  until the command starts, and removes both markers from the output. With
  a `NOPASSWD` rule there is no prompt, and podssh asks nothing. A second
  prompt is a refused password: podssh ends the input, and sudo exits with
  its refusal. `--su` sends `su -c '...'` in a pty, as su reads a terminal
  alone; its prompt is its output that ends with no newline before the
  command starts, and that output is shown only when su refuses. The
  remote shell must read POSIX quoting. When neither a prompt nor the
  command's start comes within 30 s, podssh stops with 255. A password
  that cannot be given (a cancelled question, an `SSH_ASKPASS` that exits
  non-zero, `BatchMode` or nothing to ask on) is never sent (T-501):
  podssh names the cause and ends the command's input, and for su also
  its line on the pty, with the pty's kill and end-of-file keys (Ctrl-U
  and Ctrl-D unless the local terminal set others), as OpenSSH's server
  keeps the pty open at the channel's EOF. sudo or su then refuses with
  its own words and status; one that does not end within 30 s ends podssh
  with 255, and podssh closes the channel. Each needs a
  command; `--sudo` with `-t`, `--su` with `-T`, or both at once, are usage
  errors (64). Such a run makes a connection of its own, with no
  `ControlPath`, and with `BatchMode` a prompt ends the input.
- **`--record FILE` keeps what the session showed** (T-033), with its
  timing, in an asciicast v2 file that `podssh play` and asciinema play
  again: the header (version 2, the terminal's size, the time of the start
  and `TERM`), then an `o` event for each output and an `r` event for each
  new size. The file is made as the run starts, closed to others (mode
  0600, or an access list of its own on Windows), and never over a file
  that exists (255); `-G` makes none. Nothing typed is recorded, and the
  header holds no command line, which can hold a secret; the output can
  hold one (a key that was printed, a password that a program echoed). A
  character cut between two reads is written whole. `-N`, `-W` and
  `--persist` cannot go with it (64), and such a run makes a connection of
  its own, with no `ControlPath`.
- **`--expect TEXT --send KEYS` are rules of a session with a pty**
  (T-191), for a host that wants keys after the login: a menu, a banner to
  confirm, a second shell. Each rule waits for TEXT, a literal text as the
  terminal shows it, in the output that came after the match of the rule
  before it (64 KiB at most), then sends KEYS, where `\r`, `\n`, `\t`, `\\`
  and `\xNN` are read; the pairs come in order, each `--expect` with its
  `--send` after it (64 else). Until the last rule sent its keys, podssh
  holds its own input, so that no key typed here comes between them. Each
  rule waits `--expect-timeout` (30 s; a time as `--timeout` takes it);
  when it sees no match, the session ends with 255, and the message names
  the rule and its text. A session with no pty (no `-t` with no terminal
  here, or a server that grants none) runs nothing and ends with 255; `-T`,
  `-N`, `-W`, `-s`, `--sudo`, `--su` and `--persist` cannot go with the
  rules (64), and such a run makes a connection of its own, with no
  `ControlPath`. Each process of this host can read the command line, so
  KEYS are no place for a password, which comes through `SSH_ASKPASS`.
  Tasks before and after a connection are the shell's: `cmd && podssh ssh
  host; cmd`. podssh adds no `--before` or `--after`.
- **`LocalCommand` runs here after the login** (T-191), only with
  `PermitLocalCommand yes`, as OpenSSH runs it: after the login and before
  the session, with `SHELL -c COMMAND`, else `/bin/sh -c COMMAND` when it is
  there, else 78 before anything connects. Its `%` tokens are those of
  `RemoteCommand`, and `%T` is `NONE`, as podssh opens no tunnel; `-G`
  prints it as given, as OpenSSH expands it only as it runs it. podssh
  waits for its end; its exit status is said with `-v` and changes nothing,
  as in OpenSSH. Its input is none, as the session reads stdin next; with
  `-W`, its stdout goes to stderr, as stdout carries the stream. It runs
  once in a run: a try after a drop of the relay (T-025) does not run it
  again, and `--persist` runs it after its first login alone. Only `podssh
  ssh` runs it: `each`, `containers`, `cp` and the other commands that log
  in run none, as OpenSSH's `scp` and `sftp` pass `PermitLocalCommand=no`
  to their `ssh`; a client of a control master runs none, as OpenSSH's.
- **`~#` lists the forwards of the session** (T-041), in a session with a
  pty, as OpenSSH's `~#` lists its connections: for each `-L`, `-D`, `-R`
  and `-W`, as it was written, the connections it carried, those open and
  those that failed, and the bytes toward the server and from it, counted as
  they pass. With `-v` the end of a run prints the same lines. A forward
  asked for again on a new connection (`--persist`) keeps its counts. A
  forward that `~C` stopped stays in the list, with `; closed` at the end
  of its line.
- **`~C` adds and stops forwards in a running session** (T-291), in a
  session with a pty, as OpenSSH's `~C` does. It opens OpenSSH's command
  line, `ssh> `, and reads one line from the session's own keys; no key of
  the line reaches the server, and the keys after its Enter go to the
  session. The commands are OpenSSH's, with the `-` optional and a space
  after the letter optional:
  - `-L SPEC`, `-D SPEC` and `-R SPEC` add a forward, with a spec as the
    command line reads it. The listeners of `-L` and `-D` are made as those
    of the command line are: the same probe, the same addresses, `-g`,
    `PODSSH_LISTEN`; one that cannot be made says why, and the session goes
    on. `-R` asks the server, and podssh waits 20 s at most for its answer:
    `Forwarding port.` once the server took the forward, or OpenSSH's
    warning when it refused. OpenSSH says `Forwarding port.` before the
    answer.
  - `-KL [BIND:]PORT`, `-KD [BIND:]PORT` and `-KR [BIND:]PORT` stop a
    forward; `-KL` and `-KD` also take a socket path. A port with no address
    names each listener of that port; `localhost` names those on loopback.
    A closed listener takes no new connection, and the connections that it
    took go on, as in OpenSSH. `-KR` sends `cancel-tcpip-forward` for the
    port that the server listens on (the one it chose, for a port of 0),
    and a channel for that port is refused from then on.
  - `help`, `-h` or `?` lists the commands; an empty line, Ctrl-C and
    Ctrl-D do nothing. Another line is refused with OpenSSH's words
    (`Invalid command.`, `Bad forwarding close specification.`); a line
    that starts with `!` runs no local command (OpenSSH's
    `PermitLocalCommand`).

  The forwards that `~C` adds last as long as the connection, and those
  that it stops stay stopped: a new connection of `--persist` asks only for
  the forwards of the command line that `~C` did not stop, and keeps a
  listener that `~C` closed closed. A session through a control master has
  no `~C`, as a client of OpenSSH's master has none: the key goes to the
  server as typed.
- **`-G` prints the settings in effect** (T-046), as OpenSSH's `ssh -G`
  does: a line of `keyword value` for each keyword of OpenSSH that podssh
  applies, with the defaults, in OpenSSH's order and spelling (`true` and
  `false` where OpenSSH writes them), then exit 0 with nothing opened: no
  relay, no token. A script can compare the two line by line. The defaults
  that differ do on purpose: `serveraliveinterval 60` (the relay's idle
  cut), `connecttimeout 60`, and the lists of algorithms, which are what
  podssh will offer (T-505). podssh tries the `_sk` identity files too,
  as OpenSSH does: a key of a security key signs in its device (T-229).
  podssh's own settings (relay hosts, `--ca-file`)
  print no line, as OpenSSH knows no such keyword; `podssh status` shows
  them.
- **A repeated value follows OpenSSH** (measured with `ssh -G`): the first
  `-p` and `-l`, the last `-e`, `-E` and `-F`, and the first value of each
  `-o` keyword. A second `-J` or `-W` is an error, as in OpenSSH. podssh's
  own `--relay-host`, `--relay-addr` and `--ca-file` may be given once: a
  comma list gives several hosts or addresses, and no relay or trust store
  is chosen by its place on the command line.
- Each flag in the usage of OpenSSH 10.3p1 has a row: supported, accepted
  with no effect (such as `scp -3`), or refused by name with what to use
  instead.
  `tests/flag_table.rs` holds the reviewed set. A refusal with nothing to use
  instead says "Leave it out."
- **`%` tokens are OpenSSH's** (ssh_config(5); the values of
  `DEFAULT_CLIENT_PERCENT_EXPAND_ARGS` in OpenSSH 10.3p1). In `-i`,
  `IdentityFile`, `UserKnownHostsFile`, `GlobalKnownHostsFile`,
  `IdentityAgent` and `ForwardAgent`: `%%`, `%C` (the SHA-1 of `%l%h%p%r%j`), `%d`, `%h` (the
  host, lowercased unless it is an address), `%i` (the user id), `%j` (the
  host of the last jump), `%k` (`HostKeyAlias`, else `%n`), `%L`, `%l`
  (the local host name, and its first label for `%L`), `%n` (the host as
  typed), `%p`, `%r` (the remote user) and `%u` (the local user, from
  `PODSSH_USER`, `USER`, `LOGNAME` or `USERNAME`, else the effective uid's
  entry in the user database, T-500). An unknown token, or one whose value
  podssh does not know, is refused (exit 64); OpenSSH refuses an unknown one
  too. `RemoteCommand` takes the same tokens, and `User` from `-o` or from a
  file takes them but `%C` and `%r`; `-l` and `user@host` take none, as in
  OpenSSH (T-273). `HostKeyAlias` is lowercased, as OpenSSH lowercases it.
  `-E FILE` is opened with the name as typed, as OpenSSH opens it. The gate
  compares the tokens with `ssh -G`.
- **`${NAME}` in those paths is a variable**, in the same pass as the
  tokens, so a variable's value takes no token; a variable that is not set
  is refused (exit 64), as OpenSSH 10.3p1 refuses it (T-036). A whole
  `$NAME` as the value of `IdentityAgent` or `ForwardAgent` is OpenSSH's
  older form: the variable that holds the path, and no agent when it is not
  set; `-G` prints it as given. Elsewhere `$NAME` is part of a file name.
- **A key's echo while a download runs** (T-661, `crates/podssh-ssh/src/pace/`).
  The window that podssh grants a channel bounds what its server has in flight,
  and so what waits in front of a key's echo in each queue between, the relay's
  too. For 2 s after a key on a session with a pty, each channel of the
  connection (the session's own, so that Ctrl-C shows sooner, the forwards,
  SFTP, a command, the agent's) gets the path's rate times its least round trip
  plus 40 ms, and a third more, as russh tops a window up once a quarter of it
  is used, not half, so that a window that bounds the flow grows (T-670);
  16 KiB at least, shared among the channels that carry bulk. Idle, plus
  200 ms. Each channel takes messages of 8 KiB at most (OpenSSH's client asks
  for 32 KiB), so that a slow path's window holds a few. The rate is the most
  bytes a second of the last 5 to 10 s; the round trip is the time from a
  window adjust to the first byte that only it allowed, less that message's
  time on the path, the least of the last 10 to 20 s: end to end, through any
  relay or proxy, against any sshd. To time the path and not its queue, the
  windows drain to 16 KiB at the first key after a pause and each 10 s of a
  download until a round trip is timed with no other bulk in flight, 10 s at
  most, not until a guess from the rate (T-670). Unmeasured, a channel has the
  window of before, 512 KiB, topped up at half. Where nobody types, the same
  rule grows a window past it, up to the cap of the road, as a window is what a
  road holds for a slow reader (T-662): 16 MiB on `--direct` (and on the direct
  road after the relay hosts), on the iroh road and at podssh's relay role (its
  resumable layer); 1.5 MiB through the default relay, under the 2 MiB of its
  `1013`; 768 KiB on a node's pair road, the layer's window there (T-443);
  512 KiB on each other road. The channels that carry bulk share the cap, each
  512 KiB at least, and a `-J` hop's channel has the whole of it. russh asks
  the handler for each target (`vendor/patches/russh/0002-window-target.patch`)
  and its room (`vendor/patches/russh/0004-window-low.patch`). podssh's own
  senders (the local side of `-L`, `-R` and `-D`, `-W`, SFTP's writes and the
  copy by exec) wait while a key waits for its echo, 1 s at most; the session's
  next output is the echo. On the direct road, `TCP_NOTSENT_LOWAT` of 16 KiB
  where `setsockopt` takes it (Linux, macOS); `-v` says a refusal.

## Forwarding

- `-L` and `-D` (T-038) listen here, as the operator ruled
  ([decisions.md](decisions.md), 2026-10-08): a listener that the user
  asks for, made before anything connects; the bind and the listen are the
  probe. One that cannot be made ends the run (255) with the system's words
  and `-W HOST:PORT`, which needs none; `PODSSH_LISTEN=no` refuses each
  (78), as for `podssh pipe` and `podssh agent`.
- The forms are OpenSSH's `parse_forward`: `-L [bind_address:]port:host:hostport`,
  `-L [bind_address:]port:remote_socket`, `-L local_socket:host:hostport`,
  `-L local_socket:remote_socket`; `-D [bind_address:]port` and, beyond
  OpenSSH, `-D local_socket`; `-o LocalForward` with a space between the
  two sides, and `-o DynamicForward`. A field in brackets is taken as it
  is, a backslash makes the next character plain, a field with a `/` is a
  socket path, and `${NAME}` is a variable. A port of 0, and a port that
  is not a number, are refused (OpenSSH also looks a name up in the
  services database).
- The address: a port with no address listens on 127.0.0.1 and ::1, or with
  `-g` or `GatewayPorts yes` on 0.0.0.0 and ::; `localhost` is loopback,
  `""` and `*` each address, another is that address, as OpenSSH's
  `channel_fwd_bind_addr` chooses for a client. One of two addresses may
  fail, not both. A TCP port takes each local user, and other hosts when
  it is not loopback, which podssh says without `-v`. A socket path is the
  listener of `podssh pipe unix-listen:`: mode 0600, a client of another
  user is closed, and a socket that nobody serves is removed first.
- Each connection goes to the destination over a new channel:
  `direct-tcpip` with the client's address as its originator, or
  `direct-streamlocal@openssh.com` to a socket on the server. `-D` speaks
  SOCKS4, SOCKS4a and SOCKS5 with CONNECT and no authentication, and
  answers once the server opened the channel, with the reason of a refusal
  (OpenSSH answers first); BIND, UDP ASSOCIATE and authentication are
  refused. The channels of many connections open at the same time; a
  server may take 60 s to open one, and a SOCKS client 30 s to ask.
- `ClearAllForwardings yes` drops each `-L`, `-D` and `-R`, and `-W`
  implies it, as in OpenSSH. `-G` prints `clearallforwardings`,
  `gatewayports`, `dynamicforward` and `localforward` as OpenSSH 10.3p1
  does.
- `-R [bind_address:]port:host:hostport` (T-035) needs no local listener:
  the server listens, and podssh connects out for each connection that it
  takes, as one more outbound connection, through `HTTPS_PROXY` when it is
  set and within 20 s. On the measured sandbox a connection back to
  loopback is refused; podssh then closes that channel, and says why on
  stderr. `-o RemoteForward=[bind_address:]port host:hostport` is the same,
  and each one is kept. A port of 0 lets the server choose, and podssh
  prints it, as OpenSSH does.
- `-R` takes each form of OpenSSH (T-365), read as `-L` reads its own: a
  socket path on the server (`remote_socket:host:hostport`), asked for with
  `streamlocal-forward@openssh.com`; a socket on this host as the target
  (`[bind_address:]port:local_socket`, `remote_socket:local_socket`), on
  Unix; and a SOCKS proxy that the server listens for and podssh serves
  (`[bind_address:]port`, or `remote_socket` alone): SOCKS4, SOCKS4a and
  SOCKS5 with CONNECT, as `-D` reads them, each target dialed from this
  host through `HTTPS_PROXY`, and the answer sent after the dial, so that a
  target that is down gets its code. A channel for a path that podssh did
  not ask for is refused. `~C -KR PATH` and `-O cancel` stop a forward of
  a path; `-G` prints each form as OpenSSH 9.6p1 does (a SOCKS one as
  `[socks]:0`). A server that refuses a path (sshd's
  `AllowStreamLocalForwarding no`, or one that it cannot bind) gives no
  reason, so podssh names the path.
- A server that refuses `tcpip-forward` gives no reason (RFC 4254, section
  4, has no field for one), so podssh names the port: a warning, or with
  `-o ExitOnForwardFailure=yes` the end of the run (exit 255). A channel
  that the server opens for a port that podssh did not ask for is refused.
  A server of Go's x/crypto/ssh (gliderlabs/ssh, and the gateways built on
  it) puts words after its refusal anyway, and data after its answer to a
  keepalive that it does not know: podssh reads past them, as OpenSSH's
  client does, so the refusal is the same warning there, and the default
  keepalive (each 60 s) holds a quiet session (T-460). russh 0.65.0 ended
  the connection on such data; `vendor/russh` carries the repair
  (`vendor/README.md`). A connection that ends while the forwards are asked
  for names its cause: the server's words, else the error.
- `-A` forwards the agent (T-036), off by default as in OpenSSH; `-a`
  turns it off, and the last of the two wins, over `-o ForwardAgent`, whose
  first value wins. podssh asks for it on the destination's session
  (`auth-agent-req@openssh.com`) before the shell or the command, never on
  a jump host of `-J`, and joins each agent channel that the server then
  opens to a new connection to the agent: the one that podssh logs in with
  (`IdentityAgent`, else `SSH_AUTH_SOCK`; on Windows also OpenSSH's named
  pipe, then Pageant), as OpenSSH forwards the agent of `IdentityAgent`, or
  the one of `-o ForwardAgent=PATH` or `$NAME`. It is one more connection
  to a local socket or pipe; nothing listens. An agent that does not answer
  within 10 s refuses that channel, and podssh says so once.
- **The risk:** while the session lasts, the server, and root on it, can
  use each key of the agent, though it cannot read one. Before the server's
  first byte on each agent channel, podssh binds the agent to the server's
  host key, as OpenSSH does (`session-bind@openssh.com`, T-279: the host
  key, the session identifier and the server's signature of it, from the
  first key exchange, which russh 0.65.0 gives the client, T-356), so an
  OpenSSH agent hides and refuses each key that
  `ssh-add -h` limits to other hosts. An agent that refuses the bind (one
  that knows no extension: Pageant, `podssh agent`) serves the channel
  unbound, as with OpenSSH, and `-v` says so; one that does not answer it
  within 30 s refuses the channel. Forward only to a server that you trust, or
  use `-J`, which needs no agent on the server. `podssh scp`, `podssh sftp`
  and `podssh cp` run nothing on the server that would use an agent:
  their `-A` is accepted and forwards none.
- A channel that the server opens for the agent with no `-A`, or on a jump
  host, is refused as administratively prohibited, with a warning, as
  OpenSSH refuses it. A server that refuses the request says so, and the
  session goes on without the agent.
- `-X` and `-Y` forward X11 (T-037) to the display that `DISPLAY` names,
  off by default; `-x` turns it off, and the last of the three wins, over
  `-o ForwardX11`. The server listens; for each `x11` channel that it opens,
  podssh connects to the local X server (`:N` is the socket
  `/tmp/.X11-unix/XN`, on Windows TCP port 6000+N; `HOST:N` is TCP port
  6000+N of HOST), as one more local connection, and puts the real cookie in
  place of a spoofed one: the server is given a random cookie of the same
  length (`x11-req`), never the real one, and a channel whose X client sends
  another is closed. `-Y` uses the cookie of the authority file
  (`XAUTHORITY`, else `~/.Xauthority`, read by podssh itself), and gives the
  server's X clients the access of each local one. `-X` uses an untrusted
  cookie that `xauth` makes (`XAuthLocation`, else `xauth` in `PATH`), which
  lasts `ForwardX11Timeout` (20 minutes), after which a new X11 channel is
  refused; with no `xauth`, `-X` is refused, naming `-Y`.
  `ForwardX11Trusted yes` makes `-X` act as `-Y`. Before anything connects,
  podssh checks `DISPLAY`, that its X server answers, and that there is a
  cookie, or that the X server takes a connection with none (as VcXsrv and
  X410 do with access control off); a check that fails ends the run with
  255 and its reason, where OpenSSH goes on with no X11. X11 goes on a
  session alone (with `-N` or `-W` it is not asked), on the destination
  alone, never on a jump host, and such a run makes a connection of its
  own, with no `ControlPath`. **The risk:** with `-Y`, a program on the
  server can read what you type in each X window and draw in each; forward
  only to a server that you trust.

## Connection sharing

`-M`, `-S`, `-O`, `ControlMaster`, `ControlPath` and `ControlPersist`
(T-039), on Unix: OpenSSH's control socket and its protocol
(`PROTOCOL.mux` version 4), so OpenSSH's `ssh -O check` and its clients
work with a podssh master, and podssh's client with an OpenSSH master. A
client passes its stdin, stdout and stderr to the master (SCM_RIGHTS),
which Windows cannot: there `-M`, `-S` and `-O` are refused (64), and the
keywords have no effect.

- A master: `-M` (`-MM` asks), or `ControlMaster yes`, `ask`, `auto` or
  `autoask` with `ControlPath` or `-S`. The socket is made before anything
  connects, as `-L` is: `podssh pipe`'s socket of mode 0600, after a
  socket that nobody serves is removed; a client of another user is closed
  (root may use it, as in OpenSSH); the socket goes when the master ends.
  A socket that cannot be made refuses the run with `-M` (255), and with
  `auto` it is said and the run connects alone; `PODSSH_LISTEN=no`
  refuses a master as each listener.
- A client: `-S PATH`, or `ControlPath` with `ControlMaster no`, `auto` or
  `autoask`. When a master answers, the run goes through it: its `-L`,
  `-D` and `-R` first, as OpenSSH's client sends them, then its session or
  its `-W`; with `-N`, the forwards stay with the master and the run ends.
  When none answers, the run connects alone, and with `auto` it becomes the
  master. A session with a pty puts the local terminal in raw mode and
  relays SIGWINCH to the master, which reads the new size from the terminal
  it holds; the exit code is the master's EXIT_MESSAGE, or 255 with none.
- The master serves sessions (a pty, the environment, a subsystem, the
  escape character of the client), `-W`, `-O check`, `exit` (the master
  ends with 0), `stop` (no new client; the socket goes), and `forward` and
  `cancel` of `-L`, `-D` and `-R`, which it serves on its own connection.
  `-O proxy` is refused. `ControlMaster ask` confirms each request that
  changes something on the terminal or through `SSH_ASKPASS`.
- `ControlPersist yes|TIME` keeps a `-N` master for that long with no
  client (`0` is forever, as in OpenSSH). A master with its own session
  ends with it, once its clients' sessions have ended: start a lasting
  master in the background with `podssh ssh -f -M -N -S PATH HOST` (T-380).
  `--persist` does not take part.
- Every client shares the master's one relay session, and its limits
  (`docs/relay.md`); a drop of the master ends each client's session.
- Read from OpenSSH 10.3p1's own bytes (`scripts/mux-capture.py`): each
  `bool` of `PROTOCOL.mux` is a `uint32`, and the port of a stdio forward
  a `uint32`, not the string that the document says.

## SSH inside TLS: `ssh+tls://`

T-372, GitHub #61: some SSH servers on port 443 sit behind TLS, as stunnel
serves them, and a proxy that waits for TLS on port 443 resets plain SSH.
`ssh+tls://[user@]HOST[:PORT]` (port 443 by default) is such a hop, as the
destination or as any hop of `-J`:

- TLS over the stream that reaches the hop: the relay's, `--direct`'s
  through `HTTPS_PROXY`, or the `direct-tcpip` channel of the hop before it;
  its certificate checked for `HOST` with podssh's trust (`--ca-file`,
  `SSL_CERT_FILE`, `CaFile`, else the system's stores and the compiled-in
  roots), as each of podssh's TLS is.
- SSH inside it, the host key checked as for each hop and recorded under
  `[HOST]:PORT`.
- A failure names its step: the connection, TLS (an unknown issuer with
  what to do, T-340, or a certificate for another name), or SSH.
- `podssh doctor --hop ssh+tls://...` runs its three probes inside TLS.

Tested against stunnel in front of the test's SSH server
(`crates/podssh-cli/tests/ssh_tls_hop.rs`).

## Shadowsocks servers: `--shadowsocks FILE`

T-373, GitHub #62: a Shadowsocks server takes a target in an address header
and dials it, as the relay's forward path does, with a key in place of a
token. `--shadowsocks FILE` makes the servers of FILE the road, in place of
the relay, for `ssh`, each command that reaches its server as `ssh` does,
and `proxy`:

- FILE is private, as a pair file is: a regular file of the user that
  others cannot read (78 otherwise). Each line is an `ss://` URI of SIP002
  (`ss://USERINFO@HOST:PORT#TAG`, USERINFO `method:password` in base64url or
  percent-encoded; the older form, all of it in base64, is read too), or
  `subscription https://URL`; `#` starts a comment. A line that cannot be
  read is refused by its number, never its text, as it holds a password. The
  URI comes from a file and never from the command line, where argv would
  show the password.
- The AEAD form alone: `chacha20-ietf-poly1305`, `aes-256-gcm` and
  `aes-128-gcm`, written in podssh-ws with the ciphers of podssh's own TLS
  (`crates/podssh-ws/src/shadowsocks/`): a salt, then chunks, each the
  payload's length sealed on its own and the sealed payload; the master key
  by `EVP_BytesToKey` with MD5, each stream's key by HKDF-SHA1 with
  `ss-subkey`; the nonce a counter of 12 bytes, little-endian, that each seal
  and each open takes. Shadowsocks 2022 (`2022-blake3-...`) and a key that
  names a plugin, another program, are refused by name (78).
- The servers are tried in the order of the file, as the relay hosts are:
  TCP to the server, through `HTTPS_PROXY` when one is set, then the salt and
  the target's address in the first chunk. `ssh` waits 10 s for the server's
  salt and first chunk, as the SSH server behind it speaks first; a server
  that is silent, closes, or whose chunk does not open gives way to the
  next. Silence names the proxy as the likely cause when one carried the TCP
  (T-317's wording), else the password or the method. `proxy` takes a server
  that says nothing for 3 s, as a pipe's client may speak first.
- A subscription is fetched through the proxy over TLS, with podssh's trust,
  at most 1 MiB: lines of `ss://`, the same in base64, or SIP008's JSON;
  other schemes are counted and passed over. Its list is kept in the cache as
  `shadowsocks-HASH.json` (mode 0600, under a hash of the URL), read for a
  day, and fetched again when each kept server failed. At most 16 servers of
  a list are tried. A line shows a subscription by its host alone, as its
  path may hold the provider's token.
- A run has one road: `--relay-host`, `--relay-failover`, `--direct`,
  `--forwarder`, `-4`, `-6` and a destination with a road of its own are
  refused beside it (64). The host key of SSH protects the session, as on
  each road.
- `podssh doctor --shadowsocks FILE` gives a line for the first server: the
  TCP, the salt and the first chunk with their time, then GitHub's published
  host key on `github.com:22` through it.
- A published key is shared with strangers, has no operator who answers for
  it, and changes: podssh names no server and no list, and its tests use
  servers that podssh did not write on the loopback, never a public one.

Tested against `ssserver` and `sslocal` of shadowsocks-rust
(`crates/podssh-cli/tests/shadowsocks_cli.rs`), and against a codec written
from the specification with known answers that OpenSSL computed
(`crates/podssh-ws/tests/shadowsocks.rs`).

## A forward proxy over TLS: `--via URL`

T-439, the operator's ruling Q66: a standard forward proxy that the user
runs over TLS (Caddy with forwardproxy, squid's `https_port`, h2o) is a road
with no relay. `--via https://[USER@]HOST[:PORT]` makes it the road, in
place of the relay, for `ssh`, each command that reaches its server as
`ssh` does, `proxy`, `pipe` (its `tcp:` and the first hop of `ssh:`) and
`doctor`, which checks it:

- podssh dials the proxy as it dials the relay, through `HTTPS_PROXY` when
  one is set (by its name, as the host's proxy resolves it), then TLS checked
  for HOST with podssh's trust (`--ca-file`, `SSL_CERT_FILE`, the stores).
  The port is 443 when none is named. A scheme other than `https://`, a
  path, a query and a password in the URL are refused (64).
- ALPN offers `h2`, then `http/1.1`, and the proxy chooses
  (`PODSSH_VIA_HTTP=1.1` or `2` offers one alone). On HTTP/2 the tunnel is
  a CONNECT of RFC 9113, section 8.5: `:method CONNECT` and `:authority
  HOST:PORT`, no `:scheme` or `:path`; its DATA frames carry the bytes, and
  END_STREAM is the half-close. The connection is kept for the run, so that
  the sessions of `podssh each` are streams of one connection; `-v` says
  whether a session took a new connection or shared one. A proxy that resets
  the CONNECT on HTTP/2 gets HTTP/1.1 on a connection of its own, and `-v`
  says why. A reset with `CONNECT_ERROR` is the proxy's word that the target
  failed, and nothing is tried again.
- On HTTP/1.1, `CONNECT HOST:PORT HTTP/1.1` with `Host` and `User-Agent`,
  and the answer's head read a byte at a time, so that the target's first
  bytes stay in the tunnel.
- The credentials are Basic, from `--via-auth-file FILE` or
  `PODSSH_VIA_AUTH_FILE`: a regular file of the user that others cannot
  read (78 otherwise), one line, `USER:PASSWORD`, or the password alone when
  the URL names USER. A URL that names a user with no file is refused (64).
  On HTTP/2 the header is sensitive, so HPACK never indexes it. No message
  shows the line.
- A `407` is said with its words: the schemes of `Proxy-Authenticate`, and
  whether podssh sent credentials or none, with the flag to give them
  (77, as `proxy` exits for a refusal of the proxy's; 403 too).
- `PODSSH_VIA` names the proxy where the command line names no other road
  (`--relay-host`, `--relay-failover`, `--forwarder`, `--shadowsocks`);
  beside `PODSSH_RELAY` or `PODSSH_FORWARDER` it is refused (78). A run has
  one road: `--via` beside one of those flags, `--direct`, `-4`, `-6` or a
  destination with a road of its own is refused (64).
- `podssh doctor --via URL` gives a line in its section `via`: the host's
  proxy that carried the TCP, if one did, the version of HTTP that the
  proxy chose and the time of its CONNECT, then GitHub's published host key
  on `github.com:22` through it.

Tested against stand-ins on the loopback, h2's own server for HTTP/2
(`crates/podssh-ws/tests/via.rs`), and against Caddy with forwardproxy and
squid over TLS in containers, through a plain squid as the host's proxy
(`scripts/interop-via.sh`, `.github/workflows/via-interop.yml`).

## VLESS servers: `--vless FILE`

T-440, the operator's ruling Q66: a VLESS server that the user runs
(Xray-core, shoes, sing-box) takes the target from a short header and dials
it, so it is a road with no relay. `--vless FILE` makes the servers of FILE
the road, in place of the relay, for `ssh`, each command that reaches its
server as `ssh` does, `proxy` and `doctor`, which checks each:

- FILE is a regular file of the user that others cannot read (78
  otherwise), as a pair file: a share link on each line, as panels and
  Xray-core's clients give them,
  `vless://ID@HOST:PORT?type=ws|xhttp&security=tls|none&sni=&host=&path=&mode=#TAG`;
  `#` starts a comment. The ID is a UUID (the dashes optional), or a word of
  1 to 30 bytes, which is UUIDv5 of it under the zero namespace, as
  `XTLS/Xray-core:common/uuid/uuid.go` maps it. No message shows a line or an
  ID: a refusal names the line's number.
- VLESS's request (`crates/podssh-ws/src/vless/header.rs`): the version 0,
  the ID's 16 bytes, no add-ons, the command TCP, the port, then the address
  (a type byte: 1 IPv4, 2 a name, 3 IPv6). The server's answer is the
  version and its add-ons, sent with the target's first bytes; a server that
  refuses the ID, or cannot reach the target, ends the session with none.
- `type=ws`: TLS to HOST:PORT through `HTTPS_PROXY` when one is set,
  checked for `sni` (else `host`, else HOST), then the upgrade at `path` with
  `host` in `Host`, and the stream in binary messages; the request rides the
  first, with no early data in a header. A refused upgrade says that
  `type=xhttp` passes where the upgrade does not.
- `type=xhttp`: XHTTP on HTTP/2, `h2` chosen by ALPN (or HTTP/2 with no TLS
  for `security=none`), each request with the padding that the server
  checks, `Referer` with a query `x_padding=` of 100 to 1000 `X`.
  `mode=packet-up` (and `auto`, as Xray-core's client takes it with TLS): a
  streamed GET of `PATH/SESSION` down, and a POST of `PATH/SESSION/SEQ` for
  each chunk up, one at a time, at most 1,000,000 bytes each; `stream-up`: the
  same GET, and one streamed POST up; `stream-one`: one POST to the path,
  its body up and its answer down. A streamed upload says
  `Content-Type: application/grpc`. A server that chooses HTTP/1.1 is
  refused (`proxy` exits 78, and `ssh` 255, as for each first hop that it
  does not reach): its split modes need a second connection, which this road
  does not open (Q67, T-456).
- The link's `extra` (JSON of `xhttpSettings`) gives `headers`,
  `xPaddingBytes`, `noGRPCHeader`, `scMaxEachPostBytes` and `mode`; a key that
  only paces or pools Xray-core's own client is passed over, and each other
  key is refused by its name unless it holds its default.
- A flow (`xtls-rprx-vision`), REALITY, VLESS's encryption and `type=tcp`
  are refused (78) by their names.
- The servers are tried in the order of the file. An SSH session waits up to
  10 s for VLESS's answer, which comes with the server's version line; a
  pipe of `proxy` takes the stream after 3 s of silence, as its client may
  speak first. Xray-core holds a session to a private address with no word
  for a VLESS inbound, unless the `finalRules` of its `freedom` outbound
  allow it (`proxy/freedom/freedom.go`), and the line of the wait says so. A run has one road: `--vless` beside `--relay-host`,
  `--relay-failover`, `--forwarder`, `--shadowsocks`, `--via`, `--wstunnel`,
  `--direct`, `-4`, `-6` or a destination with a road of its own is refused
  (64).
- `podssh doctor --vless FILE` gives a line in its section `vless` for each
  server, and for each mode where a link says `auto`: the transport that
  carried it and the time of VLESS's answer, then GitHub's published host
  key on `github.com:22` through it.

Tested against stand-ins on the loopback, h2's own server for XHTTP
(`crates/podssh-ws/tests/vless.rs`), and against Xray-core and shoes in
containers, through a plain squid as the host's proxy and behind nginx,
which does not pass the upgrade (`scripts/interop-vless.sh`,
`.github/workflows/vless-interop.yml`).

## A wstunnel server: `--wstunnel URL`

T-441, the operator's ruling Q66: a server of erebe/wstunnel that the user
runs (`wstunnel server wss://[::]:443`), one static binary that takes the
destination from its client, is a road with no relay.
`--wstunnel wss://HOST[:PORT]` makes it the road, in place of the relay, for
`ssh`, each command that reaches its server as `ssh` does, and `proxy`. The
protocol is read in wstunnel's source at v11.1.0, and at v10.0.1 and v9.7.4
for the versions before it (`crates/podssh-ws/src/wstunnel/`):

- podssh dials the server as it dials the relay, through `HTTPS_PROXY` when
  one is set, then TLS checked for HOST with podssh's trust (`--ca-file`,
  `SSL_CERT_FILE`, the stores); `ws://` has no TLS. The URL takes no path,
  no query and no user (64); `https://` and `wts://`, wstunnel's HTTP/2 and
  WebTransport, are refused with the scheme that the same server takes,
  as each server serves its WebSocket and its HTTP/2 on one port.
- The upgrade is `GET /PREFIX/events`, with
  `Sec-WebSocket-Protocol: v1, authorization.bearer.JWT`. The JWT's claims
  are those of wstunnel's client: an id (a UUID of version 4), the protocol
  `{"Tcp":{"proxy_protocol":false}}`, the host (an IPv6 one in brackets)
  and the port. It is signed with HS256 and the key that wstunnel 9.1 to
  10.0 check, a constant of its public source; 10.1 and later check no
  signature, so the one token serves 9.1 to 11. A server of 9.0 or before
  reads the protocol `Tcp` with no field, and cannot read it.
- What the server checks of a client comes from `--wstunnel-secret-file
  FILE` or `PODSSH_WSTUNNEL_SECRET_FILE`: a regular file of the user that
  others cannot read (78 otherwise), with `path-prefix PREFIX` (the prefix
  that the server's restriction holds as its secret), `credentials
  USER[:PASSWORD]` (Basic, as wstunnel's own client encodes it) or
  `authorization VALUE` (the header as it is), for a restrictions file that
  matches `Authorization`; or one line, the prefix alone. With no file,
  podssh is the client of wstunnel's defaults: the prefix `v1`. A secret
  over `ws://` goes to this host alone (64). No message shows a line of the
  file; one names it by its number.
- The server dials the target before it answers. Its 101 names the
  subprotocol `v1`; one that does not is no wstunnel server that podssh
  speaks to, and is said so (69). Each refusal is a 400 whose body names no
  cause: "Invalid request" from 10 on, "Invalid upgrade request" before.
  podssh quotes it and says what it means in that version: a path prefix or
  an `Authorization` that the server does not take, a target that its
  restrictions do not allow, or one that it could not reach, and that its
  log names which; or, from 9, a server too old for the token (77, as a
  refusal of the server's; a 401 or 403 of a server in front of it too).
- The bytes go in binary frames, each masked with a key of zero: wstunnel's
  server takes a payload without its mask unless it runs with
  `--websocket-mask-frame` (fastwebsockets 0.10 applies a mask on reads
  only when told), so a fresh key would change each byte, and a key of
  zero reads the same either way. The mask bit stays set, as RFC 6455 asks
  of a client; the bytes are SSH's, or TLS's under `wss://`.
- `PODSSH_WSTUNNEL` names the server where the command line names no other
  road (`--relay-host`, `--relay-failover`, `--forwarder`, `--shadowsocks`,
  `--via`, `--vless`); beside `PODSSH_RELAY`, `PODSSH_FORWARDER` or `PODSSH_VIA` it is
  refused (78). A run has one road: `--wstunnel` beside one of those flags,
  `--direct`, `-4`, `-6` or a destination with a road of its own is refused
  (64).
- `podssh proxy --wstunnel URL HOST PORT` carries the pipe; the end of stdin
  sends no Close, as a Close is no half-close, and the server's Close ends
  the pipe once the target closed.

Not taken (T-441's Decision): wstunnel's HTTP/2 and WebTransport, a check
of `doctor`, and `pipe`'s `tcp:`. Tested against stand-ins on the loopback
that read a client as wstunnel's server does
(`crates/podssh-ws/tests/wstunnel.rs`), and against wstunnel's own server
of the pinned release in a container, with OpenSSH's sshd as the target
(`scripts/interop-wstunnel.sh`, `.github/workflows/wstunnel-interop.yml`).

## Going to the background: `--detach` and `-f`

T-380, after the study of `docs/detach.md`: a run that must outlive its
call goes to the background by podssh itself, where `&` and `nohup` fail
(a closed pty's SIGHUP, a background job's read of the terminal, a caller
that reads its pipes to their end or kills their holder's group, a busybox
with no `nohup`).

- `podssh ssh -f` (`--detach`, or `ForkAfterAuthentication yes`), with a
  command or `-N`, as OpenSSH's `-f`; a shell or `-W` is refused (64). Ready
  once the request went: after the login, with `-L`, `-D` and a control
  socket bound before it. A command reads no stdin (`-n`), and its output
  goes to the log.
- `podssh pipe --detach`, with a listening side whose other side is not
  stdio: ready once it listens.
- `podssh node --detach`: ready once the node is online (a quick tunnel's,
  once registered; the iroh road's, once its ticket is said); with no
  `--install`, `--uninstall` or `--temporary`. For a node that must
  outlive a logout or a reboot, `--install`.

How: the parent starts this program again (`/proc/self/exe`, which runs
this image even when `podssh update` replaced its file, else the path that
the system gives, else the name that started it), with the word
`--detach-child` first, its stdout a pipe back, and its stdin and stderr the
caller's. The child closes each descriptor from 3 up and resets its signals
at its start, then runs the command as in the foreground: its prompts (a
password, a passphrase, a host key) use the caller's terminal. At ready it
sends stdin to the null device and stdout and stderr to its log, leaves the
terminal and its session (`setsid`, SIGHUP ignored; on Windows it frees the
console that it shared, out of the caller's job where the job allows it,
and a console program that it starts later opens no window), and says so to
the parent, which prints the child's pid and log
and exits 0. A child that ends first gives the parent its code, its lines
already on the caller's stderr; Ctrl-C before ready reaches both.

- The log: `detached/VERB-PID.log` in the cache (mode 0600, in a directory
  of mode 0700), cut back past 1 MiB, its earlier part in `.log.1`; none
  with `PODSSH_CACHE_DIR=none`. The cut renames the log and puts a new file
  in place of stdout and stderr (`dup2`; on Windows `SetStdHandle`), so the
  lines written meanwhile go to `.log.1`, where a copy and a cut lost them
  (T-397); a supervisor of `--restart` alone cuts the log that its runs
  share, and each run takes the new file within a minute. Where the rename
  fails, the copy and the cut of before.
- Each start of `--detach` or `-f` removes the files of `detached/` older
  than 30 days whose run runs no more: no lock of the name is held, and the
  process of a log's pid is gone (T-397).
- At ready the run leaves the caller's working directory, which an unmount
  would refuse, for the root (on Windows the system drive's), unless a word
  of the run may still need it: a relative path of this host (a separator,
  a leading `.`, a name of a file there, or the value of a flag that takes a
  file), or a command that runs here (`exec:` of `pipe`, `ProxyCommand`,
  `LocalCommand`, `KnownHostsCommand`). In doubt it stays (T-397).
- Where a sandbox has no `/dev/null`, the run's stdin is a pipe whose writer
  is closed, and with no log its outputs a pipe whose reader is closed; it
  ended with 75 before (T-397). A supervisor's runs take the same.
- Refused as the first process of a namespace (69), which ends with it.
  Named first, as they may still end the run: a unit of systemd
  (`INVOCATION_ID`), WSL (`WSL_DISTRO_NAME`), Termux (`TERMUX_VERSION`), and
  a namespace whose first process is `bwrap`.
- A CI's job ends the run at the job's end: podssh touches no variable by
  which a CI finds its processes (`RUNNER_TRACKING_ID`, `BUILD_ID`,
  `JENKINS_NODE_COOKIE`).
- A login session's scope of systemd, where logind kills a session's
  processes at logout: at ready the run asks the user's systemd, over
  D-Bus, for a scope of its own, `podssh-detached-PID.scope`, as tmux
  does (T-381, Q61); `PODSSH_SYSTEMD=no` asks nothing, `yes` asks outside a
  session too. The user's last logout still ends it where lingering is
  off, as it ends the user's systemd (`loginctl enable-linger`), and its
  log says so.

**`--restart`** (T-390, from the study of the daemonizer d-mon): a server
that only a detached tunnel reaches is locked out when the run ends, by a
crash, an abort or the OOM killer. With `--restart` beside `--detach` (or
`-f`), the parent starts a small supervisor in the child's place
(`--detach-supervise` first, a form that podssh alone writes), which starts
the child, passes on its prompts, lines and ready, then leaves the terminal
itself; the parent prints the supervisor's pid, the run's, and the log.
The supervisor holds no runtime and no connection. Once the run was ready,
it starts the run again after each end, with the relay's backoff (1 s
doubling to 30 s, jittered), the count reset after a run of 30 s, and it
never gives up; it does not restart after 64, 77 or 78, which a new start
would repeat, nor after its own SIGTERM or SIGINT, which it passes to the
run (SIGKILL after 10 s). A restarted run has no terminal: its stdin is the
null device, and its lines go to the same log, each restart a line. A run
that ends before its first ready ends the supervisor with its code, as
without `--restart`. Not adopted from d-mon: PDEATHSIG (a supervisor that is
killed leaves the run going), a cap of restarts over the run's whole life,
and a restart before the first ready. After 5 runs in a row that end within
10 s of their start, it starts the binary that `podssh update` kept,
`podssh.prev` (T-396), where it runs here. Without `--detach` it is refused
(64).

**The heartbeat** (T-394): a run that hangs (a deadlock, a stopped process,
a runtime that no longer polls) stays alive to each check, and serves
nothing. Each run that a supervisor starts sets the time of
`detached/NAME.alive` each 10 s, from a task of its own runtime, which runs
only while the runtime polls; the supervisor reads it each 10 s, and ends a
run whose file has not changed for 90 s (SIGTERM and SIGCONT, as a stopped
process acts on SIGTERM only once it goes on; SIGKILL after 10 s), with a
line, then starts it again. It compares the file's times with each other,
never with its clock, so a clock that jumps ends no run; and it watches a
run only once it has seen it beat, so a run that cannot set the time (no
cache) is never ended for it, with a line: a run ended each 90 s would lock
its server out. It sets the file's time, not its bytes, which a full disk
still takes. `podssh detached status` shows the age of the last beat.

**`--detach-name NAME` and `podssh detached`** (T-392, from the same
study): a run in the background holds the lock of its name,
`detached/NAME.lock` in the cache, from before its connection to its end;
with `--restart` its supervisor holds it, so that each restart keeps it,
and each run that the supervisor starts holds `NAME.run.lock`, so that a
run whose supervisor died still holds its name. A second start of a name
that runs (a cron line, a unit, a person) refuses with 75 before it
connects, and names the pid that runs, where it would start a second copy
that the relay refuses for a node of the same pair (409) and that a `-R`
forward meets as a port in use. With no `--detach-name`, the name is the
verb and the holder's pid (`ssh-4242`), which no other running run has, so
a run with no name is never refused. The kernel lets a lock go when its
process ends, however it ends (`flock`, or `LockFileEx` on Windows, as
`File::try_lock` takes them), so no stale file keeps a name taken; with no
cache (`PODSSH_CACHE_DIR=none`) there is no lock, a line says so, and the
run goes on. Beside the lock, `NAME.json` records the run: its pid, the pid
of a supervisor's run, its words, its log and its start.
`podssh detached list` writes a line for each run (its name, its state, its
pid, its words); with none, stdout stays empty and one line on stderr says
that no run is known and names the directory read, none with `-q`; `list
--json` writes one object, `runs` (`[]` for none) and `dir` (T-506).
`status NAME` writes its fields, with 0 when it runs and 69 when
it does not; `stop NAME` sends SIGTERM to the holder of the name, then
SIGKILL after 10 s to each holder still there, the supervisor first (on
Windows `TerminateProcess` at once, the supervisor first), and exits 0 once
each lock is free. Each trusts the locks, never a pid alone: a record stays
after its run ended, and the system gives its pid to another process; a pid
is signalled only while its run's lock is held, and it is the pid that the
holder wrote. The same lock now guards the socket of `podssh session`: two
starts of one name could both find its path free, and the second, whose
bind failed, removed the first's socket; its daemon holds `NAME.sock.lock`
for its life, and a second one is refused (69).
On Windows the supervisor's end leaves the run; it has no signal to pass.

## `podssh each`

`podssh each [OPTIONS] HOSTS [--] COMMAND...` runs one command on each host
of a list (T-183, `crates/podssh-cli/src/each/`). It is a verb of its own:
`podssh ssh` keeps the command line and the exit codes of OpenSSH for one
host, and a list of hosts changes both.

- **The hosts** are a comma list of `[user@]host[:port]`, each named in the output as it is written; a
  blank or a tab parts no hosts here (T-504): `'a b'` is refused with 64, and the refusal gives `a,b`.
  A host named twice runs once. Each one is resolved as `podssh ssh` resolves a destination, with the
  `Host` blocks of `ssh_config` for that host, before anything connects: a bad host fails
  the whole run with 64, and nothing has run anywhere.
- **Braces and groups** (T-184, `crates/podssh-cli/src/hosts.rs`) are
  expanded first, so that a shell that has no braces (dash, cmd,
  PowerShell) and a settings file can name many hosts. An item takes the
  braces of bash, in bash's order: `PREFIX{A..B}SUFFIX` (numbers, with the
  zero padding of the wider of A and B when either starts with 0, as
  `{01..12}`; or letters, `{a..c}`), `{A..B..N}` with a step,
  `{a,b,c}` (an empty item gives the rest alone), and each nested. `@NAME`
  is a group of the settings file (below), whose hosts are a list of the
  same kind and can name groups. A word gives 1000 hosts at most; more,
  none, an empty host, a range that runs backwards (bash would count down),
  braces that hold nothing or neither a list nor a range, a blank inside
  braces, and a group that is not there are usage errors (64). Square
  brackets stay an IPv6 literal (T-007), as in `pdsh` they would be a
  range: braces are what users of bash and csshw know. `podssh ssh` takes a
  pattern that gives one host, such as a group of one, and refuses one
  that gives more, with 64 and `podssh each` in the message. The settings
  for each host stay in the `Host` blocks of `ssh_config` (T-043): a group
  is a list of names, never their settings.
- **The options** are those of `ssh` that make sense for many hosts: `-p`
  and `-l` (for each host that names none), `-i`, `-o`, `-F`, `-J`, `-v`,
  `-q`, `--direct` and the relay's. `--parallel N` runs at most N hosts at
  once (8 by default, 64 at most), each on a connection of its own, in one
  process and one runtime, on the road and the SSH client of `ssh`: no
  second client. `--snippet NAME` and `--yes` run a command of the
  settings file on each host (see "Snippets").
- **No terminal, no input, no question.** Each session has no pty (`-T`)
  and reads no stdin (`-n`). `BatchMode` is on: an unknown host key
  refuses its host and gives its fingerprint and
  `-o StrictHostKeyChecking=accept-new`; a password is never asked. The
  keys that `accept-new` records go in one at a time, also within the
  process (T-029 covers two processes). A `SessionType` of `ssh_config`
  that asks for no command is refused (64), and so is a `node://` or
  `iroh:` destination; the forwards, X11 and the control socket of
  `ssh_config` are not used, and `-v` says so.
- **One relay token.** Through the relay, a token is read or minted once,
  before the hosts start, so that each host reads the one that the cache
  keeps: the relay sees one mint, not one for each host (it allows 120
  attempts with no token a minute for each address). With
  `PODSSH_CACHE_DIR=none`, each host mints its own.
- **The output.** The far output of each host goes through a sink in place
  of the process's streams (`podssh_ssh::io::Sink`): each line becomes
  `HOST: LINE` on stdout or stderr, as the host wrote it, and one writer
  puts each line whole, so that no host's line cuts another's; a line of
  more than 64 KiB comes in pieces, each with its label, and a last line
  with no newline gets one. podssh's own messages of a host are
  `podssh: HOST: ...`, each line of them, and a note or a warning that each
  host has is said once. With `--output-dir DIR`, the bytes go unchanged to
  `DIR/HOST.out` and `DIR/HOST.err`, and the status to `DIR/HOST.status` at
  the host's end; nothing of theirs goes to stdout. A byte of HOST other
  than a letter, a digit, `.`, `_`, `-` and `@` is `%XX` in a file's name,
  and two hosts whose files would differ only in case are refused (64).
  The files are made before anything connects (73 when they cannot be),
  with no status file left from an earlier run: a host with none did not
  run.
- **The exit status** is the largest status of the hosts: 0 only when each
  host gave 0, and 255 for a host that could not connect or log in, or
  whose session ended with no status. `--fail-fast` starts no new host after
  a failure (a status other than 0, or no session); the hosts that run end
  as they end. A summary on stderr gives each host and its status, or why
  it has none; `-q` leaves it out.
- **A record for a program** (T-484, GitHub #94,
  `crates/podssh-cli/src/each/record.rs`). `--result-file FILE` writes one
  JSON object to FILE at the end, a new file for its owner alone (mode
  0600 on Unix), and the lines stay as they are; `-` is refused (64), as
  stdout carries the lines. `--json` writes the same object on stdout once
  each host ended: each host's stdout and stderr go into its record in
  place of the lines, as `ssh_exec` of `podssh mcp` gives them (`stdout`,
  `stdout_encoding`, `stderr`, `stderr_encoding`: 1 MiB of each at most, as
  text when it is UTF-8 and else as base64, so that no byte changes;
  `truncated` when more came), and podssh's own lines stay on stderr. With
  `--output-dir` the bytes go to the files, and each host's record names
  them in `files` (`stdout`, `stderr`, `status`), for output past the cap.
  The object: `schema` (1), `podssh` (the version), `exit` (the run's),
  `counts` (`hosts`, `ok`, `failed`, `not_started`, as the summary counts
  them) and `hosts`, in the order of the list, each with `host` (the label),
  `destination` (`user@host:port`), `exit` (its part of the run's exit;
  null when it did not start), `status`, `signal`, `end`, `failure`,
  `bytes` and `relay` as `ssh --result-file` gives them, `error` (the
  words of its failure, or null), `duration_ms` and `files` (or null). A
  host with no session has the end `failed`, and the class `connect` when
  its session said no other. Each host's facts are its own session's: the
  record of `podssh_ssh::outcome` is the session's inside
  `outcome::scoped`, with its phase and the server's last words, so that
  two hosts that fail at once each name their own failure; with no scope,
  as for `podssh ssh`, it is the process's. `--json` and `--result-file`
  with `--interactive` are refused (64).
- A host's session is not tried again after a drop of the relay, as
  `ssh`'s is (T-025): `each` makes one try of each host. The phase of a
  try is each session's own since T-484, as the rest of its record is.

### The broadcast: `--interactive`

`podssh each --interactive [OPTIONS] HOSTS` opens a shell on each host,
and sends each line that the user types to the hosts of the selection
(T-185, `crates/podssh-cli/src/each/broadcast/`). It is the line mode of
csshw and of the `synchronize-panes` of tmux, with no panes and no full
screen: podssh is a CLI (`docs/decisions.md`, Q6). A broadcast mistake
costs once for each host, so the broadcast has a stop that acts at once.

- **The shells.** Each host gets a shell with no pty (`-T`), on the road
  and the SSH client of `ssh`, as a command of `each` does; each host is
  open at the same time, 64 at most. A `RemoteCommand` of `ssh_config` is
  not used (`-v` says so), and a `SessionType` that asks for no shell is
  refused (64). A COMMAND, `--parallel`, `--fail-fast` and `--output-dir`
  are refused (64).
- **The local terminal keeps its normal mode.** Its own line discipline
  echoes and edits the line, and podssh reads whole lines. Each line goes,
  with a newline, into the queue of each selected host; the CR of a
  console's CR LF goes. The output of each host comes as `HOST: LINE`, as
  for a command, and podssh's own words come as `podssh: ...` on stderr.
- **The commands of podssh** are the lines that start with `:`: `:all`,
  `:none`, `:only HOST...`, `:list`, `:intr` and `:help`. A word of
  `:only` takes the braces and the groups of HOSTS, and names a host by its
  label, or by its label without `USER@`; a word that names no host
  changes nothing. A line that starts with `::` goes to the hosts with one
  `:` less.
- **The emergency stop** is a key that the terminal turns into a signal,
  so that it acts at once, also while a line is half typed: `Ctrl-\`
  (SIGQUIT) on Unix, Ctrl-Break (`CTRL_BREAK_EVENT`) on Windows. The
  terminal drops the line that is half typed. podssh then selects no host,
  and drops each line that waits in a queue, a line that waits for its
  second Enter, and what it read and had not acted on; it says
  "broadcast stopped; :all starts it again". A line that a session has
  taken is sent: it is in the SSH channel, or it is the one line that the
  session sends now. The stop is armed before anything connects, also when
  SIGQUIT was ignored at the start (a script's `&` leaves it so); where it
  cannot be armed, podssh exits 78.
- **`--stop-key KEY`** moves the stop to another control key on Unix, as
  `^X` or `Ctrl-X` (T-322), for a user of dtach or abduco, which take
  Ctrl-\ for their own detach: the terminal's QUIT character is that key
  for the run, so the terminal still raises SIGQUIT and drops the half
  line, and the old character comes back on each way out. A key that the
  terminal keeps (INTR, EOF, SUSP, ERASE, KILL, the ends of a line) and
  anything but one control key are refused (64); so is the flag on
  Windows, where Ctrl-Break is the stop. The banner and `:help` name the
  key in effect. With stdin not a terminal there is no key, and the stop is
  `kill -QUIT`.
- **Ctrl-C goes to no host.** While the input goes on, podssh says what to
  type instead: `:intr` sends `signal INT` (RFC 4254, section 6.9) to each
  selected host, and a server may ignore it (`docs/terminal.md`, "Ctrl-C
  with no remote pty"). At the end of the input (Ctrl-D; Ctrl-Z on
  Windows), each shell reads what waits for it, then its end; Ctrl-C then
  cuts the hosts whose shell still runs, each with 130.
- **`--confirm`.** A line for more than one host waits for a second Enter
  (an empty line); another line drops it, with a word.
- **The queues.** Each host has a queue of 64 KiB: the lines that its
  session has not taken. A session takes a line only when it can send it,
  so a host that reads slowly fills its queue. A line that does not fit
  does not go to that host: the host leaves the selection, podssh names it,
  and the summary counts the lines that did not reach it. No byte that the
  user typed is dropped with no word.
- **The exit status** is the largest status of the shells, as for a
  command: 255 for a host with no session.

## Snippets

A snippet is a command that the settings file keeps, with placeholders for
the values that change (T-187, `crates/podssh-cli/src/snippets.rs`).
`podssh ssh --snippet NAME [user@]host [WORD...]` and
`podssh each --snippet NAME HOSTS [WORD...]` run it in place of a command.

- **The table.** After a line `[snippets]` of the settings file (below),
  each line is `NAME COMMAND`, or `NAME = COMMAND`. A name is as a group's.
  A command in double quotes, with none inside, loses them: a `#` that
  starts a word outside double quotes starts a comment, as in `ssh_config`.
- **The placeholders.** `{{host}}` is the host that podssh connects to,
  after `HostName` (OpenSSH's `%h`); `{{user}}` is the user; `{{port}}` is
  the port; `{{1}}` to `{{9}}` are the words after the host. The words must
  be as many as the highest `{{N}}`: a word that no placeholder takes would
  be a command of its own, and is refused (64). Blanks inside the braces
  are allowed. A `{{` that starts no name, as `{{.Names}}` of a Go
  template, is text, and `\{{` gives `{{`. An unknown name is the file's
  fault (78, with its line), as each bad line of the file is.
- **The quoting.** Each value goes in quoted for a POSIX shell, as one word
  that runs nothing: a value of letters, digits and `@%+:,./_-` as it is,
  else in single quotes, each `'` as `'\''`. A `=` and a `~` are quoted,
  as zsh and each shell read them first. A placeholder inside the
  command's own single or double quotes would undo the quotes of podssh,
  so the file refuses it (78), and a quote that does not close too. A
  template for another shell (cmd, PowerShell) must not put a placeholder
  inside its own quotes.
- **The question.** The command line is resolved as each one is; then the
  values go in, and the whole command is shown before anything connects:
  `the snippet NAME runs this on HOST:` and the command, each control
  character as its escape. podssh asks `Run it? [y/N]` on the terminal or
  through `SSH_ASKPASS`, and the question holds the command, as stderr can
  go elsewhere; only `y` or `yes` runs it. With `--yes` it runs with no
  question, and the command goes to stderr (not with `-q`). With nobody to
  ask (no terminal and no `SSH_ASKPASS`), or with `BatchMode`, and no
  `--yes`, the command is shown and the run is refused (64). Each other
  answer, Ctrl-D and a failed askpass program refuse it too (64). `-G`
  asks nothing and runs nothing.
- **`podssh each`** shows each host with its command, or the command once
  when it is the same on each host, and asks once for all the hosts,
  before a file of `--output-dir` is made. `BatchMode` in the
  `ssh_config` blocks of one host forbids the question.
- **The command line.** `--snippet` given twice, `--yes` with no
  `--snippet`, a name that the file does not have, and `-N`, `-s`, `-W` or
  `-O` with `--snippet` are refused (64), and so is a `SessionType` of
  `ssh_config` that asks for no command. `Match command` sees the command
  as written, with its placeholders. `--persist` and `--attach` refuse a
  snippet, as they refuse a command; `--sudo` and `--su` run it as root.
- The gate's `scripts/interop-snippets.sh` gives the values `a'b` and
  `x; touch MARK` to OpenSSH and Dropbear: each comes back unchanged, and
  MARK is never made.

## The host picker

`podssh ssh` with no destination is a usage error (64). When stdin and
stdout are both terminals, a person is there, and podssh first offers the
literal `Host` names of `ssh_config` (T-188,
`crates/podssh-cli/src/ssh/picker.rs`):

- The names come from the files that a run reads (`-F`, else
  `PODSSH_SSH_CONFIG`, else `~/.ssh/config` and the system's file), in
  their order, each once, and from each `Include` whose block holds for any
  host: outside each block, or after `Host *`. A pattern (`*`, `?`) and a
  negated name are not names, and `known_hosts` is not read, as its names
  can be hashed.
- Each name has a number. A number picks its name; other text narrows the
  list to the names that hold it, case set aside. An empty line, the end of
  input and a terminal that fails pick none (64). A number outside the list
  and a text that no name holds are said, and the question comes again, 20
  times at most.
- The name picked takes the path of a typed destination: its `Host`
  blocks, the relay or `--direct`, and the rest of the command line.
- With no name to list, or with stdin or stdout not a terminal, nothing is
  read, and the run refuses with 64 and `missing destination`, as before:
  a script still gets its usage error. A test that calls `dispatch::run`
  has no terminal, so it never sees the picker.

## `podssh containers`

`podssh containers [OPTIONS] [user@]host` lists the containers of a host,
each with the `podssh ssh` command that enters it (T-190,
`crates/podssh-cli/src/containers/`). It is a verb, not a form of the
destination: `node://` and `cf://` name a road to an SSH server, and a
container is a command on the server, which `podssh ssh -t HOST -- docker
exec -it NAME sh` already says in OpenSSH's words.

- **One login, one script.** podssh logs in as `ssh` does, through the
  relay or with `--direct`, with `-p`, `-l`, `-i`, `-o`, `-F` and `-J`, and
  runs one command with no pty: `sh -c 'SCRIPT'`, so that a login shell
  that is not POSIX (csh, fish) only starts `sh`. The script looks for
  docker, podman and kubectl with `command -v`, on the `PATH` of a command,
  and runs the list of each that it finds: `docker ps` and `podman ps` with
  the format `{{.Names}}`, and `kubectl get pods -o name` in the current
  context and namespace, with `--request-timeout=20s`. `--tool` asks one
  tool alone. A program runs only where the probe found it (AGENTS.md,
  section 5, rule 3): none here, and none there that `sh` did not find.
- **Marks.** A line `podssh-containers TOOL` comes before each tool's list
  on stdout and on stderr, `podssh-containers end TOOL STATUS` after it,
  and `podssh-containers done` at the end. Text before the first mark (a
  start-up file, a banner) is dropped; a list with no last mark was cut,
  and is not believed (69). The list waits 60 s at most, and podssh reads
  1 MiB of it at most.
- **Names.** A name is taken when it has letters, digits, `_`, `.` and `-`
  alone, a letter or a digit first, and 253 bytes at most, as Docker,
  Podman and Kubernetes name them; kubectl's has `pod/` first. Such a word
  is one word to each shell, so the command that carries it cannot be read
  as two. A name of another form is left out, and named on stderr (65).
- **The lines.** Each line on stdout is the tool, the name, padded, and
  `podssh ssh -t FLAGS HOST -- TOOL exec -it NAME sh` (`kubectl exec -it
  pod/NAME -- sh`), with the connection flags that were given; a value that
  is not one plain word is in single quotes. A tool that fails (no access
  to docker's socket, a cluster that does not answer) gives its lines of
  stderr, `podssh: TOOL: ...`, and its status; the other tools go on.
- **`--exec NAME`** enters NAME on the same connection, after the list:
  a password is asked once. The first tool, in the order docker, podman,
  kubectl, whose whole list holds NAME runs its exec with the program of
  `--shell` (`sh` by default; one word of letters, digits, `_`, `.`, `-`
  and `/`). `pod/` may be left out of a pod's name. With a terminal here,
  or with `-tt`, the session has a pty and the tool gets `-it`; with none,
  `-i` alone, as docker refuses `-t` when its input is not a terminal. A
  name that two tools list (docker and podman, or a `docker` that runs
  podman) is said on stderr, and `--tool` enters the other.
- **The exit status:** 0 when each tool gave its whole list; 65 when a
  name was left out; 69 when the host has none of the tools, one failed,
  the list was cut, or `--exec` names no container that a whole list has;
  255 when the connection or the login failed, or the list did not end in
  time. With `--exec`, the status of the session, as `ssh` gives it. A
  usage error is 64 before anything connects: a value of `--exec`,
  `--shell` or `--tool` that is not one, `--shell` or `-t` with no
  `--exec`, a word after the host, and a `node://` or `iroh:` destination.
  The forwards, X11 and the control socket of `ssh_config` are not used,
  and `-v` says so.
- `podssh pipe exec:` (T-174) carries the streams of `docker exec -i`, and
  Docker's contexts here are not used: they connect with OpenSSH, not with
  podssh.

## `podssh run`

`podssh run [OPTIONS] [user@]host[:DIR] [--] COMMAND...` copies a project to
a host, then runs a command in it, with the command's exit status (T-192,
`crates/podssh-cli/src/run_cmd/`).

- **The project** is the working directory, or `--from DIR`. The far
  directory is the DIR of `host:DIR` (a relative DIR, and `~/`, are under
  the home directory; `scp://[user@]host[:port]/DIR` works too), else
  `~/.podssh/run/NAME`, NAME the name of the project here. A parent that is
  not there is made, with mode 0700. The home directory itself and the root
  are refused (64). The connection flags are those of `ssh`, and the `Host`
  blocks of `ssh_config` apply.
- **The copy is that of `podssh cp -r -p`**
  (`crates/podssh-cli/src/cp/sync.rs`): each file to a temporary name,
  verified by its digest, then renamed, with its times kept; several files
  at once, as `cp` sends them with no `--parallel` (T-474); a new
  connection after a break, and a new relay session before its limits. It
  goes onto the far directory itself, also when the directory is there,
  and a file whose size and time of change (to the second) are the far
  file's is not sent again: a second run with no change sends no file. It
  goes over SFTP, as a directory of `cp -r` does. `target/`,
  `node_modules/` and `.git/` never go, at any depth, nor what the
  project's `.podsshignore` (a pattern a line, as the file of
  `--exclude-from`), `--exclude` and `--exclude-from` leave out; `run
  --help` names them in the row of `--exclude` and below the options
  (T-475). Before the command starts, the summary of `cp`
  says at the default level what the copy did (T-472): `1 copied (34 B), 2
  unchanged, 2 left out, in 0.6 s (56 B/s)`, also before the error of a
  copy that failed; `-q` silences it. `left out` counts the paths that the
  excludes left out, each the top of what it left out (`target`, not each
  file in it), and `-v` names each with its pattern: `PROJ/target: left out
  by target/` (T-475). A copy that lasts writes a plain line each 10 s
  where stderr is no terminal, as `cp` does.
- **`--no-ignore`** (T-475) sends `target/`, `node_modules/`, `.git/` and
  what `.podsshignore` names too; `--exclude` and `--exclude-from` still
  apply.
- **Nothing on the far side is removed**: an exclude leaves a path out of
  the copy, and what an earlier run sent stays there, as `run` has no
  `--delete` (`cp -r --delete` makes a mirror). `cp -r` has no default
  excludes and reads no `.podsshignore`: it copies what its command line
  names (T-143's Decision), where `run`, a loop of work on a project,
  reads its ignore file (T-192's Decision).
- **`--dry-run`** (T-475,
  `crates/podssh-cli/src/run_cmd/dry.rs`) connects and makes the copy's
  looks, which only read, then prints on stdout what the copy would change,
  in the lines of `cp -r --dry-run`: `mkdir DIR` for each far directory
  that is not there (the parents of the far directory first), `copy SRC ->
  DST` for each file whose size or time differs from the far file's,
  `link DST -> TARGET` for a link that is not there as it is here, `skip
  SRC: WHY` for an item that the copy would not copy (a FIFO, a loop); then
  `run cd 'DIR' && COMMAND`.
  After a run and one change, the plan is that file and the command.
  Nothing changes on either side and nothing runs; stderr counts the paths
  that the excludes left out (`2 paths left out by the excludes; -v names
  each`), and no summary comes, as for `cp`. The exit is 0, or 255 when
  the far side cannot be read: a far session that stops answering during
  the plan gives no plan, as its looks would read as files to copy.
- **Then the command** runs on the same connection, as `podssh ssh` runs
  one: `cd 'DIR' && COMMAND`, DIR in single quotes for a POSIX shell, the
  words of COMMAND joined with spaces as OpenSSH joins them, with stdin and
  no pty. When the relay session has less than 16 MiB left after the copy,
  the command runs on a new session.
- **The exit status** is the command's, with the rules of `podssh ssh`;
  a copy that failed exits 255 and runs nothing. 64 and 78 come before
  anything connects.
- **`--result-file FILE`** gives the copy's files and the command's
  status, signal, end and bytes in one object (T-486; "The record of a
  copy: `--result-file`").

## `podssh job`

`podssh job [OPTIONS] SUBCOMMAND HOST [ID [DIR]] [-- COMMAND...]` keeps jobs
on a far host that go on after the connection ends (T-193), and a queue of
them (T-197; `crates/podssh-cli/src/job/`).

- **The host** is a plain POSIX host, reached as `podssh ssh` reaches a
  destination, with the connection flags of `ssh` (`-p`, `-l`, `-i`, `-o`,
  `-F`, `-J`, `-v`, `-q`, `--direct` and the relay's) and the `Host` blocks
  of `ssh_config`. A `node://` or `iroh:` destination is refused (64).
- **Nothing of podssh runs on the host** but a POSIX sh script,
  `crates/podssh-cli/src/job/far_notmux.sh` and then
  `crates/podssh-cli/src/job/far.sh`, as one file. Each call sends it on the stdin of
  `sh -c 'INSTALL' sh MARKER ACTION ARG...`, and the host keeps it as
  `~/.podssh/jobs/jobs.sh`, mode 0600 in a directory of mode 0700: a new
  name, then a rename, so that a reader never reads half of it. The login
  shell, POSIX or not, only starts `sh`, and each word is one quoted word,
  as for the copy by exec of `cp`. The answer comes after a random marker,
  so that text which a login prints first is never read as an answer.
- **tmux holds each job.** tmux is probed, never assumed (`AGENTS.md`,
  section 5, rule 1), as for `--persist` (T-178). `start HOST -- COMMAND`
  makes the job's directory `~/.podssh/jobs/MILLIS-ID` (the time of the
  start in milliseconds, then 8 random hex digits), and starts
  `tmux new-session -d -s podssh-job-ID`, which runs the command in `sh`,
  in the home directory, with no input. The output and the errors go to the
  file `out` of that directory, and the exit status to `status` at the end.
  Then podssh prints the ID on stdout. With no tmux on `PATH`, `start` exits
  255 and names tmux, and nothing starts. The command must follow `--`, so
  that no word of it is read as a flag of podssh, and a command with a
  newline or a NUL has no word for a far shell (64 for each).
- **A host with no tmux is told what installs it** (T-481). The far script
  answers `missing tmux PM ID WHO`: PM, the first of `apk`, `apt-get`,
  `dnf`, `yum`, `zypper`, `pacman`, `brew` and `pkg` that `command -v`
  finds; ID, the `ID=` of `/etc/os-release`; WHO, `root`, `own` (the
  login owns the manager's file, as Homebrew's), `sudo` (on `PATH`) or
  `user`; each `-` when unknown. The command comes from the table of
  `crates/podssh-cli/src/install_hint.rs`, which T-590 made for an sshd:
  "to install it on ubuntu: sudo apt-get install -y tmux", with `(as
  root)` after it for a `user`, and brew never under sudo. podssh names it
  and runs none; then the refusal names `--no-tmux`. `ssh --persist` asks
  the same probe, a line of sh for the login shell
  (`crates/podssh-ssh/src/missing.rs`), whose list of managers a test
  holds to the table's.
- **`--no-tmux`, the user's choice, never the default** (T-481), for a host
  that has no tmux and cannot get it: `start` and `submit` run the job
  with no tmux. The job's directory gets `kind` (`plain`); its runner,
  `nohup setsid sh jobs.sh - plain NAME lead` (with no `setsid` on `PATH`,
  `nohup sh jobs.sh - plain NAME alone`), with no input and its output to
  the null device, writes its PID to `pid` (`pid.start` holds the PID of
  `$!` until then), starts the command in `sh` as its own child, and
  waits. **The runner alone signals the command**: `stop` writes the file
  `stop` and sends no signal; a watcher of the runner's asks it each second
  (USR1) to look, and the runner sends TERM to its process group (its own
  TERM ignored) where it leads one (`lead`, and `/proc/PID/stat` shows its
  group as its PID), else to the command alone, and KILL to the command
  10 s later. The command is a child that the runner has not waited for,
  so the system has given its PID to no other process, and no call reads a
  PID from a file to signal it: T-193's reason to set `nohup` aside is
  gone. `stop` waits 15 s for the status, then removes the directory; a job
  that runs on keeps it (`stuck`, 255), and one whose runner is gone is
  removed after 5 s (`lost`), as nothing can end its command. A job is
  `running` while the PID of its runner is alive and, where `/proc` shows
  it, its command line holds `jobs.sh`; else `lost`. `submit --no-tmux`
  starts the queue's runner the same way, `jobs.sh - runner plain`, whose
  lock is the directory `runner.lock` (made by `mkdir`, with the runner's
  PID; a lock whose runner is gone is taken over); a runner of either kind
  starts no runner of the other, and starts each job as its kind asks.
  What a job loses with no tmux: it stays in the login's scope of systemd,
  so logind's `KillUserProcesses` ends it at the logout, as it ends a tmux
  built with no systemd support; and a stop does not reach a process that
  the command put in a group of its own, nor, with no `setsid`, one that
  it started in the background.
- `list HOST` prints a line for each job, in the order of their starts:
  the ID, the state (`queued`; `running`; `done`; or `lost`, when neither
  the job's tmux session nor its status is there, as after a restart),
  the exit status (`-` while there is none) and the command. `log HOST ID`
  writes the job's output to stdout as it comes, also after the job's end.
  `stop HOST ID` ends the tmux session of that exact name,
  `-t =podssh-job-ID`, never one whose name only starts so, and removes the
  job's directory with its output.
- **The queue lives on the far host** (T-197), so that the client can stop
  at any time and needs no listener to wait (`docs/decisions.md`, Q7: no
  logic of GPUs and no list of devices; the slots are the only limit).
  `submit HOST -- COMMAND` makes the job's directory with the state
  `queued`, and starts the runner, `tmux new-session -d -s podssh-runner`,
  unless one runs: the name of the session is the lock, so that no second
  runner starts. The runner, the far script itself, starts the oldest
  queued job (the names sort by the time of the submit) while fewer jobs
  run on the host than the slots, and checks again each second; with
  nothing queued and nothing running, it gives its name up, looks once
  more, and ends, so that a submit at that moment starts a runner of its
  own. `--slots N` (1 to 64) sets the slots, which stay for the next
  submits; 1 until one sets them. A job of `start` runs at once, and counts
  against the slots. A list or a state that finds a queued job and no
  runner, as after a restart of tmux's server, starts one.
- **A list of hosts for `submit`**, with the braces and the groups of
  `podssh each` (T-184): one `list` of each host gives its jobs queued or
  running, the host with the fewest gets the job, the first of the list on
  a tie, and stdout gives `HOST ID`. A host that does not answer is left
  out, and said; with none, nothing is queued (255).
- **`log --follow HOST ID`** (T-485) gives the job's output as it comes,
  on one connection, then exits with the job's status. Each call of the far
  action `follow ID FROM` answers `out N`, N the offset where its bytes
  begin, then each new byte of `out`, read each second with `tail -c +N`
  into a file of the job's directory and counted with `wc -c`, so that each
  byte goes once; it ends once the status is there and nothing more came,
  once the job is lost, or after 20 s. Then a call of `state`: `done N`
  ends the run with N, `running` or `queued` calls `follow` again from the
  count of the bytes that came, and `lost` ends it with 255. A call that
  broke goes on, on a new connection (5 in a row at most, as `wait`), where
  the output stopped, with no byte twice; and a call of 20 s keeps the 30 s
  that each piece of an answer has, so a dead link is found as for each
  call. `--from-end` starts at the size of the output then; `--timeout
  DURATION` ends it with 75, the job running on. `--jsonl`: one object for
  each line, `{"event":"line","text":...}` or, for bytes that are not
  UTF-8, `"base64"`, a line of more than 1 MiB with no newline given as it
  is; then `{"event":"end","state":...,"status":...}` (the state last read
  at a `--timeout`). A reader that went (`| head`) ends the follow, with 0.
  `--follow` alone, with no `-f`: on `ssh`, `-f` is `--detach`, and `job`
  takes the connection's options of `ssh`. The script goes with each call,
  some 19 KiB each 20 s on a quiet job.
- `wait HOST ID` reads the job's state every 5 s, each read a call of its
  own, and exits with the job's status, or 255 for a job that is lost.
  After a lost connection it connects again, 5 times in a row at most,
  with the backoff of the relay opener; a host that does not answer the
  first connection is 255 at once. `--timeout DURATION` exits 75 when the
  job has not ended by then; the job runs on.
- `fetch HOST ID [DIR]` copies the job's output to `DIR/out`, as `podssh cp`
  copies a file (over SFTP, or by exec; a temporary name, the digests, a
  rename; a new connection after a break), and with `--files GLOB` each
  regular file of that pattern of sh, in the home directory of the host, to
  `DIR/files` by its path. DIR is `./podssh-job-ID` by default. A pattern
  with an absolute path or a `..` is refused (64), and so is each path that
  has no place under `DIR/files`. A job that is queued or running is not
  fetched, as its output is not whole until it ends (75). `list --json` gives one
  JSON object: `host`, and `jobs`, each with `id`, `state`, `status` (null
  while there is none), `started_ms` and `command`.
- **The exit status** is that of `podssh ssh`: 0; 64 for a usage error and
  78 for a setting, before anything connects; 255 when the host cannot be
  reached or logged in to, has no tmux, has no job of that ID, gives no
  answer, or a job of `--no-tmux` runs on after its stop. `wait` and `log
  --follow` give the job's status; 75 when their `--timeout` passed, and
  when `fetch` finds the job queued or running. `--no-tmux` with another
  subcommand than `start` and `submit` is 64, and so are `--from-end`,
  `--jsonl` and `--timeout` with `log` without `--follow`.

## A word with no subcommand

`podssh example.org` never connects. podssh selects a suggestion in two
steps:

1. The form of the word: `@`, `.` or `:` gives `Try: podssh ssh <word>`.
2. The edit distance, with an absolute limit and a shared two-letter prefix.

The edit distance alone suggests `doctor` for `example.org` and `cp` for
`xz`. The first step prevents this.

## `podssh cp`

`podssh cp SRC... DST` copies files between this host and a server over
SFTP (`crates/podssh-ssh/src/sftp/`), or by exec when the server has no
SFTP, through the relay or with `--direct`, with the connection flags of
`ssh` (`-o`, `-J`, `-i`, `-v`, `-q`) and `-P` for the port.

- An operand names a server when a `:` comes before any `/`, as scp reads
  it: `[user@]host:path` or `[user@][IPV6]:path`. `./a:b` is a local file;
  on Windows a drive letter (`C:\x`) is local. `host:` is the login
  directory. Two local operands, sources from both sides, or remote
  sources on two servers exit 64 before anything connects.
- **A node of a pair** (T-296): `node://[user@]NAME[/ROUTE]:path` is the
  node of the pair under the label NAME, reached as `podssh ssh node://NAME`
  reaches it (`crates/podssh-cli/src/ssh/node_roads.rs`, `reach`, T-551):
  the race of its roads, or the operator's leg alone, the resumable layer
  when the node offers it, the end-to-end channel, and the host key under `node://NAME`. The
  path comes after the first `:` after the name, as a `/` there names a
  route (T-089); with no `:`, it is the login directory. `--pair-file`,
  `--client-key`, `--node-key`, `--no-e2e` and `--no-resume` (T-612) are
  those of `ssh`. A port,
  `-J` and `--direct` cannot reach a node, and exit 64 before anything
  connects. The session carries no relay budget of its own: the layer
  moves it to a new leg before the relay's limits (T-155), and a node in
  plain mode that the relay cuts is a broken connection, which the copy
  goes on after; so is a session of `--no-resume` whose link ends. `scp` and `mv` take the same operand, and `sftp` the
  destination `node://[user@]NAME[/ROUTE][:path]`.
- **A member of the net** (T-453): `[user@]NAME:path`, where NAME is a
  member with the role `node` of the net held here (`podssh net`), is that
  member's node, as `podssh ssh NAME` reads its destination: each copy hands
  the operand's server to `ssh`'s resolution, which asks the net first
  (`crates/podssh-cli/src/ssh/node.rs`, `destination`); a name with a dot is
  a host. The net names the node's key, which the channel checks. A copy
  races the tickets that the net names beside the pair under NAME (or
  `--pair-file`), as `ssh` does (T-551), so a member that its DERP ticket
  reaches needs no pair here. `mv` takes `NAME:path` and `node://NAME:path` for one server,
  which renames within itself, and refuses one file named both ways (64).
  `scp` and `edit` take the same operand, and `sftp` the destination
  `[user@]NAME[:path]`.
- **The destination's name never holds a file that was not verified.**
  The bytes go to `.NAME.podssh-RANDOM.part` beside the destination (a new
  file of mode 0600). The SHA-256 of what was sent is compared with the far
  side's; then the file takes the source's permission bits and is renamed
  onto the destination, at once with `posix-rename@openssh.com`. Without it,
  an existing destination is removed first, and podssh says that the
  replace was not atomic. A failure removes the temporary file.
- The far digest comes from `sha256sum`, `shasum -a 256` or
  `openssl dgst -sha256` over exec, when the server runs one; else from a
  second read over SFTP (`ForceCommand internal-sftp` runs no command).
  The size and the MAC of SSH alone miss a wrong offset, a short write, and
  a source that changed while it was read.
- Several sources go into a directory. A copy from server to server goes
  through a temporary file on this host, one connection at a time.
- **Requests in flight** (T-140): on the SFTP road, the reads and the
  writes of a copy go with up to 64 requests in flight, each of the
  server's size (`limits@openssh.com`, else 32 KiB), and never more in
  flight than the cap of the road's window, which the window grows to where
  nobody types (T-662): of OpenSSH's 255 KiB, 64 on `--direct` (16 MiB), 6
  through the default relay (1.5 MiB, shared by `--parallel`'s tasks), 3 on
  a node's pair road, 2 elsewhere (512 KiB). Replies may come in any
  order; each block is written in
  the file's order, so a copy that breaks goes on from the end of the part
  that the server acknowledged, and a short read is asked again for its
  rest. No reply within 60 s of the last one is a failure. The second read
  of a far digest goes the same way. `-v` says the size and the requests
  of each copy, and its rate before the digest. `scp -X` and `sftp -R`,
  `-B` and `-X` set them.
- **`--parallel K`** (T-141): a file of more than one chunk of 8 MiB goes
  as chunks at fixed offsets, K at once (1 to 16), each over an SFTP
  session of its own, so a channel and a window of its own, in the one
  connection; each writes its chunks into the temporary file at their
  offsets. Without `--parallel` such a file goes in one stream (T-474), as
  no measurement through the live relay shows that chunks gain by default.
  The side file keeps the chunks that are done, so a copy that breaks goes
  on with the others. The digest covers the whole file after the last
  chunk, and nothing is renamed before it. Through the relay the tasks
  share 1.5 MiB in flight, below the 2 MiB queued that close a session, and
  a task takes a chunk only while the session may carry it whole. The copy
  by exec goes in one stream, and `-v` says so.
- **Several files at once** (T-297, T-474): the sources of the command
  line, the files of a tree with `-r`, and the copy of `podssh run` go 4 at
  once with no `--parallel`, K at once with `--parallel K`, and one at a
  time with `--parallel 1`, each over an SFTP session of its own in the one
  connection; the connection's own session is one of them. Through the
  relay each small file waits for its own round trips, so one at a time
  takes their sum: 100 files of 2 bytes took 210 s one at a time and 32 s 8
  at once (GitHub #100). The default of 4 keeps each file's SFTP session and
  the exec channel of its far digest within the 10 sessions that OpenSSH's
  sshd opens on one connection (`MaxSessions`); with more, the digests of
  some fall back to a second read. A server that opens fewer sessions gets
  fewer files at once, and `-v` says so. Each file goes as one copy goes:
  its temporary name, its side file, its digest and its rename. A file of
  more than one chunk waits, and goes after the others, alone: in chunks
  with `--parallel`, else in one stream. A broken connection ends the files
  in flight where they are; the next connection goes on with each from its
  side file, at most 5 times in a row with no new byte, as for one file.
  Through the relay the files share 1.5 MiB in flight, as the chunks do.
  The report keeps the order of the sources, and the exit code is that of
  the first failure in that order. `mv` removes each source after the
  copies, and `scp`, which copies as `cp` does and has no `--parallel`,
  takes the default too. The copy by exec, `podssh edit` and `sftp`'s batch
  go one file at a time.
- **`--delta`** (T-142): over an older version of the same file on the
  other side, only the blocks of 1 MiB that changed go. The SHA-256 of each
  far block comes from one command over exec (`dd` into `sha256sum`,
  `shasum` or `openssl`), that of each local block is read here. The
  temporary file is made from the old one where it is (for a copy up
  `copy-data` inside the server, else, T-470, the file made over SFTP as
  for any copy and filled by one command there, `cat -- OLD >| TEMP`, so no
  byte of the old file crosses; for a copy down a copy on this disk), only
  the blocks that differ cross, and the size is set. The digest of the
  whole file then decides: a difference falls back once to a full copy,
  and says so. Each other reason for a full copy is one line at the default
  level, once for each file (`-q` silences it): no `copy-data` and no
  command; no command, `dd` or digest tool for the blocks; a command that
  made no copy of the old file; a copy by exec, which sends no delta; a
  copy that goes on from an earlier attempt's temporary file, in full where
  it was. A destination that is not there, or is empty, says it at `-v`
  alone. With `--jsonl` the `done` object gains `"delta"`:
  `{"blocks": N, "sent": K, "bytes": B}`, or `{"full": "REASON"}` with
  `no-older-file`, `no-copy-data`, `no-block-digests`, `no-far-copy`,
  `by-exec`, `resumed` or `digests-differ`. `-v` says the blocks sent and
  their bytes. The full copy stays the default.
- **`-r`** (T-143) copies a directory and what it holds, depth first with
  `lstat`, 64 levels at most: each file as one copy goes (a temporary name,
  the digest, the rename), each symbolic link as a link; a directory gets
  its mode after its files. `scp -r` follows links, as OpenSSH's does, and
  refuses a loop. A device, a FIFO or a socket is not copied, and is no
  failure (T-476), as OpenSSH's `scp` and `sftp` skip one: one line at the
  default level names its kind (`SRC: not copied: a FIFO`), `--jsonl` gives
  a `skipped` object, and the exit stays 0 when nothing else failed; the
  same in `podssh run` and `sftp`'s `put -r` and `get -r`. Each name that a
  far listing gives must be one component: `.`, `..`, a `/` or a NUL, and
  here on Windows a `\`, a `:`, a device's name or a trailing dot or space,
  are refused (70), so nothing is written outside the target. Into a
  directory that exists the copy goes under it, with the source's name; else
  it is the destination. Each other item that fails (a loop, a depth past
  64, a listing or a link that cannot be read, a name that is not UTF-8, a
  refused name) is said once, when it comes, as is each failed file of a
  list of sources; the rest goes on, and the exit is the first failure's,
  in the order of the sources. With `--jsonl` each failure is an `error`
  object. `--exclude PATTERN` (repeatable; `*` and `?` within a name; with
  a `/`, from the root of the copy) and `--exclude-from FILE` (a pattern a
  line; `#` starts a comment) leave paths out, and nothing else does: `cp
  -r` has no default excludes and reads no `.podsshignore`, which `podssh
  run` reads (T-475); `--dry-run` says each action
  (`mkdir`, `copy`, `link`, `skip`; with `--jsonl` an object each) and
  changes nothing. `mv -r` removes the source once each item of it is
  copied, and leaves a special file and the directories that hold it, and
  says so. `--delete` goes on past a special file, and never deletes its
  name. A directory goes up or down, over SFTP, not between two servers.
- **What a copy keeps** (T-146, `crates/podssh-cli/src/cp/meta.rs`): the
  source's permission bits always. `-p` keeps the access and the
  modification times too (`scp -p`, `sftp -p`, `get -p` and `put -p` as
  well), and with `-r` each directory's, set after its files; `--owner`
  keeps the owner and the group by number where the side that writes may
  give a file away (root), and says once where it could not. Each is set
  on the temporary file before the rename; a side that refuses the mode or
  the times fails the copy, and the destination stays as it was. Where a
  server's rename changes the times (Cygwin's sets the access time), they
  are set once more after it. A block of 64 KiB of zeros, aligned in the
  file, is a hole, never sent, and the size is set at the end: up when the
  source has holes (fewer blocks than its size, or the sparse attribute on
  Windows), and both ways with `--sparse`; not with `--parallel` or
  `--delta`, which may write a block again. Within one `-r` upload, two
  names of one file (one device and inode; on Windows one volume and file
  index) arrive as one file with two names, by `hardlink@openssh.com`, else
  as two files, said once. SFTP
  version 3 carries the times in whole seconds from 1970 to 2106 and no
  inode, extended attribute or ACL: those, a far source's hard links, and
  the owner on Windows are not kept.
- **`--inplace`** (T-147, `crates/podssh-cli/src/cp/in_place.rs`) writes
  into the destination itself, with no temporary name and no rename: the
  file keeps its inode, so its other hard links and each program that
  holds it open see the new bytes, no second copy needs room, and no name
  is added to its directory. It is opened with no truncation, written, and
  cut to the source's size; the digests are compared as for each copy.
  podssh says first, on stderr, that a copy that fails leaves its
  destination damaged, and each failure after the first write names the
  destination as damaged (a mismatch exits 70). A destination that is a
  symbolic link or a directory is refused (64), here before anything
  connects. A copy that broke goes on at its offset in the destination;
  with `--delta` only the changed blocks are written into it, and no
  `copy-data` is needed; `mv` removes the source only after the check. By
  exec, the first attempt writes with `cat >` (a truncation keeps the
  inode) and a later one appends. No holes are made in place.
- **A destination that is there** (T-473,
  `crates/podssh-cli/src/cp/clobber.rs`), with the names of GNU `cp` and
  rsync, as OpenSSH's `scp` has none (`scp -n` stays an unknown flag, 64).
  `-n` (`--no-clobber`) leaves it as it is: the copy looks first, before
  any byte goes (`lstat`, here `symlink_metadata`), says `DST: there, so
  not replaced` once at the default level, and the file is a skip, with
  exit 0. A name that comes during the copy stays too: the verified file
  takes its name by a hard link (`hardlink@openssh.com`, POSIX `link()` on
  OpenSSH's server; here `std::fs::hard_link`; by exec `ln`), which never
  takes a name that is there, then its temporary name goes. With no hard
  link, the look is the guard, and `-v` says so; with `--inplace` too, as
  the bytes go into the name itself. `-u` (`--update`) copies a file when
  its destination is missing, when the source's time of change is later,
  or when the times are equal and the sizes differ, as rsync's does; the
  times in whole seconds, as `podssh run` compares them. A file that stays
  is said at `-v`; a time that is not known (by exec, no `stat`) copies the
  file, said at the default level. `-b` (`--backup`) keeps the old file at
  its name with the suffix `~` (`--suffix SUFFIX`): a hard link of the old
  file takes that name before the rename (an older backup there goes
  first), so the destination's name is never missing; with no hard link, a
  rename of the old file first, which `-v` says. With `--delete`, a name
  that ends with the suffix, and a directory that holds one, are never
  deleted, as rsync protects its backups. A link of a tree under `-n` or
  `-u` is made only where its name is missing or names the same, as a link
  has no time of the source's; under `-b` the old one takes the suffix.
  `mv -n` and `mv -u` keep each source that they did not copy. Between two
  servers the look is at the second, before any byte goes there; the
  first leg keeps the source's time for `-u`. `-n` with `-b`, `-b` with
  `--inplace`, `--suffix` with no `-b`, and a suffix that is empty or
  holds a `/` are refused (64). Each file left out counts as skipped in
  the summary, and is a `skipped` object with `--jsonl` (`"why"`: `exists`
  or `not newer`); the `done` object of a copy with a backup gains
  `"backup"`; `--dry-run` says `skip SRC: exists`, `skip SRC: not newer`
  and `backup DST -> DST~`.
- **Progress** (T-145, T-472). One gauge for
  the run, which each road feeds: a file in one stream, the chunks of
  `--parallel`, the files K at once and the copy by exec. On stderr, when
  it is a terminal and `-q` is not given, one line that a carriage return
  rewrites, 4 times a second at most: for one file the name, the bytes of
  the total, the percent, the rate and the time left; with several, the
  file in flight, the run's files done of its files, its bytes and its
  rate, one line for the run and not one for each file at once. Where
  stderr is no terminal, `cp`, `mv` and `run` write a plain line each 10 s
  once the run has passed 10 s, with no carriage return and no escape
  (`podssh: 3 of 20 files, 1.2 MiB in 10 s (122.9 KiB/s); now NAME, 40.0
  KiB of 80.0 KiB`), so that a copy that lasts shows that it lives and a
  short one writes none; `scp`, `sftp`, `edit` and `job` write none there,
  as OpenSSH's `scp` and `sftp` write none. A control character of a name
  is a `?` on either line. `-q` and `PODSSH_PROGRESS=off` silence both;
  `PODSSH_PROGRESS=line` draws the terminal's line whatever stderr is.
  With `--jsonl`, a `progress` object on stdout each second for each file,
  before its `done` one.
- **The summary** (T-472). At its end a run of `cp` or `mv`, and the copy
  of `podssh run`, says on one line at the default level what it did:
  `3 copied (3.1 MiB), 2 unchanged, 1 skipped, 1 failed, in 12.0 s (264.5
  KiB/s)`. Each count of zero is left out but the first, and so are the
  bytes and the rate when nothing was copied; unchanged counts the files
  that `run` left as they were, skipped a device, a FIFO or a socket of a
  tree and a file that `-n` or `-u` left out (T-473), left out the paths of
  a tree's source that an exclude left out, each named at `-v` with its
  pattern (T-475), and failed each failure, said when it came. It comes also after a
  failure, before an error that no line said before it, so that the error
  stays the last line. `-q` silences it; with `--jsonl` a `summary` object on
  stdout takes its place (`copied`, `bytes`, `unchanged`, `skipped`,
  `left_out`, `failed` and `seconds`). `run` says it before the command starts, so
  that the command's stdout stays its own. A dry run gives none, nor a run
  that the `--timeout` ended, whose records went with it, nor `scp` and
  `sftp`, which keep the output of OpenSSH's.
- **An interruption and a limit** (T-145). The first SIGINT or SIGTERM
  (Ctrl-C on Windows) ends the copy in
  flight, keeps the temporary file and its side file, names them, and
  exits 130; the same command then goes on from them; a second signal ends
  podssh at once. `-l LIMIT` (`cp`, `mv`, `scp`, `sftp`) is OpenSSH's, in
  Kbit/s: a token bucket before each request, requests of 10 s of bytes at
  most, and about one second of them in flight.
- **`--delete`** (T-144), with `-r`, makes the copy's root a mirror: what
  it holds and the source lacks goes, a directory after what it holds, at
  the end of the run and only when each copy of the run succeeded; after a
  failed copy nothing goes, and stderr says so. An excluded name never
  goes, nor the file that a link names (the link goes). A root of a file
  system and the home directory are refused as the root (64). `--dry-run`
  lists each `delete`; at the end stderr gives the number of deletes, and
  `-v` and `--jsonl` give each one.
- **A server with no SFTP subsystem gets a copy by exec**
  (`crates/podssh-cli/src/cp/byexec.rs`), and podssh says so once. Each
  step is one command on a channel with no pty, `sh -c 'SCRIPT' sh PATH...`:
  the login shell, POSIX or not, only starts `sh`, and each path is one
  quoted word. A path with a newline or a NUL has no such word and is
  refused (64).
- A probe finds the far tools first: `cat`, `wc`, `mv` and `rm` are needed;
  `chmod`, `base64` and the digest tools are used when they are there. Then
  the 256 byte values go through `cat`. When they come back unchanged, the
  bytes go raw; else through `base64`, which adds a third to what counts
  against the relay, or the copy is refused. With no POSIX `sh`, or a
  needed tool missing, the copy exits 69 and names what is missing.
- Each answer comes after a random marker, so text that a login prints
  first (a start-up file, a `ForceCommand` banner) is never taken as data.
  The temporary name, the digests and the rename (`mv -f`, atomic on one
  file system) are those of the SFTP road. A copy down keeps mode 0600: no
  portable command reads the far file's mode; with `-p` or `--owner`,
  `stat` gives it (GNU's and BusyBox's `-c`, else BSD's `-f`), where the
  server has one. Up, `chown`, `chmod` and `touch -t` (in UTC) set what a
  copy keeps on the temporary file before `mv`. A copy within one server
  goes through this host. Each step with no file data waits 15 s at most.
- `--jsonl` prints one object per file: `{"event":"done", "source",
  "destination", "bytes", "sha256", "verified_by", "atomic"}`, with
  `"delta"` too after `--delta` (T-470), or
  `{"event":"error", "source", "message", "code"}`, one for each failure;
  and `{"event":"skipped", "source", "why"}` for each special file of a
  tree (T-476), and each file that `-n` or `-u` left out (T-473), with
  `"backup"` in the `done` object of a copy that kept the old file.
- Each SFTP reply with no file data waits 30 s at most, each read or write
  60 s (T-133); `--timeout` bounds the whole copy, the login included, and
  with no terminal it is required, or `PODSSH_TIMEOUT` in its place (64
  with neither): nobody may be there to stop a run that waits. `scp` and
  `sftp` take it as a bound and need none (T-508).
- **A copy goes on after a broken connection**
  (`crates/podssh-cli/src/cp/resume.rs`): a relay close, a lost link or a
  step with no reply keeps the temporary file, and a new connection writes
  on at the offset below which each byte is in it; by exec, once the far
  file stands still (two sizes 2 s apart), up with `cat >>` and down with
  `tail -c`. At most 5 attempts in a row with no new byte, with the relay
  opener's backoff between them; a refused login, a host key other than
  the first connection's, or another answer ends it at once.
- The offset is kept across runs too, in a private side file of the cache
  directories (`podssh-cp-*.resume`, never a byte of the file): the same
  command, run again, goes on while the source is as it was; else it
  starts over and says so. The digest covers the whole file: a continued
  copy whose digests differ starts once more from the first byte, then
  fails.
- **Before the relay's limits** (64 MiB both ways, 12 h for each session),
  a copy opens a new session and goes on at its offset, with no wait: it
  counts each session's payload bytes and age against a budget of 60 MiB
  and 11 h 30 min (`docs/relay.md`, "Limits that users see";
  `PODSSH_SESSION_BUDGET` lowers the bytes). Each new connection meets the
  first one's host key, and logs in as the first did: a key that a
  passphrase opened, or a password that the server took, is kept in memory
  for the run, so no new question comes. `--direct` has no such limit.

## `podssh mv`

`podssh mv SRC... DST` moves files, with the operands and the flags of `cp`
(`crates/podssh-cli/src/cp/moving.rs`).

- **Within one server, the server renames**, and no byte moves:
  `posix-rename@openssh.com` (else the rule of `cp`: remove, then rename,
  said), or `mv -f` by exec. When the server fails the rename for a reason
  of its own (two file systems), the move is a copy and a delete, said
  first.
- **Between hosts a move is not atomic**, and podssh says so on stderr
  before any byte moves: the copy of `cp`, its digest check, then a delete
  of the source. Between two servers, a third connection removes it.
- **The source goes last**: after the digests matched and the rename onto
  the destination succeeded, and only while it is still the file that was
  copied: the same size and time of change; here the same file (the device
  and inode, or on Windows when it was made); by exec the same line of
  `ls -lnid`; and where a digest command runs on its side, the same bytes.
  A source that changed stays, and the move exits 66. A delete that fails
  exits 70 and says that the copy is complete and verified: the data is
  then in two places, never in none.
- One file named twice is refused (64): as typed, before anything connects
  (`host:a host:./a`), or by the server's answer (`realpath`, or `test -ef`
  by exec).
- `--jsonl` adds `"source_removed"` to each `done` object; a rename has no
  digest (`"sha256": null`) and `"verified_by": "rename"`.
- **`-n`, `-u` and `-b`** (T-473) are `cp`'s: a source whose destination
  stays is not moved and stays, and `mv -r` leaves it with the directories
  that hold it. Within one server, `-n` moves by a hard link
  (`hardlink@openssh.com`, by exec `ln`) and the removal of the source's
  name, so a name that came since the look stays; `-b` keeps the old
  destination before the rename.

## `podssh scp` and `podssh sftp`

Each takes the command line of OpenSSH's own (`crates/podssh-cli/src/flags/scp.rs`,
`crates/podssh-cli/src/sftp/`), and copies as `cp` does: over SFTP (or by
exec for `scp`), under a temporary name, verified by its digest, then
renamed.

- **Each letter of OpenSSH 10.3p1's usage parses**: supported, accepted
  with no effect (`scp -3`, `-s`, `-T`; `sftp -a`, `-f`, `-N`), or refused
  by name with what to use instead. `-s`, `-R` and `-B` are switches on
  `scp` and take a value on `sftp`, so each verb has its own table.
  `scp -B` is `BatchMode=yes`; `sftp -s NAME` names the subsystem.
- **The requests in flight and their size** (T-140): `sftp -R COUNT` and
  `-B BYTES`, and `-X nrequests=COUNT` and `-X buffer=BYTES` of both, as
  OpenSSH reads them (`K`, `M` and `G` scale a size; the last of each
  wins). A count is 1 or more, and a size 1 to 256K bytes; out of range is
  a usage error (64) that names the flag. podssh keeps 64 requests and 512
  KiB in flight at most, and the size within the server's limit.
- **A URI operand**, `scp://[user@]host[:port][/path]` (or `sftp://`), is
  read as OpenSSH's `parse_uri` reads it: the path after the first `/` is
  under the login directory, `//` makes it absolute, the user and the path
  are percent-decoded, and the port is that operand's own. `cp` and `mv`
  take URIs too.
- **A node of a pair** (T-296): an operand of `scp`,
  `node://[user@]NAME[/ROUTE]:path`, and a destination of `sftp`,
  `node://[user@]NAME[/ROUTE][:path]`, reach the node as `cp` reaches it;
  `-P`, `-J` and `--direct` with a node exit 64. A member of the net is
  reached by its name alone, as for `cp` (T-453).
- **`--timeout DURATION` bounds the whole run and is never required**
  (T-508, the operator's ruling Q72): the login, each file and, for `sftp`,
  the batch, with `PODSSH_TIMEOUT` as its default, and 75 when it passes,
  as for `cp`. With no terminal it is not asked for, as OpenSSH's `scp` and
  `sftp` run in pipes with no such flag, and each wait of a copy has its
  own limit: `ConnectTimeout` the login's (60 s by default), 30 s each SFTP
  reply with no file data, 60 s each read or write. `cp` and `mv` need it
  with no terminal (64), as nothing else bounds the whole run there. The
  gate reads the row of `--timeout`: `optional` is a bound that is never
  required (`crates/podssh-cli/src/flags.rs`, `FlagRow`). Usage errors are
  64 where OpenSSH gives 1.
- **`sftp -b FILE`** (`-b -` for stdin) runs each line in order and prints
  it first; `@` before a command keeps the line from being printed, and `-`
  keeps its failure from ending the batch. Else, on a terminal, `sftp`
  asks at a prompt; with no terminal and no `-b` it refuses (64). A
  destination whose path names a file fetches it and ends.
- The commands: `get` and `put` (`reget` and `reput` are the same: a copy
  that broke goes on by itself; `-p` keeps the times, as `sftp -p` does
  for each), `rename`, `rm` (with `*` and `?` in the
  last name), `mkdir [-p]`, `rmdir`, `ls [-1afhlnrSt]`, `cd`, `lcd`, `pwd`,
  `lpwd`, `chmod`, `df [-hi]` (`statvfs@openssh.com`), `help`, `version`,
  and `bye`. The local commands (`lls`, `lmkdir`, `!command`) and `ln`,
  `chown`, `chgrp` are refused by name.
- **`ls` lists as OpenSSH's sftp does** (T-471,
  `crates/podssh-cli/src/sftp/listing.rs`; `do_ls_dir`, `do_globbed_ls` and
  `ls_file` of OpenSSH 10.2p1 to 10.6p1). Without `-l` or `-1` the names go
  in columns of the width of the terminal on stdin, else 80; `-1` puts one
  a line. `-l` gives OpenSSH's long form, seven columns: the mode with the
  type letter of each kind (`-`, `d`, `l`, `p`, `s`, `c`, `b`) and the
  set-id and sticky bits, `?` for the link count (SFTP version 3 carries
  none), the owner and the group 8 wide at least, the size 8 wide, the time
  of change in the local zone (the hour within half a year, else the year),
  then the name as typed. For a directory, each entry is the line that the
  server wrote (its long name), as OpenSSH prints it, unless the server
  names owners by number (`users-groups-by-id@openssh.com`, asked once for
  a listing) or `-n` or `-h` is given; then podssh makes the line, and also
  for an entry that came with no long name. A file or a pattern always gets
  the line made here. `-n` gives the numbers, as OpenSSH 10.4p1 and later
  do (10.2p1 and 10.3p1 still named them), `-h` the sizes as `fmt_scaled`
  (`512B`, `1.5K`, `5.0M`). `-t` sorts the newest first, `-S` the largest
  first, `-r` turns the order round, `-f` keeps the server's (and `-r` does
  nothing with it); `-a` shows the names that start with a dot. A path is
  shown before each name (`ls dir` gives `dir/a`); a pattern, in the last
  name, matches a name that starts with a dot only when it starts with one,
  `.` and `..` too, as OpenSSH's glob does.
- **`get -r` and `put -r`** (or `-R`; each `get` and `put` after `sftp
  -r`) copy a directory with T-143's walk, its checks of names and its copy
  of each file (`crates/podssh-cli/src/cp/tree_conn.rs`): each link as a
  link, a device, a FIFO or a socket skipped with a note and no failure
  (T-476), each directory's
  mode (and with `-p` its times) after its files, and a name of a far
  listing that is not one component refused. Into a directory that exists
  the tree goes under it, with its own name; else it takes the name given.
  The batch prints its line once, as for one file; an item that fails is
  said, the rest goes on, and the command fails at its end with the first
  failure's code. Each file goes over the batch's session, as a `get` or a
  `put` does: a broken session ends the command, and no side file is kept.
  Several sources that a pattern names (`get -r dir*`) each go under the
  local directory, with their own names.

## The record of a copy: `--result-file`

`cp`, `mv`, `scp`, `run` and `sftp` take `--result-file FILE` (T-486,
GitHub #97, `crates/podssh-cli/src/cp/result.rs`): at the end of each run,
also of one refused before it connected, one JSON object in FILE, so that a
harness reads what happened with no parsing of stderr and no sum of the
events of `--jsonl`, which stay as they are.

- **The keys of `ssh --result-file` keep their meaning**
  (`crates/podssh-cli/src/ssh/result.rs`), and each verb adds keys:
  `schema` (1), `verb`, `exit` (the code that podssh exits with),
  `failure` (the class, or null), `error` (its words, or null),
  `duration_ms` and `relay` (`host`, `close_code`, `reason`, and
  `sessions`, the relay sessions that the run opened: a copy past the
  relay's limits opens more than one; null with no relay). `ssh`'s own
  object keeps its keys, with no `verb`: a reader of it compares it whole.
- **The classes**: those of T-054 where the connection failed, as the
  run's own record says (`connect`, `relay`, `host-key`, `auth`); `copy`
  for a source, a destination, or a step that the server refused (no SFTP
  after the login is one); `verify` for digests that differ; `session` for
  a session that broke; `timeout` after `--timeout` (75) and `interrupted`
  after a signal (130); `usage` and `config` for a refusal before anything
  connects (64, 78).
- **The copies** add `files` (`sent`, `unchanged`, `skipped`, `deleted`,
  `failed`, as the summary counts them) and `transferred` (`up` and `down`:
  the bytes of the files through this host, with `--delta` the blocks that
  went, none for a rename or a hard link, and both ways between two servers
  through this host). `bytes` is null: it is the streams of a command in
  `ssh`'s object, and a copy runs none. After `--timeout`, `files` and
  `transferred` are null, as the run's counts went with it (T-472). `mv`
  adds `removed`, the sources that it removed once their copy was verified.
- **`run`** adds the `status`, `signal`, `end` and `bytes` of its command,
  as `ssh` gives them; `bytes` is null when the command did not run, as
  after a copy that failed. Its `transferred` is up alone.
- **`sftp`** adds `commands` (`run`, `failed`) and `failed_command`, the
  line of the batch whose failure ended it, as the user wrote it, or null;
  a fetch of the destination's file is one command. Its unit is the
  command: it has no `files` and no `transferred`, and `bytes` is null.
- The facts are the run's own: its outcome, and the record of its own
  scope (`podssh_ssh::outcome::Scope`, T-484), which its connections and
  the command's session write, never the process's. A new file is made for
  its owner alone (mode 0600 on Unix), by the one writer of `ssh`'s; `-` is
  refused (64), as stdout is the run's. A file that cannot be written is a
  line on stderr, and the exit code stays the run's.

## `podssh edit`

`podssh edit [user@]host:PATH` changes one file of a server in an editor
here (`crates/podssh-cli/src/edit/`), with the connection flags of `cp`;
on a terminal no `--timeout`: a person decides how long an edit takes.

- **The fetch** is the copy down of `cp` (a temporary name, the digests, a
  rename; a new connection after a break), into a new directory of mode
  0700 in the cache directories (`edit-RANDOM`), as a file of mode 0600
  with the far file's name, so that the editor knows its kind by its name
  or its extension; a name that this system cannot hold becomes `file` with
  the extension. podssh records the far file's size and time of change (by
  exec, the line of `ls -lnid`), its SHA-256 and its mode.
- **No session while a person edits.** The connection closes before the
  editor starts: no relay session waits, so its idle limit (180 s) and its
  12 h cap cannot end an edit, and a lost link costs nothing. The second
  connection meets the first one's host key and logs in as the first did,
  with no second question (T-136, T-137).
- **The editor** is `VISUAL`, else `EDITOR`, else `vi` when a probe finds
  it on `PATH` (`AGENTS.md`, rule 3); with none, the exit is 78 and the
  message names `EDITOR`. A value is a program and its words, split at
  blanks with no shell, or one program whose path has a blank. The editor
  runs on this terminal: `edit` needs a terminal on stdin and stdout (else
  64, checked after the editor's choice, so that a test with no terminal
  reaches both refusals; the refusal names `--no-terminal`). While it runs,
  SIGINT and SIGQUIT are ignored here (on Windows a listener holds Ctrl-C),
  so the keys are the editor's.
- **`--no-terminal`** (T-510) runs an editor that needs no terminal, a
  script that changes the file in place (`EDITOR='sed -i s/a/b/'`): its
  stdin is `/dev/null` (`Stdio::null`), its stdout goes to podssh's stderr,
  so podssh's stdout stays empty, and the check of the far file before the
  send is the same, so an agent gets the check that `cp` has not. With no
  terminal it needs `--timeout` or `PODSSH_TIMEOUT` (64 with neither, the
  gate's words of `cp`), which bounds the editor's run: when it passes,
  podssh kills the editor, sends nothing and exits 75; the first SIGINT or
  SIGTERM does the same with 130; a copy that holds a change then stays,
  named. `--timeout` without `--no-terminal` is 64, and `PODSSH_TIMEOUT` is
  read only with it: on a terminal a person decides. A flag, not a guess
  from `EDITOR`: podssh cannot tell an editor that needs a terminal from
  one that needs none, and `vi` with no terminal waits for ever.
  An editor whose program returns while its window stays open leaves no
  change when it returns, and the copy goes: give it its flag to wait, as
  `code --wait`.
- **The check before the send.** A copy whose SHA-256 did not change sends
  nothing (exit 0). Else a new connection compares the far file with the
  record: its size and time of change (by exec, the line of `ls -lnid`),
  then its SHA-256 (`sha256sum` over exec, else a second read), as a write
  in the same second keeps the size and the time. When the far file
  changed, nothing is sent and the exit is 73: a change made there is never
  overwritten. The check and the rename are a moment apart; no lock of
  SFTP version 3 closes that moment.
- **The send** is the copy up of `cp`, with the far file's mode on the
  temporary file before the rename, so the name never has another mode.
  `Shape::mode` carries it to both roads; without a mode from the server,
  the file gets the copy's mode, and podssh says so.
- **A symbolic link stays a link**: over SFTP, `lstat` finds it and
  `realpath` names the file that the edit changes; by exec, where no
  portable command names that file, a link is refused (66).
- **The copy here** goes after a success. After a failure it stays and is
  named when it holds a change, with its directory: `your copy stays at P;
  rm -r DIR once you merged it`; and goes when it holds none. A later run
  says once, at the default level, which kept copies are more than 7 days
  old (the newest file in each `edit-*` directory of the cache), with their
  directories, and removes none: each holds a change of the user's. An
  editor that
  ends with a status other than 0 sends nothing, and `edit` exits with that
  status (128 + N for signal N). The first SIGINT or SIGTERM while a file
  moves ends the run with 130: during the fetch nothing stays here; during
  the send the copy stays, named, with the far side's partial copy.

## `podssh doctor`

`podssh man doctor` gives the checks. The rules behind them:

- `doctor` takes the relay settings of `ssh` and `proxy` (`--relay-host`,
  `--relay-addr`, `--ca-file` and their variables), so it checks the path
  that they use.
- **The sections at once** (T-511, the operator's ruling Q73). The
  sections that connect (the egress's probes, the quick tunnel's edge, the
  relay, the forwarders and each road that the run names, iroh and tor in a
  build with them, OpenTunnel, DERP, the public carriers, the pairs and the net, T-435) start together by default, each into
  its own part of the report, and the report keeps its order: a part's
  lines go out once each part before it has ended, the first that still
  runs line by line, as a run of one section at a time showed them. A run
  then takes about as long as its longest section, not their sum (22 to
  40 s in the testers' runs of `v1.0.0`, most of it the iroh relays, the
  DERP servers and the quick tunnel's edge). Each section still reaches its
  servers one after another, so a run holds at most one connection for
  each section that runs, five in a run with no flag, no stored pair and no member relay
  (the egress, the relay, OpenTunnel, DERP, the public carriers), and the relay's forward races its hosts as `ssh` does
  (Q10). `--jobs N` (1 to 64), or `DoctorJobs N` in the settings file,
  starts at most N together, in the order of the report; `--jobs 1` is one
  after another, as before. A bad value is 64 for the flag, 78 for the
  file.
- **`--quick`** (T-511) checks this host, the egress and the relay alone,
  what each run of `ssh` and `proxy` needs, with the section of each road
  that the run names (`--forwarder`, `--shadowsocks`, `--via`, `--vless`).
  It leaves out the quick tunnel's edge (its roots, `UDP out`, `edge
  road`), iroh and tor in a build with them, OpenTunnel, DERP, the public carriers, the pairs and the net, and says
  so in its last line, `sections` in the section `left out`, as `????`: a
  check that did not run. The MCP tool `doctor` takes it as `quick`.
- `ok`: the check ran and podssh can work with the result. A condition that
  podssh is made for (no listener, no pty, no user database entry, no DNS)
  is a fact and gives `ok`.
- `FAIL`: something that podssh or one of its fallbacks needs is broken: a
  proxy setting that cannot be used, no place to record host keys, a relay
  host that does not answer, no token, a forward session that fails or
  meets the wrong host key, or a clock more than one hour wrong.
- `????`: the check could not run. It never counts as `ok`, and it never
  makes the run fail.
- Servers are identified by equality (GitHub's published host key), never
  by the form of a banner. The lines `listen AF_INET` and `listen AF_UNIX`
  bind a socket (127.0.0.1 port 0; a file of mode 0600 in the temporary
  directory, and on Linux an abstract name), listen once with a backlog of
  1, accept nothing and close it at once; each says what the bind and the
  listen did, and which listeners of podssh can or cannot listen here (`-L`
  and `-D` on a port or a path, `pipe tcp-listen:` and `unix-listen:`, the
  control socket of `-M`, `podssh agent` and `podssh session`). A refusal is
  `ok`: no road needs a listener. With `PODSSH_LISTEN=no` no listen is
  tried, and the line says so. Proxy credentials and tokens are never shown.
- `sshd` (T-590, GitHub #116), in the section `this host`: where this host
  has the sshd of a roost, looked for as the roost looks (above), and one
  dial of `127.0.0.1:22`, the roost's default TARGET, with its first line
  within 2 s, judged by the roost's own rule: `present at /usr/sbin/sshd;
  127.0.0.1:22 answers SSH-2.0-...`; `nothing listens at 127.0.0.1:22`,
  with what a roost needs; another first line; or `absent (...)`, with the
  command that installs one. Each form is `ok`: a host with no roost needs
  no sshd, so the line is a note, never a failure. The dial is of the
  loopback, so no proxy carries it and `PODSSH_OFFLINE` does not stop it.
- **Names and addresses** (T-366). Each road of the release binaries asks
  the proxy for a name, so a proxy of an allowlist of names and one that
  takes any public address answer those probes alike. Through a proxy, the
  line `IP CONNECT` asks for an address, the first resolver of DNS over
  HTTPS, sampled as each probe is, then does its TLS for that address, so
  that a `200` which carries nothing is named; the line `egress takes`
  names the case: names and addresses, names only (a road to an address,
  `--direct` to one, WARP's endpoint or Tor's first hops, cannot leave),
  addresses only, or neither. With no proxy, it comes of `direct TCP` and of
  DNS over HTTPS, which reaches its resolvers by their addresses.
- **A reset, a timeout, and the diagnosis** (T-487, GitHub #99). The dial
  and the TLS of `podssh-ws` keep the kind of the error that ended them
  (`podssh_ws::Cut`: reset, refused, timed out, closed with nothing,
  other), read from its `std::io::ErrorKind`, never from the system's
  words, which differ between systems (Windows says os error 10054 for a
  reset). The line `TLS reference` makes TLS with `github.com` on port 443
  by its name, its certificate checked, with doctor's trust: straight out
  with no proxy (one connection), else over the first `CONNECT` that the
  proxy took for `github.com:443` (no new connection); it is `ok` with what
  it met, a handshake, a reset or a timeout, as the other reference probes
  are. A reset and a close with nothing before the handshake ended are both
  the far end's, and read as a reset. After the counts, a line
  `diagnosis:` names a case that the handshakes of the roads (each relay
  host's `/health`, each DERP server's probe, each resolver of DNS over
  HTTPS that the check `DNS over HTTPS` asked, and each relay of n0's in a
  build with iroh, T-604) show beside the reference, and it counts as
  nothing: each relay host reset, none of the roads by a name timed out (a
  resolver is asked by its address, with no name, so its timeout says
  nothing of names), and `github.com`'s completed is an egress that resets TLS for each
  name that it does not list (`tls-names`: each road through the relay's
  name stays closed until the name is listed, and a road through a listed
  name serves: `--forwarder`, `--via`, a relay of your own), with each name
  whose handshake completed as evidence; each reset, `github.com`'s too, is
  an egress that resets each TLS handshake on port 443 (`tls-reset`); each
  timed out, `github.com`'s too, is a path that drops them and resets none
  (`tls-dropped`). Through a proxy the same cases read the TLS after its
  `CONNECT`; the resolvers, which `doctor` asks only with no proxy and
  straight at their addresses, count only beside a reference that went with
  no proxy.
- **The line `ipv6`** (T-253), in the section `relay`, after the relay
  hosts: whether an IPv6 target can be reached, with no connection of its
  own beyond one request. Through the first relay host that answered, by
  its `/relays.json`: `podssh relay serve` says in `egress.ipv6` whether
  its host routes IPv6 out (yes; none, and it refuses an IPv6 target before
  the upgrade; or `null`, it cannot tell), and in `known_by` how it knows
  ([relay.md](relay.md), "IPv6 targets"). The default relay says nothing
  of it, and the line gives its egress when last measured, on 2026-11-03:
  none, as each IPv6 target upgraded and then closed with `1011`. Direct,
  by this host's own probes, which send nothing: where a proxy takes a
  public IPv6 address, the proxy's way out decides and the line names the
  proxy by its address; else an IPv6 socket made and closed (a kernel with
  no IPv6 refuses it), then the table of IPv6 routes that Linux gives as a
  file, as the role reads it. It is `ok`, a fact; `????` when no relay host
  answered or its `/relays.json` cannot be read.
- **`--exit NAME`** (T-458) checks the exit NAME of the user's net in a
  section `exit`, among the roads that a run names (so with `--quick` too),
  as `podssh proxy --exit NAME` reaches it. `exit net`: what the net held
  says, that NAME is a member with the role `exit` and which rule of its
  policy lets this client (`--client-key FILE`, else `client.key` in the
  cache, as `proxy --exit` takes it) reach `exit:NAME`; `????` when this
  host holds no net, as the exit's own net decides. `exit pair`: the pair
  kept under NAME, its relay host and its expiry. `exit`: one session from
  the exit to `--exit-target HOST:PORT` (default `github.com:22`, identified
  by its published host key; another target by its first bytes, or none in
  5 s), over the pair's road, with the time to the node's verdict. A
  refusal says whose it is, by the words that each writes: the road (the
  relay, or the pair), the channel (the exit let this key not in), the net's
  policy, the exit's check of an address, or its dial. `--exit-target` and
  `--client-key` with no `--exit` are 64.
- **The line `cleartext`** (T-326, GitHub #56), in the section `relay`,
  after `ipv6`: what a request with no TLS meets on the way to the first
  relay host that answered, else to the first host, at its port and at port
  80 beside 443, as the cleartext road would meet it once the TLS road
  failed: the `CONNECT` that the proxy takes, then `GET /health` with no
  token and no target, and what came back, named (a reset or a close with
  no answer, as a hop that expects TLS cuts cleartext; a record of TLS; the
  edge's refusal, a `400` that says a request of plain HTTP went to its
  HTTPS port; a refusal by policy, `403`; a redirect; or an answer, the
  relay's own `/health` named), then whether the road reaches the relay.
  One probe after another, 10 s each. It is `ok`, a fact, as a reset is no
  fault where TLS answers; `????` when the proxy setting cannot be read.
  With `--forwarder`, the section of the forwarders has the same line for
  each one's host, at 443 and 80, and says whether a `ws://` form of it can
  pass.
- **The line `http2`** (T-321), in the section `relay`, after `cleartext`:
  what the same host offers the WebSocket over HTTP/2, with nothing sent but
  HTTP/2's preface, its SETTINGS and a PING: the protocol that its TLS chose
  when podssh offered `h2` then `http/1.1`, and on `h2` whether its SETTINGS
  offer extended CONNECT, with its streams at once; then whether the
  sessions of a run share one connection to it, by `PODSSH_H2`. It is `ok`,
  a fact; `????` when the host was not reached; `FAIL` for a word of
  `PODSSH_H2` that is not `auto`, `yes` or `no`. With `--forwarder`, the
  section of the forwarders has the line for each `wss://` one, whose road
  keeps the upgrade of HTTP/1.1. The line `forward` names the road that
  carried its session.
- `--full` adds the check `login` (GitHub #13): a login to `github.com` as
  `git` through the relay, with an Ed25519 key made for the check, kept in
  memory and never written. GitHub refuses it, which is `ok`: the handshake,
  the host key (equal to the one that `forward` identified) and the
  authentication path work. Another host key, or a broken link, is `FAIL`.
  No pty request is tested (GitHub refuses the key before a channel), and
  the binary runs no OpenSSH: `scripts/sandbox-check.sh` keeps that step,
  and calls `doctor --full`.
- `--hop [USER@]HOST[:PORT]` (T-371) checks this host and a first hop of
  `-J` alone, as `--direct` reaches it: `hop`, the connection through
  `HTTPS_PROXY` (or straight out with none), sampled as the other probes,
  and the server's banner, as T-317 reads it; `hop key`, the host key that
  it presents; `hop login`, a login as USER (or `podssh-doctor`) with a key
  made for the check, whose refusal names the methods that the server
  offers. A proxy that takes the CONNECT and then waits for TLS carries no
  SSH: the line says so, and names the relay as the road for SSH over
  HTTPS. A password of a hop comes from `SSH_ASKPASS` or the terminal,
  never from the command line. A value that does not read is 64.
- `UDP out` (T-359) says whether `podssh node --quick-tunnel` takes QUIC:
  with a proxy set, nothing is sent, as the node then takes HTTP/2; with
  none, `--full` sends the node's probe of UDP (T-400), then, answered,
  a QUIC handshake with the quick tunnel's edge (Cloudflare's), each region
  at once, closed with nothing registered. A run without `--full` reaches no
  server of Cloudflare's, and says so. In a build with the feature `iroh`,
  `iroh UDP out` gives the iroh road's own answer: whether a QUIC address
  discovery to its home relay came back.
- `edge road` (T-374) says, with `--full`, which road over TCP reaches the
  quick tunnel's edge, as `podssh node --quick-tunnel` tries them: TLS with
  the edge on port 7844 directly or through the proxy; else, in a build with
  the feature `warp` and with a device of WARP kept in the cache, inside
  WARP's tunnel (`warp://`, above); doctor registers no device. TLS closes
  at once, with nothing registered. A run without `--full` says so.
- `tor` (T-353), in a build with the feature `tor`, says with `--full`
  whether Arti bootstraps here as a `tor://` destination makes it: through
  the proxy, its first hops on the ports of `PODSSH_TOR_PORTS`, or the
  bridges of `PODSSH_TOR_BRIDGES` and their transports (T-385), in the
  network of `PODSSH_TOR_NETWORK` when one is named; and in how long. It
  opens no stream. A first bootstrap fetches Tor's directory, a few MiB, so
  a run without `--full` tries none, and says so.
- The section `derp` (T-379) asks `/derp/probe` of each DERP server of the
  list (`PODSSH_DERP_SERVER`, else Tailscale's tailcat fleet), in order,
  through the proxy, 5 s at most each, as `node --derp` finds its home: a
  line for each server, `FAIL` for one that does not answer, as it is a
  fallback that does not work here, and `DERP home server`, the first that
  answered.
- `--json` writes the same report as one JSON object, when every check has
  run (GitHub #9): `schema` (1), `podssh`, `os`, `arch`, `checks` (each
  with `section`, `check`, `status` and `detail`; `status` is `ok`, `FAIL`
  or `unknown`), `counts`, and `diagnosis` (each case after the counts, with
  `kind`, `detail` and `evidence`; empty when none, T-487). The exit code does not change. `--json` is
  for a report that ends; `--jsonl` stays for the events of a long run.
- Each probe that connects (each `CONNECT`, and `direct TCP`) is tried nine
  times, 125 ms apart (GitHub #54, T-324): one time cannot tell a path that
  refuses from one that was slow, nor a steady path from a lossy one. The
  line gives the best time (the floor), the median, the 95th percentile, the
  jitter (the median change from one try to the next) and the loss, the
  timeouts and the other breaks counted apart; a refusal is an answer, not a
  loss. `--json` gives the same as `samples`. A first try that timed out is
  not repeated, a later try waits four times the first try's time (3 s to
  8 s), and none starts that could end more than 10 s after the first: a path
  that does not answer never holds `doctor` for minutes. Only the probes of
  TCP are sampled: the relay's `/health`, its upgrade and the SSH handshake
  stay one each, as each is a request to the relay's Worker and a session
  to GitHub.
- A forward session whose upgrade fails names one of three failures, each
  with its own way out: an answer other than `101` (its status and its text:
  the relay or a hop refused), a `101` whose `Sec-WebSocket-Accept` is not
  the one of the request's key (something between answered in the relay's
  place), and a valid `101` after which the connection ends with no Close
  (something between drops the stream after the upgrade). A Close from the
  relay is the relay's own end, with its code and its reason.
- **What the path does to a stream** (T-325, GitHub #54). `--stream URL`
  checks this host, then the section `stream` alone, one connection at a
  time, as `--hop` checks a hop alone: URL is `https://HOST[:PORT][/PATH]`
  (TLS checked with doctor's trust) or `http://...`, through `HTTPS_PROXY`
  as each road dials, its probes under PATH, `/v1/probe` by default, where
  `podssh relay serve` and the quick tunnel of `podssh node --relay` serve
  them; go-httpbin serves the same paths with `-prefix /v1/probe`. A URL
  with a user, a password or a query is 64. The lines: `stream server`, the
  server's own limits from `limits.probe` of its `/relays.json` (the role's,
  or, behind a quick tunnel's node, the node's, which takes a body whole,
  32 KiB at most, and ends an answer quiet for 60 s), so that what is met
  below them is the path's, and a server that names none is said so;
  `response`, 5 bytes over 2 s, which come as they are sent, at once after
  the last (held until its end) or in parts; `request body`, 4 pieces of 1
  KiB half a second apart, which the server says came over 1.5 s or at once;
  `body cap`, bodies from 64 KiB, twice as big each time, to 8 MiB or the
  server's own cap, until one does not pass, with the sizes between which
  the cap lies and the status that refused it; `quiet stream`, a response
  whose second byte comes `--stream-idle SECONDS` after its first (1 to
  600, 130 by default, past Cloudflare's 125 s), and when and how it ended.
  A size or a time that is a product's documented default gets "looks like"
  and the product (the table of `crates/podssh-cli/src/doctor/stream/prints.rs`),
  never a claim that it is. A path that holds a stream is `ok`, as podssh
  works with it; a server that cannot be reached is `FAIL`; a probe that the
  server does not serve, `????`. With `--full` (not `--quick`), the section
  runs last among the others: the four probes at the relay that the user
  named, and at the default relay, which serves none, a socket of its
  reverse road alone, for a pair made for the check and stopped after it,
  held quiet after the relay's hello; an end before the hold is the path's,
  or the relay's own drop of a node's socket, and the line says both; a run
  of `--full` so lasts its hold at least, and its other sections' lines come
  first. With `--json`, each probe's line gives its numbers in `samples`,
  which the HTTP road of T-319 is to read.

## `podssh status`

`podssh status [--relay-host HOSTS] [--relay-addr HOST=IP] [--net] [[user@]host]`
writes one line of JSON and exits 0 (GitHub #11). It is the cheap call
before anything else; `podssh doctor` is the report that measures.

- The line: `schema`, `podssh`, `relays` and `relays_from`, `deployments`
  (each deployment of the list, with its hosts and its signed list, or
  `false` for the default's pool and null for a list that you named, and
  each list kept that does not hold, with why; T-346), `settings`
  (the path of podssh's settings file, or null), `pool`,
  `token` (its source, the relay that it is for, its expiry, whether it can
  be used), `proxy` (the variable, `HOST:PORT` and the kind, `http` or
  `socks5`), `offline`, `attachment`, `stdin_tty`, `stdout_tty`,
  and `host` for a destination (its name in `known_hosts`, whether a key is
  recorded, the key types); `session_log` (T-056) and `relay_failures`, the
  relay hosts that each run tries last now, with `ago_s`, the `reason` and the `road` (T-059), and
  `relay_opened`, those that opened lately, with `ago_s` and `opens` (T-563); `relay_rank`, the rank kept, with `age_s`, `this_egress`, `holds`, `named`, `source` (`relay rank`, or `background` for a session's, T-608), `partial`, `first` and `hosts`, null with none (T-606); `relay_rank_auto`, whether a setting asks for a rank in a session's background and which (`asked`, `by`), and when the last was made (`last_ms`, `last_age_s`) and whether it is `partial` (T-608); `open_files`, the limit of open files: podssh raises its soft limit at start to the hard one, at most 65,536 (on macOS within `kern.maxfilesperproc`, then `OPEN_MAX` if the host refuses more), and gives the `soft` limit, the `hard` one (null for none), the soft one `at_start`, whether it was `raised` and the host's `refused` answer, a line at `-v` ("open file limit: 256 -> 10240") and the limit after an error of too many open files; null on Windows (T-564); `pairs`, each stored pair's `label`, `expires_ms`, whether it
  `expired`, and `next_now`, whether `relay pair LABEL` makes its next pair
  now, in its last 24 hours (T-395).
- It never holds a token: it reads the cache entry without its token field
  (`cache::peek`). It shows no proxy credentials, opens no connection, asks
  no DNS and writes nothing; it reads the signed lists kept, and checks each
  again.
- A bad flag or destination is 64, a bad variable 78, as for `doctor`.

## `podssh ping`

`podssh ping [OPTIONS] [[user@]host]` is a short check of the path (T-053,
GitHub #23): the time of each step, the round trip, and the throughput.

- With no destination, the relay leg of each relay host: the token (from
  `PODSSH_RELAY_TOKEN`, the cache, or minted), DNS and TCP or CONNECT
  through the proxy, TLS, and the WebSocket upgrade, which the relay
  answers once it reached the target, each with its time; then `--count`
  WebSocket pings (10 by default, at most 100), each with its sequence and
  its send time in its payload and matched to its pong, as the minimum,
  p50, p95 and maximum. A ping with no pong in 5 s is lost; a leg with no
  pong at all fails.
- The leg's target is `--target HOST:PORT`, else `github.com:22`, the
  reference that `podssh doctor` reaches too. It is never the destination:
  its server would see a connection that sends no SSH bytes, and OpenSSH's
  `PerSourcePenalties` (9.8 and later) count those against the relay's
  address, which other users share.
- With a destination, the run is resolved as `podssh ssh` resolves it
  (`ssh_config`, `-J`, `-i`, `-o`, `--direct`). Through the relay, the legs
  come first; then the time to log in (through the pool and the failover of
  `ssh`, with the relay's steps to the destination), the echo of one byte
  at a time through `cat`, `--count` times after one that is not counted
  (the first can wait for the shell to start `cat`), and the throughput
  down with `head -c SIZE /dev/zero` and up with `cat > /dev/null`, each
  line naming its command. These programs are an assumption about the host, so they
  run only for a destination.
- `--size` is 8 MiB each way by default, and at most 30 MiB, so that both
  ways stay under the relay's 64 MiB for one session (`docs/relay.md`).
- What a user feels (T-660), with a destination: `--under-load` types 40
  keys 150 ms apart through `cat`, idle, then from 3 s into a download of
  60 MiB (`head -c`) on a second channel of the same connection, and gives
  the echo's p50 and p95 of each; it takes the place of the plain echo and
  rates, and refuses `--count` and `--size` (64). `--connect-runs N` (1 to
  20) times N cold connects, each to the exit status of `true`. A node is
  measured as a host with either flag. `--json` carries each raw sample.
  `scripts/feel-matrix.py` runs each road through the four links of
  `scripts/fake_shape.py` (`profile:far`, `cellular`, `wifi` and `slow`).
- Each step has a limit: 20 s for a step to the relay, 60 s for a wait of a
  measure, and 600 s for the whole run. A program that the host lacks ends
  the run with its status (127), never with a hang, also when the status
  comes before the server's reply to the command.
- `--json` writes one JSON object when the run ends, in the shape of
  `doctor --json`: `schema` (1), `podssh`, `count`, `size`, `relays` (each
  with its steps in milliseconds, `pings` with `min_ms`, `p50_ms`, `p95_ms`
  and `max_ms`, `pings_lost` and `error`), `destination` and `exit`.
- 0 when the path works: a relay host gave its measures, or each measure
  through the destination has its number. 64 for a bad flag, before
  anything connects; 69 when no relay host answered, or with
  `PODSSH_OFFLINE`. With a destination: the code of `podssh ssh` when it
  cannot be reached or logged in to, the status of a remote program that
  failed, and 255 for a measure that broke.

## `podssh health`

`podssh health [OPTIONS] [user@]host` gives the facts of the far host
(T-189): its load and CPUs, the busy share of the CPUs, its memory and
swap, its uptime, the bytes of each network interface, the use of its
disks, and its processes; in a container, the CPUs and the memory that its
cgroup leaves it (T-480). It only reads: it never stops or changes a
process.

- The host is resolved, reached and logged in to as `podssh ssh` does it
  (`ssh_config`, `-J`, `-i`, `-o`, the relay or `--direct`). Then one exec
  runs a fixed script, as `sh -c 'SCRIPT' sh`, so that a login shell of
  fish or csh only starts `sh`. No text of the user goes into the script.
- The script reads `loadavg`, `uptime`, `meminfo`, `stat` and `net/dev` of
  `/proc` with the shell's `read`, and counts the processes with a glob of
  the shell. It runs `sleep 1` and a second read of `stat`, `uptime` and
  `net/dev` only where `command -v` finds `sleep`, and `df -P -k` of the
  root and the home only where it finds `df`: a host with neither gives no
  rate, no busy share and no disk, and the other facts.
- The available memory is the kernel's `MemAvailable`. A kernel before
  3.14 has none: then the free memory, the buffers and the cache stand for
  it, and the line and the JSON say that it is an estimate. The rates are
  the difference of two samples over the seconds between them, by the
  host's own `/proc/uptime`. A name that the host gives (an interface, a
  mount, a file system) has the controls of a terminal taken out.
- A host with no `/proc` gives the name that `uname -s` prints (when it has
  `uname`) and "no facts for this system", with exit 0.
- The kernel gives `/proc/stat`, `/proc/meminfo` and `/proc/loadavg` for
  the whole host, also inside a container (proc(5)), so a container of 4
  CPUs and 4 GiB on a host of 48 CPUs read 48 there (GitHub #88). The
  script also reads the cgroup of its own shell: `/proc/self/cgroup`, then
  that cgroup's files under `/sys/fs/cgroup`, at the mount's root where a
  cgroup namespace shows the container's own cgroup as `/`, and each
  parent's limits up to that root. Of cgroup v2: `memory.max`,
  `memory.current`, `memory.swap.max`, the `inactive_file` of
  `memory.stat`, `cpu.max`, `cpuset.cpus.effective`, `cpu.stat` before and
  after the second, `io.max`, `pids.max`, `pids.current`, `cpu.pressure`
  and `memory.pressure`; of v1: `memory.limit_in_bytes`,
  `memory.usage_in_bytes`, `total_inactive_file` and
  `hierarchical_memory_limit` of `memory.stat`, `cpu.cfs_quota_us` and
  `cpu.cfs_period_us`, `cpuset.effective_cpus`, `pids.max` and
  `cpuacct.usage` before and after (the kernel's `cgroup-v2.rst`,
  `cgroup-v1/memory.rst`, `cgroup-v1/cpusets.rst`, `sched-bwc.rst` and
  `psi.rst`).
- The effective facts: the CPUs are the least of the quota over its period
  (`max` and -1 are none), the CPUs of the effective cpuset, and the
  host's; the memory is the least limit below the host's memory, and the
  available memory the limit less the working set (the use less the
  inactive file cache, which the kernel takes back before its killer runs,
  as `docker stats` counts it), at each level that limits, never more
  than the host's `MemAvailable`. A limit at or above the host's memory
  limits nothing: cgroup v1 writes its "none" as a huge number, and LXCFS
  gives a container its own `/proc/meminfo`, so nothing is counted twice.
  A host that hides `/sys/fs/cgroup` gives the host's facts, with the
  source `host`: a fact that the answer lacks is absent, never a guess.
- Where a cgroup limits the CPUs or the memory, the lines say so beside the
  host's: `cpus 4 (cgroup v2 cpu.max), 48 on the host`; `memory 3.1 GiB
  available of 4.0 GiB (78 %, cgroup v2 memory.max); the host: ...`; the
  load line ends with "the whole host's"; the line of the CPUs adds the
  cgroup's share of its CPUs over the second and the periods in which it
  was throttled; the cgroup's pressure (PSI, the share of the last 10 s
  that its tasks waited) is a line of its own, and so is each line of
  `io.max` and a `pids.max` that is not `max`. With no limit the lines are
  those of before.
- One line for each fact on stdout; with `--json`, one JSON object, also
  after a failure, in the shape of `doctor --json`: `schema` (1),
  `podssh`, `destination`, `system`, `load`, `cpus`, `cpu_busy_percent`,
  `interval_s`, `memory` (in KiB, with `available_estimated`), `uptime_s`,
  `network` (each `interface` with `rx_bytes`, `tx_bytes`, `rx_per_s` and
  `tx_per_s`), `disks`, `processes`, `error` and `exit`. Each of these
  keeps its meaning, the host's. `effective` holds the facts to plan from
  on any host: `cpus` (4.0 or 1.5), `cpus_from` (`cgroup v2 cpu.max`,
  `cgroup v2 cpu.max of a parent`, `cgroup v2 cpuset`, `cgroup v1
  cfs_quota_us`, `cgroup v1 cpuset` or `host`), `memory_total_kib`,
  `memory_available_kib`, `memory_from`, and the cgroup's `cpu_used`,
  `cpu_busy_percent`, `throttled_periods` and `periods`. `cgroup`, where
  one was read, holds its `version`, its `path`, each value as read in
  `values`, and `cpu_usage_usec`, `pids_current`, `pids_max`, `io_max` and
  the pressure's `avg10`s.
- The exit codes of `podssh ssh`: 0 with the facts; 255 when the host
  cannot be reached or logged in to, has no `sh`, or gave none of the
  script's lines; 64 and 78 before anything connects. The script has 30 s,
  and the whole run 120 s.

### `health --preflight`

`--preflight` (T-482, GitHub #92) asks, after the facts and on the same
login, what the far server allows of what a long command needs later.
Each of a server's answers showed before only when the command that needed
it failed, often late and in the words of a dead link: the server of #92
ended each idle session at a keepalive's reply (#83), refused
`tcpip-forward` (#85), opened no `direct-tcpip` (#86) and named no
`copy-data` (#87). `doctor` checks this host and the road, and its `--hop`
reaches a hop as `--direct` does; neither reports the far server, and
`doctor` takes no option of `ssh`, where `health` logs in with each of them.

- A section `preflight` follows the facts, in `doctor`'s lines: `ok`,
  `FAIL` or `????`, the check's name, and what was found; then the counts.
  Each probe asks once, within 10 s of its own, so that a server that never
  answers fails that probe alone; the run has 70 s more.
- `login`: the user, the hops of `-J`, the method that let the user in, and
  the server's version line. `road`: the relay host and its limits on a
  session, 64 MiB both ways, 180 s with no payload and 12 h, from its
  `/relays.json` where one was read (T-342), else podssh's own; or the road
  that is not the relay, which has none of them.
- `sftp`: the subsystem, its sizes of a read and of a write, its
  extensions, and what `cp` does without `copy-data`,
  `posix-rename@openssh.com`, `hardlink@openssh.com` and
  `limits@openssh.com`. No subsystem is `ok`: `cp` then copies by exec. A
  subsystem that does not answer, or breaks SFTP, is `FAIL`, as `cp` fails
  there too.
- `remote forward`: `tcpip-forward` for the server's `127.0.0.1`, port 0,
  so that the server chooses a port, then `cancel-tcpip-forward` at once. A
  refusal, or no answer, is `FAIL`: `-R` cannot work there (OpenSSH with
  `AllowTcpForwarding no`, Dropbear with `-k`). This host binds nothing:
  the far server listens for a moment on its own loopback, which the user
  asks for with `--preflight` (the operator, Q83); `health` alone only
  reads.
- `jump`: a `direct-tcpip` channel to the server's own `127.0.0.1`, port
  22, as no port of the far side is known, closed at once. RFC 4254
  (section 5.1) tells `connect failed` from `administratively prohibited`:
  a channel that opened, or one refused as `connect failed`, is `ok`, as
  the server opens such channels and the target was a guess;
  `administratively prohibited`, an unknown channel type, or no answer is
  `FAIL`: `-J`, `-L`, `-D` and `-W` through this host cannot work (OpenSSH
  with `AllowTcpForwarding no`, Dropbear with `-j`). A resource shortage is
  `????`.
- `exec tools`: one exec of `sh -c 'SCRIPT' sh tmux`, one line with no
  single quote and no backslash, as each far script of podssh, names each
  tool on `PATH` of the copy by exec, of `job`, of `cp --delta` (`dd`) and
  of `ping` through the host (`head`). A host whose login runs no `sh`, or
  one that lacks `cat`, `mv`, `rm`, `mkdir`, `sleep` or `wc`, is `FAIL`;
  each other tool that is missing is named with what it stops, and no
  `sha256sum`, `shasum` or `openssl` means a check by a second read.
- `tmux`, from the same exec: missing, it is `FAIL`, as `ssh --persist`
  cannot work and `job` needs `--no-tmux`; the line names what could
  install it, from T-481's probe, which the same `sh` runs at the end.
- `cgroup`: the CPUs and the memory to plan from (T-480), from the facts.
- `keepalive`, last: one `keepalive@openssh.com` with a reply wanted. A
  reply, a success or a failure, is `ok` (OpenSSH's sshd answers with a
  failure); no reply, or a connection that ends at it, is `FAIL`, with `-o
  ServerAliveInterval=0` as the way round. It goes last, as a reply that
  cannot be read ends the connection, once each other probe has run. A
  probe after the connection ended is `????`, and asks nothing.
- The exit, once the login is done, is `doctor`'s: 1 when a check failed
  or the facts did not come, else 0. A login that fails is 255, as without
  `--preflight`, and the section holds its one line, `FAIL`. With `--json`,
  `preflight` holds `checks` (each with `section`, `check`, `status` and
  `detail`, as `doctor --json` gives them) and `counts` (`ok`, `fail`,
  `unknown`); without `--preflight` it is `null`.
- A flag of `health`, not of `doctor`: the far host's answer needs the
  login of `ssh`, with each of its options. `doctor --via HOST`, as the
  issue wrote it, names T-439's second proxy.

## `podssh keygen`

`podssh man keygen` gives the flags. The rules behind them:

- The `ssh-keygen` of OpenSSH does not run without a user database entry,
  so podssh makes keys itself, in the formats of OpenSSH.
- A new key is never written over an existing file.
- Only its owner may open the private key: mode 0600, and on Windows an
  access list of its own for the user, SYSTEM and the Administrators, with
  nothing from the directory above, as OpenSSH's `ssh-keygen` makes it;
  OpenSSH for Windows refuses a key that others may open. Each may read
  `FILE.pub`, and only its owner may change it (mode 0644; on Windows,
  Everyone reads it). A missing directory is made private (T-288).
- `-p` changes the passphrase of the key in `-f FILE`, and `-c` its comment,
  in the key and in `FILE.pub` (T-018). The file is replaced only with the
  same key: the new text goes to a new private file beside it, which is
  read back, opened with the new passphrase and compared by its public
  key, and only then renamed over the file. No copy of the old file is
  kept: it holds the key under the passphrase that the user wants gone.
- `-p` and `-c` read each format that `podssh ssh -i` reads, and write the
  format of OpenSSH, as `ssh-keygen -p` does. Measured with keys that
  OpenSSH's `ssh-keygen -m` made: PEM (RSA, also encrypted, and ECDSA) and
  PKCS#8 became keys of OpenSSH with the same public key, and so did the
  keys of PuTTY. An encrypted key of each format is asked for (T-287).
- A passphrase given with `-N` or `-P` is refused (exit 64), because each
  process on the host can read a command line. `-N ''` and `-P ''` are
  accepted. With no terminal and no `SSH_ASKPASS`, podssh refuses at once
  and names `-N ''` (and `-P ''` for `-p` and `-c`); it does not wait.
- `-F HOST`, `-R HOST` and `-H` find, remove and hash the lines of a
  `known_hosts` file (`-f FILE`, else `~/.ssh/known_hosts`), with the lines
  and the messages of OpenSSH's `ssh-keygen` (T-019); a host on another port
  than 22 is `[HOST]:PORT`. `-R` and `-H` keep the old text in `FILE.old`,
  and put the new one in place whole, under the lock of `podssh ssh`: a run
  that waited for it meanwhile writes its line to the new file. Each line
  that is not changed stays byte for byte. Two calls differ from OpenSSH's,
  so that nothing is lost: `-R` keeps a line that names the host through a
  wildcard, as its key is for other hosts too, and says so; and a line that
  is no line of a host key stays as it is, where OpenSSH refuses to rewrite
  the file.
- `-Y sign`, `verify`, `check-novalidate`, `find-principals` and
  `match-principals` make and check SSH signatures (PROTOCOL.sshsig) as
  `ssh-keygen -Y` does, with its lines and messages (T-020); git's signing
  with SSH keys calls them. `sign` signs each FILE to `FILE.sig`, never over
  one, or standard input to standard output; the agent signs when it holds
  the key of `-f` (with `-U`, the agent alone), else the private key in
  `-f`. An RSA key signs with SHA-512 through aws-lc-rs. `verify` reads an
  allowed-signers file with its `namespaces=`, `valid-after=` and
  `valid-before=`, and a failure exits 1 where OpenSSH exits 255; `-r`, a
  revocation list, is refused.
- `-Y sign -f KEY-cert.pub` signs with a certificate, as OpenSSH's does:
  the private key is KEY (the path without `-cert.pub`, or `.pub`), or the
  agent's, and the signature carries the certificate (T-289). `-f KEY`
  signs with the plain key even when `KEY-cert.pub` is beside it, as
  OpenSSH reads `KEY.pub` there. A `cert-authority` line of the allowed
  signers allows such a signature when its key is the certificate's CA and
  the certificate is a user certificate, valid at the time (or
  `-O verify-time=`), that lists the principal of `-I` (with no wildcard);
  a refusal says OpenSSH's `FILE:N: certificate not authorized: REASON`.
  A plain line of the key does not allow it, and a `cert-authority` line
  allows no plain signature, as OpenSSH compares the types.
  `find-principals` prints the principals of the certificate that the
  line's patterns match, `check-novalidate` and `verify` name the key
  `ED25519-CERT` (or the type's), and `-O print-pubkey` prints the
  certificate. As in OpenSSH, the critical options of the certificate are
  not read: they restrict a login, not a signature.
- `-s CA -I ID` certifies each FILE, a public key, into `FILE-cert.pub`
  (PROTOCOL.certkeys), and `-L` prints a certificate, with the lines and the
  messages of `ssh-keygen` (T-021): `-n` the principals, `-V` the validity
  (`+52w`, or FROM:TO of `+TIME`, `-TIME`, `YYYYMMDD[HHMM[SS]][Z]`, `always`
  and `forever`), `-z` the serial, `-h` a host certificate, `-O` its
  options (`clear`, the `permit-` and `no-` flags, `force-command=`,
  `source-address=`, `verify-required`, `extension:` and `critical:`), `-U`
  a CA in the agent, and `-t rsa-sha2-256` the signature of an RSA CA
  (SHA-512 by default, through aws-lc-rs). As OpenSSH does, a certificate
  replaces the one that is there: it is public, and made again at each
  renewal. A failure exits 1 where OpenSSH exits 255; `-D` (PKCS#11) is
  refused.
- `-e` prints a public key in the format of `-m`: RFC4716 (the default),
  PKCS8 or PEM; `-i` reads one and prints it as a line of OpenSSH; `-m PEM`
  or `-m PKCS8` with a new key or `-p` writes the private key in that format,
  encrypted as OpenSSH encrypts it (T-022). An Ed25519 key has a form of
  RFC 4716 only: `-e` refuses the others by name, and a new key or `-p`
  keeps OpenSSH's format and says so, as `ssh-keygen` writes it. `-i`
  imports public keys only: podssh never prints a private key. `-y` and
  `-l` read a key in each format that `podssh ssh -i` reads, and ask for its
  passphrase.
- `-t ed25519-sk` and `-t ecdsa-sk` make a key in a security key (FIDO2),
  as OpenSSH's `ssh-keygen` does (T-229). The device keeps the key; the
  file holds the device's handle of it, the application and the flags, in
  the format of OpenSSH (PROTOCOL.u2f), and needs the device for each
  signature. `-O resident`, `-O verify-required` (the device's PIN at each
  use), `-O no-touch-required`, `-O application=ssh:NAME` and
  `-O user=NAME` are those of `ssh-keygen`; `-O device=PATH` names a
  device on Linux. `-O challenge=` and `-O write-attestation=` are
  refused: podssh keeps no attestation of the device. The probe comes
  first: with no device that podssh may reach, `keygen` names the reason
  and exits 1, before it asks a passphrase or writes a file. See
  "Security keys" below.
- DSA is refused, because OpenSSH 10 removed it.
- An RSA key is made by aws-lc-rs, whose RSA is constant-time, never by the
  `rsa` crate, whose private-key operations are not (RUSTSEC-2023-0071, the
  Marvin attack): 2048, 3072 (the default), 4096 or 8192 bits, the sizes
  that aws-lc-rs makes (T-257).
- The comment is `USER@HOST`, with the local user's name as `podssh ssh`
  takes it: the variables first, the user database's entry last (T-500).

### Security keys

A key of a security key (`sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com`) signs in its FIDO2 device: the key
never leaves it, and each signature needs a touch (T-229). podssh makes
such a key (`podssh keygen`), signs a login with its file (`podssh ssh -i`,
and the default files `id_ecdsa_sk` and `id_ed25519_sk`), and holds one in
`podssh agent`. Each use probes the way to the device first, and never
assumes one:

- On Linux, podssh speaks CTAP2 over the kernel's raw HID devices,
  `/dev/hidraw*`, in its own code: the framing of CTAPHID, CBOR, and the
  PIN protocol one. The probe keeps the devices whose report descriptor is
  a FIDO device's, read in sysfs, else from the device, and that this user
  may open; most systems give that access through a udev rule
  (`TAG+="uaccess"`). A device that speaks U2F only (CTAP1) is refused.
  With several devices, `keygen` asks for one (`-O device=PATH` or
  `PODSSH_SK_DEVICE`), and a signature goes to the device that holds the
  key, which each device tells at once with no touch.
- On Windows, podssh asks the WebAuthn API of the system (`webauthn.dll`,
  of Windows 10 1903 and later), loaded at run time; Windows shows its own
  dialog for the touch and the PIN, and needs no right of an
  administrator. A session with no window for that dialog is refused.
- On each other system (macOS among them) podssh has no way to the device
  and says so; a key that an agent holds (OpenSSH's `ssh-agent`, with its
  own helper) still signs through the agent.
- A device has 30 s for an operation, the touch included; then podssh
  cancels it and says that nobody touched the key. The touch is no
  question: `BatchMode` does not stop it, and forbids only the question of
  the PIN of a key made with `verify-required`. The time of the device
  does not count against `ConnectTimeout`. The server is asked first
  whether it takes the key, so a key that it does not take asks for no
  touch.
- With no device, a login skips the key before the server sees it: `-v`
  says why, and so does the message of a login that fails. A device that
  does not sign (no touch, a wrong PIN) lets the next key go on.
- `PODSSH_SK_DEVICE` names the device on Linux (a path of
  `/dev/hidraw*`); `none` turns security keys off on each system.
- The signature that podssh sends is OpenSSH's (PROTOCOL.u2f): the
  device's signature, then the flags and the counter that the device
  signed. The tests check it against signatures that OpenSSH made, the
  vectors of ssh-key 0.7.0-rc.11.

## `podssh node`, `podssh operator` and `podssh relay`

`podssh man node`, `podssh man operator` and `podssh man relay` give the
commands. The rules behind them:

- **A pair has a label.** The relay names a pair, and the name changes with
  each new pair. NAME is the user's label for the pair in the cache
  (`pair-NAME.json`, mode 0600), so a script stays the same.
  `relay pair NAME` makes and keeps one; `node NAME TARGET` serves it;
  `relay status NAME` asks whether its node is online, and `relay status
  --pair-file FILE` the same of an operator's file (T-591); `relay revoke
  NAME` stops it and forgets it. At podssh's relay role, `relay halt NAME
  [--reason TEXT]` keeps its operators out while its node keeps its
  socket, and `relay resume NAME` lets them in again (T-647).
- **A pair expires, and its node goes on (T-395).** A pair lives 72 h at
  most and the relay renews none. The node says the expiry 24 h, 6 h and
  1 h before it, with the command that makes the next pair. `relay pair
  NAME` refuses a pair with more than 24 h left, and in the last 24 h makes
  the next one, which takes the label's place in the store; the node takes
  it at the expiry, with no new start, and exits 77 when none was made. A
  node stopped on the relay deletes the stored pair only while it is its
  own.
- **A pair's part moves by a short code (T-086).** `relay pair NAME
  --code` gives the pair stored under NAME while it has 10 minutes left
  (else it makes the next one first) and the node's key, by a code of the
  mailbox's nameplate and three words of the PGP list. The code shows on
  the run's terminal alone, stderr when it is one, else the process's
  terminal; a run with none is refused (64) before a pair is made. stdout
  gets one line, `NAME: given to SHA256:...; expires ...`. `relay join
  NAME` reads the code at a prompt, or one line of a pipe, never argv; it
  pins the node's key under NAME (`known-nodes`), gives this host's key
  (`client.key`, `--client-key FILE`), and keeps the part as
  `operator-NAME.json`, which `operator`, `ssh node://`, `proxy node://`,
  `pipe`'s `node:` and `relay status NAME` read where no pair is stored
  under NAME; a whole pair under NAME refuses the join (78). `--allow FILE`
  of the giver adds the operator's key to the node's allowlist. The ends
  meet at magic-wormhole's public mailbox, then Least Authority's (Q65), or
  at those of `--pair-mailbox URLS` or `PODSSH_PAIR_MAILBOX` (`no` turns the
  pairing off, 78; the flag's `no`, 64), such as `relay serve`'s
  `wss://HOST/v1/mailbox`. A wrong code, a code that nobody holds (it
  expired, it was used) and a node's key that differs from the pin are 77;
  nobody within the code's 10 minutes and no mailbox reached are 69.
- **`relay spec` checks the relay, not a pair.** It reads the relay's
  `/health` and `/llms-full.txt`, or the file of `--document`, and checks
  the document against the facts that podssh was built with: exit 0 when
  each holds, 1 when one does not (the relay changed), 69 when the relay
  could not be read (T-060).
- **The relay's own state, with nothing but the binary (T-058).**
  `relay status` with no NAME asks each relay host for its `/health`, one
  after the other, a line for each as it answers (the code that `doctor`
  uses, in `podssh-relay`): 0 when a host answered, 69 when none did.
  `relay rank` measures each host from this host, one at a time (T-606):
  the default host and each host of its pool, or the hosts of
  `--relay-host`; `--rounds N` rounds (3) of a session to `github.com:22`
  (`--target HOST:PORT`) each, in a new random order, 250 ms apart, within
  10 minutes; the dial, TLS and the upgrade timed, the token's time left
  out, and `--count N` pings (5). The order: the share of failed probes,
  then the median time to open, then the p95, a tie within 50 ms or 10 %
  kept in the order given. The rank goes to stdout (`--json`, one object)
  and into the cache, `relay-rank.json`, private, with no token and the
  egress as a digest of the proxy's host and port or `direct`; it holds
  24 h for that egress. `--cached` prints it and `--forget` removes it,
  neither connecting. Exit 0 when a host opened, 69 when none did or with
  `PODSSH_OFFLINE`, 64 for a bad flag. While a rank holds for this
  egress, the default list takes it (T-607): the default host and the best
  three other hosts of the pool, the default host at its place in the rank;
  the times of each run's own race order the pool where none holds;
  `PODSSH_RELAY_RANK=no` or `RelayRank no` turns both off (a variable that
  is set wins over the file), and `status`'s `relay_order`, `doctor`'s
  line `rank` and `relay info` say which order a run takes. With `RelayRank auto` or
  `PODSSH_RELAY_RANK=auto` alone, never by default (Q89, T-608), a session
  of `ssh` on the default list ranks in its background when no rank holds
  for this egress: the default host and its pool, 8 hosts in a day, one at
  a time, the first after 60 s, then one each 10 s at most, none during a
  race, none past the session's end, each a session to `github.com:22` with
  `?dial=lazy` and three pings that dials no target; kept after each probe,
  source `background`, and gone on with by the next session of the day when
  the first ended before it. `status` gives `relay_rank_auto` and the
  rank's `source`, and `doctor`'s line `rank` the setting and the last
  background rank's age.
  `relay info [HOST PORT]` reads the first host's `/relays.json`: the edge
  that this host reaches, the pool in the relay's order, the limits, and
  with a target the URL that the relay chooses for it. The relay ranks the
  pool from the edge that served the request, so the line says so, names
  the edge, and points to `relay rank` (each host of the pool),
  `relay status` and `ping --relay-host HOST`, which measure from this
  host; a document that names no edge and scores no host above 0, as
  `relay serve`'s, reads "the relay gives no estimate of a round trip".
  The next line names the order that a run from this host takes, in the
  words of `doctor`'s line `rank`, with the list in that order, read from
  the cache with no connection. `--json` keeps the relay's fields and adds
  `pool_order` (`by`, `edge`, `measured_here`) (T-610, GitHub #125),
  `relay_order` (`status`'s word, or `named` for a list that the user
  named) and `relay_list` (each `host` and `port`, in that order) (T-618). `relay trace HOST PORT`
  asks the first host to dial the target and read its first line: the
  verdict, the address dialed, the times and the banner, cleaned to one
  line. The token goes in `X-Relay-Token`, never in the URL, and a cached
  token that the relay refuses is minted again once. The target is checked
  first, so no text can add a query parameter. 0 when the trace ran, 69
  when the relay would not dial the target (a blocked range, a name with
  no address), 77 when it refused the token. On the relay's VPC road a
  closed port also connects, so the verdict (`live`, or
  `silent-or-unreachable` for a target that sent nothing) is the answer,
  not the connection. The caller's address and place, which `/trace` also
  sends, are never shown. `--json` gives each answer as one object: each
  host, the relay's `/relays.json` as it came, or its view of the target.
- **`relay serve` renews its certificate with no restart (T-447).** It reads
  `--cert` and `--key` again on SIGHUP, and when either file changes (it
  looks each minute, the one way on Windows, which has no SIGHUP): the next
  handshakes take the new pair, each open session keeps its own, and a pair
  that does not load, or whose key is not its leaf's, is said on stderr
  while the old one stays. `--acme NAME` takes the certificate from an ACME
  CA instead: Let's Encrypt, or the directory of `--acme-directory URL`,
  checked against `--ca-file`. The CA validates NAME by TLS-ALPN-01 on the
  role's own listener, so NAME must resolve to the host and its port 443
  reach `--listen`; nothing else listens. The account's key and the
  certificate, with its own key, are kept in the cache (`acme/HOST-DIGEST/`:
  `account.key` and `NAME.pem`, mode 0600), so a restart serves the one kept;
  the role renews it 30 days before its end (a third of its life, for a
  shorter one), with a new key, and asks again after 5 minutes, doubling to
  6 hours, when a renewal fails, keeping the old one. A first order that
  fails stops the role with the CA's reason (69); `--acme` beside `--cert`,
  a name that is no DNS name of two labels, and `--ca-file` with files are
  usage errors (64). `scripts/interop-acme.sh` runs it against Pebble, Let's
  Encrypt's server for tests (`.github/workflows/acme-interop.yml`).
- **`relay serve` takes the cleartext road beside TLS (T-326).** Its
  listener peeks at the first byte of each connection: a record of TLS's
  handshake goes to TLS, as before; another is served with no TLS, for a
  client whose proxy cuts TLS, and only with what a session needs with a
  token of one session: `GET /health`; `POST /v1/mint?once=1`, for whom
  `--mint` names and under the same brake, a token that lives 5 minutes,
  with `"once": true`; and `/connect/HOST/PORT` with that token, which its
  upgrade spends, whatever its end. A token of 72 h, its mint, the reverse
  road, the documents and the probes get `403` there. `--cleartext no`
  serves TLS alone; another word is a usage error (64). The first line says
  which ([relay.md](relay.md), "The cleartext road").
- **A signed list of deployments (T-346).** A relay host outside the
  default's domain joins the default list from a list that `/relays.json`
  carries, signed by a key that this binary trusts ([relay.md](relay.md),
  "A signed list of deployments"): after the default host and three hosts of
  its pool, at most four hosts of the other deployments, each minting its
  own token; never in a list that the user names, nor with
  `PODSSH_RELAY_TOKEN`. The keys: those compiled in, `PODSSH_RELAY_KEYS`
  and the settings file's `RelayKeys` (`SHA256:...` or 64 hex digits, by
  commas; `none` trusts no key), and the members of the net with the role
  `relay`; a bad word is 78. `relay info` names the first host's list (the
  key, whence it is trusted, the serial, the end, each deployment) or why it
  is not used, and keeps a list that holds (`--json`: `signed_list`); `relay
  status`, `status` (`deployments`) and `doctor` (`deployments`) name each
  deployment of the list, and whether its list was signed. `relay serve
  --deployment NAME=HOST[:PORT][,...]`, repeatable, signs a list of those
  deployments in its `/relays.json` with the key of `--list-key FILE`
  (`relay-list.key` in the cache, made when it is missing), whose
  fingerprint its first line names; `--list-key` with no `--deployment`,
  two deployments of one name and a bad host are usage errors (64).
- **The net's relay members (T-617).** A member of the net with the role
  `relay` whose host the net's document names (`podssh net add NAME KEY
  --roles relay --relay-host HOST[:PORT]`) is asked for its list with no
  `--relay-host`: before the race of a session on the default list, and
  before `relay status` asks its hosts, a run asks that host's
  `/relays.json`, once a day for each member whatever it answered, 5 s for
  each and 8 s in all, with no token; the list is taken only when the
  member's key signed it, and its deployments follow the default list in
  that run. None is asked with `PODSSH_RELAY_TOKEN`, a list that you name,
  or no cache; the asks are kept as `relay-members.json`. `relay status`
  names each relay member, its host, and its list taken (its serial) or
  why not, and when it was asked; `--json` adds `members`.
- **`relay serve` offers HTTP/2 with extended CONNECT (T-321).** Its TLS
  offers `h2` before `http/1.1`; a client that chooses it gets SETTINGS that
  offer extended CONNECT (RFC 8441), 16 streams at once and windows of 1
  MiB for each and 16 MiB for the connection. A `CONNECT` with `:protocol
  websocket` is the upgrade of its path, with its token, its checks and its
  brake, answered `200`; `/health`, `/relays.json`, `/trace`,
  `/llms-full.txt` and the mint answer there too, and each other request is
  reset with `HTTP_1_1_REQUIRED`, which a client of HTTP/2 follows over
  HTTP/1.1. Its stdout says `h2` for each such connection. `--http2 no`
  offers `http/1.1` alone, as before; another word is a usage error (64).
  The first line says which ([relay.md](relay.md), "The relay role's
  HTTP/2").
- **`relay serve` counts what each key carried (T-636).** With `--mint
  keys:FILE` or `net`, each session of its forward road is charged to its
  token's key at its end, each way apart; `--quota MIB` (1 to 16777216) is
  each key's budget for a day (UTC), past which a session gets `403 forward:
  this key's quota of MIB for today is spent` before its target is dialed,
  and `--usage FILE` keeps each key's totals of today and the day before
  across a restart, a private file written each 2 s while a count moved (a
  file that does not read stops the start, 78). SIGHUP says each key's
  totals on stderr. Either flag with `--mint anyone` or `nobody`, or a quota
  that is no whole number in its bounds, is a usage error (64)
  ([relay.md](relay.md), "What each key carried, and its budget for a
  day").
- **`relay serve --mint keys:https://URL` (T-646).** The list of keys may
  be a URL's, for a role whose image has no writable volume: fetched through
  the host's proxy with the trust of `--ca-file`, before the role takes a
  connection (a fetch that fails stops the start, 78), then each
  `--list-ttl SECONDS` (300); a copy older than that and `--list-stale
  SECONDS` (3600) lets no key mint. An `http://` URL, and `--list-ttl` or
  `--list-stale` with no list of a URL, are usage errors (64); each line
  names the URL by its host alone. `node --quick-tunnel --relay --mint
  keys:https://URL` takes it too ([relay.md](relay.md), "A list of keys at
  a URL").
- **A node as a service, with no privilege (T-121).** `node NAME TARGET
  --install` probes for a way that this user may use: a user unit of
  systemd when `systemctl --user` answers, else a LaunchAgent when
  `launchctl` has the user's login session, else two lines of the crontab
  when `crontab -l` answers, and on Windows a task at the user's logon,
  made from XML by `schtasks`, as a logon trigger of a user with no
  privilege must name that user and run with its token; never a Windows
  service. With none, the command to run at login, and 69. The service runs
  the binary by its absolute path with the node's TARGET and flags, and
  `--env-file`: a service starts with none of the shell's variables, and a
  node behind a proxy reaches no relay without them, so the variables that
  the node reads go into `node-NAME.env`, a private file beside the pair.
  No token goes into it or on a command line: the pair's tokens stay in
  `pair-NAME.json`, and `PODSSH_RELAY_TOKEN` and the secrets of Cloudflare
  Access are not carried (a proxy's password is, in the private file, as a
  proxy that asks for one is not reached without it). podssh says whether
  lingering is on, and never runs `loginctl`. `--uninstall` removes the
  unit (stopped first), the LaunchAgent (booted out first), the lines of
  the crontab with their mark, or the task, and the files of variables, of
  the lock and of the log: what `--install` and its runs wrote, and nothing
  else. `podssh serve` has no command yet (T-107; the operator holds it,
  Q32); it takes the same module when it comes.
- **A service that always starts again (T-393).** A server that only the
  tunnel reaches is locked out while the tunnel is down, so each way starts
  the run again whenever it ends, with no limit of starts. The unit has
  `Restart=always`, `RestartSec=5` and `StartLimitIntervalSec=0` (in
  `[Unit]`, and `StartLimitInterval=0` in `[Service]` for a systemd older
  than 230), and `RestartPreventExitStatus=64 78`: a refused command line or
  setting stays down, as no start changes it, but 77 (an expired pair, a
  refusal of the relay) starts again, so that a pair made again with `relay
  pair NAME` is taken at the next start with no new `--install`. The
  LaunchAgent (`~/Library/LaunchAgents/dev.podssh.node.NAME.plist`) has
  `RunAtLoad`, `KeepAlive` and a `ThrottleInterval` of 5 s, and is loaded
  by `launchctl bootstrap gui/UID`, removed by `bootout`; its stderr goes
  to `node-NAME.log` beside the variables, as launchd keeps no journal.
  With no login session at the screen (a Mac reached over SSH alone) the
  crontab's way is taken, whose line at boot needs no login. The crontab
  gets a line each 5 minutes beside `@reboot`, which starts the run when it
  is not running. The Windows task also starts each 5 minutes while the
  user is logged on (a time trigger, with `IgnoreNew` for a running one),
  and a minute after a failure; after a reboot it waits for the logon, and
  its line names the task at boot that only an administrator can make.
  A new `--install` removes what an earlier one made by another way, so
  that two ways never start the same service.
- **The journal's priorities (T-640, GitHub #138).** systemd files each
  line of a unit's stderr at one priority, `info`, so `journalctl -p
  warning -u UNIT` showed nothing that the node said. Where stderr is the
  journal's own stream (`JOURNAL_STREAM` holds its device and inode, and
  they are descriptor 2's: a program that inherited the variable has
  another stderr, and a detached run's log is a file), each error line
  also goes to the journal's socket beside that stream (`socket` beside
  its `stdout`, `/run/systemd/journal/socket` by default) as one entry of
  the journal's native protocol: `PRIORITY` (3, and 2 for a fatal one),
  `SYSLOG_IDENTIFIER=podssh`, then `MESSAGE`, a message of many lines in
  the binary form, so that it stays one entry. Each line stays on stderr
  first, as before: the stream keeps the order and the unit, which the
  journal reads from the sending process and can miss when it ended at
  once. A line at `info` or below gets no copy, as the stream gives it
  that priority already, and a copy would show it twice. The lines copied
  are a refusal of each command (`Refusal`), the end of a node by a fault,
  and a retired variable ("Variables that a release stopped reading",
  below); the lines of the SSH client (`Log`), such as a tunnel's, are
  not. The socket binds nothing and does not block, and a send that fails
  is dropped, never an exit code: a unit stops for good on 64 and 78.
  This is no outbound connection (rule 2 of `AGENTS.md`) and no helper,
  as the copy reaches the service that each line of the stream reaches,
  on the host (the call of Q86). `-y` stays refused: this is not syslog,
  and no flag turns it on or off.
- **One run of a service at a time (T-393).** A run with `--env-file FILE`
  holds an exclusive lock on `FILE.lock` (`flock`, `LockFileEx`) for its
  life, with its pid in the file. A second run with the same FILE (the
  crontab's each 5 minutes, a person, a way that an earlier install left)
  ends at once with 0, and says so only on a terminal, so that cron mails
  nothing; a second node would meet the first at the relay, and a second
  tunnel would ask the server for a port that the first holds. The kernel
  lets the lock go when the run ends, however it ends, so no stale file
  keeps a service down, as a file of a pid can. A file system that takes
  no lock is said, and the run goes on without one: a service that does
  not start is worse than two.
- **A tunnel of `podssh ssh` as a service (T-393).** `podssh ssh --install
  NAME -N -R ... --persist DEST` makes the same service of a reverse
  tunnel to a standard sshd (`podssh-ssh-NAME.service`,
  `dev.podssh.ssh.NAME`, the crontab's lines, or the task
  `podssh-ssh-NAME`). It runs the words that the user typed but
  `--install NAME`, in the directory where they were typed, so that each
  flag and each relative path means what it meant, with no second list of
  ssh's flags to keep in step; after the verb come `-o BatchMode=yes`,
  `-o ForkAfterAuthentication=no`, `-o ControlPath=none` and
  `-o ExitOnForwardFailure=yes`, which win over the user's words and over
  ssh_config, as OpenSSH keeps the first value, then `--env-file` with
  `ssh-NAME.env`, and `--persist-forever` (T-391) unless the words hold it,
  so that an outage of the relay never ends the tunnel between two starts.
  The command line is resolved before anything is written,
  so that a service is never made of one that each start would refuse; a
  shell, a command, `-W`, `-f`, `-G`, `-O`, `--attach`, `--upgrade`,
  `--snippet`, no `--persist`, or no forward is refused (64). `podssh ssh
  --uninstall NAME` removes it.
- **No token in the output.** `relay pair` prints the label and the expiry.
  The operator's part, the connect token alone, goes to the new private
  file of `--operator-file`; the node's token and the stop token stay in
  the store.
- **The expiry, on each host of a pair** (T-591, GitHub #117). `relay pair`
  keeps its one line on stdout, which scripts read, and says on stderr the
  way past the expiry: in its last 24 h, `podssh relay pair NAME
  --operator-file NEW` makes the next pair, which the node takes at the
  expiry, and NEW goes to each operator. `relay status --pair-file FILE
  [NAME]` asks the relay for the pair in FILE, or for its operator's part,
  which the relay answers to the connect token, so an operator's host,
  which stores no pair, sees the node online or offline and the expiry;
  NAME is then the label shown (else FILE). In the last 24 h the expiry
  says how long is left (`expires in 5 h, at ...`), on both hosts. `--json`
  goes with `status NAME` and `--pair-file` too: one object, `schema`,
  `podssh`, `label`, `online`, `sessions`, `expires` (RFC 3339) and
  `seconds_left`. `--pair-file` with another subcommand is refused (64).
  `pair::status` takes the operator's part (`OperatorPart`), of a stored
  pair or of a file.
- **A connect token of one upgrade, on podssh's relay role** (T-226).
  `relay pair NAME --once` asks `POST /v1/pair?once=1`: the role's answer
  says `"once": true`, and its connect token takes the first operator's
  upgrade alone, then is refused, the status too, so that one session uses
  it (`crates/podssh-relay/src/pair/once.rs`), which resumes on the tokens
  of one leg that its node gives (T-615, below), and else has no resume. A
  relay that makes none (the default relay's contract has no such pair)
  gives a pair with no `once`, which is stopped, exit 69. `--once` with
  another subcommand, or with `--renew`, is refused (64).
- **A token for each leg, and a stop token that the node rotates, on
  podssh's relay role** (T-615; [reverse.md](reverse.md), "Tokens of one
  leg"). Where the node's socket heard the role's offer, each session that
  the end-to-end channel lets in above the layer gets the seed of its
  tokens of one leg in the node's verdict, and the node registers their
  digests at the role (`crates/podssh-relay/src/e2e/legs.rs`). `operator`,
  `proxy node://`, `ssh node://`, `pipe`'s `node:` side and each command
  that rides them open each leg after the first with the session's next
  token, by `podssh_relay::reverse::legs::start`
  (`crates/podssh-relay/src/reverse/legs.rs`), from `crate::layered` and the
  race of `ssh node://`'s roads; a refused token is tried once more, then
  the next, and after eight refusals in a row the pair's token. With no
  seed (a relay of the contract, a node of before, `--plain`, `--no-e2e`),
  each leg takes the pair's token as before. The node rotates its stop
  token at its first socket that heard the role's offer and each day
  after (`crates/podssh-cli/src/node_rotate.rs`): `POST /v1/rotate/<name>`
  with the digest of the next one, the store's copy rewritten, then the
  new one's first use; its lines say each rotation, and its renewal takes
  the token now. A pair of `--pair-file` keeps its stop token, and the node
  says so once. The next pair that the node goes on with at an expiry is rotated and renewed so too (T-620).
- **A renewal, on podssh's relay role** (T-592, GitHub #117). `relay pair
  --renew NAME` renews the pair stored under NAME at the relay that made
  it (`crates/podssh-cli/src/relay_renew.rs`): `POST /v1/renew/<name>` with
  the stop token, 72 h from then with the same tokens, so that each
  operator's file holds and the node goes on with no next pair; one line on
  stdout, `NAME: expires AT`, and the store keeps the new end. A relay that
  renews none (`404` or `405` at the path; the default relay's contract has
  no such request) is said so with the way of the next pair, exit 69; a
  refused stop token (403) is a pair that was stopped or ended, 77; an
  expired stored pair, 77; `--operator-file` and `--relay-host` with it,
  64. A node renews its own pair the same way at the start of its last
  24 h, then each hour until it took, and says each renewal
  (`crates/podssh-cli/src/node_expiry.rs`); where the relay renews none, it
  says the lines of T-395. An operator's file is never touched: past the
  end that it names, the operator asks its relay's status once
  (`renewed` of `crates/podssh-cli/src/pairs.rs`), takes the later end that
  podssh's role names, and refuses the part as expired (77) as before
  where the relay names none, refuses it, or is offline. `relay status`
  shows the end that the relay names, else the file's.
- **A standard sshd's session outlives a drop, through podssh's relay role**
  (T-173). `relay serve` serves `/v1/layer/HOST/PORT` beside the contract,
  and offers it in `/relays.json` as `forward.layer: true`: the role is the
  far end of the resumable layer for a target that speaks none, as a node is
  for its TARGET (`crates/podssh-relay/src/serve/layer.rs`). Each WebSocket
  is one link; the role dials the target once, after a new session's
  handshake, and keeps it while the client's link is lost, until a resume on
  a new link carries the session on or the layer's 10 minutes pass. The
  token, the upgrade and the policy are checked as on `/connect/`, with the
  same refusals; the layer's secret never crosses the role (each resume
  proves it) and the path names the target alone. The sessions hold 256 MiB
  of replay buffers at most, 4 MiB each, and one whose link is lost is kept
  10 minutes: `relay serve --resume-budget MIB` (4 to 16384, or 0 for none,
  which offers no road) and `--resume-deadline TIME` (1 minute to 72 h, a
  node's words) change them, and the first line says them
  (`crates/podssh-cli/src/relay_serve/resumes.rs`). A new session past the
  budget is refused in the layer's handshake, a `REFUSE` (busy) that says
  what holds the budget, before its client sent a byte of it. Where several
  processes serve one name, `--resume-host HOST[:PORT]` names this one in
  `/relays.json` (`forward.host`), and the client sends each link of a
  session there. `podssh proxy HOST PORT` and `podssh ssh` take the road
  where the first relay host offers it (T-173): with `PODSSH_RELAY_LAYER=yes`
  each reads that host's `/relays.json` at each run, and says each case;
  unset, each takes the offer that the host made within a day, kept in the
  cache (`crates/podssh-relay/src/forward_layer/kept.rs`), with no line
  where there is none, and reads it once, 1 s at most, for a relay that the
  user named whose offer is not kept (the default relay's comes with its
  pool's refresh), so that a silent first host costs its failover that
  second once a day; a kept offer whose host answers 404 for the layer's path
  is forgotten, with one line, and the contract's road carries the session;
  `no` takes the contract's road alone. Where the road is taken, each sends
  each link of the session to the process that the offer names, of its
  deployment, else to that host alone
  (`crates/podssh-cli/src/relay_layer.rs`), each loss and resume a line on
  stderr; OpenSSH's SIGHUP at its exit ends the whole session, so the role
  forgets it at once. The end of stdin is the layer's `END` where the role
  takes it (T-632, `crates/podssh-cli/src/relay_layer/half.rs`): the role
  half-closes its connection to the target, a target that reads to the end
  of its input still answers (`echo QUERY | podssh proxy HOST PORT`), and
  the target's end ends stdin too, so the session ends with the target, as
  before; with a role that takes no `END`, the end of stdin stops sending
  and keeps receiving until the target closes, as on the contract's road,
  as the layer's `CLOSE` would end the whole session and lose a reply on
  its way. `podssh ssh` runs the layer on a thread
  of its own beside SSH (`crates/podssh-cli/src/relay_layer/ssh.rs`), holds
  `-4` and `-6` on each link, and sends no SSH keepalive unless
  `ServerAliveInterval` is given; the copies, `run`, `each` and `job`, which
  log in as it does, take the road too, and `--no-resume` takes the
  contract's road. A host that offers none, that refused a new session for
  its budget, or whose first link fails as another host may not, takes the
  contract's road with one line; a refusal that the contract's road would
  get too ends the run with its code. `no` is the contract's road with no
  request more, and another word is refused (78). A role
  without a listener, behind a quick tunnel (`node --relay`), serves the
  same path.
- **One pair for each label.** A pair that has not expired is not replaced:
  a second pair would leave the first with no holder, for up to 72 hours.
  When a new pair cannot be stored, or its operator file cannot be written,
  it is stopped at once. A relay that cannot be reached keeps the stored
  copy at `revoke`: its stop token is the one way to stop the pair before
  it expires.
- **`relay` has no `--timeout`.** Each request has a bound: 30 s for the
  pairs, 10 s for `/health` and `/relays.json` and 30 s for a trace, and
  `status`, `info` and `trace` 120 s in all, so a script needs no
  `--timeout` (T-058's decision). `status` asks each host of
  `--relay-host`; `pair`, `info` and `trace` use the first, the control
  host.
- **Routes (T-089).** `node NAME [TARGET] ROUTE=TARGET...` offers each
  TARGET under its ROUTE, with one pair and one node: a route has the form
  of a pair's name, and a TARGET with no route is the one of an operator
  that names none. The operator names one as `NAME/ROUTE`: `podssh operator
  lab/web`, `podssh ssh node://user@lab/web`, `podssh ssh
  user@iroh:TICKET/web`. The route travels in the end-to-end channel, in
  the operator's encrypted proof of its key, so the relay never sees it,
  and `--no-e2e` offers none (64). With `--allow FILE`, a key reaches a
  route only when its line says so, after the key: `SHA256:... routes=web,db
  laptop`, or `routes=*` for each; a line with no `routes=` reaches the
  TARGET with no route alone, as before, and a list that is not one makes
  its line a bad one. The node checks the route after the key, before it
  dials: a route that it does not have, and one that the key may not use,
  are refused with the same words, so that an operator learns no route
  that it may not use. With no allowlist, each operator with the pair's
  connect token may use each route. The known hosts keep a route's host key
  under `node://NAME/ROUTE`. `pipe`'s `node:` and `iroh:` addresses name no
  route.
- **A node dials TARGET first,** once, and exits 69 when it cannot; else
  each operator would get a `reject`. With routes, each TARGET is dialled
  once. It says `online` once the relay has
  its socket, and `online again` after a loss: an operator reaches it from
  that line on, not from the first (T-271). It runs until Ctrl-C or SIGTERM
  (exit 0). Its stdout stays empty.
- **A roost is `node --sshd`** (T-166): a node in front of a standard
  sshd, TARGET, or `127.0.0.1:22` when none is given, so that a normal
  server gets the resumable layer and, with `--iroh`, the iroh road. Before
  it goes online, it dials each TARGET and reads the first line, which must
  be SSH's version line (`SSH-2.0-`, or `SSH-1.99-`; RFC 4253, section 4.2)
  within 10 s; else it exits, and names TARGET and what came back: 78 for
  another service, 69 for no line or a close. The node's first line gives
  each version line. Each session's connection to sshd, made after the
  layer's handshake, is checked the same way: a session whose TARGET no
  longer answers as sshd ends at once with the reason. The check peeks and
  takes no byte, so the client reads sshd's line itself. `ssh node://NAME`
  keeps sshd's host key under `node://NAME`, the name that the user gives,
  as OpenSSH keeps a host's behind a `ProxyCommand`; not under the address
  of sshd behind the roost, which each roost shares (`127.0.0.1`).
- **A roost's sshd runs already** (T-590, GitHub #116): podssh brings
  none. When each address of a TARGET on the loopback refuses the dial, the
  roost exits 69 and, after the dial's words, says whether this host has an
  sshd: `sshd` on `PATH`, then in `/usr/sbin`, `/usr/local/sbin` and
  `/sbin` (on Windows, `System32\OpenSSH`). One found: "an sshd is
  installed at /usr/sbin/sshd, and nothing listens at 127.0.0.1:2222: start
  it, or give the port that it listens on". None: "no sshd is installed on
  this host (...); install one, as apt-get install -y openssh-server, and
  start it", from the first package manager on `PATH` (`apk`, `apt-get`,
  `dnf`, `yum`, `zypper`, `pacman`, `brew`, `pkg`), with `sudo` first where
  the user is not root, does not own the manager's file, and has `sudo` on
  `PATH`, else `(as root)`; Homebrew never takes `sudo`. The table is
  `crates/podssh-cli/src/install_hint.rs`, for T-481's tmux too. podssh
  names the command and runs none. A TARGET off the loopback, and a dial
  that timed out, keep the dial's words alone. `doctor`'s line `sshd` says
  the same before a roost starts.
- **`node --temporary KEY` is the far end of `ssh --upgrade`** (T-167),
  which starts it in its own SSH session on the server: a roost in front of
  the sshd of `SSH_CONNECTION` (on the loopback first, then at the server's
  address), or of TARGET; a pair made on the relay of `PODSSH_RELAY`, else
  the default, and kept in no file; a key for this run only; and the client
  key KEY alone let in. Its one line on stdout, `podssh-upgrade/1` and
  JSON, goes out once the relay takes the pair's sessions. It ends with
  its last session, or 10 minutes after its start with none, and stops its
  pair. With it, `--iroh`, `--pair-file`, `--plain`, `--no-e2e`, the flags
  of the node's key and a route are usage errors (64).
- **`node --plain`** carries each session's bytes as they are, with no
  resumable layer, for an operator that does not speak it (T-263): a lost
  link ends the session, as before T-153. The node's first line names its
  mode. The iroh road always runs the layer, so `--plain` with `--iroh` is
  refused (64).
- **`node --resume-deadline TIME`** keeps a session whose link is lost for
  TIME in place of 10 minutes (T-306), on each road: `90s`, `30m`, `8h` or
  `3d`, from 1 minute to 72 h, the longest life of a pair; a bad TIME, or
  one with `--plain` or `--temporary`, is refused (64). The node names the
  time to each operator in the layer's `GREETING`, and its first line says
  it. An operator waits as long; with `--resume-deadline` of its own
  (`ssh`, `operator`), at most that. A session kept longer holds its replay
  buffers longer; the node's bound of 64 MiB holds.
- **`node NAME udp:HOST:PORT` offers a UDP service** (T-168), on a host that
  allows UDP: the relay carries TCP only, so the datagrams leave from the
  node. Each session is one flow, a UDP socket from the node's host to
  HOST:PORT, with each datagram after its length (two bytes, big-endian) in
  the session's bytes; the flow ends with its session, or after 60 s with
  no datagram either way. Before it registers, the node opens a UDP socket
  to TARGET and closes it, with nothing sent: a host that refuses UDP (a
  sandbox's EPERM) exits 78, a name with no address 69. A UDP TARGET is the
  node's only one: a second TARGET, a route of UDP and `--iroh` are usage
  errors (64). The client is `pipe`'s `udp:node:NAME`; `operator` carries
  the same framing on stdin and stdout.
- **`node NAME TARGET --quick-tunnel` serves TARGET at
  `https://NAME.trycloudflare.com`** (T-300), a quick tunnel of
  Cloudflare's that podssh makes itself: no pair, no account and no
  `cloudflared`. The name is new each run, and the one line on stdout. The
  node asks `api.trycloudflare.com` for the tunnel (through `HTTPS_PROXY`
  when it is set), then races its roads to the edge's port 7844 (T-400),
  each 2 s after the one before or at once when it failed, and keeps the
  first that the edge registers: QUIC where no proxy is set and a probe of
  UDP (one QUIC packet) got its answer within 300 ms, as cloudflared does
  (T-301); HTTP/2 on TCP, directly or through a proxy that allows it; and,
  with the feature `warp` (T-374), HTTP/2 inside WARP's tunnel with the
  device of `warp://` (above), as a cage whose proxy allows port 443 alone
  reaches the edge so. `--warp` puts WARP's tunnel first (70 without the
  feature); the node exits 69 when no road reaches the edge. The
  API's refusal for now (429, or a 5xx) is asked again for up to 5 minutes,
  after its `Retry-After` or a growing wait (T-401); a wait past them ends
  the node with 75, and its line names the wait and its end; each text of
  the API and of the edge is shown on one line, with no control character.
  It registers its connection on the first stream; its line of the
  registration names the road and its race's time; each visitor's WebSocket is
  one link of the resumable layer. The name is public, so `--allow FILE` is
  needed: only an operator whose key is in FILE reaches TARGET, through
  the end-to-end channel. It keeps two connections to the edge, each to its own region first, so that one stays while the other is made again (T-414; rule 2's exception of Q62); on the edge's GOAWAY its visitors go on for up to 90 s while a new connection takes the new ones (T-402). A lost connection is made again with
  the same name, and Ctrl-C unregisters each. `--iroh`, `--plain`,
  `--no-e2e`, `--pair-file`, a route and a UDP TARGET are refused with it
  (64). The client is `podssh ssh cf://NAME.trycloudflare.com`, or `cp`,
  `each` and the other commands of a destination on that road: it tells the
  node apart by the layer's greeting (`cf://[user@]HOST`, above). The node
  prints its key as it starts, for the client's `--node-key`.
- **`node NAME [TARGET] --quick-tunnel --relay` is its owner's relay too,
  with no listener** (T-428): behind its quick tunnel it serves the relay
  role of `relay serve` (T-169, T-427), each request of the edge a pipe in
  the process. The paths of the relay (`/health`, `/v1/mint`,
  `/connect/HOST/PORT`, `/relays.json`, `/trace`, `/llms-full.txt` and each
  path under `/v1/`) go to the role, over HTTP/2 and over QUIC, where a
  request that is no visitor's WebSocket got 404; the request goes to it as
  cloudflared sends one to an origin, and its answer back as cloudflared's.
  The line on stdout is the relay host: `--relay-host
  https://NAME.trycloudflare.com` reaches the relay as any other does. With
  no TARGET the node is the relay alone, and each path is the role's, whose
  404 answers the others. It mints, and makes pairs, for the keys of
  `--allow` by default, each by its signature of the role's challenge
  (T-448), and a signed request must name the tunnel, which stands for the
  name that a TLS asks for; `--mint keys:FILE`, `net`, `net,keys:FILE`,
  `anyone` and `nobody` are `relay serve`'s words, and `--mint net` mints
  for the members of the node's net as its policy lets them reach
  `relay:NAME`, the node's name in the net, or `relay:*` (T-455; a net that
  this host does not hold, or that ended, stops the start, 78). `--pairs
  FILE`, `--allow-private` and `--routes RANGES` (T-635) are `relay
  serve`'s too, and its keepalive is the default, an empty frame each 25 s.
  The role's events are lines on stderr, and Ctrl-C or SIGTERM
  closes each socket of its reverse road with `1012` before the tunnel
  unregisters. `--mint`, `--pairs` and `--allow-private` without `--relay`,
  `--routes` without `--relay` or `--exit`, `--routes` beside
  `--allow-private`, and `--relay` without `--quick-tunnel`, are usage
  errors (64); a list of
  `--mint keys:FILE` that cannot be read stops the start (78). The role
  dials each target from this host, as `relay serve` does: through the
  host's `HTTPS_PROXY` when one is set, by each checked address, or by the
  name with `--allow-private`; a proxy's refusal is its `502` with the
  proxy's status (T-457, [relay.md](relay.md), "The relay role's way out").
- **The exit codes follow the faults of E24**
  (`crates/podssh-cli/src/exitmap.rs`): 69 for a relay or TARGET out of
  reach, a stopped pair, or a pair that another node serves; 77 for a
  refused or expired pair, a node key that differs from its pin or from
  `--node-key`, and an operator key that the node's allowlist refuses; 78
  for no stored pair, a node that cannot connect as it is set up, or a
  roost whose TARGET is another service; 70 for
  a fault of the node that the relay closed (`1003`, `1009`), or a failure
  of the end-to-end channel; 75 for a quick tunnel's API that refuses for
  now past 5 minutes.
- **Each session runs the end-to-end channel** (T-088): Noise XX above the
  resumable layer, on both roads, in which each end proves its key
  (T-087). The node's key is `node-NAME.key` in the cache, or the file of
  `--key`; `--ephemeral-key` keeps none. The node says its fingerprint as it
  starts, and `--allow FILE` lets in only the operator keys of FILE, read
  again for each session. A client's key is `client.key`, or the file of
  `--client-key`. The operator pins the node's key at its first sight in
  `known-nodes`, and refuses a changed key with both fingerprints; `--node-key
  KEY` names the key instead, and reads and writes no pin. `--no-e2e`,
  given at both ends, carries the bytes with no channel. A conflict of these
  flags (`--key` with `--iroh-key`, `--node-key` with `--no-e2e`) is a usage
  error (64), before anything is read.
- **A grant used once** (T-226, GitHub #35; [reverse.md](reverse.md),
  "Grants used once") lets one operator's key in, once, also a key that no
  `--allow` names: an OpenSSH user certificate of that key, signed by the
  node's key or by a key of `--allow` (or a member of the net) for what it
  may reach itself, with the principal `node:SHA256:...` (and `/ROUTE`), a
  window and the critical option `once@podssh`. `podssh node NAME
  --grant-to KEY` prints one on stdout and serves nothing: the node's key
  signs it, read and never made, for KEY (`ssh-ed25519 BASE64`, 64 hex
  digits, or a file of one line), `--grant-route ROUTE` and `--grant-for
  TIME` (1 minute to 30 days, 1 h by default); `ssh-keygen -s` of OpenSSH
  makes one with an issuer's key. The operator gives it with `--grant FILE`
  on `operator`, `proxy node://`, `ssh node://` and `pipe`'s `node:` side:
  the channel carries it, encrypted, to the node whose key it checked, for
  the run's first session alone. A URL in place of FILE, or `--no-e2e`
  beside it, is a usage error (64), and a file that is no Ed25519
  certificate 78. The node checks the grant before it dials, records it in
  `grants-NAME` of the cache, synced, then lets the session in; a second
  use, another key, another node or route, a window that is not now, an
  unknown critical option and a revoked serial (`--revoked FILE`) are
  refused, and the operator exits 77, the reasons in the node's log. A node
  with no `--allow` and no net says, as it starts, that the pair's token
  alone is its door.
- **`--pair-file FILE`** uses a pair of the store's form, which must be a
  regular file of the user that nobody else can read, as ssh reads a key.
  The store is not used. For `operator` and `ssh node://NAME`, the operator's
  file of `relay pair --operator-file` will do.
- **`operator` is a byte pipe**, as `proxy` is: stdout carries the node's
  bytes and nothing else, and it exits 0 only when the node took the
  session. Its codes are those of `node`. `ssh node://NAME` runs the SSH
  client over the same leg, and keeps the codes of OpenSSH (255).
- **`proxy node://NAME[/ROUTE]` is `operator NAME[/ROUTE]`** (T-587, GitHub
  #113): one function carries both, with the pair stored under NAME or that
  of `--pair-file`, the channel's `--client-key`, `--node-key` and
  `--no-e2e`, `--resume-deadline`, `--no-resume`, and the same codes, so that a
  ProxyCommand names a node in the form that `ssh` and `cp` take: `ssh -o
  ProxyCommand='podssh proxy node://lab' user@lab`. The node's TARGET or
  route names the service, so a PORT is refused (64), as `cf://HOST` takes
  none; so are `--relay-host` and `--relay-failover`, as the pair names its
  relay, and `--forwarder`, `--shadowsocks`, `--via`, `--vless`,
  `--wstunnel`, `--exit` and `--idle-warn`, each a road in the relay's place
  or a word of its forward road. `--relay-addr` and `--ca-file` reach the
  pair's relay. A flag of a node beside another target is refused (64). A
  word that starts with `node:` and is no `node://NAME` (`node:lab`, as
  `pipe` writes a node) is refused with the three forms of a node's
  ProxyCommand: `proxy node://NAME`, `operator NAME` and `pipe - node:NAME`;
  `node:22`, one word, stays the host `node` and its port.
- **`--ConnectTimeout SECONDS` of `operator` and `proxy`** (T-589, GitHub
  #115), `ssh`'s flag, its meaning taken to a pipe: one bound, 1 to 86400 s,
  on the time from the start to the session's open, never on the bytes after
  it. For `proxy`, the relay's answer (each host's dial, TLS, the upgrade,
  the relay's dial of the target) or that of the road in its place; for
  `operator` and `node://`, the relay's answer, the node's `ready`, its first
  bytes, and the handshakes of the layer and of the channel. Each step keeps
  its own limit too, and the first limit to pass ends the wait. A watch on a
  thread of its own ends the run past the bound: one line names the step
  that waited (`no relay host answered within 25 s (--ConnectTimeout)`), and
  the exit is 69; a session that opened is never cut, as the road says its
  open first. 0 is refused (64), and so is `-o ConnectTimeout=N`, as these
  verbs take no `-o`; with none, each wait is as before.
- **`--timeout DURATION` and `PODSSH_TIMEOUT` are other names of that
  bound** (T-613, the operator's ruling Q90), on `operator`, `proxy` and
  `pipe`'s remote sides: the time to the session's open, never the bytes
  after it. They take the duration of the other commands' `--timeout`
  (`30s`, `2m`, `1h`, `500ms`), in whole seconds rounded up; the flag takes
  a day at most, as `--ConnectTimeout` does (64 past it, and for 0 or a
  typo, also beside `--ConnectTimeout`), and the variable, which bounds
  whole runs of other commands, is held to a day (78 for a bad one).
  `--ConnectTimeout` wins over `--timeout`, and either over the variable;
  the line past the bound names the one that set it (`within 25 s
  (--timeout)`). None of them is ever required, with no terminal either.
- **`--no-resume`** (T-612, the operator's ruling Q90) of `operator`,
  `proxy node://NAME`, `pipe`'s `node:`, `udp:node:` and `iroh:` sides, and
  of `ssh`, `cp`, `mv`, `scp` and `sftp` to a node: a session that ends with
  its link. The client names `once.v1` in the layer's `OPEN`; a node that
  knows the ask names it in its `GREETING`, and with both names it forgets
  the session and shuts its connection to TARGET as the link ends, whatever
  the end, so that its budget of replay buffers holds nothing of it. The
  client carries the session on its first link alone: no resume, no move
  before the relay's limits and no spare link, so a lost link, or the
  relay's limits, end the session, as on a node of `--plain`; a line says
  so, and the exit is that of the leg's end. A node of an earlier podssh
  ignores the name, as each name that it does not know, and keeps the
  session for its deadline; a line says so too, and the client still does
  not resume. `ssh` and the copies refuse the flag with a destination that
  is no node (64), and so does a `pipe` with no side of a node.
- **`node --iroh` needs no pair** (T-163, a build with the feature
  `iroh`). Its key is the node's key of each road (`--iroh-key` and
  `--iroh-ephemeral` are `--key` and `--ephemeral-key` by their earlier
  names). The node prints its key's fingerprint and its ticket on stderr. A
  client's key gets in only from the file of `--allow` (or `--iroh-allow`);
  with no such file, none does. `ssh iroh:TICKET` dials the ticket with this
  user's key (`client.key`, or `--client-key`), prints its fingerprint when
  it is new and when a node refuses it, and records the host key under
  `iroh:` and the node's key in hex. `--iroh-relay` with no `--iroh`, and
  the flags of the channel with a destination that is no podssh end, are
  usage errors (64); in a build without the feature, `--iroh` and an iroh
  destination exit 70 and name the feature.
- **`node --iroh` with a pair serves both roads** (T-164), with one keeper,
  and `ssh node://NAME --iroh-ticket TICKET` races them: the iroh road
  first, the pair's road after 250 ms or when the iroh road fails, the first
  far end that speaks wins, again at each resume. `--iroh-ticket` with
  another destination is a usage error (64).
- **`node --derp` serves the DERP road** (T-379), in each build: DERP over a
  WebSocket through `HTTPS_PROXY` to Tailscale's servers for tailcat, or to
  those of `--derp-server` or `PODSSH_DERP_SERVER`, under the resumable
  layer ([design.md](design.md), section 8). The home is the first server
  whose `/derp/probe` answers; the node's key there is derived from its
  identity, so the ticket (`derp:...`, on stderr) stays while the home does.
  After 3 failed connections in a row to its home, the node calls the next
  server of its list home that takes one, and prints the new ticket. A DERP
  server lets any key send, so `--derp` needs the end-to-end channel and a
  door for it: `--no-e2e`, `--plain` and a `udp:` TARGET are refused (64),
  and so is `--derp` with `--quick-tunnel` or `--temporary`. With a pair,
  and with `--iroh`, the node serves each road with one keeper.
- **The DERP road's door** (T-452) is `--allow`, or, where the node's key,
  as it is already kept, is a member of the net held here and in force, the
  net's members alone, as its policy lets (`podssh net`): the first line
  then ends `with no --allow, the members of the net NAME are its door`, no
  line of an allowlist follows, and the admission of each road of the node
  takes the members alone, so that a node that leaves its net, or whose
  document goes, lets nobody in rather than each key
  (`crates/podssh-cli/src/net/admit.rs`, `members_only`). A node with
  neither is refused before its key is made (64), with the net's reason: no
  key made, `PODSSH_NET=no`, no net held, a net that does not name the key,
  or one that ended.
- **A node with no pair serves the DERP road unasked** (the operator's
  ruling Q50, [decisions.md](decisions.md)): with no pair stored under NAME
  (or an expired one), a door (an allowlist, or a net that names its key),
  and no `--iroh`, `--plain` or `--pair-file`, its first line says so.
  `PODSSH_DERP=no` turns that off, and the node refuses as before (78).
- **`ssh derp:TICKET`** dials the node of the ticket: its server first,
  then the rest of the list (`--derp-server`, else `PODSSH_DERP_SERVER`,
  else the fleet) when the list holds that server. This client's key on
  the servers is new for each run; the node lets in the key that the
  end-to-end channel proves (`client.key`, or `--client-key`), so
  `--no-e2e` is refused (64). The host key is recorded under `derp:` and
  the node's key in hex.
- **`ssh node://NAME --derp-ticket TICKET`** races the DERP road third:
  after the iroh road of `--iroh-ticket` and the pair's road, 250 ms after
  the one before it, or at once when the roads before it failed. The two
  tickets must name one node (64). The ticket is kept under NAME
  (`derp-NAME.ticket` in the cache), and a later `ssh node://NAME` that
  gives none dials it only once the roads before it failed, or alone when
  no pair is stored: the fallback of Q50, which `PODSSH_DERP=no` turns off.
  `--derp-ticket` with another destination, and `--derp-server` with a
  destination that is no node, are usage errors (64).
- **`node --opentunnel` serves the OpenTunnel road** (T-531, drafted
  2026-11-03), in each build: a blind TLS tunnel of `opentunnel.xyz` with
  no account, or of the service of `PODSSH_OPENTUNNEL`
  ([carriers.md](carriers.md), the reverse road, item 6). The node makes one
  tunnel and keeps it, its token and its key in a private file of the cache
  (`opentunnel-HOST-NAME.json`) before the service orders its certificate,
  so that each start keeps its name and binds no new CSR; its key and its
  CSR are made as the ACME client makes them. Its name, `ROUTE.ID.DOMAIN`,
  a route of 26 random letters under the tunnel, is its line `name`, with
  the command of a client; its bridge is a WebSocket through `HTTPS_PROXY`,
  again after each loss, and TLS ends at the node. Anyone may connect to a
  tunnel's name, so the road needs the end-to-end channel and a door, as
  the DERP road does: `--allow`, or the net's members; `--plain`,
  `--no-e2e`, `--exit`, a `udp:` TARGET, `--derp` and `--iroh` beside it are
  refused (64), and with no door it is refused before any tunnel is made.
  With a pair, the node serves the pair's road beside it with one keeper.
- **A node with no other road serves it unasked** (the operator's ruling
  Q76, [decisions.md](decisions.md)): no pair stored under NAME (or an
  expired one), a door, and the DERP road turned off (`PODSSH_DERP=no`); its
  first line says so. `PODSSH_OPENTUNNEL=no` turns the road off; another
  word there is 78. A node whose DERP servers do not answer names
  `--opentunnel` in its refusal (69).
- **`ssh node://NAME --opentunnel-name HOST`** races the OpenTunnel road
  250 ms after the DERP road: TCP to HOST on port 443 through `HTTPS_PROXY`,
  then TLS by HOST, checked with the host's trust for a name of
  `opentunnel.xyz` and with `--ca-file`'s for another service's, with no
  WebSocket upgrade. The name is kept under NAME (`opentunnel-NAME.name` in
  the cache), and a later run that gives none dials it only once each road
  before it failed (Q76). The node's key is the pins' of NAME, or
  `--node-key`; `--no-e2e` with the flag is 64, and the flag with another
  destination too.
- **A carrier: the node's road on a stream that exists already (T-595).**
  For a host whose every road out is closed but that grants one channel,
  as the exec channel of a platform's own SSH: `node NAME TARGET --carrier
  ADDR` and `operator --carrier ADDR NAME`, ADDR in `pipe`'s words, `stdio`
  (or `-`), `fd:N` (Unix) or `exec:CMD`, a program that the end which names
  it starts, with no shell. The stream carries the node's socket of the
  reverse road, its WebSocket frames with no HTTP before them: the node
  runs its own `reverse::serve` on it, and the operator's end serves the
  relay role's side of that socket in its own process, for this one node
  (`crates/podssh-relay/src/serve/reverse/carrier.rs`), each operator's leg
  a pipe to it, so that the layer, the end-to-end channel and the routes are
  the pair's road's. No relay, no pair and no token: the stream is the door,
  NAME a label alone, under which the operator pins the node's key. The
  node dials TARGET, then sends one Ping, its first frame, and the
  operator opens no session before it (60 s at most), as the role ends a
  session that the node does not answer within 15 s. One stream for the
  node's life: it exits 0 after the operator's Close, 69 for a stream that
  failed. A stream of `exec:` that the operator started is started again,
  once for each wait, for the next leg, and the node that it starts knows no
  session of the one before; `stdio` and `fd:N` have one life (410). The
  relay's limits (64 MiB a session, a pair's 72 h) do not hold. `--carrier
  stdio` on a terminal (64), `operator --carrier stdio` (its stdio is the
  session's), a relay's or a pair's flag, `--iroh`, `--derp`,
  `--quick-tunnel`, `--install` and `--detach` with it are usage errors
  (64); `--exit` goes with it (T-596, "The exit of the net", below).
  `ssh --carrier ADDR node://NAME`, and `cp`, `mv`, `scp` and
  `sftp` with it to `node://NAME`, take the same road
  (`crates/podssh-cli/src/ssh/carried.rs`): the command serves the role's
  side, each of its connections a leg of the one stream, which ends with the
  command (the node's Close, then the program of `exec:`); the session runs
  as on the pair's road (`run_on` of `crates/podssh-cli/src/ssh/node.rs`),
  and no other road races it. `stdio`, `--pair-file`, a relay's flag,
  `--direct`, `--iroh-ticket`, `--derp-ticket`, `--derp-server`, a server's
  road and `--upgrade` with it, and `--carrier` with a destination that is
  no node and no `--exit`, are usage errors (64); `--exit NAME` takes the
  stream as its exit's one road (T-614, "The exit of the net", below).
  `proxy --carrier ADDR node://NAME` is the pipe of `operator --carrier`,
  with its checks and codes (`run_as` of `crates/podssh-cli/src/operator.rs`), and
  `--ConnectTimeout` bounds the open of both on a carrier: the node's read
  of the stream, its ready, then the layer and the channel. `pipe`'s
  `node:` and `udp:node:` sides take `--carrier` too
  (`crates/podssh-cli/src/pipe/node.rs`): each node side, and each client of
  a listening side, a leg of the one stream, which ends with the pipe; the
  other side keeps its road and its flags; `stdio`, `--pair-file` and a pipe
  with no node side are usage errors (64). The exit's clients over a carrier
  are `podssh exit NAME --listen ADDR:PORT --carrier ADDR` (T-596), whose
  `stdio` is its own to give, and `ssh`, `proxy` and `pipe` with `--exit
  NAME --carrier ADDR` (T-614).
- **A link can drop.** The relay's side ends a socket of the reverse road
  at random, with no Close (T-255). `operator` and `ssh node://NAME` then
  say that the link ended with no Close, or that the node's link ended
  (`1011 node disconnected`), or that the relay is restarting (`1012`,
  which `podssh relay serve` sends before a planned stop), and that a new
  session may work: the node connects again by itself, at once the first
  time, with a line that says how its socket ended. `operator` exits 69. A
  session of the resumable layer resumes on a new leg in each case.

## `podssh net`

`podssh net` (T-429, milestone M10, [mesh.md](mesh.md)) keeps a net of the
user's own nodes, as a tailnet does with no server to trust: one document
that the owner's key signs, and that each end keeps.

- **The document** is one JSON object: `podssh-net` (its form, 1), `name`,
  `serial`, `issued` and `expires` (seconds since 1970), `owner` (the
  owner's OpenSSH public key, `TYPE BASE64`), `members` (each with `name`,
  `key`, `roles` and `tickets`) and `requires`. A member's name has letters,
  digits, `-` and `_`, 63 at most, and no dot; its key is the Ed25519 key
  that a node says as it starts, as 64 hex digits, iroh's base32 or its
  fingerprint `SHA256:...`; its roles are `node`, `exit`, `relay` and
  `share`; its tickets are `iroh` and `derp`, checked to name its key. A
  field that this podssh does not know stays as it is when the owner signs a
  change; a document whose `requires` names a part that it does not read is
  refused (the policy below takes its own part, `policy`).
- **The signature** is OpenSSH's SSHSIG over the document's bytes, in the
  namespace `podssh-net`, with SHA-512: `ssh-keygen -Y verify -f ALLOWED -I
  owner -n podssh-net -s FILE.sig < FILE` checks it, and a document that
  `ssh-keygen -Y sign -n podssh-net` signed is taken. The key that signed
  must be the document's owner. podssh writes the document on one line with
  its keys in order, then the armoured signature, in one file (`net.doc` of
  the cache, or the file of `PODSSH_NET`), replaced whole.
- **The owner's subcommands** each sign a document with a serial one higher
  and a new end (`--days N`, 365 by default, at most 3650): `init NAME`,
  with `--owner-key FILE` or `~/.ssh/id_ed25519`; `add NAME KEY` with
  `--roles`, `--iroh-ticket` and `--derp-ticket`, which also replaces a
  member; `rm NAME`; `renew`. A change finds the owner's key in
  `--owner-key`, else in the agent, else in `~/.ssh/id_*` by its public
  half; a passphrase is asked once.
- **A relay member's host** (T-617): `add NAME KEY --roles relay
  --relay-host HOST[:PORT]` writes the member's field `relay`, one host as
  `--relay-host` takes it (64 without the role `relay`, or with two hosts);
  each end that holds the net asks it for the role's signed list, with no
  `--relay-host` of its own (see "The net's relay members" under `podssh
  relay`).
- **Each end's subcommands**: `ls` (a line for each member on stdout:
  name, roles, fingerprint, kinds of tickets, apart by tabs; the net in one
  line on stderr), `show` (the document's bytes as signed; `--signature`,
  the armour), `take FILE` (a signed file, or `FILE` with `FILE.sig`).
- **A new device by a short code** (T-616): `invite NAME` on the owner's
  host, with `--roles` (`node` by default), `--owner-key`, `--days` and
  `--pair-mailbox`; `join` on the device, with `--owner KEY`, `--key FILE`
  and `--pair-mailbox`. They run the exchange of `podssh relay pair
  --code` ("Pairing by a short code" in [reverse.md](reverse.md), T-086)
  with words of their own, which its version phase tells apart: a code of
  the other command is refused with the name of the command that takes it.
  The code shows on the owner's run's terminal alone, beside the owner's
  fingerprint (64 with no terminal, before the owner's key is asked or
  anything signed); the owner's key is found, and a passphrase asked,
  before the code is made.
  The offer is the net's name, the owner's public key, NAME and its roles;
  the device's answer is its key, or why it refuses; the owner's host reads
  its document again, adds NAME with the key, signs and keeps the next
  serial as `add` does, then gives the signed document in parts of 6 KiB at
  most, as a mailbox bounds each message. The device takes the code at a
  prompt, or one line of a pipe, never argv, and checks the owner before it
  keeps anything: the owner of `--owner`, else of the net that it holds,
  else the person's `yes` at the terminal of stdin, with the fingerprint
  that the device made from the owner's key; with a pipe and neither, 64
  before the code is read. A refusal of the device is said to the owner's
  host, which signs nothing. Then its key (`--key FILE`, else
  `node-NAME.key` of the cache, made when missing), and the document,
  checked against the offer and the key, taken by the rule of `take`. A
  NAME that is a member already goes to its own key alone, with the
  document held (the way back after a lost last word), another key is
  refused, and `--roles` with it is 64. Each end writes one line on stdout.
  A wrong code, a code that nobody holds, and a refusal at either end are
  77; no mailbox reached, or nobody within 10 minutes, 69.
- **The rule of a new document**: the owner's signature, an end still to
  come, and, when a document is held, the same owner and a higher serial;
  the same document again is no change (0). The first document is the one
  that the user takes, and `--owner KEY` checks its owner. Each refusal
  exits 65 with its reason; a host with no net, 78.
- **Two ends of the net** that meet on any road give each other the newer
  document inside the end-to-end channel, only to a key that is a member of
  it: the operator's before the node's verdict, so that it holds for that
  session, the node's after it. A node says each document that it takes.
- **A node whose key is a member** lets in each member of the document
  held, read again for each session, beside the keys of `--allow`; with no
  `--allow`, only the members. A member removed by a newer document is
  refused at its next session. A document that ended, or one that fails its
  check, lets nobody in by the net. A node of no net keeps its door as
  before. The node's first lines say its net. A node of the DERP road needs
  no `--allow` when its key is a member (T-452): the members are then its
  whole door, on each of its roads.
- **The policy** (T-430), as Tailscale's ACLs: who may reach which node,
  route, exit and range. With none, each member reaches each other; once
  the document has one, only what a rule allows. It is the field `policy`:
  `rules`, each `from` (a list of `*`, a member's name or `tag:TAG`), `to`
  (a list of `*`; `NODE`, its TARGET with no route and each route;
  `NODE/ROUTE`, one route, as `node://NODE/ROUTE` reaches it, and so a
  share of T-433; `tag:TAG`, each member of the tag as `NODE`; `exit:NODE`
  and `exit:*`, the egress of T-431; `relay:NODE` and `relay:*`, the
  tokens and pairs of a relay role that mints for the net, the one behind
  NODE's quick tunnel or each one, `relay serve`'s too, which has no name in
  the net (T-455), and no door of NODE; `ADDR/BITS` or one address, the
  routes of T-432) and an optional `note`; and `tags`, each a list of
  members' names. A rule only allows; a word or a field of a rule that
  this podssh does not read allows nothing, so a later podssh's rule never
  lets in more here, and a later part that narrows a rule must be named in
  `requires`. The owner's `policy set FILE` checks the file strictly (each
  field, each form, each tag; a name that no member has is said, not
  refused), signs it in with `policy` in `requires`, so that a podssh of
  before refuses the document and keeps the one before; `policy clear`
  removes it; `policy show` gives it back as a file that `set` takes.
- **The policy at a node**: the node that is reached checks it for each
  session, with the newest document that it holds, against the route that
  the operator named in the channel (none: its TARGET with no route),
  before it dials; the iroh road's door, before the channel, lets in a
  member that a rule lets reach anything of the node. A refusal is the
  channel's (77 at the operator, 255 at `podssh ssh`), and the node's line
  gives the policy's words: `no rule of the net home's policy (serial 6)
  lets phone reach lab/db`. The keys of `--allow` come in as before: the
  policy rules the net's door, not the node's own list.
- **`policy check FROM TO`** says what the policy lets, with no connection:
  FROM a member's name, key or fingerprint; TO `NODE`, `NODE/ROUTE`,
  `exit:NODE`, `relay:NODE`, `relay:*` (a relay role that is no member) or
  an address. One line on stdout, `allowed` or `refused`, a tab, then the
  rule that lets it or the reason; 0 or 77.
- **A member's name** is a destination: `podssh ssh node://NAME`, and
  `podssh ssh NAME` alone when NAME is a member with the role `node`. The
  net names the member's key, which the channel checks in place of the pins
  of `known-nodes`, and its tickets, which race beside the pair kept under
  NAME when the command line names none: the iroh ticket first, as
  `--iroh-ticket`; the DERP ticket after the roads before it failed, as a
  ticket kept under NAME. A `Host` block that sets `HostName` for a
  member's name is refused, as for `node://NAME`. So is `[user@]NAME:path`
  of `cp`, `mv`, `scp` and `edit`, and `[user@]NAME` of `sftp` (T-453), each
  read by `ssh`'s resolution; a copy races the same roads as `ssh` (T-551),
  the net's tickets among them.
- `PODSSH_NET=no` turns the net off: no name, no door, no document of the
  channel. Exit codes: 64 for the command line, 65 for a document or a
  policy refused, 66 for a file of `take` or `policy set` that is not there,
  69 for a mailbox of `invite` or `join` out of reach, 73 for a document
  that could not be kept, 77 for `policy check` refused and for a code or a
  join refused, 78 for a host with no net, an owner's key that is not
  found, `PODSSH_PAIR_MAILBOX=no`, or a bad `PODSSH_NET`.

## The exit of the net

`podssh node NAME [TARGET] --exit` (T-431, milestone M10,
[mesh.md](mesh.md), section 5) lends the node's egress to the members of
its net, as a Tailscale exit node does: an operator names a target of its
own, and the forward road starts at the node.

- **The node.** It needs a net that it is a member of, whose owner gave it
  the role `exit` (`podssh net add NAME KEY --roles node,exit`); else it
  does not start (78), and a newer document that takes the role away lets
  nobody out at the next session. TARGET is optional: with none, the node
  is an exit alone. `--routes RANGES` (`ADDR/BITS` or one address, apart by
  commas) names the private ranges that it dials too. `--no-e2e`,
  `--quick-tunnel`, `--temporary` and a `udp:` TARGET are refused with it
  (64), as the target travels in the end-to-end channel; `--routes` with no
  `--exit` is refused too. `--install` keeps both flags.
- **Who.** A member that the net's policy (T-430) lets reach `exit:NODE`,
  `exit:*` or `*`, for a public address; for an address of a range, a rule
  that reaches that address (`ADDR/BITS`). With no policy, each member. A key
  of `--allow`, or an operator of the pair's connect token alone, never
  reaches the exit, whatever it reaches of the node.
- **Which address.** The node resolves the name with podssh's resolver,
  checks each address, and dials those addresses alone, through
  `HTTPS_PROXY` when it is set, with the address in place of the name: a
  name that resolves anew elsewhere reaches nothing that was not checked. A
  public address is one that the relay role dials (`crates/podssh-relay/src/serve/policy.rs`):
  private, loopback, link-local, CGNAT, unique-local, multicast,
  documentation and NAT64 addresses are not; such an address needs a range
  of `--routes`. A name with one address that fails is refused whole. No
  port is refused: the members are the owner's.
- **The node's own host** (T-432). A loopback address (with the
  unspecified one, which reaches the host too), or an address of the
  node's own host, is dialled only when a range of `--routes` names it
  alone (`127.0.0.1`, `ADDR/32`, `ADDR/128`): `10.0.0.0/8` or `::/0` does
  not hand the node's own services to the net by accident. The host's
  addresses are read at each dial from its list of interfaces (`getifaddrs`
  on Unix, `crates/podssh-cli/src/node_exit_own.rs`), before any dial, so
  the refusal is the same whether the port is open; a connection whose two
  ends have one address is the host's own too, and is closed unread, which
  catches what the list missed (Windows, an address added since). Through
  `HTTPS_PROXY` the proxy dials, and that second check does not apply.
- **The net's routes** (T-432). The owner lists an exit's ranges in the
  net's document: `podssh net add gw KEY --roles node,exit --routes
  10.1.0.0/16,fd00:1::/32`, each a range as `--routes` reads it, and only
  with the role `exit` (64); a member's object then has `"routes"`, and one
  with none is written as before. A podssh that reads a word as no range
  keeps it and leaves it unused. The node's `--routes` stays what it
  dials; at its start it says when the document lists other routes for it,
  as `--exit auto` sends a session there by the document's.
- **`--exit auto`** (T-432), in place of NAME, on `ssh`, `cp`, `scp`,
  `sftp`, `proxy`, `pipe`, `exit --listen` and `doctor`: the exit is the
  member with the role `exit` whose route holds the target's address, the
  narrowest route first, then the first member by name, so each end of the
  net picks the same one (`crates/podssh-cli/src/exit/auto.rs`). A line
  says which (`-v` for `ssh`): `--exit auto: 10.1.2.3 is in 10.1.0.0/16, a
  route of the exit lab`, with the other exits whose routes hold it.
  `ssh` picks once the first hop is known, after `HostName`; `exit
  --listen` picks for each connection. The target must be an address: a
  name is refused (64), as the exit resolves a name itself and a private
  name (split DNS) may resolve there otherwise; an address that no route
  holds is refused (78), and so are `--pair-file` and `--carrier` beside it
  (64), as each names one exit. `auto` is no member's name: `net add auto`
  is refused (64).
- **The words of a refusal** go to the operator in the channel, and on the
  node's lines: `github.com:22 resolves to 10.0.0.1, which is not a public
  address, and no range of the exit's --routes holds it`, or the policy's
  `no rule of the net home's policy (serial 6) lets b reach exit:gw`.
- **`--exit NAME`** of `podssh ssh`, `cp`, `scp` and `sftp`: the road to the
  first hop (the destination, or the first host of `-J`, with its
  `HostName` and port) starts at the exit NAME, a member of the net and the
  label of its pair here. `ssh` races the node's roads as for `node://NAME`
  and resumes on any; the copies take the pair's road. The host key is the
  host's, under its own name. It goes with no `node://`, `iroh:`, `derp:`,
  `cf://`, `iap://` or `eice://` destination, no `--direct`, `-4`, `-6` or
  `--no-e2e`, and no road of another server (64).
- **`podssh proxy --exit NAME HOST PORT`** carries the pipe from the exit,
  with no relay host and no other server's road (64); stdout gets no byte
  before the node reached the target. **`podssh pipe --exit NAME`** starts
  each `relay:HOST:PORT`, and each `relay:%h:%p` of `http-listen:`, at the
  exit; with no `relay:` address it is refused (64).
- **`podssh exit NAME --listen ADDR:PORT`**: a local proxy, one port for
  SOCKS5, SOCKS4a and HTTP CONNECT, told apart by the first byte; each
  connection is one session to the exit over its pair's road, and a client
  hears its success only once the node reached its target, else the
  refusal of its protocol (SOCKS 2 or HTTP 403 for a refusal; SOCKS 5 or
  HTTP 502 for a target out of reach; SOCKS 1 or HTTP 502 for a road that
  failed). The listener is one that the user asks for (Q1): on a loopback
  address alone, as its SOCKS takes no credentials; `PODSSH_LISTEN=no`
  refuses it (78), a refused bind is 77. 32 connections at once; `-q`
  drops the line of each. It runs until Ctrl-C or SIGTERM (0). `curl
  --proxy socks5h://127.0.0.1:1080 URL` sends the name, which the exit
  resolves.
- **The exit over a carrier** (T-596, GitHub #124). `podssh node NAME
  --exit --carrier ADDR` lends its egress on T-595's road, a stream that
  exists already, and `podssh exit NAME --listen ADDR:PORT --carrier ADDR`
  is its client at the stream's other end, with no relay and no pair: so a
  host whose one channel is the exec channel of a platform's own SSH gets
  egress through that channel's other end. The issue's case, at the end
  with egress: `podssh node gw --exit --carrier 'exec:ssh -T sandbox podssh
  exit gw --listen 127.0.0.1:1080 --carrier stdio'`, then
  `HTTPS_PROXY=http://127.0.0.1:1080` in the sandbox. The net's rule of the
  exit holds as on each road: a member's key, and a rule to `exit:NAME` or
  a range; the stream is no door to the egress. `exit --carrier` takes
  `stdio` (or `-`), as nothing else of it reads stdin or writes stdout,
  `fd:N` and `exec:CMD`; it starts the stream with the proxy
  (`crates/podssh-cli/src/exit/listen.rs`), as the node drops a stream that
  answers nothing for 30 s, and each connection is a leg of the one stream
  (`crates/podssh-cli/src/exit/open.rs`). A stream of `stdio` or `fd:N` has
  one life: when its node leaves, the proxy says so and ends (0); one of
  `exec:` is started again for the next connection. Ctrl-C closes the
  stream with 1000, which ends the node (0). `--pair-file`, `--relay-addr`
  and `--ca-file` with it, and `stdio` on a terminal, are usage errors
  (64).
- **`--exit NAME --carrier ADDR` of `ssh`, `proxy` and `pipe`** (T-614,
  the operator's ruling Q90). Each takes the exit over a carrier itself, as
  `exit --listen` does: the command starts the stream (`exec:CMD`) or was
  given it (`fd:N`), serves the relay role's side of it, and each of its
  sessions is a leg of that one stream whose channel's word is the target,
  so that the node at the other end dials it from its own host by the net's
  rule; at the end the node hears the Close, and the program of `exec:`
  ends. `stdio` is refused (64), as each one's stdin and stdout are its
  session's or its pipe's; so the closed host of GitHub #124, whose end with
  egress starts the channel, keeps `exit --listen --carrier stdio`, and the
  three serve a host that starts the channel itself, as `podssh ssh --exit
  gw --carrier 'exec:ssh -T gateway podssh node gw --exit --carrier stdio'
  user@host.example`. `ssh` resolves the exit to the node's transport with
  the carrier as its one road (`crates/podssh-cli/src/ssh/exit_road.rs`):
  no other road races it, a flag of another road is refused in the
  carrier's words (64), and the host key is the host's; `cp`, `scp` and
  `sftp` take it too, as they share the resolver. `proxy --exit NAME
  --carrier ADDR HOST PORT` gives the stream to the exit's session
  (`crates/podssh-cli/src/exit/open.rs`), with no `--relay-addr` or
  `--ca-file` (64). `pipe --exit NAME --carrier ADDR` starts each `relay:`
  side, and each `relay:%h:%p` of `http-listen:`, at the node of the
  stream; a `node:` side beside it is refused (64), as one node is at the
  other end of a stream.

## `podssh pipe`

`podssh man pipe` gives the command (T-174). The rules behind it:

- **No listener unless one side asks for one.** `podssh pipe A B` joins
  two byte streams that exist already: stdin and stdout (`-` or `stdio`), a
  descriptor that the caller opened (`fd:N`, 3 or more, on Unix), a program
  (`exec:CMD`), or a road (T-175): `relay:HOST:PORT`, `tcp:HOST:PORT`,
  `ssh:[USER@]HOP[,HOP...],HOST:PORT`, `node:NAME`, `udp:node:NAME` (T-168)
  and `iroh:TICKET`; or a local socket (T-176), `unix-connect:PATH`; or a
  serial line (T-181), `serial:PATH[,BAUD]`; or, on one side at most, a
  listener (T-177): `unix-listen:PATH` or `tcp-listen:[ADDR:]PORT`, an
  HTTP CONNECT proxy (T-367), `http-listen:`, or a WebSocket server
  (T-368), `ws-listen:`; or a WebSocket by its URL (T-368), `ws://` or
  `wss://`. Both addresses are checked before anything starts; an unknown
  kind is a usage error (64) that lists the kinds.
- **A listener only when asked, and only where a probe allows it** (the
  operator's ruling of 2026-10-08). `PODSSH_LISTEN=no` turns listening off:
  a listening address then exits 78 before any bind. The bind itself is
  the probe: a host that refuses it gives 77, and the line names the error
  and the addresses that need no listener; another failure gives 69.
  `unix-listen:PATH` takes the names of `unix-connect:`; a socket's file is
  made mode 0600 (umask 0177, as ssh-agent makes its socket), and a client
  of another user is closed before a byte passes (`SO_PEERCRED`, or on
  Windows the user of the client's process token), which also guards
  `@NAME`, which has no file. `tcp-listen:PORT` listens on 127.0.0.1 and
  `tcp-listen:ADDR:PORT` on an IP address of this host (`[::1]`, or
  `localhost`); a TCP port takes each user of this host, and other hosts
  too when ADDR is not loopback, and podssh says which; port 0 asks the
  system for a free port, and the line names it. The first client is
  joined to a new instance of the other side, which opens only then; the
  listener closes, and its file goes, as soon as the client connects, and
  the pipe ends with that session's status. `--keep-listening` takes each
  client in turn, 8 at once, each with its own instance of the other side
  (a new relay session, a new program), until SIGINT or SIGTERM. A signal
  removes the socket's file, and podssh exits with 128 and its number. A
  path that is a file and not a socket is kept (64); a socket that answers
  is another program's (69); one that nobody serves is replaced. A named
  pipe has no half-close: its listening side closes it at the end of its
  input, and the client reads the rest, then its end.
- **An HTTP CONNECT proxy, for a program that knows only `HTTPS_PROXY`**
  (T-367, GitHub #75). `http-listen:[ADDR:]PORT` listens as `tcp-listen:`
  does, and `http-listen:PATH` (a path with a `/`, or `@NAME`) as
  `unix-listen:` does, by the same rules and the same probe. Its other side
  names its target `%h:%p`, once and last (or none, as the next item says),
  as `ProxyCommand` names the host and the port: `relay:%h:%p`, `tcp:%h:%p` or
  `ssh:[USER@]HOP[,HOP...],%h:%p`; another side exits 64, and so does
  `%h:%p` beside a side that is not a proxy. A proxy takes each client, 32
  at once (a program opens a connection for each host, npm up to 15 at a
  time), and each request opens a road of its own, until SIGINT or SIGTERM;
  its first line names the value of `HTTPS_PROXY`. A request's head is read
  within 16 KiB and 30 s (431 and 408 past them), by the reader of requests
  of podssh-ws (`http::request`), which refuses a head that two readers
  could read two ways (400): a bare CR, a space before a header's colon, a
  folded line. Then, in this order: the credentials, when
  `--proxy-auth-file FILE` names some (407 with `Proxy-Authenticate:
  Basic`); the method, CONNECT alone (405 with `Allow: CONNECT`; a request
  in absolute form, `GET http://...`, too); and the target, `HOST:PORT` or
  `[IPV6]:PORT`, checked as each target is (400). Nothing is dialed for a
  request that is refused. Then the road opens with the target, and only
  then does the client hear `200 Connection Established`, so that it learns
  whether the target was reached, as `-D` answers: a refusal of a policy is
  403 with its words (the relay's `not in the ALLOW list`, an upstream
  proxy's 403, an SSH server's administratively prohibited), a dial past
  its limit 504, and another failure 502 with its reason, in the status line
  and in the body. The bytes that a client sends after its CONNECT go to
  the road once it is open. `--proxy-auth-file` names a private file (read
  as a pair's file is: this user's, which nobody else can read; else 78) of
  lines `USER:PASSWORD`, `#` for a comment; a client gives one in
  `Proxy-Authorization: Basic`, and podssh keeps only the SHA-256 of each,
  compared in constant time. A port on an address that is not loopback
  needs the file (64): scanners find an open proxy, and each request would
  spend this host's road. With `ssh:`, each request logs in anew; `podssh
  ssh -D` keeps one connection for many SOCKS clients.
- **A proxy's other side with no target** (T-483, GitHub #93). A side with
  no `%h` and no `%p` is read with its target: `ssh:HOP[,HOP...]` takes
  `,%h:%p` at its end, and `relay` and `tcp`, with a colon or none, take
  `:%h:%p`; one line says the reading before the proxy listens
  (`http-listen: ssh:me@bastion is read as ssh:me@bastion,%h:%p: each
  CONNECT's target is reached from the last hop`). Each word of `ssh:` is a
  hop, as a proxy has no fixed target: `ssh:me@bastion,db:5432` logs in to
  `db:5432` from `bastion`, which the line shows, and a hop that is no SSH
  server fails at its login. A side of another kind (`exec:`, `stdio`,
  `node:`, a socket, a listener) exits 64 with why first: each CONNECT
  names its own target, which that side does not take. `pipe --help` shows
  the proxy of an SSH server on a port with curl as its client: curl
  reaches a proxy over TCP, as its `--unix-socket` makes `--proxy` of no
  effect, so `http-listen:PATH` needs a client that speaks to a proxy at a
  socket.
- **A WebSocket by its URL, with no token** (T-368, GitHub #76).
  `wss://HOST[:PORT]/PATH` and `ws://HOST[:PORT]/PATH`, the URL as a user
  copies it for websocat (the form `wss:HOST:PORT/PATH` is refused with the
  URL's, 64): TLS checked for HOST with podssh's trust and `--ca-file`, or
  plain TCP, through `HTTPS_PROXY` as each road. The dial of podssh-ws
  (`podssh_ws::url`) sends no `X-Relay-Token`, no `Origin`, no subprotocol
  and no extension; the path and its query are the user's, sent as written
  but for a byte that is not ASCII (percent-encoded), and CR, LF, a space
  and a control character are refused (64), as is a user or a password in
  the URL, as a credential does not go in a URL. `ws:` is in the clear, as
  `tcp:` is: the rule of `plain-ws` is for the relay's token, which never
  goes on this road. podssh's lines show the URL without its query. Bytes
  go out in binary frames of 32 KiB at most; text and binary frames come
  in as bytes. At the end of this side's input podssh sends a Close 1000,
  and what the other end sends before its own Close still comes (RFC 6455
  section 5.5.1); the other end's Close is answered at once and ends the
  pipe, and a code other than 1000 gives its code and its reason on stderr
  and 69. Pings every 10 s find a link that died, as on the relay's road.
  A refused upgrade gives its status: 77 for 401 and 403, 69 else.
- **A WebSocket server** (T-368). `ws-listen:[ADDR:]PORT` and
  `ws-listen:PATH` listen by the rules of `tcp-listen:` and `unix-listen:`
  (the same probe, `PODSSH_LISTEN`, the mode 0600 and the peer's user), and
  each client is joined to the other side as given: the request names no
  target, as podssh is no public forwarder. A client's request is read as
  `http-listen:` reads one, and checked as RFC 6455 section 4.2.1 asks (GET
  405, HTTP/1.1 and a Host 400, `Upgrade: websocket` and `Connection:
  Upgrade` 426, version 13 426 with `Sec-WebSocket-Version: 13`, a key of 16
  bytes 400); a request with an `Origin` is a browser's and gets 403, so
  that a page that the user opens cannot reach the other side. The other
  side opens next, and the client hears `101` with `Sec-WebSocket-Accept`
  once it is open, or 502. Then podssh writes frames as a server, unmasked,
  and takes only masked ones: an unmasked frame of the client closes the
  session with 1002. One client by default, the first whose upgrade is
  good (a refused request is no session); `--keep-listening` takes each in
  turn. No `wss-listen:`: a server of TLS would need a certificate and a
  key of the user's.
- **A page for a visit to a WebSocket server** (T-639, GitHub #137).
  `--cover DIR` gives `ws-listen:` a page for a request that asks for no
  upgrade (no `Upgrade: websocket` with `Connection: Upgrade`), as a
  browser's visit, in place of the 426 that names the protocol: a `GET` or
  `HEAD` gets the file of DIR that its path names (its query set aside),
  typed by its name, with `X-Content-Type-Options: nosniff`, and
  `index.html` for `/` and for a directory, which is never listed; 404 when
  there is none, the same for each path. The path is walked under DIR part
  by part, each part percent-decoded: `..`, a name that starts with `.`
  (`.git`, `.env`), a `/`, `\`, `:` or NUL inside a part, and a `%` that is
  no escape give 404; then the file is resolved, links and all, and served
  only while it is still under DIR, a regular file of 1 MiB at most, opened
  with no link followed and checked again on its handle. Another method
  gets 405 with `Allow: GET, HEAD`, and a request of HTTP/1.1 with no
  `Host` 400. A page is no session: its connection closes after it, the
  listener waits for the next client, and only an upgrade opens the other
  side, with the refusals of the item above (an `Origin` among them). DIR
  is resolved at the start: one that is no directory exits 64, and so does
  `--cover` with no `ws-listen:` side. The relay role takes no cover: its
  404 is its contract's.
- **An upgrade with no key, for a client of WebTunnel's shape** (T-645,
  GitHub #143). `--raw-upgrade` lets `ws-listen:` answer the request that
  podssh's own WebTunnel client sends (T-385): `GET` with a `Host`,
  `Upgrade: websocket` and `Connection: Upgrade`, and no
  `Sec-WebSocket-Key` and no version. The checks of
  `podssh_ws::server::check_upgrade_or_raw` run in this order: the method
  (405), HTTP/1.1 and a `Host` (400), the two tokens (426), as for a framed
  client; then the key decides, before the version: a request with a key is
  framed, with the version (426) and the key's 16 bytes (400) checked as
  without the flag, so a broken client is never carried raw, and only a
  request with no key at all is the raw form; then an `Origin` is 403 in
  both, so that a page cannot reach the other side. The other side opens,
  then the client hears `101 Switching Protocols` with the two headers and
  no `Sec-WebSocket-Accept` (502 when the other side did not open), and its
  bytes go both ways as `tcp-listen:` carries them, the ones that it sent
  after its request first, with a half-close passed on: no frames, so no
  close code, no Ping and no idle bound; TCP alone finds a path that died.
  Without the flag a request with no key gets 426, as before, and the relay
  role's roads keep `check_upgrade`, whose contract is framed. What the flag
  admits: each program that can send such a `GET` reaches the other side,
  as at `tcp-listen:`, which checks nothing; `ws-listen:` has no
  authentication either way, and the key of RFC 6455 is no credential. A
  browser cannot send the two tokens from a page's `fetch`, and its
  WebSocket sends a key and an `Origin`, which is refused. No TLS on
  `ws-listen:`: a client of `https://` needs a front that ends TLS before
  it. `--raw-upgrade` with no `ws-listen:` side exits 64.
- **A local socket, by its name.** `unix-connect:PATH` connects, which the
  rule of no listener allows; `@NAME` is Linux's abstract namespace. A name
  that does not fit a socket's address is refused first (64). A missing
  socket, or one that nobody serves, exits 69, and one that this user may
  not use 77; each line names the path and the error. On Windows, a
  `\\.\pipe\` path is a named pipe, and another path an AF_UNIX socket
  (Windows 10 1803 and later), each tried when the pipe starts: where one
  fails, the line says why (the operator's ruling of 2026-10-08).
- **The roads, as the other commands take them.** `relay:` is what
  `podssh proxy` carries: since T-175, proxy runs the pipe of `stdio` and
  `relay:`, with its words and codes. `tcp:` dials as `ssh --direct` does.
  The hops of `ssh:` log in as `podssh ssh` does, with `-i`, `-o`
  (a keyword of a session, such as `RequestTTY`, is refused) and `--direct`;
  `node:` takes the pair of the label or of `--pair-file`; `iroh:` the key
  of `--iroh-key` and the relays of `--iroh-relay`.
- **`--ConnectTimeout SECONDS` bounds the open of a `node:` or `relay:`
  side** (T-589), as `operator` and `proxy` bound theirs, the other side's
  open with it. Its id is `ssh`'s, so each hop of an `ssh:` side takes it as
  its own ConnectTimeout too, and alone where no side is `node:` or
  `relay:`. A listening side refuses it (64), as each client opens a road
  long after the start, and so does a pipe with no `node:`, `relay:` or
  `ssh:` side. `--timeout DURATION` is another name of it (T-613), with the
  same refusals, and is each `ssh:` hop's ConnectTimeout too, in whole
  seconds; `PODSSH_TIMEOUT` bounds the open of a `node:` or `relay:` side
  where no side listens, and refuses no pipe and is no hop's ConnectTimeout,
  as it bounds whole runs of other commands.
- **`--no-resume` ends the session of each `node:`, `udp:node:` and
  `iroh:` side with its link** (T-612), as `operator --no-resume` does
  (above), for each client of a listening side too; a pipe with none of
  those sides refuses it (64).
- **A serial line is a stream too** (the operator's ruling of 2026-10-08,
  T-181). `serial:PATH[,BAUD]` opens a device such as `/dev/ttyUSB0` at
  BAUD, one of the speeds that Linux names from 1200 to 4000000 (115200 when
  none is given), with 8 data bits, no parity, 1 stop bit and no flow
  control, in raw mode, with the modem's lines ignored; the text after the
  last comma is BAUD. The attempt is the probe: a path that is not a
  character device, or one that is no terminal (`/dev/null`), exits 64;
  an open that this user may not make exits 77, and the line gives the
  device's mode, uid and gid, as podssh assumes no group such as
  `dialout`; another failure exits 69 with the error. The open has
  `O_NOCTTY` and `O_NONBLOCK`, so it never takes a controlling terminal
  nor waits for a carrier; `TIOCEXCL` then holds the line alone. Its
  settings are saved first and go back on each way out: when the pipe
  ends, at SIGINT and SIGTERM (130 and 143), and in the panic hook. A
  line has no half-close and no end: the end of the other side's input
  leaves it open, and the pipe ends when the other side ends it, at a
  signal, or when the device fails (a read or a write that fails, 69).
  On Windows, `serial:COM3` exits 64: a COM port is not built yet.
- **No shell.** `exec:` splits its words with single and double quotes
  only, as podssh assumes no shell; `exec:sh -c 'CMD'` names one. The child
  gets one end of a socketpair as its stdin and stdout, so that the end of
  its input is a half-close, or two pipes where a socketpair is refused (a
  sandbox's seccomp) and on Windows. Its stderr is podssh's.
- **Half-close, as `podssh proxy` does.** When one side's input ends, the
  other side's write half is shut, and the other direction goes on: a reply
  still comes back. `tcp:`, `ssh:` and `unix-connect:` pass it on as TCP,
  SSH and a socket do; the relay has no half-close, so `relay:` sends no
  Close, and the target's bytes come until it closes, as a named pipe's do;
  `node:` and `iroh:` end their session, as they ask the layer for no end
  of one direction (`podssh proxy` alone does, T-632). A writer whose reader is gone ends the pipe; a
  program that exited after its output ended ends it too, and so does a
  road that ended, as the other side's input may never end. podssh waits
  for each program, as a shell does.
- **UDP through a node, with no UDP here** (T-168). `udp:node:NAME` is the
  session to the node of the pair under NAME, whose TARGET is
  `udp:HOST:PORT`: this host sends no UDP and binds nothing, and the relay
  carries TCP. In the session, each datagram is its length (two bytes,
  big-endian) then its bytes, 65,507 at most, one flow for each session;
  the other side gives and takes that framing on stdin and stdout, a
  descriptor or a socket. A length over 65,507 is refused (65), with the
  reason. `exec:` beside it gets one end of an AF_UNIX `SOCK_DGRAM`
  socketpair as its stdin and stdout on Unix, which needs no bind: each
  send is one datagram at the target and each receive one answer, and a
  datagram over 65,507 bytes is counted and dropped. Where the socketpair
  is refused, and on Windows, which has none, its stdin and stdout carry
  the framing, and a line says so where it was refused. The node's session
  is opened first, so a program does not start when it fails. The session
  has no half-close, so after the end of this side's input it waits for
  answers until none came for 5 s. A datagram socket has no end of input:
  when the other side ends, the program gets 10 s to exit, then SIGTERM,
  then 10 s more and SIGKILL; its status is the pipe's. `udp:HOST:PORT`
  here is a usage error (64) that names the node's form. A local UDP
  listener is not made.
- **The exit status.** A road that failed gives it, as `podssh proxy` gives
  it: 69 for a road out of reach, 77 for a refusal (the relay, a proxy, a
  host key, a login) and 78 for a setting that cannot be used; 65 for a
  stream of `udp:` that is not its framing. Else the program's, B's when
  both are programs, 128 + N for a signal, 127 for a program that is not
  found and 126 for one that cannot run; with neither, 0.

## `podssh agent`

An SSH agent inside podssh (T-034), for a host with no `ssh-agent` and no
OpenSSH program that runs; one binary, as the operator ruled (Q5).

- `podssh agent` serves the agent protocol (russh's agent server) until
  SIGINT, SIGTERM or SIGHUP, and stays in the foreground: start it with
  `&`. It prints `SSH_AUTH_SOCK=PATH; export SSH_AUTH_SOCK;` and
  `echo Agent pid N;`, as `ssh-agent -s` does. The socket is `agent.sock`
  in a new directory of mode 0700 in `XDG_RUNTIME_DIR` or the temporary
  directory, made mode 0600; a client of another uid is closed; both go at
  the end. On Windows it is the named pipe
  `\\.\pipe\podssh-agent-USER-PID`, which takes only processes of this
  user. `--socket PATH` names another place. It binds through the listener
  of `podssh pipe`: `PODSSH_LISTEN=no` refuses it (78), and a host that
  refuses the bind gets the reason and the ways with no agent: key files
  with `-i`, whose passphrase is asked on the terminal or through
  `SSH_ASKPASS`.
- `podssh agent add FILE...` sends each key, its passphrase asked on the
  terminal or through `SSH_ASKPASS` (`-t SECONDS`, `--lifetime`: the key
  leaves after that); `list` writes a line for each key as `ssh-add -l`
  does (1 when there is none); `remove FILE...` or `remove --all`; `lock`
  (the password asked twice) and `unlock`. They talk to the agent of
  `SSH_AUTH_SOCK`, so they work with OpenSSH's agent too, and OpenSSH's
  `ssh` and `ssh-add` work with podssh's.
- Keys stay in the agent's memory only. A key added for a confirmation of
  each use (`ssh-add -c`) is refused as it is added: nobody can confirm one,
  and russh's agent server would sign with it unasked (T-284). russh's
  agent keeps no comment of a key, so `list` shows the size, the
  fingerprint and the type. podssh agent keeps no RSA key (T-257): russh's
  agent server would sign with it through the `rsa` crate, which is not
  constant-time, so `podssh agent add` of an RSA key fails with the reason
  (exit 70); OpenSSH's `ssh-agent` keeps one.
- A key of a security key (T-229) is kept by the front of the agent, as
  russh's agent server cannot sign with one: `podssh agent add` and
  OpenSSH's `ssh-add` give it (with the constraint
  `sk-provider@openssh.com`, which names OpenSSH's helper; podssh reaches
  the device its own way, whatever it names), `list` and `ssh-add -l` show
  it with its comment, and a signature with it goes to the device. The
  agent says the touch on its own stderr, and `podssh ssh` says it too. A
  key made with `verify-required` gets its PIN only through `SSH_ASKPASS`
  with `SSH_ASKPASS_REQUIRE=force`: the agent runs in the background, where
  a read of the terminal would stop it. With no device, the agent answers
  FAILURE and says why on its stderr.
- A store of credentials (T-228): `podssh agent add-password
  [USER@]HOST[:PORT]` keeps a server's password, under the user, host and
  port that `podssh ssh` logs in with (its ssh_config read), and
  `add-passphrase FILE` the passphrase of a key file that the agent does not
  hold, once it opens the file. The secret comes from stdin when stdin is no
  terminal, else from the terminal or `SSH_ASKPASS`; never from the command
  line. `-t SECONDS` ends it. Only podssh's agent keeps them, in its memory,
  and tells them to its own user only. `podssh ssh` asks the agent of
  `SSH_AUTH_SOCK` (none with `IdentityAgent none`) before each prompt for a
  key file's passphrase, a password, or the password that keyboard-interactive
  asks for with one prompt with no echo; `BatchMode` forbids the prompt, not
  the question. A secret that a server or a key file refuses is forgotten,
  and never tried twice. `-v` names where a secret came from, never its
  value; `podssh doctor` says how many the agent keeps, never which; a
  locked agent tells none.
- The agent protocol carries them in its extension message (27,
  draft-miller-ssh-agent, section 3.8), under these names, which podssh
  agent answers before russh's server: `store@podssh` (kind, name, secret,
  a lifetime in seconds or 0), `lookup@podssh` (kind, name: SUCCESS, a
  byte 1 and the secret, or a byte 0), `forget@podssh` (kind, name) and
  `count@podssh` (SUCCESS and a count). A kind is `password`, whose name is
  `USER@HOST:PORT`, the host in lower case, or `passphrase`, whose name is
  the key file's absolute path. Another agent answers FAILURE or
  EXTENSION_FAILURE (28), or closes the connection: podssh reads each as an
  agent with no store, and goes on to the prompt. On Windows, with no
  `SSH_AUTH_SOCK` and no OpenSSH agent, podssh asks Pageant only when its
  window is there.
- Exit codes: 0; 1 (`list`, no key); 64 a usage error; 65 a passphrase
  that does not open its file, or a file that needs none; 66 a key file
  that cannot be read, or no secret came; 69 no agent answers at
  `SSH_AUTH_SOCK`, or it keeps no passwords; 70 the agent refused a
  request; 73 the agent's directory could not be made; 77 a passphrase or
  password that was wrong or did not come; 78 `PODSSH_LISTEN=no`; 129, 130
  or 143 at the signal that ends the agent.

## `podssh chat`

`podssh man chat` gives the command, and [irc.md](irc.md) the protocol. The
rules behind it:

- **Two podssh ends, one road.** One side waits, `chat --listen NAME`, as
  the node of the pair NAME; the other reaches it, `chat NAME` (or
  `node:NAME`, `node://NAME`), as its operator. With `--iroh`, the side that
  waits serves the iroh road too, as `node --iroh` does, and the other
  reaches its ticket, `chat iroh:TICKET`. A rendezvous where both sides dial
  lost: the relay's contract has none.
- **Always the channel.** Chat runs the end-to-end channel of T-088 with the
  keys of T-087, and has no `--no-e2e`: the relay never reads a message.
  The flags of the keys are those of `node` (`--key`, `--ephemeral-key`,
  `--allow`) at the side that waits, and of `operator` (`--client-key`,
  `--node-key`) at the side that reaches; a flag of the other side is a
  usage error.
- **Lines in, lines out.** stdin and stdout carry lines, so that a script or
  an agent can talk; there is no TUI. A line that starts with `/` is a
  command, and `//` sends a literal `/`. Notices go to stderr, and
  `--jsonl` puts each event on stdout as one JSON object.
- **A file only once accepted.** `/accept`, or `--accept-dir` for a script,
  is the only way a file is written, under a temporary name, checked
  against its SHA-256, then given its name, never over a file that is there.
- **The one thing of a script.** `--send`, `--sendfile` and `--file` each
  give a run its one thing, and at most one is given. `--timeout` is
  required with no terminal: a run that waits for a peer has nobody to stop
  it.
- **A listener that stays.** The end of stdin ends a listener once each line
  went, which `--listen NAME < lines` relies on; so a listener that a
  service or an agent starts with stdin at `/dev/null` leaves as its first
  peer comes, and its end says that stdin ended (`input-ended` in
  `--jsonl`). `--linger` (T-489) keeps it: the end of stdin ends no
  conversation, and the listener waits for the next peer until `--timeout`,
  a signal or `/quit`; the `--timeout` is then the run's planned end, with
  exit 0 when each message went. A flag with no value, as `--timeout`
  bounds the run already; it opens no socket, as the listener connects out
  to the relay. With `--send` or `--file`, which end the run once done, it
  is a usage error.
- **IRC second.** `--irc SERVER` talks in a channel of a network, with TLS
  inside the relay stream unless `--irc-plaintext` names the risk, and over
  TCP with `--direct`, as `ssh --direct`; the flags of the roads' keys do
  not go with it, and PEER is the channel. The server and each user of the
  channel read the messages; a file goes between two nicks alone.
- **Nothing lost unsaid.** A message that the peer did not acknowledge is
  said when its conversation ends, and the exit is then 69. The lines that
  wait for a peer stay in memory, 1000 lines or 1 MiB at most.

## `podssh play`

`podssh play [OPTIONS] FILE` (T-033) writes the output of a recording again,
on stdout, with its timing: a file of `podssh ssh --record`, or another
asciicast v2 file. `--speed FACTOR` plays it faster or slower, and
`--idle-limit SECONDS` cuts each wait to that many seconds, as the file's
`idle_time_limit` does when it has one. An event of another kind than
output (`r`, `i`, `m`) is passed over. A file of another version, and a
line that is no event, are refused (exit 1, the line named); a missing
FILE and a bad value are usage errors (64). The name is not `replay`, which
is one edit from `relay` and would confuse the suggestion of a mistyped
command. A recording sends its control sequences to the terminal again:
play only a file that you trust.

## `podssh config`

`podssh config import ansible FILE` (T-047) prints a `Host` block of
`ssh_config` for each host of an Ansible inventory in its INI form (FILE,
or `-` for stdin), and a summary on stderr. It writes no file: you add what
it printed, as `podssh config import ansible hosts.ini >> ~/.ssh/config`.
The inventory is read as Ansible's `ini` plugin reads it, which
`tests/config_import.rs` checks against what Ansible itself made of a
fixture: hosts before any section are ungrouped, `[G:vars]` and
`[G:children]` give a group's variables and children, `host:PORT` gives a
port, and a range names several hosts (`www[01:03]`, `db-[a:c]`,
`n[1:9:2]`). A host's variables are those of `all`, then of its groups from
the farthest parent to the nearest, then its own line's, the later winning.
`ansible_host`, `ansible_port`, `ansible_user` and
`ansible_ssh_private_key_file` give `HostName`, `Port`, `User` and
`IdentityFile`; of a variable and its `ansible_ssh_` name, the latter wins,
as Ansible's ssh connection takes it.
The `-o` options of `ansible_ssh_common_args` and `ansible_ssh_extra_args`,
which Ansible gives to ssh after those, follow as lines of the block, and
`-J` as `ProxyJump`; `ProxyCommand` and the other keywords that run a
command, and each other flag, are named in a comment, with no value.

A password or a passphrase (a variable whose name holds `pass`) is never
imported and never printed: the summary counts it. A host whose
`ansible_connection` is not `ssh` gets a comment and no block. A host name
that a `Host` line cannot hold (a space, `*`, `?`, `!`, `"` or `#`) is refused by
name on stderr. A bad line ends the run with its number (65); a file that
cannot be read gives 66.

`podssh config import putty`, `mobaxterm` and `remmina` (T-292), and
`mremoteng` (T-327), read the saved sessions of those programs, and are
tested on exports that each program wrote and that were published under a
license that this repository can hold (`tests/fixtures/sessions/THIRD-PARTY.md`;
mRemoteNG's own test files under the GPL-2.0 by the ruling of Q46,
`tests/fixtures/mremoteng/NOTICE.md`), kept byte for byte:

- **PuTTY**: a `.reg` file of `Software\SimonTatham\PuTTY\Sessions`, as
  `regedit` and `reg export` write it (UTF-16LE with its mark, UTF-8, or the
  ANSI of `REGEDIT4`, the key's name in any case), or the session files of
  PuTTY on Unix, one file or their directory, each name `%XX` escaped.
  `Default Settings` is the template, never a host. `user@host` in
  `HostName` gives `User`, as PuTTY reads it. A `.ppk` key is a comment, as
  ssh cannot read PuTTY's format; an SSH proxy (method 6) is `ProxyJump`;
  `ProxyPassword` is counted; `Environment`, a local proxy command and the
  other proxies are comments with no value.
- **MobaXterm**: an `.mxtsessions` export, or `MobaXterm.ini`. Each line of
  a bookmark is `NAME= #ICON#TYPE%FIELD...`; for SSH (type 0) the fields
  give the host, the port, the user and the gateways (`ProxyJump`), and
  MobaXterm's escapes (`__PIPE__`, `__PTVIRG__` and the others) are undone.
  A command after the login, a proxy and a key path in MobaXterm's own form
  are comments; each entry of `[Passwords]` and `[Sesspass]` is counted.
  The text is UTF-8, else Windows-1252.
- **Remmina**: one `.remmina` profile, or each of a directory.
  `protocol=SSH` makes a block; `server` (`host`, `host:port`, `[v6]:port`)
  gives `HostName` and `Port`; `name` is the label and `group` the folder.
  Each secret, `.` for the keyring or an encrypted blob, is counted; a value
  of a template such as `%Host%` is no host.
- **mRemoteNG**: `confCons.xml`, or an export of it. Each `Node` of
  `Type="Connection"` is a session in the folders (`Type="Container"`)
  above it; `Protocol="SSH2"` makes a block, `SSH1` and each other protocol
  a comment. A field that a node inherits (`InheritUsername`, `InheritPort`
  and the others, `True` or `true`) comes from the nearest folder above it
  that has its own, as mRemoteNG takes it. `SSHTunnelConnectionName` gives
  `ProxyJump` through the connection of that name, its own tunnel first; a
  tunnel that is no SSH connection of the file, or a loop, is a comment.
  A PuTTY session other than `Default Settings`, and `SSHOptions`, are
  comments with no value. Each password (`Password`, `VNCProxyPassword`,
  `RDGatewayPassword`), encrypted with the user's master password, is
  counted, never decrypted. A file encrypted whole (`FullFileEncryption`)
  is refused by name (65): in mRemoteNG, turn that off and save, or export
  the connections, and import that file.

A session's label becomes the name of its block, each run of characters
that a `Host` line cannot hold made one `-`, with the label itself in a
comment above it, and a second label of the same name gets `-2`. FinalShell
and Termius, and Ansible's YAML, are refused by name (64) until a real export
of each, under such a license, is at hand to test against (T-328):
FinalShell and Termius have no export.

## `podssh mcp`

`podssh mcp` (T-055) is a server of the Model Context Protocol on stdin and
stdout, for an agent whose MCP client starts it: each line of stdin is one
JSON-RPC 2.0 message and each line of stdout one answer, as the protocol's
stdio transport has them, and podssh's own words go to stderr. It serves a
client of the revision 2026-07-28, whose requests name their version in
`_meta` (`server/discover`, `tools/list`, `tools/call`), and one that opens
with `initialize` (the revisions 2025-11-25, 2025-06-18, 2025-03-26 and
2024-11-05; `ping` too). It ends at the end of stdin: the calls then in
flight have 2 s to end, and end with their children after it; SIGTERM,
SIGINT and SIGHUP, or Ctrl-C and the close of the console on Windows, end
them at once.

The tools:

- **`ssh_exec`** runs one command on a host: `destination` (`[user@]host`)
  and `command`, and at will `stdin` (text), `timeout_seconds` (1 to 3600,
  default 60) and `host_key_fingerprint`. Its result (`structuredContent`,
  and the same JSON as text) has `exit` (podssh's exit code), `status`,
  `signal`, `end` and `failure` as `--result-file` gives them (T-054),
  `stdout` and `stderr` (at most 1 MiB each; `truncated` says that more
  came; output that is not UTF-8 comes as base64, as its `_encoding` says),
  `timed_out` and `duration_ms`. A status that is not 0 is the command's:
  `isError` is true only when podssh failed, or the limit passed.
- **`status`**, **`doctor`** and **`man`** give the JSON of `podssh
  status` (with a `destination`, which must be allowed), `podssh doctor
  --json` (with `full`, and `quick` since T-511) and `podssh man --json`
  (with a `section`).
- **`health`** and the **`job_`** tools (T-488, GitHub #101), with a host
  allowed: `podssh health --json`; `job_start` (a command in the host's
  tmux, which outlives the call; the result's `id`), `job_list` (`job list
  --json`), `job_log` (a window of the output: `offset`, `max_bytes`, 256
  KiB by default and 1 MiB at most, `next_offset` and `more`; `job log` has
  no offset, so the child keeps the output up to the window's end, 32 MiB
  at most), `job_wait` (`job wait --timeout`, at most `wait_seconds`, under
  a call's limit of that and 30 s; a job that runs on is a result, `ended`
  false, not an error) and `job_stop`. Until `--json` and `--result-file`
  come for those verbs (T-484, T-486), a result is the exit, the streams and
  the fields that the tool reads from them. `health` takes `preflight`, a
  boolean: `podssh health --json --preflight`, with a limit of 180 s when
  the call names none (T-482).
- **`cp_put`** and **`cp_get`** (T-488), with `--allow-dir DIR` too: `podssh
  cp --jsonl` between a path of this host in a DIR and a path of an allowed
  host, each file's SHA-256 checked at both ends, with `recursive` for a
  tree as `cp -r` copies it (a link as a link); `cp_put` takes `content`,
  the bytes of one file in base64 (1 MiB at most), in place of a local
  path. The result has cp's exit, its streams and the objects of its
  `--jsonl` as `events`.
- **The `session_` tools** (T-488), with `--allow-session`:
  `session_start` (`podssh session start` with the options of each child
  below, a pty, and the session's socket in the result), `session_send`
  (the text on the child's stdin, then Enter unless `enter` is false),
  `session_wait` (`idle_seconds`, `match`, `wait_seconds`; `ended_by` is
  `idle`, `match` or `limit`), `session_capture` (`raw` at will) and
  `session_stop`.

**The local side has a gate of its own.** `--allow-host` lets an agent reach
a host, not read the files of this one: no tool read or wrote one before
T-488. So the copies are offered only with `--allow-dir DIR` (repeat it for
more), and a local path of a call is resolved, its links followed, and
refused unless it lies inside a DIR, before any child runs; a relative path
is under the first DIR. A DIR that holds `~/.ssh` or a directory of
podssh's cache, or lies inside one, and the root of the file system, are
refused as the server starts (64), as a copy from them would hand your keys
to the agent; a DIR that is not there is 78. `cp_get` puts a tree only into
a new path, so that each path below it is one that the copy makes, and none
a link made before it.

**Sessions outlive a call.** A session's daemon outlives its call, and would
outlive the server: so the session tools come only with `--allow-session`,
the server drives only the sessions that it started (a name of yours is
refused), and stops each of them as it ends, its stdin's end or a signal,
so that none stays on the host with no owner. A start that the client
cancelled, or that passed its limit, may have started, and is stopped too.

**The risk, and the hosts allowed.** An agent with `ssh_exec` runs commands
on each allowed host as you, with your keys and your `ssh_config`. The words
of a call come from a model, and text that the model read can ask it for a
command or for a host. So `ssh_exec` reaches no host unless
`--allow-host PATTERN` lets it in, and is not offered with none. A pattern
is `[USER@]HOST` with `*` and `?`, as a `Host` line has them; `!PATTERN`
excludes what it matches; a pattern with `USER@` lets in only a destination
that names that user. The host is matched as the call names it, with no
regard to case, before the `HostName` of your configuration: name each
host, or the fewest patterns that hold them. A destination is a host with
no port and no path: they come from your configuration.

Each call runs `podssh ssh` again, as a child with pipes, so that a
session's output never reaches the protocol's stdout and calls run at once
(four, and the others wait); `health`, `job`, `cp` and `session start` get
the same options, but for `-T` and `-e none`, which are `ssh`'s, and none
of them has a `host_key_fingerprint`: a host key that `known_hosts` holds.
The child gets `-o BatchMode=yes` (no prompt,
ever), `-o StrictHostKeyChecking=yes` (a host whose key `known_hosts` does
not hold is refused, unless `host_key_fingerprint` names its key, as
`--host-key-fingerprint` does), `-o ClearAllForwardings=yes`,
`-o ForwardAgent=no`, `-o ForwardX11=no`, `-o ControlMaster=no`,
`-o ControlPath=none`, `-T` and `-e none`, before `-F FILE` and
`--direct` when `podssh mcp` has them: the first value of a keyword holds,
so a file cannot undo these. A call past its limit, or one that the client
cancels (`notifications/cancelled`), ends with its child; a cancelled call
gets no answer.

`podssh mcp` exits 0 at the end of stdin, 64 for a pattern that is not one
(empty, with a space or a comma, or `USER@` with no host) or an
`--allow-dir` of keys, and 78 for a `-F` file or an `--allow-dir` that does
not exist.

## `podssh session`

`podssh session` (T-186) keeps one SSH session with a pty between the calls
of an agent, which runs one command at a time and must not wait for a
shell to end: it opens the session once, types into it, waits until its
output stops, and reads its screen, each with a call of its own.

- `podssh session start NAME [OPTIONS] HOST [COMMAND]` runs `podssh session
  serve` in the background: this binary again, which leaves the session of
  its starter at ready (`setsid`; on Windows it frees the console and is out
  of the caller's job where the job allows it), logs in as
  `podssh ssh` does, with its connection flags and the `Host` blocks of
  ssh_config, and holds a session with a pty: the login shell, or COMMAND.
  It is the one SSH client of podssh, on each of its roads. `start` returns
  once the request of the session went to the server, after the login and
  the pty, with the path of the socket on stdout. What the session's podssh
  says until then comes on stderr, and when it ends first, its exit code is
  `start`'s: 255 for a connection or a login that failed, 77 for a bind
  that this host refuses. When the session is not ready within `--timeout`
  (60 s), it is stopped, and `start` exits 75. A name that runs already is
  refused (69).
- Until it is ready, the session's podssh keeps `start`'s terminal and
  session (T-382): a password, a key's passphrase and a new host key are
  asked there as `podssh ssh` asks them, within `--timeout`, and Ctrl-C
  reaches it; at ready it leaves them (`setsid`, SIGHUP ignored; on Windows
  it frees the console, T-383). With no
  terminal, a passphrase comes from `podssh agent` or `SSH_ASKPASS`, and a
  new host key needs `StrictHostKeyChecking=accept-new` or a `known_hosts`
  that has it. The pty's size is that of `COLUMNS` and `LINES`, else 80 by 24. No
  forward, no X11 and no control socket of ssh_config is used (said with
  `-v`).
- `send NAME TEXT` types TEXT, then Enter (a carriage return), which
  `--no-enter` leaves out. In TEXT, `\r`, `\n`, `\t`, `\e` (Escape), `\xNN`
  (`\x03` is Ctrl-C) and `\\` give the bytes that they name; each other `\`
  is refused, so a path of Windows writes each `\` twice. `send NAME` with
  no TEXT types stdin as it is, 512 KiB at most: a password goes so, and
  never stands in a command line, which each process of the host can read.
- `wait NAME` returns when the output has stopped for `--idle` (2 s by
  default), counted from the later of the last output and the last send:
  a wait right after a send waits for what the send brings. Output that
  stops inside an escape sequence or a UTF-8 character has not stopped,
  until the grammar of T-221 calls the sequence broken (10 s). With
  `--match TEXT` it returns when TEXT comes in the output since the last
  send, with the terminal's sequences and control bytes taken out (a colour
  between two letters hides no match); with both, the first that comes. It
  writes `idle` or `match` on stdout. The echo of the line that `send`
  typed is output too: match a text that only the command writes. It exits
  75 when `--timeout` (60 s) passes first, and 69 when the session ended
  first, with its status.
- `capture NAME` writes the screen, as a terminal of the pty's size shows
  it after the session's output: its rows, with no blank at their ends and
  no empty row at the end, as `tmux capture-pane` gives them. The model is
  the one of the terminal oracle (T-200), `vt100`, pure Rust. `--raw`
  writes the last 64 KiB of the output as it came, from a place where a
  terminal can start to read it: the ring of T-221, never inside a
  sequence or a character.
- `stop NAME` ends the session and its podssh. `list` writes a line for
  each session of the cache: its name, `running` or `ended` and the
  status, and its host, with a tab between them (T-506). A session whose
  podssh takes the connection and gives no answer within 2 s is a line
  with the state `no-answer` and no host, and why on stderr: it is there,
  busy or stuck, and a script that counts the lines counts it. A socket
  that nobody serves any more (`ECONNREFUSED`, as after a crash) is no
  session; the next `start` of its name takes its place. With no session,
  stdout stays empty and one line on stderr says so and names the
  directories read, so that "none" is not a list that could not be made; a
  directory that is there and cannot be read is a line on stderr with its
  error; `-q` leaves these lines out. `--json` writes one object instead:
  `sessions` (`name`, `state`, `host` and `socket`; `[]` for none), `read`
  and `unreadable` (`dir` and `error`). The exit is 0.
- The session's podssh ends at `stop`, 60 s after its session ended (so
  that its last screen and its status can be read), after an hour with no
  request, or at SIGINT, SIGTERM or SIGHUP. `podssh session serve NAME
  [OPTIONS] HOST` is that podssh in the foreground, for a program that keeps
  it itself: one line of JSON on stdout when it is ready, and its messages
  on stderr; `--detach`, which `start` gives it, writes nothing more on
  stdout and stderr after that line, so that a program that reads them to
  their end does not wait for it.

**The socket.** `start` and `serve` listen, as the operator allowed (Q1):
on `NAME.sock` in the directory `sessions` of the first usable directory of
the cache (FILES), made with mode 0700, through the listener of `podssh
pipe` (T-177): the socket is made mode 0600, and a client of another user
is closed before a byte of it is read; on Windows it is an AF_UNIX socket
whose clients must run as this user. `--socket PATH` names another place:
also `\\.\pipe\NAME` on Windows, and `@NAME` in Linux's abstract namespace,
which has no file and where the check of the user is the guard. No TCP: a
request types into a shell, and a TCP peer's user cannot be read. The bind
is the probe: a host that refuses it gets the reason, and `start` exits 77;
`PODSSH_LISTEN=no` refuses `start` and `serve` before any bind (78), and
so does `PODSSH_CACHE_DIR=none` with no `--socket`. A client looks for NAME
in each directory of the cache, in its order.

**The risk.** Each program that runs as you can type into the session and
read its screen, as it can use your keys. The socket carries no key,
password or token: the session's podssh logs in with what `podssh ssh`
would use, and a request carries text to type.

**The protocol** of the socket, for a program that speaks to it itself:
one JSON line for each request and one for each answer, with the version
first (`"schema":1`). A request has the session's `name` and its `op`:
`info`; `send`, with `text`, or `bytes` in base64; `wait`, with `idle_ms`,
`match` and `timeout_ms`; `capture`, with `raw`; `stop`. An answer has
`ok`, and the fields of its operation (`screen`, `cursor`, `rows` and
`cols`; or `bytes`; `by`; `state` and `status`), or `code`, the exit code
that the client gives, and `error`. A line of another schema, or another
session's name, is refused (64).

Exit codes: 0; 64 a usage error; 69 no session of that name answers, or it
ended; 70 an answer that this podssh cannot read; 75 the `--timeout` passed
first; 77 the bind refused; 78 `PODSSH_LISTEN=no`, or no directory for the
socket; 255 the connection or the login of `start` failed.

## `podssh update`

`podssh update [--check] [--version TAG] [--ca-file FILE]` (T-375) replaces
this binary with the binary of a release for its own target, and only when
asked: no other command looks for a release. `podssh update --rollback`
(T-396) puts back the binary before the last update.

- **Which release.** `--version TAG` takes that one, an older one too.
  Without it, the newest one, from GitHub's API, else from the releases'
  Atom feed (the API allows 60 calls an hour to an address with no token): a
  prerelease only when this binary is one, as a `-` in its tag says, and
  never one older than this build, which is then nothing to do (exit 0).
- **Which binary.** The release's file for this build's architecture and
  system, as `podssh-x86_64-unknown-linux-musl` or
  `podssh-aarch64-pc-windows-msvc.exe`: on Linux the static one of musl,
  whatever this build's libc. A system with no binary in the release is
  refused (78).
- **Two checks before anything is written.** First the release's
  `SHA256SUMS` against `SHA256SUMS.sigstore.json`, the signature that the
  release workflow made with Sigstore (T-211): the leaf certificate that
  Fulcio gave the workflow `release.yml` of this repository at that tag,
  checked by Sigstore's roots, which are compiled into podssh
  (`crates/podssh-cli/src/update/trust/`); its use for code signing and the
  issuer of its token, GitHub Actions; and Rekor's signed record of the
  signature, which gives the time at which the leaf must hold. No other
  network is needed for it. Then the binary's SHA-256 against its line. A
  failed check is exit 65.
- **The replacement.** The new binary goes beside the old one, in its
  directory, with its mode, and then over it in one rename, so that a
  running podssh keeps running from the old file. Windows refuses to write
  over a running program and allows its rename: there the running file is
  renamed `podssh.prev.exe` first (else `podssh.exe.old`, which the next
  run of podssh removes). A failure at any step leaves the old binary as it
  was (exit 73 when it cannot be written, as in a directory that this user
  cannot write).
- **A run before the replacement (T-396).** An installed node that ends
  starts again from the new file, and one that does not start on this host
  (a libc, a CPU feature, a defect) would lock out the server that only the
  node reaches. So the new file, written beside the old one, runs there
  once as `podssh --version`, with no input, for 10 s at most; its exit
  code is read directly, and its first line must be `podssh VERSION` of
  the release asked for. Else it is removed and refused (65), and the old
  binary stays. Its signature and its sum were checked first, so the run
  trusts nothing new.
- **The binary before, kept (T-396).** On Unix the old file is kept as
  `podssh.prev` beside the new one before the rename (a hard link, which
  costs no space, else a copy); on Windows it is the file renamed aside.
  `podssh update --rollback`, with no network, runs `podssh.prev
  --version`, then puts it over this binary in one rename and keeps this
  one as `podssh.prev`, so that a second rollback goes forward again; 69
  when none is kept, 65 when it does not run here. A run that started
  before goes on with its own binary until it starts again. A supervisor of
  a detached run (T-390) can start `podssh.prev` after the new binary
  failed to start again and again: `update::keep::fallback` names it, and
  changes no file.
- **The way back that the line names (T-507).** The kept file itself:
  `mv podssh.prev podssh`, with the paths of this host (on Windows `cmd /c
  move /Y`, which cmd and PowerShell both run), needs no podssh and is
  always named. `--rollback` came in `1.0.0-beta.4` (`ROLLBACK_SINCE`
  beside its flag row); `--version` can install a release before it, whose
  binary says "unknown flag '--rollback'" (64), so the line names
  `podssh update --rollback` beside the move only when the version now in
  place has it, by the version that the trial read: no second run of the
  new binary. The line of `--rollback` says the same of the binary that
  it put back.
- **Through the proxy.** Each connection goes through `HTTPS_PROXY` when it
  is set, one after another: the list, then each file, through the redirect
  that GitHub gives an asset, whose query is a credential of the moment and
  is never printed. TLS to GitHub trusts `--ca-file`, else `SSL_CERT_FILE`,
  else `CaFile`, else the system's; it carries none of the update's trust,
  which is the signature's. GitHub or a file that does not come is exit 69.
- **`--check`** stops before the binary: it names the release, checks its
  signature, and names the file that it would replace.
- **When Sigstore changes.** A rotation of Fulcio's roots, or cosign's
  move to Rekor v2, makes a binary of before refuse the releases after it;
  its message says to download the release by hand. Each release's proofs
  (`release-proofs.yml`) run podssh update on it, so the day it comes shows.

## podssh's settings file

A file states podssh's own settings once (T-048), below the flags and the
variables and above the built-in defaults: `RelayHost` (as `--relay-host`
and `PODSSH_RELAY`), `RelayAddr` (as `--relay-addr` and `PODSSH_RELAY_ADDR`;
each line adds to the flag's and the variable's pins), `RelayFailover` (as
`--relay-failover`), `CaFile` (as `--ca-file` and `SSL_CERT_FILE`; `~` is
the home), `SessionLog` (as `PODSSH_SESSION_LOG`, below), `Direct` (yes
or no, as `PODSSH_DIRECT`: the direct road after the relay hosts, T-363),
`RelayRank` (yes, no or auto, as `PODSSH_RELAY_RANK`: the measured order of
the default relay hosts, T-607, and with auto a rank in a session's
background, T-608),
`DoctorJobs` (1 to 64, as `doctor --jobs`, T-511) and `RelayKeys` (keys
of a signed list of relay deployments, as `PODSSH_RELAY_KEYS`; each line
adds, T-346). It has `Keyword value` lines, `Keyword=value` too, and `#`
comments, read as an `ssh_config` line is; the first value of a keyword
wins. The file is the one that `PODSSH_SETTINGS` names, an absolute path
that must exist (`none` reads none); else the first that exists of
`$XDG_CONFIG_HOME/podssh/settings` (`~/.config/podssh/settings`, and
`%APPDATA%\podssh\settings` on Windows) and `podssh.settings` beside the
binary. It is never read from the working directory or `/tmp`, as a file
that names relay hosts decides where tokens go. A symbolic link, a file of
another user than you or root, one that others can change, an unknown
keyword and a bad value are refused (78, with the file and the line) by each
command that reaches the relay. podssh never writes the file, and no
keyword holds a token. `podssh status` gives its path as `settings` and
`relays_from: "the settings file"`, and `podssh doctor` names it.

After a line `[groups]`, to the next table or the end of the file, each line is
`NAME HOSTS` (or `NAME=HOSTS`): a group of hosts for `podssh each`, named
`@NAME` (T-184). A name has letters, digits, `.`, `_` and `-`, and does
not start with `.` or `-`; its hosts are a word of `podssh each`, with commas or blanks between
items (a group's line alone may part its hosts with blanks), braces, and other groups. The settings
come before the table: a line of the table that is a setting's keyword is
refused, and so are a group given twice, another table, and a group that
names one that is not there or itself, through others or not (78, with
its line), as each bad line of the file is.

After a line `[snippets]`, each line is `NAME COMMAND`: a command for
`--snippet NAME` (T-187, "Snippets" above). The two tables can come in
either order; a table other than `[groups]` and `[snippets]` is refused.

## The log of the sessions

When the user asks for it, podssh keeps a line for each session of this
host (T-056): `PODSSH_SESSION_LOG=1` (or `yes`) keeps it in the cache, as
`sessions.jsonl` in the first directory of the cache that takes it; an
absolute path keeps it in that file; `0` or `no` keeps none, also over
`SessionLog` in the settings file, which takes the same values. It is off
by default, and another value is refused (78) before anything connects.

Each run of `podssh ssh` and `podssh proxy` that named a destination adds
one JSON line at its end: `start` (UTC), `duration_ms`, `verb`, `host`,
`port`, `via` (the relay host, or `direct`, `node`, `iroh`, `cloudflare`,
or `relay` when no relay host answered), `end`, `exit`, `failure` and
`bytes` as `--result-file` has them (T-054; a proxy ends `closed` or
`failed`), and the relay's `close_code`. A line never holds a command, an
environment value, a token or a password; an `-O` request, `-G` and a usage
error add none.

The file has mode 0600 (on Windows, an access list of its own), is opened
to append with no symbolic link followed, and takes each line in one write,
so that two runs at once give two whole lines. A file that is another
user's, or that others can read, is refused, and the run says so on stderr
with its exit code unchanged. At 1 MiB the file becomes `sessions.1.jsonl`
(the name with `.1` before its extension), and a new file starts.
`podssh status` gives the file and the last line, in short, as
`session_log`.

## The report of a failure

When podssh itself fails, it gives a report of the failure to a program
that the user names in `PODSSH_ERROR_PROGRAM` (T-195): a script that files
a ticket, or a tool that asks an AI for the cause. podssh calls no AI
service and no network address for this; the program decides what to do
with the report (`docs/decisions.md`, 2026-10-08).

- **The program.** podssh starts it as it starts `SSH_ASKPASS`: by its
  name, with no shell and no argument. A variable, and no flag, so that it
  reaches each command, also `podssh proxy` under the `ProxyCommand` of
  OpenSSH. The program's environment has no `PODSSH_ERROR_PROGRAM`, so a
  podssh that it runs starts no program of its own, and no credential
  variable (`PODSSH_RELAY_TOKEN` and the tokens of Cloudflare Access); the
  proxy variables stay, for a program that needs the proxy. Its stdout and
  stderr go to podssh's stderr, as stdout is data. After 30 s podssh stops
  it. Its status is ignored, and podssh's exit code does not change. A
  program that does not start gives one line on stderr.
- **When.** Only when podssh itself fails: each exit code that is not 0,
  but a status that podssh passes on and a stop that the user asked for.
  The code path decides, not the number. `podssh ssh` passes on the remote
  command's status (255 too) and a session's end with no status: each
  run whose `--result-file` has no `failure`. `podssh each` passes on the
  statuses of its hosts when each host had a session; `podssh ping` the
  status of the remote program of a measure; `podssh pipe` a child's
  status; `podssh edit` the editor's. 130 and 143, which podssh gives after
  SIGINT and SIGTERM, start no program.
- **The report.** One JSON object and a line break on the program's stdin:
  `schema` (1), `podssh` (the version), `os`, `arch`, `verb` (the
  command's canonical name, or null for a word that names no command),
  `exit`, `messages` and `relay`. `messages` holds the last 64 lines of
  podssh's own messages, 16 KiB at most, each line 2048 bytes at most:
  what podssh wrote to stderr, or to the file of `-E`, and the errors that
  `-q` hides. `relay` is the relay host of the run with its `close_code`
  and `reason`, or null. The lines that `podssh node`, `operator`, `chat`,
  `pipe` and `agent` write while they serve are not kept; a server's banner
  and the bytes of a session never are.
- **No credential.** A report never holds a token, a proxy URL or its
  password, a key, the environment, the command line as typed, or a byte
  of a session. podssh's messages hold none (`SECURITY.md`), and each line
  also goes through a mask: the value of each credential variable and of
  each proxy variable, with its user and its password, becomes `<hidden>`,
  so does the user and password of each URL, and the controls of a
  terminal are dropped, as in the lines of `podssh doctor`.

## Variables that a release stopped reading

podssh refuses a flag and a keyword that it does not take, by name and
with what to use instead; a `PODSSH_` variable that a release stopped
reading is refused the same way (T-634, GitHub #132), so that a service
whose file still sets it does not start, look healthy, and do something
else than its owner believes. `crates/podssh-cli/src/retired.rs` holds each
such name, the release that stopped reading it, what replaced it (or that
nothing did), and why.

- **A run.** While one is set to a value that is not empty, each command
  ends with 78 before it tries anything, with a line for each name on
  stderr: `podssh: NAME is no longer read (since vN): use OTHER instead;
  remove it (why)`. Its order is what the name is not, what took its
  place, what to do, and only then why. `--help`, `--version`, `podssh
  man` and a usage error still answer, so that `podssh man environment`
  can say what replaced the name. An empty value is unset, as for each of
  podssh's variables.
- **A service's file.** `--env-file` refuses one with its line and the
  same words (78), and `--install` leaves one out with a line. A unit
  stops on 78 (`RestartPreventExitStatus`), so an upgrade with a stale
  file is an outage at once rather than a setting that does nothing.
- **Only the table.** A name that podssh never read is not refused, so a
  stray variable of a shell changes nothing and a misspelt name is still
  ignored: this is never a list of allowed names. A name that a release
  reads again loses its row in that release; the manual's tests refuse a
  row whose name a source reads, or that the manual lists as read.
- **Empty.** No release has stopped reading a name: each `PODSSH_` name
  that the manuals and the sources of the releases from `v1.0.0-beta.1` to
  `v1.1.0-beta.2` read is read still (read on 2026-11-04). `podssh man
  environment` lists the rows, after the variables that are read.

## Exit codes

`podssh man exit-status` gives each code. The rules behind them:

- A usage error is 64 (`EX_USAGE`) for each command, before podssh does
  anything. A configuration error is 78 (`EX_CONFIG`): a variable of the
  environment that cannot be used, such as `PODSSH_RELAY` or
  `PODSSH_RELAY_ADDR` (also for `podssh ssh`). The same value as a flag is a
  usage error. The shell statuses 1 and 2 are not used for these, because a
  script cannot tell them from other programs' failures.
- `podssh ssh` uses the codes of OpenSSH, so it can replace `ssh` in
  scripts: the remote status unchanged (0 and 127 included), and 255 for a
  failure of podssh. A remote command stopped by a signal gives 128 plus the
  signal number (OpenSSH gives 255), and podssh names the signal on stderr.
- `podssh proxy` is not an SSH client: its failures use sysexits (64 to 78).
- `podssh cp` and `podssh mv` use sysexits too: 64 a usage error, 66 a
  source that is missing or cannot be read (for `mv`, also one that changed
  during the move), 69 no connection, or neither SFTP nor a copy by exec,
  70 digests that differ or a session that broke (the destination is
  unchanged), or a verified move whose source could not be removed, 73 a
  destination that cannot be written, 75 the `--timeout` passed, 77 a login
  or a host key refused, 78 a setting of the environment.
- `podssh chat` uses sysexits too: 0 when each message was acknowledged
  and the one thing of `--send` or `--file` is done, 64 a usage error, 66 a
  file of `--file` or `--sendfile` that cannot be read, 69 the relay out of
  reach, or a message with no acknowledgement, 70 a peer that broke the
  protocol, a failed channel, or a file that arrived damaged, 73 a missing
  `--accept-dir`, 75 the `--timeout` passed, or the peer talks with
  another, 77 a key or a pair refused, or the file of `--file` declined, 78
  a setting or a pair that cannot be used.
- `podssh ping` gives 69 when no relay host answers, and with a
  destination the codes of `podssh ssh`: 255 for a failure of podssh, and
  the status of the remote program of a measure (127 when the host lacks
  it).
- `podssh each` gives the largest status of its hosts: 0 only when each
  host gave 0, and 255 for a host with no session; 64 and 78 come before
  anything connects, and 73 when a file of `--output-dir` cannot be made.
- `podssh session` uses sysexits: 69 no session of that name, or one that
  ended; 75 a `--timeout` that passed; 77 a bind that the host refuses; 78
  `PODSSH_LISTEN=no`; and `start` gives 255 for a connection or a login
  that failed, as `podssh ssh` does.
- `podssh run` gives the status of its command, as `podssh ssh` gives it,
  and 255 when the copy failed, which runs nothing.
- `podssh job` uses the codes of `podssh ssh`: 255 for a failure of podssh,
  a host with no tmux or no such job among them. `job wait` gives the job's
  status, and 75 when its `--timeout` passed; `job fetch` gives 75 for a
  job that has not ended.
- A command that is not implemented exits 70. It never exits 0.
- A drop of the relay before any request reached the destination is tried
  again (T-025): during the SSH handshake or the login, before the
  command, the shell, the subsystem, `-W`'s connection, `-R`'s forwards or
  `-N`'s wait. A drop of the link to the relay goes to the next relay
  host, and one of the relay's link to the target tries once more (by the
  close, as `docs/relay.md` classifies it). A close at the relay's limits
  (1001, 1009) or for a backlog (1013), and each drop after a request, end
  the run with 255 as before: a command never runs twice. Each try says
  why on stderr, with the backoff of a failed upgrade; a try after the
  first asks nothing (a key that a passphrase opened and a password that
  the server took are used again), so a login that needs a prompt stops.
  The tries are at most `ConnectionAttempts` times the relay hosts.
- `podssh ssh` never ends as a success with no exit status (T-026). When
  stdout closes (EPIPE), podssh stops writing, sends the end of input, and
  waits 5 s at most for the status: it gives that status, or 255 with a
  note. `-N` ends only when the server or the network ends it: 255, with
  the server's words when it sent some. `-W` gives 0 when the far end
  closes and when stdout closes, and 255 when the connection died. These
  are the codes of OpenSSH's `ssh`, and the gate compares both clients
  (`scripts/interop-status.sh`). A status above 255 gives 255: OpenSSH passes the
  value to `exit()`, where 256 reads as 0.
- A link lost after the exit status and before the end of the output (the
  channel's EOF or its Close) is no success (T-461, GitHub #84): a server
  may send the status while its last output still waits for the window,
  and the relay's cap at 64 MiB can come between them. podssh exits 255
  with "the connection to HOST was lost before the output ended (the remote
  command had exited with N)", then the relay's close and its remedy; with
  the EOF before the cut, the status holds. OpenSSH's client gives the
  status there, but the bytes after the cut are lost, and a script reads
  the code. The copy by exec and the probes take the same rule, and so does
  a session through a control master, which then tells no status. Through
  the relay, once a session has carried 60 MiB (the relay's budget, or
  `PODSSH_SESSION_BUDGET`), podssh says once that the relay ends it at
  64 MiB and that `podssh cp` copies more on new sessions (not with `-q`).
- A session that does not open after the login says why (T-464, GitHub
  #104), and its open has `ConnectTimeout`: a refusal of the server in
  OpenSSH's words of its reason ("the server refused to open a session:
  open failed: administratively prohibited"); a connection that ended
  first is none: "the server ended the connection right after the login,
  before a session opened", then the server's words of its DISCONNECT, or
  the cause that russh gave, and a line of what it may mean (the far host
  may be stopped, the login may no longer be valid, or the server takes no
  more sessions). The copy by exec, SFTP, a control master's session and
  `podssh ping` read an open the same way, so a copy or a job never reads
  a connection that ended as a server that runs no command.

## Prompts and time limits

- Prompts (host key, passphrase, password, keyboard-interactive) go to the
  controlling terminal, as with OpenSSH. Thus
  `echo x | podssh ssh host cat` can still ask for a password.
  `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE` works as in OpenSSH.
- A key file is read in the format of OpenSSH, PEM (RSA or ECDSA), PKCS#8 or
  PuTTY, and its passphrase is asked when it is encrypted, in each of them
  (T-287): a PEM key of AES-128-CBC, AES-192-CBC, AES-256-CBC or
  DES-EDE3-CBC, as OpenSSH's `ssh-keygen -m PEM` and OpenSSL write them; a
  PKCS#8 key of PBES2, with PBKDF2 or scrypt, as `ssh-keygen -m PKCS8` and
  OpenSSL's `-v2` write them; and an encrypted PuTTY key. A key that no
  passphrase would open (DSA, a PEM key of another cipher, a PKCS#8 key of
  PBES1 or of a scheme of PKCS#12) is skipped before the question, and
  podssh says why.
- With no terminal and no askpass program, a prompt becomes a refusal that
  names the remedy. For an unknown host key: its fingerprint and
  `-o StrictHostKeyChecking=accept-new`. For a password: a key file.
- podssh asks on `/dev/tty` only when the kernel names it as the controlling
  terminal: the descriptor is a terminal of this process's session, and
  `/proc/self/stat` (when it can be read) names a terminal. In a measured
  sandbox, `/dev/tty` opened with no controlling terminal, and a read
  blocked for ever.
- When stdin, stdout and stderr are all redirected, a prompt on the terminal
  waits 60 s at most (`terminal::UNWATCHED_PROMPT`), then refuses with the
  remedy. A person at the terminal can still answer; a terminal that nobody
  watches does not stop podssh for ever. So does a console of Windows since
  T-588: a console with no window, as an agent's, opens, and its question
  waited for ever (GitHub #114). A key is the console's answer; a focus, a
  mouse or a size is taken from it, and the wait goes on.
- `-o BatchMode=yes` makes each prompt a refusal.
- A changed host key is refused, also on a terminal.
  So it is under `StrictHostKeyChecking=no`, where OpenSSH warns, turns off
  passwords and forwarding, and logs in with a key (T-225).
- A host that a `@cert-authority` line names is asked for a host
  certificate (T-027), which is checked as OpenSSH checks it: from a CA of
  such a line, signed, within its validity window, a host certificate,
  with the host (or `HostKeyAlias`) as a principal, and no critical option.
  Then it is accepted, also under `StrictHostKeyChecking=yes`, and nothing
  is recorded. A certificate that fails a check is refused with the check
  (an expired one names this host's clock, which `podssh doctor` checks),
  and one from a CA that no line names is checked as its plain key. podssh
  asks for a principal where OpenSSH takes a certificate with none.
- Under `accept-new` and `no`, a key that podssh cannot verify is refused
  (T-028): one that no readable file knows while a user `known_hosts` file
  exists and cannot be read (a directory, a FIFO, no permission), as a key
  recorded there is not seen. OpenSSH reads a directory there as empty, and
  logs in (T-225). A key that is accepted and not recorded
  (`HOME` is not set, `UserKnownHostsFile none`, or the write failed) holds
  for this connection only, and podssh says so: the next run cannot tell a
  changed key from a new one. `UserKnownHostsFile /dev/null` reads as empty.
- Two runs that meet a new host at once record its key once (T-029): the
  first user file is locked for the write, and read again under the lock. A
  second key of the type that another run recorded meanwhile is refused as
  changed. The lock refuses no reader, OpenSSH included: an advisory `flock`
  on Unix, and on Windows one byte past any end of the file.
- A duration is parsed as a whole string. A malformed duration is an error,
  never zero. A time limit applies to the whole operation, not only to the
  dial.
- `PODSSH_TIMEOUT` gives `--timeout` its default, for each command that has
  the flag (GitHub #12): the flag wins, and an empty value is no value. A
  bad value of the variable exits 78 and names it; a bad `--timeout` exits
  64. It never bounds `ssh`, which has no `--timeout`. For `operator`,
  `proxy` and `pipe`, whose `--timeout` is another name of
  `--ConnectTimeout`, it bounds the session's open alone, and is never
  required (T-613). A command that is not implemented exits 70 first.
- `ConnectTimeout` (60 s by default) limits the SSH handshake, and each
  answer of the server while podssh logs in: a server that stalls after the
  key exchange ends the run with 255 and names the request that it did not
  answer. A prompt runs before its request, and the time that the agent
  spends signing (`ssh-add -c`) does not count, nor does the time of a
  security key, whose touch has 30 s (T-229). Nor, since T-588, does the
  question of a new host key, which runs inside the handshake: the
  handshake's limit stops while it waits, and the question has its own
  bound, as each prompt has.
- A handshake that does not finish within `ConnectTimeout` names what came
  (T-588, GitHub #114), one form for each case: "HOST: the SSH handshake did
  not finish within N s: no byte came from the server"; "... N bytes came
  from the server, with no SSH version line: the first line was "TEXT"";
  "... SSH-2.0-OpenSSH_10.0p2 came, then nothing after this side's KEXINIT";
  "... VERSION came; the last messages were the server's KEXINIT and this
  side's KEX_ECDH_INIT". Through a node, the far end is the node's TARGET
  after the layer opened, and the bytes of the layer and of the end-to-end
  channel follow each way: "(through the layer: N bytes from the node, M
  to it; through the end-to-end channel: N from it, M to it)", or "the
  resumable layer to the node did not open". The record reads the stream
  between russh and the road (`crates/podssh-ssh/src/handshake.rs`): the
  lines before the version line, the version line, and the header of each
  packet up to NEWKEYS, after which the packets are encrypted.
- 10 s into a handshake that has not finished (through a node, 10 s after
  its layer opened: the node's own bound on its TARGET's answer), one line
  says where it is, as above, and that it waits until `ConnectTimeout`; so a
  long `ConnectTimeout` is no long silence. While the question of a host
  key waits and none of stdin, stdout and stderr is a terminal, the line
  says that the question waits, its bound, and
  `-o StrictHostKeyChecking=accept-new`; a person at the terminal gets no
  line in the middle of the question.

## `ssh_config` (milestone M8)

`podssh ssh` reads `~/.ssh/config` and then the system's file
(`/etc/ssh/ssh_config`, `%ProgramData%\ssh\ssh_config` on Windows), or only
the file of `-F FILE`, or of `PODSSH_SSH_CONFIG` when `-F` is not given;
`-F none` reads no file (T-043, T-044).
So do `cp`, `mv`, `scp`, `sftp` and the `ssh:` address of `pipe`, which reach
a host as `podssh ssh` does. A line goes through the same parser as `-o`,
and an error names the file and the line. The command line beats the file:
`-l`, `-o User` and `user@host`, then the file's `User`; `-p`, `-o Port` and
`host:PORT`, then the file's `Port`. A missing `-F` file exits 78; a missing
`~/.ssh/config` is no error. On Unix, `~/.ssh/config` must be the user's or
root's, and no one else may change it, checked on the file that a link
names; a file that `-F` names is the user's choice, and is not checked.
`ProxyCommand podssh proxy %h %p`, which a user of OpenSSH writes for
podssh, is accepted, as `podssh ssh` takes that road anyway, and so is
`ProxyCommand none`; `-v` names the file and the line of one that podssh
does not run. The first `ProxyCommand` holds, as OpenSSH reads the first
alone (T-502): either value, on the command line or in an earlier block,
goes past a later block's command, so `-o ProxyCommand=none` goes past a
`Host *` that names a jump host for OpenSSH, and keeps each other setting
of the file; it holds for each hop of `-J` too. A `ProxyJump` after the
`ProxyCommand` that holds is not read, as OpenSSH 10.3p1's `parse_jump`
does not read it then (`readconf.c`); one given before it keeps its hops.
A command with no value before it is refused with its file and line (78),
and the refusal names `-o ProxyCommand=none` (Q70); `cp`, `mv`, `scp`,
`sftp` and each verb that reaches a host read it the same way. `Include` is
read where it stands, with each file that it reads checked as
`~/.ssh/config` is. A `Match` line starts a block that applies when each of
its criteria holds (T-045): `all`, `host`, `originalhost`, `user`,
`localuser`, `tagged`, `command`, `sessiontype`, `version` (it matches
`OpenSSH_10.3p1`, the release whose reading podssh follows), `final` and
`canonical`, each with `!`, and each with a comma list of patterns but the
last two and `all`. `Match exec` and `Match localnetwork` are refused by
name with the file and the line (78), and run nothing, where they would
decide the block: podssh runs no program for a configuration, and probes no
interface. `Tag` and `-P` set the tag of `Match tagged`. The keywords of the GSSAPI patch of Debian and Fedora
(`GSSAPIKexAlgorithms` in Fedora's crypto policy) are accepted with no
effect, as podssh has no GSSAPI. The rest of Fedora's crypto policy
applies (T-505): its `Ciphers`, `MACs`, `KexAlgorithms`,
`HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, `CASignatureAlgorithms`
and `RequiredRSASize`, read in the final pass of its `Match final all`,
restrict what podssh offers as they restrict OpenSSH, with no note, as
they come from the system's file.

Each hop of `-J` or `ProxyJump` reads the blocks of its own name, as
OpenSSH's jump host does (T-290): its `HostName`, `Port`, `User`,
`IdentityFile`, `HostKeyAlias` and the settings of its host keys and login.
Its `user@` and `:PORT` beat the file; with neither a `user@` nor a `User`,
the hop logs in as the local user, never as the destination's: `-l`, `-p`
and the destination's blocks are the destination's alone. The `ProxyJump` of
the first hop of a list puts its own chain before it; a later hop's is not
read, as OpenSSH gives that hop the hops before it as its `-J`. A chain that
comes back to a hop is refused (64), and so is one of more than 16 hops. The
settings of host keys, authentication, keys and time of `-o` and `-i` hold
for each hop too, where OpenSSH's command line holds for the destination
only.

These are the rules of OpenSSH 10.3p1, measured with `ssh -G`, and podssh
follows them; `crates/podssh-cli/tests/ssh_config_file.rs`,
`crates/podssh-cli/tests/ssh_config_include.rs` and
`crates/podssh-cli/tests/ssh_config_match.rs` hold OpenSSH's results:

- The first value obtained wins, from top to bottom. The most specific block
  does not win.
- A `Host` pattern matches the host as typed, with its case: `Host MyHost`
  does not apply to `myhost`. A negated pattern excludes the host from that
  block only, and a line of negated patterns alone matches nothing.
- `IdentityFile` and `-i` add up; they do not replace each other.
- A `#` that starts a word outside double quotes starts a comment, also
  after a value.
- `IgnoreUnknown` holds for the keywords after it. Only the first one
  counts, and `-o IgnoreUnknown` beats the file's.
- `HostName` takes `%h`, the host as typed, and `%%`; another token is an
  error. The result is lowercased.
- `Include` is expanded where it appears, its arguments in order and the
  names of a glob sorted; a wildcard may be in a directory part too. A
  relative `Include` starts from `~/.ssh` (a user's file, also one of `-F`)
  or `/etc/ssh` (the system's), not from the directory of the file that
  includes it. It takes `~` and each `%` token but `%T`, with the values of
  the moment: `%p` the port of `-p` or of an earlier `Port`, else 22; `%r`
  the user of `-l` or of an earlier `User`, else the local user; `%h` an
  earlier `HostName` as written, else the host as typed.
- A file that an `Include` reads is checked as `~/.ssh/config` is, also
  from a file of `-F`. A missing file is no error, and a directory that a
  glob names is skipped. A `Host` line in an included file holds to the end
  of that file. A chain of more than 16 includes is an error.
- `*` matches across dots.
- `Match` never overrides a value that is already set. Its block applies
  when each criterion holds. `host` and `originalhost` match with no regard
  to case, the others with it, and `criterion=patterns` reads as `criterion
  patterns`. `host` is the host after a `HostName` read so far, also one
  that a `Match` block set; `user` is the user of `-l`, `-o User` or
  `user@host`, else of a `User` read so far, else the local user; `tagged`
  with no tag, and `command` with no command, match `""`. `RemoteCommand` is
  no command for `command` and `sessiontype`. `all` stands alone, or after
  one criterion: `Match all host h` is an error.
- A `Match` with `final` and no `!`, also one whose other criterion fails,
  asks for a final pass: each file is read again, `Host` lines and `Match
  host` see the host after `HostName`, lowercased, `final` and `canonical`
  hold, and the blocks that apply then fill what is still unset; a
  `HostName` in that pass is not taken. A `HostName` alone asks for no final
  pass, and with none `canonical` never holds. A key file and a forward
  given twice are kept once, `SendEnv` adds up, and the first `SetEnv` line
  holds whole.
- Debian 13 starts its system file with `Include
  /etc/ssh/ssh_config.d/*.conf`; Fedora 42 includes its crypto policy from a
  `Match final all` block.
- A missing `-F` file is an error (255), and `-F` stops the reading of each
  other configuration file. A missing `~/.ssh/config` is not an error.
- `~/.ssh/config` that is another user's than the user's or root's, or that
  the group or others can change, is an error; a link is followed. A file
  of `-F` is not checked.

One difference, on purpose: OpenSSH checks each line, also in a block that
does not apply. podssh reads only the blocks that apply, as it refuses some
keywords that OpenSSH runs (`LocalForward`), and a block for another host
must not stop each connection.

NOTE: In its recommended parsing mode, `ssh2-config` 0.8.1 drops
`ProxyCommand` and `StrictHostKeyChecking` silently (read 2026-10-01). Do not
use it.

## The status of the net

`podssh ping NAME`, `podssh status --net` and the sections `carriers` and
`net` of `podssh doctor` (T-435, milestone M10, [mesh.md](mesh.md)) are
Tailscale's `ping`, `status` and `netcheck` for the net of `podssh net`.

- **`podssh ping node://NAME`**, and `podssh ping NAME` of a member with the
  role `node`, read as `podssh ssh` reads the destination, race the roads
  that `ssh` races to that node, chosen as it chooses them, in its order and
  with its delays (`crates/podssh-cli/src/ssh/road_probe.rs`): the pair's
  road, with the Piping Server road behind it when no other road races, as
  `ssh` takes the pair's road alone; and the iroh road, the DERP road, the
  OpenTunnel road, the record's roads and the transit road where `ssh` has
  them. The race is measured, not won: each road that starts runs on to the
  far end's first bytes, so each has its time
  (`crates/podssh-relay/src/session/race.rs`, `each_timed`); a road whose
  wait came after another answered still starts at its wait, as the race
  would have started it had the first been slow; a fallback that waits for
  each road before it to fail does not start once one answered, and says so.
  The road that answered first is the first far end that spoke, from the
  start of the race, as `ssh -v` names it. The whole measure has a bound of
  45 s, above each road's own limits.
- **What `ping NAME` opens.** Each road that starts opens its one connection,
  as a race of `ssh` opens it, and its link ends as soon as the far end
  spoke, before a byte is sent on it: no `OPEN`, so the node opens no session
  and dials nothing at its TARGET, and no end-to-end channel is made, as no
  session goes above the roads. Nothing logs in, so `ping NAME` needs no key
  of the node's server; the login, the echo and the throughput stay a host's
  measures, and `--size`, `--count` and `--target` with a node are 64.
- Its lines: one for each road, `node://NAME: ROAD: answered in T ms`, with
  `, started S ms into the race` for a road that did not start first, or
  `failed after T ms: WHY`, or `not started`; then `node://NAME: ROAD answered
  first, in T ms`, or `node://NAME: not reached: no road answered`. `--json`
  gives one object: `node` (`name`, `roads`, each with `road`, `started`,
  `started_ms`, `ms`, `answered` and `error`, then `won` and `won_ms`) beside
  `schema`, `podssh`, `relays` (empty), `destination` (null) and `exit`. 0
  when a road answered, 69 when none did or with `PODSSH_OFFLINE`, the
  refusal's code of the node's resolution before anything connects.
- **The record of the roads** (`crates/podssh-cli/src/net/reached.rs`).
  Each race to `node://NAME` keeps its end in `net-roads.json` in the cache,
  by the label: the road that answered first, its time and when, written by
  `ssh`'s race and each of its resumes, a copy's race, `ping`, and the
  pair's road alone where `ssh` and the copies take it; and the race that
  found no road, with why. At most 256 labels, the oldest word going first;
  two runs at once may each lose the other's word, which costs a status line
  its newest race and nothing else. It holds no secret.
- **`podssh status --net`** (`crates/podssh-cli/src/net/state.rs`). The line
  of `status` has `net` in each run: the net held, read with no connection
  (`name`, `serial`, `owner`, `expires_ms`, `ended`, `file`, `count`), null
  when this host holds none or `PODSSH_NET=no`, and `error` when its file
  does not read, which never stops the line. With `--net`, `net.members`
  too: each member's `name`, `roles`, `key` (its fingerprint), `tickets`
  (their kinds, never a ticket) and `routes`, and of the record `reached`
  (`road`, `ms`, `ago_s`), `missed` (`why`, `ago_s`) and `last`, `reached` or
  `missed`, whichever came last, or null. `status` still opens no connection
  and writes nothing.
- **`podssh doctor`'s section `carriers`** (`crates/podssh-cli/src/doctor/carriers.rs`):
  the public carriers of Q65 that this host reaches, as the roads of a node
  try them unasked, one connection through the proxy each, one after
  another: the transit relay of `PODSSH_TRANSIT` (Least Authority's), its
  WebSocket opened and closed with no line said, so that it pairs nothing;
  each mailbox of `PODSSH_PAIR_MAILBOX` (magic-wormhole's, then Least
  Authority's), its welcome read and podssh's application bound, no
  nameplate claimed; and the Piping Server of `PODSSH_PIPING` (`ppng.io`),
  asked its `/version`, which waits for no sender. A variable's `no` asks
  none of its carrier (`????`), a value that its road refuses is `FAIL`. The
  Wisp demo server is a forwarder: the line `fallback` names it, and
  `--forwarder wisp` asks it.
- **The section `net`** (`crates/podssh-cli/src/doctor/members.rs`): the net
  held, read with no connection, `FAIL` for a file that does not read or a
  net that ended; then `/health` of each member with the role `relay`, at
  most 8, one after another, at the host that its object names in the
  document (the field `relay`, T-617), verified with doctor's trust, as the
  relay section asks the relay hosts; one with no host is `????`. With
  `PODSSH_OFFLINE`, the net's line comes and no member relay is asked.
  `--quick` leaves out both sections.
