//! The notes of `podssh relay`: the pairs (T-083), the document (T-060),
//! the relay's own state (T-058) and the relay role (T-169, T-427), with its
//! certificate (T-447), apart from the others so that each file stays short.

pub const RELAY: &[&str] = &[
    "podssh relay pair NAME makes a pair on the relay and keeps it under the label NAME, in a private \
     file of the cache (see FILES). It prints the label and when the pair expires, 72 hours later, and \
     never a token. With --operator-file, the operator's part of the pair, its connect token alone, \
     goes to FILE, a new file that only its owner can read: give it to the operator by a channel that \
     you trust. On stderr it says the way past the expiry: in its last 24 hours, podssh relay pair NAME \
     --operator-file NEW makes the next pair, which the node takes at the expiry, and NEW goes to each \
     operator; stdout keeps its one line.",
    "A pair under NAME with more than 24 hours left is not replaced: stop it first with podssh relay \
     revoke NAME. In its last 24 hours, the next pair is made and takes its place in the store, and a \
     node of NAME that runs takes it at the expiry, with no new start (see podssh node); the old pair \
     can no longer be stopped, and ends at its expiry. The default relay renews no pair, so each node of \
     a pair needs the next one every 72 hours. revoke stops the pair on the relay and deletes the stored \
     copy; when the relay cannot be reached, the copy is kept, because its stop token is the one way to \
     stop the pair before it expires.",
    "podssh relay pair --renew NAME renews the pair stored under NAME at the relay that made it, 72 hours \
     from now and never less than it had, with the same three tokens, so that each operator's file keeps \
     working and the node goes on with no next pair; podssh relay serve renews, by the stop token, which \
     the pair's owner alone holds, as often as asked. It prints the label and the new expiry, and the \
     store keeps it. A relay that renews none (the default relay's contract has no such request: its \
     answer is 404 or 405) is said so, with the next pair of the last 24 hours as the way, and the exit \
     is 69; a refused stop token (403) is a pair that was stopped or ended (77). --operator-file and \
     --relay-host are refused with it (64): the operator's file is never touched, and its end is asked \
     of the relay once the file's has passed.",
    "podssh relay status NAME says whether the pair's node is online, its sessions, and when the pair \
     expires, as the relay names it where it does (podssh relay serve, whose renewal moves it), else as \
     the file does; in its last 24 hours, how long is left too (expires in 5 h, at ...). On an operator's host, \
     which stores no pair, podssh relay status --pair-file FILE [NAME] asks the same of the pair in FILE, \
     or of its operator's part, which podssh relay pair --operator-file writes: the relay answers the \
     status to its connect token. NAME is then only the label shown (else FILE). With --json, the pair's \
     state is one object: schema (1), podssh, label, online, sessions, expires (RFC 3339) and \
     seconds_left, for a check.",
    "podssh relay spec reads the relay's /health and its published document, /llms-full.txt, and checks \
     the document against the facts that podssh was built with (see RELAY FACTS). It prints ok, with the \
     document's lines, its digest and the version that the relay serves, or a FAIL line for each fact \
     that disagrees, and exits 1: the relay changed something that podssh depends on. With --document \
     FILE, it checks FILE and reads nothing from the network.",
    "podssh relay status with no NAME asks each relay host for its /health, one after the other, and \
     prints a line for each as it answers: the relay's version, the edge that answered, the time, the \
     TLS version and how the connection was made, or why it failed. It needs one host that answers.",
    "podssh relay info reads /relays.json from the first relay host: the edge that this host reaches, \
     the pool in the relay's order with its rank and its estimate of each round trip, and the limits of \
     a session. The relay makes that order from the edge that served the request, so two calls can \
     disagree, and neither measures this host's path: podssh relay status times the hosts that podssh \
     tries, and podssh ping --relay-host HOST times one, from this host. With --json, the relay's fields \
     are unchanged, and pool_order says whose order it is and from which edge. With HOST PORT, also the \
     URL that the relay chooses for that target.",
    "podssh relay rank measures each relay host from this host, one at a time, and keeps the rank: the \
     default host and each host of its pool (the pool read first when none is cached), or the hosts of \
     --relay-host. Each round probes each host in a new random order, 250 ms apart, with a session to \
     github.com:22 (--target HOST:PORT for another) that sends no byte, and times the dial, TLS and the \
     upgrade, the token's time left out, then --count pings; --rounds rounds, 3 by default, within 10 \
     minutes. The hosts go in the order of the share of probes that failed, then the median time to \
     open, then its p95; two medians within 50 ms or 10 % keep the order that the hosts came in. A line \
     for each probe goes to stderr, and the rank to stdout, best first, or as one object with --json. \
     The rank is a private file of the cache, relay-rank.json, with no token and no name of the proxy: \
     the egress is a digest of the proxy's host and port, or direct, and the rank holds 24 h for it. \
     --cached prints the rank kept, its age and whether it holds here, and --forget removes it; neither \
     connects. Exit 0 when a host opened, 69 when none did or PODSSH_OFFLINE is set, 64 for a bad flag. \
     podssh probes no host that the user did not ask it to, unless RelayRank auto asks (Q89, below).",
    "The default list of relay hosts takes the rank (T-607): while a rank of podssh relay rank holds for this \
     egress, the default list is the default host and the best three other hosts of the pool, in the rank's \
     order, and a run tries the default host at its place among them; the record of failures still moves a \
     host that failed lately to the end. Each run also keeps the time to open of each host that opened in \
     its race, the last 8 of each, with no connection of its own; where no rank holds, those times order the \
     pool. A list that the user names (--relay-host, PODSSH_RELAY, RelayHost) keeps its order. \
     PODSSH_RELAY_RANK=no, or RelayRank no in the settings file, gives the relay's order of the pool, as \
     before; podssh status says which order a run takes (relay_order), and podssh doctor's line rank names \
     it with the list.",
    "A rank in a session's background (T-608) comes only when the user asks for it, with RelayRank auto in \
     the settings file or PODSSH_RELAY_RANK=auto, never by default (Q89). Then, when no rank holds for this \
     egress, a session of podssh ssh that the default list carries probes the default host and the hosts \
     of its pool, 8 at most in a day, in its own process, one at a time: the first after the session ran \
     60 s, then one each 10 s at most, none while a race of relay hosts runs, none with PODSSH_OFFLINE, \
     and none past the session's end, which drops a probe in flight. Each probe is a session to \
     github.com:22 with ?dial=lazy that sends no byte and three pings, so the relay dials no target and \
     the time to open is this host's leg alone. The rank is kept after each probe, source background, and \
     the default list takes it as it takes one of podssh relay rank; a session that ended first leaves it \
     partial, and the next session of the day goes on with the hosts that it lacks. A rank that holds, \
     of either source, makes no new one for 24 h. podssh proxy, pipe, cp and the other commands make \
     none. podssh status gives relay_rank_auto (asked, by, last_ms, last_age_s, partial), and podssh \
     doctor's line rank names the setting and when the last background rank was made.",
    "podssh relay trace HOST PORT asks the first relay host to dial the target and to read its first \
     line, with a forward token in a header and never in the URL: the relay's verdict (live, or \
     silent-or-unreachable for a target that sent nothing), the address that it dialed, the times of \
     the connection and of the first byte, and the banner. A target that the relay will not dial (a \
     blocked range, a name with no address) gives the relay's reason. It tells a target that is down \
     from a relay that cannot be reached. The relay's view of this host's address and place, which it \
     sends too, is never shown.",
    "With --json, status, info and trace write one JSON object on stdout when the run ends: schema (1), \
     podssh, and the answer: each host for status with no NAME, the pair's state for status NAME or \
     --pair-file, the relay's /relays.json as it came for info, and the relay's view of the target for \
     trace. The exit codes are in EXIT STATUS.",
    "podssh relay serve is the relay itself, as a role of podssh: it serves the relay's forward road, \
     the contract that podssh speaks (version 2026-10-03-r2), on --listen ADDR:PORT, with TLS from \
     --cert FILE and --key FILE (a P-256 key in PEM) or from --acme NAME, so that each podssh reaches \
     it with --relay-host and the CA that signed its certificate. It serves /health, /v1/mint, \
     /connect/HOST/PORT, /relays.json, /trace and /llms-full.txt, dials a target only once its name \
     resolves to public addresses (--allow-private dials the others too), refuses port 25, and keeps \
     the default relay's limits: 180 s with no payload, 12 hours and 64 MiB a session. --mint anyone \
     mints a token for each client; by default it mints for no one (503), as its tokens are given \
     another way. A token lives until the relay stops. Each mint, upgrade and client's Close is a line \
     on stdout. It listens because you ask it to, and PODSSH_LISTEN=no refuses it; Ctrl-C or SIGTERM \
     stops it.",
    "Where HTTPS_PROXY (or https_proxy, all_proxy, ALL_PROXY) is set, the relay dials each target \
     through that proxy, as each client of podssh reaches its relay, by HTTP CONNECT or SOCKS5; the \
     loopback, and what NO_PROXY names, go directly. Its policy checks each address of a name as it \
     resolves on this host, and the proxy is asked for each checked address, never for the name, so a \
     proxy that resolves the name otherwise reaches nothing unchecked; with --allow-private, which \
     checks nothing, the name goes to the proxy as it came, so a host with no DNS reaches each target \
     that its proxy reaches. A proxy's refusal is the relay's 502, with the proxy's status, in words \
     that never say where the proxy is; the relay's own line on stdout names it, and never its \
     credentials. /trace names the road proxy and its kind. The first line on stderr names the proxy \
     by its host and port, and a proxy that cannot be read stops the start (78).",
    "The relay dials an IPv6 target where its host routes IPv6 out. Where it does not, as the table \
     of routes that Linux gives as a file says (/proc/net/ipv6_route), or else as a dial that met no \
     route in the last minute, the target gets 502 before the upgrade, also with ?dial=lazy: this \
     relay's host has no IPv6 route out, and a client tries its next relay host. A name of both \
     families keeps its IPv4 addresses; the loopback is the relay's own; through HTTPS_PROXY the \
     proxy decides. /relays.json says what the relay knows, as egress.ipv6: true, false, or null.",
    "Beside the contract it serves /v1/layer/HOST/PORT, the forward road in the resumable layer, for a \
     target that speaks no layer, a standard sshd among them (T-173): each WebSocket is one link, the \
     relay dials the target once, after the layer's handshake of a new session, and keeps it while the \
     client's link is lost, until a resume on a new link to this relay carries the session on, or 10 \
     minutes pass and the target is shut. The token, the upgrade and the policy are checked as on \
     /connect/, with the same refusals; the layer's secret never crosses the relay, as each resume \
     proves it, and the path names the target alone. Each link keeps the limits of a session, and the \
     client moves the session to a new link before them. The sessions hold 256 MiB of replay buffers at \
     most, 4 MiB each; past it a new session is refused with what holds them, a line on stdout once a \
     minute. /relays.json offers it as forward.layer: true, and podssh proxy takes it with \
     PODSSH_RELAY_LAYER=yes. A restart forgets each session.",
    "It serves the reverse road too: /v1/pair, for whom it mints, /v1/node/NAME, /v1/connect/NAME, \
     /v1/status/NAME and /v1/stop/NAME, so that podssh relay pair --relay-host, podssh node and podssh \
     ssh node:// work through it with no other relay. A pair lives 72 hours, and /v1/renew/NAME, with \
     the stop token, gives it 72 hours from then with its tokens, as often as its owner asks (podssh \
     relay pair --renew, and its node in its last day); /v1/status/NAME names the expiry beside the \
     contract's fields. --pairs FILE keeps the \
     pairs in FILE, a file of mode 0600 that holds the digests of their tokens and never a token, so \
     that they outlive a restart. At most 1 MiB waits for a slow operator: past it, the session ends \
     with 1011 relay backpressure, and the node's other sessions go on; a node that reads slowly slows \
     its operators instead. A frame of the node for a session that ended in the last 2 seconds was on \
     its way, and is dropped; one for an id never given closes the node's socket with 1003, as the \
     contract says. Ctrl-C or SIGTERM first closes each socket of the reverse road with 1012, so that \
     each node connects again and each session resumes once the relay is back with its pairs: each \
     socket gets the frames that wait for it first, 1 second at most, and the role waits for each \
     answer to its Close, 3 seconds at most in all; a node or an operator that comes meanwhile gets \
     503 and tries again. Where \
     nothing may listen, the node of a quick tunnel serves the same roads behind its tunnel, with no \
     listener, and the tunnel's name is the relay host: see podssh node --relay.",
    "--mint keys:FILE mints tokens and makes pairs for the keys of FILE alone, a list in the format of \
     podssh node --allow, read again for each request. A request with no key gets 401 and a challenge \
     of the relay's, which lives a minute; podssh then asks once more with the key of this client \
     (client.key in the cache, the key that a node's list lets in), the challenge and the key's \
     signature of them, of the relay's name and of the path. A key that is not on the list, a \
     signature that does not verify, a challenge that ended or was answered before, and a request \
     whose Host is not the name that its TLS asked for each get 403, which names the key's \
     fingerprint for the owner's list. podssh caches the token as any other.",
    "--mint net mints tokens and makes pairs for the members of the net that this host holds (see podssh \
     net), each by the same signature with the key that the net names for it; --mint net,keys:FILE for \
     those and the keys of FILE. The document is read again, and its owner's signature checked, for each \
     request: a member that a newer document removed is refused from that serial on, and a token that it \
     minted before lives until its end or the relay's stop, as a token of a list's key does. Where the net \
     has a policy, a member mints only where a rule lets it reach relay:*, as podssh relay serve is no \
     member of the net; the relay behind a node's quick tunnel is reached by relay:NAME too, NAME the \
     node's name in the net; with no policy each member mints. A host that holds no net, or one that \
     ended, does not start (78). The 403 of a key that is no member names the key and the document's \
     serial, never the net or its members, which a member's refusal by the policy names.",
    "The certificate and its key are read again on SIGHUP, and when either file changes, which the \
     role looks at each minute; on Windows, which has no SIGHUP, that is the way. The handshakes after \
     the read take the new pair, and each session that is open goes on with its own. A pair that does \
     not load, or whose key is not the key of its first certificate, is said on stderr, and the pair \
     of before stays. The role takes SIGHUP for this, so SIGHUP no longer stops it.",
    "--acme NAME takes a certificate for NAME from an ACME CA (RFC 8555): Let's Encrypt, unless \
     --acme-directory URL names another, such as a CA's staging directory or Pebble for a test, whose \
     own certificate --ca-file names. The CA validates NAME by TLS-ALPN-01 (RFC 8737) on the role's \
     own listener, so nothing else listens: NAME must resolve to this host, and the CA's connection to \
     its port 443 must reach --listen. A new account agrees to the CA's terms, which the role names as \
     it makes the account. The account's key, and the certificate with its own P-256 key in one file, \
     are kept in the cache (acme/, see FILES), each of mode 0600 in a directory of mode 0700, so that \
     a restart serves the certificate kept and asks the CA for nothing; PODSSH_CACHE_DIR=none refuses \
     --acme (78), and so does a cache with no directory that can be made private (73). The role renews \
     the certificate 30 days before its end, or at a third of its life left for a shorter one, with a \
     new key, and the next handshakes take it. A renewal that fails is said on stderr and asked again \
     after 5 minutes, then twice as long each time up to 6 hours, and the certificate of before stays. \
     When no certificate is kept and the first order fails, the role stops with the CA's reason (69). \
     SIGHUP reads the file kept again.",
    "The relay brakes /v1/mint and /v1/pair for each address, as the default relay does: 120 requests \
     of one address within a minute, the two together, and then 429 with Retry-After, the seconds \
     until the oldest of them is a minute old, which podssh says. The address is the connection's own, \
     never a header that a client sends; an IPv6 address counts by its first 64 bits. The relay counts \
     4096 addresses at most, and forgets the one heard from least lately first. /health, the documents \
     and the sockets of both roads are not braked, and the first refusal of an address is a line on \
     stdout.",
    super::notes_grant::RELAY,
    super::notes_doctor::RELAY_PROBES,
];
