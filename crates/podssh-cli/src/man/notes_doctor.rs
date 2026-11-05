//! The notes of `podssh doctor` for the time of a run (T-511): its sections
//! at once, `--jobs` and `--quick`; its diagnosis of the TLS handshakes
//! (T-487); its line of the NAT's mapping (T-641); its line of IPv6 targets (T-253); its line of a request with no
//! TLS (T-326); its line of HTTP/2 (T-321); its section of an exit (T-458);
//! and its probes of what a path does to a stream (T-325), with the relay
//! role's side of them. Apart from the others so that each file stays short.

pub(super) const DOCTOR_AT_ONCE: &str = "The sections that connect run at once by default, each into its own part \
     of the report, and the report keeps its order: a section's lines go out once each section before it has ended, \
     the first one that still runs line by line, so a run takes about as long as its longest section, not their \
     sum. Each section reaches its servers one at a time, as before, so a run holds at most one connection for each \
     section that runs (the egress, the relay, OpenTunnel, DERP, the public carriers, the net's member relays, and \
     each road that it names), with the one UDP socket of the line nat, and the relay's \
     forward races its hosts as podssh ssh does. --jobs N, or DoctorJobs N in the settings file, starts at most N \
     sections together, in the order of the report; --jobs 1 runs one after another.";

pub(super) const DOCTOR_QUICK: &str = "--quick checks this host, the egress and the relay alone, what each run of \
     podssh ssh and podssh proxy needs, with the section of each road that the run names (--forwarder, \
     --shadowsocks, --via, --vless). It leaves out the quick tunnel's edge (the lines quick tunnel roots, UDP out \
     and edge road), the line nat, iroh and tor in a build with them, OpenTunnel, DERP, the public carriers, the \
     pairs and the net held; its last line, sections \
     in the section left out, names them, as ????: checks that did not run.";

pub(super) const DOCTOR_DIAGNOSIS: &str = "The line TLS reference makes TLS with github.com on port 443 by its \
     name, its certificate checked, straight out with no proxy, else over the CONNECT that the proxy took for it, \
     and says what it met: a handshake, a reset or a timeout. After the counts, a line diagnosis names a case that \
     the handshakes of the roads (each relay host, each DERP server, each resolver of DNS over HTTPS with no \
     proxy, each relay of n0's in a build with iroh) show beside it, and counts as nothing: each \
     relay host reset while github.com's completed is an egress that resets TLS for each name that it does not \
     list, where a road through a listed name serves (--forwarder, --via, a relay of your own); each handshake \
     reset, github.com's too, is an egress that resets each one on port 443; each timed out, github.com's too, is \
     a path that drops them, not one that lists names; a resolver, asked by its address with no name, that \
     timed out says nothing of names. A reset and a timeout are read from the kind of the error, \
     never from its words, which differ between systems. With --json, diagnosis lists each, with kind (tls-names, \
     tls-reset or tls-dropped), detail and evidence, the names that show it.";

pub(super) const DOCTOR_NAT: &str = "The line nat, in the section egress, says whether the NAT in front of this \
     host keeps one mapping for a local port whatever the destination (T-641): one UDP socket of port 0 asks two \
     STUN servers in turn for the address that each saw, a Binding Request of RFC 8489 with 3 tries of 1 s, an \
     answer taken only from the address asked and with the request's id. The servers by default: Cloudflare's \
     stun.cloudflare.com:3478, which its Realtime TURN documentation names, then Google's stun.l.google.com:19302, \
     which WebRTC's samples name; PODSSH_STUN names others, or no turns the line off. Both saw this host's own \
     address: no NAT. Both saw one address: one mapping for all destinations, so a peer that learns it may reach \
     this host directly (hole punching can work). Two addresses: a mapping for each destination, where hole \
     punching will not work and the relays carry each session. Each is ok, a fact; ???? with fewer than two mapped \
     addresses (a server silent, or one that answered with none or with an error, each named) and where no UDP \
     socket binds. UDP goes straight out, as no proxy carries it, whether a proxy is set or not; PODSSH_OFFLINE \
     sends nothing.";

pub(super) const DOCTOR_IPV6: &str = "The line ipv6, in the section relay, says whether an IPv6 target can be \
     reached (T-253). Through the first relay host that answered, by what its /relays.json says of its host's way \
     out: podssh relay serve says yes, none (and refuses an IPv6 target before the upgrade) or that it cannot tell, \
     and how it knows; the default relay says nothing of it, and the line gives its egress when last measured, on \
     2026-11-03: none, as each IPv6 target upgraded and then closed with 1011. Direct, by this host's own probes, \
     which send nothing: through a proxy, the proxy's way out decides; else an IPv6 socket made and closed, then \
     this host's table of IPv6 routes where Linux gives one. The line is ok, a fact; ???? when no relay host \
     answered or its /relays.json cannot be read.";

pub(super) const DOCTOR_EXIT: &str = "--exit NAME checks the exit NAME of your net (T-458), among the roads \
     that the run names, with --quick too, as podssh proxy --exit NAME reaches it: exit net, what the net held \
     says, NAME a member with the role exit and the rule of its policy that lets this client (--client-key FILE, \
     else client.key in the cache) reach exit:NAME, ???? where this host holds no net; exit pair, the pair kept \
     under NAME; exit, one session from the exit to --exit-target HOST:PORT (github.com:22 by default, identified \
     by its published host key; another target by its first bytes), with the node's verdict. A refusal says whose \
     it is: the road (the relay, or the pair), the channel, the net's policy, the exit's check of an address, or \
     its dial.";

pub(super) const DOCTOR_CLEARTEXT: &str = "The line cleartext, in the section relay, says what a request with no \
     TLS meets on the way to the first relay host that answered (else the first host), at its port and at port 80 \
     beside 443, as the cleartext road would meet it (T-326, GitHub #56): the CONNECT that the proxy takes, then GET \
     /health with no token and no target, and what came back, named: a reset or a close with no answer (a hop that \
     expects TLS cuts cleartext), a record of TLS (the far end speaks TLS alone there), the edge's refusal (a 400 \
     that says that a request of plain HTTP was sent to its HTTPS port), a refusal by policy (403), a redirect, \
     or an answer, the relay's own /health named; then whether the road reaches the relay. One probe after \
     another. The line is ok, a fact, as a reset is no fault where TLS answers; ???? when the proxy setting \
     cannot be read. With --forwarder, the section of the forwarders has the same line for each one's host, at \
     443 and 80, and says whether a ws:// form of it can pass.";

pub(super) const DOCTOR_HTTP2: &str = "The line http2, in the section relay, after cleartext, says what the \
     same host offers the WebSocket over HTTP/2 (T-321, RFC 8441), with nothing sent but HTTP/2's preface, its \
     SETTINGS and a PING: the protocol that its TLS chose when podssh offered h2 then http/1.1, and on h2 whether \
     its SETTINGS offer extended CONNECT, with its streams at once; then whether the sessions of a run share one \
     connection to it, by PODSSH_H2 (podssh relay serve offers it; the default relay's edge chooses h2 and offers \
     no extended CONNECT). The line is ok, a fact; ???? when the host was not reached; FAIL for a word of \
     PODSSH_H2 that is not auto, yes or no. With --forwarder, the section of the forwarders has the line for \
     each wss:// one, whose road keeps the upgrade of HTTP/1.1.";

pub(super) const DOCTOR_STREAM: &str = "--stream URL checks this host, then what the path to URL does to a \
     stream, and nothing else, one connection at a time: URL is https://HOST[:PORT][/PATH] (TLS checked with \
     doctor's trust) or http://..., through HTTPS_PROXY as each road dials, the probes under PATH, /v1/probe by \
     default, where podssh relay serve serves them, and a quick tunnel of podssh node --relay; go-httpbin serves \
     the same paths under its prefix /v1/probe. The section stream gives: stream server, the server's own limits, \
     from limits.probe of its /relays.json, so that what is met below them is the path's (behind a quick tunnel's \
     node, the node's: a body taken whole, 32 KiB at most, and an answer quiet for 60 s ended); response, 5 bytes \
     sent over 2 s, which come as they are sent or at once after the last, held until the end; request body, 4 \
     pieces of 1 KiB half a second apart, which the server says came over 1.5 s or at once; body cap, bodies \
     from 64 KiB, twice as big each time up to 8 MiB or the server's own cap, until one does not pass, with the \
     sizes between which the cap lies and the status that refused it; quiet stream, a response whose second byte \
     comes --stream-idle SECONDS after its first (130 by default, 1 to 600), and when and how it ended. Where a \
     size or a time is the documented default of a product, the line says that it looks like it (nginx's \
     client_max_body_size of 1 MiB and proxy_read_timeout of 60 s, an AWS Application Load Balancer's 60 s, \
     Cloudflare's 125 s, a Google Cloud load balancer's 30 s, Heroku's 30 s), never that it is. A path that \
     holds a stream is ok: podssh works with it; a server that cannot be reached is FAIL, and a probe that it \
     does not serve ????. With --full, the same section runs among the others at the relay that you named \
     (--relay-host, PODSSH_RELAY or RelayHost), and at the default relay, which serves no probe, a socket of its \
     reverse road alone, for a pair made for the check and stopped after it, held quiet after the relay's \
     hello; an end before the hold is the path's, or the relay's own drop of a node's socket. With --json, \
     each probe's line has its numbers in samples: the times in ms, the sizes in bytes, the status.";

pub(super) const RELAY_PROBES: &str = "The relay also serves the probes of podssh doctor --stream, with no \
     token, as go-httpbin's /drip and /anything under /v1/probe: GET /v1/probe/drip?duration=S&numbytes=N \
     (&delay=S, &code=C) sends its N bytes, the first at once and the last after S seconds, 600 s and 64 KiB at \
     most; POST /v1/probe/anything reads a body of its Content-Length, 8 MiB at most (413 past it, 411 with \
     none), drops it, and answers its length and the time, from the head, that each part of it came. At most 16 \
     run together (503 past them). /relays.json names their limits in limits.probe, and behind a node's quick \
     tunnel the node's own.";
