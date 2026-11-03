//! The notes of `podssh doctor` for the time of a run (T-511): its sections
//! at once, `--jobs` and `--quick`; its diagnosis of the TLS handshakes
//! (T-487); and its probes of what a path does to a stream (T-325), with
//! the relay role's side of them. Apart from the others so that each file
//! stays short.

pub(super) const DOCTOR_AT_ONCE: &str = "The sections that connect run at once by default, each into its own part \
     of the report, and the report keeps its order: a section's lines go out once each section before it has ended, \
     the first one that still runs line by line, so a run takes about as long as its longest section, not their \
     sum. Each section reaches its servers one at a time, as before, so a run holds at most one connection for each \
     section that runs (the egress, the relay, OpenTunnel, DERP, and each road that it names), and the relay's \
     forward races its hosts as podssh ssh does. --jobs N, or DoctorJobs N in the settings file, starts at most N \
     sections together, in the order of the report; --jobs 1 runs one after another.";

pub(super) const DOCTOR_QUICK: &str = "--quick checks this host, the egress and the relay alone, what each run of \
     podssh ssh and podssh proxy needs, with the section of each road that the run names (--forwarder, \
     --shadowsocks, --via, --vless). It leaves out the quick tunnel's edge (the lines quick tunnel roots, UDP out \
     and edge road), iroh and tor in a build with them, OpenTunnel, DERP and the pairs; its last line, sections \
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
