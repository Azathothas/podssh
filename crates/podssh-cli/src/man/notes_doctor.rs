//! The notes of `podssh doctor` for the time of a run (T-511): its sections
//! at once, `--jobs` and `--quick`; and its diagnosis of the TLS handshakes
//! (T-487). Apart from the others so that each file stays short.

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
