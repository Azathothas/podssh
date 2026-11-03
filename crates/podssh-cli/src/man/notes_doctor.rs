//! The notes of `podssh doctor` for the time of a run (T-511): its sections
//! at once, `--jobs` and `--quick`, apart from the others so that each file
//! stays short.

pub(super) const DOCTOR_AT_ONCE: &str = "The sections that connect run at once by default, each into its own part \
     of the report, and the report keeps its order: a section's lines go out once each section before it has ended, \
     the first one that still runs line by line, so a run takes about as long as its longest section, not their \
     sum. Each section reaches its servers one at a time, as before, so a run holds at most one connection for each \
     section that runs (the egress, the relay, DERP, and each road that it names), and the relay's forward races its \
     hosts as podssh ssh does. --jobs N, or DoctorJobs N in the settings file, starts at most N sections together, \
     in the order of the report; --jobs 1 runs one after another.";

pub(super) const DOCTOR_QUICK: &str = "--quick checks this host, the egress and the relay alone, what each run of \
     podssh ssh and podssh proxy needs, with the section of each road that the run names (--forwarder, \
     --shadowsocks, --via, --vless). It leaves out the quick tunnel's edge (the lines quick tunnel roots, UDP out \
     and edge road), iroh and tor in a build with them, DERP and the pairs; its last line, sections in the section \
     left out, names them, as ????: checks that did not run.";
