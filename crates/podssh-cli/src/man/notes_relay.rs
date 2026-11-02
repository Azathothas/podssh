//! The notes of `podssh relay`: the pairs (T-083), the document (T-060),
//! the relay's own state (T-058) and the relay role (T-169, T-427), apart
//! from the others so that each file stays short.

pub const RELAY: &[&str] = &[
    "podssh relay pair NAME makes a pair on the relay and keeps it under the label NAME, in a private \
     file of the cache (see FILES). It prints the label and when the pair expires, 72 hours later, and \
     never a token. With --operator-file, the operator's part of the pair, its connect token alone, \
     goes to FILE, a new file that only its owner can read: give it to the operator by a channel that \
     you trust.",
    "A pair under NAME with more than 24 hours left is not replaced: stop it first with podssh relay \
     revoke NAME. In its last 24 hours, the next pair is made and takes its place in the store, and a \
     node of NAME that runs takes it at the expiry, with no new start (see podssh node); the old pair \
     can no longer be stopped, and ends at its expiry. The relay renews no pair, so each node of a pair \
     needs the next one every 72 hours. revoke stops the pair on the relay and deletes the stored copy; \
     when the relay cannot be reached, the copy is kept, because its stop token is the one way to stop \
     the pair before it expires.",
    "podssh relay status NAME says whether the pair's node is online, and its sessions.",
    "podssh relay spec reads the relay's /health and its published document, /llms-full.txt, and checks \
     the document against the facts that podssh was built with (see RELAY FACTS). It prints ok, with the \
     document's lines, its digest and the version that the relay serves, or a FAIL line for each fact \
     that disagrees, and exits 1: the relay changed something that podssh depends on. With --document \
     FILE, it checks FILE and reads nothing from the network.",
    "podssh relay status with no NAME asks each relay host for its /health, one after the other, and \
     prints a line for each as it answers: the relay's version, the edge that answered, the time, the \
     TLS version and how the connection was made, or why it failed. It needs one host that answers.",
    "podssh relay info reads /relays.json from the first relay host: the edge that this host reaches, \
     the pool best first with the relay's estimate of each round trip, and the limits of a session. \
     With HOST PORT, also the URL that the relay chooses for that target.",
    "podssh relay trace HOST PORT asks the first relay host to dial the target and to read its first \
     line, with a forward token in a header and never in the URL: the relay's verdict (live, or \
     silent-or-unreachable for a target that sent nothing), the address that it dialed, the times of \
     the connection and of the first byte, and the banner. A target that the relay will not dial (a \
     blocked range, a name with no address) gives the relay's reason. It tells a target that is down \
     from a relay that cannot be reached. The relay's view of this host's address and place, which it \
     sends too, is never shown.",
    "With --json, status, info and trace write one JSON object on stdout when the run ends: schema (1), \
     podssh, and the answer: each host for status, the relay's /relays.json as it came for info, and \
     the relay's view of the target for trace. The exit codes are in EXIT STATUS.",
    "podssh relay serve is the relay itself, as a role of podssh: it serves the relay's forward road, \
     the contract that podssh speaks (version 2026-10-03-r2), on --listen ADDR:PORT, with TLS from \
     --cert FILE and --key FILE (a P-256 key in PEM; ACME is not built in), so that each podssh reaches \
     it with --relay-host and the CA that signed its certificate. It serves /health, /v1/mint, \
     /connect/HOST/PORT, /relays.json, /trace and /llms-full.txt, dials a target only once its name \
     resolves to public addresses (--allow-private dials the others too), refuses port 25, and keeps \
     the default relay's limits: 180 s with no payload, 12 hours and 64 MiB a session. --mint anyone \
     mints a token for each client; by default it mints for no one (503), as its tokens are given \
     another way. A token lives until the relay stops. Each mint, upgrade and client's Close is a line \
     on stdout. It listens because you ask it to, and PODSSH_LISTEN=no refuses it; Ctrl-C or SIGTERM \
     stops it.",
    "It serves the reverse road too: /v1/pair, for whom it mints, /v1/node/NAME, /v1/connect/NAME, \
     /v1/status/NAME and /v1/stop/NAME, so that podssh relay pair --relay-host, podssh node and podssh \
     ssh node:// work through it with no other relay. A pair lives 72 hours; --pairs FILE keeps the \
     pairs in FILE, a file of mode 0600 that holds the digests of their tokens and never a token, so \
     that they outlive a restart. At most 1 MiB waits for a slow operator: past it, the session ends \
     with 1011 relay backpressure, and the node's other sessions go on; a node that reads slowly slows \
     its operators instead. A frame of the node for a session that ended in the last 2 seconds was on \
     its way, and is dropped; one for an id never given closes the node's socket with 1003, as the \
     contract says. Ctrl-C or SIGTERM first closes each socket of the reverse road with 1012, so that \
     each node connects again and each session resumes once the relay is back with its pairs.",
];
