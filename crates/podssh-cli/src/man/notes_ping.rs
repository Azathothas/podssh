//! The notes of `podssh ping` (T-053), apart from the others so that each
//! file stays short.

pub const PING: &[&str] = &[
    "With no destination, podssh ping measures the relay leg of each relay host, one after the other: \
     the token (from PODSSH_RELAY_TOKEN, cached or minted), DNS and TCP or CONNECT through the proxy, \
     TLS, and the WebSocket upgrade, which the relay answers once it reached the target, each with its \
     time; then --count WebSocket pings, each with its send time in its payload and matched to its \
     pong, as the minimum, p50, p95 and maximum in milliseconds, and the pings that had no pong in \
     time. The target is --target, else github.com port 22, which podssh doctor reaches too; never the \
     destination, whose server would see a connection that sends no SSH bytes: OpenSSH's \
     PerSourcePenalties count those against the relay's address, which other users share.",
    "With a destination, the run is resolved as podssh ssh resolves it (ssh_config, -J, -i, --direct), \
     and the relay leg is followed by the time to log in, the echo of one byte at a time through cat, \
     --count times after one that is not counted (the first can wait for cat to start), and the \
     throughput down and up of --size bytes, which stay under the relay's limit of one session in both \
     ways together. Down reads what head writes from /dev/zero, and up writes \
     into cat > /dev/null; each line names the remote command that ran. These programs are an \
     assumption about the host, so they run only for a destination. A program that the host lacks \
     ends the run with its status, never with a hang: each step and the whole run have a limit.",
    "With node://NAME, or the name alone of a member of the net with the role node, podssh ping measures the \
     roads that podssh ssh races to that node (T-435), as tailscale ping names the path that answered: in the \
     order of the race and with its delays, each road that starts runs on to the far end's first bytes, and a \
     line for each says its time and when it started into the race, why it failed, or that it did not start, as \
     a fallback starts only when each road before it failed; the last line names the road that answered first, \
     with its time from the start of the race. Each road that starts opens its one connection, as a race of \
     podssh ssh does, and each link ends before a byte is sent on it, so the node opens no session and dials \
     nothing at its TARGET, and nothing logs in. The exit is 0 when a road answered and 69 when none did; --size, \
     --count and --target are a host's, and refused with a node (64). --json gives node (name, roads, each with \
     road, started, started_ms, ms, answered and error, then won and won_ms) beside schema, podssh, relays, \
     empty, destination, null, and exit. The road that answered, or the race that found none, is what podssh \
     status --net says of the node. With --under-load or --connect-runs, a node is measured as a host is, \
     through the road that podssh ssh takes to it, and logged in to.",
    "What a user feels (T-660). --under-load measures the echo of keys typed as a user types them, 40 keys \
     150 ms apart, each sent at its time whether or not the one before came back, through cat: first idle, \
     then beside head -c 62914560 /dev/zero, a download of 60 MiB on a second channel of the same \
     connection, once it ran for 3 s, so that the path's queue is full when the first key goes. The \
     download stops once the last key came back; a key whose echo came after it ended is not counted beside \
     it, and a download that ended within its 3 s is said, with no figure. The lines give the echo idle and \
     under load (minimum, p50, p95 and maximum) and the download's rate while the keys ran. It replaces the \
     echo, down and up, so --count and --size are refused with it (64), as the plain measures beside the \
     download would pass the relay's 64 MiB for one session.",
    "--connect-runs N (1 to 20) comes first: N cold connects, one after the other, each a connection of its \
     own, the login, and true run to its exit status, each timed from the start of its own connection; the \
     destination is resolved once before them. A run that fails ends the measures, with the code that podssh \
     ssh would give. Both measure through a host, and are refused with none (64). --under-load opens no \
     connection beside the run's own; --connect-runs opens one at a time, each closed before the next.",
    "With --json, the run writes one JSON object on stdout when it ends, and nothing before it: schema \
     (1), podssh, count, size, relays (each with host, target, token, token_ms, connect, connect_ms, \
     tls_ms, upgrade_ms, pings with min_ms, p50_ms, p95_ms and max_ms, pings_lost and error), \
     destination (destination, login_ms, echo with samples_ms, the raw time of each echo, connect with \
     runs, command, its summary and samples_ms, under_load with keys, gap_ms, warmup_ms, idle and loaded, \
     each with its summary and samples, each with sent_ms, from the download's start under load, and \
     echo_ms, and beside under load, and load with command, bytes, typing_bytes, typing_seconds and \
     ended_ms; down and up with command, seconds and bytes or error, and error) and exit. The exit codes \
     are in EXIT STATUS.",
];
