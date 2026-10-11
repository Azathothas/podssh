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
    "With --json, the run writes one JSON object on stdout when it ends, and nothing before it: schema \
     (1), podssh, count, size, relays (each with host, target, token, token_ms, connect, connect_ms, \
     tls_ms, upgrade_ms, pings with min_ms, p50_ms, p95_ms and max_ms, pings_lost and error), \
     destination (destination, login_ms, echo, down and up with command, seconds and bytes or error, \
     and error) and exit. The exit codes are in EXIT STATUS.",
];
