//! The notes of `podssh each` (T-183), apart from the others so that each
//! file stays short.

pub const EACH: &[&str] = &[
    "podssh each HOSTS -- COMMAND runs one command on each host of a comma list, [user@]host[:port],..., \
     through the relay or with --direct, with the connection flags of podssh ssh: -p and -l for each host \
     that names none, -i, -o, -F and -J; the Host blocks of ssh_config apply to each host as podssh ssh \
     applies them. Each host is checked before anything connects: a bad one exits 64, and nothing has run \
     anywhere. A host named twice runs once.",
    "At most --parallel hosts run at once (8; 1 to 64), each on a connection of its own. No host gets a \
     terminal or stdin: each session is as podssh ssh -T -n makes it. Nothing asks a question: BatchMode is \
     on, and an unknown host key refuses its host and names its fingerprint and -o \
     StrictHostKeyChecking=accept-new, which records each new key. Through the relay, one token serves \
     each host.",
    "Each line of a host's output starts with HOST: , on stdout or stderr as the host wrote it, and \
     podssh's own messages about a host start with podssh: HOST: . A line is never cut by another host's; \
     one longer than 64 KiB comes in pieces, each with its host. With --output-dir DIR, the bytes go \
     unchanged into DIR/HOST.out and DIR/HOST.err, and the exit status into DIR/HOST.status at the host's \
     end; each byte of HOST but a letter, a digit, a dot, an underscore, a hyphen and @ is written %XX. \
     The files are made before anything connects (73 when they cannot be), and a host with no status \
     file did not run.",
    "At the end a summary on stderr gives each host and its status; -q leaves it out. The exit status is \
     the largest of the hosts': 0 only when each host gave 0, and 255 when one could not connect or log \
     in. With --fail-fast no host starts after one failed, and the hosts that run end as they end.",
];
