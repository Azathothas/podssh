//! The notes of the two ends of the reverse road, `node` and `operator`,
//! apart from the others for the length of the file: the pair, the layer,
//! the end-to-end channel and its keys (T-087, T-088), and the iroh road.

pub(super) const NODE: &[&str] = &[
    "podssh node serves TARGET, a TCP service, to the operators of the pair stored under NAME (see \
     podssh relay). Each session that an operator opens is one connection to TARGET, from this host, \
     through HTTPS_PROXY unless TARGET is on the loopback. podssh dials TARGET once at the start, and \
     exits when it cannot. It says online once the relay has its socket, and online again after a \
     loss: an operator reaches it from that line on.",
    "Each session runs the resumable layer: an operator that loses its link to the relay resumes the \
     session on a new link, and the node keeps the session and its connection to TARGET for 10 minutes \
     after a loss. TARGET is dialled only once the operator's handshake is done. The node keeps at most \
     64 MiB of replay buffers (16 sessions with the default of PODSSH_REPLAY_BUFFER); a new session past \
     that ends at once with the reason. podssh ssh node:// and podssh operator speak the layer. For an \
     operator that does not, --plain carries each session's bytes as they are, TARGET dialled at the \
     start of the session: a lost link then ends the session. The node's first line names its mode.",
    "Each session runs the end-to-end channel above the layer (Noise XX): the relay sees ciphertext \
     only, and the operator's key and the node's prove themselves in it. The node's key is a private \
     file in the cache (node-NAME.key, or iroh-node-NAME.key of an earlier podssh), or the file of \
     --key, made when it is missing; --ephemeral-key makes one for this run only. The node says its \
     fingerprint as it starts, and an operator pins it at the first sight. With --allow FILE, only the \
     operator keys of FILE come in, on each road: one key or fingerprint on each line, read again for \
     each session; a refused operator gets no byte of TARGET, and its key is said on stderr, as the \
     line to add. With no allowlist, each operator with the pair's connect token comes in, and its key \
     is said. TARGET is dialled only once the operator's key is let in. --no-e2e carries the bytes with \
     no channel, to operators run with --no-e2e too: the relay then sees them.",
    "The node runs until Ctrl-C or SIGTERM (exit 0), or until the relay ends the pair: stopped, \
     expired, refused, or served by another node; each has its code in EXIT STATUS. A broken \
     connection to the relay is made again, after a growing wait. After a loss the relay can still \
     hold the old connection, and answer 409: the node then connects again for 10 minutes, the time \
     that it keeps a session, with a line for each 409. A 409 at the start means that another node \
     serves the pair. stdout stays empty; notes go to stderr.",
    "With --pair-file, the pair comes from FILE, in the form of the store, and the store is not used. \
     FILE must be a regular file of the user that nobody else can read.",
    "With --iroh, in a build with the feature iroh, the node serves TARGET over the iroh road, with no \
     pair: QUIC between keys, through an iroh relay and HTTPS_PROXY, and directly when UDP works. The \
     relays are n0's public ones, or those of --iroh-relay, and the first that answers is the node's \
     (see THE RELAY). The node's key is the same on both roads (see above); --iroh-key and \
     --iroh-ephemeral are --key and --ephemeral-key by their earlier names. When it starts, the node \
     prints its key's \
     fingerprint and its ticket (iroh:...) on stderr, and a new ticket when its home \
     relay changes; a client dials the ticket with podssh ssh iroh:TICKET. When the pair NAME is stored \
     and good, or --pair-file gives one, the node serves the pair's road too, with one keeper of \
     sessions for both: a session resumes on either road, and podssh ssh node://NAME --iroh-ticket \
     TICKET races them. When the pair's road ends, the node says why, and the iroh road goes on.",
    "A client of the iroh road gets in only when its key, or the key's fingerprint, is a line of the \
     file of --allow (or --iroh-allow, its earlier name), which \
     the node reads again for each connection, so a key added counts at once. With no such file, no \
     client gets in. Each refused key is said on stderr: it is the line to add. A session reaches TARGET \
     only after the layer's handshake, and resumes on a new link for 10 minutes, as on the relay.",
];

pub(super) const OPERATOR: &[&str] = &[
    "podssh operator NAME carries stdin to the node of the pair under the label NAME, and the bytes of \
     the node's TARGET to stdout, as podssh proxy carries a forward session. It is the ProxyCommand of \
     OpenSSH for a node: ssh -o ProxyCommand='podssh operator NAME' user@NAME.",
    "Before the node takes the session, up to 1 MiB of stdin is kept, and sent then. The session ends \
     when stdin ends or the node's TARGET closes; it exits 0 only when the node took the session. An \
     error is one line on stderr; the codes are in EXIT STATUS.",
    "With a node that offers the resumable layer, a lost link to the relay is replaced by a new one, \
     for 10 minutes, and the session goes on where it was; one line on stderr tells of each loss and \
     each resume. A close that a new link would only get again (a stopped or expired pair) ends the \
     session.",
    "With --pair-file, the pair comes from FILE, or its operator's part alone, as podssh relay pair \
     writes it for the operator, and the store is not used.",
    "The session runs the end-to-end channel (see podssh node). This operator's key is a private file \
     in the cache (client.key, or iroh-client.key of an earlier podssh), or the file of --client-key, \
     made when it is missing, and its fingerprint is said when it is new. The node's key is pinned at \
     its first sight in known-nodes, in the cache, one line for each label; a node whose key changed is \
     refused, with both fingerprints, the file and the line, and exit 77, and the pin is never \
     replaced. --node-key KEY expects that key, or fingerprint, instead, and reads and writes no pin. A \
     node that refuses this operator's key ends the session with exit 77, and the line names the key to \
     add to its allowlist. --no-e2e carries the bytes with no channel, to a node run with --no-e2e.",
];
