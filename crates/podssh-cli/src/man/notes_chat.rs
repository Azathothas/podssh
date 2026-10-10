//! The notes of `chat` (T-099), apart from the others for the length of the
//! file: the two sides, the lines and the files, the end of a run, and the
//! end-to-end channel with its keys.

pub(super) const CHAT: &[&str] = &[
    "podssh chat carries messages and files between two podssh ends, over the end-to-end channel of a \
     road (see podssh node): the relay sees ciphertext only. One side waits: podssh chat --listen NAME \
     serves the pair NAME as its node (see podssh relay). The other side reaches it: podssh chat NAME, \
     with the pair stored under NAME, or the operator's part of it in --pair-file. One peer talks at a \
     time; another is told that the chat is busy.",
    "In a build with the feature iroh, --listen NAME --iroh serves the iroh road too, with no pair \
     needed for it, and says its ticket on stderr; the other side reaches it as podssh chat \
     iroh:TICKET, and the ticket names the key that the channel checks. On the iroh road, only the \
     keys of --allow come in, as on each node of that road. --iroh-relay gives the relays.",
    "Each line of stdin is a message, and each message of the peer is a line of stdout, NICK: TEXT, made \
     safe for a terminal. A line that starts with / is a command: /file PATH offers a file; /accept ID \
     [PATH] takes the file ID, into PATH (a directory, or the path of a new file) or else the working \
     directory; /decline ID refuses it; /quit ends. A line that starts with // is a message that starts \
     with /. Notes go to stderr; with --jsonl, each message and each event is one JSON object on stdout. \
     Nothing that the peer sends is run.",
    "A file is written only once the user accepts it, with /accept, or each file with --accept-dir DIR: \
     under a temporary name in its directory, checked against the SHA-256 that the peer offered, and only \
     then given its name; never over a file that is there, and never out of the directory, as the name \
     is the last part of the offered one. The peer hears whether each file was kept.",
    "The peer acknowledges each message, and a message with no acknowledgement when a conversation ends \
     is said, as not delivered. A run ends once stdin ended and each message and file went; with \
     --accept-dir, once the peer leaves, as its files can come after stdin ended. --send MESSAGE sends one \
     message and ends once it is acknowledged; --file PATH offers one file and ends once it arrived \
     whole; --sendfile FILE sends each line of FILE in place of stdin. The exit is 0 only when each message \
     was acknowledged; the other codes are in EXIT STATUS.",
    "While no peer is there, the lines wait in memory, 1000 lines or 1 MiB at most; podssh then reads no \
     more until some go, and says so. Nothing goes to disk. When the peer leaves, the side that waits \
     takes the next one, and the side that reaches tries again each 5 s, as it does while the node is \
     not there, until stdin ended and each line went. --timeout bounds the run, and is required when \
     stdin or stdout is not a terminal.",
    "With --irc SERVER[:PORT], podssh chat talks in the channel PEER (#name) of an IRC network, \
     through the relay: TLS inside the relay stream, port 6697 by default, the certificate checked \
     against SERVER; a failed handshake ends the run, and never falls back to plain text. \
     --irc-plaintext takes port 6667 and plain text, which the relay and each server read, and podssh \
     says so; --irc-ca-file gives the CAs of the server's TLS. The nick follows the grammar of IRC. \
     Each line is a message to the channel; a message of the channel comes out as NICK: TEXT, and one \
     to this client as NICK (to you): TEXT. With echo-message, a message is delivered once the server \
     echoes it; a server with none gives no proof, which podssh says. The server and each user of the \
     channel read the messages: IRC has no end-to-end channel. A lost connection is made again each \
     5 s, and the channel joined again; a server's ERROR before the channel ends the run with its \
     words. With --direct, podssh connects to SERVER over TCP, through HTTPS_PROXY when it is set, \
     not through the relay.",
    "Over IRC, /file PATH offers the file to the channel; the transfer then runs between the two \
     nicks alone, in chunks that each server can relay, each line in its turn so that a server's rate \
     limit does not close the link, and with the SHA-256 of the file at the end. One file goes at a \
     time: another accept meanwhile is told that this side is busy. A file is written only once \
     accepted, under a temporary name, and kept only whole, as on the roads.",
    "The channel is always on: chat has no --no-e2e. The side that waits proves its key, the file of \
     --key (default node-NAME.key in the cache) or a key of --ephemeral-key, and lets in the keys of \
     --allow FILE, else each peer with the pair's connect token. The side that reaches proves the key \
     of --client-key (default client.key in the cache), and checks the other side's key against the \
     pins of known-nodes, or against --node-key. A changed key, or a key that the allowlist refuses, \
     ends the run with exit 77.",
];
