//! The notes of `podssh net` (T-429), apart from the others so that each
//! file stays short.

pub const NET: &[&str] = &[
    "podssh net keeps a net of the user's own nodes, as a tailnet does but with no server to trust: one document \
     of JSON that names the net and each member, with its name, its Ed25519 key (the key that the node says as it \
     starts, or its fingerprint), its roles (node, exit, relay, share) and its tickets, with a serial and an end. \
     The owner's key signs it with SSHSIG in the namespace podssh-net, as ssh-keygen -Y sign does, so that \
     ssh-keygen -Y verify -n podssh-net checks it too. The owner's key is an OpenSSH key, which podssh keygen makes, \
     and which can stay on one host.",
    "The owner's subcommands each sign a new document, its serial one higher: init NAME (the first, with \
     --owner-key or ~/.ssh/id_ed25519), add NAME KEY (a member, or a new key, roles or tickets of one, with \
     --roles, --iroh-ticket and --derp-ticket), rm NAME and renew (the same members, a new end). --days sets how \
     long a document lasts, a year by default: no end takes it after its end, and a node no longer lets in by it. \
     Each end's: ls, one line for each member on stdout (its name, roles, fingerprint and tickets, apart by tabs); \
     show, the document's bytes as signed, or with --signature its signature; take FILE, a document from its owner, \
     as FILE alone or as FILE and FILE.sig, as ssh-keygen -Y sign writes them.",
    "Each end keeps the newest document that it was given, in net.doc of the cache (or the file of PODSSH_NET), \
     and takes another only with the owner's signature, a serial higher than the one held, and an end still to \
     come; its first is the one that the user takes, whose owner --owner can name. Two ends of the net give each \
     other the newer one inside the end-to-end channel, on any road, and only to a member: the operator's before \
     the node's verdict, so that it counts for that session, and the node's after it. A node of the net says each \
     document that it takes. A field that this podssh does not know stays when the owner signs a change; a \
     document that requires a part that it does not read is refused, with podssh update as the remedy.",
    "A node whose key is a member lets in each member of the document held, read again for each session, beside \
     the keys of podssh node --allow; a member removed by a newer document is refused at its next session. A node \
     of no net keeps its door as before. A document that ended, or one that is there and fails its check, lets \
     nobody in by the net, so a node that must not be locked out keeps an allowlist too.",
    "The net's policy says who may reach what, as Tailscale's ACLs do; with none, each member reaches each other. \
     Its owner writes it as a file of JSON, {\"tags\": {\"dev\": [\"phone\"]}, \"rules\": [{\"from\": [\"laptop\", \
     \"tag:dev\"], \"to\": [\"lab/web\"], \"note\": \"...\"}]}, and signs it into the net with policy set FILE (policy \
     clear removes it); policy show gives it back. A rule is from *, a member's name or tag:TAG, to * (each node, \
     route, exit and range), NODE (its TARGET with no route and each route), NODE/ROUTE (one route, as \
     node://NODE/ROUTE reaches it), tag:TAG, exit:NODE or exit:* (an exit node's egress), or ADDR/BITS (a range of \
     routes); a rule only allows, and once a policy is there nothing else is allowed. The node that is reached \
     checks it, for each session, against the newest document that it holds, and refuses the rest with the \
     policy's words on its own lines; the keys of podssh node --allow are not narrowed by it. policy check FROM TO \
     says what the policy lets, with no connection: FROM a member's name or key, TO NODE, NODE/ROUTE, exit:NODE or \
     an address; on stdout allowed or refused, a tab and the rule or the reason, and 0 or 77. A document with a \
     policy requires it, so a podssh that cannot read the rules refuses the document and keeps the one before.",
    "A member's name is a destination: podssh ssh node://NAME, and podssh ssh NAME alone when NAME is a member \
     with the role node, as MagicDNS names a host of its tailnet. A name has no dot, so no DNS name is a member's. \
     The net names the member's key, which the end-to-end channel checks in place of the pins of known-nodes, and \
     its tickets, which race beside the pair kept under NAME when the command line names none. Once each road \
     with a ticket failed, or at once with none, podssh ssh of a build with the iroh road asks the member's record \
     of pkarr by that key, and races each road that it names and no ticket gave (see iroh record in THE RELAY). \
     PODSSH_NET=no turns the net off: no name, no door and no document of the channel comes from it.",
];

/// The notes of `podssh exit` (T-431), beside the net's, as an exit is a
/// node of the net.
pub const EXIT: &[&str] = &[
    "podssh exit NAME --listen ADDR:PORT is a local proxy for the programs of this host, whose each connection \
     starts at NAME, a node of your net that lends its egress (podssh node --exit), as a Tailscale exit node \
     carries a device's traffic. One port takes SOCKS5, SOCKS4a and HTTP CONNECT: a program reaches it with \
     ALL_PROXY=socks5h://ADDR:PORT, or HTTPS_PROXY=http://ADDR:PORT; through socks5h://, a program sends the name \
     of its target, which the exit resolves. NAME is the label of the exit's pair here (or --pair-file), and a member \
     of the net, whose key the end-to-end channel checks.",
    "Each connection is one session to the exit, over its pair's road, in the resumable layer and the end-to-end \
     channel, which carries the target: the relay sees neither the target nor a byte. A client hears its success \
     only once the exit reached the target; a refusal of the exit, of its net's policy, or of an address that is \
     not public, is the refusal of its protocol (SOCKS 2 or HTTP 403; a target out of reach, SOCKS 5 or HTTP 502) \
     and one line on stderr. 32 connections go at once; -q says no line for each one.",
    "The listener is one that you ask for, on a loopback address alone (127.0.0.1:0 takes a free port, which the \
     first line names): SOCKS here takes no credentials, and each host that found the port would spend the exit's \
     egress. PODSSH_LISTEN=no refuses it before anything binds (78), and a refused bind is 77. The proxy runs until \
     Ctrl-C or SIGTERM (0).",
];
