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
     --roles, --iroh-ticket, --derp-ticket and an exit's --routes), rm NAME and renew (the same members, a new end). --days sets how \
     long a document lasts, a year by default: no end takes it after its end, and a node no longer lets in by it. \
     Each end's: ls, one line for each member on stdout (its name, roles, fingerprint and tickets, apart by tabs); \
     show, the document's bytes as signed, or with --signature its signature; take FILE, a document from its owner, \
     as FILE alone or as FILE and FILE.sig, as ssh-keygen -Y sign writes them.",
    "podssh net invite NAME, on the owner's host, adds a new device by a short code (T-616), as podssh relay pair \
     gives a pair by one: the code, such as 7-crossover-clockwork-adroitness, shows on this run's terminal alone, \
     beside the owner's fingerprint, never on stdout, in a log or in argv, and a run with no terminal is refused \
     (64). The owner's key is found, and its passphrase asked, before the code is made. On the device, podssh net \
     join takes the code; the two ends meet at a mailbox and run the exchange of the pairing, SPAKE2 keyed by the \
     whole code, so the mailbox learns nothing and changes nothing; the code lives 10 minutes and its first \
     exchange spends it, so a wrong code, or a guess, gets one try and adds no member (77 at both ends). The \
     owner's host offers the net's name, its owner's key, NAME and its roles (--roles, node by default); the device \
     answers with its key; the owner's host adds the member NAME with that key, signs and keeps the next serial as \
     add does, and gives the signed document back. A NAME that is a member already goes to its own key alone, with \
     the document held, as after a last word that was lost: another key is refused (77), so no code hands a \
     member's name to a new key, and --roles is refused with it (64). stdout has one line at each end.",
    "podssh net join takes the code at a prompt on the terminal, or as one line of stdin from a pipe, never from \
     argv, and checks the net's owner before it keeps anything: the owner that --owner KEY names (its fingerprint \
     SHA256:... or its public key), else the owner of the net that this host holds, else the person at the \
     terminal, who sees the owner key's fingerprint, made here from the key, and answers yes; the owner's host \
     shows it beside the code and in each line of its podssh net ls. With the code on a pipe and neither, the run \
     is refused (64) before the code is read, as a stranger's code would make this host a member of the \
     stranger's net. A refusal is said to the owner's host, which signs nothing (77 at each end). The device's key \
     is --key FILE, else node-NAME.key in the cache, the key of podssh node NAME, made when missing; with \
     --client-key and that file, a client of this host reaches the other members as NAME. The document that comes \
     is checked (the owner's signature, the owner and the net of the offer, this key as NAME), then taken by the \
     rule of take. The mailboxes are the pairing's: magic-wormhole's public one, then Least Authority's, or \
     --pair-mailbox URLS and PODSSH_PAIR_MAILBOX, such as podssh relay serve's wss://HOST/v1/mailbox; no turns the \
     code off (78), and add and take are the way left.",
    "Each end keeps the newest document that it was given, in net.doc of the cache (or the file of PODSSH_NET), \
     and takes another only with the owner's signature, a serial higher than the one held, and an end still to \
     come; its first is the one that the user takes, whose owner --owner can name. Two ends of the net give each \
     other the newer one inside the end-to-end channel, on any road, and only to a member: the operator's before \
     the node's verdict, so that it counts for that session, and the node's after it. A node of the net says each \
     document that it takes. A field that this podssh does not know stays when the owner signs a change; a \
     document that requires a part that it does not read is refused, with podssh update as the remedy. An end that \
     offers its document to a node that gives none (it holds none, or its podssh is older) goes on without it, as \
     such a node lets it in by its own door, and podssh ssh says so once among its verbose lines.",
    "A node whose key is a member lets in each member of the document held, read again for each session, beside \
     the keys of podssh node --allow; a member removed by a newer document is refused at its next session. A node \
     of no net keeps its door as before. A document that ended, or one that is there and fails its check, lets \
     nobody in by the net, so a node that must not be locked out keeps an allowlist too. A node of the DERP road \
     (podssh node --derp, or unasked with no pair) whose key is a member needs no podssh node --allow: the net's \
     members are then its door alone, on each of its roads, as a DERP server lets any key send; its first line says so.",
    "The net's policy says who may reach what, as Tailscale's ACLs do; with none, each member reaches each other. \
     Its owner writes it as a file of JSON, {\"tags\": {\"dev\": [\"phone\"]}, \"rules\": [{\"from\": [\"laptop\", \
     \"tag:dev\"], \"to\": [\"lab/web\"], \"note\": \"...\"}]}, and signs it into the net with policy set FILE (policy \
     clear removes it); policy show gives it back. A rule is from *, a member's name or tag:TAG, to * (each node, \
     route, exit and range), NODE (its TARGET with no route and each route), NODE/ROUTE (one route, as \
     node://NODE/ROUTE reaches it), tag:TAG, exit:NODE or exit:* (an exit node's egress), relay:NODE or relay:* \
     (the tokens and pairs of a relay role that mints for the net, the node's own behind its quick tunnel or each \
     one, podssh relay serve's too: see podssh relay), or ADDR/BITS (a range of routes); a rule only allows, and \
     once a policy is there nothing else is allowed. The node that is reached checks it, for each session, against \
     the newest document that it holds, and refuses the rest with the policy's words on its own lines; the keys of \
     podssh node --allow are not narrowed by it. policy check FROM TO says what the policy lets, with no \
     connection: FROM a member's name or key, TO NODE, NODE/ROUTE, exit:NODE, relay:NODE, relay:* (a relay that is \
     no member) or an address; on stdout allowed or refused, a tab and the rule or the reason, and 0 or 77. A \
     document with a policy requires it, so a podssh that cannot read the rules refuses the document and keeps the \
     one before.",
    "A member's name is a destination: podssh ssh node://NAME, and podssh ssh NAME alone when NAME is a member \
     with the role node, as MagicDNS names a host of its tailnet; so is [user@]NAME:path of podssh cp, mv, scp \
     and edit, and NAME of podssh sftp, each read as podssh ssh reads it. A name has no dot, so no DNS name is \
     a member's. The net names the member's key, which the end-to-end channel checks in place of the pins of \
     known-nodes, and its tickets, which race beside the pair kept under NAME when the command line names none; \
     a copy races them as podssh ssh does. Once each road \
     with a ticket failed, or at once with none, podssh ssh of a build with the iroh road asks the member's record \
     of pkarr by that key, and races each road that it names and no ticket gave (see iroh record in THE RELAY); \
     so does a copy. \
     PODSSH_NET=no turns the net off: no name, no door and no document of the channel comes from it.",
    "An exit reaches the private networks of its host for the net, as a Tailscale subnet router does: inside the \
     ranges of its own --routes (see podssh node), for a member that the policy lets reach the address (a rule to \
     ADDR/BITS). A loopback address, or one of the exit's own host, is dialled only where a range names it alone \
     (127.0.0.1, or ADDR/32), so that 10.0.0.0/8 does not hand the node's own services to the net. add NAME KEY \
     --roles node,exit --routes RANGES lists an exit's routes in the document, which --exit auto reads (see podssh \
     exit); the node says at its start when the document lists other routes than its own.",
    "A member with the role relay is a podssh relay serve of yours, whose key the net names: the key that signs \
     its list of deployments, which its first line names (see podssh relay). add NAME KEY --roles relay --relay-host \
     HOST[:PORT] names where it serves that list, one host, written as relay.example.org or relay.example.org:8443; \
     --relay-host with no role relay is refused (64). Each end that holds the net then asks that host's \
     /relays.json before the race of a session on the default list, once a day whatever the answer, within 5 s, \
     and takes the list there only when the member's key signed it, so that a client with no --relay-host and no \
     key of its own learns its role's deployments; the host itself joins no list by it, as the role's list names \
     where sessions go. podssh relay status names each relay member, its host, and whether its list was taken.",
];

/// The note of `podssh status --net` (T-435), as `tailscale status` lists a
/// tailnet: the notes of status name it.
pub const STATUS_NET: &str = "The line's net is the net that this host holds, read with no connection: name, serial, \
     owner (its fingerprint), expires_ms, ended, file and count, the number of members; null when this host holds \
     none or PODSSH_NET is no, and error, with why, when its file does not read. With --net, net also holds \
     members: each member's name, roles, key (its fingerprint), tickets (their kinds, never a ticket) and routes, \
     and what the races from this host last found of it: reached, the road that answered first in the words of \
     podssh ssh -v, with ms from the start of the race and ago_s; missed, why the last race found no road, with \
     ago_s; and last, reached or missed, whichever came last, or null when no race to it was kept. Each race of \
     podssh ssh, of the copies and of podssh ping to node://NAME, and the pair's road alone, keeps its end in \
     net-roads.json in the cache (see FILES), at most 256 nodes.";

/// The note of `podssh doctor`'s sections of the net and of the public
/// carriers (T-435), as `tailscale netcheck` says what a host reaches.
pub const DOCTOR_NET: &str = "The section carriers asks each public carrier that the roads of a node try \
     unasked, one connection through the proxy each, one after another, carrying nothing of yours: the transit \
     relay of PODSSH_TRANSIT (Least Authority's by default), whose WebSocket opens and closes with no line said, so \
     it pairs nothing; each mailbox of PODSSH_PAIR_MAILBOX (magic-wormhole's and Least Authority's by default), \
     which says its welcome and is bound to podssh's application, no nameplate claimed; and the Piping Server of \
     PODSSH_PIPING (ppng.io by default), asked its /version. A variable's no asks none of its carrier, ????; a \
     value that its road refuses is a FAIL. The Wisp demo server is a forwarder, which the line fallback names. \
     The section net says the net held, read with no connection (FAIL for a file that does not read, or a net \
     that ended), then asks /health of each member with the role relay, at most 8, at the host that the net's \
     document names for it, as the relay section asks the relay hosts; a member relay that the document names no \
     host for is ????. With PODSSH_OFFLINE, the net's line comes, and no member relay is asked.";

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
    "With --carrier ADDR, the exit is the node at the other end of ADDR, a stream that exists already, with no \
     relay and no pair, as podssh node NAME --exit --carrier serves it: stdio (or -), the stdin and stdout that \
     the exec channel of a platform's own SSH gives the program that it starts; fd:N (Unix); or exec:CMD, a \
     program started with no shell. So a host whose every road out is closed, but that such a channel reaches, \
     gets egress through the channel's other end: there, podssh node gw --exit --carrier \"exec:ssh -T sandbox \
     podssh exit gw --listen 127.0.0.1:1080 --carrier stdio\"; in the sandbox, HTTPS_PROXY=http://127.0.0.1:1080. \
     Each connection is a session of the one stream; NAME is a member of the net, whose key the channel checks, \
     and the net's rule of the exit holds as on each road. The stream starts with the proxy; one of stdio or \
     fd:N has one life, and when its node leaves, the proxy ends (0); a program of exec: is started again for \
     the next connection. Ctrl-C ends the stream with a Close, which ends the node (0). --pair-file, \
     --relay-addr and --ca-file are refused with it (64), and so is --carrier stdio on a terminal. podssh \
     ssh, podssh proxy and podssh pipe take --exit NAME beside --carrier ADDR too, on a stream of their own, \
     exec:CMD or fd:N, as their stdin and stdout are their own (see their notes).",
    "--exit auto, in place of NAME here and for podssh ssh, proxy, pipe and doctor, takes the exit whose route of \
     the net holds the target's address: the routes that the net's owner lists for each exit (see podssh net), \
     the narrowest first, then the first by name; a line says which, for each connection here. podssh ssh --exit \
     auto user@10.1.2.3 reaches a host of a lab whose exit routes 10.1.0.0/16. It takes an address, not a name, as \
     the exit resolves a name itself and may resolve it otherwise; an address that no route holds is refused (78), \
     and so are --pair-file and --carrier beside it (64), as each names one exit. auto is no member's name.",
];
