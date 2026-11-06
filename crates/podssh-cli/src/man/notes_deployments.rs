//! The notes of the signed list of relay deployments (T-346), for `relay`,
//! apart from the others so that each file stays short.

/// The list, its keys, its check and the role's side of it.
pub(super) const RELAY: &str = "A relay host outside the default's domain (ssh.relay.ajam.dev) comes from \
     a signed list of deployments alone (T-346). /relays.json may carry one as its field signed: the document's \
     exact text (its form podssh-relays 1, a serial, issued, not_after, and its deployments, each a name and up \
     to 8 hosts), the Ed25519 key that signed it, and that key's signature of podssh-relays/1, a zero byte and \
     the text. podssh uses it only when the key is one that it trusts: one compiled in, a key of \
     PODSSH_RELAY_KEYS or of RelayKeys in the settings file (SHA256:... or its 64 hex digits; none trusts no \
     key at all), or the key of a member of your net with the role relay. A list of another key, with one \
     changed byte, past its not_after, living more than 400 days, or with a serial below the list kept of its \
     key is not used, and the default list keeps the default's domain alone. A list that holds is kept in the \
     cache (relay-deployments.json, one for each key, checked again at each read), from the pool's refresh \
     after a mint and from podssh relay info, so that a binary keeps the other deployments when the default's \
     domain is gone. The default list is then the default host and up to 3 hosts of its pool, then up to 4 \
     hosts of the other deployments, the first of each deployment first; a list that you name takes none, \
     and neither does a run with PODSSH_RELAY_TOKEN, as that token is the default deployment's. Each host of \
     another deployment mints a token of its own and is sent no other, and its TLS is checked by its own \
     name. podssh relay info says whether the first host's list is signed, by which key and whence it is \
     trusted, and keeps it; podssh relay status names each deployment of the default list and whether its \
     list was signed, and so do podssh status (deployments) and podssh doctor (deployments). podssh relay \
     serve --deployment, repeatable, a name and its hosts as backup=relay.example.org,relay2.example.org:8443, \
     signs a list of those deployments in its \
     /relays.json with the key of --list-key FILE (relay-list.key in the cache, made when it is missing), \
     signs it again each day with a higher serial, for 90 days each time, and names the key's fingerprint on \
     its first line: give that fingerprint to each client, in PODSSH_RELAY_KEYS or RelayKeys, or name the \
     key as a member of your net with the role relay. Nothing of a request goes into what the role signs.";

/// The net's relay members, asked for their lists with no --relay-host
/// (T-617).
pub(super) const MEMBERS: &str = "A member of your net with the role relay and a host in the net's document \
     (see podssh net) is asked for its list with no --relay-host: before the race of a session on the default \
     list, and before podssh relay status asks its hosts, a run asks that host's /relays.json, at most once a day \
     for each member whatever it answered, 5 s for each and 8 s in all, with no token, through the proxy of the \
     environment and with TLS checked by the host's name. Its list is taken only when the member's key signed it, \
     by the rules above (PODSSH_RELAY_KEYS=none takes none), and its deployments then follow the default list in \
     that run; a list there of another key is not the member's, also when another setting trusts that key. No run \
     asks with PODSSH_RELAY_TOKEN, nor with a list that you name, nor when the cache keeps no file. The asks are \
     kept in the cache (relay-members.json). podssh relay status names each relay member: its host, then its list \
     taken with its serial, or why not, and when it was asked; --json gives them as members.";

/// A member that relays between two others (T-434).
pub(super) const LEGS: &str = "A member of your net with the role relay and a host in the net's document also \
     carries sessions between two other members that reach no common road. podssh node makes a pair at each \
     such member, at most three, the relay of its own pair aside, by its own key, and keeps a socket on each \
     beside its own road, with the one keeper of its sessions (never for a node with no resumable layer or no \
     end-to-end channel); each pair made, \
     or refused, is a line of the node. podssh ssh NAME, NAME a member with its key in the document, asks each \
     such member for a leg once each road before it failed: POST /v1/leg/KEY, KEY the node's key, with the proof \
     of the key of the client's end-to-end channel, then the upgrade with the token of one leg that the role \
     drew; -v names it a member's relay role. No pair of the node's is needed on the client's host. A role \
     gives a leg only with --mint keys:FILE or --mint net, and only to a key that it mints for; it sees bytes \
     that it cannot read, and the node's allowlist, or the net, still decides who gets in.";
