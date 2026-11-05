//! The notes of `podssh share` (T-433), apart from the others so that each
//! file stays short.

pub const SHARE: &[&str] = &[
    "podssh share offers a running node's local services by name to its net, as Tailscale's serve offers a \
     node's: on the host of the node lab, podssh share add web=127.0.0.1:8080 shares that TCP service as \
     node://lab/web, which an operator reaches as a route (podssh ssh node://lab/web, podssh operator lab/web, \
     podssh proxy node://lab/web) from the node's next session, with no restart; podssh share rm web takes it \
     away, and the node refuses it from its next session; podssh share ls lists the shares on stdout, each name \
     and its HOST:PORT apart by a tab. A share's name has the form of a route's, and its service is TCP; a route \
     of the node's command line wins over a share of its name.",
    "The node keeps its shares in a file, one name=HOST:PORT on each line and # before a comment: node-NAME.shares \
     in the cache, beside its key, or the file of podssh node --shares FILE, which podssh share names with \
     --shares FILE too. The node reads it again for each session that names a route, on each of its roads but \
     the quick tunnel's, which serves one TARGET with no route; it says where at its start, and says once a line \
     that is no share, or a file that it refuses, as one that others may change. A change is made under the lock \
     of FILE.lock beside the file, on the file read again there, and kept whole by a rename, so that two changes \
     at once both count and a node never reads half of one; a lock that another change keeps for 5 s fails this \
     one (75). The lines that a change does not touch stay as they are. --node NAME names the node of this host; \
     with none, the one node whose key or shares are in the cache. A node whose sessions carry no route has no \
     share (podssh node --no-e2e, podssh node --temporary, or a udp: TARGET), and PODSSH_CACHE_DIR=none keeps no \
     file of them: --shares FILE names one (78 with neither).",
    "A share is a route of the node, so each door that holds a route holds a share: an allowlist's routes=web, \
     and the net's policy, whose rule to NODE/ROUTE names a share as node://NODE/ROUTE reaches it (see podssh \
     net). With no allowlist and no net, each operator with the pair's connect token reaches each share, as each \
     route. podssh share ls --net lists the shares that the net held here names for each member: the member, the \
     name and node://NODE/NAME apart by tabs. The net's owner lists them with podssh net --shares NAMES of add, \
     for a member with the role share. The list is the net's; each node serves what its own file holds.",
];
