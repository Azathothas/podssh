//! The note of a node's person (T-638), for `node`, apart from the others so
//! that each file stays short.

/// `node --ask`.
pub(super) const NODE: &str = "With --ask, a person at the node's terminal lets each operator key in, after \
     the node's door, on each road of the node: for each key that --allow, the net or a grant lets through, \
     the node asks on stderr and reads y or n on stdin. The question names the key's fingerprint, its name in \
     the net held here, what it asks (the target, a route, or an exit's target) and whether a grant brought \
     it; no answer within 100 s is a no. One question for each key at a time: each session of that key that \
     comes meanwhile waits for its answer; one question shows at a time, and a line typed before it showed \
     is no answer to it. A yes lets the key in while one of its sessions is open and 120 s after its last, \
     with no question; a no stands 15 s, in which the key is refused with no question and with its grant \
     unspent. A key that the door refuses raises no question, and a yes lets in nothing that the door \
     refused; a grant meets the question after its check, which spends it. The node's line of each session \
     that came in says by what: the door or a grant, and a yes or its cover. The operator hears only that \
     its key is not let in (77). An operator waits 130 s for the node's verdict, one of an earlier podssh \
     30 s, and a yes that comes later lets its next session in. stdin and stderr must each be a terminal, \
     else --ask is refused (78); --detach, --install, --uninstall, --temporary, --no-e2e and --carrier \
     stdio are refused with it (64), as nobody could answer there. Nothing is kept: a node that starts again \
     asks again.";
