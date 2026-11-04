//! The notes of the tokens of one leg and of the stop token's rotation
//! (T-615), for `node`, `operator`, `ssh` and `relay`, apart from the others
//! so that each file stays short.

/// The node's tokens of one leg, and its rotation of the stop token.
pub(super) const NODE: &str = "Where its relay is podssh relay serve, whose hello on the node's socket says \
     so, each session that the node lets in gets the seed of its tokens of one leg in the node's verdict, \
     inside the end-to-end channel, where no relay sees it: one connect token for each leg after the \
     first, which only that leg takes, so that a token that a proxy logged from a leg's headers is spent \
     already. The node registers the SHA-256 of the next four at the relay, on its socket, never a token; \
     the relay says which one each upgrade took, and the node registers the four after it; a session's end \
     withdraws them, and a new socket registers each session's again. A session of --plain or --no-e2e \
     gets none. At its first socket that heard it, and each day after, the node rotates the pair's stop \
     token there too: it draws the next one, names its SHA-256 to the relay by the token now, keeps it in \
     the store in the place of the one before, then uses it once, which makes it the pair's and ends the \
     one before; a stop at any step leaves a token that the relay takes. podssh relay revoke, and the \
     renewal of podssh relay pair, on the node's host read the store, so they take the new one; a copy of \
     the pair on another host can no longer stop or renew it. A pair of --pair-file keeps its stop token, as its file \
     is the user's and is never rewritten, and the node says so. The next pair that the node goes on with at \
     an expiry is rotated so too, from its own first socket that hears the offer, and renewed in its last 24 \
     hours where its relay renews, also when the pair before it was on a relay that does neither. A relay of \
     the contract (the default relay) offers neither, and the pair's tokens stay as they were.";

/// An operator's legs, each with a token of its own.
pub(super) const OPERATOR: &str = "Where the node gave the seed of the session's tokens of one leg (a node \
     through podssh relay serve), each leg after the first, the one that a resume, a move to a new link or \
     a spare link opens, carries the session's next token in the place of the pair's connect token, which \
     the first leg alone carries; the relay takes each once. So a session of a pair whose connect token \
     takes one upgrade alone (see podssh relay) resumes too, and a token that leaks from a leg's headers \
     is spent already. A token that the \
     relay refuses is tried once more, then the next one, and after eight refusals in a row the legs take \
     the pair's token, as with a node that gives no seed.";

/// `ssh node://NAME` and its legs.
pub(super) const SSH: &str = "node://NAME opens each leg after the first with the session's next token of one \
     leg, where the node gave them through podssh relay serve, as podssh operator does (see its notes).";

/// The relay's side of it, for `relay serve`.
pub(super) const RELAY: &str = "Beside the contract, podssh relay serve takes a node's tokens of one leg: the \
     node's socket gets a hello that offers them, and a text frame of the node's, {\"type\":\"token\", \
     \"digest\":HEX,\"expires\":MS}, registers the SHA-256 of one until MS, a day at most, or withdraws it \
     with an end that passed. Such a token takes one upgrade of /v1/connect/NAME, never the status, and \
     only while the node is joined with room for a session, else 503 and the token waits; the node hears \
     {\"type\":\"spent\",\"digest\":HEX} before the session's open, and a token taken once is refused after, \
     also when the node registers it again. A pair keeps 256 such tokens at once, and 256 spent ones, the \
     ones that end first making room; they live in memory, and a node registers its own again on its next \
     socket. POST /v1/rotate/NAME with the stop token and {\"digest\":HEX} makes HEX, the SHA-256 of the \
     next stop token, the one to come: the first request that uses that token makes it the pair's stop \
     token and ends each one before it, so the new token crosses no wire before its use; --pairs FILE \
     keeps both. /relays.json offers both, as reverse.leg_tokens and reverse.rotate.";
