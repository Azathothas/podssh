//! A node's ask for sessions readied ahead (T-650, GitHub #148). A run of
//! short legs to one node (a copy of many files, a loop of commands) paid, at
//! each leg, a round trip of `open` and `ready` and the node's open of its
//! local side before its first byte. podssh's relay role keeps a few sessions
//! open and readied for the node's next operators, but only for a node that
//! asks, by its own flag: a spare is a session at rest at the node, and with
//! no layer and no channel a connection to TARGET with nobody on it, which the
//! node's owner chooses to pay for.
//!
//! The role's `hello` offers them (`"spares": true`, an offer of
//! `crate::answer`); a node of `--spares N` answers once on each socket that
//! heard the offer, `{"type":"spares","want":N}`. The role's `open` of a spare
//! says `"spare": true`, which this node reads nothing of: a spare is a session
//! as each other, readied once the handler has its local side. The node's
//! line says once whether its relay keeps them.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

use serde_json::json;

use super::control::Hello;

/// The field of the role's `hello` that offers them.
pub const OFFER: &str = "spares";
/// The type of the node's frame that asks for them.
pub const ASK: &str = "spares";
/// The most that a node asks for, and that the role keeps for one: each is
/// a session at rest, inside the node's 64.
pub const MOST: u8 = 16;

/// Where the node's line of its spares goes.
type Say = Box<dyn Fn(&str) + Send + Sync>;

static SAY: OnceLock<Say> = OnceLock::new();

/// What the node's line said last: 0 nothing, 1 kept, 2 not offered; a
/// socket that hears the same says nothing again.
static SAID: AtomicU8 = AtomicU8::new(0);

/// Send the node's line of its spares to `say` from now on: its stderr, which
/// a detached node's log keeps. The first call holds.
pub fn tell(say: impl Fn(&str) + Send + Sync + 'static) {
    let _ = SAY.set(Box::new(say));
}

/// Whether a role's `hello` offers sessions readied ahead: `true`, and nothing
/// else.
pub fn offered(hello: &Hello) -> bool {
    crate::answer::offers(hello.extra.get(OFFER))
}

/// The node's frame that asks for `want`, [`MOST`] at most.
pub fn ask(want: u8) -> String {
    json!({ "type": ASK, "want": want.min(MOST) }).to_string()
}

/// What a node that wants `want` answers to `hello`: the frame that asks,
/// where the role offers them; nothing for a node that wants none. The node's
/// line says whether its relay keeps them, when that changed.
pub fn heard(hello: &Hello, want: u8) -> Option<String> {
    if want == 0 {
        return None;
    }
    let offered = offered(hello);
    let now = if offered { 1 } else { 2 };
    if SAID.swap(now, Ordering::SeqCst) != now {
        if let Some(say) = SAY.get() {
            say(&line(offered, want));
        }
    }
    offered.then(|| ask(want))
}

/// The node's line of its spares, by whether its relay offers them.
pub fn line(offered: bool, want: u8) -> String {
    match offered {
        true => format!(
            "the relay keeps up to {} sessions readied ahead for this node's operators (--spares)",
            want.min(MOST)
        ),
        false => "the relay keeps no session readied ahead (its hello offers none), so --spares does nothing there; \
                  podssh relay serve keeps them"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(text: &str) -> Hello {
        serde_json::from_str(text).unwrap()
    }

    /// The offer is `true` alone (T-633); a node asks only where it is made,
    /// and only when it wants some.
    #[test]
    fn a_node_asks_only_where_the_role_offers_and_it_wants_some() {
        let offering = hello(r#"{"maxSessions":64,"spares":true}"#);
        assert!(offered(&offering));
        assert_eq!(heard(&offering, 3).as_deref(), Some(r#"{"type":"spares","want":3}"#));
        assert_eq!(heard(&offering, 0), None, "a node that wants none says nothing");
        for text in [r#"{"maxSessions":64}"#, r#"{"spares":false}"#, r#"{"spares":"true"}"#, r#"{"spares":1}"#] {
            assert!(!offered(&hello(text)), "{text}");
            assert_eq!(heard(&hello(text), 3), None, "{text}");
        }
    }

    #[test]
    fn a_node_asks_for_sixteen_at_most() {
        let asked: serde_json::Value = serde_json::from_str(&ask(40)).unwrap();
        assert_eq!(asked["want"], 16);
        assert!(line(true, 40).contains("up to 16 sessions"));
        assert!(line(false, 4).contains("does nothing there"));
    }
}
