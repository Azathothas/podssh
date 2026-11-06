//! Pairing by a short code (T-086): a node's host gives a code that a person
//! reads to the operator, who types it, and the two ends move what a pair's
//! file moved before: the operator's part of the pair and the node's key one
//! way, the operator's key the other. The code is used once and lives 10
//! minutes; it never crosses the network.
//!
//! The ends meet at a magic-wormhole mailbox, a WebSocket on port 443 that
//! needs no account (the operator's ruling Q65 lets podssh use the public
//! ones unasked; their terms are in docs/carriers.md), or at podssh's relay
//! role, which serves the same protocol (`crate::serve::mailbox`). The
//! mailbox stores and forwards ([`mailbox`]); the ends run SPAKE2 keyed by
//! the whole code over it, then seal each later message with a key of it
//! ([`wormhole`]), as magic-wormhole's own client does, so that a peer of its
//! Python library pairs with podssh's. The mailbox learns nothing of the
//! code and can change nothing, and an attacker who claims the code's
//! nameplate gets one guess of its 24 bits: the giver ends the code at the
//! first exchange, whatever its end ([`run`]). What the ends say is
//! podssh's own ([`exchange`]).

pub mod exchange;
pub mod mailbox;
pub mod phrase;
pub mod run;
pub mod words;
pub mod wormhole;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::url::WsUrl;

pub use phrase::Code;

/// podssh's application in the mailbox, as magic-wormhole asks each to name
/// one: nameplates and mailboxes of another application never meet it.
pub const APPID: &str = "github.com/PodUtils/podssh/pair";
/// The public mailboxes, in order: magic-wormhole's, on port 443 since its
/// commit "public_relay.py: use TLS" (2026-05-13), then Least Authority's:
/// the services of the kind `mailbox` of `pod-services`, by their rank.
pub fn public_mailboxes() -> Vec<String> {
    pod_services::of_kind("mailbox").filter_map(|s| s.endpoint("mailbox")).map(|e| e.url()).collect()
}
/// `no` turns pairing by code off; mailbox URLs, by commas, name others.
pub const ENV: &str = "PODSSH_PAIR_MAILBOX";
/// How long a code lives: past it the giver leaves, and the code fails.
pub const LIFETIME: Duration = Duration::from_secs(600);
/// The words of a code after its nameplate: 24 bits, one guess for each.
pub const WORDS: usize = 3;

/// Where the lines of a pairing go, for the user. No line holds the code.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// Why a pairing by code gave nothing. No variant holds the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// No mailbox could be reached: why, for each.
    Unreachable(String),
    /// A mailbox refused this end, in its words.
    Refused(String),
    /// Nobody took the code within its life: the giver's end.
    Expired(Duration),
    /// No giver waits at the code: it expired, it was used, or it never was.
    Nobody,
    /// The two ends' keys differ: a code typed wrong, or a guess. The code
    /// is spent at both ends.
    WrongCode,
    /// The other end broke the exchange, or is no pairing of podssh's.
    Peer(String),
    /// This end refused what the other end gave: why.
    Mine(String),
    /// The connection to the mailbox failed or stalled.
    Broken(String),
    /// The system gave no random bytes.
    NoRandom,
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failed::Unreachable(why) => write!(f, "no mailbox could be reached: {why}"),
            Failed::Refused(why) | Failed::Peer(why) | Failed::Mine(why) | Failed::Broken(why) => f.write_str(why),
            Failed::Expired(life) => {
                write!(f, "nobody took the code within its {} minutes; it is spent", life.as_secs().div_ceil(60))
            }
            Failed::Nobody => f.write_str("no node waits at this code: it expired, it was used, or it was typed wrong"),
            Failed::WrongCode => f.write_str(
                "the code did not match at the other end: it was typed wrong, or someone guessed; the code is spent",
            ),
            Failed::NoRandom => f.write_str("the system gave no random bytes"),
        }
    }
}

impl std::error::Error for Failed {}

/// The mailboxes to try, in order: the ones of `named` (`--pair-mailbox`),
/// else of the variable's `value`, else the public ones. `no` turns pairing
/// by code off, which is an error with the way that is left. A refusal does
/// not echo the text, as a URL's query may hold a secret.
pub fn mailboxes(named: Option<&str>, value: Option<&str>) -> Result<Vec<WsUrl>, String> {
    mailboxes_for(named, value, "give the operator's part as a file (podssh relay pair NAME --operator-file FILE)")
}

/// [`mailboxes`], with `way`, the way left when `no` turns the code off,
/// for each command that gives or takes one (T-616).
pub fn mailboxes_for(named: Option<&str>, value: Option<&str>, way: &str) -> Result<Vec<WsUrl>, String> {
    let (text, whose) = match named.map(str::trim).filter(|t| !t.is_empty()) {
        Some(text) => (text, "--pair-mailbox"),
        None => (value.map(str::trim).unwrap_or_default(), ENV),
    };
    match text.to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => public_mailboxes().iter().map(|url| WsUrl::parse(url)).collect(),
        "no" | "off" | "false" | "0" => Err(format!("{whose} no turns pairing by code off: {way}")),
        _ => text
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(|url| WsUrl::parse(url).map_err(|why| format!("{whose}: no, or mailboxes' URLs: {why}")))
            .collect(),
    }
}

/// Lower-case hex, as the mailbox carries a body.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The bytes of hex in either case; `None` for another text.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16);
    text.as_bytes().chunks(2).map(|pair| u8::try_from(digit(pair[0])? * 16 + digit(pair[1])?).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_mailboxes_come_unless_a_flag_or_the_variable_names_others_or_no() {
        let public = mailboxes(None, None).unwrap();
        assert_eq!(public.len(), 2);
        assert_eq!((public[0].tls, public[0].host.as_str(), public[0].port), (true, "relay.magic-wormhole.io", 443));
        assert_eq!(public[1].host, "mailbox.mw.leastauthority.com");
        assert!(public.iter().all(|url| url.target == "/v1"));
        assert_eq!(mailboxes(None, Some(" yes ")).unwrap(), public);
        let own = mailboxes(None, Some("ws://127.0.0.1:4000/v1, wss://relay.example.org/v1/mailbox")).unwrap();
        assert_eq!(own.len(), 2);
        assert_eq!((own[0].tls, own[0].port), (false, 4000));
        assert_eq!(own[1].target, "/v1/mailbox");
        let flag = mailboxes(Some("wss://mine.example.org/v1/mailbox"), Some("no")).unwrap();
        assert_eq!(flag[0].host, "mine.example.org", "the flag wins over the variable");
        let off = mailboxes(None, Some("No")).unwrap_err();
        assert!(off.starts_with("PODSSH_PAIR_MAILBOX no turns pairing by code off"), "{off}");
        assert!(mailboxes(Some("off"), None).unwrap_err().starts_with("--pair-mailbox no"));
        let bad = mailboxes(None, Some("https://x.example/?key=SECRET")).unwrap_err();
        assert!(bad.starts_with("PODSSH_PAIR_MAILBOX: ") && !bad.contains("SECRET"), "{bad}");
        let net = mailboxes_for(None, Some("off"), "the net's own way").unwrap_err();
        assert_eq!(net, "PODSSH_PAIR_MAILBOX no turns pairing by code off: the net's own way");
        assert_eq!(mailboxes_for(None, None, "x").unwrap(), public);
    }

    #[test]
    fn hex_goes_both_ways_and_refuses_what_is_not_hex() {
        assert_eq!(hex(&[0, 0x5a, 0xff]), "005aff");
        assert_eq!(unhex("005AfF"), Some(vec![0, 0x5a, 0xff]));
        for bad in ["0", "0g", "zz", "a b "] {
            assert_eq!(unhex(bad), None, "{bad:?}");
        }
        assert_eq!(unhex(""), Some(Vec::new()));
    }

    #[test]
    fn no_failure_says_more_than_its_words() {
        assert!(Failed::Expired(LIFETIME).to_string().contains("within its 10 minutes"));
        assert!(Failed::WrongCode.to_string().contains("the code is spent"));
        assert!(Failed::Nobody.to_string().starts_with("no node waits at this code"));
    }
}
