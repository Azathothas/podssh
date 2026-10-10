//! The capabilities that podssh asks for (T-092), against what three real
//! servers sent a client of `CAP LS 302`, captured byte for byte on the
//! loopback of the build image on 2026-10-10: ngircd 27, InspIRCd 4.11.0
//! with its IRCv3 modules, and ergo 2.18.0. ergo sends its list on two
//! lines, the first with the `*` marker, and gives values; InspIRCd ends its
//! list with a space; each server refused a request that carries a value.

use podssh_core::irc::cap::Stage;
use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Server, Session};
use podssh_core::irc::Event;

const ERGO_LS: [&[u8]; 2] = [
    b":ergo.test CAP * LS * :account-notify account-tag away-notify batch cap-notify chghost draft/account-registration=before-connect draft/channel-rename draft/chathistory draft/event-playback draft/extended-isupport draft/languages=17,en,~bs,~de,~el,~en-AU,~es,~fi,~fr-FR,~it,~nl,~no,~pl,~pt-BR,~ro,~sq-AL,~tr-TR,~zh-CN draft/metadata-2=before-connect,max-subs=100,max-keys=100 draft/multiline=max-bytes=4096,max-lines=100 draft/no-implicit-names draft/persistence draft/pre-away draft/read-marker\r\n",
    b":ergo.test CAP * LS :draft/relaymsg=/ echo-message ergo.chat/nope extended-join extended-monitor invite-notify labeled-response message-tags multi-prefix sasl=PLAIN,EXTERNAL,SCRAM-SHA-256 server-time setname standard-replies userhost-in-names znc.in/playback znc.in/self-message\r\n",
];
const ERGO_ACK: &[u8] = b":ergo.test CAP * ACK :echo-message znc.in/self-message\r\n";
const ERGO_ACK_MIDDLE: &[u8] = b":ergo.test CAP * ACK echo-message\r\n";
const INSPIRCD_LS: &[u8] = b":irc.inspircd.test CAP * LS :account-notify away-notify cap-notify echo-message extended-join inspircd.org/poison inspircd.org/stats-tags no-implicit-names standard-replies \r\n";
const INSPIRCD_ACK: &[u8] = b":irc.inspircd.test CAP pc2 ACK :echo-message\r\n";
const INSPIRCD_OFF: &[u8] = b":irc.inspircd.test CAP pc2 ACK :-echo-message\r\n";
const INSPIRCD_WELCOME: &[u8] = b":irc.inspircd.test 001 pe1 :Welcome to the PodTest IRC Network pe1!pe1@127.0.0.1\r\n";
// The same server's echoes, with `echo-message` on: a message to the
// client's own nick came back twice, one copy after the other.
const INSPIRCD_ECHOES: &[&[u8]] = &[
    b":pe1!pe1@127.0.0.1 PRIVMSG #podtest :hello channel\r\n",
    b":pe1!pe1@127.0.0.1 PRIVMSG pe1 :hello self\r\n",
    b":pe1!pe1@127.0.0.1 PRIVMSG pe1 :hello self\r\n",
    b":pe1!pe1@127.0.0.1 PRIVMSG #podtest :PODSSH1|x\r\n",
];

fn server(nick: &str) -> Server {
    Server {
        host: "irc.test".into(),
        port: 6667,
        nick: nick.into(),
        username: nick.into(),
        realname: "podssh test".into(),
    }
}

/// What podssh writes for `bytes`, as lines.
fn answer(s: &mut Session, bytes: &[u8]) -> Vec<String> {
    let (out, _) = s.on_bytes(bytes);
    out.iter().map(|m| m.to_line()).collect()
}

/// A session that has sent `CAP LS 302`.
fn started(nick: &str) -> Session {
    let mut s = Session::new(server(nick), ReapPolicy::default());
    let _ = s.initial_burst();
    s
}

#[test]
fn only_listed_capabilities_are_requested() {
    let mut s = started("pc1");
    let _ = answer(&mut s, ERGO_LS[0]);
    assert_eq!(answer(&mut s, ERGO_LS[1]), ["CAP REQ :echo-message znc.in/self-message"]);
}

#[test]
fn a_value_is_never_sent_back() {
    let mut s = started("pc1");
    let mut sent = answer(&mut s, ERGO_LS[0]);
    sent.extend(answer(&mut s, ERGO_LS[1]));
    assert!(sent.iter().all(|l| !l.contains('=') && !l.contains("sasl")), "{sent:?}");
    // The names are kept, the values left out.
    assert!(s.negotiation().offered().iter().any(|o| o == "sasl"));
    assert!(s.negotiation().offered().iter().all(|o| !o.contains('=')), "{:?}", s.negotiation().offered());
}

#[test]
fn a_list_on_several_lines_gives_one_request() {
    let mut s = started("pc1");
    assert!(answer(&mut s, ERGO_LS[0]).is_empty(), "no request before the last line");
    assert_eq!(s.negotiation().stage(), Stage::LsSent);
    assert_eq!(answer(&mut s, ERGO_LS[1]).len(), 1);
    assert_eq!(answer(&mut s, ERGO_ACK), ["CAP END"]);
    assert_eq!(s.negotiation().enabled(), ["echo-message", "znc.in/self-message"]);
}

#[test]
fn the_continuation_marker_is_not_a_capability() {
    let mut s = started("pc1");
    let _ = answer(&mut s, ERGO_LS[0]);
    let _ = answer(&mut s, ERGO_LS[1]);
    let offered = s.negotiation().offered();
    assert!(!offered.iter().any(|o| o == "*"), "{offered:?}");
    assert!(offered.iter().any(|o| o == "account-notify") && offered.iter().any(|o| o == "znc.in/self-message"));
}

#[test]
fn only_an_offered_name_is_asked_and_an_ack_enables_what_was_asked() {
    // InspIRCd offers no znc.in/self-message, and refused a request that
    // named it whole; its list ends with a space.
    let mut s = started("pc2");
    assert_eq!(answer(&mut s, INSPIRCD_LS), ["CAP REQ :echo-message"]);
    assert_eq!(answer(&mut s, INSPIRCD_ACK), ["CAP END"]);
    assert_eq!(s.negotiation().enabled(), ["echo-message"]);
    // `-name` turns one off.
    assert!(answer(&mut s, INSPIRCD_OFF).is_empty());
    assert!(s.negotiation().enabled().is_empty());
    // ergo's ACK names it as a middle.
    let mut s = started("pc1");
    let _ = answer(&mut s, ERGO_LS[0]);
    let _ = answer(&mut s, ERGO_LS[1]);
    assert_eq!(answer(&mut s, ERGO_ACK_MIDDLE), ["CAP END"]);
    assert_eq!(s.negotiation().enabled(), ["echo-message"], "only what the ACK names");
}

#[test]
fn each_echo_is_shown_once_and_is_no_peer_s_message() {
    let mut s = started("pe1");
    let _ = answer(&mut s, INSPIRCD_LS);
    let _ = answer(&mut s, INSPIRCD_ACK);
    let _ = answer(&mut s, INSPIRCD_WELCOME);
    let mut events = Vec::new();
    for line in INSPIRCD_ECHOES {
        events.extend(s.on_bytes(line).1);
    }
    let echoes: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            Event::Echo { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(echoes, ["hello channel", "hello self", "PODSSH1|x"], "{events:?}");
    assert!(
        !events.iter().any(|e| matches!(e, Event::Privmsg { .. } | Event::Transfer(_))),
        "an echo read as a peer's: {events:?}"
    );
    // A peer's message is still a message.
    let (_, events) = s.on_bytes(b":bob!b@127.0.0.1 PRIVMSG #podtest :hello\r\n");
    assert!(matches!(&events[..], [Event::Privmsg { .. }]), "{events:?}");
}

#[test]
fn without_echo_message_a_message_to_oneself_is_a_message() {
    // ngircd offers no echo-message; a message to the client's own nick
    // comes back once, as before.
    let mut s = started("pe1");
    let _ = answer(&mut s, b":irc.ngircd.test CAP * LS :multi-prefix\r\n");
    let _ = answer(&mut s, INSPIRCD_WELCOME);
    let (_, events) = s.on_bytes(b":pe1!~pe1@127.0.0.1 PRIVMSG pe1 :hello self\r\n");
    assert!(matches!(&events[..], [Event::Privmsg { .. }]), "{events:?}");
}
