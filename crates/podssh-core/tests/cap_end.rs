//! `CAP END` answers the server, not its `001` (T-091). A server that answers
//! `CAP LS` holds the registration until the client ends the negotiation:
//! ngircd 27's `001` came only after the client's `CAP END`. The lines here
//! are what ngircd 27 and InspIRCd 4.11.0 sent a client that registered with
//! `CAP LS 302` (captured on 2026-10-10). Since T-092 podssh asks only for
//! what it reads, so ngircd's list, `multi-prefix` alone, leaves nothing to
//! ask, and InspIRCd's has `echo-message`. A server with no `CAP` answers
//! `421`, and holds nothing.

use podssh_core::irc::cap::Stage;
use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Registered, Server, Session};

fn server() -> Server {
    Server {
        host: "irc.ngircd.test".into(),
        port: 6667,
        nick: "podtest".into(),
        username: "podtest".into(),
        realname: "podssh test".into(),
    }
}

/// What podssh writes for `bytes`, as lines.
fn answer(s: &mut Session, bytes: &[u8]) -> Vec<String> {
    let (out, _) = s.on_bytes(bytes);
    out.iter().map(|m| m.to_line()).collect()
}

const NGIRCD_LS: &[u8] = b":irc.ngircd.test CAP * LS :multi-prefix\r\n";
const LS: &[u8] = b":irc.inspircd.test CAP * LS :account-notify away-notify cap-notify echo-message extended-join inspircd.org/poison inspircd.org/stats-tags no-implicit-names standard-replies \r\n";
const ACK: &[u8] = b":irc.inspircd.test CAP pc2 ACK :echo-message\r\n";
// InspIRCd's NAK, of the form it sent for a request of two names, for the
// one name asked here.
const NAK: &[u8] = b":irc.inspircd.test CAP pc2 NAK :echo-message\r\n";
const WELCOME: &[u8] = b":irc.inspircd.test 001 pc2 :Welcome to the PodTest IRC Network pc2!pc2@127.0.0.1\r\n";

#[test]
fn cap_end_follows_the_answer_to_the_request() {
    for (answered, verb) in [(ACK, "ACK"), (NAK, "NAK")] {
        let mut s = Session::new(server(), ReapPolicy::default());
        let burst: Vec<String> = s.initial_burst().iter().map(|m| m.to_line()).collect();
        assert!(!burst.iter().any(|l| l.starts_with("CAP END")), "{burst:?}");
        let lines = answer(&mut s, LS);
        assert_eq!(lines, ["CAP REQ :echo-message"], "the request, and no end before its answer");
        let lines = answer(&mut s, answered);
        assert_eq!(lines, ["CAP END"], "the {verb} of the request ends the negotiation");
        assert_eq!(s.negotiation().stage(), Stage::Ended);
        // The server's `001` comes only now, and asks for nothing more.
        assert!(answer(&mut s, WELCOME).is_empty());
        assert_eq!(s.registered(), Registered::Yes);
    }
}

#[test]
fn cap_end_is_sent_at_once_when_nothing_is_wanted() {
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.initial_burst();
    // `sasl` is never asked for, so this list leaves nothing to ask.
    let lines = answer(&mut s, b":irc.ngircd.test CAP * LS :sasl\r\n");
    assert_eq!(lines, ["CAP END"], "no empty request, which would wait for an answer that ends nothing");
    assert_eq!(s.negotiation().stage(), Stage::Ended);
    // Nor does ngircd 27's own list: podssh does not read `multi-prefix`.
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.initial_burst();
    assert_eq!(answer(&mut s, NGIRCD_LS), ["CAP END"]);
}

#[test]
fn cap_end_is_not_sent_after_a_421_for_cap() {
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.initial_burst();
    let lines = answer(&mut s, b":irc.example.org 421 podtest CAP :Unknown command\r\n");
    assert!(lines.is_empty(), "a server with no CAP holds nothing, and gets no CAP END: {lines:?}");
    assert_eq!(s.registered(), Registered::Pending, "a 421 for CAP is no refusal of the registration");
    assert_eq!(s.negotiation().stage(), Stage::Ended);
    assert!(answer(&mut s, b":irc.example.org 001 podtest :Welcome\r\n").is_empty());
    assert_eq!(s.registered(), Registered::Yes);
    // A 421 for another command, before 001, is still a refusal.
    let mut other = Session::new(server(), ReapPolicy::default());
    let _ = other.initial_burst();
    let _ = answer(&mut other, b":irc.example.org 421 podtest FOO :Unknown command\r\n");
    assert!(matches!(other.registered(), Registered::Refused(_)), "{:?}", other.registered());
}

/// InspIRCd 4 with no cap module answers nothing to `CAP LS`, not even `421`,
/// and welcomes the client (captured on 2026-10-10): the negotiation ends
/// there, with no `CAP END`.
#[test]
fn a_welcome_before_any_answer_to_cap_ls_ends_the_negotiation() {
    let mut s = Session::new(server(), ReapPolicy::default());
    let _ = s.initial_burst();
    let welcome = b":irc.inspircd.test 001 pq :Welcome to the PodTest IRC Network pq!pq@127.0.0.1\r\n";
    let lines = answer(&mut s, welcome);
    assert!(lines.is_empty(), "no CAP END to a server with no CAP: {lines:?}");
    assert_eq!(s.registered(), Registered::Yes);
    assert_eq!(s.negotiation().stage(), Stage::Ended);
}

/// A server's `CAP` names its target, `*` or the client's nick, before the
/// verb; ngircd names the nick in its `ACK`. Each reads as its verb, and
/// goes back out as it came.
#[test]
fn a_server_s_cap_names_its_target_a_star_or_the_nick() {
    use podssh_core::irc::message::{CapVerb, Command, Message};
    for (line, target, verb) in [
        (":irc.ngircd.test CAP * LS :multi-prefix", "*", CapVerb::Ls),
        (":irc.ngircd.test CAP podtest ACK :multi-prefix", "podtest", CapVerb::Ack),
        (":irc.ngircd.test CAP podtest NAK :multi-prefix", "podtest", CapVerb::Nak),
    ] {
        let message = Message::parse(line).expect(line);
        let Command::Cap { target: Some(t), subcommand, .. } = &message.command else { panic!("{line}: {message:?}") };
        assert_eq!((t.0.as_str(), *subcommand), (target, verb), "{line}");
        assert_eq!(message.to_line(), line);
    }
    // A client's own CAP starts with its verb.
    let ls = Message::parse("CAP LS 302").unwrap();
    assert!(matches!(ls.command, Command::Cap { target: None, subcommand: CapVerb::Ls, .. }), "{ls:?}");
}
