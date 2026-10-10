//! The session knows its own nick (T-095), against what three real servers
//! sent, captured byte for byte on the loopback of the build image on
//! 2026-10-10: ngircd 27, InspIRCd 4.11.0 and ergo 2.18.0. A `JOIN`, a
//! `PART` or a `KICK` changes the channels to rejoin only when it is about
//! this client's nick; the `005` lines add up; a reconnect is a new
//! connection that keeps only the channels; a nick in use before the
//! welcome is tried again with a suffix.

use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Registered, RegistrationFailure, Server, Session};
use podssh_core::irc::Event;

const NGIRCD_LS: &[u8] = b":irc.ngircd.test CAP * LS :multi-prefix\r\n";
const NGIRCD_WELCOME: &[u8] = b":irc.ngircd.test 001 pa :Welcome to the Internet Relay Network pa!~pa@127.0.0.1\r\n";
const NGIRCD_005: [&[u8]; 2] = [
    b":irc.ngircd.test 005 pa RFC2812 IRCD=ngIRCd CHARSET=UTF-8 CASEMAPPING=ascii PREFIX=(qaohv)~&@%+ CHANTYPES=#&+ CHANMODES=beI,k,l,imMnOPQRstVz CHANLIMIT=#&+:10 :are supported on this server\r\n",
    b":irc.ngircd.test 005 pa CHANNELLEN=50 NICKLEN=9 TOPICLEN=490 AWAYLEN=127 KICKLEN=400 MODES=5 MAXLIST=beI:50 EXCEPTS=e INVEX=I PENALTY FNC :are supported on this server\r\n",
];
const INSPIRCD_005: [&[u8]; 3] = [
    b":irc.inspircd.test 005 pa AWAYLEN=200 CASEMAPPING=ascii CHANLIMIT=#:20 CHANMODES=b,k,l,imnpst CHANNELLEN=60 CHANTYPES=# ELIST=CMNTU EXTBAN=, HOSTLEN=64 KEYLEN=32 KICKLEN=300 LINELEN=512 :are supported by this server\r\n",
    b":irc.inspircd.test 005 pa MAXLIST=b:100 MAXTARGETS=5 MODES=20 NAMELEN=130 NETWORK=PodTest NICKLEN=30 PREFIX=(ov)@+ SAFELIST STATUSMSG=@+ TOPICLEN=330 USERLEN=10 USERMODES=,,s,iow :are supported by this server\r\n",
    b":irc.inspircd.test 005 pa WHOX :are supported by this server\r\n",
];
const NGIRCD_PEER_JOIN: &[u8] = b":pb!~pb@127.0.0.1 JOIN :#t\r\n";
const NGIRCD_PEER_PART: &[u8] = b":pb!~pb@127.0.0.1 PART #t :bye\r\n";
const ERGO_PEER_JOIN: &[u8] = b":pb!~u@j927qtzt3xx7u.irc JOIN #t\r\n";
const ERGO_PEER_PART: &[u8] = b":pb!~u@j927qtzt3xx7u.irc PART #t bye\r\n";
const NGIRCD_KICK: &[u8] = b":pa!~pa@127.0.0.1 KICK #t pb :out\r\n";
const ERGO_KICK: &[u8] = b":pa!~u@j927qtzt3xx7u.irc KICK #t pb out\r\n";
const NGIRCD_IN_USE: &[u8] = b":irc.ngircd.test 433 * pa :Nickname already in use\r\n";
const NGIRCD_WELCOME_SUFFIXED: &[u8] =
    b":irc.ngircd.test 001 pa_ :Welcome to the Internet Relay Network pa_!~pa@127.0.0.1\r\n";
const NGIRCD_NICK: &[u8] = b":pa!~pa@127.0.0.1 NICK :pa2\r\n";
const ERGO_NICK: &[u8] = b":pa!~u@j927qtzt3xx7u.irc NICK pa2\r\n";

fn server(nick: &str) -> Server {
    Server {
        host: "irc.test".into(),
        port: 6667,
        nick: nick.into(),
        username: nick.into(),
        realname: "podssh test".into(),
    }
}

/// A session of `nick`, registered with ngircd's lines, in `#t`: ngircd's
/// welcome with the session's own nick in it.
fn joined(nick: &str) -> Session {
    let mut s = Session::new(server(nick), ReapPolicy::default());
    let _ = s.initial_burst();
    let _ = s.on_bytes(NGIRCD_LS);
    let welcome = String::from_utf8_lossy(NGIRCD_WELCOME).replace("pa", nick);
    let _ = s.on_bytes(welcome.as_bytes());
    let _ = s.send_join("#t", None);
    s
}

#[test]
fn a_part_by_another_user_keeps_the_channel() {
    for (join, part) in [(NGIRCD_PEER_JOIN, NGIRCD_PEER_PART), (ERGO_PEER_JOIN, ERGO_PEER_PART)] {
        let mut s = joined("pa");
        let (_, events) = s.on_bytes(join);
        assert!(
            matches!(&events[..], [Event::PeerJoined { nick, channel }] if nick == "pb" && channel == "#t"),
            "{events:?}"
        );
        let (_, events) = s.on_bytes(part);
        assert!(matches!(&events[..], [Event::PeerLeft { nick, .. }] if nick == "pb"), "{events:?}");
        assert_eq!(s.memory().channels(), ["#t"], "another user's PART took the channel");
    }
}

#[test]
fn a_kick_of_this_client_is_forgotten_and_of_another_is_an_event() {
    for kick in [NGIRCD_KICK, ERGO_KICK] {
        // pb, kicked: the channel is not joined again.
        let mut s = joined("pb");
        let (_, events) = s.on_bytes(kick);
        assert!(
            matches!(&events[..], [Event::Kicked { channel, by, reason: Some(r) }] if channel == "#t" && by == "pa" && r == "out"),
            "{events:?}"
        );
        assert!(s.memory().is_empty());
        assert!(!s.reconnect_burst().iter().any(|m| m.to_line().starts_with("JOIN")));
        // pa, who kicked: another user left.
        let mut s = joined("pa");
        let (_, events) = s.on_bytes(kick);
        assert!(matches!(&events[..], [Event::PeerLeft { nick, .. }] if nick == "pb"), "{events:?}");
        assert_eq!(s.memory().channels(), ["#t"]);
    }
}

#[test]
fn a_nick_change_of_this_client_is_followed() {
    for nick in [NGIRCD_NICK, ERGO_NICK] {
        let mut s = joined("pa");
        let _ = s.on_bytes(nick);
        assert_eq!(s.nick(), "pa2");
        // Lines of the new nick are this client's.
        let (_, events) = s.on_bytes(b":pa2!~pa@127.0.0.1 PART #t :bye\r\n");
        assert!(matches!(&events[..], [Event::Left { .. }]), "{events:?}");
        assert!(s.memory().is_empty());
    }
}

#[test]
fn the_005_lines_add_up_and_a_minus_takes_a_token_away() {
    let mut s = joined("pa");
    for line in NGIRCD_005 {
        let _ = s.on_bytes(line);
    }
    assert_eq!(s.isupport().get("CASEMAPPING"), Some("ascii"), "the first line's token, kept");
    assert_eq!(s.isupport().nicklen(), 9);
    let mut s = joined("pa");
    for line in INSPIRCD_005 {
        let _ = s.on_bytes(line);
    }
    assert_eq!((s.isupport().get("CASEMAPPING"), s.isupport().nicklen()), (Some("ascii"), 30));
    assert!(s.isupport().contains("WHOX") && s.isupport().contains("SAFELIST"));
    let _ = s.on_bytes(b":irc.inspircd.test 005 pa -WHOX :are supported by this server\r\n");
    assert!(!s.isupport().contains("WHOX"));
}

#[test]
fn nicks_compare_by_the_casemapping() {
    // No CASEMAPPING is rfc1459: `[]\~` fold to `{}|^`.
    let mut s = Session::new(server("[pa]"), ReapPolicy::default());
    let _ = s.initial_burst();
    let _ = s.on_bytes(b":irc.test 001 [pa] :Welcome\r\n");
    let _ = s.send_join("#t", None);
    let (_, events) = s.on_bytes(b":{PA}!u@h PART #t\r\n");
    assert!(matches!(&events[..], [Event::Left { .. }]), "{events:?}");
    // With CASEMAPPING=ascii they are two nicks.
    let mut s = Session::new(server("[pa]"), ReapPolicy::default());
    let _ = s.initial_burst();
    let _ = s.on_bytes(b":irc.test 001 [pa] :Welcome\r\n");
    let _ = s.on_bytes(b":irc.test 005 [pa] CASEMAPPING=ascii :are supported by this server\r\n");
    let _ = s.send_join("#t", None);
    let (_, events) = s.on_bytes(b":{PA}!u@h PART #t\r\n");
    assert!(matches!(&events[..], [Event::PeerLeft { .. }]), "{events:?}");
}

#[test]
fn a_nick_in_use_before_the_welcome_is_tried_with_a_suffix_three_times() {
    let mut s = Session::new(server("pa"), ReapPolicy::default());
    let _ = s.initial_burst();
    let _ = s.on_bytes(NGIRCD_LS);
    let mut tried = Vec::new();
    for _ in 0..3 {
        let (out, _) = s.on_bytes(NGIRCD_IN_USE);
        tried.extend(out.iter().map(|m| m.to_line()));
        assert_eq!(s.registered(), Registered::Pending);
    }
    assert_eq!(tried, ["NICK pa_", "NICK pa__", "NICK pa___"]);
    let _ = s.on_bytes(NGIRCD_IN_USE);
    assert_eq!(s.registered(), Registered::Refused(RegistrationFailure::NicknameInUse));
    // The server took `pa_`: its welcome names the nick in use from now on.
    let mut s = Session::new(server("pa"), ReapPolicy::default());
    let _ = s.initial_burst();
    let _ = s.on_bytes(NGIRCD_LS);
    let _ = s.on_bytes(NGIRCD_IN_USE);
    let _ = s.on_bytes(NGIRCD_WELCOME_SUFFIXED);
    assert_eq!((s.registered(), s.nick()), (Registered::Yes, "pa_"));
    // After the welcome, a 433 is only an event.
    let (out, events) = s.on_bytes(b":irc.ngircd.test 433 pa_ pa2 :Nickname already in use\r\n");
    assert!(out.is_empty() && matches!(&events[..], [Event::Numeric { code: 433, .. }]), "{out:?} {events:?}");
    assert_eq!(s.registered(), Registered::Yes);
}

#[test]
fn a_reconnect_is_a_new_connection_that_keeps_only_the_channels() {
    let mut s = Session::new(server("pa"), ReapPolicy::default());
    let _ = s.initial_burst();
    let _ = s.on_bytes(NGIRCD_LS);
    let _ = s.on_bytes(NGIRCD_IN_USE);
    let _ = s.on_bytes(NGIRCD_WELCOME_SUFFIXED);
    for line in NGIRCD_005 {
        let _ = s.on_bytes(line);
    }
    let _ = s.send_join("#t", None);
    let _ = s.on_bytes(b"PING :later\r\n:half a line");
    let lines: Vec<String> = s.reconnect_burst().iter().map(|m| m.to_line()).collect();
    assert_eq!(lines, ["CAP LS 302", "NICK pa", "USER pa 0 * :podssh test", "JOIN #t"]);
    assert_eq!((s.registered(), s.nick()), (Registered::Pending, "pa"));
    assert!(s.pending_pongs().is_empty() && s.isupport().get("CASEMAPPING").is_none());
    // No old half line comes back.
    let (_, events) = s.on_bytes(NGIRCD_WELCOME);
    assert!(!events.iter().any(|e| matches!(e, Event::Protocol(_))), "{events:?}");
    assert_eq!(s.registered(), Registered::Yes);
}
