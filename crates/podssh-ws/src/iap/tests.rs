//! The upgrade of the IAP road against gcloud's own (T-351): each request
//! that gcloud 570.0.0's client sent to a stand-in on the loopback on
//! 2026-10-31, its connect and its reconnect, with the key, the `Host` and
//! the `User-Agent` of that run; the names of a target as GCP writes them;
//! and a token that cannot go in a header, refused without being quoted.

use super::*;

const TOKEN: &str = "TEST-TOKEN-NOT-A-CREDENTIAL";

/// The connect that gcloud sent, but for its `Host`: the stand-in's
/// address, here IAP's own name, as gcloud writes it with no
/// `--iap-tunnel-url-override`.
const GCLOUD_CONNECT: &str = "GET /v4/connect?project=a-project&port=22&newWebsocket=True&zone=us-central1-a\
&instance=a-vm&interface=nic0 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: tunnel.cloudproxy.app\
\r\nOrigin: bot:iap-tunneler\r\nSec-WebSocket-Key: JFa+CFu3GcIe/Hl6hjiocQ==\r\nSec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Protocol: relay.tunnel.cloudproxy.app\r\nUser-Agent: gcloud-capture\r\n\
Authorization: Bearer TEST-TOKEN-NOT-A-CREDENTIAL\r\n\r\n";

/// Its reconnect, after a Close 4004, with the session's id and the 5
/// bytes that it had.
const GCLOUD_RECONNECT: &str = "GET /v4/reconnect?sid=sid-of-the-capture&ack=5&newWebsocket=True&zone=us-central1-a \
HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: tunnel.cloudproxy.app\r\nOrigin: bot:iap-tunneler\r\n\
Sec-WebSocket-Key: ZQFa5uhp+xNPLaJJsaA2bQ==\r\nSec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Protocol: relay.tunnel.cloudproxy.app\r\nUser-Agent: gcloud-capture\r\n\
Authorization: Bearer TEST-TOKEN-NOT-A-CREDENTIAL\r\n\r\n";

fn target() -> Target {
    Target::new("a-project", "us-central1-a", "a-vm", 22).unwrap()
}

#[test]
fn iap_upgrade_is_the_one_of_gcloud() {
    let path = path(&target(), None);
    let got = request(HOST, &path, TOKEN, "JFa+CFu3GcIe/Hl6hjiocQ==", "gcloud-capture").unwrap();
    assert_eq!(String::from_utf8_lossy(&got), GCLOUD_CONNECT);
    // The token is in its header, and the request line holds none.
    let line = GCLOUD_CONNECT.lines().next().unwrap();
    assert!(!line.contains(TOKEN) && !line.to_ascii_lowercase().contains("token"), "{line}");
}

#[test]
fn iap_reconnect_is_the_one_of_gcloud() {
    let resume = Resume { sid: b"sid-of-the-capture".to_vec(), received: 5 };
    let path = path(&target(), Some(&resume));
    assert_eq!(path, "/v4/reconnect?sid=sid-of-the-capture&ack=5&newWebsocket=True&zone=us-central1-a");
    let got = request(HOST, &path, TOKEN, "ZQFa5uhp+xNPLaJJsaA2bQ==", "gcloud-capture").unwrap();
    assert_eq!(String::from_utf8_lossy(&got), GCLOUD_RECONNECT);
    assert!(!format!("{resume:?}").contains("capture"), "the id is not shown");
}

/// The query is written as Python's `urlencode` writes it: a project of a
/// domain keeps its name, its `:` escaped, and an id of any bytes goes.
#[test]
fn iap_query_is_encoded_as_python_encodes_it() {
    let domain = Target::new("example.com:a-project", "europe-west1-b", "vm-2", 2222).unwrap();
    assert_eq!(
        path(&domain, None),
        "/v4/connect?project=example.com%3Aa-project&port=2222&newWebsocket=True&zone=europe-west1-b\
         &instance=vm-2&interface=nic0"
    );
    assert_eq!(form(b"a b/c+d~e_f.g-h"), "a+b%2Fc%2Bd~e_f.g-h");
    assert_eq!(form(&[0x00, 0xff, b'=']), "%00%FF%3D");
}

#[test]
fn iap_target_names_are_those_of_gcp() {
    for (project, zone, instance) in [
        ("", "us-central1-a", "vm"),
        ("Project", "us-central1-a", "vm"),
        ("a project", "us-central1-a", "vm"),
        ("-project", "us-central1-a", "vm"),
        ("p", "uscentral", "vm"),
        ("p", "us-central1-a/x", "vm"),
        ("p", "us-central1-a", ""),
        ("p", "us-central1-a", "1vm"),
        ("p", "us-central1-a", "vm-"),
        ("p", "us-central1-a", "VM"),
        ("p", "us-central1-a", "vm.example"),
    ] {
        assert!(Target::new(project, zone, instance, 22).is_err(), "{project:?} {zone:?} {instance:?}");
    }
    assert!(Target::new("p", "us-central1-a", "vm", 0).is_err());
    assert!(Target::new("p", "us-central1-a", &"v".repeat(64), 22).is_err());
    let ok = Target::new("p1", "us-central1-a", &format!("v{}", "m".repeat(62)), 22).unwrap();
    assert_eq!((ok.interface.as_str(), ok.port), (INTERFACE, 22));
}

/// A token with a space, a line break or nothing is refused, by a message
/// that does not quote it; so is a host or a path that would break the
/// request.
#[test]
fn iap_a_token_that_is_no_header_value_is_refused_unquoted() {
    let long = "t".repeat(MAX_TOKEN + 1);
    for bad in ["", "two words", "line\r\nX-Injected: 1", long.as_str()] {
        let why = request(HOST, "/v4/connect", bad, "k", "ua").unwrap_err();
        assert!(why.contains("not one of Google's"), "{why}");
        if !bad.is_empty() {
            assert!(!why.contains(bad), "the token was quoted: {why}");
        }
    }
    assert!(request("evil.example/x", "/v4/connect", TOKEN, "k", "ua").is_err());
    assert!(request(HOST, "/v4/connect x", TOKEN, "k", "ua").is_err());
    assert!(request(HOST, "/v4/connect", TOKEN, "k", "ua\r\nX: 1").is_err());
}

/// A refusal that quotes the token shows none of it, also when the cut of
/// its text falls inside the token.
#[test]
fn iap_a_refusal_shows_no_part_of_the_token() {
    let token = "ya29.a0AfB_TEST-TOKEN-NOT-A-CREDENTIAL";
    let whole = format!("denied: Authorization: Bearer {token} for you");
    assert_eq!(hide_token(&whole, token), "denied: Authorization: Bearer <not shown> for you");
    let cut = format!("denied: Bearer {}\u{2026}", &token[..20]);
    assert_eq!(hide_token(&cut, token), "denied: Bearer <not shown>\u{2026}");
    assert_eq!(hide_token("no token here\u{2026}", token), "no token here\u{2026}");
}
