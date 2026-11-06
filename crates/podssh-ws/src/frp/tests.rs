use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::cfb::{self, Cfb};
use super::dial::Server;
use super::msg::{self, Msg};
use super::mux::Mux;
use super::mux_frame::{self as frame, Header};

/// The vectors below come from Python's hashlib and cryptography, not from
/// podssh: PBKDF2-HMAC-SHA1 of the token with frp's salt and rounds, MD5 of
/// the token and a timestamp, and AES-128-CFB of a text with that key.
const TOKEN: &str = "token-of-the-test";

#[test]
fn the_control_key_is_frp_s_pbkdf2_of_the_token() {
    let key = cfb::key(TOKEN.as_bytes());
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "69eba49449b246c4e4d8414c1cc9c92d");
}

#[test]
fn the_auth_key_is_the_md5_of_the_secret_and_the_decimal_timestamp() {
    assert_eq!(msg::auth_key(TOKEN, 1_700_000_000), "27e3aa75421644fbb3ad8d045af5f712");
    assert_ne!(msg::auth_key(TOKEN, 1_700_000_001), msg::auth_key(TOKEN, 1_700_000_000), "another second");
}

#[test]
fn cfb_matches_aes_128_cfb_and_reads_back_in_any_pieces() {
    let key = cfb::key(TOKEN.as_bytes());
    let iv: [u8; 16] = std::array::from_fn(|i| i as u8);
    let text = b"the frp control stream, 37 bytes long";
    let mut sealed = text.to_vec();
    Cfb::encrypter(&key, &iv).apply(&mut sealed);
    let hex: String = sealed.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "cfa2935c8c3e50674815548f95eeec234d2b9fc96f1fb64f6d17d3a748f9c6eea661a6631a");
    // A reader takes the stream in pieces that cross the blocks.
    let mut dec = Cfb::decrypter(&key, &iv);
    let mut back = Vec::new();
    for piece in sealed.chunks(7) {
        let mut piece = piece.to_vec();
        dec.apply(&mut piece);
        back.extend_from_slice(&piece);
    }
    assert_eq!(back, text);
}

#[test]
fn a_message_is_a_type_a_length_of_eight_bytes_and_json() {
    let bytes = msg::encode(msg::PING, &serde_json::json!({ "timestamp": 1 }));
    assert_eq!(bytes[0], b'h');
    assert_eq!(&bytes[1..9], &(15i64).to_be_bytes());
    assert_eq!(&bytes[9..], br#"{"timestamp":1}"#);
    let (m, used) = msg::decode(&bytes).unwrap().unwrap();
    assert_eq!((m.kind, used), (msg::PING, bytes.len()));
    assert_eq!(msg::decode(&bytes[..12]).unwrap(), None, "a message not whole yet");
    assert!(matches!(msg::decode(b"Z\0\0\0\0\0\0\0\0"), Err(msg::MsgError::Kind(b'Z'))), "no v1 type");
    let mut long = vec![b'h'];
    long.extend_from_slice(&(msg::MAX_LEN as i64 + 1).to_be_bytes());
    assert!(matches!(msg::decode(&long), Err(msg::MsgError::Length(_))));
}

#[test]
fn the_messages_hold_what_frps_checks_and_never_a_secret() {
    let login = msg::login(TOKEN, "", "", 1_700_000_000);
    assert_eq!(login["privilege_key"], "27e3aa75421644fbb3ad8d045af5f712");
    let stcp = msg::new_stcp("lab", "the-stcp-secret");
    assert_eq!((stcp["proxy_type"].as_str(), stcp["sk"].as_str()), (Some("stcp"), Some("the-stcp-secret")));
    let visit = msg::new_visitor_conn("lab", "the-stcp-secret", "", 1_700_000_000);
    assert_eq!(visit["sign_key"], msg::auth_key("the-stcp-secret", 1_700_000_000));
    assert_eq!(visit["use_encryption"], false);
    for body in [login, visit, msg::ping(TOKEN, 5), msg::new_work_conn(TOKEN, "r", 5)] {
        assert!(!body.to_string().contains(TOKEN) && !body.to_string().contains("the-stcp-secret"), "{body}");
    }
    let refused = Msg { kind: msg::LOGIN_RESP, body: serde_json::json!({ "error": "token mismatch" }) };
    assert_eq!(refused.error(), Some("token mismatch"));
}

#[test]
fn a_yamux_header_is_twelve_bytes_big_endian() {
    let h = Header::new(frame::WINDOW_UPDATE, frame::SYN | frame::ACK, 7, 262_144);
    let bytes = h.encode();
    assert_eq!(bytes, [0, 1, 0, 3, 0, 0, 0, 7, 0, 4, 0, 0]);
    assert_eq!(Header::decode(&bytes).unwrap(), h);
    assert!(Header::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(), "another version");
    assert!(Header::decode(&[0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(), "another type");
}

#[test]
fn servers_are_frp_with_tls_or_a_websocket_over_tls_and_nothing_in_the_clear() {
    assert_eq!(Server::parse("frp://frps.example").unwrap(), Server::Tls { host: "frps.example".into(), port: 7000 });
    assert_eq!(Server::parse("frp://frps.example:7443").unwrap().shown(), "frp://frps.example:7443");
    let ws = Server::parse("wss://edge.example").unwrap();
    assert_eq!(ws.shown(), "wss://edge.example/...");
    let Server::WebSocket(url) = ws else { panic!() };
    assert_eq!(url.target, "/~!frp", "frp's path when the URL names none");
    let Server::WebSocket(at) = Server::parse("wss://edge.example/frp-behind").unwrap() else { panic!() };
    assert_eq!(at.target, "/frp-behind", "a front end's own path is kept");
    for bad in ["ws://edge.example", "tcp://frps.example:7000", "frps.example:7000", "frp://u@frps.example"] {
        assert!(Server::parse(bad).is_err(), "{bad}");
    }
}

/// A stand-in of frps's side of yamux, written here from hashicorp's
/// specification: it reads the client's frames and answers.
async fn read_frame(io: &mut tokio::io::DuplexStream) -> (Header, Vec<u8>) {
    let mut head = [0u8; frame::HEADER];
    io.read_exact(&mut head).await.unwrap();
    let h = Header::decode(&head).unwrap();
    let mut payload = vec![0u8; if h.kind == frame::DATA { h.length as usize } else { 0 }];
    io.read_exact(&mut payload).await.unwrap();
    (h, payload)
}

#[tokio::test]
async fn a_stream_opens_with_syn_carries_both_ways_grants_back_and_answers_a_ping() {
    let (ours, mut theirs) = tokio::io::duplex(1 << 20);
    let mux = Mux::client(ours);
    let mut stream = mux.open().unwrap();
    let (syn, _) = read_frame(&mut theirs).await;
    assert_eq!((syn.kind, syn.flags, syn.stream), (frame::WINDOW_UPDATE, frame::SYN, 1), "odd ids from 1");
    stream.write_all(b"up").await.unwrap();
    let (data, payload) = read_frame(&mut theirs).await;
    assert_eq!((data.kind, data.stream, payload.as_slice()), (frame::DATA, 1, b"up".as_slice()));
    theirs.write_all(&frame::data(1, frame::ACK, b"down")).await.unwrap();
    let mut got = [0u8; 4];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"down");
    // The four bytes taken are granted back.
    let (grant, _) = read_frame(&mut theirs).await;
    assert_eq!((grant.kind, grant.stream, grant.length), (frame::WINDOW_UPDATE, 1, 4));
    theirs.write_all(&Header::new(frame::PING, frame::SYN, 0, 77).encode()).await.unwrap();
    let (pong, _) = read_frame(&mut theirs).await;
    assert_eq!((pong.kind, pong.flags, pong.length), (frame::PING, frame::ACK, 77));
    let second = mux.open().unwrap();
    let (syn, _) = read_frame(&mut theirs).await;
    assert_eq!(syn.stream, 3);
    drop(second);
    // A go-away ends the session, and says so.
    theirs.write_all(&Header::new(frame::GO_AWAY, 0, 0, 0).encode()).await.unwrap();
    let why = tokio::time::timeout(std::time::Duration::from_secs(5), mux.closed()).await.unwrap();
    assert!(why.contains("went away"), "{why}");
    assert!(mux.open().is_err(), "no stream after the end");
}

#[tokio::test]
async fn a_stream_sends_no_more_than_its_window_until_frps_grants_more() {
    let (ours, mut theirs) = tokio::io::duplex(4 << 20);
    let mux = Mux::client(ours);
    let mut stream = mux.open().unwrap();
    let _syn = read_frame(&mut theirs).await;
    let big = vec![9u8; frame::INITIAL_WINDOW as usize + 1000];
    let writer = tokio::spawn(async move {
        stream.write_all(&big).await.unwrap();
        stream
    });
    let mut carried = 0usize;
    while carried < frame::INITIAL_WINDOW as usize {
        let (h, payload) = read_frame(&mut theirs).await;
        assert_eq!(h.kind, frame::DATA);
        carried += payload.len();
    }
    assert_eq!(carried, frame::INITIAL_WINDOW as usize, "the window, not a byte more");
    let quiet = tokio::time::timeout(std::time::Duration::from_millis(300), read_frame(&mut theirs)).await;
    assert!(quiet.is_err(), "nothing past the window before a grant");
    theirs.write_all(&frame::window(1, 0, 1000)).await.unwrap();
    let (h, payload) = read_frame(&mut theirs).await;
    assert_eq!((h.kind, payload.len()), (frame::DATA, 1000));
    drop(writer.await.unwrap());
}
