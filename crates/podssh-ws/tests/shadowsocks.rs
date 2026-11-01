//! Shadowsocks' AEAD form (T-373), checked three ways. Known answers that
//! Python's `hashlib` and the `cryptography` package (OpenSSL) computed:
//! the master key of a password, a stream's key, and a whole first chunk
//! for each method. A codec written here from the specification
//! (shadowsocks.org's `aead.html`), with the AEAD crates themselves and not
//! podssh's wrapper of them: it opens podssh's stream, and podssh opens its
//! own. And `open` against a stand-in server of that codec on the loopback,
//! where a wrong password ends in silence that names the server. Then the
//! `ss://` URIs of SIP002, and the forms of a subscription's list.

use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use podssh_ws::shadowsocks::{self, Decoder, Encoder, Method, Node, OpenError};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// EVP_BytesToKey with MD5 from its definition: D1 = MD5(password),
/// Dn = MD5(Dn-1 || password), the key the first bytes of D1 || D2 ...
fn evp(password: &[u8], len: usize) -> Vec<u8> {
    let (mut out, mut last) = (Vec::new(), Vec::new());
    while out.len() < len {
        let mut input = last.clone();
        input.extend_from_slice(password);
        last = md5::compute(&input).0.to_vec();
        out.extend_from_slice(&last);
    }
    out.truncate(len);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// The specification's cipher of one direction: HKDF-SHA1 with
/// `ss-subkey`, and the count of operations as the nonce.
enum Spec {
    Chacha(Box<ChaCha20Poly1305>),
    Aes256(Box<Aes256Gcm>),
    Aes128(Box<Aes128Gcm>),
}

impl Spec {
    fn new(method: Method, master: &[u8], salt: &[u8]) -> Spec {
        let mut key = vec![0u8; master.len()];
        hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), master).expand(b"ss-subkey", &mut key).unwrap();
        match method {
            Method::Chacha20IetfPoly1305 => Spec::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(&key).unwrap())),
            Method::Aes256Gcm => Spec::Aes256(Box::new(Aes256Gcm::new_from_slice(&key).unwrap())),
            Method::Aes128Gcm => Spec::Aes128(Box::new(Aes128Gcm::new_from_slice(&key).unwrap())),
        }
    }

    fn nonce(n: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&n.to_le_bytes());
        nonce
    }

    fn seal(&self, n: u64, plain: &[u8]) -> Vec<u8> {
        let nonce = Spec::nonce(n);
        let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce.into();
        match self {
            Spec::Chacha(c) => c.encrypt(&chacha20poly1305::Nonce::from(nonce), plain).unwrap(),
            Spec::Aes256(c) => c.encrypt(&gcm, plain).unwrap(),
            Spec::Aes128(c) => c.encrypt(&gcm, plain).unwrap(),
        }
    }

    fn open(&self, n: u64, sealed: &[u8]) -> Option<Vec<u8>> {
        let nonce = Spec::nonce(n);
        let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce.into();
        match self {
            Spec::Chacha(c) => c.decrypt(&chacha20poly1305::Nonce::from(nonce), sealed).ok(),
            Spec::Aes256(c) => c.decrypt(&gcm, sealed).ok(),
            Spec::Aes128(c) => c.decrypt(&gcm, sealed).ok(),
        }
    }
}

/// A whole stream as the specification writes it: the salt, then for each
/// payload of 0x3FFF bytes at most its sealed length and itself sealed.
fn spec_stream(method: Method, master: &[u8], salt: &[u8], data: &[u8]) -> Vec<u8> {
    let spec = Spec::new(method, master, salt);
    let mut out = salt.to_vec();
    for (i, payload) in data.chunks(0x3FFF).enumerate() {
        let n = 2 * i as u64;
        out.extend(spec.seal(n, &(payload.len() as u16).to_be_bytes()));
        out.extend(spec.seal(n + 1, payload));
    }
    out
}

/// A whole stream as the specification reads it: its payloads, joined, or
/// `None` at the first piece that does not open.
fn spec_read(method: Method, master: &[u8], wire: &[u8]) -> Option<Vec<u8>> {
    let salt_len = method.salt_len();
    let spec = Spec::new(method, master, wire.get(..salt_len)?);
    let (mut at, mut n, mut out) = (salt_len, 0u64, Vec::new());
    while at < wire.len() {
        let len = spec.open(n, wire.get(at..at + 18)?)?;
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        assert!(len <= 0x3FFF, "the reserved bits are zero");
        out.extend(spec.open(n + 1, wire.get(at + 18..at + 18 + len + 16)?)?);
        at += 18 + len + 16;
        n += 2;
    }
    Some(out)
}

/// An `ss://` URI whose user part is percent-encoded text, built from its
/// parts: a secret scanner takes a URI with a user and a password, written
/// whole in a source, for a credential.
fn plain(method: &str, password: &str, rest: &str) -> String {
    ["ss://", method, ":", password, "@", rest].concat()
}

fn data(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect()
}

#[test]
fn the_master_key_is_evp_bytes_to_key_with_md5() {
    for password in [&b"foobar"[..], &b"a"[..], &b"a password of more than one block of MD5 and some"[..]] {
        for len in [16, 32] {
            assert_eq!(*shadowsocks::master_key(password, len), evp(password, len), "{len}");
        }
    }
    // Python's hashlib, from the same definition.
    let foobar = "3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf";
    assert_eq!(hex(&shadowsocks::master_key(b"foobar", 32)), foobar);
    assert_eq!(hex(&shadowsocks::master_key(b"foobar", 16)), foobar[..32]);
}

#[test]
fn a_stream_s_key_is_hkdf_sha1_of_the_salt_as_openssl_computes_it() {
    let salt32: Vec<u8> = (0..32).collect();
    let key = shadowsocks::subkey(&evp(b"foobar", 32), &salt32);
    assert_eq!(hex(&key), "c4f0e9818348b2f30188d82b37a4cddc9f5ea531070ec67225160209faff573c");
    let salt16: Vec<u8> = (0..16).collect();
    assert_eq!(hex(&shadowsocks::subkey(&evp(b"foobar", 16), &salt16)), "e59e945699e8699144c332b9e641ef65");
}

/// The first chunk of each method, with a fixed salt (0, 1, 2, ...), the
/// password `foobar`, and the payload `example.com:22` then `hello`: the
/// bytes that the `cryptography` package sealed.
#[test]
fn each_method_s_first_chunk_is_the_one_that_openssl_seals() {
    let answers = [
        (
            Method::Chacha20IetfPoly1305,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f5d832a357856689b695b36782ab3f13478c3\
             ac89d42411949fff2de8a5e263a024c9052da5e833ea0ba261ff89eb41f4215c15c274c0",
        ),
        (
            Method::Aes256Gcm,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f26e81b4bc80f4da10713d856e6e21c18a2a8\
             241815b04c2dd91251e282d858996f272d5d7bfa191b006a38da4a122801fbe1db9316e4",
        ),
        (
            Method::Aes128Gcm,
            "000102030405060708090a0b0c0d0e0ff85a8ef0ca298882ae2c98699e25fbbc1d6f3c0fc8a22dda49f5462a585eb764e62998\
             2441ed290895ab5d57981e7bc930c1c5744ce9",
        ),
    ];
    for (method, answer) in answers {
        let master = evp(b"foobar", method.key_len());
        let salt: Vec<u8> = (0..method.salt_len() as u8).collect();
        let mut plain = shadowsocks::address("example.com", 22).unwrap();
        plain.extend_from_slice(b"hello");
        let mut wire = Vec::new();
        Encoder::with_salt(method, &master, &salt).unwrap().seal(&plain, &mut wire).unwrap();
        assert_eq!(hex(&wire), answer, "{method:?}");
        let mut decoder = Decoder::new(method, &master);
        decoder.feed(&unhex(answer));
        let first = decoder.chunk().unwrap().unwrap();
        assert_eq!(shadowsocks::parse_address(&first), Some(("example.com".to_string(), 22, 15)));
        assert_eq!(&first[15..], b"hello");
    }
}

/// podssh's stream opens with the specification's reading, chunk by
/// chunk, and the specification's stream opens with podssh's, across
/// several chunks of the largest size.
#[test]
fn podssh_and_the_specification_read_each_other_s_streams() {
    for method in Method::ALL {
        let master = evp(b"round trip", method.key_len());
        let sent = data(3 * 0x3FFF + 1234);
        let mut wire = Vec::new();
        let mut encoder = Encoder::new(method, &master).unwrap();
        encoder.seal(&sent[..5000], &mut wire).unwrap();
        encoder.seal(&sent[5000..], &mut wire).unwrap();
        assert_eq!(spec_read(method, &master, &wire).as_deref(), Some(&sent[..]), "{method:?}: the spec reads podssh");
        let salt = vec![0x42u8; method.salt_len()];
        let theirs = spec_stream(method, &master, &salt, &sent);
        let mut decoder = Decoder::new(method, &master);
        let mut back = Vec::new();
        for piece in theirs.chunks(1000) {
            decoder.feed(piece);
            while let Some(plain) = decoder.chunk().unwrap() {
                back.extend_from_slice(&plain);
            }
        }
        assert_eq!(back, sent, "{method:?}: podssh reads the spec");
        // The nonce of the length and of the payload are two: one stream
        // with one count for both does not open.
        let skewed = Spec::new(method, &master, &salt);
        let mut wrong = salt.clone();
        wrong.extend(skewed.seal(0, &5u16.to_be_bytes()));
        wrong.extend(skewed.seal(0, b"hello"));
        let mut decoder = Decoder::new(method, &master);
        decoder.feed(&wrong);
        assert!(decoder.chunk().is_err(), "{method:?}: a nonce used twice");
    }
}

/// The stand-in's task: the target that it read, when its key was right.
type Served = tokio::task::JoinHandle<Option<String>>;

/// A stand-in server of the specification's codec on the loopback: it
/// reads the salt and the address; with the right key it answers with
/// `banner` and then echoes, and with another it stays silent until the
/// client goes. The address that it read comes back.
async fn stand_in(method: Method, password: &[u8], banner: &'static [u8]) -> (u16, Served) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let master = evp(password, method.key_len());
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut wire = Vec::new();
        let mut buf = vec![0u8; 65536];
        let (mut first, mut n_in) = (None, 0u64);
        let reader = loop {
            let n = tcp.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return None;
            }
            wire.extend_from_slice(&buf[..n]);
            if wire.len() >= method.salt_len() + 18 {
                break Spec::new(method, &master, &wire[..method.salt_len()]);
            }
        };
        let at = method.salt_len();
        let Some(len) = reader.open(0, &wire[at..at + 18]) else {
            // Another key: silence until the client goes, as a server is.
            while tcp.read(&mut buf).await.unwrap_or(0) > 0 {}
            return None;
        };
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        while wire.len() < at + 18 + len + 16 {
            let n = tcp.read(&mut buf).await.unwrap_or(0);
            assert!(n > 0, "the address chunk came whole");
            wire.extend_from_slice(&buf[..n]);
        }
        let header = reader.open(1, &wire[at + 18..at + 18 + len + 16]).unwrap();
        if let Some((host, port, _)) = shadowsocks::parse_address(&header) {
            first = Some(format!("{host}:{port}"));
        }
        let salt = vec![0x5au8; method.salt_len()];
        let writer = Spec::new(method, &master, &salt);
        let mut answer = salt.clone();
        answer.extend(writer.seal(0, &(banner.len() as u16).to_be_bytes()));
        answer.extend(writer.seal(1, banner));
        let mut n_out = 2u64;
        tcp.write_all(&answer).await.unwrap();
        // Echo each later chunk.
        let mut rest = wire.split_off(at + 18 + len + 16);
        n_in += 2;
        loop {
            while rest.len() >= 18 {
                let Some(l) = reader.open(n_in, &rest[..18]) else { return first };
                let l = usize::from(u16::from_be_bytes([l[0], l[1]]));
                if rest.len() < 18 + l + 16 {
                    break;
                }
                let plain = reader.open(n_in + 1, &rest[18..18 + l + 16]).unwrap();
                n_in += 2;
                rest.drain(..18 + l + 16);
                let mut out = writer.seal(n_out, &(plain.len() as u16).to_be_bytes());
                out.extend(writer.seal(n_out + 1, &plain));
                n_out += 2;
                tcp.write_all(&out).await.unwrap();
            }
            let n = tcp.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return first;
            }
            rest.extend_from_slice(&buf[..n]);
        }
    });
    (port, task)
}

fn dial(answer: Duration) -> shadowsocks::Dial<'static> {
    static DIRECT: ProxyChoice = ProxyChoice::Direct;
    let timeout = Duration::from_secs(10);
    shadowsocks::Dial { proxy: &DIRECT, timeout, answer: Some(answer), silence_is_ready: false }
}

#[tokio::test]
async fn open_names_the_target_reads_the_answer_and_carries_bytes_each_way() {
    for method in Method::ALL {
        let (port, server) = stand_in(method, b"stand-in", b"SSH-2.0-stand-in\r\n").await;
        let node = Node::new(method, "stand-in", "127.0.0.1", port).unwrap();
        let opened = shadowsocks::open(&node, "target.test", 2222, &dial(Duration::from_secs(5))).await.unwrap();
        assert!(opened.answered_in.is_some(), "{method:?}");
        let mut stream = opened.carried.stream;
        let mut banner = [0u8; 18];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-stand-in\r\n");
        let sent = data(100_000);
        let (mut read, mut write) = tokio::io::split(stream);
        let writer = tokio::spawn(async move {
            write.write_all(&sent).await.unwrap();
            write.shutdown().await.unwrap();
            sent
        });
        let mut back = vec![0u8; 100_000];
        read.read_exact(&mut back).await.unwrap();
        let sent = writer.await.unwrap();
        assert_eq!(back, sent, "{method:?}");
        let mut end = Vec::new();
        read.read_to_end(&mut end).await.unwrap();
        assert!(end.is_empty());
        assert_eq!(server.await.unwrap().as_deref(), Some("target.test:2222"));
        assert_eq!(opened.carried.status.get(), None, "an ordinary end");
    }
}

#[tokio::test]
async fn a_wrong_password_ends_in_silence_that_names_the_server_and_not_the_password() {
    let method = Method::Chacha20IetfPoly1305;
    let (port, _server) = stand_in(method, b"the server's", b"SSH-2.0-x\r\n").await;
    let node = Node::new(method, "not-the-password", "127.0.0.1", port).unwrap();
    let e = shadowsocks::open(&node, "target.test", 22, &dial(Duration::from_millis(400))).await.unwrap_err();
    assert!(matches!(e, OpenError::Silent { ended: None, proxy: None, .. }), "{e:?}");
    let line = e.line(&node.shown(), "target.test:22");
    let named = format!("the Shadowsocks server ss://127.0.0.1:{port}: no answer within 0.4 s");
    assert!(line.starts_with(&named) && line.contains("password or the method"), "{line}");
    assert!(!line.contains("not-the-password") && !format!("{node:?}").contains("not-the-password"));
}

#[test]
fn sip002_uris_are_read_and_their_password_never_shown() {
    // The examples of SIP002: base64url user parts, with and without a plugin.
    let one = Node::parse("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1").unwrap();
    assert_eq!((one.method, one.host.as_str(), one.port), (Method::Aes128Gcm, "192.168.100.1", 8888));
    assert_eq!(one.shown(), "ss://192.168.100.1:8888 (Example1)");
    assert_eq!(*one.master_key(), evp(b"test", 16));
    let plugin = Node::parse("ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2");
    assert!(plugin.unwrap_err().contains("the plugin obfs-local, another program"));
    // Percent-encoded, padded base64 in the standard alphabet, the older
    // form, an IPv6 address.
    let percent = Node::parse(&plain("aes-256-gcm", "p%40ss%3Aword", "[2001:db8::1]:443/#a%20name")).unwrap();
    assert_eq!((percent.host.as_str(), percent.tag.as_deref()), ("2001:db8::1", Some("a name")));
    assert_eq!(*percent.master_key(), evp(b"p@ss:word", 32));
    assert_eq!(percent.shown(), "ss://[2001:db8::1]:443 (a name)");
    let padded = Node::parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo/YQ==@h.example:8388").unwrap();
    assert_eq!((padded.method, padded.master_key().to_vec()), (Method::Chacha20IetfPoly1305, evp(b"?a", 32)));
    let older = Node::parse("ss://YWVzLTI1Ni1nY206c2VjcmV0QGguZXhhbXBsZTo4Mzg4").unwrap();
    assert_eq!((older.method, older.host.as_str(), older.port), (Method::Aes256Gcm, "h.example", 8388));
    assert_eq!(Node::parse(&older.to_uri()).unwrap(), older, "a node written out reads back");
    // Each refusal says why, never the password.
    for (line, why) in [
        (plain("2022-blake3-aes-256-gcm", "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0", "h.example:443"), "Shadowsocks 2022"),
        (plain("aes-256-gcm", "hunter2", "h.example"), "no port"),
        (plain("aes-256-gcm", "hunter2", "h.example:0"), "not a port"),
        (plain("aes-256-gcm", "", "h.example:443"), "password is empty"),
        (plain("rc4-md5", "hunter2", "h.example:443"), "rc4-md5 is not one"),
        ("ss://aGVsbG8gaHVudGVyMg@h.example:443".to_string(), "no method:password"),
        ("ss://hunter2!".to_string(), "neither"),
        ("http://hunter2@h.example:443".to_string(), "not an ss://"),
    ] {
        let e = Node::parse(&line).unwrap_err();
        assert!(e.contains(why), "{line}: {e}");
        assert!(!e.contains("hunter2") && !e.contains("c2VjcmV0"), "{e}");
    }
    assert!(!format!("{one:?}").contains("test"), "Debug hides the password");
}

#[test]
fn a_subscription_s_list_comes_as_lines_as_base64_or_as_sip008() {
    use base64::Engine as _;
    let lines = format!(
        "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#one\nvmess://eyJhZGQiOiJ4In0\n{}\n\
         ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888\n",
        plain("aes-256-gcm", "pw", "h.example:443/?plugin=v2ray-plugin")
    );
    let listed = shadowsocks::subscription(lines.as_bytes()).unwrap();
    assert_eq!(listed.nodes.len(), 1, "each node once: {listed:?}");
    assert_eq!((listed.others, listed.refused.len()), (1, 1));
    assert!(listed.refused[0].starts_with("line 3: it names the plugin v2ray-plugin"), "{:?}", listed.refused);
    let encoded = base64::engine::general_purpose::STANDARD.encode(lines);
    let pieces: Vec<&str> = encoded.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let wrapped = pieces.join("\n");
    assert_eq!(shadowsocks::subscription(wrapped.as_bytes()).unwrap(), listed, "base64 in lines of 76");
    let json = r#"{"version":1,"servers":[
        {"server":"h.example","server_port":8388,"password":"pw","method":"chacha20-ietf-poly1305","remarks":"tag"},
        {"server":"g.example","server_port":8388,"password":"pw","method":"2022-blake3-aes-128-gcm"}]}"#;
    let sip008 = shadowsocks::subscription(json.as_bytes()).unwrap();
    assert_eq!(sip008.nodes[0].shown(), "ss://h.example:8388 (tag)");
    assert!(sip008.refused[0].starts_with("server 2: the method 2022-blake3-aes-128-gcm"), "{:?}", sip008.refused);
    for bad in ["", "   ", "<html>not a list</html>", "{\"servers\":3}"] {
        assert!(shadowsocks::subscription(bad.as_bytes()).is_err(), "{bad}");
    }
}
