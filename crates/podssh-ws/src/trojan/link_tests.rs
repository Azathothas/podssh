use super::*;

// Built from its parts: a scanner of secrets takes a whole link with a
// password for a credential.
fn link(rest: &str) -> String {
    ["trojan://", "s3cr3t", "-pw@", rest].concat()
}

#[test]
fn the_password_is_the_lower_hex_of_its_sha224_and_is_never_shown() {
    // SHA-224("password"), the published vector.
    let p = Password::new("password").unwrap();
    assert_eq!(&p.hex()[..], b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01");
    assert_eq!(format!("{p:?}"), "Password(<redacted>)");
    assert!(Password::new("").is_err());
}

#[test]
fn a_link_gives_the_dial_the_tls_name_the_host_the_path_and_the_transport() {
    let tls = Server::parse(&link("t.example:443?security=tls&type=tcp#My%20server")).unwrap();
    assert_eq!((tls.host.as_str(), tls.port, tls.transport), ("t.example", 443, Transport::Tls));
    assert_eq!((tls.sni.as_str(), tls.authority.as_str()), ("t.example", "t.example"));
    assert_eq!((tls.shown().as_str(), tls.name.as_deref()), ("trojan://t.example:443", Some("My server")));
    assert!(!format!("{tls:?}").contains("s3cr3t"), "{tls:?}");
    let ws = "203.0.113.9:8443?type=ws&sni=t.example&host=cdn.example&path=%2Ftr%3Fed%3D2048";
    let ws = Server::parse(&link(ws)).unwrap();
    assert_eq!((ws.sni.as_str(), ws.authority.as_str(), ws.path.as_str()), ("t.example", "cdn.example", "/tr"));
    assert_eq!((ws.transport, ws.shown().as_str()), (Transport::Ws, "trojan://203.0.113.9:8443/tr"));
    let bare = Server::parse(&link("[2001:db8::1]")).unwrap();
    assert_eq!((bare.port, bare.authority.as_str()), (443, "[2001:db8::1]"));
    let peer = Server::parse(&link("203.0.113.9:443?peer=t.example&fp=chrome&alpn=h2%2Chttp%2F1.1")).unwrap();
    assert_eq!(peer.sni, "t.example", "peer is trojan-gfw's name of sni; fp and alpn pass");
}

#[test]
fn a_setting_that_podssh_does_not_follow_is_refused_by_its_name_never_with_the_password() {
    for (rest, words) in [
        ("t.example:443?type=grpc", "type=grpc"),
        ("t.example:443?security=none", "security=none"),
        ("t.example:443?security=reality&pbk=x", "pbk"),
        ("t.example:443?flow=xtls-rprx-vision", "flow=xtls-rprx-vision"),
        ("t.example:443?allowInsecure=1", "allowInsecure"),
        ("t.example:0", "port 0"),
        ("t.example:443?type=ws&host=a%0d%0ab", "host"),
        ("t.example:443?type=ws&path=%2Fa%20b", "path"),
    ] {
        let why = Server::parse(&link(rest)).unwrap_err();
        assert!(why.contains(words), "{rest}: {why}");
        assert!(!why.contains("s3cr3t"), "{why}");
    }
    assert!(Server::parse("vless://abc").unwrap_err().contains("trojan://"));
    assert!(Server::parse("trojan://t.example:443").unwrap_err().contains("PASSWORD@"));
}
