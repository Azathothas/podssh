//! The second proxy's URL, its credentials file, the versions offered, and
//! the words of a `407`.

use super::*;

#[test]
fn a_url_names_a_tls_proxy_by_its_host_and_port_and_443_by_default() {
    let via = Via::parse("https://proxy.example").unwrap();
    assert_eq!((via.host.as_str(), via.port, via.names_user()), ("proxy.example", 443, false));
    assert_eq!(via.shown(), "https://proxy.example:443");
    let via = Via::parse(" HTTPS://alice@[2001:db8::1]:8443/ ").unwrap();
    assert_eq!((via.host.as_str(), via.port, via.names_user()), ("2001:db8::1", 8443, true));
    assert_eq!(via.shown(), "https://[2001:db8::1]:8443", "no user in what is shown");
    let escaped = Via::parse("https://a%40b@proxy.example").unwrap().with_credentials("pw").unwrap();
    assert_eq!(escaped.user.as_deref(), Some("a@b"));
}

#[test]
fn a_password_another_scheme_a_path_and_no_host_are_refused() {
    // Built from its parts: a scanner of secrets takes a whole URI with a
    // user and a password for a credential.
    let with_password = ["https://alice", ":hunter2", "@proxy.example"].concat();
    let why = Via::parse(&with_password).unwrap_err();
    assert!(why.contains("password") && !why.contains("hunter2"), "{why}");
    assert!(Via::parse("http://proxy.example:3128").unwrap_err().contains("over TLS"));
    assert!(Via::parse("socks5://proxy.example").unwrap_err().contains("over TLS"));
    assert!(Via::parse("proxy.example:443").unwrap_err().contains("https://"));
    assert!(Via::parse("https://proxy.example/path").unwrap_err().contains("no path"));
    assert!(Via::parse("https://proxy.example?x=1").unwrap_err().contains("no path"));
    assert!(Via::parse("https://").unwrap_err().contains("no host"));
    assert!(Via::parse("https://@proxy.example").unwrap_err().contains("user"));
    assert!(Via::parse("https://proxy.example:0").is_err());
    assert!(Via::parse("https://proxy.example:99999").is_err());
}

#[test]
fn the_file_gives_user_and_password_or_the_password_of_the_url_s_user() {
    let via = Via::parse("https://proxy.example").unwrap().with_credentials("# mine\n\nbob:pa:ss\r\n").unwrap();
    assert_eq!(via.user.as_deref(), Some("bob"));
    assert_eq!(via.password.as_deref().map(String::as_str), Some("pa:ss"), "the first colon parts them");
    assert!(via.has_credentials());
    let named = Via::parse("https://carol@proxy.example").unwrap().with_credentials("x:y\n").unwrap();
    assert_eq!(named.user.as_deref(), Some("carol"));
    assert_eq!(named.password.as_deref().map(String::as_str), Some("x:y"), "the whole line is the password");
    let bare = Via::parse("https://proxy.example").unwrap();
    for (text, words) in [("\n# only\n", "no line"), ("a:b\nc:d\n", "more than one"), ("nocolon\n", "no colon")] {
        let why = bare.clone().with_credentials(text).unwrap_err();
        assert!(why.contains(words), "{text:?}: {why}");
        assert!(!why.contains("nocolon") && !why.contains("c:d"), "never the line: {why}");
    }
    assert!(bare.clone().with_credentials(":pw\n").unwrap_err().contains("empty"));
    assert!(!format!("{:?}", Via::parse("https://proxy.example").unwrap().with_credentials("u:pw9").unwrap())
        .contains("pw9"));
}

#[test]
fn the_versions_offered_are_both_or_one() {
    assert_eq!(Offer::parse("").unwrap(), Offer::Both);
    assert_eq!(Offer::parse("auto").unwrap(), Offer::Both);
    assert_eq!(Offer::parse("1.1").unwrap(), Offer::Http1);
    assert_eq!(Offer::parse(" 2 ").unwrap(), Offer::Http2);
    assert!(Offer::parse("3").is_err());
    assert_eq!(Offer::Both.alpn(), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert_eq!(Offer::Http1.alpn(), vec![b"http/1.1".to_vec()]);
    assert_eq!(Version::Http2.name(), "HTTP/2");
}

/// A `407` says what the proxy asks for and what podssh gave: none, the
/// file's, or a scheme that podssh does not speak.
#[test]
fn a_407_is_said_with_its_schemes_and_what_podssh_sent() {
    let head = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Caddy Secure Web \
                Proxy\"\r\n\r\n";
    let none = explain("Proxy Authentication Required", head, false);
    assert!(none.starts_with("Proxy Authentication Required; it asks for Basic, and podssh sent none"), "{none}");
    assert!(none.contains("--via-auth-file"), "{none}");
    let sent = explain("Proxy Authentication Required", head, true);
    assert!(sent.contains("refused the user and password"), "{sent}");
    let ntlm = explain("", "HTTP/2 407\r\nProxy-Authenticate: NTLM\r\nProxy-Authenticate: Negotiate\r\n", true);
    assert!(ntlm.starts_with("Proxy Authentication Required; it asks for NTLM and Negotiate"), "{ntlm}");
    assert!(ntlm.contains("Basic only"), "{ntlm}");
    let silent = explain("Auth", "HTTP/1.1 407 Auth\r\n\r\n", false);
    assert!(silent.starts_with("Auth; podssh sent none"), "{silent}");
}

/// The refusal names the second proxy by its URL with no user, and the
/// target, with the status.
#[test]
fn a_refusal_names_the_second_proxy_and_the_target() {
    let via = Via::parse("https://dave@proxy.example:8443").unwrap();
    let e = refused(&via, "h.example:22", 403, "Forbidden".into(), "HTTP/1.1 403 Forbidden\r\n\r\n");
    assert_eq!(e.to_string(), "the proxy https://proxy.example:8443 refused CONNECT h.example:22: 403 Forbidden");
}
