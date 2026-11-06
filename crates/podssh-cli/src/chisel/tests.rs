use super::*;

/// A fingerprint of the form that chisel server prints: 32 bytes in base64.
const PRINT: &str = "B3Jrbmtfbm90X2FfcmVhbF9rZXlfanVzdF8zMmJ5dGU=";

#[test]
fn a_file_gives_auth_and_a_fingerprint_and_names_a_bad_line_by_its_number() {
    let s = Secret::parse(&format!("# the run\nauth podssh:p4ss:word\nfingerprint {PRINT}\n")).unwrap();
    assert_eq!((s.user.as_str(), s.password.as_str()), ("podssh", "p4ss:word"), "the password keeps its colons");
    assert_eq!(s.fingerprint.as_deref(), Some(PRINT));
    let alone = Secret::parse(&format!("fingerprint {PRINT}")).unwrap();
    assert!(alone.user.is_empty() && alone.password.is_empty());
    for (text, words) in [
        ("auth podssh", "line 1: auth takes USER:PASSWORD"),
        ("auth :pw", "line 1: auth names no user"),
        ("auth a:b\nauth c:d", "line 2: a second auth"),
        ("fingerprint aa:bb:cc", "MD5"),
        ("fingerprint short", "44 characters"),
        ("password x", "line 1: it takes auth"),
        ("# nothing", "it has no line"),
    ] {
        let why = Secret::parse(text).unwrap_err();
        assert!(why.contains(words), "{text:?}: {why}");
        assert!(!why.contains(":b") && !why.contains("pw"), "no secret in the words: {why}");
    }
}

#[test]
fn a_secret_s_debug_shows_no_password() {
    let s = Secret::parse("auth podssh:hunter2-of-the-test").unwrap();
    assert!(!format!("{s:?}").contains("hunter2"));
}

#[test]
fn the_flag_wins_and_a_url_with_a_user_or_no_tls_is_refused() {
    let flags = |url: &str| Flags { url: Some(url.into()), auth_file: None };
    let road = from(&flags("https://chisel.example.org"), Some("https://other.example".into()), None, Trust::Default)
        .unwrap()
        .unwrap();
    assert_eq!(road.shown(), "https://chisel.example.org");
    let user = from(&flags("https://u:p@chisel.example.org"), None, None, Trust::Default).unwrap_err();
    assert_eq!(user.code, crate::exitmap::sysexits::EX_USAGE);
    assert!(user.message.contains("--chisel-auth-file") && !user.message.contains("u:p"), "{}", user.message);
    let clear = from(&flags("http://chisel.example.org"), None, None, Trust::Default).unwrap_err();
    assert!(clear.message.contains("in the clear"), "{}", clear.message);
    let var = from(&Flags::default(), Some("ftp://x".into()), None, Trust::Default).unwrap_err();
    assert_eq!(var.code, crate::exitmap::sysexits::EX_CONFIG);
    let lone = from(&Flags { url: None, auth_file: Some("f".into()) }, None, None, Trust::Default).unwrap_err();
    assert!(lone.message.contains("--chisel-auth-file is for --chisel"), "{}", lone.message);
    assert!(from(&Flags::default(), None, None, Trust::Default).unwrap().is_none());
}

#[test]
fn the_config_is_chisel_s_json_of_one_stdio_remote() {
    let doc: serde_json::Value = serde_json::from_slice(&link::config("sshd.test", 22)).unwrap();
    assert!(doc["Version"].as_str().unwrap().starts_with("podssh-"));
    let remote = &doc["Remotes"][0];
    assert_eq!(remote["RemoteHost"], "sshd.test");
    assert_eq!(remote["RemotePort"], "22", "chisel's ports are text");
    assert_eq!(remote["Stdio"], true);
    assert_eq!(remote["Reverse"], false);
    assert_eq!(doc["Remotes"].as_array().unwrap().len(), 1);
}

#[test]
fn a_channel_s_target_brackets_an_ipv6_address() {
    assert_eq!(link::target("sshd.test", 22), "sshd.test:22");
    assert_eq!(link::target("2001:db8::1", 22), "[2001:db8::1]:22");
}
