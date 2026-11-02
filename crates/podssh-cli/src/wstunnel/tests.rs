//! The settings of `--wstunnel`: the flag before the variable, each with its
//! exit code, and the secret from a private file alone.

use super::*;
use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_CONFIG;

fn flags(url: Option<&str>, file: Option<&str>) -> Flags {
    Flags { url: url.map(String::from), secret_file: file.map(String::from) }
}

#[test]
fn the_flag_wins_and_a_bad_flag_is_64_and_a_bad_variable_78() {
    let both = flags(Some("wss://a.example"), None);
    let road = from(&both, Some("wss://b.example".into()), None, Trust::Default).unwrap().unwrap();
    assert_eq!(road.shown(), "wss://a.example");
    assert!(road.secret.is_default());
    let road = from(&flags(None, None), Some("ws://127.0.0.1:8080".into()), None, Trust::Default).unwrap().unwrap();
    assert_eq!(road.shown(), "ws://127.0.0.1:8080");
    assert_eq!(from(&flags(None, None), None, None, Trust::Default).unwrap(), None);
    let flag = from(&flags(Some("https://a.example"), None), None, None, Trust::Default).unwrap_err();
    assert_eq!(flag.code, EXIT_USAGE);
    assert!(flag.message.starts_with("--wstunnel: https:// is wstunnel's HTTP/2 transport"), "{}", flag.message);
    let env = from(&flags(None, None), Some("wss://a.example/p".into()), None, Trust::Default).unwrap_err();
    assert_eq!(env.code, EX_CONFIG);
    assert!(env.message.starts_with("PODSSH_WSTUNNEL: "), "{}", env.message);
}

#[test]
fn a_file_needs_a_server_and_a_missing_file_is_78() {
    let alone = from(&flags(None, Some("secret")), None, None, Trust::Default).unwrap_err();
    assert_eq!(alone.code, EXIT_USAGE);
    assert!(alone.message.starts_with("--wstunnel-secret-file is for --wstunnel"), "{}", alone.message);
    let gone = flags(Some("wss://a.example"), Some("/nonexistent/podssh-wstunnel-secret"));
    assert_eq!(from(&gone, None, None, Trust::Default).unwrap_err().code, EX_CONFIG);
}

/// The file of mode 0600 gives the secret; one that others can read is
/// refused, a secret over ws:// to another host too, and no refusal holds
/// the secret.
#[cfg(unix)]
#[test]
fn the_secret_comes_from_a_private_file_and_a_refusal_never_shows_it() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!("podssh-wstunnel-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("secret");
    let secret = ["pfx", "-never-", "shown"].concat();
    std::fs::write(&path, format!("path-prefix {secret}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = path.to_str().unwrap();
    let road = from(&flags(Some("wss://a.example"), Some(file)), None, None, Trust::Default).unwrap().unwrap();
    assert!(!road.secret.is_default());
    assert!(!format!("{road:?}").contains(&secret));
    // The variable's file when the flag gives none.
    let road = from(&flags(Some("wss://a.example"), None), None, Some(file.into()), Trust::Default);
    assert!(!road.unwrap().unwrap().secret.is_default());
    let clear = from(&flags(Some("ws://a.example:8080"), Some(file)), None, None, Trust::Default).unwrap_err();
    assert_eq!(clear.code, EXIT_USAGE);
    assert!(clear.message.contains("give wss://") && !clear.message.contains(&secret), "{}", clear.message);
    std::fs::write(&path, format!("path-prefix {secret}\npath-prefix {secret}\n")).unwrap();
    let two = from(&flags(Some("wss://a.example"), Some(file)), None, None, Trust::Default).unwrap_err();
    assert_eq!(two.code, EX_CONFIG);
    assert!(two.message.contains("a second path-prefix") && !two.message.contains(&secret), "{}", two.message);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let open = from(&flags(Some("wss://a.example"), Some(file)), None, None, Trust::Default).unwrap_err();
    assert_eq!(open.code, EX_CONFIG);
    assert!(!open.message.contains(&secret), "{}", open.message);
    let _ = std::fs::remove_dir_all(&dir);
}
