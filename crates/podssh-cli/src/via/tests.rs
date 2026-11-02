//! The settings of `--via`: the flag before the variable, each with its
//! exit code, and the credentials from a private file alone.

use super::*;
use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_CONFIG;

fn flags(url: Option<&str>, auth: Option<&str>) -> Flags {
    Flags { url: url.map(String::from), auth_file: auth.map(String::from) }
}

#[test]
fn the_flag_wins_and_a_bad_flag_is_64_and_a_bad_variable_78() {
    let both = flags(Some("https://a.example"), None);
    let road = from(&both, Some("https://b.example".into()), None, None, Trust::Default).unwrap().unwrap();
    assert_eq!(road.shown(), "https://a.example:443");
    assert_eq!(road.offer, Offer::Both);
    let env = Some("https://b.example:8443".into());
    let road = from(&flags(None, None), env, None, Some("1.1".into()), Trust::Default).unwrap().unwrap();
    assert_eq!((road.shown().as_str(), road.offer), ("https://b.example:8443", Offer::Http1));
    assert_eq!(from(&flags(None, None), None, None, None, Trust::Default).unwrap(), None);
    let flag = from(&flags(Some("http://a.example"), None), None, None, None, Trust::Default).unwrap_err();
    assert_eq!(flag.code, EXIT_USAGE);
    assert!(flag.message.starts_with("--via: http:// is not taken"), "{}", flag.message);
    let env = from(&flags(None, None), Some("a.example".into()), None, None, Trust::Default).unwrap_err();
    assert_eq!(env.code, EX_CONFIG);
    assert!(env.message.starts_with("PODSSH_VIA: "), "{}", env.message);
    let http = from(&flags(Some("https://a.example"), None), None, None, Some("3".into()), Trust::Default);
    assert_eq!(http.unwrap_err().code, EX_CONFIG);
}

#[test]
fn a_user_needs_a_file_and_a_file_needs_a_proxy() {
    let user = from(&flags(Some("https://me@a.example"), None), None, None, None, Trust::Default).unwrap_err();
    assert_eq!(user.code, EXIT_USAGE);
    assert!(user.message.contains("--via-auth-file"), "{}", user.message);
    let alone = from(&flags(None, Some("auth")), None, None, None, Trust::Default).unwrap_err();
    assert_eq!(alone.code, EXIT_USAGE);
    assert!(alone.message.starts_with("--via-auth-file is for --via"), "{}", alone.message);
    let gone = flags(Some("https://a.example"), Some("/nonexistent/podssh-via-auth"));
    assert_eq!(from(&gone, None, None, None, Trust::Default).unwrap_err().code, EX_CONFIG);
}

/// The file of mode 0600 gives the credentials; one that others can read
/// is refused, and no refusal holds its line.
#[cfg(unix)]
#[test]
fn the_credentials_come_from_a_private_file_and_a_refusal_never_shows_them() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!("podssh-via-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("auth");
    let secret = ["pw", "-never-", "shown"].concat();
    std::fs::write(&path, format!("alice:{secret}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = path.to_str().unwrap();
    let road = from(&flags(Some("https://a.example"), Some(file)), None, None, None, Trust::Default).unwrap().unwrap();
    assert!(road.via.has_credentials());
    assert!(!format!("{road:?}").contains(&secret));
    // The variable's file when the flag gives none.
    let road = from(&flags(Some("https://a.example"), None), None, Some(file.into()), None, Trust::Default);
    assert!(road.unwrap().unwrap().via.has_credentials());
    std::fs::write(&path, format!("alice:{secret}\nbob:{secret}\n")).unwrap();
    let two = from(&flags(Some("https://a.example"), Some(file)), None, None, None, Trust::Default).unwrap_err();
    assert_eq!(two.code, EX_CONFIG);
    assert!(two.message.contains("more than one line") && !two.message.contains(&secret), "{}", two.message);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let open = from(&flags(Some("https://a.example"), Some(file)), None, None, None, Trust::Default).unwrap_err();
    assert_eq!(open.code, EX_CONFIG);
    assert!(!open.message.contains(&secret), "{}", open.message);
    let _ = std::fs::remove_dir_all(&dir);
}
