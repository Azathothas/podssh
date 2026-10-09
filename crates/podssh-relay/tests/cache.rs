//! The relay-token cache, in temporary directories: what it reuses, what it
//! ignores, and where it falls back to.

use std::path::PathBuf;

use podssh_relay::cache::{file_name, load_from, remove_from, store_in_first, valid_token, MIN_REMAINING_MS};
use podssh_relay::relay::{parse_relay, DEFAULT_RELAY_HOST};
use podssh_relay::token::{relay_name, token_key, usable};

const NOW: i64 = 1_900_000_000_000;
const TOKEN: &str = "ephm1.1900000000000.forward.TESTONLYNOTACREDENTIAL";

/// A fresh, empty scratch directory unique to one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-token-cache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_stored_token_is_loaded_back_while_it_has_time_left() {
    let dir = scratch("roundtrip").join("cache");
    let path =
        store_in_first(std::slice::from_ref(&dir), "relay.example", TOKEN, NOW + MIN_REMAINING_MS + 1, "relay.example")
            .unwrap();
    assert_eq!(path, dir.join(file_name("relay.example")));
    let cached = load_from(std::slice::from_ref(&dir), "relay.example", NOW).expect("a cached token");
    assert_eq!(cached.token, TOKEN);
    assert!(!format!("{cached:?}").contains(TOKEN), "Debug must not show the token");

    // Another relay has its own entry.
    assert!(load_from(&[dir], "other.example", NOW).is_none());
}

#[test]
fn a_token_close_to_expiry_is_not_reused() {
    let dir = scratch("expiry");
    store_in_first(std::slice::from_ref(&dir), "relay.example", TOKEN, NOW + MIN_REMAINING_MS - 1, "relay.example")
        .unwrap();
    assert!(load_from(&[dir], "relay.example", NOW).is_none());
}

#[test]
fn the_first_usable_directory_wins_and_unusable_ones_are_skipped() {
    let root = scratch("fallback");
    // A plain file where a directory should be: nothing can be created under it.
    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"not a directory").unwrap();
    let usable = root.join("usable");
    let path = store_in_first(
        &[blocked.join("sub"), usable.clone()],
        "relay.example",
        TOKEN,
        NOW + MIN_REMAINING_MS * 2,
        "relay.example",
    )
    .unwrap();
    assert!(path.starts_with(&usable), "{}", path.display());
    assert!(load_from(&[blocked.join("sub"), usable], "relay.example", NOW).is_some());
}

#[test]
fn when_no_directory_works_the_error_names_each_one() {
    let root = scratch("nowhere");
    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"file").unwrap();
    let err = store_in_first(&[blocked.join("a")], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example")
        .unwrap_err();
    assert!(err.contains("blocked"), "{err}");
    assert!(!err.contains(TOKEN), "the error must not contain the token");
}

#[test]
fn remove_forgets_the_token() {
    let dir = scratch("remove");
    store_in_first(std::slice::from_ref(&dir), "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example")
        .unwrap();
    remove_from(std::slice::from_ref(&dir), "relay.example");
    assert!(load_from(&[dir], "relay.example", NOW).is_none());
}

#[test]
fn garbage_in_the_cache_is_ignored() {
    let dir = scratch("garbage");
    std::fs::write(dir.join(file_name("relay.example")), b"{not json").unwrap();
    assert!(load_from(std::slice::from_ref(&dir), "relay.example", NOW).is_none());
    std::fs::write(dir.join(file_name("relay.example")), br#"{"token":"has space","expires":9999999999999}"#).unwrap();
    assert!(load_from(&[dir], "relay.example", NOW).is_none(), "a malformed token is not reused");
}

#[test]
fn only_header_safe_strings_count_as_tokens() {
    assert!(valid_token(TOKEN));
    for bad in ["", "short", "has space in it", "line\r\nbreak!!", &"x".repeat(5000)] {
        assert!(!valid_token(bad), "{bad:?}");
    }
    assert!(store_in_first(&[scratch("refuse")], "relay.example", "not a token", NOW, "relay.example").is_err());
}

#[test]
fn cache_file_names_cannot_escape_the_directory() {
    assert_eq!(file_name("Relay.Example"), "relay-token-relay.example.json");
    assert_eq!(file_name("../../etc/passwd"), "relay-token-.._.._etc_passwd.json");
}

#[cfg(unix)]
#[test]
fn files_others_could_read_or_symlinks_are_not_trusted() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("unix-perms");
    let path =
        store_in_first(&[dir.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example").unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_from(&[dir.clone()], "relay.example", NOW).is_none(), "a world-readable file is ignored");

    let other = scratch("unix-link");
    let real =
        store_in_first(&[other.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example").unwrap();
    let linked_dir = scratch("unix-linked");
    std::os::unix::fs::symlink(&real, linked_dir.join(file_name("relay.example"))).unwrap();
    assert!(load_from(&[linked_dir], "relay.example", NOW).is_none(), "a symlink is ignored");
}

/// One token for each relay deployment: the hosts of the default deployment
/// share the default host's key, and any other host has its own (GitHub #3).
#[test]
fn token_key_is_one_for_each_deployment() {
    let key = |r: &str| token_key(&parse_relay(r).unwrap());
    assert_eq!(key(DEFAULT_RELAY_HOST), DEFAULT_RELAY_HOST);
    assert_eq!(key("tcp-eu-west-3.ssh.relay.ajam.dev"), DEFAULT_RELAY_HOST);
    assert_eq!(key("TCP-EU-WEST-3.ssh.relay.ajam.dev"), DEFAULT_RELAY_HOST);
    assert_eq!(key("tcp.ssh.relay.ajam.dev:8443"), DEFAULT_RELAY_HOST);
    assert_eq!(key("other.example"), "other.example");
    assert_eq!(key("other.example:8443"), "other.example:8443");
    for foreign in ["relay.ajam.dev", "evil.relay.ajam.dev", "x.ssh.relay.ajam.dev.attacker.example", "dead.invalid"] {
        assert_eq!(key(foreign), foreign, "{foreign} is not of the default deployment");
    }
}

/// A cached token goes only to the deployment that minted it; an entry that
/// does not name its minting relay is not used.
#[test]
fn a_token_is_usable_only_under_the_key_of_the_relay_that_minted_it() {
    assert!(usable(DEFAULT_RELAY_HOST, Some("tcp-eu-west-3.ssh.relay.ajam.dev")));
    assert!(usable(DEFAULT_RELAY_HOST, Some(DEFAULT_RELAY_HOST)));
    assert!(usable("other.example", Some("other.example")));
    assert!(usable("other.example:8443", Some("other.example:8443")));
    assert!(!usable(DEFAULT_RELAY_HOST, Some("other.example")));
    assert!(!usable("other.example", Some(DEFAULT_RELAY_HOST)));
    assert!(!usable("other.example", Some("other.example:8443")));
    assert!(!usable(DEFAULT_RELAY_HOST, None), "an old entry is not used, also under the default key");
    assert!(!usable(DEFAULT_RELAY_HOST, Some("not a host")));
}

#[test]
fn an_old_entry_with_no_minting_relay_loads_but_is_not_usable() {
    let dir = scratch("old-entry");
    let old = format!(r#"{{"token":"{TOKEN}","expires":{}}}"#, NOW + MIN_REMAINING_MS * 2);
    std::fs::write(dir.join(file_name(DEFAULT_RELAY_HOST)), old).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join(file_name(DEFAULT_RELAY_HOST)), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let cached = load_from(&[dir], DEFAULT_RELAY_HOST, NOW).expect("the old entry parses");
    assert_eq!(cached.minted_at, None);
    assert!(!usable(DEFAULT_RELAY_HOST, cached.minted_at.as_deref()));
}

/// GitHub #3: with `dead.invalid,tcp.ssh.relay.ajam.dev`, the second host
/// mints; the token is filed for its deployment, never under the first host.
#[test]
fn a_failover_files_the_token_under_the_host_that_minted_it() {
    let dir = scratch("failover");
    let (dead, live) = (parse_relay("dead.invalid").unwrap(), parse_relay(DEFAULT_RELAY_HOST).unwrap());
    let path = store_in_first(
        std::slice::from_ref(&dir),
        &token_key(&live),
        TOKEN,
        NOW + MIN_REMAINING_MS * 2,
        &relay_name(&live),
    )
    .unwrap();
    assert!(path.ends_with(file_name(DEFAULT_RELAY_HOST)), "{}", path.display());
    assert!(
        load_from(std::slice::from_ref(&dir), &token_key(&dead), NOW).is_none(),
        "nothing is filed under the dead host"
    );
    let cached = load_from(&[dir], &token_key(&live), NOW).unwrap();
    assert_eq!(cached.minted_at.as_deref(), Some(DEFAULT_RELAY_HOST));
    assert!(usable(&token_key(&live), cached.minted_at.as_deref()));
}
