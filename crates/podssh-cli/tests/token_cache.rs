//! The relay-token cache, in temporary directories: what it reuses, what it
//! ignores, and where it falls back to.

use std::path::PathBuf;

use podssh_cli::token_cache::{
    file_name, load_from, remove_from, store_in_first, valid_token, MIN_REMAINING_MS,
};

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
    let path = store_in_first(&[dir.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS + 1).unwrap();
    assert_eq!(path, dir.join(file_name("relay.example")));
    let cached = load_from(&[dir.clone()], "relay.example", NOW).expect("a cached token");
    assert_eq!(cached.token, TOKEN);
    assert!(!format!("{cached:?}").contains(TOKEN), "Debug must not show the token");

    // Another relay has its own entry.
    assert!(load_from(&[dir], "other.example", NOW).is_none());
}

#[test]
fn a_token_close_to_expiry_is_not_reused() {
    let dir = scratch("expiry");
    store_in_first(&[dir.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS - 1).unwrap();
    assert!(load_from(&[dir], "relay.example", NOW).is_none());
}

#[test]
fn the_first_usable_directory_wins_and_unusable_ones_are_skipped() {
    let root = scratch("fallback");
    // A plain file where a directory should be: nothing can be created under it.
    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"not a directory").unwrap();
    let usable = root.join("usable");
    let path = store_in_first(&[blocked.join("sub"), usable.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2)
        .unwrap();
    assert!(path.starts_with(&usable), "{}", path.display());
    assert!(load_from(&[blocked.join("sub"), usable], "relay.example", NOW).is_some());
}

#[test]
fn when_no_directory_works_the_error_names_each_one() {
    let root = scratch("nowhere");
    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"file").unwrap();
    let err = store_in_first(&[blocked.join("a")], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2).unwrap_err();
    assert!(err.contains("blocked"), "{err}");
    assert!(!err.contains(TOKEN), "the error must not contain the token");
}

#[test]
fn remove_forgets_the_token() {
    let dir = scratch("remove");
    store_in_first(&[dir.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2).unwrap();
    remove_from(&[dir.clone()], "relay.example");
    assert!(load_from(&[dir], "relay.example", NOW).is_none());
}

#[test]
fn garbage_in_the_cache_is_ignored() {
    let dir = scratch("garbage");
    std::fs::write(dir.join(file_name("relay.example")), b"{not json").unwrap();
    assert!(load_from(&[dir.clone()], "relay.example", NOW).is_none());
    std::fs::write(dir.join(file_name("relay.example")), br#"{"token":"has space","expires":9999999999999}"#).unwrap();
    assert!(load_from(&[dir], "relay.example", NOW).is_none(), "a malformed token is not reused");
}

#[test]
fn only_header_safe_strings_count_as_tokens() {
    assert!(valid_token(TOKEN));
    for bad in ["", "short", "has space in it", "line\r\nbreak!!", &"x".repeat(5000)] {
        assert!(!valid_token(bad), "{bad:?}");
    }
    assert!(store_in_first(&[scratch("refuse")], "relay.example", "not a token", NOW).is_err());
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
    let path = store_in_first(&[dir.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_from(&[dir.clone()], "relay.example", NOW).is_none(), "a world-readable file is ignored");

    let other = scratch("unix-link");
    let real = store_in_first(&[other.clone()], "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2).unwrap();
    let linked_dir = scratch("unix-linked");
    std::os::unix::fs::symlink(&real, linked_dir.join(file_name("relay.example"))).unwrap();
    assert!(load_from(&[linked_dir], "relay.example", NOW).is_none(), "a symlink is ignored");
}
