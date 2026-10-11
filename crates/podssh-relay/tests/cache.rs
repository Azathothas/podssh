//! The relay-token cache, in temporary directories: what it reuses, what it
//! ignores, and where it falls back to.

mod cleanup;

use std::path::PathBuf;

use podssh_relay::cache::{
    candidate_dirs_from, chosen_from, chosen_note, file_name, load_from, remove_from, store_in_first, store_noting,
    valid_token, Chosen, MIN_REMAINING_MS,
};
use podssh_relay::relay::{parse_relay, DEFAULT_RELAY_HOST};
use podssh_relay::token::{relay_name, token_key, usable};

const NOW: i64 = 1_900_000_000_000;
const TOKEN: &str = "ephm1.1900000000000.forward.TESTONLYNOTACREDENTIAL";

/// A fresh, empty scratch directory unique to one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-token-cache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).unwrap();
    cleanup::at_test_end(&dir);
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
        store_in_first(std::slice::from_ref(&dir), "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example")
            .unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_from(std::slice::from_ref(&dir), "relay.example", NOW).is_none(), "a world-readable file is ignored");

    let other = scratch("unix-link");
    let real = store_in_first(
        std::slice::from_ref(&other),
        "relay.example",
        TOKEN,
        NOW + MIN_REMAINING_MS * 2,
        "relay.example",
    )
    .unwrap();
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

/// An environment for [`candidate_dirs_from`]: each pair is a variable.
fn env<'a>(pairs: &'a [(&'a str, PathBuf)]) -> impl Fn(&str) -> Option<std::ffi::OsString> + 'a {
    move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone().into_os_string())
}

/// The order of T-243: the directory of PODSSH_CACHE_DIR, the user's cache
/// directory, the runtime directory, the temporary directory with the
/// user's tag, the working directory.
#[test]
fn the_order_follows_the_environment() {
    let root = scratch("order");
    let user_cache = if cfg!(windows) { "LOCALAPPDATA" } else { "XDG_CACHE_HOME" };
    let pairs = [
        ("PODSSH_CACHE_DIR", root.join("chosen")),
        (user_cache, root.join("cache")),
        ("XDG_RUNTIME_DIR", root.join("run")),
        ("TMPDIR", root.join("tmp")),
    ];
    let dirs = candidate_dirs_from(&env(&pairs), Some(root.join("work")));
    assert_eq!(dirs.len(), 5, "{dirs:?}");
    assert_eq!(dirs[0], root.join("chosen"));
    assert_eq!(dirs[1], root.join("cache").join("podssh"));
    assert_eq!(dirs[2], root.join("run").join("podssh"));
    assert!(dirs[3].starts_with(root.join("tmp")), "{dirs:?}");
    assert!(dirs[3].file_name().unwrap().to_string_lossy().starts_with("podssh-"), "{dirs:?}");
    assert_eq!(dirs[4], root.join("work").join(".podssh"));
    // With no variable, the user's places are missing, never guessed.
    let bare = candidate_dirs_from(&env(&[]), None);
    assert!(!bare.iter().any(|d| d.ends_with("podssh") && !d.to_string_lossy().contains("podssh-")), "{bare:?}");
}

/// PODSSH_CACHE_DIR=none gives no directory, and a store says why; a
/// relative path is not used.
#[test]
fn none_keeps_no_file_and_a_relative_path_is_not_used() {
    let root = scratch("none");
    for spelling in ["none", "NONE"] {
        let pairs = [("PODSSH_CACHE_DIR", PathBuf::from(spelling)), ("TMPDIR", root.clone())];
        assert_eq!(chosen_from(&env(&pairs)), Chosen::Nothing);
        assert!(candidate_dirs_from(&env(&pairs), Some(root.clone())).is_empty());
    }
    let err = store_noting(&[], "relay.example", b"x").unwrap_err();
    assert!(err.contains("PODSSH_CACHE_DIR is none"), "{err}");
    let pairs = [("PODSSH_CACHE_DIR", PathBuf::from("relative/dir")), ("TMPDIR", root.clone())];
    assert_eq!(chosen_from(&env(&pairs)), Chosen::Relative("relative/dir".into()));
    let dirs = candidate_dirs_from(&env(&pairs), None);
    assert!(!dirs.iter().any(|d| d.ends_with("dir")), "{dirs:?}");
    assert_eq!(chosen_from(&env(&[("PODSSH_CACHE_DIR", PathBuf::new())])), Chosen::Unset);
}

/// A named directory that refuses a write is skipped, the next one takes
/// the file, and the note names the refusal.
#[test]
fn a_refused_cache_dir_is_named_and_the_next_one_takes_the_file() {
    let root = scratch("refused");
    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"a file where the directory should be").unwrap();
    let chosen = blocked.join("cache");
    let next = root.join("next");
    let stored = store_noting(&[chosen.clone(), next.clone()], "relay.example", b"body").unwrap();
    assert!(stored.path.starts_with(&next), "{stored:?}");
    let note = chosen_note(&Chosen::Dir(chosen.clone()), &stored).expect("a note");
    assert!(note.contains("PODSSH_CACHE_DIR could not be used") && note.contains("blocked"), "{note}");
    // A choice that was followed says nothing.
    let followed = store_noting(std::slice::from_ref(&next), "relay.example", b"body").unwrap();
    assert_eq!(chosen_note(&Chosen::Dir(next), &followed), None);
}

/// With no variable that names the temporary directory, the fixed places
/// of Unix come last, after each place that the environment gives.
#[cfg(unix)]
#[test]
fn with_no_temporary_variable_the_fixed_places_come_last() {
    let root = scratch("fixed");
    let pairs = [("XDG_CACHE_HOME", root.join("cache"))];
    let dirs = candidate_dirs_from(&env(&pairs), Some(root.join("work")));
    let n = dirs.len();
    assert!(dirs[n - 3].starts_with("/tmp") && dirs[n - 2].starts_with("/dev/shm"), "{dirs:?}");
    assert_eq!(dirs[0], root.join("cache").join("podssh"));
}

/// No absolute path stays in the code of the cache's module but the temporary
/// directory's two fixed places, in their one list (T-243, and the
/// operator's ruling of 2026-10-08).
#[test]
fn the_scan_finds_no_other_absolute_path_in_the_cache() {
    let code =
        [include_str!("../src/cache.rs"), include_str!("../src/cache/dirs.rs"), include_str!("../src/cache/own.rs")]
            .concat();
    let mut found = Vec::new();
    for (i, _) in code.match_indices('"') {
        let rest = &code[i + 1..];
        let Some(end) = rest.find('"') else { continue };
        let word = &rest[..end];
        let windows = word.len() > 2 && word.as_bytes()[1] == b':' && word.as_bytes()[0].is_ascii_alphabetic();
        if word.starts_with('/') && word.len() > 1 || windows {
            found.push(word.to_string());
        }
    }
    found.sort();
    found.dedup();
    assert_eq!(found, ["/dev/shm", "/tmp"], "{found:?}");
    let fixed = code.lines().filter(|l| l.contains("\"/tmp\"") || l.contains("\"/dev/shm\"")).count();
    assert_eq!(fixed, 1, "the fixed places are in one list");
}

/// `icacls FILE ARGS`, as a user would open a file to others.
#[cfg(windows)]
fn icacls(file: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("icacls").arg(file).args(args).output().expect("icacls runs");
    assert!(out.status.success(), "icacls {args:?}: {}", String::from_utf8_lossy(&out.stdout));
}

/// On Windows the owner and the access list say whether a file is closed,
/// as OpenSSH for Windows reads them (T-274). podssh's own token file is read
/// back, and ignored once the group Users (S-1-5-32-545) may read it. A list
/// that the group may read is still read as a file that others may read,
/// and refused as a secret; one that it may write, append to, or whose access
/// list it may change is refused.
#[cfg(windows)]
#[test]
fn on_windows_a_file_that_others_may_open_is_not_trusted() {
    use podssh_relay::cache::{read_own, Others};
    let dir = scratch("win-acl");
    let path =
        store_in_first(std::slice::from_ref(&dir), "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example")
            .unwrap();
    assert!(load_from(std::slice::from_ref(&dir), "relay.example", NOW).is_some(), "podssh's own file is read");
    icacls(&path, &["/grant", "*S-1-5-32-545:(R)"]);
    assert!(load_from(std::slice::from_ref(&dir), "relay.example", NOW).is_none(), "a token that others may read");

    let list = dir.join("list");
    std::fs::write(&list, "a list\n").unwrap();
    assert_eq!(read_own(&list, Others::Read).unwrap().as_deref(), Some("a list\n"));
    icacls(&list, &["/grant", "*S-1-5-32-545:(R)"]);
    assert_eq!(read_own(&list, Others::Read).unwrap().as_deref(), Some("a list\n"), "others may read a list");
    let why = read_own(&list, Others::NoAccess).unwrap_err();
    assert!(why.contains("others can read it") && why.contains("S-1-5-32-545"), "{why}");
    for right in ["W", "AD", "WDAC"] {
        let file = dir.join(format!("open-{right}"));
        std::fs::write(&file, "x").unwrap();
        icacls(&file, &["/grant", &format!("*S-1-5-32-545:({right})")]);
        let why = read_own(&file, Others::Read).unwrap_err();
        assert!(why.contains("others can change it") && why.contains("the group Users"), "{right}: {why}");
    }
}

/// A directory that others may open is made private: it gets an access list
/// of its own, and the file in it, which others could change, is closed.
#[cfg(windows)]
#[test]
fn on_windows_a_directory_open_to_others_is_made_private() {
    use podssh_relay::cache::{read_own, Others};
    let dir = scratch("win-dir").join("open");
    std::fs::create_dir_all(&dir).unwrap();
    icacls(&dir, &["/grant", "*S-1-5-32-545:(OI)(CI)(M)"]);
    let file = dir.join("list");
    std::fs::write(&file, "x").unwrap();
    assert!(read_own(&file, Others::Read).unwrap_err().contains("others can change it"));
    podssh_relay::cache::private_dir(&dir).unwrap();
    assert_eq!(read_own(&file, Others::NoAccess).unwrap().as_deref(), Some("x"), "closed now");
}
