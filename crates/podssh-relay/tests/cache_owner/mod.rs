//! The cache in another user's tree (T-593, GitHub #118): a home of another
//! uid is passed over for the home of the uid's entry in the user database,
//! no directory but the cache's own is made there, and what podssh kept
//! there before is read and said, never moved. Each test gives the list the
//! owner of the directories that it calls another user's, so that it runs as
//! any user, root or not, with no second account.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use podssh_relay::cache::{
    load_from, make_dirs_with, places_with, private_dir, store_in_first, store_noting, Host, Places, MIN_REMAINING_MS,
};
use podssh_relay::identity::file::{self, Place};
use podssh_relay::identity::pins::{self, Seen};
use podssh_relay::session::OsEntropy;

use super::{env, scratch, NOW, TOKEN};

/// This user's uid, as the owner of a directory that the test made, and
/// another uid that is not root's.
fn uids(made: &Path) -> (u32, u32) {
    let me = std::fs::metadata(made).unwrap().uid();
    (me, me.checked_add(1).unwrap_or_else(|| me - 1))
}

/// Run `f` with a host of the uid `uid`, whose owners are the real ones but
/// for `given`, and whose user database gives `home` to `uid` alone.
fn with_host<R>(uid: u32, given: &[(PathBuf, u32)], home: Option<PathBuf>, f: impl FnOnce(&Host) -> R) -> R {
    let owner = |path: &Path| -> Result<Option<u32>, String> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
            Ok(meta) => Ok(Some(given.iter().find(|(p, _)| p.as_path() == path).map_or(meta.uid(), |(_, u)| *u))),
        }
    };
    let home_of = |asked: u32| -> Option<PathBuf> {
        if asked == uid {
            home.clone()
        } else {
            None
        }
    };
    f(&Host { uid, owner: &owner, home_of: &home_of })
}

/// The places of `HOME=home`, with `theirs` another uid's and `entry` the
/// home of the user database.
fn places_of(home: &Path, theirs: &Path, entry: Option<&Path>, root: &Path) -> (Places, u32) {
    let (me, other) = uids(root);
    let pairs = [("HOME", home.to_path_buf()), ("TMPDIR", root.join("tmp"))];
    let given = [(theirs.to_path_buf(), other)];
    (with_host(me, &given, entry.map(Path::to_path_buf), |host| places_with(&env(&pairs), None, host)), other)
}

fn cache_of(home: &Path) -> PathBuf {
    home.join(".cache").join("podssh")
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_home_of_another_uid_is_passed_over_for_the_passwd_home() {
    let root = scratch("other-home");
    let (theirs, mine) = (root.join("theirs"), root.join("mine"));
    for dir in [&theirs, &mine] {
        private_dir(dir).unwrap();
    }
    let (places, other) = places_of(&theirs, &theirs, Some(&mine), &root);
    assert_eq!(places.dirs.first(), Some(&cache_of(&mine)), "the passwd home's cache comes first: {places:?}");
    assert_eq!(places.user, Some(cache_of(&mine)));
    assert_eq!(places.passed.len(), 1, "{places:?}");
    assert_eq!(places.passed[0].dir, cache_of(&theirs));
    assert_eq!(places.passed[0].why, format!("uid {other} owns {}", theirs.display()));
    assert!(!places.dirs.contains(&cache_of(&theirs)), "nothing is written there");
    assert_eq!(places.read().last(), Some(&cache_of(&theirs)), "it is read last");
    assert!(!theirs.join(".cache").exists(), "the list makes nothing");

    // A .cache there that an earlier run made this user's is still in their
    // home, and so is XDG_CACHE_HOME in it.
    std::fs::create_dir(theirs.join(".cache")).unwrap();
    let (me, other) = uids(&root);
    let pairs = [("HOME", theirs.clone()), ("XDG_CACHE_HOME", theirs.join("xdg")), ("TMPDIR", root.join("tmp"))];
    let given = [(theirs.clone(), other)];
    let places = with_host(me, &given, Some(mine.clone()), |host| places_with(&env(&pairs), None, host));
    assert_eq!(places.dirs.first(), Some(&cache_of(&mine)), "{places:?}");
    let passed: Vec<&PathBuf> = places.passed.iter().map(|p| &p.dir).collect();
    assert_eq!(passed, [&theirs.join("xdg").join("podssh"), &cache_of(&theirs)], "{places:?}");

    // This user's own home is kept, and nothing is passed over.
    let (places, _) = places_of(&mine, &theirs, None, &root);
    assert_eq!(places.dirs.first(), Some(&cache_of(&mine)));
    assert!(places.passed.is_empty(), "{places:?}");

    // With no entry in the user database, the list goes on without a cache
    // of the user's: the temporary directory comes first.
    let (places, _) = places_of(&theirs, &theirs, None, &root);
    assert_eq!(places.user, None);
    assert!(places.dirs[0].starts_with(root.join("tmp")), "{places:?}");
    assert_eq!(places.passed.len(), 1, "{places:?}");

    // A passwd home that is another uid's too gives nothing either.
    let (places, _) = places_of(&theirs, &theirs, Some(&theirs), &root);
    assert_eq!(places.user, None, "{places:?}");
}

#[test]
fn no_parent_is_made_in_another_user_s_home() {
    let root = scratch("no-parent");
    let (theirs, mine) = (root.join("theirs"), root.join("mine"));
    for dir in [&theirs, &mine] {
        private_dir(dir).unwrap();
    }
    let (me, other) = uids(&root);
    let given = [(theirs.clone(), other)];
    let why = with_host(me, &given, None, |host| make_dirs_with(&cache_of(&theirs), host)).unwrap_err();
    assert_eq!(why.kind(), std::io::ErrorKind::PermissionDenied, "{why}");
    assert!(why.to_string().contains(&format!("uid {other} owns {}", theirs.display())), "{why}");
    assert!(!theirs.join(".cache").exists(), "no .cache is made in their home");

    // The cache's own directory may be made in any directory that lets the
    // user in, as one that PODSSH_CACHE_DIR names.
    let own = theirs.join("podssh-cache");
    let made = with_host(me, &given, None, |host| make_dirs_with(&own, host)).unwrap();
    assert_eq!(made, std::slice::from_ref(&own));
    assert_eq!(mode(&own), 0o700);

    // In this user's own tree each missing directory is made, mode 0700,
    // the highest first; made again, nothing.
    let made = with_host(me, &given, None, |host| make_dirs_with(&cache_of(&mine), host)).unwrap();
    assert_eq!(made, [mine.join(".cache"), cache_of(&mine)]);
    assert_eq!(mode(&mine.join(".cache")), 0o700);
    assert!(with_host(me, &given, None, |host| make_dirs_with(&cache_of(&mine), host)).unwrap().is_empty());

    // A file stored by the list of a home of another uid goes to the passwd
    // home's cache, and their home stays as it was.
    std::fs::remove_dir_all(mine.join(".cache")).unwrap();
    let (places, _) = places_of(&theirs, &theirs, Some(&mine), &root);
    let stored = store_noting(&places.dirs, "relay.example", b"body").unwrap();
    assert_eq!(stored.path, cache_of(&mine).join("relay.example"), "{stored:?}");
    assert!(!theirs.join(".cache").exists());
}

#[test]
fn a_key_kept_there_before_is_read_and_said() {
    let root = scratch("kept-key");
    let (theirs, mine) = (root.join("theirs"), root.join("mine"));
    // What an earlier run kept in their home, in a directory of this user's
    // there: a node's key, a token and the pins.
    let old = cache_of(&theirs);
    private_dir(&old).unwrap();
    private_dir(&mine).unwrap();
    let before = file::load_in(std::slice::from_ref(&old), &file::node_place("lab"), &mut OsEntropy).unwrap();
    assert!(before.made);
    store_in_first(std::slice::from_ref(&old), "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example")
        .unwrap();
    let pinned = before.identity.public();
    std::fs::write(old.join(pins::FILE), format!("a {}\n", pinned.fingerprint())).unwrap();
    std::fs::set_permissions(old.join(pins::FILE), std::fs::Permissions::from_mode(0o600)).unwrap();

    let (places, other) = places_of(&theirs, &theirs, Some(&mine), &root);
    let kept = old.join(file::node_file("lab"));
    // The key is read there: the node keeps its identity, and none is made.
    let found = file::load_split(&places.read(), &places.dirs, &file::node_place("lab"), &mut OsEntropy).unwrap();
    assert!(!found.made, "no new identity");
    assert_eq!(found.identity.public(), before.identity.public());
    assert_eq!(found.path.as_deref(), Some(kept.as_path()));
    // The run says where it is, why, and where to move it.
    let to = cache_of(&mine).join(file::node_file("lab"));
    let note = places.kept_note(&kept).expect("a note for the kept key");
    assert!(note.contains(&kept.display().to_string()), "{note}");
    assert!(note.contains(&format!("uid {other} owns {}", theirs.display())), "{note}");
    assert!(note.contains(&format!("move it to {}", to.display())), "{note}");
    // The token kept there is used.
    assert!(load_from(&places.read(), "relay.example", NOW).is_some(), "the token is read there");
    // The pins kept there are checked; a new pin goes into a copy in this
    // user's own cache, with the old lines.
    assert_eq!(pins::check_split(&places.read(), &places.dirs, "a", &pinned), Ok(Seen::Known));
    let newer = file::load_in(&[], &Place::Ephemeral, &mut OsEntropy).unwrap().identity.public();
    let copy = cache_of(&mine).join(pins::FILE);
    assert_eq!(pins::check_split(&places.read(), &places.dirs, "b", &newer), Ok(Seen::Pinned(copy.clone())));
    let text = std::fs::read_to_string(&copy).unwrap();
    assert_eq!(text, format!("a {}\nb {}\n", pinned.fingerprint(), newer.fingerprint()));
    assert_eq!(std::fs::read_to_string(old.join(pins::FILE)).unwrap(), format!("a {}\n", pinned.fingerprint()));

    // Nothing more was written in their home.
    let mut names: Vec<String> =
        std::fs::read_dir(&old).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, [pins::FILE, "node-lab.key", "relay-token-relay.example.json"]);

    // Once the user moves it, the key is read in this user's own cache, the
    // same identity, and nothing is said.
    std::fs::rename(&kept, &to).unwrap();
    let moved = file::load_split(&places.read(), &places.dirs, &file::node_place("lab"), &mut OsEntropy).unwrap();
    assert_eq!(moved.path.as_deref(), Some(to.as_path()));
    assert_eq!(moved.identity.public(), before.identity.public());
    assert_eq!(places.kept_note(&to), None);
}
