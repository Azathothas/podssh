//! The walk of whose tree a directory is in, and the home of the user
//! database, with each owner given: they run as any user, and touch no file.

use super::*;

const ME: u32 = 1000;
const ALICE: u32 = 1001;

/// A host whose directories are the pairs given, each with its owner; any
/// other path is missing.
fn walk(owners: &[(&str, u32)], dir: &str, top: Option<&str>) -> Option<String> {
    let owner = |path: &Path| -> Result<Option<u32>, String> {
        Ok(owners.iter().find(|(p, _)| Path::new(p) == path).map(|(_, uid)| *uid))
    };
    let home_of = |_: u32| -> Option<PathBuf> { None };
    let host = Host { uid: ME, owner: &owner, home_of: &home_of };
    foreign(Path::new(dir), top.map(Path::new), &host)
}

/// The tree of a home: `/` and `/home` root's, and the home its user's.
fn tree(home_owner: u32, cache_owner: Option<u32>) -> Vec<(&'static str, u32)> {
    let mut owners = vec![("/", ROOT), ("/home", ROOT), ("/home/alice", home_owner)];
    owners.extend(cache_owner.map(|uid| ("/home/alice/.cache", uid)));
    owners
}

#[test]
fn a_home_of_another_uid_is_another_user_s_tree() {
    let home = Some("/home/alice");
    // A missing .cache, and one that its owner made.
    let why = walk(&tree(ALICE, None), "/home/alice/.cache", home).expect("passed over");
    assert_eq!(why, "uid 1001 owns /home/alice");
    assert!(walk(&tree(ALICE, Some(ALICE)), "/home/alice/.cache", home).is_some());
    // A .cache that an earlier run made this uid's, in that home: still theirs.
    let why = walk(&tree(ALICE, Some(ME)), "/home/alice/.cache", home).expect("passed over");
    assert_eq!(why, "uid 1001 owns /home/alice");
    // This user's own home, with its .cache missing or made.
    assert_eq!(walk(&tree(ME, None), "/home/alice/.cache", home), None);
    assert_eq!(walk(&tree(ME, Some(ME)), "/home/alice/.cache", home), None);
}

#[test]
fn the_walk_stops_at_the_home_and_takes_root_s_directories_on_the_way() {
    // A home in a directory that another user shares: the walk stops at the
    // home, as OpenSSH's StrictModes stops there.
    let owners = [("/", ROOT), ("/srv", ROOT), ("/srv/team", ALICE), ("/srv/team/me", ME)];
    assert_eq!(walk(&owners, "/srv/team/me/.cache", Some("/srv/team/me")), None);
    // The same directory outside the home is walked up to the root.
    assert_eq!(walk(&owners, "/srv/team/me/.cache", None).as_deref(), Some("uid 1001 owns /srv/team"));
    // A home of root's, as a service account's often is, and /tmp.
    let owners = [("/", ROOT), ("/var", ROOT), ("/var/lib", ROOT), ("/var/lib/svc", ROOT), ("/tmp", ROOT)];
    assert_eq!(walk(&owners, "/var/lib/svc/.cache", Some("/var/lib/svc")), None);
    assert_eq!(walk(&owners, "/tmp/.cache", Some("/tmp")), None);
    // A home that does not exist at all is nobody's.
    assert_eq!(walk(&[("/", ROOT)], "/nonexistent/.cache", Some("/nonexistent")), None);
}

#[test]
fn a_directory_whose_owner_cannot_be_read_is_passed_over_with_why() {
    let owner = |path: &Path| -> Result<Option<u32>, String> {
        if path == Path::new("/root") {
            Err("/root: Permission denied".to_string())
        } else {
            Ok(Some(ROOT))
        }
    };
    let home_of = |_: u32| -> Option<PathBuf> { None };
    let host = Host { uid: ME, owner: &owner, home_of: &home_of };
    let why = foreign(Path::new("/root/.cache"), Some(Path::new("/root")), &host);
    assert_eq!(why.as_deref(), Some("/root: Permission denied"));
}

#[test]
fn the_home_is_that_of_the_first_usable_entry_of_the_uid() {
    let text = "# a comment\n\
                +nis:x:1000:1000::/home/nis:/bin/sh\n\
                bad name:x:1000:1000::/home/bad:/bin/sh\n\
                short:x:1000\n\
                root:x:0:0:root:/root:/bin/sh\n\
                me:x:1000:1000:Me:/home/me:/bin/sh\n\
                again:x:1000:1000::/home/again:/bin/sh\n\
                rel:x:1002:1002::home/rel:/bin/sh\n";
    assert_eq!(passwd_home(text, 1000), Some(PathBuf::from("/home/me")));
    assert_eq!(passwd_home(text, 0), Some(PathBuf::from("/root")));
    assert_eq!(passwd_home(text, 1002), None, "a relative home is no home");
    assert_eq!(passwd_home(text, 4242), None, "no entry");
    assert_eq!(passwd_home("", 0), None);
}
