//! The key file of each end (T-163, T-087), in temporary directories: a
//! private file made once and read again, under the names of T-163 too;
//! never shown; and a file that is not private, that is a symbolic link or
//! that holds no key, refused with the reason and kept, as a new key would
//! give the node a new identity.

mod cleanup;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use podssh_relay::identity::file::{self, Key, Place};
use podssh_relay::session::{Entropy, NoRandom, OsEntropy};

/// A fresh, empty scratch directory unique to one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-identity-file-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// Entropy that gives one byte again and again: a known seed, so that the
/// test can look for its text.
struct Fixed(u8);

impl Entropy for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), NoRandom> {
        buf.fill(self.0);
        Ok(())
    }
}

/// No random source at all, as under a seccomp filter.
struct Empty;

impl Entropy for Empty {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), NoRandom> {
        Err(NoRandom)
    }
}

/// The seed of [`Fixed`]`(byte)`, as the key file and iroh write it.
fn seed_text(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn load(place: &Place) -> Key {
    file::load_in(&[], place, &mut OsEntropy).unwrap()
}

fn cache(name: &str, old: Option<&str>) -> Place {
    Place::Cache { name: name.to_string(), old: old.map(str::to_string) }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_key_file_is_made_private_once_then_read_again() {
    let path = scratch("once").join("node.key");
    let place = Place::File(path.clone());
    let first = file::load_in(&[], &place, &mut Fixed(0x2a)).unwrap();
    assert!(first.made, "a new key is made where there is none");
    assert_eq!(first.path.as_deref(), Some(path.as_path()));
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text, format!("{}\n", seed_text(0x2a)), "the seed in hex and a newline, as iroh parses it");
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600, "only its owner can read the key");

    let again = load(&place);
    assert!(!again.made, "the key is read again, not made again");
    assert_eq!(again.identity.public(), first.identity.public(), "the same identity");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "the file is not written again");
}

#[test]
fn a_key_in_the_cache_is_read_from_the_first_directory_that_has_it() {
    let base = scratch("cache");
    let (a, b) = (base.join("a"), base.join("b"));
    let name = file::node_file("lab");
    assert_eq!(name, "node-lab.key");
    let made = file::load_in(std::slice::from_ref(&b), &cache(&name, None), &mut OsEntropy).unwrap();
    assert!(made.made);
    let found = file::load_in(&[a.clone(), b.clone()], &cache(&name, None), &mut OsEntropy).unwrap();
    assert!(!found.made, "the key in the second directory is found");
    assert_eq!(found.identity.public(), made.identity.public());
    assert_eq!(found.path, Some(b.join(&name)));
    assert!(!a.join(&name).exists(), "no second key is made in the first directory");

    // With no key anywhere, the first directory that takes one gets it: a
    // file where a directory should be takes none.
    let (blocked, c) = (base.join("blocked"), base.join("c"));
    std::fs::write(&blocked, b"not a directory").unwrap();
    let client = file::load_in(&[blocked, c.clone()], &cache(file::CLIENT_FILE, None), &mut OsEntropy).unwrap();
    assert!(client.made);
    assert_eq!(client.path, Some(c.join(file::CLIENT_FILE)));
}

#[test]
fn a_key_under_the_name_of_t163_stays_the_identity() {
    let base = scratch("old-name");
    let (a, b) = (base.join("a"), base.join("b"));
    std::fs::create_dir_all(&b).unwrap();
    // A node key that the iroh road made before T-087, in the second directory.
    let old = b.join(file::old_node_file("lab"));
    assert_eq!(file::old_node_file("lab"), "iroh-node-lab.key");
    let before = file::load_in(&[], &Place::File(old.clone()), &mut Fixed(0x11)).unwrap();
    let dirs = [a.clone(), b.clone()];
    let found = file::load_in(&dirs, &file::node_place("lab"), &mut OsEntropy).unwrap();
    assert!(!found.made, "no new identity beside the old one");
    assert_eq!(found.path, Some(old));
    assert_eq!(found.identity.public(), before.identity.public());
    assert!(!a.join(file::node_file("lab")).exists() && !b.join(file::node_file("lab")).exists());

    // The new name, where there is one, comes first.
    std::fs::create_dir_all(&a).unwrap();
    let new = file::load_in(&[], &Place::File(a.join(file::node_file("lab"))), &mut Fixed(0x22)).unwrap();
    let found = file::load_in(&dirs, &file::node_place("lab"), &mut OsEntropy).unwrap();
    assert_eq!(found.identity.public(), new.identity.public());

    // The client's key of T-163 too.
    let c = base.join("c");
    std::fs::create_dir_all(&c).unwrap();
    let old_client = file::load_in(&[], &Place::File(c.join(file::OLD_CLIENT_FILE)), &mut OsEntropy).unwrap();
    let found = file::load_in(std::slice::from_ref(&c), &file::client_place(), &mut OsEntropy).unwrap();
    assert_eq!(found.identity.public(), old_client.identity.public());
}

#[test]
fn an_ephemeral_key_is_new_each_time_and_written_nowhere() {
    let dir = scratch("ephemeral");
    let one = file::load_in(std::slice::from_ref(&dir), &Place::Ephemeral, &mut OsEntropy).unwrap();
    let two = file::load_in(std::slice::from_ref(&dir), &Place::Ephemeral, &mut OsEntropy).unwrap();
    assert!(one.made && one.path.is_none());
    assert_ne!(one.identity.public(), two.identity.public());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "nothing was written");
}

#[test]
fn no_output_holds_the_secret_key() {
    let dir = scratch("secret");
    let path = dir.join("node.key");
    let key = file::load_in(&[], &Place::File(path.clone()), &mut Fixed(0x5c)).unwrap();
    let seed = seed_text(0x5c);
    let shown = [format!("{key:?}"), key.identity.public().to_string(), format!("{:?}", key.identity)];
    for text in &shown {
        assert!(!text.contains(&seed), "the seed is in {text:?}");
    }

    // A file that is not a key: the error names the file, and holds none of
    // its text.
    let bad = dir.join("bad.key");
    let near_miss = format!("{}zz\n", &seed[..62]);
    std::fs::write(&bad, &near_miss).unwrap();
    restrict(&bad);
    let why = file::load_in(&[], &Place::File(bad.clone()), &mut OsEntropy).unwrap_err();
    assert!(why.contains("bad.key") && why.contains("not a key"), "{why}");
    assert!(!why.contains(&near_miss[..16]), "the error shows the file's text: {why}");
    assert_eq!(std::fs::read_to_string(&bad).unwrap(), near_miss, "a file that is not a key is kept");
}

#[test]
fn two_first_runs_at_once_get_one_key() {
    let path = scratch("race").join("node.key");
    let runs = 8;
    let start = Arc::new(Barrier::new(runs));
    let threads: Vec<_> = (0..runs)
        .map(|_| {
            let (path, start) = (path.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                file::load_in(&[], &Place::File(path), &mut OsEntropy).unwrap()
            })
        })
        .collect();
    let got: Vec<Key> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(got.iter().filter(|k| k.made).count(), 1, "one run makes the key");
    assert!(got.iter().all(|k| k.identity.public() == got[0].identity.public()), "each run has the one key");
    let names: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(names.len(), 1, "no temporary file is left: {names:?}");
}

#[test]
fn no_random_source_is_an_error_not_a_panic() {
    let path = scratch("norandom").join("node.key");
    let why = file::load_in(&[], &Place::File(path.clone()), &mut Empty).unwrap_err();
    assert!(why.contains("random"), "{why}");
    assert!(!path.exists(), "no file is made without a key");
}

#[test]
fn a_symbolic_link_is_refused_and_not_followed() {
    let dir = scratch("link");
    let elsewhere = dir.join("elsewhere.key");
    let link = dir.join("node.key");
    if !make_link(&elsewhere, &link) {
        eprintln!("skipped: this host makes no symbolic link for this user");
        return;
    }
    // A link that points nowhere: no key is made at its target.
    let why = file::load_in(&[], &Place::File(link.clone()), &mut OsEntropy).unwrap_err();
    assert!(why.contains("symbolic link"), "{why}");
    assert!(!elsewhere.exists(), "the link was followed");

    // A link to a real key file is refused too, and both are kept.
    let real = load(&Place::File(elsewhere.clone()));
    let why = file::load_in(&[], &Place::File(link.clone()), &mut OsEntropy).unwrap_err();
    assert!(why.contains("symbolic link"), "{why}");
    assert_eq!(load(&Place::File(elsewhere)).identity.public(), real.identity.public());
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
}

#[cfg(unix)]
#[test]
fn a_key_file_that_others_can_read_is_refused_and_kept() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch("open").join("node.key");
    let key = load(&Place::File(path.clone()));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let why = file::load_in(&[], &Place::File(path.clone()), &mut OsEntropy).unwrap_err();
    assert!(why.contains("others can read it") && why.contains("chmod 600"), "{why}");
    // In the cache, too: the search stops there, and no new key is made in
    // the next directory.
    let base = scratch("open-cache");
    let (a, b) = (base.join("a"), base.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::copy(&path, a.join(file::CLIENT_FILE)).unwrap();
    std::fs::set_permissions(a.join(file::CLIENT_FILE), std::fs::Permissions::from_mode(0o640)).unwrap();
    let why = file::load_in(&[a, b.clone()], &file::client_place(), &mut OsEntropy).unwrap_err();
    assert!(why.contains("others can read it"), "{why}");
    assert!(!b.join(file::CLIENT_FILE).exists(), "a new identity was made beside the refused one");
    // Once private again, the same key.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(load(&Place::File(path)).identity.public(), key.identity.public());
}

/// Make `path` readable by its owner only, where modes exist.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// A symbolic link at `link` to `target`; `false` when this host makes none
/// for this user (Windows without the privilege).
fn make_link(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}
