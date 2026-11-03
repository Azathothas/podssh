use std::path::{Path, PathBuf};

use super::*;

/// A directory of this test alone, gone at its end.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-mcp-dirs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(std::fs::canonicalize(&dir).unwrap())
    }

    fn dir(&self, name: &str) -> PathBuf {
        let dir = self.0.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}

#[test]
fn a_path_of_the_directory_is_read_and_one_outside_it_is_refused() {
    let s = Scratch::new("source");
    let (inside, outside) = (s.dir("allowed"), s.dir("other"));
    std::fs::write(inside.join("a.txt"), b"a").unwrap();
    std::fs::write(outside.join("b.txt"), b"b").unwrap();
    let dirs = Dirs::new(&[shown(&inside)], &[]).unwrap();
    assert_eq!(dirs.source("a.txt").unwrap(), inside.join("a.txt"), "relative: under the first directory");
    assert_eq!(dirs.source(&shown(&inside.join("a.txt"))).unwrap(), inside.join("a.txt"));
    for bad in [shown(&outside.join("b.txt")), "../other/b.txt".to_string(), "missing.txt".to_string()] {
        assert!(dirs.source(&bad).is_err(), "{bad}");
    }
    let refused = dirs.source(&shown(&outside.join("b.txt"))).unwrap_err();
    assert!(refused.contains("outside the directories of --allow-dir"), "{refused}");
    assert!(dirs.source("").is_err() && dirs.source("a\0b").is_err());
}

/// A link inside the directory that leads out of it is held to where it
/// leads, for a read and for a write.
#[cfg(unix)]
#[test]
fn a_link_that_leads_out_of_the_directory_is_refused() {
    let s = Scratch::new("link");
    let (inside, outside) = (s.dir("allowed"), s.dir("other"));
    std::fs::write(outside.join("secret"), b"s").unwrap();
    std::os::unix::fs::symlink(outside.join("secret"), inside.join("to-secret")).unwrap();
    std::os::unix::fs::symlink(&outside, inside.join("to-other")).unwrap();
    std::os::unix::fs::symlink(inside.join("gone"), inside.join("dangling")).unwrap();
    let dirs = Dirs::new(&[shown(&inside)], &[]).unwrap();
    assert!(dirs.source("to-secret").unwrap_err().contains("outside"));
    assert!(dirs.target("to-secret", false).unwrap_err().contains("outside"));
    assert!(dirs.target("to-other/new.txt", false).unwrap_err().contains("outside"));
    assert!(dirs.target("dangling", false).unwrap_err().contains("names nothing"));
}

#[test]
fn a_write_goes_to_a_path_there_or_a_new_name_in_a_directory_there() {
    let s = Scratch::new("target");
    let inside = s.dir("allowed");
    std::fs::write(inside.join("old.txt"), b"o").unwrap();
    let dirs = Dirs::new(&[shown(&inside)], &[]).unwrap();
    assert_eq!(dirs.target("old.txt", false).unwrap(), inside.join("old.txt"));
    assert_eq!(dirs.target("new.txt", false).unwrap(), inside.join("new.txt"));
    assert_eq!(dirs.target(".", false).unwrap(), inside, "the directory itself");
    // A tree goes into a path that is not there.
    assert!(dirs.target("old.txt", true).unwrap_err().contains("new path"));
    assert_eq!(dirs.target("tree", true).unwrap(), inside.join("tree"));
    for bad in ["no-such-dir/new.txt", "../new.txt", "new/.."] {
        assert!(dirs.target(bad, false).is_err(), "{bad}");
    }
}

#[test]
fn a_directory_of_keys_or_above_one_is_refused_and_none_allows_nothing() {
    let s = Scratch::new("keys");
    let (home, elsewhere) = (s.dir("home"), s.dir("work"));
    let keys = [home.join(".ssh")];
    let (code, why) = Dirs::new(&[shown(&home)], &keys).unwrap_err();
    assert_eq!(code, EX_USAGE);
    assert!(why.contains(".ssh is inside it"), "{why}");
    let below = s.dir("home/.ssh/sub");
    let (code, why) = Dirs::new(&[shown(&below)], &keys).unwrap_err();
    assert!(code == EX_USAGE && why.contains("which holds keys"), "{why}");
    assert_eq!(Dirs::new(&[shown(&s.0.join("missing"))], &keys).unwrap_err().0, EX_CONFIG);
    assert!(Dirs::new(&[shown(&elsewhere)], &keys).is_ok());
    let root = if cfg!(windows) { r"C:\".to_string() } else { "/".to_string() };
    if Path::new(&root).is_dir() {
        assert_eq!(Dirs::new(&[root], &[]).unwrap_err().0, EX_USAGE);
    }
    let none = Dirs::new(&[], &keys).unwrap();
    assert!(none.is_empty());
    assert!(none.source("x").unwrap_err().contains("no --allow-dir"));
}
