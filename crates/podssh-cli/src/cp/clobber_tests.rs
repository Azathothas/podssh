//! The tests of `--no-clobber`, `--update` and `--backup` (T-473) that need no
//! server: the rule of the command line, the look's answer, the names that
//! `--delete` keeps, a dry run's actions, and the placing here.

use super::*;
use crate::cp::meta::Stamp;

fn seen(mtime: u32, size: u64) -> Seen {
    Seen { mtime: Some(mtime), size }
}

fn quiet() -> Log {
    Log::new(podssh_ssh::LogLevel::Quiet)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-clobber-{name}-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_flags_that_do_not_go_together_are_refused() {
    assert!(of(true, false, true, None, false).unwrap_err().contains("--no-clobber and --backup"));
    assert!(of(false, false, true, None, true).unwrap_err().contains("--backup and --inplace"));
    assert_eq!(of(false, false, false, Some(".bak"), false), Err("--suffix goes with --backup".into()));
    for bad in ["", "/x", "a\\b"] {
        assert!(of(false, false, true, Some(bad), false).is_err(), "{bad:?}");
    }
    assert_eq!(of(false, false, false, None, false), Ok(Clobber::default()));
    assert_eq!(of(false, false, true, None, false).unwrap().backup, Some("~"), "GNU cp's and rsync's");
    assert_eq!(
        of(false, true, true, Some(".bak"), false).unwrap(),
        Clobber { mode: Mode::Update, backup: Some(".bak") }
    );
    // -n wins over -u, and goes with --inplace: the look keeps the name.
    assert_eq!(of(true, true, false, None, true).unwrap().mode, Mode::Keep);
}

#[test]
fn update_copies_a_later_source_or_one_of_the_same_second_and_another_size() {
    let source = seen(100, 10);
    assert_eq!(decide(Mode::Update, source, None), None, "a missing name");
    assert_eq!(decide(Mode::Update, source, Some(seen(99, 10))), None, "an older destination");
    assert_eq!(decide(Mode::Update, source, Some(seen(101, 10))), Some(Skip::NotNewer));
    assert_eq!(decide(Mode::Update, source, Some(seen(100, 9))), None, "the same second, another size");
    assert_eq!(decide(Mode::Update, source, Some(seen(100, 10))), Some(Skip::NotNewer));
    // No time to compare: the file goes, and the look says so.
    assert_eq!(decide(Mode::Update, source, Some(Seen { mtime: None, size: 10 })), None);
    assert_eq!(decide(Mode::Keep, source, Some(seen(1, 1))), Some(Skip::Exists));
    assert_eq!(decide(Mode::Keep, source, None), None);
    assert_eq!(decide(Mode::Replace, source, Some(seen(200, 10))), None);
    assert_eq!((Skip::Exists.why(), Skip::NotNewer.why()), ("exists", "not newer"));
}

#[test]
fn delete_keeps_each_name_with_the_suffix_and_what_holds_it() {
    let dir = |r: &str| Item::Dir { rel: r.into(), stamp: Stamp::default() };
    let file = |r: &str| Item::File { rel: r.into() };
    let all = vec![dir("a"), file("a/f~"), dir("b"), file("b/g"), file("h~"), file("i"), dir("j~"), file("j~/k")];
    let mut target = all.clone();
    protect(&mut target, Clobber { backup: Some("~"), ..Clobber::default() });
    let rels: Vec<&str> = target.iter().map(tree::rel_of).collect();
    assert_eq!(rels, ["b", "b/g", "i"], "a holds a backup, h~ is one, and j~ and what it holds");
    let mut same = all.clone();
    protect(&mut same, Clobber::default());
    assert_eq!(same, all, "no --backup, no name is kept");
}

#[test]
fn a_dry_run_says_the_skip_or_the_backup_then_the_copy() {
    let (from, to) = ("src/f".to_string(), "dest/f".to_string());
    let keep = Clobber { mode: Mode::Keep, backup: None };
    let update = Clobber { mode: Mode::Update, backup: None };
    let backup = Clobber { backup: Some("~"), ..Clobber::default() };
    let at = Some(seen(100, 1));
    let shown = |p: Vec<Planned>| p.into_iter().map(|(a, f, t)| format!("{a} {f} {t}")).collect::<Vec<_>>();
    assert_eq!(shown(planned(from.clone(), to.clone(), at, at, keep)), ["skip src/f exists"]);
    assert_eq!(shown(planned(from.clone(), to.clone(), at, None, keep)), ["copy src/f dest/f"]);
    assert_eq!(shown(planned(from.clone(), to.clone(), at, Some(seen(200, 1)), update)), ["skip src/f not newer"]);
    assert_eq!(shown(planned(from.clone(), to.clone(), at, Some(seen(50, 1)), update)), ["copy src/f dest/f"]);
    assert_eq!(
        shown(planned(from.clone(), to.clone(), at, at, backup)),
        ["backup dest/f dest/f~", "copy src/f dest/f"]
    );
    assert_eq!(shown(planned(from, to, at, None, backup)), ["copy src/f dest/f"], "nothing there to keep");
}

#[test]
fn no_clobber_here_keeps_a_name_that_came_and_takes_a_missing_one() {
    let dir = scratch("keep");
    let keep = Clobber { mode: Mode::Keep, backup: None };
    let (temp, target) = (dir.join(".f.part"), dir.join("f"));
    std::fs::write(&temp, b"new").unwrap();
    std::fs::write(&target, b"came during the copy").unwrap();
    let placed = place_local(&temp, &target, keep, &quiet()).unwrap();
    assert_eq!(placed.skipped, Some(Skip::Exists));
    assert_eq!(std::fs::read(&target).unwrap(), b"came during the copy");
    assert!(!temp.exists(), "the temporary name goes");
    std::fs::write(&temp, b"new").unwrap();
    let other = dir.join("g");
    assert_eq!(place_local(&temp, &other, keep, &quiet()).unwrap(), Placed::default());
    assert_eq!(std::fs::read(&other).unwrap(), b"new");
    assert!(!temp.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn backup_here_keeps_the_old_file_under_the_suffix() {
    let dir = scratch("backup");
    let backup = Clobber { backup: Some(".bak"), ..Clobber::default() };
    let (temp, target) = (dir.join(".f.part"), dir.join("f"));
    std::fs::write(&target, b"old").unwrap();
    std::fs::write(dir.join("f.bak"), b"older").unwrap();
    std::fs::write(&temp, b"new").unwrap();
    let placed = place_local(&temp, &target, backup, &quiet()).unwrap();
    assert_eq!(placed.backup.as_deref(), Some(dir.join("f.bak").display().to_string().as_str()));
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert_eq!(std::fs::read(dir.join("f.bak")).unwrap(), b"old", "an older backup went first");
    // Nothing there: no backup.
    std::fs::write(&temp, b"first").unwrap();
    let placed = place_local(&temp, &dir.join("g"), backup, &quiet()).unwrap();
    assert_eq!(placed.backup, None);
    assert!(!dir.join("g.bak").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_look_here_keeps_a_destination_that_is_there() {
    let dir = scratch("look");
    std::fs::write(dir.join("f"), b"there").unwrap();
    let keep = Clobber { mode: Mode::Keep, backup: None };
    let source = seen(100, 3);
    let done = before_local("src", &dir.join("f"), source, keep, false, &quiet()).unwrap().expect("kept");
    assert_eq!((done.skipped, done.bytes, done.sum), (Some(Skip::Exists), 0, None));
    assert!(before_local("src", &dir.join("g"), source, keep, false, &quiet()).unwrap().is_none(), "missing");
    // A copy that goes on looked at its first attempt.
    assert!(before_local("src", &dir.join("f"), source, keep, true, &quiet()).unwrap().is_none());
    assert!(before_local("src", &dir.join("f"), source, Clobber::default(), false, &quiet()).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
