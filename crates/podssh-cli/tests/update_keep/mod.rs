//! The tests of T-396, a module of `tests/update.rs`: the new binary runs
//! once before it takes the old one's place, through the stand-in release,
//! and is refused when it does not start here or names another version;
//! the trial on the podssh of this build itself, on each system; the binary
//! before an update kept, `--rollback` putting it back and keeping the
//! other, and the fallback that a supervisor (T-390) can start, through the
//! library and through the command on a link of this build. The way back
//! that each line names: the move of the kept file, and `--rollback` only
//! for a release that has it (T-507).

// Some helpers serve Unix alone.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use podssh_cli::update::release::Version;
use podssh_cli::update::{keep, trial, Failure};

use super::{run, Stand, OLD, TAG};
use crate::update_support::Leaf;

/// A script that answers `--version` as podssh does, with `version`, and
/// prints `prints` otherwise.
pub fn script(version: &str, prints: &str) -> Vec<u8> {
    format!("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'podssh {version}'; exit 0; fi\necho '{prints}'\nexit 0\n")
        .into_bytes()
}

/// A script of `body`, made runnable at `path`.
#[cfg(unix)]
fn put_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A directory beside the binaries of this build, on their file system, so
/// that a hard link to one is made with no copy.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("update-keep-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The podssh of this build at `path`: a hard link, else a copy.
fn this_podssh_at(path: &Path) {
    let built = Path::new(env!("CARGO_BIN_EXE_podssh"));
    if std::fs::hard_link(built, path).is_err() {
        std::fs::copy(built, path).unwrap();
    }
}

fn this_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
}

/// A new binary that does not start here never takes the old one's place,
/// and nothing is kept: the trial is the real one, on each system.
#[tokio::test]
async fn a_new_binary_that_does_not_run_here_is_refused_and_the_old_one_stays() {
    let stand = Stand::new("trial-refused").await;
    let binary = b"\x7fELF but no program of any system\n".to_vec();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    let options = podssh_cli::update::Options { trial: trial::by_version, ..stand.options("1.0.0-beta.2") };
    let (result, out) = run(&options, false, Some(TAG)).await;
    match result {
        Err(failure @ Failure::Refused(_)) => {
            assert!(failure.why().contains("did not run here") && failure.why().contains("nothing was replaced"));
            assert_eq!(failure.code(), 65);
        }
        other => panic!("refused, not {other:?}\n{out}"),
    }
    assert!(!out.contains("replaced;"), "{out}");
    stand.assert_untouched();
}

/// A new binary that runs and fails, or names another version than the
/// release's, is refused as well.
#[cfg(unix)]
#[tokio::test]
async fn a_new_binary_that_fails_or_names_another_version_is_refused() {
    let stand = Stand::new("trial-version").await;
    let cases = [
        (script("1.0.0-beta.9", "x"), "it is podssh 1.0.0-beta.9, not 1.0.0-beta.3"),
        (b"#!/bin/sh\necho 'no libc here' >&2\nexit 3\n".to_vec(), "it ended with exit status: 3: no libc here"),
        (b"#!/bin/sh\necho 'podssh'\n".to_vec(), "not podssh VERSION"),
    ];
    for (binary, says) in cases {
        stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
        let (result, out) = run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await;
        match result {
            Err(Failure::Refused(why)) => assert!(why.contains(says), "{says}: {why}"),
            other => panic!("{says}: refused, not {other:?}\n{out}"),
        }
        stand.assert_untouched();
    }
}

/// The trial on the podssh of this build: its version, and no other.
#[test]
fn the_trial_reads_the_version_of_this_build() {
    let built = Path::new(env!("CARGO_BIN_EXE_podssh"));
    let line = trial::check(built, Some(&this_version()), trial::LIMIT).unwrap();
    assert!(line.starts_with(&format!("podssh {}", env!("CARGO_PKG_VERSION"))), "{line}");
    assert!(trial::check(built, None, trial::LIMIT).is_ok());
    let other = Version::parse("9.9.9").unwrap();
    let why = trial::check(built, Some(&other), trial::LIMIT).unwrap_err();
    assert!(why.contains("not 9.9.9"), "{why}");
    let why = trial::check(&built.with_file_name("no-such-podssh"), None, trial::LIMIT).unwrap_err();
    assert!(why.contains("does not start here"), "{why}");
}

/// A new binary that never ends is killed at the bound, and refused.
#[cfg(unix)]
#[test]
fn a_trial_that_does_not_end_is_killed_at_its_bound() {
    use std::time::{Duration, Instant};
    let dir = scratch("trial-hangs");
    let file = dir.join("podssh");
    put_script(&file, "exec sleep 30");
    let started = Instant::now();
    let why = trial::check(&file, None, Duration::from_secs(1)).unwrap_err();
    assert!(why.contains("did not end within 1 s"), "{why}");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--rollback` through the library: the kept binary back, once it ran
/// here; the other one kept in its place; nothing to put back, or a kept
/// one that does not run, changes nothing. On Windows the kept one is a
/// link of this build, and the current one `whoami.exe`, which answers no
/// `--version`.
#[test]
fn rollback_puts_the_kept_binary_back_and_keeps_the_other() {
    let dir = scratch("rollback");
    let exe = dir.join(if cfg!(windows) { "podssh.exe" } else { "podssh" });
    let prev = keep::prev_of(&exe);
    #[cfg(unix)]
    {
        std::fs::write(&exe, script("1.0.0-beta.3", "new")).unwrap();
        put_script(&prev, "[ \"$1\" = --version ] && echo 'podssh 1.0.0-beta.2'; exit 0");
    }
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        std::fs::copy(Path::new(&root).join("System32").join("whoami.exe"), &exe).unwrap();
        this_podssh_at(&prev);
    }
    let (new, old) = (std::fs::read(&exe).unwrap(), std::fs::read(&prev).unwrap());
    assert_eq!(keep::fallback(&exe), Some(prev.clone()), "a supervisor's way back");
    let lines = keep::rollback(&exe).unwrap();
    assert!(lines[0].contains("rolled back") && lines[0].contains("said podssh "), "{lines:?}");
    // T-507: the way back names the move; --rollback only where the binary
    // now in place has it, which 1.0.0-beta.2 has not, and this build has.
    let mv = keep::moved_back(&prev, &exe);
    if cfg!(windows) {
        let back = format!("podssh update --rollback goes back to it, and so does {mv}");
        assert!(lines[1].ends_with(&back), "{lines:?}");
    } else {
        let back = format!("{mv} goes back to it; podssh 1.0.0-beta.2 has no update --rollback");
        assert!(lines[1].ends_with(&back), "{lines:?}");
    }
    assert_eq!(std::fs::read(&exe).unwrap(), old);
    assert_eq!(std::fs::read(&prev).unwrap(), new);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "nothing left aside");
    // A kept binary that does not run is not put back.
    std::fs::write(&prev, b"\x7fELF but no program\n").unwrap();
    assert_eq!(keep::fallback(&exe), None);
    match keep::rollback(&exe) {
        Err(failure @ Failure::Refused(_)) => assert_eq!(failure.code(), 65, "{failure:?}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(std::fs::read(&exe).unwrap(), old);
    // None kept: nothing to put back.
    std::fs::remove_file(&prev).unwrap();
    assert_eq!(keep::fallback(&exe), None);
    match keep::rollback(&exe) {
        Err(failure @ Failure::Unavailable(_)) => {
            assert!(failure.why().contains("no update kept"), "{failure:?}");
            assert_eq!(failure.code(), 69);
        }
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `podssh update --rollback`, run as a link of this build, puts back the
/// kept binary beside that link with no network, and keeps the link in its
/// place; with nothing kept, 69; with `--check`, 64.
#[cfg(unix)]
#[test]
fn the_command_rolls_back_the_binary_that_runs_it() {
    let dir = scratch("rollback-cli");
    let exe = dir.join("podssh");
    this_podssh_at(&exe);
    let prev = keep::prev_of(&exe);
    let run = |args: &[&str]| {
        let out = std::process::Command::new(&exe).args(args).env("PODSSH_OFFLINE", "1").output().unwrap();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
    };
    let (code, _, err) = run(&["update", "--rollback"]);
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("no update kept a binary before this one"), "{err}");
    let (code, _, err) = run(&["update", "--rollback", "--check"]);
    assert_eq!(code, 64, "{err}");
    put_script(&prev, "[ \"$1\" = --version ] && echo 'podssh 1.0.0-beta.2'; exit 0");
    let kept = std::fs::read(&prev).unwrap();
    let (code, out, err) = run(&["update", "--rollback"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("rolled back") && out.contains("said podssh 1.0.0-beta.2"), "{out}");
    assert_eq!(std::fs::read(&exe).unwrap(), kept);
    let built = std::fs::read(env!("CARGO_BIN_EXE_podssh")).unwrap();
    assert!(std::fs::read(&prev).unwrap() == built, "the binary that ran is kept");
    let _ = std::fs::remove_dir_all(&dir);
}

/// T-507: an update to a release before 1.0.0-beta.4, whose binary says
/// "unknown flag '--rollback'", names the move of the kept file alone; to
/// one of 1.0.0-beta.4 or later, `podssh update --rollback` and the move.
#[tokio::test]
async fn the_way_back_names_rollback_only_for_a_release_that_has_it() {
    let stand = Stand::new("way-back").await;
    let prev = keep::prev_of(&stand.exe);
    let mv = keep::moved_back(&prev, &stand.exe);
    let binary = super::release_binary();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    let (result, out) = run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await;
    assert!(result.is_ok(), "{result:?}\n{out}");
    let kept = format!("the binary before it is {}", prev.display());
    let want = format!("{kept}: {mv} puts it back; podssh 1.0.0-beta.3 has no update --rollback");
    assert!(out.lines().any(|l| l == want), "{want}\n{out}");
    assert!(!out.contains("podssh update --rollback puts it back"), "{out}");
    let stable = if cfg!(windows) { b"a binary of the release".to_vec() } else { script("1.0.0", "stable") };
    stand.release("v1.0.0", &stable, stand.sums_of(&stable), &Leaf::of_tag("v1.0.0"));
    let (result, out) = run(&stand.options("1.0.0-beta.3"), false, Some("v1.0.0")).await;
    assert!(result.is_ok(), "{result:?}\n{out}");
    let want = format!("{kept}: podssh update --rollback puts it back, and so does {mv}");
    assert!(out.lines().any(|l| l == want), "{want}\n{out}");
    assert_eq!(std::fs::read(&prev).unwrap(), binary, "the binary of beta.3 is the one kept now");
}

/// The first release with `--rollback` is the constant's, a fact of this
/// repository's notes: none before 1.0.0-beta.4 names it, and those of
/// beta.4 do; the check of a version holds at that boundary.
#[test]
fn rollback_came_with_the_release_that_the_constant_names() {
    let notes: [(&str, &str); 4] = [
        ("1.0.0-beta.1", include_str!("../../../../docs/releases/v1.0.0-beta.1.md")),
        ("1.0.0-beta.2", include_str!("../../../../docs/releases/v1.0.0-beta.2.md")),
        ("1.0.0-beta.3", include_str!("../../../../docs/releases/v1.0.0-beta.3.md")),
        ("1.0.0-beta.4", include_str!("../../../../docs/releases/v1.0.0-beta.4.md")),
    ];
    let first = notes.iter().find(|(_, text)| text.contains("--rollback")).map(|(version, _)| *version);
    assert_eq!(first, Some(keep::ROLLBACK_SINCE));
    let has = |v: &str| keep::has_rollback(&Version::parse(v).unwrap());
    assert!(!has("1.0.0-beta.3") && !has("0.9.0") && !has("1.0.0-beta.2"));
    assert!(has("1.0.0-beta.4") && has("1.0.0-beta.10") && has("1.0.0") && has("1.0.1") && has("1.1.0-beta.1"));
    assert!(has(env!("CARGO_PKG_VERSION")), "this build has --rollback");
    let mv = keep::moved_back(Path::new("/opt/my bin/podssh.prev"), Path::new("/opt/my bin/podssh"));
    if cfg!(windows) {
        assert!(mv.starts_with("cmd /c move /Y \""), "{mv}");
    } else {
        assert_eq!(mv, "mv '/opt/my bin/podssh.prev' '/opt/my bin/podssh'");
    }
}

/// The replacement keeps the old binary: the one before the update, as it
/// was, beside the new one.
#[tokio::test]
async fn the_binary_before_an_update_is_kept_beside_it() {
    let stand = Stand::new("kept").await;
    let binary = super::release_binary();
    stand.release(TAG, &binary, stand.sums_of(&binary), &Leaf::of_tag(TAG));
    let (result, out) = run(&stand.options("1.0.0-beta.2"), false, Some(TAG)).await;
    assert!(result.is_ok(), "{result:?}\n{out}");
    let prev = keep::prev_of(&stand.exe);
    assert!(out.contains(&format!("the binary before it is {}", prev.display())), "{out}");
    assert_eq!(std::fs::read(&prev).unwrap(), OLD);
    assert_eq!(std::fs::read(&stand.exe).unwrap(), binary);
}
