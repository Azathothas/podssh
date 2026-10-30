//! The command line of `podssh run` (T-192), with no host: the target, the
//! far directory, the excludes and the command, and each refusal (64).

use super::*;

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-run-unit-{}-{name}", std::process::id())).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(target: &str, from: &Path, command: &[&str]) -> RunArgs {
    let mut a = RunArgs { target: Some(target.into()), from: Some(from.display().to_string()), ..RunArgs::default() };
    a.ssh.command = command.iter().map(|w| w.to_string()).collect();
    a
}

#[test]
fn a_target_is_a_host_with_a_directory_or_none() {
    let t = target("u@build1").unwrap();
    assert_eq!((t.user.as_deref(), t.host.as_str(), t.path.as_str()), (Some("u"), "build1", ""));
    assert_eq!(target("build1:src/app").unwrap().path, "src/app");
    assert_eq!(target("build1:~/app").unwrap().path, "app", "~/ is the home directory");
    assert_eq!(target("build1:/srv/app").unwrap().path, "/srv/app");
    assert_eq!(target("scp://build1:2222/srv/app").unwrap().port, Some(2222));
    assert!(target("a/b").is_err(), "no host");
}

#[test]
fn the_plan_names_the_far_directory_the_excludes_and_the_command() {
    let dir = project("app");
    std::fs::write(dir.join(IGNORE_FILE), "# a comment\n*.tmp\n").unwrap();
    let got = plan(&args("build1", &dir, &["make", "-j4", "test"])).unwrap();
    assert_eq!(got.far.path, ".podssh/run/app", "the name of the project, under the home directory");
    assert_eq!(got.command, "cd '.podssh/run/app' && make -j4 test");
    for pattern in ["target/", "node_modules/", ".git/", "*.tmp"] {
        assert!(got.tree.excludes.iter().any(|e| e == pattern), "{pattern}: {:?}", got.tree.excludes);
    }
    assert!(got.tree.onto && got.tree.changed_only);
    // The planted defect of the entry drops the default excludes.
    assert!(got.tree.excluded("target") && got.tree.excluded("web/node_modules"));
    let named = plan(&args("build1:it's here", &dir, &["true"])).unwrap();
    assert_eq!(named.command, r"cd 'it'\''s here' && true");
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn a_run_with_no_command_no_project_or_no_place_is_refused() {
    let dir = project("refused");
    for (target, from, command, says) in [
        ("build1", dir.clone(), &[][..], "give the command"),
        ("build1", dir.join("none"), &["true"][..], "is no directory here"),
        ("build1:~", dir.clone(), &["true"][..], "the home directory or the root"),
        ("build1:/", dir.clone(), &["true"][..], "the home directory or the root"),
        ("a/b", dir.clone(), &["true"][..], "names no host"),
    ] {
        let why = plan(&args(target, &from, command)).expect_err("a refusal");
        assert!(why.contains(says), "{target}: {why}");
    }
    let none = RunArgs::default();
    assert!(plan(&none).unwrap_err().contains("give the host"));
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}
