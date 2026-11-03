//! The command line of `podssh run` (T-192), with no host: the target, the
//! far directory, the excludes and the command, and each refusal (64);
//! `--no-ignore` and `--dry-run`, and the text of a dry run (T-475).

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

#[test]
fn no_ignore_drops_the_defaults_and_the_ignore_file_and_keeps_the_rest() {
    let dir = project("noignore");
    std::fs::write(dir.join(IGNORE_FILE), "*.tmp\n").unwrap();
    let from = dir.parent().unwrap().join("more");
    std::fs::write(&from, "build/\n").unwrap();
    let mut a = args("build1", &dir, &["true"]);
    a.excludes = vec!["*.log".into()];
    a.exclude_from = Some(from.display().to_string());
    let kept = plan(&a).unwrap();
    assert!(kept.tree.excluded("target") && kept.tree.excluded("x.tmp"), "{:?}", kept.tree.excludes);
    a.no_ignore = true;
    let all = plan(&a).unwrap();
    assert_eq!(all.tree.excludes, ["build/", "*.log"], "--exclude-from, then --exclude");
    assert!(!all.tree.excluded("target") && !all.tree.excluded("web/node_modules") && !all.tree.excluded(".git"));
    assert!(!all.tree.excluded("x.tmp"), "the ignore file is not read");
    assert!(all.tree.excluded("a.log") && all.tree.excluded("build"));
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn the_flags_parse_and_a_dry_run_is_the_trees() {
    let crate::tree::Parsed::Run(parsed) =
        crate::tree::parse(["run", "--dry-run", "--no-ignore", "build1", "--", "make", "test"])
    else {
        panic!("run parses");
    };
    assert!(parsed.dry_run && parsed.no_ignore && parsed.refused.is_empty(), "{parsed:?}");
    assert_eq!(parsed.ssh.command, ["make", "test"]);
    let dir = project("dry");
    let mut a = args("build1", &dir, &["true"]);
    assert!(!plan(&a).unwrap().tree.dry_run);
    a.dry_run = true;
    let got = plan(&a).unwrap();
    assert!(got.tree.dry_run && got.tree.onto && got.tree.changed_only);
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn a_dry_run_says_the_parents_the_actions_then_the_command() {
    let dir = project("plan");
    let got = plan(&args("build1", &dir, &["make", "test"])).unwrap();
    let parents = [".podssh".to_string(), ".podssh/run".to_string()];
    let actions = ["mkdir .podssh/run/plan".to_string(), "copy here/a -> .podssh/run/plan/a".to_string()];
    assert_eq!(
        dry::lines(&got, &parents, &actions),
        "mkdir .podssh\nmkdir .podssh/run\nmkdir .podssh/run/plan\ncopy here/a -> .podssh/run/plan/a\n\
         run cd '.podssh/run/plan' && make test\n"
    );
    // A plan with nothing to change still names the command.
    assert_eq!(dry::lines(&got, &[], &[]), "run cd '.podssh/run/plan' && make test\n");
    assert_eq!(dry::left_out(0), None);
    assert_eq!(dry::left_out(1).as_deref(), Some("1 path left out by the excludes; -v names it"));
    assert_eq!(dry::left_out(2).as_deref(), Some("2 paths left out by the excludes; -v names each"));
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}
