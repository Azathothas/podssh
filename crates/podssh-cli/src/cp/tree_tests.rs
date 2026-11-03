//! The tests of a tree's walk and its rules that need no server (T-143,
//! T-476): the names, the patterns and what they leave out (T-475), an
//! exclude file, what `--delete` takes, and the kinds of a special file.

use super::*;

#[test]
fn a_name_is_one_component() {
    for bad in ["", ".", "..", "../x", "a/b", "/abs", "nul\0"] {
        assert!(check_name(bad, false).is_err(), "{bad:?}");
    }
    for good in ["a", ".hidden", "with space", "a..b", "x:y", "back\\slash"] {
        assert_eq!(check_name(good, false), Ok(()), "{good:?}");
    }
    for bad in ["x:y", "back\\slash", "CON", "con.txt", "LPT1", "trailing.", "trailing ", "a|b"] {
        assert!(check_name(bad, true).is_err(), "{bad:?} on Windows");
    }
    assert_eq!(check_name("console", true), Ok(()));
}

#[test]
fn the_patterns_match_a_component_or_a_path_from_the_root() {
    let tree =
        Tree { excludes: vec!["*.log".into(), "build/".into(), "src/gen/*.rs".into(), "?x".into()], ..Tree::default() };
    assert!(tree.excluded("a.log"));
    assert!(tree.excluded("deep/down/b.log"), "a name anywhere");
    assert!(tree.excluded("build") && tree.excluded("x/build"));
    assert!(tree.excluded("src/gen/a.rs"));
    assert!(!tree.excluded("src/gen/sub/a.rs"), "* never matches /");
    assert!(!tree.excluded("other/src/gen/a.rs"), "a path from the root");
    assert!(tree.excluded("ax") && !tree.excluded("abx"));
    assert!(!tree.excluded("a.logs"));
    // The pattern as it was given, which -v names (T-475).
    assert_eq!(tree.excluded_by("x/build"), Some("build/"));
    assert_eq!(tree.excluded_by("deep/b.log"), Some("*.log"));
    assert_eq!(tree.excluded_by("src/gen/a.rs"), Some("src/gen/*.rs"));
    assert_eq!(tree.excluded_by("a.logs"), None);
}

#[test]
fn an_exclude_file_has_a_pattern_a_line() {
    let dir = std::env::temp_dir().join(format!("podssh-tree-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ignore");
    std::fs::write(&path, "# comment\n*.tmp\r\n\n  \nbuild/\n").unwrap();
    assert_eq!(read_excludes(&path).unwrap(), vec!["*.tmp".to_string(), "build/".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn delete_takes_what_the_source_lacks_the_deepest_first() {
    let dir = |r: &str| Item::Dir { rel: r.into(), stamp: Stamp::default() };
    let file = |r: &str| Item::File { rel: r.into() };
    let source = [dir(""), dir("a"), file("a/keep"), file("top")];
    let target = [
        dir(""),
        dir("a"),
        file("a/keep"),
        file("a/extra"),
        dir("old"),
        dir("old/deeper"),
        file("old/deeper/x"),
        Item::Link { rel: "link".into(), target: "/etc/passwd".into() },
        Item::Special { rel: "fifo".into(), kind: Special::Fifo },
        Item::Skip { rel: "unread".into(), why: "not read".into() },
        file("top"),
    ];
    let rels: Vec<String> = to_delete(&source, &target).iter().map(|i| rel_of(i).to_string()).collect();
    assert_eq!(rels, ["old/deeper/x", "old/deeper", "a/extra", "old", "link"]);
}

#[test]
fn a_local_walk_is_depth_first_with_its_directories_first() {
    let dir = std::env::temp_dir().join(format!("podssh-walk-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(dir.join("b/c")).unwrap();
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    std::fs::write(dir.join("a file"), b"1").unwrap();
    std::fs::write(dir.join("b/c/d"), b"2").unwrap();
    std::fs::write(dir.join("b/skip.log"), b"3").unwrap();
    std::fs::create_dir_all(dir.join("target/deep")).unwrap();
    std::fs::write(dir.join("target/deep/big.bin"), b"4").unwrap();
    let tree = Tree { excludes: vec!["*.log".into(), "target/".into()], ..Tree::default() };
    let (items, left) = walk_local(&dir, &tree);
    // Each path left out, once, the top of what it left out (T-475).
    assert_eq!(left, ["b/skip.log", "target"]);
    let rels: Vec<String> = items
        .into_iter()
        .map(|i| match i {
            Item::Dir { rel, .. } => format!("d:{rel}"),
            Item::File { rel } => format!("f:{rel}"),
            Item::Link { rel, .. } => format!("l:{rel}"),
            Item::Special { rel, .. } => format!("p:{rel}"),
            Item::Skip { rel, .. } => format!("s:{rel}"),
        })
        .collect();
    assert_eq!(rels, ["d:", "f:a file", "d:b", "d:b/c", "f:b/c/d", "d:empty"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_kind_of_a_special_file_is_read_from_its_mode() {
    assert_eq!(Special::of_mode(0o010_644), Special::Fifo);
    assert_eq!(Special::of_mode(0o140_755), Special::Socket);
    assert_eq!(Special::of_mode(0o020_620), Special::CharDevice);
    assert_eq!(Special::of_mode(0o060_660), Special::BlockDevice);
    assert_eq!(Special::of_mode(0), Special::Other);
    assert_eq!(Special::Fifo.noun(), "a FIFO");
}
