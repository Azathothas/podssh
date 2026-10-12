//! The copy of a directory (T-143): `-r` walks the source depth first, with
//! `lstat`, [`MOST_DEPTH`] levels at most, and copies each file as one copy
//! goes (a temporary name, the digest, the rename), each symbolic link as a
//! link (`cp`) or what it names (`scp -r`, which follows links, as OpenSSH's
//! does, with a check for a loop), and skips a device, a FIFO or a socket with
//! a note. Each name that a listing gives must be one component: `.`, `..`,
//! a `/` or a NUL, and here on Windows a `\`, a `:`, a device's name or a
//! trailing dot or space, are refused, so that nothing is written outside the
//! target. `--exclude` and `--exclude-from` leave paths out; `--dry-run`
//! says each action and changes nothing.

use std::collections::HashSet;
use std::path::Path;

use podssh_ssh::sftp::Sftp;

/// The levels of a walk at most.
pub const MOST_DEPTH: usize = 64;

/// What `-r` does: the patterns that leave paths out, whether it only says
/// what it would do, and whether it follows links.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    pub excludes: Vec<String>,
    pub dry_run: bool,
    pub follow: bool,
    /// `--delete` (T-144): what the target has and the source lacks goes,
    /// once each copy of the run succeeded.
    pub delete: bool,
}

/// One thing of a tree, by its path under the root of the copy: components
/// joined by `/`, the root itself `""`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Dir {
        rel: String,
        mode: Option<u32>,
    },
    File {
        rel: String,
    },
    Link {
        rel: String,
        target: String,
    },
    /// Not copied, and why: a special file, a refused name, a loop, or a
    /// listing that failed. Each makes the exit code not zero.
    Skip {
        rel: String,
        why: String,
    },
}

/// The names that Windows keeps for devices, with or without an extension.
const DEVICES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Whether `name`, from a listing, is one component that may be written
/// here; `windows` adds the rules of a Windows file system.
pub fn check_name(name: &str, windows: bool) -> Result<(), String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(format!("{name:?} is not one component of a path"));
    }
    if windows {
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if name.contains(['\\', ':', '<', '>', '"', '|', '?', '*']) || name.chars().any(|c| (c as u32) < 32) {
            return Err(format!("{name:?} holds a character that a Windows file name cannot"));
        }
        if DEVICES.contains(&stem.as_str()) {
            return Err(format!("{name:?} is the name of a Windows device"));
        }
        if name.ends_with(['.', ' ']) {
            return Err(format!("{name:?} ends with a dot or a space, which Windows drops"));
        }
    }
    Ok(())
}

/// `pattern` against `text`: `*` is any run of characters and `?` any one,
/// neither a `/`.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob(&pattern[1..], text) || (text.first().is_some_and(|c| *c != b'/') && glob(pattern, &text[1..]))
        }
        (Some(b'?'), Some(c)) if *c != b'/' => glob(&pattern[1..], &text[1..]),
        (Some(p), Some(c)) if p == c => glob(&pattern[1..], &text[1..]),
        _ => false,
    }
}

impl Tree {
    /// Whether `rel` is left out: a pattern with no `/` against its last
    /// component, one with a `/` against the whole path from the root.
    pub fn excluded(&self, rel: &str) -> bool {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        self.excludes.iter().any(|pattern| {
            let pattern = pattern.trim_start_matches("./").trim_end_matches('/');
            if pattern.contains('/') {
                glob(pattern.trim_start_matches('/').as_bytes(), rel.as_bytes())
            } else {
                glob(pattern.as_bytes(), name.as_bytes())
            }
        })
    }
}

/// The patterns of an exclude file: one a line; an empty line, and a line
/// that starts with `#`, are none.
pub fn read_excludes(path: &Path) -> std::io::Result<Vec<String>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// The path under the root of an item.
pub fn rel_of(item: &Item) -> &str {
    match item {
        Item::Dir { rel, .. } | Item::File { rel } | Item::Link { rel, .. } | Item::Skip { rel, .. } => rel,
    }
}

/// What `--delete` removes: each item of the target that the source does
/// not have, a directory after what it holds; never the root, never a
/// skipped item.
pub fn to_delete(source: &[Item], target: &[Item]) -> Vec<Item> {
    let kept: HashSet<&str> = source.iter().map(rel_of).collect();
    let mut gone: Vec<Item> = target
        .iter()
        .filter(|i| !matches!(i, Item::Skip { .. }) && !rel_of(i).is_empty() && !kept.contains(rel_of(i)))
        .cloned()
        .collect();
    // The deepest first: a directory's contents before it.
    gone.sort_by(|a, b| {
        rel_of(b).matches('/').count().cmp(&rel_of(a).matches('/').count()).then(rel_of(b).cmp(rel_of(a)))
    });
    gone
}

fn join(rel: &str, name: &str) -> String {
    if rel.is_empty() {
        name.to_string()
    } else {
        format!("{rel}/{name}")
    }
}

/// The local tree under `root`, depth first, a directory before what it
/// holds; each item is left out that a pattern names.
pub fn walk_local(root: &Path, tree: &Tree) -> Vec<Item> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    walk_local_in(root, "", tree, 0, &mut seen, &mut items);
    items
}

fn walk_local_in(
    dir: &Path,
    rel: &str,
    tree: &Tree,
    depth: usize,
    seen: &mut HashSet<std::path::PathBuf>,
    items: &mut Vec<Item>,
) {
    if depth > MOST_DEPTH {
        items.push(Item::Skip { rel: rel.into(), why: format!("deeper than {MOST_DEPTH} levels") });
        return;
    }
    // A directory met twice is a loop (a link that a walk follows).
    if let Ok(real) = std::fs::canonicalize(dir) {
        if !seen.insert(real) {
            items.push(Item::Skip { rel: rel.into(), why: "a loop: this directory is met again".into() });
            return;
        }
    }
    items.push(Item::Dir {
        rel: rel.into(),
        mode: std::fs::metadata(dir).ok().map(|m| super::transfer::local_mode(&m)),
    });
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(read) => read.filter_map(Result::ok).collect(),
        Err(e) => {
            items.push(Item::Skip { rel: rel.into(), why: format!("not listed: {e}") });
            return;
        }
    };
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            let shown = entry.file_name().to_string_lossy().into_owned();
            items.push(Item::Skip {
                rel: join(rel, &shown),
                why: "the name is not UTF-8, and SFTP names are text here".into(),
            });
            continue;
        };
        let path = entry.path();
        let child = join(rel, &name);
        if tree.excluded(&child) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        let kind = meta.file_type();
        if kind.is_symlink() && !tree.follow {
            match std::fs::read_link(&path) {
                Ok(target) => items.push(Item::Link { rel: child, target: target.to_string_lossy().into_owned() }),
                Err(e) => items.push(Item::Skip { rel: child, why: format!("the link is not read: {e}") }),
            }
            continue;
        }
        // A link that a walk follows is what it names.
        let meta = if kind.is_symlink() { std::fs::metadata(&path) } else { Ok(meta) };
        match meta {
            Ok(m) if m.is_dir() => walk_local_in(&path, &child, tree, depth + 1, seen, items),
            Ok(m) if m.is_file() => items.push(Item::File { rel: child }),
            Ok(_) => items.push(Item::Skip { rel: child, why: "a device, a FIFO or a socket".into() }),
            Err(e) => items.push(Item::Skip { rel: child, why: format!("the link names nothing here: {e}") }),
        }
    }
}

/// The far tree under `root` on the server, depth first, a directory before
/// what it holds; each name of a listing is checked (`windows`: also for a
/// Windows file system here).
pub async fn walk_far(sftp: &Sftp, root: &str, tree: &Tree, windows: bool) -> Vec<Item> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    // Depth first, without recursion in an async fn: each directory waits on
    // a stack, its listing in the order of its names.
    let mut stack: Vec<(String, String, usize)> = vec![(root.to_string(), String::new(), 0)];
    while let Some((dir, rel, depth)) = stack.pop() {
        if depth > MOST_DEPTH {
            items.push(Item::Skip { rel, why: format!("deeper than {MOST_DEPTH} levels") });
            continue;
        }
        if let Ok(real) = sftp.realpath(&dir).await {
            if !seen.insert(real) {
                items.push(Item::Skip { rel, why: "a loop: this directory is met again".into() });
                continue;
            }
        }
        let mode = sftp.stat(&dir).await.ok().and_then(|a| a.permissions).map(|p| p & 0o7777);
        items.push(Item::Dir { rel: rel.clone(), mode });
        let mut entries = match sftp.read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) => {
                items.push(Item::Skip { rel, why: format!("not listed: {e}") });
                continue;
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut below = Vec::new();
        for entry in entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let child = join(&rel, &entry.name);
            if let Err(why) = check_name(&entry.name, windows) {
                items.push(Item::Skip { rel: child, why: format!("refused: {why}") });
                continue;
            }
            if tree.excluded(&child) {
                continue;
            }
            let path = format!("{}/{}", dir.trim_end_matches('/'), entry.name);
            let attrs = match sftp.lstat(&path).await {
                Ok(attrs) => attrs,
                Err(e) => {
                    items.push(Item::Skip { rel: child, why: format!("not read: {e}") });
                    continue;
                }
            };
            if attrs.is_symlink() && !tree.follow {
                match sftp.readlink(&path).await {
                    Ok(target) => items.push(Item::Link { rel: child, target }),
                    Err(e) => items.push(Item::Skip { rel: child, why: format!("the link is not read: {e}") }),
                }
                continue;
            }
            let attrs = if attrs.is_symlink() { sftp.stat(&path).await } else { Ok(attrs) };
            match attrs {
                Ok(a) if a.is_dir() => below.push((path, child, depth + 1)),
                Ok(a) if a.is_regular() => items.push(Item::File { rel: child }),
                Ok(_) => items.push(Item::Skip { rel: child, why: "a device, a FIFO or a socket".into() }),
                Err(e) => items.push(Item::Skip { rel: child, why: format!("the link names nothing there: {e}") }),
            }
        }
        // The first name first: the stack takes them in reverse.
        stack.extend(below.into_iter().rev());
    }
    items
}

#[cfg(test)]
mod tests {
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
        let tree = Tree {
            excludes: vec!["*.log".into(), "build/".into(), "src/gen/*.rs".into(), "?x".into()],
            ..Tree::default()
        };
        assert!(tree.excluded("a.log"));
        assert!(tree.excluded("deep/down/b.log"), "a name anywhere");
        assert!(tree.excluded("build") && tree.excluded("x/build"));
        assert!(tree.excluded("src/gen/a.rs"));
        assert!(!tree.excluded("src/gen/sub/a.rs"), "* never matches /");
        assert!(!tree.excluded("other/src/gen/a.rs"), "a path from the root");
        assert!(tree.excluded("ax") && !tree.excluded("abx"));
        assert!(!tree.excluded("a.logs"));
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
        let dir = |r: &str| Item::Dir { rel: r.into(), mode: None };
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
            Item::Skip { rel: "fifo".into(), why: "a FIFO".into() },
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
        let tree = Tree { excludes: vec!["*.log".into()], ..Tree::default() };
        let rels: Vec<String> = walk_local(&dir, &tree)
            .into_iter()
            .map(|i| match i {
                Item::Dir { rel, .. } => format!("d:{rel}"),
                Item::File { rel } => format!("f:{rel}"),
                Item::Link { rel, .. } => format!("l:{rel}"),
                Item::Skip { rel, .. } => format!("s:{rel}"),
            })
            .collect();
        assert_eq!(rels, ["d:", "f:a file", "d:b", "d:b/c", "f:b/c/d", "d:empty"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
