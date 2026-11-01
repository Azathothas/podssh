//! The tests of the manual's facts: each variable, file and exit code that
//! the manual names agrees with the source in both directions.

use super::*;
use std::path::{Path, PathBuf};

fn crate_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(name).join("src")
}

/// The non-test source of the crates in the binary's path, without the
/// manual itself (which names each variable).
fn sources() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut crates = vec!["podssh-cli", "podssh-ssh", "podssh-relay", "podssh-ws"];
    // The iroh road's crate is in the binary with its feature only.
    if cfg!(feature = "iroh") {
        crates.push("podssh-iroh");
    }
    // WARP's road's crate is in the binary with its feature only (T-352).
    if cfg!(feature = "warp") {
        crates.push("podssh-warp");
    }
    // The Tor road's crate is in the binary with its feature only (T-353).
    if cfg!(feature = "tor") {
        crates.push("podssh-tor");
    }
    let mut dirs: Vec<PathBuf> = crates.iter().map(|c| crate_dir(c)).collect();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "man") {
                    continue;
                }
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                out.push((path, non_test(&text)));
            }
        }
    }
    out
}

/// `text` without its test-only items: each `#[cfg(test)]` drops the item
/// that follows it, a line such as `use ...;` or `mod tests;`, or a block
/// such as `mod tests { ... }`, and nothing more. A cut at the first
/// `#[cfg(test)]` hid the rest of a file behind a test-only import at its
/// top, and so a variable that the file reads.
fn non_test(text: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        out.push_str(&rest[..at]);
        let item = &rest[at + MARK.len()..];
        let (semi, brace) = (item.find(';'), item.find('{'));
        let end = match (semi, brace) {
            (Some(s), Some(b)) if s < b => Some(s + 1),
            (Some(s), None) => Some(s + 1),
            (_, Some(b)) => block_end(item, b),
            (None, None) => None,
        };
        // An item with no end hides the rest, as the old cut did.
        let Some(end) = end else { return out };
        rest = &item[end..];
    }
    out.push_str(rest);
    out
}

/// The offset just after the brace that closes the one at `open`.
fn block_end(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The control of [`non_test`]: a read after a test-only import counts, a
/// read inside a test-only block does not.
#[test]
fn a_test_only_item_hides_itself_alone() {
    let text = "use a;\n#[cfg(test)]\nuse b::{c, d};\nconst X: &str = \"READ_AFTER\";\n\
        #[cfg(test)]\nmod tests {\n    fn f() { let _ = \"IN_TESTS\"; }\n}\nconst Y: &str = \"READ_LAST\";\n";
    let kept = non_test(text);
    assert_eq!(variables_read(&kept), vec!["READ_AFTER", "READ_LAST"], "{kept}");
    assert!(kept.contains("use a;") && !kept.contains("use b::"), "{kept}");
}

fn documented() -> Vec<&'static str> {
    variables().flat_map(|(n, _)| n.iter().copied()).collect()
}

/// Each documented variable is read somewhere: a removed variable fails.
#[test]
fn each_documented_variable_is_in_the_source() {
    let src = sources();
    for name in documented() {
        let quoted = format!("\"{name}\"");
        let indirect = name == "TMPDIR"; // std::env::temp_dir reads it too
        assert!(
            indirect || src.iter().any(|(_, code)| code.contains(&quoted)),
            "{name} is documented, but no source reads it"
        );
    }
}

/// Each variable that the source reads by name is documented.
#[test]
fn each_variable_in_the_source_is_documented() {
    let documented = documented();
    let mut missing = Vec::new();
    for (path, code) in sources() {
        for name in variables_read(&code) {
            if !documented.contains(&name.as_str()) {
                missing.push(format!("{name} ({})", path.display()));
            }
        }
    }
    assert!(missing.is_empty(), "read but not in ENVIRONMENT: {missing:?}");
}

/// The names that `code` reads: arguments of `var("..")` and
/// `var_os("..")`, and quoted names shaped like variables.
fn variables_read(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in code.match_indices('"') {
        let rest = &code[i + 1..];
        let Some(end) = rest.find('"') else { continue };
        let word = &rest[..end];
        // A prefix such as PODSSH_ names no variable.
        let shaped = word.contains('_')
            && !word.ends_with('_')
            && word.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && word.starts_with(|c: char| c.is_ascii_uppercase())
            || word.ends_with("_proxy") && word.chars().all(|c| c.is_ascii_lowercase() || c == '_');
        let called = code[..i].ends_with("var(") || code[..i].ends_with("var_os(");
        // A name that the compiler reads (env!, option_env!) is no variable
        // of a run, so ENVIRONMENT does not list it (T-210).
        let compiled = code[..i].ends_with("env!(");
        if (shaped || called) && !compiled && !word.starts_with("CARGO_") && !out.iter().any(|w| w == word) {
            out.push(word.to_string());
        }
    }
    out
}

/// The control for the test above: the reader finds a planted variable.
#[test]
fn the_reader_finds_a_planted_variable() {
    let code = r#"let a = std::env::var("PLANTED_NAME"); let b = var_os("Plain"); let c = "not a var"; "PREFIX_";
        let d = option_env!("BUILT_NAME"); let e = env!("BUILT_TOO"); let f = "LATER_NAME";"#;
    assert_eq!(variables_read(code), vec!["PLANTED_NAME", "Plain", "LATER_NAME"]);
}

/// The cache directories are the ones FILES describes (T-243): the one of
/// PODSSH_CACHE_DIR, the user's cache directory, the user's runtime
/// directory, the temporary directory, and the working directory, last.
#[test]
fn the_cache_directories_are_the_ones_described() {
    let root = std::env::temp_dir();
    let named = |n: &str| root.join(n).into_os_string();
    let user_cache = if cfg!(windows) { "LOCALAPPDATA" } else { "XDG_CACHE_HOME" };
    let var = |name: &str| match name {
        "PODSSH_CACHE_DIR" => Some(named("chosen")),
        "XDG_RUNTIME_DIR" => Some(named("run")),
        "TMPDIR" => Some(named("tmp")),
        other if other == user_cache => Some(named("cache")),
        _ => None,
    };
    let dirs = podssh_relay::cache::candidate_dirs_from(&var, Some(root.join("work")));
    let parents: Vec<String> =
        dirs.iter().map(|d| d.strip_prefix(&root).map(|p| p.display().to_string()).unwrap_or_default()).collect();
    let tagged = parents[3].clone();
    assert!(tagged.starts_with(&format!("tmp{}podssh-", std::path::MAIN_SEPARATOR)), "{parents:?}");
    let sep = std::path::MAIN_SEPARATOR;
    assert_eq!(
        parents,
        [
            "chosen".to_string(),
            format!("cache{sep}podssh"),
            format!("run{sep}podssh"),
            tagged,
            format!("work{sep}.podssh")
        ],
    );
}

#[test]
fn the_exit_codes_are_the_constants() {
    let blocks = exit_status();
    let codes: Vec<String> = blocks
        .iter()
        .filter_map(|b| match b {
            Block::Item { term, .. } => Some(super::super::model::plain(term)),
            _ => None,
        })
        .collect();
    for c in [0, 1, 64, 69, 70, 77, 78, 255] {
        assert!(codes.contains(&c.to_string()), "exit {c} is not documented: {codes:?}");
    }
    assert_eq!(crate::keygen::EXIT_FAILED, crate::doctor::EXIT_FAILED, "one row documents both");
}
