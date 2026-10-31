//! The default relay's name is a string literal in exactly one place in
//! library code, `podssh-relay/src/relay.rs`, so changing relays is a one-line
//! edit.

/// The default relay is compiled in (operator decision 2026-10-08) and its
/// name appears as a string literal in exactly one place in library code,
/// `podssh-relay/src/relay.rs`, so that changing it is a one-line edit. Tests,
/// examples and documentation may name it freely.
///
/// (This replaced a sweep asserting there was no default relay at all; that
/// sweep skipped any line containing `=`, so it never caught a constant.)
#[test]
fn the_default_relay_is_named_in_exactly_one_place() {
    let hits = default_relay_literals_in_library_code();
    assert_eq!(hits.len(), 1, "expected one definition, in podssh-relay/src/relay.rs; found {hits:?}");
    assert!(hits[0].starts_with("crates/podssh-relay/src/relay.rs:"), "{hits:?}");
}

/// Every non-comment line outside test modules, in `crates/*/src/**/*.rs`,
/// that contains the default relay's name as a string literal.
fn default_relay_literals_in_library_code() -> Vec<String> {
    const NEEDLE: &str = "\"tcp.ssh.relay.ajam.dev\"";
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let mut hits = Vec::new();
    let mut files = 0usize;
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !matches!(name.as_str(), "target" | "tests" | "examples" | "benches") {
                    stack.push(path);
                }
                continue;
            }
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if !rel.ends_with(".rs") || !rel.contains("/src/") {
                continue;
            }
            files += 1;
            if is_test_file(&path) {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("UTF-8 source");
            for (n, line) in text.lines().enumerate() {
                // Unit tests sit in a `#[cfg(test)]` module at the end of a file.
                if line.trim_start().starts_with("#[cfg(test)]") {
                    break;
                }
                if !line.trim_start().starts_with("//") && line.contains(NEEDLE) {
                    hits.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    assert!(files > 20, "the sweep read only {files} source files, so it measured nothing");
    hits
}

/// Whether the module of `path` is test code of a file of its own: its
/// parent declares it as `mod NAME;` under `#[cfg(test)]`. The parent of
/// `a/b.rs` is `a.rs`, or `a/mod.rs`, `a/lib.rs`, `a/main.rs`; of `a/mod.rs`,
/// the same three one level up.
fn is_test_file(path: &std::path::Path) -> bool {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
    let Some(dir) = path.parent() else { return false };
    let (name, home) = if stem == "mod" {
        let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_string();
        (name, dir.parent().map(|p| p.to_path_buf()))
    } else {
        (stem, Some(dir.to_path_buf()))
    };
    let Some(home) = home else { return false };
    let mut parents = vec![home.join("mod.rs"), home.join("lib.rs"), home.join("main.rs")];
    if let (Some(up), Some(base)) = (home.parent(), home.file_name()) {
        parents.push(up.join(format!("{}.rs", base.to_string_lossy())));
    }
    let declared = format!("mod {name};");
    parents.iter().filter_map(|p| std::fs::read_to_string(p).ok()).any(|text| {
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        lines.windows(2).any(|w| w[0] == "#[cfg(test)]" && w[1].trim_start_matches("pub ") == declared)
    })
}
