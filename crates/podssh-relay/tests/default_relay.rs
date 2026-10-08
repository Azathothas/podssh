//! The default relay's name is a string literal in exactly one place in
//! library code, `podssh-relay/src/relay.rs`, so changing relays is a one-line
//! edit. (Moved here from podssh-transport's tests when its unused DNS code,
//! which those tests also covered, was removed on 2026-10-08.)

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
