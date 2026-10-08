//! The recorded version of the compiled-in roots is the one that Cargo.lock
//! builds, so the date that `podssh doctor` gives them stays true.

#[test]
fn the_recorded_roots_are_the_ones_built() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).expect("Cargo.lock");
    let mut versions = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"webpki-roots\"" {
            let version = lines.next().unwrap_or_default().trim();
            versions.push(version.trim_start_matches("version = \"").trim_end_matches('"').to_string());
        }
    }
    assert_eq!(
        versions,
        vec![podssh_ws::tls::ROOTS_VERSION.to_string()],
        "Cargo.lock builds other roots: update ROOTS_VERSION, and ROOTS_PUBLISHED to the day crates.io published them"
    );
}
