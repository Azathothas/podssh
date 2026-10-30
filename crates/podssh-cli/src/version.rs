//! The commit that a release build names (T-210): the release workflow
//! gives it to the compiler as `PODSSH_BUILD_COMMIT`, so the binary carries
//! it and a tester can tie a download to its source. It is read at compile
//! time only (no build script, no `git` call); a local build names none.

/// The commit of this build, when the build named one.
pub fn commit() -> Option<&'static str> {
    commit_of(option_env!("PODSSH_BUILD_COMMIT"))
}

/// Anything but a hex digest is no commit: a stray value must not reach
/// `--version`, which scripts read.
fn commit_of(given: Option<&'static str>) -> Option<&'static str> {
    given.filter(|c| (7..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `podssh VERSION`, with `(COMMIT)` after it in a release build, as rustc
/// names its own: the line of `podssh --version` and of doctor's header.
/// A script that reads `podssh VERSION` finds it at the start either way.
pub fn line() -> String {
    line_of(commit())
}

fn line_of(commit: Option<&str>) -> String {
    match commit {
        Some(c) => format!("podssh {} ({c})", crate::help::version()),
        None => format!("podssh {}", crate::help::version()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_a_commit_and_nothing_else_is() {
        let full = "224ccd2bf9e5c4d1b8a7f6e5d4c3b2a1f0e9d8c7";
        assert_eq!(commit_of(Some(full)), Some(full));
        assert_eq!(commit_of(Some("224ccd2")), Some("224ccd2"));
        for stray in ["", "224ccd", "main", "224ccd2\n", "224ccd2 (dirty)", "v1.0.0-beta.2"] {
            assert_eq!(commit_of(Some(stray)), None, "{stray:?}");
        }
        assert_eq!(commit_of(None), None);
    }

    #[test]
    fn the_line_names_the_commit_after_the_version() {
        let v = env!("CARGO_PKG_VERSION");
        assert_eq!(line_of(None), format!("podssh {v}"));
        assert_eq!(line_of(Some("224ccd2")), format!("podssh {v} (224ccd2)"));
    }

    /// The build of the tests names no commit unless its environment did,
    /// and then the line carries it.
    #[test]
    fn this_build_names_what_its_environment_gave() {
        match option_env!("PODSSH_BUILD_COMMIT") {
            Some(c) if commit_of(Some(c)).is_some() => assert!(line().ends_with(&format!(" ({c})"))),
            _ => assert_eq!(line(), format!("podssh {}", env!("CARGO_PKG_VERSION"))),
        }
    }
}
