//! A session that ends with its link (T-612): `--no-resume` of a client.
//!
//! The client names [`ONCE`] in its `OPEN`, and a far end that knows the ask
//! names it in its `GREETING`, as one more feature name. With both names the
//! far end forgets the session and shuts its target as its link ends,
//! whatever the end, so that its budget holds nothing of it after
//! ([`super::keep`]). A far end that does not know the name ignores it, as
//! each name that it does not know, and keeps the session for its deadline
//! as before; the client learns that from the names that both gave. The
//! client carries such a session on its first link alone, with no resume,
//! no move and no spare link ([`super::resume::run`]), as it would carry one
//! whose far end has no layer: a resume would find nothing at the far end.

use super::Settings;

/// The feature name of the ask, and of a far end that knows it.
pub const ONCE: &str = "once.v1";

/// The names of a client's `OPEN`: its features, and the ask when its user
/// turned the resumes off.
pub fn asked(settings: &Settings) -> Vec<String> {
    let mut names: Vec<String> = settings.features.iter().map(|name| name.to_string()).collect();
    if !settings.resumes && !names.iter().any(|name| name == ONCE) {
        names.push(ONCE.to_string());
    }
    names
}

/// Whether both sides named the ask, by the names that both gave: the far
/// end ends the session with its link.
pub fn agreed(features: &[String]) -> bool {
    features.iter().any(|name| name == ONCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ask_goes_out_only_when_the_resumes_are_off() {
        let resumes = Settings::default();
        assert!(!asked(&resumes).iter().any(|name| name == ONCE), "{:?}", asked(&resumes));
        let once = Settings { resumes: false, ..Settings::default() };
        let names = asked(&once);
        assert_eq!(names.last().map(String::as_str), Some(ONCE), "after the features: {names:?}");
        assert_eq!(names.len(), super::super::FEATURES.len() + 1);
        assert!(agreed(&names));
        assert!(!agreed(&["replay.v1".to_string(), "deadline.600".to_string()]), "a far end that knows no ask");
    }
}
