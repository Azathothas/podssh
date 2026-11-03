//! The notes of what podssh accepts and does not use, for the log once it
//! exists, shown with -v: a `ProxyCommand` that podssh does not run, with
//! the place that gave it (T-502), and each keyword accepted with no effect.

use super::options::Settings;

/// The notes of `settings`, shown with -v.
pub(super) fn of(settings: &Settings) -> Vec<String> {
    let mut notes = Vec::new();
    // `none` runs nothing; podssh's own proxy names the road that podssh
    // ssh takes anyway.
    if let Some(given) = settings.proxy_command.as_ref().filter(|g| !g.value.eq_ignore_ascii_case("none")) {
        notes.push(format!(
            "ProxyCommand {} ({}) is not run: podssh ssh carries the session itself",
            given.value,
            given.place.shown()
        ));
    }
    notes.extend(settings.ignored.iter().map(|k| format!("-o {k} has no effect in podssh")));
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::given::Place;

    #[test]
    fn a_proxy_command_that_is_not_run_is_noted_with_its_place() {
        let mut s = Settings::default();
        s.apply_at("ProxyCommand=podssh proxy %h %p", &Place::line("/f", 3, false)).unwrap();
        assert_eq!(
            of(&s),
            ["ProxyCommand podssh proxy %h %p (/f:3) is not run: podssh ssh carries the session itself"]
        );
        let mut s = Settings::default();
        s.apply("ProxyCommand=none").unwrap();
        assert!(of(&s).is_empty(), "none runs nothing, and needs no note");
    }
}
