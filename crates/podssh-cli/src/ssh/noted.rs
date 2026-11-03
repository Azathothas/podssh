//! The notes of what podssh accepts and does not use. At -v: a
//! `ProxyCommand` that podssh does not run, with the place that gave it
//! (T-502); each keyword accepted with no effect, with its place; each name
//! of a list that podssh does not speak; and a restriction of the system's
//! file that podssh does not apply. At the default level, once each: a
//! restriction that the user gave and podssh does not apply (T-505), as a
//! hardened configuration must not lose its restriction with no word.

use super::given::Given;
use super::keywords;
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
    notes.extend(settings.ignored.iter().map(|given| match given.place.shown() {
        "-o" => format!("-o {} has no effect in podssh", given.name),
        at => format!("{at}: {} has no effect in podssh", given.name),
    }));
    notes.extend(settings.algorithms.notes());
    notes.extend(settings.noted.iter().filter(|g| !g.place.users()).map(not_applied));
    notes
}

/// The notes of `settings` at the default level: each restriction that the
/// user gave, on the command line or in a file of the user's, and that
/// podssh does not apply. None for the system's file, which a distribution
/// writes for each program; `-q` shows none, as it shows no warning.
pub(super) fn said(settings: &Settings) -> Vec<String> {
    settings.noted.iter().filter(|g| g.place.users()).map(not_applied).collect()
}

/// "KEYWORD VALUE (PLACE) is not applied: WHY".
fn not_applied(given: &Given) -> String {
    let why = keywords::noted(&given.name).unwrap_or("podssh does not apply it");
    let shown = if given.value.is_empty() { given.name.clone() } else { format!("{} {}", given.name, given.value) };
    format!("{shown} ({}) is not applied: {why}", given.place.shown())
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

    /// An inert keyword names its place at -v; a restriction of the user's
    /// is said at the default level, once, and one of the system's file at
    /// -v alone (T-505).
    #[test]
    fn each_note_names_its_place_and_a_restriction_of_the_users_is_said() {
        let mut s = Settings::default();
        s.apply("HashKnownHosts=yes").unwrap();
        s.apply_at("GSSAPIAuthentication yes", &Place::line("/etc/ssh/ssh_config", 22, true)).unwrap();
        s.apply_at("VerifyHostKeyDNS yes", &Place::line("/home/u/.ssh/config", 4, false)).unwrap();
        s.apply_at("VerifyHostKeyDNS no", &Place::line("/home/u/.ssh/config", 9, false)).unwrap();
        s.apply_at("TCPKeepAlive no", &Place::line("/etc/ssh/ssh_config", 30, true)).unwrap();
        assert_eq!(
            said(&s),
            ["VerifyHostKeyDNS yes (/home/u/.ssh/config:4) is not applied: podssh checks host keys against \
              known_hosts alone"]
        );
        let notes = of(&s);
        assert!(notes.contains(&"-o HashKnownHosts has no effect in podssh".to_string()), "{notes:?}");
        assert!(notes.contains(&"/etc/ssh/ssh_config:22: GSSAPIAuthentication has no effect in podssh".to_string()));
        assert!(notes.iter().any(|n| n.starts_with("TCPKeepAlive no (/etc/ssh/ssh_config:30) is not applied")));
        assert!(!notes.iter().any(|n| n.starts_with("VerifyHostKeyDNS")), "said once, at the default level");
    }
}
