//! The features that listen, each with the family of its socket, and the
//! words of doctor's bind lines about them (T-357). A bind that works is not
//! a listener that works: a host can allow the bind and refuse the listen, so
//! doctor listens once on each socket that it binds, accepts nothing and
//! closes it at once (T-358, the operator's ruling on Q53). No road needs a
//! listener; these features need one, each when the user asks for it.

use std::io;

/// The family of a listener's socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Inet,
    Unix,
}

/// A feature that listens when the user asks for it.
#[derive(Debug)]
pub struct Listener {
    pub family: Family,
    /// The verb, as `podssh help` names it.
    pub verb: &'static str,
    /// Its flag, or its address form, or nothing for the verb itself.
    pub form: &'static str,
    /// What doctor's line calls it.
    pub label: &'static str,
}

/// Each listener of podssh; a test holds each verb and form to the flag
/// tables and to the addresses of `pipe`.
pub const LISTENERS: &[Listener] = &[
    Listener { family: Family::Inet, verb: "ssh", form: "-L", label: "-L on a port" },
    Listener { family: Family::Inet, verb: "ssh", form: "-D", label: "-D on a port" },
    Listener { family: Family::Inet, verb: "pipe", form: "tcp-listen:", label: "podssh pipe tcp-listen:" },
    Listener { family: Family::Unix, verb: "ssh", form: "-L", label: "-L on a path" },
    Listener { family: Family::Unix, verb: "ssh", form: "-D", label: "-D on a path" },
    Listener { family: Family::Unix, verb: "ssh", form: "-M", label: "the control socket of -M" },
    Listener { family: Family::Unix, verb: "agent", form: "", label: "podssh agent" },
    Listener { family: Family::Unix, verb: "session", form: "", label: "podssh session" },
    Listener { family: Family::Unix, verb: "pipe", form: "unix-listen:", label: "podssh pipe unix-listen:" },
];

/// The listeners of `family`, as a list in words.
pub fn names(family: Family) -> String {
    let labels: Vec<&str> = LISTENERS.iter().filter(|l| l.family == family).map(|l| l.label).collect();
    match labels.split_last() {
        None => String::new(),
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// What came of one socket's probe.
#[derive(Debug)]
pub enum Probe {
    /// The bind was refused.
    BindRefused(io::Error),
    /// Bound, and the listen refused.
    ListenRefused(io::Error),
    /// Bound and listened, nothing accepted, closed.
    Listened,
    /// Bound and closed; `PODSSH_LISTEN` turned listening off, so no
    /// listen was tried.
    NotTried,
}

impl Probe {
    /// Whether the listeners of its family can listen here; `None` when
    /// `PODSSH_LISTEN` turned listening off, so that no listen was tried.
    pub fn listens(&self) -> Option<bool> {
        match self {
            Probe::BindRefused(_) | Probe::ListenRefused(_) => Some(false),
            Probe::Listened => Some(true),
            Probe::NotTried => None,
        }
    }
}

/// The words of one probe of `what`, which may name a place.
pub fn words(what: &str, probe: &Probe) -> String {
    match probe {
        Probe::BindRefused(e) => format!("{what}: the bind was refused: {e}"),
        Probe::ListenRefused(e) => format!("{what}: bound, and the listen was refused: {e}"),
        Probe::Listened => format!("{what}: bound, listened and closed with no connection taken"),
        Probe::NotTried => format!("{what}: bound and closed, with no listen tried"),
    }
}

/// What the probes of one family mean for its listeners: the end of the line.
pub fn verdict(family: Family, can_listen: Option<bool>) -> String {
    let names = names(family);
    match can_listen {
        Some(true) => format!("so {names} can listen here"),
        Some(false) => format!("so {names} cannot listen here; no road needs a listener"),
        None => format!("PODSSH_LISTEN turns listening off, so {names} do not listen; no road needs a listener"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A planted refusal: EACCES, 13 on Linux and on macOS.
    fn planted() -> io::Error {
        io::Error::from_raw_os_error(13)
    }

    #[test]
    fn a_refused_bind_names_each_listener_of_its_family_and_no_other() {
        let line = format!(
            "{}; {}",
            words("127.0.0.1", &Probe::BindRefused(planted())),
            verdict(Family::Inet, Probe::BindRefused(planted()).listens())
        );
        for l in LISTENERS {
            assert_eq!(line.contains(l.label), l.family == Family::Inet, "{line}: {}", l.label);
        }
        assert!(line.contains("cannot listen here") && line.contains("no road needs a listener"), "{line}");
        let unix = verdict(Family::Unix, Some(false));
        for l in LISTENERS.iter().filter(|l| l.family == Family::Unix) {
            assert!(unix.contains(l.label), "{unix}: {}", l.label);
        }
    }

    #[test]
    fn a_bind_that_worked_says_what_its_listen_did() {
        let refused = words("127.0.0.1:41000", &Probe::ListenRefused(planted()));
        assert!(refused.contains("bound, and the listen was refused"), "{refused}");
        assert_eq!(Probe::ListenRefused(planted()).listens(), Some(false));
        let listened = words("127.0.0.1:41000", &Probe::Listened);
        assert!(listened.contains("listened and closed with no connection taken"), "{listened}");
        assert!(verdict(Family::Inet, Probe::Listened.listens()).contains("can listen here"));
        let off = words("127.0.0.1:41000", &Probe::NotTried);
        assert!(off.contains("with no listen tried"), "{off}");
        let off = verdict(Family::Unix, Probe::NotTried.listens());
        assert!(off.contains("PODSSH_LISTEN turns listening off") && off.contains("podssh agent"), "{off}");
    }

    #[test]
    fn the_names_are_a_list_in_words() {
        assert_eq!(names(Family::Inet), "-L on a port, -D on a port and podssh pipe tcp-listen:");
    }
}
