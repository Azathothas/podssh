//! `TERM` selection: which name goes on the `pty-req`.
//!
//! **A pty with no `TERM` is not a terminal to a terminfo program.** This is
//! the whole reason this module exists, and it is a defect three sibling
//! projects recorded independently. **READ**, `sandhome` `shell/faketty:82-93`,
//! verbatim:
//!
//! > # # STOP: A PTY WITH NO TERM IS NOT A TERMINAL TO A TERMININFO PROGRAM.
//! > isatty answers yes and the window size answers 80x24, but a caller whose
//! > TERM is unset or `dumb` still gets `'unknown': I need something more
//! > specific.` from less, because a name a terminal database cannot resolve
//! > is the same problem as no terminal at all (issue #145).
//!
//! ## The predicate, and it is exactly three values
//!
//! **`''|dumb|unknown` and nothing else.** **READ**, `shell/faketty:89-93`:
//!
//! ```sh
//! case "${TERM:-}" in
//!     ''|dumb|unknown)
//!         TERM=${SANDHOME_FAKEPTY_TERM:-xterm-256color}
//!         ;;
//! esac
//! ```
//!
//! **The negative half is the load-bearing half.** A caller who named
//! `xterm-256color`, `screen` or `tmux` keeps it, and substituting over that
//! would override a user who has a real terminal on the other end. A test that
//! only proves the substitution will substitute over a good value forever, so
//! the negative case is a required test and not an afterthought.
//!
//! ## What is different from the sibling
//!
//! The override's name. `SANDHOME_FAKEPTY_TERM` is the sibling's; podssh's is
//! **`PODSSH_TERM`** — this entry's own text, and a name podssh owns. **The
//! default substitution value is the sibling's `xterm-256color`, kept**:
//! inventing a different one would be a decision about terminfo contents that
//! nobody has measured, and the sibling chose it on a machine where the choice
//! worked.

/// The environment variable `TERM` itself. Named so the predicate and its tests
/// cannot drift onto a literal.
pub const TERM_ENV: &str = "TERM";
/// The override. **Only consulted when the current value is unusable.** An
/// override that reached over a good `TERM` would be the defect this module
/// exists to prevent, run in the other direction.
pub const TERM_OVERRIDE_ENV: &str = "PODSSH_TERM";
/// What an unset, `dumb` or `unknown` `TERM` becomes.
/// **READ**, `shell/faketty:91` — `${SANDHOME_FAKEPTY_TERM:-xterm-256color}`.
pub const TERM_FALLBACK: &str = "xterm-256color";
/// The three values the predicate refuses. **READ**, `shell/faketty:90`, which
/// names them and no others.
pub const TERM_PREDICATE_USABLE: [&str; 3] = ["", "dumb", "unknown"];

/// What `select_term` decided, and why. **The reason is carried, not just the
/// value**: a session that reports `term=xterm-256color reason=Substituted`
/// tells its user why their `TERM` was not honoured, and one that reports only
/// the value looks like it ignored them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermChoice {
    /// The existing value was usable and was kept untouched.
    Kept,
    /// The existing value was one of the three unusable ones, and the override
    /// named the replacement.
    Substituted,
    /// The existing value was unusable and nothing named a replacement, so
    /// [`TERM_FALLBACK`] was used.
    SubstitutedWithFallback,
}

impl TermChoice {
    /// Whether the existing value was replaced. **The negative half of the
    /// predicate as a question**, so a caller does not have to compare the
    /// string it passed in against the string it got back to learn whether it
    /// was overridden.
    pub fn replaced(self) -> bool {
        matches!(self, TermChoice::Substituted | TermChoice::SubstitutedWithFallback)
    }
}

/// Whether a `TERM` value is one of the three the predicate refuses.
///
/// **Exactly three values, and the set is the specification.** A predicate
/// that also refused, say, `vt100` would override a caller who deliberately
/// asked for a VT100, and nothing here has measured that such a caller does not
/// exist. **READ**, `shell/faketty:89-93`.
pub fn is_unusable(value: &str) -> bool {
    TERM_PREDICATE_USABLE.contains(&value)
}

/// Decide the `TERM` to send, from what the environment holds.
///
/// **The parameters are the environment**, passed in rather than read. The
/// predicate is then a pure function of two strings, so its negative half is
/// testable without touching the process environment a test suite shares — and
/// a test that mutates `TERM` to test something else can no longer race it.
pub fn select_term(current: Option<&str>, override_value: Option<&str>) -> (String, TermChoice) {
    let current = current.unwrap_or("");
    if !is_unusable(current) {
        // The half that is easy to get wrong. A usable value returns as it
        // arrived, and the override is not even looked at.
        return (current.to_string(), TermChoice::Kept);
    }
    match override_value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(chosen) => (chosen.to_string(), TermChoice::Substituted),
        None => (TERM_FALLBACK.to_string(), TermChoice::SubstitutedWithFallback),
    }
}

/// [`select_term`], reading the two variables out of the process environment.
///
/// **Only for the caller that owns the process.** The tests use
/// [`select_term`] directly, because a test that sets `TERM` changes it for
/// every other test in the same binary, and cargo runs them in threads.
pub fn select_term_from_env() -> (String, TermChoice) {
    let current = std::env::var(TERM_ENV).ok();
    let over = std::env::var(TERM_OVERRIDE_ENV).ok();
    select_term(current.as_deref(), over.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────── the plant: TERM unset must not reach a pager as 'unknown'

    #[test]
    fn term_unset_is_substituted() {
        // **The `Prove` plant, positive half.** With no `TERM` the sibling's
        // defect is `'unknown': I need something more specific.` from `less`.
        // This is the *unit* form of that plant: it proves the predicate,
        // and the real `less` run is named on the entry as not executable from
        // this machine.
        let (term, choice) = select_term(None, None);
        assert_eq!(term, "xterm-256color", "an unset TERM must become a resolvable name");
        assert_eq!(choice, TermChoice::SubstitutedWithFallback);
        assert!(choice.replaced());
    }

    #[test]
    fn an_empty_string_is_the_same_as_unset() {
        // `TERM=""` is what a program that clears it leaves behind, and the
        // shell predicate's `''` arm exists for it. A Rust `Option` that mapped
        // `Some("")` to "present" would miss it.
        let (term, choice) = select_term(Some(""), None);
        assert_eq!(term, "xterm-256color");
        assert_eq!(choice, TermChoice::SubstitutedWithFallback);
    }

    #[test]
    fn dumb_and_unknown_are_substituted() {
        // **The predicate is three values, so all three are named.** Testing
        // only the empty one proves a predicate that refuses blanks, which is
        // a different predicate.
        for unusable in ["dumb", "unknown"] {
            let (term, choice) = select_term(Some(unusable), None);
            assert_eq!(term, "xterm-256color", "{unusable} is unusable");
            assert_eq!(choice, TermChoice::SubstitutedWithFallback, "{unusable}");
        }
    }

    // ─────────── the negative half: a good value must survive untouched

    #[test]
    fn term_xterm_256color_is_left_alone() {
        // **The `Prove` plant, negative half, and the most important line in
        // this file.** A test that only proves the substitution passes and
        // keeps substituting over a good value forever.
        let (term, choice) = select_term(Some("xterm-256color"), None);
        assert_eq!(term, "xterm-256color");
        assert_eq!(choice, TermChoice::Kept);
        assert!(!choice.replaced(), "a usable TERM must not be reported as replaced");
    }

    #[test]
    fn a_real_terminal_name_is_never_overridden_even_by_the_override() {
        // **The override does not outrank a good value.** This is the case a
        // naive "check the override first" implementation gets wrong, and it is
        // why the order in `select_term` is what it is.
        for good in ["xterm", "screen", "screen-256color", "tmux-256color", "vt100", "linux"] {
            let (term, choice) = select_term(Some(good), Some("somethingelse"));
            assert_eq!(term, good, "{good} must survive PODSSH_TERM");
            assert_eq!(choice, TermChoice::Kept, "{good}");
        }
    }

    #[test]
    fn a_near_miss_is_not_in_the_predicate() {
        // `Dumb` and `unknown-256color` are *different strings* from `dumb`
        // and `unknown`. The predicate is exact — a case-insensitive or
        // prefix match would override a caller who deliberately named one of
        // them, and nothing here has measured that no such caller exists.
        for near in ["Dumb", "UNKNOWN", "unknown-256color", "dumber", "xterm-dumb"] {
            let (term, choice) = select_term(Some(near), None);
            assert_eq!(term, near, "{near} is not one of the three");
            assert_eq!(choice, TermChoice::Kept, "{near}");
        }
    }

    // ─────────── the override, on the half where it is allowed to act

    #[test]
    fn the_override_names_the_replacement_when_the_value_is_unusable() {
        let (term, choice) = select_term(Some("dumb"), Some("screen"));
        assert_eq!(term, "screen");
        assert_eq!(choice, TermChoice::Substituted);
        assert!(choice.replaced());
    }

    #[test]
    fn an_empty_or_blank_override_falls_back_rather_than_sending_an_empty_term() {
        // **Substituting in an empty name would reproduce the defect the
        // module exists to fix.** `TERM=""` and `TERM=dumb` are the same
        // failure, so an override that yields one must not be honoured.
        for blank in ["", "   ", "\t"] {
            let (term, choice) = select_term(Some("dumb"), Some(blank));
            assert_eq!(term, TERM_FALLBACK, "blank override {blank:?}");
            assert_eq!(choice, TermChoice::SubstitutedWithFallback, "{blank:?}");
        }
    }

    #[test]
    fn the_override_is_not_trimmed_into_something_else() {
        // It is trimmed at the edges, because a shell script that exported
        // `TERM="screen "` has named `screen`. It is not trimmed of internal
        // space, because that would be a different name from the one given.
        let (term, _) = select_term(None, Some("  screen  "));
        assert_eq!(term, "screen");
    }

    // ─────────── the constants themselves, so the predicate cannot drift

    #[test]
    fn the_predicate_is_exactly_three_values() {
        // **This assertion is the specification.** If someone adds a fourth
        // value to make some new caller happy, this fails and the decision is
        // made in the open rather than by widening an array.
        assert_eq!(TERM_PREDICATE_USABLE, ["", "dumb", "unknown"]);
        for value in TERM_PREDICATE_USABLE {
            assert!(is_unusable(value), "{value:?} must be refused");
        }
    }

    #[test]
    fn the_fallback_is_resolvable_and_the_override_has_podssh_s_name() {
        // The sibling's fallback value, kept deliberately: see the module
        // docs. And the override is podssh's own name, not `SANDHOME_`'s.
        assert_eq!(TERM_FALLBACK, "xterm-256color");
        assert_eq!(TERM_OVERRIDE_ENV, "PODSSH_TERM");
        assert_eq!(TERM_ENV, "TERM");
        assert!(
            !TERM_OVERRIDE_ENV.starts_with("SANDHOME"),
            "a sibling's variable name in podssh is a copy, not an adoption"
        );
    }
}
