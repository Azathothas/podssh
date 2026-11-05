//! The switch of ECH, the names that it seals, and the outcomes kept for
//! `podssh doctor`. No test here sets the process's mode, which each other
//! test of the crate would then see.

use super::*;

#[test]
fn the_variable_takes_yes_no_and_strict_and_refuses_another_word() {
    for (word, mode) in
        [("yes", Mode::On), ("ON", Mode::On), ("1", Mode::On), ("no", Mode::Off), ("strict", Mode::Strict)]
    {
        assert_eq!(Mode::parse(Some(word)), Ok(Some(mode)), "{word}");
    }
    assert_eq!(Mode::parse(None), Ok(None));
    assert_eq!(Mode::parse(Some(" ")), Ok(None), "an empty value is no value");
    assert_eq!(Mode::parse(Some("maybe")), Err("give yes, no or strict".to_string()));
    assert_eq!([Mode::Off, Mode::On, Mode::Strict].map(Mode::word), ["no", "yes", "strict"]);
    assert_eq!(Mode::default(), Mode::Off, "off unless the user asks");
}

/// The mode that a command set wins; else the variable's; a word of the
/// variable that is none of its own is off.
#[test]
fn a_mode_set_wins_over_the_variable_and_a_bad_word_is_off() {
    assert_eq!(chosen(Some(Mode::Off), Ok(Some(Mode::On))), Mode::Off);
    assert_eq!(chosen(None, Ok(Some(Mode::Strict))), Mode::Strict);
    assert_eq!(chosen(None, Ok(None)), Mode::Off);
    assert_eq!(chosen(None, Err("PODSSH_ECH: give yes, no or strict".into())), Mode::Off);
}

/// A name of two labels at least, under podssh's own trust, is sealed when
/// asked for; an address, a name of one label and a caller's configuration
/// never are.
#[test]
fn only_a_name_under_podssh_s_own_trust_is_sealed() {
    let own = Trust::Default;
    assert!(asks(Mode::On, "relay.example.org", &own));
    assert!(asks(Mode::Strict, "relay.example.org.", &own));
    assert!(!asks(Mode::Off, "relay.example.org", &own));
    for address in ["127.0.0.1", "::1", "[2001:db8::1]", "localhost"] {
        assert!(!asks(Mode::On, address, &own), "{address}");
    }
    let config = crate::tls::client_config(&crate::tls::roots_from_compiled_set()).expect("a configuration");
    let caller = Trust::caller(config).expect("no ALPN");
    assert!(!asks(Mode::On, "relay.example.org", &caller), "a caller's configuration cannot be sealed");
}

/// Each outcome says whether the name went sealed, and its words say why
/// not.
#[test]
fn each_outcome_says_whether_the_name_went_sealed() {
    assert!(Outcome::Sealed { retried: false }.sealed() && Outcome::Sealed { retried: true }.sealed());
    for outcome in [
        Outcome::NotPublished,
        Outcome::ReadFailed("no resolver answered".into()),
        Outcome::Refused("a reset".into()),
        Outcome::Cooled,
        Outcome::Strict("relay.example: a reset".into()),
    ] {
        assert!(!outcome.sealed(), "{outcome:?}");
        assert!(!outcome.words().is_empty());
    }
    assert!(Outcome::Strict("x".into()).words().contains("PODSSH_ECH=strict"));
}

/// The last outcome of each name is kept, by its name in any case, and the
/// names kept are bounded.
#[test]
fn the_last_outcome_of_each_name_is_kept_within_a_bound() {
    note("Outcome-Kept.example.", Outcome::NotPublished);
    note("outcome-kept.example", Outcome::Sealed { retried: false });
    assert_eq!(outcome("OUTCOME-KEPT.example"), Some(Outcome::Sealed { retried: false }));
    for at in 0..OUTCOMES {
        note(&format!("outcome-{at}.example"), Outcome::Cooled);
    }
    assert_eq!(outcome("outcome-kept.example"), None, "the oldest went");
    assert!(kept().len() <= OUTCOMES);
}
