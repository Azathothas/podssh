//! The tests of `-o`: its three spellings, the first value, the refusals
//! that name the real keyword, and the keywords that are accepted with no
//! effect.

use super::*;

#[test]
fn three_spellings_and_first_value_wins() {
    let mut s = Settings::default();
    s.apply("StrictHostKeyChecking=accept-new").unwrap();
    s.apply("StrictHostKeyChecking yes").unwrap();
    assert_eq!(s.strict, Some(StrictHostKeyChecking::AcceptNew));
    s.apply("Port = 2222").unwrap();
    assert_eq!(s.port, Some(2222));
    s.apply("identityfile=a").unwrap();
    s.apply("IdentityFile b").unwrap();
    assert_eq!(s.identity_files, vec!["a", "b"]);
}

#[test]
fn a_typo_is_an_error_that_names_the_real_option() {
    let err = Settings::default().apply("StrictHostKeyChekcing=no").unwrap_err();
    assert!(err.contains("unknown option"), "{err}");
    assert!(err.contains("StrictHostKeyChecking"), "{err}");
    assert!(Settings::default().apply("NoSuchThing=1").unwrap_err().contains("unknown option"));
}

#[test]
fn bad_values_and_refused_keywords_are_errors() {
    assert!(Settings::default().apply("StrictHostKeyChecking=maybe").is_err());
    assert!(Settings::default().apply("ConnectTimeout=30x").is_err());
    assert!(Settings::default().apply("LocalForward=8080").unwrap_err().contains("LocalForward"));
    Settings::default().apply("LocalForward=8080 db:5432").unwrap();
    assert!(Settings::default().apply("ProxyCommand=nc %h %p").unwrap_err().contains("podssh proxy"));
    Settings::default().apply("ProxyCommand=none").unwrap();
}

#[test]
fn ignored_keywords_are_accepted_and_remembered() {
    let mut s = Settings::default();
    s.apply("UpdateHostKeys=yes").unwrap();
    s.apply("HashKnownHosts=yes").unwrap();
    assert_eq!(s.ignored, vec!["UpdateHostKeys", "HashKnownHosts"]);
}

#[test]
fn set_env_takes_several_pairs() {
    let mut s = Settings::default();
    s.apply("SetEnv=A=1 B=two").unwrap();
    assert_eq!(s.set_env, vec![("A".into(), "1".into()), ("B".into(), "two".into())]);
}

/// LocalCommand and PermitLocalCommand are applied (T-191), not ignored.
#[test]
fn local_command_and_its_permit_are_read() {
    let mut s = Settings::default();
    s.apply("LocalCommand=touch /tmp/lc-%h").unwrap();
    s.apply("PermitLocalCommand yes").unwrap();
    assert_eq!((s.local_command.as_deref(), s.permit_local_command), (Some("touch /tmp/lc-%h"), Some(true)));
    assert!(s.ignored.is_empty(), "{:?}", s.ignored);
    assert!(Settings::default().apply("PermitLocalCommand=maybe").is_err());
}
