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

/// The first ProxyCommand holds, as OpenSSH reads the first alone (T-502):
/// `none`, or podssh's own proxy, and a later one is not read, so the
/// command line's `none` beats a file's command.
#[test]
fn the_first_proxy_command_holds_and_a_later_one_is_not_read() {
    let mut s = Settings::default();
    s.apply("ProxyCommand=none").unwrap();
    let file = Place::line("/etc/f", 2, false);
    s.apply_at("ProxyCommand=ssh -W %h:%p b", &file).unwrap();
    assert_eq!(s.proxy_command.as_ref().map(|g| g.value.as_str()), Some("none"));
    let mut s = Settings::default();
    s.apply_at("ProxyCommand=podssh proxy %h %p", &file).unwrap();
    s.apply("ProxyCommand=nc %h %p").unwrap();
    assert_eq!(s.proxy_command.map(|g| (g.value, g.place)), Some(("podssh proxy %h %p".into(), file.clone())));
}

/// A ProxyCommand that holds goes before a later ProxyJump, which OpenSSH
/// 10.3p1 does not read then (`parse_jump` of its `readconf.c`); a
/// ProxyJump given first keeps its hops.
#[test]
fn a_proxy_command_that_holds_goes_before_a_later_proxy_jump() {
    let mut s = Settings::default();
    s.apply("ProxyCommand=none").unwrap();
    s.apply_at("ProxyJump=bastion", &Place::line("/etc/f", 3, false)).unwrap();
    assert_eq!(s.proxy_jump, None, "not read after the ProxyCommand that holds");
    let mut s = Settings::default();
    s.apply("ProxyJump=bastion").unwrap();
    s.apply("ProxyCommand=none").unwrap();
    assert_eq!(s.proxy_jump.as_deref(), Some("bastion"), "given first, it holds");
}

/// A file's command is refused, and names the flag that goes past it with
/// the file's other settings (Q70); the command line's names OpenSSH's way.
#[test]
fn a_proxy_command_that_runs_a_program_is_refused_with_the_way_out() {
    let file = Place::line("/etc/f", 2, false);
    let err = Settings::default().apply_at("ProxyCommand=ssh -W %h:%p b", &file).unwrap_err();
    assert!(err.contains("runs no ProxyCommand") && err.contains("-o ProxyCommand=none"), "{err}");
    let err = Settings::default().apply_at("ProxyCommand=podssh proxy --relay-host r %h %p", &file).unwrap_err();
    assert!(err.contains("podssh proxy %h %p") && err.contains("-o ProxyCommand=none"), "{err}");
    let err = Settings::default().apply("ProxyCommand=nc %h %p").unwrap_err();
    assert!(err.contains("podssh proxy %h %p") && !err.contains("ProxyCommand=none"), "{err}");
}
