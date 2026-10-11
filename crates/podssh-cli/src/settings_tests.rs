//! The settings file: its lines, its place, and its rank below the flags
//! and the variables (T-048).

use super::*;
use crate::relay_settings::{failover_from, relays_from};
use podssh_relay::failover::Mode;

fn read(text: &str) -> Defaults {
    parse(text, "f", Some(Path::new("/home/u"))).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn a_file_gives_each_setting_and_the_first_value_wins_but_for_relay_addr() {
    let d = read(
        "# podssh's own settings\nRelayHost a.example,b.example:8443\nRelayHost c.example\n\
         RelayAddr a.example=192.0.2.1\nRelayAddr=b.example=192.0.2.2\nrelayfailover serial # a comment\n\
         CaFile ~/ca.pem\n",
    );
    let host = d.relay_host.as_ref().unwrap();
    assert_eq!((host.text.as_str(), host.at.as_str()), ("a.example,b.example:8443", "f:2"));
    let pins: Vec<&str> = d.relay_addr.iter().map(|v| v.text.as_str()).collect();
    assert_eq!(pins, ["a.example=192.0.2.1", "b.example=192.0.2.2"]);
    assert_eq!(d.relay_failover.unwrap().text, "serial");
    assert_eq!(d.ca_file.unwrap().text, Path::new("/home/u").join("ca.pem").display().to_string());
}

#[test]
fn an_unknown_keyword_or_an_empty_value_is_refused_with_its_line() {
    let err = parse("RelayHost a\nRelayHosts b\n", "f", None).unwrap_err();
    assert!(err.starts_with("f:2: RelayHosts is not a setting of podssh; the settings are RelayHost"), "{err}");
    assert!(parse("CaFile\n", "f", None).unwrap_err().starts_with("f:1: CaFile needs a value"));
    // No keyword holds a token: a token in a file would be a stored credential.
    assert!(parse("RelayToken t\n", "f", None).unwrap_err().contains("not a setting of podssh"));
    assert!(parse("Host x\n", "f", None).is_err(), "not an ssh_config");
}

#[test]
fn the_flag_beats_the_variable_and_the_variable_the_file() {
    let file = read("RelayHost file.example\nRelayFailover serial\nCaFile /file/ca.pem\n");
    let host = |flag: Option<&str>, env: Option<&str>, file: &Defaults| {
        relays_from(flag, env.map(String::from), file).unwrap().hosts[0].host.clone()
    };
    assert_eq!(host(None, None, &file), "file.example");
    assert_eq!(host(None, Some("env.example"), &file), "env.example");
    assert_eq!(host(Some("flag.example"), Some("env.example"), &file), "flag.example");
    assert_eq!(host(None, Some("  "), &file), "file.example", "an empty variable is no variable");
    assert_eq!(host(None, None, &Defaults::default()), podssh_relay::DEFAULT_RELAY_HOST);
    assert_eq!(failover_from(None, None, &file).unwrap(), Mode::Serial);
    assert_eq!(failover_from(None, Some("parallel".into()), &file).unwrap(), Mode::Parallel);
    assert_eq!(failover_from(Some("staggered"), Some("parallel".into()), &file).unwrap(), Mode::Staggered);
    assert_eq!(ca_file_from(None, None, &file).as_deref(), Some("/file/ca.pem"));
    assert_eq!(ca_file_from(None, Some("/env.pem".into()), &file).as_deref(), Some("/env.pem"));
    assert_eq!(ca_file_from(Some("/flag.pem"), Some("/env.pem".into()), &file).as_deref(), Some("/flag.pem"));
}

/// A bad value of the file is refused as the file is read, and names its
/// line.
#[test]
fn a_bad_value_of_the_file_names_its_line() {
    for (text, says) in [
        ("RelayHost bad host!\n", "f:1: RelayHost bad host!: "),
        ("RelayAddr a.example=x\n", "f:1: RelayAddr a.example=x: "),
        ("CaFile /c.pem\nRelayFailover sideways\n", "f:2: RelayFailover \"sideways\" is not a mode"),
    ] {
        let err = parse(text, "f", None).unwrap_err();
        assert!(err.starts_with(says), "{text:?}: {err}");
    }
    // A value that a test puts in by hand is refused where it is used, as 78.
    let bad = Value { text: "bad host!".into(), at: "f:1".into() };
    let file = Defaults { relay_host: Some(bad), ..Defaults::default() };
    let err = relays_from(None, None, &file).unwrap_err();
    assert_eq!(err.code, crate::exitmap::sysexits::EX_CONFIG);
    assert!(err.message.starts_with("f:1: RelayHost bad host!: "), "{}", err.message);
    // A flag or a variable is read before the file, and the file's value not at all.
    assert!(relays_from(Some("good.example"), None, &file).is_ok());
}

#[test]
fn the_file_is_the_variables_or_the_first_usual_place_that_exists() {
    let dir = std::env::temp_dir().join(format!("podssh-settings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (config, bin) = (dir.join("config"), dir.join("bin"));
    std::fs::create_dir_all(config.join("podssh")).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let places = |given: Option<&str>| Places {
        given: given.map(String::from),
        config_home: Some(config.clone()),
        home: None,
        binary_dir: Some(bin.clone()),
    };
    assert_eq!(locate(&places(None)).unwrap(), None, "no file at all");
    std::fs::write(bin.join(BESIDE_BINARY), "").unwrap();
    assert_eq!(locate(&places(None)).unwrap(), Some(bin.join(BESIDE_BINARY)));
    std::fs::write(config.join("podssh").join("settings"), "").unwrap();
    assert_eq!(locate(&places(None)).unwrap(), Some(config.join("podssh").join("settings")), "the user's first");
    assert_eq!(locate(&places(Some("none"))).unwrap(), None);
    let given = bin.join(BESIDE_BINARY).display().to_string();
    assert_eq!(locate(&places(Some(&given))).unwrap(), Some(bin.join(BESIDE_BINARY)));
    // A relative path would be the working directory's: never read.
    assert!(locate(&places(Some("settings"))).unwrap_err().contains("give an absolute path"));
    let missing = dir.join("missing").display().to_string();
    assert!(locate(&places(Some(&missing))).is_err(), "a file that the variable names must exist");
    let _ = std::fs::remove_dir_all(&dir);
}
