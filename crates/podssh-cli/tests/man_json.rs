//! `podssh man --json` against the readers of `--help`: each flag that
//! `--help` shows, with its value name, its kind and what to type instead;
//! each `-o` keyword, variable and exit code; and the same bytes in any
//! environment.

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use serde_json::Value;

mod man_extract;
use man_extract::*;

/// The option that every verb takes; the readers need its name.
const UNIVERSAL: &str = "--help";

fn document() -> Value {
    podssh_cli::man::json::document()
}

/// What `--help` says of a flag's kind, from the suffix that `help_text`
/// writes, and what it names to use instead.
fn kind_in_help(description: &str) -> (&'static str, Option<String>) {
    if let Some(at) = description.rfind(" (refused: use ") {
        let rest = &description[at + " (refused: use ".len()..];
        let instead = rest.strip_suffix(')').unwrap_or(rest);
        return ("refused", Some(instead.to_string()));
    }
    if description.ends_with(" (refused)") {
        return ("refused", None);
    }
    if description.ends_with(" (accepted and ignored)") {
        return ("accepted", None);
    }
    if description.ends_with(" (not in this release)") {
        return ("not-in-this-release", None);
    }
    ("supported", None)
}

#[test]
fn each_flag_of_help_is_in_the_json_with_its_kind() {
    let doc = document();
    for (name, verb) in sections() {
        let block = options_block(&help_text(verb));
        let values = help_map(&block, verb);
        let described = help_descriptions(&block, verb);
        assert_eq!(values.keys().collect::<Vec<_>>(), described.keys().collect::<Vec<_>>(), "{name:?}");
        let items: Vec<Value> = match verb {
            None => doc["options"].as_array().unwrap().clone(),
            Some(v) => {
                let command = doc["commands"].as_array().unwrap().iter().find(|c| c["name"] == v.name).unwrap();
                command["flags"].as_array().unwrap().clone()
            }
        };
        let mut json: BTreeMap<String, &Value> = BTreeMap::new();
        for item in &items {
            json.insert(canonical(verb, item["long"].as_str().unwrap()), item);
        }
        assert_eq!(json.keys().collect::<Vec<_>>(), values.keys().collect::<Vec<_>>(), "{name:?}: other flags");
        if verb.is_none() {
            continue; // the options before a command have no value and no kind
        }
        for (flag, value) in &values {
            let item = json[flag];
            assert_eq!(item["value"].as_str().map(str::to_string), *value, "{name}: {flag}");
            let (kind, instead) = kind_in_help(&described[flag]);
            assert_eq!(item["kind"], kind, "{name}: {flag}");
            assert_eq!(item["instead"].as_str().map(str::to_string), instead, "{name}: {flag}");
        }
    }
}

#[test]
fn each_keyword_variable_and_exit_code_is_in_the_json() {
    let doc = document();
    let names = |list: &Value, key: &str| -> Vec<String> {
        list.as_array().unwrap().iter().map(|i| i[key].as_str().unwrap().to_string()).collect()
    };
    let keywords = &doc["ssh_keywords"];
    for k in podssh_cli::ssh::keywords::HONOURED {
        assert!(names(&keywords["honoured"], "name").contains(&k.name.to_string()), "{}", k.name);
    }
    let ignored: Vec<&str> = keywords["ignored"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(ignored, podssh_cli::ssh::keywords::IGNORED);
    for (k, _) in podssh_cli::ssh::keywords::REFUSED {
        assert!(names(&keywords["refused"], "name").contains(&k.to_string()), "{k}");
    }
    let variables: Vec<String> = doc["variables"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["names"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()))
        .collect();
    for (list, _) in podssh_cli::man::facts::VARIABLES {
        for n in *list {
            assert!(variables.contains(&n.to_string()), "{n}");
        }
    }
    let codes: Vec<String> = doc["exit_codes"].as_array().unwrap().iter().map(|c| c["code"].to_string()).collect();
    for code in [
        0,
        podssh_cli::doctor::EXIT_FAILED,
        podssh_cli::exit_codes::EXIT_USAGE,
        podssh_cli::exitmap::sysexits::EX_UNAVAILABLE,
        podssh_cli::exit_codes::EXIT_NOT_IMPLEMENTED,
        podssh_cli::exitmap::sysexits::EX_NOPERM,
        podssh_cli::exitmap::sysexits::EX_CONFIG,
        podssh_ssh::EXIT_FAILURE,
    ] {
        assert!(codes.contains(&code.to_string()), "{code}: {codes:?}");
    }
    assert!(codes.contains(&"\"N\"".to_string()), "{codes:?}");
}

/// Run the binary with `args`; with `clear`, in an empty environment.
fn podssh(args: &[&str], set: &[(&str, &str)], clear: bool) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    if clear {
        cmd.env_clear();
        // Windows needs these to start a process at all.
        for name in ["SystemRoot", "SYSTEMROOT"] {
            if let Ok(v) = std::env::var(name) {
                cmd.env(name, v);
            }
        }
    }
    cmd.envs(set.iter().copied());
    let out = cmd.stdin(Stdio::null()).output().expect("podssh runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_json_is_the_same_in_any_environment() {
    let (rc, bare, err) = podssh(&["man", "--json"], &[], true);
    assert_eq!(rc, 0, "{err}");
    let token = "podssh-test-token-0123456789abcdef";
    let set = [("PODSSH_RELAY_TOKEN", token), ("HOME", "/home/someone"), ("USERPROFILE", "C:\\Users\\someone")];
    let (rc, full, _) = podssh(&["man", "--json"], &set, false);
    assert_eq!(rc, 0);
    assert_eq!(bare, full, "the JSON depends on the environment");
    assert!(!full.contains(token) && !full.contains("someone"));
    let doc: Value = serde_json::from_str(&full).expect("one JSON object");
    assert_eq!(doc["schema"], 1);
}

#[test]
fn a_section_gives_one_command_or_one_table() {
    let (rc, out, _) = podssh(&["man", "--json", "irc"], &[], false);
    assert_eq!(rc, 0);
    let doc: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc["command"]["name"], "chat", "an alias finds its command");
    let (rc, out, _) = podssh(&["man", "--json", "exit-status"], &[], false);
    assert_eq!(rc, 0);
    assert!(serde_json::from_str::<Value>(&out).unwrap()["exit_codes"].is_array());
    for args in
        [&["man", "--json", "relay-facts"][..], &["man", "--json", "--roff"][..], &["man", "--json", "nonsense"][..]]
    {
        let (rc, out, err) = podssh(args, &[], false);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
}
