//! `podssh man --json`: the manual's tables as data, for a program. It walks
//! the tables that the parser and the commands use (commands, flags, `-o`
//! keywords, variables, files, exit codes), not the text, so it keeps what
//! the text drops: the kind of each flag, and what to type instead of a
//! refused one. Like the text, it shows no setting of this host.

use serde_json::{json, Value};

use crate::flags::{availability, Availability, FlagKind, FlagRow, Verb, HELP_FLAG, TOP_OPTIONS, VERBS};
use crate::ssh::keywords;

use super::data::{self, Code};

/// The version of the document's shape: a change that breaks a reader
/// raises it.
pub const SCHEMA: u32 = 1;

fn kind(k: FlagKind) -> &'static str {
    match k {
        FlagKind::Supported => "supported",
        FlagKind::Accepted => "accepted",
        FlagKind::Refused => "refused",
        FlagKind::NotInFirstRelease => "not-in-this-release",
    }
}

fn flag(row: &FlagRow) -> Value {
    json!({
        "short": row.short.map(|c| format!("-{c}")),
        "long": format!("--{}", row.long),
        "value": row.arg,
        "kind": kind(row.kind),
        "help": row.help,
        // What to type instead of a refused flag; null when it is to be left out.
        "instead": row.instead.filter(|i| *i != "no flag"),
    })
}

fn arguments(verb: &'static Verb) -> Vec<Value> {
    crate::tree::verb_command(verb)
        .get_positionals()
        .map(|a| {
            let name = a
                .get_value_names()
                .and_then(|n| n.first())
                .map(|n| n.to_string())
                .unwrap_or_else(|| a.get_id().as_str().to_ascii_uppercase());
            json!({
                "name": name,
                "many": a.get_num_args().is_some_and(|r| r.max_values() > 1),
                "help": a.get_help().map(|h| h.to_string()).unwrap_or_default(),
            })
        })
        .collect()
}

/// One command. A command that does not work here has no option but
/// `--help` and no argument, as in `--help` and the manual: its options
/// cannot be used.
pub fn command(verb: &'static Verb) -> Value {
    let works = availability(verb) == Availability::Works;
    let mut flags: Vec<Value> = if works { verb.flags.iter().map(flag).collect() } else { Vec::new() };
    flags.push(flag(&HELP_FLAG));
    json!({
        "name": verb.name,
        "aliases": verb.aliases.iter().filter(|a| **a != verb.name).collect::<Vec<_>>(),
        "about": verb.about,
        "availability": match availability(verb) {
            Availability::Works => "works",
            Availability::NotYet => "not-implemented",
            Availability::NotInBuild => "not-in-build",
        },
        "usage": format!("podssh {} {}", verb.name, crate::help::usage_tail(verb)),
        "arguments": if works { arguments(verb) } else { Vec::new() },
        "flags": flags,
    })
}

fn ssh_keywords() -> Value {
    json!({
        "honoured": keywords::HONOURED
            .iter()
            .map(|k| json!({
                "name": k.name, "value": k.value, "help": k.help,
                "default": keywords::documented_default(k.name),
            }))
            .collect::<Vec<_>>(),
        "ignored": keywords::IGNORED,
        "refused": keywords::REFUSED.iter().map(|(name, why)| json!({ "name": name, "reason": why })).collect::<Vec<_>>(),
    })
}

fn variables() -> Value {
    super::facts::VARIABLES.iter().map(|(names, what)| json!({ "names": names, "help": what })).collect()
}

fn files() -> Value {
    data::files().into_iter().map(|(names, what)| json!({ "names": names, "help": what })).collect()
}

fn exit_codes() -> Value {
    data::exit_codes()
        .into_iter()
        .map(|(code, what)| match code {
            Code::Value(n) => json!({ "code": n, "help": what }),
            Code::Remote => json!({ "code": "N", "help": what }),
        })
        .collect()
}

fn envelope(name: &str, body: Value) -> Value {
    let mut doc = serde_json::Map::new();
    doc.insert("schema".into(), json!(SCHEMA));
    doc.insert("podssh".into(), json!(crate::help::version()));
    doc.insert(name.into(), body);
    Value::Object(doc)
}

/// The whole document.
pub fn document() -> Value {
    let options: Vec<Value> =
        TOP_OPTIONS.iter().map(|(short, long, help)| json!({ "short": short, "long": long, "help": help })).collect();
    json!({
        "schema": SCHEMA,
        "podssh": crate::help::version(),
        "options": options,
        "commands": VERBS.iter().map(command).collect::<Vec<_>>(),
        "ssh_keywords": ssh_keywords(),
        "variables": variables(),
        "files": files(),
        "exit_codes": exit_codes(),
    })
}

/// One section: a command, by its name or an alias, or a topic that is a
/// table (environment, files, exit-status). The other topics are prose, and
/// their text is the form to read.
pub fn section(name: &str) -> Result<Value, String> {
    let manual = super::model::manual();
    let found = manual.find(name).ok_or_else(|| crate::refuse::unknown_man_section(name, &manual.keys()))?;
    if found.command {
        let verb = VERBS.iter().find(|v| v.name == found.key).expect("each command section has its verb");
        return Ok(envelope("command", command(verb)));
    }
    match found.key {
        "environment" => Ok(envelope("variables", variables())),
        "files" => Ok(envelope("files", files())),
        "exit-status" => Ok(envelope("exit_codes", exit_codes())),
        key => Err(format!(
            "podssh man: the section {key} is prose and has no JSON form; podssh man {key} shows it. \
             --json takes a command, environment, files or exit-status."
        )),
    }
}
