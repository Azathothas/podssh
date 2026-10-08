//! The readers that the parity gate (`man_flag_parity.rs`) reads the two
//! renderings with: the `OPTIONS:` blocks of `--help`, and the `Options:`
//! lists of the text manual. They read the text a user sees, not the tables,
//! so a renderer that drops or changes a row fails the gate.
#![allow(dead_code)] // each test uses a subset.

use crate::UNIVERSAL;
use podssh_cli::flags::{availability, Availability, FlagRow, Verb, VERBS};
use podssh_cli::help;
use std::collections::BTreeMap;

// ---------------------------------------------------------------- the sections

/// `""` is the top level, then each verb that works in this binary, in the
/// order of `--help`. A verb that does not work has no option list in the
/// manual: its section says that it exits 70.
pub fn sections() -> Vec<(String, Option<&'static Verb>)> {
    let mut out: Vec<(String, Option<&'static Verb>)> = vec![(String::new(), None)];
    for v in VERBS.iter().filter(|v| availability(v) == Availability::Works) {
        out.push((v.name.to_string(), Some(v)));
    }
    out
}

/// The help text for a section: the top-level block, or one verb's.
pub fn help_text(verb: Option<&'static Verb>) -> String {
    match verb {
        None => help::top_level_help(),
        Some(v) => help::verb_help(v),
    }
}

/// The lines inside the `OPTIONS:` block of a help text. The block ends at
/// the first blank line; the footer after it mentions flags in prose.
pub fn options_block(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim_end() == "OPTIONS:" {
            inside = true;
            continue;
        }
        if inside {
            if line.trim().is_empty() {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

// ------------------------------------------------------------- the help side

/// A single-character or long option spelling, as a user types it.
pub fn looks_like_flag(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix("--") {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    } else if let Some(rest) = token.strip_prefix('-') {
        rest.chars().count() == 1 && rest.chars().all(|c| c.is_ascii_alphanumeric())
    } else {
        false
    }
}

/// The descriptions that a section's `OPTIONS:` block can end a line with,
/// longest first, so that a description that ends another one cannot cut a
/// line in the wrong place.
pub fn descriptions_for(verb: Option<&'static Verb>) -> Vec<String> {
    match verb {
        Some(v) => {
            let mut d: Vec<String> = v.flags.iter().map(help::help_text).collect();
            d.push(podssh_cli::flags::HELP_FLAG.help.to_string());
            d.sort_by_key(|s| std::cmp::Reverse(s.len()));
            d
        }
        None => podssh_cli::flags::TOP_OPTIONS.iter().map(|(_, _, about)| about.to_string()).collect(),
    }
}

/// The usage part of each line of an `OPTIONS:` block. The padding between
/// usage and description can be one space, so the boundary is found from the
/// row's own description, which is known exactly, never from the spaces.
pub fn option_usages(block: &str, descriptions: &[String]) -> Vec<String> {
    option_rows(block, descriptions).into_iter().map(|(usage, _)| usage).collect()
}

/// Each row of an `OPTIONS:` block: its usage and its description.
pub fn option_rows(block: &str, descriptions: &[String]) -> Vec<(String, String)> {
    let lines: Vec<&str> = block.lines().map(str::trim).collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        let found = descriptions
            .iter()
            .filter_map(|d| line.strip_suffix(d.as_str()).map(|u| (u.trim_end(), d)))
            .filter(|(u, _)| !u.is_empty())
            .find(|(u, _)| {
                u.split_whitespace()
                    .next()
                    .map(|t| looks_like_flag(t.trim_end_matches(',')))
                    .unwrap_or(false)
            });
        let row = match found {
            Some((u, d)) => (u.to_string(), d.clone()),
            // A row too wide for the column has its description on the next
            // line, so its usage is the line above the description.
            None => {
                let alone = descriptions.iter().find(|d| *line == d.as_str());
                match (alone, i) {
                    (Some(d), 1..) => (lines[i - 1].to_string(), d.clone()),
                    _ => continue,
                }
            }
        };
        out.push(row);
    }
    out
}

/// Each flag in a rendered `OPTIONS:` block, with the description that
/// `--help` gives it.
pub fn help_descriptions(block: &str, verb: Option<&'static Verb>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (usage, description) in option_rows(block, &descriptions_for(verb)) {
        let (names, _) = flags_and_value(&usage);
        for name in names {
            map.insert(canonical(verb, &name), description.clone());
        }
    }
    map
}

/// The flags and the value name of one usage: `-p, --port PORT`.
fn flags_and_value(usage: &str) -> (Vec<String>, Option<String>) {
    let tokens: Vec<&str> = usage.split_whitespace().collect();
    let mut names = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i].trim_end_matches(',');
        if !looks_like_flag(token) {
            break;
        }
        names.push(token.to_string());
        i += 1;
    }
    let value = (i < tokens.len()).then(|| tokens[i..].join(" "));
    (names, value)
}

/// Each flag in a rendered `OPTIONS:` block, with its value name.
pub fn help_map(block: &str, verb: Option<&'static Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    for usage in option_usages(block, &descriptions_for(verb)) {
        let (names, value) = flags_and_value(&usage);
        for name in names {
            map.insert(canonical(verb, &name), value.clone());
        }
    }
    map
}

// ------------------------------------------------------------- the manual side

/// One option of the text manual: its flags, value name and description.
#[derive(Debug, Clone)]
pub struct Item {
    pub flags: Vec<String>,
    pub value: Option<String>,
    pub text: String,
}

/// The manual split into regions: `""` is the list of options before a
/// command, and each command's region runs from its heading to the next
/// heading (a line that starts in column 0).
pub fn man_regions(page: &str) -> BTreeMap<String, String> {
    let mut regions: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in page.lines() {
        let heading = !line.is_empty() && !line.starts_with(' ');
        if heading {
            let name = line.trim().to_ascii_lowercase();
            current = VERBS.iter().any(|v| v.name == name).then_some(name);
            if let Some(n) = &current {
                regions.entry(n.clone()).or_default();
            }
            continue;
        }
        if line == "  Options before a command:" {
            current = Some(String::new());
            regions.entry(String::new()).or_default();
        }
        if let Some(name) = &current {
            let region = regions.get_mut(name).expect("the region was inserted above");
            region.push_str(line);
            region.push('\n');
        }
    }
    regions
}

/// The options of a region. In a command's section, the `Options:` list has
/// each term at four spaces and its description at eight. The options before
/// a command are a table: the term and the description on one line.
pub fn man_items(region: &str) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut table: Option<bool> = None;
    for line in region.lines() {
        match line {
            "  Options:" => {
                table = Some(false);
                continue;
            }
            "  Options before a command:" => {
                table = Some(true);
                continue;
            }
            _ => {}
        }
        let Some(table) = table else { continue };
        if !line.starts_with("    ") {
            break;
        }
        if let Some(text) = line.strip_prefix("        ").filter(|_| !table) {
            if let Some(last) = items.last_mut() {
                if !last.text.is_empty() {
                    last.text.push(' ');
                }
                last.text.push_str(text.trim());
            }
            continue;
        }
        let (flags, rest) = flags_and_value(line.trim());
        let (value, text) = if table { (None, rest.unwrap_or_default()) } else { (rest, String::new()) };
        items.push(Item { flags, value, text });
    }
    items
}

/// Each flag in a region of the manual, with its value name.
pub fn man_map(region: &str, verb: Option<&Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    for item in man_items(region) {
        for flag in &item.flags {
            map.insert(canonical(verb, flag), item.value.clone());
        }
    }
    map
}

// ------------------------------------------------------------- one spelling

/// `--flag`, `-f` and the aliases, as one name: the row's long spelling. A
/// token the table does not know is kept as it is, so that a flag in one
/// rendering and not in the binary is reported by name.
pub fn canonical(verb: Option<&Verb>, token: &str) -> String {
    match verb {
        Some(v) => {
            if let Some(long) = token.strip_prefix("--") {
                if v.flags.iter().any(|r| r.long == long) {
                    return format!("--{long}");
                }
            } else if token.chars().count() == 2 {
                let c = token.chars().nth(1).expect("two characters");
                if let Some(row) = v.flags.iter().find(|r| r.short == Some(c)) {
                    return format!("--{}", row.long);
                }
            }
            token.to_string()
        }
        None => podssh_cli::flags::TOP_OPTIONS
            .iter()
            .find(|(short, _, _)| *short == token)
            .map(|(_, long, _)| long.to_string())
            .unwrap_or_else(|| token.to_string()),
    }
}

/// The table itself, as the third reading: both renderings agreeing on a
/// flag that the table does not have is still a failure.
pub fn tree_map(verb: Option<&Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    match verb {
        Some(v) => {
            for row in v.flags {
                map.insert(format!("--{}", row.long), row.arg.map(str::to_string));
            }
        }
        None => {
            for (_, long, _) in podssh_cli::flags::TOP_OPTIONS {
                map.insert(long.to_string(), None);
            }
        }
    }
    map.insert(UNIVERSAL.to_string(), None);
    map
}

/// The row for a canonical name, when the section has one.
pub fn row_for(verb: Option<&'static Verb>, canonical: &str) -> Option<&'static FlagRow> {
    let v = verb?;
    v.flags.iter().find(|r| format!("--{}", r.long) == canonical)
}
