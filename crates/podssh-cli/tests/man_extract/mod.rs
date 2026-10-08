//! The extractors E32's parity gate reads the two renderings with.
//!
//! ⛔ **Their own file, because the gate outgrew one.** ⛔ `RULES.md`:80-91:
//! *"No source file may exceed 500 lines ... split it into modules with names
//! that say what they hold."* ⛔ This module holds the reading half and
//! `man_flag_parity.rs` holds the five claims, ⛔ so a reader looking for the
//! *rule* does not have to walk a parser to find it.
//!
//! ⛔ **Nothing here is compiled into the binary.** ⛔ The gate parses the text a
//! user sees; ⛔ a parser that shipped in `podssh-cli` would be one more thing
//! that can be wrong in the same place as the emitter.
#![allow(dead_code)] // each claim below uses a subset.

use crate::UNIVERSAL;
use podssh_cli::flags::{FlagRow, Verb, VERBS};
use podssh_cli::help;
use std::collections::BTreeMap;

// ---------------------------------------------------------------- the sections

/// ⛔ `""` is the top level, and every verb follows in `--help` order.
pub fn sections() -> Vec<(String, Option<&'static Verb>)> {
    let mut out: Vec<(String, Option<&'static Verb>)> = vec![(String::new(), None)];
    for v in VERBS {
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

/// ⛔ **The flags inside an `OPTIONS:` block, and only there.** ⛔ Scoping it
/// matters: `verb_help` prints a footer that *mentions* `-L`, `-R`, `-D`, `-W`,
/// `-P` and `-p` in prose, and an unscoped scan would read a sentence as a
/// flag. ⛔ The block ends at the first blank line.
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
        !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    } else if let Some(rest) = token.strip_prefix('-') {
        rest.chars().count() == 1 && rest.chars().all(|c| c.is_ascii_alphanumeric())
    } else {
        false
    }
}

/// The descriptions a section's `OPTIONS:` block can end a line with.
pub fn descriptions_for(verb: Option<&'static Verb>) -> Vec<String> {
    match verb {
        Some(v) => {
            let mut d: Vec<String> = v.flags.iter().map(help::help_text).collect();
            d.push(podssh_cli::flags::HELP_FLAG.help.to_string());
            // ⛔ Longest first: a description that is the tail of another would
            // otherwise cut a usage line in the middle of its own sentence.
            d.sort_by_key(|s| std::cmp::Reverse(s.len()));
            d
        }
        // ⛔ The top level is not a verb, so its two descriptions are the
        // literals `help::top_level_help` writes — ⛔ and the page has its own
        // copies, which `every_description_in_the_page_is_the_one_help_prints`
        // compares.
        None => vec!["Print help".to_string(), "Print version".to_string()],
    }
}

/// ⛔ **Where a usage ends and a description begins cannot be read off the
/// spaces.** ⛔ `help::flag_line` pads to `flag_column`, which is *the widest
/// row plus two*, so a row one character short of the column gets a **single
/// space** — measured on `--sendfile FILE`, and on `--StrictHostKeyChecking`,
/// whose description also *contains* `--insecure`. ⛔ A scan that guessed the
/// boundary reported `--insecure` as a flag, which is the false-defect failure
/// E31's `flag_table_matches_spec.rs`:44-48 records. ⛔ So the boundary is the
/// row's own description, which is the one thing that is exactly known.
pub fn option_usages(block: &str, descriptions: &[String]) -> Vec<String> {
    let lines: Vec<&str> = block.lines().map(str::trim).collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        let usage = descriptions
            .iter()
            .filter_map(|d| line.strip_suffix(d.as_str()).map(|u| u.trim_end()))
            // ⛔ Not the wrapped form: that one leaves nothing before the
            // description.
            .filter(|u| !u.is_empty())
            // ⛔ And it must still begin with a flag.
            .find(|u| {
                u.split_whitespace()
                    .next()
                    .map(|t| looks_like_flag(t.trim_end_matches(',')))
                    .unwrap_or(false)
            });
        let usage = match usage {
            Some(u) => u.to_string(),
            // ⛔ The wrapped form: `flag_line` puts a row too wide for the
            // column on its own line, so the usage is the line above the
            // description.
            None => {
                let alone = descriptions.iter().any(|d| *line == d.as_str());
                match (alone, i) {
                    (true, 1..) => lines[i - 1].to_string(),
                    _ => continue,
                }
            }
        };
        out.push(usage);
    }
    out
}

/// Every flag in a rendered `OPTIONS:` block, with its metavariable.
///
/// ⛔ **A parser that reads half its input is worse than none** — E31's
/// `flag_table_matches_spec.rs`:44-48 — so this one takes every spelling on the
/// line: rows group them (`-p, --port PORT`), and ⛔ a first-token-only scan
/// would report seven false defects.
///
/// ⛔ The metavariable is what remains after the usage's leading flag run, and
/// `None` when nothing remains: `-N, --no-remote-command` takes no argument,
/// ⛔ and the description has already been cut away, so a leftover word cannot
/// be prose.
pub fn help_map(block: &str, verb: Option<&'static Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    for usage in option_usages(block, &descriptions_for(verb)) {
        let tokens: Vec<&str> = usage.split_whitespace().collect();
        let mut names: Vec<String> = Vec::new();
        let mut i = 0;
        while i < tokens.len() {
            let token = tokens[i].trim_end_matches(',');
            if !looks_like_flag(token) {
                break;
            }
            names.push(token.to_string());
            i += 1;
        }
        if names.is_empty() {
            continue;
        }
        let metavar = if i < tokens.len() {
            Some(tokens[i..].join(" "))
        } else {
            None
        };
        for name in names {
            map.insert(canonical(verb, &name), metavar.clone());
        }
    }
    map
}

// -------------------------------------------------------------- the man side

/// One `.Fl` line of the page: the flags it names and their metavariable.
#[derive(Debug)]
pub struct Item {
    pub flags: Vec<String>,
    pub metavar: Option<String>,
}

/// Undo the emitter's escaping for one token: `\-` is `-`, `\&` is nothing.
pub fn unescape(token: &str) -> String {
    let mut out = String::new();
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('-') => out.push('-'),
            Some('&') => {}
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Every `.It`/`.Fl` item in a page region — `06-cli.md`:163's extraction.
pub fn man_items(region: &str) -> Vec<Item> {
    let mut items = Vec::new();
    for line in region.lines() {
        let Some(args) = line.strip_prefix(".Fl ") else { continue };
        let mut flags = Vec::new();
        let mut metavar = None;
        for token in args.split_whitespace() {
            let token = unescape(token);
            if looks_like_flag(&token) {
                flags.push(token);
            } else if metavar.is_none() {
                metavar = Some(token);
            }
        }
        items.push(Item { flags, metavar });
    }
    items
}

/// The page split into one region per section: `""` is the top-level
/// `OPTIONS:` block, and a verb's region runs from its `.SS` to the next
/// heading.
pub fn man_regions(page: &str) -> BTreeMap<String, String> {
    let mut regions: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in page.lines() {
        if let Some(name) = line.strip_prefix(".SS ") {
            let name = name.trim().to_string();
            regions.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        if line.starts_with(".SH") {
            current = if line.trim_end() == ".SH OPTIONS" {
                regions.entry(String::new()).or_default();
                Some(String::new())
            } else {
                None
            };
            continue;
        }
        if let Some(name) = &current {
            let region = regions.get_mut(name).expect("the region was inserted above");
            region.push_str(line);
            region.push('\n');
        }
    }
    regions
}

/// Every flag in a page region, with its metavariable.
pub fn man_map(region: &str, verb: Option<&Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    for item in man_items(region) {
        for flag in &item.flags {
            map.insert(canonical(verb, flag), item.metavar.clone());
        }
    }
    map
}

// ------------------------------------------------------------- one spelling

/// ⛔ **`--flag`, `-f` and the aliases, normalised to one name** — the row's
/// long spelling, which is the only name both renderers carry.
///
/// ⛔ A token the tree does not know is kept **verbatim** rather than dropped:
/// ⛔ that is how a flag that exists in the page and not in the binary is
/// reported *by name*, which is plant 2 and the whole point of the extra
/// direction.
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
        // ⛔ The top level is not a verb, so its two options have no table row
        // to resolve against; the short spellings are mapped to the long ones
        // here, which is the alising `06-cli.md`:163 asks for.
        None => match token {
            "-h" => "--help".to_string(),
            "-V" => "--version".to_string(),
            other => other.to_string(),
        },
    }
}

/// ⛔ **The table itself, as the third reading.** ⛔ Both renderings agreeing on
/// a flag the tree does not have is still a failure: the page would document
/// something the binary refuses.
pub fn tree_map(verb: Option<&Verb>) -> BTreeMap<String, Option<String>> {
    let mut map = BTreeMap::new();
    match verb {
        Some(v) => {
            for row in v.flags {
                map.insert(format!("--{}", row.long), row.arg.map(str::to_string));
            }
        }
        None => {
            map.insert("--help".to_string(), None);
            map.insert("--version".to_string(), None);
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

