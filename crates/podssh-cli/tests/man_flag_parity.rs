//! The parity gate: `--help` and the manual must show the same flags, with
//! the same value names and the same descriptions, and both must be the
//! flag table. Each side is read from the text that a user sees (the readers
//! are in `man_extract/`), in both directions, and each failure names the
//! flag.

use podssh_cli::flags::{Availability, FlagRow, VERBS};
use podssh_cli::{help, man};

mod man_extract;
use man_extract::*;

/// The option that every verb takes. The parser declares it, so it is in no
/// verb's table.
const UNIVERSAL: &str = "--help";

/// A gate that read nothing would pass on nothing.
#[test]
fn the_readers_are_not_vacuous() {
    let page = man::page();
    let regions = man_regions(&page);
    assert!(regions.contains_key(""), "no region for the options before a command");
    for (name, verb) in sections() {
        let expected = tree_map(verb);
        let h = help_map(&options_block(&help_text(verb)), verb);
        let m = man_map(regions.get(&name).unwrap_or_else(|| panic!("no region {name:?}")), verb);
        assert!(h.len() >= expected.len(), "{name:?}: help gave {} flags, the table has {}", h.len(), expected.len());
        assert!(
            m.len() >= expected.len(),
            "{name:?}: the manual gave {} flags, the table has {}",
            m.len(),
            expected.len()
        );
    }
    // The flags that a careless reader loses: digits, a long-only flag, and
    // a row whose meaning differs between verbs.
    let ssh = VERBS.iter().find(|v| v.name == "ssh").unwrap();
    let ssh_page = man_map(regions.get("ssh").unwrap(), Some(ssh));
    for want in ["--port", "--tag", "--forward-local", "--StrictHostKeyChecking", "--ipv4-only"] {
        assert!(ssh_page.contains_key(want), "the manual reader missed {want}");
    }
    let items = man_items(regions.get("ssh").unwrap());
    let port = items.iter().find(|i| i.flags.iter().any(|f| f == "-p")).expect("an item for -p");
    assert!(port.flags.iter().any(|f| f == "--port"), "one spelling only: {port:?}");
}

#[test]
fn each_section_shows_the_same_flags_in_help_and_in_the_manual() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let h = help_map(&options_block(&help_text(verb)), verb);
        let m = man_map(regions.get(&name).unwrap(), verb);
        let missing: Vec<&String> = h.keys().filter(|k| !m.contains_key(*k)).collect();
        let extra: Vec<&String> = m.keys().filter(|k| !h.contains_key(*k)).collect();
        assert!(missing.is_empty(), "{name:?}: in --help, not in the manual: {missing:?}");
        assert!(extra.is_empty(), "{name:?}: in the manual, not in --help: {extra:?}");
        assert_eq!(h, m, "{name:?}: the value names differ");
    }
}

#[test]
fn each_section_shows_the_flags_of_the_table() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let expected = tree_map(verb);
        let h = help_map(&options_block(&help_text(verb)), verb);
        let m = man_map(regions.get(&name).unwrap(), verb);
        for (label, got) in [("--help", &h), ("the manual", &m)] {
            let missing: Vec<&String> = expected.keys().filter(|k| !got.contains_key(*k)).collect();
            let extra: Vec<&String> = got.keys().filter(|k| !expected.contains_key(*k)).collect();
            assert!(missing.is_empty(), "{name:?}: {label} leaves out {missing:?}");
            assert!(extra.is_empty(), "{name:?}: {label} has {extra:?}, which the table does not");
            assert_eq!(&expected, got, "{name:?}: {label} shows other value names than the table");
        }
    }
}

/// Each description in the manual is the sentence that `--help` prints, and
/// each command's section has the synopsis that `--help` prints.
#[test]
fn each_description_is_the_one_help_prints() {
    let page = man::page();
    let regions = man_regions(&page);
    let squeeze = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
    for (name, verb) in sections() {
        let region = regions.get(&name).unwrap();
        let items = man_items(region);
        match verb {
            Some(v) => {
                for row in v.flags {
                    let item = items
                        .iter()
                        .find(|i| i.flags.iter().any(|f| canonical(Some(v), f) == format!("--{}", row.long)))
                        .unwrap_or_else(|| panic!("{name}: no item for --{}", row.long));
                    assert_eq!(squeeze(&item.text), squeeze(&help::help_text(row)), "{name}: --{}", row.long);
                    assert!(help_text(Some(v)).contains(&help::help_text(row)), "{name}: --help lacks it");
                }
                let synopsis = format!("podssh {} {}", v.name, help::usage_tail(v));
                assert!(region.contains(&synopsis), "{name}: no synopsis {synopsis:?}");
                assert!(help_text(Some(v)).contains(&synopsis), "{name}: --help has another synopsis");
            }
            None => {
                for (_, long, about) in podssh_cli::flags::TOP_OPTIONS {
                    let item = items.iter().find(|i| i.flags.iter().any(|f| f == long)).unwrap();
                    assert_eq!(item.text, *about, "{long}");
                    assert!(help::top_level_help().contains(about), "--help lacks {about:?}");
                }
            }
        }
    }
}

/// A command that does not work in this binary says so in both renderings,
/// in its own help too, and neither shows an option of it.
#[test]
fn a_command_that_does_not_work_says_so_in_both() {
    let page = man::page();
    let regions = man_regions(&page);
    let top = help::top_level_help();
    let squeeze = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
    let broken: Vec<_> = VERBS.iter().filter(|v| podssh_cli::flags::availability(v) != Availability::Works).collect();
    // Since chat (T-099), each command works in a build with the feature
    // ts; in another, ts does not, so this check has a command to check.
    #[cfg(not(feature = "ts"))]
    assert!(!broken.is_empty(), "no command to check");
    #[cfg(feature = "ts")]
    if broken.is_empty() {
        return;
    }
    for v in broken {
        let region = regions.get(v.name).unwrap_or_else(|| panic!("no section for {}", v.name));
        assert!(man_items(region).is_empty(), "{}: the manual shows options", v.name);
        assert!(region.contains("exits 70"), "{}: the manual does not say that it exits 70", v.name);
        let line = top.lines().find(|l| l.trim_start().starts_with(&format!("{} ", v.name))).unwrap();
        assert!(line.contains("(not "), "{}: --help does not mark it: {line:?}", v.name);
        // Its own help: the mark in the title, the manual's sentence, and no
        // option but --help.
        let own = help::verb_help(v);
        let sentence = help::availability_sentence(v).expect("a sentence");
        assert!(own.lines().next().unwrap_or("").contains("(not "), "{}: the title is not marked:\n{own}", v.name);
        assert!(squeeze(&own).contains(&squeeze(sentence)), "{}: its help lacks the sentence:\n{own}", v.name);
        assert!(squeeze(region).contains(&squeeze(sentence)), "{}: the manual lacks the sentence", v.name);
        let block = options_block(&own);
        let options: Vec<&str> = block.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(options.len(), 1, "{}: options other than --help:\n{own}", v.name);
        assert!(options[0].trim_start().starts_with(UNIVERSAL), "{}: {options:?}", v.name);
    }
}

/// `--help` starts in the columns of the other options. It had a line of its
/// own, four spaces in, where each other long option starts eight in, and its
/// text at character 12, where the others share the column of the verb's
/// widest row: the block read as two tables. Read in the text of each verb's
/// `--help`: each long name, `--help` among them, starts eight characters in
/// (four for the block, four for `-c, ` or its place); each description beside
/// its flag starts in the column of the text of `--help`; and `--help` is the
/// last line of the block.
#[test]
fn help_starts_in_the_columns_of_the_other_options() {
    for v in VERBS {
        let block = options_block(&help::verb_help(v));
        let lines: Vec<&str> = block.lines().collect();
        let last = lines.last().copied().unwrap_or_default();
        assert!(last.trim_start().starts_with("--help "), "{}: --help is not the last line:\n{block}", v.name);
        // A command that does not work here shows no option but --help.
        let shown: &[FlagRow] = if podssh_cli::flags::availability(v) == Availability::Works { v.flags } else { &[] };
        let mut text_columns = Vec::new();
        for row in shown.iter().chain(std::iter::once(&podssh_cli::flags::HELP_FLAG)) {
            let start = match row.short {
                Some(c) => format!("-{c}, --{}", row.long),
                None => format!("--{}", row.long),
            };
            let line = lines
                .iter()
                .find(|l| l.trim_start() == start || l.trim_start().starts_with(&format!("{start} ")))
                .unwrap_or_else(|| panic!("{}: no line starts with {start:?}:\n{block}", v.name));
            assert_eq!(line.find("--"), Some(8), "{}: {start} does not start eight characters in: {line:?}", v.name);
            // A row too wide for the column has its text on the next line.
            if let Some(flag) = line.strip_suffix(help::help_text(row).as_str()) {
                text_columns.push((row.long, flag.chars().count()));
            }
        }
        let help_column = text_columns
            .iter()
            .find(|(long, _)| *long == podssh_cli::flags::HELP_FLAG.long)
            .map(|(_, column)| *column)
            .unwrap_or_else(|| panic!("{}: the text of --help is not beside it:\n{block}", v.name));
        for (long, column) in &text_columns {
            assert_eq!(
                *column, help_column,
                "{}: the text of --{long} starts at {column}, that of --help at {help_column}",
                v.name
            );
        }
    }
}
