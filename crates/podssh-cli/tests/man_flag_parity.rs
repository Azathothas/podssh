//! The parity gate: `--help` and the manual must show the same flags, with
//! the same value names and the same descriptions, and both must be the
//! flag table. Each side is read from the text that a user sees (the readers
//! are in `man_extract/`), in both directions, and each failure names the
//! flag.

use podssh_cli::flags::{Availability, VERBS};
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
        assert!(m.len() >= expected.len(), "{name:?}: the manual gave {} flags, the table has {}", m.len(), expected.len());
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
/// and the manual shows no options for it.
#[test]
fn a_command_that_does_not_work_says_so_in_both() {
    let page = man::page();
    let regions = man_regions(&page);
    let top = help::top_level_help();
    for v in VERBS.iter().filter(|v| podssh_cli::flags::availability(v) != Availability::Works) {
        let region = regions.get(v.name).unwrap_or_else(|| panic!("no section for {}", v.name));
        assert!(man_items(region).is_empty(), "{}: the manual shows options", v.name);
        assert!(region.contains("exits 70"), "{}: the manual does not say that it exits 70", v.name);
        let line = top.lines().find(|l| l.trim_start().starts_with(&format!("{} ", v.name))).unwrap();
        assert!(line.contains("(not "), "{}: --help does not mark it: {line:?}", v.name);
    }
}
