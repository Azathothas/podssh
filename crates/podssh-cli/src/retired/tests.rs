//! The tests of the retired names (T-634), on a table of one row of the
//! tests', as the release's table is empty.

use super::*;

/// The row of the tests: a name that no release read, retired for a
/// variable that the manual lists as read. The tests of dispatch, of a
/// service's file and of the manual take it too.
pub(crate) const ROW: Retired = Retired {
    name: "PODSSH_RETIRED_FOR_TESTS",
    since: "v0.0.0",
    instead: Instead::Use("PODSSH_RELAY"),
    why: "a row of the tests",
};

const TABLE: &[Retired] = &[ROW];

/// The variables of a run, as `environment` gives them.
pub(crate) fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect()
}

fn a_command() -> Parsed {
    crate::tree::parse(vec!["chat"])
}

#[test]
fn a_retired_name_that_is_set_is_refused_with_its_replacement() {
    let mut err = Vec::new();
    let code = check(&a_command(), TABLE, &vars(&[("PODSSH_RETIRED_FOR_TESTS", "yes")]), &mut err);
    assert_eq!(code, Some(78));
    let text = String::from_utf8(err).unwrap();
    let parts = ["podssh: PODSSH_RETIRED_FOR_TESTS is no longer read", "(since v0.0.0)", "use PODSSH_RELAY instead"];
    for part in parts.iter().chain(&["remove it", "a row of the tests"]) {
        assert!(text.contains(part), "{part}: {text}");
    }
    // What it is not, then what took its place, what to do, and why last.
    let at = |part: &str| text.find(part).unwrap();
    assert!(at("no longer read") < at("use PODSSH_RELAY") && at("use PODSSH_RELAY") < at("remove it"), "{text}");
    assert!(at("remove it") < at("a row of the tests"), "{text}");
    assert_eq!(text.lines().count(), 1, "{text}");
}

#[test]
fn an_empty_value_is_not_set() {
    let mut err = Vec::new();
    assert_eq!(check(&a_command(), TABLE, &vars(&[("PODSSH_RETIRED_FOR_TESTS", "")]), &mut err), None);
    assert!(err.is_empty());
}

/// Any value that is not empty refuses, whatever its shape: `no` turns
/// nothing off that nothing reads.
#[test]
fn each_value_that_is_not_empty_is_set() {
    for value in ["no", "none", "[]", "0", " "] {
        let found = set_in(TABLE, &vars(&[("PODSSH_RETIRED_FOR_TESTS", value)]));
        assert_eq!(found, [&ROW], "{value:?}");
    }
}

/// The line that this check must never cross: a name that no row holds
/// passes, so that it never becomes a list of allowed names.
#[test]
fn an_unknown_name_is_let_through() {
    let set = vars(&[("PODSSH_NO_SUCH_THING", "1"), ("PODSSH_RETIRED_FOR_TESTSX", "1"), ("PATH", "/bin")]);
    assert!(set_in(TABLE, &set).is_empty(), "{:?}", set_in(TABLE, &set));
    let mut err = Vec::new();
    assert_eq!(check(&a_command(), TABLE, &set, &mut err), None);
    assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
}

/// What only prints answers with the name set: `--version`, `--help`, the
/// manual, and a usage error, which says its own words.
#[test]
fn what_only_prints_answers_with_a_retired_name_set() {
    let set = vars(&[("PODSSH_RETIRED_FOR_TESTS", "yes")]);
    let printing: [Vec<&str>; 6] =
        [vec!["--version"], vec!["--help"], vec!["ssh", "--help"], vec!["man", "environment"], vec![], vec!["sttaus"]];
    for words in printing {
        let mut err = Vec::new();
        assert_eq!(check(&crate::tree::parse(words.clone()), TABLE, &set, &mut err), None, "{words:?}");
        assert!(err.is_empty(), "{words:?}");
    }
}

/// Two names set: a line for each, in the table's order.
#[test]
fn each_retired_name_that_is_set_has_its_line() {
    let other = Retired { name: "PODSSH_RETIRED_TOO", since: "v0.0.1", instead: Instead::Nothing, why: "gone" };
    let table = [ROW, other];
    let set = vars(&[("PODSSH_RETIRED_TOO", "1"), ("PODSSH_RETIRED_FOR_TESTS", "1")]);
    let mut err = Vec::new();
    assert_eq!(check(&a_command(), &table, &set, &mut err), Some(78));
    let text = String::from_utf8(err).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(lines[0].contains("PODSSH_RETIRED_FOR_TESTS") && lines[1].contains("PODSSH_RETIRED_TOO"), "{text}");
    assert!(lines[1].contains("nothing replaces it; remove it (gone)"), "{text}");
}

/// Each row names its replacement, or says that there is none, and none
/// of the release's rows is a dead end: a replacement is never a retired
/// name, nor the row's own.
#[test]
fn each_row_names_a_replacement_or_says_there_is_none() {
    let mut rows: Vec<&Retired> = RETIRED.iter().collect();
    rows.push(&ROW);
    for row in rows {
        assert!(row.name.starts_with("PODSSH_") && !row.since.is_empty() && !row.why.is_empty(), "{row:?}");
        match row.instead {
            Instead::Use(what) => {
                assert!(!what.is_empty() && what != row.name, "{row:?}");
                assert!(named(RETIRED, what).is_none() && what != ROW.name, "{row:?}: its replacement is retired");
            }
            Instead::Nothing => assert!(row.refusal().contains("nothing replaces it"), "{row:?}"),
        }
    }
}

/// Each name of the release's table appears once.
#[test]
fn no_name_has_two_rows() {
    for (i, row) in RETIRED.iter().enumerate() {
        assert!(RETIRED[i + 1..].iter().all(|other| other.name != row.name), "{} twice", row.name);
    }
}
