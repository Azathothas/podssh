//! The texts of the services and the file of variables (T-121), on each
//! system: each quoting, the unit, the crontab's lines, the task, and the
//! variables carried and refused.

use std::path::PathBuf;

use super::env::{body_of, parse, CARRIED, SECRET};
use super::text::{
    cron_line, cron_mark, cron_table, sh_word, systemd_word, task_xml, unit, windows_word, xml, UNIT_MARK,
};
use super::Spec;

fn spec(args: &[&str]) -> Spec {
    Spec {
        name: "lab".into(),
        exe: PathBuf::from("/opt/pod ssh/podssh"),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn each_syntax_quotes_what_it_must() {
    assert_eq!(sh_word("node"), "node");
    assert_eq!(sh_word("a b"), "'a b'");
    assert_eq!(sh_word("it's"), "'it'\\''s'");
    assert_eq!(sh_word(""), "''");
    assert_eq!(systemd_word("/usr/bin/podssh"), "/usr/bin/podssh");
    assert_eq!(systemd_word("a b"), "\"a b\"");
    assert_eq!(systemd_word("100%"), "\"100%%\"");
    assert_eq!(systemd_word("$HOME"), "\"$$HOME\"");
    assert_eq!(systemd_word("say \"hi\"\\"), "\"say \\\"hi\\\"\\\\\"");
    assert_eq!(windows_word("C:\\podssh.exe"), "C:\\podssh.exe");
    assert_eq!(windows_word("C:\\Program Files\\x\\"), "\"C:\\Program Files\\x\\\\\"");
    assert_eq!(windows_word("a\"b"), "\"a\\\"b\"");
    assert_eq!(windows_word(""), "\"\"");
    assert_eq!(xml("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
}

#[test]
fn a_unit_runs_the_binary_by_its_path_with_the_node_s_words() {
    let unit = unit(&spec(&["node", "lab", "127.0.0.1:22", "--env-file", "/c/node-lab.env"]));
    assert!(unit.starts_with(UNIT_MARK), "{unit}");
    let exec = "ExecStart=\"/opt/pod ssh/podssh\" node lab 127.0.0.1:22 --env-file /c/node-lab.env\n";
    assert!(unit.contains(exec), "{unit}");
    assert!(unit.contains("RestartPreventExitStatus=64 77 78") && unit.contains("WantedBy=default.target"), "{unit}");
}

#[test]
fn the_crontab_gets_one_line_of_the_name_and_loses_it_again() {
    let line = cron_line(&spec(&["node", "lab", "--env-file", "/c/100%/node-lab.env"]));
    // cron gives sh `%` for `\%`, before sh reads the quotes.
    assert_eq!(line, "@reboot '/opt/pod ssh/podssh' node lab --env-file '/c/100\\%/node-lab.env'");
    let before = "MAILTO=x\n0 * * * * backup\n";
    let (with, found) = cron_table(before, "lab", Some(&line));
    assert!(!found);
    assert_eq!(with, format!("{before}{}\n{line}\n", cron_mark("lab")));
    // Again: the line is replaced, never doubled.
    let (again, found) = cron_table(&with, "lab", Some("@reboot new"));
    assert!(found && again.matches("@reboot").count() == 1 && again.contains("@reboot new"), "{again}");
    // The line of another NAME stays.
    let (both, _) = cron_table(&again, "other", Some("@reboot other"));
    let (rest, found) = cron_table(&both, "lab", None);
    assert!(found && rest.contains("@reboot other") && !rest.contains("@reboot new"), "{rest}");
    assert_eq!(cron_table(&rest, "other", None).0, before);
    // A line below the mark that is not an @reboot line is the user's.
    let edited = format!("{}\n0 1 * * * mine\n", cron_mark("lab"));
    assert_eq!(cron_table(&edited, "lab", None), ("0 1 * * * mine\n".to_string(), true));
}

#[test]
fn the_task_runs_as_this_user_at_its_logon_with_no_privilege() {
    let task = task_xml(&spec(&["node", "lab", "--env-file", "C:\\Users\\a b\\node-lab.env"]), "HOST\\a&b");
    assert_eq!(task.matches("<UserId>HOST\\a&amp;b</UserId>").count(), 2, "{task}");
    assert!(task.contains("<LogonType>InteractiveToken</LogonType>"), "{task}");
    assert!(task.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{task}");
    assert!(task.contains("<Command>/opt/pod ssh/podssh</Command>"), "{task}");
    let arguments = "<Arguments>node lab --env-file &quot;C:\\Users\\a b\\node-lab.env&quot;</Arguments>";
    assert!(task.contains(arguments), "{task}");
}

#[test]
fn the_file_of_variables_carries_the_proxy_and_never_a_token() {
    let pair = |n: &str, v: &str| (n.to_string(), v.to_string());
    let env = [
        pair("https_proxy", "http://proxy.example:3128"),
        pair("PODSSH_RELAY_TOKEN", "a-token"),
        pair("NO_PROXY", "a\nb"),
        pair("PODSSH_CACHE_DIR", "/c"),
        pair("PODSSH_OFFLINE", "1"),
        pair("PATH", "/bin"),
        pair("EDITOR", "vi"),
    ];
    let (text, left) = body_of(env.into_iter());
    assert!(text.contains("\nhttps_proxy=http://proxy.example:3128\n"), "{text}");
    assert!(text.contains("\nPODSSH_CACHE_DIR=/c\n"), "{text}");
    for absent in ["a-token", "NO_PROXY", "PODSSH_OFFLINE", "PATH", "EDITOR"] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    assert_eq!(left, ["PODSSH_RELAY_TOKEN"]);
    // What it wrote, it reads back, in the order of the names.
    let read = parse(&text).unwrap();
    assert_eq!(read, [pair("PODSSH_CACHE_DIR", "/c"), pair("https_proxy", "http://proxy.example:3128")]);
    let refused = [("PODSSH_RELAY_TOKEN=x", "is a token"), ("EDITOR=vi", "not a variable"), ("words", "NAME=VALUE")];
    for (bad, why) in refused {
        assert!(parse(bad).unwrap_err().contains(why), "{bad}");
    }
    assert_eq!(parse("# c\n\nPODSSH_RELAY=r.example:443\r\n").unwrap(), [pair("PODSSH_RELAY", "r.example:443")]);
    assert!(SECRET.iter().all(|s| !CARRIED.contains(s)));
}
