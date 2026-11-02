//! The local user's name (T-500): the variables in their order, then the
//! effective uid's entry of a passwd file, then `root` for uid 0; and the
//! words of the refusal and of `-v`.

use super::*;

const PASSWD_TEXT: &str = "\
# a comment, and a line of NIS, are no entries
+::1000:1000:::
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
agent:x:1000:1000:An Agent,,,:/home/agent:/bin/bash
second:x:1000:1000::/home/second:/bin/sh
short:x:1001:1001
blank name:x:1002:1002::/home/b:/bin/sh
late:x:1002:1002::/home/late:/bin/sh
";

#[test]
fn the_entry_of_the_uid_names_the_user_and_the_first_one_wins() {
    assert_eq!(passwd_name(PASSWD_TEXT, 1000).as_deref(), Some("agent"), "the first entry, not the NIS line");
    assert_eq!(passwd_name(PASSWD_TEXT, 0).as_deref(), Some("root"));
    assert_eq!(passwd_name(PASSWD_TEXT, 1).as_deref(), Some("daemon"));
    // A name with a blank is no login's: the next entry of the uid is.
    assert_eq!(passwd_name(PASSWD_TEXT, 1002).as_deref(), Some("late"));
}

#[test]
fn no_line_for_the_uid_too_few_fields_or_an_empty_file_give_no_name() {
    assert_eq!(passwd_name(PASSWD_TEXT, 4242), None, "no line for the uid");
    assert_eq!(passwd_name(PASSWD_TEXT, 1001), None, "a line with too few fields");
    assert_eq!(passwd_name("", 1000), None, "an empty file");
    assert_eq!(passwd_name("agent:x:1000x:1000::/h:/bin/sh\n", 1000), None, "a uid field that is no number");
    assert_eq!(passwd_name("agent:x:1000:1000::/h:/bin/sh\r\n", 1000).as_deref(), Some("agent"), "CRLF");
}

/// The variables of the process, as a test gives them.
fn vars(set: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    let set = set.to_vec();
    move |name| set.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
}

fn entry(name: Option<&'static str>) -> impl Fn(u32) -> Option<String> {
    move |_| name.map(str::to_string)
}

#[test]
fn podssh_user_comes_first_then_user_logname_and_username() {
    let all = vars(&[("PODSSH_USER", "p"), ("USER", "u"), ("LOGNAME", "l"), ("USERNAME", "w")]);
    let got = local_user_from(&all, Some(1000), &entry(Some("agent")));
    assert_eq!(got, LocalUser { name: Some("p".into()), from: UserFrom::Variable });
    let three = vars(&[("USER", "u"), ("LOGNAME", "l"), ("USERNAME", "w")]);
    assert_eq!(local_user_from(&three, Some(1000), &entry(Some("agent"))).name.as_deref(), Some("u"));
    let two = vars(&[("LOGNAME", "l"), ("USERNAME", "w")]);
    assert_eq!(local_user_from(&two, Some(1000), &entry(Some("agent"))).name.as_deref(), Some("l"));
    // A blank variable is not set: the next one names the user.
    let blank = vars(&[("PODSSH_USER", " "), ("USER", ""), ("USERNAME", "w")]);
    assert_eq!(local_user_from(&blank, Some(1000), &entry(Some("agent"))).name.as_deref(), Some("w"));
}

#[test]
fn with_no_variable_the_entry_names_the_user_and_uid_0_with_none_is_root() {
    let none = vars(&[]);
    let got = local_user_from(&none, Some(1000), &entry(Some("agent")));
    assert_eq!(got, LocalUser { name: Some("agent".into()), from: UserFrom::Entry { uid: 1000 } });
    let root = local_user_from(&none, Some(0), &entry(None));
    assert_eq!(root, LocalUser { name: Some("root".into()), from: UserFrom::Root });
    let missing = local_user_from(&none, Some(1000), &entry(None));
    assert_eq!(missing, LocalUser { name: None, from: UserFrom::Missing { uid: Some(1000) } });
    // A system with no uids reads no entry.
    let windows = local_user_from(&none, None, &entry(Some("never")));
    assert_eq!(windows, LocalUser { name: None, from: UserFrom::Missing { uid: None } });
}

#[test]
fn the_refusal_says_what_was_read_and_each_way_to_give_a_name() {
    let env = Env { user: None, user_from: UserFrom::Missing { uid: Some(1000) }, ..Env::default() };
    let why = env.login_user(None).unwrap_err();
    assert_eq!(
        why,
        format!(
            "no user name: PODSSH_USER, USER, LOGNAME and USERNAME are not set, and uid 1000 has no entry in \
             {DATABASE}: give user@host or -l USER, set PODSSH_USER or USER, or set User in ssh_config"
        )
    );
    // A jump host: its user is the hop's, which -l does not give.
    let why = env.login_user(Some("hop.example")).unwrap_err();
    assert!(why.starts_with("no user name for the jump host hop.example: "), "{why}");
    assert!(why.contains("give one as user@host in -J, set PODSSH_USER or USER") && !why.contains("-l"), "{why}");
    // A name that is there is the login.
    let named = Env { user: Some("agent".into()), user_from: UserFrom::Entry { uid: 1000 }, ..Env::default() };
    assert_eq!(named.login_user(None).as_deref(), Ok("agent"));
}

#[test]
fn v_says_where_the_name_came_from_when_no_variable_gave_it() {
    let entry = Env { user: Some("agent".into()), user_from: UserFrom::Entry { uid: 1000 }, ..Env::default() };
    assert_eq!(
        entry.user_note(),
        Some(format!(
            "the local user name agent is uid 1000's entry in {DATABASE}, as PODSSH_USER, USER, LOGNAME and \
             USERNAME are not set"
        ))
    );
    let root = Env { user: Some("root".into()), user_from: UserFrom::Root, ..Env::default() };
    assert!(root.user_note().is_some_and(|n| n.contains("uid 0's by convention")), "{:?}", root.user_note());
    let variable = Env { user: Some("u".into()), user_from: UserFrom::Variable, ..Env::default() };
    assert_eq!(variable.user_note(), None, "a variable needs no line");
    assert_eq!(Env::default().user_note(), None, "no name, no line");
}
