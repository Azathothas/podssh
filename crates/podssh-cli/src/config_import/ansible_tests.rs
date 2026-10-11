//! The INI inventory, one rule at a time; `tests/config_import.rs` holds
//! what Ansible itself made of a whole inventory.

use super::*;

fn names(pattern: &str) -> Vec<String> {
    expand(pattern).unwrap_or_else(|e| panic!("{pattern}: {e}")).0
}

#[test]
fn a_range_names_each_host_and_keeps_the_width() {
    assert_eq!(names("www[01:03].example.org"), ["www01.example.org", "www02.example.org", "www03.example.org"]);
    assert_eq!(names("db-[a:c]"), ["db-a", "db-b", "db-c"]);
    assert_eq!(names("n[1:9:4]"), ["n1", "n5", "n9"]);
    assert_eq!(names("r[1:2]c[1:2]"), ["r1c1", "r1c2", "r2c1", "r2c2"]);
    assert_eq!(names("plain.example.org"), ["plain.example.org"]);
    for bad in ["www[01:03.example.org", "a[1:2:3:4]", "a[3:1]", "a[x:10]", "a[1:9:0]"] {
        assert!(expand(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_port_follows_one_colon_outside_brackets() {
    assert_eq!(expand("web2.example.org:2222").unwrap(), (vec!["web2.example.org".into()], Some("2222".into())));
    assert_eq!(expand("www[1:2]:22").unwrap().1, Some("22".into()));
    // An IPv6 address has more than one colon: no port.
    assert_eq!(expand("2001:db8::1").unwrap(), (vec!["2001:db8::1".into()], None));
}

#[test]
fn a_host_line_splits_as_a_shell_does() {
    assert_eq!(split("h a=1 b='two words' c=\"x\" # a comment").unwrap(), ["h", "a=1", "b=two words", "c=x"]);
    assert!(split("h a='open").is_err());
}

#[test]
fn a_hosts_variables_come_from_all_its_groups_then_itself() {
    let text = "solo\n\
                [web]\nw1 ansible_user=own\nw2\n\
                [web:vars]\nansible_port=2200\n\
                [prod:children]\nweb\n\
                [prod:vars]\nansible_user=produser\nansible_port=2201\n\
                [all:vars]\nansible_user=admin\nansible_password=x\n";
    let hosts = read(text).unwrap();
    let get = |name: &str, var: &str| {
        let host = hosts.iter().find(|h| h.name == name).unwrap_or_else(|| panic!("{name}"));
        host.vars.get(var).cloned()
    };
    assert_eq!(hosts.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), ["solo", "w1", "w2"]);
    assert_eq!(get("solo", "ansible_user").as_deref(), Some("admin"));
    assert_eq!(get("w1", "ansible_user").as_deref(), Some("own"));
    assert_eq!(get("w2", "ansible_user").as_deref(), Some("produser"), "a parent group beats all");
    assert_eq!(get("w2", "ansible_port").as_deref(), Some("2200"), "a child group beats its parent");
    assert_eq!(hosts[1].groups, ["web"]);
}

#[test]
fn a_bad_line_is_refused_with_its_number() {
    assert!(read("[web]\nh a=1\n[web:vars]\nnot a pair\n").unwrap_err().starts_with("4: "));
    assert!(read("[web:nonsense]\nh\n").unwrap_err().starts_with("1: "));
    assert!(read("h a='open\n").unwrap_err().starts_with("1: "));
}
