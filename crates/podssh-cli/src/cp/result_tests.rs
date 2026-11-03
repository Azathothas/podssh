//! The tests of the record of a copy (T-486): the bytes of each file each
//! way, the class of each failure, and the keys of each verb's object.

use super::*;

fn done(source: &str, bytes: u64) -> Done {
    Done { source: source.into(), bytes, verified_by: "sha256sum".into(), ..Done::default() }
}

#[test]
fn a_file_moves_its_bytes_and_a_rename_or_a_link_none() {
    assert_eq!(moved(&done("a", 70)), 70);
    let renamed = Done { verified_by: "rename".into(), ..done("b", 70) };
    let linked = Done { verified_by: "a hard link to a".into(), ..done("c", 70) };
    assert_eq!((moved(&renamed), moved(&linked)), (0, 0));
    let delta = Done { delta: Some(Delta::Sent { blocks: 5, sent: 1, bytes: 1 << 20 }), ..done("d", 5 << 20) };
    assert_eq!(moved(&delta), 1 << 20, "with --delta, the blocks that went");
}

#[test]
fn the_files_go_each_way_by_the_copy_s_direction() {
    let mut outcome = Outcome::default();
    outcome.add(done("a", 3));
    outcome.add(Done { removed: Some(true), ..done("b", 4) });
    outcome.deleted.push("gone".into());
    outcome.unchanged = 2;
    let up = Copied::of(&outcome, Direction::Up);
    assert_eq!((up.sent, up.unchanged, up.deleted, up.up, up.down), (2, 2, 1, 7, 0));
    assert_eq!(up.removed, ["b"]);
    assert_eq!((Copied::of(&outcome, Direction::Down).up, Copied::of(&outcome, Direction::Down).down), (0, 7));
    // Within one server, no byte came through this host; through it, both ways.
    assert_eq!(Copied::of(&outcome, Direction::Across).up, 0);
    outcome.through = true;
    let across = Copied::of(&outcome, Direction::Across);
    assert_eq!((across.up, across.down), (7, 7));
}

#[test]
fn each_failure_has_its_class() {
    let none = Facts::default();
    let logged_in = Facts { method: Some("publickey"), ..Facts::default() };
    let refused_key = Facts { failure: Some("auth"), ..Facts::default() };
    let of = |fault, cause| Failed { fault, message: "x".into(), cause };
    assert_eq!(class(&of(Fault::NoInput, Cause::Answer), &none), "copy");
    assert_eq!(class(&of(Fault::CantCreate, Cause::Answer), &none), "copy");
    assert_eq!(class(&of(Fault::SessionFault, Cause::Digests), &none), "verify");
    assert_eq!(class(&of(Fault::SessionFault, Cause::Broke), &none), "session");
    assert_eq!(class(&of(Fault::TimedOut, Cause::Answer), &none), "timeout");
    assert_eq!(class(&of(Fault::RelayUnreachable, Cause::Answer), &none), "connect");
    assert_eq!(class(&of(Fault::Auth, Cause::Answer), &refused_key), "auth");
    assert_eq!(
        class(&of(Fault::Auth, Cause::Answer), &Facts { failure: Some("host-key"), ..none.clone() }),
        "host-key"
    );
    // Past the login: a server with neither SFTP nor a copy by exec.
    assert_eq!(class(&of(Fault::RelayUnreachable, Cause::Answer), &logged_in), "copy");
}

/// The keys of each verb's object, and `bytes` of a copy null: its bytes
/// are `transferred`, as `bytes` keeps the meaning of `ssh`'s.
#[test]
fn each_verb_gives_its_keys() {
    let copied = Copied { sent: 1, up: 9, removed: vec!["a".into()], ..Copied::default() };
    let did = Did { copied: Some(copied), ..Did::default() };
    let record = Record::default();
    let cp = copy_object("cp", 0, Duration::from_millis(5), &record, &did);
    assert_eq!(
        (&cp["verb"], &cp["exit"], &cp["failure"], &cp["bytes"]),
        (&json!("cp"), &json!(0), &Value::Null, &Value::Null)
    );
    assert_eq!(cp["files"], json!({ "sent": 1, "unchanged": 0, "skipped": 0, "deleted": 0, "failed": 0 }));
    assert_eq!(cp["transferred"], json!({ "up": 9, "down": 0 }));
    assert!(cp.get("removed").is_none(), "only mv names what it removed");
    let mv = copy_object("mv", 0, Duration::ZERO, &record, &did);
    assert_eq!(mv["removed"], json!(["a"]));
    // A refusal before the copy: its class from the exit, its words, no files.
    let refused = Did { error: Some("give a source and a destination".into()), ..Did::default() };
    let usage = copy_object("scp", 64, Duration::ZERO, &record, &refused);
    assert_eq!(
        (&usage["failure"], &usage["files"], &usage["transferred"]),
        (&json!("usage"), &Value::Null, &Value::Null)
    );
    assert_eq!(usage["error"], json!("give a source and a destination"));
    // sftp has no files of its own.
    let sftp = object("sftp", 0, Duration::ZERO, &record, &Did::default());
    assert!(sftp.get("files").is_none() && sftp.get("transferred").is_none());
}

#[test]
fn the_relay_names_its_sessions() {
    let facts = Facts { relay_host: Some("relay.example.org".into()), relay_sessions: 2, ..Facts::default() };
    let record = Record { facts, ..Record::default() };
    let cp = copy_object("cp", 0, Duration::ZERO, &record, &Did::default());
    assert_eq!(cp["relay"], json!({ "host": "relay.example.org", "close_code": null, "reason": null, "sessions": 2 }));
}
