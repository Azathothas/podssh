//! The record of a run of `podssh run` (T-486): the keys of the copies'
//! (`crate::cp::result`), `files` and `transferred` of its copy, and the
//! `status`, `signal`, `end` and `bytes` of its command as `ssh
//! --result-file` gives them. Each comes from the run's own scope, which
//! the copy's connections and the command's session wrote; the copy writes
//! no status, end or bytes, as SFTP takes no channel of a session.

use std::time::Duration;

use podssh_ssh::outcome::Record;
use serde_json::Value;

use crate::cp::result::Did;
use crate::ssh::result::{bytes, signal};

/// What a run did, for its record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Ran {
    /// What its copy did, and the class and words of a failure.
    pub did: Did,
    /// The command's session was opened: its bytes are counted.
    pub command: bool,
}

/// The object of a run that exits with `exit` after `took`.
pub(super) fn object(exit: i32, took: Duration, record: &Record, ran: &Ran) -> Value {
    let mut object = crate::cp::result::object("run", exit, took, record, &ran.did);
    let f = &record.facts;
    // A command that ended with a status or a signal gave the run its exit:
    // no failure, as `ssh`'s record says of it, not the class of an exit
    // with no session.
    if ran.command && ran.did.failure.is_none() && (f.status.is_some() || f.signal.is_some()) {
        object.insert("failure".into(), Value::Null);
    }
    object.insert("status".into(), f.status.into());
    object.insert("signal".into(), signal(f));
    object.insert("end".into(), f.end.into());
    object.insert("bytes".into(), ran.command.then(|| bytes(record)).into());
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use podssh_ssh::outcome::Facts;
    use serde_json::json;

    use super::*;
    use crate::cp::result::Copied;

    #[test]
    fn a_run_gives_its_command_s_end_and_its_copy() {
        let facts = Facts { status: Some(3), end: Some("status"), ..Facts::default() };
        let record = Record { stdin: 0, stdout: 4, stderr: 0, facts };
        let copied = Copied { sent: 1, unchanged: 2, up: 10, ..Copied::default() };
        let ran = Ran { did: Did { copied: Some(copied), ..Did::default() }, command: true };
        let r = object(3, Duration::ZERO, &record, &ran);
        assert_eq!(
            (&r["verb"], &r["exit"], &r["status"], &r["end"]),
            (&json!("run"), &json!(3), &json!(3), &json!("status"))
        );
        assert_eq!((&r["failure"], &r["signal"]), (&Value::Null, &Value::Null), "the status is the command's");
        assert_eq!(r["files"]["unchanged"], json!(2));
        assert_eq!(r["transferred"], json!({ "up": 10, "down": 0 }));
        assert_eq!(r["bytes"], json!({ "stdin": 0, "stdout": 4, "stderr": 0 }));
        // A copy that failed ran no command: no bytes, and the copy's class.
        let failed = Did { failure: Some("copy"), error: Some("x: not written".into()), ..Did::default() };
        let r = object(255, Duration::ZERO, &Record::default(), &Ran { did: failed, command: false });
        assert_eq!((&r["failure"], &r["bytes"], &r["status"]), (&json!("copy"), &Value::Null, &Value::Null));
    }
}
