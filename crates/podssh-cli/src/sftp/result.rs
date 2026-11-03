//! The record of a run of `podssh sftp` (T-486): the keys of the copies'
//! (`crate::cp::result`), `commands` (run and failed), and
//! `failed_command`, the line of the batch whose failure ended it, as the
//! user wrote it. `bytes` is null, as for `cp`: no command's streams.

use std::time::Duration;

use podssh_ssh::outcome::Record;
use serde_json::{json, Value};

use crate::cp::result::{class, Did};
use crate::cp::transfer::Failed;

/// What a run of `sftp` did, for its record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Tally {
    /// The class and the words of its failure.
    pub did: Did,
    /// The commands that it ran, and those that failed.
    pub run: usize,
    pub failed: usize,
    /// The line of the batch whose failure ended it.
    pub failed_command: Option<String>,
}

impl Tally {
    /// The failure that ended the run: its class, as the connection's
    /// record of this run says it, its words, and the line of the batch.
    pub(super) fn ended_by(&mut self, failed: &Failed, line: Option<&str>) {
        let facts = podssh_ssh::outcome::record().facts;
        self.did.failure = Some(class(failed, &facts));
        self.did.error = Some(failed.message.clone());
        if let Some(line) = line {
            self.failed_command = Some(line.trim().to_string());
        }
    }
}

/// The object of a run that exits with `exit` after `took`.
pub(super) fn object(exit: i32, took: Duration, record: &Record, tally: &Tally) -> Value {
    let mut object = crate::cp::result::object("sftp", exit, took, record, &tally.did);
    object.insert("commands".into(), json!({ "run": tally.run, "failed": tally.failed }));
    object.insert("failed_command".into(), tally.failed_command.clone().into());
    object.insert("bytes".into(), Value::Null);
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exitmap::Fault;

    #[test]
    fn the_record_names_the_command_that_ended_the_batch() {
        let mut tally = Tally { run: 3, failed: 2, ..Tally::default() };
        tally.ended_by(&Failed::new(Fault::NoInput, "far/x: no such file".into()), Some("  get far/x  "));
        let r = object(66, Duration::ZERO, &Record::default(), &tally);
        assert_eq!((&r["verb"], &r["exit"], &r["failure"]), (&json!("sftp"), &json!(66), &json!("copy")));
        assert_eq!((&r["commands"], &r["failed_command"]), (&json!({ "run": 3, "failed": 2 }), &json!("get far/x")));
        assert_eq!((&r["error"], &r["bytes"]), (&json!("far/x: no such file"), &Value::Null));
        assert!(r.get("files").is_none(), "its unit is the command");
    }
}
