//! The jobs of a host as the far script lists them (T-193), and as `podssh
//! job list` prints them: one line for each job, in the order of their
//! start, with its ID, its state, its exit status and its command; or, with
//! `--json`, one object (T-197).

/// One job of a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The 8 hex digits that name it.
    pub id: String,
    /// When it was started, in milliseconds since 1970, by the clock of the
    /// client that started it.
    pub started_ms: u64,
    /// `queued` (T-197), `running`, `done`, or `lost` (no status and no
    /// session: the host or tmux's server stopped).
    pub state: String,
    /// The exit status, once it ended; 128 + N for a signal, as sh gives it.
    pub status: Option<i32>,
    /// The command, its words joined with spaces.
    pub command: String,
}

/// The name of a job's directory: the time of its start, 16 digits of
/// milliseconds so that the names sort in that order, then its ID.
pub fn dir_name(started_ms: u64, id: &str) -> String {
    format!("{started_ms:016}-{id}")
}

/// A line `job NAME STATE STATUS COMMAND` of the far script, its fields
/// apart by tabs; `None` for another line, or one that is not whole.
pub fn parse_line(line: &str) -> Option<Job> {
    let mut fields = line.splitn(5, '\t');
    if fields.next()? != "job" {
        return None;
    }
    let (started, id) = fields.next()?.split_once('-')?;
    let state = fields.next()?.to_string();
    let status = match fields.next()? {
        "-" => None,
        text => Some(text.trim().parse().ok()?),
    };
    let command = fields.next()?.to_string();
    Some(Job { id: id.to_string(), started_ms: started.parse().ok()?, state, status, command })
}

/// The jobs of an answer, in the order of their start: the far script lists
/// them in the order of their names. `None` when the answer did not end,
/// as a list cut by a lost connection does.
pub fn parse(lines: &[String]) -> Option<Vec<Job>> {
    if lines.last().map(String::as_str) != Some("end") {
        return None;
    }
    let mut jobs: Vec<Job> = lines.iter().filter_map(|l| parse_line(l.as_str())).collect();
    jobs.sort_by(|a, b| a.started_ms.cmp(&b.started_ms).then_with(|| a.id.cmp(&b.id)));
    Some(jobs)
}

/// The lines that `podssh job list` prints: `ID  STATE  STATUS  COMMAND`,
/// a status of `-` while there is none.
pub fn text(jobs: &[Job]) -> String {
    let mut out = String::new();
    for job in jobs {
        let status = job.status.map_or_else(|| "-".to_string(), |s| s.to_string());
        out.push_str(&format!("{}  {:<7}  {:>3}  {}\n", job.id, job.state, status, job.command));
    }
    out
}

/// The list as one JSON object, for `--json` (T-197): the host as it was
/// named, and each job with its ID, state, status (null while there is
/// none), the time of its start and its command.
pub fn json(host: &str, jobs: &[Job]) -> serde_json::Value {
    let jobs: Vec<serde_json::Value> = jobs
        .iter()
        .map(|j| {
            serde_json::json!({
                "id": j.id,
                "state": j.state,
                "status": j.status,
                "started_ms": j.started_ms,
                "command": j.command,
            })
        })
        .collect();
    serde_json::json!({ "host": host, "jobs": jobs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_json_list_is_one_object_with_each_job() {
        let jobs = vec![Job {
            id: "aaaaaaaa".into(),
            started_ms: 7,
            state: "queued".into(),
            status: None,
            command: "make".into(),
        }];
        let value = json("web1", &jobs);
        assert_eq!(value["host"], "web1");
        assert_eq!(value["jobs"][0]["id"], "aaaaaaaa");
        assert_eq!(value["jobs"][0]["state"], "queued");
        assert!(value["jobs"][0]["status"].is_null());
        assert_eq!(value["jobs"][0]["started_ms"], 7);
    }

    #[test]
    fn a_line_of_the_far_script_is_one_job() {
        let job = parse_line("job\t0001791234567890-abcd1234\tdone\t3\tmake\ttest").unwrap();
        assert_eq!(job.id, "abcd1234");
        assert_eq!(job.started_ms, 1_791_234_567_890);
        assert_eq!((job.state.as_str(), job.status), ("done", Some(3)));
        assert_eq!(job.command, "make\ttest", "a tab of the command stays");
        let running = parse_line("job\t0000000000000001-00000000\trunning\t-\tsleep 300").unwrap();
        assert_eq!(running.status, None);
        for bad in ["end", "job\tnodash\tdone\t0\tx", "job\t1-a\tdone\tx\ty", "job\t1-a\tdone\t0"] {
            assert_eq!(parse_line(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_list_is_whole_and_in_the_order_of_the_starts() {
        let lines: Vec<String> = [
            "job\t0000000000000002-bbbbbbbb\trunning\t-\tsleep 300",
            "job\t0000000000000001-aaaaaaaa\tdone\t0\techo hi",
            "end",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let jobs = parse(&lines).unwrap();
        assert_eq!(jobs.iter().map(|j| j.id.as_str()).collect::<Vec<_>>(), ["aaaaaaaa", "bbbbbbbb"]);
        assert_eq!(text(&jobs), "aaaaaaaa  done       0  echo hi\nbbbbbbbb  running    -  sleep 300\n");
        assert_eq!(parse(&lines[..2]), None, "no end: the list was cut");
        assert_eq!(dir_name(1, "aaaaaaaa"), "0000000000000001-aaaaaaaa");
    }
}
