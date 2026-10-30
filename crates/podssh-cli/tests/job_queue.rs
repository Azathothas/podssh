//! The queue of `podssh job` (T-197) against the test's SSH server, whose
//! commands run in sh as on a POSIX host (`job_harness`), with tmux. Three
//! jobs with one slot, `sleep 3; echo J` twice, then `exit 5`: no list shows
//! more than one running, and the first that shows one running shows the
//! two others queued (the planted defect, a runner that ignores the slots,
//! runs more); `wait` on the last exits 5 within 30 s; `fetch` gets an `out`
//! that holds J, and with `--files` the files of a pattern under `files/`;
//! `--json` gives one object. A list of two hosts sends a submit to the one
//! with fewer jobs queued or running. With no tmux on this host, the tests
//! say so and pass.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use std::time::{Duration, Instant};

use job_harness::Far;

/// `podssh job submit HOST --slots 1 -- COMMAND`: the ID that it printed.
fn submit(far: &Far, command: &str) -> String {
    let (code, out, err) = far.job("submit", &["--slots", "1", "--", command]);
    assert_eq!(code, 0, "{err}");
    let id = out.trim().to_string();
    assert!(id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{out}");
    id
}

/// The state of `id` in a list, empty when it is not there.
fn state_in(list: &str, id: &str) -> String {
    let line = list.lines().find(|l| l.starts_with(id)).unwrap_or("");
    line.split_whitespace().nth(1).unwrap_or("").to_string()
}

#[test]
fn three_jobs_with_one_slot_run_one_at_a_time_and_the_last_gives_5() {
    let Some(far) = Far::with_tmux("queue") else { return };
    let submitted = Instant::now();
    let ids = [submit(&far, "sleep 3; echo J"), submit(&far, "sleep 3; echo J"), submit(&far, "exit 5")];
    // The slot holds at each look until the last job ended, not only at the
    // first: a runner that ignores it is seen with two running, or ends the
    // three in the time of one.
    let (mut seen, until) = (false, Instant::now() + Duration::from_secs(30));
    loop {
        let (code, list, err) = far.job("list", &[]);
        assert_eq!(code, 0, "{err}");
        let states: Vec<String> = ids.iter().map(|id| state_in(&list, id)).collect();
        let count = |s: &str| states.iter().filter(|x| x.as_str() == s).count();
        assert!(count("running") <= 1, "one slot, and more jobs run: {list}");
        if count("running") == 1 && count("queued") == 2 {
            seen = true;
        }
        if count("done") == 3 || Instant::now() >= until {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(seen, "no list showed the first job running while the two others waited");
    // Two jobs of 3 s, one after the other, came before the last.
    assert!(submitted.elapsed() >= Duration::from_millis(5500), "the queue took {:?}", submitted.elapsed());
    let began = Instant::now();
    let (code, _, err) = far.job("wait", &[ids[2].as_str(), "--timeout", "30s"]);
    assert_eq!(code, 5, "{err}");
    assert!(began.elapsed() < Duration::from_secs(30), "{:?}", began.elapsed());
    let (_, list, _) = far.job("list", &[]);
    for id in &ids {
        assert_eq!(state_in(&list, id), "done", "{list}");
    }
    let got = far.local.join("got");
    let (code, _, err) = far.job("fetch", &[ids[0].as_str(), got.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read_to_string(got.join("out")).unwrap(), "J\n");
    // The list as one object.
    let (code, json, err) = far.job("list", &["--json"]);
    assert_eq!(code, 0, "{err}");
    let value: serde_json::Value = serde_json::from_str(&json).expect("one JSON object");
    assert_eq!(value["host"], far.host().as_str());
    assert_eq!(value["jobs"].as_array().map(Vec::len), Some(3), "{json}");
    assert_eq!(value["jobs"][2]["status"], 5, "in the order of the submits: {json}");
}

#[test]
fn fetch_gets_the_files_of_a_pattern_and_waits_for_the_end() {
    let Some(far) = Far::with_tmux("fetch") else { return };
    let id = far.start("sleep 2; mkdir -p made; echo F > made/f.txt; echo O");
    // Not ended yet: its output is not whole, and fetch says so with 75.
    let (code, _, err) = far.job("fetch", &[id.as_str(), "--files", "made/*"]);
    assert_eq!(code, 75, "{err}");
    assert!(err.contains("podssh job wait"), "{err}");
    let (code, _, err) = far.job("wait", &[id.as_str()]);
    assert_eq!(code, 0, "{err}");
    let got = far.local.join("got");
    let (code, _, err) = far.job("fetch", &[id.as_str(), got.to_str().unwrap(), "--files", "made/*"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read_to_string(got.join("out")).unwrap(), "O\n");
    assert_eq!(std::fs::read_to_string(got.join("files").join("made").join("f.txt")).unwrap(), "F\n");
}

#[test]
fn a_submit_to_a_list_goes_to_the_host_with_fewer_jobs() {
    let (Some(busy), Some(idle)) = (Far::with_tmux("busy"), Far::with_tmux("idle")) else { return };
    submit(&busy, "sleep 60");
    submit(&busy, "sleep 60");
    let both = format!("{},{}", busy.host(), idle.host());
    // From the idle host's home, which takes both keys.
    let (code, out, err) = idle.podssh("job", &["submit", both.as_str(), "--", "sleep 60"]);
    assert_eq!(code, 0, "{err}");
    let (host, id) = out.trim().split_once(' ').expect("HOST ID, from a list of hosts");
    assert_eq!(host, idle.host(), "{out}");
    let line = idle.line_of(id, Duration::from_secs(10), |l| l.contains("running"));
    assert!(line.is_some_and(|l| l.contains("running")), "the runner of the idle host starts it");
}
