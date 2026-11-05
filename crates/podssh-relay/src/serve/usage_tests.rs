//! The tests of a key's counts (T-636): a session charged once, at its end,
//! each way apart; a token minted for anyone charged to no key; a key's 64
//! tokens; the budget turned over by the day; the counts back from the file
//! after a restart; and a write that fails, which leaves the file of before
//! whole.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::serve::brake::Clock;

/// A day of the test, as days since the epoch.
const DAY: u64 = 20_400;
/// A minute before that day ends, in ms since the epoch.
const LATE: u64 = (DAY + 1) * DAY_MS - 60_000;
const KEY_A: &str = "SHA256:the-key-of-a";
const KEY_B: &str = "SHA256:the-key-of-b";
/// A token's end, an hour after [`LATE`].
const ENDS: u64 = LATE + 3_600_000;

/// A clock that the test moves, and the counts' view of it.
fn clock(at: u64) -> (Arc<AtomicU64>, Clock) {
    let now = Arc::new(AtomicU64::new(at));
    let read = now.clone();
    (now, Arc::new(move || read.load(Ordering::SeqCst)))
}

/// The counts on a clock at [`LATE`], with `quota`, in memory.
fn usage(quota: Option<u64>) -> (Arc<AtomicU64>, Usage) {
    let (now, clock) = clock(LATE);
    (now, Usage::open_on(quota, None, clock).unwrap())
}

/// One session of `token`: its frames up and down, then its end.
fn session(usage: &Usage, token: &str, up: &[usize], down: &[usize]) {
    let meter = usage.meter(token, true).expect("a session");
    meter.start();
    up.iter().for_each(|n| meter.up(*n));
    down.iter().for_each(|n| meter.down(*n));
    drop(meter);
}

/// A private scratch directory, removed when the test ends, pass or fail:
/// the gate counts what tests leave.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-usage-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::cache::private_dir(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The plant charges at each frame, in place of the session's end: this
/// test, which counts one session once, fails then.
#[test]
fn one_session_is_charged_once_at_its_end_each_way_apart() {
    let (_, usage) = usage(None);
    assert!(usage.minted("ephm1.a", KEY_A, ENDS));
    let meter = usage.meter("ephm1.a", true).unwrap();
    assert_eq!(meter.key(), Some(KEY_A));
    meter.start();
    for n in [3, 4, 5] {
        meter.up(n);
    }
    meter.down(10);
    meter.down(20);
    assert_eq!(usage.totals(KEY_A), None, "nothing is charged before the session's end");
    meter.settle();
    let today = usage.totals(KEY_A).expect("charged at its end").today;
    assert_eq!((today.day, today.up, today.down, today.sessions), (DAY, 12, 30, 1));
    meter.settle();
    drop(meter);
    assert_eq!(usage.totals(KEY_A).unwrap().today.sessions, 1, "a second settle and the drop charge nothing more");
    // Two keys count apart.
    assert!(usage.minted("ephm1.b", KEY_B, ENDS));
    session(&usage, "ephm1.b", &[7], &[]);
    session(&usage, "ephm1.a", &[], &[1]);
    let (a, b) = (usage.totals(KEY_A).unwrap().today, usage.totals(KEY_B).unwrap().today);
    assert_eq!((a.up, a.down, a.sessions), (12, 31, 2));
    assert_eq!((b.up, b.down, b.sessions), (7, 0, 1));
    // A request that never became a session charges nothing.
    drop(usage.meter("ephm1.b", true).unwrap());
    assert_eq!(usage.totals(KEY_B).unwrap().today.sessions, 1, "a refusal or a dial that failed is no session");
}

#[test]
fn a_token_minted_for_anyone_is_charged_to_no_key() {
    let (_, usage) = usage(None);
    let meter = usage.meter("ephm1.anyone", false).expect("no budget, no key: a session");
    assert_eq!(meter.key(), None);
    meter.start();
    meter.up(1 << 20);
    drop(meter);
    assert_eq!(usage.keys(), 0, "no key holds a count");
    assert_eq!(usage.lines(), vec!["usage: no key carried a byte today or the day before".to_string()]);
    // Under a budget, a role that mints for anyone counts no key, and
    // refuses nothing.
    let (_, budget) = self::usage(Some(16));
    assert!(budget.meter("ephm1.anyone", false).is_ok());
    // A role that mints for keys refuses a token that it holds no more,
    // which would else count against no key.
    assert_eq!(budget.meter("ephm1.anyone", true).err().as_deref(), Some(FORGOTTEN));
}

#[test]
fn a_key_keeps_64_live_tokens_and_one_token_is_one_keys() {
    let (now, usage) = usage(None);
    for i in 0..=TOKENS_A_KEY {
        assert!(usage.minted(&format!("ephm1.{i}"), KEY_A, ENDS));
    }
    assert_eq!(usage.key_of("ephm1.0"), None, "the oldest is forgotten past 64");
    assert_eq!(usage.key_of("ephm1.1").as_deref(), Some(KEY_A));
    assert_eq!(usage.key_of(&format!("ephm1.{TOKENS_A_KEY}")).as_deref(), Some(KEY_A));
    // Two mints in one millisecond make one token: another key's is not
    // taken over, and the same key's is kept once.
    assert!(!usage.minted("ephm1.1", KEY_B, ENDS), "another key's live token");
    assert!(usage.minted("ephm1.1", KEY_A, ENDS), "the same key's, again");
    assert_eq!(usage.key_of("ephm1.1").as_deref(), Some(KEY_A));
    // A token that ended counts for no key, and its place is another's.
    now.store(ENDS, Ordering::SeqCst);
    assert_eq!(usage.key_of("ephm1.1"), None);
    assert!(usage.minted("ephm1.1", KEY_B, ENDS + 1000), "an ended token's digest is free");
    assert_eq!(usage.key_of("ephm1.1").as_deref(), Some(KEY_B));
}

#[test]
fn the_day_turns_the_budget_over() {
    let (now, usage) = usage(Some(100));
    let said = Arc::new(Mutex::new(Vec::new()));
    let lines = said.clone();
    usage.say_to(Arc::new(move |line: &str| lines.lock().unwrap().push(line.to_string())));
    assert!(usage.minted("ephm1.a", KEY_A, ENDS));
    session(&usage, "ephm1.a", &[60], &[39]);
    assert!(usage.meter("ephm1.a", true).is_ok(), "99 of 100 bytes: one more session");
    session(&usage, "ephm1.a", &[1], &[]);
    let refused = usage.meter("ephm1.a", true).err().expect("the budget is spent");
    assert_eq!(refused, "this key's quota of 100 bytes for today is spent");
    assert_eq!(usage.spent(KEY_A), 100);
    // Said once, as the session that spent it ended.
    let spent: Vec<String> = said.lock().unwrap().iter().filter(|l| l.contains("spent its quota")).cloned().collect();
    let want = "spent its quota of 100 bytes for today, 61 bytes up and 39 bytes down in 2 sessions";
    assert_eq!(spent, vec![format!("usage: the key {KEY_A} {want}")]);
    // Another key's budget is its own.
    assert!(usage.minted("ephm1.b", KEY_B, ENDS));
    assert!(usage.meter("ephm1.b", true).is_ok());
    // The next day, in UTC, begins it again; the day before is kept.
    now.store((DAY + 1) * DAY_MS, Ordering::SeqCst);
    assert!(usage.meter("ephm1.a", true).is_ok(), "a new day");
    let totals = usage.totals(KEY_A).unwrap();
    assert_eq!((totals.today.day, totals.today.sessions), (DAY + 1, 0));
    assert_eq!(totals.before.map(|d| (d.day, d.bytes(), d.sessions)), Some((DAY, 100, 2)));
    assert!(usage.lines()[0].ends_with("; the day before, 61 bytes up and 39 bytes down in 2 sessions"));
    // A day later still, nothing of it is left.
    now.store((DAY + 2) * DAY_MS, Ordering::SeqCst);
    assert_eq!(usage.totals(KEY_A).map(|t| t.carried()), Some(false));
    // The words of a budget in whole MiB.
    assert_eq!(quota_words(1024 << 20), "1024 MiB");
}

#[test]
fn a_keys_totals_come_back_from_the_file_after_a_restart() {
    let dir = Scratch::new("restart");
    let file = dir.0.join("usage.json");
    let (now, clock) = clock(LATE);
    let usage = Usage::open_on(Some(1 << 30), Some(file.clone()), clock.clone()).unwrap();
    assert_eq!(usage.save(), Ok(false), "nothing to write yet");
    assert!(usage.minted("ephm1.a", KEY_A, ENDS));
    session(&usage, "ephm1.a", &[1000], &[2000]);
    assert_eq!(usage.save(), Ok(true));
    assert_eq!(usage.save(), Ok(false), "no count moved since");
    // The restart: a new run with no token of before, and the counts back.
    let again = Usage::open_on(Some(1 << 30), Some(file.clone()), clock.clone()).unwrap();
    assert_eq!(again.totals(KEY_A), usage.totals(KEY_A));
    assert_eq!(again.key_of("ephm1.a"), None, "a token ends at a restart");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "a private file: {mode:o}");
    }
    // Two days later the file holds nothing that counts.
    now.store((DAY + 2) * DAY_MS, Ordering::SeqCst);
    let later = Usage::open_on(None, Some(file.clone()), clock).unwrap();
    assert_eq!(later.keys(), 0);
    // A file that is no file of counts stops the start, which never
    // forgets what a key spent.
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    let mut cut = crate::cache::create_new_private(&file).unwrap();
    std::io::Write::write_all(&mut cut, &text.as_bytes()[..text.len() / 2]).unwrap();
    drop(cut);
    let refused = Usage::open(None, Some(file.clone())).err().expect("a file cut short");
    assert!(refused.contains("not a file of counts"), "{refused}");
}

#[test]
fn a_write_that_fails_leaves_the_file_of_before_whole() {
    let dir = Scratch::new("failed-write");
    let file = dir.0.join("usage.json");
    let (_, clock) = clock(LATE);
    let usage = Usage::open_on(None, Some(file.clone()), clock.clone()).unwrap();
    assert!(usage.minted("ephm1.a", KEY_A, ENDS));
    session(&usage, "ephm1.a", &[1], &[1]);
    assert_eq!(usage.save(), Ok(true));
    let before = std::fs::read(&file).unwrap();
    // The writer's private file beside it cannot be made: a directory holds
    // its name.
    let tmp = dir.0.join(format!(".usage.json.{}.tmp", std::process::id()));
    std::fs::create_dir(&tmp).unwrap();
    session(&usage, "ephm1.a", &[5], &[5]);
    let failed = usage.save().err().expect("the write fails");
    assert!(failed.starts_with(&file.display().to_string()), "{failed}");
    assert_eq!(std::fs::read(&file).unwrap(), before, "the file of before, whole");
    let kept = Usage::open_on(None, Some(file.clone()), clock.clone()).unwrap();
    assert_eq!(kept.totals(KEY_A).unwrap().today.sessions, 1, "it reads as it was");
    // The next write takes each count that the failed one held.
    std::fs::remove_dir(&tmp).unwrap();
    assert_eq!(usage.save(), Ok(true), "tried again");
    let after = Usage::open_on(None, Some(file), clock).unwrap();
    assert_eq!(after.totals(KEY_A).unwrap().today.sessions, 2);
}
