//! The drop after the bind (T-629), its system calls replaced: what each
//! start plans, which errors a step takes as done, and which refuse the
//! start; and on Linux, the real calls on a thread of the test, read back
//! from the kernel's own status of that thread.

use super::*;

/// The last capability of the kernel of the tests, as Linux 6 has it.
const LAST: u32 = 40;
/// Each capability up to [`LAST`]: a start as root.
const ALL: u64 = (1u64 << (LAST + 1)) - 1;
/// `CAP_NET_BIND_SERVICE` alone: a file capability on the binary.
const BIND: u64 = 1 << 10;

/// A thread whose sets the test gives; its steps that fail, and with which
/// errno; and each step that the drop made, in order.
struct Fake {
    sets: Option<Sets>,
    bounding: u64,
    fail: Vec<(Step, i32)>,
    /// The errno of each drop from the bounding set, when all fail alike.
    bound_errno: Option<i32>,
    made: Vec<Step>,
}

impl Fake {
    fn with(sets: Option<Sets>) -> Fake {
        Fake { sets, bounding: ALL, fail: Vec::new(), bound_errno: None, made: Vec::new() }
    }

    fn root() -> Fake {
        Fake::with(Some(Sets { effective: ALL, permitted: ALL, inheritable: 0 }))
    }

    fn step(&mut self, step: Step) -> Result<(), i32> {
        self.made.push(step);
        if let (Step::Bound(_), Some(errno)) = (step, self.bound_errno) {
            return Err(errno);
        }
        match self.fail.iter().find(|(s, _)| *s == step) {
            Some((_, errno)) => Err(*errno),
            None => Ok(()),
        }
    }
}

impl Calls for Fake {
    fn sets(&mut self) -> Result<Sets, i32> {
        // ENOSYS, as a sandbox that refuses capget gives it.
        self.sets.ok_or(38)
    }

    fn bounded(&mut self, cap: u32) -> Result<bool, i32> {
        match cap > LAST {
            true => Err(EINVAL),
            false => Ok((self.bounding >> cap) & 1 == 1),
        }
    }

    fn no_new_privs(&mut self) -> Result<(), i32> {
        self.step(Step::NoNewPrivs)
    }

    fn bound_drop(&mut self, cap: u32) -> Result<(), i32> {
        self.step(Step::Bound(cap))
    }

    fn clear(&mut self) -> Result<(), i32> {
        self.step(Step::Clear)
    }
}

fn each_bound() -> impl Iterator<Item = Step> {
    (0..=LAST).map(Step::Bound)
}

#[test]
fn a_thread_with_no_capability_asks_for_no_new_privileges_alone_and_says_nothing() {
    let mut fake = Fake::with(Some(Sets::default()));
    let outcome = drop_with(&mut fake).unwrap();
    assert_eq!(outcome.steps, [Step::NoNewPrivs]);
    assert_eq!(fake.made, [Step::NoNewPrivs], "no capset and no drop from the bounding set");
    assert_eq!(words(&outcome, None, &Ok(3), 1000), None, "the usual start says nothing");
    // Its failure refuses nothing either.
    let mut fake = Fake::with(Some(Sets::default()));
    fake.fail.push((Step::NoNewPrivs, 1));
    assert!(drop_with(&mut fake).is_ok());
}

#[test]
fn a_start_as_root_drops_the_bounding_set_then_empties_each_set() {
    let mut fake = Fake::root();
    let outcome = drop_with(&mut fake).unwrap();
    let want: Vec<Step> = std::iter::once(Step::NoNewPrivs).chain(each_bound()).chain([Step::Clear]).collect();
    assert_eq!(outcome.steps, want);
    assert_eq!(fake.made, want, "the sets emptied last, once the bounding set went");
    assert_eq!(outcome.found.bounding, ALL, "the probe stops at the kernel's last capability");
    let line = words(&outcome, Some(&outcome), &Ok(2), 0).expect("a line");
    assert!(line.contains("the capabilities of its start dropped after the bind, on each of its 2 threads"), "{line}");
    assert!(line.contains("and its bounding set") && line.contains("stays uid 0"), "{line}");
}

#[test]
fn a_file_capability_without_cap_setpcap_keeps_the_bounding_set_and_says_so() {
    let mut fake = Fake::with(Some(Sets { effective: BIND, permitted: BIND, inheritable: 0 }));
    let outcome = drop_with(&mut fake).unwrap();
    assert_eq!(outcome.steps, [Step::NoNewPrivs, Step::Clear]);
    let line = words(&outcome, None, &Ok(2), 1000).expect("a line");
    assert!(line.contains("its bounding set stays, as no CAP_SETPCAP") && !line.contains("uid 0"), "{line}");
}

#[test]
fn a_capability_past_the_kernel_table_is_tolerated() {
    let mut fake = Fake::root();
    fake.fail.push((Step::Bound(LAST), EINVAL));
    assert_eq!(apply(&[Step::Bound(LAST), Step::Clear], true, &mut fake).unwrap(), Vec::<String>::new());
    assert_eq!(fake.made, [Step::Bound(LAST), Step::Clear]);
}

#[test]
fn a_drop_without_cap_setpcap_is_tolerated() {
    let mut fake = Fake::root();
    fake.bound_errno = Some(EPERM);
    let outcome = drop_with(&mut fake).expect("EPERM of the bounding set is taken as done");
    assert_eq!(fake.made.last(), Some(&Step::Clear), "the sets are still emptied");
    assert!(outcome.notes.is_empty(), "{:?}", outcome.notes);
}

#[test]
fn any_other_drop_failure_is_a_config_fault_78() {
    let mut fake = Fake::root();
    fake.fail.push((Step::Bound(3), 5));
    let refused = drop_with(&mut fake).unwrap_err();
    assert_eq!(refused.code, crate::exitmap::sysexits::EX_CONFIG, "{refused:?}");
    assert!(refused.message.contains("prctl(PR_CAPBSET_DROP, 3) after the bind"), "{}", refused.message);
    assert!(!fake.made.contains(&Step::Clear), "no step after the one that failed");
}

#[test]
fn a_failed_capset_is_fatal_even_when_the_set_went_quietly() {
    let mut fake = Fake::root();
    fake.fail.push((Step::Clear, EPERM));
    let refused = drop_with(&mut fake).unwrap_err();
    assert_eq!(refused.code, crate::exitmap::sysexits::EX_CONFIG);
    assert!(refused.message.starts_with("capset after the bind: "), "{}", refused.message);
    assert!(fake.made.contains(&Step::Bound(LAST)), "the bounding set went first: {:?}", fake.made);
}

#[test]
fn an_old_kernel_with_no_flag_of_no_new_privileges_is_said_and_the_drop_goes_on() {
    let mut fake = Fake::root();
    fake.fail.push((Step::NoNewPrivs, EINVAL));
    let outcome = drop_with(&mut fake).unwrap();
    assert_eq!(outcome.notes, ["this kernel has no PR_SET_NO_NEW_PRIVS"]);
    let line = words(&outcome, None, &Ok(2), 1000).unwrap();
    assert!(line.ends_with("(this kernel has no PR_SET_NO_NEW_PRIVS)"), "{line}");
}

#[test]
fn sets_that_cannot_be_read_get_each_step_and_a_failure_is_a_note() {
    let mut fake = Fake::with(None);
    fake.fail.push((Step::Clear, EPERM));
    let outcome = drop_with(&mut fake).expect("no capability known: no refusal");
    assert!(outcome.steps.contains(&Step::Bound(0)) && outcome.steps.last() == Some(&Step::Clear));
    assert_eq!(outcome.notes.len(), 1, "{:?}", outcome.notes);
    assert!(outcome.notes[0].starts_with("capset: "), "{:?}", outcome.notes);
    let line = words(&outcome, None, &Err("/proc/self/task: gone".into()), 1000).unwrap();
    assert!(line.contains("not read (capget: ") && line.contains("each asked to go after the bind"), "{line}");
    assert!(line.contains("its threads not read again (/proc/self/task: gone)"), "{line}");
}

#[test]
fn the_first_thread_that_held_a_capability_is_said_too() {
    let mut none = Fake::with(Some(Sets::default()));
    let here = drop_with(&mut none).unwrap();
    let mut root = Fake::root();
    let first = drop_with(&mut root).unwrap();
    let line = words(&here, Some(&first), &Err("no /proc".into()), 0).unwrap();
    assert!(line.contains("dropped after the bind, on this thread and the first"), "{line}");
}

#[test]
fn the_status_of_a_thread_gives_each_set_and_its_flags() {
    let text = "Name:\tpodssh\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t0000000000000400\n\
                CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\n";
    let sets = status_sets(text).unwrap();
    assert_eq!(sets, Sets { effective: BIND, permitted: ALL, inheritable: 0 });
    assert_eq!(status_value(text, "CapBnd", 16), Some(ALL));
    assert_eq!(status_value(text, "NoNewPrivs", 10), Some(1));
    assert_eq!(status_value(text, "Missing", 10), None);
    assert_eq!(status_sets("Name:\tpodssh\n"), None);
}

/// The real calls, on a thread of the test alone: each set and flag acts on
/// the calling thread, so the other tests keep theirs.
#[cfg(target_os = "linux")]
#[test]
fn a_thread_drops_what_it_held_and_the_kernel_reads_none_left() {
    use super::super::harden_sys::Sys;
    let read = || std::fs::read_to_string("/proc/thread-self/status").ok();
    let checked = std::thread::spawn(move || {
        let Some(before) = read() else { return None };
        let outcome = drop_with(&mut Sys).expect("the drop on this thread");
        Some((before, outcome, read().expect("the status after the drop")))
    });
    let Some((before, outcome, after)) = checked.join().unwrap() else {
        eprintln!("did not run: no /proc/thread-self/status here");
        return;
    };
    let value = |text: &str, name: &str, radix| status_value(text, name, radix).unwrap();
    assert_eq!((value(&after, "CapEff", 16), value(&after, "CapPrm", 16)), (0, 0), "{after}");
    assert_eq!(value(&after, "NoNewPrivs", 10), 1, "{after}");
    let held = value(&before, "CapEff", 16);
    if (held >> CAP_SETPCAP) & 1 == 1 {
        assert_eq!(value(&after, "CapBnd", 16), 0, "with CAP_SETPCAP the bounding set goes: {after}");
    } else {
        assert_eq!(value(&after, "CapBnd", 16), value(&before, "CapBnd", 16), "{after}");
    }
    let none = status_sets(&before).expect("the sets before the drop").none();
    assert_eq!(outcome.found.holds(), !none, "the probe read what the kernel says: {before}");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn a_start_elsewhere_drops_nothing_and_says_nothing() {
    assert_eq!(give_up(), Ok(None));
    assert!(!dropped());
}
