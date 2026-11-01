//! The heartbeat of a run of `--restart` (T-394). A run that hangs (a
//! deadlock, a stopped process, a runtime that no longer polls) stays alive
//! to each check of the supervisor and of `podssh detached`, and serves
//! nothing. So each run that a supervisor starts touches `NAME.alive`, in the
//! directory of the runs, each [`BEAT`] from a task of its own runtime, which
//! beats only while that runtime polls; and the supervisor, which reads the
//! file's time each [`CHECK`], ends a run whose file has not changed for
//! [`HUNG`] and starts it again.
//!
//! The supervisor compares the file's times with each other, never with its
//! clock, so a clock that jumps ends no run; it watches a run only once the
//! run has beaten, so a run that cannot write the file (a full disk, no
//! cache) is never ended for it, as a run ended each 90 s would lock its
//! server out.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use super::lock;

/// How often a run touches its file.
pub const BEAT: Duration = Duration::from_secs(10);
/// How often the supervisor reads it.
pub const CHECK: Duration = Duration::from_secs(10);
/// A run whose file did not change for this long is ended and started
/// again: nine beats missed.
pub const HUNG: Duration = Duration::from_secs(90);

/// The heartbeat's file of the run `name` in `dir`.
pub fn alive_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.alive"))
}

/// In a run that a supervisor started: its heartbeat, a task of `handle`'s
/// runtime. Elsewhere nothing.
pub fn keep(handle: &tokio::runtime::Handle) {
    if !super::is_child() || std::env::var_os(lock::SUPERVISOR_VARIABLE).is_none() {
        return;
    }
    let Some(name) = lock::name() else { return };
    let Some(path) = lock::dir().map(|dir| alive_path(&dir, name)) else { return };
    handle.spawn(async move {
        loop {
            touch(&path);
            tokio::time::sleep(BEAT).await;
        }
    });
}

/// The file's time set to now, the file made when missing. Its time, not
/// its bytes: a disk that is full still takes a new time.
fn touch(path: &Path) {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if let Ok(file) = options.open(path) {
        let _ = file.set_modified(SystemTime::now());
    }
}

/// The supervisor's watch of its run's heartbeat.
pub struct Watch {
    path: Option<PathBuf>,
    /// The file's last time that the watch read.
    seen: Option<SystemTime>,
    /// Whether this run has beaten: only then is it watched.
    armed: bool,
    /// When the file last changed, or the run started.
    changed: Instant,
    checked: Instant,
    /// Whether the line of a run that never beat was said.
    said: bool,
}

impl Watch {
    /// The watch of the heartbeat of the run `name`; none with no directory
    /// of the runs.
    pub fn new(name: Option<&str>) -> Watch {
        let path = name.and_then(|name| lock::dir().map(|dir| alive_path(&dir, name)));
        let now = Instant::now();
        Watch { path, seen: None, armed: false, changed: now, checked: now, said: false }
    }

    /// Whether there is a file to watch.
    pub fn watches(&self) -> bool {
        self.path.is_some()
    }

    fn time(&self) -> Option<SystemTime> {
        std::fs::metadata(self.path.as_ref()?).and_then(|m| m.modified()).ok()
    }

    /// A new run started: the file's time now is the one before it, and the
    /// run is watched once the file changes.
    pub fn reset(&mut self) {
        self.seen = self.time();
        self.armed = false;
        self.changed = Instant::now();
        self.checked = Instant::now();
        self.said = false;
    }

    /// Read the file once each [`CHECK`]: [`Verdict::Hung`] when the run
    /// beat and then did not for [`HUNG`]; [`Verdict::Never`] once, when a
    /// run never beat within [`HUNG`] of its start.
    pub fn check(&mut self) -> Verdict {
        if self.path.is_none() || self.checked.elapsed() < CHECK {
            return Verdict::Fine;
        }
        self.checked = Instant::now();
        if let Some(time) = self.time() {
            if Some(time) != self.seen {
                self.seen = Some(time);
                self.armed = true;
                self.changed = Instant::now();
            }
        }
        verdict(self.armed, self.changed.elapsed(), &mut self.said)
    }
}

/// What a check of the heartbeat found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Fine,
    /// The run beat, and then not for [`HUNG`]: it is ended and started again.
    Hung,
    /// The run never beat within [`HUNG`]: said once, and it is not watched.
    Never,
}

/// The verdict for a run that has beaten (`armed`) or not, whose file last
/// changed (or which started) `quiet` ago.
fn verdict(armed: bool, quiet: Duration, said: &mut bool) -> Verdict {
    match (armed, quiet >= HUNG) {
        (true, true) => Verdict::Hung,
        (false, true) if !*said => {
            *said = true;
            Verdict::Never
        }
        _ => Verdict::Fine,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run that beat and then stopped is hung after [`HUNG`]; one that
    /// never beat is said once and never ended.
    #[test]
    fn only_a_run_that_beat_and_then_stopped_is_hung() {
        let mut said = false;
        assert_eq!(verdict(true, HUNG - Duration::from_secs(1), &mut said), Verdict::Fine);
        assert_eq!(verdict(true, HUNG, &mut said), Verdict::Hung);
        assert_eq!(verdict(false, HUNG - Duration::from_secs(1), &mut said), Verdict::Fine);
        assert_eq!(verdict(false, HUNG, &mut said), Verdict::Never);
        assert_eq!(verdict(false, HUNG * 10, &mut said), Verdict::Fine, "said once");
    }

    /// A touch changes the file's time, which is what the watch compares;
    /// the watch arms at the first change after its reset, and not before.
    #[test]
    fn a_touch_arms_the_watch() {
        let dir = std::env::temp_dir().join(format!("podssh-beat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = alive_path(&dir, "web");
        let earlier = SystemTime::now() - Duration::from_secs(600);
        touch(&path);
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(earlier).unwrap();
        let now = Instant::now();
        let mut watch =
            Watch { path: Some(path.clone()), seen: None, armed: false, changed: now, checked: now, said: false };
        watch.reset();
        assert_eq!(watch.seen, Some(earlier));
        watch.checked = Instant::now().checked_sub(CHECK).expect("a clock older than 10 s");
        assert_eq!(watch.check(), Verdict::Fine);
        assert!(!watch.armed, "no beat since the reset");
        touch(&path);
        watch.checked = Instant::now().checked_sub(CHECK).expect("a clock older than 10 s");
        assert_eq!(watch.check(), Verdict::Fine);
        assert!(watch.armed, "the beat armed it");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
