//! Jobs of Windows for the tests of T-383: a job that kills its processes
//! when its last handle closes, as Win32-OpenSSH's job of a session does,
//! and a command started by `cmd` inside it. `cmd` is put in the job first
//! and waits a moment before it starts the command, so that the command
//! starts inside the job.
#![cfg(windows)]
// Each test binary uses a part of it.
#![allow(dead_code)]

use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// A job that kills its processes when it closes, and allows breakaway or
/// not. Closed when dropped.
pub struct Job(HANDLE);

impl Job {
    pub fn new(breakaway: bool) -> Job {
        // SAFETY: a new job of this test, its result checked; the
        // information is a zeroed structure of the size given, with its
        // flags set.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            assert!(!job.is_null(), "CreateJobObjectW: {}", std::io::Error::last_os_error());
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | if breakaway { JOB_OBJECT_LIMIT_BREAKAWAY_OK } else { 0 };
            let set = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            assert_ne!(set, 0, "SetInformationJobObject: {}", std::io::Error::last_os_error());
            Job(job)
        }
    }

    /// `cmd /d /s /c "LINE"` in the job, LINE run after about two seconds;
    /// `cmd` carries the environment and the pipes that it was given. The
    /// line goes as it is: `cmd` reads no `\"` of the C runtime's quoting,
    /// and `/s` keeps each quote inside the outer pair.
    pub fn run(&self, mut cmd: Command, line: &str) -> Child {
        use std::os::windows::process::CommandExt;
        cmd.args(["/d", "/s", "/c"]).raw_arg(format!("\"ping -n 3 127.0.0.1 >nul & {line}\""));
        let child = cmd.spawn().unwrap();
        // SAFETY: the job and the handle of the test's own child, both open.
        let assigned = unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle()) };
        assert_ne!(assigned, 0, "AssignProcessToJobObject: {}", std::io::Error::last_os_error());
        child
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the test's own job; its processes end with it.
        unsafe { CloseHandle(self.0) };
    }
}
