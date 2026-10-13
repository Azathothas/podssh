//! A Windows pseudo console (ConPTY, what Windows Terminal uses) for the
//! tests (T-132): a program runs in it as in a terminal's window, and the
//! test types into it and reads what the console shows. The counterpart, in
//! the test process, of `scripts/interop-conpty.py`, which needs a server
//! with a shell; this one runs against the test's own SSH server.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, SetConsoleCtrlHandler, COORD, HPCON,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess, InitializeProcThreadAttributeList,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

/// A pseudo console and the one process that runs in it.
pub struct Console {
    hpc: HPCON,
    input: File,
    seen: Arc<Mutex<Vec<u8>>>,
    process: HANDLE,
}

// The handles are used from one thread at a time.
unsafe impl Send for Console {}

/// One pipe: its read end and its write end.
fn pipe() -> (HANDLE, HANDLE) {
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: two out pointers to handles, no attributes, the default size.
    let ok = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) };
    assert!(ok != 0, "CreatePipe: {}", std::io::Error::last_os_error());
    (read, write)
}

/// This process's environment with `changes`: a value sets a name, `None`
/// removes it. As CreateProcessW takes it: `NAME=VALUE` pairs in UTF-16,
/// each ending in 0, sorted by name, and a 0 after the last.
fn environment(changes: &[(&str, Option<&str>)]) -> Vec<u16> {
    let mut vars: Vec<(String, String)> = std::env::vars()
        .filter(|(name, _)| !changes.iter().any(|(changed, _)| changed.eq_ignore_ascii_case(name)))
        .collect();
    vars.extend(changes.iter().filter_map(|(name, value)| value.map(|v| (name.to_string(), v.to_string()))));
    vars.sort_by_key(|(name, _)| name.to_uppercase());
    let mut block: Vec<u16> =
        vars.iter().flat_map(|(name, value)| format!("{name}={value}\0").encode_utf16().collect::<Vec<_>>()).collect();
    block.push(0);
    block
}

impl Console {
    /// Run `command_line` in a new pseudo console of `rows` by `cols`, in
    /// this process's environment with `changes`.
    pub fn start(command_line: &str, changes: &[(&str, Option<&str>)], rows: i16, cols: i16) -> Console {
        let (in_read, in_write) = pipe();
        let (out_read, out_write) = pipe();
        let mut hpc: HPCON = 0;
        // SAFETY: the pipe ends just made, and an out pointer.
        let hr = unsafe { CreatePseudoConsole(COORD { X: cols, Y: rows }, in_read, out_write, 0, &mut hpc) };
        assert_eq!(hr, 0, "CreatePseudoConsole: {hr:#x}");
        // The pseudo console holds its own references to these ends.
        // SAFETY: handles of this process, closed once.
        unsafe {
            CloseHandle(in_read);
            CloseHandle(out_write);
        }
        let mut size = 0usize;
        // SAFETY: the first call only asks for the size of a list of one.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        let mut attrs = vec![0u8; size];
        let list = attrs.as_mut_ptr().cast();
        // SAFETY: `attrs` holds `size` bytes, as the first call asked.
        let ok = unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) };
        assert!(ok != 0, "InitializeProcThreadAttributeList: {}", std::io::Error::last_os_error());
        // SAFETY: the list just initialised; the value is the pseudo console's
        // handle itself, as the attribute takes it.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                hpc as *const core::ffi::c_void,
                std::mem::size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert!(ok != 0, "UpdateProcThreadAttribute: {}", std::io::Error::last_os_error());
        // SAFETY: a plain C struct, zero is its empty value.
        let mut info: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // Null standard handles, explicitly: else a child of a process whose
        // stdio is redirected, as under the test runner, inherits that stdio
        // and does not use the pseudo console.
        info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        info.lpAttributeList = list;
        // SAFETY: a plain C struct, filled by the call.
        let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let mut line: Vec<u16> = command_line.encode_utf16().chain(std::iter::once(0)).collect();
        let block = environment(changes);
        // A child inherits whether Ctrl-C is ignored, and a test runner that
        // a service or a shell with no console started can have it ignored;
        // podssh then keeps it ignored, as OpenSSH keeps an ignored SIGINT.
        // A user's terminal delivers it, so the console's program must get it.
        // SAFETY: no handler, only the flag that the child inherits.
        unsafe { SetConsoleCtrlHandler(None, 0) };
        // SAFETY: a writable command line ending in 0, the extended start-up
        // information with its list, and an out struct.
        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                block.as_ptr().cast(),
                std::ptr::null(),
                &info.StartupInfo,
                &mut process,
            )
        };
        let created = std::io::Error::last_os_error();
        // SAFETY: the list initialised above, deleted once.
        unsafe { DeleteProcThreadAttributeList(list) };
        assert!(ok != 0, "CreateProcessW {command_line}: {created}");
        // SAFETY: a handle of this process, closed once.
        unsafe { CloseHandle(process.hThread) };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        // SAFETY: the read end, owned by the reader from here on.
        let mut output = unsafe { File::from_raw_handle(out_read as RawHandle) };
        // The console's output must be read as it comes: a full pipe stops
        // the program, and the pseudo console's close waits for it.
        std::thread::spawn(move || {
            let mut chunk = vec![0u8; 65536];
            while let Ok(n) = output.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                into.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        // SAFETY: the write end, owned by the console from here on.
        let input = unsafe { File::from_raw_handle(in_write as RawHandle) };
        Console { hpc, input, seen, process: process.hProcess }
    }

    /// Type `bytes`, as a terminal sends its keys.
    pub fn send(&mut self, bytes: &[u8]) {
        self.input.write_all(bytes).expect("the console's input");
        self.input.flush().expect("the console's input");
    }

    /// Give the console a new size, as a terminal's window does.
    pub fn resize(&self, rows: i16, cols: i16) {
        // SAFETY: the pseudo console of this value.
        let hr = unsafe { ResizePseudoConsole(self.hpc, COORD { X: cols, Y: rows }) };
        assert_eq!(hr, 0, "ResizePseudoConsole: {hr:#x}");
    }

    /// What the console has drawn, with no escape sequences.
    pub fn text(&self) -> String {
        plain(&self.seen.lock().unwrap())
    }

    /// Wait until the console shows `needle`, at most `limit`.
    pub fn expect(&self, needle: &str, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if self.text().contains(needle) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The program's exit code, when it ends within `limit`.
    pub fn wait(&self, limit: Duration) -> Option<u32> {
        // SAFETY: the process handle of this value.
        if unsafe { WaitForSingleObject(self.process, limit.as_millis() as u32) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        // SAFETY: the process handle, and an out pointer.
        (unsafe { GetExitCodeProcess(self.process, &mut code) } != 0).then_some(code)
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        // SAFETY: the handles of this value, each closed once.
        unsafe {
            if WaitForSingleObject(self.process, 0) != WAIT_OBJECT_0 {
                TerminateProcess(self.process, 1);
            }
            ClosePseudoConsole(self.hpc);
            CloseHandle(self.process);
        }
    }
}

/// `bytes` with the escape sequences of the console taken out: CSI, OSC and
/// the two-byte ones. The rest is read as UTF-8, a bad byte as U+FFFD.
pub fn plain(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != 0x1b || i + 1 == bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += match bytes[i + 1] {
            b'[' => {
                let end = bytes[i + 2..].iter().position(|b| (0x40..=0x7e).contains(b));
                end.map_or(bytes.len() - i, |at| at + 3)
            }
            b']' => {
                let rest = &bytes[i + 2..];
                let bel = rest.iter().position(|b| *b == 0x07).map(|at| at + 3);
                let st = rest.windows(2).position(|w| w == b"\x1b\\").map(|at| at + 4);
                match (bel, st) {
                    (Some(a), Some(b)) => a.min(b),
                    (Some(a), None) | (None, Some(a)) => a,
                    (None, None) => bytes.len() - i,
                }
            }
            _ => 2,
        };
    }
    String::from_utf8_lossy(&out).into_owned()
}
