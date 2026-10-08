//! Windows consoles, through the console API.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::sync::Mutex;

use russh::Pty;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleW, SetConsoleMode,
    CONSOLE_SCREEN_BUFFER_INFO, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use zeroize::Zeroizing;

use super::Size;

fn std_handle(which: u32) -> Option<HANDLE> {
    // SAFETY: GetStdHandle has no preconditions.
    let h = unsafe { GetStdHandle(which) };
    (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(h)
}

fn console_mode(h: HANDLE) -> Option<u32> {
    let mut mode = 0u32;
    // SAFETY: `mode` is a valid out pointer; a non-console handle fails.
    (unsafe { GetConsoleMode(h, &mut mode) } != 0).then_some(mode)
}

pub fn size() -> Option<Size> {
    let h = std_handle(STD_OUTPUT_HANDLE)?;
    // SAFETY: an all-zero CONSOLE_SCREEN_BUFFER_INFO is valid; the call only
    // writes into it.
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(h, &mut info) } == 0 {
        return None;
    }
    let cols = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
    let rows = i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
    (cols > 0 && rows > 0).then(|| Size { cols: cols as u32, rows: rows as u32, px_width: 0, px_height: 0 })
}

/// Console modes to put back: (input handle, mode), (output handle, mode).
/// Kept where a panic hook can reach them, because the release build aborts
/// on panic and `Drop` alone would leave the console raw.
struct Saved {
    input: Option<(usize, u32)>,
    output: Option<(usize, u32)>,
}

static SAVED: Mutex<Option<Saved>> = Mutex::new(None);

fn restore_saved() {
    let saved = SAVED.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(s) = saved {
        // SAFETY: handles and modes read from the same console earlier.
        if let Some((h, m)) = s.input {
            unsafe { SetConsoleMode(h as HANDLE, m) };
        }
        if let Some((h, m)) = s.output {
            unsafe { SetConsoleMode(h as HANDLE, m) };
        }
        super::set_raw_active(false);
    }
}

/// The console in raw mode, with VT sequences both ways, until dropped.
pub struct RawMode(());

impl RawMode {
    pub fn enter() -> std::io::Result<RawMode> {
        let input = std_handle(STD_INPUT_HANDLE).ok_or_else(std::io::Error::last_os_error)?;
        let in_mode = console_mode(input).ok_or_else(std::io::Error::last_os_error)?;
        let output = std_handle(STD_OUTPUT_HANDLE);
        let out_mode = output.and_then(console_mode);
        *SAVED.lock().unwrap_or_else(|e| e.into_inner()) = Some(Saved {
            input: Some((input as usize, in_mode)),
            output: output.zip(out_mode).map(|(h, m)| (h as usize, m)),
        });
        let raw_in = (in_mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        // SAFETY: setting modes on console handles we just read.
        if unsafe { SetConsoleMode(input, raw_in) } == 0 {
            let err = std::io::Error::last_os_error();
            SAVED.lock().unwrap_or_else(|e| e.into_inner()).take();
            return Err(err);
        }
        if let (Some(h), Some(m)) = (output, out_mode) {
            // Older consoles refuse DISABLE_NEWLINE_AUTO_RETURN; VT output
            // alone is still worth having.
            let vt = m | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if unsafe { SetConsoleMode(h, vt | DISABLE_NEWLINE_AUTO_RETURN) } == 0 {
                unsafe { SetConsoleMode(h, vt) };
            }
        }
        super::set_raw_active(true);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_saved();
            previous(info);
        }));
        Ok(RawMode(()))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        restore_saved();
    }
}

/// A console has no termios to copy, so send what a VT console produces:
/// DEL for backspace, and ordinary cooked-mode settings.
pub fn pty_modes() -> Vec<(Pty, u32)> {
    if std_handle(STD_INPUT_HANDLE).and_then(console_mode).is_none() {
        return Vec::new();
    }
    vec![
        (Pty::VINTR, 3),
        (Pty::VERASE, 127),
        (Pty::VEOF, 4),
        (Pty::VSUSP, 26),
        (Pty::ICRNL, 1),
        (Pty::IUTF8, 1),
        (Pty::ISIG, 1),
        (Pty::ICANON, 1),
        (Pty::ECHO, 1),
        (Pty::ECHOE, 1),
        (Pty::ECHOK, 1),
        (Pty::IEXTEN, 1),
        (Pty::OPOST, 1),
        (Pty::ONLCR, 1),
        (Pty::CS8, 1),
        (Pty::TTY_OP_ISPEED, 38400),
        (Pty::TTY_OP_OSPEED, 38400),
    ]
}

/// Ask on the console (`CONIN$`/`CONOUT$`), which works even when stdin and
/// stdout are redirected. An error when the process has no console.
pub fn read_line(prompt: &str, echo: bool) -> std::io::Result<Zeroizing<String>> {
    let mut out = OpenOptions::new().write(true).open("CONOUT$")?;
    let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
    let h = input.as_raw_handle() as HANDLE;
    out.write_all(prompt.as_bytes())?;
    out.flush()?;
    let saved = console_mode(h).ok_or_else(std::io::Error::last_os_error)?;
    let mut mode = saved | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
    if echo {
        mode |= ENABLE_ECHO_INPUT;
    } else {
        mode &= !ENABLE_ECHO_INPUT;
    }
    // SAFETY: a console input handle we hold open.
    unsafe { SetConsoleMode(h, mode) };
    let mut units: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::new());
    let mut buf = Zeroizing::new([0u16; 256]);
    let result = loop {
        let mut read = 0u32;
        // SAFETY: `buf` holds 256 UTF-16 units and `read` is a valid out pointer.
        let ok = unsafe { ReadConsoleW(h, buf.as_mut_ptr().cast(), 256, &mut read, std::ptr::null()) };
        if ok == 0 {
            break Err(std::io::Error::last_os_error());
        }
        if read == 0 {
            break Ok(());
        }
        units.extend_from_slice(&buf[..read as usize]);
        if units.contains(&u16::from(b'\n')) {
            break Ok(());
        }
    };
    unsafe { SetConsoleMode(h, saved) };
    if !echo {
        let _ = out.write_all(b"\r\n");
    }
    result?;
    let text = String::from_utf16_lossy(&units);
    Ok(Zeroizing::new(text.trim_end_matches(['\r', '\n']).to_string()))
}
