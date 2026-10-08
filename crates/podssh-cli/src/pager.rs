//! The pager of `podssh man`. It is used only when stdin and stdout are both a
//! terminal (`--no-pager` turns it off), and its choice is probed on each run:
//!
//! 1. `PAGER`, when it is set. Empty, or `cat`, means no pager.
//! 2. `less`, when `PATH` has it and `TERM` names a terminal that is not
//!    `dumb`. Not on Windows, where a console seldom has `TERM` or `less`.
//! 3. The built-in pager: a screenful at a time, Enter for the next, `q` to
//!    stop. It needs nothing from the host.
//!
//! A program that does not start falls back to the built-in pager. A pager
//! program gets the text on its stdin and writes to the terminal itself; the
//! built-in pager writes the text to stdout and its prompt to stderr.

use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// A screenful when the terminal cannot be measured.
pub const PAGE_LINES: usize = 24;

/// Whether stdin and stdout are terminals. `false` also means "could not be
/// asked", and both mean: do not page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tty {
    pub stdin: bool,
    pub stdout: bool,
}

impl Tty {
    /// Ask the operating system, once, where the real descriptors are.
    pub fn probed() -> Tty {
        use std::io::IsTerminal as _;
        Tty { stdin: std::io::stdin().is_terminal(), stdout: std::io::stdout().is_terminal() }
    }

    /// No terminal: what tests get, so that no test can wait for a key.
    pub fn none() -> Tty {
        Tty::default()
    }

    /// A pager needs both: output to show and a keyboard to read.
    pub fn can_page(&self) -> bool {
        self.stdin && self.stdout
    }
}

/// What the choice of a pager reads from the environment.
#[derive(Clone, Debug, Default)]
pub struct PagerEnv {
    pub pager: Option<String>,
    pub term: Option<String>,
    /// `less` on `PATH`, if there is one.
    pub less: Option<PathBuf>,
    pub windows: bool,
}

impl PagerEnv {
    pub fn from_process() -> Self {
        let windows = cfg!(windows);
        PagerEnv {
            pager: std::env::var("PAGER").ok(),
            term: std::env::var("TERM").ok(),
            less: if windows { None } else { find_program("less", std::env::var_os("PATH")) },
            windows,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Write the text, with no pager.
    Direct,
    /// Start this program with the text on its stdin.
    Program(Vec<OsString>),
    BuiltIn,
}

pub fn choose(env: &PagerEnv) -> Choice {
    if let Some(pager) = &env.pager {
        let words: Vec<&str> = pager.split_whitespace().collect();
        return match words.first() {
            None | Some(&"cat") => Choice::Direct,
            Some(_) => Choice::Program(words.into_iter().map(OsString::from).collect()),
        };
    }
    let term = env.term.as_deref().map(str::trim).unwrap_or("");
    match &env.less {
        Some(less) if !env.windows && !term.is_empty() && term != "dumb" => {
            Choice::Program(vec![less.clone().into_os_string()])
        }
        _ => Choice::BuiltIn,
    }
}

/// The first `name` in `path` that is a file this process may run.
pub fn find_program(name: &str, path: Option<OsString>) -> Option<PathBuf> {
    std::env::split_paths(&path?).map(|dir| dir.join(name)).find(|p| runnable(p))
}

fn runnable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Show `text` on the terminal, with the pager that [`choose`] selects.
pub fn show(text: &str, env: &PagerEnv, keys: &mut dyn BufRead, out: &mut dyn Write, err: &mut dyn Write) {
    let rows = podssh_ssh::terminal::size()
        .map(|s| s.rows as usize)
        .filter(|r| *r > 2)
        .unwrap_or(PAGE_LINES);
    match choose(env) {
        Choice::Direct => {
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
        }
        Choice::Program(cmd) => {
            if run_program(&cmd, text).is_err() {
                let _ = page(text, rows - 1, keys, out, err);
            }
        }
        Choice::BuiltIn => {
            let _ = page(text, rows - 1, keys, out, err);
        }
    }
}

/// Start `cmd` with `text` on its stdin and wait for it. `Err` only when it
/// did not start. Ctrl-C belongs to the pager while it runs, so podssh
/// ignores it and does not leave the pager behind on the terminal.
pub fn run_program(cmd: &[OsString], text: &str) -> std::io::Result<()> {
    let Some((program, args)) = cmd.split_first() else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no pager program"));
    };
    let mut command = std::process::Command::new(program);
    command.args(args).stdin(std::process::Stdio::piped());
    if std::env::var_os("LESS").is_none() {
        // Quit when the text fits one screen, pass control characters, and
        // leave the text on the screen at the end.
        command.env("LESS", "FRX");
    }
    let mut child = command.spawn()?;
    let _ignored = Interrupts::ignore();
    if let Some(mut stdin) = child.stdin.take() {
        // A pager that quits early closes its input: not an error.
        let _ = stdin.write_all(text.as_bytes());
    }
    let _ = child.wait();
    Ok(())
}

/// SIGINT and SIGQUIT ignored while the value lives, then restored.
struct Interrupts {
    #[cfg(unix)]
    previous: [libc::sighandler_t; 2],
}

impl Interrupts {
    fn ignore() -> Interrupts {
        #[cfg(unix)]
        {
            // SAFETY: setting SIG_IGN has no preconditions; Drop restores the
            // handlers that were there.
            let previous = unsafe { [libc::signal(libc::SIGINT, libc::SIG_IGN), libc::signal(libc::SIGQUIT, libc::SIG_IGN)] };
            Interrupts { previous }
        }
        #[cfg(not(unix))]
        Interrupts {}
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: restores the handlers that `ignore` read.
        unsafe {
            libc::signal(libc::SIGINT, self.previous[0]);
            libc::signal(libc::SIGQUIT, self.previous[1]);
        }
    }
}

/// What the user typed at the prompt of the built-in pager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Enter, or a line that does not start with `q`: the next screenful.
    Next,
    /// A line that starts with `q` or `Q`.
    Quit,
    /// The input ended: stop, never wait.
    Eof,
}

/// Read one line of keys. A terminal sends input a line at a time, so the
/// prompt asks for Enter rather than for one key.
pub fn read_key(from: &mut dyn BufRead) -> Key {
    let mut line = Vec::new();
    match from.read_until(b'\n', &mut line) {
        Ok(0) | Err(_) => Key::Eof,
        Ok(_) => match line.iter().find(|b| !b.is_ascii_whitespace()) {
            Some(b'q' | b'Q') => Key::Quit,
            _ => Key::Next,
        },
    }
}

/// The built-in pager: `rows` lines at a time, then a prompt on `err`.
/// Paging to the end writes the same bytes as no pager.
pub fn page(
    text: &str,
    rows: usize,
    keys: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> std::io::Result<()> {
    let rows = rows.max(1);
    let lines: Vec<&str> = text.lines().collect();
    let mut start = 0;
    while start < lines.len() {
        let end = (start + rows).min(lines.len());
        for line in &lines[start..end] {
            writeln!(out, "{line}")?;
        }
        out.flush()?;
        start = end;
        if start >= lines.len() {
            break;
        }
        write!(err, "-- more -- (Enter: next page, q: quit) ")?;
        err.flush()?;
        match read_key(keys) {
            Key::Next => {}
            Key::Quit => break,
            Key::Eof => {
                writeln!(err)?;
                break;
            }
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn lines(n: usize) -> String {
        (0..n).map(|i| format!("line {i}\n")).collect()
    }

    fn paged(text: &str, keys: &[u8]) -> (String, String) {
        let mut keys = Cursor::new(keys.to_vec());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        page(text, PAGE_LINES, &mut keys, &mut out, &mut err).unwrap();
        (String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    /// The control: Enter at each prompt gives the whole text, unchanged.
    #[test]
    fn enter_at_each_prompt_gives_the_whole_text() {
        let text = lines(PAGE_LINES * 3 + 7);
        assert_eq!(paged(&text, b"\n\n\n").0, text);
    }

    #[test]
    fn q_stops_after_the_first_screenful() {
        let (out, _) = paged(&lines(PAGE_LINES * 3), b"q\n");
        assert_eq!(out.lines().count(), PAGE_LINES);
    }

    #[test]
    fn the_prompt_goes_to_stderr_only() {
        let text = lines(PAGE_LINES + 1);
        let (out, err) = paged(&text, b"\n");
        assert_eq!(out, text);
        assert!(!out.contains("more"));
        assert!(err.contains("-- more --"));
    }

    /// The end of the input stops the pager: with no keys there is no wait.
    #[test]
    fn the_end_of_the_input_stops_the_pager() {
        let (out, _) = paged(&lines(PAGE_LINES * 2), b"");
        assert_eq!(out.lines().count(), PAGE_LINES);
    }

    #[test]
    fn only_a_terminal_on_both_ends_may_page() {
        assert!(!Tty::none().can_page());
        assert!(!Tty { stdin: true, stdout: false }.can_page());
        assert!(!Tty { stdin: false, stdout: true }.can_page());
        assert!(Tty { stdin: true, stdout: true }.can_page());
    }

    fn env(pager: Option<&str>, term: Option<&str>, less: bool, windows: bool) -> PagerEnv {
        PagerEnv {
            pager: pager.map(str::to_string),
            term: term.map(str::to_string),
            less: less.then(|| PathBuf::from("/usr/bin/less")),
            windows,
        }
    }

    #[test]
    fn pager_wins_and_empty_or_cat_means_none() {
        let p = |v| choose(&env(Some(v), Some("xterm"), true, false));
        assert_eq!(p("most -s"), Choice::Program(vec!["most".into(), "-s".into()]));
        assert_eq!(p(""), Choice::Direct);
        assert_eq!(p("  "), Choice::Direct);
        assert_eq!(p("cat"), Choice::Direct);
    }

    #[test]
    fn less_needs_a_terminal_name_and_is_not_used_on_windows() {
        let less = Choice::Program(vec!["/usr/bin/less".into()]);
        assert_eq!(choose(&env(None, Some("xterm-256color"), true, false)), less);
        assert_eq!(choose(&env(None, Some("dumb"), true, false)), Choice::BuiltIn);
        assert_eq!(choose(&env(None, None, true, false)), Choice::BuiltIn);
        assert_eq!(choose(&env(None, Some("xterm"), false, false)), Choice::BuiltIn);
        assert_eq!(choose(&env(None, Some("xterm"), true, true)), Choice::BuiltIn);
    }

    #[test]
    fn find_program_finds_only_a_runnable_file() {
        let dir = std::env::temp_dir().join(format!("podssh-pager-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = Some(OsString::from(dir.as_os_str()));
        assert_eq!(find_program("less", path.clone()), None);
        let file = dir.join("less");
        std::fs::write(&file, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(find_program("less", path.clone()), None, "a file that cannot run");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(find_program("less", path), Some(file));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_program_that_does_not_start_is_an_error() {
        let cmd = vec![OsString::from("podssh-no-such-pager-program")];
        assert!(run_program(&cmd, "text").is_err());
        assert!(run_program(&[], "text").is_err());
    }

    /// A pager that quits at once does not make podssh fail or wait, also
    /// with more text than a pipe holds.
    #[test]
    fn a_pager_that_quits_at_once_is_not_an_error() {
        let cmd: Vec<OsString> = if cfg!(windows) {
            vec!["cmd".into(), "/C".into(), "exit 0".into()]
        } else {
            vec!["true".into()]
        };
        run_program(&cmd, &lines(100_000)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_pager_gets_the_whole_text_on_its_stdin() {
        let file = std::env::temp_dir().join(format!("podssh-pager-out-{}", std::process::id()));
        let script = format!("cat > '{}'", file.display());
        let text = lines(10_000);
        run_program(&["sh".into(), "-c".into(), script.into()], &text).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
        let _ = std::fs::remove_file(&file);
    }
}
