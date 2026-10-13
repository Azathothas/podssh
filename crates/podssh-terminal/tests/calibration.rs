//! The model of the terminal oracle against a real terminal (T-200): each
//! sequence of `tests/screen/corpus.txt` goes through tmux, in a pane of its
//! own, and through the model of `tests/screen/mod.rs`; the rows and the
//! cursor must be the same before the model judges podssh's bytes.
//!
//! `PODSSH_TEST_TMUX` names tmux: the gate installs it and names it. A name
//! with no program there fails. With no name, a tmux at a usual place runs
//! the check, and with none the test says that it did not run. The corpus
//! itself is read on each host.

mod screen;
use screen::Screen;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const CORPUS: &str = include_str!("screen/corpus.txt");

/// Where tmux usually is, when no variable names it.
const USUAL: [&str; 3] = ["/usr/bin/tmux", "/usr/local/bin/tmux", "/opt/homebrew/bin/tmux"];

/// How long one call of tmux may take.
const LIMIT: Duration = Duration::from_secs(10);

/// The size asked of each pane. The model takes the size that tmux reports,
/// as a status line can take a row.
const COLS: u16 = 80;
const ROWS: u16 = 24;

/// One case of the corpus: its name and its bytes.
struct Case {
    name: String,
    bytes: Vec<u8>,
}

/// The cases of the corpus, in order.
fn corpus() -> Vec<Case> {
    CORPUS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, text) = line.split_once(' ').unwrap_or((line, ""));
            let bytes = unescape(text).unwrap_or_else(|why| panic!("{name}: {why}"));
            Case { name: name.to_string(), bytes }
        })
        .collect()
}

/// The bytes that `text` stands for, as the head of the corpus says.
fn unescape(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next().ok_or("a \\ at the end")? {
                'e' => out.push(0x1b),
                'r' => out.push(b'\r'),
                'n' => out.push(b'\n'),
                'b' => out.push(0x08),
                't' => out.push(b'\t'),
                'a' => out.push(0x07),
                '\\' => out.push(b'\\'),
                'x' => {
                    let hex: String = chars.by_ref().take(2).collect();
                    out.push(u8::from_str_radix(&hex, 16).map_err(|_| format!("\\x{hex} is no byte"))?);
                }
                other => return Err(format!("\\{other} is no escape")),
            },
            '{' => {
                let body: String = chars.by_ref().take_while(|&c| c != '}').collect();
                let (count, repeated) = body.split_once('*').ok_or_else(|| format!("{{{body}}} has no *"))?;
                let count: usize = count.parse().map_err(|_| format!("{{{body}}}: {count} is no count"))?;
                out.extend(unescape(repeated)?.repeat(count));
            }
            c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    Ok(out)
}

/// The corpus reads, each name once, and the model draws each case with
/// the cursor inside the screen.
#[test]
fn the_corpus_reads_and_the_model_draws_each_case() {
    let cases = corpus();
    assert!(cases.len() >= 30, "{} cases", cases.len());
    for (i, case) in cases.iter().enumerate() {
        assert!(!case.bytes.is_empty(), "{}: no bytes", case.name);
        assert!(cases[..i].iter().all(|c| c.name != case.name), "{}: two cases of that name", case.name);
        let screen = Screen::of(ROWS, COLS, &case.bytes);
        let (row, col) = screen.cursor();
        assert!(row < ROWS && col < COLS, "{}: the cursor past the screen\n{}", case.name, screen.show());
    }
    assert_eq!(unescape("a\\e[{3*\\r\\n}\\x41").unwrap(), b"a\x1b[\r\n\r\n\r\nA");
    assert!(unescape("\\q").is_err() && unescape("{3}").is_err());
}

fn tmux_path() -> Option<PathBuf> {
    match std::env::var_os("PODSSH_TEST_TMUX") {
        Some(named) => {
            let path = PathBuf::from(named);
            assert!(path.is_file(), "PODSSH_TEST_TMUX names {}, and no program is there", path.display());
            Some(path)
        }
        None => USUAL.iter().map(PathBuf::from).find(|p| p.is_file()),
    }
}

/// `row` with each tab as the blanks up to the next stop of 8, counted in
/// characters: the corpus's rows before a tab are of one cell a character.
fn tabs_as_blanks(row: &str) -> String {
    let mut out = String::with_capacity(row.len());
    let mut col = 0;
    for c in row.chars() {
        if c == '\t' {
            let next = (col / 8 + 1) * 8;
            out.extend(std::iter::repeat_n(' ', next - col));
            col = next;
        } else {
            out.push(c);
            col += 1;
        }
    }
    out
}

/// A tmux server on a socket of a scratch directory: the server is killed
/// and the directory removed when it is dropped, as the gate fails a run of
/// the tests that leaves one (T-272).
struct Tmux {
    program: PathBuf,
    dir: PathBuf,
}

impl Tmux {
    fn new(program: PathBuf) -> Tmux {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("podssh-oracle-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        Tmux { program, dir }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("sock")
    }

    /// tmux with `args`, within [`LIMIT`]: its standard output, or why not.
    fn call(&self, args: &[&str]) -> Result<String, String> {
        let mut child = Command::new(&self.program)
            .args(["-u", "-f", "/dev/null", "-S"])
            .arg(self.socket())
            .args(args)
            .env("LC_ALL", "C.UTF-8")
            .env("SHELL", "/bin/sh")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{}: {e}", self.program.display()))?;
        let start = Instant::now();
        while child.try_wait().map_err(|e| e.to_string())?.is_none() {
            if start.elapsed() > LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("tmux {args:?} took more than {} s", LIMIT.as_secs()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("tmux {args:?}: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        String::from_utf8(out.stdout).map_err(|_| format!("tmux {args:?} wrote text that is not UTF-8"))
    }

    /// The rows of a pane, each with no blank at its end, and its cursor,
    /// columns and rows. tmux 3.7 gives the cells that a tab skipped as the
    /// tab itself; they are blanks up to the next stop of 8, as on the screen.
    fn look(&self, pane: &str) -> (Vec<String>, String) {
        let rows = self.call(&["capture-pane", "-p", "-t", pane]).unwrap();
        let state = self
            .call(&["display-message", "-p", "-t", pane, "#{cursor_x} #{cursor_y} #{pane_width} #{pane_height}"])
            .unwrap();
        (rows.lines().map(|row| tabs_as_blanks(row).trim_end().to_string()).collect(), state.trim().to_string())
    }

    /// The screen of `case` in a pane of its own: its rows up to the last
    /// that holds a character, its cursor (row, column) and its size (rows,
    /// columns).
    fn show(&self, i: usize, case: &Case) -> (Vec<String>, (u16, u16), (u16, u16)) {
        let file = self.dir.join(format!("case-{i}"));
        std::fs::write(&file, &case.bytes).unwrap();
        let pane = format!("c{i}");
        // The pane writes the case raw, with no ONLCR, as podssh's terminal
        // is in a session; then it signals the test and waits to be killed.
        let script = format!(
            "stty raw -echo; cat '{}'; '{}' -S '{}' wait-for -S {pane}; exec sleep 600",
            file.display(),
            self.program.display(),
            self.socket().display()
        );
        let (cols, rows) = (COLS.to_string(), ROWS.to_string());
        self.call(&["new-session", "-d", "-s", &pane, "-x", &cols, "-y", &rows, &script]).unwrap();
        self.call(&["wait-for", &pane]).unwrap();
        // tmux reads the pane's output in its own time: the screen counts
        // when two looks 50 ms apart agree.
        let mut last = self.look(&pane);
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(50));
            let now = self.look(&pane);
            if now == last {
                break;
            }
            last = now;
        }
        let _ = self.call(&["kill-session", "-t", &pane]);
        let (mut text, state) = last;
        let numbers: Vec<u16> = state.split(' ').map(|n| n.parse().unwrap_or(u16::MAX)).collect();
        let &[x, y, width, height] = numbers.as_slice() else { panic!("{}: tmux said {state:?}", case.name) };
        while text.last().is_some_and(|row| row.is_empty()) {
            text.pop();
        }
        (text, (y, x), (height, width))
    }
}

impl Drop for Tmux {
    fn drop(&mut self) {
        let _ = self.call(&["kill-server"]);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Each case shows the same rows, and the cursor in the same cell, in tmux
/// and in the model.
#[test]
fn the_model_and_tmux_show_the_same_screens() {
    let Some(program) = tmux_path() else {
        eprintln!("did not run: no tmux here; PODSSH_TEST_TMUX names one");
        return;
    };
    let tmux = Tmux::new(program);
    let mut differ = Vec::new();
    for (i, case) in corpus().iter().enumerate() {
        let (rows, cursor, (height, width)) = tmux.show(i, case);
        let model = Screen::of(height, width, &case.bytes);
        if model.text() != rows || model.cursor() != cursor {
            differ.push(format!(
                "{}: tmux shows the cursor at {cursor:?} and\n{}\nthe model shows\n{}",
                case.name,
                rows.iter().enumerate().map(|(n, row)| format!("{n:>3} |{row}|")).collect::<Vec<_>>().join("\n"),
                model.show()
            ));
        }
    }
    assert!(differ.is_empty(), "{} cases differ:\n{}", differ.len(), differ.join("\n"));
}

/// The scratch of a run goes with it.
#[test]
fn the_scratch_directory_goes_when_the_server_goes() {
    let tmux = Tmux::new(PathBuf::from("/nonexistent/tmux"));
    let dir = tmux.dir.clone();
    assert!(dir.is_dir(), "{}", dir.display());
    drop(tmux);
    assert!(!dir.exists(), "{}", dir.display());
}
