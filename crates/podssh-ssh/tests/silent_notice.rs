//! The notice while the far end is silent (T-302), as a terminal shows it:
//! the session's output and the notice's bytes go through the terminal
//! oracle (T-200), with a stack of window titles beside it, which the
//! `vt100` crate does not keep. The screen of a full-screen program after
//! the notice is the screen before it, and so is the title; the notice
//! counts up, waits for the end of a sequence that the far end cut, and
//! gives the title back before the far end's next bytes. A planted notice
//! written at the cursor, as a line, fails the check of the screen.

#[path = "../../podssh-terminal/tests/screen/mod.rs"]
mod screen;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::notice::{title, Action, Notice, Place, Silence};
use screen::Screen;
use tokio::time::Instant;

/// The start of a window's title.
const OSC2: &[u8] = b"\x1b]2;";

/// The window's title, and the stack of titles of XTWINOPS 22 and 23,
/// read from the bytes that a terminal gets; a sequence that the end of a
/// piece cuts waits for the next.
#[derive(Debug, Default)]
struct Titles {
    now: String,
    stack: Vec<String>,
    pending: Vec<u8>,
}

impl Titles {
    fn feed(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        let data = std::mem::take(&mut self.pending);
        let mut at = 0;
        while at < data.len() {
            let rest = &data[at..];
            if rest.starts_with(title::PUSH) {
                self.stack.push(self.now.clone());
                at += title::PUSH.len();
            } else if rest.starts_with(title::POP) {
                if let Some(old) = self.stack.pop() {
                    self.now = old;
                }
                at += title::POP.len();
            } else if let Some(body) = rest.strip_prefix(OSC2) {
                let Some(end) = body.iter().position(|b| *b == 0x07) else {
                    self.pending = rest.to_vec();
                    return;
                };
                self.now = String::from_utf8_lossy(&body[..end]).into_owned();
                at += OSC2.len() + end + 1;
            } else if cut_short(rest) {
                self.pending = rest.to_vec();
                return;
            } else {
                at += 1;
            }
        }
    }
}

/// Whether `rest` is the start of a sequence of the model, cut short.
fn cut_short(rest: &[u8]) -> bool {
    [title::PUSH, title::POP, OSC2].iter().any(|whole| rest.len() < whole.len() && whole.starts_with(rest))
}

/// A terminal: its screen and its titles.
struct Terminal {
    screen: Screen,
    titles: Titles,
}

impl Terminal {
    fn new() -> Terminal {
        Terminal { screen: Screen::new(24, 80), titles: Titles::default() }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.screen.feed(bytes);
        self.titles.feed(bytes);
    }

    /// What a person sees: the rows, the cursor and the title.
    fn seen(&self) -> (Vec<String>, (u16, u16), String) {
        (self.screen.rows(), self.screen.cursor(), self.titles.now.clone())
    }
}

/// A silence that the test sets: how long the far end has said nothing,
/// past the wait of a question; `None` while it answers.
fn silence() -> (Silence, Arc<Mutex<Option<Duration>>>) {
    let silent: Arc<Mutex<Option<Duration>>> = Arc::default();
    let read = silent.clone();
    let words = Silence::default();
    words.attach(move || *read.lock().unwrap());
    (words, silent)
}

/// The far end's output to `terminal`, through the notice.
fn output(notice: &mut Notice, terminal: &mut Terminal, data: &[u8]) {
    let first = notice.before_output(data, false);
    terminal.feed(&first);
    terminal.feed(data);
}

/// A tick of the notice, its bytes to `terminal`: what it wrote.
fn tick(notice: &mut Notice, terminal: &mut Terminal) -> Option<Vec<u8>> {
    match notice.tick(Instant::now()) {
        Some(Action::Write(bytes)) => {
            terminal.feed(&bytes);
            Some(bytes)
        }
        Some(Action::Say(line)) => panic!("a title notice said a line: {line}"),
        None => None,
    }
}

/// A full-screen program: its title, a cleared screen, text at two places,
/// and the cursor in the middle of a row.
const PROGRAM: &[u8] = b"\x1b]2;vi notes.txt\x07\x1b[2J\x1b[Hfirst line\x1b[12;30Hmiddle\x1b[12;33H";

#[test]
fn the_notice_counts_up_in_the_title_and_leaves_the_screen_as_it_was() {
    let (words, silent) = silence();
    let mut notice = Notice::new(Place::Title, &words, "node://lab", Some(b'~'));
    assert!(words.titled(), "the road leaves its lines out while the title shows the notice");
    let mut terminal = Terminal::new();
    output(&mut notice, &mut terminal, PROGRAM);
    let before = terminal.seen();
    assert_eq!(before.2, "vi notes.txt");

    // The far end answers: nothing.
    assert_eq!(tick(&mut notice, &mut terminal), None);
    *silent.lock().unwrap() = Some(Duration::from_secs(7));
    assert!(tick(&mut notice, &mut terminal).is_some(), "the notice shows");
    let (rows, cursor, shown) = terminal.seen();
    assert_eq!((rows, cursor), (before.0.clone(), before.1), "{}", terminal.screen.show());
    assert_eq!(shown, "podssh: no word from node://lab for 7 s, ~. ends the session");
    // The same second writes nothing; the next counts up.
    assert_eq!(tick(&mut notice, &mut terminal), None);
    *silent.lock().unwrap() = Some(Duration::from_secs(8));
    assert!(tick(&mut notice, &mut terminal).is_some());
    assert!(terminal.titles.now.contains("for 8 s"), "{:?}", terminal.titles);
    assert_eq!(terminal.titles.stack, ["vi notes.txt"], "one title saved, once");

    // The far end answers again: the title comes back.
    *silent.lock().unwrap() = None;
    assert_eq!(tick(&mut notice, &mut terminal), Some(title::POP.to_vec()));
    assert_eq!(terminal.seen(), before, "{}", terminal.screen.show());
    assert!(!notice.shows());
}

#[test]
fn the_title_comes_back_before_the_far_end_s_next_bytes() {
    let (words, silent) = silence();
    let mut notice = Notice::new(Place::Title, &words, "node://lab", Some(b'~'));
    let mut terminal = Terminal::new();
    output(&mut notice, &mut terminal, PROGRAM);
    *silent.lock().unwrap() = Some(Duration::from_secs(5));
    tick(&mut notice, &mut terminal).expect("the notice shows");
    // The program sets a new title in its first bytes after the silence:
    // that title stays, not the one under the notice.
    *silent.lock().unwrap() = None;
    output(&mut notice, &mut terminal, b"\x1b]2;vi other.txt\x07x");
    assert!(!notice.shows());
    assert_eq!(terminal.titles.now, "vi other.txt");
    assert!(terminal.titles.stack.is_empty());
    assert_eq!(tick(&mut notice, &mut terminal), None, "nothing more to take back");
}

#[test]
fn the_notice_waits_for_the_end_of_a_sequence_that_the_far_end_cut() {
    let (words, silent) = silence();
    let mut notice = Notice::new(Place::Title, &words, "node://lab", None);
    let mut terminal = Terminal::new();
    // The output stops inside a control sequence, and inside a character.
    for cut in [&b"\x1b[12;3"[..], &b"caf\xc3"[..], &b"\x1b]2;half a tit"[..]] {
        output(&mut notice, &mut terminal, cut);
        *silent.lock().unwrap() = Some(Duration::from_secs(9));
        assert_eq!(tick(&mut notice, &mut terminal), None, "nothing inside {cut:?}");
        // The rest comes: the notice may show.
        let rest: &[u8] = match cut[cut.len() - 1] {
            b'3' => b"0H",
            0xc3 => b"\xa9",
            _ => b"le\x07",
        };
        output(&mut notice, &mut terminal, rest);
        assert!(tick(&mut notice, &mut terminal).is_some(), "after {cut:?}");
        *silent.lock().unwrap() = None;
        assert_eq!(tick(&mut notice, &mut terminal), Some(title::POP.to_vec()));
    }
    // The cut sequence moved the cursor to row 12, column 30: the character
    // cut in two shows whole there.
    assert!(terminal.screen.rows()[11].ends_with("café"), "{}", terminal.screen.show());
}

/// The control of the check of the screen: a notice written at the cursor,
/// as a line, changes the screen of the program.
#[test]
fn a_notice_written_at_the_cursor_changes_the_screen() {
    let (words, silent) = silence();
    let mut notice = Notice::new(Place::Line, &words, "node://lab", Some(b'~'));
    let mut terminal = Terminal::new();
    output(&mut notice, &mut terminal, PROGRAM);
    let before = terminal.seen();
    *silent.lock().unwrap() = Some(Duration::from_secs(5));
    let Some(Action::Say(line)) = notice.tick(Instant::now()) else { panic!("a line") };
    terminal.feed(podssh_ssh::log::message_text(&line, true, true).as_bytes());
    assert_ne!(terminal.seen().0, before.0, "a line at the cursor is written into the screen");
    *silent.lock().unwrap() = None;
    let Some(Action::Say(back)) = notice.tick(Instant::now()) else { panic!("a line") };
    assert!(back.starts_with("node://lab answers again, after "), "{back}");
}

#[test]
fn the_escape_character_shows_as_a_person_types_it() {
    let (words, silent) = silence();
    *silent.lock().unwrap() = Some(Duration::from_secs(12));
    for (escape, says) in [(Some(b'%'), "%. ends"), (Some(0x1d), "^]. ends"), (None, "for 12 s")] {
        let mut notice = Notice::new(Place::Title, &words, "h", escape);
        let mut terminal = Terminal::new();
        tick(&mut notice, &mut terminal).expect("the notice shows");
        assert!(terminal.titles.now.contains(says), "{escape:?}: {:?}", terminal.titles);
        assert!(!terminal.titles.now.contains('\x1d'), "no control character in the title");
        *silent.lock().unwrap() = None;
        tick(&mut notice, &mut terminal).expect("the title comes back");
        *silent.lock().unwrap() = Some(Duration::from_secs(12));
    }
}
