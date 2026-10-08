//! The manual as plain text: what `podssh man` writes. Lines are filled to
//! [`WIDTH`] columns so the page reads in an 80-column terminal, and the text
//! is ASCII so it reads on any terminal and in any log.

use std::fmt::Write as _;

use super::model::{plain, Block, Manual, Section};

/// The widest line, except a word that is longer by itself.
pub const WIDTH: usize = 79;

pub fn render(manual: &Manual) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "podssh {} - {}", crate::help::version(), crate::flags::ABOUT);
    out.push('\n');
    blocks(&mut out, &manual.intro);
    let mut commands = false;
    for s in &manual.sections {
        if s.command && !commands {
            out.push_str("\nCOMMAND REFERENCE\n");
            commands = true;
        }
        out.push('\n');
        section(&mut out, s);
    }
    out
}

/// One section, as `podssh man SECTION` writes it.
pub fn render_section(s: &Section) -> String {
    let mut out = String::new();
    section(&mut out, s);
    out
}

fn section(out: &mut String, s: &Section) {
    out.push_str(&s.heading);
    out.push('\n');
    blocks(out, &s.blocks);
}

/// The blocks of one section. A blank line separates blocks, except after a
/// sub-heading and between the items of one list. After a sub-heading, the
/// blocks move in by two.
fn blocks(out: &mut String, list: &[Block]) {
    let mut indent = 2;
    let mut previous: Option<&Block> = None;
    for b in list {
        let tight = matches!(
            (previous, b),
            (Some(Block::Sub(_)), _) | (Some(Block::Item { .. }), Block::Item { .. })
        );
        if previous.is_some() && !tight {
            out.push('\n');
        }
        match b {
            Block::Para(t) => fill(out, t, indent, indent),
            Block::Line(spans) => {
                let _ = writeln!(out, "{:indent$}{}", "", plain(spans));
            }
            Block::Sub(t) => {
                let _ = writeln!(out, "  {t}:");
                indent = 4;
            }
            Block::Item { term, text } => {
                // A long term, such as a list of files, wraps at its spaces.
                fill(out, &plain(term), indent, indent);
                if !text.is_empty() {
                    fill(out, text, indent + 4, indent + 4);
                }
            }
            Block::Table(rows) => table(out, rows, indent),
            Block::Example { text, command } => {
                fill(out, text, indent, indent);
                let _ = writeln!(out, "{:w$}{}", "", command, w = indent + 4);
            }
        }
        previous = Some(b);
    }
}

/// Two columns: the terms, padded to the widest (up to a limit), then the
/// text, filled with a hanging indent. A wider term puts its text below.
fn table(out: &mut String, rows: &[(Vec<super::model::Span>, String)], indent: usize) {
    const MAX_TERM: usize = 16;
    let column = rows.iter().map(|(t, _)| plain(t).len()).filter(|w| *w <= MAX_TERM).max().unwrap_or(0) + 2;
    for (term, text) in rows {
        let term = plain(term);
        if term.len() + 2 > column {
            let _ = writeln!(out, "{:indent$}{term}", "");
            fill(out, text, indent + column, indent + column);
        } else {
            let mut first = format!("{:indent$}{term:<column$}", "");
            let width = WIDTH.saturating_sub(indent + column).max(20);
            let lines = wrap(text, width);
            first.push_str(lines.first().map(String::as_str).unwrap_or(""));
            out.push_str(first.trim_end());
            out.push('\n');
            for l in lines.iter().skip(1) {
                let _ = writeln!(out, "{:w$}{l}", "", w = indent + column);
            }
        }
    }
}

/// `text`, filled to [`WIDTH`]: the first line after `first` spaces, the
/// others after `rest` spaces.
fn fill(out: &mut String, text: &str, first: usize, rest: usize) {
    let width = WIDTH.saturating_sub(rest).max(20);
    for (i, line) in wrap(text, width).iter().enumerate() {
        let pad = if i == 0 { first } else { rest };
        let _ = writeln!(out, "{:pad$}{line}", "");
    }
}

/// The words of `text` in lines of `width` or fewer characters. A word that
/// is longer by itself gets its own line, unbroken: a broken flag name is a
/// flag name that nobody can type.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::man::model::{manual, Span};

    /// An example's command stays on one line, to be copied whole; each
    /// other line fits the page, unless it is one long word.
    #[test]
    fn no_line_is_wider_than_the_page_except_one_long_word() {
        let m = manual();
        let commands: Vec<String> = m
            .intro
            .iter()
            .chain(m.sections.iter().flat_map(|s| s.blocks.iter()))
            .filter_map(|b| match b {
                Block::Example { command, .. } => Some(command.clone()),
                _ => None,
            })
            .collect();
        let page = render(&m);
        for line in page.lines() {
            if line.len() > WIDTH && !commands.iter().any(|c| c == line.trim()) {
                let words = line.split_whitespace().count();
                assert_eq!(words, 1, "a line of {} characters: {line:?}", line.len());
            }
        }
    }

    #[test]
    fn the_page_is_ascii_and_has_no_trailing_spaces() {
        let page = render(&manual());
        assert!(page.is_ascii(), "the page is not ASCII");
        for line in page.lines() {
            assert_eq!(line, line.trim_end(), "trailing space: {line:?}");
        }
    }

    #[test]
    fn wrap_keeps_each_word_and_their_order() {
        let text = "a bb ccc dddd eeeee --a-very-long-flag-name-that-is-wider-than-the-width f";
        let lines = wrap(text, 10);
        assert_eq!(lines.join(" "), text);
        assert!(lines.iter().all(|l| l.len() <= 10 || !l.contains(' ')), "{lines:?}");
    }

    /// Each item of the model is on the page: its term, then its text.
    #[test]
    fn each_item_of_the_model_is_on_the_page() {
        let m = manual();
        let squeeze = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
        let page = squeeze(&render(&m));
        for s in &m.sections {
            for b in &s.blocks {
                if let Block::Item { term, text } = b {
                    let item = squeeze(&format!("{} {text}", plain(term)));
                    assert!(page.contains(&item), "{}: {item:?} is missing", s.key);
                }
            }
        }
    }

    #[test]
    fn the_page_starts_with_the_name_the_version_and_the_commands() {
        let page = render(&manual());
        let first = page.lines().next().unwrap();
        assert_eq!(first, format!("podssh {} - {}", crate::help::version(), crate::flags::ABOUT));
        assert!(page.contains("\nCOMMAND REFERENCE\n"));
        for v in crate::flags::VERBS {
            assert!(page.contains(&format!("\n{}\n", v.name.to_ascii_uppercase())), "no section {}", v.name);
        }
    }

    #[test]
    fn a_table_puts_a_wide_term_on_its_own_line() {
        let mut out = String::new();
        let rows = vec![
            (vec![Span::Lit("ab".into())], "short".to_string()),
            (vec![Span::Lit("a-term-that-is-too-wide".into())], "below".to_string()),
        ];
        table(&mut out, &rows, 2);
        assert_eq!(out, "  ab  short\n  a-term-that-is-too-wide\n      below\n");
    }
}
