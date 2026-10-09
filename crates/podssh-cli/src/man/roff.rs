//! The manual as a man(7) page: what `podssh man --roff` writes, for
//! `man -l` or a man directory. It uses only man(7) macros and requests that
//! groff and mandoc both render, and it defines no macro of its own: a
//! macro defined in the page is roff that one renderer reads differently from
//! another (an `Fl` macro that used `\$*` printed blank flag names under
//! groff).

use std::fmt::Write as _;

use super::model::{Block, Manual, Section, Span};

/// Each request the page may contain.
pub const MACROS: &[&str] = &[".TH", ".SH", ".SS", ".PP", ".TP", ".RS", ".RE", ".nf", ".fi", ".nh", ".ad"];

/// Text made safe for roff: a backslash is `\e`, a hyphen is `\-` (the
/// hyphen-minus that a user types), and a line that starts with `.` or `'`
/// starts with the zero-width `\&`, so no text can become a request.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut line_start = true;
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\e"),
            '-' => out.push_str("\\-"),
            '\n' => {
                out.push('\n');
                line_start = true;
                continue;
            }
            '.' | '\'' if line_start => {
                out.push_str("\\&");
                out.push(c);
            }
            _ => out.push(c),
        }
        line_start = false;
    }
    out
}

/// A term: what a user types in bold, a value to replace in italics.
fn spans(list: &[Span]) -> String {
    let mut out = String::new();
    for s in list {
        match s {
            Span::Lit(t) => {
                let _ = write!(out, "\\fB{}\\fR", escape(t));
            }
            Span::Var(t) => {
                let _ = write!(out, "\\fI{}\\fR", escape(t));
            }
            Span::Plain(t) => out.push_str(&escape(t)),
        }
    }
    // A term that starts with a space or a period must not start a request.
    if out.starts_with(['.', '\'']) {
        out.insert_str(0, "\\&");
    }
    out
}

/// `title` is `PODSSH` or `PODSSH-` and a section key: letters and hyphens,
/// which a header shows as they are.
fn header(out: &mut String, title: &str) {
    debug_assert!(title.chars().all(|c| c.is_ascii_uppercase() || c == '-'), "{title}");
    let _ = writeln!(out, ".TH {title} 1 \"\" \"podssh {}\" \"podssh manual\"", escape(&crate::help::version()));
    // No hyphenation, and a ragged right margin: a flag broken at a line
    // end, or spread with extra spaces, cannot be copied.
    out.push_str(".nh\n.ad l\n");
}

pub fn render(manual: &Manual) -> String {
    let mut out = String::new();
    header(&mut out, "PODSSH");
    out.push_str(".SH NAME\n");
    let _ = writeln!(out, "podssh \\- {}", escape(crate::flags::ABOUT));
    out.push_str(".SH SYNOPSIS\n");
    out.push_str("\\fBpodssh\\fR \\fICOMMAND\\fR [\\fIOPTIONS\\fR]\n");
    out.push_str(".SH DESCRIPTION\n");
    blocks(&mut out, &manual.intro);
    let mut commands = false;
    for s in &manual.sections {
        if s.command {
            if !commands {
                out.push_str(".SH COMMANDS\n");
                commands = true;
            }
            let _ = writeln!(out, ".SS {}", escape(s.key));
        } else {
            let _ = writeln!(out, ".SH \"{}\"", escape(&s.heading));
        }
        blocks(&mut out, &s.blocks);
    }
    out
}

/// One section, as `podssh man --roff SECTION` writes it.
pub fn render_section(s: &Section) -> String {
    let mut out = String::new();
    header(&mut out, &format!("PODSSH-{}", s.key.to_ascii_uppercase()));
    let _ = writeln!(out, ".SH \"{}\"", escape(&s.heading));
    blocks(&mut out, &s.blocks);
    out
}

/// The blocks after a heading. A heading starts a paragraph itself, so the
/// first block needs no `.PP` (mandoc warns about one).
fn blocks(out: &mut String, list: &[Block]) {
    for (i, b) in list.iter().enumerate() {
        let pp = if i == 0 { "" } else { ".PP\n" };
        match b {
            Block::Para(t) => {
                let _ = writeln!(out, "{pp}{}", escape(t));
            }
            Block::Line(s) => {
                let _ = writeln!(out, "{pp}{}", spans(s));
            }
            Block::Sub(t) => {
                let _ = writeln!(out, "{pp}\\fB{}:\\fR", escape(t));
            }
            Block::Item { term, text } => item(out, term, text),
            Block::Table(rows) => {
                for (term, text) in rows {
                    item(out, term, text);
                }
            }
            Block::Example { text, command } => {
                let _ = writeln!(out, "{pp}{}\n.RS 4\n.nf\n{}\n.fi\n.RE", escape(text), escape(command));
            }
        }
    }
}

fn item(out: &mut String, term: &[Span], text: &str) {
    let _ = writeln!(out, ".TP\n{}", spans(term));
    if !text.is_empty() {
        let _ = writeln!(out, "{}", escape(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::man::model::{flag_term, manual, plain};

    #[test]
    fn the_first_line_is_th_and_the_name_follows() {
        let page = render(&manual());
        let first = page.lines().next().unwrap();
        assert!(first.starts_with(".TH PODSSH 1 "), "{first}");
        assert!(page.contains(".SH NAME\npodssh \\- "), "no NAME section");
    }

    /// Each request line of the page is one of [`MACROS`]: no text became a
    /// request, and no macro is defined.
    #[test]
    fn the_page_uses_only_the_listed_requests() {
        let m = manual();
        let mut pages = vec![render(&m)];
        pages.extend(m.sections.iter().map(render_section));
        for page in pages {
            for line in page.lines().filter(|l| l.starts_with(['.', '\''])) {
                let request = line.split_whitespace().next().unwrap();
                assert!(MACROS.contains(&request), "unlisted request {request:?} in {line:?}");
            }
        }
    }

    /// A planted text that tries to start a request, change a font or end a
    /// macro argument stays text.
    #[test]
    fn text_cannot_become_a_request() {
        let planted = ".SH INJECTED\n'br\n\\fBbold\\fR -flag";
        assert_eq!(escape(planted), "\\&.SH INJECTED\n\\&'br\n\\efBbold\\efR \\-flag");
        let mut out = String::new();
        item(&mut out, &[Span::Lit(".x".into())], planted);
        let requests: Vec<&str> = out.lines().filter(|l| l.starts_with(['.', '\''])).collect();
        assert_eq!(requests, vec![".TP"], "{out}");
    }

    /// Each flag of `ssh` is a `.TP` term with its spelling in bold.
    #[test]
    fn each_flag_is_a_tagged_paragraph_in_bold() {
        let page = render(&manual());
        for row in crate::flags::SSH_FLAGS {
            let term = spans(&flag_term(row));
            assert!(page.contains(&format!(".TP\n{term}\n")), "{}: no .TP for {term}", plain(&flag_term(row)));
            assert!(term.contains(&format!("\\fB\\-\\-{}\\fR", escape(row.long))), "{term}");
        }
    }
}
