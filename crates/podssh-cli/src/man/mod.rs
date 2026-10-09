//! `podssh man`: the manual of this binary, generated from its own tables.
//!
//! The manual must be enough on a host that has only the binary: no man(1),
//! no groff, no pager, no network, no documents. So it is plain text that
//! podssh writes itself, and it covers each command, argument, flag, `-o`
//! keyword, variable, file, relay fact and exit code. Nothing in it is typed
//! twice: [`model`] builds it from the tables that the parser and the
//! commands use, and the tests in each module check it against them.
//!
//! - `podssh man` pages the text on a terminal, else writes it to stdout.
//! - `--no-pager` writes it to stdout, also on a terminal.
//! - `--roff` writes a man(7) page instead, for `man -l` or a man directory.
//! - `--json` writes the tables as one JSON object, for a program.
//! - `podssh man SECTION` writes one section: a command, or a topic.

pub mod data;
pub mod examples;
pub mod facts;
pub mod json;
pub mod model;
pub mod notes;
pub mod roff;
pub mod text;

use std::io::{BufRead, Write};

/// What the command line asked for.
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<'a> {
    pub section: Option<&'a str>,
    pub no_pager: bool,
    pub roff: bool,
    pub json: bool,
}

/// The whole manual as text, as `podssh man --no-pager` writes it.
pub fn page() -> String {
    text::render(&model::manual())
}

/// The whole manual as a man(7) page, as `podssh man --roff` writes it.
pub fn roff_page() -> String {
    roff::render(&model::manual())
}

/// The bytes for `req`, or the refusal for a section that does not exist.
pub fn body(req: &Request<'_>) -> Result<String, String> {
    if req.json {
        if req.roff {
            return Err("podssh man: --json and --roff are two forms of the manual; give one".into());
        }
        let doc = match req.section {
            None => json::document(),
            Some(name) => json::section(name)?,
        };
        return Ok(serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n");
    }
    let manual = model::manual();
    match req.section {
        None if req.roff => Ok(roff::render(&manual)),
        None => Ok(text::render(&manual)),
        Some(name) => match manual.find(name) {
            Some(s) if req.roff => Ok(roff::render_section(s)),
            Some(s) => Ok(text::render_section(s)),
            None => Err(crate::refuse::unknown_man_section(name, &manual.keys())),
        },
    }
}

/// Run `podssh man`; returns the exit code. The manual goes to stdout, the
/// same bytes on each path; a pager is used only when both stdin and stdout
/// are a terminal. `keys` is where the built-in pager reads its keys.
pub fn run(
    req: &Request<'_>,
    tty: crate::pager::Tty,
    keys: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let body = match body(req) {
        Ok(b) => b,
        Err(refusal) => {
            let _ = writeln!(err, "{refusal}");
            return crate::exit_codes::EXIT_USAGE;
        }
    };
    if req.no_pager || req.roff || req.json || !tty.can_page() {
        // A reader that went away (`podssh man | head`) is not a failure.
        let _ = out.write_all(body.as_bytes());
        let _ = out.flush();
        return 0;
    }
    crate::pager::show(&body, &crate::pager::PagerEnv::from_process(), keys, out, err);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pager::Tty;
    use std::io::Cursor;

    fn run_with(req: Request<'_>, tty: Tty) -> (i32, String, String) {
        let mut keys = Cursor::new(Vec::new());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc = run(&req, tty, &mut keys, &mut out, &mut err);
        (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    /// With no terminal there is no pager: the whole manual, nothing on stderr.
    #[test]
    fn with_no_terminal_the_whole_manual_is_written() {
        let (rc, out, err) = run_with(Request::default(), Tty::none());
        assert_eq!(rc, 0);
        assert_eq!(out, page());
        assert!(err.is_empty(), "{err}");
    }

    #[test]
    fn no_pager_and_roff_write_at_once_even_on_a_terminal() {
        let tty = Tty { stdin: true, stdout: true };
        let (rc, out, _) = run_with(Request { no_pager: true, ..Default::default() }, tty);
        assert_eq!((rc, out), (0, page()));
        let (rc, out, _) = run_with(Request { roff: true, ..Default::default() }, tty);
        assert_eq!((rc, out), (0, roff_page()));
    }

    #[test]
    fn a_section_is_found_by_its_name_or_an_alias() {
        for (name, heading) in
            [("ssh", "SSH\n"), ("connect", "SSH\n"), ("env", "ENVIRONMENT\n"), ("EXIT", "EXIT STATUS\n")]
        {
            let (rc, out, _) = run_with(Request { section: Some(name), ..Default::default() }, Tty::none());
            assert_eq!(rc, 0, "{name}");
            assert!(out.starts_with(heading), "{name}: {out}");
        }
        let (rc, out, _) = run_with(Request { section: Some("proxy"), roff: true, ..Default::default() }, Tty::none());
        assert_eq!(rc, 0);
        assert!(out.starts_with(".TH PODSSH-PROXY 1 "), "{out}");
    }

    /// An unknown section is a usage error that lists the real sections, and
    /// nothing reaches stdout.
    #[test]
    fn an_unknown_section_is_refused_with_the_list() {
        let (rc, out, err) = run_with(Request { section: Some("nonsense"), ..Default::default() }, Tty::none());
        assert_eq!(rc, crate::exit_codes::EXIT_USAGE);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("nonsense"), "{err}");
        for key in model::manual().keys() {
            assert!(err.contains(key), "the refusal does not list {key}: {err}");
        }
    }
}
