//! Dispatch: the parse result becomes bytes on two streams and an exit code.
//!
//! ⛔ **stdout carries the answer and nothing else.** `06-cli.md`:251-252:
//! *"stdout is protocol data or the answer, and nothing else. Diagnostics go to
//! stderr, always, in every subcommand."* ⛔ This module is where that is
//! enforced, and it is the module E31's plant 6 targets: one `println!` on the
//! wrong path and `podssh example.org 2>/dev/null | wc -c` stops reading 0.
//!
//! ⛔ **The terminal state is a parameter, not a probe.** [`run`] — the entry
//! point every test calls — gets [`Tty::none`], so ⛔ no test can enter the
//! pager and block on a terminal; [`main_with_args`] asks the operating system
//! once, where the real file descriptors are, and passes the answer down.

use std::io::Write;

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::flags::VERB_OWNER;
use crate::help;
use crate::pager::Tty;
use crate::tree::Parsed;

/// The two streams, as a pair of sinks, so a test can assert on both without
/// spawning a process. ⛔ This is what makes plant 6 a unit test as well as a
/// shell assertion — and the shell assertion is still the one that counts,
/// because it runs the real binary.
pub struct Streams<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

/// Run a parsed command line **with no terminal**. Returns the process exit
/// code.
///
/// ⛔ This is the entry point tests use, and it cannot page — ⛔ `RULES.md`:101
/// puts it as *"nothing blocks on a terminal"*, and a test that could page
/// would block on a key nobody presses.
pub fn run(p: &Parsed, s: &mut Streams<'_>) -> i32 {
    run_with(p, s, Tty::none())
}

/// Run a parsed command line, with the terminal state the caller probed.
pub fn run_with(p: &Parsed, s: &mut Streams<'_>, tty: Tty) -> i32 {
    match p {
        Parsed::Help(section) => {
            let text = if section.is_empty() {
                help::top_level_help()
            } else {
                match crate::flags::verb_for(section) {
                    Some(v) => help::verb_help(v),
                    None => help::top_level_help(),
                }
            };
            let _ = s.out.write_all(text.as_bytes());
            0
        }
        Parsed::Version => {
            let _ = writeln!(s.out, "podssh {}", help::version());
            0
        }
        // ⛔ A usage error is a refusal. Nothing goes to stdout, because the
        // only thing that should ever be there is an answer.
        Parsed::Usage(m) => {
            let _ = writeln!(s.err, "{m}");
            EXIT_USAGE
        }
        Parsed::NoArguments(m) => {
            let _ = writeln!(s.err, "{m}");
            EXIT_USAGE
        }
        Parsed::UnknownVerb(m) => {
            let _ = writeln!(s.err, "{m}");
            EXIT_USAGE
        }
        // Refusals are read first, so a `Refused` row added to `MAN_FLAGS`
        // later refuses rather than being dropped.
        Parsed::Man { section, no_pager, roff, refused } => {
            if refusals("man", refused, s.err) {
                return EXIT_USAGE;
            }
            let stdin = std::io::stdin();
            let mut keys = stdin.lock();
            let request = crate::man::Request { section: section.as_deref(), no_pager: *no_pager, roff: *roff };
            crate::man::run(&request, tty, &mut keys, s.out, s.err)
        }
        Parsed::Proxy { target, port, relay_host, relay_addr, ca_file, refused } => {
            if refusals("proxy", refused, s.err) {
                return EXIT_USAGE;
            }
            crate::proxy::run_proxy(
                &crate::proxy::ProxyArgs {
                    target: target.clone(),
                    port: port.clone(),
                    relay_host: relay_host.clone(),
                    relay_addr: relay_addr.clone(),
                    ca_file: ca_file.clone(),
                },
                s.err,
            )
        }
        Parsed::Doctor { relay_host, relay_addr, ca_file, refused } => {
            if refusals("doctor", refused, s.err) {
                return EXIT_USAGE;
            }
            crate::doctor::run_doctor(
                &crate::doctor::DoctorArgs {
                    relay_host: relay_host.clone(),
                    relay_addr: relay_addr.clone(),
                    ca_file: ca_file.clone(),
                },
                s.out,
                s.err,
            )
        }
        // A build without the `ts` feature still parses `ts` (so help and the
        // man page stay complete) but refuses it, naming the feature.
        #[cfg(not(feature = "ts"))]
        Parsed::Ts { refused, .. } => {
            if refusals("ts", refused, s.err) {
                return EXIT_USAGE;
            }
            let _ = writeln!(
                s.err,
                "podssh: 'ts' is not available in this build.\n  \
                 It was compiled without Tailscale support; rebuild with \
                 `cargo build -p podssh-cli --features ts`."
            );
            EXIT_NOT_IMPLEMENTED
        }
        // ⛔ `ts` is dispatched, not refused: `ts.rs` owns the verb the way
        // `man.rs` owns `man`. The VERB_OWNER row is gone — and
        // `tests/ts_behave.rs` proves no `ts` shape exits 0 having done
        // nothing, which is what the row used to guarantee.
        #[cfg(feature = "ts")]
        Parsed::Ts {
            destination,
            args,
            w_target,
            mode,
            proxy,
            auth_key_file,
            state,
            ephemeral,
            relay,
            wait_allowlist,
            refused,
            timeout,
            jsonl,
        } => {
            if refusals("ts", refused, s.err) {
                return EXIT_USAGE;
            }
            crate::ts::run_ts(
                &crate::ts::TsArgs {
                    destination: destination.clone(),
                    args: args.clone(),
                    w_target: w_target.clone(),
                    mode: mode.clone(),
                    proxy: proxy.clone(),
                    auth_key_file: auth_key_file.clone(),
                    state: state.clone(),
                    ephemeral: *ephemeral,
                    relay: relay.clone(),
                    wait_allowlist: wait_allowlist.clone(),
                    timeout: timeout.clone(),
                    jsonl: *jsonl,
                },
                s.out,
                s.err,
                tty,
            )
        }
        Parsed::Command { verb, refused, tag, timeout, jsonl, ssh, keygen } => {
            // ⛔ `-P TAG` on ssh: accepted, ignored, and it says so on stderr so
            // a user who meant a port learns before the connection fails.
            if let Some(t) = tag {
                let _ = writeln!(s.err, "{}", crate::refuse::accepted_tag_notice(t));
            }
            // ⛔ E33's gate, computed once and passed down: the attachment from
            // the probed TTY and `--jsonl`, then the required `--timeout`.
            // Only verbs whose table declares `--timeout` enter the gate, so
            // enforcement follows the flag's existence and never invents a
            // requirement the tree cannot satisfy (`ssh` carries no timeout
            // row and skips it). `man` never reaches here (handled above: it
            // has no `--timeout` row and its pipeless acceptance forbids one),
            // and neither do `Help`/`Version` or the parse-level refusals.
            //
            // A verb that is not implemented skips the gate and is refused
            // below (70): it has nothing to bound, and a 64 would tell a script
            // that its command line is wrong. A --timeout that was given and
            // does not parse is wrong for each verb, so it stays 64.
            let not_yet = VERB_OWNER.iter().any(|(name, _)| *name == *verb);
            let gated = crate::flags::verb_for(verb).is_some_and(|v| v.flags.iter().any(|r| r.long == "timeout"));
            let checked = if not_yet {
                timeout.as_deref().map(crate::non_interactive::parse_timeout).transpose()
            } else if gated {
                let attachment = crate::non_interactive::resolve_tty(tty, *jsonl);
                crate::non_interactive::require_timeout(verb, attachment, timeout.as_deref())
            } else {
                Ok(None)
            };
            if let Err(refusal) = checked {
                let _ = writeln!(s.err, "{}", refusal.message);
                return refusal.fault.code();
            }
            // ⛔ Refused flags first, and they refuse before anything else
            // happens, so nothing is half-done.
            if refusals(verb, refused, s.err) {
                return EXIT_USAGE;
            }
            if let Some(args) = ssh {
                return crate::ssh::run_ssh(args, s.err);
            }
            if let Some(args) = keygen {
                return crate::keygen::run_keygen(args, s.out, s.err);
            }
            // A verb that parses and has no behaviour is refused, never a stub
            // that exits 0. A verb with neither a handler above nor a
            // VERB_OWNER row is a dispatch bug, and is refused the same way.
            if VERB_OWNER.iter().any(|(name, _)| *name == *verb) {
                let _ = writeln!(s.err, "{}", crate::refuse::not_implemented(verb));
            } else {
                let _ = writeln!(s.err, "podssh: internal error: '{verb}' has no handler.");
            }
            EXIT_NOT_IMPLEMENTED
        }
    }
}

/// Print every refused flag, and say whether there was one. ⛔ One function so
/// `man` and every other verb refuse in the same words.
///
/// ⛔ **The third line is the row's own reason.** It used to be `-L`'s
/// sentence — "podssh never binds a listener, so it cannot forward" — for
/// **every** refused row, which is wrong for `-R` (its reason is *"remote
/// forwarding is not in the first release"*) and read as a contradiction beside
/// the `-W HOST:PORT` the same message recommends.
fn refusals(verb: &str, refused: &[(String, &'static str, &'static str)], err: &mut dyn Write) -> bool {
    if refused.is_empty() {
        return false;
    }
    for (given, instead, reason) in refused {
        let _ = if *instead == "no flag" {
            writeln!(err, "podssh {verb}: {given} is refused. Leave it out.\n  {reason}.")
        } else {
            writeln!(err, "podssh {verb}: {given} is refused.\n  Use {instead} instead.\n  {reason}.")
        };
    }
    true
}

/// The one function `main` calls. ⛔ It is here rather than in `main.rs` so a
/// test can call the whole path — parse, dispatch, both streams, exit code —
/// with no process and no pipe.
pub fn main_with_args<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let parsed = crate::tree::parse(args);
    // Unlocked handles: each write takes the lock briefly. Holding the lock
    // for the whole run would deadlock any verb that writes through
    // tokio's stdout, which locks from a helper thread.
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let rc = run_with(
        &parsed,
        &mut Streams { out: &mut out, err: &mut err },
        Tty::probed(),
    );
    let _ = out.flush();
    let _ = err.flush();
    rc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ **Plant 6, as a unit test.** The shell assertion
    /// `podssh example.org 2>/dev/null | wc -c` is the acceptance; this is the
    /// same claim with both streams captured, so a `println!` on a refusal path
    /// fails here as well.
    #[test]
    fn nothing_but_the_answer_reaches_stdout() {
        let cases: Vec<Vec<&str>> = vec![
            vec![],
            vec!["example.org"],
            vec!["user@example.org"],
            vec!["sttaus"],
            vec!["chatr"],
            vec!["xz"],
            vec!["ssh", "--StrictHostKeyChekcing=no", "host"],
            vec!["ssh", "-L", "8080:db:5432", "host"],
            vec!["--bogus"],
            vec!["-Z"],
        ];
        for c in cases {
            let p = crate::tree::parse(c.clone());
            assert!(p.needs_refusal(), "{c:?} should be a refusal");
            let mut out: Vec<u8> = Vec::new();
            let mut err: Vec<u8> = Vec::new();
            let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
            assert_eq!(rc, EXIT_USAGE, "{c:?} exit");
            assert!(out.is_empty(), "{c:?} wrote {} bytes to stdout", out.len());
            assert!(!err.is_empty(), "{c:?} wrote nothing to stderr");
        }
    }

    #[test]
    fn the_refusal_text_goes_where_the_entry_says() {
        let p = crate::tree::parse(vec!["example.org"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, 64);
        let text = String::from_utf8(err).unwrap();
        assert!(text.contains("Try: podssh ssh example.org"), "{text}");
        // ⛔ `doctor` is ON the printed subcommand list; what must not happen is
        // it being SUGGESTED. The only "Try:" line names ssh.
        let tries: Vec<&str> = text.lines().filter(|l| l.starts_with("Try:")).collect();
        assert_eq!(tries, vec!["Try: podssh ssh example.org"], "{text}");
    }

    #[test]
    fn help_and_version_do_go_to_stdout() {
        for c in [vec!["--help"], vec!["ssh", "--help"], vec!["--version"]] {
            let p = crate::tree::parse(c.clone());
            let mut out: Vec<u8> = Vec::new();
            let mut err: Vec<u8> = Vec::new();
            let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
            assert_eq!(rc, 0, "{c:?}");
            assert!(!out.is_empty(), "{c:?} printed nothing to stdout");
        }
    }

    #[test]
    fn a_parsed_verb_with_no_behaviour_refuses_and_is_not_zero() {
        let p = crate::tree::parse(vec!["status"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_ne!(rc, 0, "an unimplemented verb must never exit 0");
        assert!(out.is_empty());
        assert!(String::from_utf8(err).unwrap().contains("not implemented yet"));
    }

    #[test]
    fn minus_p_on_ssh_prints_a_notice_and_still_refuses_the_missing_behaviour() {
        // A destination the relay cannot take: ssh stops before any network.
        let p = crate::tree::parse(vec!["ssh", "-P", "mytag", "invalid!host"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_ne!(rc, 0);
        let text = String::from_utf8(err).unwrap();
        assert!(text.contains("accepted and ignored"), "{text}");
        assert!(text.contains("For a port use -p"), "{text}");
    }

    #[test]
    fn a_refused_flag_names_its_replacement_on_stderr() {
        let p = crate::tree::parse(vec!["ssh", "-L", "8080:db:5432", "host"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, 64);
        let text = String::from_utf8(err).unwrap();
        assert!(text.contains("-L"), "{text}");
        assert!(text.contains("-W HOST:PORT"), "{text}");
        assert!(!text.contains("Usage:"), "no usage header: {text}");
        assert!(!text.contains("For more information"), "no clap trailer: {text}");
    }

    /// `man` is dispatched, not refused: with no terminal it writes the
    /// whole manual to stdout and exits 0.
    #[test]
    fn man_writes_the_page_to_stdout_and_exits_zero() {
        let p = crate::tree::parse(vec!["man"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        // ⛔ `run` and not `run_with`: the test entry point has no terminal, so
        // this can never page and never block.
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, 0, "stderr: {}", String::from_utf8_lossy(&err));
        assert_eq!(String::from_utf8(out).unwrap(), crate::man::page());
        assert!(err.is_empty(), "{:?}", String::from_utf8_lossy(&err));
    }

    /// ⛔ The control for the refusal path: an unknown man section is a usage
    /// error at exit **64**, with nothing on stdout.
    #[test]
    fn an_unknown_man_section_is_a_usage_error() {
        let p = crate::tree::parse(vec!["man", "nonsense"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, EXIT_USAGE);
        assert!(out.is_empty());
        assert!(String::from_utf8(err).unwrap().contains("nonsense"));
    }

    /// ⛔ **E33 Prove check 6, as a unit test.** `run` uses `Tty::none`, which
    /// is a pipe: `chat --send` with no `--timeout` is refused as a verb that
    /// is not implemented (70), not as a usage error that asks for a flag
    /// that would change nothing (GitHub #6).
    #[test]
    fn chat_without_timeout_in_a_pipe_is_refused_as_not_implemented() {
        let p = crate::tree::parse(vec!["chat", "--send", "#chan hi"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        let err = String::from_utf8(err).unwrap();
        assert_eq!(rc, EXIT_NOT_IMPLEMENTED, "{err}");
        assert!(out.is_empty(), "a refusal writes nothing to stdout");
        assert!(err.contains("not implemented yet") && !err.contains("--timeout"), "{err}");
    }

    /// The gate's message names its verb, one true reason, and an example of
    /// that verb; no internal name and no other verb (GitHub #6).
    #[test]
    fn the_timeout_refusal_names_the_verb() {
        use crate::non_interactive::{require_timeout, Attachment};
        let m = require_timeout("ts", Attachment::Pipe, None).unwrap_err().message;
        assert!(
            m.starts_with("podssh ts: --timeout DURATION is required when stdin or stdout is not a terminal"),
            "{m}"
        );
        assert!(m.contains("Example: podssh ts --timeout 30s -W HOST:PORT"), "{m}");
        assert!(!m.contains("chat") && !m.contains("Pipe") && !m.contains("hangs for ever"), "{m}");
        let m = require_timeout("ts", Attachment::Forced, None).unwrap_err().message;
        assert!(m.contains("when --jsonl was given"), "{m}");
    }

    /// A valid `--timeout` passes the gate; `chat` itself is still E33's to
    /// build, so it lands on the unimplemented refusal, not on 64.
    #[test]
    fn chat_with_a_valid_timeout_passes_the_gate() {
        let p = crate::tree::parse(vec!["chat", "--send", "#chan hi", "--timeout", "30s"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, EXIT_NOT_IMPLEMENTED);
        assert!(out.is_empty());
    }

    /// `30x` is rejected at the gate, before anything is attempted.
    #[test]
    fn chat_with_a_garbage_timeout_is_usage_64_immediately() {
        let p = crate::tree::parse(vec!["chat", "--send", "#chan hi", "--timeout", "30x"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        assert_eq!(rc, 64);
        assert!(String::from_utf8(err).unwrap().contains("--timeout"));
    }

    /// ⛔ **Enforcement follows the flag's existence.** `ssh` has no
    /// `--timeout` row, so a piped `ssh` run reaches ssh itself (here it stops
    /// on a destination the relay cannot take, before any network) — the
    /// gate must not invent a requirement the tree cannot satisfy.
    #[test]
    fn ssh_without_a_timeout_row_is_unaffected_by_the_gate() {
        let p = crate::tree::parse(vec!["ssh", "-l", "test", "invalid!host", "--", "true"]);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let rc = run(&p, &mut Streams { out: &mut out, err: &mut err });
        let text = String::from_utf8(err).unwrap();
        assert_eq!(rc, EXIT_USAGE, "{text}");
        assert!(text.contains("invalid!host"), "ssh itself refused the destination: {text}");
        assert!(!text.contains("--timeout"), "the timeout gate must not apply to ssh: {text}");
    }
}