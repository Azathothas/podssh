//! Dispatch: the parse result becomes bytes on two streams and an exit code.
//!
//! **stdout carries the answer and nothing else.** `docs/architecture.md`, "Design rules":
//! *"stdout is data. Diagnostics go to stderr, so podssh can be in a pipe or be the
//! `ProxyCommand` of OpenSSH."* This module is where that is
//! enforced, and the target of plant 6 (`tests/binary_streams.rs`): one `println!` on the
//! wrong path and `podssh example.org 2>/dev/null | wc -c` stops reading 0.
//!
//! **The terminal state is a parameter, not a probe.** [`run`] — the entry
//! point every test calls — gets [`Tty::none`], so no test can enter the
//! pager and block on a terminal; [`main_with_args`] asks the operating system
//! once, where the real file descriptors are, and passes the answer down.

use std::io::Write;

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::flags::VERB_OWNER;
use crate::help;
use crate::pager::Tty;
use crate::tree::Parsed;

/// The two streams, as a pair of sinks, so a test can assert on both without
/// spawning a process. This is what makes plant 6 a unit test as well as a
/// shell assertion — and the shell assertion is still the one that counts,
/// because it runs the real binary.
pub struct Streams<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

/// Run a parsed command line **with no terminal**. Returns the process exit
/// code.
///
/// This is the entry point tests use, and it cannot page — nothing in a test
/// may block on a terminal, and a test that could page
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
        // A usage error is a refusal. Nothing goes to stdout, because the
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
        Parsed::Man { section, no_pager, roff, json, refused } => {
            if refusals("man", refused, s.err) {
                return EXIT_USAGE;
            }
            let stdin = std::io::stdin();
            let mut keys = stdin.lock();
            let request =
                crate::man::Request { section: section.as_deref(), no_pager: *no_pager, roff: *roff, json: *json };
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
        Parsed::Node(args) if refusals("node", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Node(args) => crate::node::run_node(args, s.err),
        Parsed::Operator(args) if refusals("operator", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Operator(args) => crate::operator::run_operator(args, s.err),
        Parsed::Pipe(args) if refusals("pipe", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Pipe(args) => crate::pipe::run_pipe(args, s.err),
        Parsed::Relay(args) if refusals("relay", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Relay(args) => crate::relay_cmd::run_relay(args, s.out, s.err),
        Parsed::Status { relay_host, relay_addr, destination, refused } => {
            if refusals("status", refused, s.err) {
                return EXIT_USAGE;
            }
            let args = crate::status::StatusArgs {
                relay_host: relay_host.clone(),
                relay_addr: relay_addr.clone(),
                destination: destination.clone(),
            };
            crate::status::run_status(&args, tty, s.out, s.err)
        }
        Parsed::Doctor { relay_host, relay_addr, ca_file, json, full, refused } => {
            if refusals("doctor", refused, s.err) {
                return EXIT_USAGE;
            }
            crate::doctor::run_doctor(
                &crate::doctor::DoctorArgs {
                    relay_host: relay_host.clone(),
                    relay_addr: relay_addr.clone(),
                    ca_file: ca_file.clone(),
                    json: *json,
                    full: *full,
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
        // `ts` is dispatched, not refused: `ts.rs` owns the verb the way
        // `src/man/` owns `man`. The VERB_OWNER row is gone — and
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
        Parsed::Command { verb, refused, tag, timeout, jsonl, ssh, keygen, cp, sftp, chat } => {
            // `-P TAG` on ssh: accepted, ignored, and it says so on stderr so
            // a user who meant a port learns before the connection fails.
            if let Some(t) = tag {
                let _ = writeln!(s.err, "{}", crate::refuse::accepted_tag_notice(t));
            }
            // The `--timeout` gate, computed once and passed down: the attachment from
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
                crate::non_interactive::require_timeout_or_env(verb, attachment, timeout.as_deref(), |n| {
                    std::env::var(n).ok()
                })
            } else {
                Ok(None)
            };
            let deadline = match checked {
                Ok(deadline) => deadline,
                Err(refusal) => {
                    let _ = writeln!(s.err, "{}", refusal.message);
                    return refusal.fault.code();
                }
            };
            // Refused flags first, and they refuse before anything else
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
            if let Some(args) = cp {
                return crate::cp::run_cp(args, deadline, *jsonl, s.out, s.err);
            }
            if let Some(args) = sftp {
                return crate::sftp::run_sftp(args, tty, s.out, s.err);
            }
            if let Some(args) = chat {
                return crate::chat::run_chat(args, deadline, *jsonl, s.out, s.err);
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

/// Print every refused flag, and say whether there was one. One function so
/// `man` and every other verb refuse in the same words.
///
/// The third line is the row's own reason, because the causes differ: `-L`
/// and `-D` need a local listener, and `-A` is not supported.
fn refusals(verb: &str, refused: &[(String, &'static str, &'static str)], err: &mut dyn Write) -> bool {
    if refused.is_empty() {
        return false;
    }
    for (given, instead, reason) in refused {
        let _ = writeln!(err, "{}", crate::refuse::refused(verb, given, instead, reason));
    }
    true
}

/// The one function `main` calls. It is here rather than in `main.rs` so a
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
    let rc = run_with(&parsed, &mut Streams { out: &mut out, err: &mut err }, Tty::probed());
    let _ = out.flush();
    let _ = err.flush();
    rc
}

#[cfg(test)]
mod tests;
