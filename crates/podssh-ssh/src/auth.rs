//! The authentication chain.
//!
//! `none` first, which tells podssh what the server accepts (and is enough on
//! a server that wants nothing). Then the methods of `PreferredAuthentications`
//! in order, each only while the server still lists it: public keys (agent,
//! then key files), keyboard-interactive, password. A partial success (a
//! server that wants two methods) carries on with the methods the server names
//! next. Methods that need a person are skipped, with a note, when there is
//! nobody to ask; the final refusal says what was tried and what would help.

use std::sync::Arc;

use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::MethodKind;

use crate::handler::Client;
use crate::keys::PublicKeys;
use crate::log::Log;
use crate::options::{Method, Options};
use crate::prompt::{self, PromptError};

/// The result of one attempt.
pub(crate) enum Step {
    Success,
    /// Refused; the server lists what may continue.
    Failure { remaining: Vec<MethodKind>, partial: bool },
    /// This method has nothing left to try.
    Exhausted,
}

impl From<AuthResult> for Step {
    fn from(r: AuthResult) -> Self {
        match r {
            AuthResult::Success => Step::Success,
            AuthResult::Failure { remaining_methods, partial_success } => Step::Failure {
                remaining: remaining_methods.iter().copied().collect(),
                partial: partial_success,
            },
        }
    }
}

fn kind(m: Method) -> MethodKind {
    match m {
        Method::PublicKey => MethodKind::PublicKey,
        Method::KeyboardInteractive => MethodKind::KeyboardInteractive,
        Method::Password => MethodKind::Password,
    }
}

fn kind_name(k: &MethodKind) -> &'static str {
    k.into()
}

/// Log in as `user` on the host called `host` in prompts. On failure, the
/// message to print.
pub async fn authenticate(
    handle: &mut Handle<Client>,
    user: &str,
    host: &str,
    opts: &Options,
    log: &Arc<Log>,
) -> Result<(), String> {
    let mut allowed: Vec<MethodKind> = match handle.authenticate_none(user).await {
        Ok(AuthResult::Success) => return Ok(()),
        Ok(AuthResult::Failure { remaining_methods, .. }) => remaining_methods.iter().copied().collect(),
        Err(e) => return Err(format!("authentication failed before it started: {e}")),
    };
    log.debug(&format!(
        "the server accepts: {}",
        allowed.iter().map(kind_name).collect::<Vec<_>>().join(",")
    ));
    let mut keys = PublicKeys::new(opts, log.clone());
    let mut exhausted: Vec<Method> = Vec::new();
    let mut kbd_rounds = 0u32;
    let mut password_tries = 0u32;
    let mut notes: Vec<String> = Vec::new();
    loop {
        let next = opts
            .methods
            .iter()
            .copied()
            .find(|m| allowed.contains(&kind(*m)) && !exhausted.contains(m));
        let Some(method) = next else { break };
        let step = match method {
            Method::PublicKey => keys.try_next(handle, user).await?,
            Method::KeyboardInteractive => {
                kbd_rounds += 1;
                if kbd_rounds > opts.password_prompts.max(1) {
                    Step::Exhausted
                } else {
                    keyboard_interactive(handle, user, opts, log, &mut notes).await?
                }
            }
            Method::Password => {
                password_tries += 1;
                if password_tries > opts.password_prompts.max(1) {
                    Step::Exhausted
                } else {
                    password(handle, user, host, opts, &mut notes).await?
                }
            }
        };
        match step {
            Step::Success => return Ok(()),
            Step::Failure { remaining, partial } => {
                if partial {
                    log.verbose(&format!("{} accepted; the server asks for another method", method.name()));
                }
                allowed = remaining;
            }
            Step::Exhausted => exhausted.push(method),
        }
    }
    notes.extend(keys.notes());
    let mut message = format!(
        "{user}@{host}: Permission denied ({}).",
        allowed.iter().map(kind_name).collect::<Vec<_>>().join(",")
    );
    for note in notes {
        message.push_str("\n  ");
        message.push_str(&note);
    }
    Err(message)
}

/// Ask on a blocking thread, so the relay is still read while the user types.
async fn ask(text: String, echo: bool) -> Result<zeroize::Zeroizing<String>, PromptError> {
    tokio::task::spawn_blocking(move || prompt::ask(&text, echo))
        .await
        .unwrap_or(Err(PromptError::Failed("the prompt thread failed".into())))
}

async fn keyboard_interactive(
    handle: &mut Handle<Client>,
    user: &str,
    opts: &Options,
    log: &Log,
    notes: &mut Vec<String>,
) -> Result<Step, String> {
    if opts.batch_mode || !prompt::can_ask() {
        notes.push("keyboard-interactive was skipped: there is no terminal or SSH_ASKPASS to answer it".into());
        return Ok(Step::Exhausted);
    }
    let fail = |e: russh::Error| format!("keyboard-interactive authentication failed: {e}");
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await
        .map_err(fail)?;
    // A server may send any number of rounds; bound them.
    for _ in 0..16 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(Step::Success),
            KeyboardInteractiveAuthResponse::Failure { remaining_methods, partial_success } => {
                return Ok(Step::Failure {
                    remaining: remaining_methods.iter().copied().collect(),
                    partial: partial_success,
                })
            }
            KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                for text in [name, instructions] {
                    let text = podssh_ws::text::multi_line(&text);
                    if !text.trim().is_empty() {
                        log.banner(&text);
                    }
                }
                let mut answers = Vec::with_capacity(prompts.len());
                for p in prompts {
                    let shown = podssh_ws::text::multi_line(&p.prompt);
                    match ask(shown, p.echo).await {
                        Ok(answer) => answers.push(answer.to_string()),
                        Err(e) => {
                            notes.push(format!("keyboard-interactive was abandoned: {e}"));
                            return Ok(Step::Exhausted);
                        }
                    }
                }
                response = handle.authenticate_keyboard_interactive_respond(answers).await.map_err(fail)?;
            }
        }
    }
    notes.push("keyboard-interactive was abandoned: the server kept asking".into());
    Ok(Step::Exhausted)
}

async fn password(
    handle: &mut Handle<Client>,
    user: &str,
    host: &str,
    opts: &Options,
    notes: &mut Vec<String>,
) -> Result<Step, String> {
    if opts.batch_mode || !prompt::can_ask() {
        notes.push("password authentication was skipped: there is no terminal or SSH_ASKPASS to ask on".into());
        return Ok(Step::Exhausted);
    }
    match ask(format!("{user}@{host}'s password: "), false).await {
        Ok(pw) => handle
            .authenticate_password(user, pw.as_str())
            .await
            .map(Step::from)
            .map_err(|e| format!("password authentication failed: {e}")),
        Err(e) => {
            notes.push(format!("password authentication was abandoned: {e}"));
            Ok(Step::Exhausted)
        }
    }
}
