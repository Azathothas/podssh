//! Each message of the session's channel, on its way to the terminal: the
//! output, the exit status or signal, the close, and the answer to `~d`.

use russh::ChannelMsg;
use tokio::io::AsyncWriteExt;

use super::{end_with, status_code, End, Out, Sink, Through};
use crate::log::Log;
use crate::signals;

pub(super) async fn handle_msg(
    msg: ChannelMsg,
    status: &mut Option<i32>,
    out: &mut Out,
    through: &mut Through,
    log: &Log,
) -> Option<End> {
    // Any message of the channel answers SSH's own question (T-332).
    if let Some(asked) = &through.asked {
        asked.heard();
    }
    match msg {
        ChannelMsg::Data { data } => {
            let data = out.consoles.text(false, through.out(&data, false, log));
            // Whoever reads our stdout has gone (EPIPE): the data goes
            // nowhere, and the exit status is awaited (T-026).
            if out.gone.is_none() && write_out(out.sink.as_ref(), &data, false).await.is_err() {
                out.gone = Some(tokio::time::Instant::now());
            }
        }
        ChannelMsg::ExtendedData { data, .. } => {
            let data = out.consoles.text(true, through.out(&data, true, log));
            let _ = write_out(out.sink.as_ref(), &data, true).await;
        }
        ChannelMsg::ExitStatus { exit_status } => {
            crate::outcome::status(exit_status);
            *status = Some(status_code(exit_status));
        }
        ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, .. } => {
            let name = signals::name(&signal_name);
            crate::outcome::signal(&name, core_dumped);
            *status = Some(signals::number(&signal_name).map_or(255, |n| 128 + n));
            let mut note = format!("the remote command was killed by signal {name}");
            if core_dumped {
                note.push_str(" (core dumped)");
            }
            let detail = podssh_ws::text::one_line(&error_message);
            if !detail.is_empty() {
                note.push_str(": ");
                note.push_str(&detail);
            }
            log.info(&note);
        }
        ChannelMsg::Close => {
            // A command that never started: what su said, its refusal.
            if let Some(e) = through.elevated.as_mut().filter(|e| !e.started()) {
                let _ = write_out(out.sink.as_ref(), &out.consoles.text(true, e.finish()), true).await;
            }
            // A sequence that the end cut, for a console (T-294).
            for stderr in [false, true] {
                let tail = out.consoles.finish(stderr);
                if !tail.is_empty() {
                    let _ = write_out(out.sink.as_ref(), &tail, stderr).await;
                }
            }
            return Some(end_with(*status));
        }
        // The answer to `~d`, when one is awaited (T-158).
        reply @ (ChannelMsg::Success | ChannelMsg::Failure) => return through.detaching.answer(&reply, log),
        // Eof: the server sends nothing more, but the exit status and the
        // close are still to come.
        _ => {}
    }
    None
}

pub(super) async fn write_out(sink: Option<&Sink>, data: &[u8], to_stderr: bool) -> std::io::Result<()> {
    if let Some(sink) = sink {
        sink.send((data.to_vec(), to_stderr))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
    } else if to_stderr {
        let mut err = tokio::io::stderr();
        err.write_all(data).await?;
        err.flush().await?;
    } else {
        let mut out = tokio::io::stdout();
        out.write_all(data).await?;
        out.flush().await?;
    }
    // What `--result-file` counts (T-054).
    crate::outcome::output(data.len(), to_stderr);
    Ok(())
}
