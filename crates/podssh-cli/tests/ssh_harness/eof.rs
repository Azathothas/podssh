//! The client's end of input on a channel of the test's server: each
//! command that reads its input to its end ends then. Apart from the
//! handler (`mod.rs`), so that each file stays short.

use std::sync::atomic::Ordering;

use russh::server::Session;
use russh::ChannelId;

use super::far::Far;

pub(super) fn ended(far: &mut Far, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    // The server's stdin closes, and it ends.
    if far.sftps.remove(&channel).is_some() {
        return Ok(());
    }
    // sudo with no password to read refuses; su reads its pty, still open.
    if let Some(elevated) = far.elevated.remove(&channel) {
        far.elevated.extend(super::sudo::eof(elevated, channel, session)?.map(|waiting| (channel, waiting)));
        return Ok(());
    }
    if let Some((stop, status)) = far.spews.remove(&channel) {
        stop.store(true, Ordering::SeqCst);
        if status {
            session.exit_status_request(channel, 7)?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        return Ok(());
    }
    let echoed = far.echoes.iter().position(|c| *c == channel).map(|at| far.echoes.remove(at)).is_some();
    let drained = far.drains.iter().position(|c| *c == channel).map(|at| far.drains.remove(at)).is_some();
    if echoed || drained {
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
    }
    if let Some(bytes) = far.sinks.remove(&channel) {
        session.data(channel, format!("{bytes}\n").into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
    }
    Ok(())
}
