//! Keys typed on a beat through `cat` (T-660), as a user types: each key goes
//! at its time whether or not the one before came back, so a slow echo does
//! not slow the typing and hide the queue behind it. `cat` keeps the order,
//! so the n-th byte back answers the n-th key.

use std::time::{Duration, Instant};

use podssh_ssh::russh::client::Msg;
use podssh_ssh::russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf};

use super::far::{Failed, STEP};

/// The keys of a measure, and the time between two, as osewa's harness types
/// them.
pub const KEYS: usize = 40;
pub const GAP: Duration = Duration::from_millis(150);
/// A letter, which no terminal and no line discipline acts on.
const KEY: u8 = b'k';
const COMMAND: &str = "cat";

/// One key: when it went, from the measure's zero, and how long its echo took.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Key {
    pub sent: Duration,
    pub echo: Duration,
}

impl Key {
    /// When its echo came back, from the measure's zero.
    pub fn back(&self) -> Duration {
        self.sent + self.echo
    }
}

/// `count` keys through the channel of `cat`, [`GAP`] apart from now, each
/// sent from `zero`; each wait has the limit [`STEP`] from the last send or
/// echo, so a lost echo ends the measure and never hangs it.
pub async fn typed(
    writer: &ChannelWriteHalf<Msg>,
    reader: &mut ChannelReadHalf,
    count: usize,
    zero: Instant,
) -> Result<Vec<Key>, Failed> {
    let first = Instant::now();
    let mut sent: Vec<Instant> = Vec::with_capacity(count);
    let mut keys = Vec::with_capacity(count);
    while keys.len() < count {
        // The next key's time on the beat, while a key is left to send.
        let due = first + GAP * sent.len() as u32;
        let more = sent.len() < count;
        tokio::select! {
            _ = tokio::time::sleep_until(due.into()), if more => {
                // Its time is taken before it goes, so its echo always finds it.
                sent.push(Instant::now());
                if writer.data_bytes(vec![KEY]).await.is_err() {
                    return Err(Failed::Broke(format!("{COMMAND}: the channel closed")));
                }
            }
            msg = tokio::time::timeout(STEP, reader.wait()) => match msg {
                Ok(Some(ChannelMsg::Data { data })) => {
                    let now = Instant::now();
                    for _ in 0..data.len() {
                        if let Some(at) = sent.get(keys.len()) {
                            keys.push(Key { sent: at.duration_since(zero), echo: now.duration_since(*at) });
                        }
                    }
                }
                Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                    return Err(Failed::Status(COMMAND.into(), i32::try_from(exit_status).unwrap_or(255)))
                }
                Ok(Some(ChannelMsg::Close)) | Ok(None) => return Err(Failed::Broke(format!("{COMMAND}: closed"))),
                Ok(Some(_)) => {}
                Err(_) => return Err(Failed::Broke(format!("{COMMAND}: no echo within {} s", STEP.as_secs()))),
            },
        }
    }
    Ok(keys)
}

/// The echo of each key.
pub fn echoes(keys: &[Key]) -> Vec<Duration> {
    keys.iter().map(|k| k.echo).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_comes_back_at_its_send_and_its_echo() {
        let key = Key { sent: Duration::from_millis(3_150), echo: Duration::from_millis(420) };
        assert_eq!(key.back(), Duration::from_millis(3_570));
        assert_eq!(echoes(&[key, key]), vec![Duration::from_millis(420); 2]);
    }
}
