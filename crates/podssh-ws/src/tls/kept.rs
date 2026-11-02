//! One TLS configuration for each trust in the process (T-444). rustls keeps
//! its cache of sessions in the configuration, so a configuration made for
//! each connection let no connection of a run resume TLS: `podssh each`, the
//! staggered failover, `cp --parallel` and each move of the resumable layer
//! paid a whole handshake, and read a CA file again.
//!
//! A configuration is kept by its trust, so that a session that one trust
//! verified is never resumed under another: a resumed handshake checks no
//! certificate. A CA file that changed, by its time or its length, gets a
//! new configuration, read again, as a long-lived node is given a new CA.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use rustls::ClientConfig;

use super::Trust;
use crate::error::WsError;

/// The most trusts kept: a run names one or two; a process that is given
/// many CA files keeps the newest.
const MOST: usize = 16;

/// What tells that a CA file changed: its time and its length; `None` for a
/// trust with no file, or a file that cannot be read now.
type Stamp = Option<(Option<SystemTime>, u64)>;

struct Kept {
    trust: Trust,
    stamp: Stamp,
    config: Arc<ClientConfig>,
}

static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

/// The configuration of `trust`, made by `make` the first time, and again
/// when its CA file changed. A failure is not kept: the next call tries
/// again.
pub(super) fn config<F>(trust: &Trust, make: F) -> Result<Arc<ClientConfig>, WsError>
where
    F: FnOnce() -> Result<Arc<ClientConfig>, WsError>,
{
    let stamp = stamp(trust);
    let found = find(&lock(), trust, &stamp);
    if let Some(config) = found {
        return Ok(config);
    }
    // Made outside the lock: a CA file or a system store can be slow to read.
    let made = make()?;
    let mut kept = lock();
    // Two threads that missed at once keep the first one's, so that each
    // connection of a trust shares one cache of sessions.
    if let Some(config) = find(&kept, trust, &stamp) {
        return Ok(config);
    }
    kept.retain(|k| k.trust != *trust);
    if kept.len() >= MOST {
        kept.remove(0);
    }
    kept.push(Kept { trust: trust.clone(), stamp, config: made.clone() });
    Ok(made)
}

fn find(kept: &[Kept], trust: &Trust, stamp: &Stamp) -> Option<Arc<ClientConfig>> {
    kept.iter().find(|k| k.trust == *trust && k.stamp == *stamp).map(|k| k.config.clone())
}

fn stamp(trust: &Trust) -> Stamp {
    match trust {
        Trust::File(path) => file_stamp(path),
        Trust::Default | Trust::Caller(_) => None,
    }
}

fn file_stamp(path: &Path) -> Stamp {
    std::fs::metadata(path).ok().map(|m| (m.modified().ok(), m.len()))
}

fn lock() -> MutexGuard<'static, Vec<Kept>> {
    KEPT.lock().unwrap_or_else(|e| e.into_inner())
}
