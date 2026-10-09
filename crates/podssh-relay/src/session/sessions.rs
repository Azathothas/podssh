//! The sessions that a far end keeps, by id: the secret of each, and its
//! received offset, which a resume's `ACCEPT` gives the client.
//!
//! Once a session's state exists, the offset is read from it at the moment of
//! the resume: the old link may still be carrying bytes then, and an offset
//! older than the far end's last `ACK` would ask the client for bytes that it
//! no longer keeps (T-153).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use super::link::Link;
use super::secret::{Secret, SessionId};

/// A session that a far end keeps.
struct Kept {
    secret: Secret,
    /// The received offset, until `state` exists.
    received: u64,
    state: Option<Arc<Mutex<Link>>>,
}

impl Kept {
    fn received(&self) -> u64 {
        match &self.state {
            Some(state) => state.lock().unwrap_or_else(|e| e.into_inner()).received(),
            None => self.received,
        }
    }
}

/// The sessions that a far end keeps, by id. A session stays after its link
/// ends, so that a client can resume it, until the far end removes it.
#[derive(Default)]
pub struct Sessions {
    kept: HashMap<SessionId, Kept>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions::default()
    }

    pub fn len(&self) -> usize {
        self.kept.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kept.is_empty()
    }

    pub fn contains(&self, id: &SessionId) -> bool {
        self.kept.contains_key(id)
    }

    /// The far end's received offset of a session.
    pub fn received(&self, id: &SessionId) -> Option<u64> {
        self.kept.get(id).map(Kept::received)
    }

    /// The far end now has each byte of the session below `offset`; for a
    /// session with no state attached.
    pub fn set_received(&mut self, id: &SessionId, offset: u64) {
        if let Some(kept) = self.kept.get_mut(id) {
            kept.received = offset;
        }
    }

    /// The session's state, from which its received offset is read from now
    /// on.
    pub fn attach(&mut self, id: &SessionId, state: Arc<Mutex<Link>>) {
        if let Some(kept) = self.kept.get_mut(id) {
            kept.state = Some(state);
        }
    }

    /// Forget a session: its secret is wiped, and no client can resume it.
    pub fn remove(&mut self, id: &SessionId) -> bool {
        self.kept.remove(id).is_some()
    }

    pub(crate) fn insert(&mut self, id: SessionId, secret: Secret) {
        self.kept.insert(id, Kept { secret, received: 0, state: None });
    }

    pub(crate) fn secret(&self, id: &SessionId) -> Option<&Secret> {
        self.kept.get(id).map(|kept| &kept.secret)
    }
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sessions({} kept)", self.kept.len())
    }
}
