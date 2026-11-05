//! What a session carries from one link to the next, as values (T-668): a
//! handover gives them to the next binary, which carries the session on
//! from them as from a lost link. The `DATA` records of a resume are not
//! among them: a session between links holds none, and each byte of them is
//! in the replay buffer.

use std::sync::Arc;

use super::{lock, Carry};
use crate::session::link::{Link, LinkParts};

/// What a [`Carry`] holds besides its link.
#[derive(Clone, PartialEq, Eq)]
pub struct CarryParts {
    /// Bytes received and not yet written to the target.
    pub undelivered: Vec<u8>,
    pub app_ended: bool,
    pub app_shut: bool,
}

impl std::fmt::Debug for CarryParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CarryParts {{ {} bytes undelivered, app_ended: {}, app_shut: {} }}",
            self.undelivered.len(),
            self.app_ended,
            self.app_shut
        )
    }
}

impl Carry {
    /// The session's state between two links, as values.
    pub fn parts(&self) -> (LinkParts, CarryParts) {
        let link = lock(&self.state).parts();
        let carry = CarryParts {
            undelivered: self.undelivered.clone(),
            app_ended: self.app_ended,
            app_shut: self.app_shut,
        };
        (link, carry)
    }

    /// A session's state from its values: the link's, and what it carries.
    pub fn from_parts(link: Link, parts: CarryParts) -> Carry {
        let CarryParts { undelivered, app_ended, app_shut } = parts;
        Carry {
            state: Arc::new(std::sync::Mutex::new(link)),
            undelivered,
            again: Vec::new(),
            app_ended,
            hearing: Arc::default(),
            app_shut,
        }
    }
}
