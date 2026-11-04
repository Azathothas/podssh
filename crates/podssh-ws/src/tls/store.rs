//! The store of sessions of podssh's own TLS configurations (T-664): the
//! tickets in rustls's own cache in memory, one for each configuration, so
//! that TLS resumes within a process under the trust that verified it alone
//! (T-444); and the group that each server took, from the process's
//! [`Kept`], so that a later run offers it at once.

use std::sync::Arc;

use rustls::client::{ClientSessionMemoryCache, ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::NamedGroup;
use rustls_pki_types::ServerName;

use super::groups::Kept;

/// The sessions kept in memory, as rustls's default store keeps them.
const SESSIONS: usize = 256;

/// rustls's cache in memory, with the groups kept across runs.
#[derive(Debug)]
pub(super) struct Store {
    memory: ClientSessionMemoryCache,
    kept: Arc<Kept>,
}

impl Store {
    pub(super) fn new(kept: Arc<Kept>) -> Store {
        Store { memory: ClientSessionMemoryCache::new(SESSIONS), kept }
    }
}

impl ClientSessionStore for Store {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.kept.took(&server_name.to_str(), u16::from(group));
        self.memory.set_kx_hint(server_name, group);
    }

    /// This process's hint first, then a run's before; rustls offers a group
    /// that it does not have as if there were no hint.
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.memory.kx_hint(server_name).or_else(|| self.kept.group(&server_name.to_str()).map(NamedGroup::from))
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.memory.set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.memory.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.memory.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.memory.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(&self, server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.memory.take_tls13_ticket(server_name)
    }
}
