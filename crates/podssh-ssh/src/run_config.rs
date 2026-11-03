//! russh's configuration of a client for one hop: the lists of ssh_config's
//! keywords (T-505), the host-key algorithms that the known_hosts files and
//! `@cert-authority` lines ask for first, the compression of `-C`, the
//! keepalive and the window (out of `run.rs`, at its 500 lines).

use std::borrow::Cow;

use russh::client::Config;
use russh::keys::{Algorithm, HashAlg};
use russh::{Preferred, SshId};

use super::WINDOW;
use crate::hostkey::Policy;
use crate::known_hosts;
use crate::options::Options;

pub(super) fn client_config(opts: &Options, policy: &Policy) -> Config {
    let mut preferred = Preferred::default();
    // The lists that the keywords gave, in place of russh's (T-505).
    crate::algorithms::restrict(&mut preferred, &opts.algorithms);
    // Host-key algorithms already recorded for this host go first, as in
    // OpenSSH, so a host known by its RSA key is not asked for an unknown
    // Ed25519 one. An RSA key is asked for with SHA-2 signatures, never SHA-1.
    // Within a list that HostKeyAlgorithms gave too, of each form: a key
    // that podssh knows is never passed over for one that it does not.
    let files: Vec<_> = policy.user_files.iter().chain(&policy.global_files).cloned().collect();
    let mut order: Vec<Algorithm> = Vec::new();
    for algorithm in known_hosts::recorded_algorithms(&files, &policy.name) {
        let wanted = match algorithm {
            Algorithm::Rsa { .. } => {
                vec![Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }]
            }
            other => vec![other],
        };
        for a in wanted {
            if preferred.key.contains(&a) && !order.contains(&a) {
                order.push(a);
            }
        }
    }
    if !order.is_empty() {
        for a in preferred.key.iter() {
            if !order.contains(a) {
                order.push(a.clone());
            }
        }
        preferred.key = Cow::Owned(order);
    }
    // A host that a `@cert-authority` line names is asked for a certificate
    // first, of each algorithm it may sign with but SHA-1 RSA (T-027); of
    // those that HostKeyAlgorithms names, when it gave a list (T-505).
    if crate::hostcert::trusted_for(&files, &policy.name) {
        let certs: Vec<Algorithm> = match &opts.algorithms.host_key {
            Some(list) => crate::algorithms::certificates(list),
            None => preferred
                .key
                .iter()
                .filter(|a| !matches!(a, Algorithm::Rsa { hash: None } | Algorithm::Dsa | Algorithm::Other(_)))
                .cloned()
                .collect(),
        };
        preferred.host_key_certificates = Cow::Owned(certs);
    }
    if opts.compression {
        preferred.compression =
            Cow::Owned(vec![russh::compression::ZLIB_LEGACY, russh::compression::ZLIB, russh::compression::NONE]);
    }
    Config {
        // RFC 4253, section 4.2: no `-` in the software version, as in `1.0.0-beta.1`.
        client_id: SshId::Standard(format!("SSH-2.0-podssh_{}", env!("CARGO_PKG_VERSION").replace('-', "_")).into()),
        keepalive_interval: opts.keepalive_interval,
        keepalive_max: opts.keepalive_max,
        inactivity_timeout: None,
        window_size: WINDOW,
        nodelay: true,
        preferred,
        ..Config::default()
    }
}
