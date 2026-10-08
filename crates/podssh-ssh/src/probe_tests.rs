//! The login probe against a russh server in this process: with its host key
//! named, the server refuses the key made for the call; with another host key
//! named, no key is offered.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth};

use super::*;

/// Refuses every key, as GitHub refuses a key that no account has.
struct Strict;

impl server::Handler for Strict {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _user: &str, _key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }
}

/// A login to a [`Strict`] server; `named` says whether its own host key is
/// the one accepted.
async fn against(named: bool) -> Result<Login, String> {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key");
    let own = crate::known_hosts::fingerprint(host.public_key());
    let mut config = server::Config::default();
    config.keys.push(host);
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, Strict).await {
            let _ = session.await;
        }
    });
    let other = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let accepted = if named { vec![own] } else { vec![other] };
    login(client_end, "git", &accepted, Duration::from_secs(20)).await
}

#[tokio::test]
async fn login_with_the_named_host_key_reaches_the_refusal() {
    match against(true).await {
        Ok(Login::Refused { methods, .. }) => assert!(methods.contains(&"publickey".to_string()), "{methods:?}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn login_stops_at_a_host_key_that_was_not_named() {
    match against(false).await {
        Ok(Login::WrongHostKey { .. }) => {}
        other => panic!("{other:?}"),
    }
}
