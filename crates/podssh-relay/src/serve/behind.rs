//! The relay role behind a node's quick tunnel (T-428): the role's routes as
//! the origin of the node's tunnel ([`crate::quick::origin`]), a pipe in
//! this process for each request of the edge, so that the role has no
//! socket of its own to wait on. The tunnel's name stands for the name that
//! a client's TLS asks for behind a listener: the edge took the visitor's
//! TLS for that name, so a key's signed mint or pair must name it (T-448).

use std::sync::Arc;

use tokio::io::DuplexStream;

use super::Config;
use crate::quick::origin::{Origin, PIPE};

/// The role, as the origin of the quick tunnel of the name `name`.
pub struct Behind {
    cfg: Arc<Config>,
    name: String,
    /// Each path, for a node that serves no TARGET: the role's own 404
    /// answers the paths that are not its own.
    every: bool,
}

impl Behind {
    pub fn new(cfg: Arc<Config>, name: impl Into<String>, every: bool) -> Behind {
        Behind { cfg, name: name.into(), every }
    }
}

impl Origin for Behind {
    fn serves(&self, path: &str) -> bool {
        self.every || super::serves(path)
    }

    fn connect(&self) -> DuplexStream {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(super::serve_named(theirs, self.cfg.clone(), Some(self.name.clone())));
        ours
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg() -> Arc<Config> {
        Arc::new(Config {
            version: "test".into(),
            mint: super::super::Mint::Anyone,
            tokens: super::super::tokens::Tokens::new([6; 32]),
            policy: Default::default(),
            limits: Default::default(),
            pairs: Default::default(),
            answered: Default::default(),
            events: None,
        })
    }

    /// Each route of the role is its own, and the node's paths stay the
    /// node's; with no TARGET, each path is the role's.
    #[test]
    fn the_role_s_paths_are_its_own_and_the_node_s_stay_the_node_s() {
        for path in ["/health", "/v1/mint", "/relays.json", "/trace", "/llms-full.txt", "/connect/github.com/22"] {
            assert!(serves_alone(path), "{path}");
        }
        for path in ["/v1/pair", "/v1/node/p-a", "/v1/connect/p-a", "/v1/status/p-a", "/v1/stop/p-a", "/v1/other"] {
            assert!(serves_alone(path), "{path}");
        }
        for path in ["/", "/index.html", "/connect", "/healthz", "/v2/mint"] {
            assert!(!serves_alone(path), "{path}");
        }
        assert!(Behind::new(cfg(), "n.example", true).serves("/"), "a node with no TARGET");
    }

    fn serves_alone(path: &str) -> bool {
        Behind::new(cfg(), "n.example", false).serves(path)
    }

    /// A request on a pipe gets the role's answer: its `/health`.
    #[tokio::test]
    async fn a_pipe_to_the_role_gets_its_answer() {
        let mut pipe = Behind::new(cfg(), "n.example", false).connect();
        pipe.write_all(b"GET /health HTTP/1.1\r\nHost: n.example\r\n\r\n").await.unwrap();
        let mut answer = Vec::new();
        let read = tokio::time::timeout(std::time::Duration::from_secs(20), pipe.read_to_end(&mut answer));
        read.await.expect("an answer in time").unwrap();
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 200 ") && answer.contains("\"contract\""), "{answer}");
    }
}
