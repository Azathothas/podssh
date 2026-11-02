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

    /// The visitor that the edge named is whom the brake counts (T-454): the
    /// TCP peer here is the edge itself.
    fn connect(&self, visitor: Option<std::net::IpAddr>) -> DuplexStream {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(super::serve_from(theirs, self.cfg.clone(), Some(self.name.clone()), visitor));
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
            brake: Default::default(),
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
        let mut pipe = Behind::new(cfg(), "n.example", false).connect(None);
        pipe.write_all(b"GET /health HTTP/1.1\r\nHost: n.example\r\n\r\n").await.unwrap();
        let mut answer = Vec::new();
        let read = tokio::time::timeout(std::time::Duration::from_secs(20), pipe.read_to_end(&mut answer));
        read.await.expect("an answer in time").unwrap();
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 200 ") && answer.contains("\"contract\""), "{answer}");
    }

    /// The status of a mint on a pipe for `visitor`.
    async fn mint(behind: &Behind, visitor: &str) -> String {
        let mut pipe = behind.connect(Some(visitor.parse().unwrap()));
        let ask = b"POST /v1/mint HTTP/1.1\r\nHost: n.example\r\nContent-Length: 2\r\n\r\n{}";
        pipe.write_all(ask).await.unwrap();
        let mut answer = Vec::new();
        let read = tokio::time::timeout(std::time::Duration::from_secs(20), pipe.read_to_end(&mut answer));
        read.await.expect("an answer in time").unwrap();
        String::from_utf8_lossy(&answer).split(' ').nth(1).unwrap_or_default().to_string()
    }

    /// Behind the tunnel the peer is the edge: the brake counts the visitor
    /// that the edge names, so one visitor's mints do not spend another's.
    #[tokio::test]
    async fn the_brake_counts_each_visitor_that_the_edge_names() {
        let mut cfg = Arc::into_inner(cfg()).unwrap();
        cfg.brake = super::super::brake::Brake::new(2, 60_000, 16, super::super::brake::monotonic());
        let behind = Behind::new(Arc::new(cfg), "n.example", false);
        assert_eq!(mint(&behind, "192.0.2.1").await, "200");
        assert_eq!(mint(&behind, "192.0.2.1").await, "200");
        assert_eq!(mint(&behind, "192.0.2.1").await, "429", "the third of one visitor");
        assert_eq!(mint(&behind, "198.51.100.7").await, "200", "another visitor's first");
    }
}
