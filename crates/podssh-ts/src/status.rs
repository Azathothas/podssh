//! The one machine-readable status line: facts only, secrets never.
//!
//! `podssh ts` prints [`StatusFacts::render`]: the node-key prefix (8 hex),
//! the tailnet IP, the home region. The full node key and the auth key never
//! reach this struct — there is no field for them, so no renderer can leak them.

/// What `podssh ts` prints for a live node: node-key prefix, tailnet IP, home region.
pub struct StatusFacts {
    /// First 8 hex chars of the node key. Never the key.
    pub nodekey_prefix: String,
    /// Tailnet IP in string form.
    pub tailnet_ip: String,
    /// Home DERP region id (900+ when the override knob is on).
    pub home_region: u16,
}

impl StatusFacts {
    /// `node NODEKEY… ip IP home REGION`: one line, no secrets.
    pub fn render(&self) -> String {
        format!("node {}… ip {} home {}", self.nodekey_prefix, self.tailnet_ip, self.home_region)
    }
}
