//! What a control server is asked first (T-334): the path of its key, with
//! the capability version that the fork's node sends. A check before the
//! start then asks what the node will ask, and a server that refuses the
//! node's version refuses the check too.

/// The capability version of the fork's node, as `/key` takes it.
pub fn capability_version() -> String {
    ts_capabilityversion::CapabilityVersion::CURRENT.to_string()
}

/// The path of the control server's key: `/key?v=N`, as the fork's
/// `fetch_control_key` asks for it.
pub fn key_path() -> String {
    format!("/key?v={}", capability_version())
}
