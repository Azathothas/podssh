//! The reverse road (feature `pair`): its codecs (the framing of each leg,
//! the control messages, the close table, the state of each session) and its
//! runners, the node (T-079) and the operator (T-080); the node's far end of
//! the resumable layer (T-153); a node's handlers of a TCP target and of a
//! UDP one (T-168); and the check of a roost's sshd (T-166).

pub mod closes;
pub mod control;
pub mod e2e;
pub mod framing;
pub mod layered;
pub mod node;
pub mod operator;
pub mod routes;
pub mod serve;
pub mod sessions;
pub mod sshd;
pub mod tcp;
pub mod udp;
pub mod wire;

pub use closes::RelayClose;
pub use e2e::E2e;
pub use framing::SessionId;
pub use layered::Layered;

pub use node::{after_close, run, Exit, Handler, Next, NodeConfig, Opening, RepairHook, QUEUE_BYTES};
pub use operator::{OperatorConfig, OperatorLimits, Outcome};
pub use serve::{serve, End, Settings};
pub use tcp::TcpHandler;
pub use udp::UdpHandler;
pub use wire::Wire;
