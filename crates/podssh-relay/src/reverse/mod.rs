//! The reverse road (feature `pair`): its codecs (the framing of each leg,
//! the control messages, the close table, the state of each session) and its
//! runners, the node (T-079) and the operator (T-080); and the node's far end
//! of the resumable layer (T-153).

pub mod closes;
pub mod control;
pub mod e2e;
pub mod framing;
pub mod layered;
pub mod node;
pub mod operator;
pub mod serve;
pub mod sessions;
pub mod tcp;
pub mod wire;

pub use closes::RelayClose;
pub use e2e::E2e;
pub use framing::SessionId;
pub use layered::Layered;

pub use node::{after_close, run, Exit, Handler, Next, NodeConfig, Opening, RepairHook, QUEUE_BYTES};
pub use operator::{OperatorConfig, OperatorLimits, Outcome};
pub use serve::{serve, End, Settings};
pub use tcp::TcpHandler;
pub use wire::Wire;
