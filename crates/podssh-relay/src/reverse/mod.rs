//! The reverse road (feature `pair`): its codecs (the framing of each leg,
//! the control messages, the close table, the state of each session) and its
//! runners, the node (T-079) and the operator (T-080).

pub mod closes;
pub mod control;
pub mod framing;
pub mod node;
pub mod operator;
pub mod serve;
pub mod sessions;
pub mod tcp;
pub mod wire;

pub use closes::RelayClose;
pub use framing::SessionId;

pub use node::{after_close, run, Exit, Handler, Next, NodeConfig, Opening, RepairHook};
pub use serve::{serve, End, Settings};
pub use operator::{OperatorConfig, OperatorLimits, Outcome};
pub use tcp::TcpHandler;
pub use wire::Wire;
