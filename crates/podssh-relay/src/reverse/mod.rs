//! The runners of the reverse road (feature `pair`): the node (T-079); the
//! operator comes next (T-080). They use the codecs of `podssh-transport`
//! until T-082 moves them here.

pub mod node;
pub mod serve;
pub mod tcp;

pub use node::{after_close, run, Exit, Handler, Next, NodeConfig, Opening, RepairHook};
pub use serve::{serve, End, Settings};
pub use tcp::TcpHandler;
