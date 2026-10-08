//! E02 — the relay client, both legs and the forward path.
//!
//! ⛔ **This crate moves bytes and never learns the protocol it carries.**
//! `RULES.md:138-142` is the rule and `AGENTS.md`'s fifth fact restates it: the
//! operator said *"our ssh is not real ssh either, so its the same way"*, so one
//! transport carries N protocols and ⛔ **no method in this crate names SSH**.
//!
//! ⛔ **The relay accepts no inbound TCP**, and the live legs cannot be exercised
//! from a machine with no minted token — so the framing layer is pure and lives
//! in [`framing`] and [`control`], and the acceptance for E02 is a byte-exact
//! test over those, not a network.
//!
//! # The three shapes
//!
//! | | forward | reverse node | reverse operator |
//! | --- | --- | --- | --- |
//! | id prefix | ⛔ **none** | **32 lowercase hex** | ⛔ **none** |
//! | text frames | ⛔ closes `1003` | **is the control channel** | ⛔ closes `1003` |
//! | max wire frame | **262144** (**MEASURED**) | **65568** | **65536** |
//!
//! ⛔ **The two cap numbers are different and merging the legs is the defect this
//! crate exists to prevent.** The forward cap is **MEASURED** 2026-10-02 from
//! `/relays.json` `limits.max_frame_bytes`; the node cap is **READ** from spec
//! line 182; the operator cap is **READ** from spec line 184 and is a *payload*
//! cap, so the two 65536 numbers are equal for different reasons and are kept as
//! two constants.
//!
//! ⛔ **There is no `Option<SessionId>` anywhere in the framing path**, and that is
//! deliberate: `reverse-operator.md:174-177` names it as *"how a prefix gets
//! added by accident"*. The operator's and the forward path's `encode` functions
//! take `&[u8]` and a `usize`, and neither has a parameter that could hold an id.

pub mod backoff;
pub mod backpressure;
pub mod closes;
pub mod control;
pub mod endpoint;
pub mod error;
pub mod forward;
pub mod framing;
pub mod socket;
pub mod transport;

/// ⛔ **C1: the live session behind the seam.** `adapt` is the only module
/// that names `podssh-ws` — everything above it is pure, and the seam's
/// tests run without a network because of it.
pub mod adapt;

pub use backoff::Backoff;
pub use backpressure::{Direction, FrameDrop, Ledger, Permit, SessionBudgetRefused};
pub use closes::{classify, Classified, CloseRow, RelayClose, CLOSE_ROWS};
pub use control::{ControlError, Hello, NodeLimits};
pub use endpoint::{endpoint, Endpoint, Knobs, LegTarget, RelayConfig, TOKEN_HEADER};
pub use error::{HttpFailure, Retry, SessionAction, TransportError};
pub use framing::{CodecError, SessionId};
pub use socket::{FrameQueue, Leg, Socket};
pub use transport::{Control, LegShape, Limits, Transport};