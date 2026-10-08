//! podssh-probe — capability detection. Probes; never assumes.
//!
//! ⛔ Every answer this crate gives is **three-valued**: `ok`, a failure, or
//! `????` for something that could not be measured. ⛔ **A capability that was
//! not probed is never reported as present**, and a check that could not run is
//! never reported as a pass — that is the defect four sibling projects shipped
//! and the one this repository shipped itself.
//!
//! It currently owns **E06**, the relay's structural facts, because the relay
//! moves under its clients and a client that discovers it mid-session reports it
//! as a mysterious close code.

pub mod facts;
pub mod relay_facts;

pub use facts::{Facts, FACT_SOURCE};
pub use relay_facts::{verdict_from, Verdict};