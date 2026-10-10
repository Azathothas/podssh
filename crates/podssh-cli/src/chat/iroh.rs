//! The iroh road of `podssh chat` (T-099): `--listen NAME --iroh` serves the
//! conversations on both roads, with a ticket, and `chat iroh:TICKET`
//! reaches them. In a build without the feature `iroh`, each is refused
//! before anything connects, with exit 70 and the feature's name, as
//! `podssh node --iroh` is.

#[cfg(feature = "iroh")]
mod listen;
#[cfg(feature = "iroh")]
mod reach;

#[cfg(feature = "iroh")]
pub(super) use built::*;
#[cfg(not(feature = "iroh"))]
pub(super) use stub::*;

#[cfg(feature = "iroh")]
mod built {
    pub(in crate::chat) use super::listen::{prepare as prepare_waiting, run as run_waiting, Ready as Waiting};
    pub(in crate::chat) use super::reach::{prepare as prepare_reach, run as run_reach, Ready as Reach};
}

#[cfg(not(feature = "iroh"))]
mod stub {
    use podssh_relay::identity::file::Place;
    use std::path::PathBuf;
    use tokio::io::AsyncWrite;

    use crate::channel::Ask;
    use crate::chat::args::ChatArgs;
    use crate::chat::converse::Options;
    use crate::chat::lines::Lines;
    use crate::chat::output::Output;
    use crate::chat::run::Until;
    use crate::relay_settings::Refusal;

    /// No side of the iroh road in this build: neither can be made.
    pub(in crate::chat) enum Waiting {}
    pub(in crate::chat) enum Reach {}

    impl Waiting {
        pub fn label(&self) -> &str {
            match *self {}
        }
    }

    impl Reach {
        pub fn label(&self) -> &str {
            match *self {}
        }
    }

    fn not_built(what: &str) -> Refusal {
        Refusal { message: crate::ssh::iroh::not_built(what), code: crate::exit_codes::EXIT_NOT_IMPLEMENTED }
    }

    pub(in crate::chat) fn prepare_waiting(
        _: String,
        _: Place,
        _: Option<PathBuf>,
        _: &ChatArgs,
    ) -> Result<Waiting, Refusal> {
        Err(not_built("--iroh"))
    }

    pub(in crate::chat) fn prepare_reach(ticket: String, _: Ask, _: &ChatArgs) -> Result<Reach, Refusal> {
        Err(not_built(&ticket))
    }

    pub(in crate::chat) async fn run_waiting<W: AsyncWrite + Unpin>(
        ready: Waiting,
        _: &mut Lines,
        _: &mut Output<W>,
        _: Options,
        _: Until,
    ) -> i32 {
        match ready {}
    }

    pub(in crate::chat) async fn run_reach<W: AsyncWrite + Unpin>(
        ready: Reach,
        _: &mut Lines,
        _: &mut Output<W>,
        _: Options,
        _: Until,
    ) -> i32 {
        match ready {}
    }
}
