//! The side of `podssh chat` that waits, with `--iroh` (T-099): the node of
//! both roads, as `podssh node --iroh` serves them (`node_iroh`), whose every
//! session is a conversation once the channel let its key in. The iroh road
//! takes only the keys of `--allow`, and its ticket is said; the pair's road
//! runs too when the pair NAME is stored and good.

use std::path::PathBuf;

use podssh_relay::identity::file::Place;
use tokio::io::AsyncWrite;
use tokio::sync::watch;

use crate::chat::args::ChatArgs;
use crate::chat::converse::Options;
use crate::chat::lines::Lines;
use crate::chat::listen::{busy, flipped, talk, Door};
use crate::chat::output::Output;
use crate::chat::run::{self, Until, CLOSE_WAIT};
use crate::node_iroh::{self, Flags, Roads};
use crate::relay_settings::Refusal;

/// The side that waits on both roads, once each check that needs no network
/// passed.
pub(in crate::chat) struct Ready {
    pub label: String,
    node: node_iroh::Ready,
}

impl Ready {
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// The relays, the pins and the pair, as `podssh node --iroh` checks them.
pub(in crate::chat) fn prepare(
    label: String,
    place: Place,
    allow: Option<PathBuf>,
    args: &ChatArgs,
) -> Result<Ready, Refusal> {
    let node = node_iroh::ready(Flags {
        label: &label,
        place,
        allow,
        iroh_relay: args.iroh_relay.as_deref(),
        relay_addr: args.relay_addr.as_deref(),
        pair_file: args.pair_file.as_deref(),
        ca_file: args.ca_file.as_deref(),
        e2e: true,
    })?;
    Ok(Ready { label, node })
}

/// Serve both roads until the run ends; each session is a conversation.
pub(in crate::chat) async fn run<W: AsyncWrite + Unpin>(
    ready: Ready,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: Options,
    until: Until,
) -> i32 {
    let Ready { label, node } = ready;
    let (door, mut peers) = Door::new();
    let open = {
        let door = door.clone();
        move || door.session()
    };
    let roads = Roads {
        verb: "chat",
        serving: "waiting for the peer".to_string(),
        after: ", one peer at a time",
        handler: door.clone(),
        open,
    };
    let (stop, stopped) = watch::channel(false);
    let (gone_tx, gone) = watch::channel(false);
    let node_part = async {
        let mut err = std::io::stderr();
        let code = node_iroh::serve(node, roads, flipped(stopped), &mut err).await;
        let _ = gone_tx.send(true);
        code
    };
    let talk_part = async {
        let ended = talk(&label, &mut peers, lines, out, &opts, until, gone, "the roads of the node ended").await;
        // No peer from now on; the last one's session gets a while to close.
        peers.close();
        while let Ok(late) = peers.try_recv() {
            busy(late, &label);
        }
        door.closed(CLOSE_WAIT).await;
        let _ = stop.send(true);
        ended
    };
    let (code, (ended, lost)) = tokio::join!(node_part, talk_part);
    if code != 0 {
        // The node said why as it stopped.
        return run::refused(code, "the node could not serve its roads".into(), lines, out).await;
    }
    run::finish(&ended, lost, lines, out).await
}
