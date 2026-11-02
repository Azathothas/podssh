//! `podssh node NAME [TARGET] --quick-tunnel --relay` (T-428): the relay role
//! of `podssh relay serve` (T-169, T-427) behind the node's quick tunnel,
//! with no listener. The node gives the role's paths (`/health`, `/v1/mint`,
//! `/connect/HOST/PORT`, `/relays.json`, `/trace`, `/llms-full.txt` and
//! `/v1/...`) to the role in place of its 404, or, with no TARGET, each
//! path; its one line on stdout, `https://NAME.trycloudflare.com`, is the
//! relay host of `--relay-host`. The role mints for the keys of `--allow` by
//! default, each by its signature of the role's challenge (T-448), and for
//! another list, anyone or no one when `--mint` says so; the net's members
//! are T-455's.

use std::sync::Arc;

use podssh_relay::quick::origin::Origin;
use podssh_relay::serve::behind::Behind;
use podssh_relay::serve::{self, Config, Limits, Mint};

use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The role of a node, its settings checked before anything connects.
pub(crate) struct Role {
    pub cfg: Arc<Config>,
    /// Whom it mints for, as its line says it.
    who: String,
    kept: String,
}

/// The role's flags need `--relay`, and `--relay` needs `--quick-tunnel`:
/// a listener's relay is `podssh relay serve`.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    let given =
        [(args.mint.is_some(), "--mint"), (args.pairs.is_some(), "--pairs"), (args.allow_private, "--allow-private")];
    if let Some((_, flag)) = given.iter().find(|(given, _)| *given).filter(|_| !args.relay) {
        return Err(Refusal::usage(format!("{flag} is a setting of the relay role of a quick tunnel: add --relay")));
    }
    if args.relay && !args.quick_tunnel {
        let why = "--relay is for --quick-tunnel, whose node then serves the relay with no listener; a relay \
                   that listens is podssh relay serve --listen";
        return Err(Refusal::usage(why));
    }
    Ok(())
}

/// The role that `--relay` asks for, or none: whom it mints for (the keys of
/// `allow` by default), and its pairs, read now.
pub(crate) fn role(args: &NodeArgs, label: &str, allow: &std::path::Path) -> Result<Option<Role>, Refusal> {
    if !args.relay {
        return Ok(None);
    }
    let mint = match args.mint.as_deref() {
        Some(word) => crate::relay_serve::mint_of(word)?,
        None => Mint::Keys(allow.to_path_buf()),
    };
    let who = crate::relay_serve::minting_for(&mint)?;
    let tokens = serve::tokens::Tokens::random().map_err(Refusal::config)?;
    let pairs = serve::reverse::Pairs::open(args.pairs.as_deref().map(Into::into)).map_err(Refusal::config)?;
    let kept = match args.pairs.as_deref() {
        Some(file) => format!(", its pairs kept in {file} ({} now)", pairs.len()),
        None => String::new(),
    };
    // Each mint, upgrade, Close and step of the reverse road, a line of the
    // node's: stdout holds the tunnel's name alone.
    let label = label.to_string();
    let events: serve::Events =
        Box::new(move |line: &str| podssh_ssh::err_line!("podssh node: {label}: relay: {line}"));
    let cfg = Config {
        version: format!("podssh {}", env!("CARGO_PKG_VERSION")),
        mint,
        tokens,
        policy: serve::policy::Policy { private: args.allow_private, ..Default::default() },
        limits: Limits::default(),
        pairs,
        answered: Default::default(),
        events: Some(events),
        brake: Default::default(),
    };
    let who = if args.allow_private { format!("{who}, private targets too") } else { who };
    Ok(Some(Role { cfg: Arc::new(cfg), who, kept }))
}

impl Role {
    /// The origin of the node's tunnel of the name `name`: the role's paths,
    /// or each path for a node with no TARGET.
    pub fn origin(&self, name: &str, alone: bool) -> Arc<dyn Origin> {
        Arc::new(Behind::new(self.cfg.clone(), name, alone))
    }

    /// The node's line of the role, once the tunnel has its name.
    pub fn shown(&self, name: &str) -> String {
        format!(
            "the relay's forward and reverse roads (contract {}) at {name}, with no listener, minting for {}{}; \
             a client reaches them with --relay-host https://{name}",
            serve::CONTRACT,
            self.who,
            self.kept
        )
    }
}
