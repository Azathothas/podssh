//! The parse of `podssh ts` (Tailscale), apart from `tree.rs` for its
//! length.

use clap::ArgMatches;

use super::Parsed;

/// **`ts` carries its behaviour inputs** (Tailscale): every flag value the
/// dispatch needs, read here where `clap` owns them. `--ts-mode` was
/// validated by `parse_verb`, so absence here means `auto` — the default,
/// not a guess. Only rows `TS_FLAGS` declares are read.
pub(super) fn parsed(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Parsed {
    let get = |id: &str| matches.get_one::<String>(id).cloned();
    Parsed::Ts {
        destination: get("destination"),
        args: matches.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default(),
        w_target: get("stdio-forward"),
        mode: get("ts-mode").unwrap_or_else(|| "auto".to_string()),
        proxy: get("ts-proxy"),
        auth_key_file: get("ts-auth-key-file"),
        state: get("ts-state"),
        ephemeral: matches.get_flag("ts-ephemeral"),
        relay: get("ts-relay"),
        wait_allowlist: get("ts-wait-allowlist"),
        refused,
        timeout: get("timeout"),
        jsonl: matches.get_flag("jsonl"),
    }
}
