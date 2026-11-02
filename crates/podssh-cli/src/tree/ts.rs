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
        control_url: get("ts-control-url"),
        wait_allowlist: get("ts-wait-allowlist"),
        refused,
        timeout: get("timeout"),
        jsonl: matches.get_flag("jsonl"),
    }
}

/// `--ts-mode` values are closed: auto tun socks tcp relay. Anything else
/// is usage 64 now, not a fallthrough to auto later. Both spellings
/// (`--ts-mode bogus` and `--ts-mode=bogus`); a `--ts-mode` with no usable
/// value falls through to clap, which reports the missing value itself.
/// Apart from `tree.rs` for its length.
pub(super) fn bad_mode(rest: &[std::ffi::OsString]) -> Option<Parsed> {
    let mut mode_value: Option<String> = None;
    let mut rest_iter = rest.iter().peekable();
    while let Some(a) = rest_iter.next() {
        let Some(s) = a.to_str() else { continue };
        if let Some(v) = s.strip_prefix("--ts-mode=") {
            mode_value = Some(v.to_string());
        } else if s == "--ts-mode" {
            if let Some(next) = rest_iter.peek() {
                if let Some(ns) = next.to_str() {
                    if !ns.starts_with('-') {
                        mode_value = Some(ns.to_string());
                    }
                }
            }
        }
    }
    let m = mode_value?;
    if matches!(m.as_str(), "auto" | "tun" | "socks" | "tcp" | "relay") {
        return None;
    }
    Some(Parsed::Usage(format!("podssh ts: --ts-mode {m} is not a mode. Use one of: auto, tun, socks, tcp, relay.")))
}
