//! `ts` parse tests (Tailscale): all three forms parse to `Parsed::Ts` carrying
//! every behaviour input, and a bad `--ts-mode` is usage 64 at parse.

use podssh_cli::tree::{parse, Parsed};

#[test]
fn ts_alias_parses_to_ts_with_auto_mode() {
    let p = parse(vec!["tailscale".to_string(), "--timeout".to_string(), "30s".to_string()]);
    match p {
        Parsed::Ts { mode, .. } => assert_eq!(mode, "auto"),
        other => panic!("expected Ts, got {other:?}"),
    }
}

#[test]
fn ts_good_modes_parse_with_empty_refusals() {
    for mode in ["auto", "tun", "socks", "tcp", "relay"] {
        let owned = vec!["ts".to_string(), "--ts-mode".to_string(), mode.to_string()];
        match parse(owned) {
            Parsed::Ts { mode: m, refused, .. } => {
                assert_eq!(m, mode);
                assert!(refused.is_empty(), "{mode}: {refused:?}");
            }
            other => panic!("{mode}: expected Ts, got {other:?}"),
        }
    }
}

/// `--jsonl` with `-W` is refused at parse, as under `proxy`: stdout there is
/// the stream to the peer (T-240). Each spelling of each flag.
#[test]
fn ts_w_with_jsonl_is_refused_at_parse() {
    for argv in [
        &["ts", "-W", "peer:22", "--jsonl", "--timeout", "5s"][..],
        &["ts", "--jsonl", "-W", "peer:22"],
        &["ts", "-Wpeer:22", "--jsonl"],
        &["ts", "-W", "peer:22", "--jsonl=1"],
        &["tailscale", "-W", "peer:22", "--jsonl"],
    ] {
        let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        match parse(owned) {
            Parsed::Usage(message) => {
                assert!(message.contains("--jsonl is refused with ts -W"), "{argv:?}: {message}");
                assert!(message.contains("byte stream"), "the reason: {message}");
            }
            other => panic!("{argv:?}: expected the refusal, got {other:?}"),
        }
    }
    // The status form takes it.
    let owned = vec!["ts".to_string(), "--jsonl".to_string(), "--timeout".to_string(), "5s".to_string()];
    assert!(matches!(parse(owned), Parsed::Ts { jsonl: true, .. }));
}

#[test]
fn ts_bad_mode_is_usage_naming_the_values() {
    for argv in
        [vec!["ts", "--ts-mode", "bogus", "--timeout", "30s"], vec!["ts", "--ts-mode=bogus", "--timeout", "30s"]]
    {
        let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        match parse(owned) {
            Parsed::Usage(m) => {
                assert!(m.contains("bogus"), "{m}");
                assert!(m.contains("auto, tun, socks, tcp, relay"), "{m}");
            }
            other => panic!("{argv:?}: expected Usage, got {other:?}"),
        }
    }
}

#[test]
fn ts_forms_carry_their_positionals() {
    // Bare: no destination, no args, no pipe target.
    match parse(vec!["ts".to_string()]) {
        Parsed::Ts { destination, args, w_target, .. } => {
            assert_eq!(destination, None);
            assert!(args.is_empty());
            assert_eq!(w_target, None);
        }
        other => panic!("expected Ts, got {other:?}"),
    }
    // Host form: destination plus trailing command words.
    let owned: Vec<String> = ["ts", "peer", "--", "uptime"].iter().map(|s| s.to_string()).collect();
    match parse(owned) {
        Parsed::Ts { destination, args, .. } => {
            assert_eq!(destination.as_deref(), Some("peer"));
            assert_eq!(args, vec!["uptime".to_string()]);
        }
        other => panic!("expected Ts, got {other:?}"),
    }
    // Pipe form: the -W target rides along.
    let owned: Vec<String> = ["ts", "-W", "peer:22"].iter().map(|s| s.to_string()).collect();
    match parse(owned) {
        Parsed::Ts { w_target, .. } => assert_eq!(w_target.as_deref(), Some("peer:22")),
        other => panic!("expected Ts, got {other:?}"),
    }
}

#[test]
fn ts_flags_ride_along_verbatim() {
    let owned: Vec<String> = [
        "ts",
        "--ts-auth-key-file",
        "k.key",
        "--ts-state",
        "s.json",
        "--ts-ephemeral",
        "--ts-relay",
        "r.example",
        "--ts-wait-allowlist",
        "30s",
        "--ts-proxy",
        "http://127.0.0.1:3128",
        "--timeout",
        "30s",
        "--jsonl",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    match parse(owned) {
        Parsed::Ts { auth_key_file, state, ephemeral, relay, wait_allowlist, proxy, timeout, jsonl, .. } => {
            assert_eq!(auth_key_file.as_deref(), Some("k.key"));
            assert_eq!(state.as_deref(), Some("s.json"));
            assert!(ephemeral);
            assert_eq!(relay.as_deref(), Some("r.example"));
            assert_eq!(wait_allowlist.as_deref(), Some("30s"));
            assert_eq!(proxy.as_deref(), Some("http://127.0.0.1:3128"));
            assert_eq!(timeout.as_deref(), Some("30s"));
            assert!(jsonl);
        }
        other => panic!("expected Ts, got {other:?}"),
    }
}
