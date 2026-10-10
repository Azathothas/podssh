//! `podssh chat` (T-099) as a process, offline, with a scratch HOME and
//! cache: each refusal of the command line and its code, the files that it
//! names, the pair of each side, the gate of runs with no terminal, the
//! manual, and no token in any output.

mod pair_harness;

use pair_harness::*;

/// Each run but the gate's has a time limit, as a script gives one.
fn chat(home: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let mut all = vec!["chat", "--timeout", "5s"];
    all.extend_from_slice(args);
    podssh(home, &all, &[])
}

#[test]
fn each_refusal_of_the_command_line_is_64_with_its_words() {
    let home = scratch("chat-usage");
    let long = "x".repeat(16 * 1024 + 1);
    let nick = "n".repeat(65);
    for (args, says) in [
        (vec![], "missing PEER"),
        (vec!["--send", "hi", "--file", "f", "lab"], "--send, --sendfile and --file each give the run its one thing"),
        (vec!["--send", long.as_str(), "lab"], "a message has 16384 bytes at most"),
        (vec!["--listen", "--client-key", "k", "lab"], "are for the side that reaches the peer"),
        (vec!["--listen", "--node-key", "SHA256:abc", "lab"], "are for the side that reaches the peer"),
        (vec!["--key", "k", "lab"], "are for the side that waits: add --listen"),
        (vec!["--allow", "a", "lab"], "are for the side that waits: add --listen"),
        (vec!["--iroh", "lab"], "are for the side that waits: add --listen"),
        (vec!["--listen", "iroh:abc"], "--listen serves the pair NAME, not a ticket"),
        (vec!["--iroh-relay", "https://r.example.org", "lab"], "--iroh-relay is for the iroh road"),
        (vec!["--pair-file", "p", "iroh:abc"], "a peer iroh:TICKET needs none"),
        (vec!["--nick", "", "lab"], "a nick has 1 to 64 bytes"),
        (vec!["--nick", nick.as_str(), "lab"], "a nick has 1 to 64 bytes"),
        (vec!["--node-key", "garbage", "lab"], "--node-key \"garbage\": not a key"),
        (vec!["--listen", "--key", "k", "--ephemeral-key", "lab"], "--ephemeral-key keeps the key in no file"),
        (vec!["../x"], "not a pair name"),
        (vec!["node://../x"], "not a pair name"),
        (vec!["--no-e2e", "lab"], "--no-e2e"),
    ] {
        let (rc, out, err) = chat(&home, &args);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

#[test]
fn the_files_that_it_names_are_checked_before_any_pair() {
    let home = scratch("chat-files");
    let missing = home.join("missing");
    let missing = missing.to_str().unwrap();
    for (args, code, says) in [
        (vec!["--file", missing, "lab"], 66, "--file"),
        (vec!["--file", home.to_str().unwrap(), "lab"], 66, "not a regular file"),
        (vec!["--sendfile", missing, "lab"], 66, "--sendfile"),
        (vec!["--accept-dir", missing, "lab"], 73, "not a directory"),
    ] {
        let (rc, out, err) = chat(&home, &args);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

#[test]
fn with_no_stored_pair_each_side_names_the_remedy() {
    let home = scratch("chat-none");
    for args in [vec!["lab"], vec!["node://lab"], vec!["--listen", "lab"]] {
        let (rc, out, err) = chat(&home, &args);
        assert_eq!(rc, 78, "{args:?}: {err}");
        assert!(err.contains("podssh relay pair lab"), "{args:?}: {err}");
        assert!(out.is_empty());
    }
}

#[test]
fn an_expired_pair_is_refused_with_77_and_the_remedy() {
    let home = scratch("chat-expired");
    store(&home, "lab", EXPIRED);
    for args in [vec!["lab"], vec!["--listen", "lab"]] {
        let (rc, _, err) = chat(&home, &args);
        assert_eq!(rc, 77, "{args:?}: {err}");
        assert!(err.contains("expired") && err.contains("podssh relay pair lab"), "{args:?}: {err}");
    }
}

/// With a pair in the store, each side gets as far as the network, which
/// `PODSSH_OFFLINE` stops; no key is made before it, and no token shown.
#[test]
fn a_stored_pair_reaches_the_network_and_no_token_is_shown() {
    let home = scratch("chat-offline");
    store(&home, "lab", 0);
    for args in [vec!["lab"], vec!["node:lab", "--send", "hi"], vec!["--listen", "lab"]] {
        let (rc, out, err) = chat(&home, &args);
        assert_eq!(rc, 69, "{args:?}: {err}");
        assert!(err.contains("not attempted: PODSSH_OFFLINE is set"), "{args:?}: {err}");
        no_token(&out);
        no_token(&err);
    }
    let keys: Vec<_> = std::fs::read_dir(cache_dir(&home))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".key"))
        .collect();
    assert!(keys.is_empty(), "a key was made before the network: {keys:?}");
}

/// With no terminal, a run that waits for a peer needs a time limit.
#[test]
fn a_run_with_no_terminal_needs_a_timeout() {
    let home = scratch("chat-gate");
    let (rc, out, err) = podssh(&home, &["chat", "lab"], &[]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.starts_with("podssh chat: --timeout DURATION is required when"), "{err}");
    assert!(err.contains("Example: podssh chat --timeout 60s --send MESSAGE NAME"), "{err}");
    assert!(out.is_empty());
}

#[test]
fn the_help_and_the_manual_give_the_peer_and_the_commands() {
    let home = scratch("chat-man");
    let (rc, help, _) = podssh(&home, &["chat", "--help"], &[]);
    assert_eq!(rc, 0);
    assert!(help.contains("podssh chat [OPTIONS] PEER"), "{help}");
    assert!(!help.contains("not implemented"), "{help}");
    // The page wraps its lines: the words are looked for in one line.
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let (rc, page, err) = podssh(&home, &["man", "chat"], &[]);
    assert_eq!(rc, 0, "{err}");
    let page = flat(&page);
    for words in ["--listen", "--accept-dir DIR", "/accept ID", "known-nodes", "1000 lines or 1 MiB"] {
        assert!(page.contains(words), "{words}: {page}");
    }
    let (rc, exits, _) = podssh(&home, &["man", "exit-status"], &[]);
    assert_eq!(rc, 0);
    let exits = flat(&exits);
    assert!(exits.contains("podssh chat: the --timeout passed, or the peer talks with another peer"), "{exits}");
}

/// A build without the feature `iroh` refuses each side of the iroh road
/// before anything connects, with exit 70 and the feature's name.
#[cfg(not(feature = "iroh"))]
#[test]
fn the_iroh_road_is_refused_in_a_build_without_it() {
    let home = scratch("chat-noiroh");
    for (args, says) in [
        (vec!["iroh:abcdef"], "iroh:abcdef: the iroh road is not in this build"),
        (vec!["--listen", "--iroh", "lab"], "--iroh: the iroh road is not in this build"),
    ] {
        let (rc, out, err) = chat(&home, &args);
        assert_eq!(rc, 70, "{args:?}: {err}");
        assert!(err.contains(says) && err.contains("--features iroh"), "{args:?}: {err}");
        assert!(out.is_empty());
    }
}

/// `--irc` (T-252): PEER is a channel, the nick follows the grammar of IRC,
/// and the flags of the roads do not go with it.
#[test]
fn the_irc_command_line_refuses_what_does_not_go_with_it() {
    let home = scratch("chat-irc-usage");
    for (args, says) in [
        (vec!["--irc", "irc.example.org", "podssh"], "is not a channel"),
        (vec!["--irc", "irc.example.org", "#a b"], "is not a channel"),
        (vec!["--irc", "irc.example.org", "--listen", "#c"], "--listen is for the roads"),
        (vec!["--irc", "irc.example.org", "--pair-file", "p", "#c"], "--pair-file is for the roads"),
        (vec!["--irc", "irc.example.org", "--nick", "9lives", "#c"], "an IRC nick is a letter"),
        (vec!["--irc", "irc.example.org", "--irc-plaintext", "--irc-ca-file", "f", "#c"], "--irc-plaintext turns off"),
        (vec!["--irc", "irc.example.org:x", "#c"], "--irc"),
        (vec!["--irc-plaintext", "lab"], "are for --irc SERVER"),
    ] {
        let (rc, out, err) = chat(&home, &args);
        assert_eq!(rc, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

/// A nick that the variable gives is checked as the flag's is; a bad one is
/// a setting of the environment (78).
#[test]
fn a_bad_nick_of_the_variable_is_a_configuration_error() {
    let home = scratch("chat-irc-nick");
    let (rc, _, err) =
        podssh(&home, &["chat", "--timeout", "5s", "--irc", "irc.example.org", "#c"], &[("PODSSH_NICK", "9lives")]);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("PODSSH_NICK"), "{err}");
}

/// With a good command line, the chat goes as far as the network, which
/// `PODSSH_OFFLINE` stops.
#[test]
fn the_irc_chat_reaches_the_network_and_no_further_offline() {
    let home = scratch("chat-irc-offline");
    for args in [vec!["--irc", "irc.example.org", "#c"], vec!["--irc", "irc.example.org:6667", "--irc-plaintext", "#c"]]
    {
        let (rc, out, err) = chat(&home, &args);
        assert_eq!(rc, 69, "{args:?}: {err}");
        assert!(err.contains("not attempted: PODSSH_OFFLINE is set"), "{args:?}: {err}");
        assert!(out.is_empty());
    }
}
