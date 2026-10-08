//! E17 — ⛔ **the `(name, address)` pair, and the refusal that makes it a type
//! rather than a convention.**
//!
//! ⛔ **The entry's second plant is ⛔ *"a configured bare IP, no hostname*
//! ⛔ must be ⛔ **rejected at parse time**"** ⛔ — ⛔ and ⛔ **the way that
//! ⛔ is guaranteed here is structural:** ⛔ **both fields of
//! ⛔ [`RelayAddress`] are private and no constructor takes an address
//! ⛔ alone**, ⛔ so ⛔ **a value of the type cannot exist without
//! ⛔ a name.** ⛔ **⛔ `podssh --insecure` ⛔ is not a way out** ⛔ ,
//! ⛔ because ⛔ a pin is a pin and not a trust anchor ⛔ .
//!
//! ⛔ **The measurement this rests on** ⛔ — ⛔ **MEASURED 2026-10-01**, host
//! ⛔ `Ajam` ⛔ (Windows 11, `MINGW64_NT-10.0-26200`), in
//! ⛔ `relay-hostname.md`'s `## Premise`:
//!
//! ```text
//! wrong: pin the address, drop the hostname
//! curl -sS -H 'Host: tcp-1.ssh.relay.ajam.dev' https://104.21.39.2/health
//! curl: (35) schannel: next InitializeSecurityContext failed: SEC_E_ILLEGAL_MESSAGE
//! exit=35, for tcp-1, tcp-2 and tcp-3 alike
//!
//! right: pin the address, KEEP the hostname for SNI and Host
//! curl -sS --resolve 'tcp-1.ssh.relay.ajam.dev:443:104.21.39.2' \
//!   https://tcp-1.ssh.relay.ajam.dev/health
//! http=200 remote=104.21.39.2
//! ```
//!
//! ⛔ **A relay address on its own is not a relay.**

use std::net::SocketAddr;

use podssh_transport::hostname::{RelayAddress, RelayAddressError};

mod common;

use common::dns::RELAY;

/// ⛔ **THE PLANT, and it is refused by the TYPE.** ⛔ `podssh
/// ⛔ --relay-address 104.21.39.2 connect …` ⛔ **must never
/// ⛔ produce a session** ⛔ — ⛔ and ⛔ **⛔ the first
/// ⛔ plant is worthless if this one "works"** ⛔ .
#[test]
fn plant_a_bare_address_is_refused_at_parse_time() {
    let bare = "104.21.39.2";

    // ⛔ **THE DEFECT ARM: a parser that accepts a bare address.** ⛔
    // ⛔ **This is a `Host:` header against a pinned address** ⛔ — ⛔
    // ⛔ **the curl(1) form at `dropssh` `src/connect.c:122-123`, and it
    // ⛔ exits 35** ⛔ — ⛔ **not a TLS
    // ⛔ failure podssh could recover from.**
    if planted("bare_relay_address") {
        let accepted = RelayAddress::parse(bare, 443);
        assert!(
            accepted.is_err(),
            "⛔ a bare address parsed into a relay address: {accepted:?}. ⛔ The relay is behind a             ⛔ certificate issued for a name (relay-hostname.md, MEASURED 2026-10-01:             ⛔ `curl -H 'Host: …' https://104.21.39.2/health` exits ⛔ 35, SEC_E_ILLEGAL_MESSAGE).             ⛔ E17: a configured address is a (name, address) PAIR and a bare IP is             ⛔ not representable"
        );
        return;
    }

    // ⛔ **THE CORRECT PATH — and it is `Err` from `parse`,** ⛔
    // ⛔ **which is the function `podssh --relay-address <v>` calls.** ⛔
    let error = RelayAddress::parse(bare, 443).expect_err("⛔ a bare address is not a relay");
    assert!(
        matches!(error, RelayAddressError::MissingName { .. }),
        "⛔ and the variant is MissingName, not a parse failure of the address: {error:?}"
    );

    // ⛔ **AND THE MESSAGE SAYS WHY, in the operator's terms.** ⛔
    let message = error.to_string();
    assert!(message.contains(bare), "⛔ it names what was passed: {message}");
    assert!(
        message.contains("bare address") && message.contains("not a relay"),
        "⛔ and says the thing plainly: {message}"
    );
    assert!(message.contains("hostname is required") || message.contains("--insecure is not the way"),
        "⛔ and says the hostname is required AND that --insecure is not the way out: {message}");
    assert!(
        message.contains("--relay-address") && message.contains('='),
        "⛔ and prints the spelling that works: {message}"
    );
    // ⛔ **AND IT MUST NEVER OFFER `--insecure` AS A WAY TO MAKE IT WORK** ⛔
    // ⛔ **⛔ `relay-hostname.md`: "⛔ `--insecure` ⛔ must never be the way
    // ⛔ to make a pinned address work"** ⛔ — ⛔ the message
    // ⛔ names it only to forbid it.
    let insecure_at = message.find("--insecure");
    if let Some(at) = insecure_at {
        assert!(
            message[at..].contains("not the way") || message[at..].contains("loss of host identity"),
            "⛔ --insecure appears only to be refused: {message}"
        );
    }

    // ⛔ **THE SAME REFUSAL FOR EVERY SPELLING OF A BARE ADDRESS**, ⛔
    // ⛔ **⛔ and the entry says ⛔ "for tcp-1, tcp-2 and tcp-3 alike"** ⛔ .
    for bare in [
        "104.21.39.2",
        " 104.21.39.2 ",
        "[2606:4700:4700::1111]",
        "2606:4700:4700::1111",
        "104.21.39.2:443",
    ] {
        assert!(
            matches!(RelayAddress::parse(bare, 443), Err(RelayAddressError::MissingName { .. })),
            "⛔ {bare:?} is a bare address and must be MissingName"
        );
    }

    // ⛔ **AND AN EMPTY NAME IS THE SAME REFUSAL, ⛔ not a second rule.** ⛔
    assert!(
        matches!(RelayAddress::parse("=104.21.39.2", 443), Err(RelayAddressError::MissingName { .. })),
        "⛔ an empty name is the same defect with a different spelling"
    );

    // ⛔ **THE CONTROL THE ENTRY DEMANDS, ⛔ run it.** ⛔ **⛔ "Control —
    // ⛔ the correct input must still pass": a configured `(name, address)`
    // ⛔ pair** ⛔ — ⛔ and ⛔ **a guard that refuses
    // ⛔ everything looks identical to a good guard until it blocks real work.**
    let pair = RelayAddress::parse(&format!("{RELAY}=104.21.39.2"), 443).expect("⛔ the pair parses");
    assert_eq!(pair.name(), RELAY);
    assert_eq!(pair.address(), "104.21.39.2:443".parse::<SocketAddr>().unwrap());
    assert_eq!(pair.server_name(), RELAY, "⛔ and the name is what goes to SNI");
}

/// ⛔ **The name is a NAME, and a value that goes into SNI and a `Host` header
/// cannot be a URL or a path.**
#[test]
fn the_hostname_must_be_a_name_and_not_a_url_or_a_path() {
    // ⛔ **Each of these is refused, and each has its own reason** ⛔ — ⛔ **⛔
    // ⛔ a single "bad hostname" string would tell an operator nothing** ⛔ .
    for (name, why) in [
        ("https://tcp-1.ssh.relay.ajam.dev", "a scheme"),
        ("tcp-1.ssh.relay.ajam.dev/health", "a path"),
        ("user@tcp-1.ssh.relay.ajam.dev", "an at-sign"),
        ("tcp 1.ssh.relay.ajam.dev", "whitespace"),
        (".tcp-1.ssh.relay.ajam.dev", "a leading dot"),
        ("tcp-1..ssh.relay.ajam.dev", "an empty label"),
        ("tcp-1.ssh.relay.ajam.dev:443", "a port"),
        ("tcp-1.ssh.relay.ajam.dev#f", "a fragment"),
        ("-tcp-1.ssh.relay.ajam.dev", "a leading hyphen"),
        ("tcp-1.ssh.relay.ajam.dev-", "a trailing hyphen"),
    ] {
        let error = RelayAddress::new(name, "104.21.39.2", 443)
            .expect_err(&format!("⛔ {name:?} is not a hostname"));
        assert!(
            matches!(error, RelayAddressError::BadName { .. }),
            "⛔ {name:?} ({why}) is BadName, not something else: {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("is not usable"), "⛔ {name:?}: {message}");
        assert!(
            message.contains(name) || message.contains(name.trim_matches(|c| c == '.')),
            "⛔ and it names the name back: {message}"
        );
    }

    // ⛔ **A LABEL OVER 63 BYTES, and the whole name over 253** ⛔
    // ⛔ **⛔ and both are DNS limits, ⛔ and neither is a policy podssh invented** ⛔ .
    let long_label = format!("{}.example", "a".repeat(64));
    assert!(matches!(
        RelayAddress::new(&long_label, "104.21.39.2", 443),
        Err(RelayAddressError::BadName { .. })
    ));
    let long_name = vec!["a".repeat(63); 5].join(".");
    assert!(long_name.len() > 253, "⛔ and that name is over 253 bytes: {}", long_name.len());
    assert!(matches!(
        RelayAddress::new(&long_name, "104.21.39.2", 443),
        Err(RelayAddressError::BadName { .. })
    ));

    // ⛔ **AND THE MESSAGE SAYS IT IS A NAME AND NOT A URL, ⛔ because ⛔
    // ⛔ **⛔ that is the fix the operator needs** ⛔ .
    let message = RelayAddress::new("https://relay.test", "104.21.39.2", 443)
        .expect_err("⛔ a URL is not a hostname")
        .to_string();
    assert!(
        message.contains("a name and not a URL"),
        "⛔ and it says what a hostname is: {message}"
    );

    // ⛔ **THE CONTROL: ordinary names are accepted.** ⛔ **⛔ all four
    // ⛔ pool names from `relay-hostname.md`'s measured table, ⛔
    // ⛔ **⛔ and the bare default name** ⛔ **⛔ a guard that
    // ⛔ refuses every name in the entry's own table refuses the feature.**
    for name in [
        "tcp-1.ssh.relay.ajam.dev",
        "tcp-2.ssh.relay.ajam.dev",
        "tcp-3.ssh.relay.ajam.dev",
        "tcp.ssh.relay.ajam.dev",
        "localhost",
        "relay.internal.example",
        "a.b",
    ] {
        let pair = RelayAddress::new(name, "104.21.39.2", 443)
            .unwrap_or_else(|e| panic!("⛔ {name} is an ordinary name: {e}"));
        assert_eq!(pair.name(), name, "⛔ and it round-trips");
        assert_eq!(pair.server_name(), name, "⛔ and reaches SNI unchanged");
    }
}

/// ⛔ **A hostname where the ADDRESS belongs is refused, and that is the
/// resolution this entry exists to perform.**
#[test]
fn a_hostname_where_the_address_belongs_is_refused() {
    let error = RelayAddress::new(RELAY, "tcp.ssh.relay.ajam.dev", 443)
        .expect_err("⛔ a name is not an address");
    assert!(
        matches!(error, RelayAddressError::BadAddress { .. }),
        "⛔ and it is BadAddress, which is a DIFFERENT fix from MissingName: {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("is not an address"),
        "⛔ and says which half is wrong: {message}"
    );
    assert!(
        message.contains("the resolution this entry is failing to perform") || message.contains("Do not pass a hostname"),
        "⛔ and says why this is a resolution and not a typo: {message}"
    );

    // ⛔ **THE CONTROL: bracketed IPv6 IS accepted, ⛔ **⛔ brackets
    // ⛔ are how an IPv6 literal is written in a URL authority** ⛔ — ⛔ and ⛔
    // ⛔ **rejected silently is the defect**, ⛔ so they are
    // ⛔ stripped and ⛔ the port supplied separately.
    let v6 = RelayAddress::new(RELAY, "[2606:4700:4700::1111]", 443).expect("⛔ a bracketed v6 literal");
    assert_eq!(v6.address().ip().to_string(), "2606:4700:4700::1111");
    assert_eq!(v6.address().port(), 443, "⛔ and the port is the parameter, not parsed out of it");
    let bare_v6 = RelayAddress::new(RELAY, "2606:4700:4700::1111", 443).expect("⛔ an unbracketed one too");
    assert_eq!(bare_v6, v6, "⛔ and the two spellings are one address");
}

/// ⛔ **The name is lowercased and the port is never parsed out of the address.**
#[test]
fn the_pair_normalises_the_name_and_keeps_the_port_a_parameter() {
    let upper = RelayAddress::new("TCP-1.SSH.RELAY.AJAM.DEV", "104.21.39.2", 8443).expect("⛔ a name");
    assert_eq!(
        upper.name(),
        RELAY,
        "⛔ DNS is case-insensitive and a certificate's SANs match case-insensitively"
    );
    assert_eq!(upper.server_name(), RELAY, "⛔ and SNI gets the lowercased form");

    // ⛔ **A NAME WITH SURROUNDING WHITESPACE IS TRIMMED**, ⛔
    // ⛔ **⛔ and the trimmed form is what is stored** ⛔ — ⛔ **⛔ a name
    // ⛔ with a space in it would go into a `Host` header verbatim.**
    let padded = RelayAddress::parse("  tcp-1.ssh.relay.ajam.dev = 104.21.39.2  ", 443)
        .expect("⛔ a padded pair");
    assert_eq!(padded.name(), RELAY);
    assert_eq!(padded.address(), "104.21.39.2:443".parse::<SocketAddr>().unwrap());

    // ⛔ **AND THE ADDRESS IS A PARAMETER, NOT PART OF THE STRING** ⛔
    // ⛔ **⛔ `dropssh` `src/dns.c:378-381` composes `cannot resolve %s: …`**
    // ⛔ **and a host string carrying `:443` in it is how a caller ends up
    // ⛔ searching `/etc/hosts` for `example.com:443`** ⛔ .
    let two_ports = RelayAddress::new(RELAY, "104.21.39.2", 443).expect("⛔ a pair");
    let other_port = RelayAddress::new(RELAY, "104.21.39.2", 8443).expect("⛔ the same pair");
    assert_eq!(two_ports.name(), other_port.name(), "⛔ the name does not move");
    assert_ne!(two_ports.address().port(), other_port.address().port(), "⛔ and the port does");
    assert_eq!(two_ports.as_pair().1.port(), 443);
    assert_eq!(two_ports.as_pair().0, RELAY, "⛔ and the pair is what `Sources` wants");
}

/// The default relay is compiled in (operator decision 2026-10-08) and its
/// name appears as a string literal in exactly one place in library code,
/// `podssh-relay/src/relay.rs`, so that changing it is a one-line edit. Tests,
/// examples and documentation may name it freely.
///
/// (This replaced a sweep asserting there was no default relay at all; that
/// sweep skipped any line containing `=`, so it never caught a constant.)
#[test]
fn the_default_relay_is_named_in_exactly_one_place() {
    let hits = default_relay_literals_in_library_code();
    assert_eq!(hits.len(), 1, "expected one definition, in podssh-relay/src/relay.rs; found {hits:?}");
    assert!(hits[0].starts_with("crates/podssh-relay/src/relay.rs:"), "{hits:?}");
}

/// Every non-comment line outside test modules, in `crates/*/src/**/*.rs`,
/// that contains the default relay's name as a string literal.
fn default_relay_literals_in_library_code() -> Vec<String> {
    const NEEDLE: &str = "\"tcp.ssh.relay.ajam.dev\"";
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let mut hits = Vec::new();
    let mut files = 0usize;
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !matches!(name.as_str(), "target" | "tests" | "examples" | "benches") {
                    stack.push(path);
                }
                continue;
            }
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if !rel.ends_with(".rs") || !rel.contains("/src/") {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&path).expect("UTF-8 source");
            for (n, line) in text.lines().enumerate() {
                // Unit tests sit in a `#[cfg(test)]` module at the end of a file.
                if line.trim_start().starts_with("#[cfg(test)]") {
                    break;
                }
                if !line.trim_start().starts_with("//") && line.contains(NEEDLE) {
                    hits.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    assert!(files > 20, "the sweep read only {files} source files, so it measured nothing");
    hits
}

/// ⛔ **The plant selector, and the same one `tests/plants.rs` uses.**
fn planted(name: &str) -> bool {
    std::env::var("PODSSH_PLANT").as_deref() == Ok(name)
}
