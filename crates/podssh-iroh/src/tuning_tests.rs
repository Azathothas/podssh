//! The QUIC settings of the iroh road (T-665): each arm's values in iroh's
//! own config, iroh's settings kept where podssh sets nothing, and iroh's
//! own value kept where its types refuse one of podssh's.

use std::time::Instant;

use super::*;

/// The settings as iroh's config says them.
fn said(tuning: &Tuning) -> String {
    format!("{:?}", tuning.config().0)
}

/// The first window of the arm's congestion controller, in bytes.
fn first_window(tuning: Tuning) -> u64 {
    tuning.controller().build(Instant::now(), PACKET as u16).initial_window()
}

#[test]
fn the_default_arm_is_iroh_s_own_until_the_a_b_run() {
    for value in [None, Some(""), Some("  "), Some("iroh"), Some("IROH")] {
        assert_eq!(Tuning::from_value(value), Ok(Tuning::IROH), "{value:?}");
    }
    assert_eq!(Tuning::IROH.to_string(), "iroh's own settings");
    let text = said(&Tuning::IROH);
    // noq's own first round trip and stream window, and iroh's keep-alive,
    // which noq alone does not set: iroh's builder is the base.
    for part in ["initial_rtt: 333ms", "stream_receive_window: 1250000", "keep_alive_interval: Some(5s)"] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert!(Tuning::IROH.config().1.is_empty(), "nothing of iroh's was refused");
}

#[test]
fn the_tuned_arm_reaches_iroh_s_config_with_iroh_s_own_beside_it() {
    assert_eq!(Tuning::from_value(Some("tuned")), Ok(Tuning::TUNED));
    assert_eq!(Tuning::from_value(Some(" rtt, WINDOW ,streams")), Ok(Tuning::TUNED));
    let (config, kept) = Tuning::TUNED.config();
    assert!(kept.is_empty(), "{kept:?}");
    let text = format!("{config:?}");
    for part in [
        "initial_rtt: 100ms",
        "stream_receive_window: 8388608",
        "receive_window: 16777216",
        // iroh's own, which the arm leaves: the keep-alive of its hole
        // punching, and the first MTU, which is already osewa's 1200.
        "keep_alive_interval: Some(5s)",
        "initial_mtu: 1200",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert_eq!(Tuning::TUNED.words(), "rtt,window,streams,cubic");
}

#[test]
fn each_controller_starts_with_its_arm_s_window() {
    // noq's own, 10 packets, where the arm leaves it.
    assert_eq!(first_window(Tuning::IROH), 12_000);
    assert_eq!(first_window(Tuning::TUNED), INITIAL_PACKETS * PACKET);
    for (value, congestion) in [("window,bbr", Congestion::Bbr), ("newreno,window", Congestion::NewReno)] {
        let tuning = Tuning::from_value(Some(value)).unwrap();
        assert_eq!(tuning.congestion, congestion, "{value}");
        assert_eq!(first_window(tuning), 38_400, "{value}");
    }
    let bbr = Tuning::from_value(Some("bbr")).unwrap();
    assert_eq!(first_window(bbr), 12_000, "BBR alone keeps noq's first window");
}

#[test]
fn a_window_that_quic_cannot_say_keeps_iroh_s_own_and_says_so() {
    let past = Tuning { receive_windows: Some((u64::MAX, CONNECTION_WINDOW)), ..Tuning::TUNED };
    let (config, kept) = past.config();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(kept[0].contains("iroh's own are kept"), "{kept:?}");
    let text = format!("{config:?}");
    assert!(text.contains("stream_receive_window: 1250000"), "iroh's own stream window: {text}");
    // The arm's other settings still reach iroh's config.
    assert!(text.contains("initial_rtt: 100ms"), "{text}");
}

#[test]
fn a_word_that_is_no_setting_and_two_controllers_are_refused() {
    let why = Tuning::from_value(Some("tuned,fast")).unwrap_err();
    assert!(why.contains("\"fast\"") && why.contains(QUIC_ENV), "{why}");
    let why = Tuning::from_value(Some("bbr,newreno")).unwrap_err();
    assert!(why.contains("two congestion controllers"), "{why}");
    // The same controller twice is one.
    assert_eq!(Tuning::from_value(Some("bbr,bbr")).unwrap().congestion, Congestion::Bbr);
    // Each word of the table is taken.
    for (word, _) in WORDS {
        assert!(Tuning::from_value(Some(*word)).is_ok(), "{word}");
    }
}

/// The endpoint takes its arm, for the connections that it dials and those
/// that it takes (its server's settings say them); nothing is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_endpoint_takes_the_arm_s_settings() {
    let relay: iroh::RelayUrl = "https://relay.podssh.test".parse().unwrap();
    for (tuning, rtt) in [(Tuning::TUNED, "initial_rtt: 100ms"), (Tuning::IROH, "initial_rtt: 333ms")] {
        let options = crate::Options {
            relays: vec![relay.clone()],
            proxy: podssh_ws::ProxyChoice::Direct,
            udp: crate::Udp::Off,
            quic: Some(tuning),
            ..crate::Options::default()
        };
        let opened = crate::endpoint::open(&options).await.expect("an endpoint");
        assert_eq!(opened.quic, tuning);
        let said = format!("{:?}", opened.endpoint.create_server_config_builder(Vec::new()));
        assert!(said.contains(rtt), "{rtt}: {said}");
        assert_eq!(opened.quic_lines().is_empty(), tuning == Tuning::IROH, "{:?}", opened.quic_lines());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), opened.endpoint.close()).await;
    }
}

#[test]
fn an_arm_says_its_settings_and_its_words() {
    assert_eq!(
        Tuning::TUNED.to_string(),
        "an initial round trip of 100 ms, an initial window of 32 packets, receive windows of 8 MiB a stream \
         and 16 MiB a connection, Cubic (rtt,window,streams,cubic)"
    );
    assert_eq!(Tuning::from_value(Some("bbr")).unwrap().to_string(), "BBR (bbr)");
}
