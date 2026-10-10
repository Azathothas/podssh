//! **File transfer: bytes over sessions, chunked at the relay's limits, and
//! resumable from the chunk boundary.**
//!
//! **One limit is read from the facts file and five are transcriptions**,
//! see [`podssh_core::irc::limits`]: `forward-max-frame-bytes` comes from
//! `crates/podssh-probe/facts/relay-facts.toml`, the file that podssh-probe and the
//! Python script read too, and the rest are records in code with the peer's
//! line beside them. **The tests below assert the numbers against the pinned
//! document; nothing here asserts a line number**, and the header of the module
//! says so rather than leaving a claim of provenance to be believed.

use podssh_core::irc::limits::{
    TransferLimits, FORWARD_MAX_FRAME_BYTES, IDLE_REAPER_MS, OPERATOR_FRAME_PAYLOAD_BYTES, SESSION_BYTES,
};
use podssh_core::irc::message::Message;
use podssh_core::irc::reap::{payload_plan_for, ReapPolicy, HEARTBEAT_PERIOD_MS};
use podssh_core::irc::transfer::{Chunk, Line, Offer, Receiver, Sender};

// ── the limits are the relay's, and they are read ───────────────────────────

#[test]
fn the_facts_file_is_read_and_the_transcribed_numbers_match_it() {
    // **The name is the claim, and the old name was false.** This asserts
    // the values the module carries — one read from the facts file, the rest
    // transcribed into constants — and it does not and cannot prove that a
    // transcription was re-measured. A test called "not typed here" that
    // asserted typed constants was worse than no name at all.
    //
    // A second `65536` written into a Rust constant is a number that can
    // drift silently from the peer's, and the symptom is a transfer that
    // closes `1009 frame byte cap` only on files over the cap which is the
    // shape of a bug that survives every smoke test.
    let limits = TransferLimits::from_embedded_facts()
        .expect("crates/podssh-probe/facts/relay-facts.toml must carry the relay's caps");

    // **The 64 MiB session cap**, both directions, from spec line 183.
    assert_eq!(SESSION_BYTES, 67_108_864, "spec line 183 says 64 MiB");
    assert!(
        limits.session_bytes < SESSION_BYTES,
        "a session budget at or over the relay's cap would close 1009 before \
         the transfer could report that it finished"
    );
    assert_eq!(limits.frame_bytes, OPERATOR_FRAME_PAYLOAD_BYTES);
    assert_eq!(OPERATOR_FRAME_PAYLOAD_BYTES, 65_536, "spec line 184");
    assert_eq!(FORWARD_MAX_FRAME_BYTES, 262_144, "/relays.json max_frame_bytes");
}

#[test]
fn a_renamed_fact_is_a_build_failure_and_not_a_default() {
    // **THE PLANT, for the limits.** If the facts file stops carrying
    // the number, podssh must fail to build rather than fall back to a
    // constant nobody measured. The rule: a capability is `MEASURED` or the
    // client does not depend on it.
    let relaid = TransferLimits::from_facts_text("origin = \"https://example\"\n");
    let err = relaid.expect_err("a facts file with no forward-max-frame-bytes must be refused");
    assert!(err.contains("forward-max-frame-bytes"), "the error must name the fact it could not read: {err}");

    // **And a fact whose value moved is refused too**, because this crate
    // was written against a number and a changed number is a changed protocol.
    let moved = TransferLimits::from_facts_text("forward-max-frame-bytes = 524288\n")
        .expect_err("a moved cap must be refused, not adopted");
    assert!(moved.contains("262144"), "the error must name both numbers: {moved}");
}

// ── chunking ────────────────────────────────────────────────────────────────

#[test]
fn a_chunk_line_fits_the_rfc_limit_and_that_is_proved_not_assumed() {
    // **THE CHUNK SIZE IS ARITHMETIC ON PAPER UNTIL THE WIRE IS ASKED.**
    // Base64 expands by 4/3, a chunk becomes one `PRIVMSG`, the server puts
    // the sender's prefix in front of it, and RFC 2812 §2.3 caps a message at
    // 512 including the terminator (T-097).
    let isupport = podssh_core::irc::isupport::Isupport::empty();
    let size = podssh_core::irc::transfer::chunk_bytes(&isupport, "#c", "transfer-id", 999_999).expect("room");
    let limits = TransferLimits { chunk_bytes: size, ..TransferLimits::default() };
    let length = podssh_core::irc::transfer::chunk_line_length(&limits, &isupport, "#c", "transfer-id", 99, 999_999);
    assert!(length <= 512, "a chunk line is {length} bytes; the RFC's limit is 512");
    // **And raising the chunk size must break it**, because a test that
    // passes at any size is not a test.
    let greedy = TransferLimits { chunk_bytes: 512, ..limits };
    assert!(
        podssh_core::irc::transfer::chunk_line_length(&greedy, &isupport, "#c", "t", 0, 0) > 512,
        "a 512-byte chunk cannot fit a 512-byte message; the limit is real"
    );
}

#[test]
fn a_file_over_the_session_cap_is_chunked_across_sessions_and_never_through_one() {
    // **THE ENTRY'S CLAUSE, as a number.** "a file larger than 64 MiB
    // is chunked across sessions, never streamed through one" MEASURED
    // here: `session_count` returns more than one, and it is the *only* thing
    // that decides how many sessions a transfer opens.
    let limits = TransferLimits::default();

    // **Exactly at the cap**: one session.
    assert_eq!(limits.session_count(limits.session_bytes as u64), 1);
    // **One byte over**: two. The boundary is the relay's, not a
    // rounded-down one, and a `>=` here would put the last byte over the cap.
    assert_eq!(limits.session_count(limits.session_bytes as u64 + 1), 2);

    // **A file over 64 MiB** needs at least two sessions, and the
    // number of sessions is what stops the relay closing it 1009.
    let big = 100 * 1024 * 1024u64;
    assert_eq!(limits.session_count(big), 2);
    assert!(big > SESSION_BYTES as u64, "the test file must exceed the relay's cap");

    // **And nothing is ever streamed through one session.**
    for total in [1u64, 1000, 1 << 20, limits.session_bytes as u64, big, 1 << 34] {
        let sessions = limits.session_count(total);
        let bytes_per_session = total.div_ceil(sessions);
        assert!(
            bytes_per_session <= limits.session_bytes as u64,
            "{total} bytes over {sessions} sessions needs {bytes_per_session} \
             per session, over the {}-byte budget",
            limits.session_bytes
        );
    }
}

#[test]
fn chunk_ranges_are_a_property_of_the_file_and_not_of_the_session() {
    // **THE RESUME RULE.** Chunk `i` is always bytes
    // `[i*320, i*320+320)` of the file not "the next chunk in this
    // session", so a resume that counted received chunks is a resume that
    // silently corrupts the file if one chunk was lost.
    let limits = TransferLimits::default();
    let total = 1000u64;
    for i in 0..limits.chunk_count(total) {
        let (offset, len) = limits.chunk_range(total, i).expect("inside the file");
        assert_eq!(offset, i * limits.chunk_bytes as u64, "chunk {i} has the wrong offset");
        assert!(len > 0 && len <= limits.chunk_bytes);
    }
    assert_eq!(limits.chunk_range(total, limits.chunk_count(total)), None, "a chunk past the end must not exist");
    assert_eq!(limits.chunk_count(0), 0, "a zero-byte file needs no chunks");
    assert_eq!(limits.session_count(0), 0);
}

#[test]
fn a_chunk_sent_twice_is_refused_rather_than_written_out_of_place() {
    // **THE DEFECT THIS EXPLAINS.** A receiver that buffered an
    // out-of-order chunk would take its idea of "what is next" from the peer
    // and a peer that reorders then produces a file with a chunk in the wrong
    // place and a digest that still passes because the sender hashes what
    // it sent.
    let limits = TransferLimits::default();
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let mut sender = Sender::new("t1", "file.bin", data.len() as u64, limits).expect("a safe id and name");

    let mut receiver = Receiver::from_offer(&the_offer(&sender)).expect("a well-formed offer is accepted");

    let mut delivered: Vec<u8> = Vec::new();
    let mut written: Vec<u8> = Vec::new();
    let mut index = 0u64;
    while let Some((offset, len)) = sender.next_range() {
        let message = sender
            .next_chunk_message("#c", &data[offset as usize..offset as usize + len])
            .expect("the right number of bytes");
        let line = offer_text(&message).expect("a chunk line");
        let Line::Chunk(chunk) = line else { panic!("expected a chunk, got {line:?}") };
        written.extend(receiver.accept(&chunk).expect("in order"));
        delivered.extend_from_slice(&data[offset as usize..offset as usize + len]);
        // **Now send chunk 0 again**, after everything. It must be
        // refused, not absorbed.
        if index == 2 {
            let duplicate = Chunk {
                transfer_id: "t1".into(),
                index: 0,
                offset: 0,
                payload: podssh_core::irc::transfer::b64::encode(&data[..limits.chunk_bytes]),
            };
            let err = receiver.accept(&duplicate).expect_err("a duplicate chunk must be refused, not written twice");
            assert!(err.contains("refusing"), "the refusal must say so: {err}");
            assert_eq!(
                receiver.bytes_received(),
                delivered.len() as u64,
                "the duplicate changed the receiver's byte count"
            );
        }
        index += 1;
        assert!(sender.acknowledge(index - 1), "the ack for {index} was refused");
    }

    assert!(sender.is_complete());
    assert!(receiver.is_complete(), "the receiver disagrees about completeness");
    receiver.finish().expect("complete");
    assert_eq!(written, data, "the bytes given to the caller are the file");
    assert!(receiver.verify(&sender_digest(&data)), "the digest must match");
}

/// **Pull the `Offer` out of the `PRIVMSG` the sender composed**, so the
/// receiver is built from what actually went on the wire and not from a
/// struct the test assembled itself.
fn the_offer(sender: &Sender) -> Offer {
    match offer_text(&sender.offer("#c")).expect("the offer is a transfer line") {
        Line::Offer(o) => o,
        other => panic!("expected an offer, got {other:?}"),
    }
}

fn offer_text(message: &Message) -> Option<Line> {
    let podssh_core::irc::message::Command::Privmsg { text, .. } = &message.command else {
        return None;
    };
    Line::parse(text.as_str())
}

fn sender_digest(data: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(data))
}

// ── the resume across a session boundary ────────────────────────────────────

#[test]
fn a_transfer_resumes_from_the_chunk_boundary_after_a_session_ends() {
    // **"resumable from the chunk boundary", as a test.** The file
    // crosses a session boundary; the sender's next chunk after the
    // boundary is the receiver's next expected offset and nothing is
    // re-sent and nothing is skipped.
    let limits = TransferLimits::default();
    let total = limits.session_bytes as u64 + 5_000;
    let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let mut sender = Sender::new("t2", "big.bin", total, limits).expect("a safe id and name");

    // **Session 1** carries whole chunks until the budget is used up.
    let mut received: Vec<u8> = Vec::new();
    let mut chunks_in_session_1 = 0u64;
    // **The first session is opened too**, and asserting it here is what
    // catches a counter that only moves on the *second* session and so
    // reports the second one as the first.
    assert_eq!(sender.session(), 0, "a session was open before the first was opened");
    assert_eq!(sender.open_session(), 1);
    loop {
        if sender.needs_new_session() {
            break;
        }
        let (offset, len) = sender.next_range().expect("not finished");
        let _ = sender.next_chunk_message("#c", &data[offset as usize..offset as usize + len]);
        received.extend_from_slice(&data[offset as usize..offset as usize + len]);
        chunks_in_session_1 += 1;
        assert!(sender.acknowledge(sender.next_chunk()));
    }
    assert!(chunks_in_session_1 > 0, "session 1 carried nothing");
    assert!(
        chunks_in_session_1 * limits.chunk_bytes as u64 <= limits.session_bytes as u64,
        "session 1 carried {} bytes, over the {}-byte budget",
        chunks_in_session_1 * limits.chunk_bytes as u64,
        limits.session_bytes
    );

    // **The session ends here.** A new one opens and the first thing
    // it sends is the chunk the receiver expects the file offset, not a
    // count of what a socket carried.
    let resume_chunk = sender.resume_chunk();
    let (resume_offset, _) = limits.chunk_range(total, resume_chunk).expect("inside the file");
    assert_eq!(resume_offset, received.len() as u64, "the resume offset is not the receiver's");

    let session = sender.open_session();
    assert_eq!(session, 2, "the second session was numbered {session}");

    while !sender.is_complete() {
        let (offset, len) = sender.next_range().expect("not finished");
        assert!(offset >= resume_offset, "the resumed session went backwards");
        received.extend_from_slice(&data[offset as usize..offset as usize + len]);
        assert!(sender.acknowledge(sender.next_chunk()));
    }
    assert_eq!(received, data, "the resumed file differs from the original");
}

#[test]
fn a_receiver_built_from_the_offer_computes_the_same_geometry_as_the_sender() {
    // **The two ends must agree**, and the offer carries the sender's
    // chunk count so a mismatch is caught before the first byte rather than
    // at chunk 90.
    let limits = TransferLimits::default();
    let total = 12_345u64;
    let sender = Sender::new("t3", "x.bin", total, limits).expect("a safe id and name");
    let offer = match offer_text(&sender.offer("#c")).expect("a transfer line") {
        Line::Offer(o) => o,
        other => panic!("expected an offer, got {other:?}"),
    };
    let receiver = Receiver::from_offer(&offer).expect("a matching offer is accepted");
    assert_eq!(receiver.total(), total);
    assert_eq!(receiver.chunks(), sender.chunks());
    assert_eq!(receiver.resume_from(), 0);

    // **And a sender with a different chunk size is refused** which is
    // what stops two builds disagreeing about where a chunk boundary is.
    let wrong = Offer { chunks: 3, ..offer.clone() };
    let err = Receiver::from_offer(&wrong).expect_err("a mismatched chunk count must be refused");
    assert!(err.contains("chunk"), "the refusal must name the chunk count: {err}");
}

// ── the digest, and a partial file ──────────────────────────────────────────

#[test]
fn a_partial_file_is_never_handed_back() {
    // **"Report partial work with its remaining clauses."** Handing back
    // a partial file is how a transfer that failed at chunk 90 of 100 becomes a
    // file on the user's disk that opens and is wrong.
    let limits = TransferLimits::default();
    let data = vec![7u8; 1000];
    let mut sender = Sender::new("t4", "f.bin", data.len() as u64, limits).expect("a safe id and name");
    let offer = match offer_text(&sender.offer("#c")).unwrap() {
        Line::Offer(o) => o,
        other => panic!("expected an offer, got {other:?}"),
    };
    let mut receiver = Receiver::from_offer(&offer).expect("accepted");

    // **Two chunks of four.**
    for _ in 0..2 {
        let (offset, len) = sender.next_range().unwrap();
        let message = sender.next_chunk_message("#c", &data[offset as usize..offset as usize + len]).unwrap();
        let Line::Chunk(chunk) = offer_text(&message).unwrap() else { panic!("chunk") };
        receiver.accept(&chunk).unwrap();
        sender.acknowledge(sender.next_chunk());
    }
    assert!(!receiver.is_complete(), "a partial transfer claimed completeness");
    let err = receiver.finish().expect_err("a partial file must not be handed back");
    assert!(err.contains("not finished"), "the error must say so: {err}");
}

#[test]
fn a_wrong_digest_is_detected() {
    // **Compared against what arrived, not against what the sender said it
    // sent** a digest that is only echoed back proves that two strings
    // agree.
    let limits = TransferLimits::default();
    let data: Vec<u8> = (0..700u32).map(|i| (i % 256) as u8).collect();
    let mut sender = Sender::new("t5", "f.bin", data.len() as u64, limits).expect("a safe id and name");
    let offer = match offer_text(&sender.offer("#c")).unwrap() {
        Line::Offer(o) => o,
        other => panic!("expected an offer, got {other:?}"),
    };
    let mut receiver = Receiver::from_offer(&offer).unwrap();
    while let Some((offset, len)) = sender.next_range() {
        let message = sender.next_chunk_message("#c", &data[offset as usize..offset as usize + len]).unwrap();
        let Line::Chunk(chunk) = offer_text(&message).unwrap() else { panic!("chunk") };
        receiver.accept(&chunk).unwrap();
        sender.acknowledge(sender.next_chunk());
    }
    assert!(receiver.verify(&sender_digest(&data)), "the correct digest was rejected");
    assert!(!receiver.verify(&sender_digest(&data[..10])), "a wrong digest was accepted");
    assert!(!receiver.verify("not-a-digest"), "junk was accepted as a digest");
}

// ── the transfer line's own round trip ──────────────────────────────────────

#[test]
fn every_transfer_line_round_trips_byte_exactly() {
    for line in [
        Line::Offer(Offer {
            transfer_id: "t1".into(),
            name: "file.bin".into(),
            total: 1000,
            chunks: 4,
            chunk_bytes: 320,
        }),
        Line::Accept(podssh_core::irc::transfer::Accept { transfer_id: "t1".into(), from_chunk: 12 }),
        Line::Chunk(Chunk { transfer_id: "t1".into(), index: 3, offset: 960, payload: "QUJD".into() }),
        Line::Ack(podssh_core::irc::transfer::Ack { transfer_id: "t1".into(), index: 3 }),
        Line::Digest(podssh_core::irc::transfer::Digest { transfer_id: "t1".into(), sha256: "ab".into() }),
        Line::Done(podssh_core::irc::transfer::Done { transfer_id: "t1".into() }),
        Line::Deny(podssh_core::irc::transfer::Deny { transfer_id: "t1".into(), reason: "too big".into() }),
    ] {
        let rendered = line.render();
        assert_eq!(Line::parse(&rendered).as_ref(), Some(&line), "{rendered:?} did not round trip");
    }
}

#[test]
fn a_message_that_is_not_a_transfer_line_costs_nothing() {
    // **The overwhelming majority of `PRIVMSG`s in a channel are not
    // transfers** and they must cost one prefix check.
    assert!(Line::parse("hello everyone").is_none());
    assert!(Line::parse("PODSSH").is_none());
    assert!(Line::parse("PODSSH2|offer|t|1|1|1").is_none(), "a wrong marker was accepted");
}

// ── the reaper ──────────────────────────────────────────────────────────────

#[test]
fn a_client_that_only_answers_pings_still_loses_to_the_reaper() {
    // **THE POINT OF THIS MODULE.** Spec line 233 and the clause
    // that matters: *"idle sessions (180000 ms of payload inactivity;
    // transport keepalives do not reset this)"*. A `PONG` is one IRC
    // message so a client that thinks "I answered the ping, I am alive" has
    // measured the wrong thing.
    assert_eq!(IDLE_REAPER_MS, 180_000, "spec line 233");

    // **A third of the window**, so one missed beat (120 s of silence)
    // is still inside 180 s and leaves 60 s of headroom.
    assert_eq!(HEARTBEAT_PERIOD_MS, 60_000);
    // **THE MARGIN IS EXACTLY ONE BEAT**, and **that is arithmetic,
    // not hope**: two missed beats is 180 s, which *is* the window, so
    // the session is reaped. **MEASURED 2026-10-02**: an earlier version
    // of this test asserted `3 * PERIOD < IDLE_REAPER_MS` and the assertion
    // is what the numbers contradicted 180 000 is not less than 180 000.
    // Constants only: checked when the test compiles.
    const {
        assert!(2 * HEARTBEAT_PERIOD_MS < IDLE_REAPER_MS, "ONE missed beat must be survivable");
        assert!(
            3 * HEARTBEAT_PERIOD_MS >= IDLE_REAPER_MS,
            "TWO missed beats must not be survivable; the margin is one beat, not two"
        );
    };
}

#[test]
fn the_plan_sends_a_heartbeat_when_the_client_is_quiet_and_not_when_it_is_not() {
    let period = HEARTBEAT_PERIOD_MS;

    // **Quiet for longer than the period**: send one and **this is a
    // `PRIVMSG`, not a `PONG`** because the reaper counts payload.
    let plan = payload_plan_for(1_000_000, period, 0, false, period);
    assert!(plan.send_heartbeat, "an idle client must heartbeat");
    assert!(!plan.received_since_last_beat, "nothing arrived, so nothing was received");

    // **Active**: do not send and this is the control, because a
    // client that heartbeats on a timer regardless is a client spamming a
    // channel every 60 seconds.
    let plan = payload_plan_for(1_000_000, period - 1, 0, false, period);
    assert!(!plan.send_heartbeat, "a client that just spoke must not heartbeat");
}

#[test]
fn the_plan_reports_a_reception_so_a_one_sided_link_is_visible() {
    // **The reaper is symmetric** and the two booleans exist because a
    // client that only tracked its own writes would keep a link alive that
    // the far end had stopped using.
    let period = HEARTBEAT_PERIOD_MS;
    let quiet_send = payload_plan_for(0, period, 0, false, period);
    assert!(quiet_send.send_heartbeat);

    let quiet_both = payload_plan_for(0, period, period, false, period);
    assert!(quiet_both.send_heartbeat);
    assert!(!quiet_both.received_since_last_beat, "nothing arrived, so no reception may be claimed");
    assert!(
        quiet_both.both_ends_quiet,
        "both ends quiet is the state closest to being reaped, and the caller \
         must be able to tell it apart"
    );
    assert!(!quiet_send.both_ends_quiet, "only one end quiet is a different state");

    let receiving = payload_plan_for(0, period, 5, true, period);
    assert!(receiving.send_heartbeat, "the client's own side is still quiet");
    assert!(receiving.received_since_last_beat, "something arrived; that must be visible");
    assert!(!receiving.both_ends_quiet, "a reception happened; this is not a dead link");
}

#[test]
fn a_policy_built_from_a_measured_reaper_window_divides_it_and_refuses_zero() {
    // **`/relays.json` publishes `idle_timeout_ms`** and the honest
    // thing is to use what the peer says rather than a hardcoded third.
    assert_eq!(ReapPolicy::from_reaper_ms(180_000).expect("a sane window").heartbeat_period_ms, 60_000);
    assert_eq!(
        ReapPolicy::from_reaper_ms(300_000).expect("a moved window").heartbeat_period_ms,
        100_000,
        "a relay that moved its window must change the cadence, not be ignored"
    );
    let err = ReapPolicy::from_reaper_ms(0).expect_err("zero must be refused, not divided");
    assert!(err.contains("idle_timeout_ms"), "the error must name the knob: {err}");
}
