//! The end-to-end channel between two podssh ends (T-088): Noise XX against
//! the vector of the cacophony suite; a session whose relay sees no byte of
//! plain text, with the half-close of TCP; the operator's check of the
//! node's key before its own proof; the node's refusals, with no byte of its
//! target; a peer with no channel; and a node that replays another's proof.

mod e2e_harness;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use e2e_harness::{echo_back, holds, identity, node, run, Fault, LIMIT, PIPE};
use podssh_relay::e2e::{self, ends, Error, Refusal, MAGIC, PATTERN};
use podssh_relay::identity::PublicKey;
use snow::Builder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// `Noise_XX_25519_ChaChaPoly_SHA256` of the cacophony suite (public domain),
/// as snow 0.10.0 ships it: snow, set up with the channel's pattern, gives
/// each message and the handshake's hash of an implementation that podssh
/// did not write.
#[test]
fn the_pattern_gives_the_cacophony_vector() {
    let prologue = hex("4a6f686e2047616c74");
    let (i_static, i_eph) = (
        hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
        hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
    );
    let (r_static, r_eph) = (
        hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
        hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
    );
    let messages = [
        ("4c756477696720766f6e204d69736573", "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"),
        ("4d757272617920526f746862617264", "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad"),
        ("462e20412e20486179656b", "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030"),
        ("4361726c204d656e676572", "96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df"),
        ("4a65616e2d426170746973746520536179", "3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5"),
        ("457567656e2042f6686d20766f6e2042617765726b", "eb3f3515110702e047a6c9da4478b6ead94873c11c0f2d710ddb3f09fce024b3a58502ae3f"),
    ];
    fn build<'a>(key: &'a [u8], eph: &'a [u8], prologue: &'a [u8]) -> Builder<'a> {
        Builder::new(PATTERN.parse().unwrap())
            .local_private_key(key)
            .unwrap()
            .prologue(prologue)
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(eph)
    }
    let mut init = build(&i_static, &i_eph, &prologue).build_initiator().unwrap();
    let mut resp = build(&r_static, &r_eph, &prologue).build_responder().unwrap();
    let (mut out, mut read) = (vec![0u8; 65535], vec![0u8; 65535]);
    for (i, (payload, cipher)) in messages[..3].iter().enumerate() {
        let (writer, reader) = if i % 2 == 0 { (&mut init, &mut resp) } else { (&mut resp, &mut init) };
        let n = writer.write_message(&hex(payload), &mut out).unwrap();
        assert_eq!(out[..n], hex(cipher)[..], "handshake message {i}");
        let k = reader.read_message(&out[..n], &mut read).unwrap();
        assert_eq!(read[..k], hex(payload)[..]);
    }
    let hash = hex("c8e5f64e846193be2a834104c2a009868d6c9f3bd3c186299888b488b2f1f58e");
    assert_eq!(init.get_handshake_hash(), &hash[..]);
    assert_eq!(resp.get_handshake_hash(), &hash[..]);
    // The transport, with each direction's nonce counted from 0, as the
    // channel counts them: the responder first, then the initiator.
    let (init, resp) = (init.into_stateless_transport_mode().unwrap(), resp.into_stateless_transport_mode().unwrap());
    for (i, nonce, from_responder) in [(3, 0, true), (4, 0, false), (5, 1, true)] {
        let (payload, cipher) = messages[i];
        let writer = if from_responder { &resp } else { &init };
        let n = writer.write_message(nonce, &hex(payload), &mut out).unwrap();
        assert_eq!(out[..n], hex(cipher)[..], "transport message {i}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_carries_bytes_that_the_relay_never_sees_in_plain() {
    let (operator, node_key) = (identity(1), identity(2));
    let node_public = node_key.public();
    let mut r = run(
        operator.clone(),
        move |key| (key == &node_public).then_some(()).ok_or_else(|| "?".into()),
        node(node_key.clone(), |_| Ok(())),
        Fault::None,
        Fault::None,
    );
    let marker = b"podssh-plain-text-marker-0123456789".repeat(100);
    let big: Vec<u8> = (0..3 << 20).map(|i| (i * 7 % 251) as u8).collect();
    assert_eq!(echo_back(&mut r.app, &marker).await.unwrap(), marker);
    assert_eq!(echo_back(&mut r.app, &big).await.unwrap(), big, "3 MiB, in many messages");
    r.app.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(LIMIT, r.app.read_to_end(&mut rest)).await.unwrap().unwrap();
    assert!(rest.is_empty(), "the node's END ends the stream, with nothing more");
    let seen = tokio::time::timeout(LIMIT, r.session).await.unwrap().unwrap().unwrap();
    assert_eq!(seen, node_key.public(), "the operator knows the node it reached");
    tokio::time::timeout(LIMIT, r.node_task).await.unwrap().unwrap();
    assert_eq!(r.opened.load(Ordering::SeqCst), 1);
    let carried = r.carried.lock().unwrap().clone();
    assert!(carried.len() > big.len(), "the relay carried the session");
    assert!(holds(&carried, MAGIC), "each end's magic goes in plain");
    assert!(!holds(&carried, b"podssh-plain-text-marker"), "the relay saw plain text");
    assert!(!holds(&carried, &big[1000..1032]), "the relay saw plain text");
    let lines = r.lines.lock().unwrap().join("\n");
    assert!(lines.contains(&format!("the operator key {} came in", operator.public())), "{lines}");
}

/// The half-close of TCP: the operator ends its bytes, the target reads to
/// its end, and only then answers, which the operator still gets whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_side_that_ends_its_bytes_still_gets_the_others() {
    let (node_end, _lines) = node(identity(2), |_| Ok(()));
    let (app, app_end) = tokio::io::duplex(PIPE);
    let (cipher, session) = ends::operator(app_end, identity(1), |_| Ok(()));
    let target = || {
        let (ours, mut theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let mut all = Vec::new();
            theirs.read_to_end(&mut all).await.unwrap();
            let answer = format!("read {} bytes", all.len());
            theirs.write_all(answer.as_bytes()).await.unwrap();
            theirs.shutdown().await.unwrap();
        });
        std::future::ready(Ok::<_, String>(ours))
    };
    tokio::spawn(async move { ends::serve_node(cipher, &node_end, target).await });
    let session = tokio::spawn(session);
    let (mut r, mut w) = tokio::io::split(app);
    w.write_all(&[7u8; 100_000]).await.unwrap();
    w.shutdown().await.unwrap();
    let mut answer = String::new();
    tokio::time::timeout(LIMIT, r.read_to_string(&mut answer)).await.unwrap().unwrap();
    assert_eq!(answer, "read 100000 bytes");
    assert!(tokio::time::timeout(LIMIT, session).await.unwrap().unwrap().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_that_refuses_the_nodes_key_proves_nothing_and_reaches_nothing() {
    let operator = identity(1);
    let mut r = run(
        operator.clone(),
        |key| Err(format!("{key} is not the pinned key")),
        node(identity(9), |_| Ok(())),
        Fault::None,
        Fault::None,
    );
    let outcome = tokio::time::timeout(LIMIT, r.session).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Err(Error::NodeKey(why)) if why.contains(&identity(9).public().to_string())),
        "{outcome:?}"
    );
    let _ = r.app.shutdown().await;
    tokio::time::timeout(LIMIT, r.node_task).await.unwrap().unwrap();
    assert_eq!(r.opened.load(Ordering::SeqCst), 0, "the target was never opened");
    // The node's handshake ended before the operator's proof came.
    let lines = r.lines.lock().unwrap().join("\n");
    assert!(lines.contains("ended in the channel's handshake"), "{lines}");
    assert!(!lines.contains(&operator.public().to_string()), "the node learned the operator's key: {lines}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_lets_in_only_its_allowlist_and_its_target_sees_no_one_else() {
    let operator = identity(1);
    let allowed = identity(3).public();
    let r = run(
        operator.clone(),
        |_| Ok(()),
        node(identity(2), move |key| (key == &allowed).then_some(()).ok_or_else(|| "not in the test's list".into())),
        Fault::None,
        Fault::None,
    );
    let outcome = tokio::time::timeout(LIMIT, r.session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Err(Error::Refused(Refusal::NotAllowed))), "{outcome:?}");
    tokio::time::timeout(LIMIT, r.node_task).await.unwrap().unwrap();
    assert_eq!(r.opened.load(Ordering::SeqCst), 0, "a refused operator costs the target no connection");
    let lines = r.lines.lock().unwrap().join("\n");
    assert!(
        lines.contains(&format!("refused the operator key {}: not in the test's list", operator.public())),
        "{lines}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_that_cannot_be_reached_is_the_nodes_refusal_with_the_reason() {
    let (node_end, _lines) = node(identity(2), |_| Ok(()));
    let (_app, app_end) = tokio::io::duplex(PIPE);
    let (cipher, session) = ends::operator(app_end, identity(1), |_| Ok(()));
    let target = || std::future::ready(Err::<tokio::io::DuplexStream, _>("connection refused".to_string()));
    tokio::spawn(async move { ends::serve_node(cipher, &node_end, target).await });
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap();
    assert!(
        matches!(&outcome, Err(Error::Refused(Refusal::NoTarget(why))) if why == "connection refused"),
        "{outcome:?}"
    );
}

/// No fallback to plain text: each end refuses a peer with no channel, and
/// names what it sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_with_no_channel_is_refused_at_both_ends() {
    // An operator, to a node that is plain sshd.
    let (_app, app_end) = tokio::io::duplex(PIPE);
    let (mut cipher, session) = ends::operator(app_end, identity(1), |_| Ok(()));
    cipher.write_all(b"SSH-2.0-OpenSSH_10.3\r\n").await.unwrap();
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap();
    assert!(matches!(&outcome, Err(Error::NotChannel(saw)) if saw.contains("SSH-2.0")), "{outcome:?}");
    // A node, to an operator with no channel: its target is never opened.
    let (node_end, lines) = node(identity(2), |_| Ok(()));
    let (mut plain, link) = tokio::io::duplex(PIPE);
    plain.write_all(b"SSH-2.0-podssh_1.0\r\n").await.unwrap();
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    tokio::time::timeout(LIMIT, ends::serve_node(link, &node_end, e2e_harness::echo(opened.clone()))).await.unwrap();
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    assert!(lines.lock().unwrap().join("\n").contains("does not speak podssh's end-to-end channel"));
}

/// A node that replays another node's proof, its key and signature, with a
/// Noise key of its own: the signature does not sign that Noise key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_proof_of_another_key_is_refused() {
    let (victim, forger) = (identity(5), identity(6));
    let (_app, app_end) = tokio::io::duplex(PIPE);
    let victim_public = victim.public();
    let (cipher, session) = ends::operator(app_end, identity(1), move |key: &PublicKey| {
        (key == &victim_public).then_some(()).ok_or_else(|| "not the victim".into())
    });
    tokio::spawn(async move {
        let mut link = cipher;
        let mut state = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(forger.dh_secret())
            .unwrap()
            .prologue(e2e::PROLOGUE)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut magic = [0u8; MAGIC.len()];
        link.read_exact(&mut magic).await.unwrap();
        let mut len = [0u8; 2];
        link.read_exact(&mut len).await.unwrap();
        let mut first = vec![0u8; usize::from(u16::from_be_bytes(len))];
        link.read_exact(&mut first).await.unwrap();
        let mut scratch = vec![0u8; 65535];
        state.read_message(&first, &mut scratch).unwrap();
        let proof = [&[1u8][..], &victim.public().0, victim.binding()].concat();
        let n = state.write_message(&proof, &mut scratch).unwrap();
        link.write_all(MAGIC).await.unwrap();
        link.write_all(&(n as u16).to_be_bytes()).await.unwrap();
        link.write_all(&scratch[..n]).await.unwrap();
        let _ = link.read(&mut scratch).await;
    });
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap();
    assert!(matches!(&outcome, Err(Error::Handshake(why)) if why.contains("does not sign")), "{outcome:?}");
}
