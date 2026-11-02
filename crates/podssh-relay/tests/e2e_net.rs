//! The net's document in the end-to-end channel (T-429): of two ends that
//! hold a document of one owner, the one with the higher serial gives it to
//! the other, the operator's before the node's verdict and the node's after
//! it; nothing travels between two equal serials or two owners, to a peer
//! that is not a member, or to an operator that the node refused; and an
//! end with no documents, as a podssh of before, meets one that has them.
//! The documents here are the bytes `OWNER SERIAL MEMBER...`: the binary's
//! check of the owner's signature is `podssh net`'s, tested there.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::e2e::net::{Docs, Held};
use podssh_relay::e2e::{initiate_with, respond_with, Error, Refusal};
use podssh_relay::identity::{Identity, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(30);

/// A store in memory: the document held, as `(owner, serial, members)`,
/// and each document that a peer gave.
#[derive(Default)]
struct Memory {
    doc: Mutex<Option<(u8, u64, Vec<PublicKey>)>>,
    given: Mutex<Vec<(PublicKey, Vec<u8>)>>,
}

impl Memory {
    fn holding(owner: u8, serial: u64, members: &[&Identity]) -> Arc<Memory> {
        let members = members.iter().map(|id| id.public()).collect();
        Arc::new(Memory { doc: Mutex::new(Some((owner, serial, members))), given: Mutex::default() })
    }

    fn serial(&self) -> Option<u64> {
        self.doc.lock().unwrap().as_ref().map(|(_, serial, _)| *serial)
    }

    fn given(&self) -> usize {
        self.given.lock().unwrap().len()
    }
}

fn bytes_of(owner: u8, serial: u64, members: &[PublicKey]) -> Vec<u8> {
    let mut text = format!("{owner} {serial}");
    for key in members {
        text.push(' ');
        text.push_str(&key.hex());
    }
    text.into_bytes()
}

fn read(bytes: &[u8]) -> Option<(u8, u64, Vec<PublicKey>)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut words = text.split(' ');
    let owner = words.next()?.parse().ok()?;
    let serial = words.next()?.parse().ok()?;
    let members = words.map(PublicKey::parse).collect::<Option<Vec<_>>>()?;
    Some((owner, serial, members))
}

impl Docs for Memory {
    fn held(&self) -> Option<(Held, Vec<u8>)> {
        let doc = self.doc.lock().unwrap();
        let (owner, serial, members) = doc.as_ref()?;
        Some((Held { owner: [*owner; 32], serial: *serial }, bytes_of(*owner, *serial, members)))
    }

    fn shares_with(&self, peer: &PublicKey) -> bool {
        self.doc.lock().unwrap().as_ref().is_some_and(|(_, _, members)| members.contains(peer))
    }

    fn take(&self, from: &PublicKey, bytes: &[u8]) -> Result<(), String> {
        self.given.lock().unwrap().push((*from, bytes.to_vec()));
        let (owner, serial, members) = read(bytes).ok_or("not a document")?;
        let mut doc = self.doc.lock().unwrap();
        match doc.as_ref() {
            Some((held_owner, held, _)) if *held_owner == owner && *held < serial => {
                *doc = Some((owner, serial, members));
                Ok(())
            }
            _ => Err("not newer".into()),
        }
    }
}

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

/// One session between an operator with `op` and a node with `node`, whose
/// verdict is `admit`: each side's bytes, or the operator's error.
async fn meet(op: Option<Arc<Memory>>, node: Option<Arc<Memory>>, admit: bool) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (op_id, node_id) = (id(1), id(2));
    let (a, b) = tokio::io::duplex(1 << 16);
    let node_side = async move {
        let docs = node.map(|m| m as Arc<dyn Docs>);
        let asked = respond_with(b, &node_id, docs).await.expect("the node's handshake");
        if !admit {
            asked.refuse(Refusal::NotAllowed).await;
            return Vec::new();
        }
        let channel = asked.admit().await.expect("the verdict goes");
        let (mut app, theirs) = tokio::io::duplex(4096);
        let talk = async {
            app.write_all(b"from the node").await.unwrap();
            app.shutdown().await.unwrap();
            let mut got = Vec::new();
            app.read_to_end(&mut got).await.unwrap();
            got
        };
        let (carried, got) = tokio::join!(channel.carry(theirs), talk);
        carried.expect("the node's side carries");
        got
    };
    let op_side = async move {
        let docs = op.map(|m| m as Arc<dyn Docs>);
        let offered = initiate_with(a, &op_id, docs).await?;
        let channel = offered.accept(None).await?;
        let (mut app, theirs) = tokio::io::duplex(4096);
        let talk = async {
            app.write_all(b"from the operator").await.unwrap();
            app.shutdown().await.unwrap();
            let mut got = Vec::new();
            app.read_to_end(&mut got).await.unwrap();
            got
        };
        let (carried, got) = tokio::join!(channel.carry(theirs), talk);
        carried?;
        Ok::<Vec<u8>, Error>(got)
    };
    let (node_got, op_got) = tokio::time::timeout(LIMIT, async { tokio::join!(node_side, op_side) }).await.unwrap();
    Ok((op_got?, node_got))
}

fn members() -> [Identity; 2] {
    [id(1), id(2)]
}

#[tokio::test]
async fn the_node_s_newer_document_reaches_the_operator_after_the_verdict() {
    let [op, node] = members();
    let (theirs, ours) = (Memory::holding(9, 2, &[&op, &node]), Memory::holding(9, 3, &[&op, &node]));
    let (op_got, node_got) = meet(Some(theirs.clone()), Some(ours.clone()), true).await.unwrap();
    assert_eq!((op_got.as_slice(), node_got.as_slice()), (&b"from the node"[..], &b"from the operator"[..]));
    assert_eq!(theirs.serial(), Some(3), "the operator keeps the newer document");
    assert_eq!((theirs.given(), ours.given()), (1, 0));
    assert_eq!(theirs.given.lock().unwrap()[0].0, node.public(), "the document is the node's");
}

#[tokio::test]
async fn the_operator_s_newer_document_holds_before_the_node_s_verdict() {
    let [op, node] = members();
    let (theirs, ours) = (Memory::holding(9, 5, &[&op, &node]), Memory::holding(9, 4, &[&op, &node]));
    let (op_got, _) = meet(Some(theirs.clone()), Some(ours.clone()), true).await.unwrap();
    assert_eq!(op_got, b"from the node");
    assert_eq!(ours.serial(), Some(5), "the node keeps the newer document");
    assert_eq!((theirs.given(), ours.given()), (0, 1));
    // A refused operator's document came before the verdict: the node took
    // it, and gave nothing back.
    let (theirs, ours) = (Memory::holding(9, 7, &[&op, &node]), Memory::holding(9, 6, &[&op, &node]));
    assert!(matches!(meet(Some(theirs.clone()), Some(ours.clone()), false).await, Err(Error::Refused(_))));
    assert_eq!((ours.serial(), theirs.given()), (Some(7), 0));
}

#[tokio::test]
async fn nothing_travels_between_equal_serials_owners_apart_or_to_a_stranger() {
    let [op, node] = members();
    let stranger = id(3);
    for (theirs, ours) in [
        (Memory::holding(9, 4, &[&op, &node]), Memory::holding(9, 4, &[&op, &node])),
        (Memory::holding(8, 2, &[&op, &node]), Memory::holding(9, 6, &[&op, &node])),
        // The node's newer document does not name the operator, nor the
        // operator's the node: neither is given.
        (Memory::holding(9, 2, &[&op, &node]), Memory::holding(9, 6, &[&node, &stranger])),
        (Memory::holding(9, 8, &[&op, &stranger]), Memory::holding(9, 6, &[&op, &node])),
    ] {
        let before = (theirs.serial(), ours.serial());
        let (op_got, node_got) = meet(Some(theirs.clone()), Some(ours.clone()), true).await.unwrap();
        assert_eq!((op_got.as_slice(), node_got.as_slice()), (&b"from the node"[..], &b"from the operator"[..]));
        assert_eq!((theirs.serial(), ours.serial()), before);
        assert_eq!((theirs.given(), ours.given()), (0, 0));
    }
    // A refused operator gets no document of the node's.
    let (theirs, ours) = (Memory::holding(9, 1, &[&op, &node]), Memory::holding(9, 6, &[&op, &node]));
    assert!(matches!(meet(Some(theirs.clone()), Some(ours), false).await, Err(Error::Refused(Refusal::NotAllowed))));
    assert_eq!((theirs.serial(), theirs.given()), (Some(1), 0));
}

#[tokio::test]
async fn an_end_with_no_documents_meets_one_that_has_them() {
    let [op, node] = members();
    // A node of before, or one with no net: the operator's offer is set
    // aside, and the proofs keep their first form.
    let theirs = Memory::holding(9, 2, &[&op, &node]);
    let (op_got, node_got) = meet(Some(theirs.clone()), None, true).await.unwrap();
    assert_eq!((op_got.as_slice(), node_got.as_slice()), (&b"from the node"[..], &b"from the operator"[..]));
    assert_eq!(theirs.given(), 0);
    // An operator of before, or one with no net: no offer, so the node
    // answers in the first form.
    let ours = Memory::holding(9, 3, &[&op, &node]);
    let (op_got, _) = meet(None, Some(ours.clone()), true).await.unwrap();
    assert_eq!(op_got, b"from the node");
    assert_eq!(ours.given(), 0);
    // Two ends with stores that hold nothing are two ends of before.
    let (empty_op, empty_node) = (Arc::new(Memory::default()), Arc::new(Memory::default()));
    let (op_got, _) = meet(Some(empty_op), Some(empty_node), true).await.unwrap();
    assert_eq!(op_got, b"from the node");
}
