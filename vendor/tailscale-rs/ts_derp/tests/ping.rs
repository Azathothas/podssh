//! podssh's patch 0019: the client pings its server, and the server's pong is counted, where it
//! was an unexpected frame that ended the connection. The server is a stand-in that speaks the
//! DERP handshake over an in-memory pipe.

use crypto_box::aead::{Aead, AeadCore, OsRng};
use futures::{SinkExt, StreamExt};
use tokio_util::codec::{FramedRead, FramedWrite};
use ts_derp::frame::{self, RawFrame};
use ts_keys::{DerpServerPublicKey, NodeKeyPair};

#[tokio::test]
async fn a_pong_is_counted_and_the_link_stays_up() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let (read, write) = tokio::io::split(server_io);
        let mut from_client = FramedRead::new(read, frame::Codec);
        let mut to_client = FramedWrite::new(write, frame::Codec);
        let secret = crypto_box::SecretKey::generate(&mut OsRng);

        let key = frame::ServerKey {
            magic: frame::Magic::MAGIC,
            key: DerpServerPublicKey::from_bytes(*secret.public_key().as_bytes()),
        };
        let none: &[u8] = &[];
        to_client
            .send((RawFrame::from_body(&key, 0).unwrap(), none))
            .await
            .unwrap();

        let info = from_client.next().await.unwrap().unwrap();
        let (info, _) = info.get().as_type::<frame::ClientInfo>().unwrap();
        let client_key = info.key;
        let cbox = crypto_box::SalsaBox::new(&client_key.to_crypto_box(), &secret);
        let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);
        let payload = cbox.encrypt(&nonce, br#"{"version":2}"#.as_ref()).unwrap();
        let server_info = frame::ServerInfo {
            nonce: ts_derp::Nonce(nonce.into()),
        };
        to_client
            .send((
                RawFrame::from_body(&server_info, payload.len()).unwrap(),
                &payload[..],
            ))
            .await
            .unwrap();

        // The client's ping, answered.
        let ping = from_client.next().await.unwrap().unwrap();
        let (&ping, _) = ping.get().as_type::<frame::Ping>().unwrap();
        let pong: frame::Pong = ping.into();
        to_client
            .send((RawFrame::from_body(&pong, 0).unwrap(), none))
            .await
            .unwrap();

        // A packet after the pong: the link outlived it.
        let packet = frame::RecvPacket { src: client_key };
        to_client
            .send((RawFrame::from_body(&packet, 5).unwrap(), &b"hello"[..]))
            .await
            .unwrap();
        // Held open until the test is done.
        from_client.next().await;
    });

    let client = ts_derp::Client::handshake(client_io, &NodeKeyPair::random())
        .await
        .expect("the handshake with the stand-in");
    let before = client.last_heard();
    assert_eq!(client.pongs(), 0);
    client.send_ping().await.unwrap();
    let (_, packet) = client.recv_one().await.expect("the link outlives the pong");
    assert_eq!(packet.as_ref(), b"hello");
    assert_eq!(client.pongs(), 1);
    assert!(client.last_heard() >= before);
    drop(client);
    server.await.unwrap();
}
