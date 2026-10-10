//! podssh's patch 0021: a WebSocket close keeps its code and its reason through `ts_derp::Error`,
//! as the relay's refusal of a node key, a close 1008 "not authorized", needs. The close comes
//! from a WebSocket server over an in-memory pipe.

use futures::StreamExt;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use ts_derp::ws::{WsClose, WsIo};

#[tokio::test]
async fn a_close_1008_keeps_its_code_and_reason() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_async(server_io).await.unwrap();
        ws.close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: "not authorized".into(),
        }))
        .await
        .unwrap();
        // Until the client's answer to the close.
        while let Some(Ok(_)) = ws.next().await {}
    });

    let (client_ws, _) = tokio_tungstenite::client_async("ws://relay.invalid/derp", client_io)
        .await
        .expect("the upgrade over the pipe");
    let mut io = WsIo::new(client_ws);
    let mut buf = [0u8; 16];
    let read = io.read(&mut buf).await.expect_err("the server closed");
    let e = ts_derp::Error::from(read);

    assert_eq!(
        e.ws_close(),
        Some(&WsClose {
            code: Some(1008),
            reason: "not authorized".to_string(),
        })
    );
    // The text that it always had.
    assert_eq!(
        e.to_string(),
        "websocket closed: code=1008 reason=\"not authorized\""
    );
    drop(io);
    server.await.unwrap();
}
