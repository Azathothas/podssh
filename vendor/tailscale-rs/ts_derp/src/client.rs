use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};

use crypto_box::aead::{Aead, AeadCore, AeadMutInPlace, OsRng};
use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf},
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use ts_http_util::Client as _;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_transport::{BatchRecvIter, BatchSendIter, DynEndpoint, UnderlayTransport};
use url::Url;

use crate::{
    Error, ServerConnInfo, TlsValidationConfig, frame,
    frame::{ClientInfo, FrameType, PeerGone, Ping, RawFrame, ServerInfo, ServerKey},
    ws::WsIo,
};

/// How the DERP transport is reached. Carried per-connection; no globals.
///
/// ⛔ **The default is the old behavior.** `TcpUpgrade` dials TCP +
/// HTTP/1.1 `Upgrade: DERP`, exactly as upstream. `WebSocket` is the only
/// mode that crosses an HTTP/443-only egress, and it is always selected, never
/// assumed — a runtime that names no mode dials exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectMode {
    /// TCP + HTTP/1.1 `Upgrade: DERP` (upstream behavior).
    #[default]
    TcpUpgrade,
    /// DERP over WebSocket: `wss://{host}:{port}/derp` with
    /// `Sec-WebSocket-Protocol: derp`, then the DERP handshake inside WS
    /// binary messages.
    WebSocket,
}

/// The transport under a [`Client`]: either upgrade flavor, by delegation.
///
/// ⛔ **One enum, not a boxed trait object**: the two arms are named, matched
/// exhaustively, and a third transport cannot slip in without touching this
/// type — which is where the audit looks first.
pub enum DefaultIo {
    /// TCP + HTTP/1.1 `Upgrade: DERP`.
    Http(ts_http_util::Upgraded),
    /// DERP over WebSocket. Boxed: it is far larger than the other arm (podssh's patch 0020).
    Ws(Box<WsIo>),
}

impl AsyncRead for DefaultIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            DefaultIo::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            DefaultIo::Ws(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for DefaultIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            DefaultIo::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            DefaultIo::Ws(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            DefaultIo::Http(stream) => Pin::new(stream).poll_flush(cx),
            DefaultIo::Ws(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            DefaultIo::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            DefaultIo::Ws(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Type alias for the default derp client over upgraded HTTP on a tokio executor.
pub type DefaultClient = Client<DefaultIo>;

/// Single-region DERP client.
pub struct Client<Io> {
    read_conn: Mutex<FramedRead<ReadHalf<Io>, frame::Codec>>,
    write_conn: Mutex<FramedWrite<WriteHalf<Io>, frame::Codec>>,
    /// When the last frame of any kind came: the link's liveness (podssh's patch 0019).
    heard: std::sync::Mutex<tokio::time::Instant>,
    /// Pongs received: the server answers pings, so its silence means a dead link.
    pongs: std::sync::atomic::AtomicU64,
    /// Pings sent, which give each ping its payload.
    pings: std::sync::atomic::AtomicU64,
}

/// Establish and upgrade a http connection to the derp region, in the given mode.
///
/// `TcpUpgrade` keeps the upstream path: dial TLS, then HTTP/1.1
/// `Upgrade: DERP`. `WebSocket` dials `wss://{host}:{port}/derp` with the
/// `derp` subprotocol against the first dialable server ([`ws_target`]).
#[tracing::instrument(skip_all, err)]
pub async fn connect<'c>(
    region: impl IntoIterator<Item = &'c ServerConnInfo>,
    mode: ConnectMode,
) -> Result<Option<DefaultIo>, Error> {
    match mode {
        ConnectMode::TcpUpgrade => {
            // Upstream #439: this used to unwrap the dial result and panic on a dial
            // error. Dial errors are returned now.
            let Some((conn, _, addr)) = crate::dial::dial_region_tls(region).await? else {
                return Ok(None);
            };

            let url = Url::parse(&format!("https://{addr}/derp"))?;

            let client = ts_http_util::http1::connect(conn).await?;

            let resp = client
                .send(ts_http_util::make_upgrade_req(&url, "DERP", None)?)
                .await?;

            let upgraded = ts_http_util::do_upgrade(resp)
                .await
                .map_err(tokio::io::Error::other)
                .map_err(Error::from)?;

            Ok(Some(DefaultIo::Http(upgraded)))
        }
        ConnectMode::WebSocket => {
            let Some(server) = ws_target(region) else {
                return Ok(None);
            };
            let io = crate::ws::connect(&server.hostname, server.https_port).await?;
            Ok(Some(DefaultIo::Ws(Box::new(io))))
        }
    }
}

/// The first server the WebSocket mode may dial: hostname-addressed, not
/// stun-only, and no self-signed certificate (unsupported — the same rule as
/// the TCP path in `dial.rs`, which skips such servers before dialing).
///
/// ⛔ **Public because the proxy increment reuses it.** The CONNECT dialer
/// dials by hostname too, and two first-server selections drift — the second
/// one calls this instead of re-deriving it.
pub fn ws_target<'c>(
    servers: impl IntoIterator<Item = &'c ServerConnInfo>,
) -> Option<&'c ServerConnInfo> {
    servers.into_iter().find(|server| {
        !server.stun_only
            && !matches!(
                server.tls_validation_config,
                TlsValidationConfig::SelfSigned { .. }
            )
    })
}

impl<Io> Client<Io>
where
    Io: AsyncRead + AsyncWrite,
{
    /// Perform a derp handshake over the given transport and return a [`Client`].
    #[tracing::instrument(skip_all)]
    pub async fn handshake(conn: Io, node_keypair: &NodeKeyPair) -> Result<Self, Error> {
        let (read_conn, write_conn) = tokio::io::split(conn);

        let mut fw = FramedWrite::new(write_conn, frame::Codec);
        let mut fr = FramedRead::new(read_conn, frame::Codec);

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server key",
            )
        })??;
        let (sk, _rest) = frame
            .get()
            .as_type::<ServerKey>()
            .ok_or_else(|| std::io::Error::other("initial message was not serverkey"))?;

        sk.validate()?;

        tracing::trace!(
            server_public_key = %sk.key,
            "derp server public key"
        );

        let (client_info, encrypted) = make_clientinfo(node_keypair, &sk.key)?;
        tracing::trace!(?client_info);

        fw.send((
            RawFrame::from_body(&client_info, encrypted.len())?,
            encrypted.as_ref(),
        ))
        .await?;

        tracing::trace!("sent client info");

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server info",
            )
        })??;
        let (si, payload) = frame
            .get()
            .as_type::<ServerInfo>()
            .ok_or_else(|| std::io::Error::other("frame was not serverinfo"))?;

        tracing::trace!(server_info = ?si, "got server info");

        let info = decrypt_server_info(node_keypair, sk, si, payload)?;
        tracing::trace!(server_info = ?info);

        Ok(Self {
            read_conn: Mutex::new(fr),
            write_conn: Mutex::new(fw),
            heard: std::sync::Mutex::new(tokio::time::Instant::now()),
            pongs: Default::default(),
            pings: Default::default(),
        })
    }

    /// Send a message to a nodekey on the derp server.
    pub async fn send_one(&self, node_key: NodePublicKey, msg: &[u8]) -> Result<(), Error> {
        self.send_frame_with_extra(&frame::SendPacket { dest: node_key }, msg)
            .await
    }

    /// Send a frame to the derp server.
    pub async fn send_frame(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
    ) -> Result<(), Error> {
        self.send_frame_with_extra(frame, &[]).await
    }

    /// Send a frame to the derp server with the specified additional payload.
    pub async fn send_frame_with_extra(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
        additional_payload: &[u8],
    ) -> Result<(), Error> {
        let raw = RawFrame::from_body(frame, additional_payload.len())?;

        {
            let mut wr = self.write_conn.lock().await;
            wr.send((raw, additional_payload)).await?;
        }

        Ok(())
    }

    /// Send a ping, which the server answers with a pong (podssh's patch 0019).
    pub async fn send_ping(&self) -> Result<(), Error> {
        let n = self
            .pings
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.send_frame(&Ping {
            payload: n.to_be_bytes(),
        })
        .await
    }

    /// When the last frame of any kind came, as [`Client::recv_one`] read it.
    pub fn last_heard(&self) -> tokio::time::Instant {
        *self.heard.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many pongs have come.
    pub fn pongs(&self) -> u64 {
        self.pongs.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Waits for a single data packet from a peer to arrive via this DERP server and returns it.
    /// DERP control messages (KeepAlive, Ping, etc) are handled inline and are not returned.
    pub async fn recv_one(&self) -> Result<(NodePublicKey, PacketMut), Error> {
        // DERP exchanges control messages (KeepAlives, Pings, etc) in-band with data messages
        // (SendPacket, RecvPacket, etc). The caller only cares about the payloads of data
        // messages, so we recv_one_raw() in a loop to handle any control messages while waiting
        // for data messages.

        loop {
            let frame = {
                let mut r = self.read_conn.lock().await;
                r.next().await.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "derp stream ended")
                })??
            };
            let frame = frame.get();
            *self.heard.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();

            match frame.header.typ {
                // TODO (dylan): handle other control message types
                // TODO (dylan): handle other data message types (ForwardPacket, etc)
                #[allow(deprecated)]
                FrameType::KeepAlive => {
                    // TODO (dylan): do we need to do anything on KeepAlive other than reset a timer?
                    // TODO (dylan): handle KeepAlive timer
                    tracing::trace!("received KeepAlive frame");
                }
                FrameType::Ping => {
                    let Some((&ping, _)) = frame.as_type::<Ping>() else {
                        tracing::warn!("ping frame was not ping");
                        continue;
                    };

                    tracing::trace!(payload = ?ping.payload, "ping");

                    let pong: frame::Pong = ping.into();
                    self.send_frame(&pong).await?;

                    tracing::trace!(payload = ?pong.payload, "pong");
                }
                // The answer to `send_ping` (podssh's patch 0019): it counts, and
                // it was an error before, which ended the connection.
                FrameType::Pong => {
                    self.pongs
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::trace!("pong");
                }
                FrameType::PeerGone => {
                    let (gone, _rest) = frame.as_type::<PeerGone>().unwrap();

                    tracing::debug!(
                        peer = %gone.key,
                        reason = %gone.reason()?,
                        "peer gone from derp server"
                    );
                }
                FrameType::RecvPacket => {
                    let (recv, payload) = frame.as_type::<frame::RecvPacket>().unwrap();

                    return Ok((recv.src, payload.into()));
                }
                t => {
                    return Err(Error::UnexpectedRecvFrameType(t));
                }
            }
        }
    }
}

impl Client<DefaultIo> {
    /// Connect to and handshake with the derp server with the given URL over HTTP.
    ///
    /// The mode selects the transport; `TcpUpgrade` is upstream behavior and
    /// the default a caller that names no mode gets via [`ConnectMode`].
    pub async fn connect<'c>(
        region: impl IntoIterator<Item = &'c ServerConnInfo>,
        node_keypair: &NodeKeyPair,
        mode: ConnectMode,
    ) -> Result<Self, Error> {
        // Upstream #439: this used to unwrap the un-reachable-region case and
        // panic. An unreachable region is an error now.
        let Some(conn) = connect(region, mode).await? else {
            return Err(Error::NoServerReachable);
        };

        Client::handshake(conn, node_keypair).await
    }

    /// Connect over DERP-over-WebSocket and handshake: the mode-C path to a
    /// relay that only speaks the `derp` subprotocol.
    pub async fn connect_ws(
        hostname: &str,
        port: u16,
        node_keypair: &NodeKeyPair,
    ) -> Result<Self, Error> {
        let io = crate::ws::connect(hostname, port).await?;
        Client::handshake(DefaultIo::Ws(Box::new(io)), node_keypair).await
    }
}

impl<Io> fmt::Debug for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<Io> fmt::Display for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Client").finish()
    }
}

fn make_clientinfo(
    node_keypair: &NodeKeyPair,
    server_key: &ts_keys::DerpServerPublicKey,
) -> Result<(ClientInfo, Vec<u8>), Error> {
    let cbox = crypto_box::SalsaBox::new(
        &server_key.to_crypto_box(),
        &node_keypair.private.to_crypto_box(),
    );
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);

    let json = serde_json::to_vec(&frame::ClientInfoPayload {
        can_ack_pings: false,
        is_prober: false,
        mesh_key: "none".to_string(),
        version: 2,
    })?;
    let encrypted = cbox
        .encrypt(&nonce, &json[..])
        .map_err(|_| frame::Error::EncryptionFailed)?;

    Ok((
        ClientInfo {
            key: node_keypair.public,
            nonce: nonce.into(),
        },
        encrypted,
    ))
}

fn decrypt_server_info(
    node_keypair: &NodeKeyPair,
    sk: &ServerKey,
    server_info: &ServerInfo,
    payload: &[u8],
) -> Result<frame::ServerInfoPayload, Error> {
    let mut payload = PacketMut::from(payload);

    let mut cbox = crypto_box::SalsaBox::new(
        &sk.key.to_crypto_box(),
        &node_keypair.private.to_crypto_box(),
    );
    cbox.decrypt_in_place(&server_info.nonce.into(), &[], &mut payload)
        .map_err(|e| frame::Error::DecryptionFailed(format!("err: {e}")))?;

    let sip = serde_json::from_slice::<frame::ServerInfoPayload>(payload.as_ref())?;
    if sip.version() != frame::PROTOCOL_VERSION {
        return Err(Error::UnsupportedProtocolVersion(
            sip.version(),
            frame::PROTOCOL_VERSION,
        ));
    }

    Ok(sip)
}

impl<Io> UnderlayTransport for Client<Io>
where
    Io: AsyncRead + AsyncWrite + Send,
{
    type Error = Error;

    async fn send(&self, packet_batch: impl BatchSendIter) -> Result<(), Self::Error> {
        for (ep, pkt) in packet_batch.batch_iter() {
            let Some(key) = ep.as_derp() else {
                tracing::warn!(?ep, "derp transport got wrong endpoint info type");
                continue;
            };

            for pkt in pkt {
                self.send_one(key, pkt.as_ref()).await?;
            }
        }

        Ok(())
    }

    async fn recv(&self) -> impl BatchRecvIter<Error = Self::Error> {
        [self
            .recv_one()
            .await
            .map(|(k, pkt)| (DynEndpoint::derp(k), [pkt]))]
    }
}
