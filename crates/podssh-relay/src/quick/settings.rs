//! HTTP/2 as the node serves its connection to the edge (T-300): the
//! streams and the windows that it grants the edge, and h2's budget of small
//! DATA frames (T-408).

/// The most streams at once: a quick tunnel takes 200 requests in flight.
pub const MAX_STREAMS: u32 = 256;
/// Each stream's window, and the connection's: as many as the streams, so
/// that streams whose users read slowly never hold the window of the
/// others, or of the control stream.
pub const STREAM_WINDOW: u32 = 64 * 1024;
pub const CONNECTION_WINDOW: u32 = MAX_STREAMS * STREAM_WINDOW;
/// The smallest DATA frame that the edge sends for a visitor, as it passes
/// on what the visitor's client writes: a WebSocket frame of no payload, a
/// header of 2 bytes and a mask of 4 (RFC 6455, section 5.2).
pub const SMALLEST_FRAME: usize = 6;
/// h2's budget of small DATA frames that wait unread (T-408). h2 counts, for
/// each frame under 256 bytes, 256 bytes less its size until the reader
/// takes it, and past the budget ends the connection with ENHANCE_YOUR_CALM
/// ("too_many_data_frames"), and each visitor's stream with it. Its own
/// budget, half the connection's window, is 8 MiB here: some 42,800 unread
/// frames of 60 bytes, what 40 to 60 visitors whose users read nothing hold.
/// This one holds the whole window in the smallest frames, so that the
/// windows, which each visitor's reader releases, stop the edge first. Its
/// price, at worst: 2.8 million frames that wait, some 700 MB of h2's
/// bookkeeping by h2's own measure of 256 bytes a frame.
pub const FRAME_BUDGET: usize = CONNECTION_WINDOW as usize / SMALLEST_FRAME * (256 - SMALLEST_FRAME);
// It holds the window in frames of 60 bytes, as h2's own does not.
const _: () = assert!(FRAME_BUDGET >= CONNECTION_WINDOW as usize / 60 * (256 - 60));
const _: () = assert!(CONNECTION_WINDOW as usize / 2 < CONNECTION_WINDOW as usize / 60 * (256 - 60));

/// HTTP/2's server as the node speaks it to the edge: the streams, the
/// windows and the budget of small frames above.
pub fn server_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_STREAMS)
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .data_frame_budget(FRAME_BUDGET);
    builder
}
