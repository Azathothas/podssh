//! The messages of a QUIC stream against the bytes that the reference tool
//! `capnp encode` (Cap'n Proto 1.0.1) writes from the text beside each, with
//! cloudflared's schema at 2026.10.6 (`scripts/quick-fixtures.sh`).

use super::*;

const REQUEST: &[u8] = include_bytes!("../../tests/fixtures/quick/quic-connect-request.bin");
const RESPONSE: &[u8] = include_bytes!("../../tests/fixtures/quick/quic-connect-response.bin");
const REFUSAL: &[u8] = include_bytes!("../../tests/fixtures/quick/quic-connect-refusal.bin");

#[test]
fn the_edge_s_request_for_a_websocket_reads_as_the_reference_wrote_it() {
    let request = read_request(REQUEST).expect("a request");
    assert_eq!(request.dest, "https://podssh-test.trycloudflare.com/");
    assert_eq!(request.kind, Kind::WebSocket);
    assert_eq!(request.metadata.len(), 6);
    assert_eq!(request.metadata[1], ("HttpHost".to_string(), "podssh-test.trycloudflare.com".to_string()));
    assert_eq!(request.header("sec-websocket-key"), Some("dGhlIHNhbXBsZSBub25jZQ=="));
    assert_eq!(request.header("Upgrade"), Some("websocket"));
    assert_eq!(request.header("HttpHost"), None, "a key that is no header");
}

#[test]
fn the_node_s_answers_are_the_reference_s_bytes() {
    // RFC 6455's example key, whose accept value is s3pPLMBiTxaQ9kYGzzhZRbK+xOo=.
    assert_eq!(websocket_answer("dGhlIHNhbXBsZSBub25jZQ=="), RESPONSE);
    assert_eq!(refusal(), REFUSAL);
}

#[test]
fn a_stream_is_told_by_its_signature_and_the_answer_starts_with_the_preamble() {
    assert_eq!(stream(&DATA_STREAM), Stream::Data);
    assert_eq!(stream(&RPC_STREAM), Stream::Rpc);
    assert_eq!(stream(&[0; 6]), Stream::Unknown);
    assert_eq!(preamble(), [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E, b'0', b'1']);
}

#[test]
fn a_request_cut_short_or_of_another_shape_is_malformed_not_a_panic() {
    for cut in [0, 8, 16, REQUEST.len() - 1] {
        assert!(read_request(&REQUEST[..cut]).is_err(), "cut at {cut}");
    }
    // A response read as a request: no dest, and the metadata where a
    // request's sits; it reads, as capnp reads any struct, with no panic.
    let other = read_request(RESPONSE).expect("a struct");
    assert_eq!(other.kind, Kind::Http);
}

/// A request for a WebSocket whose metadata is a list of `count` pairs of no
/// size, in five words.
fn request_of_nothing(count: u64) -> Vec<u8> {
    crate::quick::capnp::tests::framed(&[&[
        // The root: a struct at the next word, of one data word and two
        // pointers.
        (1 << 32) | (2 << 48),
        // Its data: the type, a WebSocket.
        1,
        // `dest`, not set.
        0,
        // `metadata`: a list of structs at the next word, of no words.
        1 | (7 << 32),
        // The tag: `count` pairs, each of no data and no pointers.
        count << 2,
    ]])
}

/// The pairs of a request are bounded by the control stream's budget, where
/// capnp's let up to 2^23 - 4 pairs of no size be kept (T-403): 2^23 are
/// refused, and the most within the budget read, each as an empty pair.
#[test]
fn a_request_of_more_pairs_than_the_budget_is_refused() {
    assert_eq!(read_request(&request_of_nothing(1 << 23)), Err(Malformed("more words read than the limit")));
    // The root's three words are spent first.
    let most = CONTROL_BUDGET - 3;
    let request = read_request(&request_of_nothing(most)).expect("within the budget");
    assert_eq!((request.kind, request.metadata.len()), (Kind::WebSocket, most as usize));
    assert!(request.metadata.iter().all(|(key, value)| key.is_empty() && value.is_empty()));
    assert_eq!(request.header("upgrade"), None);
    assert_eq!(read_request(&request_of_nothing(most + 1)), Err(Malformed("more words read than the limit")));
}
