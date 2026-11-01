//! The request on a QUIC stream of a quick tunnel
//! (`podssh_relay::quick::connect::read_request`, T-403), as the edge sends
//! it: it reads with no panic within the control stream's budget, so that
//! its pairs are no more than that; each text lies within the frame; and the
//! texts of a request read, written again as an answer, read back the same.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_relay::quick::capnp::CONTROL_BUDGET;
use podssh_relay::quick::connect::{read_request, response};

fuzz_target!(|data: &[u8]| {
    let Ok(request) = read_request(data) else { return };
    assert!(request.metadata.len() as u64 <= CONTROL_BUDGET, "{} pairs", request.metadata.len());
    assert!(request.dest.len() < data.len(), "a dest of {} bytes from {}", request.dest.len(), data.len());
    for (key, value) in &request.metadata {
        assert!(key.len() < data.len() && value.len() < data.len(), "{key:?}: {value:?}");
    }
    let _ = request.header("sec-websocket-key");
    // An answer's `error` and `metadata` are where a request's `dest` and
    // `metadata` are; each word of it is read once, so an answer within the
    // budget's words reads back whole.
    let pairs: Vec<(&str, &str)> = request.metadata.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let again = response(&request.dest, &pairs);
    if again.len() as u64 <= 8 * CONTROL_BUDGET {
        let back = read_request(&again).expect("an answer of the same texts");
        assert_eq!((back.dest, back.metadata), (request.dest, request.metadata));
    }
});
