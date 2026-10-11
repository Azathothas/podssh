//! WebSocket frames (`podssh_ws::frame::decode`), as each side writes them: a
//! frame consumes at most its input; a control frame has FIN and at most 125
//! bytes (RFC 6455 section 5.5, T-063); a decoded frame, encoded again by the
//! same side, decodes to itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_ws::frame::{decode, encode, Role, MAX_CONTROL_PAYLOAD};

fuzz_target!(|data: &[u8]| {
    for role in [Role::Client, Role::Server] {
        let Ok(Some((frame, used))) = decode(data, role) else { continue };
        assert!((2..=data.len()).contains(&used), "{used} bytes of {}", data.len());
        if frame.opcode >= 0x8 {
            assert!(frame.fin && frame.payload.len() <= MAX_CONTROL_PAYLOAD, "{frame:?}");
        }
        let again = encode(&frame, role, [0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(decode(&again, role).ok().flatten(), Some((frame, again.len())));
    }
});
