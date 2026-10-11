//! A proxy URL (`podssh_ws::Proxy::parse`), as a proxy variable holds it: a
//! proxy shows only its host and port, and its URL, which carries the
//! credentials again for a library, parses back to the same proxy.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_fuzz::text;
use podssh_ws::dial::authority;
use podssh_ws::Proxy;

fuzz_target!(|data: &[u8]| {
    let Some(url) = text(data) else { return };
    let Ok(proxy) = Proxy::parse(url) else { return };
    assert_eq!(proxy.to_string(), authority(&proxy.host, proxy.port));
    assert_eq!(Proxy::parse(&proxy.url()), Ok(proxy.clone()), "{}", proxy.url());
});
