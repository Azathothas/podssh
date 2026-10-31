//! The manual's item on trust: where the roots of the default trust come
//! from, in their order on each system (T-340), and what a certificate that
//! no root signs says.

use super::super::model::Block;
use super::{item, lit};

pub(super) fn block() -> Block {
    item(
        vec![lit("Trust")],
        format!(
            "TLS is always verified, and no option turns the check off. With --ca-file or SSL_CERT_FILE, \
             only that file is trusted. Else the trust store is the Mozilla roots in the binary \
             (webpki-roots {} of {}), {} next to the binary, the roots of the system's stores, and the first \
             system bundle. The stores are, on Windows, ROOT of the current user and of the machine, less a \
             certificate that a Disallowed store holds, that is not valid today, or whose usage leaves out \
             servers; on macOS, the trust settings of the user and of the administrator, where security \
             add-trusted-cert and an MDM profile put a root; elsewhere the roots are the bundle's. podssh \
             doctor names each store with its count. A certificate that no root here signs ends with \
             UnknownIssuer and what to do: a proxy that re-signs TLS needs its CA, in --ca-file or \
             SSL_CERT_FILE, which replace podssh's roots, or in {} next to the binary, which adds to them. A \
             system bundle adds roots and removes none: to stop trusting a root that Mozilla removed after \
             this binary was built, give --ca-file or SSL_CERT_FILE with a current bundle, or use a newer \
             podssh. podssh doctor says when the roots in the binary are older than 12 months. podssh offers \
             TLS 1.3 first, and TLS 1.2 with ECDHE and AES-GCM or ChaCha20-Poly1305, for a proxy that \
             intercepts TLS and speaks only 1.2; a server that speaks 1.3 gets 1.3, and a fall to 1.2 cannot \
             be forced. There is no CBC suite and no RSA key exchange.",
            podssh_ws::tls::ROOTS_VERSION,
            podssh_ws::tls::ROOTS_PUBLISHED,
            podssh_ws::bundle::BUNDLE_FILE_NAME,
            podssh_ws::bundle::BUNDLE_FILE_NAME
        ),
    )
}
