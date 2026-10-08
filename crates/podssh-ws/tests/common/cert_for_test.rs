// ⛔ **A minimal X.509 certificate, minted here, in pure Rust.**
//
// ⛔ **Why this exists, and why not `rcgen`.** MEASURED 2026-10-02 in
// `rust:1-alpine`, in this order:
//
// 1. `rcgen 0.14` with **default features** pulls in `ring 0.17`, which
//    needs `cc`: `cargo tree -i ring` prints `ring -> rcgen -> podssh-ws
//    [dev-dependencies]` and the build fails with *"failed to run custom
//    build command for `ring v0.17.14`"*.
// 2. `rcgen` with **`default-features = false, features = ["crypto","pem"]`**
//    resolves to zero `ring` and zero `aws-lc-sys` — and then fails to
//    compile: `compile_error!("At least one of the 'ring' or 'aws_lc_rs'
//    features must be activated when the 'crypto' feature is enabled")`.
//
// ⛔ So rcgen has no pure-Rust configuration at all, and this is the same
// wall `ring` and `aws-lc-sys` present. The primitives are already here —
// `p256` for the key and the signature, `sha2` for the digest — so the
// certificate is built from those and nothing is added.
//
// ⛔ **Two subjects, two files, and this file is only the seam.**
// `cert_encoding.rs` writes the DER and mints the certificate;
// `cert_server.rs` is the rustls server that presents it. ⛔ MEASURED
// 2026-10-02: the failures in this area were never "the bytes are wrong" and
// "the server is wrong" at the same time — one file holding both is what made
// each look like the other.

pub mod encoding {
    include!("cert_encoding.rs");
}

pub mod server {
    include!("cert_server.rs");
}

pub use encoding::self_signed;
#[allow(unused_imports)]
pub use server::server_for;