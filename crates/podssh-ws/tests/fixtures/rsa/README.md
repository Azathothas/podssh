RSA test vectors made by OpenSSL 3.5.7 on 2026-10-08 (the private keys were
not kept):

- `pub.der`: a 2048-bit public key, PKCS #1 `RSAPublicKey` DER
  (`openssl rsa -RSAPublicKey_out -outform DER`).
- `pkcs1.sig`: `msg` signed with PKCS #1 v1.5 and SHA-256
  (`openssl dgst -sha256 -sign`).
- `pss384.sig`: `msg` signed with PSS, SHA-384, salt length = digest length
  (`-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest`).
- `small.der`, `small.sig`: the same for a 1024-bit key, which podssh refuses.
