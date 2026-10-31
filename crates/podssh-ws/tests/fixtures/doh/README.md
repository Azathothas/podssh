Answers of DNS over HTTPS in RFC 8484's wire form (`application/dns-message`),
as three operators sent them on 2026-10-31 (T-344). Each was asked by a GET
with `Accept: application/dns-message` and `?dns=` the base64url of a query
of ID 0, recursion desired and one question of class IN, through
fetch.web.pkgforge.dev, which passes the origin's status, headers and body
(its `x-web-egress` said `responseFramingModified=false`), at each operator's
endpoint by name, which serves the same answers as its addresses:

- `cloudflare-*.bin`: `https://cloudflare-dns.com/dns-query` (1.1.1.1, 1.0.0.1)
- `google-*.bin`: `https://dns.google/dns-query` (8.8.8.8, 8.8.4.4)
- `quad9-*.bin`: `https://dns.quad9.net/dns-query` (9.9.9.9, 149.112.112.112)

| File | Question | The answer |
| --- | --- | --- |
| `OPERATOR-a.bin` | `tcp.ssh.relay.ajam.dev` A | 104.21.39.2 and 172.67.141.178, TTL 300, each owner a pointer to the question's name |
| `OPERATOR-aaaa.bin` | `tcp.ssh.relay.ajam.dev` AAAA | 2606:4700:3037::6815:2702 and 2606:4700:3036::ac43:8db2 |
| `OPERATOR-srv.bin` | `_v2-origintunneld._tcp.argotunnel.com` SRV | `1 1 7844 region1.v2.argotunnel.com.` and `2 1 7844 region2.v2.argotunnel.com.`, each target written out |
| `OPERATOR-nxdomain.bin` | `podssh-no-such-name.invalid` A | RCODE 3, and the root's SOA in the authority section |
| `OPERATOR-cname.bin` | `www.github.com` A | a CNAME to `github.com`, then its A record (Cloudflare 140.82.114.3, Google and Quad9 140.82.112.3) |

The order of the records is each operator's, and `../../doh_wire.rs` holds
it. The same day Quad9 answered the JSON API's query
(`?name=tcp.ssh.relay.ajam.dev&type=A`, `Accept: application/dns-json`) with
`400 DoH unable to decode BASE64-URL`: it serves the wire form alone.
