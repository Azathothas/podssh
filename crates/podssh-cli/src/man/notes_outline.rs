//! The note of `podssh ssh` on Outline's access keys in the file of
//! `--shadowsocks` (T-493), apart from `notes_ssh` for its length: it
//! follows the note of `--shadowsocks`.

/// An Outline access key, and Shadowsocks in a WebSocket.
pub const OUTLINE: &str =
    "A line of the file of --shadowsocks may also be an Outline access key: ssconf://HOST[:PORT]/PATH, which \
     podssh fetches as https://HOST[:PORT]/PATH, or key https://URL; a name after # is its server's. It is \
     fetched as a subscription is, over TLS through HTTPS_PROXY, and kept in the cache for a day (see FILES); \
     its body is one server: an ss:// link, JSON with server, server_port, password and method, or the YAML \
     of Outline's configuration, whose transport (tcpudp's tcp part, or a shadowsocks one) names cipher, \
     secret and an endpoint: HOST:PORT for raw TCP, a websocket with its wss:// URL, or first-supported with \
     its options, of which podssh takes the first that it reads. A server in a WebSocket is reached as \
     Outline's servers serve it (outline-ss-server 1.9 and later, behind a TLS front): TLS checked for the \
     URL's host with podssh's trust (--ca-file), through HTTPS_PROXY when one is set, then the same \
     Shadowsocks stream in binary messages, so a proxy that waits for TLS on port 443 carries it. A path \
     that the server does not serve (404), an upgrade that its front refuses and a key that is not the \
     server's are each named; the URL's path, often the server's secret, is never shown, nor the key's own \
     path. The UDP part is not read, as podssh carries TCP; a salt's prefix, a WebSocket with an endpoint of \
     its own and the other types of Outline's configuration are refused by their names when the key is \
     read, and a ws:// URL goes to this host alone. podssh reads the subset of YAML that the keys use: \
     mappings and lists by their indentation, quoted and plain values, comments and anchors.";
