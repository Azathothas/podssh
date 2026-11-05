//! The notes of a name published on the relay role's port (T-649), for
//! `relay` and `node`, apart from the others for the length of their files.

/// The relay's side: `relay serve --publish`.
pub(super) const RELAY: &str = "--publish publishes a TLS site of a node by its name (T-649), for an owner with \
     one port: each takes a DNS name and the name of a pair of this relay joined by =, such as \
     site.example.org=p-0123..., the name that the pair's file holds, and is repeatable. Before its own TLS, the \
     relay peeks at a connection's ClientHello, within 10 s and its one record of 16 KiB at most, and takes none of \
     its bytes: one whose server name is a published name, in any case and with or without a trailing dot, goes \
     to that pair's node as a session of the pair, each byte as it came, so that the node's TLS (podssh node \
     --publish-tls TARGET) answers it with its own certificate, and the relay holds no key of the name. Each other \
     connection goes on as before: a client by address, which sends no name; another name; a record cut short or \
     longer than 16 KiB, which goes to the relay's TLS after the 10 s; and what is no TLS. A CA's validation of a \
     published name, which offers acme-tls/1 alone, goes to the node too, so that the node can take a certificate \
     of its own for it; the name of --acme is the relay's own and is never published (64). The relay reads the \
     name and never the bytes, and a line on stdout names the name and the visitor's address at the start and at \
     the end of each. The session is one of the reverse road's, with its bounds: 64 MiB, the bound of 1 MiB for a \
     visitor that reads more slowly than its node sends, and the pair's life, which the node renews at this relay \
     by its stop token. A name whose pair is not here, has ended, or has no node joined, closes, with a line that \
     says why. Pairs are made after the relay starts: keep them with --pairs so that a name of --publish outlives \
     a restart. The first line names each published name and its pair.";

/// The node's side: `node --publish-tls TARGET`.
pub(super) const NODE: &str = "With --publish-tls TARGET, the pair's sessions are a site that podssh relay serve \
     publishes by its name (T-649; see its notes): the relay sends each TLS connection whose ClientHello names it \
     here, before any handshake and with each byte untouched. Each session is one connection to TARGET, a TLS \
     service of this host whose own certificate answers, carried as it came, with no resumable layer and no \
     end-to-end channel, as a visitor speaks neither; a connection that ends is a visitor that left, and no \
     session resumes. The first line names the pair's name for the relay's table, and says that the relay reads \
     the name of each connection and never its bytes. With --acme NAME, the published name, the node ends TLS \
     itself and TARGET gets the cleartext: its certificate comes from an ACME CA (Let's Encrypt, or the directory \
     of --acme-directory, reached with the trust of --ca-file), proven by TLS-ALPN-01, whose validation the relay \
     sends here too, so the node needs no port of its own. The order starts once the node is online, the \
     certificate is kept in the cache and renewed while the node runs, and a first order that fails stops the \
     node (69). TARGET is the flag's own: a TARGET beside it, and each flag of another road, of the channel or of \
     the layer, are refused (64). A visitor that reads more slowly than TARGET sends meets the relay's bound of 1 \
     MiB, as an operator of a node with --plain does.";
