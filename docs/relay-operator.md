# A note to the relay's operator

From podssh, for the agent that works on the relay (`tcp-ssh-relay`,
`https://tcp.ssh.relay.ajam.dev`). podssh uses the relay's contract at
version `2026-10-03-r2` ([relay.md](relay.md) gives the parts that podssh
uses). The items below wait for the relay. Each names the entry of
[TODO/](../TODO/INDEX.md) that holds the detail, and the GitHub issue where
there is one. The most urgent come first.

## Defects on the relay's side

1. **Reverse sockets end with no Close** (T-255, [TODO/relay.md](../TODO/relay.md)).
   Measured on 2026-10-09 from two networks: sockets of the reverse road end
   at random with no WebSocket Close, one socket at a time or both of one
   pair at once. The entry gives the times in UTC. Find the cause in the
   relay's logs, and send a Close with a code when the relay ends a socket.
2. **No IPv6 egress** (T-253, [TODO/relay.md](../TODO/relay.md)). The relay
   reaches no IPv6 host. Add the egress, or state in `/health` that there is
   none.
3. **A slow client's bytes are held with no bound** (T-336,
   [TODO/relay.md](../TODO/relay.md)). Measured on 2026-10-31 from two
   networks, through the relay's own loop: a client that read 16 KiB/s got
   no Close in 90 s, while 47 MiB that it had not read had left the far end.
   Neither `1013 client receive backlog` (2 MiB) nor `1011 relay
   backpressure` (1 MiB) came; the forward check reads `bufferedAmount`.
   Bound the queue: stop reading the target, or the node's socket, while the
   limit waits for the client, or close with the code, and say which in the
   contract. Check also whether an isolate that ran out of memory is a cause
   of item 1's drops.

## Roads for networks that block the WebSocket

The testers asked for these. podssh's operator allowed each road (the rulings
Q44 and Q45 in [decisions.md](decisions.md)).

4. **An HTTP road** (T-319, [TODO/roads.md](../TODO/roads.md); [#55](https://github.com/Azathothas/podssh/issues/55)).
   For a proxy that refuses the upgrade: a session on two HTTP connections,
   with sequenced chunks and acknowledgements. The entry's Approach holds the
   wire protocol.
5. **A cleartext upgrade on port 443** (T-326, [TODO/ws.md](../TODO/ws.md); [#56](https://github.com/Azathothas/podssh/issues/56)).
   An endpoint that takes the WebSocket upgrade with no TLS, with a token for
   one session. Cloudflare's edge serves TLS on 443, so this needs another
   front.
6. **Extended CONNECT** (T-321, [TODO/roads.md](../TODO/roads.md); [#51](https://github.com/Azathothas/podssh/issues/51)).
   The relay's edge chose `h2` and did not offer RFC 8441's extended CONNECT
   (measured on 2026-10-30). Only a relay with its own front can offer it
   (item 10).
7. **Endpoints that `doctor` can measure** (T-325, [TODO/ws.md](../TODO/ws.md)).
   One that streams a response slowly, and one that takes a body, so that
   `podssh doctor` can measure the buffering of a path, its limit on bodies,
   and its idle limit.

## Pairing

8. **Signed grants, used once** (T-226, [TODO/reverse.md](../TODO/reverse.md); [#35](https://github.com/Azathothas/podssh/issues/35)).
   An endpoint that gives a signed grant for one pairing, in place of a
   bearer token that can be used again.
9. **Pairing by a short code** (T-086, [TODO/reverse.md](../TODO/reverse.md)).
   A mailbox endpoint, the code given out of band.

## Larger work of the relay project

10. **A relay that its users host** and that speaks the same contract (T-169,
    [TODO/roads.md](../TODO/roads.md)).
11. **Resumption in the relay for a standard sshd** (T-173,
    [TODO/roads.md](../TODO/roads.md)). Decide it with podssh's operator first
    ([design.md](design.md), section 8, question 1).
12. **A local HTTP service published at `https://NAME`** through the relay
    (T-180, [TODO/pipe.md](../TODO/pipe.md)).
13. **The live test of `podssh ts` with two nodes** (T-106,
    [TODO/ts.md](../TODO/ts.md)). It needs the node keys of two kept state files
    on the relay's allowlist, a Tailscale admin token, and the relay's
    deployment credential ([tailscale.md](tailscale.md)).

## When an item is ready

Change the live contract (`/llms-full.txt`), give it a new version, and tell
podssh's operator which item it is. A podssh session then reads the new
contract (`podssh relay spec`), lifts the entry's blocker, builds the client's
side, and tests it against the live relay.
