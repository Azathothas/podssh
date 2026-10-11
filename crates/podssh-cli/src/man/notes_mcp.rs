//! The notes of `podssh mcp` (T-055), apart from the others so that each
//! file stays short.

pub const MCP: &[&str] = &[
    "podssh mcp is a server of the Model Context Protocol on stdin and stdout, for an agent that runs it: \
     each line of stdin is one JSON-RPC message and each line of stdout one answer, and podssh's own words go \
     to stderr. It answers a client of the revision 2026-07-28, whose requests name their version in _meta, \
     and one that opens with initialize (2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05). It ends at the \
     end of stdin, and each call then in flight ends with it.",
    "The tools: ssh_exec runs one command on a host (destination [user@]host, command, and stdin, \
     timeout_seconds and host_key_fingerprint at will); its result has podssh's exit code, the command's \
     status or signal, how the session ended and why it failed, stdout and stderr (at most 1 MiB each, \
     truncated says so, and output that is not UTF-8 comes as base64), and timed_out. status, doctor and \
     man give what podssh status, podssh doctor and podssh man give, in their JSON form.",
    "THE RISK: an agent with ssh_exec runs commands on each allowed host, as you, with your keys and your \
     ssh_config. The words of a call come from a model, and text that the model read can ask it for a \
     command or a host; so ssh_exec reaches no host unless --allow-host names it, and is not offered with \
     none. Name each host, or the fewest patterns that hold them; !PATTERN excludes, and a pattern with \
     USER@ needs a destination that names that user. The host is matched as the call names it, before the \
     HostName of your configuration.",
    "Each call runs podssh ssh as a child, with BatchMode=yes (no prompt, ever), \
     StrictHostKeyChecking=yes (a host whose key known_hosts does not hold is refused, unless \
     host_key_fingerprint names its key, as --host-key-fingerprint), no pty, no escape character, no \
     forwarding of a port, an agent or X11, and no shared connection; these come before -F FILE, so a \
     file cannot undo them. A call past its limit (60 s, or timeout_seconds, at most 3600) ends its \
     session, as a cancelled call does; four calls run at once, and the others wait.",
];
