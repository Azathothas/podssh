//! The examples of the manual. The tests parse each podssh command line here
//! with the parser of the binary, so an example cannot keep a flag that is
//! gone or use a command that does not work.

use super::model::{Block, Section};

/// `(what it does, the command line)`, in the order of the manual.
fn examples() -> Vec<(&'static str, String)> {
    let relay = podssh_relay::DEFAULT_RELAY_HOST;
    let other = podssh_relay::pool::SEED[0];
    vec![
        ("what works on this host, one line for each check", "podssh doctor".into()),
        (
            "the state of this host as one line of JSON, and whether a host's key is known",
            "podssh status github.com".into(),
        ),
        (
            "how good the path is: each step to each relay host, and the round trip of WebSocket pings",
            "podssh ping".into(),
        ),
        (
            "and through a host: the login, the echo through cat, and 8 MiB down and up",
            "podssh ping user@example.org".into(),
        ),
        (
            "a host's load, memory, uptime, network and disks, from one command that only reads",
            "podssh health user@example.org".into(),
        ),
        ("log in to a host, through the relay", "podssh ssh user@example.org".into()),
        ("run one command; podssh exits with its exit status", "podssh ssh user@example.org 'uname -a'".into()),
        (
            "keys for a menu after the login, then the session; with no match in 30 s, exit 255",
            r"podssh ssh -tt --expect 'Choice: ' --send '2\r' user@example.org".into(),
        ),
        (
            "the same command on three hosts, two at once: each line starts with its host; the exit is the worst",
            "podssh each --parallel 2 web1.example.org,web2.example.org,user@db.example.org -- uptime".into(),
        ),
        (
            "the containers of a host, of docker, podman and kubectl, each with the command that enters it",
            "podssh containers user@example.org".into(),
        ),
        (
            "enter one of them on the same connection, with bash",
            "podssh containers --exec web --shell bash user@example.org".into(),
        ),
        (
            "twelve hosts in one word, and the group db of the settings file; each host once",
            "podssh each 'web{01..12}.example.org,@db' -- 'df -h /'".into(),
        ),
        (
            "the command logs of the settings file, nginx as its {{1}}: shown, quoted, and asked first",
            "podssh ssh --snippet logs user@example.org nginx".into(),
        ),
        (
            "each line typed to the shells of three hosts; Ctrl-\\ (Ctrl-Break on Windows) stops it at once",
            "podssh each --interactive 'web{1..3}.example.org'".into(),
        ),
        (
            "a long build that goes on after the connection, in the host's tmux: its ID, then each job of the host",
            "podssh job start user@build.example.org -- make all && podssh job list user@build.example.org".into(),
        ),
        (
            "copy the project here to a stronger host, only what changed, then run its tests there",
            "podssh run user@build.example.org -- cargo test".into(),
        ),
        (
            "queue a build on the least busy of three hosts, wait 2 h at most for its status, then fetch its output",
            "podssh job submit 'build{1..3}.example.org' -- make all && podssh job wait --timeout 2h \
             build2.example.org 0123abcd && podssh job fetch build2.example.org 0123abcd"
                .into(),
        ),
        (
            "a Unix socket on the server, on stdin and stdout",
            "podssh ssh -W /run/postgresql/.s.PGSQL.5432 user@db.example.org".into(),
        ),
        (
            "Host blocks for the hosts of an Ansible inventory, added to the user's ssh_config",
            "podssh config import ansible inventory.ini >> ~/.ssh/config".into(),
        ),
        (
            "tools for an agent, run by its MCP client: commands on the web hosts but web9",
            "podssh mcp --allow-host 'web*.example.org' --allow-host '!web9.example.org'".into(),
        ),
        (
            "a shell that stays between the calls of an agent: type a line, wait for 2 s of quiet, read the screen",
            "podssh session start work user@example.org && podssh session send work 'make test' && \
             podssh session wait work --idle 2s && podssh session capture work"
                .into(),
        ),
        (
            "keep what a session showed, with its timing, and show it again twice as fast",
            "podssh ssh -tt --record top.cast user@example.org top && podssh play --speed 2 top.cast".into(),
        ),
        (
            "say what an update would do, its signature checked, then replace this binary with the newest release",
            "podssh update --check && podssh update".into(),
        ),
        (
            "a port, a key, and a new host key recorded with no question",
            "podssh ssh -p 2222 -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new user@example.org".into(),
        ),
        ("an interactive program, from a host with no terminal", "podssh ssh -tt user@example.org top".into()),
        (
            "a host whose key fingerprint the operator gave: that key only, and no known_hosts",
            "podssh ssh --host-key-fingerprint SHA256:JfDOvc6FaJOB34ANs+ou385/Kh+mMQhnUx0gHXVAfUI user@example.org"
                .into(),
        ),
        (
            "a shell in the server's tmux, attached again after a lost link",
            "podssh ssh --persist user@example.org".into(),
        ),
        ("through a jump host", "podssh ssh -J user@bastion.example.org user@inner.example.org".into()),
        (
            "a host from a script: -- before it, so it is never read as a flag",
            "podssh ssh -- user@example.org uptime".into(),
        ),
        ("an IPv6 address with a port, with no relay", "podssh ssh --direct 'user@[2001:db8::1]:2222'".into()),
        (
            "with no relay, on Linux: Multipath TCP, and -v says whether the server took it",
            "PODSSH_MPTCP=yes podssh ssh --direct -v user@example.org".into(),
        ),
        ("send a file with no scp", "podssh ssh user@example.org 'cat > notes.txt' < notes.txt".into()),
        (
            "a failure of podssh as one JSON object on the stdin of your program; a remote status starts none",
            "PODSSH_ERROR_PROGRAM=$HOME/bin/triage podssh ssh user@example.org uptime".into(),
        ),
        (
            "change a file of a host in an editor here; it goes back only if the host's file did not change",
            "EDITOR=nano podssh edit user@example.org:notes.txt".into(),
        ),
        (
            "through an HTTP CONNECT proxy",
            "HTTPS_PROXY=http://proxy.example.org:3128 podssh ssh user@example.org".into(),
        ),
        (
            "through a SOCKS5 proxy, which gets the relay's name",
            "ALL_PROXY=socks5h://proxy.example.org:1080 podssh ssh user@example.org".into(),
        ),
        (
            "on a host with no DNS: give the address of the relay",
            format!("podssh ssh --relay-addr {relay}=ADDRESS user@example.org"),
        ),
        ("try these relay hosts, in this order", format!("podssh ssh --relay-host {relay},{other} user@example.org")),
        (
            "use the OpenSSH client, with podssh as its way out",
            "ssh -o ProxyCommand='podssh proxy %h %p' -o ServerAliveInterval=60 user@example.org".into(),
        ),
        (
            "another TCP protocol: here, HTTP",
            r"printf 'HEAD / HTTP/1.0\r\nHost: example.org\r\n\r\n' | podssh proxy example.org 80".into(),
        ),
        (
            "a VNC desktop at 127.0.0.1:5901 for a viewer: OpenSSH listens, podssh carries its session",
            "ssh -N -L 5901:127.0.0.1:5901 -o ProxyCommand='podssh proxy %h %p' user@desktop.example.org".into(),
        ),
        (
            "a program at the other end of stdin and stdout, as socat joins them; its exit status is the pipe's",
            r#"podssh pipe stdio "exec:sh -c 'tr a-z A-Z'""#.into(),
        ),
        ("a descriptor that the calling program opened for podssh, on Unix", "podssh pipe fd:3 stdio".into()),
        (
            "a board's serial console on stdin and stdout, at 115200 baud, on Unix; Ctrl-C ends it",
            "podssh pipe serial:/dev/ttyUSB0,115200 stdio".into(),
        ),
        (
            "a TCP service behind an SSH server, on stdin and stdout, as -W reaches it",
            "podssh pipe stdio ssh:user@bastion.example.org,db.internal:5432".into(),
        ),
        (
            "the same service on a local port, for a client that connects: one client, then the port closes",
            "podssh pipe tcp-listen:5432 ssh:user@bastion.example.org,db.internal:5432".into(),
        ),
        (
            "offer a service of this host to an operator outside: a pair, with its operator's part in a file",
            "podssh relay pair lab --operator-file lab-operator.json".into(),
        ),
        (
            "then the node, a roost in front of this host's sshd at 127.0.0.1:22: each operator's session reaches it",
            "podssh node lab --sshd".into(),
        ),
        (
            "from outside, log in to the node's SSH server with the operator's file",
            "podssh ssh --pair-file lab-operator.json node://user@lab".into(),
        ),
        (
            "copy a file to the node's SSH server with the same file; the path comes after the first : after the name",
            "podssh scp --pair-file lab-operator.json notes.txt node://user@lab:notes.txt".into(),
        ),
        (
            "or with OpenSSH, with podssh as its way to the node",
            "ssh -o ProxyCommand='podssh operator lab --pair-file lab-operator.json' user@lab".into(),
        ),
        ("whether the node is online; then stop the pair", "podssh relay status lab && podssh relay revoke lab".into()),
        (
            "log in, then move the session to a node that the server's own podssh starts: it resumes after a lost link",
            "podssh ssh --upgrade user@example.org".into(),
        ),
        (
            "a node of a DNS server, on a host that allows UDP: each session is one flow of datagrams",
            "podssh node dns udp:10.0.0.2:53".into(),
        ),
        (
            "from outside, a program whose stdin and stdout are a datagram socket (Unix) sends each query",
            "podssh pipe 'exec:python3 query.py' udp:node:dns --pair-file dns-operator.json".into(),
        ),
        (
            "whether the relay reaches a target, and the first line that the target sends",
            "podssh relay trace github.com 22".into(),
        ),
        ("make a key where ssh-keygen does not work", "podssh keygen -t ed25519 -f ~/.ssh/id_ed25519".into()),
        ("a key with no passphrase, for a script", "podssh keygen -N '' -f ./deploy_key".into()),
        ("the public key of a private key", "podssh keygen -y -f ~/.ssh/id_ed25519".into()),
        ("the fingerprint of a key", "podssh keygen -l -f ~/.ssh/id_ed25519.pub".into()),
        ("this manual with no pager", "podssh man --no-pager".into()),
        ("one section of this manual", "podssh man environment".into()),
        ("this manual as a man page", "podssh man --roff > podssh.1 && man -l podssh.1".into()),
    ]
}

fn block((text, command): (&'static str, String)) -> Block {
    Block::Example { text: text.into(), command }
}

pub fn section() -> Section {
    Section {
        key: "examples",
        aliases: vec![],
        heading: "EXAMPLES".into(),
        command: false,
        blocks: examples().into_iter().map(block).collect(),
    }
}

/// The first steps, for the start of the manual: three of the examples.
pub fn start_here() -> Vec<Block> {
    let first = |c: &str| {
        c == "podssh doctor" || c == "podssh ssh user@example.org" || c.starts_with("ssh -o ProxyCommand='podssh proxy")
    };
    examples().into_iter().filter(|(_, c)| first(c)).map(block).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{parse, Parsed};

    /// Shell words, with single and double quotes; stops at an operator.
    fn shell_words(line: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quote: Option<char> = None;
        let mut started = false;
        for c in line.chars() {
            match quote {
                Some(q) if c == q => quote = None,
                Some(_) => word.push(c),
                None if c == '\'' || c == '"' => {
                    quote = Some(c);
                    started = true;
                }
                None if c.is_whitespace() => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                None => {
                    word.push(c);
                    started = true;
                }
            }
        }
        if started {
            words.push(word);
        }
        words
    }

    /// The parts of a command line between the operators |, <, >, ; and &&,
    /// outside quotes.
    fn segments(line: &str) -> Vec<String> {
        let mut out = vec![String::new()];
        let mut quote: Option<char> = None;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match quote {
                Some(q) if c == q => quote = None,
                Some(_) => {}
                None if c == '\'' || c == '"' => quote = Some(c),
                None if "|<>;".contains(c) || (c == '&' && chars.peek() == Some(&'&')) => {
                    if c == '&' {
                        chars.next();
                    }
                    out.push(String::new());
                    continue;
                }
                None => {}
            }
            out.last_mut().unwrap().push(c);
        }
        out
    }

    /// The podssh command lines in an example: each pipeline segment that
    /// runs podssh, and the ProxyCommand that OpenSSH would run.
    fn podssh_lines(command: &str) -> Vec<Vec<String>> {
        let mut out = Vec::new();
        for segment in segments(command) {
            let mut words = shell_words(&segment);
            while words.first().is_some_and(|w| w.contains('=') && !w.starts_with('-')) {
                let name = words.remove(0);
                let name = name.split('=').next().unwrap().to_string();
                let known = super::super::facts::variables().any(|(n, _)| n.contains(&name.as_str()));
                assert!(known, "{command}: {name} is not in ENVIRONMENT");
            }
            match words.first().map(String::as_str) {
                Some("podssh") => out.push(words[1..].to_vec()),
                Some("ssh") => {
                    for w in &words {
                        if let Some(inner) = w.strip_prefix("ProxyCommand=") {
                            let inner = shell_words(inner);
                            assert_eq!(inner.first().map(String::as_str), Some("podssh"), "{command}");
                            out.push(inner[1..].to_vec());
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    #[test]
    fn each_example_parses_with_the_real_parser() {
        for (text, command) in examples() {
            let lines = podssh_lines(&command);
            assert!(!lines.is_empty(), "{text}: {command} runs no podssh");
            for argv in lines {
                let parsed = parse(argv.clone());
                assert!(!parsed.needs_refusal(), "{command}: {argv:?} is refused: {parsed:?}");
                let verb = match &parsed {
                    Parsed::Command { verb, .. } => *verb,
                    Parsed::Proxy { .. } => "proxy",
                    Parsed::Doctor { .. } => "doctor",
                    Parsed::Status { .. } => "status",
                    Parsed::Ping(_) => "ping",
                    Parsed::Health(_) => "health",
                    Parsed::Play(_) => "play",
                    Parsed::Update(_) => "update",
                    Parsed::Edit(_) => "edit",
                    Parsed::Each(_) => "each",
                    Parsed::Containers(_) => "containers",
                    Parsed::Job(_) => "job",
                    Parsed::Run(_) => "run",
                    Parsed::Config(_) => "config",
                    Parsed::Mcp(_) => "mcp",
                    Parsed::Session(_) => "session",
                    Parsed::Man { .. } => "man",
                    Parsed::Node(_) => "node",
                    Parsed::Relay(_) => "relay",
                    Parsed::Operator(_) => "operator",
                    Parsed::Pipe(_) => "pipe",
                    other => panic!("{command}: {other:?}"),
                };
                let v = crate::flags::verb_for(verb).unwrap();
                assert_eq!(crate::flags::availability(v), crate::flags::Availability::Works, "{command}");
            }
        }
    }

    /// The control: an example with a flag that does not exist is caught.
    #[test]
    fn a_planted_example_is_refused() {
        let argv = podssh_lines("podssh ssh --no-such-flag user@example.org").remove(0);
        assert!(parse(argv).needs_refusal());
        let argv = podssh_lines("ssh -o ProxyCommand='podssh proxy --jsonl %h %p' host").remove(0);
        assert!(parse(argv).needs_refusal());
    }

    #[test]
    fn operators_in_quotes_do_not_split() {
        let s = segments("podssh ssh h 'cat > x' < x | y && z");
        assert_eq!(s, vec!["podssh ssh h 'cat > x' ", " x ", " y ", " z"]);
    }

    #[test]
    fn the_start_has_the_first_steps() {
        let commands: Vec<String> = start_here()
            .into_iter()
            .filter_map(|b| match b {
                Block::Example { command, .. } => Some(command),
                _ => None,
            })
            .collect();
        assert_eq!(commands.len(), 3, "{commands:?}");
        assert!(commands[0].starts_with("podssh doctor"));
    }
}
