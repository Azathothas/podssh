//! The forwarders that the binary names (T-370), live: through each, the
//! first line of github.com port 22 is GitHub's version line. By the
//! operator's ruling Q56 they are run from GitHub Actions only, short: one
//! connection to each, one at a time, by `.github/workflows/forwarder-live.yml`,
//! each day and by hand; ignored here. With `PODSSH_TEST_FORWARDER_PLANT`
//! set, each template names a host under `.invalid` in place of its own,
//! and each check must fail: the plant of the watch.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::forwarder::{self, builtin, Dial, Template};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::AsyncReadExt;

const LIMIT: Duration = Duration::from_secs(30);

/// The template of `b`, or its plant: the same path on a host that cannot be.
fn template(b: &builtin::Builtin) -> Template {
    let text = match std::env::var_os("PODSSH_TEST_FORWARDER_PLANT") {
        None => b.template.to_string(),
        Some(_) => {
            let rest = b.template.strip_prefix("wss://").expect("a wss:// template");
            let at = rest.find('/').unwrap_or(rest.len());
            format!("wss://podssh-plant.invalid{}", &rest[at..])
        }
    };
    Template::parse(&text).unwrap()
}

/// GitHub's version line through the forwarder of `word`.
async fn banner(word: &str) {
    let b = builtin::lookup(word).expect("a built-in word");
    let template = template(b);
    let said = word.to_string();
    let road = Dial {
        trust: &Trust::Default,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: LIMIT,
        close_at_end: true,
        note: Arc::new(move |text: &str| eprintln!("{said} says: {text}")),
    };
    let carried = match forwarder::open(&template, "github.com", 22, &road).await {
        Ok(carried) => carried,
        Err(e) => panic!("{word}: {}", e.line(template.shown())),
    };
    let mut stream = carried.stream;
    let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
    let read = tokio::time::timeout(LIMIT, async {
        while !line.ends_with(b"\r\n") && line.len() < 256 {
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                break;
            }
            line.push(byte[0]);
        }
    })
    .await;
    let text = String::from_utf8_lossy(&line).into_owned();
    assert!(read.is_ok(), "{word}: no line within {LIMIT:?}: {text:?} ({:?})", carried.status.get());
    println!("{word} ({}): {}", template.shown(), text.trim_end());
    assert!(text.starts_with("SSH-2.0-"), "{word}: not GitHub's version line: {text:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: from GitHub Actions only (Q56)"]
async fn live_mudlet_gives_github_s_version_line() {
    banner("mudlet").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: from GitHub Actions only (Q56)"]
async fn live_ssheasy_gives_github_s_version_line() {
    banner("ssheasy").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: from GitHub Actions only (Q56)"]
async fn live_mudix_gives_github_s_version_line() {
    banner("mudix").await;
}
