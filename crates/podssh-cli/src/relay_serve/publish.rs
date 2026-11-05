//! `podssh relay serve --publish NAME=PAIR` (T-649, GitHub #147): a name
//! that the owner publishes to a pair's node, routed by the ClientHello
//! before the relay's own TLS (`podssh_relay::serve::published`), so that
//! the node's own TLS answers it (`podssh node --publish-tls`). With no flag
//! nothing changes. The relay's own `--acme` name is never published: the CA
//! validates it at the relay. The first line names each name and its pair,
//! and says that the relay reads the name and never the bytes.

use std::sync::Arc;

use podssh_relay::serve::published::Published;

use super::certs::Source;
use crate::relay_settings::Refusal;

/// Each `--publish NAME=PAIR`, in the order given.
pub(super) fn args(matches: &clap::ArgMatches) -> Vec<String> {
    let given = matches.try_get_many::<String>("publish").ok().flatten();
    given.map(|rows| rows.cloned().collect()).unwrap_or_default()
}

/// The table of `rows`, for a relay whose certificate comes from `source`:
/// a row out of shape, a name twice, or the name of `--acme`, is a refusal
/// (64).
pub(super) fn of(rows: &[String], source: &Source) -> Result<Arc<Published>, Refusal> {
    let table = Published::of(rows).map_err(|why| Refusal::usage(format!("--publish {why}")))?;
    if let Source::Acme { name, .. } = source {
        if table.holds(name) {
            return Err(Refusal::usage(format!(
                "--publish {name}: the name of --acme is the relay's own, which the CA validates at the relay; \
                 publish another name"
            )));
        }
    }
    Ok(Arc::new(table))
}

/// The words of the first line, after a comma: nothing with no name.
pub(super) fn shown(table: &Published) -> String {
    if table.is_empty() {
        return String::new();
    }
    let each: Vec<String> = table.rows().map(|(name, pair)| format!("{name} to the node of {pair}")).collect();
    format!(
        ", TLS by its name before the relay's own: {} (the node's TLS answers; the relay reads the name, never the \
         bytes)",
        each.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    // T-649: the rows, the name of --acme refused, and the first line's words.
    #[test]
    fn each_name_goes_to_its_pair_and_the_relay_s_own_acme_name_is_refused() {
        let files = Source::Files { cert: "c.pem".into(), key: "k.pem".into() };
        let table = of(&rows(&["Site.Example.Org=p-0123", "api.example.org=p-4567"]), &files).unwrap();
        assert_eq!(table.len(), 2);
        let words = shown(&table);
        assert_eq!(
            words,
            ", TLS by its name before the relay's own: api.example.org to the node of p-4567, site.example.org to \
             the node of p-0123 (the node's TLS answers; the relay reads the name, never the bytes)"
        );
        assert_eq!(shown(&of(&[], &files).unwrap()), "");
        let acme = Source::Acme { name: "relay.example.org".into(), directory: None, ca_file: None };
        assert!(of(&rows(&["site.example.org=p-1"]), &acme).is_ok());
        let Err(own) = of(&rows(&["RELAY.example.org=p-1"]), &acme) else { panic!("the name of --acme published") };
        assert_eq!(own.code, crate::exit_codes::EXIT_USAGE);
        assert!(own.message.contains("the name of --acme is the relay's own"), "{own:?}");
        for wrong in [&["site.example.org"][..], &["*.example.org=p-1"], &["a.example.org=p-1", "A.example.org=p-2"]] {
            let Err(refused) = of(&rows(wrong), &files) else { panic!("{wrong:?} published") };
            assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{wrong:?}");
            assert!(refused.message.starts_with("--publish "), "{refused:?}");
        }
    }
}
