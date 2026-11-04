//! The retired variables of ENVIRONMENT (T-634): the rule, then each name
//! that a release stopped reading, from the table that a run checks. The
//! tests of the manual read these apart from the variables that are read.

use super::super::model::Block;
use super::{item, lit};
use crate::retired::{Retired, RETIRED};

/// What a run does with a retired name, said once.
const RULE: &str = "A PODSSH_ variable that a release stopped reading is refused while it is set to a value \
    that is not empty: podssh names it, says what took its place, and exits 78 before it connects; --help, \
    --version and podssh man still answer. A service's file of variables (--env-file) that sets one is \
    refused with its line, and --install leaves one out. A name that podssh never read is not refused, so \
    a misspelt name is still ignored. Each name that a release stopped reading is listed below.";

/// The heading, the rule, and an item for each row of the release's table.
pub(super) fn blocks() -> Vec<Block> {
    blocks_of(RETIRED)
}

/// [`blocks`] of `table`, for a test with a row of its own.
pub(super) fn blocks_of(table: &[Retired]) -> Vec<Block> {
    let mut out = vec![Block::Sub("Retired variables".into()), Block::Para(RULE.into())];
    out.extend(table.iter().map(|row| item(vec![lit(row.name)], row.manual())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retired::tests::ROW;

    /// A row of the table is an item of its own, with what replaced it.
    #[test]
    fn the_manual_lists_each_retired_row() {
        let blocks = blocks_of(&[ROW]);
        assert!(matches!(&blocks[0], Block::Sub(heading) if heading == "Retired variables"));
        let items: Vec<(String, String)> = blocks
            .iter()
            .filter_map(|block| match block {
                Block::Item { term, text } => Some((format!("{term:?}"), text.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(items.len(), 1, "{items:?}");
        assert!(items[0].0.contains("PODSSH_RETIRED_FOR_TESTS"), "{items:?}");
        assert!(items[0].1.contains("since v0.0.0: use PODSSH_RELAY instead; remove it"), "{items:?}");
        // The release's table: the rule alone when no name is retired.
        assert_eq!(blocks().len(), 2 + RETIRED.len());
    }
}
