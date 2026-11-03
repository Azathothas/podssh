//! The manual's EXIT STATUS: each code from the constant that the command
//! returns, apart from the other sections so that each file stays short.

use super::super::model::{Block, Span};
use super::{item, lit};

/// The exit codes, from the constants that the commands return.
pub(super) fn status() -> Vec<Block> {
    super::super::data::exit_codes()
        .into_iter()
        .map(|(code, what)| {
            let term = match code {
                super::super::data::Code::Value(n) => vec![lit(n.to_string())],
                super::super::data::Code::Remote => vec![Span::Var("N".into())],
            };
            item(term, what)
        })
        .collect()
}
