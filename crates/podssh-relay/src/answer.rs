//! A peer's answer, read by one rule (T-633). Each optional member of an
//! answer (a role's `hello`, an answer of `/v1/pair`) is of one of three
//! kinds, and its absence means one thing for each:
//!
//! - a hint, such as a `hello`'s `maxSessions`: absent, or zero, keeps a
//!   conservative floor of podssh's own, and never refuses ([`hint`]);
//! - an offer of a feature, such as `legTokens` or `rotation`: only `true`
//!   offers; absent, `false`, `"true"` and `1` are no offer, and podssh goes
//!   on without the feature ([`offers`]);
//! - a guarantee that this end asked for, such as `/v1/pair`'s `once`: only
//!   `true` confirms it ([`kept`]); else the caller undoes what the peer
//!   made, then says the refusal, and never retries, as the same peer would
//!   make the same.
//!
//! A peer of before leaves each new member out, so absence must be safe in
//! each kind: a floor, no feature, or a refusal after the undo.
//! `docs/reverse.md` ("A member that an answer leaves out") says the same.

use serde_json::Value;

/// Whether `value` says yes: JSON's `true`, and nothing else. A member that
/// a peer of before leaves out, a `false`, a string or a number is no: an
/// `is_some()` would read `false` as yes.
pub fn says_true(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

/// Whether a peer offers a feature by `value`, its member: [`says_true`].
pub fn offers(value: Option<&Value>) -> bool {
    says_true(value)
}

/// Whether a guarantee holds: one that this end did not ask for holds
/// whatever the peer said; one that it asked for, only when the peer
/// confirmed it with [`says_true`].
pub fn kept(asked: bool, confirmed: bool) -> bool {
    !asked || confirmed
}

/// A hint's value: the peer's, where it gave one that means something;
/// absent, or zero (never "none at all"), keeps `floor`.
pub fn hint<T: Copy + PartialEq + Default>(value: Option<T>, floor: T) -> T {
    value.filter(|given| *given != T::default()).unwrap_or(floor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Absent, `false`, a string, a number, null and an object are each no.
    fn noes() -> Vec<Option<Value>> {
        vec![None, Some(json!(false)), Some(json!("true")), Some(json!(1)), Some(Value::Null), Some(json!({}))]
    }

    #[test]
    fn only_true_offers() {
        assert!(offers(Some(&json!(true))));
        for value in noes() {
            assert!(!offers(value.as_ref()), "{value:?}");
        }
    }

    #[test]
    fn a_guarantee_asked_for_holds_by_true_alone() {
        assert!(kept(true, says_true(Some(&json!(true)))));
        for value in noes() {
            assert!(!kept(true, says_true(value.as_ref())), "{value:?}");
            // Not asked: whatever the peer said.
            assert!(kept(false, says_true(value.as_ref())), "{value:?}");
        }
    }

    #[test]
    fn an_absent_or_zero_hint_keeps_the_floor() {
        assert_eq!(hint(None, 16u32), 16);
        assert_eq!(hint(Some(0u32), 16), 16);
        assert_eq!(hint(Some(64u32), 16), 64);
        // A hint below the floor is the peer's: it knows its own limit.
        assert_eq!(hint(Some(4u32), 16), 4);
    }
}
