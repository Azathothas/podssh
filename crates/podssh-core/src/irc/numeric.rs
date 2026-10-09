//! Numeric replies: `001`, `005`, `433`, and the rest of RFC 2812 §6.
//!
//! **A numeric is a number, so it is named here as one.** Comparing reply
//! codes as strings is a defect that is invisible in review and fatal in
//! production: `"100"` == `"001"` as text, so a client that reads `005` as
//! "ISUPPORT present" also fires on `100` and on `0050` where it exists.
//!
//! **podssh parses numerics but composes almost none.** The registration
//! numerics, the `JOIN`-family and the error codes are the ones a client must
//! understand; the rest of RFC 2812 §6 is a long tail, and a client that
//! switches on an enum it can name behaves better than one that switches on a
//! number it recalled. **An unnamed code still arrives**, as a [`Replies`]
//! whose `code` names no [`Numeric`], because a server that invents `999` is a server whose
//! `999` podssh must be able to log.

use crate::irc::message::{Middle, Trailing};

/// The named numerics. **`RPL_WELCOME` is the one that matters**, because
/// registration is not complete until it arrives and `005` is a courtesy some
/// servers never send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Numeric {
    RplWelcome = 1,
    RplYourHost = 2,
    RplCreated = 3,
    RplMyInfo = 4,
    RplIsupport = 5,
    RplAway = 301,
    RplWhoisuser = 311,
    RplEndOfNames = 366,
    RplEndOfWho = 315,
    RplChannelModeIs = 324,
    RplTopic = 332,
    RplNamreply = 353,
    RplListStart = 321,
    RplList = 322,
    RplListEnd = 323,
    RplMotdStart = 375,
    RplMotd = 372,
    RplEndOfMotd = 376,
    ErrNoSuchNick = 401,
    ErrNoSuchChannel = 403,
    ErrCannotSendToChan = 404,
    ErrTooManyChannels = 405,
    ErrNoTextToSend = 412,
    ErrUnknownCommand = 421,
    ErrNeedMoreParams = 461,
    ErrPasswdMismatch = 464,
    ErrErroneousNickname = 432,
    ErrNicknameInUse = 433,
    ErrNickCollision = 436,
    ErrUnavailableChannel = 437,
    ErrNotOnChannel = 442,
    ErrNeedToBeOnChannel = 446,
    ErrChannelIsFull = 471,
    ErrUnknownModeChar = 472,
    ErrInviteOnlyChan = 473,
    ErrBannedFromChan = 474,
    ErrBadChannelKey = 475,
    ErrNoSuchService = 476,
}

impl Numeric {
    /// The three-digit string. `format!("{:03}")` rather than
    /// `to_string`, so `1` is `"001"` and not `"1"` — and the width is 3
    /// because RFC 2812 §6 says a numeric is three digits, so a code over 999
    /// has no legal spelling and is refused rather than silently widened.
    pub fn code(self) -> String {
        format!("{:03}", self as u16)
    }

    /// Name a code if it is one podssh knows.
    pub fn from_code(code: u16) -> Option<Self> {
        // `as u16` then a match: every variant's value is its own code, so
        // the mapping cannot drift from the enum the way a hand-written table
        // would, and there is exactly one place a new code is added.
        Some(match code {
            1 => Numeric::RplWelcome,
            2 => Numeric::RplYourHost,
            3 => Numeric::RplCreated,
            4 => Numeric::RplMyInfo,
            5 => Numeric::RplIsupport,
            301 => Numeric::RplAway,
            311 => Numeric::RplWhoisuser,
            315 => Numeric::RplEndOfWho,
            321 => Numeric::RplListStart,
            322 => Numeric::RplList,
            323 => Numeric::RplListEnd,
            324 => Numeric::RplChannelModeIs,
            332 => Numeric::RplTopic,
            353 => Numeric::RplNamreply,
            366 => Numeric::RplEndOfNames,
            372 => Numeric::RplMotd,
            375 => Numeric::RplMotdStart,
            376 => Numeric::RplEndOfMotd,
            401 => Numeric::ErrNoSuchNick,
            403 => Numeric::ErrNoSuchChannel,
            404 => Numeric::ErrCannotSendToChan,
            405 => Numeric::ErrTooManyChannels,
            412 => Numeric::ErrNoTextToSend,
            421 => Numeric::ErrUnknownCommand,
            432 => Numeric::ErrErroneousNickname,
            433 => Numeric::ErrNicknameInUse,
            436 => Numeric::ErrNickCollision,
            437 => Numeric::ErrUnavailableChannel,
            442 => Numeric::ErrNotOnChannel,
            446 => Numeric::ErrNeedToBeOnChannel,
            461 => Numeric::ErrNeedMoreParams,
            464 => Numeric::ErrPasswdMismatch,
            471 => Numeric::ErrChannelIsFull,
            472 => Numeric::ErrUnknownModeChar,
            473 => Numeric::ErrInviteOnlyChan,
            474 => Numeric::ErrBannedFromChan,
            475 => Numeric::ErrBadChannelKey,
            476 => Numeric::ErrNoSuchService,
            _ => return None,
        })
    }

    /// Does this numeric end the registration burst? RFC 2812 §3 says the
    /// server sends `001`-`004` and then, if it has `005`, that — and **no
    /// numeric after `376` (MOTD end) means registration never finished**,
    /// which is why podssh waits for `001` and not for a timer.
    pub fn is_registration_complete(self) -> bool {
        matches!(self, Numeric::RplWelcome)
    }
}

/// A numeric, split into the parts a caller acts on — **and nothing
/// is thrown away doing it.**
///
/// **This type is where a numeric's parameters live, and the encoder reads
/// them from here.** An earlier draft gave [`crate::irc::message::Command::Numeric`] no
/// parameters at all, on the grounds that a numeric's shape varies — and
/// **the fixture round-trip caught it on the first run**:
/// `:irc.example.org 001 alice :Welcome` re-encoded as
/// `:irc.example.org 1`. A parse that cannot be re-encoded is a parse that
/// threw the message away, and that is only invisible while every caller
/// happens to read the original parse.
///
/// **The target is the first parameter and is not the text.** `001 alice
/// :Welcome` has target `alice` and text `Welcome`; a client that takes the
/// last parameter as the text reads `alice` and shows the user their own
/// nick as the welcome message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replies {
    pub code: u16,
    /// `001 alice :Welcome` — **the nick the reply is addressed to**,
    /// which is not part of the code and is not the text.
    pub target: Option<Middle>,
    /// Every parameter that is not the target and not the text, in
    /// order. `005` has many, `353` has `=` or `@` then the channel, and
    /// `372` has none.
    pub params: Vec<Middle>,
    pub text: Option<Trailing>,
}

impl Replies {
    /// Build one from a parsed numeric's parameter list.
    ///
    /// **The middles and the trailing are passed separately, because the
    /// parser already knows which was which.** A reply's text is *always*
    /// the last thing on the line and often starts with `:`, and a function
    /// that re-derived the split from the parameter strings would be guessing:
    /// `322 alice #chan 4 :the:topic` and `322 alice #chan 4 the topic`
    /// are the same reply, and only one of them had a trailing on the wire.
    pub fn new(code: u16, params: &[Middle], text: Option<&Trailing>) -> Self {
        let mut iter = params.iter();
        Replies { code, target: iter.next().cloned(), params: iter.cloned().collect(), text: text.cloned() }
    }

    /// The named code, **derived from the code and never passed**, so a
    /// caller cannot attach `RplWelcome` to a reply numbered `433`.
    pub fn named(&self) -> Option<Numeric> {
        Numeric::from_code(self.code)
    }

    /// Every parameter in wire order — target first, then the rest,
    /// then the text. **The encoder reads this**, so `to_line` and
    /// the parse cannot disagree about what a numeric's parameters were.
    pub fn all_params(&self) -> Vec<Middle> {
        let mut out: Vec<Middle> = self.target.iter().cloned().collect();
        out.extend(self.params.iter().cloned());
        out
    }
}
