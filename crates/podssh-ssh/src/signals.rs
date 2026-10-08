//! Signal names as SSH carries them (RFC 4254 §6.10, without "SIG"), and the
//! numbers podssh exits with: 128 + the signal number, as a shell reports a
//! process killed by a signal. Numbers are Linux's, the target platform's.

use russh::Sig;

/// The name of a signal, as SSH spells it.
pub fn name(sig: &Sig) -> String {
    match sig {
        Sig::ABRT => "ABRT".into(),
        Sig::ALRM => "ALRM".into(),
        Sig::FPE => "FPE".into(),
        Sig::HUP => "HUP".into(),
        Sig::ILL => "ILL".into(),
        Sig::INT => "INT".into(),
        Sig::KILL => "KILL".into(),
        Sig::PIPE => "PIPE".into(),
        Sig::QUIT => "QUIT".into(),
        Sig::SEGV => "SEGV".into(),
        Sig::TERM => "TERM".into(),
        Sig::USR1 => "USR1".into(),
        Sig::Custom(other) => podssh_ws::text::one_line(other),
    }
}

/// The signal's number, if podssh knows it.
pub fn number(sig: &Sig) -> Option<i32> {
    Some(match sig {
        Sig::HUP => 1,
        Sig::INT => 2,
        Sig::QUIT => 3,
        Sig::ILL => 4,
        Sig::ABRT => 6,
        Sig::FPE => 8,
        Sig::KILL => 9,
        Sig::USR1 => 10,
        Sig::SEGV => 11,
        Sig::PIPE => 13,
        Sig::ALRM => 14,
        Sig::TERM => 15,
        Sig::Custom(other) => match other.trim_start_matches("SIG") {
            "TRAP" => 5,
            "BUS" => 7,
            "USR2" => 12,
            "STKFLT" => 16,
            "CHLD" => 17,
            "CONT" => 18,
            "STOP" => 19,
            "TSTP" => 20,
            "TTIN" => 21,
            "TTOU" => 22,
            "URG" => 23,
            "XCPU" => 24,
            "XFSZ" => 25,
            "VTALRM" => 26,
            "PROF" => 27,
            "WINCH" => 28,
            "IO" => 29,
            "PWR" => 30,
            "SYS" => 31,
            _ => return None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_is_15_so_the_exit_code_is_143() {
        assert_eq!(number(&Sig::TERM).map(|n| 128 + n), Some(143));
        assert_eq!(number(&Sig::Custom("USR2".into())), Some(12));
        assert_eq!(number(&Sig::Custom("NOPE".into())), None);
        assert_eq!(name(&Sig::KILL), "KILL");
    }
}
