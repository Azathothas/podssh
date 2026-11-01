//! A line on stderr or stdout that a failed write cannot end (T-389).
//! `eprintln!` and `println!` panic when the write fails, and the release
//! build aborts on a panic: a detached node whose log's disk filled, or whose
//! journal went away (EPIPE), would end at its next line, and a server that
//! only its tunnel reaches would be locked out. The sources of podssh use
//! these in their place (`scripts/check-repo.py` refuses the others).

use std::fmt::Arguments;
use std::io::Write;

/// The line, and its end, in one write to `to`, then a flush; a failure of
/// either is dropped, as nobody is left to tell of it.
pub fn write_line(to: &mut dyn Write, args: Arguments<'_>) {
    let mut line = std::fmt::format(args);
    line.push('\n');
    let _ = to.write_all(line.as_bytes());
    let _ = to.flush();
}

/// [`write_line`] to stderr, under its lock, so that lines of two threads
/// do not mix.
pub fn err_line(args: Arguments<'_>) {
    write_line(&mut std::io::stderr().lock(), args);
}

/// [`write_line`] to stdout, under its lock.
pub fn out_line(args: Arguments<'_>) {
    write_line(&mut std::io::stdout().lock(), args);
}

/// `eprintln!`, with a failed write dropped: see the module.
#[macro_export]
macro_rules! err_line {
    () => {
        $crate::line::err_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::line::err_line(format_args!($($arg)*))
    };
}

/// `println!`, with a failed write dropped: see the module.
#[macro_export]
macro_rules! out_line {
    () => {
        $crate::line::out_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::line::out_line(format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer whose each write and flush fails, as a full disk's.
    struct Full;

    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(28))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(28))
        }
    }

    #[test]
    fn a_failed_write_is_dropped_not_a_panic() {
        write_line(&mut Full, format_args!("podssh node: {}: {}", "lab", "online again"));
    }

    #[test]
    fn the_line_and_its_end_go_in_one_write() {
        /// Counts the writes it takes.
        #[derive(Default)]
        struct Counted(Vec<Vec<u8>>);
        impl Write for Counted {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.push(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut to = Counted::default();
        write_line(&mut to, format_args!("podssh node: {}", "online"));
        assert_eq!(to.0, vec![b"podssh node: online\n".to_vec()]);
    }

    #[test]
    fn the_macros_take_the_arguments_of_eprintln() {
        let label = "lab";
        crate::err_line!("podssh node: {label}: {}", "a line of the test");
        crate::out_line!();
    }
}
