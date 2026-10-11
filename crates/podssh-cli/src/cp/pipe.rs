//! `-B`, `-R` and `-X` of `sftp`, and `-X` of `scp` (T-140): the bytes of
//! each read or write, and the requests in flight, as OpenSSH reads them.
//! podssh then keeps the bytes in flight within the window that it gives a
//! server, and the size within the server's limit.

use podssh_ssh::sftp::Pipeline;

/// The largest buffer that OpenSSH takes (`-X buffer=`).
const MOST: u64 = 256 * 1024;

/// A size: a number, with K, M or G for 1024, 1024² or 1024³, as OpenSSH's
/// `scan_scaled` reads it.
fn size(text: &str) -> Option<u64> {
    let text = text.trim();
    let last = text.chars().last()?;
    let (digits, scale) = match last.to_ascii_uppercase() {
        'K' => (&text[..text.len() - 1], 1u64 << 10),
        'M' => (&text[..text.len() - 1], 1 << 20),
        'G' => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(scale)
}

/// The size of `-B`, or of `-X buffer=`; `shown` is the flag as typed.
fn buffer(shown: &str, text: &str) -> Result<u32, String> {
    match size(text) {
        Some(n) if (1..=MOST).contains(&n) => Ok(n as u32),
        _ => Err(format!("{shown}: the buffer is 1 to {MOST} bytes")),
    }
}

/// The count of `-R`, or of `-X nrequests=`; `shown` is the flag as typed.
fn requests(shown: &str, text: &str) -> Result<usize, String> {
    match text.trim().parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err(format!("{shown}: give one request or more")),
    }
}

/// The pipeline of `-B BYTES`, `-R COUNT` and each `-X NAME=VALUE`, which
/// come after them; the last of each wins.
pub fn pipeline(
    given_buffer: Option<&str>,
    given_requests: Option<&str>,
    options: &[String],
) -> Result<Pipeline, String> {
    let mut pipe = Pipeline::default();
    if let Some(text) = given_buffer {
        pipe.len = buffer(&format!("-B {text}"), text)?;
    }
    if let Some(text) = given_requests {
        pipe.requests = requests(&format!("-R {text}"), text)?;
    }
    for option in options {
        match option.split_once('=') {
            Some(("buffer", text)) => pipe.len = buffer(&format!("-X {option}"), text)?,
            Some(("nrequests", text)) => pipe.requests = requests(&format!("-X {option}"), text)?,
            _ => return Err(format!("-X {option}: the options are buffer=BYTES and nrequests=COUNT")),
        }
    }
    Ok(pipe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_counts_read_as_openssh_reads_them() {
        assert_eq!(pipeline(None, None, &[]), Ok(Pipeline::default()));
        let pipe = pipeline(Some("65536"), Some("8"), &[]).unwrap();
        assert_eq!((pipe.len, pipe.requests), (65536, 8));
        let pipe = pipeline(None, None, &["buffer=128k".into(), "nrequests=4".into()]).unwrap();
        assert_eq!((pipe.len, pipe.requests), (128 * 1024, 4));
        // -X comes after -B and -R, and the last wins.
        let options = ["buffer=32K".to_string(), "buffer=16k".to_string()];
        assert_eq!(pipeline(Some("1024"), None, &options).unwrap().len, 16 * 1024);
        assert_eq!(pipeline(Some("256K"), None, &[]).unwrap().len, 256 * 1024);
    }

    #[test]
    fn a_size_or_a_count_out_of_range_is_refused_with_its_flag() {
        assert_eq!(pipeline(Some("0"), None, &[]), Err("-B 0: the buffer is 1 to 262144 bytes".into()));
        assert!(pipeline(Some("257K"), None, &[]).unwrap_err().starts_with("-B 257K:"));
        assert!(pipeline(Some("1x"), None, &[]).is_err());
        assert_eq!(pipeline(None, Some("0"), &[]), Err("-R 0: give one request or more".into()));
        assert!(pipeline(None, None, &["nrequests=-1".into()]).unwrap_err().starts_with("-X nrequests=-1:"));
        assert_eq!(
            pipeline(None, None, &["fast".into()]),
            Err("-X fast: the options are buffer=BYTES and nrequests=COUNT".into())
        );
    }
}
