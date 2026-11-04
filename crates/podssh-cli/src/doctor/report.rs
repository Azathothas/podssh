//! The report of `podssh doctor`: its lines so far and their counts, the
//! text printed as each check ends, or with `--json` one object at the end.
//! Apart from the run so that each file stays short.

use std::io::Write;

use podssh_ws::Verdict;

use super::{diagnosis, parts, samples, EXIT_FAILED};

/// One check, as the report keeps it for `--json`.
pub(super) struct Line {
    pub(super) section: String,
    pub(super) check: String,
    pub(super) status: &'static str,
    pub(super) detail: String,
    /// A probe's tries as numbers (T-324).
    pub(super) samples: Option<serde_json::Value>,
}

/// The lines so far, and their counts. The text is printed as each check
/// ends; with `json`, the lines are kept and written as one object at the
/// end. One model and two renderers, as for `podssh man`.
pub(crate) struct Report<'a> {
    pub(super) out: &'a mut dyn Write,
    pub(super) json: bool,
    pub(super) section: String,
    pub(super) lines: Vec<Line>,
    /// Each TLS handshake of a road, and the reference's, for the diagnosis
    /// after the counts (T-487).
    pub(super) handshakes: Vec<diagnosis::Handshake>,
    pub(super) ok: usize,
    pub(super) failed: usize,
    pub(super) unknown: usize,
}

impl<'a> Report<'a> {
    pub(super) fn new(out: &'a mut dyn Write) -> Self {
        let (section, lines, handshakes) = (String::new(), Vec::new(), Vec::new());
        Report { out, json: false, section, lines, handshakes, ok: 0, failed: 0, unknown: 0 }
    }

    pub(super) fn section(&mut self, title: &str) {
        self.section = title.to_string();
        if !self.json {
            let _ = writeln!(self.out, "\n{title}");
        }
    }

    /// One check. The detail is made safe for a terminal here, once, because
    /// it often carries text from a peer or from the environment.
    pub(crate) fn line(&mut self, name: &str, verdict: Verdict) {
        let label = verdict.label();
        let detail = match &verdict {
            Verdict::Ok { detail } => {
                self.ok += 1;
                detail
            }
            Verdict::Failed { detail } => {
                self.failed += 1;
                detail
            }
            Verdict::Unknown { why } => {
                self.unknown += 1;
                why
            }
        };
        let detail = podssh_ws::text::one_line(detail);
        let status = match verdict {
            Verdict::Ok { .. } => "ok",
            Verdict::Failed { .. } => "FAIL",
            Verdict::Unknown { .. } => "unknown",
        };
        if !self.json {
            let _ = writeln!(self.out, "  {label:<4}  {name:<14} {detail}");
            // Network checks take seconds each: show every line as it is known.
            let _ = self.out.flush();
        }
        self.lines.push(Line { section: self.section.clone(), check: name.to_string(), status, detail, samples: None });
    }

    /// [`Report::line`] for a probe that was tried several times; `--json`
    /// gives its times and its losses as numbers too.
    pub(super) fn sampled(&mut self, name: &str, verdict: Verdict, samples: &samples::Samples) {
        self.line(name, verdict);
        if let Some(line) = self.lines.last_mut() {
            line.samples = Some(samples.json());
        }
    }

    pub(crate) fn ok(&mut self, name: &str, detail: impl Into<String>) {
        self.line(name, Verdict::Ok { detail: detail.into() });
    }

    pub(crate) fn fail(&mut self, name: &str, detail: impl Into<String>) {
        self.line(name, Verdict::Failed { detail: detail.into() });
    }

    pub(crate) fn unknown(&mut self, name: &str, why: impl Into<String>) {
        self.line(name, Verdict::Unknown { why: why.into() });
    }

    /// How a road's TLS handshake with `name` ended, for the diagnosis.
    pub(super) fn handshake(&mut self, of: diagnosis::Of, name: &str, met: diagnosis::Met) {
        self.handshakes.push(diagnosis::Handshake { of, name: name.to_string(), met, through: None });
    }

    /// A part's lines and counts, once its section has run (T-511).
    pub(super) fn ended(self) -> parts::Ended {
        let (lines, handshakes) = (self.lines, self.handshakes);
        parts::Ended { lines, handshakes, ok: self.ok, failed: self.failed, unknown: self.unknown }
    }

    /// The lines of a part that ran apart, in their order; its text went
    /// out as the part ran.
    pub(super) fn absorb(&mut self, part: parts::Ended) {
        self.lines.extend(part.lines);
        self.handshakes.extend(part.handshakes);
        self.ok += part.ok;
        self.failed += part.failed;
        self.unknown += part.unknown;
    }

    pub(super) fn finish(self) -> i32 {
        let found = diagnosis::diagnose(&self.handshakes);
        if self.json {
            let _ = writeln!(self.out, "{}", self.to_json(&found));
        } else {
            let _ = writeln!(
                self.out,
                "\n{} ok, {} FAIL, {} ???? (could not be checked)",
                self.ok, self.failed, self.unknown
            );
            // After the counts, as a line about them all is known once they
            // are; it counts as nothing (T-487).
            for one in &found {
                let _ = writeln!(self.out, "diagnosis: {}", podssh_ws::text::one_line(&one.detail));
            }
        }
        let _ = self.out.flush();
        if self.failed > 0 {
            EXIT_FAILED
        } else {
            0
        }
    }
}

impl Report<'_> {
    /// The report as one JSON object: the version and the platform, each
    /// check with its section, the counts, and each diagnosis. The details
    /// are the text's, so they hide credentials and tokens in the same way.
    pub(super) fn to_json(&self, found: &[diagnosis::Diagnosis]) -> String {
        let checks: Vec<serde_json::Value> = self
            .lines
            .iter()
            .map(|l| {
                let mut item = serde_json::json!({
                    "section": l.section, "check": l.check, "status": l.status, "detail": l.detail,
                });
                if let Some(samples) = &l.samples {
                    item["samples"] = samples.clone();
                }
                item
            })
            .collect();
        let findings: Vec<serde_json::Value> = found.iter().map(diagnosis::Diagnosis::json).collect();
        let doc = serde_json::json!({
            "schema": 1,
            "podssh": crate::help::version(),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "checks": checks,
            "counts": { "ok": self.ok, "fail": self.failed, "unknown": self.unknown },
            "diagnosis": findings,
        });
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    }
}
