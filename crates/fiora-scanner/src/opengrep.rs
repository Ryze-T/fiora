//! OpenGrep engine bridge (DESIGN.md §1/§3).
//!
//! The engine ships as a single embedded binary; here we shell out to it and
//! parse its Semgrep-compatible JSON. Lookup order: `FIORA_OPENGREP_BIN` env,
//! `<runtime_dir>/opengrep`, then PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::normalize::{parse_json, OpgrepReport};

#[derive(Debug)]
pub enum OpenGrepError {
    NotFound,
    Io(std::io::Error),
    Parse(serde_json::Error),
    Failed { status: Option<i32>, detail: String },
}

impl std::fmt::Display for OpenGrepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenGrepError::NotFound => {
                write!(f, "opengrep binary not found (set FIORA_OPENGREP_BIN)")
            }
            OpenGrepError::Io(e) => write!(f, "opengrep io error: {e}"),
            OpenGrepError::Parse(e) => write!(f, "opengrep json parse error: {e}"),
            OpenGrepError::Failed { status, detail } => {
                write!(f, "opengrep failed (status {status:?}): {detail}")
            }
        }
    }
}

impl std::error::Error for OpenGrepError {}

pub fn find_binary(runtime_dir: Option<&Path>) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FIORA_OPENGREP_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(rt) = runtime_dir {
        let p = rt.join("opengrep");
        if p.exists() {
            return Some(p);
        }
    }
    // PATH lookup
    if let Ok(out) = Command::new("sh")
        .args(["-c", "command -v opengrep"])
        .output()
    {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
    }
    None
}

/// Run the rule channel: `opengrep scan --json --config <dirs> -- <root>`.
///
/// Two failure modes this function must not swallow:
///   1. no JSON at all on stdout (engine died before writing a report);
///   2. a report whose `errors[]` carries level=error entries — OpenGrep still
///      exits 0 and prints plausible JSON, so without this check a rejected rule
///      or config reads as "0 findings", i.e. a clean scan that never happened.
pub fn scan(
    binary: &Path,
    rule_dirs: &[PathBuf],
    root: &Path,
) -> Result<OpgrepReport, OpenGrepError> {
    let mut cmd = Command::new(binary);
    cmd.arg("scan").arg("--json").arg("--quiet");
    for dir in rule_dirs {
        cmd.arg("--config").arg(dir);
    }
    cmd.arg("--").arg(root);
    let out = cmd.output().map_err(OpenGrepError::Io)?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    // opengrep exits non-zero when findings exist (semgrep convention is 0;
    // tolerate both) — only fail when there is no parsable report at all.
    let report = parse_json(&stdout).map_err(|e| OpenGrepError::Failed {
        status: out.status.code(),
        detail: format!(
            "no usable JSON report (parse error: {e}); stderr: {}; stdout: {}",
            excerpt(&stderr),
            excerpt(&stdout)
        ),
    })?;
    let hard = report.hard_errors();
    if !hard.is_empty() {
        return Err(OpenGrepError::Failed {
            status: out.status.code(),
            detail: format!(
                "{} rule/config error(s), the rule channel did not run: {}",
                hard.len(),
                hard.join(" | ")
            ),
        });
    }
    Ok(report)
}

/// Bounded, non-empty rendering of engine output for error messages. A failed
/// run that reports `stderr: <empty>` tells the operator nothing; say `<empty>`.
fn excerpt(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "<empty>".to_string();
    }
    let head: String = trimmed.chars().take(400).collect();
    if trimmed.chars().count() > 400 {
        format!("{head}…")
    } else {
        head
    }
}
