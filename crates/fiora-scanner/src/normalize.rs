//! Normalize OpenGrep (Semgrep-compatible) JSON output into ledger candidates.

use fiora_core::id::candidate_id;
use fiora_core::{Candidate, CandidateChannel};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct OpgrepReport {
    #[serde(default)]
    pub results: Vec<OpgrepResult>,
    #[serde(default)]
    pub errors: Vec<serde_json::Value>,
}

impl OpgrepReport {
    /// Errors that mean rules or config were rejected — the scan did not happen
    /// the way it claims to have happened. OpenGrep reports these in-band (exit
    /// status stays 0), so they have to be read out of the JSON.
    pub fn hard_errors(&self) -> Vec<String> {
        self.errors
            .iter()
            .filter(|e| e.get("level").and_then(|v| v.as_str()) == Some("error"))
            .map(|e| {
                e.get("long_msg")
                    .or_else(|| e.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("opengrep reported an error without a message")
                    .to_string()
            })
            .collect()
    }

    /// Non-fatal analysis warnings (timeouts, partial files): the scan ran, but
    /// coverage is not what the rest of the pipeline assumes. Surfaced to the
    /// operator instead of being silently dropped.
    pub fn warn_errors(&self) -> usize {
        self.errors
            .iter()
            .filter(|e| e.get("level").and_then(|v| v.as_str()) != Some("error"))
            .count()
    }

    /// One line per warning, for the operator: a bare count leaves them guessing
    /// which file went unanalysed and why. OpenGrep puts the path and the
    /// offending source in the first two lines of the message.
    pub fn warn_summaries(&self, limit: usize) -> Vec<String> {
        self.errors
            .iter()
            .filter(|e| e.get("level").and_then(|v| v.as_str()) != Some("error"))
            .take(limit)
            .map(|e| {
                let text = e
                    .get("long_msg")
                    .or_else(|| e.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no detail)");
                let joined = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" — ");
                let mut s: String = joined.chars().take(180).collect();
                if joined.chars().count() > 180 {
                    s.push('…');
                }
                s
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct OpgrepResult {
    pub check_id: String,
    pub path: String,
    pub start: OpgrepPos,
    #[serde(default)]
    pub end: Option<OpgrepPos>,
    pub extra: OpgrepExtra,
}

#[derive(Debug, Deserialize)]
pub struct OpgrepPos {
    pub line: u32,
    #[serde(default)]
    pub col: u32,
}

#[derive(Debug, Deserialize)]
pub struct OpgrepExtra {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub lines: String,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// Taint-mode results carry the source->sink dataflow trace here; preserved
    /// as the candidate note for L2 evidence pre-assembly.
    #[serde(default)]
    pub dataflow_trace: Option<serde_json::Value>,
}

/// Parse OpenGrep `--json` output and produce normalized, id-stable candidates.
pub fn normalize(report: &OpgrepReport, root: &str) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in &report.results {
        let rel = relative_path(&r.path, root);
        let slug = slug_of(&r.check_id);
        let id = candidate_id(&slug, &rel, r.start.line);
        // 同一规则的多个 pattern 分支会重复命中同一行——同 id 只留一条，
        // 否则重复条目永远缺 evidence、每次 run 都重试（实测 17 例）。
        if !seen.insert(id.clone()) {
            continue;
        }
        let note = r
            .extra
            .dataflow_trace
            .as_ref()
            .map(|t| format!("dataflow: {}", serde_json::to_string(t).unwrap_or_default()));
        out.push(Candidate {
            id,
            slug: slug.clone(),
            matcher_id: slug,
            channel: CandidateChannel::Rule,
            file: rel,
            line: r.start.line,
            end_line: r.end.as_ref().map(|e| e.line),
            snippet: r.extra.lines.clone(),
            note,
            evidence_id: None,
        });
    }
    out
}

pub fn parse_json(text: &str) -> Result<OpgrepReport, serde_json::Error> {
    serde_json::from_str(text)
}

/// `rules/sqli.yaml.sqli-sprintf` -> `sqli-sprintf` (last segment of check id).
fn slug_of(check_id: &str) -> String {
    check_id
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(check_id)
        .to_string()
}

fn relative_path(path: &str, root: &str) -> String {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        if let Ok(rel) = p.strip_prefix(root) {
            return rel.to_string_lossy().to_string();
        }
    }
    path.to_string()
}
