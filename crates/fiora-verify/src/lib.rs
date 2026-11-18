//! `fiora-verify` — L4 verification layer (DESIGN.md §6).
//!
//! The iron evidence: run the finding's repro probe against BOTH sides of a
//! patch (pre-revision vs post-revision). A pattern that exists before the
//! patch and disappears after it is a *verified fix*; one that persists is a
//! *verified vulnerability*. Nothing here trusts the model — probes are
//! deterministic checks of code state at a git revision.
//!
//! 产品定位：fiora 只做确定性代码态差分。环境启动 / 动态执行验证由工作台
//! Agent（pi/dsh）完成，结论经 `fiora verify record` 回填。

use std::path::Path;
use std::process::Command;

use fiora_core::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerableState {
    /// The vulnerable shape is present in this revision.
    Present,
    /// The vulnerable shape is gone (fixed or never existed here).
    Absent,
    /// Cannot tell (revision missing, file unreadable, symbol too dynamic).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffVerdict {
    /// Present before the patch, absent after — the fix works.
    Fixed,
    /// Present on both sides — the vulnerability survives the patch.
    Persisting,
    /// Absent before, present after — the patch introduced it.
    Regressed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub state: VulnerableState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Differential {
    pub finding_id: String,
    pub pre: ProbeResult,
    pub post: ProbeResult,
    pub verdict: DiffVerdict,
}

// ---------- probes ----------

/// Probe a revision's file content for the finding's vulnerable shape.
///
/// The probe is deliberately conservative and explainable: it looks for the
/// sink symbol within a drift-tolerant window around the recorded line. If the
/// symbol appears nowhere in the file the shape is `Absent`; if the file or
/// symbol cannot be judged it is `Unknown`, never a guess.
pub fn probe_content(finding: &Finding, content: Option<&str>) -> ProbeResult {
    let Some(content) = content else {
        return ProbeResult {
            state: VulnerableState::Unknown,
            detail: "file not readable at this revision".to_string(),
        };
    };
    let needle = finding
        .probe_shape
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| finding.sink_symbol.clone());
    if needle.is_empty() {
        return ProbeResult {
            state: VulnerableState::Unknown,
            detail: "finding has no probeable shape".to_string(),
        };
    }
    let window = 15i64;
    let target = finding.line as i64;
    let mut found_anywhere = false;
    for (i, line) in content.lines().enumerate() {
        if line.contains(needle.as_str()) {
            found_anywhere = true;
            let ln = i as i64 + 1;
            if (ln - target).abs() <= window {
                return ProbeResult {
                    state: VulnerableState::Present,
                    detail: format!("sink '{needle}' present at line {ln} (recorded {target})"),
                };
            }
        }
    }
    if found_anywhere {
        ProbeResult {
            state: VulnerableState::Present,
            detail: format!("sink '{needle}' present but drifted beyond ±{window} lines"),
        }
    } else {
        ProbeResult {
            state: VulnerableState::Absent,
            detail: format!("sink '{needle}' absent from file"),
        }
    }
}

/// Probe a revision via `git show <rev>:<path>` (no worktree needed).
pub fn probe_rev(root: &Path, finding: &Finding, rev: &str) -> ProbeResult {
    match read_at_rev(root, rev, &finding.file) {
        Ok(content) => probe_content(finding, Some(&content)),
        Err(detail) => ProbeResult {
            state: VulnerableState::Unknown,
            detail,
        },
    }
}

/// Probe the current working tree (fix verification without revisions).
pub fn probe_worktree(root: &Path, finding: &Finding) -> ProbeResult {
    let path = root.join(&finding.file);
    match std::fs::read_to_string(&path) {
        Ok(content) => probe_content(finding, Some(&content)),
        Err(_) => ProbeResult {
            state: VulnerableState::Absent,
            detail: format!("file {} no longer exists", finding.file),
        },
    }
}

// ---------- differential / fix verification ----------

/// Pre/post-patch differential repro for one finding.
pub fn diff_finding(root: &Path, finding: &Finding, pre_rev: &str, post_rev: &str) -> Differential {
    let pre = probe_rev(root, finding, pre_rev);
    let post = probe_rev(root, finding, post_rev);
    let verdict = match (pre.state, post.state) {
        (VulnerableState::Present, VulnerableState::Absent) => DiffVerdict::Fixed,
        (VulnerableState::Present, VulnerableState::Present) => DiffVerdict::Persisting,
        (VulnerableState::Absent, VulnerableState::Present) => DiffVerdict::Regressed,
        _ => DiffVerdict::Unknown,
    };
    Differential {
        finding_id: finding.id.clone(),
        pre,
        post,
        verdict,
    }
}

/// Fix verification for one finding on the working tree.
/// `Persisting` = still vulnerable, `Fixed` = shape gone.
pub fn verify_fix(root: &Path, finding: &Finding) -> Differential {
    let post = probe_worktree(root, finding);
    let verdict = match post.state {
        VulnerableState::Absent => DiffVerdict::Fixed,
        VulnerableState::Present => DiffVerdict::Persisting,
        VulnerableState::Unknown => DiffVerdict::Unknown,
    };
    Differential {
        finding_id: finding.id.clone(),
        pre: ProbeResult {
            state: VulnerableState::Unknown,
            detail: "no pre-revision (fix check on working tree)".to_string(),
        },
        post,
        verdict,
    }
}

// ---------- internals ----------

fn read_at_rev(root: &Path, rev: &str, file: &str) -> Result<String, String> {
    let out = Command::new("git")
        .args(["show", &format!("{rev}:{file}")])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git unavailable: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git show {rev}:{file} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Map a differential verdict to the ledger Verification record.
pub fn to_verification(d: &Differential, method: &str, at: &str) -> fiora_core::Verification {
    fiora_core::Verification {
        method: method.to_string(),
        pre_state: format!("{:?}", d.pre.state).to_ascii_lowercase(),
        post_state: format!("{:?}", d.post.state).to_ascii_lowercase(),
        verdict: match d.verdict {
            DiffVerdict::Fixed => "fixed",
            DiffVerdict::Persisting => "persisting",
            DiffVerdict::Regressed => "regressed",
            DiffVerdict::Unknown => "unknown",
        }
        .to_string(),
        at: at.to_string(),
        notes: format!("pre: {}; post: {}", d.pre.detail, d.post.detail),
    }
}

/// 差分结论落 `.fiora/diffs/<id>.json`——**不碰 finding 的 verification**。
///
/// 两个通道是正交维度：`verify record` 是 Agent 的实测真值（live/trigger/
/// code-proof/disproved），`verify diff` 是补丁态的确定性对照
/// （fixed/persisting/regressed）。此前两者写同一个槽位，跑一次
/// `verify diff` 就把整仓的 live-prove 实测记录冲成 fix-check（工作台实测
/// 事故：4 条 live-prove 全灭）。
pub fn record_diff_state(
    base_dir: &std::path::Path,
    finding_id: &str,
    v: &fiora_core::Verification,
) -> std::io::Result<std::path::PathBuf> {
    let dir = base_dir.join("diffs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{finding_id}.json"));
    let tmp = dir.join(format!(".{finding_id}.json.tmp"));
    std::fs::write(&tmp, serde_json::to_string_pretty(v).unwrap())?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}
