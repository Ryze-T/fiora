//! `fiora verify` 命令组（插件定位：确定性差分 + Agent 验证结论回填）。
//!
//! 验证职责分界（产品定位）：fiora 只做**确定性代码态差分**（pre/post 修订对照）；
//! 环境启动与动态执行验证由工作台 Agent（pi/dsh）完成，结论经 `verify record`
//! 回填账本，报告据此展示诚实的验证徽章。

use crate::support::Repo;
use std::path::Path;

/// 确定性差分：pre/post git 修订（或工作树 fix-check）上的 vulnerable shape 对照。
pub(crate) fn cmd_verify(
    root: &Path,
    pre: Option<&str>,
    post: Option<&str>,
    finding: Option<&str>,
) -> Result<(), String> {
    use fiora_verify::{diff_finding, to_verification, verify_fix};

    let Repo { base, ledger, .. } = Repo::open(root)?;
    let at = fiora_core::util::now_iso();
    let mut checked = 0;

    for fid in ledger.list_finding_ids().map_err(|e| e.to_string())? {
        if let Some(want) = finding {
            if fid != want {
                continue;
            }
        }
        let Some(f) = ledger.load_finding(&fid).map_err(|e| e.to_string())? else {
            continue;
        };
        let (diff, method) = match (pre, post) {
            (Some(pre), Some(post)) => (diff_finding(root, &f, pre, post), "static-diff"),
            _ => (verify_fix(root, &f), "fix-check"),
        };
        println!(
            "verify {} : {:?} (pre={:?}, post={:?})",
            fid, diff.verdict, diff.pre.state, diff.post.state
        );
        // 差分结论独立落盘：绝不覆盖 Agent 的实测记录（verification 槽）。
        fiora_verify::record_diff_state(&base, &fid, &to_verification(&diff, method, &at))
            .map_err(|e| e.to_string())?;
        checked += 1;
    }
    if checked > 0 {
        ledger
            .record_audit_stage("verify-diff", None, "all")
            .map_err(|e| e.to_string())?;
    }
    println!("verify: {checked} finding(s) checked（差分结论入 .fiora/diffs/，不触碰实测记录）");
    Ok(())
}

/// Agent 验证结论回填：工作台 Agent 启动环境验证后，把真值写回账本。
///
/// level 语义（诚实三级 + 证伪）：
/// - `live-prove`   真实执行实锤（载荷在目标上执行成功）
/// - `trigger-prove` 触发实锤（真实代码加载执行，canary 无害化）
/// - `code-proof`   代码级论证（静态证据链完整，未动态执行）
/// - `disproved`    证伪（验证推翻了判定）
pub(crate) fn cmd_verify_record(
    root: &Path,
    finding: &str,
    level: &str,
    note: Option<&str>,
    severity: Option<&str>,
) -> Result<(), String> {
    let verdict = match level {
        "live-prove" | "trigger-prove" | "code-proof" => "confirmed",
        "disproved" => "disproved",
        other => {
            return Err(format!(
                "未知验证等级: {other}（可选 live-prove|trigger-prove|code-proof|disproved）"
            ))
        }
    };
    let Repo { ledger, .. } = Repo::open(root)?;
    let at = fiora_core::util::now_iso();
    let v = fiora_core::Verification {
        method: level.to_string(),
        pre_state: "-".to_string(),
        post_state: "-".to_string(),
        verdict: verdict.to_string(),
        at: at.clone(),
        notes: note.unwrap_or_default().to_string(),
    };
    ledger
        .set_verification(finding, v)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("finding not found: {finding}"))?;
    // 复验结论常常推翻判定层的初判级（实测：HIGH 应降 MEDIUM），回填时一并校正，
    // 此前没有入口，报告永远按初判级展示。
    if let Some(s) = severity {
        let sev = fiora_processor::parse_severity(s)?;
        ledger
            .set_finding_severity(finding, sev)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("finding not found: {finding}"))?;
        println!("severity: {finding} → {s}");
    }
    ledger
        .record_audit_stage("verify", None, "all")
        .map_err(|e| e.to_string())?;
    println!("verify record: {finding} → {level}（{verdict}）");
    Ok(())
}
