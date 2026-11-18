//! `fiora status` 命令组（DESIGN.md §2）。

use crate::support::Repo;
use std::path::Path;

pub(crate) fn cmd_status(root: &Path) -> Result<(), String> {
    let Repo { ledger, .. } = Repo::open(root)?;
    let mut counts = [0usize, 0usize, 0usize]; // pending, analyzed, skipped
    let files = ledger.list_files().map_err(|e| e.to_string())?;
    for rel in &files {
        if let Some(rec) = ledger.load_file(rel).map_err(|e| e.to_string())? {
            match rec.status {
                fiora_core::FileStatus::Pending => counts[0] += 1,
                fiora_core::FileStatus::Analyzed => counts[1] += 1,
                fiora_core::FileStatus::Skipped => counts[2] += 1,
            }
        }
    }
    println!(
        "files:    {} tracked (pending {}, analyzed {}, skipped {})",
        files.len(),
        counts[0],
        counts[1],
        counts[2]
    );
    let findings = crate::support::findings(&ledger)?;
    println!("findings: {}", findings.len());
    // 验证覆盖率：判定 ≠ 验证，交付口必须能一眼看到「验了几条、什么等级」。
    let mut lv = [0usize; 4]; // live, trigger, code-proof, disproved
    let mut unverified = 0usize;
    for f in &findings {
        match f.verification.as_ref().map(|v| v.method.as_str()) {
            Some("live-prove") => lv[0] += 1,
            Some("trigger-prove") => lv[1] += 1,
            Some("code-proof") => lv[2] += 1,
            Some("disproved") => lv[3] += 1,
            _ => unverified += 1,
        }
    }
    if !findings.is_empty() {
        println!(
            "verify:   {}/{} 已回填（live-prove {} · trigger-prove {} · code-proof {} · disproved {} · 未验证 {}）",
            findings.len() - unverified,
            findings.len(),
            lv[0],
            lv[1],
            lv[2],
            lv[3],
            unverified
        );
    }
    println!(
        "chains:   {}",
        ledger.list_chain_ids().map_err(|e| e.to_string())?.len()
    );
    Ok(())
}

/// `fiora models` —— 模型池 / 运行档位清单（Agent 可读选型面）。
pub(crate) fn cmd_models(root: &Path, json: bool) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;
    let cfg = crate::support::config(&root.join(".fiora"));
    if json {
        println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
        return Ok(());
    }
    println!(
        "默认槽: judge={:?} budget={:?} thinking={}",
        cfg.default_model, cfg.budget_model, cfg.thinking_level
    );
    if !cfg.models.is_empty() {
        println!("模型池:");
        for (name, spec) in &cfg.models {
            println!(
                "  {name:<12} -> {}  thinking={:?}",
                spec.model, spec.thinking
            );
        }
    }
    if !cfg.profiles.is_empty() {
        println!(
            "运行档位{}:",
            if cfg.active_profile.is_some() {
                "（* 为 active）"
            } else {
                ""
            }
        );
        for (name, prof) in &cfg.profiles {
            let mark = if cfg.active_profile.as_deref() == Some(name.as_str()) {
                "*"
            } else {
                " "
            };
            println!(
                "  {mark} {name:<12} judge={} budget={}",
                prof.judge, prof.budget
            );
        }
    }
    println!("用法: fiora process --profile <档位>  或  --model <id> 单次覆盖");
    Ok(())
}
