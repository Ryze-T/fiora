//! `fiora family` —— 能力族座次表（"还有哪些 RCE / 哪些无条件"的命令化回答）。
//!
//! 族分类 + 可达性档位来自 fiora_core::family（机械规则，非 LLM）。

use crate::support::Repo;
use std::path::Path;

use fiora_core::family::{rank_by_family, ReachTier};
use fiora_core::types::VerdictConclusion;

pub(crate) fn cmd_family(
    root: &Path,
    family: Option<String>,
    severity: &str,
    all: bool,
    json: bool,
) -> Result<(), String> {
    crate::support::validate_severity(severity)?;
    let Repo { ledger, .. } = Repo::open(root)?;

    let ids = ledger.list_finding_ids().map_err(|e| e.to_string())?;
    let mut findings = Vec::new();
    let mut hidden_sev = 0usize;
    for id in &ids {
        if let Some(f) = ledger.load_finding(id).map_err(|e| e.to_string())? {
            // 默认只看 TP（座次表回答"能打的有哪些"）；--all 放开。
            if !all {
                let tp = f
                    .verdict
                    .as_ref()
                    .map(|v| v.conclusion == VerdictConclusion::TruePositive)
                    .unwrap_or(false);
                if !tp {
                    continue;
                }
            }
            // 默认只看高危及以上；--severity all 放开（低危仍落账）。
            if !fiora_core::family::passes_severity(&f, severity) {
                hidden_sev += 1;
                continue;
            }
            findings.push(f);
        }
    }
    if hidden_sev > 0 && !json {
        println!("（另有 {hidden_sev} 条中低危未展示：--severity all 查看）");
    }

    let refs: Vec<&fiora_core::Finding> = findings.iter().collect();
    let mut groups = rank_by_family(&refs);

    // --family 过滤（rce/ssrf/awf/deser/injection/authz/infoleak/dos/supplychain/other）
    if let Some(want) = family {
        let w = want.to_lowercase();
        groups.retain(|(fam, _)| fam.label().to_lowercase().contains(&w));
    }

    if json {
        let rows: Vec<serde_json::Value> = groups
            .iter()
            .flat_map(|(fam, rows)| {
                rows.iter()
                    .map(|r| {
                        serde_json::json!({
                            "family": fam.label(),
                            "id": r.id,
                            "title": r.title,
                            "severity": r.severity,
                            "tier": r.tier.label(),
                            "precondition_count": r.precondition_count,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        return Ok(());
    }

    if groups.is_empty() {
        println!("（无匹配发现）");
        return Ok(());
    }

    for (fam, rows) in &groups {
        println!("\n┌─ {}（{} 条）", fam.label(), rows.len());
        for r in rows {
            let pre = if r.precondition_count == 0 {
                "无前置".to_string()
            } else {
                format!("{} 条前置", r.precondition_count)
            };
            println!(
                "│ [{tier}] {title}  · {sev} · {pre} · {id}",
                tier = tier_mark(r.tier),
                title = r.title,
                sev = r.severity,
                pre = pre,
                id = r.id,
            );
        }
        println!("└─");
    }
    println!("\n座次 = 可达性档位升序（越无条件越靠前）· 档位图例：[0]无条件 [1]网络可达 [2]部署形态 [3]供应链 [4]工作流");
    Ok(())
}

fn tier_mark(t: ReachTier) -> String {
    format!("[{}]", t as u8)
}
