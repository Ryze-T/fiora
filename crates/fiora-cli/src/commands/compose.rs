//! `fiora compose` —— 组合假设搜索（super-0day 狩猎面）。
//!
//! 流程：账本观察 + 安全假设清单 → 组合会话（找"A+B 成链 / C 破保证"）
//! → 逐条确认会话（真追代码，判定契约输出）→ 存活者收编为 finding。
//! `fiora run` 在链组装后自动触发（观察 ≥3 条时）。

use crate::support::Repo;
use std::path::Path;

use fiora_core::AgentProvenance;
use fiora_processor::{
    build_inventory, compose_prompt, compose_verify_prompt, into_core, json_repair_prompt,
    parse_compositions, parse_judge_output, PiRequest, ThinkingLevel,
};

pub(crate) fn cmd_compose(
    root: &Path,
    model: Option<String>,
    thinking: &str,
) -> Result<usize, String> {
    let Repo { root, base, ledger } = Repo::open(root)?;
    let thinking = crate::support::parse_thinking(thinking)?;

    // 1) 观察清单：账本 findings + hunt.md 线索（确定性）
    let findings = crate::support::findings(&ledger)?;
    let leads = load_leads(&base);
    let inv = build_inventory(&findings, &leads);
    if inv.len() < 2 {
        println!(
            "compose: 观察不足（{} 条）——组合需要至少 2 个链环",
            inv.len()
        );
        return Ok(0);
    }

    let tech: Vec<String> = std::fs::read_to_string(base.join("tech.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();

    let runner = crate::support::model_runner(&base, model.as_deref())?;

    // 2) 组合会话：观察清单 → 组合假设
    let req = PiRequest {
        prompt: compose_prompt(&inv, &tech, crate::support::hunt_memo(&base).as_deref()),
        model: model.clone(),
        thinking: Some(thinking),
        name: Some("fiora-composition".to_string()),
        session_dir: Some(base.join("sessions")),
        system_prompt: None,
        timeout: None,
        tools: None,
    };
    let outcome = runner.run(&root, &req).map_err(|e| e.to_string())?;
    let mut comps = parse_compositions(&outcome.text).unwrap_or_default();
    let mut audit_log = String::new();
    if comps.is_empty() {
        let repair = PiRequest {
            prompt: json_repair_prompt(&req.prompt, &outcome.text),
            ..req.clone()
        };
        if let Ok(fixed) = runner.run(&root, &repair) {
            comps = parse_compositions(&fixed.text).unwrap_or_default();
        }
        if comps.is_empty() {
            // 不静默丢：规划失败如实留痕（含原始输出尾部，便于归因）
            let tail: String = outcome
                .text
                .chars()
                .rev()
                .take(300)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            audit_log.push_str(&format!(
                "- 规划会话输出不合 schema（已留痕）。尾部：{tail}\n"
            ));
            println!("compose: ⚠ 规划输出不合 schema，已留痕（见 compose-log.md）");
        }
    }
    println!("compose: {} 条组合假设（安全假设即攻击面）", comps.len());

    // 3) 逐条确认会话（真追代码）→ 判定契约输出 → 存活者收编
    let mut admitted = 0usize;
    for (i, comp) in comps.iter().take(8).enumerate() {
        let vreq = PiRequest {
            prompt: compose_verify_prompt(&comp.to_string(), &inv),
            model: model.clone(),
            thinking: Some(ThinkingLevel::Xhigh),
            name: Some(format!("fiora-compose-verify-{i}")),
            session_dir: Some(base.join("sessions")),
            system_prompt: None,
            timeout: None,
            tools: None,
        };
        let vout = runner.run(&root, &vreq).map_err(|e| e.to_string())?;
        // 逐条收容（设计纪律：单条裁决失败不得中止整场狩猎）
        let output = match parse_judge_output(&vout.text) {
            Ok(o) => o,
            Err(_) => {
                let repair = PiRequest {
                    prompt: json_repair_prompt(&vreq.prompt, &vout.text),
                    ..vreq.clone()
                };
                let fixed = runner.run(&root, &repair).ok();
                fixed
                    .and_then(|f| parse_judge_output(&f.text).ok())
                    .unwrap_or_else(|| {
                        // salvage 兜底：能救几条救几条，救不动的进 refusals 留痕
                        let mut o = fiora_processor::verdict::salvage_findings(&vout.text);
                        if o.findings.is_empty() && o.refusals.is_empty() {
                            o.refusals.push(format!(
                                "C{} 裁决输出不合 schema 且修复失败（会话 {}），已留痕不中止",
                                i + 1,
                                vout.session_id.clone().unwrap_or_default()
                            ));
                        }
                        o
                    })
            }
        };
        let agent = AgentProvenance {
            backend: "pi".into(),
            model: model.clone().unwrap_or_else(|| "default".into()),
            thinking_level: "xhigh".to_string(),
            run_id: format!("compose-{i}"),
            session_id: vout.session_id.clone(),
            cost: Some(vout.cost.clone()),
        };
        for jf in &output.findings {
            let mut f = into_core(jf, &agent);
            // 组合发现的稳定身份：类别固定 composition，锚用 claim 前缀
            f.id = fiora_core::id::stable_id(
                "c",
                &["composition", &f.category, &f.sink_symbol, &f.enclosing_fn],
            );
            let brief = format!("{:?}", f.severity);
            let title = f.title.clone();
            let id8 = f.id[..8].to_string();
            ledger.upsert_finding(f).map_err(|e| e.to_string())?;
            admitted += 1;
            println!("  ✓ 收编 {id8} [{brief}] {title}");
            audit_log.push_str(&format!("- 收编 {id8} [{brief}] {title}\n"));
        }
        for r in &output.refusals {
            let id = comp["id"].as_str().unwrap_or("?");
            let line = r.chars().take(160).collect::<String>();
            println!(
                "  ✗ 处刑 {id}: {}",
                line.chars().take(80).collect::<String>()
            );
            audit_log.push_str(&format!("- 处刑 {id}: {line}\n"));
        }
    }
    // 处刑/收编全量落账（组合狩猎的审计资产——不静默丢）
    if !audit_log.is_empty() {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(base.join("compose-log.md"))
            .map_err(|e| e.to_string())?;
        writeln!(f, "\n## compose run\n{audit_log}").map_err(|e| e.to_string())?;
    }
    println!(
        "compose: {} 条组合链收编（其余已处刑/留痕 → .fiora/compose-log.md）",
        admitted
    );
    Ok(admitted)
}

fn load_leads(base: &Path) -> Vec<String> {
    std::fs::read_to_string(base.join("hunt.md"))
        .map(|t| {
            t.lines()
                .filter(|l| l.starts_with("- ") && (l.contains("线索") || l.contains("：")))
                .map(|l| l.trim_start_matches("- ").to_string())
                .take(20)
                .collect()
        })
        .unwrap_or_default()
}
