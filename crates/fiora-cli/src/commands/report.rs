//! `fiora report` 命令组（DESIGN.md §2）。

use crate::support::Repo;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fiora_scanner::SurfaceEntry;

use crate::support::run_totals;

pub(crate) fn cmd_report(
    root: &Path,
    out: Option<&Path>,
    severity: &str,
    sarif: Option<&Path>,
    fail_on: Option<&str>,
) -> Result<(), String> {
    cmd_report_with(root, out, severity, sarif, fail_on, false)
}

/// `zero_model` = 本次交付没调用任何模型（`run --no-ai`）。此时报告必须说清
/// 「这份 HTML 是重渲染出来的，判定结论是账本里的旧记录」——否则会把上一轮
/// AI 的模型名写成这份报告的生成者，等于给零模型交付物挂了个假作者。
pub(crate) fn cmd_report_with(
    root: &Path,
    out: Option<&Path>,
    severity: &str,
    sarif: Option<&Path>,
    fail_on: Option<&str>,
    zero_model: bool,
) -> Result<(), String> {
    crate::support::validate_severity(severity)?;
    if let Some(level) = fail_on {
        crate::support::validate_severity(level)?;
    }
    let Repo { root, base, ledger } = Repo::open(root)?;

    let mut findings = crate::support::findings(&ledger)?;
    // 默认只看高危及以上（用户约定）；--severity all 显式放开。低危仍落账。
    let total = findings.len();
    findings.retain(|f| fiora_core::family::passes_severity(f, severity));
    let hidden = total - findings.len();
    if hidden > 0 {
        println!("report: {hidden} 条中低危未展示（--severity all 查看）");
    }
    let mut chains = Vec::new();
    for cid in ledger.list_chain_ids().map_err(|e| e.to_string())? {
        if let Some(c) = ledger.load_chain(&cid).map_err(|e| e.to_string())? {
            chains.push(c);
        }
    }
    let mut evidence = Vec::new();
    for f in &findings {
        if let Some(ref eid) = f.evidence_ref {
            if let Some(ev) = ledger.load_evidence(eid).map_err(|e| e.to_string())? {
                if !evidence
                    .iter()
                    .any(|e: &fiora_core::Evidence| e.id == ev.id)
                {
                    evidence.push(ev);
                }
            }
        }
    }

    let surface: Vec<SurfaceEntry> = crate::support::surface(&base);
    let mut coverage = fiora_report::Coverage {
        files_tracked: 0,
        files_analyzed: 0,
        files_skipped: 0,
        files_pending: 0,
        candidates_rule: 0,
        candidates_semantic: 0,
        surface_entries: surface.len(),
    };
    let mut rows = Vec::new();
    let files = ledger.list_files().map_err(|e| e.to_string())?;
    coverage.files_tracked = files.len();
    let mut file_status: BTreeMap<String, fiora_core::FileStatus> = BTreeMap::new();
    for rel in &files {
        if let Some(rec) = ledger.load_file(rel).map_err(|e| e.to_string())? {
            match rec.status {
                fiora_core::FileStatus::Analyzed => coverage.files_analyzed += 1,
                fiora_core::FileStatus::Skipped => coverage.files_skipped += 1,
                fiora_core::FileStatus::Pending => coverage.files_pending += 1,
            }
            for c in &rec.candidates {
                match c.channel {
                    fiora_core::CandidateChannel::Rule => coverage.candidates_rule += 1,
                    fiora_core::CandidateChannel::Semantic => coverage.candidates_semantic += 1,
                }
            }
            file_status.insert(rel.clone(), rec.status);
        }
    }
    for e in &surface {
        let status = match file_status.get(&e.file) {
            Some(fiora_core::FileStatus::Analyzed) => "reviewed",
            Some(fiora_core::FileStatus::Skipped) => "covered-by-scan",
            _ => "unreviewed",
        };
        rows.push(fiora_report::SurfaceRow {
            file: e.file.clone(),
            line: e.line,
            symbol: e.symbol.clone(),
            route: e.route.clone(),
            status: status.to_string(),
        });
    }

    // code context for readability: line-numbered snippets around each finding
    let mut snippets = std::collections::HashMap::new();
    for f in &findings {
        if let Ok(content) = fs::read_to_string(root.join(&f.file)) {
            let start = f.line.saturating_sub(4).max(1) as usize;
            let end = (f.line as usize + 6).min(content.lines().count());
            let snip: String = content
                .lines()
                .enumerate()
                .skip(start - 1)
                .take(end - start + 1)
                .map(|(i, l)| format!("{:>5} │ {}", i + 1, l))
                .collect::<Vec<_>>()
                .join("\n");
            snippets.insert(f.id.clone(), snip);
        }
    }
    let tech_tags: Vec<String> = fs::read_to_string(base.join("tech.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let (cost_usd, tokens) = run_totals(&ledger)?;
    let cost_summary = Some(format!(
        "本次审计成本记账：${:.4} · {} tokens（本地订阅模式下美元计费可能为 0）",
        cost_usd, tokens
    ));

    // repo@commit + 审计方式 + agent 标识（模板 Hero 区）
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&root)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "local".to_string());
    let repo_label = format!(
        "{}@{}",
        root.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        commit
    );
    // 溯源：实际跑过哪些阶段、用了哪些模型，全部取自账本（audit-meta.json），
    // 报告不许用自己的硬编码文案描述自己是怎么产出的。
    let meta = ledger.load_audit_meta().map_err(|e| e.to_string())?;
    // 旧账本可能没有 audit-meta.json，但发现已经带模型判定结论——这种情况不许
    // 降级成「AI 未参与」（那是另一句谎），改成如实说阶段记录缺失。
    let judged = findings.iter().filter(|f| f.verdict.is_some()).count();
    let (method, agent_label, scope, mut method_notes) = provenance(&meta, judged, zero_model);
    method_notes.push(format!(
        "展示口径：本次报告按 `--severity {severity}` 过滤（'all' = 全部落账发现）。"
    ));
    let data = fiora_report::ReportData {
        project: root
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "project".to_string()),
        repo_label,
        method,
        agent_label,
        generated_at: fiora_core::util::now_iso(),
        scope,
        tech_tags,
        snippets,
        cost_summary,
        findings,
        chains,
        evidence,
        coverage,
        surface: rows,
        method_notes,
    };

    let html = fiora_report::render_html(&data);
    let out_path = out
        .map(|o| {
            let p = PathBuf::from(o);
            // --out 既能给目录（SKILL/文档契约 `--out DIR`）也能给 .html 文件名：
            // 目录就写 report.html 进去，此前直接把目录当文件写报
            // 「Is a directory (os error 21)」（工作台 Agent 实测撞上）。
            if o.to_string_lossy().ends_with('/') || p.is_dir() {
                p.join("report.html")
            } else {
                p
            }
        })
        // 交付物放可见目录（fiora-report/）——.fiora 是数据目录，报告要好找
        .unwrap_or_else(|| root.join("fiora-report").join("report.html"));
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&out_path, html).map_err(|e| e.to_string())?;
    println!("report: {}", out_path.display());

    // CI / IDE 出口：SARIF 2.1.0（真值来源与 HTML 同一份 ReportData）。
    if let Some(path) = sarif {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(path, fiora_report::render_sarif(&data)).map_err(|e| e.to_string())?;
        println!("sarif: {}", path.display());
    }

    // 机器可读出口：验证就绪清单（Agent 程序化消费，插件契约）。
    let json_path = out_path.with_extension("json");
    let json = fiora_report::render_json(&data);
    fs::write(&json_path, json).map_err(|e| e.to_string())?;
    let tasks = fiora_report::build_checklist(&data.findings);
    println!(
        "verify checklist: {} → {} 条验证任务（Agent 消费 report.json 驱动验证）",
        json_path.display(),
        tasks.len()
    );

    // CI 门禁：展示范围之外的发现也要拦住构建（--fail-on 独立于 --severity）。
    if let Some(level) = fail_on {
        let hits = ledger
            .list_finding_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|id| ledger.load_finding(&id).ok().flatten())
            .filter(|f| fiora_core::family::passes_severity(f, level))
            .count();
        if hits > 0 {
            return Err(format!(
                "gate: {hits} 条发现达到或超过 `{level}`（--fail-on {level}）——构建失败",
            ));
        }
        println!("gate: 无发现达到 `{level}`，通过");
    }
    Ok(())
}

/// 报告的审计方式/生成者/范围，全部由账本里的 audit-meta 推导。
fn provenance(
    meta: &Option<fiora_core::AuditMeta>,
    judged: usize,
    zero_model: bool,
) -> (String, String, String, Vec<String>) {
    const BASE_NOTES: [&str; 4] = [
        "分工哲学：工具管「查得全」，AI 管「判得准」，框架编排管「不漏审」。",
        "判定协议：三者齐备（sink × source × entry）+ 六问强制反驳，反驳不掉才报。",
        "证据等级：dataflow-verified > callchain-verified > inferred > dead-code，断链显式暴露。",
        "候选 100% 落账：每条候选都有结论或显式的「未审」行；AI 拒答留痕可补审。",
    ];
    let Some(meta) = meta else {
        let mut notes: Vec<String> = BASE_NOTES.iter().map(|s| s.to_string()).collect();
        if judged > 0 {
            notes.push(format!(
                "本账本缺少阶段记录（audit-meta.json，旧版账本）：{judged} 条发现带模型判定结论，\
                 但所用模型与阶段未记录；重跑 `fiora process` 会补记。"
            ));
            return (
                "规则扫描 + AI 判定（阶段记录缺失，模型未记录）。".to_string(),
                format!(
                    "Fiora v{} · 判定结论存在但模型未知",
                    env!("CARGO_PKG_VERSION")
                ),
                "全仓代码审计（模型/阶段未记录）".to_string(),
                notes,
            );
        }
        notes.push("本账本无 AI 阶段记录：结论仅为候选/证据级，未经模型判定与复核。".to_string());
        return (
            "规则扫描（内嵌 OpenGrep）。本次未运行 AI 深审阶段。".to_string(),
            format!("Fiora v{} · 规则通道（零模型）", env!("CARGO_PKG_VERSION")),
            "全仓静态扫描（规则通道候选 + 证据链），AI 判定未参与".to_string(),
            notes,
        );
    };

    fn stage_label(s: &str) -> &str {
        match s {
            "scan" => "规则扫描",
            "explore" => "AI 自挖掘",
            "process" => "AI 深审（三者齐备/六问反驳）",
            "revalidate" => "对抗性复核",
            "verify" => "差分验证",
            other => other,
        }
    }
    let stages = if meta.stages.is_empty() {
        "规则扫描".to_string()
    } else {
        meta.stages
            .iter()
            .map(|s| stage_label(s))
            .collect::<Vec<_>>()
            .join(" + ")
    };
    let scope = if meta.severity_scope == "all" {
        "全仓代码审计（全部严重度）"
    } else {
        "全仓代码审计（高危及以上深审）"
    };
    let agent_label = if meta.models.is_empty() {
        format!(
            "Fiora v{} · 规则通道 + 确定性守卫（零模型）",
            env!("CARGO_PKG_VERSION")
        )
    } else {
        format!(
            "Fiora v{} · 模型 {}（pi 会话驱动）",
            env!("CARGO_PKG_VERSION"),
            meta.models.join(", ")
        )
    };
    let mut notes: Vec<String> = BASE_NOTES.iter().map(|s| s.to_string()).collect();
    if zero_model {
        // 报告是重渲染的：模型名属于账本里的历史判定轮次，不是这份工件的作者
        if judged > 0 {
            notes.push(format!(
                "本次交付零模型：HTML 由 scan + evidence 通道重渲染，其中 {judged} 条判定结论来自账本既有记录（{}）；未再次调用模型。",
                if meta.models.is_empty() {
                    "模型未记录".to_string()
                } else {
                    meta.models.join(", ")
                }
            ));
        } else {
            notes.push(
                "本次交付零模型：全部发现为规则候选 + 证据骨架，未产生任何判定结论。".to_string(),
            );
        }
        return (
            format!("本次交付：规则扫描 + 证据装配（零模型）· 账本阶段：{stages}"),
            format!(
                "Fiora v{} · 零模型交付（scan + evidence）",
                env!("CARGO_PKG_VERSION")
            ),
            format!("{scope} · 账本更新于 {}", meta.updated_at),
            notes,
        );
    }
    if meta.stages.iter().any(|s| s == "revalidate") {
        notes.push("复核：HIGH+ 的 TP/uncertain 经独立 session 对抗性复核，可改判。".to_string());
    }
    if meta.stages.iter().any(|s| s == "verify") {
        notes.push(
            "动态验证：结论由工作台 Agent 环境实测后回填（`fiora verify record`）。".to_string(),
        );
    }
    // 只有真的跑过判定/复核才写进方法描述；只扫不判的报告必须自述「仅候选」。
    let ran_judge = meta.stages.iter().any(|s| s == "process");
    let pipeline = if ran_judge {
        "流水线：候选 → 判定 → 复核"
    } else {
        "流水线：仅候选（未运行判定阶段）"
    };
    (
        format!("{stages}（{pipeline}）"),
        agent_label,
        format!("{scope} · 生成于 {}", meta.updated_at),
        notes,
    )
}
