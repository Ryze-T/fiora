//! `fiora pipeline` 命令组（DESIGN.md §2）。

use crate::support::Repo;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use fiora_core::{id, Ledger};
use fiora_processor::ThinkingLevel;
use fiora_scanner::{
    detect_tech, enumerate_surface, normalize, opengrep, RuleRegistry, SurfaceEntry,
};

use crate::support::{dirs_fiora, parse_thinking};

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_run(
    root: &Path,
    profile: Option<&str>,
    model: Option<String>,
    thinking: Option<&str>,
    workers: usize,
    no_ai: bool,
    severity: &str,
    explore_override: Option<usize>,
) -> Result<(), String> {
    crate::support::validate_severity(severity)?;
    // 深度永远全量（覆盖率是承诺）：探索预算=自动全量覆盖、多轮深挖默认开。
    // 资源调节阀是 --severity（严重度范围），不是深度。
    let (explore_budget, explore_rounds): (Option<usize>, usize) = match explore_override {
        Some(0) => (Some(0), 2),
        Some(n) => (Some(n), 2),
        None => (None, 2),
    };
    println!("== fiora run ==");
    cmd_scan(root)?;
    if no_ai {
        // 零模型也能出交付物：候选 → 证据骨架 → 报告。没跑判定就在报告的
        // provenance 里写清楚（账本阶段记录会自动体现）。
        println!("(ai stages skipped: scan + evidence + report)");
        cmd_evidence(root)?;
        // zero_model = true：这份报告不带模型作者，判定结论若有也来自账本旧记录
        super::report::cmd_report_with(root, None, severity, None, None, true)?;
        return Ok(());
    }
    // L2 项目画像（Agent Native）：模型读仓库提取画像 + 历史 CVE 模式 + 狩猎优先级，
    // 落账后供判定/探索/组合三个会话复用；已存在则沿用（--refresh 重提）。
    let base = root.join(".fiora");
    if !base.join("profile.json").exists() {
        match super::agent::cmd_profile(root, model.clone(), false) {
            Ok(()) => {}
            Err(e) => println!("profile: 画像提取失败（{e}），继续无画像跑"),
        }
    } else {
        println!("profile: 沿用既有 .fiora/profile.json（fiora profile --refresh 重提）");
    }
    // L2 语义探索通道：规则面之外的 AI 自挖（预算自动，深度由 --depth 控制）
    match explore_budget {
        Some(0) => {}
        b => {
            let label = match b {
                Some(n) => format!("{n}"),
                None => "auto".to_string(),
            };
            println!("== explore (budget {label}, rounds {explore_rounds}) ==");
            super::agent::cmd_explore(
                root,
                b,
                explore_rounds,
                model.clone(),
                thinking.unwrap_or("high"),
                workers,
            )?;
        }
    }
    cmd_evidence(root)?;
    let model_for_compose = model.clone();
    cmd_process(
        root, profile, model, thinking, None, workers, true, None, severity,
    )?;
    cmd_chain(root)?;
    // 组合狩猎（super-0day 面）：发现之间找链——观察 ≥3 条时自动触发
    {
        let ledger = fiora_core::Ledger::open(root.join(".fiora")).map_err(|e| e.to_string())?;
        let n = ledger.list_finding_ids().map_err(|e| e.to_string())?.len();
        if n >= 3 {
            println!("== compose（组合假设搜索）== ");
            let _ =
                super::compose::cmd_compose(root, model_for_compose, thinking.unwrap_or("xhigh"));
        }
    }
    // 验证由工作台 Agent 完成（`fiora verify record` 回填），管线不再自动 prove。
    // 报告展示范围跟随 run 的 --severity（默认 high = 只看高危及以上）。
    super::report::cmd_report(root, None, severity, None, None)?;
    println!("== done ==");
    Ok(())
}

pub(crate) fn cmd_scan(root: &Path) -> Result<(), String> {
    let Repo { root, base, ledger } = Repo::open(root)?;

    let tech = detect_tech(&root);
    crate::support::write_json(&base, "tech.json", &tech.tags)?;
    println!("tech: {}", tech.tags.join(", "));

    let surface = enumerate_surface(&root);
    crate::support::write_json(&base, "surface.json", &surface)?;
    println!("surface: {} entries", surface.len());
    ledger
        .record_audit_stage("scan", None, "all")
        .map_err(|e| e.to_string())?;

    let user_dir = dirs_fiora().join("rules");
    let project_dir = base.join("rules");
    // 内置规则的「可编辑副本」高级优先于编译进二进制的语料：不同步就会把新版本
    // 的规则修复静默否决掉（旧副本永远赢）。同步失败不阻断扫描。
    match fiora_scanner::sync_builtin_copies(&user_dir) {
        Ok(sync) => {
            if !sync.refreshed.is_empty() {
                println!(
                    "rules: {} builtin rule file(s) refreshed from this binary",
                    sync.refreshed.len()
                );
            }
            for name in &sync.kept_customized {
                println!("rules: {name} kept AS EDITED (overrides the bundled rule)");
            }
        }
        Err(e) => println!("rules: could not refresh builtin copies ({e})"),
    }
    let registry = RuleRegistry::load(Some(&user_dir), Some(&project_dir))
        .map_err(|e| format!("rules: {e}"))?;
    println!(
        "rules: {} loaded (builtin < user < project)",
        registry.len()
    );

    let runtime = dirs_fiora().join("runtime");
    match opengrep::find_binary(Some(&runtime)) {
        None => {
            println!("opengrep: binary not found — rule channel skipped this run");
        }
        Some(bin) => {
            let cache = base.join("cache").join("rules");
            let rule_dirs = registry.config_dirs(&cache).map_err(|e| e.to_string())?;
            let report =
                opengrep::scan(&bin, &rule_dirs, &root).map_err(|e| format!("opengrep: {e}"))?;
            let warned = report.warn_errors();
            if warned > 0 {
                println!(
                    "opengrep: {warned} analysis warning(s) — some files/rules were not analysed"
                );
                for line in report.warn_summaries(3) {
                    println!("  {line}");
                }
                if warned > 3 {
                    println!("  … {} more", warned - 3);
                }
            }
            let cands = normalize(&report, &root.to_string_lossy());

            let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
            for c in &cands {
                *by_rule.entry(c.matcher_id.clone()).or_default() += 1;
            }
            let mut by_file: BTreeMap<String, Vec<fiora_core::Candidate>> = BTreeMap::new();
            for c in cands {
                by_file.entry(c.file.clone()).or_default().push(c);
            }
            for (file, list) in &by_file {
                ledger.init_file(file).map_err(|e| e.to_string())?;
                ledger
                    .replace_rule_candidates(file, list.clone())
                    .map_err(|e| e.to_string())?;
            }
            println!(
                "opengrep: {} candidates across {} files",
                by_rule.values().sum::<usize>(),
                by_file.len()
            );
            for (rule, n) in by_rule.iter().take(20) {
                println!("  {n:>5}  {rule}");
            }
        }
    }
    println!(
        "ledger: {} files tracked",
        ledger.list_files().map_err(|e| e.to_string())?.len()
    );
    Ok(())
}

pub(crate) fn cmd_evidence(root: &Path) -> Result<(), String> {
    let Repo { root, base, ledger } = Repo::open(root)?;
    let surface: Vec<SurfaceEntry> = crate::support::surface(&base);

    let mut total = 0;
    // 一次收集全部候选、一次装配：pre_assemble 内部会把全仓解析成调用图
    // （tree-sitter 全量），逐文件调用 = 每文件重建一次全仓索引——6k 文件级
    // 大型仓库上实测 O(n²)（12 个/分钟），且断点续跑每次都重算。
    // 已装配（evidence_id 已在）的候选直接跳过。
    let mut per_file: Vec<(String, Vec<fiora_core::Candidate>)> = Vec::new();
    let mut pending: Vec<fiora_core::Candidate> = Vec::new();
    for rel in ledger.list_files().map_err(|e| e.to_string())? {
        let Some(rec) = ledger.load_file(&rel).map_err(|e| e.to_string())? else {
            continue;
        };
        if rec.candidates.is_empty() {
            continue;
        }
        for c in &rec.candidates {
            if c.evidence_id.is_none() {
                pending.push(c.clone());
            }
        }
        per_file.push((rel, rec.candidates));
    }
    let map = if pending.is_empty() {
        Default::default()
    } else {
        fiora_evidence::pre_assemble(&pending, &surface, &root)
    };
    for (rel, cands) in per_file {
        let mut updated = Vec::new();
        for mut c in cands {
            if c.evidence_id.is_none() {
                if let Some(ev) = map.get(&c.id) {
                    ledger.save_evidence(ev).map_err(|e| e.to_string())?;
                    c.evidence_id = Some(ev.id.clone());
                    total += 1;
                }
            }
            updated.push(c);
        }
        ledger
            .merge_candidates(&rel, updated)
            .map_err(|e| e.to_string())?;
    }
    println!("evidence: {total} skeletons pre-assembled");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_process(
    root: &Path,
    profile: Option<&str>,
    model: Option<String>,
    thinking: Option<&str>,
    budget_model: Option<String>,
    workers: usize,
    revalidate: bool,
    max_cost_usd: Option<f64>,
    severity: &str,
) -> Result<(), String> {
    crate::support::validate_severity(severity)?;
    let Repo { root, base, ledger } = Repo::open(root)?;
    let proj = crate::support::config(&base);
    // 模型解析：CLI --model/--budget-model > --profile/active_profile 档位 > 默认槽
    let resolved = proj.resolve_models(model, budget_model, profile);
    let model = resolved.judge;
    let budget_model = resolved.budget;
    println!(
        "models:   judge={:?} budget={:?} profile={:?}",
        model, budget_model, resolved.profile
    );
    let thinking = parse_thinking(
        thinking.unwrap_or(&resolved.thinking.unwrap_or(proj.thinking_level.clone())),
    )?;
    // 单点装配：pi 二进制 + 凭据注入（此前只有判定通道注入，其余通道裸奔）
    let runner = crate::support::model_runner(&base, model.as_deref())?;

    let tech: Vec<String> = fs::read_to_string(base.join("tech.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let info_md = fiora_processor::load_info_md(&root);
    let hunt_memo = crate::support::hunt_memo(&base);
    let prompts_dir = dirs_fiora().join("prompts");

    let cfg = fiora_processor::ProcessConfig {
        severity_scope: severity.to_string(),
        batch_files: 5,
        workers,
        model,
        thinking,
        budget_model,
        budget_thinking: ThinkingLevel::Medium,
        revalidate,
        max_cost_usd,
    };
    let run_id = format!(
        "run-{}",
        id::stable_id("r", &[&fiora_core::util::now_iso()])
    );
    ledger
        .record_audit_stage("process", cfg.model.as_deref(), severity)
        .map_err(|e| e.to_string())?;
    let summary = fiora_processor::process_pending(
        &fiora_processor::RunContext {
            runner: &runner,
            root: &root,
            ledger: &ledger,
            run_id: &run_id,
            prompts_dir: Some(&prompts_dir),
            tech_tags: &tech,
            info_md: &info_md,
            hunt_memo: hunt_memo.as_deref(),
        },
        &cfg,
    )
    .map_err(|e| format!("process: {e}"))?;

    if summary.revalidated > 0 {
        ledger
            .record_audit_stage("revalidate", cfg.model.as_deref(), severity)
            .map_err(|e| e.to_string())?;
    }
    println!(
        "process: {} batch(es), {} file(s), {} finding(s), {} revalidated, {} refusal(s), cost ${:.4} · {} in/{} out tokens",
        summary.batches,
        summary.files_analyzed,
        summary.findings,
        summary.revalidated,
        summary.refusals,
        summary.cost.usd,
        summary.cost.tokens_in,
        summary.cost.tokens_out
    );
    Ok(())
}

pub(crate) fn cmd_chain(root: &Path) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;
    let ledger = Ledger::open(root.join(".fiora")).map_err(|e| format!("ledger: {e}"))?;
    let findings = crate::support::findings(&ledger)?;
    let chains = fiora_processor::compose_chains(&findings);
    let n = fiora_processor::persist_chains(&ledger, &chains).map_err(|e| e.to_string())?;
    println!(
        "chain: {n} chain(s) composed from {} finding(s)",
        findings.len()
    );
    Ok(())
}
