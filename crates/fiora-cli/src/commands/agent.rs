//! `fiora agent` 命令组（DESIGN.md §2）。

use crate::support::Repo;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use fiora_core::Ledger;
use fiora_processor::{ExploreBudget, PiRunner, SemanticChannel, ThinkingLevel};
use fiora_scanner::SurfaceEntry;

use crate::support::{dirs_fiora, parse_thinking};

/// 每会话模块数（盲扫分区大小）。
const MODULES_PER_SESSION: usize = 8;

/// 盲扫会话数：**全量覆盖**（覆盖率是承诺，不是选项），不封顶。
fn sweep_sessions(uncovered: usize) -> usize {
    uncovered.div_ceil(MODULES_PER_SESSION).max(1)
}

/// 自动探索预算 = 盲扫会话 + 假设驱动会话（有 plan 时留 50% 增量）。
/// 关键：假设会话由**额外**预算承担，不再从盲扫里切——否则「全量覆盖」是假的。
fn auto_explore_budget(uncovered: usize, with_plan: bool) -> usize {
    let sweep = sweep_sessions(uncovered);
    if with_plan {
        sweep + sweep.div_ceil(2).max(1)
    } else {
        sweep
    }
}

pub(crate) fn cmd_explore(
    root: &Path,
    budget: Option<usize>,
    rounds: usize,
    model: Option<String>,
    thinking: &str,
    jobs: usize,
) -> Result<(), String> {
    let Repo { root, ledger, .. } = Repo::open(root)?;
    let thinking = parse_thinking(thinking)?;
    // 模型回落：--model 缺省时用项目配置的默认模型（与 run/process 一致）
    let model = model.or_else(|| crate::support::config(&root.join(".fiora")).default_model);

    let source_files = fiora_core::fsutil::list_files(
        &root,
        &["go", "py", "ts", "tsx", "js", "jsx", "java", "kt"],
    )
    .map_err(|e| e.to_string())?;
    let covered = covered_files(&root)?;
    let covered_list: Vec<String> = covered.iter().cloned().collect();
    let uncovered: Vec<String> = source_files
        .iter()
        .map(|(rel, _)| rel.clone())
        .filter(|rel| !covered.contains(rel))
        .collect();
    let user_budget = budget;
    let want_plan = user_budget
        .map(|b| b >= 3)
        .unwrap_or(sweep_sessions(uncovered.len()) >= 2);
    println!(
        "explore: {} source files, {} covered, {} uncovered -> {} sweep session(s){}{}",
        source_files.len(),
        covered.len(),
        uncovered.len(),
        sweep_sessions(uncovered.len()),
        match user_budget {
            Some(b) => format!(", budget {b}"),
            None => ", auto".to_string(),
        },
        if want_plan { ", +plan" } else { "" }
    );
    // 预算无界时先报数再花钱：auto 在大仓库上是几百上千个模型会话，
    // 操作者必须在第一笔模型消耗之前知道规模，并有机会收敛。
    let est = auto_explore_budget(uncovered.len(), want_plan);
    if user_budget.is_none() && est > 20 {
        println!(
            "explore: auto 预算 = {est} 个模型会话（未覆盖 {} 文件）——大仓库请先估算；收敛用 --explore <N>，跳过用 --explore 0",
            uncovered.len()
        );
    }

    let runner = resolve_runner(&root.join(".fiora"), model.as_deref())?;
    let prompts_dir = dirs_fiora().join("prompts");
    let channel = SemanticChannel {
        runner: &runner,
        prompts_dir: Some(&prompts_dir),
        model: model.clone(),
        thinking,
        jobs,
    };
    // 狩猎回路：轮 1 广扫（hunting protocol），轮 2+ 沿线索深挖（多跳/组合变体）。
    // hunt journal（.fiora/hunt.md）是跨轮记忆：线索与覆盖核算逐轮追加。
    let rounds = rounds.max(1);
    let tech_tags = fiora_scanner::detect_tech(&root).tags;

    // ---- plan/execute 分离：先出狩猎计划（假设清单），执行会话按假设分工 ----
    let mut hunt_plan: Vec<fiora_processor::HuntHypothesis> = Vec::new();
    if want_plan && !uncovered.is_empty() {
        let surface_summary = {
            let p = root.join(".fiora").join("surface.json");
            std::fs::read_to_string(&p)
                .unwrap_or_default()
                .chars()
                .take(4000)
                .collect::<String>()
        };
        let req = fiora_processor::PiRequest {
            prompt: fiora_processor::prompts::hunt_plan_prompt(
                &tech_tags,
                &surface_summary,
                &uncovered,
            ),
            model: model.clone(),
            thinking: Some(thinking),
            name: Some("fiora-hunt-plan".to_string()),
            session_dir: Some(root.join(".fiora").join("sessions")),
            system_prompt: None,
            timeout: None,
            tools: None,
        };
        match runner.run(&root, &req) {
            Ok(outcome) => {
                let parsed = fiora_processor::parse_plan(&outcome.text).unwrap_or_default();
                if parsed.is_empty() {
                    // 单次修复回路（带任务上下文），失败则退化为盲扫。
                    // 静默零假设 = 违反落账契约：失败原因必须可见。
                    let repair = fiora_processor::PiRequest {
                        prompt: fiora_processor::json_repair_prompt(&req.prompt, &outcome.text),
                        ..req.clone()
                    };
                    if let Ok(fixed) = runner.run(&root, &repair) {
                        hunt_plan = fiora_processor::parse_plan(&fixed.text).unwrap_or_default();
                    }
                    if hunt_plan.is_empty() {
                        let snippet: String = outcome.text.chars().take(400).collect();
                        println!("plan: 假设解析为空——原始输出片段：{snippet:?}");
                    }
                } else {
                    hunt_plan = parsed;
                }
                println!("plan: {} hypotheses（plan/execute 分离）", hunt_plan.len());
            }
            Err(e) => println!("plan: 规划会话失败（{e}）——退化为盲扫"),
        }
    }
    // 预算口径：轮 1 拿满额（盲扫 + 假设会话），轮 2+ 深挖按线索数另计，
    // 这样「全量覆盖」与「多轮深挖」互不挪用。
    let budget =
        user_budget.unwrap_or_else(|| auto_explore_budget(uncovered.len(), !hunt_plan.is_empty()));
    let mut journal = String::new();
    let mut all_cands: Vec<fiora_core::Candidate> = Vec::new();
    let mut leads: Vec<fiora_processor::SemanticFinding> = Vec::new();

    for round in 0..rounds {
        if round == 0 {
            let report = channel
                .explore(
                    &root,
                    &uncovered,
                    &covered_list,
                    &ExploreBudget {
                        max_sessions: budget,
                        modules_per_session: MODULES_PER_SESSION,
                    },
                    if hunt_plan.is_empty() {
                        None
                    } else {
                        Some(&hunt_plan)
                    },
                )
                .map_err(|e| format!("semantic channel: {e}"))?;
            println!(
                "explore: swept {} module(s) in {} session(s){}",
                report.swept_modules,
                report.session_ids.len(),
                if report.hypotheses_dropped > 0 {
                    format!(
                        "（预算不足，{} 条假设未分配会话：加大 --budget）",
                        report.hypotheses_dropped
                    )
                } else {
                    String::new()
                }
            );
            // 失败/无账的会话绝不冒领覆盖——沉默不是证据。
            if report.sessions_failed > 0 || report.sessions_unverified > 0 {
                println!(
                    "explore: {} 会话失败、{} 会话未交回覆盖账——这些模块**未**被扫过",
                    report.sessions_failed, report.sessions_unverified
                );
                for note in report.failure_notes.iter().take(3) {
                    println!("  {note}");
                }
                if report.failure_notes.len() > 3 {
                    println!("  … {} more", report.failure_notes.len() - 3);
                }
            }
            if !report.coverage.is_empty() {
                let clean = report
                    .coverage
                    .iter()
                    .filter(|c| c.status == "clean")
                    .count();
                println!(
                    "explore: coverage ledger {} module(s), {} clean",
                    report.coverage.len(),
                    clean
                );
            }
            journal.push_str(&format!(
                "## round 1（广扫）· {} 候选 · 扫过 {} 模块 · {} 会话失败 · {} 会话未交账\n",
                report.candidates.len(),
                report.swept_modules,
                report.sessions_failed,
                report.sessions_unverified
            ));
            for note in &report.failure_notes {
                journal.push_str(&format!("- 失败 {note}\n"));
            }
            if !report.coverage.is_empty() {
                journal.push_str("\n### 覆盖核算（Phase 4）\n");
                for note in &report.coverage {
                    journal.push_str(&format!(
                        "- [{}] {}：{}\n",
                        note.status, note.module, note.reason
                    ));
                }
            }
            if !report.session_ids.is_empty() {
                journal.push_str(&format!(
                    "\n### 会话轨迹（`fiora trace <id>`）\n{}\n",
                    report.session_ids.join(", ")
                ));
            }
            let cands = report.candidates;
            for c in &cands {
                journal.push_str(&format!(
                    "- 线索 {}:{} {}\n",
                    c.file,
                    c.line,
                    c.note.as_deref().unwrap_or("")
                ));
                leads.push(fiora_processor::SemanticFinding {
                    file: c.file.clone(),
                    line: c.line,
                    slug: c.slug.clone(),
                    note: c.note.clone().unwrap_or_default(),
                    snippet: c.snippet.clone(),
                });
            }
            all_cands.extend(cands);
        } else {
            // 深挖轮：每条线索一个会话（并发），沿数据流 2-3 跳、查组合变体
            let mut round_found = 0usize;
            let deep_queue = std::sync::Mutex::new(
                leads
                    .iter()
                    .take(budget)
                    .enumerate()
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            let deep_out: std::sync::Mutex<Vec<(usize, Vec<fiora_processor::SemanticFinding>)>> =
                std::sync::Mutex::new(Vec::new());
            let jobs_n = jobs.clamp(1, 16);
            std::thread::scope(|s| {
                for _ in 0..jobs_n {
                    s.spawn(|| loop {
                        let next = { deep_queue.lock().unwrap().next() };
                        let Some((i, lead)) = next else { break };
                        let prompt = deepdive_prompt(lead, &journal);
                        let req = fiora_processor::PiRequest {
                            prompt,
                            model: model.clone(),
                            thinking: Some(thinking),
                            name: Some(format!("fiora-deepdive-{round}-{i}")),
                            session_dir: Some(root.join(".fiora").join("sessions")),
                            system_prompt: None,
                            timeout: None,
                            tools: None,
                        };
                        match runner.run(&root, &req) {
                            Ok(outcome) => {
                                let found = fiora_processor::parse_findings(&outcome.text)
                                    .unwrap_or_default();
                                deep_out.lock().unwrap().push((i, found));
                            }
                            Err(e) => eprintln!("deepdive session {i} failed: {e}"),
                        }
                    });
                }
            });
            let mut merged_deep = deep_out.into_inner().unwrap();
            merged_deep.sort_by_key(|(i, _)| *i);
            for (_, found) in merged_deep {
                round_found += found.len();
                for f in found {
                    journal.push_str(&format!(
                        "- 深挖[{}] {}:{} {}\n",
                        round + 1,
                        f.file,
                        f.line,
                        f.note
                    ));
                    all_cands.push(semantic_to_candidate(f));
                }
            }
            journal.push_str(&format!(
                "## round {}（深挖）· {} 新候选\n",
                round + 1,
                round_found
            ));
        }
    }

    if !hunt_plan.is_empty() {
        journal.push_str("\n## hunt plan（plan/execute 分离：执行会话按此分工）\n");
        for h in &hunt_plan {
            journal.push_str(&format!(
                "- [{}] {} @ {}：{}\n",
                h.id,
                h.area,
                h.targets.join(","),
                h.claim
            ));
        }
    }
    // hunt journal 落盘（跨轮记忆 + 覆盖核算，审计资产）
    if !journal.is_empty() {
        std::fs::write(root.join(".fiora").join("hunt.md"), &journal)
            .map_err(|e| format!("hunt.md: {e}"))?;
    }

    let mut by_file: BTreeMap<String, Vec<fiora_core::Candidate>> = BTreeMap::new();
    for c in all_cands {
        by_file.entry(c.file.clone()).or_default().push(c);
    }
    for (file, list) in &by_file {
        ledger.init_file(file).map_err(|e| e.to_string())?;
        ledger
            .merge_candidates(file, list.clone())
            .map_err(|e| e.to_string())?;
    }
    ledger
        .record_audit_stage("explore", model.as_deref(), "all")
        .map_err(|e| e.to_string())?;
    println!(
        "explore: {} semantic candidates across {} files ({} rounds, journal: .fiora/hunt.md)",
        by_file.values().map(|v| v.len()).sum::<usize>(),
        by_file.len(),
        rounds
    );
    Ok(())
}

/// 深挖提示词：沿线索追数据流 2-3 跳、查组合变体（0day 常在单点安全的组合里）。
fn deepdive_prompt(lead: &fiora_processor::SemanticFinding, journal: &str) -> String {
    format!(
        "You are an elite vulnerability hunter doing a DEEP PROBE of one lead.\n\n         Lead: {{\"file\": \"{}\", \"line\": {}, \"slug\": \"{}\"}}\n         Note: {}\nSnippet: {}\n\n         Hunt journal so far:\n{}\n---\n         Protocol: follow the data 2-3 hops (callers and callees) before concluding.\n         - When the lead looks safe, ask 'who calls it, and with what?'\n         - Check the COMPOSED variant: A safe + B safe can chain into impact.\n         - Report ONLY what survives deep scrutiny (entry -> flow -> impact).\n         - READ-ONLY; cite file:line; reasoning is the product.\n\n         Output STRICT JSON only: {{\"findings\":[...],\"coverage\":[...]}}          (same schema as the hunting protocol; empty findings is a valid outcome).",
        lead.file, lead.line, lead.slug, lead.note, lead.snippet,
        journal.chars().take(4000).collect::<String>()
    )
}

/// 语义发现 → 账本候选（semantic 通道，id 稳定）。
fn semantic_to_candidate(f: fiora_processor::SemanticFinding) -> fiora_core::Candidate {
    use fiora_core::id::stable_id;
    let id = stable_id("s", &[&f.file, &f.line.to_string(), &f.slug, &f.note]);
    fiora_core::Candidate {
        id,
        slug: f.slug.clone(),
        matcher_id: format!("semantic-{}", f.slug),
        channel: fiora_core::CandidateChannel::Semantic,
        file: f.file.clone(),
        line: f.line,
        end_line: None,
        snippet: f.snippet.clone(),
        note: Some(f.note.clone()),
        evidence_id: None,
    }
}

// ---------- helpers ----------

/// 改写类命令的共享批次回路：collect（调用方）→ chunk → 会话（容错回路）→
/// 逐条 apply 回写。refine / enrich / localize 三命令共用的单一实现。
struct RewritePass<'a, P, A> {
    name: &'a str,
    thinking: ThinkingLevel,
    chunk_size: usize,
    prompt_of: P,
    apply: A,
}

fn batch_rewrite(
    root: &Path,
    runner: &PiRunner,
    model: &Option<String>,
    items: Vec<serde_json::Value>,
    pass: RewritePass<
        impl Fn(&str) -> String,
        impl Fn(&Ledger, &serde_json::Value) -> Result<bool, String>,
    >,
) -> Result<usize, String> {
    println!("{}: {} finding(s) to process", pass.name, items.len());
    let ledger = Ledger::open(root.join(".fiora")).map_err(|e| format!("ledger: {e}"))?;
    let mut updated = 0usize;
    for chunk in items.chunks(pass.chunk_size) {
        let req = fiora_processor::PiRequest::simple(
            pass.name,
            (pass.prompt_of)(&serde_json::to_string(chunk).unwrap()),
            model.clone(),
            pass.thinking,
            Some(root.join(".fiora").join("sessions")),
        );
        let out: Vec<serde_json::Value> =
            fiora_processor::run_json_with_repair(runner, root, &req)?;
        for item in &out {
            if (pass.apply)(&ledger, item)? {
                updated += 1;
            }
        }
    }
    Ok(updated)
}

/// 账本收集起点：全部 finding 的（id, Finding）对，按 id 升序。
fn all_findings(root: &Path) -> Result<Vec<fiora_core::Finding>, String> {
    let ledger = Ledger::open(root.join(".fiora")).map_err(|e| format!("ledger: {e}"))?;
    crate::support::findings(&ledger)
}

fn resolve_runner(base: &Path, model: Option<&str>) -> Result<PiRunner, String> {
    crate::support::model_runner(base, model)
}

fn str_field<'a>(item: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    item.get(key).and_then(|v| v.as_str())
}

/// 已覆盖文件集 = 账本里已有候选的文件（HashSet：explore/gen_rules 都按源文件
/// 逐个探测，Vec.contains 是 O(n²)，大仓下这里是热点）。
fn covered_files(root: &Path) -> Result<std::collections::HashSet<String>, String> {
    let ledger = Ledger::open(root.join(".fiora")).map_err(|e| format!("ledger: {e}"))?;
    let mut covered = std::collections::HashSet::new();
    for rel in ledger.list_files().map_err(|e| e.to_string())? {
        if let Some(rec) = ledger.load_file(&rel).map_err(|e| e.to_string())? {
            if !rec.candidates.is_empty() {
                covered.insert(rel);
            }
        }
    }
    Ok(covered)
}

/// 生成层：把「从未产生候选的入口」交给模型起草 Semgrep 规则。
///
/// 与手写规则走**同一条**校验与执行路径（三级注册表 + 内嵌 OpenGrep）：
/// 模型只写 YAML 数据，逐条结构校验，坏规则拒收并给出原因；草稿落在
/// `.fiora/rules-draft/`，人工复核后用 `fiora rules add --project` 入账。
pub(crate) fn cmd_draft_rules(root: &Path, model: Option<String>) -> Result<(), String> {
    use fiora_scanner::RuleRegistry;

    let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;
    let base = root.join(".fiora");
    let runner = resolve_runner(&root.join(".fiora"), model.as_deref())?;

    let surface: Vec<SurfaceEntry> = crate::support::surface(&base);
    let covered = covered_files(&root)?;
    let mut gaps = String::new();
    for e in surface.iter().filter(|e| !covered.contains(&e.file)) {
        gaps.push_str(&format!(
            "- {}:{} {:?} {}\n",
            e.file, e.line, e.kind, e.symbol
        ));
    }
    if gaps.is_empty() {
        println!("draft-rules: 无未覆盖入口（surface 全部已产生候选）");
        return Ok(());
    }
    let tech = fs::read_to_string(base.join("tech.json"))
        .ok()
        .map(|t| t.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let req = fiora_processor::PiRequest {
        prompt: fiora_processor::prompts::rule_draft_prompt(&gaps, &tech),
        model,
        thinking: Some(ThinkingLevel::High),
        name: Some("draft-rules".to_string()),
        session_dir: Some(base.join("sessions")),
        system_prompt: None,
        timeout: None,
        tools: None,
    };
    let outcome = runner.run(&root, &req).map_err(|e| e.to_string())?;
    let yaml = strip_code_fence(&outcome.text);
    if !yaml.contains("rules:") {
        return Err("模型输出不是规则 YAML（缺少 rules: 根键）".to_string());
    }

    // 与 `rules add` 同构：结构校验通过才落盘。
    let draft_dir = base.join("rules-draft");
    fs::create_dir_all(&draft_dir).map_err(|e| e.to_string())?;
    let draft = draft_dir.join("draft.yaml");
    fs::write(&draft, &yaml).map_err(|e| e.to_string())?;
    let registry = RuleRegistry::load(None, Some(&draft_dir)).map_err(|e| {
        let _ = fs::remove_file(&draft);
        format!("规则校验失败（草稿已丢弃）：{e}")
    })?;
    for r in registry.iter() {
        println!("  {} [{:?}] {}", r.spec.id, r.spec.severity, r.spec.message);
    }
    println!(
        "draft-rules: {} 条规则草稿 -> {}（复核后 `fiora rules add {} --project`）",
        registry.len(),
        draft.display(),
        draft.display()
    );
    Ok(())
}

fn strip_code_fence(text: &str) -> String {
    let t = text.trim();
    let body = match t.strip_prefix("```") {
        Some(rest) => {
            let rest = rest.split_once('\n').map(|(_, b)| b).unwrap_or(rest);
            rest.strip_suffix("```").unwrap_or(rest)
        }
        None => t,
    };
    body.trim().to_string()
}

pub(crate) fn cmd_refine(root: &Path, model: Option<String>) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;
    let runner = resolve_runner(&root.join(".fiora"), model.as_deref())?;

    let items: Vec<serde_json::Value> = all_findings(&root)?
        .into_iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "description": f.description,
                "impact": f.impact,
                "reasoning": f.verdict.as_ref().map(|v| v.reasoning.clone()).unwrap_or_default(),
            })
        })
        .collect();

    let updated = batch_rewrite(
        &root,
        &runner,
        &model,
        items,
        RewritePass {
            name: "refine",
            thinking: ThinkingLevel::Low,
            chunk_size: 8,
            prompt_of: fiora_processor::prompts::refine_prompt,
            apply: |ledger: &Ledger, item: &serde_json::Value| {
                let Some(id) = str_field(item, "id") else {
                    return Ok(false);
                };
                ledger
                    .rewrite_text_full(
                        id,
                        None,
                        str_field(item, "description"),
                        str_field(item, "reasoning"),
                        None,
                        str_field(item, "impact"),
                        None,
                    )
                    .map_err(|e| e.to_string())?;
                Ok(true)
            },
        },
    )?;
    println!("refine: {updated} finding(s) refined to short-sentence points");
    Ok(())
}

pub(crate) fn cmd_enrich(root: &Path, model: Option<String>) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;
    let runner = resolve_runner(&root.join(".fiora"), model.as_deref())?;

    let items: Vec<serde_json::Value> = all_findings(&root)?
        .into_iter()
        .filter(|f| f.impact.is_none() || f.repro_pack.is_none())
        .map(|f| {
            let poc_hint = match fiora_processor::verdict::poc_kind(&f) {
                fiora_processor::verdict::PocKind::CodeExec => {
                    "触发 harness（喂恶意载荷给危险函数的最小脚本）"
                }
                fiora_processor::verdict::PocKind::Network => "curl/HTTP 请求模板",
                fiora_processor::verdict::PocKind::FileOp => "文件路径操作序列",
                fiora_processor::verdict::PocKind::Logic => "请求模板或推演步骤",
            };
            serde_json::json!({
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "poc_form_hint": poc_hint,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "description": f.description,
                "data_flow": f.data_flow,
                "verdict": f.verdict.as_ref().map(|v| v.conclusion),
                "existing_impact": f.impact,
                "existing_repro": f.repro_pack.is_some(),
            })
        })
        .collect();

    let updated = batch_rewrite(
        &root,
        &runner,
        &model,
        items,
        RewritePass {
            name: "enrich",
            thinking: ThinkingLevel::Medium,
            chunk_size: 5,
            prompt_of: fiora_processor::prompts::enrich_prompt,
            apply: |ledger: &Ledger, item: &serde_json::Value| {
                let Some(id) = str_field(item, "id") else {
                    return Ok(false);
                };
                // tolerant repro parsing: one missing field must not kill the PoC
                let repro = item.get("repro_pack").and_then(|r| {
                    let str_or = |k: &str| -> String {
                        r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
                    };
                    let request = str_or("request");
                    if request.trim().is_empty() {
                        None // no request, no PoC — surface as missing instead of garbage
                    } else {
                        let preconditions = r
                            .get("preconditions")
                            .map(|p| match p {
                                serde_json::Value::Array(a) => a
                                    .iter()
                                    .filter_map(|x| x.as_str().map(str::to_string))
                                    .collect(),
                                serde_json::Value::String(s) => vec![s.clone()],
                                _ => vec![],
                            })
                            .unwrap_or_default();
                        Some(fiora_core::ReproPack {
                            preconditions,
                            request,
                            expected: str_or("expected"),
                            actual: str_or("actual"),
                            status: match str_or("status").as_str() {
                                "verified" => fiora_core::ReproStatus::Verified,
                                "todo" => fiora_core::ReproStatus::Todo,
                                _ => fiora_core::ReproStatus::Inferred,
                            },
                        })
                    }
                });
                if item.get("repro_pack").is_some() && repro.is_none() {
                    eprintln!(
                        "enrich: warning — repro for {id} unusable (no request), left as missing"
                    );
                }
                ledger
                    .rewrite_text_full(id, None, None, None, None, str_field(item, "impact"), repro)
                    .map_err(|e| e.to_string())?;
                Ok(true)
            },
        },
    )?;
    println!("enrich: {updated} finding(s) enriched with impact + PoC");
    Ok(())
}

pub(crate) fn cmd_localize(root: &Path, model: Option<String>) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;
    let runner = resolve_runner(&root.join(".fiora"), model.as_deref())?;

    let items: Vec<serde_json::Value> = all_findings(&root)?
        .into_iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "reasoning": f.verdict.as_ref().map(|v| v.reasoning.clone()).unwrap_or_default(),
                "notes": f.verdict.as_ref().map(|v| v.rebuttals.notes.clone()).unwrap_or_default(),
            })
        })
        .collect();

    let updated = batch_rewrite(
        &root,
        &runner,
        &model,
        items,
        RewritePass {
            name: "localize",
            thinking: ThinkingLevel::Low,
            chunk_size: 12,
            prompt_of: fiora_processor::prompts::localize_prompt,
            apply: |ledger: &Ledger, item: &serde_json::Value| {
                let Some(id) = str_field(item, "id") else {
                    return Ok(false);
                };
                ledger
                    .rewrite_text(
                        id,
                        str_field(item, "title"),
                        str_field(item, "description"),
                        str_field(item, "reasoning"),
                        str_field(item, "notes"),
                    )
                    .map_err(|e| e.to_string())?;
                Ok(true)
            },
        },
    )?;
    println!("localize: {updated} finding(s) updated to Chinese");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{auto_explore_budget, sweep_sessions};

    #[test]
    fn explore_budget_guarantees_full_coverage() {
        // 契约：深度永远全量（覆盖率是承诺）——会话数按未覆盖文件量走、不封顶。
        // 每会话 8 个模块：16 文件 → 2 会话，10000 文件 → 1250 会话。
        assert_eq!(sweep_sessions(0), 1, "空仓也给 1 会话（最少）");
        assert_eq!(sweep_sessions(16), 2);
        assert_eq!(sweep_sessions(10000), 1250, "不封顶——多大扫多深");
        // 假设会话是额外预算：盲扫份额不被 plan 挪用（否则覆盖承诺是假的）
        assert_eq!(auto_explore_budget(16, false), 2);
        assert_eq!(auto_explore_budget(16, true), 3);
        assert_eq!(auto_explore_budget(10000, true), 1875);
    }
}
