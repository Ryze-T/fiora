//! Judgment pipeline (DESIGN.md §5): triage -> judge -> revalidate.
//!
//! Anti-leak discipline lives here: every candidate reaches a verdict, refusals
//! are recorded, true-positives must carry traced evidence, and revalidation
//! may flip verdicts. Batch-granularity pi sessions (same-module files judged
//! together); cost accounted per finding.

use std::collections::HashMap;
use std::path::Path;

use fiora_core::{AgentProvenance, Cost, Evidence, EvidenceGrade, FileStatus, Ledger, Verdict};
use fiora_evidence::upgrade_with_chain;

use crate::pi::{PiError, PiRequest, PiRunner, ThinkingLevel};
use crate::prompts::{
    contract_repair_prompt, json_repair_prompt, judge_prompt, load_or_default, revalidate_prompt,
    triage_prompt,
};
use crate::verdict::{entries_to_core, hops_to_core, into_core, parse_judge_output, JudgeOutput};

#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub batch_files: usize,
    /// Parallel judge workers (each claims batches via the TTL lease).
    pub workers: usize,
    /// Deep-judge model (P0/P1 batches).
    pub model: Option<String>,
    pub thinking: ThinkingLevel,
    /// Cheap model for triage and P2 batches; falls back to `model`.
    pub budget_model: Option<String>,
    pub budget_thinking: ThinkingLevel,
    pub revalidate: bool,
    pub max_cost_usd: Option<f64>,
    /// 严重度范围（唯一资源调节阀）："high"=高危及以上全契约、其余精简；"all"=全量全契约。
    pub severity_scope: String,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        ProcessConfig {
            batch_files: 5,
            workers: 1,
            model: None,
            thinking: ThinkingLevel::Xhigh,
            budget_model: None,
            budget_thinking: ThinkingLevel::Medium,
            revalidate: true,
            max_cost_usd: None,
            severity_scope: "high".to_string(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ProcessSummary {
    pub batches: usize,
    pub files_analyzed: usize,
    pub findings: usize,
    pub refusals: usize,
    pub revalidated: usize,
    pub cost: Cost,
}

#[derive(Debug)]
pub enum PipelineError {
    Pi(PiError),
    Io(std::io::Error),
    BudgetExhausted,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Pi(e) => write!(f, "pi: {e}"),
            PipelineError::Io(e) => write!(f, "io: {e}"),
            PipelineError::BudgetExhausted => write!(f, "cost budget exhausted (resumable)"),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<PiError> for PipelineError {
    fn from(e: PiError) -> Self {
        PipelineError::Pi(e)
    }
}
impl From<std::io::Error> for PipelineError {
    fn from(e: std::io::Error) -> Self {
        PipelineError::Io(e)
    }
}

/// Everything a pipeline run needs about where and how to work.
#[derive(Clone, Copy)]
pub struct RunContext<'a> {
    pub runner: &'a PiRunner,
    pub root: &'a Path,
    pub ledger: &'a Ledger,
    pub run_id: &'a str,
    pub prompts_dir: Option<&'a Path>,
    pub tech_tags: &'a [String],
    pub info_md: &'a str,
    /// 模型画像注入块（`.fiora/profile.json` 渲染）：狩猎注意力引导，不作证据。
    pub hunt_memo: Option<&'a str>,
}

pub fn process_pending(
    ctx: &RunContext,
    cfg: &ProcessConfig,
) -> Result<ProcessSummary, PipelineError> {
    let RunContext {
        runner,
        root,
        ledger,
        run_id,
        ..
    } = *ctx;
    let mut summary = ProcessSummary::default();

    // Files without candidates need no AI — anti-leak accounting: an explicit
    // row ("skipped: no candidates"), not silence. They stay open for the
    // semantic channel.
    let mut work: Vec<(String, Vec<fiora_core::Candidate>)> = Vec::new();
    for rel in ledger.pending().map_err(PipelineError::Io)? {
        let Some(rec) = ledger.load_file(&rel).map_err(PipelineError::Io)? else {
            continue;
        };
        if rec.candidates.is_empty() {
            ledger
                .append_analysis(
                    &rel,
                    fiora_core::AnalysisEntry {
                        run_id: run_id.to_string(),
                        agent: agent_prov(run_id, "none", "none", "none", None),
                        at: fiora_core::util::now_iso(),
                        summary: "no candidates from rule channel (eligible for semantic explore)"
                            .to_string(),
                        finding_ids: vec![],
                        refused: None,
                        refusal_note: None,
                    },
                )
                .map_err(PipelineError::Io)?;
            ledger
                .complete(&rel, FileStatus::Skipped)
                .map_err(PipelineError::Io)?;
            continue;
        }
        work.push((rel, rec.candidates));
    }

    // Triage orders the queue (cheap; nothing is discarded).
    let priorities = run_triage(runner, root, &work, cfg)?;
    work.sort_by_key(|(rel, cands)| {
        let best = cands
            .iter()
            .map(|c| match priorities.get(&c.id).map(String::as_str) {
                Some("P0") => 0,
                Some("P1") => 1,
                Some("P2") => 2,
                Some("skip") => 3,
                _ => 1,
            })
            .min()
            .unwrap_or(1);
        (best, rel.clone())
    });

    // Judge stage: worker pool over batch queue. workers=1 is the sequential
    // path (same code, no forks). Each batch is one pi session; each worker
    // claims its files through the lease so crashes cannot double-process.
    let batches: Vec<Vec<(String, Vec<fiora_core::Candidate>)>> =
        work.chunks(cfg.batch_files).map(|c| c.to_vec()).collect();
    let queue = std::sync::Arc::new(std::sync::Mutex::new(batches.into_iter()));
    let cost = std::sync::Arc::new(std::sync::Mutex::new(Cost::zero()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let parts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<BatchPart>::new()));
    let batch_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let first_err = std::sync::Arc::new(std::sync::Mutex::new(None::<PipelineError>));
    let priorities = std::sync::Arc::new(priorities);
    std::thread::scope(|scope| {
        for _ in 0..cfg.workers.max(1) {
            let priorities = &priorities;
            let queue = &queue;
            let cost = &cost;
            let stop = &stop;
            let parts = &parts;
            let batch_counter = &batch_counter;
            let first_err = &first_err;
            scope.spawn(move || loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                if let Some(cap) = cfg.max_cost_usd {
                    if cost.lock().unwrap().usd >= cap {
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
                let batch = queue.lock().unwrap().next();
                let Some(batch) = batch else { break };
                let idx = batch_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                match judge_batch(ctx, cfg, run_id, idx, &batch, priorities) {
                    Ok(part) => {
                        cost.lock().unwrap().merge(&part.cost);
                        parts.lock().unwrap().push(part);
                    }
                    Err(e) => {
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        let mut slot = first_err.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(e);
                        }
                    }
                }
            });
        }
    });

    if let Some(e) = first_err.lock().unwrap().take() {
        return Err(e);
    }
    let mut budget_hit = false;
    for part in parts.lock().unwrap().iter() {
        summary.batches += 1;
        summary.findings += part.findings;
        summary.refusals += part.refusals;
        summary.files_analyzed += part.files;
    }
    {
        let c = cost.lock().unwrap();
        if let Some(cap) = cfg.max_cost_usd {
            budget_hit = c.usd >= cap && summary.batches < work.chunks(cfg.batch_files).count();
        }
        summary.cost = c.clone();
    }
    if budget_hit {
        return Err(PipelineError::BudgetExhausted);
    }

    if cfg.revalidate {
        let mut reval_cost = Cost::zero();
        summary.revalidated = revalidate_all(
            runner,
            root,
            ledger,
            run_id,
            cfg.budget_model.clone().or_else(|| cfg.model.clone()),
            &mut reval_cost,
        )?;
        summary.cost.merge(&reval_cost);
    }

    Ok(summary)
}

/// Absorb judge findings into the ledger: evidence upgrade + finding upsert.
fn absorb(
    root: &Path,
    ledger: &Ledger,
    output: &JudgeOutput,
    agent: &AgentProvenance,
    session_id: Option<&str>,
) -> Result<Vec<String>, PipelineError> {
    let mut ids = Vec::new();
    for f in &output.findings {
        let ev_id = sync_evidence(ledger, f)?;
        let mut finding = into_core(f, agent);
        // 机械核查（五族语义降级 + 已知洞标注）入库前应用——判定层的错误不进账本。
        let file_context = std::fs::read_to_string(root.join(&f.file)).unwrap_or_default();
        crate::guard_check::apply_mechanical_review(&mut finding, &file_context);
        finding.evidence_ref = Some(ev_id);
        if let Some(v) = finding.verdict.as_mut() {
            v.evidence_ref = Some(finding.evidence_ref.clone().unwrap_or_default());
        }
        let _ = session_id; // full trace lives in the pi session referenced by run id
        let saved = ledger.upsert_finding(finding).map_err(PipelineError::Io)?;
        ids.push(saved.id);
    }
    Ok(ids)
}

/// Merge the agent's traced chain into the pre-assembled evidence (or create
/// fresh evidence for sites the agent found beyond the candidates) and persist.
fn sync_evidence(
    ledger: &Ledger,
    f: &crate::verdict::JudgeFinding,
) -> Result<String, PipelineError> {
    let id = fiora_core::id::evidence_id(&f.sink_symbol, &f.file, f.line);
    let mut ev = ledger
        .load_evidence(&id)
        .map_err(PipelineError::Io)?
        .unwrap_or_else(|| Evidence {
            id: id.clone(),
            sink: fiora_core::CodeAnchor {
                symbol: f.sink_symbol.clone(),
                file: f.file.clone(),
                line: f.line,
            },
            sources: vec![],
            entries: vec![],
            call_chain: vec![],
            grade: EvidenceGrade::Inferred,
            unresolved_hops: vec![],
            tool: "agent-traced".to_string(),
        });

    if let Some(je) = &f.evidence {
        upgrade_with_chain(
            &mut ev,
            hops_to_core(&je.call_chain),
            entries_to_core(&je.entries),
        );
        if ev.sources.is_empty() {
            ev.sources = je
                .sources
                .iter()
                .map(|s| fiora_core::CodeAnchor {
                    symbol: s.symbol.clone(),
                    file: s.file.clone(),
                    line: s.line,
                })
                .collect();
        }
    }
    ledger.save_evidence(&ev).map_err(PipelineError::Io)?;
    Ok(id)
}

/// Adversarial second pass over HIGH+ true-positives and uncertains.
fn revalidate_all(
    runner: &PiRunner,
    root: &Path,
    ledger: &Ledger,
    run_id: &str,
    model: Option<String>,
    cost: &mut Cost,
) -> Result<usize, PipelineError> {
    let mut count = 0;
    for fid in ledger.list_finding_ids().map_err(PipelineError::Io)? {
        let Some(f) = ledger.load_finding(&fid).map_err(PipelineError::Io)? else {
            continue;
        };
        let needs = matches!(
            f.verdict.as_ref().map(|v| v.conclusion),
            Some(
                fiora_core::VerdictConclusion::TruePositive
                    | fiora_core::VerdictConclusion::Uncertain
            )
        ) && matches!(
            f.severity,
            fiora_core::Severity::Critical | fiora_core::Severity::High
        );
        if !needs {
            continue;
        }
        let finding_json = serde_json::to_string(&f).unwrap_or_default();
        let req = PiRequest {
            prompt: revalidate_prompt(&finding_json),
            model: model.clone(),
            thinking: Some(ThinkingLevel::High),
            name: Some(format!("{run_id}-revalidate-{fid}")),
            session_dir: Some(root.join(".fiora").join("sessions")),
            system_prompt: None,
            timeout: None,
            tools: None,
        };
        let outcome = runner.run(root, &req)?;
        cost.merge(&outcome.cost);
        // Anti-leak accounting: revalidation spend lands in the ledger too.
        ledger
            .record_cost(run_id, &outcome.cost, &fiora_core::util::now_iso())
            .map_err(PipelineError::Io)?;
        if let Some(v) = parse_revalidation(&outcome.text) {
            ledger.set_verdict(&fid, v).map_err(PipelineError::Io)?;
            count += 1;
        }
    }
    Ok(count)
}

fn parse_revalidation(text: &str) -> Option<Verdict> {
    let v: serde_json::Value = serde_json::from_str(crate::verdict::extract_json(text)).ok()?;
    let conclusion = crate::verdict::parse_conclusion(v.get("conclusion")?.as_str()?).ok()?;
    let confidence = crate::verdict::parse_confidence(
        v.get("confidence")
            .and_then(|c| c.as_str())
            .unwrap_or("medium"),
    );
    let rebut = v.get("rebuttals");
    let b = |k: &str| rebut.and_then(|r| r.get(k)).and_then(|x| x.as_bool());
    Some(Verdict {
        conclusion,
        confidence,
        evidence_ref: None,
        reasoning: v
            .get("reasoning")
            .and_then(|r| r.as_str())
            .unwrap_or("revalidated")
            .to_string(),
        rebuttals: fiora_core::RebuttalAnswers {
            parameterized: b("parameterized"),
            reachable: b("reachable"),
            business_method: b("business_method"),
            allowlisted: b("allowed"),
            user_input_controlled: b("user_input_controlled"),
            protected_by_guard: b("protected_by_guard"),
            notes: rebut
                .and_then(|r| r.get("notes"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string(),
        },
    })
}

/// Cheap triage over candidate text only. Falls back to heuristic ordering
/// when the budget model is unavailable. Scheduling only — nothing discarded.
fn run_triage(
    runner: &PiRunner,
    root: &Path,
    work: &[(String, Vec<fiora_core::Candidate>)],
    cfg: &ProcessConfig,
) -> Result<HashMap<String, String>, PipelineError> {
    let mut map = HashMap::new();
    let mut blob = String::new();
    for (_rel, cands) in work {
        for c in cands {
            map.insert(c.id.clone(), heuristic_priority(c));
            blob.push_str(&format!(
                "- id={} slug={} file={}:{} snippet={}\n",
                c.id,
                c.slug,
                c.file,
                c.line,
                c.snippet.chars().take(120).collect::<String>()
            ));
        }
    }
    if blob.is_empty() {
        return Ok(map);
    }
    let req = PiRequest {
        prompt: triage_prompt(&blob),
        model: cfg.budget_model.clone().or_else(|| cfg.model.clone()),
        thinking: Some(ThinkingLevel::Low),
        name: Some("triage".to_string()),
        session_dir: Some(root.join(".fiora").join("sessions")),
        system_prompt: None,
        timeout: None,
        tools: None,
    };
    if let Ok(out) = runner.run(root, &req) {
        if let Ok(items) =
            serde_json::from_str::<Vec<serde_json::Value>>(extract_json_array(&out.text))
        {
            for it in items {
                if let (Some(id), Some(p)) = (
                    it.get("id").and_then(|x| x.as_str()),
                    it.get("priority").and_then(|x| x.as_str()),
                ) {
                    map.insert(id.to_string(), p.to_string());
                }
            }
        }
    }
    Ok(map)
}

fn heuristic_priority(c: &fiora_core::Candidate) -> String {
    let s = format!("{} {}", c.slug, c.snippet).to_ascii_lowercase();
    if s.contains("exec") || s.contains("eval") || s.contains("rce") || s.contains("sqli") {
        "P0".to_string()
    } else if s.contains("auth") || s.contains("ssrf") || s.contains("traversal") {
        "P1".to_string()
    } else {
        "P2".to_string()
    }
}

fn extract_json_array(text: &str) -> &str {
    let s = crate::verdict::extract_json(text);
    if s.starts_with('[') {
        s
    } else {
        "[]"
    }
}

/// Render the batch context: candidates + pre-assembled evidence per file.
fn render_batch(
    ledger: &Ledger,
    batch: &[(String, Vec<fiora_core::Candidate>)],
) -> Result<String, PipelineError> {
    let mut out = String::new();
    for (rel, cands) in batch {
        out.push_str(&format!("\n### File: {rel}\n"));
        for c in cands {
            out.push_str(&format!(
                "- candidate id={} slug={} line={} snippet: {}\n",
                c.id,
                c.slug,
                c.line,
                c.snippet.chars().take(200).collect::<String>()
            ));
            if let Some(note) = &c.note {
                out.push_str(&format!(
                    "  note: {}\n",
                    note.chars().take(300).collect::<String>()
                ));
            }
            if let Some(eid) = &c.evidence_id {
                if let Some(ev) = ledger.load_evidence(eid).map_err(PipelineError::Io)? {
                    out.push_str(&format!(
                        "  evidence[{}]: grade={:?} entries={} sources={} chain={}\n",
                        ev.id,
                        ev.grade,
                        ev.entries.len(),
                        ev.sources.len(),
                        ev.call_chain
                            .iter()
                            .map(|h| format!("{}->{}({:?})", h.from, h.to, h.quality))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
        }
    }
    Ok(out)
}

fn agent_prov(
    run_id: &str,
    backend: &str,
    model: &str,
    thinking: &str,
    session_id: Option<&str>,
) -> AgentProvenance {
    AgentProvenance {
        backend: backend.to_string(),
        model: model.to_string(),
        thinking_level: thinking.to_string(),
        run_id: run_id.to_string(),
        session_id: session_id.map(str::to_string),
        cost: None,
    }
}

fn thinking_label(t: ThinkingLevel) -> &'static str {
    match t {
        ThinkingLevel::Off => "off",
        ThinkingLevel::Minimal => "minimal",
        ThinkingLevel::Low => "low",
        ThinkingLevel::Medium => "medium",
        ThinkingLevel::High => "high",
        ThinkingLevel::Xhigh => "xhigh",
        ThinkingLevel::Max => "max",
    }
}

pub fn load_info_md(root: &Path) -> String {
    std::fs::read_to_string(root.join("INFO.md")).unwrap_or_default()
}

// ---------- one judge batch (shared by every worker — single code path) ----------

#[derive(Debug, Default)]
struct BatchPart {
    findings: usize,
    refusals: usize,
    files: usize,
    cost: Cost,
}

#[allow(clippy::too_many_arguments)]
fn judge_batch(
    ctx: &RunContext,
    cfg: &ProcessConfig,
    run_id: &str,
    batch_idx: usize,
    batch: &[(String, Vec<fiora_core::Candidate>)],
    priorities: &HashMap<String, String>,
) -> Result<BatchPart, PipelineError> {
    let RunContext {
        runner,
        root,
        ledger,
        prompts_dir,
        tech_tags,
        info_md,
        ..
    } = *ctx;
    let mut part = BatchPart::default();

    // 分级深审：整批都是 P2 弱信号时换便宜模型（triage 的调度结论，不是字段猜测）。
    let p2_only = !priorities.is_empty()
        && batch.iter().all(|(_, cands)| {
            cands
                .iter()
                .all(|c| priorities.get(&c.id).is_some_and(|p| p == "P2"))
        });
    let (model, thinking) = if p2_only {
        (
            cfg.budget_model.clone().or_else(|| cfg.model.clone()),
            cfg.budget_thinking,
        )
    } else {
        (cfg.model.clone(), cfg.thinking)
    };

    let batch_context = render_batch(ledger, batch)?;
    let prompt = load_or_default(
        prompts_dir,
        "judge",
        &judge_prompt(
            info_md,
            tech_tags,
            &batch_context,
            &cfg.severity_scope,
            ctx.hunt_memo,
        ),
    );
    let mut agent = agent_prov(
        run_id,
        "pi",
        model.as_deref().unwrap_or("default"),
        thinking_label(thinking),
        None,
    );

    let req = PiRequest {
        prompt,
        model,
        thinking: Some(thinking),
        name: Some(format!("{run_id}-judge-{batch_idx}")),
        // 会话随项目走：.fiora/sessions —— provenance 里的 session id 在任何
        // 机器上 `pi --resume` 都能回放（durable 证据链可移植）
        session_dir: Some(root.join(".fiora").join("sessions")),
        system_prompt: None,
        timeout: None,
        tools: None,
    };
    let outcome = runner.run(root, &req)?;
    part.cost.merge(&outcome.cost);
    agent.session_id = outcome.session_id.clone();

    let first = match parse_judge_output(&outcome.text) {
        Ok(o) => o,
        Err(violation) => {
            // one repair attempt, then per-item salvage: invalid entries fall
            // into the refusal log, valid findings are kept (no silent loss).
            // 违约与「不是 JSON」要用不同的修复提示：前者必须把违规点喂回去，
            // 否则模型原样重发，一份真阳性就被降级成 refusal。
            let prompt = if violation.starts_with("judge output is not valid JSON") {
                json_repair_prompt(&req.prompt, &outcome.text)
            } else {
                contract_repair_prompt(&req.prompt, &violation, &outcome.text)
            };
            let repair = PiRequest {
                prompt,
                ..req.clone()
            };
            let fixed = runner.run(root, &repair)?;
            part.cost.merge(&fixed.cost);
            parse_judge_output(&fixed.text)
                .unwrap_or_else(|_| crate::verdict::salvage_findings(&fixed.text))
        }
    };

    // 「合法 JSON，但缺必填字段」是最常见的丢真阳性方式（实测：模型漏写
    // `severity`，其余字段全对）。和结构性违约一样，这是一次可修的机会——
    // 把 serde 的原话喂回去。只在修复结果确实少了 refusal 时才采用；修不回来
    // 就保留原输出，refusal 照实记，不静默放过。
    let output = if first
        .refusals
        .iter()
        .any(|r| r.starts_with("unparseable finding"))
    {
        let errors = first
            .refusals
            .iter()
            .map(|r| {
                r.replace(
                    "unparseable finding dropped to refusal log: ",
                    "schema error: ",
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let repair = PiRequest {
            prompt: contract_repair_prompt(&req.prompt, &errors, &outcome.text),
            ..req.clone()
        };
        let fixed = runner.run(root, &repair)?;
        part.cost.merge(&fixed.cost);
        match parse_judge_output(&fixed.text) {
            Ok(ok) if ok.refusals.len() < first.refusals.len() => ok,
            _ => first,
        }
    } else {
        first
    };

    let ids = absorb(root, ledger, &output, &agent, outcome.session_id.as_deref())?;
    part.findings = ids.len();
    part.refusals = output.refusals.len();

    for (rel, _cands) in batch {
        ledger
            .append_analysis(
                rel,
                fiora_core::AnalysisEntry {
                    run_id: run_id.to_string(),
                    agent: agent.clone(),
                    at: fiora_core::util::now_iso(),
                    summary: format!("{} finding(s) this pass", ids.len()),
                    finding_ids: ids.clone(),
                    refused: Some(!output.refusals.is_empty()),
                    refusal_note: if output.refusals.is_empty() {
                        None
                    } else {
                        Some(output.refusals.join("; "))
                    },
                },
            )
            .map_err(PipelineError::Io)?;
        ledger
            .complete(rel, FileStatus::Analyzed)
            .map_err(PipelineError::Io)?;
        part.files += 1;
    }

    ledger
        .record_cost(run_id, &outcome.cost, &fiora_core::util::now_iso())
        .map_err(PipelineError::Io)?;
    Ok(part)
}
