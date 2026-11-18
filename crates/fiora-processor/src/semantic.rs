//! Channel B: semantic self-mining (DESIGN.md §3).
//!
//! Budget-quota pi exploration over code OUTSIDE covered paths. Output is
//! normalized candidates with reasoning notes + session ids (the exploration
//! trace stays recoverable).

use std::path::Path;

use fiora_core::id::candidate_id;
use fiora_core::{Candidate, CandidateChannel};
use serde::{Deserialize, Serialize};

use crate::pi::{PiError, PiRequest, PiRunner, ThinkingLevel};
use crate::prompts::{json_repair_prompt, load_or_default, SEMANTIC_EXPLORE_BUILTIN};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticFinding {
    pub file: String,
    pub line: u32,
    pub slug: String,
    pub note: String,
    #[serde(default)]
    pub snippet: String,
}

#[derive(Debug, Clone)]
pub struct ExploreBudget {
    /// How many pi sessions this run may spend.
    pub max_sessions: usize,
    /// Modules per session prompt.
    pub modules_per_session: usize,
}

impl Default for ExploreBudget {
    fn default() -> Self {
        ExploreBudget {
            max_sessions: 4,
            modules_per_session: 8,
        }
    }
}

pub struct SemanticChannel<'a> {
    pub runner: &'a PiRunner,
    pub prompts_dir: Option<&'a Path>,
    pub model: Option<String>,
    pub thinking: ThinkingLevel,
    /// 并发会话数（会话间独立，结果单点合并）。
    pub jobs: usize,
}

impl<'a> SemanticChannel<'a> {
    /// Run self-mining over `uncovered` module dirs. `covered_files` are named
    /// in the prompt as excluded territory (budget goes to the dark corners).
    ///
    /// Allocation is **coverage-first**: blind sweeps get their full share of
    /// the session budget (one session per `modules_per_session` chunk), and
    /// hypothesis-driven sessions take what is left. This is what makes the
    /// "全量覆盖" promise true — before, the plan silently ate 2/3 of the
    /// budget and only ~1/3 of the uncovered modules were ever swept.
    /// `hypotheses_dropped` reports hypotheses that did not fit, so the caller
    /// can surface the tradeoff instead of hiding it.
    pub fn explore(
        &self,
        root: &Path,
        uncovered: &[String],
        covered_files: &[String],
        budget: &ExploreBudget,
        plan: Option<&[HuntHypothesis]>,
    ) -> Result<ExploreReport, PiError> {
        let prompt_base = load_or_default(
            self.prompts_dir,
            "semantic-explore",
            SEMANTIC_EXPLORE_BUILTIN,
        );

        // ---- 阶段一：建任务段（纯计算，无 IO）----
        // (模块数, prompt)——模块数只在会话真正跑完并交回覆盖账时才计入 swept，
        // 不能在发牌时就记账（会话失败也会被报成「扫过」，那是假账）。
        let mut session_prompts: Vec<(usize, String)> = Vec::new();
        let per_session = budget.modules_per_session.max(1);
        for chunk in uncovered.chunks(per_session) {
            if session_prompts.len() >= budget.max_sessions {
                break;
            }
            let mut prompt = prompt_base.clone();
            prompt.push_str("\n## Modules to explore (this session)\n");
            for m in chunk {
                prompt.push_str(&format!("- {m}\n"));
            }
            if !covered_files.is_empty() {
                prompt.push_str(SELF_COVERED_HEADER);
                for f in covered_files.iter().take(200) {
                    prompt.push_str(&format!("- {f}\n"));
                }
            }
            session_prompts.push((chunk.len(), prompt));
        }

        // 假设驱动会话：plan 的假设按优先级分组，占剩余预算（没有就明确报告丢弃数）。
        let mut dropped = 0usize;
        let remaining = budget.max_sessions.saturating_sub(session_prompts.len());
        if let Some(hyps) = plan {
            let mut sorted: Vec<&HuntHypothesis> = hyps.iter().collect();
            sorted.sort_by_key(|h| h.priority);
            let units: Vec<String> = sorted
                .iter()
                .map(|h| {
                    format!(
                        "\n## Hypothesis {id}（priority {p}）\n- area: {a}\n- claim: {c}\n- targets: {t}\nProbe it to CONFIRM or KILL; follow data 2-3 hops past the targets if the flow continues.\n",
                        id = h.id, p = h.priority, a = h.area, c = h.claim,
                        t = h.targets.join(", "),
                    )
                })
                .collect();
            let targets: Vec<&String> = sorted.iter().flat_map(|h| h.targets.iter()).collect();
            if remaining == 0 {
                dropped = units.len();
            } else {
                let per = units.len().div_ceil(remaining).max(1);
                for group in units.chunks(per).take(remaining) {
                    let mut prompt = prompt_base.clone();
                    prompt
                        .push_str("\n## Assigned hypotheses (this session — plan/execute split)\n");
                    for seg in group {
                        prompt.push_str(seg);
                    }
                    prompt.push_str("\n## Files in scope for these hypotheses\n");
                    for m in targets.iter().take(60) {
                        prompt.push_str(&format!("- {m}\n"));
                    }
                    if !covered_files.is_empty() {
                        prompt.push_str(SELF_COVERED_HEADER);
                        for f in covered_files.iter().take(200) {
                            prompt.push_str(&format!("- {f}\n"));
                        }
                    }
                    session_prompts.push((0, prompt));
                }
                dropped = units.len().saturating_sub(remaining * per);
            }
        }

        // ---- 阶段二：并发执行（--jobs 个工人；会话独立，结果单点合并）----
        let queue = std::sync::Mutex::new(session_prompts.into_iter().enumerate());
        let results: std::sync::Mutex<Vec<SessionOutcome>> = std::sync::Mutex::new(Vec::new());
        let failures: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let jobs = self.jobs.clamp(1, 16);
        std::thread::scope(|s| {
            for _ in 0..jobs {
                s.spawn(|| loop {
                    let next = { queue.lock().unwrap().next() };
                    let Some((i, (modules, prompt))) = next else {
                        break;
                    };
                    let req = PiRequest {
                        prompt,
                        model: self.model.clone(),
                        thinking: Some(self.thinking),
                        name: Some(format!("fiora-explore-{i}")),
                        session_dir: Some(root.join(".fiora").join("sessions")),
                        system_prompt: None,
                        timeout: None,
                        tools: None,
                    };
                    // 单会话失败不整场中止：记录后继续（落账契约：不静默、不弃场）。
                    let run_one = || -> Result<SessionOutcome, PiError> {
                        let outcome = self.runner.run(root, &req)?;
                        let (findings, coverage_candidates) = match parse_explore(&outcome.text) {
                            Ok(parsed) => parsed,
                            Err(_) => {
                                let repair = PiRequest {
                                    prompt: json_repair_prompt(&req.prompt, &outcome.text),
                                    ..req.clone()
                                };
                                let fixed = self.runner.run(root, &repair)?;
                                parse_explore(&fixed.text).unwrap_or_default()
                            }
                        };
                        Ok(SessionOutcome {
                            index: i,
                            session_id: outcome.session_id,
                            modules,
                            findings,
                            coverage: coverage_candidates,
                        })
                    };
                    match run_one() {
                        Ok(mut out) => {
                            out.index = i;
                            results.lock().unwrap().push(out);
                        }
                        Err(e) => {
                            // 失败必须可见：会话没跑成 ≠ 这些模块被扫过。
                            eprintln!("explore session {i} failed: {e}");
                            failures.lock().unwrap().push(format!("session {i}: {e}"));
                        }
                    }
                });
            }
        });

        // ---- 阶段三：按任务段顺序合并（输出确定性）----
        let mut merged = results.into_inner().unwrap();
        merged.sort_by_key(|o| o.index);
        let failures = failures.into_inner().unwrap();
        let mut report = ExploreReport {
            sessions_failed: failures.len(),
            failure_notes: failures,
            hypotheses_dropped: dropped,
            ..Default::default()
        };
        for out in merged {
            // 覆盖账是证据：交回逐模块账目、或带回发现的会话才算「扫过」；
            // 双手空空的会话（含输出不可解析者）计入 unverified，不冒领覆盖。
            if out.coverage.is_empty() && out.findings.is_empty() {
                report.sessions_unverified += 1;
            } else {
                report.swept_modules += out.modules;
            }
            if let Some(id) = out.session_id {
                report.session_ids.push(id);
            }
            for note in out.coverage {
                if !report.coverage.iter().any(|c| c.module == note.module) {
                    report.coverage.push(note);
                }
            }
            report
                .candidates
                .extend(out.findings.into_iter().map(|f| Candidate {
                    id: candidate_id(&f.slug, &f.file, f.line),
                    slug: f.slug,
                    matcher_id: "semantic-explore".to_string(),
                    channel: CandidateChannel::Semantic,
                    file: f.file,
                    line: f.line,
                    end_line: None,
                    snippet: f.snippet,
                    note: Some(f.note),
                    evidence_id: None,
                }));
        }
        Ok(report)
    }
}

const SELF_COVERED_HEADER: &str = "\n## Already covered by the rule scan — do NOT re-investigate\n";

/// One session's raw output (merged deterministically by `index`).
struct SessionOutcome {
    index: usize,
    session_id: Option<String>,
    /// 本会话分到的模块数——只有交回覆盖账时才计入 swept_modules。
    modules: usize,
    findings: Vec<SemanticFinding>,
    coverage: Vec<CoverageNote>,
}

/// What a semantic run produced: candidates, coverage accounting and the pi
/// sessions behind them (trace ids stay recoverable via `fiora trace`).
#[derive(Debug, Default)]
pub struct ExploreReport {
    pub candidates: Vec<Candidate>,
    pub coverage: Vec<CoverageNote>,
    pub session_ids: Vec<String>,
    /// 只统计交回逐模块覆盖账的会话所分到的模块数（诚实口径）。
    pub swept_modules: usize,
    /// 会话失败（pi 报错/无输出）——这些模块**没有**被扫过。
    pub sessions_failed: usize,
    pub failure_notes: Vec<String>,
    /// 会话跑完了但没交回覆盖账——覆盖未经验证，不算扫过。
    pub sessions_unverified: usize,
    pub hypotheses_dropped: usize,
}

/// One line of the hunting protocol's Phase-4 coverage ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageNote {
    #[serde(default)]
    pub module: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
}

/// Parse one session's `{"findings":[...],"coverage":[...]}` reply.
pub fn parse_explore(
    text: &str,
) -> Result<(Vec<SemanticFinding>, Vec<CoverageNote>), serde_json::Error> {
    let v: serde_json::Value = serde_json::from_str(crate::verdict::extract_json(text))?;
    match v {
        // 兼容裸数组（旧协议/修复回路）
        serde_json::Value::Array(_) => Ok((serde_json::from_value(v)?, Vec::new())),
        serde_json::Value::Object(mut m) => {
            let findings = match m.remove("findings") {
                Some(f) => serde_json::from_value(f)?,
                None => Vec::new(),
            };
            let coverage = match m.remove("coverage") {
                Some(c) => serde_json::from_value(c).unwrap_or_default(),
                None => Vec::new(),
            };
            Ok((findings, coverage))
        }
        _ => Ok((Vec::new(), Vec::new())),
    }
}

/// Extract findings only (deep-dive rounds use the same hunting protocol but
/// we do not need their coverage rows there).
pub fn parse_findings(text: &str) -> Result<Vec<SemanticFinding>, serde_json::Error> {
    parse_explore(text).map(|(findings, _)| findings)
}

// ---------- 狩猎规划（plan/execute 分离）----------

/// 执行会话要探的假设（plan 端产出）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HuntHypothesis {
    pub id: String,
    pub area: String,
    pub claim: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default = "default_priority")]
    pub priority: u8,
}

fn default_priority() -> u8 {
    2
}

/// 解析规划会话输出（严格 JSON；坏 schema 走修复回路由调用方兜底）。
pub fn parse_plan(text: &str) -> Result<Vec<HuntHypothesis>, serde_json::Error> {
    let v: serde_json::Value = serde_json::from_str(crate::verdict::extract_json(text))?;
    match v.get("hypotheses") {
        Some(h) => serde_json::from_value(h.clone()),
        None => Ok(Vec::new()),
    }
}
