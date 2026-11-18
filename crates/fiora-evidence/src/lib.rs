//! `fiora-evidence` — L2 evidence protocol (DESIGN.md §4).

//! Evidence is a deterministic artifact, not a model opinion. This crate
//! pre-assembles Evidence skeletons (surface anchors + taint fragments) before
//! any AI runs, enforces the three-elements rule (sink x source x entry), and
//! upgrades evidence when the agent traces the chain with code coordinates.
//! Gaps are exposed, never papered over.

/// Layer-2 call-chain engine (docs/TAINT-DESIGN.md).
pub mod callchain;

use std::collections::HashMap;

use fiora_core::id::evidence_id;
use fiora_core::{
    CallHop, Candidate, CodeAnchor, EntryAnchor, Evidence, EvidenceGrade, HopQuality,
};
use fiora_scanner::SurfaceEntry;

/// Three-elements completeness (P2/P5): the verdict gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completeness {
    pub sink: bool,
    pub source: bool,
    pub entry: bool,
}

pub fn three_elements(e: &Evidence) -> Completeness {
    Completeness {
        sink: !e.sink.symbol.is_empty(),
        source: !e.sources.is_empty(),
        entry: !e.entries.is_empty(),
    }
}

pub fn is_complete(e: &Evidence) -> bool {
    let c = three_elements(e);
    c.sink && c.source && c.entry
}

/// Pre-assemble one Evidence skeleton per candidate (deterministic, no AI).
///
/// - sink: the candidate site itself;
/// - entries: surface entries in the same file, falling back to the same
///   top-level module (attacker's route in is usually co-located);
/// - sources: parsed from the OpenGrep taint fragment when present;
/// - grade: `DataflowVerified` when the engine produced a taint trace,
///   otherwise `Inferred` until the agent traces the chain.
///
pub fn pre_assemble(
    candidates: &[Candidate],
    surface: &[SurfaceEntry],
    root: &std::path::Path,
) -> HashMap<String, Evidence> {
    // 层 2：全仓索引一次（同一 root 只解析一次；本函数一次接收全部候选，
    // 所以不需要跨调用缓存——原实现的全局 CHAIN_CACHE 是「每文件重建索引」
    // 时代的遗留，已删），逐候选反向追链（2~3 跳预算）
    let chain_index = callchain::CallIndex::index_repo(root);
    let mut out = HashMap::new();
    for c in candidates {
        let id = evidence_id(&c.slug, &c.file, c.line);
        let (sources, has_taint) = sources_from_note(c);
        let entries: Vec<EntryAnchor> = surface
            .iter()
            .filter(|e| e.file == c.file || same_module(&e.file, &c.file))
            .take(5)
            .map(|e| EntryAnchor {
                symbol: e.symbol.clone(),
                file: e.file.clone(),
                line: e.line,
                route: e.route.clone(),
            })
            .collect();

        let mut unresolved = Vec::new();
        // 层 2 调用链（跨函数）：引擎反向追 2~3 跳；失败/未闭合如实标注
        let trace = chain_index.trace_chain(&c.file, c.line);
        let mut call_chain = trace.hops;
        if call_chain.is_empty() && entries.iter().any(|e| e.file == c.file) {
            // 引擎无链时的旧语义兜底：同文件入口一步占位（Unresolved 诚实标注）
            call_chain = vec![CallHop {
                from: entries[0].symbol.clone(),
                to: c.slug.clone(),
                quality: HopQuality::Unresolved,
            }];
        } else if call_chain.is_empty() {
            // 无链且无占位：引擎注记如实进 unresolved（透明暴露，不静默）
            if let Some(note) = trace.note.clone() {
                unresolved.push(note);
            }
            if !entries.is_empty() {
                unresolved.push("entry-to-sink link untraced (cross-module)".to_string());
            }
        }

        let grade = if has_taint {
            EvidenceGrade::DataflowVerified
        } else {
            EvidenceGrade::Inferred
        };

        out.insert(
            c.id.clone(),
            Evidence {
                id,
                sink: CodeAnchor {
                    symbol: c.slug.clone(),
                    file: c.file.clone(),
                    line: c.line,
                },
                sources,
                entries,
                call_chain,
                grade,
                unresolved_hops: unresolved,
                tool: if has_taint {
                    "opengrep-taint".to_string()
                } else {
                    "pre-assemble".to_string()
                },
            },
        );
    }
    out
}

/// Merge the agent's traced chain into the evidence and upgrade the grade
/// honestly: a fully traced chain reaches `CallchainVerified`; the taint trace
/// (if any) keeps `DataflowVerified` on top.
pub fn upgrade_with_chain(e: &mut Evidence, hops: Vec<CallHop>, entries: Vec<EntryAnchor>) {
    if hops.iter().all(|h| h.quality != HopQuality::Unresolved) && !hops.is_empty() {
        e.grade = match e.grade {
            EvidenceGrade::Inferred | EvidenceGrade::CallchainVerified
                if e.tool != "opengrep-taint" =>
            {
                EvidenceGrade::CallchainVerified
            }
            other => other,
        };
    }
    for h in &hops {
        if h.quality == HopQuality::Unresolved {
            let label = format!("{} -> {}", h.from, h.to);
            if !e.unresolved_hops.contains(&label) {
                e.unresolved_hops.push(label);
            }
        }
    }
    if !hops.is_empty() {
        e.call_chain = hops;
    }
    for ent in entries {
        if !e
            .entries
            .iter()
            .any(|x| x.file == ent.file && x.line == ent.line)
        {
            e.entries.push(ent);
        }
    }
}

/// Dead-code verdict from empty caller sets (documented in the evidence, and
/// the candidate leaves the AI queue).
pub fn mark_dead_code(e: &mut Evidence) {
    e.grade = EvidenceGrade::DeadCode;
    e.tool = "dead-code-check".to_string();
}

// ---------- internals ----------

fn top_dir(p: &str) -> &str {
    p.split('/').next().unwrap_or("")
}

fn same_module(a: &str, b: &str) -> bool {
    let (ta, tb) = (top_dir(a), top_dir(b));
    !ta.is_empty() && ta == tb
}

/// Tolerant extraction of source anchors from an OpenGrep dataflow fragment
/// (`note` = `dataflow: <json>`). The exact trace shape varies across engine
/// versions, so anything unrecognizable degrades to "source unknown" instead
/// of fabricating anchors.
fn sources_from_note(c: &Candidate) -> (Vec<CodeAnchor>, bool) {
    let Some(note) = &c.note else {
        return (Vec::new(), false);
    };
    let Some(json) = note.strip_prefix("dataflow: ") else {
        return (Vec::new(), false);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return (
            vec![CodeAnchor {
                symbol: "<taint-source>".into(),
                file: c.file.clone(),
                line: c.line,
            }],
            true,
        );
    };
    let mut anchors = Vec::new();
    collect_trace_anchors(&v, &mut anchors);
    if anchors.is_empty() {
        anchors.push(CodeAnchor {
            symbol: "<taint-source>".into(),
            file: c.file.clone(),
            line: c.line,
        });
    }
    (anchors, true)
}

fn collect_trace_anchors(v: &serde_json::Value, out: &mut Vec<CodeAnchor>) {
    match v {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_trace_anchors(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(loc) = map.get("location") {
                let file = loc
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or_default()
                    .to_string();
                let line = loc
                    .get("start")
                    .and_then(|s| s.get("line"))
                    .and_then(|l| l.as_u64())
                    .unwrap_or(0) as u32;
                let symbol = map
                    .get("content")
                    .and_then(|c| c.get(0))
                    .and_then(|c| c.get("label"))
                    .and_then(|l| l.as_str())
                    .unwrap_or("<taint-step>")
                    .to_string();
                if !file.is_empty() {
                    out.push(CodeAnchor { symbol, file, line });
                }
            }
            for (_k, child) in map {
                collect_trace_anchors(child, out);
            }
        }
        _ => {}
    }
}
