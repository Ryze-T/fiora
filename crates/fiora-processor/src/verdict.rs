//! Verdict contract (DESIGN.md §5): AI output is untrusted input.
//!
//! The judge must answer the three-elements rule and the six rebuttal
//! questions in strict JSON. `true-positive` is only accepted with a traced
//! evidence chain; anything less is demoted to `uncertain` instead of being
//! silently accepted.

use fiora_core::id::finding_id;
use fiora_core::{
    AgentProvenance, CallHop, Confidence, EntryAnchor, Finding, HopQuality, ReproPack, ReproStatus,
    Severity, Verdict, VerdictConclusion,
};
use serde::Deserialize;

/// PoC 形态分类（B1）：按 sink/类别分派正确的复现形态——
/// 网络 sink→HTTP 模板；代码执行 sink→触发 harness；路径 sink→文件操作；其余→逻辑推演。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocKind {
    /// HTTP/网络请求类（SSRF/XSS/未鉴权端点）
    Network,
    /// 代码执行类（eval/pickle/反序列化/命令注入）——curl 打不动，需触发 harness
    CodeExec,
    /// 文件操作类（路径穿越/任意覆写）
    FileOp,
    /// 逻辑类（越权/配置错误）——请求模板或推演
    Logic,
}

pub fn poc_kind(f: &fiora_core::Finding) -> PocKind {
    let text = format!("{} {} {}", f.category, f.title, f.description).to_ascii_lowercase();
    if [
        "eval",
        "pickle",
        "unpickle",
        "反序列",
        "code-injection",
        "cmdi",
        "命令执行",
        "代码执行",
    ]
    .iter()
    .any(|k| text.contains(k))
    {
        PocKind::CodeExec
    } else if ["path-traversal", "覆写", "文件", "file"]
        .iter()
        .any(|k| text.contains(k))
    {
        PocKind::FileOp
    } else if [
        "ssrf",
        "xss",
        "http",
        "端点",
        "endpoint",
        "未鉴权",
        "无鉴权",
        "cors",
    ]
    .iter()
    .any(|k| text.contains(k))
    {
        PocKind::Network
    } else {
        PocKind::Logic
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeFinding {
    pub slug: String,
    pub category: String,
    pub title: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    /// Identity anchor inputs (stable across re-runs and models).
    pub sink_symbol: String,
    pub enclosing_fn: String,
    #[serde(default)]
    pub probe_shape: Option<String>,
    pub description: String,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub data_flow: Option<String>,
    #[serde(default)]
    pub evidence: Option<JudgeEvidence>,
    pub verdict: JudgeVerdict,
    #[serde(default)]
    pub repro_pack: Option<JudgeRepro>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeEvidence {
    #[serde(default)]
    pub entries: Vec<JudgeEntry>,
    #[serde(default)]
    pub call_chain: Vec<JudgeHop>,
    #[serde(default)]
    pub sources: Vec<JudgeAnchor>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeEntry {
    pub symbol: String,
    pub file: String,
    pub line: u32,
    #[serde(default)]
    pub route: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeAnchor {
    pub symbol: String,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeHop {
    pub from: String,
    pub to: String,
    #[serde(default = "default_quality")]
    pub quality: String,
}

fn default_quality() -> String {
    "traced".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeVerdict {
    pub conclusion: String,
    pub confidence: String,
    #[serde(default)]
    pub evidence_ref: Option<String>,
    pub rebuttals: JudgeRebuttals,
    pub reasoning: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeRebuttals {
    pub parameterized: Option<bool>,
    pub reachable: Option<bool>,
    pub business_method: Option<bool>,
    pub allowed: Option<bool>,
    pub user_input_controlled: Option<bool>,
    pub protected_by_guard: Option<bool>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeRepro {
    #[serde(default)]
    pub preconditions: Vec<String>,
    pub request: String,
    pub expected: String,
    pub actual: String,
    #[serde(default = "default_repro_status")]
    pub status: String,
}

fn default_repro_status() -> String {
    "todo".to_string()
}

/// The full judge output: findings plus refusal log (no silent skips).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JudgeOutput {
    #[serde(default)]
    pub findings: Vec<JudgeFinding>,
    #[serde(default)]
    pub refusals: Vec<String>,
}

/// Shared JSON extraction for agent output: strips accidental ``` fences and
/// locates the outermost JSON value. Used by every parser (judge, semantic,
/// revalidation) — one implementation, one place to fix.
pub fn extract_json(text: &str) -> &str {
    let trimmed = text.trim();
    let cleaned = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|s| s.strip_suffix("```").unwrap_or(s))
        .unwrap_or(trimmed);
    let start = cleaned.find(['{', '[']);
    let end = cleaned.rfind(['}', ']']);
    match (start, end) {
        (Some(s), Some(e)) if e > s => &cleaned[s..=e],
        _ => cleaned,
    }
}

/// 批量 JSON 会话的容错回路（全 CLI 改写类命令共用）：
/// 直解 → 一次修复重试 → 仍失败则逐条抢救（合法条目保留，坏条目跳过计数）。
/// 既不整批死亡也不静默丢弃（DESIGN.md §5 容错纪律）。
pub fn run_json_with_repair<T: serde::de::DeserializeOwned>(
    runner: &crate::pi::PiRunner,
    root: &std::path::Path,
    req: &crate::pi::PiRequest,
) -> Result<Vec<T>, String> {
    let outcome = runner.run(root, req).map_err(|e| e.to_string())?;
    if let Ok(v) = serde_json::from_str::<Vec<T>>(extract_json(&outcome.text)) {
        return Ok(v);
    }
    let repair = crate::pi::PiRequest {
        prompt: crate::prompts::json_repair_prompt(&req.prompt, &outcome.text),
        ..req.clone()
    };
    let fixed = runner.run(root, &repair).map_err(|e| e.to_string())?;
    let slice = extract_json(&fixed.text);
    if let Ok(v) = serde_json::from_str::<Vec<T>>(slice) {
        return Ok(v);
    }
    // 逐条抢救：数组中合法的条目保留
    let vals: Vec<serde_json::Value> = serde_json::from_str(slice).unwrap_or_default();
    let mut out = Vec::new();
    let mut bad = 0usize;
    for v in vals {
        match serde_json::from_value::<T>(v) {
            Ok(t) => out.push(t),
            Err(_) => bad += 1,
        }
    }
    if bad > 0 {
        eprintln!("repair: {bad} unusable item(s) skipped after salvage");
    }
    Ok(out)
}

pub fn parse_judge_output(text: &str) -> Result<JudgeOutput, String> {
    let slice = extract_json(text);

    // Accept both the object form {"findings":[...],"refusals":[...]} and a
    // bare array of findings.
    if let Ok(out) = serde_json::from_str::<JudgeOutput>(slice) {
        return validate(out);
    }
    if let Ok(findings) = serde_json::from_str::<Vec<JudgeFinding>>(slice) {
        return validate(JudgeOutput {
            findings,
            refusals: Vec::new(),
        });
    }
    Err("judge output is not valid JSON matching the verdict schema".to_string())
}

fn validate(mut out: JudgeOutput) -> Result<JudgeOutput, String> {
    for f in &out.findings {
        // 解析结果必须参与判定：此前只做校验、再拿原始字符串比 "true-positive"，
        // 模型写 "tp" 就能绕过身份锚点 / impact / PoC 三道反泄漏检查。
        let conclusion = parse_conclusion(&f.verdict.conclusion)
            .map_err(|e| format!("finding '{}': {e}", f.title))?;
        parse_severity(&f.severity).map_err(|e| format!("finding '{}': {e}", f.title))?;
        // Anti-leak discipline (P2): a true-positive must carry a traced chain
        // and a reachable entry — otherwise demote, never accept blind.
        if conclusion == VerdictConclusion::TruePositive {
            // 身份锚点必须非空：sink_symbol+enclosing_fn 是稳定 id 的输入，
            // 缺失的发现无法锚定（换模型重跑会重复）也无法被评测/报告挂证据。
            if f.sink_symbol.trim().is_empty() || f.enclosing_fn.trim().is_empty() {
                return Err(format!(
                    "finding '{}' claims true-positive without a sink_symbol/enclosing_fn identity anchor",
                    f.title
                ));
            }
            let has_entry = f
                .evidence
                .as_ref()
                .map(|e| !e.entries.is_empty())
                .unwrap_or(false);
            let has_chain = f
                .evidence
                .as_ref()
                .map(|e| !e.call_chain.is_empty())
                .unwrap_or(false);
            if !has_entry || !has_chain {
                return Err(format!(
                    "finding '{}' claims true-positive without entry+call_chain evidence",
                    f.title
                ));
            }
            if f.verdict.rebuttals.reachable != Some(true) {
                return Err(format!(
                    "finding '{}' claims true-positive but rebuttal 'reachable' is not confirmed",
                    f.title
                ));
            }
            // 无法评定/复现的发现不算交付：TP 必须带影响分析与 PoC
            if f.impact.as_deref().unwrap_or("").trim().is_empty() {
                return Err(format!(
                    "finding '{}' claims true-positive without impact analysis",
                    f.title
                ));
            }
            if f.repro_pack.is_none() {
                return Err(format!(
                    "finding '{}' claims true-positive without a repro pack (PoC)",
                    f.title
                ));
            }
        }
    }
    out.findings.retain(|f| !f.title.trim().is_empty());
    Ok(out)
}

pub fn parse_conclusion(s: &str) -> Result<VerdictConclusion, String> {
    match s {
        "true-positive" | "tp" => Ok(VerdictConclusion::TruePositive),
        "false-positive" | "fp" => Ok(VerdictConclusion::FalsePositive),
        // Real models legitimately express doubt with varied vocabulary —
        // anything uncertain-shaped lands in `uncertain`, never hard-fails.
        "uncertain" | "needs-more-info" | "needs_more_info" | "inconclusive" | "maybe"
        | "unclear" => Ok(VerdictConclusion::Uncertain),
        other => Err(format!("unknown conclusion: {other}")),
    }
}

/// Per-item salvage: when the batch output has some invalid entries, keep the
/// valid findings and log the broken ones as refusals (anti-leak: no silent
/// loss, no whole-batch death).
pub fn salvage_findings(text: &str) -> JudgeOutput {
    let slice = extract_json(text);
    let mut out = JudgeOutput {
        findings: vec![],
        refusals: vec![],
    };
    let parsed_value = serde_json::from_str::<serde_json::Value>(slice);
    let parse_error = parsed_value
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    let parsed = parsed_value.ok();
    let items = parsed.map(|v| match &v {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Object(m) => m
            .get("findings")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => vec![],
    });
    match items {
        Some(items) => salvage_items(items, &mut out),
        None => {
            // 截断容错：整批 JSON 解不开时，扫描文本里「完整的」顶层 finding 对象逐个抢救
            // （大批次输出超限截断是真实场景——已写完的发现不许随尾巴丢失）。
            let rescued = salvage_truncated(slice);
            if !rescued.is_empty() {
                out.refusals.push(format!(
                    "truncated output: {}/.. findings salvaged",
                    rescued.len()
                ));
                salvage_items(rescued, &mut out);
                return out;
            }
            // 括号错位（模型写出多一个 `{` / 少一个 `]`）收不到任何完整对象。
            // 这里**不**做字符级手术：删一个括号能让 JSON 解析通过，但被吞掉的
            // 往往正是那条真阳性——用「救回来一条别的发现」掩盖丢了一条，比
            // 明确拒绝更糟。把解析器原话写进 refusal，配上带解析错误的修复提示
            // （`json_repair_prompt` 的第三个实参），由模型自己重发。
            out.refusals
                .push(format!("output is not JSON at all: {parse_error}"));
        }
    }
    out
}

fn salvage_items(items: Vec<serde_json::Value>, out: &mut JudgeOutput) {
    for item in items {
        match serde_json::from_value::<JudgeFinding>(item.clone()) {
            Ok(f) => match validate(JudgeOutput {
                findings: vec![f],
                refusals: vec![],
            }) {
                Ok(ok) => out.findings.extend(ok.findings),
                Err(e) => out.refusals.push(format!("salvaged-out: {e}")),
            },
            Err(e) => out
                .refusals
                .push(format!("unparseable finding dropped to refusal log: {e}")),
        }
    }
}

/// 从（可能被截断的）文本中扫描出「完整的」finding 形状 JSON 对象——字符串感知
/// （跳过引号内的括号/转义），每个 `{` 独立尝试記对；未闭合的（含截断的外层包裹）
/// 跳过继续，只收尾部闭合且带 slug/category 的对象。
fn salvage_truncated(slice: &str) -> Vec<serde_json::Value> {
    let bytes = slice.as_bytes();
    let mut objects = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let mut depth = 0i32;
            let mut j = i;
            let mut in_str = false;
            let mut closed = false;
            while j < bytes.len() {
                match bytes[j] {
                    b'"' if j == 0 || bytes[j - 1] != b'\\' => in_str = !in_str,
                    b'{' if !in_str => depth += 1,
                    b'}' if !in_str => {
                        depth -= 1;
                        if depth == 0 {
                            closed = true;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if closed {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&slice[i..=j]) {
                    // 只收 finding 形状的对象（有 slug/category 字段），
                    // 避免把包裹层/证据子对象当发现
                    if v.get("slug").is_some() || v.get("category").is_some() {
                        objects.push(v);
                    }
                }
                i = j + 1;
            } else {
                i += 1; // 未闭合（截断的外层或尾巴）：跳过它，内部的完整对象继续尝试
            }
        } else {
            i += 1;
        }
    }
    objects
}

pub fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Ok(Severity::Critical),
        "HIGH" => Ok(Severity::High),
        "MEDIUM" => Ok(Severity::Medium),
        "LOW" => Ok(Severity::Low),
        "INFO" => Ok(Severity::Info),
        "HIGH_BUG" | "HIGHBUG" => Ok(Severity::HighBug),
        "BUG" => Ok(Severity::Bug),
        // judge 用 NONE 标注「非问题」——入账为 Info，结构化保留否决证据
        "NONE" => Ok(Severity::Info),
        other => Err(format!("unknown severity: {other}")),
    }
}

pub fn parse_confidence(s: &str) -> Confidence {
    match s.to_ascii_lowercase().as_str() {
        "high" => Confidence::High,
        "low" => Confidence::Low,
        _ => Confidence::Medium,
    }
}

/// 类别词表归一（入库单点）：判定层自由措辞会产生
/// `pathtraversal` / `path_traversal` / `path-traversal` 这类漂移，报告分组、
/// 能力族座次与身份锚点都被打散。保守归一：只统一分隔符 + 已观测到的同义
/// 变体，不发明新分类学。
///
/// 注意：类别参与 finding_id 推导，归一会让旧版本账本的同发现 id 变化
/// （0.x 阶段接受；已在 CHANGELOG 注明）。
pub fn normalize_category(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase().replace(['_', ' '], "-");
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    match s.as_str() {
        "pathtraversal" => "path-traversal".to_string(),
        "missing-authz" => "missing-authorization".to_string(),
        "insecure-deserialization" => "deserialization".to_string(),
        other => other.to_string(),
    }
}

/// Convert a validated judge finding into the ledger entity.
/// Identity = hash(category, sink symbol, enclosing fn) — title/line excluded
/// so a different model's re-run merges instead of duplicating (P4).
pub fn into_core(f: &JudgeFinding, agent: &AgentProvenance) -> Finding {
    let conclusion =
        parse_conclusion(&f.verdict.conclusion).unwrap_or(VerdictConclusion::Uncertain);
    let category = normalize_category(&f.category);
    Finding {
        id: finding_id(&category, &f.sink_symbol, &f.enclosing_fn),
        slug: f.slug.clone(),
        title: f.title.clone(),
        severity: parse_severity(&f.severity).unwrap_or(Severity::Medium),
        category,
        file: f.file.clone(),
        line: f.line,
        end_line: None,
        sink_symbol: f.sink_symbol.clone(),
        enclosing_fn: f.enclosing_fn.clone(),
        probe_shape: f.probe_shape.clone(),
        description: f.description.clone(),
        impact: f.impact.clone(),
        preconditions: f.preconditions.clone(),
        data_flow: f.data_flow.clone(),
        evidence_ref: f.verdict.evidence_ref.clone(),
        repro_pack: f.repro_pack.as_ref().map(repro_to_core),
        verdict: Some(Verdict {
            conclusion,
            confidence: parse_confidence(&f.verdict.confidence),
            evidence_ref: f.verdict.evidence_ref.clone(),
            reasoning: f.verdict.reasoning.clone(),
            rebuttals: fiora_core::RebuttalAnswers {
                parameterized: f.verdict.rebuttals.parameterized,
                reachable: f.verdict.rebuttals.reachable,
                business_method: f.verdict.rebuttals.business_method,
                allowlisted: f.verdict.rebuttals.allowed,
                user_input_controlled: f.verdict.rebuttals.user_input_controlled,
                protected_by_guard: f.verdict.rebuttals.protected_by_guard,
                notes: f.verdict.rebuttals.notes.clone(),
            },
        }),
        chain_ids: vec![],
        agent: Some(agent.clone()),
        verification: None,
    }
}

pub fn hops_to_core(hops: &[JudgeHop]) -> Vec<CallHop> {
    hops.iter()
        .map(|h| CallHop {
            from: h.from.clone(),
            to: h.to.clone(),
            quality: match h.quality.as_str() {
                "compiler" => HopQuality::Compiler,
                "llm" => HopQuality::Llm,
                "unresolved" => HopQuality::Unresolved,
                _ => HopQuality::Traced,
            },
        })
        .collect()
}

pub fn entries_to_core(entries: &[JudgeEntry]) -> Vec<EntryAnchor> {
    entries
        .iter()
        .map(|e| EntryAnchor {
            symbol: e.symbol.clone(),
            file: e.file.clone(),
            line: e.line,
            route: e.route.clone(),
        })
        .collect()
}

fn repro_to_core(r: &JudgeRepro) -> ReproPack {
    ReproPack {
        preconditions: r.preconditions.clone(),
        request: r.request.clone(),
        expected: r.expected.clone(),
        actual: r.actual.clone(),
        status: match r.status.as_str() {
            "verified" => ReproStatus::Verified,
            "inferred" => ReproStatus::Inferred,
            _ => ReproStatus::Todo,
        },
    }
}

#[cfg(test)]
mod category_tests {
    use super::normalize_category;

    /// 同一概念的判定层自由措辞必须落进同一个词表项——否则报告分组碎成三块。
    #[test]
    fn observed_category_variants_collapse_to_one() {
        assert_eq!(normalize_category("pathtraversal"), "path-traversal");
        assert_eq!(normalize_category("path_traversal"), "path-traversal");
        assert_eq!(normalize_category("Path_Traversal"), "path-traversal");
        assert_eq!(normalize_category("missing-authz"), "missing-authorization");
        assert_eq!(
            normalize_category("insecure-deserialization"),
            "deserialization"
        );
    }

    #[test]
    fn untouched_categories_pass_through() {
        assert_eq!(normalize_category("ssrf"), "ssrf");
        assert_eq!(normalize_category("rce-python-eval"), "rce-python-eval");
        assert_eq!(normalize_category("cache-poisoning"), "cache-poisoning");
    }
}

#[cfg(test)]
mod salvage_tests {
    use super::salvage_findings;

    #[test]
    fn truncated_batch_salvages_complete_findings() {
        // 大批次输出被 token 上限截断：第二个 finding 只写了一半。
        // 已写完的第一个 finding 必须被抢救，截断的尾巴丢弃，不整批报废。
        let truncated = r#"{"findings":[
{"slug":"ssrf","category":"ssrf","title":"SSRF","severity":"HIGH","file":"a.go","line":1,
 "sink_symbol":"http.Get","enclosing_fn":"f","description":"d","impact":"i",
 "data_flow":"x","evidence":{"entries":[{"symbol":"POST /proxy","file":"routes.go","line":14,"route":"/proxy"}],
   "call_chain":[{"from":"POST /proxy","to":"http.Get","file":"proxy.go","line":7,"quality":"traced"}]},
 "repro_pack":{"preconditions":["目标端口可达"],"request":"curl -X POST 'http://t/proxy?url=http://169.254.169.254/'","expected":"拒绝","actual":"元数据回显","status":"inferred"},
 "verdict":{"conclusion":"true-positive","confidence":"high","reasoning":"r","rebuttals":{"parameterized":false,"reachable":true}}},
{"slug":"sqli","category":"sqli","title":"SQLi","severity":"CRITICAL","file":"b.go","line":2,
 "sink_sym"#;
        let out = salvage_findings(truncated);
        assert_eq!(
            out.findings.len(),
            1,
            "complete finding must survive truncation"
        );
        assert_eq!(out.findings[0].slug, "ssrf");
        assert!(
            out.refusals.iter().any(|r| r.contains("truncated")),
            "truncation must be visible in the refusal log: {:?}",
            out.refusals
        );
    }

    #[test]
    fn string_braces_do_not_confuse_the_scanner() {
        // 字符串里的花括号/转义引号不得让括号配对错乱
        let text = r#"{"findings":[{"slug":"x","category":"ssrf","title":"a{b}c \"q\"","severity":"LOW","file":"a.go","line":1,"sink_symbol":"s","enclosing_fn":"f","description":"d","impact":"i","data_flow":"x","evidence":{"entries":[],"call_chain":[]},"verdict":{"conclusion":"uncertain","confidence":"low","reasoning":"r","rebuttals":{}}}]}"#;
        let out = salvage_findings(text);
        assert_eq!(out.findings.len(), 1);
    }
}

#[cfg(test)]
mod anchor_tests {
    use super::parse_judge_output;

    #[test]
    fn tp_without_identity_anchor_is_rejected() {
        // sink_symbol 为空的 TP 会被契约拒绝（稳定 id 无法锚定）
        let text = r#"{"findings":[{"slug":"x","category":"ssrf","title":"T","severity":"HIGH","file":"a.go","line":1,"sink_symbol":"","enclosing_fn":"f","description":"d","evidence":{"entries":[{"symbol":"E","file":"r.go","line":1}],"call_chain":[{"from":"E","to":"sink"}]},"repro_pack":{"request":"curl x","expected":"y","actual":"z"},"verdict":{"conclusion":"true-positive","confidence":"high","reasoning":"r","rebuttals":{"parameterized":false,"reachable":true}}}]}"#;
        assert!(parse_judge_output(text).is_err());
    }

    #[test]
    fn tp_spelled_as_tp_does_not_bypass_the_contract() {
        // 模型写 "tp" 也是真阳性：身份锚点 / 证据 / impact / PoC 四道门必须同样生效
        let text = r#"{"findings":[{"slug":"x","category":"ssrf","title":"T","severity":"HIGH","file":"a.go","line":1,"sink_symbol":"","enclosing_fn":"f","description":"d","evidence":{"entries":[{"symbol":"E","file":"r.go","line":1}],"call_chain":[{"from":"E","to":"sink"}]},"repro_pack":{"request":"curl x","expected":"y","actual":"z"},"verdict":{"conclusion":"tp","confidence":"high","reasoning":"r","rebuttals":{"parameterized":false,"reachable":true}}}]}"#;
        assert!(
            parse_judge_output(text).is_err(),
            "缩写 tp 不能绕过身份锚点契约"
        );
    }
}
