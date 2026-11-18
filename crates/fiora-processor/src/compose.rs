//! 组合假设搜索（super-0day 的狩猎面）：0day 藏在发现与发现的"之间"。
//!
//! 机制：把本仓所有观察（TP/uncertain/FP + 狩猎线索）连同**安全假设**（FP 否决
//! 理由里"因为 XX 所以安全"的 XX）汇成清单，交给组合会话找「A 的产出喂进 B 的
//! 前置 / C 破掉 A 赖以安全的保证」；每条组合假设再走确认会话（真追代码），
//! 存活者按判定契约收编为 finding（category=composition）。
//!
//! 设计要点：**安全假设是攻击面**——单看无害的观察在组合里是链环；判定层的
//! 否决理由不是噪声，是"待击破的保证清单"。

use fiora_core::Finding;

/// 组合猎物清单里的一条观察。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Observation {
    pub id: String,
    pub area: String,
    pub kind: String,
    pub claim: String,
    /// 单看无害的原因 / 可达性前提 —— 组合搜索要击破的假设
    pub safety: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_flow: Option<String>,
}

/// 从账本 + 线索构建观察清单（确定性，零模型调用）。
pub fn build_inventory(findings: &[Finding], leads: &[String]) -> Vec<Observation> {
    let mut out = Vec::new();
    for f in findings {
        let v = f.verdict.as_ref();
        let kind = match v.map(|x| x.conclusion) {
            Some(fiora_core::VerdictConclusion::TruePositive) => "TP",
            Some(fiora_core::VerdictConclusion::FalsePositive) => "FP",
            Some(fiora_core::VerdictConclusion::Uncertain) => "uncertain",
            None => "unjudged",
        };
        let mut safety = String::new();
        if let Some(v) = v {
            safety.push_str(&v.reasoning);
            let r = &v.rebuttals;
            if r.parameterized == Some(true) {
                safety.push_str(" [已参数化]");
            }
            if r.allowlisted == Some(true) {
                safety.push_str(" [有白名单/约束]");
            }
            if r.protected_by_guard == Some(true) {
                safety.push_str(" [有守卫]");
            }
            if r.reachable == Some(false) {
                safety.push_str(" [判为不可达]");
            }
            if r.business_method == Some(true) {
                safety.push_str(" [判为普通业务方法]");
            }
        }
        if safety.trim().is_empty() {
            safety.push_str("（无安全假设记录）");
        }
        out.push(Observation {
            id: f.id.clone(),
            area: format!("{}:{} {}", f.file, f.line, f.sink_symbol),
            kind: kind.to_string(),
            claim: f.title.clone(),
            safety,
            data_flow: f.data_flow.clone(),
        });
    }
    for (i, lead) in leads.iter().enumerate() {
        out.push(Observation {
            id: format!("lead-{i}"),
            area: "hunt-journal".to_string(),
            kind: "lead".to_string(),
            claim: lead.chars().take(160).collect(),
            safety: "狩猎线索（未裁决）".to_string(),
            data_flow: None,
        });
    }
    out
}

/// 组合狩猎提示词：清单 + 威胁画像 → 组合假设（含待击破的保证）。
pub fn compose_prompt(inv: &[Observation], tech: &[String], hunt_memo: Option<&str>) -> String {
    let table = inv
        .iter()
        .map(|o| {
            format!(
                "- [{id}] ({kind}) {area}\\n  claim: {claim}\\n  safety/前提: {safety}{flow}",
                id = o.id,
                kind = o.kind,
                area = o.area,
                claim = o.claim,
                safety = o.safety,
                flow = o
                    .data_flow
                    .as_ref()
                    .map(|d| format!("\\n  flow: {d}"))
                    .unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>()
        .join("\\n");
    format!(
        r#"You are hunting SUPER-VULNS by COMPOSITION. Individually-safe observations
become critical when chained. The observations below come with their **safety
assumptions** — treat every assumption as an attack surface.

## Threat highlights
{highlights}

## Observations (findings + leads, with why each looks safe)
{table}

## Composition patterns to hunt
1. ASSUMPTION BREAK: A is safe "because guard/policy/component X holds" — find C that
   weakens, bypasses, or forges X (X is often in another observation or a field write).
2. OUTPUT→INPUT: the output/capability of one observation feeds the input/precondition
   of another (info leak + forgeable input; write primitive + reader; misconfig + sink).
3. TRUST-BOUNDARY HOP: observations on opposite sides of a boundary that connect
   (user-writable field consumed by privileged component; low-priv A reaches high-priv B).
4. CAPABILITY STACKING: weak primitives that compose (read + write = overwrite;
   reflect + forward = forge; race + retry = bypass).

Output STRICT JSON only:{{"compositions":[
  {{"id":"C1","chain":["obs-id-1","obs-id-2",...],
    "claim":"one sentence: what composes into what",
    "impact":"concrete worst case if composed",
    "preconditions":["what must hold"],
    "missing_link":"what is NOT yet verified (or empty if fully grounded)"}}
]}}

Rules: chains must reference observation ids from the list; prefer chains that
break a stated safety assumption; 1-8 compositions; quality over quantity —
a composition whose parts do not actually connect is noise."#,
        highlights = crate::prompts::with_memo(crate::prompts::tech_highlights(tech), hunt_memo),
        table = table,
    )
}

/// 组合假设的确认会话：真追代码，产出判定契约格式的 findings（存活者收编）。
pub fn compose_verify_prompt(comp_json: &str, inv: &[Observation]) -> String {
    let refs = inv
        .iter()
        .map(|o| {
            format!(
                "- [{o_id}] {area} — {claim}",
                o_id = o.id,
                area = o.area,
                claim = o.claim
            )
        })
        .collect::<Vec<_>>()
        .join("\\n");
    format!(
        r#"Verify (or kill) this COMPOSITION hypothesis by reading the real code.
The chain claims that individually-benign observations compose into impact.

## Composition under test
{comp}

## Referenced observations
{refs}

## Protocol
- Trace the ACTUAL data/capability flow between the parts (read/grep, cite file:line).
- If the composition holds: output findings in STRICT JSON exactly like this:
  {{"findings":[{{"slug":"multi-hop","category":"composition","title":"...",
    "severity":"HIGH|CRITICAL","file":"<most critical hop>","line":0,
    "sink_symbol":"<composed capability>","enclosing_fn":"...",
    "description":"how the parts compose, 每步一行","impact":"...",
    "preconditions":["..."],"data_flow":"partA -> partB -> impact in one line",
    "evidence":{{"entries":[],"call_chain":[],"sources":[]}},
    "verdict":{{"conclusion":"true-positive","confidence":"high","evidence_ref":"auto",
      "reasoning":"why the composition survives",
      "rebuttals":{{"parameterized":false,"reachable":true,"business_method":false,
        "allowlisted":false,"user_input_controlled":true,"protected_by_guard":false,
        "notes":"..."}}}},
    "repro_pack":{{"preconditions":[],"request":"steps to exercise the chain",
      "expected":"...","actual":"...","status":"inferred"}}}}],"refusals":[]}}
- If the composition is broken (parts do not connect / assumption is stronger than claimed):
  return {{"findings":[],"refusals":["why it died, one line each"]}}.
- READ-ONLY. 中文可读文本、短句分点。静默放弃是被禁止的——必须二选一：收编或处刑。"#,
        comp = comp_json,
        refs = refs,
    )
}

/// 解析组合会话输出。
pub fn parse_compositions(text: &str) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    let v: serde_json::Value = serde_json::from_str(crate::verdict::extract_json(text))?;
    match v.get("compositions").and_then(|c| c.as_array()) {
        Some(a) => Ok(a.clone()),
        None => Ok(Vec::new()),
    }
}
