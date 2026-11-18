//! 验证就绪清单（verification checklist）——插件契约的机器可读出口。
//!
//! 产品定位：fiora 判定（code-proof 封顶），工作台 Agent 启动环境验证真值。
//! 本模块把每条 TP 翻译成 Agent 可直接执行的**验证任务**：repro 材料 + 前置 +
//! 建议验证等级 + 打法提示。Agent 读 `report.json` 的 `verification_checklist`
//! 驱动验证，结论经 `fiora verify record` 回填。

use fiora_core::family::{cwe_for, reach_tier, Family};
use fiora_core::{Finding, VerdictConclusion};
use serde::Serialize;

/// 一条验证任务（Agent 程序化消费）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyTask {
    pub id: String,
    pub title: String,
    pub severity: String,
    /// 能力族（rce/ssrf/awf/deser/injection/authz/...）
    pub family: String,
    /// 可达性档位（无条件/网络可达/部署形态/供应链/工作流）
    pub tier: String,
    pub cwe: Option<String>,
    pub preconditions: Vec<String>,
    /// 复现材料（有 repro_pack 时）
    pub repro: Option<ReproSummary>,
    /// 建议验证等级（目标）：live-prove | trigger-prove | code-proof
    pub suggested_level: String,
    /// 打法提示（按族分派的验证方法）
    pub verify_hint: String,
    /// 当前判定结论（复验后可能与初始不同）
    pub verdict_conclusion: String,
    /// 复验修正/判定备注——repro 材料可能被复验推翻，照清单盲跑会得假阴性，
    /// 修正必须随任务下发（实测教训：agent 用被推翻的前置跑了两次才定位）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict_notes: Option<String>,
    /// 已回填的验证结论（未验证则缺席）——Agent 接力前先看这里，不重复劳动。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationSummary>,
}

/// 回填过的验证结论（`fiora verify record` 的产物）摘要。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationSummary {
    pub method: String,
    pub verdict: String,
    pub at: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReproSummary {
    pub request: String,
    pub expected: String,
    pub actual: String,
    pub status: String,
}

/// 只收 true-positive（验证的对象是"判为真"的发现）。
pub fn build_checklist(findings: &[Finding]) -> Vec<VerifyTask> {
    findings
        .iter()
        .filter(|f| {
            f.verdict
                .as_ref()
                .map(|v| v.conclusion == VerdictConclusion::TruePositive)
                .unwrap_or(false)
        })
        .map(|f| {
            let fam = fiora_core::family::classify(f);
            let repro = f.repro_pack.as_ref().map(|r| ReproSummary {
                request: r.request.clone(),
                expected: r.expected.clone(),
                actual: r.actual.clone(),
                status: format!("{:?}", r.status).to_lowercase(),
            });
            let has_request = repro
                .as_ref()
                .map(|r| !r.request.trim().is_empty())
                .unwrap_or(false);
            let (level, hint) = suggest(fam, has_request);
            VerifyTask {
                id: f.id.clone(),
                title: f.title.clone(),
                severity: format!("{:?}", f.severity),
                family: fam.label().to_string(),
                tier: reach_tier(&f.preconditions).label().to_string(),
                cwe: cwe_for(f).map(|s| s.to_string()),
                preconditions: f.preconditions.clone(),
                repro,
                suggested_level: level.to_string(),
                verify_hint: hint.to_string(),
                verdict_conclusion: format!(
                    "{:?}",
                    f.verdict
                        .as_ref()
                        .map(|v| v.conclusion)
                        .unwrap_or(VerdictConclusion::Uncertain)
                )
                .to_lowercase(),
                verdict_notes: f
                    .verdict
                    .as_ref()
                    .map(|v| v.rebuttals.notes.trim().to_string())
                    .filter(|s| !s.is_empty()),
                verification: f.verification.as_ref().map(|v| VerificationSummary {
                    method: v.method.clone(),
                    verdict: v.verdict.clone(),
                    at: v.at.clone(),
                    notes: v.notes.clone(),
                }),
            }
        })
        .collect()
}

/// 建议验证等级 + 打法（按族分派）。
fn suggest(fam: Family, has_request: bool) -> (&'static str, &'static str) {
    match fam {
        // 执行类：lab 模式（真实代码 + canary）打 trigger-prove；有请求模板冲 live。
        Family::Rce | Family::Deser => (
            if has_request {
                "live-prove"
            } else {
                "trigger-prove"
            },
            "lab 模式：真实代码加载 + canary 载荷 + 正控往返；反序列化类先核 loader 语义",
        ),
        // 文件写/读：canary 文件落盘验证（trigger-prove 起步）。
        Family::Awf | Family::InfoLeak => (
            if has_request {
                "live-prove"
            } else {
                "trigger-prove"
            },
            "canary 文件/回调验证；注意写入先于响应的时序语义（5xx 不代表失败）",
        ),
        // 请求伪造：回调差分（probe 命中 + 对照组沉默）。
        Family::Ssrf => (
            if has_request {
                "live-prove"
            } else {
                "trigger-prove"
            },
            "canary 回调差分：probe 回调 >0 且对照组（死地址）=0 才判实锤",
        ),
        // 鉴权：对比请求（有/无凭据）即可 live 证明。
        Family::Authz => (
            "live-prove",
            "对比请求：无凭据 vs 有凭据响应差异即实锤；注意默认部署形态",
        ),
        // 注入：构造注入串观察响应差异；模板注入同 RCE 级谨慎。
        Family::Injection => (
            if has_request {
                "live-prove"
            } else {
                "trigger-prove"
            },
            "注入串差分：探测串响应特征 + 对照参数化变体；勿取数据（canary 语义）",
        ),
        // 供应链/工作流：环境复刻路径长，code-proof 复核证据链为主。
        Family::SupplyChain | Family::Dos | Family::Other => (
            "code-proof",
            "复核证据链完整性；可达性前置逐条核对（供应链/工作流类环境复刻成本高）",
        ),
    }
}

/// 机器可读报告 JSON（含验证就绪清单）。
pub fn render_json(d: &crate::ReportData) -> String {
    let checklist = build_checklist(&d.findings);
    let val = serde_json::json!({
        "project": d.project,
        "repoLabel": d.repo_label,
        "generatedAt": d.generated_at,
        "method": d.method,
        "findings": d.findings,
        "chains": d.chains,
        "verificationChecklist": checklist,
        "costSummary": d.cost_summary,
    });
    serde_json::to_string_pretty(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fiora_core::types::Severity;

    fn tp(title: &str, cat: &str, request: Option<&str>) -> Finding {
        Finding {
            id: format!("id-{title}"),
            slug: cat.into(),
            title: title.into(),
            severity: Severity::Critical,
            category: cat.into(),
            file: "a.py".into(),
            line: 1,
            end_line: None,
            sink_symbol: "s".into(),
            enclosing_fn: "g".into(),
            probe_shape: None,
            description: String::new(),
            impact: Some("可执行任意命令".into()),
            preconditions: vec!["默认可打".into()],
            data_flow: None,
            evidence_ref: None,
            repro_pack: request.map(|r| fiora_core::ReproPack {
                preconditions: vec![],
                request: r.into(),
                expected: "x".into(),
                actual: "y".into(),
                status: fiora_core::ReproStatus::Inferred,
            }),
            verdict: Some(fiora_core::Verdict {
                conclusion: VerdictConclusion::TruePositive,
                confidence: fiora_core::Confidence::High,
                evidence_ref: None,
                reasoning: String::new(),
                rebuttals: fiora_core::RebuttalAnswers {
                    parameterized: Some(false),
                    reachable: Some(true),
                    business_method: Some(false),
                    allowlisted: Some(false),
                    user_input_controlled: Some(true),
                    protected_by_guard: Some(false),
                    notes: String::new(),
                },
            }),
            chain_ids: vec![],
            agent: None,
            verification: None,
        }
    }

    #[test]
    fn checklist_carries_repro_and_level() {
        let f = tp("反序列化 RCE", "deser", Some("POST /x"));
        let tasks = build_checklist(&[f]);
        assert_eq!(tasks.len(), 1);
        let t = &tasks[0];
        assert_eq!(t.suggested_level, "live-prove", "有请求模板建议冲 live");
        assert!(t.repro.is_some(), "repro 材料进清单");
        assert_eq!(t.cwe.as_deref(), Some("CWE-502"));
        assert_eq!(t.tier, "无条件");
        assert!(!t.verify_hint.is_empty(), "带打法提示");
    }

    #[test]
    fn checklist_skips_false_positives() {
        let mut f = tp("误报", "sqli", None);
        f.verdict.as_mut().unwrap().conclusion = VerdictConclusion::FalsePositive;
        assert!(build_checklist(&[f]).is_empty(), "FP 不进验证清单");
    }

    #[test]
    fn family_drives_suggestion() {
        let mut f = tp("未鉴权改权重", "authz", None);
        f.impact = Some("可篡改在线模型权重".into());
        let tasks = build_checklist(&[f]);
        assert_eq!(tasks[0].family, "鉴权/授权");
        assert_eq!(
            tasks[0].suggested_level, "live-prove",
            "鉴权类对比请求即实锤"
        );
        assert_eq!(tasks[0].cwe.as_deref(), Some("CWE-862"));
    }

    #[test]
    fn render_json_embeds_checklist() {
        let d = crate::ReportData {
            project: "p".into(),
            repo_label: "r".into(),
            method: "m".into(),
            agent_label: "a".into(),
            generated_at: "now".into(),
            scope: "s".into(),
            tech_tags: vec![],
            findings: vec![tp("注入", "sqli", None)],
            chains: vec![],
            evidence: vec![],
            snippets: Default::default(),
            coverage: crate::Coverage {
                files_tracked: 0,
                files_analyzed: 0,
                files_skipped: 0,
                files_pending: 0,
                candidates_rule: 0,
                candidates_semantic: 0,
                surface_entries: 0,
            },
            surface: vec![],
            method_notes: vec![],
            cost_summary: None,
        };
        let out = render_json(&d);
        assert!(out.contains("verificationChecklist"), "JSON 含清单");
        assert!(out.contains("CWE-89"), "JSON 含 CWE 映射");
    }
}
