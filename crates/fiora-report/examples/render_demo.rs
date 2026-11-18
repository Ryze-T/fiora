//! Demo report renderer — regenerates `docs/demo-report.html`（在仓库根运行）：
//!
//! ```bash
//! cargo run -p fiora-report --example render_demo -- docs/demo-report.html
//! ```
//!
//! 构造一份展示用 ReportData（RCE 链 + SSRF + 越权 + FP 否决 + 验证徽章样态），
//! 覆盖报告的全部区块。改版式后重跑本命令刷新 demo。

use std::collections::HashMap;

use fiora_core::{
    CallHop, Chain, ChainPattern, ChainStep, Confidence, Evidence, EvidenceGrade, Finding,
    HopQuality, RebuttalAnswers, ReproPack, ReproStatus, Severity, Verdict, VerdictConclusion,
};
use fiora_report::{render_html, Coverage, ReportData, SurfaceRow};

fn f(
    id: &str,
    title: &str,
    sev: Severity,
    conc: VerdictConclusion,
    category: &str,
    verified: bool,
) -> Finding {
    Finding {
        id: id.into(),
        slug: category.into(),
        title: title.into(),
        severity: sev,
        category: category.into(),
        file: "api/peer.go".into(),
        line: 88,
        end_line: None,
        sink_symbol: "gob.NewDecoder(req.Body)".into(),
        enclosing_fn: "handlePeerSync".into(),
        probe_shape: None,
        description: "peer 同步接口未鉴权。\n请求体直接进 gob 解码器。".into(),
        impact: Some("攻击者可投递恶意 gob 载荷。\n在目标进程执行任意代码。".into()),
        preconditions: vec!["默认可打（无鉴权）".into()],
        data_flow: Some("POST /internal/peer -> handlePeerSync -> gob.NewDecoder".into()),
        evidence_ref: Some(format!("e-{id}")),
        repro_pack: Some(ReproPack {
            preconditions: vec!["目标端口可达".into()],
            request: "curl -X POST http://target:8080/internal/peer --data-binary @gob-payload"
                .into(),
            expected: "400 / 拒绝".into(),
            actual: "canary 回调命中".into(),
            status: if verified {
                ReproStatus::Verified
            } else {
                ReproStatus::Inferred
            },
        }),
        verdict: Some(Verdict {
            conclusion: conc,
            confidence: Confidence::High,
            evidence_ref: Some(format!("e-{id}")),
            reasoning: "入口枚举命中公开路由。\nsink 语义为原生反序列化。".into(),
            rebuttals: RebuttalAnswers {
                parameterized: Some(false),
                reachable: Some(true),
                business_method: Some(false),
                allowlisted: Some(false),
                user_input_controlled: Some(true),
                protected_by_guard: Some(false),
                notes: "六问反驳：入口公开、用户可控、无 guard。".into(),
            },
        }),
        chain_ids: vec![],
        agent: Some(fiora_core::AgentProvenance {
            backend: "pi".into(),
            model: "demo".into(),
            thinking_level: "xhigh".into(),
            run_id: "run-1".into(),
            session_id: None,
            cost: None,
        }),
        verification: verified.then(|| fiora_core::Verification {
            method: "agent-lab (canary 差分)".into(),
            pre_state: "static".into(),
            post_state: "confirmed".into(),
            verdict: "confirmed".into(),
            at: "2026-11-11".into(),
            notes: "canary 无害化验证，正控往返通过。".into(),
        }),
    }
}

fn main() {
    let d = ReportData {
        project: "demo-service".into(),
        repo_label: "demo-service@abc1234".into(),
        method: "规则扫描 + 语义判定 + Agent 环境验证回填".into(),
        agent_label: "Fiora".into(),
        generated_at: "2026-11-11".into(),
        scope: "针对 demo-service 的未授权与反序列化攻击面审计".into(),
        tech_tags: vec!["go".into(), "gin".into()],
        findings: vec![
            f(
                "f1",
                "未鉴权 /internal/peer 反序列化 RCE",
                Severity::Critical,
                VerdictConclusion::TruePositive,
                "insecure-deserialization",
                true,
            ),
            f(
                "f2",
                "SSRF：/proxy URL 用户可控",
                Severity::High,
                VerdictConclusion::TruePositive,
                "ssrf",
                false,
            ),
            f(
                "f3",
                "越权读取：租户过滤缺失",
                Severity::Medium,
                VerdictConclusion::Uncertain,
                "acl-check",
                false,
            ),
        ],
        chains: vec![Chain {
            id: "c1".into(),
            title: "未授权 SSRF → 内网元数据 → 凭据窃取 → 反序列化落地".into(),
            pattern: ChainPattern::Dataflow,
            steps: vec![
                ChainStep {
                    finding_id: "f2".into(),
                    note: "SSRF 打内网元数据".into(),
                },
                ChainStep {
                    finding_id: "f1".into(),
                    note: "反序列化落地执行".into(),
                },
            ],
            impact: "可获取云凭据并横向移动至任意代码执行。".into(),
            severity: Severity::Critical,
            reach: fiora_core::ChainReach::TransportGap,
        }],
        evidence: vec![Evidence {
            id: "e-f1".into(),
            sink: fiora_core::CodeAnchor {
                symbol: "gob.NewDecoder".into(),
                file: "api/peer.go".into(),
                line: 88,
            },
            sources: vec![],
            entries: vec![fiora_core::EntryAnchor {
                symbol: "POST /internal/peer".into(),
                file: "api/peer.go".into(),
                line: 86,
                route: Some("/internal/peer".into()),
            }],
            call_chain: vec![CallHop {
                from: "POST /internal/peer".into(),
                to: "gob.NewDecoder".into(),
                quality: HopQuality::Traced,
            }],
            grade: EvidenceGrade::CallchainVerified,
            unresolved_hops: vec![],
            tool: "fiora".into(),
        }],
        snippets: {
            let mut m = HashMap::new();
            m.insert(
                "f1".into(),
                " 86 | func handlePeerSync(w http.ResponseWriter, r *http.Request) {\n 87 |     // 无鉴权中间件挂载\n 88 |     dec := gob.NewDecoder(r.Body)\n 89 |     dec.Decode(&peerMsg)".into(),
            );
            m
        },
        coverage: Coverage {
            files_tracked: 42,
            files_analyzed: 42,
            files_skipped: 0,
            files_pending: 0,
            candidates_rule: 18,
            candidates_semantic: 5,
            surface_entries: 12,
        },
        surface: vec![SurfaceRow {
            file: "api/peer.go".into(),
            line: 86,
            symbol: "handlePeerSync".into(),
            route: Some("POST /internal/peer".into()),
            status: "audited".into(),
        }],
        method_notes: vec!["规则通道 recall 100% 门禁通过（31 案例语料）".into()],
        cost_summary: Some("$0.42 · 121k tokens".into()),
    };

    let html = render_html(&d);
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "docs/demo-report.html".into());
    std::fs::write(&out, html).expect("write demo report");
    println!("demo report -> {out}");
}
