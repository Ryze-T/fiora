//! Report template contract tests —— 版式契约 = 用户模板
//! `代码审计报告模板.html`（docs/REPORT-TEMPLATE.md 为规范摘要）。
//! 改模板必须先改规范，再改本测试。

use std::collections::HashMap;

use fiora_core::{
    CallHop, Chain, ChainPattern, ChainStep, Confidence, Evidence, EvidenceGrade, Finding,
    HopQuality, RebuttalAnswers, ReproPack, ReproStatus, Severity, Verdict, VerdictConclusion,
};
use fiora_report::{is_rce, render_html, Coverage, ReportData, SurfaceRow};

fn finding(
    id: &str,
    title: &str,
    sev: Severity,
    conc: VerdictConclusion,
    category: &str,
) -> Finding {
    Finding {
        id: id.into(),
        slug: category.into(),
        title: title.into(),
        severity: sev,
        category: category.into(),
        file: "api/vuln.go".into(),
        line: 12,
        end_line: None,
        sink_symbol: "db.Exec".into(),
        enclosing_fn: "QueryUser".into(),
        probe_shape: None,
        description: "用户输入进入 db.Exec。\n缺少参数化处理。".into(),
        impact: Some("攻击者可拖库。\n可篡改任意用户数据。".into()),
        preconditions: vec!["默认可打（无鉴权）".into()],
        data_flow: Some("POST /login -> QueryUser -> db.Exec".into()),
        evidence_ref: Some(format!("e-{id}")),
        repro_pack: Some(ReproPack {
            preconditions: vec!["已登录".into()],
            request: "curl -X POST /login".into(),
            expected: "空结果".into(),
            actual: "全表".into(),
            status: ReproStatus::Inferred,
        }),
        verdict: Some(Verdict {
            conclusion: conc,
            confidence: Confidence::High,
            evidence_ref: Some(format!("e-{id}")),
            reasoning: "反驳全部失败。\n六问逐项不成立。".into(),
            rebuttals: RebuttalAnswers {
                parameterized: Some(false),
                reachable: Some(true),
                business_method: Some(false),
                allowlisted: Some(false),
                user_input_controlled: Some(true),
                protected_by_guard: Some(false),
                notes: "sprintf 拼接".into(),
            },
        }),
        chain_ids: vec![],
        agent: Some(fiora_core::AgentProvenance {
            backend: "pi".into(),
            model: "test".into(),
            thinking_level: "high".into(),
            run_id: "run-1".into(),
            session_id: None,
            cost: None,
        }),
        verification: Some(fiora_core::Verification {
            method: "live-prove (canary 差分)".into(),
            pre_state: "static".into(),
            post_state: "confirmed".into(),
            verdict: "confirmed".into(),
            at: "2026-02-03".into(),
            notes: "canary 命中".into(),
        }),
    }
}

fn evidence_for(id: &str) -> Evidence {
    Evidence {
        id: format!("e-{id}"),
        sink: fiora_core::CodeAnchor {
            symbol: "pickle.loads".into(),
            file: "io_struct.py".into(),
            line: 2737,
        },
        sources: vec![],
        entries: vec![fiora_core::EntryAnchor {
            symbol: "POST /internal/peer".into(),
            file: "info.rs".into(),
            line: 56,
            route: Some("/internal/peer".into()),
        }],
        call_chain: vec![
            CallHop {
                from: "POST /internal/peer".into(),
                to: "forward".into(),
                quality: HopQuality::Traced,
            },
            CallHop {
                from: "forward".into(),
                to: "pickle.loads".into(),
                quality: HopQuality::Traced,
            },
        ],
        grade: EvidenceGrade::CallchainVerified,
        unresolved_hops: vec![],
        tool: "agent-traced".into(),
    }
}

fn sample() -> ReportData {
    let mut fp = finding(
        "f4",
        "误报样例",
        Severity::Medium,
        VerdictConclusion::FalsePositive,
        "sqli",
    );
    fp.verdict.as_mut().unwrap().reasoning = "常量输入，非用户可控".into();
    let findings = vec![
        finding(
            "f1",
            "未鉴权 /internal/peer 反序列化 RCE <x>",
            Severity::Critical,
            VerdictConclusion::TruePositive,
            "insecure-deserialization",
        ),
        finding(
            "f2",
            "SSRF：/proxy URL 用户可控",
            Severity::High,
            VerdictConclusion::TruePositive,
            "ssrf",
        ),
        finding(
            "f3",
            "越权读取",
            Severity::Medium,
            VerdictConclusion::Uncertain,
            "acl-check",
        ),
        fp,
    ];
    ReportData {
        project: "demo".into(),
        repo_label: "demo@abc1234".into(),
        method: "规则扫描 + AI 深审".into(),
        agent_label: "Fiora · pi/mimo".into(),
        generated_at: "2026-02-03".into(),
        scope: "针对 demo 服务的未授权与反序列化攻击面审计".into(),
        tech_tags: vec!["go".into(), "gin".into()],
        snippets: {
            let mut m = HashMap::new();
            m.insert(
                "f1".to_string(),
                " 2737 │ pickle.loads(obj.data)".to_string(),
            );
            m
        },
        findings,
        cost_summary: None,
        chains: vec![Chain {
            id: "ch1".into(),
            title: "SSRF → 写文件 → RCE".into(),
            pattern: ChainPattern::Stacking,
            reach: Default::default(),
            steps: vec![
                ChainStep {
                    finding_id: "f2".into(),
                    note: "起点".into(),
                },
                ChainStep {
                    finding_id: "f1".into(),
                    note: "终点".into(),
                },
            ],
            impact: "远程代码执行".into(),
            severity: Severity::Critical,
        }],
        evidence: vec![evidence_for("f1"), evidence_for("f2"), evidence_for("f3")],
        coverage: Coverage {
            files_tracked: 10,
            files_analyzed: 8,
            files_skipped: 1,
            files_pending: 1,
            candidates_rule: 12,
            candidates_semantic: 2,
            surface_entries: 5,
        },
        surface: vec![SurfaceRow {
            file: "api/routes.go".into(),
            line: 5,
            symbol: "GET /users".into(),
            route: Some("/users".into()),
            status: "reviewed".into(),
        }],
        method_notes: vec!["工具管查得全，AI 管判得准，编排管不漏审".into()],
    }
}

#[test]
fn template_skeleton_matches_user_template() {
    let html = render_html(&sample());

    // 布局骨架
    for hook in [
        "class=\"toc\"",
        "id=\"toc-rce-list\"",
        "id=\"toc-other-list\"",
        "id=\"toc-poc-list\"",
        "class=\"hero\"",
        "CODE SECURITY AUDIT",
    ] {
        assert!(html.contains(hook), "missing skeleton {hook}");
    }
    // 六区顺序（模板编号 00-05）
    let mut last = 0;
    for sec in [
        "id=\"summary\"",
        "id=\"dashboard\"",
        "id=\"rce\"",
        "id=\"other\"",
        "id=\"poc\"",
        "id=\"method\"",
    ] {
        let idx = html
            .find(sec)
            .unwrap_or_else(|| panic!("missing section {sec}"));
        assert!(idx > last, "section {sec} out of order");
        last = idx;
    }
    // C2 部署形态 × 风险面矩阵
    assert!(
        html.contains("部署形态 × 风险面"),
        "deployment matrix required"
    );
    // 自动统计 / 交互 JS 钩子（模板自带脚本负责生成）
    for hook in [
        "stat-grid",
        "sevbar",
        "id=\"donut\"",
        "mermaid.initialize",
        "expand-all",
        "copy-btn",
    ] {
        assert!(html.contains(hook), "missing js hook {hook}");
    }
}

#[test]
fn finding_cards_use_template_contract() {
    let html = render_html(&sample());

    // data-sev / data-track 契约（模板 JS 依赖）
    assert!(
        html.contains("data-sev=\"CRITICAL\" data-track=\"rce\""),
        "RCE track card"
    );
    assert!(
        html.contains("data-sev=\"HIGH\" data-track=\"other\""),
        "other track card"
    );

    // XSS 转义
    assert!(!html.contains("RCE <x>"), "unescaped title!");
    assert!(html.contains("RCE &lt;x&gt;"));

    // 卡片结构：问题/影响 双栏 + 证据表 + 判定 + 跳转
    for block in [
        "问题",
        "影响",
        "ev-table",
        "触发条件",
        "判定：TRUE-POSITIVE",
        "复现与 PoC ↓",
    ] {
        assert!(html.contains(block), "missing card block {block}");
    }
    // A1 两轴定级：前置条件必须渲染
    assert!(
        html.contains("默认可打（无鉴权）"),
        "preconditions must render"
    );

    // mermaid 流程图（证据链驱动）
    assert!(html.contains("flowchart LR"), "mermaid flow required");
    assert!(html.contains("pickle.loads"), "sink in mermaid");
}

#[test]
fn poc_cards_link_back_and_forth() {
    let html = render_html(&sample());

    // 发现 ↔ PoC 双向跳转（id 后缀一致）
    assert!(html.contains("id=\"poc-f1\""), "poc card for f1");
    assert!(
        html.contains("href=\"#poc-f1\">复现与 PoC ↓"),
        "finding -> poc jump"
    );
    assert!(
        html.contains("href=\"#finding-f1\">↑ 返回链路分析"),
        "poc -> finding jump"
    );
    // 前置条件 / 复现步骤 / 预期实际 / 验证徽章
    for block in ["前置条件", "复现步骤", "预期（安全行为）", "已实测验证"] {
        assert!(html.contains(block), "missing poc block {block}");
    }
    // 速览表
    assert!(html.contains("overview-table"), "overview table required");
}

#[test]
fn rce_extraction_and_negative_cards() {
    let d = sample();
    assert!(is_rce(&d.findings[0]), "deserialization must be RCE");
    assert!(!is_rce(&d.findings[1]), "ssrf alone is not RCE");

    let html = render_html(&d);
    // RCE 区/其余区由 data-track 区分
    let rce_sec = &html[html.find("id=\"rce\"").unwrap()..html.find("id=\"other\"").unwrap()];
    assert!(rce_sec.contains("f1"), "RCE finding in rce section");
    assert!(
        !rce_sec.contains("finding-f2\""),
        "non-RCE must not be in rce section"
    );

    // 负向结论轻卡片（FALSE-POSITIVE）
    assert!(html.contains("FALSE-POSITIVE"), "FP card required");
    assert!(
        html.contains("常量输入，非用户可控"),
        "FP reasoning rendered"
    );

    // 独立攻击链（mermaid 表达）
    assert!(html.contains("攻击链-1"), "chain card required");
    assert!(
        html.contains("id=\"chain-1\""),
        "chain card must carry an anchor id"
    );
    assert!(
        !html.contains("href=\"\"") && !html.contains("href=\"#\""),
        "no empty anchors"
    );

    // 离线契约（REPORT-TEMPLATE.md）：零外部资源；含图报告必须内嵌渲染器
    assert!(
        !html.contains("src=\"http") && !html.contains("href=\"http"),
        "no external resources (offline promise)"
    );
    assert!(
        html.contains(fiora_report::MERMAID_TAG),
        "mermaid renderer must be vendored inline when diagrams exist"
    );
    assert!(!html.contains("cdn.jsdelivr"), "no CDN references");
}

#[test]
fn report_is_offline_with_zero_external_resources() {
    // 无图报告（零 mermaid 块）不应携带 3.3MB 渲染器，同样零外部资源
    let mut d = sample();
    d.findings.retain(|f| f.evidence_ref.is_none());
    d.chains.clear();
    let html = render_html(&d);
    assert!(
        !html.contains(fiora_report::MERMAID_TAG),
        "diagram-free report must stay lightweight (no vendored mermaid)"
    );
    assert!(
        !html.contains("src=\"http") && !html.contains("href=\"http"),
        "no external resources (offline promise)"
    );
    assert!(
        !html.contains("cdn.jsdelivr") && !html.contains("fonts.googleapis"),
        "no CDN references"
    );
}
