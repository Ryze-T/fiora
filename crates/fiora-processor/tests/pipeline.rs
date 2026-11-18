//! M3 tests: verdict contract, full pipeline (triage→judge→revalidate) over a
//! smart fake pi that answers differently per prompt, and the chain engine.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use fiora_core::id::candidate_id;
use fiora_core::{Candidate, CandidateChannel, FileStatus, Ledger, Severity, VerdictConclusion};
use fiora_processor::{
    compose_chains, parse_judge_output, persist_chains, process_pending, PiRunner, ProcessConfig,
    ThinkingLevel,
};
use tempfile::TempDir;

const JUDGE_PAYLOAD: &str = r#"{"findings":[{"slug":"sqli-sprintf-into-where","category":"sqli","title":"SQL injection in QueryUser","severity":"HIGH","file":"api/vuln.go","line":12,"sink_symbol":"db.Exec","enclosing_fn":"QueryUser","description":"user input q flows into raw SQL via fmt.Sprintf","impact":"攻击者可拖库、篡改任意用户数据","data_flow":"POST /login -> QueryUser -> db.Exec","evidence":{"entries":[{"symbol":"POST /login","file":"api/routes.go","line":5,"route":"/login"}],"call_chain":[{"from":"POST /login","to":"QueryUser","quality":"traced"},{"from":"QueryUser","to":"db.Exec","quality":"traced"}],"sources":[{"symbol":"q","file":"api/vuln.go","line":11}]},"verdict":{"conclusion":"true-positive","confidence":"high","evidence_ref":"auto","reasoning":"every rebuttal fails: raw string interpolation, reachable from POST /login, user-controlled q","rebuttals":{"parameterized":false,"reachable":true,"business_method":false,"allowed":false,"user_input_controlled":true,"protected_by_guard":false,"notes":"db.Exec receives fmt.Sprintf output"}},"repro_pack":{"preconditions":["valid session"],"request":"curl -X POST /login --data \"name=x' OR 1=1--\"","expected":"empty result","actual":"full table dump","status":"inferred"}}],"refusals":[]}"#;

const REVALIDATE_PAYLOAD: &str = r#"{"conclusion":"false-positive","confidence":"high","reasoning":"the value comes from a validated internal config, not user input; original claim of user control was wrong","rebuttals":{"parameterized":null,"reachable":true,"business_method":null,"allowed":null,"user_input_controlled":false,"protected_by_guard":null,"notes":"re-traced the source: it is config.Get, not request input"}}"#;

const TRIAGE_PAYLOAD: &str = r#"[]"#;

/// Smart fake pi: answers the judge prompt with a TP finding, the revalidation
/// prompt with a verdict flip, everything else with an empty array.
fn smart_fake_pi(dir: &TempDir) -> PathBuf {
    let bin = dir.path().join("fake-pi");
    // serde_json string literals are valid Python literals, so the payloads
    // embed cleanly via json.loads(...).
    let script = format!(
        r#"#!/usr/bin/env python3
import sys, json
prompt = sys.argv[-1] if len(sys.argv) > 1 else ""
if "KILL it" in prompt:
    payload = json.loads({reval})
elif "evidence-backed code audit" in prompt:
    payload = json.loads({judge})
else:
    payload = json.loads({triage})
events = [
  {{"type":"session","version":3,"id":"sess-9","timestamp":"t","cwd":"r"}},
  {{"type":"message_end","message":{{"role":"assistant","content":[{{"type":"text","text":json.dumps(payload)}}]}}}},
  {{"type":"message_update","usage":{{"input":1000,"output":400,"cacheRead":0,"cacheWrite":0,"totalTokens":1400,"cost":{{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0.05}}}}}},
  {{"type":"agent_settled","aborted":False}},
]
print("\n".join(json.dumps(e) for e in events))
"#,
        judge = serde_json::to_string(JUDGE_PAYLOAD).unwrap(),
        reval = serde_json::to_string(REVALIDATE_PAYLOAD).unwrap(),
        triage = serde_json::to_string(TRIAGE_PAYLOAD).unwrap(),
    );
    fs::write(&bin, script).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn candidate(slug: &str, file: &str, line: u32) -> Candidate {
    Candidate {
        id: candidate_id(slug, file, line),
        slug: slug.to_string(),
        matcher_id: slug.to_string(),
        channel: CandidateChannel::Rule,
        file: file.to_string(),
        line,
        end_line: None,
        snippet: "db.Exec(fmt.Sprintf(...))".to_string(),
        note: None,
        evidence_id: None,
    }
}

#[test]
fn judge_validation_rejects_tp_without_traced_evidence() {
    let bad = r#"{"findings":[{"slug":"x","category":"sqli","title":"t","severity":"HIGH","file":"a.go","line":1,"sink_symbol":"s","enclosing_fn":"f","description":"d","verdict":{"conclusion":"true-positive","confidence":"high","reasoning":"r","rebuttals":{"reachable":true,"notes":""}}}],"refusals":[]}"#;
    assert!(
        parse_judge_output(bad).is_err(),
        "TP without entry+chain must be rejected"
    );

    let unreachable = r#"{"findings":[{"slug":"x","category":"sqli","title":"t","severity":"HIGH","file":"a.go","line":1,"sink_symbol":"s","enclosing_fn":"f","description":"d","evidence":{"entries":[{"symbol":"GET /","file":"a.go","line":1}],"call_chain":[{"from":"GET /","to":"s","quality":"traced"}]},"verdict":{"conclusion":"true-positive","confidence":"high","reasoning":"r","rebuttals":{"reachable":false,"notes":""}}}],"refusals":[]}"#;
    assert!(
        parse_judge_output(unreachable).is_err(),
        "TP with reachable=false must be rejected"
    );
}

#[test]
fn pipeline_end_to_end_judge_and_revalidate_flip() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(root.join("api")).unwrap();
    let ledger = Ledger::open(root.join(".fiora")).unwrap();
    ledger.init_file("api/vuln.go").unwrap();
    ledger
        .merge_candidates(
            "api/vuln.go",
            vec![candidate("sqli-sprintf-into-where", "api/vuln.go", 12)],
        )
        .unwrap();
    ledger.init_file("api/clean.go").unwrap(); // no candidates -> explicit skip

    let bin = smart_fake_pi(&dir);
    let runner = PiRunner::from_binary(bin);
    let cfg = ProcessConfig {
        batch_files: 5,
        workers: 1,
        revalidate: true,
        thinking: ThinkingLevel::High,
        ..Default::default()
    };

    let summary = process_pending(
        &fiora_processor::RunContext {
            runner: &runner,
            root: &root,
            ledger: &ledger,
            run_id: "run-1",
            prompts_dir: None,
            tech_tags: &["gin".to_string()],
            info_md: "demo service",
            hunt_memo: None,
        },
        &cfg,
    )
    .unwrap();

    assert_eq!(summary.findings, 1);
    assert_eq!(summary.files_analyzed, 1);
    assert_eq!(summary.revalidated, 1);
    assert!(summary.cost.usd > 0.0, "cost accounted");

    // finding landed with stable identity and traced evidence
    let ids = ledger.list_finding_ids().unwrap();
    assert_eq!(ids.len(), 1);
    let f = ledger.load_finding(&ids[0]).unwrap().unwrap();
    assert_eq!(f.severity, Severity::High);
    // revalidation flipped the verdict TP -> FP (adversarial pass did its job)
    assert_eq!(
        f.verdict.as_ref().unwrap().conclusion,
        VerdictConclusion::FalsePositive
    );
    assert_eq!(
        f.verdict.as_ref().unwrap().reasoning,
        "the value comes from a validated internal config, not user input; original claim of user control was wrong"
    );

    // evidence got upgraded from the agent's traced chain
    let ev = ledger
        .load_evidence(&f.evidence_ref.unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(ev.call_chain.len(), 2);

    // anti-leak accounting: the clean file has an explicit row, not silence
    let clean = ledger.load_file("api/clean.go").unwrap().unwrap();
    assert_eq!(clean.status, FileStatus::Skipped);
    assert_eq!(clean.analysis_history.len(), 1);
    assert!(clean.analysis_history[0].summary.contains("no candidates"));

    // the judged file is analyzed with history + refusal tracking fields
    let judged = ledger.load_file("api/vuln.go").unwrap().unwrap();
    assert_eq!(judged.status, FileStatus::Analyzed);
    assert_eq!(judged.analysis_history.len(), 1);
    assert_eq!(judged.analysis_history[0].refused, Some(false));
}

#[test]
fn chain_engine_composes_and_persists() {
    let dir = TempDir::new().unwrap();
    let ledger = Ledger::open(dir.path().join(".fiora")).unwrap();

    let tp =
        |category: &str, title: &str, file: &str, sev: Severity, desc: &str| fiora_core::Finding {
            id: fiora_core::id::finding_id(category, "sink", title),
            slug: category.to_string(),
            title: title.to_string(),
            severity: sev,
            category: category.to_string(),
            file: file.to_string(),
            line: 1,
            end_line: None,
            sink_symbol: "sink".to_string(),
            probe_shape: None,
            enclosing_fn: title.to_string(),
            description: desc.to_string(),
            impact: None,
            preconditions: vec![],
            data_flow: None,
            evidence_ref: None,
            repro_pack: None,
            verdict: Some(fiora_core::Verdict {
                conclusion: VerdictConclusion::TruePositive,
                confidence: fiora_core::Confidence::High,
                evidence_ref: None,
                reasoning: "r".to_string(),
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
        };

    let findings = vec![
        // capability stacking: credential read + SSRF
        tp(
            "secrets-exposure",
            "Hardcoded admin token in config loader",
            "config/load.go",
            Severity::High,
            "reads admin token",
        ),
        tp(
            "ssrf",
            "User-controlled URL fetch in webhook proxy",
            "api/proxy.go",
            Severity::High,
            "fetch() with user URL",
        ),
        // privilege progression: IDOR read + write endpoint without auth
        tp(
            "acl-check",
            "acl gap: read owner via /profile",
            "api/profile.go",
            Severity::Medium,
            "read other owner data",
        ),
        tp(
            "missing-auth",
            "write endpoint without auth",
            "api/admin.go",
            Severity::Medium,
            "POST update without auth",
        ),
    ];

    let chains = compose_chains(&findings);
    assert!(
        chains
            .iter()
            .any(|c| c.pattern == fiora_core::ChainPattern::Stacking),
        "stacking chain expected"
    );
    assert!(
        chains
            .iter()
            .any(|c| c.pattern == fiora_core::ChainPattern::Privilege),
        "privilege chain expected"
    );
    // two HIGH steps escalate to CRITICAL chain severity
    let stacking = chains
        .iter()
        .find(|c| c.pattern == fiora_core::ChainPattern::Stacking)
        .unwrap();
    assert_eq!(stacking.severity, Severity::Critical);
    assert_eq!(stacking.steps.len(), 2);

    for f in &findings {
        ledger.upsert_finding(f.clone()).unwrap();
    }
    let n = persist_chains(&ledger, &chains).unwrap();
    assert_eq!(n, chains.len());
    assert_eq!(ledger.list_chain_ids().unwrap().len(), chains.len());
    // findings are linked back into their chains (additive union)
    let linked = ledger.load_finding(&findings[0].id).unwrap().unwrap();
    assert!(!linked.chain_ids.is_empty());
}

#[test]
fn parallel_workers_process_every_file_exactly_once() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(root.join("api")).unwrap();
    let ledger = Ledger::open(root.join(".fiora")).unwrap();

    // 6 files each with a candidate -> 6 batches at batch_files=1
    let mut files = Vec::new();
    for i in 0..6 {
        let rel = format!("api/mod{i}.go");
        ledger.init_file(&rel).unwrap();
        ledger
            .merge_candidates(&rel, vec![candidate("sqli-sprintf-into-where", &rel, 12)])
            .unwrap();
        files.push(rel);
    }

    let bin = smart_fake_pi(&dir);
    let runner = PiRunner::from_binary(bin);
    let cfg = ProcessConfig {
        batch_files: 1,
        workers: 4,
        revalidate: false,
        thinking: ThinkingLevel::High,
        ..Default::default()
    };

    let summary = process_pending(
        &fiora_processor::RunContext {
            runner: &runner,
            root: &root,
            ledger: &ledger,
            run_id: "run-par",
            prompts_dir: None,
            tech_tags: &[],
            info_md: "",
            hunt_memo: None,
        },
        &cfg,
    )
    .unwrap();

    assert_eq!(summary.batches, 6, "all batches processed");
    assert_eq!(summary.files_analyzed, 6);
    for rel in &files {
        let rec = ledger.load_file(rel).unwrap().unwrap();
        assert_eq!(
            rec.status,
            fiora_core::FileStatus::Analyzed,
            "{rel} not analyzed"
        );
        assert_eq!(
            rec.analysis_history.len(),
            1,
            "{rel} processed {} times",
            rec.analysis_history.len()
        );
        assert!(rec.locked_by_run_id.is_none(), "{rel} left locked");
    }
    // stable-identity merge: the same judge output across 6 batches collapses
    // into one deduplicated finding set (append-only, never duplicated)
    assert_eq!(ledger.list_finding_ids().unwrap().len(), 1);
}

#[test]
fn verdict_vocabulary_is_real_model_tolerant() {
    use fiora_core::VerdictConclusion as VC;
    use fiora_processor::verdict::parse_conclusion;

    // legitimate doubt vocabulary maps to Uncertain instead of hard-failing
    assert_eq!(parse_conclusion("needs-more-info").unwrap(), VC::Uncertain);
    assert_eq!(parse_conclusion("inconclusive").unwrap(), VC::Uncertain);
    assert_eq!(parse_conclusion("uncertain").unwrap(), VC::Uncertain);
    assert!(parse_conclusion("banana").is_err());
}

#[test]
fn salvage_keeps_valid_findings_and_logs_the_broken_ones() {
    use fiora_processor::verdict::salvage_findings;

    let mixed = r#"{"findings":[
      {"slug":"sqli","category":"sqli","title":"good finding","severity":"HIGH",
       "file":"a.go","line":1,"sink_symbol":"db.Exec","enclosing_fn":"F","description":"d","impact":"可拖库",
       "evidence":{"entries":[{"symbol":"GET /","file":"a.go","line":1}],
                   "call_chain":[{"from":"GET /","to":"F","quality":"traced"}]},
       "repro_pack":{"preconditions":[],"request":"curl http://x/","expected":"e","actual":"a","status":"inferred"},
       "verdict":{"conclusion":"true-positive","confidence":"high","reasoning":"r",
                  "rebuttals":{"reachable":true,"notes":""}}},
      {"slug":"x","title":"broken entry","severity":"NONSENSE","file":"b.go","line":2,
       "sink_symbol":"s","enclosing_fn":"g","description":"d",
       "verdict":{"conclusion":"true-positive","confidence":"high","reasoning":"r",
                  "rebuttals":{"reachable":true,"notes":""}}}
    ],"refusals":[]}"#;

    let out = salvage_findings(mixed);
    assert_eq!(out.findings.len(), 1, "valid finding kept");
    assert_eq!(out.findings[0].title, "good finding");
    assert_eq!(
        out.refusals.len(),
        1,
        "broken entry lands in the refusal log, not silence"
    );
    assert!(out.refusals[0].contains("salvaged-out") || out.refusals[0].contains("unparseable"));
}

#[test]
fn transport_classification_and_chain_reach() {
    use fiora_processor::chain::{transport_compatible, transport_of, Transport};
    use fiora_processor::verdict::{poc_kind, PocKind};

    let mk = |category: &str, title: &str, pre: &[&str]| fiora_core::Finding {
        id: format!("t-{category}-{title}"),
        slug: category.into(),
        title: title.into(),
        severity: fiora_core::Severity::High,
        category: category.into(),
        file: "a.go".into(),
        line: 1,
        end_line: None,
        sink_symbol: "s".into(),
        enclosing_fn: "f".into(),
        probe_shape: None,
        description: title.into(),
        impact: None,
        preconditions: pre.iter().map(|x| x.to_string()).collect(),
        data_flow: None,
        evidence_ref: None,
        repro_pack: None,
        verdict: None,
        chain_ids: vec![],
        agent: None,
        verification: None,
    };

    // A2 传输层分类
    let ssrf = mk("ssrf", "图片 URL 抓取", &["默认部署即暴露"]);
    let zmq = mk(
        "insecure-deserialization",
        "ZMQ unpickle",
        &["回环绑定：TCP 服务"],
    );
    let eval = mk("code-injection", "eval 数据集", &["供应链语境：benchmark"]);
    let file = mk("path-traversal", "任意文件覆写", &["需 multimodal-gen"]);

    assert_eq!(transport_of(&ssrf), Transport::Http);
    assert_eq!(transport_of(&zmq), Transport::RawTcp);
    assert_eq!(transport_of(&eval), Transport::Benchmark);
    assert_eq!(transport_of(&file), Transport::LocalFile);

    // 机制兼容：HTTP SSRF 能打 HTTP/文件面，打不到裸 TCP/供应链面
    assert!(transport_compatible(&ssrf, &file));
    assert!(!transport_compatible(&ssrf, &zmq), "HTTP 打不动 ZMTP");
    assert!(!transport_compatible(&ssrf, &eval));
    assert!(
        transport_compatible(&zmq, &ssrf),
        "本地立足点不受传输层限制"
    );

    // B1 PoC 形态分派
    assert_eq!(poc_kind(&zmq), PocKind::CodeExec);
    assert_eq!(poc_kind(&eval), PocKind::CodeExec);
    assert_eq!(poc_kind(&ssrf), PocKind::Network);
    assert_eq!(poc_kind(&file), PocKind::FileOp);
}

#[test]
fn audit_trace_parses_pi_session_into_fiora_events() {
    use fiora_processor::{find_session_file, parse_session, render_trace, TraceEvent};
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    // 模拟持久会话 JSONL（pi 格式：message entries）
    // 真实 pi 会话格式：session 头 / thinking 块 / toolCall(name,arguments) / 时间戳文件名
    let lines = [
        r#"{"type":"session","version":3,"id":"sess-abc","timestamp":"t","cwd":"/r"}"#,
        r#"{"type":"message","id":"1","message":{"role":"system","content":"","sections":{"preamble":"judge"},"toolsAdded":[{"name":"read"},{"name":"grep"}]}}"#,
        r#"{"type":"message","id":"2","message":{"role":"user","content":[{"type":"text","text":"审计这个文件"}]}}"#,
        r#"{"type":"message","id":"3","message":{"role":"assistant","model":"mimo/mimo-v2.6-flash","content":[{"type":"thinking","thinking":"先想想入口"},{"type":"text","text":"先看入口点"},{"type":"toolCall","id":"c1","name":"grep","arguments":{"pattern":"pickle"}}]}}"#,
        r#"{"type":"message","id":"4","message":{"role":"toolResult","toolName":"grep","content":[{"type":"text","text":"io_struct.py:2737 pickle.loads"}],"isError":false}}"#,
        r#"{"type":"message","id":"5","message":{"role":"assistant","content":[{"type":"text","text":"结论：反序列化 RCE"}]}}"#,
        r#"{"type":"bogus-entry","id":"6"}"#,
    ];
    // 真实文件名形态：时间戳_uuid
    std::fs::write(
        sessions.join("2026-01-01T00-00-00-000Z_sess-abc.jsonl"),
        lines.join("\n"),
    )
    .unwrap();

    // 定位（按 id 子串命中时间戳文件名）+ 解析 + 渲染
    let file = find_session_file(&sessions, "sess-abc").expect("session file located");
    let trace = parse_session("sess-abc", &file);
    assert_eq!(trace.model.as_deref(), Some("mimo/mimo-v2.6-flash"));
    assert_eq!(
        trace.events.len(),
        7,
        "unknown entries skipped, no chain break"
    );
    assert!(
        matches!(&trace.events[0], TraceEvent::PromptLoaded { tools } if tools.contains(&"grep".to_string()))
    );
    assert!(matches!(&trace.events[1], TraceEvent::Task { .. }));
    assert!(
        matches!(&trace.events[2], TraceEvent::Reasoning { text } if text.contains("先想想入口")),
        "thinking 块必须渲染"
    );
    assert!(matches!(&trace.events[3], TraceEvent::Reasoning { .. }));
    assert!(
        matches!(&trace.events[4], TraceEvent::ToolCall { tool, .. } if tool == "grep"),
        "真实 toolCall 格式必须解析"
    );
    assert!(matches!(
        &trace.events[5],
        TraceEvent::ToolResult { ok: true, .. }
    ));

    let rendered = render_trace(&trace);
    assert!(rendered.contains("[任务]"), "task rendered");
    assert!(rendered.contains("[工具] grep"), "tool call rendered");
    assert!(rendered.contains("先想想入口"), "thinking rendered");
    assert!(
        rendered.contains("pickle.loads"),
        "tool result excerpt rendered"
    );
    assert!(
        rendered.contains("结论：反序列化 RCE"),
        "final reasoning rendered"
    );
}

#[test]
fn json_repair_prompt_must_carry_original_task() {
    // 回归锁定：修复请求丢任务上下文会让 agent 返回 []，静默吞掉整批判定
    use fiora_processor::prompts::json_repair_prompt;
    let repair = json_repair_prompt(
        "审计 client.go 的 APIEndpoint 流",
        "{\"findings\":[{\"slug\":\"a\",\"evidence\":{{\"entries\":[]}}],\"refusals\":[]}",
    );
    assert!(
        repair.contains("审计 client.go"),
        "原始任务必须在修复请求里"
    );
    assert!(
        repair.contains("line 1 column"),
        "解析器原话要喂回去，否则模型原样重发"
    );
    assert!(repair.contains("Previous reply"), "旧回复保留");
    assert!(repair.contains("ONLY the JSON value"), "收口指令保留");
}

#[test]
fn explore_output_accepts_hunting_protocol_shape() {
    // 狩猎协议输出 {"findings":[...],"coverage":[...]}，兼容裸数组
    use fiora_processor::semantic::{parse_explore, parse_findings};
    let v1 = r#"{"findings":[{"file":"a.go","line":1,"slug":"race","note":"n","snippet":"s"}],
                 "coverage":[{"module":"pkg/x","status":"clean","reason":"no entry"}]}"#;
    assert_eq!(parse_findings(v1).unwrap().len(), 1);
    let (_, cov) = parse_explore(v1).unwrap();
    assert_eq!(cov.len(), 1);
    assert_eq!(cov[0].module, "pkg/x");
    assert_eq!(cov[0].status, "clean");
    let v2 = r#"[{"file":"b.go","line":2,"slug":"x","note":"n","snippet":"s"}]"#;
    assert_eq!(parse_findings(v2).unwrap().len(), 1, "裸数组兼容");
}

#[test]
fn hunt_plan_parses_hypotheses_and_priorities() {
    // plan/execute 分离：规划会话输出 → 假设清单（执行会话按此分工）
    use fiora_processor::parse_plan;
    let plan = parse_plan(
        r#"{"hypotheses":[
            {"id":"H1","area":"pkg/proxy","claim":"url 参数直达 http.Get","targets":["proxy.go"],"priority":1},
            {"id":"H2","area":"pkg/auth","claim":"中间件顺序导致路由裸奔","targets":["app.go"],"priority":2}
          ],"coverage":[{"module":"pkg/x","angle":"check creds"}]}"#,
    )
    .unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].priority, 1);
    assert_eq!(plan[0].targets, vec!["proxy.go"]);
    // 空/无 hypotheses 均安全
    assert!(parse_plan(r#"{"coverage":[]}"#).unwrap().is_empty());
}

#[test]
fn tech_highlights_cover_security_critical_families() {
    // 威胁画像是可积累资产：序列化/认证/队列/云SDK/RPC/XML 六族必须在列
    use fiora_processor::prompts::tech_highlights;
    let h = tech_highlights(&[
        "serialization".into(),
        "jwt".into(),
        "kafka".into(),
        "cloudsdk".into(),
        "grpc".into(),
        "xml".into(),
    ]);
    for kw in [
        "序列化/编解码",
        "认证/令牌框架",
        "消息队列/缓存/NoSQL",
        "云 SDK/对象存储",
        "RPC/服务间调用",
        "XML 处理",
    ] {
        assert!(h.contains(kw), "威胁画像缺族: {kw}");
    }
}

#[test]
fn composition_inventory_carries_safety_assumptions() {
    // super-0day 狩猎面：FP 的"因为 XX 所以安全"是待击破的保证——必须进清单
    use fiora_core::{Confidence, Finding, RebuttalAnswers, Severity, Verdict, VerdictConclusion};
    use fiora_processor::{build_inventory, compose_prompt, parse_compositions};
    let f = Finding {
        id: "aaa".into(),
        slug: "x".into(),
        title: "placements 字段可写".into(),
        severity: Severity::Bug,
        category: "logic".into(),
        file: "a.go".into(),
        line: 1,
        end_line: None,
        sink_symbol: "write".into(),
        enclosing_fn: "f".into(),
        probe_shape: None,
        description: "d".into(),
        impact: None,
        preconditions: vec![],
        data_flow: Some("x -> y".into()),
        evidence_ref: None,
        repro_pack: None,
        verification: None,
        verdict: Some(Verdict {
            conclusion: VerdictConclusion::FalsePositive,
            confidence: Confidence::High,
            evidence_ref: None,
            reasoning: "由调度器写入，用户不可伪造".into(),
            rebuttals: RebuttalAnswers {
                parameterized: None,
                reachable: Some(false),
                business_method: Some(true),
                allowlisted: Some(true),
                user_input_controlled: None,
                protected_by_guard: Some(true),
                notes: String::new(),
            },
        }),
        chain_ids: vec![],
        agent: None,
    };
    let leads = vec!["线索：controller 键无属主校验".to_string()];
    let inv = build_inventory(&[f], &leads);
    assert_eq!(inv.len(), 2);
    assert!(
        inv[0].safety.contains("调度器写入"),
        "FP 否决理由=安全假设必入清单"
    );
    assert!(inv[0].safety.contains("[有守卫]"), "rebuttal 标记聚合");
    let p = compose_prompt(&inv, &[], None);
    assert!(p.contains("ASSUMPTION BREAK"), "组合模式词表在场");
    assert!(p.contains("controller 键无属主校验"), "线索入清单");
    // 解析兼容
    let comps = parse_compositions(r#"{"compositions":[{"id":"C1","chain":["aaa","lead-0"],"claim":"调度器签名可伪造","impact":"接管","preconditions":["可写该字段"],"missing_link":""}]}"#).unwrap();
    assert_eq!(comps.len(), 1);
    assert_eq!(comps[0]["chain"][1], "lead-0");
}
#[test]
fn contract_repair_prompt_quotes_the_violation_and_offers_a_demotion_path() {
    // 违约修复不能复用「不是 JSON」的提示：必须把违规点喂回去，并允许诚实降级
    let p = fiora_processor::prompts::contract_repair_prompt(
        "TASK",
        "finding 'X' claims true-positive without impact analysis",
        "{\"findings\":[]}",
    );
    assert!(p.contains("TASK"));
    assert!(p.contains("without impact analysis"), "违规点必须回传: {p}");
    assert!(p.contains("uncertain"), "必须给出诚实降级出口: {p}");
    assert!(p.contains("repro_pack"));
    assert!(p.contains("Previous reply"));
}

#[test]
fn a_finding_missing_a_required_field_gets_one_repair_round() {
    // 实测缺陷：模型把 severity 漏了，其余字段全对 —— 旧行为是直接丢进
    // refusal 日志，一条真阳性就这样消失。合法 JSON + 缺字段也属于可修违约，
    // 必须把 serde 的原话喂回去（和结构性违约同等对待）。
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(root.join("api")).unwrap();
    let ledger = Ledger::open(root.join(".fiora")).unwrap();
    ledger.init_file("api/vuln.go").unwrap();
    ledger
        .merge_candidates(
            "api/vuln.go",
            vec![candidate("sqli-sprintf-into-where", "api/vuln.go", 12)],
        )
        .unwrap();

    let dropped = JUDGE_PAYLOAD.replace("\"severity\":\"HIGH\",", "");
    assert!(dropped.len() < JUDGE_PAYLOAD.len(), "payload 真的少了字段");
    let bin = dir.path().join("fake-pi");
    let script = format!(
        r#"#!/usr/bin/env python3
import sys, json
prompt = sys.argv[-1] if len(sys.argv) > 1 else ""
if "violated the audit contract" in prompt:
    payload = json.loads({fixed})
elif "evidence-backed code audit" in prompt:
    payload = json.loads({dropped})
else:
    payload = json.loads({triage})
events = [
  {{"type":"session","version":3,"id":"sess-7","timestamp":"t","cwd":"r"}},
  {{"type":"message_end","message":{{"role":"assistant","content":[{{"type":"text","text":json.dumps(payload)}}]}}}},
  {{"type":"message_update","usage":{{"input":1000,"output":400,"cacheRead":0,"cacheWrite":0,"totalTokens":1400,"cost":{{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0.01}}}}}},
  {{"type":"agent_settled","aborted":False}},
]
print("\n".join(json.dumps(e) for e in events))
"#,
        fixed = serde_json::to_string(JUDGE_PAYLOAD).unwrap(),
        dropped = serde_json::to_string(&dropped).unwrap(),
        triage = serde_json::to_string(TRIAGE_PAYLOAD).unwrap(),
    );
    fs::write(&bin, script).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    let runner = PiRunner::from_binary(bin);

    let summary = process_pending(
        &fiora_processor::RunContext {
            runner: &runner,
            root: &root,
            ledger: &ledger,
            run_id: "run-1",
            prompts_dir: None,
            tech_tags: &["gin".to_string()],
            info_md: "demo service",
            hunt_memo: None,
        },
        &ProcessConfig {
            batch_files: 5,
            workers: 1,
            revalidate: false,
            thinking: ThinkingLevel::High,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(summary.findings, 1, "修复轮把漏字段的发现救了回来");
    assert_eq!(summary.refusals, 0, "修好之后不该留 refusal");
    let file = ledger.load_file("api/vuln.go").unwrap().unwrap();
    let note = file.analysis_history[0]
        .refusal_note
        .clone()
        .unwrap_or_default();
    assert!(note.is_empty(), "refusal 日志应清空，实际: {note}");
}
