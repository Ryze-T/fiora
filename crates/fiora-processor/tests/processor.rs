//! Pi driver + semantic channel tests. The pi binary is faked with a shell
//! script emitting the documented JSONL event stream.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use fiora_processor::{
    parse_event_stream, parse_findings, PiRequest, PiRunner, SemanticChannel, ThinkingLevel,
};
use tempfile::TempDir;

/// Write a fake `pi` that emits a session header, an assistant message with the
/// given JSON payload, usage, and settles.
fn fake_pi(dir: &TempDir, reply_json: &str) -> PathBuf {
    let bin = dir.path().join("fake-pi");
    let script = format!(
        r#"#!/bin/sh
cat <<'EVENTS'
{{"type":"session","version":3,"id":"sess-42","timestamp":"2026-01-01T00:00:00.000Z","cwd":"/repo"}}
{{"type":"agent_start"}}
{{"type":"message_end","message":{{"role":"assistant","content":[{{"type":"text","text":{}}}]}}}}
{{"type":"message_update","usage":{{"input":1200,"output":340,"cacheRead":100,"cacheWrite":0,"totalTokens":1640,"cost":{{"input":0.01,"output":0.02,"cacheRead":0,"cacheWrite":0,"total":0.03}}}}}}
{{"type":"agent_settled","aborted":false}}
EVENTS
"#,
        serde_json::to_string(reply_json).unwrap()
    );
    fs::write(&bin, script).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[test]
fn event_stream_parses_session_text_and_cost() {
    let stream = r#"{"type":"session","version":3,"id":"sess-7","timestamp":"t","cwd":"/r"}
{"type":"agent_start"}
{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"hello"}]}}
{"type":"message_update","usage":{"input":100,"output":50,"cacheRead":10,"cacheWrite":0,"totalTokens":160,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0.5}}}
{"type":"agent_settled","aborted":false}"#;
    let out = parse_event_stream(stream);
    assert_eq!(out.session_id.as_deref(), Some("sess-7"));
    assert_eq!(out.text, "hello");
    assert_eq!(out.cost.tokens_in, 110);
    assert_eq!(out.cost.tokens_out, 50);
    assert!((out.cost.usd - 0.5).abs() < 1e-9);
    assert!(!out.aborted);
}

#[test]
fn provider_error_is_not_mistaken_for_a_refusal() {
    // pi 在鉴权失败时仍然 exit 0 且事件流合法，只是 content 为空。
    // 必须把 stopReason=error 抓成 errors，否则整批会被记成「模型拒绝」，
    // 召回率被打成 0 而没人知道是 key 错了。
    let stream = r#"{"type":"session","version":3,"id":"sess-err","timestamp":"t","cwd":"/r"}
{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"401: AuthenticationError"}}
{"type":"agent_settled","aborted":false}"#;
    let out = parse_event_stream(stream);
    assert!(out.text.is_empty());
    assert_eq!(out.errors, vec!["401: AuthenticationError".to_string()]);

    // 正常拒绝（模型回了文本）不应该被当成 provider 错误
    let ok = r#"{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"{\"findings\":[],\"refusals\":[\"no\"]}"}]}}
{"type":"agent_settled","aborted":false}"#;
    assert!(parse_event_stream(ok).errors.is_empty());
}

#[test]
fn runner_fails_loudly_when_the_model_returned_nothing() {
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("pi-empty");
    let stream = r#"{"type":"session","version":3,"id":"s","timestamp":"t","cwd":"/r"}
{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"401: AuthenticationError"}}
{"type":"agent_settled","aborted":false}"#;
    let stream_file = dir.path().join("stream.jsonl");
    fs::write(&stream_file, stream).unwrap();
    let script = format!("#!/bin/sh\ncat '{}'\n", stream_file.display());
    fs::write(&bin, script).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

    let runner = PiRunner::from_binary(bin);
    let err = runner
        .run(
            dir.path(),
            &PiRequest {
                prompt: "p".into(),
                model: None,
                thinking: None,
                name: None,
                session_dir: None,
                system_prompt: None,
                timeout: None,
                tools: None,
            },
        )
        .expect_err("空回答 + provider 错误必须硬失败");
    assert!(format!("{err}").contains("AuthenticationError"), "{err}");
}

#[test]
fn runner_invokes_pi_and_parses_outcome() {
    let dir = TempDir::new().unwrap();
    let bin = fake_pi(
        &dir,
        r#"[{"file":"a.go","line":1,"slug":"auth-bypass","note":"x","snippet":"s"}]"#,
    );
    let runner = PiRunner::from_binary(bin);

    let req = PiRequest {
        prompt: "explore".to_string(),
        model: Some("test-model".to_string()),
        thinking: Some(ThinkingLevel::High),
        name: Some("batch-0".to_string()),
        session_dir: None,
        system_prompt: None,
        timeout: Some(Duration::from_secs(5)),
        tools: None,
    };
    let out = runner.run(dir.path(), &req).unwrap();
    assert_eq!(out.session_id.as_deref(), Some("sess-42"));
    assert!(out.text.contains("auth-bypass"));
    assert!((out.cost.usd - 0.03).abs() < 1e-9);
    assert_eq!(out.cost.tokens_in, 1300);
}

#[test]
fn parse_findings_tolerates_fences_but_not_slop() {
    let ok = "```json\n[{\"file\":\"a.go\",\"line\":9,\"slug\":\"backdoor\",\"note\":\"weird\",\"snippet\":\"x\"}]\n```";
    let findings = parse_findings(ok).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 9);

    let with_prose = "Here is what I found:\n[{\"file\":\"b.go\",\"line\":3,\"slug\":\"auth-bypass\",\"note\":\"n\"}]\nThat's all.";
    assert_eq!(parse_findings(with_prose).unwrap().len(), 1);

    assert!(parse_findings("not json at all").is_err());
}

/// 模型偶尔会写出括号错位的 JSON（多一个 `{`）。这时**不能**做字符级手术：
/// 删一个括号能让解析通过，但被吞掉的往往正是那条真阳性——用"救回一条别的
/// 发现"掩盖"丢了一条"比明确拒绝更糟。refusal 必须带上解析器原话。
#[test]
fn malformed_judge_json_is_refused_with_the_parser_message() {
    // 真实采样的形状：模型在 `"evidence":{` 后又多开了一层 `{`，于是这条 finding
    // 永远闭合不上——「顶层完整对象」扫描一个都收不到，整批归零。
    let skewed = r#"{"findings":[{"slug":"a","category":"rce","title":"A","severity":"HIGH","file":"a.js","line":1,"sink_symbol":"eval","enclosing_fn":"f","impact":"i","evidence":{{"entries":[]}}],"refusals":[]}"#;
    let out = fiora_processor::verdict::salvage_findings(skewed);
    assert!(out.findings.is_empty(), "no fabricated structure: {out:?}");
    assert_eq!(out.refusals.len(), 1);
    assert!(
        out.refusals[0].starts_with("output is not JSON at all:"),
        "refusal must name the parser failure: {}",
        out.refusals[0]
    );
    assert!(
        out.refusals[0].contains("line 1 column"),
        "refusal must carry the position: {}",
        out.refusals[0]
    );
}

/// 修复提示必须把解析器原话喂回去：只说「不是合法 JSON」时模型会原样重发同一份
/// 错位输出，一次修复机会白扔。
#[test]
fn json_repair_prompt_carries_the_parser_error() {
    let skewed = r#"{"findings":[{"slug":"a","evidence":{{"entries":[]}}],"refusals":[]}"#;
    let p = fiora_processor::prompts::json_repair_prompt("TASK", skewed);
    assert!(p.contains("line 1 column"), "must carry the position: {p}");
    assert!(p.contains("unbalanced brace"), "must name the likely cause");
    assert!(p.contains("TASK") && p.contains("Previous reply"));
    // 能解析但 shape 不对时不能假装有行列号：换成「键对不上 schema」的说法。
    let shaped = fiora_processor::prompts::json_repair_prompt("TASK", r#"{"foo":1}"#);
    assert!(shaped.contains("matched none of the accepted shapes"));
}

#[test]
fn semantic_channel_normalizes_candidates_with_session_ids() {
    let dir = TempDir::new().unwrap();
    let payload = r#"[{"file":"api/hidden.go","line":77,"slug":"auth-bypass","note":"skips SSO check when X header present","snippet":"if req.Header.Get(\"X-Skip\") != \"\" { return nil }"}]"#;
    let bin = fake_pi(&dir, payload);
    let runner = PiRunner::from_binary(bin);
    let channel = SemanticChannel {
        runner: &runner,
        prompts_dir: None,
        model: None,
        thinking: ThinkingLevel::High,
        jobs: 1,
    };

    let cands = channel
        .explore(
            dir.path(),
            &["api/hidden.go".to_string()],
            &["api/covered.go".to_string()],
            &fiora_processor::ExploreBudget {
                max_sessions: 1,
                modules_per_session: 4,
            },
            None,
        )
        .unwrap();

    assert_eq!(cands.candidates.len(), 1);
    assert_eq!(
        cands.session_ids,
        vec!["sess-42".to_string()],
        "exploration trace stays recoverable"
    );
    assert_eq!(cands.swept_modules, 1);
    let c = &cands.candidates[0];
    assert_eq!(c.channel, fiora_core::CandidateChannel::Semantic);
    assert_eq!(c.matcher_id, "semantic-explore");
    assert!(c.note.as_deref().unwrap().contains("SSO"));
    // stable id: same slug+file+line -> same id across runs
    assert_eq!(
        c.id,
        fiora_core::id::candidate_id("auth-bypass", "api/hidden.go", 77)
    );
}
