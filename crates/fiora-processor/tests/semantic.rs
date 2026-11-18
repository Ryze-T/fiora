//! 语义通道的诚实性契约：会话失败/空手而归绝不冒领「扫过」。
//!
//! 真实事故形态（大仓实测）：pi 缺 API key 时 exit 1、stdout 只有一行
//! session 头、原因在 stderr——旧实现把它计成「swept 8 modules」。

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use fiora_processor::{ExploreBudget, PiRunner, SemanticChannel, ThinkingLevel};

/// 写一个假 pi（sh 脚本）当运行时，返回它的 runner。
fn fake_pi(script: &str) -> (tempfile::TempDir, PiRunner) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let bin = dir.path().join("pi");
    fs::write(&bin, script).expect("write fake pi");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod");
    (dir, PiRunner::from_binary(&bin))
}

fn channel<'a>(runner: &'a PiRunner) -> SemanticChannel<'a> {
    SemanticChannel {
        runner,
        prompts_dir: None,
        model: None,
        thinking: ThinkingLevel::Off,
        jobs: 1,
    }
}

const FAKE_SESSION: &str = r#"{"type":"session","id":"test-session","timestamp":"t","cwd":"."}"#;

#[test]
fn a_failed_session_is_not_counted_as_swept() {
    // 精确复刻实测现场：138 字节 stdout + stderr 说明真相 + exit 1。
    let (_d, runner) = fake_pi(&format!(
        "#!/bin/sh\nprintf '%s\\n' '{FAKE_SESSION}'\necho 'No API key found for volc.' >&2\nexit 1\n"
    ));
    let root = PathBuf::from(".");
    let report = channel(&runner)
        .explore(
            &root,
            &["a.py".into(), "b.py".into()],
            &[],
            &ExploreBudget::default(),
            None,
        )
        .expect("explore returns a report");
    assert_eq!(report.sessions_failed, 1, "失败会话必须入账为失败");
    assert_eq!(report.swept_modules, 0, "失败会话不得计入扫过");
    assert!(!report.failure_notes.is_empty(), "失败原因必须可见");
}

#[test]
fn a_zero_turn_stream_is_a_failure_not_a_clean_sweep() {
    // exit 0 但一个回合都没有（模型从未被调用）同样不算「扫过」。
    let (_d, runner) = fake_pi(&format!(
        "#!/bin/sh\nprintf '%s\\n' '{FAKE_SESSION}'\nexit 0\n"
    ));
    let root = PathBuf::from(".");
    let report = channel(&runner)
        .explore(
            &root,
            &["a.py".into(), "b.py".into()],
            &[],
            &ExploreBudget::default(),
            None,
        )
        .expect("explore returns a report");
    assert_eq!(report.sessions_failed, 1);
    assert_eq!(report.swept_modules, 0);
}

#[test]
fn swept_modules_are_counted_only_when_the_session_returns_coverage() {
    let answer = r#"{"findings":[],"coverage":[{"module":"a.py","status":"clean","reason":"r"}]}"#;
    let (_d, runner) = fake_pi(&format!(
        "#!/bin/sh\nprintf '%s\\n' '{FAKE_SESSION}'\nprintf '%s\\n' '{{\"type\":\"message_end\",\"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"{escaped}\"}}],\"stopReason\":\"stop\"}}}}'\nprintf '%s\\n' '{{\"type\":\"agent_settled\",\"aborted\":false}}'\nexit 0\n",
        escaped = answer.replace('"', "\\\""),
    ));
    let root = PathBuf::from(".");
    let report = channel(&runner)
        .explore(
            &root,
            &["a.py".into(), "b.py".into(), "c.py".into()],
            &[],
            &ExploreBudget {
                max_sessions: 1,
                modules_per_session: 8,
            },
            None,
        )
        .expect("explore returns a report");
    assert_eq!(report.sessions_failed, 0);
    assert_eq!(report.sessions_unverified, 0);
    assert_eq!(
        report.swept_modules, 3,
        "覆盖账齐全的会话按分到的模块数计入"
    );
}

#[test]
fn a_session_without_coverage_accounts_is_unverified_not_swept() {
    let answer = r#"{"findings":[],"coverage":[]}"#;
    let (_d, runner) = fake_pi(&format!(
        "#!/bin/sh\nprintf '%s\\n' '{FAKE_SESSION}'\nprintf '%s\\n' '{{\"type\":\"message_end\",\"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"{escaped}\"}}],\"stopReason\":\"stop\"}}}}'\nprintf '%s\\n' '{{\"type\":\"agent_settled\",\"aborted\":false}}'\nexit 0\n",
        escaped = answer.replace('"', "\\\""),
    ));
    let root = PathBuf::from(".");
    let report = channel(&runner)
        .explore(
            &root,
            &["a.py".into(), "b.py".into()],
            &[],
            &ExploreBudget::default(),
            None,
        )
        .expect("explore returns a report");
    assert_eq!(report.sessions_unverified, 1, "空手而归 = 覆盖未验证");
    assert_eq!(report.swept_modules, 0);
}
