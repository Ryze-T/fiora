//! `fiora trace` —— 审计轨迹查看（fiora 原生，不依赖执行器）。
//!
//! 判定过程的完整推理/工具调用从 `.fiora/sessions/` 解析渲染——
//! 用户全程与 fiora 交互，pi 只是内部执行细节。

use crate::support::Repo;
use std::path::Path;

use fiora_processor::{find_session_file, parse_session, render_trace};

pub(crate) fn cmd_trace(root: &Path, id: &str, json: bool) -> Result<(), String> {
    let Repo { base, ledger, .. } = Repo::open(root)?;

    // id 先按 finding 解析（拿它的轨迹 id），否则当作轨迹 id 直查
    let mut session_id = id.to_string();
    if let Ok(Some(f)) = ledger.load_finding(id) {
        session_id = f
            .agent
            .as_ref()
            .and_then(|a| a.session_id.clone())
            .ok_or_else(|| {
                format!("finding {id} 无审计轨迹记录（该发现未经 AI 判定，或判定时未落会话）")
            })?;
    }

    let sessions = base.join("sessions");
    let file = find_session_file(&sessions, &session_id).ok_or_else(|| {
        format!(
            "轨迹 {session_id} 不在 {} —— 换机器请携带 .fiora/ 目录",
            sessions.display()
        )
    })?;

    let trace = parse_session(&session_id, &file);
    if json {
        println!("{}", serde_json::to_string_pretty(&trace).unwrap());
    } else {
        print!("{}", render_trace(&trace));
    }
    Ok(())
}
