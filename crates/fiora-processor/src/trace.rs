//! 审计轨迹（fiora 原生）——判定过程的一等证据资产。
//!
//! pi 的持久会话 JSONL 只是**内部存储细节**：本模块把它解析为 fiora 自己的
//! 轨迹模型并渲染。用户全程与 fiora 交互（`fiora trace`），不接触执行器。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 轨迹事件（fiora 自有语义，与执行器解耦）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum TraceEvent {
    /// 指令载入（prompt/工具面）
    PromptLoaded { tools: Vec<String> },
    /// 用户任务
    Task { text: String },
    /// agent 推理/结论文本
    Reasoning { text: String },
    /// 工具调用
    ToolCall { tool: String, args: String },
    /// 工具结果
    ToolResult {
        tool: String,
        ok: bool,
        excerpt: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrace {
    pub session_id: String,
    pub model: Option<String>,
    pub events: Vec<TraceEvent>,
}

/// 解析持久会话文件为审计轨迹（尽力而为：未知条目跳过，不断链）。
pub fn parse_session(session_id: &str, path: &Path) -> AuditTrace {
    let mut events = Vec::new();
    let mut model = None;
    let Ok(text) = std::fs::read_to_string(path) else {
        return AuditTrace {
            session_id: session_id.to_string(),
            model: None,
            events,
        };
    };
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("message") {
            continue;
        }
        let Some(msg) = v.get("message") else {
            continue;
        };
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
        match role {
            "system" => {
                let tools = msg
                    .get("toolsAdded")
                    .and_then(|t| t.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| {
                                x.get("name").and_then(|n| n.as_str()).map(str::to_string)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                events.push(TraceEvent::PromptLoaded { tools });
            }
            "user" => {
                let text = content_text(msg.get("content"));
                if !text.is_empty() {
                    events.push(TraceEvent::Task { text });
                }
            }
            "assistant" => {
                if model.is_none() {
                    model = msg
                        .get("model")
                        .and_then(|m| m.as_str())
                        .map(str::to_string);
                }
                if let Some(blocks) = msg.get("content").and_then(|c| c.as_array()) {
                    for b in blocks {
                        match b.get("type").and_then(|t| t.as_str()) {
                            // 真实格式：thinking / text / toolCall；兼容文档示例的 toolUse
                            Some("thinking") => {
                                let t = b
                                    .get("thinking")
                                    .or_else(|| b.get("text"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if !t.trim().is_empty() {
                                    events.push(TraceEvent::Reasoning { text: t });
                                }
                            }
                            Some("text") => {
                                let t = b
                                    .get("text")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if !t.trim().is_empty() {
                                    events.push(TraceEvent::Reasoning { text: t });
                                }
                            }
                            Some("toolCall") | Some("toolUse") => {
                                let tool = b
                                    .get("name")
                                    .or_else(|| b.get("toolName"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("?")
                                    .to_string();
                                let args = b
                                    .get("arguments")
                                    .or_else(|| b.get("input"))
                                    .or_else(|| b.get("args"))
                                    .map(|a| serde_json::to_string(a).unwrap_or_default())
                                    .unwrap_or_default();
                                events.push(TraceEvent::ToolCall { tool, args });
                            }
                            _ => {}
                        }
                    }
                }
            }
            "toolResult" => {
                let tool = msg
                    .get("toolName")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string();
                let ok = !msg
                    .get("isError")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let excerpt = content_text(msg.get("content"));
                events.push(TraceEvent::ToolResult { tool, ok, excerpt });
            }
            _ => {}
        }
    }
    AuditTrace {
        session_id: session_id.to_string(),
        model,
        events,
    }
}

fn content_text(v: Option<&serde_json::Value>) -> String {
    match v {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// 渲染为可读审计轨迹（终端/报告通用的纯文本）。
pub fn render_trace(trace: &AuditTrace) -> String {
    let mut out = format!(
        "审计轨迹 {}{}\n{}\n",
        trace.session_id,
        trace
            .model
            .as_ref()
            .map(|m| format!("（model: {m}）"))
            .unwrap_or_default(),
        "─".repeat(60)
    );
    for ev in &trace.events {
        match ev {
            TraceEvent::PromptLoaded { tools } => {
                out.push_str(&format!(
                    "[指令] 判定协议载入 · 工具面：{}\n",
                    tools.join(", ")
                ));
            }
            TraceEvent::Task { text } => {
                out.push_str(&format!("\n[任务] {}\n", truncate(text, 300)));
            }
            TraceEvent::Reasoning { text } => {
                for line in text.lines() {
                    let line = line.trim_end();
                    if !line.is_empty() {
                        out.push_str(&format!("[推理] {line}\n"));
                    }
                }
            }
            TraceEvent::ToolCall { tool, args } => {
                out.push_str(&format!("[工具] {tool} ← {}\n", truncate(args, 160)));
            }
            TraceEvent::ToolResult { tool, ok, excerpt } => {
                let mark = if *ok { "ok" } else { "ERR" };
                out.push_str(&format!(
                    "[结果] {tool} ({mark}) {}\n",
                    truncate(excerpt, 160)
                ));
            }
        }
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// 在会话目录中定位会话文件（id 前缀匹配）。
pub fn find_session_file(sessions_dir: &Path, session_id: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(sessions_dir).ok()?;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.contains(session_id) && name.ends_with(".jsonl") {
            return Some(e.path());
        }
    }
    None
}
