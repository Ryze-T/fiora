//! Pi runner — the single audit agent runtime (DESIGN.md §1/§5).
//!
//! Drives `pi` in JSON mode: `{"type":"session"}` header gives the session id
//! (every judgment keeps a recoverable reasoning trace), `message_end` gives the
//! final text, `usage.cost` feeds L0 cost accounting. The tool set is locked to
//! read-only (`read,grep,find,ls`) — static analysis only, the agent must not
//! run or exploit anything.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fiora_core::Cost;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum PiError {
    NotFound,
    Io(std::io::Error),
    Failed { status: Option<i32>, detail: String },
    Timeout,
}

impl std::fmt::Display for PiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiError::NotFound => write!(f, "pi binary not found (set FIORA_PI_BIN)"),
            PiError::Io(e) => write!(f, "pi io error: {e}"),
            PiError::Failed { status, detail } => write!(f, "pi failed ({status:?}): {detail}"),
            PiError::Timeout => write!(f, "pi run timed out"),
        }
    }
}

impl std::error::Error for PiError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingLevel {
    Off,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

impl ThinkingLevel {
    fn as_str(&self) -> &'static str {
        match self {
            ThinkingLevel::Off => "off",
            ThinkingLevel::Minimal => "minimal",
            ThinkingLevel::Low => "low",
            ThinkingLevel::Medium => "medium",
            ThinkingLevel::High => "high",
            ThinkingLevel::Xhigh => "xhigh",
            ThinkingLevel::Max => "max",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PiRequest {
    pub prompt: String,
    pub model: Option<String>,
    pub thinking: Option<ThinkingLevel>,
    /// Session name — the batch id; sessions are the recoverable evidence trail.
    pub name: Option<String>,
    pub session_dir: Option<PathBuf>,
    pub system_prompt: Option<String>,
    pub timeout: Option<Duration>,
    /// Tool allowlist; None = read-only audit tools (judge default).
    pub tools: Option<String>,
}

impl PiRequest {
    /// 常规构造：判定/改写类会话的标准形态（无自定义 system prompt、无超时、
    /// 只读工具集）。全 CLI 十余处字面量构造收敛于此。
    pub fn simple(
        name: &str,
        prompt: String,
        model: Option<String>,
        thinking: ThinkingLevel,
        session_dir: Option<PathBuf>,
    ) -> Self {
        PiRequest {
            prompt,
            model,
            thinking: Some(thinking),
            name: Some(name.to_string()),
            session_dir,
            system_prompt: None,
            timeout: None,
            tools: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PiOutcome {
    pub text: String,
    pub session_id: Option<String>,
    pub cost: Cost,
    pub aborted: bool,
    /// 助手消息条数（含纯工具调用回合）。0 = 这个会话从没真正跑过一个回合
    /// （如 pi 启动即死：「No API key found」只在 stderr，stdout 仅剩 session 头）。
    pub assistant_turns: usize,
    /// `stopReason: "error"` 里带的 provider 错误（鉴权失败、限流、模型不存在…）。
    /// 必须单独浮出来：pi 在这种情况下仍然 exit 0 且事件流合法，光看 text
    /// 会把「模型根本没回答」误记成「模型拒绝了」。
    pub errors: Vec<String>,
}

pub struct PiRunner {
    binary: PathBuf,
    /// Env overlay injected into every spawn (e.g. provider API keys resolved
    /// from the Fiora credential store). Never logged, never persisted here.
    env: Vec<(String, String)>,
}

impl PiRunner {
    /// Wrap a known binary path (used by tests and custom installs).
    pub fn from_binary(binary: impl Into<PathBuf>) -> PiRunner {
        PiRunner {
            binary: binary.into(),
            env: Vec::new(),
        }
    }

    /// Attach the env overlay (credential injection point).
    pub fn with_env(mut self, env: Vec<(String, String)>) -> PiRunner {
        self.env = env;
        self
    }

    /// Lookup order: `FIORA_PI_BIN`, `<runtime_dir>/pi`, PATH (DESIGN.md §1).
    pub fn resolve(runtime_dir: Option<&Path>) -> Option<PiRunner> {
        if let Ok(p) = std::env::var("FIORA_PI_BIN") {
            let p = PathBuf::from(p);
            if p.exists() {
                return Some(PiRunner {
                    binary: p,
                    env: Vec::new(),
                });
            }
        }
        if let Some(rt) = runtime_dir {
            let p = rt.join("pi");
            if p.exists() {
                return Some(PiRunner {
                    binary: p,
                    env: Vec::new(),
                });
            }
        }
        if let Ok(out) = Command::new("sh").args(["-c", "command -v pi"]).output() {
            if out.status.success() {
                let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !p.is_empty() {
                    return Some(PiRunner {
                        binary: PathBuf::from(p),
                        env: Vec::new(),
                    });
                }
            }
        }
        None
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// One batch run: fresh session (clean context, no cross-contamination),
    /// read-only tools, JSON event stream parsed into text + session + cost.
    pub fn run(&self, cwd: &Path, req: &PiRequest) -> Result<PiOutcome, PiError> {
        let mut cmd = Command::new(&self.binary);
        cmd.envs(self.env.iter().cloned());
        cmd.arg("--mode")
            .arg("json")
            .arg("--tools")
            .arg(self_tools(req))
            .current_dir(cwd);
        if let Some(m) = &req.model {
            cmd.arg("--model").arg(m);
        }
        if let Some(t) = req.thinking {
            cmd.arg("--thinking").arg(t.as_str());
        }
        if let Some(n) = &req.name {
            cmd.arg("--name").arg(n);
        }
        if let Some(d) = &req.session_dir {
            cmd.arg("--session-dir").arg(d);
        }
        if let Some(sp) = &req.system_prompt {
            cmd.arg("--system-prompt").arg(sp);
        }
        cmd.arg(&req.prompt);

        let out = cmd.output().map_err(PiError::Io)?;
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let outcome = parse_event_stream(&stdout);
        // 非零退出 = 会话异常死亡。不能因为 stdout 非空就放行：pi 缺 API key
        // 时 exit 1，stdout 只有一行 session 头（138 字节）+ stderr「No API
        // key found for <provider>」，放行的结果是整条通道把「没跑」记成
        // 「跑了、无发现」。原因必须带 stderr 原话报出去。
        if !out.status.success() {
            return Err(PiError::Failed {
                status: out.status.code(),
                detail: excerpt(&stderr),
            });
        }
        // 一个回合都没有 = 模型从未被调用（或 pi 静默退化）。stdout 里
        // 只有 session/agent 生命周期事件时，「空回答」不等于「无发现」。
        if outcome.assistant_turns == 0 {
            return Err(PiError::Failed {
                status: out.status.code(),
                detail: if stderr.trim().is_empty() {
                    "pi returned a stream without any assistant turn (no message_end)".to_string()
                } else {
                    excerpt(&stderr)
                },
            });
        }
        // 鉴权/限流这类 provider 错误 pi 会以 exit 0 + 合法事件流返回，只是
        // 内容为空。空回答 + 有错误 = 这一批根本没跑，必须报错，不能记成一致
        // 的「模型拒绝」把召回率悄悄打成 0。
        if outcome.text.trim().is_empty() && !outcome.errors.is_empty() {
            return Err(PiError::Failed {
                status: out.status.code(),
                detail: if stderr.trim().is_empty() {
                    outcome.errors.join("; ")
                } else {
                    format!("{stderr}; {}", outcome.errors.join("; "))
                },
            });
        }
        Ok(outcome)
    }
}

/// 错误详情摘录：空 stderr 也要明说，不能输出一片空白让人无从排查。
fn excerpt(stderr: &str) -> String {
    let text = stderr.trim();
    if text.is_empty() {
        return "<no stderr>".to_string();
    }
    let mut s: String = text.chars().take(400).collect();
    if text.chars().count() > 400 {
        s.push('…');
    }
    s
}

fn self_tools(req: &PiRequest) -> &str {
    req.tools.as_deref().unwrap_or("read,grep,find,ls")
}

/// Parse the pi JSONL event stream into the pieces the pipeline needs.
pub fn parse_event_stream(stream: &str) -> PiOutcome {
    let mut session_id = None;
    let mut text = String::new();
    let mut cost = Cost::zero();
    let mut aborted = false;
    let mut assistant_turns = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for line in stream.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        match ev.get("type").and_then(|t| t.as_str()) {
            Some("session") => {
                session_id = ev.get("id").and_then(|v| v.as_str()).map(str::to_string);
            }
            Some("message_end") => {
                if let Some(msg) = ev.get("message") {
                    if msg.get("role").and_then(|r| r.as_str()) == Some("assistant") {
                        assistant_turns += 1;
                        text = extract_text(msg.get("content"));
                        if msg.get("stopReason").and_then(|r| r.as_str()) == Some("error") {
                            let detail = msg
                                .get("errorMessage")
                                .and_then(|m| m.as_str())
                                .unwrap_or("provider error (no message)");
                            let detail = detail.to_string();
                            if !errors.contains(&detail) {
                                errors.push(detail);
                            }
                        }
                    }
                }
            }
            Some("message_update") => {
                if let Some(usage) = ev.get("usage") {
                    cost = parse_usage(usage);
                }
            }
            Some("agent_settled") => {
                aborted = ev.get("aborted").and_then(|v| v.as_bool()).unwrap_or(false);
            }
            _ => {}
        }
    }

    PiOutcome {
        text,
        session_id,
        cost,
        aborted,
        assistant_turns,
        errors,
    }
}

/// Assistant content is either a string or an array of content blocks.
fn extract_text(content: Option<&serde_json::Value>) -> String {
    match content {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| {
                if b.get("type").and_then(|t| t.as_str()) == Some("text") {
                    b.get("text").and_then(|t| t.as_str())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

fn parse_usage(usage: &serde_json::Value) -> Cost {
    let num = |k: &str| usage.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    let cost_obj = usage.get("cost");
    let usd = cost_obj
        .and_then(|c| c.get("total"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    Cost {
        tokens_in: num("input") + num("cacheRead") + num("cacheWrite"),
        tokens_out: num("output"),
        usd,
    }
}
