//! 项目画像（Agent Native）：模型读仓库提取画像 + 历史 CVE 模式 + 狩猎优先级，
//! 一次提取落账，供判定 / 探索 / 组合三个会话做注意力引导。
//!
//! 取代原先的手工哨兵词表：词表要随框架迭代维护且永远滞后，判定模型本身
//! 就认识新框架——让它自己看项目、按栈的历史教训主动思考，产物还可审计。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::pi::{PiError, PiRequest, PiRunner, ThinkingLevel};

/// 画像产物（落 `.fiora/profile.json`，可审计、可复查）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjProfile {
    /// 提取时间（落账元数据）。
    pub generated_at: String,
    /// 一句话画像。
    pub summary: String,
    /// 技术栈。
    pub stack: Vec<String>,
    /// 入口面。
    pub entry_surfaces: Vec<String>,
    /// 信任边界。
    pub trust_boundaries: Vec<String>,
    /// 历史 CVE 模式（编号仅在模型确信时给出，无据不编）。
    pub cve_patterns: Vec<CvePattern>,
    /// 狩猎优先级（结合本仓结构与 CVE 模式的主动推理）。
    pub hunting_priorities: Vec<HuntPriority>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CvePattern {
    pub pattern: String,
    pub cve: Option<String>,
    pub why: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HuntPriority {
    pub focus: String,
    pub reason: String,
    pub severity_hint: String,
}

/// 画像提取 prompt（工具会话：模型自己翻仓库）。
pub fn proj_profile_prompt(root: &Path, info_md: &str) -> String {
    format!(
        include_str!("../assets/prompts/proj-profile.md"),
        root = root.display(),
        info_md = if info_md.trim().is_empty() {
            "(none)"
        } else {
            info_md
        },
    )
}

/// 解析画像 JSON（容忍 markdown 围栏 / 前后杂散文本；字段缺省不致命）。
pub fn parse_proj_profile(text: &str) -> Result<ProjProfile, String> {
    let t = text.trim().trim_start_matches("```").trim();
    let start = t.find('{').ok_or("no JSON object in output")?;
    let end = t.rfind('}').ok_or("unclosed JSON object")?;
    serde_json::from_str::<ProjProfile>(&t[start..=end])
        .map_err(|e| format!("profile JSON invalid: {e}"))
}

/// 跑一次画像提取（一次修复回路，与判定同纪律）。
pub fn run_proj_profile(
    runner: &PiRunner,
    root: &Path,
    info_md: &str,
    model: Option<String>,
) -> Result<ProjProfile, PiError> {
    let req = PiRequest {
        prompt: proj_profile_prompt(root, info_md),
        model,
        thinking: Some(ThinkingLevel::High),
        name: Some("fiora-proj-profile".to_string()),
        session_dir: Some(root.join(".fiora").join("sessions")),
        system_prompt: None,
        timeout: None,
        tools: None,
    };
    let out = runner.run(root, &req)?;
    match parse_proj_profile(&out.text) {
        Ok(p) => Ok(p),
        Err(e) => {
            let repair = PiRequest {
                prompt: crate::json_repair_prompt(&req.prompt, &out.text),
                ..req.clone()
            };
            let fixed = runner.run(root, &repair)?;
            parse_proj_profile(&fixed.text).map_err(|_| PiError::Failed {
                status: None,
                detail: format!("profile parse failed after repair: {e}"),
            })
        }
    }
}

/// 渲染成注入判定/探索 prompt 的引导块（自带小节标题）。
pub fn render_hunt_memo(p: &ProjProfile) -> String {
    let mut out = String::from("### 项目画像与狩猎重点（模型提取 · 仅注意力引导，不作证据）\n");
    if !p.summary.trim().is_empty() {
        out.push_str(&format!("- 画像：{}\n", p.summary.trim()));
    }
    if !p.stack.is_empty() {
        out.push_str(&format!("- 栈：{}\n", p.stack.join(" · ")));
    }
    if !p.entry_surfaces.is_empty() {
        out.push_str(&format!("- 入口面：{}\n", p.entry_surfaces.join("；")));
    }
    if !p.trust_boundaries.is_empty() {
        out.push_str(&format!("- 信任边界：{}\n", p.trust_boundaries.join("；")));
    }
    if !p.cve_patterns.is_empty() {
        out.push_str("- 历史 CVE 模式：\n");
        for c in &p.cve_patterns {
            let id = c.cve.as_deref().filter(|s| !s.trim().is_empty());
            let tag = match id {
                Some(v) => format!("（{v}）"),
                None => String::new(),
            };
            out.push_str(&format!("  - {}{}：{}\n", c.pattern, tag, c.why));
        }
    }
    if !p.hunting_priorities.is_empty() {
        out.push_str("- 狩猎优先级：\n");
        for (i, h) in p.hunting_priorities.iter().enumerate() {
            out.push_str(&format!("  {}. {} —— {}\n", i + 1, h.focus, h.reason));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_fenced_json() {
        let raw = r#"```json
{"summary":"推理服务","stack":["python","fastapi"],
 "entry_surfaces":["OpenAI 兼容 HTTP API"],
 "trust_boundaries":["鉴权在上游网关"],
 "cve_patterns":[{"pattern":"权重加载反序列化","cve":null,"why":"该栈历史高发"}],
 "hunting_priorities":[{"focus":"权重热更接口","reason":"管理面未鉴权","severity_hint":"high"}]}
```"#;
        let p = parse_proj_profile(raw).expect("parse");
        assert_eq!(p.summary, "推理服务");
        assert_eq!(p.cve_patterns.len(), 1);
        assert!(p.cve_patterns[0].cve.is_none());
        assert_eq!(p.hunting_priorities[0].severity_hint, "high");
    }

    #[test]
    fn missing_optional_fields_default_instead_of_failing() {
        let p = parse_proj_profile(r#"{"summary":"cli 工具"}"#).expect("parse");
        assert!(p.stack.is_empty());
        assert!(p.hunting_priorities.is_empty());
    }

    #[test]
    fn garbage_is_rejected_not_guessed() {
        assert!(parse_proj_profile("not json at all").is_err());
    }

    #[test]
    fn memo_renders_all_sections_with_evidence_caveat() {
        let p = ProjProfile {
            generated_at: String::new(),
            summary: "s".into(),
            stack: vec!["go".into()],
            entry_surfaces: vec!["HTTP".into()],
            trust_boundaries: vec!["t".into()],
            cve_patterns: vec![CvePattern {
                pattern: "p".into(),
                cve: Some("CVE-2020-1".into()),
                why: "w".into(),
            }],
            hunting_priorities: vec![HuntPriority {
                focus: "f".into(),
                reason: "r".into(),
                severity_hint: "high".into(),
            }],
        };
        let m = render_hunt_memo(&p);
        assert!(m.contains("项目画像与狩猎重点"));
        assert!(m.contains("CVE-2020-1"));
        assert!(m.contains("1. f —— r"));
        assert!(m.contains("不作证据"));
    }
}
